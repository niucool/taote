// tests/Uefi_Test.cpp — the uefi loader slice fixtures (the module boot ride)

#include <cstdint>
#include <optional>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "qiling/core.hpp"
#include "qiling/loader/pe_uefi.hpp"
#include "qiling/os/uefi/uefi.hpp"

using namespace qiling;

namespace {

constexpr std::uint64_t kModuleBase = 0x100000;

// the PUT32/PUT16 helpers for the hand-built PE
void put16(std::vector<std::uint8_t>& v, std::size_t off, std::uint16_t x) {
    v[off] = static_cast<std::uint8_t>(x & 0xff);
    v[off + 1] = static_cast<std::uint8_t>(x >> 8);
}

void put32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
    }
}

void put64(std::vector<std::uint8_t>& v, std::size_t off, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
    }
}

// a minimal PE64 EFI application: the entry stores the ImageHandle (rcx)
// and the SystemTable (rdx) into the .data cells and returns EFI_SUCCESS.
// SectionAlignment=0x200 rides the map-all branch (0x200 is not page
// aligned)
std::vector<std::uint8_t> make_efi_module() {
    std::vector<std::uint8_t> v(0x230, 0x00);

    // the DOS header
    v[0] = 'M'; v[1] = 'Z';
    put32(v, 0x3C, 0x40);

    // the PE signature
    v[0x40] = 'P'; v[0x41] = 'E'; v[0x42] = 0; v[0x43] = 0;

    // the COFF header
    put16(v, 0x44, 0x8664);   // machine = x64
    put16(v, 0x46, 2);        // the sections
    put16(v, 0x54, 0xF0);     // SizeOfOptionalHeader
    put16(v, 0x56, 0x0022);   // characteristics

    // the OptionalHeader64
    put16(v, 0x58, 0x20B);    // PE32+
    v[0x5A] = 1;              // the linker version
    put32(v, 0x5C, 0x10);     // SizeOfCode
    put32(v, 0x68, 0x200);    // AddressOfEntryPoint
    put32(v, 0x6C, 0x200);    // BaseOfCode
    put64(v, 0x70, kModuleBase);  // ImageBase
    put32(v, 0x78, 0x200);    // SectionAlignment
    put32(v, 0x7C, 0x200);    // FileAlignment
    put16(v, 0x88, 1);        // MajorSubsystemVersion
    put32(v, 0x90, 0x1000);   // SizeOfImage
    put32(v, 0x94, 0x200);    // SizeOfHeaders
    put16(v, 0x9C, 10);       // Subsystem = EFI application
    put32(v, 0xC4, 16);       // NumberOfRvaAndSizes

    // the .text section header
    v[0x148] = '.'; v[0x149] = 't'; v[0x14A] = 'e'; v[0x14B] = 'x'; v[0x14C] = 't';
    put32(v, 0x150, 0x20);    // VirtualSize (the 18-byte code blob + the pad)
    put32(v, 0x154, 0x200);   // VirtualAddress
    put32(v, 0x158, 0x20);    // SizeOfRawData
    put32(v, 0x15C, 0x200);   // PointerToRawData
    put32(v, 0x168, 0x60000020);

    // the .data section header
    v[0x170] = '.'; v[0x171] = 'd'; v[0x172] = 'a'; v[0x173] = 't'; v[0x174] = 'a';
    put32(v, 0x178, 0x10);
    put32(v, 0x17C, 0x400);
    put32(v, 0x180, 0x10);
    put32(v, 0x184, 0x220);
    put32(v, 0x188, 0xC0000040);

    // the code: mov [rip+0x1f9], rcx | mov [rip+0x1fa], rdx | xor rax,rax | ret
    const std::vector<std::uint8_t> code = {
        0x48, 0x89, 0x0D, 0xF9, 0x01, 0x00, 0x00,
        0x48, 0x89, 0x15, 0xFA, 0x01, 0x00, 0x00,
        0x48, 0x31, 0xC0, 0xC3,
    };
    std::copy(code.begin(), code.end(), v.begin() + 0x200);

    return v;
}

Qiling make_uefi_qiling(const std::vector<std::uint8_t>& module, const std::string& name) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_uefi_rootfs";
    std::filesystem::create_directories(rootfs);

    const auto module_path = rootfs / name;
    {
        std::ofstream f(module_path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(module.data()), static_cast<std::streamsize>(module.size()));
    }

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.argv = {module_path.string()};
    options.ostype = QL_OS::UEFI;
    options.archtype = QL_ARCH::X8664;
    return Qiling{options};
}

}  // namespace

// the uefi boot ride: the PE64 module maps at the image base, the entry
// point receives (ImageHandle = the image base, SystemTable = the gST
// allocation) and the module stores both into its .data cells; the return
// hits the end-of-execution trap and the run terminates gracefully
TEST(UefiOs, ModuleBootReceivesHandleAndSystemTable) {
    auto ql = make_uefi_qiling(make_efi_module(), "BOOT.EFI");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the ImageHandle cell: the module base (the upstream's ImageHandle =
    // image_base)
    EXPECT_EQ(ql.mem().read_ptr(kModuleBase + 0x400, 8), kModuleBase);
    // the SystemTable cell: the gST allocation from the DXE heap (nonzero)
    EXPECT_NE(ql.mem().read_ptr(kModuleBase + 0x408, 8), 0u);
}

// the service-table dispatch: the module walks gST->BootServices (the
// offset 96) and calls BS->RaiseTPL(1) (the field at gBS+24, the first
// pointer after the table header); the hook returns the previous TPL (the
// TPL_APPLICATION level 4) and the module stores it
//   00: 48 8B 42 60     mov rax, [rdx+0x60]     ; rdx = the SystemTable
//   04: B9 01 00 00 00  mov ecx, 1
//   09: FF 50 18        call qword [rax+0x18]   ; BS->RaiseTPL
//   0C: 48 89 05 2B 01 00 00   mov [rip+0x12b], rax
//   13: 48 31 C0        xor rax, rax
//   16: C3              ret
TEST(UefiOs, BootServicesRaiseTplReturnsPreviousTpl) {
    const std::vector<std::uint8_t> code = {
        0x48, 0x8B, 0x42, 0x60,                    // mov rax, [rdx+0x60]
        0xB9, 0x01, 0x00, 0x00, 0x00,              // mov ecx, 1
        0xFF, 0x50, 0x18,                          // call [rax+0x18]
        0x48, 0x89, 0x05, 0xED, 0x01, 0x00, 0x00,  // mov [rip+0x1ed], rax (the .data cell)
        0x48, 0x31, 0xC0,                          // xor rax, rax
        0xC3,                                      // ret
    };
    std::vector<std::uint8_t> v(0x230, 0x00);

    // the PE skeleton (the same shape as make_efi_module with this code)
    v[0] = 'M'; v[1] = 'Z';
    {
        auto put16 = [&v](std::size_t off, std::uint16_t x) {
            v[off] = static_cast<std::uint8_t>(x & 0xff);
            v[off + 1] = static_cast<std::uint8_t>(x >> 8);
        };
        auto put32 = [&v](std::size_t off, std::uint32_t x) {
            for (int i = 0; i < 4; ++i) {
                v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
            }
        };
        auto put64 = [&v](std::size_t off, std::uint64_t x) {
            for (int i = 0; i < 8; ++i) {
                v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
            }
        };
        put32(0x3C, 0x40);
        v[0x40] = 'P'; v[0x41] = 'E'; v[0x42] = 0; v[0x43] = 0;
        put16(0x44, 0x8664);
        put16(0x46, 2);
        put16(0x54, 0xF0);
        put16(0x56, 0x0022);
        put16(0x58, 0x20B);
        v[0x5A] = 1;
        put32(0x5C, 0x20);
        put32(0x68, 0x200);
        put32(0x6C, 0x200);
        put64(0x70, 0x100000);
        put32(0x78, 0x200);
        put32(0x7C, 0x200);
        put16(0x88, 1);
        put32(0x90, 0x1000);
        put32(0x94, 0x200);
        put16(0x9C, 10);
        put32(0xC4, 16);

        v[0x148] = '.'; v[0x149] = 't'; v[0x14A] = 'e'; v[0x14B] = 'x'; v[0x14C] = 't';
        put32(0x150, 0x20);
        put32(0x154, 0x200);
        put32(0x158, 0x20);
        put32(0x15C, 0x200);
        put32(0x168, 0x60000020);

        v[0x170] = '.'; v[0x171] = 'd'; v[0x172] = 'a'; v[0x173] = 't'; v[0x174] = 'a';
        put32(0x178, 0x10);
        put32(0x17C, 0x400);
        put32(0x180, 0x10);
        put32(0x184, 0x220);
        put32(0x188, 0xC0000040);

        std::copy(code.begin(), code.end(), v.begin() + 0x200);
    }

    auto ql = make_uefi_qiling(v, "TPL.EFI");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the previous TPL: the TPL_APPLICATION level (the loader-initialized
    // state), stored by the module at the 0x100400 cell
    EXPECT_EQ(ql.mem().read_ptr(0x100400, 8), 4u);
}

// the shared PE skeleton builder: the code blob rides at the RVA 0x200 (the
// 0x40-byte .text), the .data at the RVA 0x400 (the 0x40 bytes); the base
// is the fixed 0x100000 so the code uses the absolute addressing
std::vector<std::uint8_t> build_pe_with_code(const std::vector<std::uint8_t>& code, std::size_t data_size) {
    std::vector<std::uint8_t> v(0x400 + data_size + 0x80, 0x00);
    v[0] = 'M'; v[1] = 'Z';
    auto put16 = [&v](std::size_t off, std::uint16_t x) {
        v[off] = static_cast<std::uint8_t>(x & 0xff);
        v[off + 1] = static_cast<std::uint8_t>(x >> 8);
    };
    auto put32 = [&v](std::size_t off, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) {
            v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
        }
    };
    auto put64 = [&v](std::size_t off, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) {
            v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
        }
    };
    put32(0x3C, 0x40);
    v[0x40] = 'P'; v[0x41] = 'E'; v[0x42] = 0; v[0x43] = 0;
    put16(0x44, 0x8664);
    put16(0x46, 2);
    put16(0x54, 0xF0);
    put16(0x56, 0x0022);
    put16(0x58, 0x20B);
    v[0x5A] = 1;
    put32(0x5C, 0x40);
    put32(0x68, 0x200);
    put32(0x6C, 0x200);
    put64(0x70, 0x100000);
    put32(0x78, 0x200);
    put32(0x7C, 0x200);
    put16(0x88, 1);
    put32(0x90, 0x1000);
    put32(0x94, 0x200);
    put16(0x9C, 10);
    put32(0xC4, 16);

    v[0x148] = '.'; v[0x149] = 't'; v[0x14A] = 'e'; v[0x14B] = 'x'; v[0x14C] = 't';
    put32(0x150, 0x80);
    put32(0x154, 0x200);
    put32(0x158, 0x80);
    put32(0x15C, 0x200);
    put32(0x168, 0x60000020);

    v[0x170] = '.'; v[0x171] = 'd'; v[0x172] = 'a'; v[0x173] = 't'; v[0x174] = 'a';
    put32(0x178, static_cast<std::uint32_t>(data_size));
    put32(0x17C, 0x400);
    put32(0x180, static_cast<std::uint32_t>(data_size));
    put32(0x184, 0x400);
    put32(0x188, 0xC0000040);

    std::copy(code.begin(), code.end(), v.begin() + 0x200);
    return v;
}

// the protocol ride: the module installs a protocol on a fresh handle
// (InstallProtocolInterface(handle-out, the GUID at the .data, native,
// the interface ptr)) then resolves it back (HandleProtocol(handle, the
// GUID, the out)) and stores the interface
//   the .data: 0x400 the GUID (16 bytes), 0x420 the interface value
//   (0x100450), 0x440 the handle out, 0x448 the interface out, 0x450 the
//   status out
TEST(UefiOs, InstallThenHandleProtocolRoundTrip) {
    std::vector<std::uint8_t> guid = {0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
                                      0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b};
    const std::uint64_t kBase = 0x100000;
    const std::uint64_t kGuidCell = kBase + 0x400;
    const std::uint64_t kInterfaceCell = kBase + 0x420;
    const std::uint64_t kHandleOut = kBase + 0x440;
    const std::uint64_t kInterfaceOut = kBase + 0x448;
    const std::uint64_t kStatusCell = kBase + 0x450;
    const std::vector<std::uint8_t> code = {
        // rax = gST->BootServices (rdx = the SystemTable, loaded first)
        0x48, 0x8B, 0x42, 0x60,                    // mov rax, [rdx+0x60]
        // rdx = kGuidCell (the arg2: the Protocol ptr)
        0x48, 0xBA, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        // r9 = kInterfaceCell (the arg4: the Interface)
        0x49, 0xB9, 0x20, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        // r8d = 1 (the arg3: EFI_NATIVE_INTERFACE)
        0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,
        // rcx = kHandleOut (the arg1: the handle out)
        0x48, 0xB9, 0x40, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        // r10 = [gBS+0x80] (the Install field)
        0x4C, 0x8B, 0x90, 0x80, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xD2,                          // call r10
        // mov r10, [kHandleOut] (the handle value)
        0x4C, 0x8B, 0x15, 0x07, 0x02, 0x00, 0x00,  // mov r10, [rip+0x207] -> 0x100440
        // lea rdx, [kGuidCell]
        0x48, 0xBA, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        // lea r8, [kInterfaceOut]
        0x4C, 0x8D, 0x05, 0xFE, 0x01, 0x00, 0x00,  // lea r8, [rip+0x1fe] -> 0x100448
        // mov rcx, r10
        0x4C, 0x89, 0xD1,
        // r10 = [gBS+0x88] (the HandleProtocol field, rip-relative: rax holds
        // the install status after the call)
        0x4C, 0x8B, 0x15, 0xBC, 0xFF, 0xEF, 0x03,
        0x41, 0xFF, 0xD2,                          // call r10
        // mov [kStatusCell], rax
        0x48, 0xA3, 0x50, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x31, 0xC0,
        0xC3,
    };
    (void)guid;
    auto ql = make_uefi_qiling(build_pe_with_code(code, 0x60), "PROTO.EFI");
    (void)kStatusCell;

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the upstream common.py InstallProtocolInterface stores the Interface
    // param verbatim (no dereference), so the HandleProtocol round trip
    // returns the same pointer the module passed (kInterfaceCell)
    EXPECT_EQ(ql.mem().read_ptr(kInterfaceOut, 8), kInterfaceCell);
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell, 8), 0u);
}
