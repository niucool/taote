// tests/Uefi_Test.cpp — the uefi loader slice fixtures (the module boot ride)

#include <cstdint>
#include <optional>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "qiling/core.hpp"
#include "qiling/loader/pe_uefi.hpp"
#include "qiling/os/uefi/services.hpp"
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
std::vector<std::uint8_t> build_pe_with_code(const std::vector<std::uint8_t>& code, std::size_t data_size,
                                             const std::vector<std::uint8_t>& data = {}) {
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
    // the .text sizes must cover the whole code blob (the 0x80 minimum kept
    // for the short fixtures; the event blob rides ~0x150 bytes and the
    // original 0x80 truncated its tail — the pinned "second-pass anomaly"
    // root cause)
    const std::uint32_t text_size = static_cast<std::uint32_t>(code.size() < 0x80 ? 0x80 : code.size());
    put32(0x150, text_size);
    put32(0x154, 0x200);
    put32(0x158, text_size);
    put32(0x15C, 0x200);
    put32(0x168, 0x60000020);

    v[0x170] = '.'; v[0x171] = 'd'; v[0x172] = 'a'; v[0x173] = 't'; v[0x174] = 'a';
    put32(0x178, static_cast<std::uint32_t>(data_size));
    put32(0x17C, 0x400);
    put32(0x180, static_cast<std::uint32_t>(data_size));
    put32(0x184, 0x400);
    put32(0x188, 0xC0000040);

    std::copy(code.begin(), code.end(), v.begin() + 0x200);
    if (!data.empty()) {
        std::copy(data.begin(), data.end(), v.begin() + 0x400);
    }
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
        // r10 = [gBS+0x98] (the HandleProtocol field, rip-relative: rax holds
        // the install status after the call; the field is the descriptor
        // index 16 = hdr(24) + 16*8 over the 0x4000188 base)
        0x4C, 0x8B, 0x15, 0xCC, 0xFF, 0xEF, 0x03,
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

// the event family: the module creates the event (the notify fn parked in
// the .data), checks it (NOT_READY), signals it (OK), re-checks (OK),
// closes it (OK) and re-signals (INVALID_PARAMETER). The gBS field offsets
// ride the corrected descriptor order: CreateEvent 0x50 (index 7),
// SignalEvent 0x68 (10), CloseEvent 0x70 (11), CheckEvent 0x78 (12) over
// the 24-byte header. gBS persists in r15 across the calls (rax carries
// the statuses)
// The blob's rip-relative loads were re-derived for the real layout (the
// original .text truncation hid the post-check2 flow, so the close/re-signal
// loads were never validated — the pinned "second-pass anomaly" was this
// fixture artifact, not a unicorn mechanism).
TEST(UefiOs, EventFamilyCreateSignalCheckClose) {
    const std::uint64_t kBase = 0x100000;
    const std::uint64_t kNotifyFnCell = kBase + 0x448;
    const std::uint64_t kEventOut = kBase + 0x450;
    const std::uint64_t kStatusCell = kBase + 0x458;
    const std::vector<std::uint8_t> code = {
        // rax = gST->BootServices, stashed in r15 (rax is the return slot)
        0x48, 0x8B, 0x42, 0x60,
        0x49, 0x89, 0xC7,
        // the CreateEvent arg block: the 5th arg rides [rsp+0x20]
        0x48, 0x83, 0xEC, 0x28,                    // sub rsp, 0x28
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x50, 0x04, 0x10, 0x00,  // mov qword [rsp+0x20], kEventOut
        0x48, 0x31, 0xC9,                          // xor ecx, ecx (Type = 0)
        0xBA, 0x04, 0x00, 0x00, 0x00,              // mov edx, 4 (NotifyTpl = TPL_APPLICATION)
        0x49, 0xC7, 0xC0, 0x48, 0x04, 0x10, 0x00,  // mov r8, kNotifyFnCell
        0x4D, 0x31, 0xC9,                          // xor r9, r9 (NotifyContext = 0)
        0x4D, 0x8B, 0x97, 0x50, 0x00, 0x00, 0x00,  // mov r10, [r15+0x50] (CreateEvent)
        0x41, 0xFF, 0xD2,                          // call r10
        0x48, 0x83, 0xC4, 0x28,                    // add rsp, 0x28
        0x48, 0xA3, 0x58, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kStatusCell+0], rax
        // CheckEvent(event): rcx = [kEventOut]
        0x48, 0x8B, 0x0D, 0x0B, 0x02, 0x00, 0x00,  // mov rcx, [rip+0x20b] -> kEventOut
        0x4D, 0x8B, 0x97, 0x78, 0x00, 0x00, 0x00,  // mov r10, [r15+0x78] (CheckEvent)
        0x41, 0xFF, 0xD2,
        0x48, 0xA3, 0x60, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kStatusCell+8], rax
        // SignalEvent(event)
        0x48, 0x8B, 0x0D, 0xF0, 0x01, 0x00, 0x00,  // mov rcx, [rip+0x1f0] -> kEventOut
        0x4D, 0x8B, 0x97, 0x68, 0x00, 0x00, 0x00,  // mov r10, [r15+0x68] (SignalEvent)
        0x41, 0xFF, 0xD2,
        0x48, 0xA3, 0x68, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kStatusCell+16], rax
        // CheckEvent again -> OK
        0x48, 0x8B, 0x0D, 0xD5, 0x01, 0x00, 0x00,  // mov rcx, [rip+0x1d5] -> kEventOut
        0x4D, 0x8B, 0x97, 0x78, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xD2,
        0x48, 0xA3, 0x70, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kStatusCell+24], rax
        // CloseEvent(event) -> OK
        // (the rip-relative loads below were re-derived for the real layout:
        // the original blob's disps were authored pre-truncation and the
        // close/re-signal loads pointed at the wrong cells — the pinned
        // "second-pass anomaly" was this fixture artifact, not a unicorn
        // mechanism)
        0x48, 0x8B, 0x0D, 0xBA, 0x01, 0x00, 0x00,  // mov rcx, [rip+0x1ba] -> kEventOut
        0x4D, 0x8B, 0x97, 0x70, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xD2,
        0x48, 0xA3, 0x78, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kStatusCell+32], rax
        // SignalEvent again -> INVALID_PARAMETER (the erased id)
        0x48, 0x8B, 0x0D, 0x9F, 0x01, 0x00, 0x00,  // mov rcx, [rip+0x19f] -> kEventOut
        0x4D, 0x8B, 0x97, 0x68, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xD2,
        0x48, 0xA3, 0x80, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kStatusCell+40], rax
        0x48, 0x31, 0xC0,                          // xor rax, rax
        0xC3,
    };
    auto ql = make_uefi_qiling(build_pe_with_code(code, 0xA0), "EVENT.EFI");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(kEventOut, 8), 0u);  // the first event id = len(events) = 0
    // the status cells ride the blob's store map: the create's status at
    // kStatusCell+0 (SUCCESS), the check1's at +8 (NOT_READY before the
    // signal), the signal's at +16 (OK), the check2's at +24 (OK — the
    // event was set), the close's at +32 (OK), the re-signal's at +40
    // (INVALID — the erased id)
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell + 0, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell + 8, 8), os::uefi::kEfiNotReady);
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell + 16, 8), os::uefi::kEfiSuccess);
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell + 24, 8), os::uefi::kEfiSuccess);
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell + 32, 8), os::uefi::kEfiSuccess);
    EXPECT_EQ(ql.mem().read_ptr(kStatusCell + 40, 8), os::uefi::kEfiInvalidParameter);

    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    ASSERT_EQ(loader.notify_list.size(), 1u);  // the signal pumped the notify list
    EXPECT_EQ(std::get<0>(loader.notify_list[0]), 0u);              // the event id
    EXPECT_EQ(std::get<1>(loader.notify_list[0]), kNotifyFnCell);   // the notify fn
    EXPECT_EQ(std::get<2>(loader.notify_list[0]), (std::vector<std::uint64_t>{0, 0}));  // the callback args
    EXPECT_TRUE(loader.events.empty());        // the close erased the registry
}

// the RT variable services ride: the module SetVariables "MyVar" (the wide
// name at the .data, the "Hello" payload) and immediately GetVariables it
// back. The gRT lives at the SystemTable+0x58; the GetVariable field is the
// RT index 6 (gRT+0x48) and SetVariable the index 8 (gRT+0x58) over the
// 24-byte header. The variable store rides ql.env verbatim (rt.py).
// (The original DISABLED_ note — the blob's tail rode past the 0x80 .text
// section and the GetVariable call never loaded; the same truncation
// artifact as the event fixture, not a unicorn mechanism.)
TEST(UefiOs, SetVariableThenGetVariableRoundTrip) {
    const std::uint64_t kBase = 0x100000;
    const std::uint64_t kNameCell = kBase + 0x400;
    const std::uint64_t kAttrOut = kBase + 0x430;
    const std::uint64_t kSizeOut = kBase + 0x438;
    const std::uint64_t kGetBuf = kBase + 0x440;
    const std::uint64_t kSetStatus = kBase + 0x460;
    const std::uint64_t kGetStatus = kBase + 0x468;
    const std::vector<std::uint8_t> code = {
        // rax = gST->RuntimeServices (rdx = the SystemTable), stashed in r15
        0x48, 0x8B, 0x42, 0x58,
        0x49, 0x89, 0xC7,
        // SetVariable(name, guid, attributes=0, size=5, data="Hello")
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x20, 0x04, 0x10, 0x00,  // [rsp+0x20] = kSetData
        0x48, 0xB9, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // rcx = kNameCell
        0x48, 0xBA, 0x10, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // rdx = kGuidCell
        0x45, 0x31, 0xC0,                                      // xor r8d, r8d (attributes = 0)
        0x41, 0xB9, 0x05, 0x00, 0x00, 0x00,                    // mov r9d, 5 (the size)
        0x4D, 0x8B, 0x97, 0x58, 0x00, 0x00, 0x00,              // mov r10, [r15+0x58] (SetVariable)
        0x41, 0xFF, 0xD2,
        0x48, 0x83, 0xC4, 0x28,
        0x48, 0xA3, 0x60, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kSetStatus], rax
        // GetVariable(name, guid, &attr_out, &size_out, data_out)
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x40, 0x04, 0x10, 0x00,  // [rsp+0x20] = kGetBuf
        0x48, 0xB9, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // rcx = kNameCell
        0x48, 0xBA, 0x10, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // rdx = kGuidCell
        0x49, 0xB8, 0x30, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // r8 = kAttrOut
        0x49, 0xB9, 0x38, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // r9 = kSizeOut
        0x4D, 0x8B, 0x97, 0x48, 0x00, 0x00, 0x00,              // mov r10, [r15+0x48] (GetVariable)
        0x41, 0xFF, 0xD2,
        0x48, 0x83, 0xC4, 0x28,
        0x48, 0xA3, 0x68, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [kGetStatus], rax
        0x48, 0x31, 0xC0,
        0xC3,
    };
    // the .data preload: the wide "MyVar ", the 16-byte guid, the "Hello"
    // payload, the size-out preloaded with the buffer size 0x20
    std::vector<std::uint8_t> data_payload(0xC0, 0x00);
    {
        const char name[] = "MyVar";
        for (std::size_t i = 0; i <= 5; ++i) {
            data_payload[i * 2] = static_cast<std::uint8_t>(name[i]);
        }
        data_payload[0x10] = 0x11; data_payload[0x11] = 0x22; data_payload[0x12] = 0x33;
        data_payload[0x13] = 0x44; data_payload[0x14] = 0x55; data_payload[0x15] = 0x66;
        data_payload[0x16] = 0x77; data_payload[0x17] = 0x88; data_payload[0x18] = 0x99;
        data_payload[0x19] = 0xAA; data_payload[0x1A] = 0xBB; data_payload[0x1B] = 0xCC;
        data_payload[0x1C] = 0xDD; data_payload[0x1D] = 0xEE; data_payload[0x1E] = 0xFF;
        data_payload[0x1F] = 0x00;
        data_payload[0x20] = 'H'; data_payload[0x21] = 'e'; data_payload[0x22] = 'l';
        data_payload[0x23] = 'l'; data_payload[0x24] = 'o';
        data_payload[0x38] = 0x20;  // the GetVariable's in-out buffer size
    }
    auto ql = make_uefi_qiling(build_pe_with_code(code, 0xC0, data_payload), "NVRAM.EFI");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(kSetStatus, 8), os::uefi::kEfiSuccess);
    EXPECT_EQ(ql.mem().read_ptr(kGetStatus, 8), os::uefi::kEfiSuccess);
    EXPECT_EQ(ql.mem().read_ptr(kSizeOut, 8), 5u);  // the in-out size updated to the data length
    EXPECT_EQ(ql.mem().read_ptr(kAttrOut, 4),
              static_cast<std::uint64_t>(os::uefi::kEfiVariableNonVolatile | os::uefi::kEfiVariableBootserviceAccess |
                                         os::uefi::kEfiVariableRuntimeAccess));
    const auto got = ql.mem().read(kGetBuf, 5);
    EXPECT_EQ(std::string(got.begin(), got.end()), "Hello");

    // the store rides ql.env verbatim
    EXPECT_EQ(ql.env_mut()["MyVar"], "Hello");
}
