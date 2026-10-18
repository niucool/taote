// tests/Uefi_Test.cpp — the uefi loader slice fixtures (the module boot ride)

#include <cstdint>
#include <optional>
#include <cstdio>
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
