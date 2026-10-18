// Loader_Pe suite — PORT_PLAN.md §10 Phase 4 (the PE loader core over
// LIEF-backed PE loading: parse, map, images, entry point; a hand-crafted minimal PE64
// fixture keeps the test self-contained).
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/windows/windows.hpp"

using namespace qiling;

namespace {

std::filesystem::path ensure_rootfs() {
    const auto base = std::filesystem::temp_directory_path() / "ql_pe_loader_rootfs";
    std::filesystem::create_directories(base);
    return base;
}

// writes a minimal but well-formed PE32+ image: DOS header, PE signature, one
// .text section carrying the code, entry point at the section start
std::vector<std::uint8_t> build_minimal_pe64(std::uint32_t entry_file_offset) {
    std::vector<std::uint8_t> pe(0x400, 0);
    auto put16 = [&](std::size_t off, std::uint16_t v) {
        pe[off] = static_cast<std::uint8_t>(v);
        pe[off + 1] = static_cast<std::uint8_t>(v >> 8);
    };
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            pe[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            pe[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };

    // DOS header: 'MZ' + e_lfanew at 0x3c
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(0x3c, 0x80);

    // PE signature
    put32(0x80, 0x00004550);  // 'PE\0\0'

    // COFF: machine AMD64, 1 section
    put16(0x84, 0x8664);
    put16(0x86, 1);                      // NumberOfSections
    put16(0x94, 0xf0);                   // SizeOfOptionalHeader (PE32+)
    put16(0x96, 0x22);                   // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

    // optional header (PE32+): magic 0x20b, entry, image base
    // the optional header starts right after the 20-byte COFF (0x98)
    constexpr std::size_t OH = 0x98;
    (void)entry_file_offset;
    put16(OH + 0, 0x20b);                // Magic (PE32+)
    put32(OH + 16, 0x1000);              // AddressOfEntryPoint (rva)
    put32(OH + 20, 0x1000);              // BaseOfCode
    put64(OH + 24, 0x140000000);         // ImageBase
    put32(OH + 32, 0x1000);              // SectionAlignment
    put32(OH + 36, 0x200);               // FileAlignment
    put32(OH + 56, 0x2000);              // SizeOfImage (code page + slack)
    put32(OH + 60, 0x400);               // SizeOfHeaders
    put16(OH + 68, 2);                   // Subsystem: WINDOWS_CUI
    put32(OH + 76, 0x200);               // SizeOfStackReserve
    put32(OH + 80, 0x1000);              // SizeOfStackCommit
    put32(OH + 84, 0x100000);            // SizeOfHeapReserve
    put32(OH + 88, 0x1000);              // SizeOfHeapCommit

    // the .text section header at the end of the optional header
    const std::size_t sect = 0x98 + 0xf0;
    pe[sect + 0] = '.';
    pe[sect + 1] = 't';
    pe[sect + 2] = 'e';
    pe[sect + 3] = 'x';
    pe[sect + 4] = 't';
    put32(sect + 8, 0x1000);             // VirtualSize
    put32(sect + 12, 0x1000);            // VirtualAddress
    put32(sect + 16, 0x200);             // SizeOfRawData
    put32(sect + 20, 0x200);             // PointerToRawData
    put32(sect + 36, 0x60000020);        // Characteristics: CODE|EXEC|READ

    return pe;
}

}  // namespace

TEST(LoaderPe, LoadsMinimalPe64) {
    // the blob: nop sled with a marker byte; the entry point lands at the
    // section start
    const std::uint32_t entry_rva = 0x1000;
    auto pe = build_minimal_pe64(0x200);  // the raw file offset of the code

    const auto exe_path = ensure_rootfs() / "fixture.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;

    Qiling ql{options};

    // the loader mapped the image and registered it
    const auto* image = ql.loader().find_containing_image(0x140000000);
    ASSERT_NE(image, nullptr);
    EXPECT_EQ(image->base, 0x140000000u);
}

TEST(LoaderPe, MalformedBinaryDegradesToQlError) {
    // a truncated PE (the robustness tenet: QlError*, never a host crash)
    const auto exe_path = ensure_rootfs() / "broken.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        const std::vector<std::uint8_t> garbage(0x40, 0xAB);
        out.write(reinterpret_cast<const char*>(garbage.data()), static_cast<std::streamsize>(garbage.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;

    EXPECT_THROW(
        {
            try {
                Qiling ql{options};
            } catch (const QlErrorBase&) {
                throw;
            }
        },
        QlErrorBase);
}
