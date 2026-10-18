// Loader_Elf suite — PORT_PLAN.md §10 Phase 5 (the ELF loader core over
// hand-parsed headers: parse, PT_LOAD region mapping, the auxv stack, and a
// full write/exit shellcode run through a self-contained ET_EXEC fixture).
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/loader/elf.hpp"
#include "qiling/os/os.hpp"

using namespace qiling;

namespace {

std::filesystem::path ensure_rootfs() {
    const auto base = std::filesystem::temp_directory_path() / "ql_elf_loader_rootfs";
    std::filesystem::create_directories(base);
    return base;
}

// builds a minimal ET_EXEC ELF64 carrying `code` in a single R+X PT_LOAD
std::vector<std::uint8_t> build_minimal_elf64(const std::vector<std::uint8_t>& code, std::uint64_t vaddr) {
    constexpr std::size_t EH_SIZE = 64;
    constexpr std::size_t PH_SIZE = 56;
    const std::size_t code_off = EH_SIZE + PH_SIZE;  // the code right after the headers

    std::vector<std::uint8_t> elf(code_off + code.size(), 0);

    // e_ident
    elf[0] = 0x7f;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 2;   // ELFCLASS64
    elf[5] = 1;   // ELFDATA2LSB
    elf[6] = 1;   // EV_CURRENT

    auto put16 = [&](std::size_t off, std::uint16_t v) {
        elf[off] = static_cast<std::uint8_t>(v);
        elf[off + 1] = static_cast<std::uint8_t>(v >> 8);
    };
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            elf[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            elf[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };

    put16(16, 2);              // e_type = ET_EXEC
    put16(18, 62);             // e_machine = EM_X86_64
    put32(20, 1);              // e_version
    put64(24, vaddr);          // e_entry (the code starts at the segment base)
    put64(32, EH_SIZE);        // e_phoff
    put64(40, 0);              // e_shoff
    put32(48, 0);              // e_flags
    put16(52, EH_SIZE);        // e_ehsize
    put16(54, PH_SIZE);        // e_phentsize
    put16(56, 1);              // e_phnum

    // the program header at EH_SIZE
    const std::size_t ph = EH_SIZE;
    put32(ph + 0, 1);                      // p_type = PT_LOAD
    put32(ph + 4, 5);                      // p_flags = R + X
    put64(ph + 8, code_off);               // p_offset
    put64(ph + 16, vaddr);                 // p_vaddr
    put64(ph + 24, vaddr);                 // p_paddr
    put64(ph + 32, code.size());           // p_filesz
    put64(ph + 40, code.size());           // p_memsz
    put64(ph + 48, 0x1000);                // p_align

    // the segment content
    std::copy(code.begin(), code.end(), elf.begin() + static_cast<std::ptrdiff_t>(code_off));

    return elf;
}

}  // namespace

// ---- the container parse (the header-level surface) ----

TEST(LoaderElf, ParsesMinimalExec) {
    // a mov eax/rax blob; the parse only needs the container to be valid
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00,  // mov rax, 42
        0x90,
    };
    const auto blob = build_minimal_elf64(code, 0x400000);

    const auto exe_path = ensure_rootfs() / "fixture.elf";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;

    Qiling ql{options};

    // the image is registered with the mapped extent
    const auto* image = ql.loader().find_containing_image(0x400000);
    ASSERT_NE(image, nullptr);
}

// ---- the end-to-end run: write(1, msg) + exit through the loaded ELF ----

TEST(LoaderElf, ExecRunsToCompletion) {
    // mov rax, 1 (write) ; mov rdi, 1 ; mov rsi, <msg> ; mov rdx, 13 ; syscall ;
    // mov rax, 60 ; mov rdi, 42 ; syscall
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1
        0x48, 0x8D, 0x35, 0x1D, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x1d] -> the msg
        0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00,  // mov rdx, 13
        0x0F, 0x05,                                 // syscall
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,  // mov rdi, 42
        0x0F, 0x05,                                 // syscall
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'Q', 'i', 'l', 'i', 'n', 'g', 0x00,
    };
    const auto blob = build_minimal_elf64(code, 0x400000);

    const auto exe_path = ensure_rootfs() / "hello.elf";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;

    Qiling ql{options};
    ql.run();

    // exit_group(42) surfaced through the os layer
    EXPECT_EQ(ql.os().exit_code(), 42);
}

// ---- the malformed-container robustness tenet ----

TEST(LoaderElf, MalformedBinaryDegradesToQlError) {
    const auto exe_path = ensure_rootfs() / "broken.elf";
    {
        std::ofstream out(exe_path, std::ios::binary);
        const std::vector<std::uint8_t> garbage(0x20, 0xAB);
        out.write(reinterpret_cast<const char*>(garbage.data()), static_cast<std::streamsize>(garbage.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::LINUX;
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
