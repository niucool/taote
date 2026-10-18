// Loader_Elf interpreter + vsyscall suite — PORT_PLAN.md §10 Phase 5 (the
// PT_INTERP path: interpreter loading through the rootfs, the AT_BASE auxv
// entry, and the x86-64 vsyscall page).
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
    // wiped once per process; the later calls must not drop the interpreter
    // file the fixture stages
    static bool cleaned = false;
    const auto base = std::filesystem::temp_directory_path() / "ql_elf_interp_rootfs";
    if (!cleaned) {
        std::filesystem::remove_all(base);
        cleaned = true;
    }
    std::filesystem::create_directories(base / "lib");
    return base;
}

// the shared fixture builder (mirrors Loader_Elf_Test's builder, plus the
// interpreter field)
std::vector<std::uint8_t> build_elf64(std::uint16_t e_type, const std::vector<std::uint8_t>& code,
                                      std::uint64_t vaddr, const std::string& interp = {}) {
    constexpr std::size_t EH_SIZE = 64;
    constexpr std::size_t PH_SIZE = 56;
    const std::size_t phnum = interp.empty() ? 1 : 2;
    const std::size_t code_off = EH_SIZE + phnum * PH_SIZE;
    const std::size_t interp_off = code_off + code.size();
    const std::size_t total = interp_off + interp.size() + (interp.empty() ? 0 : 1);

    std::vector<std::uint8_t> elf(total, 0);

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

    put16(16, e_type);
    put16(18, 62);             // EM_X86_64
    put32(20, 1);
    put64(24, vaddr);          // e_entry
    put64(32, EH_SIZE);        // e_phoff
    put32(48, 0);
    put16(52, EH_SIZE);
    put16(54, PH_SIZE);

    put16(56, static_cast<std::uint16_t>(phnum));

    std::size_t ph = EH_SIZE;
    put32(ph + 0, 1);                       // PT_LOAD
    put32(ph + 4, 5);                       // R + X
    put64(ph + 8, code_off);
    put64(ph + 16, vaddr);
    put64(ph + 24, vaddr);
    put64(ph + 32, code.size());
    put64(ph + 40, code.size());
    put64(ph + 48, 0x1000);

    if (!interp.empty()) {
        // the second program header slot sits right after the PT_LOAD one
        std::size_t ip = EH_SIZE + PH_SIZE;
        put32(ip + 0, 3);                   // PT_INTERP
        put32(ip + 4, 4);                   // R
        put64(ip + 8, interp_off);
        put64(ip + 16, 0);                  // vaddr (unused for interp)
        put64(ip + 32, interp.size() + 1);  // filesz (with the terminator)
        put64(ip + 40, interp.size() + 1);
        put64(ip + 48, 1);

        std::copy(interp.begin(), interp.end(), elf.begin() + static_cast<std::ptrdiff_t>(interp_off));
        elf[interp_off + interp.size()] = 0;  // the PT_INTERP NUL terminator
    }

    std::copy(code.begin(), code.end(), elf.begin() + static_cast<std::ptrdiff_t>(code_off));

    return elf;
}

void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

// ---- the interpreter loading (elf.py load_with_ld's PT_INTERP branch) ----

TEST(LoaderElfInterp, InterpreterLoadsAndReceivesEntry) {
    // the main image maps at its ET_EXEC base; the "interpreter" (a stub
    // ld.so) maps at the profile's interp_address and its entry takes over
    ensure_rootfs();

    // the interpreter code: mov rax, 231 (exit_group); mov rdi, 42; syscall
    const std::vector<std::uint8_t> interp_code = {
        0x48, 0xC7, 0xC0, 0xE7, 0x00, 0x00, 0x00,  // mov rax, 231 (exit_group)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,  // mov rdi, 42
        0x0F, 0x05,                                 // syscall
        0x90, 0x90,
    };
    // a relocatable interpreter (min_vaddr == 0) maps at the profile's
    // interp_address slot (linux.ql OS64: 0x7ffff7dd5000)
    const auto interp_blob = build_elf64(3 /* ET_DYN */, interp_code, 0);
    write_file(ensure_rootfs() / "lib" / "ld.so", interp_blob);

    // the main image: a nop sled whose entry hands off to the interpreter
    const std::vector<std::uint8_t> main_code = {0x90, 0x90, 0x90, 0x90};
    const auto main_blob = build_elf64(2 /* ET_EXEC */, main_code, 0x400000, "/lib/ld.so");
    const auto exe_path = ensure_rootfs() / "app.elf";
    write_file(exe_path, main_blob);

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;

    Qiling ql{options};
    ql.run();

    // the interpreter's exit_group(42) surfaced (the interpreter's entry
    // took over from the main image's)
    EXPECT_EQ(ql.os().exit_code(), 42);

    const auto* loader = static_cast<const loader::QlLoaderELF*>(&ql.loader());
    // the profile interp_address slot is the interpreter base (elf.py:
    // interp_address = profile slot iff min_vaddr == 0)
    EXPECT_EQ(loader->interp_address(), 0x7ffff7dd5000);
    // the entry hands off to the interpreter's code (interp_address + e_entry)
    EXPECT_EQ(ql.os().entry_point(), 0x7ffff7dd5000);
    // the interpreter registers as a loaded image
    bool interp_imaged = false;
    for (const auto& image : loader->images) {
        if (image.path.find("ld.so") != std::string::npos) {
            interp_imaged = true;
            EXPECT_EQ(image.base, 0x7ffff7dd5000);
        }
    }
    EXPECT_TRUE(interp_imaged);
}
