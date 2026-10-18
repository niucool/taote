// MacosOs suite — the dialect skeleton: the QlOsMacos ctor (the macosx64
// fcall), the GDT/segment load() shape, and the MACOS x8664 syscall table
// with the LIBSYSTEM 0x2000000 fixup. The fixtures ride the shellcode path
// through the syscall table (exit via the plain 1 and via the fixup'd
// 0x2000000+1) — the handler surface rides its own slices.
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/macos/macos.hpp"

using namespace qiling;

namespace {

constexpr std::uint64_t kScratch = 0x2100;

Qiling make_macos_qiling(const std::vector<std::uint8_t>& code) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = code;
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    return Qiling{options};
}

//   mov edi, 42 ; mov eax, 1 (exit) ; syscall
const std::vector<std::uint8_t>& exit_body() {
    static const std::vector<std::uint8_t> code = {
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0x05,                    // syscall
    };
    return code;
}

// the LIBSYSTEM range: the same exit but with the number riding the
// 0x2000000 fixup (0x2000000+1 = exit)
const std::vector<std::uint8_t>& exit_libsystem_body() {
    static const std::vector<std::uint8_t> code = {
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x02,  // mov eax, 0x2000001
        0x0F, 0x05,                    // syscall
    };
    return code;
}

// ---- the self-trap family + the simple stubs ----

//   mov ebx, 0x2100 ; the four traps (rax = 0x100001a..d) each followed by a
//   store into the scratch cells; exit(42)
const std::vector<std::uint8_t>& self_trap_body() {
    static const std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,  // mov ebx, 0x2100
        0xB8, 0x1A, 0x00, 0x00, 0x01,  // mov eax, 0x100001a (mach_reply_port)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xB8, 0x1B, 0x00, 0x00, 0x01,  // mov eax, 0x100001b (thread_self_trap)
        0x0F, 0x05,
        0x48, 0x89, 0x43, 0x08,        // mov [rbx+8], rax
        0xB8, 0x1C, 0x00, 0x00, 0x01,  // mov eax, 0x100001c (task_self_trap)
        0x0F, 0x05,
        0x48, 0x89, 0x43, 0x10,        // mov [rbx+0x10], rax
        0xB8, 0x1D, 0x00, 0x00, 0x01,  // mov eax, 0x100001d (host_self_trap)
        0x0F, 0x05,
        0x48, 0x89, 0x43, 0x18,        // mov [rbx+0x18], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
        0x0F, 0x05,
    };
    return code;
}

//   mov ebx, 0x2140 (the ret cell); mov edi, 0x2100 (the buf); xor esi/edx;
//   mov eax, 169 (csops); syscall; store; exit(42)
const std::vector<std::uint8_t>& csops_body() {
    static const std::vector<std::uint8_t> code = {
        0xBB, 0x40, 0x21, 0x00, 0x00,  // mov ebx, 0x2140
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100 (pid)
        0x31, 0xF6,                    // xor esi, esi (ops)
        0xBA, 0x00, 0x21, 0x00, 0x00,  // mov edx, 0x2100 (useraddr — the 3rd arg)
        0xB8, 0xA9, 0x00, 0x00, 0x00,  // mov eax, 169 (csops)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
        0x0F, 0x05,
    };
    return code;
}

//   the same shape with eax = 500 (getentropy) and esi = 32
const std::vector<std::uint8_t>& getentropy_body() {
    static const std::vector<std::uint8_t> code = {
        0xBB, 0x40, 0x21, 0x00, 0x00,  // mov ebx, 0x2140
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100
        0xBE, 0x20, 0x00, 0x00, 0x00,  // mov esi, 32
        0xB8, 0xF4, 0x01, 0x00, 0x00,  // mov eax, 500 (getentropy)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
        0x0F, 0x05,
    };
    return code;
}

TEST(MacosOs, SelfTrapFamilyReturnsPortNames) {
    auto ql = make_macos_qiling(self_trap_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the seeded surfaces (the loader/macho.py values): MachPort(2187), the
    // thread's port 0x307, the task id 9876, the host port 0x303
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 2187u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 8, 4), 0x307u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x10, 4), 9876u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x18, 4), 0x303u);
}

TEST(MacosOs, CsopsWritesFlagAndReturnsSuccess) {
    auto ql = make_macos_qiling(csops_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the (CS_ENFORCEMENT | CS_GET_TASK_ALLOW) flag = 0x00001004, LE
    const auto buf = ql.mem().read(kScratch, 4);
    EXPECT_EQ(buf[0], 0x04);
    EXPECT_EQ(buf[1], 0x10);
    EXPECT_EQ(buf[2], 0x00);
    EXPECT_EQ(buf[3], 0x00);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x40, 4), 0u);  // KERN_SUCCESS
}

TEST(MacosOs, GetentropyReturnsSuccess) {
    auto ql = make_macos_qiling(getentropy_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x40, 4), 0u);  // KERN_SUCCESS
}

}  // namespace

TEST(MacosOs, SyscallExitTerminatesWithCode) {
    auto ql = make_macos_qiling(exit_body());
    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 42);
}

TEST(MacosOs, LibsystemFixupResolvesExit) {
    auto ql = make_macos_qiling(exit_libsystem_body());
    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 42);
}
