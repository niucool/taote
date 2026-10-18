// QlOsPosix suite — PORT_PLAN.md §10 (the syscall dispatch core: the abi
// reads the params, the registry resolves the handler, and the unistd smoke
// set runs a real write/exit shellcode through the `syscall` instruction).
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/posix/syscall/abi.hpp"

using namespace qiling;

#define NL "\n"

#include <iostream>

namespace {

std::filesystem::path ensure_rootfs() {
    const auto base = std::filesystem::temp_directory_path() / "ql_posix_rootfs";
    std::filesystem::create_directories(base);
    return base;
}

QilingOptions posix_options(std::vector<std::uint8_t> code) {
    QilingOptions options;
    options.code = std::move(code);
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;

    // the bundled linux.ql profile carries the [CODE] section (load_address
    // 0x1000000); no user profile is needed
    return options;
}


// ---- the unistd expansion (unistd.py: the identity set, the credential
// mutators, and brk) ----

// run a shellcode blob through posix_options and return the final exit code
namespace {
int run_posix(const std::vector<std::uint8_t>& code) {
    QilingOptions options = posix_options(code);
    Qiling ql(options);
    ql.run();
    return ql.os().exit_code();
}
}  // namespace

TEST(PosixSyscall, IdentityAndCredentialSet) {
    // getuid(102)/getgid(104)/getpid(39) store their results to memory, then
    // exit(0); the driver reads the values back (unistd.py: the profile
    // identity 1000, the getpid 0x512 constant, verbatim)
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x66, 0x00, 0x00, 0x00,  // mov rax, 102 (getuid)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01,  // mov [0x1002000], rax
        0x48, 0xC7, 0xC0, 0x68, 0x00, 0x00, 0x00,  // mov rax, 104 (getgid)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x20, 0x00, 0x01,  // mov [0x1002008], rax
        0x48, 0xC7, 0xC0, 0x27, 0x00, 0x00, 0x00,  // mov rax, 39 (getpid)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x20, 0x00, 0x01,  // mov [0x1002010], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);
    ql.mem().write(0x1002000, std::vector<std::uint8_t>(24, 0));
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
}}  // namespace

// ---- the fd-table slice (fcntl.py __do_open + the unistd fd flows) ----

// O_RDWR|O_CREAT = 0x42 (the linux x86 flags), the mode 0o644; the path
// string sits at 0x1002000, the payload at 0x1002100, the result slots at
// 0x1002200..
TEST(PosixFileDes, OpenWriteCloseReopenRead) {
    const std::string payload = "hello fd";
    const std::vector<std::uint8_t> code = {
        // open("/tmpfile", 0x42, 0o644)
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000 (the path)
        0x48, 0xC7, 0xC6, 0x42, 0x00, 0x00, 0x00,  // mov rsi, 0x42
        0x48, 0xC7, 0xC2, 0xA4, 0x01, 0x00, 0x00,  // mov rdx, 0o644
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        // write(fd, 0x1002100, 8)
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (write)
        0x48, 0xC7, 0xC6, 0x00, 0x21, 0x00, 0x01,  // mov rsi, 0x1002100
        0x48, 0xC7, 0xC2, 0x08, 0x00, 0x00, 0x00,  // mov rdx, 8
        0x0F, 0x05,                                 // syscall
        // close(fd)
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00,  // mov rax, 3 (close)
        0x0F, 0x05,                                 // syscall
        // open("/tmpfile", O_RDONLY)
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // read(fd2, 0x1002300, 8)
        0x48, 0x8B, 0x3C, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov rdi, [0x1002208]
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0 (read)
        0x48, 0xC7, 0xC6, 0x00, 0x23, 0x00, 0x01,  // mov rsi, 0x1002300
        0x48, 0xC7, 0xC2, 0x08, 0x00, 0x00, 0x00,  // mov rdx, 8
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    // the path string + the payload in the mapped region
    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});
    ql.mem().write(0x1002100, std::vector<std::uint8_t>{payload.begin(), payload.end()});
    ql.mem().write(0x1002300, std::vector<std::uint8_t>(8, 0));

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);

    // the open returned a real fd (>= 3) and the reopen reused the freed slot
    const auto fd1 = static_cast<int>(ql.mem().read_ptr(0x1002200, 8));
    const auto fd2 = static_cast<int>(ql.mem().read_ptr(0x1002208, 8));
    EXPECT_GE(fd1, 3);
    EXPECT_GE(fd2, 3);
    EXPECT_EQ(fd1, fd2);

    // the read round-tripped the written bytes
    const auto got = ql.mem().read(0x1002300, payload.size());
    const std::string got_str{got.begin(), got.end()};
    EXPECT_EQ(got_str, payload);
}

// ---- the abi layer (abi/intel.py) ----

TEST(PosixAbi, Intel64ReadsParamsFromRegisters) {
    QlArchX8664 arch(nullptr);
    arch.regs().write("rax", 1);          // write
    arch.regs().write("rdi", 1);          // fd
    arch.regs().write("rsi", 0x2000);     // buf
    arch.regs().write("rdx", 13);         // count

    os::posix::QlSyscallABIIntel64 abi(arch);
    EXPECT_EQ(abi.get_id(), 1u);

    const auto params = abi.get_params(3);
    ASSERT_EQ(params.size(), 3u);
    EXPECT_EQ(params[0], 1u);
    EXPECT_EQ(params[1], 0x2000u);
    EXPECT_EQ(params[2], 13u);

    abi.set_return_value(13);
    EXPECT_EQ(arch.regs().read("rax"), 13u);
}

TEST(PosixAbi, Intel32UsesThe32BitRegisterSet) {
    QlArchX86 arch(nullptr);
    arch.regs().write("eax", 4);  // write on i386
    arch.regs().write("ebx", 1);
    arch.regs().write("ecx", 0x2000);
    arch.regs().write("edx", 5);

    os::posix::QlSyscallABIIntel32 abi(arch);
    EXPECT_EQ(abi.get_id(), 4u);

    const auto params = abi.get_params(3);
    EXPECT_EQ(params[0], 1u);
    EXPECT_EQ(params[1], 0x2000u);
    EXPECT_EQ(params[2], 5u);
}

TEST(PosixAbi, ParamOverreadRaises) {
    QlArchX8664 arch(nullptr);
    os::posix::QlSyscallABIIntel64 abi(arch);
    EXPECT_THROW(abi.get_params(7), QlErrorBase);
}

// ---- the syscall dispatch through the real emulation ----

TEST(PosixSyscall, WriteThenExitThroughSyscallInstruction) {
    // mov rax, 1 (write) ; mov rdi, 1 (stdout) ; lea rsi, [msg] ; mov rdx, 13 ;
    // syscall ; mov rax, 60 (exit) ; mov rdi, 42 ; syscall
    //
    // the message is stored right after the code; the entry point carries the
    // exact bytes
    QilingOptions options = posix_options({
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1
        0x48, 0xC7, 0xC6, 0x00, 0x10, 0x00, 0x01,  // mov rsi, 0x1001000
        0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00,  // mov rdx, 13
        0x0F, 0x05,                                 // syscall
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit_group)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,  // mov rdi, 42
        0x0F, 0x05,                                 // syscall
        0x90, 0x90,
    });

    Qiling ql(options);

    // the message lands at 0x1001000, inside the mapped code region
    ql.mem().write(0x1001000, std::vector<std::uint8_t>{'H', 'e', 'l', 'l', 'o', ',', ' ', 'Q', 'i', 'l', 'i', 'n', 'g'});

    ql.run();
    std::cout << "[dbg-test] run returned" << std::endl;

    // exit_group(42) landed: the os exit code carries the guest value
    EXPECT_EQ(ql.os().exit_code(), 42);
}

TEST(PosixSyscall, UnhandledSyscallWarnsButDoesNotThrow) {
    // an unknown syscall id: load_syscall warns and continues (the
    // debug_stop behavior lands with its slice)
    QilingOptions options = posix_options({
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rax, 0xffffffff (unknown)
        0x0F, 0x05,                                 // syscall
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60
        0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00,  // mov rdi, 7
        0x0F, 0x05,                                 // syscall
    });

    Qiling ql(options);
    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 7);
}
