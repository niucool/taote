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
#include "qiling/os/linux/linux.hpp"

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

// the stat.py __do_fstat flow: open /tmpfile, fstat(fd, buf) — the syscall 5
// — the packing rides the posix stat family (the x86-64 144-byte image); the
// size/mode cells carry the file, the ns/unused cells stay zero
//   mov rax,2 (open) / mov rdi,the path / mov rsi,0x42 / mov rdx,0644 / syscall
//   mov [0x1002200], rax
//   mov rdi,[0x1002200] / mov rax,5 (fstat) / mov rsi,0x1002400 / syscall
//   mov rax,60 / mov rdi,0 / syscall
TEST(PosixFileDes, FstatPacksTheX8664Image) {
    const std::string payload = "hello fd";
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x42, 0x00, 0x00, 0x00,  // mov rsi, 0x42
        0x48, 0xC7, 0xC2, 0xA4, 0x01, 0x00, 0x00,  // mov rdx, 0o644
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00,  // mov rax, 5 (fstat)
        0x48, 0xC7, 0xC6, 0x00, 0x24, 0x00, 0x01,  // mov rsi, 0x1002400
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});
    {
        std::ofstream f(ensure_rootfs() / "tmpfile", std::ios::binary);
        f << payload;
    }

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0u);  // the fstat returned 0

    // the LinuxX8664Stat image at 0x1002400: the size cell at +48, the mode
    // at +24 with the regular-file bits, the ns/unused cells zero
    EXPECT_EQ(ql.mem().read_ptr(0x1002400 + 48, 8), payload.size());
    EXPECT_EQ(ql.mem().read_ptr(0x1002400 + 24, 4) & 0xF000u, 0x8000u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002400 + 80, 8), 0u);   // st_atime_ns
    EXPECT_EQ(ql.mem().read_ptr(0x1002400 + 120, 8), 0u);  // __unused tail
}

// the procfs slice (os/linux/procfs.py): the /proc/self pseudo files resolve
// through the fd flow — open("/proc/self/cmdline") reads the argv bytes; the
// shellcode run carries the empty placeholder argv, so the read yields the
// single NUL terminator
TEST(PosixProcfs, CmdlineReadsThroughFdFlow) {
    const std::vector<std::uint8_t> code = {
        // open("/proc/self/cmdline", O_RDONLY)
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000 (the path)
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0 (O_RDONLY)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        // read(fd, 0x1002300, 64)
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0 (read)
        0x48, 0xC7, 0xC6, 0x00, 0x23, 0x00, 0x01,  // mov rsi, 0x1002300
        0x48, 0xC7, 0xC2, 0x40, 0x00, 0x00, 0x00,  // mov rdx, 64
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    // upstream runs the procfs setup only for the image loads (linux.py run:
    // the shellcode skips it); the fixture drives setup_procfs directly to
    // keep the shellcode harness while exercising the same fd flow
    ql.os<os::linux::QlOsLinux>().setup_procfs();

    const std::string path_str = "/proc/self/cmdline";
    std::vector<std::uint8_t> path_bytes(path_str.begin(), path_str.end());
    path_bytes.push_back(0);
    ql.mem().write(0x1002000, path_bytes);
    ql.mem().write(0x1002300, std::vector<std::uint8_t>(64, 0xAA));

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);

    // the open returned a real fd (>= 3)
    const auto fd = static_cast<int>(ql.mem().read_ptr(0x1002200, 8));
    EXPECT_GE(fd, 3);

    // the cmdline content: the placeholder argv ("") joined with NULs + the
    // trailing NUL — a single byte, read through the FsMappedStream
    const auto nread = static_cast<int>(ql.mem().read_ptr(0x1002208, 8));
    ASSERT_EQ(nread, 1);
    EXPECT_EQ(ql.mem().read(0x1002300, 1)[0], 0);
}

// ---- the pipe + fcntl slice (unistd.py pipe / fcntl.py) ----

// pipe(buf) -> write(fd_w) -> close(fd_w) -> read(fd_r): the host-pipe
// QlPipe pair rides the fd table
TEST(PosixPipe, PipeRoundTripsThroughFdTable) {
    const std::string payload = "ping";
    const std::vector<std::uint8_t> code = {
        // pipe(0x1002000)
        0x48, 0xC7, 0xC0, 0x16, 0x00, 0x00, 0x00,  // mov rax, 22 (pipe)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x0F, 0x05,                                 // syscall
        // write(mem[pipefd+4], 0x1002100, 4) — the 32-bit fd load (the pipe
        // writes 4-byte slots)
        0x8B, 0x3C, 0x25, 0x04, 0x20, 0x00, 0x01,  // mov edi, [0x1002004]
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (write)
        0x48, 0xC7, 0xC6, 0x00, 0x21, 0x00, 0x01,  // mov rsi, 0x1002100
        0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00,  // mov rdx, 4
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x20, 0x00, 0x01,  // mov [0x1002010], rax
        // close(mem[pipefd+4])
        0x8B, 0x3C, 0x25, 0x04, 0x20, 0x00, 0x01,  // mov edi, [0x1002004]
        0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00,  // mov rax, 3 (close)
        0x0F, 0x05,                                 // syscall
        // read(mem[pipefd], 0x1002200, 8)
        0x8B, 0x3C, 0x25, 0x00, 0x20, 0x00, 0x01,  // mov edi, [0x1002000]
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0 (read)
        0x48, 0xC7, 0xC6, 0x00, 0x22, 0x00, 0x01,  // mov rsi, 0x1002200
        0x48, 0xC7, 0xC2, 0x08, 0x00, 0x00, 0x00,  // mov rdx, 8
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x18, 0x20, 0x00, 0x01,  // mov [0x1002018], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>(16, 0));
    ql.mem().write(0x1002100, std::vector<std::uint8_t>{payload.begin(), payload.end()});
    ql.mem().write(0x1002200, std::vector<std::uint8_t>(8, 0));

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);

    // the pipe fd pair occupies two real slots (>= 3, the reader first)
    const auto fd_r = static_cast<int>(ql.mem().read_ptr(0x1002000, 4));
    const auto fd_w = static_cast<int>(ql.mem().read_ptr(0x1002004, 4));
    EXPECT_GE(fd_r, 3);
    EXPECT_GE(fd_w, 3);
    EXPECT_NE(fd_r, fd_w);

    // the write wrote all 4 bytes and the read picked them up
    const auto nwrite = static_cast<int>(ql.mem().read_ptr(0x1002010, 8));
    EXPECT_EQ(nwrite, 4);
    const auto nread = static_cast<int>(ql.mem().read_ptr(0x1002018, 8));
    ASSERT_EQ(nread, 4);
    const auto got = ql.mem().read(0x1002200, 4);
    const std::string got_str{got.begin(), got.end()};
    EXPECT_EQ(got_str, payload);
}

// fcntl F_SETFD/F_GETFD round-trip + dup3's O_CLOEXEC propagation
TEST(PosixFcntl, SetFdGetFdAndCloexecPropagation) {
    const std::vector<std::uint8_t> code = {
        // open("/tmpfile", O_RDWR|O_CREAT, 0o644)
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000 (the path)
        0x48, 0xC7, 0xC6, 0x42, 0x00, 0x00, 0x00,  // mov rsi, 0x42
        0x48, 0xC7, 0xC2, 0xA4, 0x01, 0x00, 0x00,  // mov rdx, 0o644
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        // fcntl(fd, F_SETFD=2, FD_CLOEXEC=1)
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x48, 0x00, 0x00, 0x00,  // mov rax, 72 (fcntl)
        0x48, 0xC7, 0xC6, 0x02, 0x00, 0x00, 0x00,  // mov rsi, 2 (F_SETFD)
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,  // mov rdx, 1 (FD_CLOEXEC)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // fcntl(fd, F_GETFD=1, 0)
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x48, 0x00, 0x00, 0x00,  // mov rax, 72
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1 (F_GETFD)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // dup3(fd, 7, O_CLOEXEC) — the target slot 7
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC0, 0x24, 0x01, 0x00, 0x00,  // mov rax, 292 (dup3)
        0x48, 0xC7, 0xC6, 0x07, 0x00, 0x00, 0x00,  // mov rsi, 7
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x08, 0x00,  // mov rdx, 0o2000000 (O_CLOEXEC)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        // fcntl(7, F_GETFD=1, 0)
        0x48, 0xC7, 0xC0, 0x48, 0x00, 0x00, 0x00,  // mov rax, 72
        0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00,  // mov rdi, 7
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x20, 0x22, 0x00, 0x01,  // mov [0x1002220], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);

    // F_SETFD returned 0 and F_GETFD reflects FD_CLOEXEC
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 1);

    // the dup3 target slot got the duplicated fd and inherited the flag
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 7);
    EXPECT_EQ(ql.mem().read_ptr(0x1002220, 8), 1);
}

// the typed open-error translations (fcntl.py __do_open): the missing file
// collapses to -ENOENT and the O_EXCL collision to -EEXIST
TEST(PosixFcntl, TypedOpenErrors) {
    const std::vector<std::uint8_t> code = {
        // open("/no_such_file", O_RDONLY)
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000 (the path)
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        // creat("/tmpfile", 0o644) — populates the file for the next open
        0x48, 0xC7, 0xC0, 0x55, 0x00, 0x00, 0x00,  // mov rax, 85 (creat)
        0x48, 0xC7, 0xC7, 0x08, 0x20, 0x00, 0x01,  // mov rdi, 0x1002008
        0x48, 0xC7, 0xC6, 0xA4, 0x01, 0x00, 0x00,  // mov rsi, 0o644
        0x0F, 0x05,                                 // syscall
        // open("/tmpfile", O_RDWR|O_CREAT|O_EXCL) -> -EEXIST
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2
        0x48, 0xC7, 0xC7, 0x08, 0x20, 0x00, 0x01,  // mov rdi, 0x1002008
        0x48, 0xC7, 0xC6, 0xC2, 0x00, 0x00, 0x00,  // mov rsi, 0xC2 (O_RDWR|O_CREAT|O_EXCL)
        0x48, 0xC7, 0xC2, 0xA4, 0x01, 0x00, 0x00,  // mov rdx, 0o644
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    const std::string missing = "/no_such_file";
    std::vector<std::uint8_t> missing_bytes(missing.begin(), missing.end());
    missing_bytes.push_back(0);
    ql.mem().write(0x1002000, missing_bytes);
    ql.mem().write(0x1002008, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);

    // the missing file -> -ENOENT (-2)
    EXPECT_EQ(static_cast<std::int64_t>(ql.mem().read_ptr(0x1002200, 8, true)), -2);
    // the O_EXCL collision -> -EEXIST (-17)
    EXPECT_EQ(static_cast<std::int64_t>(ql.mem().read_ptr(0x1002208, 8, true)), -17);
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
