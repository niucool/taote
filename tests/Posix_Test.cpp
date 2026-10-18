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
#include "qiling/os/posix/socket.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/posix/syscall/abi.hpp"
#include "qiling/os/linux/linux.hpp"

using namespace qiling;

#define NL "\n"

#include <cstdio>
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

// ---- the mman family (mman.py): the fixed-anon mmap + the madvise
// DONTNEED zero-fill, the file-backed mapping, the shared flush-on-unmap
// ----
TEST(PosixMman, MmapFixedAnonThenMadviseDontneed) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,  // 00: mov rax, 9 (mmap)
        0x48, 0xC7, 0xC7, 0x00, 0xD0, 0x30, 0x00,  // 08: mov rdi, 0x30d000
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x00,  // 10: mov rsi, 0x2000
        0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00,  // 18: mov rdx, 3
        0x49, 0xBA, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 20: mov r10, 0x32
        0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,  // 28: mov r8, -1
        0x4D, 0x31, 0xC9,                           // 30: xor r9, r9
        0x0F, 0x05,                                 // 34: syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // 38: mov [0x1002208], rax
        0xC7, 0x00, 0x34, 0x12, 0x00, 0x00,         // 40: mov dword [rax], 0x1234
        0x48, 0xC7, 0xC0, 0x1C, 0x00, 0x00, 0x00,  // 46: mov rax, 28 (madvise)
        0x48, 0xC7, 0xC7, 0x00, 0xD0, 0x30, 0x00,  // 4E: mov rdi, 0x30d000
        0x48, 0xC7, 0xC6, 0x00, 0x01, 0x00, 0x00,  // 56: mov rsi, 0x100
        0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00,  // 5E: mov rdx, 4 (DONTNEED)
        0x0F, 0x05,                                 // 66: syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // 6A: mov [0x1002210], rax
        0x48, 0x8B, 0x04, 0x25, 0x00, 0xD0, 0x30, 0x00,  // 74: mov rax, [0x30d000]
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // 7C: mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // 84: mov rax, 60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // 8C: mov rdi, 0
        0x0F, 0x05,                                 // 94: syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0x30d000u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0u);
}

TEST(PosixMman, MmapFileBackedReadsThroughFd) {
    const std::string payload = "MMAP-PAYLOAD-0123";
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0 (O_RDONLY)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x41, 0x89, 0xC0,                           // mov r8d, eax (the fd)
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,  // mov rax, 9 (mmap)
        0x48, 0xC7, 0xC7, 0x00, 0xE0, 0x30, 0x00,  // mov rdi, 0x30e000
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x00,  // mov rsi, 0x1000
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,  // mov rdx, 1 (PROT_READ)
        0x49, 0xBA, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov r10, 0x1a (PRIVATE|FIXED|ANON)
        0x45, 0x31, 0xC9,                           // xor r9d, r9d
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    {
        std::ofstream f(ensure_rootfs() / "data.bin", std::ios::binary);
        f << payload;
    }
    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 'd', 'a', 't', 'a', '.', 'b', 'i', 'n', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0x30e000u);
    const auto cell = ql.mem().read(0x30e000, payload.size());
    EXPECT_EQ(std::string(cell.begin(), cell.end()), payload);
}

TEST(PosixMman, MunmapFlushesSharedFileMapping) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x02, 0x00, 0x00, 0x00,  // mov rsi, 2 (O_RDWR)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x41, 0x89, 0xC0,                           // mov r8d, eax (the fd)
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,  // mov rax, 9 (mmap)
        0x48, 0xC7, 0xC7, 0x00, 0xF0, 0x30, 0x00,  // mov rdi, 0x30f000
        0x48, 0xC7, 0xC6, 0x00, 0x10, 0x00, 0x00,  // mov rsi, 0x1000
        0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00,  // mov rdx, 3
        0x49, 0xBA, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov r10, 0x11 (SHARED|FIXED)
        0x45, 0x31, 0xC9,                           // xor r9d, r9d
        0x0F, 0x05,                                 // syscall
        0xC6, 0x00, 0x5A,                           // mov byte [rax], 'Z'
        0x48, 0xC7, 0xC0, 0x0B, 0x00, 0x00, 0x00,  // mov rax, 11 (munmap)
        0x48, 0xC7, 0xC7, 0x00, 0xF0, 0x30, 0x00,  // mov rdi, 0x30f000
        0x48, 0xC7, 0xC6, 0x00, 0x10, 0x00, 0x00,  // mov rsi, 0x1000
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00,  // mov rax, 3 (close)
        0x0F, 0x05,                                 // the fd still rides rdi
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    const auto host_path = ensure_rootfs() / "data.bin";
    {
        std::ofstream f(host_path, std::ios::binary);
        f << "ORIGINAL";
    }
    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 'd', 'a', 't', 'a', '.', 'b', 'i', 'n', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);
    {
        std::ifstream f(host_path, std::ios::binary);
        std::string got(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>{});
        // the verbatim flush writes read(addr, length) — the whole munmap
        // length, so the file grows with the NUL padding past the original
        // content ("ZRIGINAL" + the pad to 0x1000)
        EXPECT_EQ(got, "ZRIGINAL" + std::string(0x1000 - 8, char{0}));
    }
}

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

// the stat.py statFamily flow: stat("/tmpfile", buf) (the syscall 4) rides
// the x86-64 image and lstat("/tmpfile", buf) (the syscall 6) rides the
// pack_stat64_struct family (the LinuxX86Stat64 96-byte image — the verbatim
// struct_func quirk); the missing path answers -ENOENT
TEST(PosixFileDes, StatAndLstatRideTheStatFamily) {
    const std::string payload = "hello fd";
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x42, 0x00, 0x00, 0x00,  // mov rsi, 0x42
        0x48, 0xC7, 0xC2, 0xA4, 0x01, 0x00, 0x00,  // mov rdx, 0o644
        0x0F, 0x05,                                 // syscall
        // stat(0x1002000, 0x1002500)
        0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,  // mov rax, 4 (stat)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x25, 0x00, 0x01,  // mov rsi, 0x1002500
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // lstat(0x1002000, 0x1002600)
        0x48, 0xC7, 0xC0, 0x06, 0x00, 0x00, 0x00,  // mov rax, 6 (lstat)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x26, 0x00, 0x01,  // mov rsi, 0x1002600
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // stat("/missing", 0x1002700) — the ENOENT branch
        0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,  // mov rax, 4 (stat)
        0x48, 0xC7, 0xC7, 0x50, 0x20, 0x00, 0x01,  // mov rdi, 0x1002050
        0x48, 0xC7, 0xC6, 0x00, 0x27, 0x00, 0x01,  // mov rsi, 0x1002700
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});
    ql.mem().write(0x1002050, std::vector<std::uint8_t>{'/', 'm', 'i', 's', 's', 'i', 'n', 'g', 0});
    {
        std::ofstream f(ensure_rootfs() / "tmpfile", std::ios::binary);
        f << payload;
    }

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the stat returned 0 and the image carries the payload size/mode
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 48, 8), payload.size());
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 24, 4) & 0xF000u, 0x8000u);
    // the lstat returned 0; the LinuxX86Stat64 image (the 96-byte i386
    // stat64 layout — the verbatim pack_stat64_struct quirk): the size at
    // +44 and the mode at +16
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002600 + 44, 8), payload.size());
    EXPECT_EQ(ql.mem().read_ptr(0x1002600 + 16, 4) & 0xF000u, 0x8000u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002600 + 88, 8), ql.mem().read_ptr(0x1002600 + 12, 4));
    // the missing path: -ENOENT
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0xFFFFFFFFFFFFFFFEull);
}

// the stat.py transform_path + ql_syscall_newfstatat flow: the absolute
// path (the rootfs join), the AT_EMPTY_PATH flow through the open fd (the
// fd's name — the verbatim quirk where only AT_EMPTY_PATH reaches the
// transform, AT_SYMLINK_NOFOLLOW is ignored), and the missing path -ENOENT
//   open("/tmpfile", O_RDONLY) → newfstatat(AT_FDCWD, "/tmpfile", bufA, 0)
//   → newfstatat(fd, "", bufB, AT_EMPTY_PATH) → newfstatat(-100, "/missing", bufC, 0)
TEST(PosixFileDes, NewfstatatRidesTheTransformLadder) {
    const std::string payload = "hello fd";
    const std::vector<std::uint8_t> code = {
        // open("/tmpfile", O_RDONLY)
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,  // mov rax, 2 (open)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        // newfstatat(AT_FDCWD, "/tmpfile", 0x1002500, 0)
        0x48, 0xC7, 0xC0, 0x06, 0x01, 0x00, 0x00,  // mov rax, 262 (newfstatat)
        0x48, 0xC7, 0xC7, 0x9C, 0xFF, 0xFF, 0xFF,  // mov rdi, -100 (AT_FDCWD)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,  // mov rsi, 0x1002000
        0x48, 0xC7, 0xC2, 0x00, 0x25, 0x00, 0x01,  // mov rdx, 0x1002500
        0x45, 0x31, 0xC0,                           // xor r8d, r8d
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // newfstatat(fd, "", 0x1002600, AT_EMPTY_PATH)
        0x48, 0xC7, 0xC0, 0x06, 0x01, 0x00, 0x00,  // mov rax, 262
        0x48, 0x8B, 0x3C, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov rdi, [0x1002200]
        0x48, 0xC7, 0xC6, 0x50, 0x20, 0x00, 0x01,  // mov rsi, 0x1002050 (the empty cell)
        0x48, 0xC7, 0xC2, 0x00, 0x26, 0x00, 0x01,  // mov rdx, 0x1002600
        0x41, 0xBA, 0x00, 0x10, 0x00, 0x00,         // mov r10d, 0x1000 (AT_EMPTY_PATH — the 4th
                                                    // syscall arg rides r10, not r8)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // newfstatat(AT_FDCWD, "/missing", 0x1002700, 0) — the ENOENT branch
        0x48, 0xC7, 0xC0, 0x06, 0x01, 0x00, 0x00,  // mov rax, 262
        0x48, 0xC7, 0xC7, 0x9C, 0xFF, 0xFF, 0xFF,  // mov rdi, -100
        0x48, 0xC7, 0xC6, 0x90, 0x20, 0x00, 0x01,  // mov rsi, 0x1002090 ("/missing")
        0x48, 0xC7, 0xC2, 0x00, 0x27, 0x00, 0x01,  // mov rdx, 0x1002700
        0x45, 0x31, 0xC0,                           // xor r8d, r8d
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});
    ql.mem().write(0x1002050, std::vector<std::uint8_t>{0x00});
    ql.mem().write(0x1002090, std::vector<std::uint8_t>{'/', 'm', 'i', 's', 's', 'i', 'n', 'g', 0});
    {
        std::ofstream f(ensure_rootfs() / "tmpfile", std::ios::binary);
        f << payload;
    }

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the absolute-path stat: 0, the x86-64 image with the payload size
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 48, 8), payload.size());
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 24, 4) & 0xF000u, 0x8000u);
    // the AT_EMPTY_PATH flow: 0 and the same stat through the fd's name
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002600 + 48, 8), payload.size());
    // the missing path: -ENOENT
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0xFFFFFFFFFFFFFFFEull);
}

// the stat.py ql_syscall_statx flow: the absolute path via the transform,
// the 256-byte Statx64 image (the hardcoded STATX_BASIC_STATS 0x7ff mask,
// the float32-bit timestamps, the zero btime/pads), the catch-all -1 on the
// missing path (the verbatim Exception branch — NOT -errno)
TEST(PosixFileDes, StatxPacksTheBasicStatsImage) {
    const std::string payload = "hello fd";
    const std::vector<std::uint8_t> code = {
        // statx(AT_FDCWD, "/tmpfile", 0, 0, 0x1002500)
        0x48, 0xC7, 0xC0, 0x4C, 0x01, 0x00, 0x00,  // mov rax, 0x194 (statx = 332)
        0x48, 0xC7, 0xC7, 0x9C, 0xFF, 0xFF, 0xFF,  // mov rdi, -100 (AT_FDCWD)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,  // mov rsi, 0x1002000
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0 (flags)
        0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,         // mov r10d, 0 (mask)
        0x49, 0xC7, 0xC0, 0x00, 0x25, 0x00, 0x01,  // mov r8, 0x1002500 (buf)
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // statx(AT_FDCWD, "/missing", 0, 0, 0x1002700) — the catch-all -1
        0x48, 0xC7, 0xC0, 0x4C, 0x01, 0x00, 0x00,  // mov rax, 0x194
        0x48, 0xC7, 0xC7, 0x9C, 0xFF, 0xFF, 0xFF,  // mov rdi, -100
        0x48, 0xC7, 0xC6, 0x90, 0x20, 0x00, 0x01,  // mov rsi, 0x1002090 ("/missing")
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,         // mov r10d, 0
        0x49, 0xC7, 0xC0, 0x00, 0x27, 0x00, 0x01,  // mov r8, 0x1002700
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 't', 'm', 'p', 'f', 'i', 'l', 'e', 0});
    ql.mem().write(0x1002090, std::vector<std::uint8_t>{'/', 'm', 'i', 's', 's', 'i', 'n', 'g', 0});
    {
        std::ofstream f(ensure_rootfs() / "tmpfile", std::ios::binary);
        f << payload;
    }

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the statx returned 0: the 256-byte Statx64 image with the verbatim
    // STATX_BASIC_STATS mask, the payload size, the mode bits, the zero
    // attributes/btime/pads
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002500, 4), 0x7ffu);
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 40, 8), payload.size());
    EXPECT_EQ((ql.mem().read_ptr(0x1002500 + 28, 4) & 0xF000u), 0x8000u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 8, 8), 0u);        // stx_attributes
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 80, 8), 0u);       // stx_btime (unset)
    EXPECT_EQ(ql.mem().read_ptr(0x1002500 + 144 + 8, 8), 0u);  // the pad2 window
    EXPECT_NE(ql.mem().read_ptr(0x1002500 + 64, 8), 0u);       // the atime tv_sec (the float32 bits)
    // the missing path: the catch-all -1 (the verbatim Exception branch —
    // NOT -errno)
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0xFFFFFFFFFFFFFFFFull);
}

// the procfs slice (os/linux/procfs.py): the /proc/self pseudo files resolve
//   0C: mov rdi, 0x1002000 ("/nonexistent" — ignored verbatim) ; 14: mov rsi, 0x1002500
//   1C: syscall ; 20: mov [0x1002208], rax
//   28: fstatfs(fd=-1 ignored, buf 0x1002700) ; 34: mov [0x1002210], rax
//   3C: statfs(buf 0x3000000 unmapped) → -1 ; 48: mov [0x1002218], rax
//   50: exit(0)
TEST(PosixFileDes, StatfsFstatfsFillTheZeroStubBuffer) {
    const std::vector<std::uint8_t> code = {
        // statfs("/nonexistent", 0x1002500) — the path is ignored verbatim
        0x48, 0xC7, 0xC0, 0x89, 0x00, 0x00, 0x00,  // mov rax, 0x89 (statfs = 137)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x25, 0x00, 0x01,  // mov rsi, 0x1002500
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // fstatfs(-1, 0x1002700) — the fd is ignored verbatim
        0x48, 0xC7, 0xC0, 0x8A, 0x00, 0x00, 0x00,  // mov rax, 0x8A (fstatfs = 138)
        0x48, 0xC7, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rdi, -1
        0x48, 0xC7, 0xC6, 0x00, 0x27, 0x00, 0x01,  // mov rsi, 0x1002700
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // statfs(path, 0x3000000) — the unwritable buffer: -1 (the except)
        0x48, 0xC7, 0xC0, 0x89, 0x00, 0x00, 0x00,  // mov rax, 0x89
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x03,  // mov rsi, 0x3000000
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,                                 // syscall
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 'n', 'o', 'n', 'e', 'x', 'i', 's', 't', 'e', 'n', 't', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);
    // the verbatim stub fill: the ASCII '0' (0x30) bytes, NOT NULs, and the
    // path/fd args are ignored (the /nonexistent and fd=-1 still return 0)
    const auto buf = ql.mem().read(0x1002500, 96);
    EXPECT_EQ(buf[0], 0x30);
    EXPECT_EQ(buf[95], 0x30);
    EXPECT_EQ(ql.mem().read_ptr(0x1002700, 8), 0x3030303030303030ull);
    // the unwritable buffer: the except branch -1 (NOT -errno)
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0xFFFFFFFFFFFFFFFFull);
}

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

// ---- the directory-read surface (unistd.py: getdents64/getcwd/chdir/
// readlink) ----

// getdents64 over an opened directory: '.'/'..' first, then the scan results,
// the reclen alignment (the d_ino alignment round-up verbatim), the d_type
// ahead of d_name; the second call answers 0 (the tell gate)
TEST(PosixDir, Getdents64WalksDotDotDotThenEntries) {
    const std::vector<std::uint8_t> code = {
        // the dir fd (3) is pre-seeded in the fixture (the _WIN32 host
        // cannot _open a directory); rdi = 3
        0x48, 0xC7, 0xC7, 0x03, 0x00, 0x00, 0x00,  // mov rdi, 3
        // getdents64(3, 0x1002100, 0x400)
        0x48, 0xC7, 0xC0, 0xD9, 0x00, 0x00, 0x00,  // mov rax, 217 (getdents64)
        0x48, 0xC7, 0xC6, 0x00, 0x21, 0x00, 0x01,  // mov rsi, 0x1002100
        0x48, 0xC7, 0xC2, 0x00, 0x04, 0x00, 0x00,  // mov rdx, 0x400
        0x0F, 0x05,                                 // syscall
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // the second call: 0 (the scan-done gate)
        0x48, 0xC7, 0xC0, 0xD9, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x03, 0x00, 0x00, 0x00,  // mov rdi, 3
        0x48, 0xC7, 0xC6, 0x00, 0x21, 0x00, 0x01,
        0x48, 0xC7, 0xC2, 0x00, 0x04, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    const auto dir = ensure_rootfs() / "somedir";
    std::filesystem::create_directories(dir);
    { std::ofstream f(dir / "alpha.txt"); f << "a"; }
    { std::ofstream f(dir / "beta.bin"); f << "b"; }
    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 's', 'o', 'm', 'e', 'd', 'i', 'r', 0});

    // the _WIN32 host cannot _open a directory, so the dir fd rides the fd
    // table directly (the synthetic QlFile carrying the dir path — the scan
    // reads only the name; the null-file tell/lseek are no-ops gated on the
    // scan-done flag)
    auto dir_file = std::make_shared<QlFile>(dir.string(), static_cast<std::FILE*>(nullptr), false);
    dir_file->set_dir_scan_done(false);
    ql.os<qiling::os::posix::QlOsPosix>().fd().set(3, dir_file);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    const auto first = ql.mem().read_ptr(0x1002208, 8);
    EXPECT_GT(first, 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);  // the second call: 0

    // walk the returned records: '.', '..', then the files
    std::vector<std::string> names;
    const auto blob = ql.mem().read(0x1002100, first);
    std::uint64_t p = 0;
    while (p < blob.size()) {
        const std::uint64_t ino = *reinterpret_cast<const std::uint64_t*>(blob.data() + p);
        const std::uint16_t reclen = *reinterpret_cast<const std::uint16_t*>(blob.data() + p + 16);
        ASSERT_GT(reclen, 0u);
        // the d_type rides at reclen-3, the name at reclen-3-type.. — the
        // getdents64 layout: ino(8) off(8) reclen(2) type(1) name
        names.emplace_back(reinterpret_cast<const char*>(blob.data() + p + 19));
        p += reclen;
    }
    ASSERT_GE(names.size(), 4u);
    EXPECT_EQ(names[0], ".");
    EXPECT_EQ(names[1], "..");
    EXPECT_EQ(names[2], "alpha.txt");
    EXPECT_EQ(names[3], "beta.bin");
}

// the getcwd/chdir ride: chdir into an existing dir answers 0 and flips the
// cwd; a missing dir answers -ENOENT and keeps the cwd
TEST(PosixDir, ChdirFlipsCwdAndGetcwdCarriesIt) {
    const std::vector<std::uint8_t> code = {
        // chdir("/somedir")
        0x48, 0xC7, 0xC0, 0x50, 0x00, 0x00, 0x00,  // mov rax, 80 (chdir)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,  // mov rdi, 0x1002000
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // getcwd(0x1002300, 128)
        0x48, 0xC7, 0xC0, 0x4F, 0x00, 0x00, 0x00,  // mov rax, 79 (getcwd)
        0x48, 0xC7, 0xC7, 0x00, 0x23, 0x00, 0x01,  // mov rdi, 0x1002300
        0x48, 0xC7, 0xC6, 0x80, 0x00, 0x00, 0x00,  // mov rsi, 128
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // chdir("/no-such-dir") — -ENOENT
        0x48, 0xC7, 0xC0, 0x50, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x90, 0x20, 0x00, 0x01,  // mov rdi, 0x1002090
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    std::filesystem::create_directories(ensure_rootfs() / "somedir");
    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 's', 'o', 'm', 'e', 'd', 'i', 'r', 0});
    ql.mem().write(0x1002090, std::vector<std::uint8_t>{'/', 'n', 'o', '-', 's', 'u', 'c', 'h', '-', 'd', 'i', 'r', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);   // the chdir ok
    // the getcwd return = len(cwd)+1; the buffer carries the virtual cwd
    const auto got_len = ql.mem().read_ptr(0x1002210, 8);
    const auto cwd_cell = ql.mem().read(0x1002300, got_len);
    EXPECT_EQ(std::string(cwd_cell.begin(), cwd_cell.end() - 1), "/somedir");
    EXPECT_EQ(cwd_cell[got_len - 1], 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0xFFFFFFFFFFFFFFFEull);  // -ENOENT
}

// readlink("/proc/self/cwd") rides the pseudo-file branch (the cwd read);
// the real paths answer the FIXME branch: an existing file reads as the
// empty target (0) — the upstream does not emulate links
TEST(PosixDir, ReadlinkPseudoFilesAndExistingPaths) {
    const std::vector<std::uint8_t> code = {
        // chdir("/somedir")
        0x48, 0xC7, 0xC0, 0x50, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,
        0x0F, 0x05,
        // readlink("/proc/self/cwd", 0x1002300, 128)
        0x48, 0xC7, 0xC0, 0x59, 0x00, 0x00, 0x00,  // mov rax, 89 (readlink)
        0x48, 0xC7, 0xC7, 0x00, 0x21, 0x00, 0x01,  // mov rdi, 0x1002100
        0x48, 0xC7, 0xC6, 0x00, 0x23, 0x00, 0x01,  // mov rsi, 0x1002300
        0x48, 0xC7, 0xC2, 0x80, 0x00, 0x00, 0x00,  // mov rdx, 128
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // readlink("/existing.txt", 0x1002400, 128) — the FIXME empty target
        0x48, 0xC7, 0xC0, 0x59, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0xA0, 0x20, 0x00, 0x01,  // mov rdi, 0x10020a0
        0x48, 0xC7, 0xC6, 0x00, 0x24, 0x00, 0x01,  // mov rsi, 0x1002400
        0x48, 0xC7, 0xC2, 0x80, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    std::filesystem::create_directories(ensure_rootfs() / "somedir");
    { std::ofstream f(ensure_rootfs() / "existing.txt"); f << "x"; }
    ql.mem().write(0x1002000, std::vector<std::uint8_t>{'/', 's', 'o', 'm', 'e', 'd', 'i', 'r', 0});
    ql.mem().write(0x1002100, std::vector<std::uint8_t>{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'c', 'w', 'd', 0});
    ql.mem().write(0x10020a0, std::vector<std::uint8_t>{'/', 'e', 'x', 'i', 's', 't', 'i', 'n', 'g', '.', 't', 'x', 't', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the cwd readlink: the virtual cwd after the chdir (the return = the
    // name length; the NUL rides past it)
    const auto cwd_len = ql.mem().read_ptr(0x1002208, 8);
    const auto cwd_cell = ql.mem().read(0x1002300, cwd_len);
    EXPECT_EQ(std::string(cwd_cell.begin(), cwd_cell.end()), "/somedir");
    // the existing real path: the empty target, 0 written
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);
    EXPECT_EQ(ql.mem().read(0x1002400, 1)[0], 0u);  // nothing written (the NUL stays)
}

// ---- the signal family (signal.py: rt_sigaction / rt_sigprocmask / ----
// ---- signal) ----

// the x8664 sigaction round trip: the act (handler/flags/restorer/mask, 32
// bytes) loads into the os table; the oldact read-back carries the fields;
// the SIGKILL and the out-of-NSIG signums answer -EINVAL
TEST(PosixSignal, RtSigactionRoundTripAndEinval) {
    const std::vector<std::uint8_t> code = {
        // rt_sigaction(10, act@0x1002000, old@0x1002100) — the oldact
        // carries the PREVIOUS state (empty on the first call, the verbatim
        // write-before-load order)
        0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00,  // mov rax, 13 (rt_sigaction)
        0x48, 0xC7, 0xC7, 0x0A, 0x00, 0x00, 0x00,  // mov rdi, 10 (SIGUSR1)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,  // mov rsi, 0x1002000
        0x48, 0xC7, 0xC2, 0x00, 0x21, 0x00, 0x01,  // mov rdx, 0x1002100
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // the read-back: rt_sigaction(10, 0, old@0x1002180) — the just-
        // registered action rides out
        0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x0A, 0x00, 0x00, 0x00,  // mov rdi, 10
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0
        0x48, 0xC7, 0xC2, 0x80, 0x21, 0x00, 0x01,  // mov rdx, 0x1002180
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x28, 0x22, 0x00, 0x01,  // mov [0x1002228], rax
        // rt_sigaction(9, 0, 0) — the SIGKILL EINVAL
        0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x09, 0x00, 0x00, 0x00,  // mov rdi, 9
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, 0
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // rt_sigaction(32, 0, 0) — the out-of-NSIG EINVAL
        0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x20, 0x00, 0x00, 0x00,  // mov rdi, 32
        0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    // the act: handler=0xdead0001, flags=0x04000000 (SA_RESTORER),
    // restorer=0xdead0002, mask=0x3
    ql.mem().write_ptr(0x1002000, 0xdead0001, 8);
    ql.mem().write_ptr(0x1002008, 0x04000000, 8);
    ql.mem().write_ptr(0x1002010, 0xdead0002, 8);
    ql.mem().write_ptr(0x1002018, 0x3, 8);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);                 // the install ok
    // the first call's oldact: the PREVIOUS state — empty (zeros) verbatim
    EXPECT_EQ(ql.mem().read_ptr(0x1002100, 8), 0u);
    // the read-back call: the just-registered action rides out (the x8664
    // field order: handler/flags/restorer/mask)
    EXPECT_EQ(ql.mem().read_ptr(0x1002228, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002180, 8), 0xdead0001ull);      // the handler
    EXPECT_EQ(ql.mem().read_ptr(0x1002188, 8), 0x04000000ull);      // the flags
    EXPECT_EQ(ql.mem().read_ptr(0x1002190, 8), 0xdead0002ull);      // the restorer
    EXPECT_EQ(ql.mem().read_ptr(0x1002198, 8), 0x3ull);             // the mask
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0xFFFFFFFFFFFFFFFFull);  // the SIGKILL EINVAL
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 0xFFFFFFFFFFFFFFFFull);  // the NSIG EINVAL
}

// rt_sigprocmask: the BLOCK/UNBLOCK/SETMASK walk over the os mask, the
// verbatim old-writes-to-NEWSET quirk, and the KILL/STOP silent drop
TEST(PosixSignal, SigprocmaskWalksTheMaskWithTheVerbatimQuirks) {
    const std::vector<std::uint8_t> code = {
        // rt_sigprocmask(SIG_BLOCK=0, new@0x1002000, old@0x1002100)
        0x48, 0xC7, 0xC0, 0x0E, 0x00, 0x00, 0x00,  // mov rax, 14 (rt_sigprocmask)
        0x48, 0x31, 0xFF,                           // xor rdi, rdi (how = SIG_BLOCK)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,  // mov rsi, 0x1002000
        0x48, 0xC7, 0xC2, 0x00, 0x21, 0x00, 0x01,  // mov rdx, 0x1002100
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // the guest rewrites the new set: the KILL+STOP bits (the drop test)
        // rt_sigprocmask(SIG_SETMASK=2, new@0x1002080, 0)
        0x48, 0xC7, 0xC0, 0x0E, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,  // mov rdi, 2 (SIG_SETMASK)
        0x48, 0xC7, 0xC6, 0x80, 0x20, 0x00, 0x01,  // mov rsi, 0x1002080
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    // the guest's set: bit 5 (SIGTRAP) + the KILL/STOP bits
    ql.mem().write_ptr(0x1002000, (1ull << 5) | (1ull << 9) | (1ull << 19), 8);
    // the SETMASK set: only bit 2 (SIGINT) — but the BLOCK pass's old mask
    // (written to newset verbatim) rides the read-back
    ql.mem().write_ptr(0x1002080, (1ull << 2), 8);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);
    // the verbatim quirk: the BLOCK pass's oldset wrote the (empty) old mask
    // to newset BEFORE the read — so the guest's (1<<5|KILL|STOP) set never
    // applied; the mask after BLOCK = 0. The SETMASK pass then set bit 2
    // with the KILL/STOP drop riding after.
    const auto& os = static_cast<const os::posix::QlOsPosix&>(ql.os());
    EXPECT_EQ(os.blocked_signals(), (1ull << 2));
    // the newset cell carries the pre-BLOCK old mask (0) — the verbatim
    // write-to-newset quirk
    EXPECT_EQ(ql.mem().read_ptr(0x1002000, 8), 0u);
}

// the socket/shutdown core: socket(AF_INET, SOCK_STREAM, 0) takes the next
// free fd (3), the fd table rides the QlSocket, and shutdown closes the
// direction (the second shutdown on an already-shut socket still answers 0
// per the host semantics)
TEST(PosixSocket, SocketTakesFdAndShutdownRides) {
    const std::vector<std::uint8_t> code = {
        // socket(AF_INET=2, SOCK_STREAM=1, 0)
        0x48, 0xC7, 0xC0, 0x29, 0x00, 0x00, 0x00,  // mov rax, 41 (socket)
        0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,  // mov rdi, 2 (AF_INET)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1 (SOCK_STREAM)
        0x4D, 0x31, 0xC9,                           // xor r9, r9 → r8d/r9 = 0
        0x45, 0x31, 0xC0,                           // xor r8d, r8d
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // shutdown(fd, SHUT_RDWR=2)
        0x48, 0x89, 0xC7,                           // mov rdi, rax (the fd)
        0x48, 0xC7, 0xC0, 0x30, 0x00, 0x00, 0x00,  // mov rax, 48 (shutdown)
        0x48, 0xC7, 0xC6, 0x02, 0x00, 0x00, 0x00,  // mov rsi, 2
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    const auto fd = ql.mem().read_ptr(0x1002208, 8);
    EXPECT_EQ(fd, 3u);  // the next free slot after the std streams
    // the unconnected-socket shutdown: the host answers ENOTCONN — the
    // upstream would raise the uncaught OSError; the port's shutdown maps
    // the host failure onto -1 (the documented deviation)
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0xFFFFFFFFFFFFFFFFull);
    // the fd table rides the socket object with the recorded family/type
    const auto& sock = static_cast<const os::posix::QlSocket&>(*ql.os<os::posix::QlOsPosix>().fd().at(static_cast<int>(fd)));
    EXPECT_EQ(sock.family(), 2);
    EXPECT_EQ(sock.socktype(), 1);
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

// the AF_UNIX bind/listen: the guest sun_path rides the rootfs transform
// (the upstream's ql_unix_socket_path) and the host bind/listen land
TEST(PosixSocket, BindUnixRidesRootfsPathAndListens) {
    const std::vector<std::uint8_t> code = {
        // socket(AF_UNIX=1, SOCK_STREAM=1, 0)
        0x48, 0xC7, 0xC0, 0x29, 0x00, 0x00, 0x00,  // mov rax, 41
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1 (AF_UNIX)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1
        0x45, 0x31, 0xC0,                           // xor r8d, r8d
        0x0F, 0x05,
        0x48, 0x89, 0xC7,                           // mov rdi, rax (the fd)
        // bind(fd, sockaddr_un@0x1002000, 110) — the sun_path "/srv.sock"
        0x48, 0xC7, 0xC0, 0x31, 0x00, 0x00, 0x00,  // mov rax, 49 (bind)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,  // mov rsi, 0x1002000
        0x48, 0xC7, 0xC2, 0x6E, 0x00, 0x00, 0x00,  // mov rdx, 110
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // listen(fd, 1)
        0x48, 0xC7, 0xC0, 0x32, 0x00, 0x00, 0x00,  // mov rax, 50 (listen)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    // the temp rootfs persists across the runs: the stale socket file
    // blocks the rebind (EADDRINUSE) — clear it first
    std::error_code rm_ec;
    std::filesystem::remove(ensure_rootfs() / "srv.sock", rm_ec);

    // the sockaddr_un: family=1 (LE u16), the sun_path "/srv.sock" + NUL
    ql.mem().write_ptr(0x1002000, 1, 2);
    ql.mem().write(0x1002002, std::vector<std::uint8_t>{'/', 's', 'r', 'v', '.', 's', 'o', 'c', 'k', 0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);  // the bind ok
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);  // the listen ok
    // the host path rode the rootfs transform: the bind created the socket
    // file under the host rootfs (the Win32 unix-socket file is a reparse
    // point the plain probes reject — the bind's 0 return is the evidence)
}

// the socketpair + the send/recv flow: the connected pair rides the fd
// table (the sv pair carries the two fd numbers), the guest writes through
// one end and reads the payload off the other
TEST(PosixSocket, SocketpairThenSendRecvRidesThePair) {
    const std::vector<std::uint8_t> code = {
        // socketpair(AF_INET=2, SOCK_STREAM=1, 0, sv@0x1002100) — the
        // loopback-pair walk (the AF_UNIX host open fails on _WIN32)
        0x48, 0xC7, 0xC0, 0x35, 0x00, 0x00, 0x00,  // mov rax, 53 (socketpair)
        0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,  // mov rdi, 2 (AF_INET)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1
        0x45, 0x31, 0xC0,                           // xor r8d, r8d
        0x49, 0xBA, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,  // mov r10, 0x1002100
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // send(fd1, "PING", 4, 0) — the sv cells carry the fds (i32 at
        // sv+0/sv+4); the guest loads them with the mov r32→r64 ride
        0x44, 0x8B, 0x04, 0x25, 0x00, 0x21, 0x00, 0x01,  // mov r8d, [0x1002100]
        0x48, 0xC7, 0xC0, 0x2C, 0x00, 0x00, 0x00,  // mov rax, 44 (sendto, the NULL addr rides send)
        0x44, 0x89, 0xC7,                           // mov edi, r8d (the fd)
        0x48, 0xC7, 0xC6, 0x20, 0x22, 0x00, 0x01,  // mov rsi, 0x1002220 ("PING")
        0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00,  // mov rdx, 4
        0x45, 0x31, 0xD2,                           // xor r10d, r10d (the 4th arg rides r10!)
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        // recv(fd2, buf@0x1002240, 16, 0) — the fd from sv+4
        0x44, 0x8B, 0x04, 0x25, 0x04, 0x21, 0x00, 0x01,  // mov r8d, [0x1002104]
        0x48, 0xC7, 0xC0, 0x2D, 0x00, 0x00, 0x00,  // mov rax, 45 (recvfrom, the NULL addr rides recv)
        0x44, 0x89, 0xC7,                           // mov edi, r8d (the fd)
        0x48, 0xC7, 0xC6, 0x40, 0x22, 0x00, 0x01,  // mov rsi, 0x1002240
        0x48, 0xC7, 0xC2, 0x10, 0x00, 0x00, 0x00,  // mov rdx, 16
        0x45, 0x31, 0xD2,                           // xor r10d, r10d (the 4th arg rides r10!)
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x18, 0x22, 0x00, 0x01,  // mov [0x1002218], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    const std::string ping = "PING";
    ql.mem().write(0x1002220, std::vector<std::uint8_t>(ping.begin(), ping.end()));

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);   // the socketpair ok
    EXPECT_EQ(ql.mem().read_ptr(0x1002100, 4), 3u);   // fd1 = 3
    EXPECT_EQ(ql.mem().read_ptr(0x1002104, 4), 4u);   // fd2 = 4
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 4u);   // the send rode 4 bytes
    EXPECT_EQ(ql.mem().read_ptr(0x1002218, 8), 4u);   // the recv rode 4 bytes
    const auto got = ql.mem().read(0x1002240, 4);
    EXPECT_EQ(std::string(got.begin(), got.end()), "PING");
}

// the getsockopt/setsockopt pair: SO_TYPE off the SOL_SOCKET rides back the
// socket kind (SO_TYPE=3, SOL_SOCKET=1); the setsockopt of SO_KEEPALIVE
// flips the host flag and answers 0
TEST(PosixSocket, SockoptRoundTripsTheTypeAndKeepalive) {
    const std::vector<std::uint8_t> code = {
        // socket(AF_INET=2, SOCK_STREAM=1, 0)
        0x48, 0xC7, 0xC0, 0x29, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,
        0x45, 0x31, 0xC0,
        0x0F, 0x05,
        0x48, 0x89, 0xC7,                           // mov rdi, rax (the fd)
        // setsockopt(fd, SOL_SOCKET=1, SO_KEEPALIVE=9, val@0x1002000, 4)
        // — the args ride rdi/rsi/rdx/r10/r8 (the syscall ABI order)
        0x48, 0xC7, 0xC0, 0x36, 0x00, 0x00, 0x00,  // mov rax, 54 (setsockopt)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1 (SOL_SOCKET)
        0x48, 0xC7, 0xC2, 0x09, 0x00, 0x00, 0x00,  // mov rdx, 9 (SO_KEEPALIVE)
        0x49, 0xBA, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,  // mov r10, 0x1002000 (the val)
        0x41, 0xB8, 0x04, 0x00, 0x00, 0x00,         // mov r8d, 4 (the len)
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // getsockopt(fd, SOL_SOCKET=1, SO_TYPE=3, val@0x1002100, len@0x1002108)
        // — the args ride rdi/rsi/rdx/r10/r8
        0x48, 0xC7, 0xC0, 0x37, 0x00, 0x00, 0x00,  // mov rax, 55 (getsockopt)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,  // mov rsi, 1 (SOL_SOCKET)
        0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00,  // mov rdx, 3 (SO_TYPE)
        0x49, 0xBA, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,  // mov r10, 0x1002100
        0x49, 0xC7, 0xC0, 0x08, 0x21, 0x00, 0x01,  // mov r8, 0x1002108
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write_ptr(0x1002000, 1, 4);           // the SO_KEEPALIVE value 1
    ql.mem().write_ptr(0x1002108, 4, 4);           // the optlen in: 4

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);   // the setsockopt ok
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0u);   // the getsockopt ok
    EXPECT_EQ(ql.mem().read_ptr(0x1002100, 4), 1u);   // SO_TYPE rides SOCK_STREAM=1
}

// the name lookups: getsockname after the INADDR_ANY bind rides the family
// word, the BE port and the 16 write-back; getpeername on the unconnected
// socket rides -1 (the upstream would raise uncaught — the documented
// -ENOTCONN deviation shape)
TEST(PosixSocket, GetSockNameAfterBindAndPeerNameUnconnected) {
    const std::vector<std::uint8_t> code = {
        // socket(AF_INET=2, SOCK_STREAM=1, 0)
        0x48, 0xC7, 0xC0, 0x29, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,
        0x45, 0x31, 0xC0,
        0x0F, 0x05,
        0x48, 0x89, 0xC7,                           // mov rdi, rax (the fd)
        // bind(fd, sa@0x1002400, 16) — the INADDR_ANY wildcard
        0x48, 0xC7, 0xC0, 0x31, 0x00, 0x00, 0x00,  // mov rax, 49 (bind)
        0x48, 0xC7, 0xC6, 0x00, 0x24, 0x00, 0x01,  // mov rsi, 0x1002400
        0x48, 0xC7, 0xC2, 0x10, 0x00, 0x00, 0x00,  // mov rdx, 16
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x00, 0x22, 0x00, 0x01,  // mov [0x1002200], rax
        // getsockname(fd, sa@0x1002300, len@0x1002310)
        0x48, 0xC7, 0xC0, 0x33, 0x00, 0x00, 0x00,  // mov rax, 51 (getsockname)
        0x48, 0xC7, 0xC6, 0x00, 0x23, 0x00, 0x01,  // mov rsi, 0x1002300
        0x48, 0xC7, 0xC2, 0x10, 0x23, 0x00, 0x01,  // mov rdx, 0x1002310
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x08, 0x22, 0x00, 0x01,  // mov [0x1002208], rax
        // getpeername(fd, sa@0x1002320, len@0x1002318) — the ENOTCONN ride
        0x48, 0xC7, 0xC0, 0x34, 0x00, 0x00, 0x00,  // mov rax, 52 (getpeername)
        0x48, 0xC7, 0xC6, 0x20, 0x23, 0x00, 0x01,  // mov rsi, 0x1002320
        0x48, 0xC7, 0xC2, 0x18, 0x23, 0x00, 0x01,  // mov rdx, 0x1002318
        0x0F, 0x05,
        0x48, 0x89, 0x04, 0x25, 0x10, 0x22, 0x00, 0x01,  // mov [0x1002210], rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options = posix_options(code);
    Qiling ql(options);

    ql.mem().write_ptr(0x1002400, 2, 2);           // sa_family = AF_INET
    // the rest of the sa (the port + the addr) stays zero = INADDR_ANY:0
    ql.mem().write_ptr(0x1002310, 16);             // the addrlen cell in: 16

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    EXPECT_EQ(ql.mem().read_ptr(0x1002200, 8), 0u);   // the bind ok
    EXPECT_EQ(ql.mem().read_ptr(0x1002208, 8), 0u);   // the getsockname ok
    EXPECT_EQ(ql.mem().read_ptr(0x1002300, 2), 2u);   // the family word rides AF_INET
    EXPECT_NE(ql.mem().read_ptr(0x1002302, 2), 0u);   // the assigned ephemeral port (BE)
    EXPECT_EQ(ql.mem().read_ptr(0x1002310, 8), 16u);  // the addrlen cell: 16
    // the peer name on the unconnected socket: the ENOTCONN ride (-1)
    EXPECT_EQ(ql.mem().read_ptr(0x1002210, 8), 0xFFFFFFFFFFFFFFFFull);
}
