// QlOsFreebsd suite — the freebsd.py dialect over the posix base, ported
// per the upstream's os/freebsd/ shape:
//   - the QlOsFreebsd(QlOsPosix) with the FREEBSD type and the syscall
//     dispatch through the FREEBSD x8664 syscall table (the freebsd numbers,
//     not the linux ones)
//   - the 6 handler deltas (the __sysctl, the sysarch, the sigprocmask, the
//     clock_gettime, the __getcwd, the fstatat)
//   - the fixture-driven flows mirror the posix test style (the code blob +
//     the data region + the exit-code/memory assertions)
#include <gtest/gtest.h>

#include <filesystem>

#include "qiling/core.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/os/freebsd/freebsd.hpp"

using namespace qiling;

namespace {

// the fixture body: the __sysctl(KERN.OSRELDATE) probe then exit(42)
//   00: mov rdi, kName ; 07: mov rsi, 2 ; 0e: mov rdx, kOld ; 15: mov r10, kOldlenp
//   1c: xor r8d ; 1f: xor r9d ; 22: mov rax, 202 ; 29: syscall
//   2b: mov rax, 1 (exit) ; 32: mov rdi, 42 ; 39: syscall
constexpr std::uint64_t kName = 0x1002000;
constexpr std::uint64_t kOld = 0x1002010;
constexpr std::uint64_t kOldlenp = 0x1002020;
constexpr std::uint64_t kNameStr = 0x1002030;

const std::vector<std::uint8_t>& sysctl_body() {
    static const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,          // 00: mov rdi, kName
        0x48, 0xC7, 0xC6, 0x02, 0x00, 0x00, 0x00,          // 07: mov rsi, 2
        0x48, 0xC7, 0xC2, 0x10, 0x20, 0x00, 0x01,          // 0E: mov rdx, kOld
        0x49, 0xC7, 0xC2, 0x20, 0x20, 0x00, 0x01,          // 15: mov r10, kOldlenp
        0x45, 0x31, 0xC0,                                   // 1C: xor r8d, r8d
        0x45, 0x31, 0xC9,                                   // 1F: xor r9d, r9d
        0x48, 0xC7, 0xC0, 0xCA, 0x00, 0x00, 0x00,          // 22: mov rax, 202
        0x0F, 0x05,                                         // 29: syscall
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,          // 2B: mov rax, 1 (exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 32: mov rdi, 42
        0x0F, 0x05,                                         // 39: syscall
    };
    return code;
}

Qiling make_freebsd_qiling(const std::vector<std::uint8_t>& code) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_freebsd_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = code;
    options.ostype = QL_OS::FREEBSD;
    options.archtype = QL_ARCH::X8664;
    return Qiling{options};
}

}  // namespace

// the KERN.OSRELDATE sysctl path: the vecs [CTL_KERN, KERN_OSRELDATE] write
// the FREEBSD_OSRELDATE constant (stable/12 as of 2021.3.12) into old; the
// upstream ignores the oldlenp check in this path (only old is written)
TEST(FreebsdOs, SysctlKernOsreldateWritesConstant) {
    auto ql = make_freebsd_qiling(sysctl_body());

    // the name vecs: [CTL_KERN=1, KERN_OSRELDATE=24] (the 4-byte signed reads)
    ql.mem().write_ptr(kName, 1, 4);
    ql.mem().write_ptr(kName + 4, 24, 4);
    ql.mem().write_ptr(kOldlenp, 0, 4);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kOld, 4), 1202505u);
    // the upstream writes only old in the OSRELDATE path (the oldlenp check
    // ignored, verbatim)
    EXPECT_EQ(ql.mem().read_ptr(kOldlenp, 4), 0u);
}

// the NAME2OID sysctl path: the CTL_SYSCTL/NAME2OID vecs with the name
// "hw.pagesizes" resolve onto [CTL_HW, HW_PAGESIZE] + the length 2; the miss
// returns -ENOENT
TEST(FreebsdOs, SysctlName2oidResolvesPagesizes) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,          // 00: mov rdi, kName (the vecs ptr)
        0x48, 0xC7, 0xC6, 0x02, 0x00, 0x00, 0x00,          // 07: mov rsi, 2
        0x48, 0xC7, 0xC2, 0x10, 0x20, 0x00, 0x01,          // 0E: mov rdx, kOld
        0x49, 0xC7, 0xC2, 0x20, 0x20, 0x00, 0x01,          // 15: mov r10, kOldlenp
        0x41, 0xB8, 0x30, 0x20, 0x00, 0x01,                // 1C: mov r8d, kNameStr (the name string)
        0x45, 0x31, 0xC9,                                   // 23: xor r9d, r9d
        0x48, 0xC7, 0xC0, 0xCA, 0x00, 0x00, 0x00,          // 26: mov rax, 202
        0x0F, 0x05,                                         // 2D: syscall
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,          // 2F: mov rax, 1 (exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 36: mov rdi, 42
        0x0F, 0x05,                                         // 3D: syscall
    };
    auto ql = make_freebsd_qiling(code);

    const std::string name = "hw.pagesizes";
    ql.mem().write_ptr(kName, 0, 4);       // CTL_SYSCTL
    ql.mem().write_ptr(kName + 4, 3, 4);   // CTL_SYSCTL_NAME2OID
    ql.mem().write(kNameStr, std::vector<std::uint8_t>{name.begin(), name.end()});
    ql.mem().write(kNameStr + name.size(), std::vector<std::uint8_t>{0});

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the oid vec lands: [CTL_HW=6, HW_PAGESIZE=7], the length 2
    EXPECT_EQ(ql.mem().read_ptr(kOld, 4), 6u);
    EXPECT_EQ(ql.mem().read_ptr(kOld + 4, 4), 7u);
    EXPECT_EQ(ql.mem().read_ptr(kOldlenp, 4), 2u);
}

// the CLOCK_REALTIME clock_gettime: the timespec lands at tp (the freebsd
// layout: the tv_sec=u64, the tv_nsec=i64; the nsec field carries the usec-
// resolution fraction per the upstream's *1e6 arithmetic, verbatim)
TEST(FreebsdOs, ClockGettimeWritesTimespec) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,          // 00: mov rdi, 0 (CLOCK_REALTIME)
        0x48, 0xC7, 0xC6, 0x10, 0x20, 0x00, 0x01,          // 07: mov rsi, tp
        0x48, 0xC7, 0xC0, 0xE8, 0x00, 0x00, 0x00,          // 0E: mov rax, 232
        0x0F, 0x05,                                         // 15: syscall
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,          // 17: mov rax, 1 (exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 1E: mov rdi, 42
        0x0F, 0x05,                                         // 25: syscall
    };
    auto ql = make_freebsd_qiling(code);

    constexpr std::uint64_t kTp = 0x1002010;
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    const auto tv_sec = ql.mem().read_ptr(kTp, 8);
    const auto tv_nsec = ql.mem().read_ptr(kTp + 8, 8);
    EXPECT_GT(tv_sec, 1600000000u);  // the 2020-ish epoch seconds
    EXPECT_LT(tv_nsec, 1000000000u);
}

// the sigprocmask: the no-op success (the upstream's debug + return 0)
TEST(FreebsdOs, SigprocmaskReturnsZero) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,          // 00: mov rdi, 1 (SIG_BLOCK)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,          // 07: mov rsi, 0x1002000 (the mask)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,          // 0E: mov rdx, 0 (omask)
        0x48, 0xC7, 0xC0, 0x54, 0x01, 0x00, 0x00,          // 15: mov rax, 340
        0x0F, 0x05,                                         // 1C: syscall
        0x48, 0xC7, 0xC3, 0x2A, 0x00, 0x00, 0x00,          // 1E: mov rbx, 42
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,          // 25: mov rax, 1 (exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 2C: mov rdi, 42
        0x0F, 0x05,                                         // 33: syscall
    };
    auto ql = make_freebsd_qiling(code);
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
}

// the sysarch: the "wild guess" handler writes parms into the FS base MSR
// (the op is ignored, the upstream verbatim)
TEST(FreebsdOs, SysarchWritesFsBaseMsr) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,          // 00: mov rdi, 1 (the op)
        0x48, 0xC7, 0xC6, 0x34, 0x12, 0x00, 0x00,          // 07: mov rsi, 0x1234 (the parms)
        0x48, 0xC7, 0xC0, 0xA5, 0x00, 0x00, 0x00,          // 0E: mov rax, 165
        0x0F, 0x05,                                         // 15: syscall
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,          // 17: mov rax, 1 (exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 1E: mov rdi, 42
        0x0F, 0x05,                                         // 25: syscall
    };
    auto ql = make_freebsd_qiling(code);
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(dynamic_cast<QlArchIntel&>(ql.arch()).msr().read(0xC0000100), 0x1234u);
}

// the __getcwd: the cwd bytes + the NUL at path_buff, the return = the length
TEST(FreebsdOs, GetcwdWritesCwdBytes) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,          // 00: mov rdi, kName (the buffer)
        0x48, 0xC7, 0xC6, 0x00, 0x01, 0x00, 0x00,          // 07: mov rsi, 0x100 (the size)
        0x48, 0xC7, 0xC0, 0x46, 0x01, 0x00, 0x00,          // 0E: mov rax, 326
        0x0F, 0x05,                                         // 15: syscall
        0x48, 0x89, 0xC3,                                   // 17: mov rbx, rax (the return)
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,          // 1A: mov rax, 1 (exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 21: mov rdi, 42
        0x0F, 0x05,                                         // 28: syscall
    };
    auto ql = make_freebsd_qiling(code);
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    const auto got = ql.mem().read(kName, 16);
    // the cwd (the profile's MISC current_path: "/") + the NUL
    EXPECT_EQ(got[0], '/');
    EXPECT_EQ(got[1], 0);
}

// the fstatat: the delegate to the posix newfstatat (the stat module defers
// with its slice); the freebsd surface surfaces the not-implemented
TEST(FreebsdOs, FstatatSurfacesNotImplemented) {
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF,          // 00: mov rdi, -1 (the AT_FDCWD-ish)
        0x48, 0xC7, 0xC6, 0x00, 0x20, 0x00, 0x01,          // 07: mov rsi, kName (the path)
        0x48, 0xC7, 0xC2, 0x10, 0x20, 0x00, 0x01,          // 0E: mov rdx, kOld (the buf)
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,          // 15: mov rcx, 0 (the flags)
        0x48, 0xC7, 0xC0, 0x28, 0x02, 0x00, 0x00,          // 1C: mov rax, 552
        0x0F, 0x05,                                         // 23: syscall
        0xEB, 0xFE,                                         // 25: jmp $
    };
    auto ql = make_freebsd_qiling(code);

    bool raised = false;
    try {
        ql.run();
    } catch (const QlErrorNotImplemented&) {
        raised = true;
    }
    EXPECT_TRUE(raised);
}
