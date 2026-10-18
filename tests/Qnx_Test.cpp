// QlOsQnx suite — the qnx.py dialect over the posix base, ported per the
// upstream's os/qnx/ shape:
//   - the QlOsQnx(QlOsPosix) with the QNX type and the ARM32 kernel-entry
//     hook (the interrupt 2) + the R12 id-register ABI override
//   - the kercalls table dispatch (the ARM numbers, not the linux ones)
//   - the fixture-driven flows mirror the posix test style (the code blob +
//     the data region + the exit-code/memory assertions)
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "qiling/core.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/qnx.hpp"

using namespace qiling;

namespace {

// the fixture body: channel_create() then thread_destroy(-1, -1, 42) —
// the channel id rides R0 into the scratch word, the exit code comes from
// the thread_destroy status (qnx.py's exit path)
//   00: mov r1, #0x2000     ; the scratch pointer
//   04: mov r12, #35        ; channel_create
//   08: swi 0
//   0C: str r0, [r1]        ; record the returned channel id
//   10: mvn r0, #0          ; tid = -1
//   14: mvn r1, #0          ; priority = -1
//   18: mov r2, #42         ; status
//   1C: mov r12, #47        ; thread_destroy
//   20: swi 0
// the clock_time flow: the CLOCK_REALTIME read writes the nanosecond
// timestamp into the caller's 8-byte cell and the thread_destroy
// (-1, -1, status) terminates with the status as the exit code
constexpr std::uint64_t kScratch = 0x2000;

// the synthetic syspage image (the prelude copies it into the syspage map)
const std::vector<std::uint8_t> kSyspageImage(0x400, 0x42);
constexpr std::uint64_t kOld = 0x2080;

const std::vector<std::uint8_t>& channel_exit_body() {
    static const std::vector<std::uint8_t> code = {
        0x02, 0x1A, 0xA0, 0xE3,  // 00: mov r1, #0x2000
        0x23, 0xC0, 0xA0, 0xE3,  // 04: mov r12, #35
        0x00, 0x00, 0x00, 0xEF,  // 08: swi 0
        0x00, 0x00, 0x81, 0xE5,  // 0C: str r0, [r1]
        0x00, 0x00, 0xE0, 0xE3,  // 10: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 14: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 18: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 1C: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 20: swi 0
    };
    return code;
}

Qiling make_qnx_qiling(const std::vector<std::uint8_t>& code) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_qnx_rootfs";
    std::filesystem::create_directories(rootfs);

    // the rootfs carries the syspage image (the upstream arm_qnx rootfs
    // shape); the content is opaque to the kernel calls, a marker pattern
    // suffices for the fixtures
    std::ofstream sp(rootfs / "syspage.bin", std::ios::binary);
    sp.write(reinterpret_cast<const char*>(kSyspageImage.data()),
             static_cast<std::streamsize>(kSyspageImage.size()));
    sp.close();

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = code;
    options.ostype = QL_OS::QNX;
    options.archtype = QL_ARCH::ARM;
    return Qiling{options};
}

//   00: mov r0, #0        ; id = CLOCK_REALTIME
//   04: mov r1, #0        ; new = 0 (the read path)
//   08: mov r2, #0x2080   ; old = kOld
//   0C: mov r12, #65      ; clock_time
//   10: swi 0
//   14: mvn r0, #0        ; tid = -1
//   18: mvn r1, #0        ; priority = -1
//   1C: mov r2, #42       ; status
//   20: mov r12, #47      ; thread_destroy
//   24: swi 0
const std::vector<std::uint8_t>& clock_time_body() {
    static const std::vector<std::uint8_t> code = {
        0x00, 0x00, 0xA0, 0xE3,  // 00: mov r0, #0
        0x00, 0x10, 0xA0, 0xE3,  // 04: mov r1, #0
        0x82, 0x2D, 0xA0, 0xE3,  // 08: mov r2, #0x2080
        0x41, 0xC0, 0xA0, 0xE3,  // 0C: mov r12, #65
        0x00, 0x00, 0x00, 0xEF,  // 10: swi 0
        0x00, 0x00, 0xE0, 0xE3,  // 14: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 18: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 1C: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 20: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 24: swi 0
    };
    return code;
}

}  // namespace

// the channel_create + the thread_destroy exit flow: the first channel id is
// 1 (the upstream ctor seeds channel_id = 1) and the thread_destroy
// (-1, -1, status) terminates with the status as the exit code
TEST(QnxOs, ChannelCreateThenThreadDestroyExitsWithStatus) {
    auto ql = make_qnx_qiling(channel_exit_body());

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 1u);
}

// the clock_time read path: the nanosecond wall clock lands in the caller's
// 8-byte cell (the upstream writes time_ns() at old and returns EOK)
TEST(QnxOs, ClockTimeReadWritesNsTimestamp) {
    auto ql = make_qnx_qiling(clock_time_body());

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the ns-since-epoch magnitude (the unix-era floor; the upstream's
    // time_ns() shape)
    const auto stamp = ql.mem().read_ptr(kOld, 8);
    EXPECT_GE(stamp, 1000000000000000000ull);
}

// the clock_cycles flow: the kernel returns the free-running counter as the
// nanosecond wall clock (the upstream's simplification). The 0xFE000000
// kercall id does not fit a mov immediate, so the fixture pools the literal
// and the pre-poisoned marker in R0 proves the dispatcher wrote the return
// register
constexpr std::uint64_t kRet = 0x2100;

//   00: mov r0, #5        ; the marker (the handler must overwrite it)
//   04: mov r4, #0x2100   ; kRet
//   08: ldr r12, [pc, #24]  ; the literal pool at 0x28
//   0C: swi 0             ; clock_cycles
//   10: str r0, [r4]
//   14: mvn r0, #0        ; tid = -1
//   18: mvn r1, #0        ; priority = -1
//   1C: mov r2, #42       ; status
//   20: mov r12, #47      ; thread_destroy
//   24: swi 0
//   28: literal 0xFE000000 (clock_cycles)
TEST(QnxOs, ClockCyclesReturnsNsClock) {
    const std::vector<std::uint8_t> code = {
        0x05, 0x00, 0xA0, 0xE3,  // 00: mov r0, #5
        0x21, 0x4C, 0xA0, 0xE3,  // 04: mov r4, #0x2100
        0x18, 0xC0, 0x9F, 0xE5,  // 08: ldr r12, [pc, #24]
        0x00, 0x00, 0x00, 0xEF,  // 0C: swi 0
        0x00, 0x00, 0x84, 0xE5,  // 10: str r0, [r4]
        0x00, 0x00, 0xE0, 0xE3,  // 14: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 18: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 1C: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 20: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 24: swi 0
        0x00, 0x00, 0x00, 0xFE,  // 28: literal 0xFE000000 (little-endian)
    };
    auto ql = make_qnx_qiling(code);

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the ns clock lands in R0 through the dispatcher's return write (the
    // marker 5 would survive a no-op dispatch); the ARM32 return register is
    // 32-bit, so the 64-bit ns counter truncates to its low 32 bits — the
    // upstream's r0 write has the same shape
    const auto cycles = ql.mem().read_ptr(kRet, 4);
    EXPECT_NE(cycles, 5u);
    EXPECT_NE(cycles, 0u);
}

// the sys_cpupage_set/get flow over the run() prelude: the CPUPAGE_PLS
// slot (cpupage+4) is set via kercall 8 and read back via kercall 7; the
// index 2 returns the syspage address the prelude mapped. (The prelude
// writes the TLS pointer at cpupage+0; the PLS slot starts unset.)
constexpr std::uint64_t kCpupageRet = 0x2100;
constexpr std::uint64_t kCpupageRet2 = 0x2104;

//   00: mov r3, #0x2100  ; the scratch cell
//   04: mov r0, #1       ; index = CPUPAGE_PLS
//   08: mov r1, #0xAB0000 ; the PLS marker
//   0C: mov r12, #8      ; sys_cpupage_set
//   10: swi 0
//   14: mov r0, #1       ; index = CPUPAGE_PLS (read back)
//   18: mov r12, #7      ; sys_cpupage_get
//   1C: swi 0
//   20: str r0, [r3]
//   24: mov r0, #2       ; index = CPUPAGE_SYSPAGE
//   28: mov r12, #7
//   2C: swi 0
//   30: str r0, [r3, #4]
//   34: mvn r0, #0 ; 38: mvn r1, #0 ; 3C: mov r2, #42
//   40: mov r12, #47 ; 44: swi 0
TEST(QnxOs, SysCpupageSetGetRoundtripsPls) {
    const std::vector<std::uint8_t> code = {
        0x21, 0x3C, 0xA0, 0xE3,  // 00: mov r3, #0x2100
        0x01, 0x00, 0xA0, 0xE3,  // 04: mov r0, #1
        0xAB, 0x18, 0xA0, 0xE3,  // 08: mov r1, #0xAB0000
        0x08, 0xC0, 0xA0, 0xE3,  // 0C: mov r12, #8
        0x00, 0x00, 0x00, 0xEF,  // 10: swi 0
        0x01, 0x00, 0xA0, 0xE3,  // 14: mov r0, #1
        0x07, 0xC0, 0xA0, 0xE3,  // 18: mov r12, #7
        0x00, 0x00, 0x00, 0xEF,  // 1C: swi 0
        0x00, 0x00, 0x83, 0xE5,  // 20: str r0, [r3]
        0x02, 0x00, 0xA0, 0xE3,  // 24: mov r0, #2
        0x07, 0xC0, 0xA0, 0xE3,  // 28: mov r12, #7
        0x00, 0x00, 0x00, 0xEF,  // 2C: swi 0
        0x04, 0x00, 0x83, 0xE5,  // 30: str r0, [r3, #4]
        0x00, 0x00, 0xE0, 0xE3,  // 34: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 38: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 3C: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 40: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 44: swi 0
    };
    auto ql = make_qnx_qiling(code);

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the PLS roundtrip: set(1, 0xAB0000) then get(1) hands the marker back
    EXPECT_EQ(ql.mem().read_ptr(kCpupageRet, 4), 0xAB0000u);
    // index 2: the syspage address the prelude mapped
    EXPECT_EQ(ql.mem().read_ptr(kCpupageRet2, 4), 0xfc404000u);
}

// the connect_attach/connect_detach flow: attaching to the sysmgr channel
// with the side-channel index hands out the first high connection id
// (NTO_SIDE_CHANNEL + 1, seeded in the ctor); the detach closes it and
// returns EOK
constexpr std::uint64_t kConnectRet = 0x2100;
constexpr std::uint64_t kConnectRet2 = 0x2104;

//   00: mov r0, #0        ; nd = ND_LOCAL_NODE
//   04: mov r1, #1        ; pid = SYSMGR_PID
//   08: mov r2, #1        ; chid = SYSMGR_CHID
//   0C: mov r3, #0x40000000 ; index (the side channel)
//   10: mov r4, #1        ; flags = _NTO_COF_CLOEXEC
//   14: mov r12, #39      ; connect_attach
//   18: swi 0
//   1C: mov r4, #0x2100   ; the scratch cell
//   20: str r0, [r4]
//   24: mov r12, #40      ; connect_detach (coid still in r0)
//   28: swi 0
//   2C: str r0, [r4, #4]
//   30: mvn r0, #0 ; 34: mvn r1, #0 ; 38: mov r2, #42
//   3C: mov r12, #47 ; 40: swi 0
TEST(QnxOs, ConnectAttachHandsSideChannelCoidThenDetach) {
    const std::vector<std::uint8_t> code = {
        0x00, 0x00, 0xA0, 0xE3,  // 00: mov r0, #0
        0x01, 0x10, 0xA0, 0xE3,  // 04: mov r1, #1
        0x01, 0x20, 0xA0, 0xE3,  // 08: mov r2, #1
        0x40, 0x34, 0xA0, 0xE3,  // 0C: mov r3, #0x40000000
        0x01, 0x40, 0xA0, 0xE3,  // 10: mov r4, #1
        0x27, 0xC0, 0xA0, 0xE3,  // 14: mov r12, #39
        0x00, 0x00, 0x00, 0xEF,  // 18: swi 0
        0x21, 0x4C, 0xA0, 0xE3,  // 1C: mov r4, #0x2100
        0x00, 0x00, 0x84, 0xE5,  // 20: str r0, [r4]
        0x28, 0xC0, 0xA0, 0xE3,  // 24: mov r12, #40
        0x00, 0x00, 0x00, 0xEF,  // 28: swi 0
        0x04, 0x00, 0x84, 0xE5,  // 2C: str r0, [r4, #4]
        0x00, 0x00, 0xE0, 0xE3,  // 30: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 34: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 38: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 3C: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 40: swi 0
    };
    auto ql = make_qnx_qiling(code);

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the first side-channel coid (the hi counter seeds at NTO_SIDE_CHANNEL+1)
    EXPECT_EQ(ql.mem().read_ptr(kConnectRet, 4), os::qnx::NTO_SIDE_CHANNEL + 1u);
    // the detach returns EOK
    EXPECT_EQ(ql.mem().read_ptr(kConnectRet2, 4), 0u);
}

// the connect_flags + the connect_client_info flow: the seeded SYSMGR coid
// passes the flags check (pid 0, the FD_CLOEXEC mask); the client_info for
// the calling process (scoid = -1) fills the _client_info record — the nd,
// the KERNEL profile pid and the zeroed creds (the super-user shape)
//   00: mov r0, #0          ; pid = 0
//   04: mov r1, #0x40000000 ; coid = SYSMGR_COID
//   08: mov r2, #1          ; mask = FD_CLOEXEC
//   0C: mov r3, #1          ; bits
//   10: mov r12, #43        ; connect_flags
//   14: swi 0
//   18: mov r4, #0x2100 ; 1C: add r4, r4, #0x18
//   20: str r0, [r4]         ; the flags result -> 0x2118
//   24: mov r1, #0x2100      ; info = 0x2100
//   28: mvn r0, #0           ; scoid = -1 (the calling process)
//   2C: mov r2, #0           ; ngroups
//   30: mov r12, #42         ; connect_client_info
//   34: swi 0
//   38: mov r4, #0x2100 ; 3C: add r4, r4, #0x14
//   40: str r0, [r4]         ; the client_info result -> 0x2114
//   44: mvn r0, #0 ; 48: mvn r1, #0 ; 4C: mov r2, #42
//   50: mov r12, #47 ; 54: swi 0
TEST(QnxOs, ConnectFlagsAndClientInfoOnSeededSysmgrCoid) {
    const std::vector<std::uint8_t> code = {
        0x00, 0x00, 0xA0, 0xE3,  // 00: mov r0, #0
        0x40, 0x14, 0xA0, 0xE3,  // 04: mov r1, #0x40000000
        0x01, 0x20, 0xA0, 0xE3,  // 08: mov r2, #1
        0x01, 0x30, 0xA0, 0xE3,  // 0C: mov r3, #1
        0x2B, 0xC0, 0xA0, 0xE3,  // 10: mov r12, #43
        0x00, 0x00, 0x00, 0xEF,  // 14: swi 0
        0x21, 0x4C, 0xA0, 0xE3,  // 18: mov r4, #0x2100
        0x18, 0x40, 0x84, 0xE2,  // 1C: add r4, r4, #0x18
        0x00, 0x00, 0x84, 0xE5,  // 20: str r0, [r4]
        0x21, 0x1C, 0xA0, 0xE3,  // 24: mov r1, #0x2100
        0x00, 0x00, 0xE0, 0xE3,  // 28: mvn r0, #0
        0x00, 0x20, 0xA0, 0xE3,  // 2C: mov r2, #0
        0x2A, 0xC0, 0xA0, 0xE3,  // 30: mov r12, #42
        0x00, 0x00, 0x00, 0xEF,  // 34: swi 0
        0x21, 0x4C, 0xA0, 0xE3,  // 38: mov r4, #0x2100
        0x14, 0x40, 0x84, 0xE2,  // 3C: add r4, r4, #0x14
        0x00, 0x00, 0x84, 0xE5,  // 40: str r0, [r4]
        0x00, 0x00, 0xE0, 0xE3,  // 44: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 48: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 4C: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 50: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 54: swi 0
    };
    auto ql = make_qnx_qiling(code);

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // both kernel calls return EOK
    EXPECT_EQ(ql.mem().read_ptr(0x2118, 4), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x2114, 4), 0u);
    // the _client_info record: the nd, the profile pid and the zero creds
    EXPECT_EQ(ql.mem().read_ptr(0x2100, 4), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x2104, 4), 1996u);
    EXPECT_EQ(ql.mem().read_ptr(0x2108, 4), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x210C, 4), 0u);
}

// the sync family: sync_create (NTO_SYNC_MUTEX_FREE) stamps the mutex-free
// owner and the NONRECURSIVE count over the caller's 8-byte _sync cell;
// sync_mutex_lock adopts the TLS owner cell (the prelude's (pid<<16|tid)
// owner, the WAITING bit clear); a second cell stays untouched as the
// control
//   00: mov r0, #0        ; type = NTO_SYNC_MUTEX_FREE
//   04: mov r1, #0x2200   ; syncp = A
//   08: mov r2, #0        ; attrp = 0
//   0C: mov r12, #78      ; sync_create
//   10: swi 0
//   14: mov r4, #0x2100 ; 18: str r0, [r4]
//   1C: mov r0, #0x2200   ; syncp = A (the lock's first arg)
//   20: mov r12, #80      ; sync_mutex_lock
//   24: swi 0
//   28: str r0, [r4, #4]
//   2C: add r1, r1, #8    ; B = 0x2208
//   30: mov r0, #0        ; type = NTO_SYNC_MUTEX_FREE
//   34: mov r12, #78      ; sync_create B
//   38: swi 0
//   3C: str r0, [r4, #8]
//   40: mvn r0, #0 ; 44: mvn r1, #0 ; 48: mov r2, #42
//   4C: mov r12, #47 ; 50: swi 0
TEST(QnxOs, SyncCreateAndMutexLockStampOwnerAndCount) {
    const std::vector<std::uint8_t> code = {
        0x00, 0x00, 0xA0, 0xE3,  // 00: mov r0, #0
        0x22, 0x1C, 0xA0, 0xE3,  // 04: mov r1, #0x2200
        0x00, 0x20, 0xA0, 0xE3,  // 08: mov r2, #0
        0x4E, 0xC0, 0xA0, 0xE3,  // 0C: mov r12, #78
        0x00, 0x00, 0x00, 0xEF,  // 10: swi 0
        0x21, 0x4C, 0xA0, 0xE3,  // 14: mov r4, #0x2100
        0x00, 0x00, 0x84, 0xE5,  // 18: str r0, [r4]
        0x22, 0x0C, 0xA0, 0xE3,  // 1C: mov r0, #0x2200
        0x50, 0xC0, 0xA0, 0xE3,  // 20: mov r12, #80
        0x00, 0x00, 0x00, 0xEF,  // 24: swi 0
        0x04, 0x00, 0x84, 0xE5,  // 28: str r0, [r4, #4]
        0x08, 0x10, 0x81, 0xE2,  // 2C: add r1, r1, #8
        0x00, 0x00, 0xA0, 0xE3,  // 30: mov r0, #0
        0x4E, 0xC0, 0xA0, 0xE3,  // 34: mov r12, #78
        0x00, 0x00, 0x00, 0xEF,  // 38: swi 0
        0x08, 0x00, 0x84, 0xE5,  // 3C: str r0, [r4, #8]
        0x00, 0x00, 0xE0, 0xE3,  // 40: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 44: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 48: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 4C: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 50: swi 0
    };
    auto ql = make_qnx_qiling(code);

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // all three kernel calls return EOK
    EXPECT_EQ(ql.mem().read_ptr(0x2100, 4), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x2104, 4), 0u);
    EXPECT_EQ(ql.mem().read_ptr(0x2108, 4), 0u);
    // A: the count is NONRECURSIVE and the owner is the TLS owner cell
    // ((pid << 16 | tid) with the WAITING bit clear; the KERNEL pid is 1996
    // = 0x7CC)
    EXPECT_EQ(ql.mem().read_ptr(0x2200, 4), 0x80000000u);
    EXPECT_EQ(ql.mem().read_ptr(0x2204, 4), 0x07CC0001u);
    // B (created, never locked): the mutex-free owner
    EXPECT_EQ(ql.mem().read_ptr(0x2208, 4), 0x80000000u);
    EXPECT_EQ(ql.mem().read_ptr(0x220C, 4), 0u);
}

// the clock_cycles flow: the kernel returns the core's free-running counter
// as the nanosecond wall clock (the upstream's simplification) in R0, which
// the fixture stores into a second scratch cell — the pre-poisoned marker
// proves the dispatcher wrote the return register
