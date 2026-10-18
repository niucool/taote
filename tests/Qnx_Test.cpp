// QlOsQnx suite — the qnx.py dialect over the posix base, ported per the
// upstream's os/qnx/ shape:
//   - the QlOsQnx(QlOsPosix) with the QNX type and the ARM32 kernel-entry
//     hook (the interrupt 2) + the R12 id-register ABI override
//   - the kercalls table dispatch (the ARM numbers, not the linux ones)
//   - the fixture-driven flows mirror the posix test style (the code blob +
//     the data region + the exit-code/memory assertions)
#include <gtest/gtest.h>

#include <filesystem>

#include "qiling/core.hpp"
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

// the clock_cycles flow: the kernel returns the core's free-running counter
// as the nanosecond wall clock (the upstream's simplification) in R0, which
// the fixture stores into a second scratch cell — the pre-poisoned marker
// proves the dispatcher wrote the return register
