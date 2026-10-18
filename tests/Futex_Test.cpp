// QlLinuxFutexManagement suite - the futex.py bookkeeping exercised in
// isolation (the gevent-based thread scheduling machinery defers; the sched_cb
// closures are invoked manually here, mirroring what the future thread
// management run loop will do).
#include <gtest/gtest.h>

#include <filesystem>

#include "qiling/core.hpp"
#include "qiling/os/linux/futex.hpp"
#include "qiling/os/linux/thread.hpp"

using namespace qiling;

namespace {

Qiling make_shellcode_qiling() {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_futex_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    return Qiling{options};
}

}  // namespace

TEST(FutexManagement, WaitRejectsMismatchedValue) {
    auto ql = make_shellcode_qiling();

    constexpr std::uint64_t uaddr = 0x1002000;
    ql.mem().write_ptr(uaddr, 1234, 4);

    os::linux::QlLinuxThread thread(&ql, 0, 0);
    os::linux::QlLinuxFutexManagement futexm;

    // the value at uaddr (1234) does not match the expected (99)
    EXPECT_EQ(futexm.futex_wait(ql, uaddr, thread, 99), -11);

    // nothing queued
    EXPECT_TRUE(futexm.wait_list().empty());
}

TEST(FutexManagement, WaitQueuesEntryAndWakeNotifies) {
    auto ql = make_shellcode_qiling();

    constexpr std::uint64_t uaddr = 0x1002000;
    ql.mem().write_ptr(uaddr, 1234, 4);

    os::linux::QlLinuxThread waiter(&ql, 0, 0);
    os::linux::QlLinuxFutexManagement futexm;

    // the wait queued the entry and parked the thread on the event (the
    // driver-model adaptation of the gevent wait)
    EXPECT_EQ(futexm.futex_wait(ql, uaddr, waiter, 1234), 0);
    ASSERT_EQ(futexm.wait_list().size(), 1u);
    EXPECT_EQ(futexm.wait_list().at(uaddr).size(), 1u);
    EXPECT_EQ(waiter.status(), os::linux::THREAD_STATUS_BLOCKING);
    EXPECT_NE(waiter.block_event(), nullptr);

    // the waker thread's sched_cb notifies the queued events
    os::linux::QlLinuxThread waker(&ql, 0, 0);
    EXPECT_EQ(futexm.futex_wake(ql, uaddr, waker, 1), 1);
    ASSERT_NE(waker.sched_cb(), nullptr);

    // the future thread-management run loop invokes the sched callbacks:
    // the wake notify sets the event, the parked waiter re-admits (the
    // driver-model readiness check is the event is_set poll)
    waker.sched_cb()();
    EXPECT_TRUE(waiter.block_event()->is_set());
    EXPECT_TRUE(waiter.ready());
}

TEST(FutexManagement, WakeCountAndBitsetFiltering) {
    auto ql = make_shellcode_qiling();

    constexpr std::uint64_t uaddr = 0x1002000;
    ql.mem().write_ptr(uaddr, 7, 4);

    os::linux::QlLinuxFutexManagement futexm;

    // three waiters: two on the ANY bitset, one on the 0x1 bitset
    os::linux::QlLinuxThread t1(&ql, 0, 0);
    os::linux::QlLinuxThread t2(&ql, 0, 0);
    os::linux::QlLinuxThread t3(&ql, 0, 0);
    EXPECT_EQ(futexm.futex_wait(ql, uaddr, t1, 7), 0);
    EXPECT_EQ(futexm.futex_wait(ql, uaddr, t2, 7), 0);
    EXPECT_EQ(futexm.futex_wait(ql, uaddr, t3, 7, 0x1), 0);

    // the wake of 2 (the ANY bitset): the first two match
    os::linux::QlLinuxThread waker(&ql, 0, 0);
    EXPECT_EQ(futexm.futex_wake(ql, uaddr, waker, 2), 2);

    // one entry remains (the bitset-filtered waiter); a 0x1-bitset wake
    // collects it
    os::linux::QlLinuxThread waker2(&ql, 0, 0);
    EXPECT_EQ(futexm.futex_wake(ql, uaddr, waker2, 1, 0x1), 1);

    // the queue drained
    EXPECT_TRUE(futexm.wait_list().empty());

    // waking an empty queue reports none
    os::linux::QlLinuxThread waker3(&ql, 0, 0);
    EXPECT_EQ(futexm.futex_wake(ql, uaddr, waker3, 4), 0);
}
