// Windows clipboard/fiber/thread suites — PORT_PLAN.md §10 Phase 4 (the
// subsystems testable without a Windows rootfs: the clipboard state machine,
// the fiber table, and the round-robin thread scheduler).
#include <gtest/gtest.h>

#include <string>

#include "qiling/os/windows/clipboard.hpp"
#include "qiling/os/windows/fiber.hpp"
#include "qiling/os/windows/thread.hpp"

using namespace qiling;
using namespace qiling::os::windows;

// ---- clipboard (clipboard.py) ----

TEST(Clipboard, OpenCloseLifecycle) {
    Clipboard cb(nullptr);

    EXPECT_TRUE(cb.open(0x1111));
    EXPECT_TRUE(cb.is_locked_by(0x1111));

    // a second window cannot take the lock
    EXPECT_FALSE(cb.open(0x2222));

    // the same window may re-open
    EXPECT_TRUE(cb.open(0x1111));

    EXPECT_TRUE(cb.close());
    EXPECT_FALSE(cb.is_locked());

    // closing twice fails with QL_ERROR_CLIPBOARD_NOT_OPEN
    EXPECT_FALSE(cb.close());
    EXPECT_EQ(cb.last_error(), QL_ERROR_CLIPBOARD_NOT_OPEN);
}

TEST(Clipboard, FormatAvailability) {
    Clipboard cb(nullptr);

    EXPECT_TRUE(cb.format_available(QL_CF_TEXT));
    EXPECT_TRUE(cb.format_available(QL_CF_UNICODETEXT));
    EXPECT_TRUE(cb.format_available(QL_CF_BITMAP));
    EXPECT_FALSE(cb.format_available(0xDEAD));
}

TEST(Clipboard, SetDataStoresContent) {
    Clipboard cb(nullptr);
    cb.force_lock(0x1111);

    // the api hook resolves the guest string and hands the bytes over
    cb.set_data_raw(QL_CF_TEXT, "clipboard payload");
    EXPECT_EQ(cb.data(), "clipboard payload");
}

// ---- fiber (fiber.py) ----

TEST(FiberManager, AllocFreeLifecycle) {
    FiberManager mgr(nullptr);

    const auto idx = mgr.alloc();
    EXPECT_EQ(mgr.size(), 1u);

    EXPECT_TRUE(mgr.free(idx));
    EXPECT_EQ(mgr.size(), 0u);

    // freeing an unknown index flags QL_ERROR_INVALID_PARAMETER
    EXPECT_FALSE(mgr.free(idx + 1));
    EXPECT_EQ(mgr.last_error(), QL_ERROR_INVALID_PARAMETER);
}

TEST(FiberManager, SetGetRoundTrip) {
    FiberManager mgr(nullptr);

    const auto idx = mgr.alloc();
    EXPECT_TRUE(mgr.set(idx, 0xCAFEBABE));
    EXPECT_EQ(mgr.get(idx), 0xCAFEBABEull);

    // get on an unknown index flags the error; get_noerr stays silent
    EXPECT_EQ(mgr.get(idx + 1), 0u);
    EXPECT_EQ(mgr.last_error(), QL_ERROR_INVALID_PARAMETER);
    mgr.clear_last_error();
    EXPECT_EQ(mgr.get_noerr(idx + 1), 0u);
    EXPECT_EQ(mgr.last_error(), 0u);
}

// ---- thread scheduler (thread.py) ----

TEST(WindowsThread, SchedulingSkipsTerminatedCandidates) {
    // the slice expires, but the only other thread is terminated: the
    // scheduler finds no candidate and stays on the current thread
    // (a live two-thread rotation needs the emulation-backed suspend/resume,
    // exercised through the fiber slice)
    QlWindowsThread main_t(nullptr, ThreadStatus::Running);
    QlWindowsThread worker(nullptr, ThreadStatus::Terminated);

    QlWindowsThreadManagement mgr(nullptr, &main_t);
    mgr.append(&worker);

    for (std::uint64_t i = 0; i < QlWindowsThreadManagement::TIME_SLICE; ++i) {
        EXPECT_FALSE(mgr.do_schedule());
        EXPECT_EQ(mgr.cur_thread(), &main_t);
    }
}

TEST(WindowsThread, ReadyStatusSurface) {
    // the THREAD_STATUS surface (thread.py: READY/RUNNING/TERMINATED)
    QlWindowsThread thread(nullptr, ThreadStatus::Ready);
    EXPECT_EQ(thread.status(), ThreadStatus::Ready);
    EXPECT_FALSE(thread.is_stop());

    thread.stop();
    EXPECT_TRUE(thread.is_stop());
}

TEST(WindowsThread, StopAndWaitfor) {
    QlWindowsThread main_t(nullptr);
    QlWindowsThread worker(nullptr);

    EXPECT_FALSE(worker.is_stop());
    worker.stop();
    EXPECT_TRUE(worker.is_stop());

    // a thread waiting on a stopped thread has no live wait-for
    main_t.waitfor(worker);
    EXPECT_FALSE(main_t.has_waitfor());
}
