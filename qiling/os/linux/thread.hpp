// Ported from qiling/os/linux/thread.py — QlLinuxThread. The upstream class
// rides gevent Greenlets (the cooperative run loop in QlLinuxThreadManagement);
// the port declares the same attribute surface (the id, the status, the sched
// callback, the child-tid addresses) over the QlThread base. The context-
// switching run machinery lands with the thread-management slice
// (PORT_PLAN.md 5.3); the futex slice consumes only the sched_cb surface.
#ifndef QILING_OS_LINUX_THREAD_HPP
#define QILING_OS_LINUX_THREAD_HPP

#include <cstdint>
#include <functional>

#include "qiling/os/thread.hpp"

namespace qiling {
namespace os {
namespace linux {

// thread.py: the thread status constants
enum ThreadStatus {
    THREAD_STATUS_NOT_STARTED = 1,
    THREAD_STATUS_RUNNING = 2,
    THREAD_STATUS_FAILED = 3,
    THREAD_STATUS_STOPPED = 4,
    THREAD_STATUS_SUSPEND = 5,
};

class QlLinuxThread : public QlThread {
public:
    explicit QlLinuxThread(Qiling* ql, std::uint64_t start_address, std::uint64_t exit_point,
                           void* context = nullptr, std::uint64_t set_child_tid_addr = 0,
                           std::int64_t thread_id = -1);

    // thread.py get_id: the assigned (or auto-incremented) thread id
    std::uint64_t get_id() const override { return thread_id_; }

    // the run machinery defers with the thread-management slice
    void exit() override {}
    void stop() override {}

    // thread.py sched_cb property: the callback the scheduler fires when the
    // thread resumes (the futex wait/wake install these)
    const std::function<void()>& sched_cb() const noexcept { return sched_cb_; }
    void set_sched_cb(std::function<void()> cb) { sched_cb_ = std::move(cb); }

    std::uint64_t start_address() const noexcept { return start_address_; }
    std::uint64_t exit_point() const noexcept { return exit_point_; }
    ThreadStatus status() const noexcept { return status_; }

    // the robust-list / child-tid attributes (set by set_robust_list and the
    // clone flags; the bookkeeping is complete, the consumers defer)
    std::uint64_t robust_list_head_ptr() const noexcept { return robust_list_head_ptr_; }
    void set_robust_list(std::uint64_t ptr, std::uint64_t len) {
        robust_list_head_ptr_ = ptr;
        robust_list_head_len_ = len;
    }

private:
    std::uint64_t thread_id_ = 0;
    std::uint64_t start_address_ = 0;
    std::uint64_t exit_point_ = 0;
    void* saved_context_ = nullptr;
    ThreadStatus status_ = THREAD_STATUS_RUNNING;
    std::uint64_t return_val_ = 0;
    std::function<void()> sched_cb_;

    std::uint64_t set_child_tid_address_ = 0;
    std::uint64_t clear_child_tid_address_ = 0;
    std::uint64_t robust_list_head_ptr_ = 0;
    std::uint64_t robust_list_head_len_ = 0;
};

}  // namespace linux
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_LINUX_THREAD_HPP
