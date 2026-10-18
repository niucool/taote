// Ported from qiling/os/linux/thread.py - QlLinuxThread and
// QlLinuxThreadManagement.
//
// OQ 10 resolution (the D18 decision): the upstream gevent machinery is
// cooperative - the greenlets interleave emu_start slices on a single host
// thread and a single uc engine (the "never give up control in unicorn
// context" rule; the switches happen only after emu_start returns). The port
// mirrors that with a cooperative driver-loop scheduler: the management owns
// the thread list, runs each thread in count-bounded emu_start slices
// (count=32337, the upstream constant), and the futex/yield/exit callbacks
// only RECORD the thread's post-slice state. No host threads, no fibers: the
// uc context save/restore plus the per-arch TLS carry the thread state.
#ifndef QILING_OS_LINUX_THREAD_HPP
#define QILING_OS_LINUX_THREAD_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "qiling/os/thread.hpp"
#include "qiling/os/linux/futex.hpp"

namespace qiling {

class Qiling;
class QlFutexEvent;

namespace os {
namespace linux {

// thread.py: the thread status constants
enum ThreadStatus {
    THREAD_STATUS_NOT_STARTED = 1,
    THREAD_STATUS_RUNNING = 2,
    THREAD_STATUS_FAILED = 3,
    THREAD_STATUS_STOPPED = 4,
    THREAD_STATUS_SUSPEND = 5,
    // the driver-model extension: the thread parked on a futex event (the
    // upstream marks this BLOCKING through the gevent hub; the status
    // constant rides the same vocabulary)
    THREAD_STATUS_BLOCKING = 6,
    THREAD_STATUS_TERMINATED = 7,
};

class QlLinuxThreadManagement;

// thread.py QlLinuxThread - the driver-loop scheduler's thread record
class QlLinuxThread : public QlThread {
public:
    explicit QlLinuxThread(Qiling* ql, std::uint64_t start_address, std::uint64_t exit_point,
                           void* context = nullptr, std::uint64_t set_child_tid_addr = 0,
                           std::int64_t thread_id = -1);

    // thread.py get_id: the assigned (or auto-incremented) thread id
    std::uint64_t get_id() const override { return thread_id_; }

    // the gevent run machinery defers with the driver-loop management (the
    // stop marks TERMINATED; the exit is a no-op shell)
    void exit() override {}
    void stop() override { status_ = THREAD_STATUS_TERMINATED; }

    // friend: the management drives the slices and the retire sweeps
    friend class QlLinuxThreadManagement;

    // thread.py sched_cb property: the callback the scheduler fires after
    // each emu_start slice (the futex/yield/exit handlers install these from
    // inside the uc callbacks; the "never yield in UC context" rule)
    const std::function<void()>& sched_cb() const noexcept { return sched_cb_; }
    void set_sched_cb(std::function<void()> cb) { sched_cb_ = std::move(cb); }

    std::uint64_t start_address() const noexcept { return start_address_; }
    void set_start_address(std::uint64_t addr) { start_address_ = addr; }
    std::uint64_t exit_point() const noexcept { return exit_point_; }
    void set_exit_point(std::uint64_t addr) { exit_point_ = addr; }
    ThreadStatus status() const noexcept { return status_; }
    void set_status(ThreadStatus s) { status_ = s; }

    // the exit code carried by the terminating thread (the _sched_cb_exit
    // sets it on the thread; the management surfaces it on the os)
    int exit_code() const noexcept { return exit_code_; }
    void set_exit_code(int code) { exit_code_ = code; }

    // the driver-model block state: the thread parked on a futex event (the
    // management skips it until the event sets)
    QlFutexEvent* block_event() const noexcept { return block_event_; }
    void block_on(QlFutexEvent* event) {
        block_event_ = event;
        status_ = THREAD_STATUS_BLOCKING;
    }
    void unblock() {
        block_event_ = nullptr;
        status_ = THREAD_STATUS_RUNNING;
    }
    bool ready() const noexcept {
        return status_ != THREAD_STATUS_TERMINATED &&
               (block_event_ == nullptr || block_event_->is_set());
    }

    // the robust-list / child-tid attributes (set by set_robust_list and the
    // clone flags)
    std::uint64_t robust_list_head_ptr() const noexcept { return robust_list_head_ptr_; }
    void set_robust_list(std::uint64_t ptr, std::uint64_t len) {
        robust_list_head_ptr_ = ptr;
        robust_list_head_len_ = len;
    }
    std::uint64_t clear_child_tid_address() const noexcept { return clear_child_tid_address_; }
    void set_clear_child_tid_address(std::uint64_t addr) { clear_child_tid_address_ = addr; }

    // thread.py spawn: the per-arch thread factory (the x86-64 variant
    // carries the FS_BASE TLS; the other arches land with their slices)
    static std::unique_ptr<QlLinuxThread> spawn(Qiling* ql, std::uint64_t start_address,
                                                std::uint64_t exit_point, void* context = nullptr,
                                                std::uint64_t set_child_tid_addr = 0,
                                                std::int64_t thread_id = -1);

    // thread.py _run body, one slice: restore, the bounded emu_start
    // (count=32337), save, fire the sched callback. Returns false when the
    // thread finished (TERMINATED or the pc reached the exit point).
    bool run_slice(std::uint64_t exit_point, std::uint64_t count);

protected:
    // thread.py save/restore: the uc context plus the per-arch TLS. The base
    // covers the context only; the per-arch subclasses extend.
    virtual void save();
    virtual void restore();

    // thread.py _on_stop: the CLONE_CHILD_CLEARTID semantics - zero the
    // clear_child_tid word and wake one futex waiter on it (the notify runs
    // directly: no next sched_cb exists for a stopped thread)
    void on_stop();

    std::uint64_t thread_id_ = 0;
    std::uint64_t start_address_ = 0;
    std::uint64_t exit_point_ = 0;
    void* saved_context_ = nullptr;
    ThreadStatus status_ = THREAD_STATUS_RUNNING;
    std::uint64_t return_val_ = 0;
    int exit_code_ = 0;
    std::function<void()> sched_cb_;

    std::uint64_t set_child_tid_address_ = 0;
    std::uint64_t clear_child_tid_address_ = 0;
    std::uint64_t robust_list_head_ptr_ = 0;
    std::uint64_t robust_list_head_len_ = 0;

    QlFutexEvent* block_event_ = nullptr;
};

// thread.py QlLinuxX8664Thread - the TLS rides the IA32_FS_BASE MSR
class QlLinuxX8664Thread final : public QlLinuxThread {
public:
    using QlLinuxThread::QlLinuxThread;

    std::uint64_t tls() const noexcept { return tls_; }
    void set_thread_tls(std::uint64_t tls_addr);

protected:
    void save() override;
    void restore() override;

private:
    std::uint64_t tls_ = 0;
};

// thread.py QlLinuxThreadManagement - the cooperative driver-loop scheduler
class QlLinuxThreadManagement {
public:
    explicit QlLinuxThreadManagement(Qiling& ql) : ql_(ql) {}

    // thread.py add_thread: registers the thread (the ownership transfers)
    void add_thread(std::unique_ptr<QlLinuxThread> t);

    // thread.py stop_thread: TERMINATED + the removal; the main thread's stop
    // stops the world
    void stop_thread(QlLinuxThread* t);

    // thread.py stop: stop the world (emu_stop + all threads terminated)
    void stop();

    // thread.py run: the _prepare_lib_patch loader pass (when an interpreter
    // is present) + the main thread spawn + the driver loop
    void run();

    QlLinuxThread* cur_thread() const noexcept { return cur_thread_; }
    QlLinuxThread* main_thread() const noexcept { return main_thread_; }
    std::size_t thread_count() const noexcept { return threads_.size(); }

    // the bounded stepping seam: up to max_slices ready-thread slices; breaks
    // early when the world stops or the list drains (the deadlock detection
    // point surfaces as false)
    std::size_t run_for(std::size_t max_slices);

private:
    // one scheduling step: the next ready thread's emu_start slice + the
    // post-slice retire sweep; false when no thread is ready (the deadlock
    // detection point)
    bool run_ready();

    Qiling& ql_;
    std::vector<std::unique_ptr<QlLinuxThread>> threads_;
    std::vector<std::unique_ptr<QlLinuxThread>> dead_;  // the pending retire
    std::size_t cursor_ = 0;
    QlLinuxThread* cur_thread_ = nullptr;
    QlLinuxThread* main_thread_ = nullptr;
    bool stopped_ = false;
};

}  // namespace linux
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_LINUX_THREAD_HPP
