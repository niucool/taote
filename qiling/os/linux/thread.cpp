// Ported from qiling/os/linux/thread.py - see the header note. The driver
// loop runs count-bounded emu_start slices (count=32337, the upstream
// constant) over a single uc engine; the futex/yield/exit callbacks record
// the post-slice state instead of blocking the host thread.
#include "qiling/os/linux/thread.hpp"

#include "qiling/core.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/os/linux/futex.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"
#include "qiling/loader/loader.hpp"
#include "qiling/loader/elf.hpp"

namespace qiling {
namespace os {
namespace linux {

namespace {

// thread.py LINUX_THREAD_ID global
std::uint64_t linux_thread_id = 2000;

// thread.py _run: the instruction-count slice bound
constexpr std::uint64_t kSliceCount = 32337;

}  // namespace

QlLinuxThread::QlLinuxThread(Qiling* ql, std::uint64_t start_address, std::uint64_t exit_point,
                             void* context, std::uint64_t set_child_tid_addr, std::int64_t thread_id)
    : QlThread(ql),
      start_address_(start_address),
      exit_point_(exit_point),
      saved_context_(context) {
    if (thread_id < 0) {
        // thread.py new_thread_id
        thread_id_ = linux_thread_id++;
    } else {
        thread_id_ = static_cast<std::uint64_t>(thread_id);
    }

    // thread.py: set_child_tid writes the thread id at the address (the very
    // first thing a CLONE_CHILD_SETTID thread does)
    if (set_child_tid_addr != 0) {
        set_child_tid_address_ = set_child_tid_addr;
        ql->mem().write_ptr(set_child_tid_addr, static_cast<std::int64_t>(thread_id_), 4);
    }
}

std::unique_ptr<QlLinuxThread> QlLinuxThread::spawn(Qiling* ql, std::uint64_t start_address,
                                                    std::uint64_t exit_point, void* context,
                                                    std::uint64_t set_child_tid_addr,
                                                    std::int64_t thread_id) {
    // the per-arch factory: the x86-64 variant carries the FS_BASE TLS (the
    // other arch subclasses land with their slices)
    if (ql->arch().type() == QL_ARCH::X8664) {
        return std::make_unique<QlLinuxX8664Thread>(ql, start_address, exit_point, context,
                                                    set_child_tid_addr, thread_id);
    }
    return std::make_unique<QlLinuxThread>(ql, start_address, exit_point, context,
                                           set_child_tid_addr, thread_id);
}

void QlLinuxThread::save() {
    // thread.py save_context: the uc context snapshot
    saved_context_ = ql_->arch().save().release();
}

void QlLinuxThread::restore() {
    // thread.py restore_context: the uc context replay
    const auto* ctx = static_cast<const UcContext*>(saved_context_);
    if (ctx != nullptr) {
        ql_->arch().restore(*ctx);
    }
}

void QlLinuxThread::on_stop() {
    // thread.py _on_stop: the CLONE_CHILD_CLEARTID semantics
    if (clear_child_tid_address_ == 0) {
        return;
    }
    ql_->mem().write_ptr(clear_child_tid_address_, 0, 4);

    // the wake list consults the os futex management (the futexm lives on the
    // linux os); the notify runs directly - no next sched_cb exists
    const auto wakes =
        ql_->os().futexm()->get_futex_wake_list(*ql_, clear_child_tid_address_, 1);
    clear_child_tid_address_ = 0;
    for (auto& [thread, event] : wakes) {
        (void)thread;
        event->set();
    }
}

bool QlLinuxThread::run_slice(std::uint64_t exit_point, std::uint64_t count) {
    // thread.py _run: rewrite the status and the current thread; a resumed
    // thread drops its block state (the futex event re-admitted it)
    status_ = THREAD_STATUS_RUNNING;
    block_event_ = nullptr;

    // the first _run entry: the pc lands on the start address and the context
    // snapshots it (thread.py: arch_pc = self.start_address; save())
    if (saved_context_ == nullptr) {
        ql_->arch().regs().set_arch_pc(start_address_);
        save();
    }

    // restore the context of the currently executing thread
    restore();

    // the per-slice begin: the CURRENT pc (the restored stop point - the
    // upstream emu_start reads the arch_pc after the restore, not the
    // original start address)
    const auto start_address = ql_->arch().adjust_emu_start(ql_->arch().regs().arch_pc());
    sched_cb_ = nullptr;  // the default sched_cb: give up control (yield)

    try {
        // the known unicorn timeout issue (issue #1355) noted upstream; the
        // count bounds the slice
        ql_->emu_start(start_address, exit_point, 0, count);
    } catch (const QlErrorBase&) {
        // thread.py: emu_error + rethrow
        throw;
    }

    // thread.py save()
    save();

    // note that the callback may be set by the uc callbacks; never give up
    // control during one (the port's switch happens here, after emu_start)
    if (sched_cb_) {
        auto cb = std::move(sched_cb_);
        sched_cb_ = nullptr;
        cb();
    }

    if (status_ == THREAD_STATUS_TERMINATED || ql_->arch().regs().arch_pc() == exit_point) {
        return false;
    }
    return true;
}

void QlLinuxThreadManagement::add_thread(std::unique_ptr<QlLinuxThread> t) {
    threads_.push_back(std::move(t));
}

void QlLinuxThreadManagement::stop_thread(QlLinuxThread* t) {
    t->stop();
    for (auto it = threads_.begin(); it != threads_.end(); ++it) {
        if (it->get() == t) {
            // the deferred destruction: the thread's run_slice may still be on
            // the stack (the exit closure runs inside it) - park the ownership
            // and let the sweep retire it after the slice returns
            dead_.push_back(std::move(*it));
            threads_.erase(it);
            break;
        }
    }
    // exit the world when the main thread stops (thread.py stop_thread)
    if (t == main_thread_) {
        stop();
    }
}

void QlLinuxThreadManagement::stop() {
    // thread.py stop: stop the world
    ql_.emu_stop();
    linux_thread_id = 2000;  // thread.py: LINUX_THREAD_ID = 2000
    while (!threads_.empty()) {
        auto t = std::move(threads_.back());
        threads_.pop_back();
        t->stop();
        dead_.push_back(std::move(t));
    }
    stopped_ = true;
}

std::size_t QlLinuxThreadManagement::run_for(std::size_t max_slices) {
    std::size_t done = 0;
    while (done < max_slices && !stopped_ && !threads_.empty()) {
        if (!run_ready()) {
            break;
        }
        ++done;
    }
    if (!stopped_ && !threads_.empty()) {
        // the loop stopped without draining: the all-blocked deadlock
        throw QlErrorExecutionStop("all threads blocked; no thread can wake them");
    }
    return done;
}

void QlLinuxThreadManagement::run() {
    // thread.py _prepare_lib_patch: the loader pass when an interpreter is
    // present (elf_entry != entry_point); the elf values come from the ELF
    // loader (the thread machinery rides the ELF loader, the python
    // duck-typed access kept typed)
    const auto* loader_elf = dynamic_cast<const loader::QlLoaderELF*>(&ql_.loader());
    const std::uint64_t entry_point = ql_.loader().entry_point;
    const std::uint64_t elf_entry =
        loader_elf != nullptr ? loader_elf->elf_entry() : entry_point;
    const bool has_interp = elf_entry != entry_point;
    if (has_interp) {
        std::uint64_t entry_address = elf_entry;
        // the arm thumb entry strip lands with the arm slices
        main_thread_ = QlLinuxThread::spawn(&ql_, entry_point, entry_address).release();
        add_thread(std::unique_ptr<QlLinuxThread>(main_thread_));
        cur_thread_ = main_thread_;
        // the joinall([main], raise_error) analogue: run the loader's slices
        // to completion
        while (run_ready()) {
        }
        // the do_lib_patch + the after-load list + the exit trap land with
        // their slices (the interp fixtures exercise them through the
        // single-threaded path)
    }

    // thread.py run: the main thread spawn (elf_entry -> exit_point)
    const auto exit_point = ql_.os().exit_point();
    main_thread_ = QlLinuxThread::spawn(&ql_, elf_entry, exit_point).release();
    add_thread(std::unique_ptr<QlLinuxThread>(main_thread_));

    // the driver loop: round-robin the ready threads until the list drains
    while (!stopped_ && !threads_.empty()) {
        if (!run_ready()) {
            // no ready thread: every thread parked on a futex nobody will
            // set - the gevent LoopExit analogue
            throw QlErrorExecutionStop("all threads blocked; no thread can wake them");
        }
    }

    // the exit code surfacing (the port addition: the upstream sets the code
    // on the terminating thread; the os-level accessor feeds the run results)
    if (main_thread_ != nullptr && main_thread_->exit_code() != 0) {
        ql_.os().set_exit_code(main_thread_->exit_code());
    }
}

bool QlLinuxThreadManagement::run_ready() {
    {
        static int rr_count = 0;
        if (++rr_count > 200) {
            std::fprintf(stderr, "[probe-rr] TOO MANY ROUNDS - bailing\n");
            std::fflush(stderr);
            std::abort();
        }
        std::fprintf(stderr, "[probe-rr] round=%d threads=%zu stopped=%d\n", rr_count, threads_.size(), (int)stopped_);
        std::fflush(stderr);
    }
    std::fflush(stderr);
    // retire the threads parked by the previous slice's callbacks - outside
    // any thread's stack frame (the exit closure parks its own thread while
    // run_slice is still on the stack; the destruction must wait)
    dead_.clear();

    if (threads_.empty()) {
        return false;
    }

    // the round-robin scan: the next ready thread from the cursor
    const std::size_t n = threads_.size();
    for (std::size_t i = 0; i < n; ++i) {
        const std::size_t idx = (cursor_ + i) % n;
        auto& t = *threads_[idx];
        if (!t.ready()) {
            continue;
        }
        cursor_ = (idx + 1) % n;
        cur_thread_ = &t;
        const bool still_running = t.run_slice(ql_.os().exit_point(), kSliceCount);

        if (!still_running) {
            // the _run's break path: the clear-child-tid wake (the idempotent
            // guard makes the double-call for the exit-parked thread safe)
            t.on_stop();
            for (auto it = threads_.begin(); it != threads_.end(); ++it) {
                if (it->get() == &t) {
                    threads_.erase(it);
                    break;
                }
            }
        }
        return true;
    }

    // every thread parked: the deadlock detection
    return false;
}

void QlLinuxX8664Thread::set_thread_tls(std::uint64_t tls_addr) {
    // thread.py QlLinuxX8664Thread.set_thread_tls: the IA32_FS_BASE MSR
    tls_ = tls_addr;
    constexpr std::uint32_t IA32_FS_BASE_MSR = 0xC0000100;
    auto& intel = dynamic_cast<QlArchIntel&>(ql_->arch());
    intel.msr().write(IA32_FS_BASE_MSR, tls_);
}

void QlLinuxX8664Thread::save() {
    // thread.py save: the context plus the fsbase
    QlLinuxThread::save();
    constexpr std::uint32_t IA32_FS_BASE_MSR = 0xC0000100;
    auto& intel = dynamic_cast<QlArchIntel&>(ql_->arch());
    tls_ = intel.msr().read(IA32_FS_BASE_MSR);
}

void QlLinuxX8664Thread::restore() {
    // thread.py restore: the context then the fsbase
    QlLinuxThread::restore();
    set_thread_tls(tls_);
}

}  // namespace linux
}  // namespace os
}  // namespace qiling
