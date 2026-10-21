#include "qiling/os/windows/thread.hpp"

#include "qiling/core.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace windows {

namespace {
std::uint64_t id_counter_ = 0;
std::uint64_t next_thread_id() {
    return id_counter_++;
}
}  // namespace

QlWindowsThread::QlWindowsThread(Qiling* ql, ThreadStatus status)
    : QlThread(ql), id_(next_thread_id()), status_(status) {}

void QlWindowsThread::reset_id_sequence() {
    // thread.py: QlWindowsThread.ID = 0 (the module-load state; the test
    // determinism helper: the C++ static persists across the tests, the
    // python module reload implicitly resets it)
    id_counter_ = 0;
}

std::unique_ptr<QlWindowsThread> QlWindowsThread::create(Qiling* ql, std::uint64_t stack_size,
                                                         std::uint64_t func_addr, std::uint64_t func_params,
                                                         ThreadStatus status) {
    auto* os = static_cast<os::windows::QlOsWindows*>(&ql->os());
    auto thread = std::unique_ptr<QlWindowsThread>(new QlWindowsThread(ql, status));

    // thread.py create: the new stack lives on the os heap; the return
    // address lands at the top (the thread-ret address comes from the
    // thread manager once the os wires it)
    const auto new_stack = os->heap().alloc(stack_size) + stack_size;

    const auto saved = ql->arch().regs().save();
    std::map<std::string, std::uint64_t> prepared(saved.begin(), saved.end());

    const auto ret_addr = os->thread_manager_ret_addr();
    if (ret_addr != 0) {
        ql->mem().write_ptr(new_stack - (ql->arch().bits() / 8), ret_addr);
    }

    if (ql->arch().type() == QL_ARCH::X86) {
        ql->mem().write_ptr(new_stack, func_params);
        prepared["eip"] = func_addr;
        prepared["ebp"] = new_stack - 4;
        prepared["esp"] = new_stack - 4;
    } else if (ql->arch().type() == QL_ARCH::X8664) {
        prepared["rcx"] = func_params;
        prepared["rip"] = func_addr;
        prepared["rbp"] = new_stack - 8;
        prepared["rsp"] = new_stack - 8;
    }

    thread->saved_context_ = std::move(prepared);
    return thread;
}

void QlWindowsThread::suspend() {
    // thread.py suspend: snapshot the live register state
    const auto saved = ql_->arch().regs().save();
    saved_context_.clear();
    saved_context_.insert(saved.begin(), saved.end());
}

void QlWindowsThread::resume() {
    // thread.py resume: restore the saved context and mark running
    if (!saved_context_.empty()) {
        ql_->arch().regs().restore(saved_context_);
    }
    status_ = ThreadStatus::Running;
}

std::optional<std::uint64_t> QlWindowsThread::get_tls(std::uint64_t index) const {
    const auto it = tls_.find(index);
    return it == tls_.end() ? std::nullopt : std::optional<std::uint64_t>(it->second);
}

bool QlWindowsThread::has_waitfor() const {
    for (const auto* thread : waitfor_) {
        if (!thread->is_stop()) {
            return true;
        }
    }
    return false;
}

// ---- QlWindowsThreadManagement ----

QlWindowsThreadManagement::QlWindowsThreadManagement(Qiling* ql, QlWindowsThread* cur_thread)
    : ql_(ql), cur_thread_(cur_thread) {
    // thread.py sets threads = [cur_thread] here and the os does not append the
    // main thread again. The port both pushed here *and* had the os call
    // append(), so the main thread sat in threads_ twice: the round robin then
    // "switched" to the main thread itself, suspending and immediately resuming
    // it — which is how a run reached its own context restore and the eip
    // truncation above. Ownership comes from append() (windows.cpp holds the
    // unique_ptr), so the ctor only records cur_thread_.
    (void)cur_thread;
}

// thread.py __init__ allocates the thread return-address cell from the windows
// heap, and the os builds this manager *before* the PE loader lays the PEB
// (whose ProcessParameters/ProcessHeap chunks come from the same heap) - so
// allocating it later shifts every subsequent chunk by 8 bytes. The os ctor
// calls this once its heap is up; install_hook keeps its own guard for the
// engine-less builds.
void QlWindowsThreadManagement::alloc_ret_addr(qiling::QlMemoryHeap& heap) {
    if (thread_ret_addr_ == 0) {
        thread_ret_addr_ = heap.alloc(8);
    }
}

void QlWindowsThreadManagement::install_hook() {
    if (scheduler_hook_.has_value()) {
        return;  // idempotent: run() may install it after a nested drive
    }
    // thread.py __init__: self.thread_ret_addr = os.heap.alloc(8) rides the
    // ctor; the port defers the alloc here so the pure-logic tests can build
    // the manager without an engine (the install_hook runs from the os setup
    // where the heap is live)
    if (thread_ret_addr_ == 0 && ql_ != nullptr) {
        auto* os = static_cast<os::windows::QlOsWindows*>(&ql_->os());
        thread_ret_addr_ = os->heap().alloc(8);
    }

    // thread.py: write the nop sled at the thread return address and hook the
    // code stream with the scheduler
    if (thread_ret_addr_ != 0) {
        const std::vector<std::uint8_t> nops(8, 0x90);
        ql_->mem().write(thread_ret_addr_, nops);
    }

    auto* self = this;
    scheduler_hook_ = ql_->hook_code([self](std::uint64_t address, std::uint32_t size) -> int {
        return self->on_hook(address, size);
    });
}

int QlWindowsThreadManagement::on_hook(std::uint64_t address, std::uint32_t size) {
    (void)size;

    if (address == thread_ret_addr_) {
        cur_thread_->stop();
    } else {
        ++icount_;
    }

    const bool switched = do_schedule();

    // thread.py gets the switch for free: its threads are gevent greenlets, so
    // resuming one is a host-level context switch. Here the registers are a
    // copy the engine reads at the *next* instruction it retires, so restoring
    // another thread's context mid-stream changes nothing — unicorn keeps
    // running the retired instruction stream and the child never starts at its
    // entry (measured: only thread id 0 was ever observed). The switch
    // therefore ends the emulation and hands the resumed thread's pc to the run
    // loop's restart target, the same facility the SEH dispatch uses.
    if (switched && ql_ != nullptr) {
        auto* os = static_cast<os::windows::QlOsWindows*>(&ql_->os());
        os->set_run_retarget(ql_->arch().regs().arch_pc());
        ql_->emu_stop();
        return static_cast<int>(QL_HOOK_BLOCK);
    }

    // thread.py: when another thread resumed, skip the remaining hooks of the
    // current address to avoid running them with the new context
    return 0;
}

void QlWindowsThreadManagement::release_hooks() {
    // the teardown helper: the ~Qiling clears the arch's uc handle before the
    // os members destruct, so the scheduler hook releases explicitly while
    // the engine is still alive
    if (scheduler_hook_.has_value()) scheduler_hook_->remove();
}

void QlWindowsThreadManagement::append(std::unique_ptr<QlWindowsThread> thread) {
    owned_.push_back(std::move(thread));
    threads_.push_back(owned_.back().get());
}

bool QlWindowsThreadManagement::do_schedule() {
    // thread.py do_schedule: the round-robin pass over the other threads
    const bool need_schedule = cur_thread_->is_stop() || (icount_ % TIME_SLICE) == 0;
    bool switched = false;

    if (need_schedule) {
        for (std::size_t i = 1; i < threads_.size(); ++i) {
            const auto next_id = (static_cast<std::size_t>(cur_thread_->get_id()) + i) % threads_.size();
            auto* next_thread = threads_[next_id];

            if (next_thread->status() == ThreadStatus::Running && !next_thread->has_waitfor()) {
                if (!cur_thread_->is_stop()) {
                    cur_thread_->suspend();
                }

                next_thread->resume();
                cur_thread_ = next_thread;
                switched = true;
                break;
            }
        }
    }

    return switched;
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
