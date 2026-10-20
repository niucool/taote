// Ported from qiling/os/windows/thread.py — the windows thread simulation
// (QlWindowsThread + the cooperative scheduler). The Python threads run as
// gevent greenlets over separate unicorn contexts; the C++ port keeps the same
// bookkeeping (status, wait-for lists, per-thread saved contexts, TLS) and the
// round-robin TIME_SLICE scheduler driven from the code hook.
#ifndef QILING_OS_WINDOWS_THREAD_HPP
#define QILING_OS_WINDOWS_THREAD_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "qiling/arch/arch.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/core_hooks_types.hpp"
#include "qiling/os/thread.hpp"

namespace qiling {

class Qiling;

namespace os {
namespace windows {

enum class ThreadStatus { Ready = 0, Running = 1, Terminated = 2 };

class QlWindowsThread final : public QlThread {
public:
    QlWindowsThread(Qiling* ql, ThreadStatus status = ThreadStatus::Running);

    // thread.py create: a new thread with a fresh stack and a prepared context
    static std::unique_ptr<QlWindowsThread> create(Qiling* ql, std::uint64_t stack_size, std::uint64_t func_addr,
                                                   std::uint64_t func_params, ThreadStatus status);
    // the test-facing id-sequence reset (thread.py: QlWindowsThread.ID static;
    // the python module reload resets it implicitly, the C++ static does not)
    static void reset_id_sequence();

    // QlThread surface
    std::uint64_t get_id() const override { return id_; }
    void exit() override { status_ = ThreadStatus::Terminated; }
    void stop() override { status_ = ThreadStatus::Terminated; }

    ThreadStatus status() const noexcept { return status_; }
    bool is_stop() const noexcept { return status_ == ThreadStatus::Terminated; }

    // the register context (thread.py suspend/resume over regs.save/restore)
    void suspend();
    void resume();

    // the per-thread TLS slots (thread.py tls/tls_index)
    void set_tls(std::uint64_t index, std::uint64_t value) { tls_[index] = value; }
    std::optional<std::uint64_t> get_tls(std::uint64_t index) const;
    bool has_tls(std::uint64_t index) const { return tls_.count(index) != 0; }
    void erase_tls(std::uint64_t index) { tls_.erase(index); }
    std::uint64_t tls_index() const noexcept { return tls_index_; }
    std::uint64_t bump_tls_index() noexcept { return tls_index_++; }

    // thread.py waitfor / has_waitfor
    void waitfor(QlWindowsThread& thread) { waitfor_.push_back(&thread); }
    bool has_waitfor() const;

    const std::map<std::string, std::uint64_t>& saved_context() const noexcept { return saved_context_; }

private:
    std::uint64_t id_ = 0;
    ThreadStatus status_ = ThreadStatus::Running;
    std::vector<QlWindowsThread*> waitfor_;
    std::map<std::uint64_t, std::uint64_t> tls_;
    std::uint64_t tls_index_ = 0;
    std::map<std::string, std::uint64_t> saved_context_;
};

class QlWindowsThreadManagement {
public:
    // thread.py TIME_SLICE
    static constexpr std::uint64_t TIME_SLICE = 10;

    QlWindowsThreadManagement(Qiling* ql, QlWindowsThread* cur_thread);

    // the scheduler hook body (thread.py __thread_scheduler): stops the
    // current thread at the thread-ret address, ticks the instruction counter,
    // and switches when a slice expires; returns QL_HOOK_BLOCK when switched
    int on_hook(std::uint64_t address, std::uint32_t size);

    QlWindowsThread* cur_thread() const noexcept { return cur_thread_; }
    void append(QlWindowsThread* thread) { threads_.push_back(thread); }
    const std::vector<QlWindowsThread*>& threads() const noexcept { return threads_; }

    // the ownership slot: the handlers create threads on the heap; the
    // manager keeps them alive for the process lifetime (the python side
    // rides the reference counting)
    void append(std::unique_ptr<QlWindowsThread> thread);

    std::size_t count() const noexcept { return threads_.size(); }
    std::uint64_t thread_ret_addr() const noexcept { return thread_ret_addr_; }

    // do_schedule: pick the next runnable thread; true when a switch happened
    bool do_schedule();

    void install_hook();
    // the thread.py ctor's heap.alloc(8) for the return-address cell (the os
    // ctor calls it right after building the manager)
    void alloc_ret_addr(QlMemoryHeap& heap);
    void release_hooks();
    void set_thread_ret_addr(std::uint64_t addr) noexcept { thread_ret_addr_ = addr; }

private:
    Qiling* ql_ = nullptr;
    QlWindowsThread* cur_thread_ = nullptr;
    std::vector<QlWindowsThread*> threads_;
    std::vector<std::unique_ptr<QlWindowsThread>> owned_;
    std::uint64_t icount_ = 0;
    std::uint64_t thread_ret_addr_ = 0;
    std::optional<HookRet> scheduler_hook_;
};

}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_THREAD_HPP
