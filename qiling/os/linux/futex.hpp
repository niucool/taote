// Ported from qiling/os/linux/futex.py - QlLinuxFutexManagement. The wait
// list bookkeeping (the per-address queue of (bitset, thread, event) entries)
// and the wake collection. The gevent.Event maps onto a mutex+cv flag pair;
// the sched_cb closures the futex installs are invoked by the thread
// management run loop (deferred) - the port keeps the callback assignment
// verbatim.
#ifndef QILING_OS_LINUX_FUTEX_HPP
#define QILING_OS_LINUX_FUTEX_HPP

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace qiling {

class Qiling;

namespace os {
namespace linux {

class QlLinuxThread;

// gevent.event.Event - set/clear/is_set/wait
class QlFutexEvent {
public:
    void set();
    void clear();
    bool is_set() const noexcept { return flag_; }

    // blocks until the event sets (the gevent cooperative wait degrades to
    // the host cv wait; the single-threaded emu never blocks in practice)
    void wait();

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool flag_ = false;
};

// futex.py QlLinuxFutexManagement
class QlLinuxFutexManagement {
public:
    // futex.py FUTEX_BITSET_MATCH_ANY
    static constexpr std::uint32_t FUTEX_BITSET_MATCH_ANY = 0xffffffffu;

    // one queued waiter: the wake bitset, the owning thread, the notify event
    struct WaitEntry {
        std::uint32_t bitset = 0;
        QlLinuxThread* thread = nullptr;
        std::shared_ptr<QlFutexEvent> event;
    };

    using WaitQueue = std::deque<WaitEntry>;

    // futex.py futex_wait: the value check (mismatch -> -EAGAIN), the emu
    // stop, the queue put, the wait sched_cb; returns 0 on success
    int futex_wait(Qiling& ql, std::uint64_t uaddr, QlLinuxThread& t, std::uint32_t val,
                   std::uint32_t bitset = FUTEX_BITSET_MATCH_ANY);

    // futex.py futex_wake: the emu stop, the wake collection (up to number,
    // the bitset matching), the wake sched_cb; returns the wake count
    int futex_wake(Qiling& ql, std::uint64_t uaddr, QlLinuxThread& t, int number,
                   std::uint32_t bitset = FUTEX_BITSET_MATCH_ANY);

    // futex.py get_futex_wake_list: pops up to number entries whose bitset
    // matches (the non-matching entries drop - the upstream behaviour)
    std::vector<std::pair<QlLinuxThread*, std::shared_ptr<QlFutexEvent>>> get_futex_wake_list(
        Qiling& ql, std::uint64_t addr, int number, std::uint32_t bitset = FUTEX_BITSET_MATCH_ANY);

    const std::map<std::uint64_t, WaitQueue>& wait_list() const noexcept { return wait_list_; }

private:
    std::map<std::uint64_t, WaitQueue> wait_list_;
};

}  // namespace linux
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_LINUX_FUTEX_HPP
