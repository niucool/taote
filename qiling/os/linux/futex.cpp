// Ported from qiling/os/linux/futex.py — see the header note. The value
// check reads 4 bytes (unpack32) at the uaddr; the wait queues
// (bitset, thread, event) under the address; the wake pops up to `number`
// bitset-matching entries and installs a notify callback on the waker.
#include "qiling/os/linux/futex.hpp"

#include <cstdio>
#include <utility>

#include "qiling/core.hpp"
#include "qiling/os/linux/thread.hpp"

namespace qiling {
namespace os {
namespace linux {

void QlFutexEvent::set() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flag_ = true;
    }
    cv_.notify_all();
}

void QlFutexEvent::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    flag_ = false;
}

void QlFutexEvent::wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return flag_; });
}

// futex.py futex_wait: EAGAIN = 11
namespace {
constexpr int kEAGAIN = 11;
}  // namespace

int QlLinuxFutexManagement::futex_wait(Qiling& ql, std::uint64_t uaddr, QlLinuxThread& t,
                                       std::uint32_t val, std::uint32_t bitset) {
    // unpack32 the uaddr value
    const auto uaddr_value = static_cast<std::uint32_t>(ql.mem().read_ptr(uaddr, 4));
    if (uaddr_value != val) {
        return -kEAGAIN;
    }

    // BISECT: the park point (the in-hook stop placement)
    std::fprintf(stderr, "[fwait] uaddr=%llx val=%x stop\n",
                 static_cast<unsigned long long>(uaddr), uaddr_value);
    ql.emu_stop();

    auto event = std::make_shared<QlFutexEvent>();
    auto& queue = wait_list_[uaddr];
    queue.push_back(WaitEntry{bitset, &t, event});

    // the wait sched_cb: the upstream blocks the greenlet (gevent event.wait
    // yields to the hub); the driver model parks the thread on the event -
    // the management skips it until the event sets (the OQ 10 adaptation)
    t.block_on(event.get());

    return 0;
}

std::vector<std::pair<QlLinuxThread*, std::shared_ptr<QlFutexEvent>>>
QlLinuxFutexManagement::get_futex_wake_list(Qiling& ql, std::uint64_t addr, int number,
                                            std::uint32_t bitset) {
    (void)ql;
    std::vector<std::pair<QlLinuxThread*, std::shared_ptr<QlFutexEvent>>> wakes;

    const auto it = wait_list_.find(addr);
    if (it == wait_list_.end() || number == 0) {
        return wakes;
    }

    auto& queue = it->second;
    if (static_cast<int>(queue.size()) < number) {
        number = static_cast<int>(queue.size());
    }
    for (int i = 0; i < number; ++i) {
        auto entry = std::move(queue.front());
        queue.pop_front();
        if ((entry.bitset & bitset) != 0) {
            wakes.emplace_back(entry.thread, std::move(entry.event));
        }
    }

    if (queue.empty()) {
        wait_list_.erase(it);
    }
    return wakes;
}

int QlLinuxFutexManagement::futex_wake(Qiling& ql, std::uint64_t uaddr, QlLinuxThread& t, int number,
                                       std::uint32_t bitset) {
    ql.emu_stop();

    auto wakes = get_futex_wake_list(ql, uaddr, number, bitset);
    const int count = static_cast<int>(wakes.size());

    // the wake sched_cb: notify the collected events, then yield
    t.set_sched_cb([wakes = std::move(wakes)]() {
        for (const auto& [thread, event] : wakes) {
            (void)thread;
            event->set();
        }
    });

    return count;
}

}  // namespace linux
}  // namespace os
}  // namespace qiling
