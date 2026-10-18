// Ported from qiling/os/thread.py — QlThread.
//
// Python derives from gevent.Greenlet (cooperative greenlets). The C++ port
// declares the same interface over std::thread; the per-OS thread derivatives
// (the Linux clone/futex layer and the Windows fiber scheduler) provide the
// context-switching behavior in their own phases (PORT_PLAN.md 5.3 / OQ 1).
#ifndef QILING_OS_THREAD_HPP
#define QILING_OS_THREAD_HPP

#include <cstdint>
#include <string>
#include <thread>

namespace qiling {

class Qiling;

class QlThread {
public:
    explicit QlThread(Qiling* ql) : ql_(ql) {}
    virtual ~QlThread() = default;

    // like pthread_self(), the id of the current thread
    virtual std::uint64_t get_id() const = 0;

    // like pthread_exit(), terminate the current thread
    virtual void exit() = 0;

    // stop the emulation driving this thread
    virtual void stop() = 0;

protected:
    Qiling* ql_;
};

}  // namespace qiling

#endif  // QILING_OS_THREAD_HPP
