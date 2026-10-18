// Ported from qiling/os/qnx/syscall.py — the QNX kernel-call handlers. The
// slice carries the channel_create and the thread_destroy (the qnx exit
// path); the message/sync/interrupt families land with their fixtures.
#include "qiling/os/qnx/syscall.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/qnx.hpp"

#include <chrono>

namespace qiling {
namespace os {
namespace qnx {

namespace {

// types.py clock_types (lib/c/public/time.h)
constexpr int kClockRealtime = 0;

// syscall.py's nanosecond wall clock (the time_ns() shape)
std::uint64_t time_ns() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// syscall.py ql_syscall_channel_create: the flags are ignored; the new
// channel id is handed out from the running counter
std::optional<std::int64_t> syscall_channel_create(Qiling& ql, const std::vector<std::uint64_t>& params) {
    (void)params;  // flags

    auto& os = static_cast<QlOsQnx&>(ql.os());
    const auto chid = os.next_channel_id();
    return static_cast<std::int64_t>(chid);
}
// syscall.py ql_syscall_thread_destroy: the (-1, -1, status) request
// terminates the process with the status as the exit code
std::optional<std::int64_t> syscall_thread_destroy(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto tid = params[0];
    const auto priority = params[1];
    const auto status = params[2];

    // Requested to terminate all threads in the current process
    if (tid == 0xffffffff && priority == 0xffffffff) {
        ql.os().set_exit_code(static_cast<int>(status));
        ql.os().stop();
        // the upstream returns EOK after the stop; the port's stop unwinds
        // the emulation first, so the return register stays untouched (the
        // posix exit shape)
        return std::nullopt;
    }
    return EOK;
}

// syscall.py ql_syscall_clock_cycles: the core's free-running 64-bit counter
// — simplified to the nanosecond wall clock (the upstream's note, verbatim)
std::optional<std::int64_t> syscall_clock_cycles(Qiling& ql, const std::vector<std::uint64_t>& params) {
    (void)params;
    return static_cast<std::int64_t>(time_ns());
}

// syscall.py ql_syscall_clock_time (source: openqnx
// lib/c/support/_syspage_time.c): the CLOCK_REALTIME read writes the
// nanosecond wall clock into the caller's 8-byte cell; the set-time path
// warns and returns -1, the unknown ids raise
std::optional<std::int64_t> syscall_clock_time(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto id = params[0];
    const auto new_ptr = params[1];
    const auto old_ptr = params[2];

    // the port's clock_types cover 0..4 (CLOCK_REALTIME..CLOCK_THREAD_CPUTIME_ID)
    if (id > 4) {
        throw QlErrorNotImplemented("qnx clock_time: unknown clock id " + std::to_string(id));
    }
    if (id != kClockRealtime) {
        throw QlErrorNotImplemented("qnx clock_time: clock type " + std::to_string(id) + " not implemented");
    }
    // set time
    if (new_ptr != 0) {
        ql.log().warn("syscall_clock_time: set time not supported");
        return -1;
    }
    // get time
    if (old_ptr != 0) {
        ql.mem().write_ptr(old_ptr, time_ns(), 8);
    }

    return 0;
}

}  // namespace

void register_qnx_syscalls() {
    auto& registry = posix::SyscallRegistry::instance();

    registry.register_syscall({"channel_create", {PARAM_INTN}, syscall_channel_create});
    // clock_cycles: the special 0xFE000000 kercall id (the kercalls.h base)
    registry.register_syscall({"clock_cycles", {}, syscall_clock_cycles});
    registry.register_syscall({"clock_time", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_clock_time});
    registry.register_syscall({"thread_destroy", {PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_thread_destroy});
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
