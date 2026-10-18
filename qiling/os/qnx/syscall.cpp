// Ported from qiling/os/qnx/syscall.py — the QNX kernel-call handlers. The
// slice carries the channel_create and the thread_destroy (the qnx exit
// path); the message/sync/interrupt families land with their fixtures.
#include "qiling/os/qnx/syscall.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/qnx.hpp"

namespace qiling {
namespace os {
namespace qnx {

namespace {

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

}  // namespace

void register_qnx_syscalls() {
    auto& registry = posix::SyscallRegistry::instance();

    registry.register_syscall({"channel_create", {PARAM_INTN}, syscall_channel_create});
    registry.register_syscall({"thread_destroy", {PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_thread_destroy});
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
