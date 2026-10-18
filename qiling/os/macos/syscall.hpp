// Ported from qiling/os/macos/syscall.py — the macos-specific handlers.
// The first slice: the mach self-trap family (mach_reply_port,
// thread_self_trap, task_self_trap, host_self_trap) + the simple posix-
// adjacent stubs (csops, getentropy).
#ifndef QILING_OS_MACOS_SYSCALL_HPP
#define QILING_OS_MACOS_SYSCALL_HPP

namespace qiling {
namespace os {
namespace macos {

void register_macos_syscalls();

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_SYSCALL_HPP
