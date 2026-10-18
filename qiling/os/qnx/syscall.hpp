// Ported from qiling/os/qnx/syscall.py — the QNX kernel-call handlers (the
// deltas over the posix set; the QNX surface is its own kernel API, not the
// linux table).
#ifndef QILING_OS_QNX_SYSCALL_HPP
#define QILING_OS_QNX_SYSCALL_HPP

#include "qiling/os/posix/syscall.hpp"

namespace qiling {
namespace os {
namespace qnx {

// syscall.py's qnx table: the handled kernel calls land in the shared static
// registry (the qnx map_syscall resolves these names)
void register_qnx_syscalls();

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_SYSCALL_HPP
