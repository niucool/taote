// Ported from qiling/os/freebsd/syscall.py — the freebsd-specific syscall
// handlers (the deltas over the posix set). The delegating handlers ride the
// posix implementations verbatim.
#ifndef QILING_OS_FREEBSD_SYSCALL_HPP
#define QILING_OS_FREEBSD_SYSCALL_HPP

#include "qiling/os/posix/syscall.hpp"

namespace qiling {
namespace os {
namespace freebsd {

// syscall.py register_freebsd_syscalls: the freebsd-specific names land in
// the shared static registry (the freebsd's map_syscall resolves these names)
void register_freebsd_syscalls();

}  // namespace freebsd
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_FREEBSD_SYSCALL_HPP
