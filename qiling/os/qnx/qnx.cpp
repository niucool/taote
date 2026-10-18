// Ported from qiling/os/qnx/qnx.py — the QNX dialect. The ctor swaps the
// syscall ABI for the QNX override (the R12 id register) and installs the
// interrupt-2 hook for the ARM; the kernel-call table lands with the
// handler slice.
#include "qiling/os/qnx/qnx.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/syscall/abi.hpp"
#include "qiling/os/qnx/map_syscall.hpp"
#include "qiling/os/qnx/syscall.hpp"

#include "qiling/cc/arm.hpp"
#include "qiling/os/fcall.hpp"

namespace qiling {
namespace os {
namespace qnx {

QlOsQnx::QlOsQnx(Qiling* ql) : QlOsPosix(ql) {
    // qnx.py __init__: the QNX ARM32 ABI override (the syscall number in R12)
    if (ql->arch().type() == QL_ARCH::ARM) {
        set_syscall_abi(std::make_unique<posix::QlSyscallABIArmQnx>(ql->arch()));
        set_fcall(std::make_unique<QlFunctionCall>(std::make_unique<cc::aarch32>(ql->arch())));
    }

    register_qnx_syscalls();
    load();
}

void QlOsQnx::load() {
    // ARM: the interrupt-2 hook is the kernel entry (hook_intno(self.hook_syscall, 2)).
    // The upstream load() early-returns for the shellcode runs (the hooks then
    // never install — the upstream qnx path is ELF-only); the port installs
    // unconditionally so the shellcode fixtures can exercise the dialect (the
    // freebsd precedent).
    if (ql().arch().type() == QL_ARCH::ARM) {
        auto* self = this;
        qnx_syscall_hook_ = ql().hook_intno([self](std::uint32_t intno) -> int {
            // qnx.py hook_syscall: just forward to the posix dispatcher
            if (intno != 2) {
                return 0;
            }
            self->load_syscall();
            return 0;
        }, 2);
    }
}

void QlOsQnx::run() {
    // the syspage/cpupage/TLS prelude (qnx.py run) lands with its fixture;
    // the shellcode path rides the posix run (the emu_start over ql.code)
    QlOsPosix::run();
}

std::string_view QlOsQnx::map_syscall(QL_ARCH archtype, unsigned num) const {
    // map_syscall.py get_syscall_mapper: the ARM kercalls table; the other
    // arches fall through to the posix tables
    if (archtype == QL_ARCH::ARM) {
        return lookup_arm_syscall(num);
    }
    return QlOsPosix::map_syscall(archtype, num);
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
