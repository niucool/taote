// Ported from qiling/os/linux/linux.py QlOsLinux (the Linux os family). The
// syscall dispatch hooks (the `syscall` insn for x86-64, int 0x80 for x86)
// live in the QlOsPosix base (the port absorbed the per-arch hook install
// into the shared run() path). The linux-specific extras land here: the
// /proc/self pseudo files (procfs.py), the futex management (futex.py), and
// the multithreaded run branch (thread.py).
#ifndef QILING_OS_LINUX_LINUX_HPP
#define QILING_OS_LINUX_LINUX_HPP

#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace os {
namespace linux {

class QlLinuxThreadManagement;

class QlOsLinux final : public posix::QlOsPosix {
public:
    explicit QlOsLinux(Qiling* ql) : QlOsPosix(ql) { init_futexm(); }

    QL_OS type() const noexcept override { return QL_OS::LINUX; }

    // procfs.py setup_procfs — the /proc/self/* pseudo files (registered as
    // the factory bindings; the user mappings take precedence, verbatim)
    void setup_procfs();

    // linux.py run: the shellcode and the drivers skip the procfs setup
    void run() override;

    // linux.py load: the futex management (the ctor-time creation; the
    // python load() assigns it)
    void init_futexm();

    // thread.py QlLinuxThreadManagement wiring: the creation + the run
    // handoff (the multithread branch of the linux.py run)
    void init_multithread();
    void run_multithread();
};

}  // namespace linux
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_LINUX_LINUX_HPP
