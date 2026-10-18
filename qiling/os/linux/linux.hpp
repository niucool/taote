// Ported from qiling/os/linux/linux.py — QlOsLinux (the Linux os family).
// The syscall dispatch hooks (the `syscall` insn for x86-64, int 0x80 for
// x86) live in the QlOsPosix base (the port absorbed the per-arch hook
// installation into the shared run() path); the linux-specific extras (the
// procfs pseudo files, the futex management, the guest threads) land here as
// their slices reach.
#ifndef QILING_OS_LINUX_LINUX_HPP
#define QILING_OS_LINUX_LINUX_HPP

#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace os {
namespace linux {

class QlOsLinux final : public posix::QlOsPosix {
public:
    explicit QlOsLinux(Qiling* ql) : QlOsPosix(ql) {}

    QL_OS type() const noexcept override { return QL_OS::LINUX; }

    // procfs.py setup_procfs — the /proc/self/* pseudo files (registered as
    // the factory bindings; the user mappings take precedence, verbatim)
    void setup_procfs();

    // linux.py run: the shellcode and the drivers skip the procfs setup
    void run() override;
};

}  // namespace linux
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_LINUX_LINUX_HPP
