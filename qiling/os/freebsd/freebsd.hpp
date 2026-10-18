// Ported from qiling/os/freebsd/freebsd.py — the freebsd dialect over the
// posix base. The load() sets up the GDT/segments (the SegmentManager64
// shape) and installs the syscall entry hook; the syscall resolution goes
// through the FREEBSD table (the freebsd numbers).
#ifndef QILING_OS_FREEBSD_FREEBSD_HPP
#define QILING_OS_FREEBSD_FREEBSD_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace os {
namespace freebsd {

class QlOsFreebsd : public posix::QlOsPosix {
public:
    explicit QlOsFreebsd(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::FREEBSD; }

    void run() override;

protected:
    // posix.py __get_syscall_mapper: the freebsd map_syscall module supplies
    // the FREEBSD per-arch table (the freebsd numbers, not the linux ones)
    std::string_view map_syscall(QL_ARCH archtype, unsigned num) const override;

private:
    void load();

    std::optional<HookRet> fbsd_syscall_hook_;
};

}  // namespace freebsd
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_FREEBSD_FREEBSD_HPP
