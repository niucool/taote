// Ported from qiling/os/macos/macos.py — the macos dialect over the posix
// base. The load() sets up the GDT/segments (the SegmentManager64 shape)
// and installs the syscall entry hook; the syscall resolution goes through
// the MACOS x8664 table (the macos numbers + the LIBSYSTEM 0x2000000 fixup).
//
// The kext/driver machinery (load_kext, the kernel-extrn symbols, the
// savedrip hooks) and the events/policy managers (events/macos.py,
// macos_policy.py) ride their own slices — the loader-side kext surface
// needs the Mach-O *kernel* loader port first.
#ifndef QILING_OS_MACOS_MACOS_HPP
#define QILING_OS_MACOS_MACOS_HPP

#include <string_view>

#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace os {
namespace macos {

class QlOsMacos : public posix::QlOsPosix {
public:
    explicit QlOsMacos(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::MACOS; }

    void run() override;

protected:
    // map_syscall.py get_syscall_mapper: the MACOS per-arch table; the
    // x8664 numbers carry the LIBSYSTEM fixup (0x2000000 <= n < 0x3000000
    // maps to n - 0x2000000) before the lookup
    std::string_view map_syscall(QL_ARCH archtype, unsigned num) const override;

private:
    void load();
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_MACOS_HPP
