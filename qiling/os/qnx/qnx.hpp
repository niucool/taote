// Ported from qiling/os/qnx/qnx.py — the QNX dialect over the posix base.
// The QNX kernel dispatch is ARM32-only: the syscall number rides R12 and
// the entry hook is the interrupt number 2 (the SWI vector), per the
// upstream's `hook_intno(self.hook_syscall, 2)`.
#ifndef QILING_OS_QNX_QNX_HPP
#define QILING_OS_QNX_QNX_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/qnx/const.hpp"

namespace qiling {
namespace os {
namespace qnx {

class QlOsQnx : public posix::QlOsPosix {
public:
    explicit QlOsQnx(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::QNX; }

    void run() override;

    // syscall.py ql_syscall_channel_create: the free channel-id counter (the
    // ctor seeds it at 1; the upstream keeps the attribute public)
    std::uint64_t next_channel_id() { return channel_id_++; }
    std::uint64_t channel_id() const noexcept { return channel_id_; }

protected:
    // qnx/map_syscall.py get_syscall_mapper: the ARM kercalls table
    // (trunk/services/system/public/sys/kercalls.h numbers)
    std::string_view map_syscall(QL_ARCH archtype, unsigned num) const override;

private:
    void load();

    std::optional<HookRet> qnx_syscall_hook_;
    std::uint64_t channel_id_ = 1;
    // TODO: replace 0x400 with NR_OPEN from Qiling 1.25 (the ctor seeds it in
    // the connect_attach slice)
    std::uint64_t connection_id_lo_ = 0x400 + 1;
    std::uint64_t connection_id_hi_ = static_cast<std::uint64_t>(NTO_SIDE_CHANNEL) + 1;
};

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_QNX_HPP
