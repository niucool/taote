// Ported from qiling/os/qnx/qnx.py — the QNX dialect over the posix base.
// The QNX kernel dispatch is ARM32-only: the syscall number rides R12 and
// the entry hook is the interrupt number 2 (the SWI vector), per the
// upstream's `hook_intno(self.hook_syscall, 2)`.
#ifndef QILING_OS_QNX_QNX_HPP
#define QILING_OS_QNX_QNX_HPP

#include <map>
#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/helpers.hpp"

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

    // the run() prelude state (qnx.py run: the OS32 profile addresses; the
    // handlers read them back — sys_cpupage_get/set)
    std::uint64_t cpupage_addr() const noexcept { return cpupage_addr_; }
    std::uint64_t cpupage_tls_addr() const noexcept { return cpupage_tls_addr_; }
    std::uint64_t tls_data_addr() const noexcept { return tls_data_addr_; }
    std::uint64_t syspage_addr() const noexcept { return syspage_addr_; }

    // qnx.py __init__: the connections map (the coid → the QnxConn record);
    // the std streams occupy 0..2 and the sysmgr rides SYSMGR_COID
    std::map<std::uint32_t, QnxConn>& connections() noexcept { return connections_; }

    // the free connection id off the low or the high (side-channel) counter;
    // returns the handed-out id and registers the connection
    std::uint32_t alloc_connection_id(bool side_channel, std::uint32_t pid, std::uint32_t chid);

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

    // the run() prelude addresses (the OS32 profile)
    std::uint64_t cpupage_addr_ = 0;
    std::uint64_t cpupage_tls_addr_ = 0;
    std::uint64_t tls_data_addr_ = 0;
    std::uint64_t syspage_addr_ = 0;

    // the connections table (qnx.py __init__ seeds the std streams and the
    // sysmgr)
    std::map<std::uint32_t, QnxConn> connections_;
};

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_QNX_HPP
