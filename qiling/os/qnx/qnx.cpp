// Ported from qiling/os/qnx/qnx.py — the QNX dialect. The ctor swaps the
// syscall ABI for the QNX override (the R12 id register) and installs the
// interrupt-2 hook for the ARM; the kernel-call table lands with the
// handler slice.
#include "qiling/os/qnx/qnx.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/syscall/abi.hpp"
#include "qiling/os/qnx/map_syscall.hpp"
#include "qiling/os/qnx/structs.hpp"
#include "qiling/os/qnx/syscall.hpp"

#include "qiling/cc/arm.hpp"
#include "qiling/os/fcall.hpp"

#include <fstream>
#include <iterator>

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

    // qnx.py __init__: the std streams and the sysmgr occupy the well-known
    // coids (0/1/2 carry the fds, SYSMGR_COID rides bare)
    connections_.emplace(0, QnxConn(SYSMGR_PID, SYSMGR_CHID, 0));
    connections_.emplace(1, QnxConn(SYSMGR_PID, SYSMGR_CHID, 1));
    connections_.emplace(2, QnxConn(SYSMGR_PID, SYSMGR_CHID, 2));
    connections_.emplace(SYSMGR_COID, QnxConn(SYSMGR_PID, SYSMGR_CHID));
}

std::uint32_t QlOsQnx::alloc_connection_id(bool side_channel, std::uint32_t pid, std::uint32_t chid) {
    // qnx.py ql_syscall_connect_attach: the side-channel index draws from the
    // high counter, the plain index from the low one
    const auto coid = side_channel ? connection_id_hi_++ : connection_id_lo_++;
    connections_.emplace(static_cast<std::uint32_t>(coid), QnxConn(pid, chid));
    return static_cast<std::uint32_t>(coid);
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
    // the syspage/cpupage/TLS prelude (qnx.py run): the profile addresses,
    // the syspage image from the rootfs, the TLS seed and the cpupage cells
    const auto& os_profile = profile();
    cpupage_addr_ = static_cast<std::uint64_t>(os_profile.get_int("OS32", "cpupage_address"));
    cpupage_tls_addr_ = static_cast<std::uint64_t>(os_profile.get_int("OS32", "cpupage_tls_address"));
    tls_data_addr_ = static_cast<std::uint64_t>(os_profile.get_int("OS32", "tls_data_address"));
    syspage_addr_ = static_cast<std::uint64_t>(os_profile.get_int("OS32", "syspage_address"));

    auto& mem = ql().mem();
    mem.map(syspage_addr_, 0x4000, UC_PROT_ALL, "[syspage_mem]");
    const auto syspage_hpath = path()->virtual_to_host_path("/syspage.bin");
    std::ifstream sp(syspage_hpath, std::ios::binary);
    if (!sp) {
        throw QlErrorBase("qnx run: the syspage image is missing (" + syspage_hpath + ")");
    }
    const std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(sp)), std::istreambuf_iterator<char>());
    mem.write(syspage_addr_, image);

    // the thread-local storage for the main thread (the upstream seeds
    // errptr/pid/tid and derives the owner via SYNC_OWNER_BITS)
    mem.write_ptr(cpupage_addr_, cpupage_tls_addr_, 4);
    ThreadLocalStorage tls{};
    tls.errptr = static_cast<std::uint32_t>(tls_data_addr_);
    tls.pid = static_cast<std::int32_t>(pid());
    tls.tid = 1;
    tls.owner = sync_owner_bits(tls.pid, tls.tid);
    const auto tls_bytes = std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&tls),
                                                     reinterpret_cast<const std::uint8_t*>(&tls) + sizeof(tls));
    mem.write(cpupage_tls_addr_, tls_bytes);

    // the syspage pointer rides the second cpupage cell
    mem.write_ptr(cpupage_addr_ + 8, syspage_addr_, 4);

    // the emulation entry rides the posix run (the code blob and the loader
    // paths)
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
