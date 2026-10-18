// Ported from qiling/os/macos/syscall.py — the macos-specific handlers.
// The first slice: the mach self-trap family (mach_reply_port 0x1a,
// thread_self_trap 0x1b, task_self_trap 0x1c, host_self_trap 0x1d) + the
// simple stubs (csops, getentropy).
#include "qiling/os/macos/syscall.hpp"

#include <cstring>

#include "qiling/core.hpp"
#include "qiling/os/macos/const.hpp"
#include "qiling/os/macos/macos.hpp"
#include "qiling/os/posix/syscall.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

// syscall.py ql_syscall_mach_reply_port: the reply port rides the seeded
// MachPort (the upstream's MachPort(2187) from loader/macho.py)
std::optional<std::int64_t> syscall_mach_reply_port(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_mach_port().name);
}

// syscall.py ql_syscall_thread_self_trap: the thread's port name
std::optional<std::int64_t> syscall_thread_self_trap(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(get_thread_port(os_macos.macho_thread()));
}

// syscall.py ql_syscall_task_self_trap: the task id
std::optional<std::int64_t> syscall_task_self_trap(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_task().id);
}

// syscall.py ql_syscall_host_self_trap: the host port name
std::optional<std::int64_t> syscall_host_self_trap(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_port_manager().host_port.name);
}

// syscall.py ql_syscall_csops: the (CS_ENFORCEMENT | CS_GET_TASK_ALLOW)
// flag into the caller's 4-byte cell, KERN_SUCCESS
std::optional<std::int64_t> syscall_csops(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto useraddr = params[2];
    const std::uint32_t flag = CS_ENFORCEMENT | CS_GET_TASK_ALLOW;
    const std::array<std::uint8_t, 4> bytes = {
        static_cast<std::uint8_t>(flag), static_cast<std::uint8_t>(flag >> 8),
        static_cast<std::uint8_t>(flag >> 16), static_cast<std::uint8_t>(flag >> 24)};
    ql.mem().write(useraddr, std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_getentropy: the no-op stub returning KERN_SUCCESS
// (the buffer stays untouched, verbatim)
std::optional<std::int64_t> syscall_getentropy(Qiling&, const std::vector<std::uint64_t>&) {
    return KERN_SUCCESS;
}

}  // namespace

void register_macos_syscalls() {
    auto& registry = posix::SyscallRegistry::instance();
    registry.register_syscall({"mach_reply_port", {}, syscall_mach_reply_port});
    registry.register_syscall({"thread_self_trap", {}, syscall_thread_self_trap});
    registry.register_syscall({"task_self_trap", {}, syscall_task_self_trap});
    registry.register_syscall({"host_self_trap", {}, syscall_host_self_trap});
    registry.register_syscall({"csops", {PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_csops});
    registry.register_syscall({"getentropy", {PARAM_PTRX, PARAM_INTN}, syscall_getentropy});
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
