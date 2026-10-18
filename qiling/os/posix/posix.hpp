// Ported from qiling/os/posix/posix.py — QlOsPosix (the syscall dispatch core).
// The dynamic hook resolution (getattr over the syscall modules) becomes the
// static SyscallRegistry lookup; the user-defined syscall overrides
// (set_syscall) keep the QL_INTERCEPT semantics.
#ifndef QILING_OS_POSIX_POSIX_HPP
#define QILING_OS_POSIX_POSIX_HPP

#include <map>
#include <optional>
#include <memory>

#include "qiling/exception.hpp"
#include "qiling/core_hooks_types.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/posix/syscall/abi.hpp"

namespace qiling {

class QlArch;
namespace cc { class QlCC; }

namespace os {
namespace posix {

inline constexpr const char* SYSCALL_PREF = "ql_syscall_";

class QlOsPosix final : public QlOs {
public:
    explicit QlOsPosix(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::LINUX; }

    void run() override;

    // posix.py set_syscall — a user override for one syscall (by name or id)
    void set_syscall(std::string_view name, SyscallHandler handler);

    // posix.py load_syscall — resolve the current syscall through the registry
    // and run it (the abi supplies the id and the parameters)
    void load_syscall();

    void shutdown() override;

    // the raw parameter count the dispatcher reads for a syscall id
    static std::size_t params_count_for_id(std::uint64_t syscall_id, QL_ARCH archtype);

    const QlSyscallABI& syscall_abi() const noexcept { return *syscall_abi_; }

    // the KERNEL profile identity (posix.py: uid/euid/gid/egid/pid)
    int uid() const noexcept { return uid_; }
    int euid() const noexcept { return euid_; }
    int gid() const noexcept { return gid_; }
    int egid() const noexcept { return egid_; }
    int pid() const noexcept { return pid_; }

private:
    static std::unique_ptr<cc::QlCC> make_cc_default(QL_ARCH archtype, QlArch& arch);

    std::unique_ptr<QlSyscallABI> syscall_abi_;
    std::map<std::string, SyscallHandler> user_syscalls_;
    std::optional<HookRet> syscall_hook_;
    int uid_ = 1000;
    int euid_ = 1000;
    int gid_ = 1000;
    int egid_ = 1000;
    int pid_ = 1996;
};

}  // namespace posix
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_POSIX_POSIX_HPP
