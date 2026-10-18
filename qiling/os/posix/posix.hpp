// Ported from qiling/os/posix/posix.py — QlOsPosix (the syscall dispatch core).
// The dynamic hook resolution (getattr over the syscall modules) becomes the
// static SyscallRegistry lookup; the user-defined syscall overrides
// (set_syscall) keep the QL_INTERCEPT semantics.
#ifndef QILING_OS_POSIX_POSIX_HPP
#define QILING_OS_POSIX_POSIX_HPP

#include <array>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "qiling/exception.hpp"
#include "qiling/core_hooks_types.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/posix/syscall/abi.hpp"

namespace qiling {

class QlArch;
namespace cc { class QlCC; }

namespace os {
namespace posix {

inline constexpr const char* SYSCALL_PREF = "ql_syscall_";

// posix.py QlFileDes — the file-descriptor table (NR_OPEN slots of the
// mapped-object refs; the std streams occupy the first three slots)
class QlFileDes {
public:
    static constexpr int NR_OPEN = 1024;

    // get_opened_fd's bounds check: nullptr when out of range or empty
    std::shared_ptr<QlFsMappedObject> at(int idx) const {
        if (idx < 0 || idx >= NR_OPEN) {
            return nullptr;
        }
        return fds_[static_cast<std::size_t>(idx)];
    }

    void set(int idx, std::shared_ptr<QlFsMappedObject> value) {
        if (idx >= 0 && idx < NR_OPEN) {
            fds_[static_cast<std::size_t>(idx)] = std::move(value);
        }
    }

    std::size_t size() const noexcept { return NR_OPEN; }

    std::vector<std::shared_ptr<QlFsMappedObject>> save() const {
        return {fds_.begin(), fds_.end()};
    }
    void restore(std::vector<std::shared_ptr<QlFsMappedObject>> fds) {
        if (fds.size() != fds_.size()) {
            throw QlErrorBase("fd table restore: size mismatch");
        }
        std::copy(fds.begin(), fds.end(), fds_.begin());
    }

private:
    std::array<std::shared_ptr<QlFsMappedObject>, NR_OPEN> fds_{};
};

class QlOsPosix : public QlOs {
public:
    explicit QlOsPosix(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::LINUX; }

    void run() override;

    // posix.py set_syscall — a user override for one syscall (by name or id)
    void set_syscall(std::string_view name, SyscallHandler handler);

    // posix.py load_syscall — resolve the current syscall through the registry
    // and run it (the abi supplies the id and the parameters)
    void load_syscall();

    // the per-arch syscall entry hooks (the single-shot run and the
    // multithread driver share the install; idempotent)
    void install_syscall_hooks();

    void shutdown() override;

    // posix.py: the fd table (self._fd, exposed as self.fd) — the std streams
    // occupy the first three slots (the property setters, verbatim)
    QlFileDes& fd() noexcept { return fd_; }

    // the kmalloc hook's heap (kernel_api.py ql.heap.alloc; the linux profile
    // carries no heap fields — the port creates the default region lazily)
    QlMemoryHeap& heap();

    // hook.py hook_kernel_api — the code hook dispatching the loader's import
    // stubs through the user overrides and the kernel api registry
    void hook_kernel_api(std::uint64_t address, std::uint32_t size);

    // elf.py run: ql.hook_code(hook_kernel_api) — the handle lives on the os
    // so the shutdown discipline releases it with the other hook owners
    void enable_kernel_api_hooks();

    // the raw parameter count the dispatcher reads for a syscall id
    static std::size_t params_count_for_id(std::uint64_t syscall_id, QL_ARCH archtype);

    const QlSyscallABI& syscall_abi() const noexcept { return *syscall_abi_; }

    // the KERNEL profile identity (posix.py: uid/euid/gid/egid/pid)
    int uid() const noexcept { return uid_; }
    void set_uid(int v) noexcept { uid_ = v; }
    int euid() const noexcept { return euid_; }
    int gid() const noexcept { return gid_; }
    void set_gid(int v) noexcept { gid_ = v; }
    int egid() const noexcept { return egid_; }
    int pid() const noexcept { return pid_; }

private:
    static std::unique_ptr<cc::QlCC> make_cc_default(QL_ARCH archtype, QlArch& arch);

    std::unique_ptr<QlSyscallABI> syscall_abi_;
    QlFileDes fd_;
    std::unique_ptr<QlMemoryHeap> heap_;
    std::map<std::string, SyscallHandler> user_syscalls_;
    std::optional<HookRet> syscall_hook_;
    bool hooks_installed_ = false;
    std::optional<HookRet> kernel_api_hook_;
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
