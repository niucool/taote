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

#include <memory>
#include <string_view>

#include "qiling/os/posix/posix.hpp"
#include "qiling/os/macos/mach_port.hpp"
#include "qiling/os/macos/kernel_func.hpp"
#include "qiling/os/macos/ev.hpp"

namespace qiling {
namespace os {
namespace macos {

struct MachoThread;

class QlOsMacos : public posix::QlOsPosix {
public:
    explicit QlOsMacos(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::MACOS; }

    void run() override;

    // macos.py QlOsMacos.RUN — the emit path consults it: true (the default,
    // the live emulation) stack-pushes the gen_stub_code trampoline at the
    // current guest rsp (the guest's next ret lands in it); false (the
    // post-run/shutdown) queues a job for the ev manager's trigger() drain
    bool RUN = true;

    // the mach-port/task/thread surfaces the self-trap handlers ride (the
    // upstream's loader/macho.py seeds them on the QlOs; the port seeds them
    // in the ctor until the Mach-O loader slice lands)
    const MachPort& macho_mach_port() const { return *macho_mach_port_; }
    const MachPortManager& macho_port_manager() const { return *macho_port_manager_; }
    const MachoTask& macho_task() const { return *macho_task_; }
    MachoTask& macho_task_mut() { return *macho_task_; }

    // loader/macho.py seeds macho_vmmap_end from the profile's
    // vmmap_trap_address (the ctor-seeded deviation, same as the mach
    // surfaces); the vm_map trap walks it
    std::uint64_t macho_vmmap_end() const { return macho_vmmap_end_; }
    void set_macho_vmmap_end(std::uint64_t v) { macho_vmmap_end_ = v; }
    const MachoThread& macho_thread() const { return *macho_thread_; }

    // loader/macho.py seeds the fs helper on the QlOs (the FileSystem over
    // the rootfs); the same ctor-seeded deviation as the mach surfaces
    const FileSystem& macho_fs() const { return *macho_fs_; }

    // events/macos.py: the QlOs seeds the ev/policy managers in its ctor
    // (macos.py __init__ verbatim shape)
    QlEvManager& ev_manager() { return *ev_manager_; }
    const QlEvManager& ev_manager() const { return *ev_manager_; }
    QlOsPolicy& policy_manager() { return *policy_manager_; }

protected:
    // map_syscall.py get_syscall_mapper: the MACOS per-arch table; the
    // x8664 numbers carry the LIBSYSTEM fixup (0x2000000 <= n < 0x3000000
    // maps to n - 0x2000000) before the lookup
    std::string_view map_syscall(QL_ARCH archtype, unsigned num) const override;

    // hook.py hook_kernel_api: the stub-address dispatch (the QlLoaderMachO
    // supplies the import symbols; the posix enable_kernel_api_hooks lambda
    // dispatches through the virtual)
    void hook_kernel_api(std::uint64_t address, std::uint32_t size) override;

private:
    void load();

    std::unique_ptr<MachPort> macho_mach_port_;
    std::unique_ptr<MachPortManager> macho_port_manager_;
    std::unique_ptr<MachoTask> macho_task_;
    std::unique_ptr<MachoThread> macho_thread_;
    std::unique_ptr<FileSystem> macho_fs_;
    std::uint64_t macho_vmmap_end_ = 0;
    std::unique_ptr<QlEvManager> ev_manager_;
    std::unique_ptr<QlOsPolicy> policy_manager_;
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_MACOS_HPP
