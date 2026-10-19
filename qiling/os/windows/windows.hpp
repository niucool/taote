// Ported from qiling/os/windows/windows.py — QlOsWindows (the Phase 4 core:
// the fcall selector, the segment setup, and the hook_winapi dispatcher over
// the static ApiRegistry). The registry/clipboard/fiber subsystems port with
// their own slices.
#ifndef QILING_OS_WINDOWS_WINDOWS_HPP
#define QILING_OS_WINDOWS_WINDOWS_HPP

#include "qiling/core_hooks_types.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/registry.hpp"
#include "qiling/os/windows/fiber.hpp"
#include "qiling/os/windows/thread.hpp"

namespace qiling {

namespace loader { class QlLoader; }

namespace os {
namespace windows {

// x86_const.py: the segment regions
inline constexpr std::uint64_t FS_SEGMENT_ADDR = 0x6000;
inline constexpr std::uint64_t FS_SEGMENT_SIZE = 0x6000;
inline constexpr std::uint64_t GS_SEGMENT_ADDR = 0x6000000;
inline constexpr std::uint64_t GS_SEGMENT_SIZE = (20 << 20);  // 20 MB

class QlOsWindows final : public QlOs {
public:
    explicit QlOsWindows(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::WINDOWS; }

    // windows.py run: the emulation entry (the exit_point override + the
    // try/emu_error discipline)
    void run() override;

    // windows.py load: the GDT/segment setup + the code hook that dispatches
    // the registered winapi surface
    void load();

    // the deferred profile reads (the heap + the path identities): the Qiling
    // ctor builds the os before the profile loads, so load()/run() seed them
    void ensure_profile_state();

    // windows.py hook_winapi — dispatch the registered api at the resolved
    // import address
    void hook_winapi(std::uint64_t address, std::uint32_t size);

    // windows.py fcall_select - the per-cc fcall (32-bit may mix STDCALL and
    // CDECL; 64-bit is always MS64)
    QlFunctionCall& fcall_select(WinCc cc);

    // windows.py `ql.os.fcall = ql.os.fcall_select(cc)`: the per-call-site
    // convention switch (non-owning; the table holds the instances)
    void bind_fcall(WinCc cc) { set_fcall_ptr(fcall_select(cc)); }

    // windows.py properties
    const std::string& windir() const noexcept { return windir_; }
    const std::string& winsys() const noexcept { return winsys_; }
    const std::string& userprofile() const noexcept { return userprofile_; }
    const std::string& username() const noexcept { return username_; }
    // os.py last_error: ONE surface — the QlOs base field (the fiber.py
    // manager and the api handlers share it; the port previously shadowed
    // the base field with a windows-local copy)
    using QlOs::last_error;
    using QlOs::set_last_error;

    // windows.py __setup_components: the registry manager (the diff store +
    // the hive front; the hive parsing defers with the real-hive fixtures)
    registry::RegistryManager& registry_manager() const noexcept { return *registry_manager_; }

    // windows.py __setup_components: the fiber manager (the Fls* family)
    FiberManager& fiber_manager() const noexcept { return *fiber_manager_; }

    // advapi32.py `self.services = {}`: the service-name -> binary-path map
    // (the CreateService/OpenService walk)
    std::map<std::string, std::string>& services() noexcept { return services_; }

    QlMemoryHeap& heap() const noexcept { return *heap_; }
    HandleManager& handle_manager() const noexcept { return *handle_manager_; }

    // windows.py __setup_components: the thread manager over the main thread
    // (the scheduler hook rides install_hook at the construction)
    QlWindowsThreadManagement& thread_manager() const noexcept { return *thread_manager_; }

    // windows.py __init__: self.pid = profile.getint('KERNEL', 'pid')
    std::uint32_t pid() const noexcept { return pid_; }

    // windows.py: os.thread_manager.thread_ret_addr accessor (the thread
    // create path writes the return address at the new stack top; forwards
    // onto the manager, whose address lands at the install_hook)
    std::uint64_t thread_manager_ret_addr() const noexcept;
    void set_thread_ret_addr(std::uint64_t addr) noexcept { thread_ret_addr_ = addr; }

    ~QlOsWindows() override;

private:
    std::string_view os_section_name() const;
    std::string_view bits_section() const noexcept;

    std::map<WinCc, std::unique_ptr<QlFunctionCall>> fcall_table_;
    std::unique_ptr<QlMemoryHeap> heap_storage_;
    QlMemoryHeap* heap_ = nullptr;
    std::unique_ptr<HandleManager> handle_manager_;
    std::unique_ptr<registry::RegistryManager> registry_manager_;
    std::unique_ptr<FiberManager> fiber_manager_;
    std::map<std::string, std::string> services_;
    std::optional<HookRet> hook_handle_;
    std::string windir_;
    std::string winsys_;
    std::string userprofile_;
    std::string username_;
    // windows.py thread_management (the typed surface; __setup_components
    // builds it over the main thread)
    std::unique_ptr<QlWindowsThreadManagement> thread_manager_;
    std::uint32_t pid_ = 0;
    bool main_thread_handle_appended_ = false;
    std::uint64_t thread_ret_addr_ = 0;
    int bits_ = 64;
};

}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_WINDOWS_HPP
