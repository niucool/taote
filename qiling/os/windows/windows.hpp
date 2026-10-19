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
#include "qiling/os/windows/clipboard.hpp"
#include "qiling/os/windows/thread.hpp"
#include "qiling/os/windows/seh.hpp"

#include <vector>

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

    // windows.py __init__: the clipboard manager (the user32 clip* family)
    Clipboard& clipboard() const noexcept { return *clipboard_; }

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

    // the ntoskrnl IoCreateDriver rider (the upstream ql.os.init_sp ride):
    // the saved stack pointer restored after the nested emulation
    std::uint64_t init_sp() const noexcept { return init_sp_; }
    void set_init_sp(std::uint64_t v) noexcept { init_sp_ = v; }

    // windows.py: os.thread_manager.thread_ret_addr accessor (the thread
    // create path writes the return address at the new stack top; forwards
    // onto the manager, whose address lands at the install_hook)
    std::uint64_t thread_manager_ret_addr() const noexcept;
    void set_thread_ret_addr(std::uint64_t addr) noexcept { thread_ret_addr_ = addr; }

    // ---- the SEH dispatch (seh.hpp): the x86 exception machinery ----

    // _except_handler4_common records one frame (the EH4 registration + the
    // current TryLevel's scope record) per chain link
    void seh_record_frame(std::uint64_t frame, const SehScopeRecord& scope);
    void seh_clear_frames() { seh_frames_.clear(); }
    const std::vector<SehFrame>& seh_frames() const noexcept { return seh_frames_; }

    // the pending emu restart target armed by the dispatch / the continue
    // walk (0 = none); QlOsWindows::run consumes it after emu_start errors
    std::uint64_t seh_retarget() const noexcept { return seh_retarget_; }
    void seh_consume_retarget() noexcept { seh_retarget_ = 0; }

    ~QlOsWindows() override;

private:
    std::string_view os_section_name() const;
    std::string_view bits_section() const noexcept;

    // the raw unicorn invalid-memory hook (registered at load() for the
    // 32-bit arch): the first-chance SEH dispatch. Rides the raw uc level
    // because the ql-layer mem hooks unconditionally report the fault
    // handled (the upstream _hook_mem_cb contract: the registered hook is
    // expected to fix the state and let the retry run) — the SEH dispatch
    // needs the not-handled return so uc_emu_start surfaces the fault and
    // the run loop restarts at the staged target
    static bool seh_fault_trampoline(uc_engine* uc, uc_mem_type access, std::uint64_t address,
                                     std::uint32_t size, std::int64_t value, void* user_data);
    bool seh_on_fault(int access, std::uint64_t address);
    bool seh_dispatch(std::uint64_t fault_addr, std::uint32_t access_type);
    bool seh_continue();
    void seh_build_context(std::uint64_t dest) const;
    void seh_load_context();
    bool seh_map_sentinel();

    std::map<WinCc, std::unique_ptr<QlFunctionCall>> fcall_table_;
    std::unique_ptr<QlMemoryHeap> heap_storage_;
    QlMemoryHeap* heap_ = nullptr;
    std::unique_ptr<HandleManager> handle_manager_;
    std::unique_ptr<registry::RegistryManager> registry_manager_;
    std::unique_ptr<FiberManager> fiber_manager_;
    std::unique_ptr<Clipboard> clipboard_;
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
    std::uint64_t init_sp_ = 0;
    bool main_thread_handle_appended_ = false;
    std::uint64_t thread_ret_addr_ = 0;
    int bits_ = 64;

    // the SEH dispatch state (seh.hpp)
    uc_hook seh_hook_ = 0;
    std::uint64_t seh_sentinel_ = 0;        // the staged return page (mapped rw-noexec)
    std::uint64_t seh_retarget_ = 0;        // the pending run-loop restart target
    std::uint64_t seh_context_addr_ = 0;    // the mapped CONTEXT (the reload path)
    std::uint64_t seh_fault_pc_ = 0;        // the repeat-guard key (pc)
    std::uint64_t seh_fault_addr_ = 0;      // the repeat-guard key (fault address)
    int seh_repeat_count_ = 0;
    std::vector<SehFrame> seh_frames_;
};

}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_WINDOWS_HPP
