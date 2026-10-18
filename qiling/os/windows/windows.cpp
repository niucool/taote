#include "qiling/os/windows/windows.hpp"
#include "qiling/loader/pe.hpp"

#include "qiling/arch/x86.hpp"
#include "qiling/cc/intel.hpp"
#include "qiling/core.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/windows/handle.hpp"

namespace qiling {
namespace os {
namespace windows {

QlOsWindows::QlOsWindows(Qiling* ql) : QlOs(ql) {
    init_paths_if_managed();

    // windows.py __init__: the fcall table (32-bit mixes STDCALL/CDECL;
    // 64-bit is always MS64)
    auto& arch = ql->arch();
    if (arch.bits() == 64) {
        fcall_table_[WinCc::Ms64] = std::make_unique<QlFunctionCall>(cc::ms64(arch));
        fcall_table_[WinCc::Stdcall] = std::make_unique<QlFunctionCall>(cc::ms64(arch));
        fcall_table_[WinCc::Cdecl] = std::make_unique<QlFunctionCall>(cc::ms64(arch));
    } else {
        fcall_table_[WinCc::Stdcall] = std::make_unique<QlFunctionCall>(cc::QlStdcall(arch));
        fcall_table_[WinCc::Cdecl] = std::make_unique<QlFunctionCall>(cc::QlCdecl(arch));
        fcall_table_[WinCc::Ms64] = std::make_unique<QlFunctionCall>(cc::QlStdcall(arch));
    }

    set_fcall(std::make_unique<QlFunctionCall>(cc::QlCdecl(arch)));

    // the heap from the OS{bits} profile section
    const auto heap_base = static_cast<std::uint64_t>(profile().get_int(os_section_name(), "heap_address"));
    const auto heap_size = static_cast<std::uint64_t>(profile().get_int(os_section_name(), "heap_size"));
    heap_storage_ = std::make_unique<QlMemoryHeap>(ql->mem(), heap_base, heap_base + heap_size);
    heap_ = heap_storage_.get();
    bits_ = static_cast<int>(arch.bits());

    // the path identities (windows.py: systemdrive + windir + username)
    const auto sysdrv = profile().get("PATH", "systemdrive").value_or("C:");
    const auto windir = profile().get("PATH", "windir").value_or("\\Windows");
    const auto username = profile().get("USER", "username").value_or("user");

    windir_ = std::string(sysdrv) + std::string(windir);
    winsys_ = windir_ + "\\System32";
    userprofile_ = std::string(sysdrv) + "\\Users\\" + std::string(username);
    username_ = username;

    // the pid from the KERNEL section
    // (posix shares the KERNEL section; windows reads it the same way)

    // the handle manager (windows.py __setup_components)
    handle_manager_ = std::make_unique<HandleManager>();

    // bind the stdio streams to their handles (windows.py stdin/stdout/stderr setters)
    HandleManager& mgr = *handle_manager_;
    if (auto* h = mgr.get(QL_STD_INPUT_HANDLE)) h->obj = &stdin_stream();
    if (auto* h = mgr.get(QL_STD_OUTPUT_HANDLE)) h->obj = &stdout_stream();
    if (auto* h = mgr.get(QL_STD_ERROR_HANDLE)) h->obj = &stderr_stream();
}

std::string_view QlOsWindows::os_section_name() const {
    // windows.py: OS{bits}
    return bits_ == 64 ? "OS64" : "OS32";
}

std::string_view QlOsWindows::bits_section() const noexcept {
    return bits_ == 64 ? "OS64" : "OS32";
}

QlFunctionCall& QlOsWindows::fcall_select(WinCc cc) {
    return *fcall_table_.at(cc);
}

void QlOsWindows::load() {
    // windows.py load: the GDT/segments (FS/GS regions) + the api dispatch hook
    auto& arch = ql().arch();
    auto& mem = ql().mem();

    if (!mem.is_available(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE)) {
        throw QlErrorBase("cannot map FS segment, memory location is taken");
    }
    mem.map(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, UC_PROT_ALL, "[FS]");

    if (!mem.is_available(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)) {
        throw QlErrorBase("cannot map GS segment, memory location is taken");
    }
    mem.map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, UC_PROT_ALL, "[GS]");

    // FS/GS base: the segment registers point at the region bases
    if (arch.bits() == 64) {
        arch.regs().write("gs_base", GS_SEGMENT_ADDR);
    }

    // the winapi dispatch hook (windows.py: ql.hook_code(self.hook_winapi))
    auto* self = this;
    hook_handle_ = ql_->hook_code([self](std::uint64_t address, std::uint32_t size) -> int {
        self->hook_winapi(address, size);
        return 0;
    });
}

void QlOsWindows::hook_winapi(std::uint64_t address, std::uint32_t size) {
    (void)size;

    // windows.py hook_winapi: the import_symbols table maps the stub address
    // to the api identity; the resolved handler comes from the ApiRegistry
    // (the C++ static registration replacing the getattr dispatch)
    const auto* imported = static_cast<const loader::QlLoaderPE&>(ql_->loader()).import_symbols_at(address);
    if (imported == nullptr) {
        return;
    }

    const auto* api = ApiRegistry::instance().find(imported->name);
    if (api == nullptr) {
        // windows.py: not implemented (a warning; debug_stop raises with the
        // QlErrorSyscallNotFound slice)
        return;
    }

    // select the calling convention for this call site and run the handler
    // through the os.call orchestration
    set_fcall_ptr(fcall_select(api->cc));
}

void QlOsWindows::run() {
    // windows.py run: the explicit entry/exit overrides, then the emulation
    if (ql_->exit_point_set()) {
        set_exit_point(ql_->exit_point());
    }
    if (ql_->entry_point_set()) {
        ql_->loader().entry_point = ql_->entry_point();
    }

    const auto entry_point = ql_->loader().entry_point;
    const auto exit_point = ql_->code().empty()
        ? exit_point_
        : (entry_point + ql_->code().size());

    try {
        ql_->emu_start(entry_point, exit_point, ql_->timeout(), ql_->count());
    } catch (const QlErrorBase&) {
        emu_error();
        throw;
    }

    // the registry/summary surface lands with its slices
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
