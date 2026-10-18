// os/uefi/uefi.py — the QlOsUefi implementation (the slice-1 shell)

#include "qiling/os/uefi/uefi.hpp"

#include "qiling/cc/intel.hpp"
#include "qiling/loader/pe_uefi.hpp"
#include "qiling/os/fcall.hpp"

namespace qiling {
namespace os {
namespace uefi {

QlOsUefi::QlOsUefi(Qiling* ql) : QlOs(ql) {
    // uefi.py ctor: the fcall over the ms64 cc (the 32-bit cdecl branch
    // lands with a 32-bit uefi slice; the upstream supports only 64-bit
    // modules)
    fcall = std::make_unique<QlFunctionCall>(std::make_unique<cc::ms64>(ql->arch()));
    // the os.call path rides the base's fcall() accessor (the non-owning rebind)
    set_fcall_ptr(*fcall);
}

bool QlOsUefi::notify_before_module_execution(const std::string& module) {
    // uefi.py: True if module execution should be thwarted
    bool veto = false;
    for (const auto& cb : on_module_enter_) {
        veto = cb(module) || veto;
    }
    return veto;
}

bool QlOsUefi::notify_after_module_execution(int nmodules) {
    // uefi.py: True if subsequent modules execution should be thwarted
    bool veto = false;
    for (const auto& cb : on_module_exit_) {
        veto = cb(nmodules) || veto;
    }
    return veto;
}

void QlOsUefi::set_api(std::string_view target, UserApiHandler handler, QL_INTERCEPT intercept) {
    // uefi.py set_api: the hook_ prefix rides the name-keyed base table
    std::string name("hook_");
    name += target;
    QlOs::set_api(name, std::move(handler), intercept);
}

void QlOsUefi::run() {
    // uefi.py run: the smm env init lands with the SMM slice; the entry
    // point rides the loader (the first module's entry), the exit point
    // stays 0 unless overridden. The module chaining (the notify hooks + the
    // next-module dispatch) rides the loader's eoe trap during this emu_start.
    std::uint64_t entry = ql().loader().entry_point;
    if (ql().entry_point_set()) {
        // uefi.py: the override rewrites the loader's entry point
        // (noted upstream as "not the right place for this" - verbatim)
        entry = ql().entry_point();
    }
    std::uint64_t exit = 0;
    if (ql().exit_point_set()) {
        exit = ql().exit_point();
    }

    try {
        ql().emu_start(entry, exit, ql().timeout(), ql().count());
    } catch (const QlErrorBase&) {
        emu_error();
        throw;
    }
}

}  // namespace uefi
}  // namespace os
}  // namespace qiling
