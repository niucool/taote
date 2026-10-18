// os/uefi/uefi.py — the QlOsUefi declaration
//
// The slice-1 shape: the os shell (the type, the fcall over the ms64 cc,
// the run() driving the loader-set entry point, the notify hooks) with the
// service-table layer (the ST/BS/RT/DS structure init) landing in the next
// slice.

#pragma once

#include <functional>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/uefi/context.hpp"

namespace qiling {
namespace os {
namespace uefi {

class QlOsUefi final : public QlOs {
public:
    explicit QlOsUefi(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::UEFI; }

    void run() override;

    // uefi.py notify_before_module_execution / notify_after_module_execution
    // (the on_module_enter / on_module_exit callback lists)
    bool notify_before_module_execution(const std::string& module);
    bool notify_after_module_execution(int nmodules);
    void on_module_enter(std::function<bool(const std::string&)> cb) { on_module_enter_.push_back(std::move(cb)); }
    void on_module_exit(std::function<bool(int)> cb) { on_module_exit_.push_back(std::move(cb)); }

    // uefi.py set_api: the uefi overrides prefix the hook_ name (the base
    // name-keyed table carries the handler)
    void set_api(std::string_view target, UserApiHandler handler, QL_INTERCEPT intercept = QL_INTERCEPT::CALL);

    // the running module path (the set by the loader's execute_module)
    std::string running_module;

    // the heap the loader initialized (the dxec context-owned)
    UefiContext* context = nullptr;

    // the fcall (the ms64 cc for the module entry calls)
    std::unique_ptr<QlFunctionCall> fcall;

    // the TPL level (the RaiseTPL/RestoreTPL surface; the TPL_APPLICATION
    // initial)
    unsigned tpl = 4;

    // the installed service-field addresses (the diagnostics)
    std::vector<std::uint64_t> uefi_installed_fields_;

private:
    std::vector<std::function<bool(const std::string&)>> on_module_enter_;
    std::vector<std::function<bool(int)>> on_module_exit_;
};

}  // namespace uefi
}  // namespace os
}  // namespace qiling
