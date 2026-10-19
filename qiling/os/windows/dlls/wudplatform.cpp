// Ported from qiling/os/windows/dlls/wudplatform.py — the debugger-presence
// probes (the verbatim zeros).
#ifndef QILING_OS_WINDOWS_DLLS_WUDPLATFORM_CPP
#define QILING_OS_WINDOWS_DLLS_WUDPLATFORM_CPP

#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace qiling {
namespace os {
namespace win {

void register_wudplatform_family() {
    using namespace qiling::os::api;

    WinsdkApi("WudfIsUserDebuggerPresent", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("WudfIsAnyDebuggerPresent", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("WudfIsKernelDebuggerPresent", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kWudplatformRegistered = [] {
    qiling::os::win::register_wudplatform_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_WUDPLATFORM_CPP
