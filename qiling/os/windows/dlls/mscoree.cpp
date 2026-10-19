// Ported from qiling/os/windows/dlls/mscoree.py — the CorExitProcess stub
// (the emu stop ride).
#ifndef QILING_OS_WINDOWS_DLLS_MSCOREE_CPP
#define QILING_OS_WINDOWS_DLLS_MSCOREE_CPP

#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace qiling {
namespace os {
namespace win {

void register_mscoree_family() {
    using namespace qiling::os::api;

    // void STDMETHODCALLTYPE CorExitProcess(int exitCode);
    WinsdkApi("CorExitProcess", WinCc::Stdcall, {
        {"exitCode", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        ql.emu_stop();
        return std::nullopt;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kMscoreeRegistered = [] {
    qiling::os::win::register_mscoree_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_MSCOREE_CPP
