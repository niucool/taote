// Ported from qiling/os/windows/dlls/msi.py — the MsiGetComponentStateA stub
// (the verbatim ERROR_INVALID_HANDLE answer).
#ifndef QILING_OS_WINDOWS_DLLS_MSI_CPP
#define QILING_OS_WINDOWS_DLLS_MSI_CPP

#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace qiling {
namespace os {
namespace win {

void register_msi_family() {
    using namespace qiling::os::api;

    // UINT MsiGetComponentStateA(MSIHANDLE hInstall, LPCSTR szComponent,
    //     INSTALLSTATE *piInstalled, INSTALLSTATE *piAction);
    WinsdkApi("MsiGetComponentStateA", WinCc::Stdcall, {
        {"hInstall", PVOID_},  // the MSIHANDLE (the api.py POINTER)
        {"szComponent", LPCSTR_},
        {"piInstalled", PVOID_},  // the INSTALLSTATE (the api.py POINTER)
        {"piAction", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return ERROR_INVALID_HANDLE;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kMsiRegistered = [] {
    qiling::os::win::register_msi_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_MSI_CPP
