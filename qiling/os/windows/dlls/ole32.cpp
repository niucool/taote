// Ported from qiling/os/windows/dlls/ole32.py — the COM-stub family (the
// upstream hooks every COM entry and manages it locally; the bodies answer the
// verbatim S_OK).
#ifndef QILING_OS_WINDOWS_DLLS_OLE32_CPP
#define QILING_OS_WINDOWS_DLLS_OLE32_CPP

#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace qiling {
namespace os {
namespace win {

void register_ole32_family() {
    using namespace qiling::os::api;

    // HRESULT OleInitialize(IN LPVOID pvReserved);
    WinsdkApi("OleInitialize", WinCc::Stdcall, {
        {"pvReserved", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // I don't think we need to do anything, we hook every call for the
        // COM library and manage them locally  (verbatim)
        return S_OK;
    };

    // HRESULT CoRegisterMessageFilter(LPMESSAGEFILTER, LPMESSAGEFILTER *);
    WinsdkApi("CoRegisterMessageFilter", WinCc::Stdcall, {
        {"lpMessageFilter", PVOID_},
        {"lplpMessageFilter", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return S_OK;
    };

    // HRESULT CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
    WinsdkApi("CoInitializeEx", WinCc::Stdcall, {
        {"pvReserved", PVOID_},
        {"dwCoInit", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return S_OK;
    };

    // HRESULT CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, ...);
    WinsdkApi("CoInitializeSecurity", WinCc::Stdcall, {
        {"pSecDesc", PVOID_},
        {"cAuthSvc", LONG_},
        {"asAuthSvc", PVOID_},
        {"pReserved1", PVOID_},
        {"dwAuthnLevel", DWORD_},
        {"dwImpLevel", DWORD_},
        {"pAuthList", PVOID_},
        {"dwCapabilities", DWORD_},
        {"pReserved3", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return S_OK;
    };

    // HRESULT CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
    WinsdkApi("CoCreateInstance", WinCc::Stdcall, {
        {"rclsid", PVOID_},
        {"pUnkOuter", PVOID_},
        {"dwClsContext", DWORD_},
        {"riid", PVOID_},
        {"ppv", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // FIXME: probably this needs implementation  (verbatim)
        return S_OK;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kOle32Registered = [] {
    qiling::os::win::register_ole32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_OLE32_CPP
