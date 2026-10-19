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

    // HRESULT CoInitialize(LPVOID pvReserved); — the S_OK shape (the first
    // apartment init; the S_FALSE (1) shape on the re-init)
    WinsdkApi("CoInitialize", WinCc::Stdcall, {
        {"pvReserved", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return S_OK;
    };

    WinsdkApi("CoInitializeEx", WinCc::Stdcall, {
        {"pvReserved", PVOID_},
        {"dwCoInit", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return S_OK;
    };

    // void CoUninitialize(void);
    WinsdkApi("CoUninitialize", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // HRESULT CoCreateGuid(GUID* pguid); — the zeroed guid (the valid-RPC
    // status rides S_OK; the bytes themselves are not consumed by the
    // samples)
    WinsdkApi("CoCreateGuid", WinCc::Stdcall, {
        {"pguid", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pguid = api_get_int(get_param(params, "pguid"));
        if (pguid != 0) {
            ql.mem().write(pguid, std::vector<std::uint8_t>(16, 0));
        }
        return S_OK;
    };

    // HRESULT StringFromCLSID(REFCLSID rclsid, LPOLESTR* lplpsz);
    WinsdkApi("StringFromCLSID", WinCc::Stdcall, {
        {"rclsid", PVOID_},
        {"lplpsz", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto out = api_get_int(get_param(params, "lplpsz"));
        if (out != 0) {
            // the {00000000-0000-0000-0000-000000000000} shape
            const std::string text = "{00000000-0000-0000-0000-000000000000}";
            auto& heap = w(ql).heap();
            const auto wide = heap.alloc((text.size() + 1) * 2);
            for (std::size_t i = 0; i <= text.size(); ++i) {
                ql.mem().write_ptr(wide + i * 2, static_cast<std::uint8_t>(i < text.size() ? text[i] : 0), 1);
                ql.mem().write_ptr(wide + i * 2 + 1, 0, 1);
            }
            ql.mem().write_ptr(out, wide);
        }
        return S_OK;
    };

    // HRESULT CoTaskMemAlloc / CoTaskMemFree (the COM heap pair)
    WinsdkApi("CoTaskMemAlloc", WinCc::Stdcall, {
        {"cb", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return w(ql).heap().alloc(api_get_int(get_param(params, "cb")));
    };
    WinsdkApi("CoTaskMemFree", WinCc::Stdcall, {
        {"pv", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).heap().free(api_get_int(get_param(params, "pv")));
        return std::nullopt;
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
