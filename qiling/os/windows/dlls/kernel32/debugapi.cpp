// Ported from qiling/os/windows/dlls/kernel32/debugapi.py — the debug
// family (the PEB.BeingDebugged readers, the OutputDebugString loggers).
// The @winsdkapi decorators map onto register_debugapi_family(); the bodies
// ride the verbatim upstream walks (the PEB ride lands with the full
// TEB/PEB/LDR stack — the flag accessor is the placeholder until then).
// The family self-registers at static-init and can be re-seeded after
// ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the shared __is_debugger_present body: the PEB.BeingDebugged read (the
// placeholder accessor until the TEB/PEB/LDR stack lands)
std::uint64_t is_debugger_present(Qiling& ql) {
    return static_cast<loader::QlLoaderPE&>(ql.loader()).peb_being_debugged();
}

// the shared OutputDebugString body (the log-info pass)
std::optional<std::uint64_t> output_debug_string_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto text = api_get_string(ql, get_param(params, "lpOutputString"));
    ql.log().info(std::string(wide ? "OutputDebugStringW: \"" : "OutputDebugStringA: \"") + text + "\"");
    return 0;
}

}  // namespace

void register_debugapi_family() {
    using namespace qiling::os::api;

    // BOOL IsDebuggerPresent();
    WinsdkApi("IsDebuggerPresent", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return is_debugger_present(ql);
    };

    // BOOL CheckRemoteDebuggerPresent(
    //   HANDLE hProcess,
    //   PBOOL  pbDebuggerPresent
    // );
    WinsdkApi("CheckRemoteDebuggerPresent", WinCc::Stdcall, {
        {"hProcess", PVOID_},
        {"pbDebuggerPresent", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pb_debugger_present = api_get_int(get_param(params, "pbDebuggerPresent"));

        const auto res = is_debugger_present(ql);
        ql.mem().write(pb_debugger_present, ql.pack8(res));

        return 1;
    };

    // void OutputDebugStringW(
    //   LPCWSTR lpOutputString
    // );
    WinsdkApi("OutputDebugStringW", WinCc::Stdcall, {
        {"lpOutputString", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return output_debug_string_body(ql, params, true);
    };

    // void OutputDebugStringA(
    //  LPCSTR lpOutputString
    // );
    WinsdkApi("OutputDebugStringA", WinCc::Stdcall, {
        {"lpOutputString", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return output_debug_string_body(ql, params, false);
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kDebugapiRegistered = [] {
    register_debugapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
