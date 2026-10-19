// Ported from qiling/os/windows/dlls/shlwapi.py — the path-walk pair and the
// StrCmp pair (the verbatim pointer arithmetic rides the python rsplit walks).
#ifndef QILING_OS_WINDOWS_DLLS_SHLWAPI_CPP
#define QILING_OS_WINDOWS_DLLS_SHLWAPI_CPP

#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <cctype>

namespace qiling {
namespace os {
namespace win {

namespace {

// windows/utils.py cmp: the sign walk ((a > b) - (a < b))
std::int64_t cmp_strings(const std::string& a, const std::string& b) {
    if (a > b) {
        return 1;
    }
    if (a < b) {
        return -1;
    }
    return 0;
}

}  // namespace

void register_shlwapi_family() {
    using namespace qiling::os::api;

    // LPCSTR PathFindExtensionA(LPCSTR pszPath);
    WinsdkApi("PathFindExtensionA", WinCc::Stdcall, {
        {"pszPath", PVOID_},  // the api.py POINTER (the raw read rides here)
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "pszPath"));
        const auto pathname = QlOsUtils::read_cstring(ql, pointer);

        // return a pointer to the dot, or null-terminator if there is no dot
        const auto head = pathname.substr(0, pathname.rfind('.'));
        return pointer + head.size();
    };

    // LPCSTR PathFindExtensionW(LPWSTR pszPath);
    WinsdkApi("PathFindExtensionW", WinCc::Stdcall, {
        {"pszPath", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "pszPath"));
        const auto pathname = QlOsUtils::read_wstring(ql, pointer);

        // return a pointer to the dot, or null-terminator if there is no dot
        // TODO: do we need to multiply the offset by sizeof wchar?  (verbatim)
        const auto head = pathname.substr(0, pathname.rfind('.'));
        return pointer + head.size();
    };

    // LPCSTR PathFindFileNameA(LPCSTR pszPath);
    WinsdkApi("PathFindFileNameA", WinCc::Stdcall, {
        {"pszPath", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "pszPath"));
        const auto pathname = QlOsUtils::read_cstring(ql, pointer);

        // return a pointer to the filename, or to the path if there is dir
        // prefix (the f'\\{pathname}' prefix ride)
        const auto prefixed = std::string("\\") + pathname;
        const auto head = prefixed.substr(0, prefixed.rfind('\\'));
        return pointer + head.size();
    };

    // LPCSTR PathFindFileNameW(LPWSTR pszPath);
    WinsdkApi("PathFindFileNameW", WinCc::Stdcall, {
        {"pszPath", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "pszPath"));
        const auto pathname = QlOsUtils::read_wstring(ql, pointer);

        // TODO: do we need to multiply the offset by sizeof wchar?  (verbatim)
        const auto prefixed = std::string("\\") + pathname;
        const auto head = prefixed.substr(0, prefixed.rfind('\\'));
        return pointer + head.size();
    };

    // int StrCmpW(PCWSTR psz1, PCWSTR psz2);
    WinsdkApi("StrCmpW", WinCc::Stdcall, {
        {"psz1", LPCWSTR_},
        {"psz2", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto& str1 = api_get_string(ql, get_param(params, "psz1"));
        const auto& str2 = api_get_string(ql, get_param(params, "psz2"));

        return static_cast<std::uint64_t>(cmp_strings(str1, str2));
    };

    // int StrCmpIW(PCWSTR psz1, PCWSTR psz2);
    WinsdkApi("StrCmpIW", WinCc::Stdcall, {
        {"psz1", LPCWSTR_},
        {"psz2", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto str1 = api_get_string(ql, get_param(params, "psz1"));
        auto str2 = api_get_string(ql, get_param(params, "psz2"));

        const auto lower = [](std::string& s) {
            for (auto& c : s) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
        };
        lower(str1);
        lower(str2);

        return static_cast<std::uint64_t>(cmp_strings(str1, str2));
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kShlwapiRegistered = [] {
    qiling::os::win::register_shlwapi_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_SHLWAPI_CPP
