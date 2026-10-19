// Ported from qiling/os/windows/dlls/kernel32/winnls.py — the NLS family
// (the locale pair, GetACP, GetCPInfo, GetLocaleInfoA, IsValidCodePage, the
// LCMapString copy walk, and the UI-language profile reads). The
// @winsdkapi decorators map onto register_winnls_family(); the bodies ride
// the verbatim upstream walks (the utf-16le encode inside the A-flavor
// GetLocaleInfoA quirk included). The family self-registers at static-init
// and can be re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
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

// the shared __LCMapString body (the byte-identity copy walk)
std::optional<std::uint64_t> lcmap_string_body(Qiling& ql, const ResolvedParams& params, const bool wstring) {
    const auto lp_src_str = api_get_int(get_param(params, "lpSrcStr"));
    const auto cch_src = api_get_int(get_param(params, "cchSrc"));
    const auto lp_dest_str = api_get_int(get_param(params, "lpDestStr"));
    const auto cch_dest = api_get_int(get_param(params, "cchDest"));

    const auto char_size = wstring ? 2u : 1u;
    const auto byte_count = static_cast<std::uint64_t>(cch_src) * char_size;

    if (cch_dest != 0 && lp_dest_str != 0) {
        const auto source_bytes = ql.mem().read(lp_src_str, static_cast<std::size_t>(byte_count));
        ql.mem().write(lp_dest_str, source_bytes);
    }

    return static_cast<std::uint64_t>(cch_src);
}

}  // namespace

void register_winnls_family() {
    using namespace qiling::os::api;

    // BOOL SetThreadLocale(
    //   LCID Locale
    // );
    WinsdkApi("SetThreadLocale", WinCc::Stdcall, {
        {"Locale", LCID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return LOCALE_CUSTOM_DEFAULT;
    };

    // LCID GetThreadLocale();
    WinsdkApi("GetThreadLocale", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return LOCALE_CUSTOM_DEFAULT;
    };

    // UINT GetACP(
    // );
    WinsdkApi("GetACP", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return OEM_US;
    };

    // BOOL GetCPInfo(
    //   UINT     CodePage,
    //   LPCPINFO lpCPInfo
    // );
    WinsdkApi("GetCPInfo", WinCc::Stdcall, {
        {"CodePage", UINT_},
        {"lpCPInfo", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // int GetLocaleInfoA(
    //   LCID   Locale,
    //   LCTYPE LCType,
    //   LPSTR  lpLCData,
    //   int    cchData
    // );
    WinsdkApi("GetLocaleInfoA", WinCc::Stdcall, {
        {"Locale", LCID_},
        {"LCType", DWORD_},
        {"lpLCData", LPSTR_},
        {"cchData", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto locale_value = api_get_int(get_param(params, "Locale"));
        const auto lctype_value = api_get_int(get_param(params, "LCType"));
        const auto cch_data = api_get_int(get_param(params, "cchData"));

        // the verbatim .get walk: only the 0x409 locale rides (the python
        // dict also carries a "default" STRING key no int lookup can hit)
        const auto it = LOCALE.find(static_cast<std::uint32_t>(locale_value));
        if (it == LOCALE.end()) {
            // raise QlErrorNotImplemented("API not implemented")  (verbatim
            // commented shape rides the error path instead)
            w(ql).set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        // the verbatim [] lookup: an LCType outside the table raises (the
        // python KeyError propagates through the hook barrier)
        const auto found = it->second->find(static_cast<std::uint32_t>(lctype_value));
        if (found == it->second->end()) {
            throw QlErrorBase("LOCALE_EN_US lookup KeyError");
        }

        // lctype = local_dict[lctype_value] + "\x00"
        const std::string lctype = found->second + std::string(1, char(0));

        if (cch_data != 0) {
            const auto lplcdata = api_get_int(get_param(params, "lpLCData"));
            // the verbatim quirk: the A-flavor handler still encodes the
            // value utf-16le (lctype.encode("utf-16le"))
            std::string encoded;
            encoded.reserve(lctype.size() * 2);
            for (const char c : lctype) {
                encoded.push_back(c);
                encoded.push_back('\0');
            }
            ql.mem().write(lplcdata, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));
        }

        return lctype.size();
    };

    // BOOL IsValidCodePage(
    //  UINT CodePage
    // );
    WinsdkApi("IsValidCodePage", WinCc::Stdcall, {
        {"CodePage", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // int LCMapStringW(
    //   LCID    Locale,
    //   DWORD   dwMapFlags,
    //   LPCWSTR lpSrcStr,
    //   int     cchSrc,
    //   LPWSTR  lpDestStr,
    //   int     cchDest
    // );
    WinsdkApi("LCMapStringW", WinCc::Stdcall, {
        {"Locale", LCID_},
        {"dwMapFlags", DWORD_},
        {"lpSrcStr", PVOID_},
        {"cchSrc", INT_},
        {"lpDestStr", PVOID_},
        {"cchDest", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return lcmap_string_body(ql, params, true);
    };

    // int LCMapStringA(
    //   LCID   Locale,
    //   DWORD  dwMapFlags,
    //   LPCSTR lpSrcStr,
    //   int    cchSrc,
    //   LPSTR  lpDestStr,
    //   int    cchDest
    // );
    WinsdkApi("LCMapStringA", WinCc::Stdcall, {
        {"Locale", LCID_},
        {"dwMapFlags", DWORD_},
        {"lpSrcStr", PVOID_},
        {"cchSrc", INT_},
        {"lpDestStr", PVOID_},
        {"cchDest", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return lcmap_string_body(ql, params, false);
    };

    // int LCMapStringEx(
    //   LPCWSTR          lpLocaleName,
    //   DWORD            dwMapFlags,
    //   LPCWSTR          lpSrcStr,
    //   int              cchSrc,
    //   LPWSTR           lpDestStr,
    //   int              cchDest,
    //   LPNLSVERSIONINFO lpVersionInformation,
    //   LPVOID           lpReserved,
    //   LPARAM           sortHandle
    // );
    WinsdkApi("LCMapStringEx", WinCc::Stdcall, {
        {"lpLocaleName", LPCWSTR_},
        {"dwMapFlags", DWORD_},
        {"lpSrcStr", PVOID_},
        {"cchSrc", INT_},
        {"lpDestStr", PVOID_},
        {"cchDest", INT_},
        {"lpVersionInformation", PVOID_},
        {"lpReserved", PVOID_},
        {"sortHandle", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return lcmap_string_body(ql, params, true);
    };

    // LANGID GetUserDefaultUILanguage();
    WinsdkApi("GetUserDefaultUILanguage", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO find better documentation
        // https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
        // (verbatim)
        return static_cast<std::uint64_t>(ql.profile().get_int("USER", "language"));
    };

    // LANGID GetSystemDefaultUILanguage();
    WinsdkApi("GetSystemDefaultUILanguage", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO find better documentation
        // https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
        // (verbatim)
        return static_cast<std::uint64_t>(ql.profile().get_int("SYSTEM", "language"));
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kWinnlsRegistered = [] {
    register_winnls_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
