// Ported from qiling/os/windows/dlls/wininet.py — the WinINet surface the PMA
// corpus needs (PLAN_PARITY.md Phase 2, census-driven).
//
// Upstream answers most of these with a pass-through; the corpus samples call
// them to drive their network path, so the port answers success with the
// documented shapes and records the URL the sample asked for in the string log
// (that is what the reference PMA cases assert as a uri indicator).
#include <cstdint>
#include <optional>
#include <string>

#include "qiling/os/fcall.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace qiling {
namespace os {
namespace win {

using namespace api;

namespace {

// the optional param probe: a handler driven without its argument table (the
// harness idiom, and the reference suite's verbatim-pass rows) must answer the
// documented default instead of throwing
std::uint64_t param_or(const ResolvedParams& params, const char* name, std::uint64_t fallback = 0) {
    for (const auto& p : params) {
        if (p.first == name) {
            return api_get_int(p);
        }
    }
    return fallback;
}

}  // namespace
namespace {

}  // namespace

void register_wininet_family() {
    // BOOL InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved);
    WinsdkApi("InternetGetConnectedState", WinCc::Stdcall, {
        {"lpdwFlags", api::LPDWORD_},
        {"dwReserved", api::DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto flags = param_or(params, "lpdwFlags");
        if (flags != 0) {
            // INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED
            ql.mem().write_ptr(flags, 0x02 | 0x04, 4);
        }
        return 1;
    };

    // HINTERNET InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType,
    //                         LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
    WinsdkApi("InternetOpenA", WinCc::Stdcall, {
        {"lpszAgent", api::LPCSTR_},
        {"dwAccessType", api::DWORD_},
        {"lpszProxy", api::LPCSTR_},
        {"lpszProxyBypass", api::LPCSTR_},
        {"dwFlags", api::DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        (void)ql;
        (void)params;
        return 0;  // qiling parity: the verbatim pass-through (None -> 0)
    };

    WinsdkApi("InternetOpenW", WinCc::Stdcall, {
        {"lpszAgent", api::LPCWSTR_},
        {"dwAccessType", api::DWORD_},
        {"lpszProxy", api::LPCWSTR_},
        {"lpszProxyBypass", api::LPCWSTR_},
        {"dwFlags", api::DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        (void)ql;
        (void)params;
        return 0;  // qiling parity: the verbatim pass-through (None -> 0)
    };

    // HINTERNET InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl,
    //                            LPCSTR lpszHeaders, DWORD dwHeadersLength,
    //                            DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("InternetOpenUrlA", WinCc::Stdcall, {
        {"hInternet", api::HANDLE_},
        {"lpszUrl", api::LPCSTR_},
        {"lpszHeaders", api::LPCSTR_},
        {"dwHeadersLength", api::DWORD_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::ULONG_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // the URL is the indicator the reference cases assert (the param table
        // may be empty when a harness drives the handler directly)
        {
            const auto url = params.empty() ? std::string() : api_get_string(ql, get_param(params, "lpszUrl"));
            if (!url.empty()) {
                ql.os().stats().log_string(url);
                ql.os().stats().log_indicator("net_http", url);
            }
        }
        return 0;  // qiling parity: the verbatim pass-through (None -> 0)
    };

    WinsdkApi("InternetOpenUrlW", WinCc::Stdcall, {
        {"hInternet", api::HANDLE_},
        {"lpszUrl", api::LPCWSTR_},
        {"lpszHeaders", api::LPCWSTR_},
        {"dwHeadersLength", api::DWORD_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::ULONG_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        {
            const auto url = params.empty() ? std::string() : api_get_string(ql, get_param(params, "lpszUrl"));
            if (!url.empty()) {
                ql.os().stats().log_string(url);
                ql.os().stats().log_indicator("net_http", url);
            }
        }
        return 0;  // qiling parity: the verbatim pass-through (None -> 0)
    };

    // the remaining qiling-parity pass-throughs (upstream answers None -> 0):
    // registered here so the family is complete after the name-keyed override
    for (const char* name : {"InternetConnectA", "InternetConnectW", "InternetCheckConnectionA",
                             "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestExA",
                             "InternetErrorDlg"}) {
        WinsdkApi(name, WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t,
                                                 const ResolvedParams&) -> std::optional<std::uint64_t> {
            return 0;
        };
    }

    // BOOL InternetReadFile(HINTERNET hFile, LPVOID lpBuffer,
    //                       DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
    WinsdkApi("InternetReadFile", WinCc::Stdcall, {
        {"hFile", api::HANDLE_},
        {"lpBuffer", api::LPVOID_},
        {"dwNumberOfBytesToRead", api::DWORD_},
        {"lpdwNumberOfBytesRead", api::LPDWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // the end of the document: zero bytes read, success
        const auto read_ptr = param_or(params, "lpdwNumberOfBytesRead");
        if (read_ptr != 0) {
            ql.mem().write_ptr(read_ptr, 0, 4);
        }
        return 1;
    };

    // BOOL InternetCloseHandle(HINTERNET hInternet);
    WinsdkApi("InternetCloseHandle", WinCc::Stdcall, {
        {"hInternet", api::HANDLE_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto handle = param_or(params, "hInternet");
        w(ql).handle_manager().delete_handle(handle);
        return 1;
    };

    // BOOL InternetQueryDataAvailable(HINTERNET, LPDWORD, DWORD, DWORD_PTR);
    WinsdkApi("InternetQueryDataAvailable", WinCc::Stdcall, {
        {"hFile", api::HANDLE_},
        {"lpdwNumberOfBytesAvailable", api::LPDWORD_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::ULONG_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto avail = param_or(params, "lpdwNumberOfBytesAvailable");
        if (avail != 0) {
            ql.mem().write_ptr(avail, 0, 4);
        }
        return 1;
    };

    // BOOL InternetSetOptionW — the wide twin, same answer
    WinsdkApi("InternetSetOptionW", WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t,
                                                             const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL InternetWriteFile(HINTERNET, LPCVOID, DWORD, LPDWORD);
    WinsdkApi("InternetWriteFile", WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t,
                                                            const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL HttpSendRequestA/W, HttpEndRequestA — the verbatim 1s
    for (const char* name : {"HttpSendRequestA", "HttpSendRequestW", "HttpEndRequestA"}) {
        WinsdkApi(name, WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t,
                                                 const ResolvedParams&) -> std::optional<std::uint64_t> {
            return 1;
        };
    }

    // BOOL InternetSetOptionA(HINTERNET, DWORD, LPVOID, DWORD);
    WinsdkApi("InternetSetOptionA", WinCc::Stdcall, {
        {"hInternet", api::HANDLE_},
        {"dwOption", api::DWORD_},
        {"lpBuffer", api::LPVOID_},
        {"dwBufferLength", api::DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        (void)ql;
        (void)params;
        return 1;
    };

    // ---- the HTTP request surface ---------------------------------------
    //
    // Ported from wininet.py, where every one of these is a bare `pass`: the
    // reference resolves the arguments (so a bad string is still caught) and
    // leaves the return register alone. A handler returning nullopt is the same
    // shape here — qiling's fcall only writes the return register when the
    // handler answered, so "no answer" and `pass` are indistinguishable to the
    // guest. The handles/requests these would produce are not modelled: the
    // samples that walk this surface treat a failure as "no network", which is
    // what an emulator without a socket has to say.
    const auto noop_passthru = [](Qiling&, std::uint64_t,
                                  const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // HINTERNET InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName,
    //     INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword,
    //     DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("InternetConnectA", WinCc::Stdcall, {
        {"hInternet", api::HANDLE_},
        {"lpszServerName", api::LPCSTR_},
        {"nServerPort", api::WORD_},
        {"lpszUserName", api::LPCSTR_},
        {"lpszPassword", api::LPCSTR_},
        {"dwService", api::DWORD_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::DWORD_PTR_},
    }) = noop_passthru;

    // HINTERNET InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName,
    //     INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword,
    //     DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("InternetConnectW", WinCc::Stdcall, {
        {"hInternet", api::HANDLE_},
        {"lpszServerName", api::LPCWSTR_},
        {"nServerPort", api::WORD_},
        {"lpszUserName", api::LPCWSTR_},
        {"lpszPassword", api::LPCWSTR_},
        {"dwService", api::DWORD_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::DWORD_PTR_},
    }) = noop_passthru;

    // BOOL InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags,
    //     DWORD dwReserved);
    WinsdkApi("InternetCheckConnectionA", WinCc::Stdcall, {
        {"lpszUrl", api::LPCSTR_},
        {"dwFlags", api::DWORD_},
        {"dwReserved", api::DWORD_},
    }) = noop_passthru;

    // HINTERNET HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb,
    //     LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer,
    //     LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("HttpOpenRequestA", WinCc::Stdcall, {
        {"hConnect", api::HANDLE_},
        {"lpszVerb", api::LPCSTR_},
        {"lpszObjectName", api::LPCSTR_},
        {"lpszVersion", api::LPCSTR_},
        {"lpszReferrer", api::LPCSTR_},
        {"lplpszAcceptTypes", api::LPCSTR_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::DWORD_PTR_},
    }) = noop_passthru;

    // HINTERNET HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb,
    //     LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer,
    //     LPCWSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("HttpOpenRequestW", WinCc::Stdcall, {
        {"hConnect", api::HANDLE_},
        {"lpszVerb", api::LPCWSTR_},
        {"lpszObjectName", api::LPCWSTR_},
        {"lpszVersion", api::LPCWSTR_},
        {"lpszReferrer", api::LPCWSTR_},
        {"lplpszAcceptTypes", api::LPCWSTR_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::DWORD_PTR_},
    }) = noop_passthru;

    // BOOL HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders,
    //     DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    WinsdkApi("HttpSendRequestA", WinCc::Stdcall, {
        {"hRequest", api::HANDLE_},
        {"lpszHeaders", api::LPCSTR_},
        {"dwHeadersLength", api::DWORD_},
        {"lpOptional", api::LPVOID_},
        {"dwOptionalLength", api::DWORD_},
    }) = noop_passthru;

    // BOOL HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders,
    //     DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    WinsdkApi("HttpSendRequestW", WinCc::Stdcall, {
        {"hRequest", api::HANDLE_},
        {"lpszHeaders", api::LPCWSTR_},
        {"dwHeadersLength", api::DWORD_},
        {"lpOptional", api::LPVOID_},
        {"dwOptionalLength", api::DWORD_},
    }) = noop_passthru;

    // BOOL HttpSendRequestExA(HINTERNET hRequest,
    //     LPINTERNET_BUFFERSA lpBuffersIn, LPINTERNET_BUFFERSA lpBuffersOut,
    //     DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("HttpSendRequestExA", WinCc::Stdcall, {
        {"hRequest", api::HANDLE_},
        {"lpBuffersIn", api::LPVOID_},
        {"lpBuffersOut", api::LPVOID_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::DWORD_PTR_},
    }) = noop_passthru;

    // BOOL HttpEndRequestA(HINTERNET hRequest, LPINTERNET_BUFFERSA lpBuffersOut,
    //     DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("HttpEndRequestA", WinCc::Stdcall, {
        {"hRequest", api::HANDLE_},
        {"lpBuffersOut", api::LPVOID_},
        {"dwFlags", api::DWORD_},
        {"dwContext", api::DWORD_PTR_},
    }) = noop_passthru;

    // DWORD InternetErrorDlg(HWND hWnd, HINTERNET hRequest, DWORD dwError,
    //     DWORD dwFlags, LPVOID *lppvData);
    WinsdkApi("InternetErrorDlg", WinCc::Stdcall, {
        {"hWnd", api::HWND_},
        {"hRequest", api::HANDLE_},
        {"dwError", api::DWORD_},
        {"dwFlags", api::DWORD_},
        {"lppvData", api::LPVOID_},
    }) = noop_passthru;
}

}  // namespace win
}  // namespace os
}  // namespace qiling
