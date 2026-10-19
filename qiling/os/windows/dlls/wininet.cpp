// Ported from qiling/os/windows/dlls/wininet.py — the internet-stub family.
// Most handlers are the verbatim no-ops (the `pass` bodies); the BOOLAPI
// members answer the verbatim 1 so the malware's request walks keep flowing.
#ifndef QILING_OS_WINDOWS_DLLS_WININET_CPP
#define QILING_OS_WINDOWS_DLLS_WININET_CPP

#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace qiling {
namespace os {
namespace win {

void register_wininet_family() {
    using namespace qiling::os::api;

    // void InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType,
    //     LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
    WinsdkApi("InternetOpenA", WinCc::Stdcall, {
        {"lpszAgent", LPCSTR_},
        {"dwAccessType", DWORD_},
        {"lpszProxy", LPCSTR_},
        {"lpszProxyBypass", LPCSTR_},
        {"dwFlags", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;  // the verbatim `pass`
    };

    // void InternetOpenW(LPCWSTR lpszAgent, ...);
    WinsdkApi("InternetOpenW", WinCc::Stdcall, {
        {"lpszAgent", LPCWSTR_},
        {"dwAccessType", DWORD_},
        {"lpszProxy", LPCWSTR_},
        {"lpszProxyBypass", LPCWSTR_},
        {"dwFlags", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl,
    //     LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags,
    //     DWORD_PTR dwContext);
    WinsdkApi("InternetOpenUrlA", WinCc::Stdcall, {
        {"hInternet", PVOID_},
        {"lpszUrl", LPCSTR_},
        {"lpszHeaders", LPCSTR_},
        {"dwHeadersLength", DWORD_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, ...);
    WinsdkApi("InternetOpenUrlW", WinCc::Stdcall, {
        {"hInternet", PVOID_},
        {"lpszUrl", LPCWSTR_},
        {"lpszHeaders", LPCWSTR_},
        {"dwHeadersLength", DWORD_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // BOOLAPI InternetCloseHandle(HINTERNET hInternet);
    WinsdkApi("InternetCloseHandle", WinCc::Stdcall, {
        {"hInternet", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // void InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName,
    //     INTERNET_PORT nServerPort, LPCSTR lpszUserName,
    //     LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags,
    //     DWORD_PTR dwContext);
    WinsdkApi("InternetConnectA", WinCc::Stdcall, {
        {"hInternet", PVOID_},
        {"lpszServerName", LPCSTR_},
        {"nServerPort", WORD_},   // the INTERNET_PORT (the api.py WORD ride)
        {"lpszUserName", LPCSTR_},
        {"lpszPassword", LPCSTR_},
        {"dwService", DWORD_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, ...);
    WinsdkApi("InternetConnectW", WinCc::Stdcall, {
        {"hInternet", PVOID_},
        {"lpszServerName", LPCWSTR_},
        {"nServerPort", WORD_},
        {"lpszUserName", LPCWSTR_},
        {"lpszPassword", LPCWSTR_},
        {"dwService", DWORD_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags,
    //     DWORD dwReserved);
    WinsdkApi("InternetCheckConnectionA", WinCc::Stdcall, {
        {"lpszUrl", LPCSTR_},
        {"dwFlags", DWORD_},
        {"dwReserved", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb,
    //     LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer,
    //     LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("HttpOpenRequestA", WinCc::Stdcall, {
        {"hConnect", PVOID_},
        {"lpszVerb", LPCSTR_},
        {"lpszObjectName", LPCSTR_},
        {"lpszVersion", LPCSTR_},
        {"lpszReferrer", LPCSTR_},
        {"lplpszAcceptTypes", PVOID_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // BOOLAPI HttpSendRequestExA(HINTERNET hRequest,
    //     LPINTERNET_BUFFERSA lpBuffersIn, LPINTERNET_BUFFERSA lpBuffersOut,
    //     DWORD dwFlags, DWORD_PTR dwContext);
    WinsdkApi("HttpSendRequestExA", WinCc::Stdcall, {
        {"hRequest", PVOID_},
        {"lpBuffersIn", PVOID_},
        {"lpBuffersOut", PVOID_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, ...);
    WinsdkApi("HttpOpenRequestW", WinCc::Stdcall, {
        {"hConnect", PVOID_},
        {"lpszVerb", LPCWSTR_},
        {"lpszObjectName", LPCWSTR_},
        {"lpszVersion", LPCWSTR_},
        {"lpszReferrer", LPCWSTR_},
        {"lplpszAcceptTypes", PVOID_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // BOOLAPI InternetSetOptionA(HINTERNET hInternet, DWORD dwOption,
    //     LPVOID lpBuffer, DWORD dwBufferLength);
    WinsdkApi("InternetSetOptionA", WinCc::Stdcall, {
        {"hInternet", PVOID_},
        {"dwOption", DWORD_},
        {"lpBuffer", PVOID_},
        {"dwBufferLength", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOLAPI InternetSetOptionW(HINTERNET hInternet, DWORD dwOption,
    //     LPVOID lpBuffer, DWORD dwBufferLength);
    WinsdkApi("InternetSetOptionW", WinCc::Stdcall, {
        {"hInternet", PVOID_},
        {"dwOption", DWORD_},
        {"lpBuffer", PVOID_},
        {"dwBufferLength", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOLAPI HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders,
    //     DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    WinsdkApi("HttpSendRequestA", WinCc::Stdcall, {
        {"hRequest", PVOID_},
        {"lpszHeaders", LPCSTR_},
        {"dwHeadersLength", DWORD_},
        {"lpOptional", PVOID_},
        {"dwOptionalLength", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOLAPI HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, ...);
    WinsdkApi("HttpSendRequestW", WinCc::Stdcall, {
        {"hRequest", PVOID_},
        {"lpszHeaders", LPCWSTR_},
        {"dwHeadersLength", DWORD_},
        {"lpOptional", PVOID_},
        {"dwOptionalLength", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // void InternetErrorDlg(HWND hWnd, HINTERNET hRequest, DWORD dwError,
    //     DWORD dwFlags, LPVOID *lppvData);
    WinsdkApi("InternetErrorDlg", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"hRequest", PVOID_},
        {"dwError", DWORD_},
        {"dwFlags", DWORD_},
        {"lppvData", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // BOOLAPI InternetReadFile(HINTERNET hFile, LPVOID lpBuffer,
    //     DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
    WinsdkApi("InternetReadFile", WinCc::Stdcall, {
        {"hFile", PVOID_},
        {"lpBuffer", PVOID_},
        {"dwNumberOfBytesToRead", DWORD_},
        {"lpdwNumberOfBytesRead", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOLAPI InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer,
    //     DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
    WinsdkApi("InternetWriteFile", WinCc::Stdcall, {
        {"hFile", PVOID_},
        {"lpBuffer", PVOID_},
        {"dwNumberOfBytesToWrite", DWORD_},
        {"lpdwNumberOfBytesWritten", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOLAPI HttpEndRequestA(HINTERNET hRequest,
    //     LPINTERNET_BUFFERSA lpBuffersOut, DWORD dwFlags,
    //     DWORD_PTR dwContext);
    WinsdkApi("HttpEndRequestA", WinCc::Stdcall, {
        {"hRequest", PVOID_},
        {"lpBuffersOut", PVOID_},
        {"dwFlags", DWORD_},
        {"dwContext", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kWininetRegistered = [] {
    qiling::os::win::register_wininet_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_WININET_CPP
