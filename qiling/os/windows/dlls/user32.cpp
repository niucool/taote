// Ported from qiling/os/windows/dlls/user32.py — the 60-handler user32
// surface. The window/GDI walkers answer the verbatim constants (the
// 0xD10C magic rides several), the clipboard pieces ride the Clipboard
// manager, the MessageBox press-table is verbatim, and the Char*/wsprintf
// walkers ride the string engine.
#ifndef QILING_OS_WINDOWS_DLLS_USER32_CPP
#define QILING_OS_WINDOWS_DLLS_USER32_CPP

#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/clipboard.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <cctype>
#include <map>

#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the user32.py magic: the recognizable handle sentinel
constexpr std::uint64_t kMagicHandle = 0xD10C;

// clipboard.py set_data: the format walk over the text handlers (the port
// keeps the locker check + the CF_TEXT/CF_UNICODETEXT readers)
std::uint64_t clipboard_set_data(Qiling& ql, std::uint32_t fmt, std::uint64_t h_mem) {
    auto& os = ql.os<windows::QlOsWindows>();
    auto& clip = os.clipboard();

    // the locker check rides the current thread id (clipboard.py verbatim)
    const auto h_wnd = static_cast<std::uint32_t>(os.thread_manager().cur_thread()->get_id());
    if (!clip.is_locked_by(h_wnd)) {
        os.set_last_error(windows::QL_ERROR_CLIPBOARD_NOT_OPEN);
        return 0;
    }

    if (fmt == windows::QL_CF_TEXT) {
        clip.set_data_raw(fmt, QlOsUtils::read_cstring(ql, h_mem));
    } else if (fmt == windows::QL_CF_UNICODETEXT) {
        clip.set_data_raw(fmt, QlOsUtils::read_wstring(ql, h_mem));
    } else {
        // TODO: support more clipboard formats  (verbatim)
        return 0;
    }

    // TODO: should create a handle for the clipboard object?  (verbatim)
    return h_mem;
}

std::uint64_t clipboard_get_data(Qiling& ql, std::uint32_t fmt) {
    auto& os = ql.os<windows::QlOsWindows>();
    auto& clip = os.clipboard();

    if (!clip.format_available(fmt)) {
        return 0;
    }

    const auto h_wnd = static_cast<std::uint32_t>(os.thread_manager().cur_thread()->get_id());
    if (!clip.is_locked_by(h_wnd)) {
        os.set_last_error(windows::QL_ERROR_CLIPBOARD_NOT_OPEN);
        return 0;
    }

    // the data bytes ride the guest buffer (the clipboard.py get_data walk;
    // the port writes the stored text at a fresh heap chunk — the upstream
    // returns the raw bytes object and the hook allocates)
    const auto& data = clip.data();
    const auto addr = os.heap().alloc(data.size());
    ql.mem().write(addr, std::vector<std::uint8_t>(data.begin(), data.end()));
    return addr;
}

}  // namespace

void register_user32_family() {
    using namespace qiling::os::api;

    // ATOM RegisterClassExA(const WNDCLASSEXA *Arg1);
    WinsdkApi("RegisterClassExA", WinCc::Stdcall, {
        {"lpWndClass", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // BOOL UpdateWindow(HWND hWnd);
    WinsdkApi("UpdateWindow", WinCc::Stdcall, {
        {"hWnd", HWND_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // HWND CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, ...);
    WinsdkApi("CreateWindowExA", WinCc::Stdcall, {
        {"dwExStyle", DWORD_},
        {"lpClassName", LPCSTR_},
        {"lpWindowName", LPCSTR_},
        {"dwStyle", DWORD_},
        {"X", INT_},
        {"Y", INT_},
        {"nWidth", INT_},
        {"nHeight", INT_},
        {"hWndParent", HWND_},
        {"hMenu", PVOID_},
        {"hInstance", HINSTANCE_},
        {"lpParam", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // HWND CreateWindowExW(...); — rides the A body
    WinsdkApi("CreateWindowExW", WinCc::Stdcall, {
        {"dwExStyle", DWORD_},
        {"lpClassName", LPCWSTR_},
        {"lpWindowName", LPCWSTR_},
        {"dwStyle", DWORD_},
        {"X", INT_},
        {"Y", INT_},
        {"nWidth", INT_},
        {"nHeight", INT_},
        {"hWndParent", HWND_},
        {"hMenu", PVOID_},
        {"hInstance", HINSTANCE_},
        {"lpParam", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // INT_PTR DialogBoxParamA(HINSTANCE, LPCSTR, HWND, DLGPROC, LPARAM);
    WinsdkApi("DialogBoxParamA", WinCc::Stdcall, {
        {"hInstance", HINSTANCE_},
        {"lpTemplateName", PVOID_},
        {"hWndParent", HWND_},
        {"lpDialogFunc", PVOID_},
        {"dwInitParam", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // UINT GetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPSTR lpString,
    //     int cchMax);
    WinsdkApi("GetDlgItemTextA", WinCc::Stdcall, {
        {"hDlg", HWND_},
        {"nIDDlgItem", INT_},
        {"lpString", LPSTR_},
        {"cchMax", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_string = api_get_int(get_param(params, "lpString"));
        const auto cch_max = api_get_int(get_param(params, "cchMax"));

        w(ql).stdout_stream().write({'I', 'n', 'p', 'u', 't', ' ', 'D', 'l', 'g', 'I', 't', 'e',
                                     'm', 'T', 'e', 'x', 't', ' ', ':', '\n'});
        // the stdin ride: the upstream readline().strip()[:cchMax] — the port
        // answers the empty input (the stdin is not wired at the handler
        // level) — the write of the empty string is the no-op
        std::string line;
        if (cch_max > 0) {
            line = QlOsUtils::read_cstring(ql, lp_string, cch_max);
            line = line.substr(0, line.find('\n'));
            if (line.size() > static_cast<std::size_t>(cch_max)) {
                line.resize(static_cast<std::size_t>(cch_max));
            }
            if (!line.empty()) {
                ql.mem().write(lp_string, std::vector<std::uint8_t>(line.begin(), line.end()));
            }
        }

        return line.size();
    };

    // BOOL EndDialog(HWND hDlg, INT_PTR nResult);
    WinsdkApi("EndDialog", WinCc::Stdcall, {
        {"hDlg", HWND_},
        {"nResult", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // HWND GetDesktopWindow();
    WinsdkApi("GetDesktopWindow", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;  // the verbatim `pass`
    };

    // BOOL OpenClipboard(HWND hWndNewOwner);
    WinsdkApi("OpenClipboard", WinCc::Stdcall, {
        {"hWndNewOwner", HWND_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_wnd = static_cast<std::uint32_t>(api_get_int(get_param(params, "hWndNewOwner")));
        return w(ql).clipboard().open(h_wnd) ? 1u : 0u;
    };

    // BOOL CloseClipboard();
    WinsdkApi("CloseClipboard", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).clipboard().close() ? 1u : 0u;
    };

    // HANDLE SetClipboardData(UINT uFormat, HANDLE hMem);
    WinsdkApi("SetClipboardData", WinCc::Stdcall, {
        {"uFormat", UINT_},
        {"hMem", HANDLE_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto uformat = static_cast<std::uint32_t>(api_get_int(get_param(params, "uFormat")));
        const auto h_mem = api_get_int(get_param(params, "hMem"));

        const auto handle = clipboard_set_data(ql, uformat, h_mem);

        if (handle == 0) {
            // Failed to set clipboard data (format = ...)  (verbatim debug)
        }
        return handle;
    };

    // HANDLE GetClipboardData(UINT uFormat);
    WinsdkApi("GetClipboardData", WinCc::Stdcall, {
        {"uFormat", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto uformat = static_cast<std::uint32_t>(api_get_int(get_param(params, "uFormat")));
        return clipboard_get_data(ql, uformat);
    };

    // BOOL IsClipboardFormatAvailable(UINT format);
    WinsdkApi("IsClipboardFormatAvailable", WinCc::Stdcall, {
        {"format", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto fmt = static_cast<std::uint32_t>(api_get_int(get_param(params, "format")));
        return w(ql).clipboard().format_available(fmt) ? 1u : 0u;
    };

    // UINT MapVirtualKeyW(UINT uCode, UINT uMapType);
    WinsdkApi("MapVirtualKeyW", WinCc::Stdcall, {
        {"uCode", UINT_},
        {"uMapType", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto map_value = api_get_int(get_param(params, "uMapType"));
        const auto code_value = api_get_int(get_param(params, "uCode"));

        const auto it = MAP_VK.find(static_cast<std::uint32_t>(map_value));
        if (it == MAP_VK.end()) {
            throw QlErrorNotImplemented("API not implemented");
        }

        const auto code_it = it->second.find(static_cast<std::uint32_t>(code_value));
        if (code_it == it->second.end()) {
            throw QlErrorNotImplemented("API not implemented");
        }

        return code_it->second;
    };

    // SHORT GetKeyState(int nVirtKey);
    WinsdkApi("GetKeyState", WinCc::Stdcall, {
        {"nVirtKey", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 2;  // DOWN=0, UP=2  (verbatim)
    };

    // UINT RegisterWindowMessageA(LPCSTR lpString);
    WinsdkApi("RegisterWindowMessageA", WinCc::Stdcall, {
        {"lpString", LPCSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // maybe some samples really use this and we need to have a real
        // implementation  (verbatim)
        return 0xD10C;
    };

    // UINT RegisterWindowMessageW(LPCWSTR lpString);
    WinsdkApi("RegisterWindowMessageW", WinCc::Stdcall, {
        {"lpString", LPCWSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xD10C;
    };

    // HWND GetActiveWindow();
    WinsdkApi("GetActiveWindow", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xD10C;
    };

    // HWND GetLastActivePopup(HWND hWnd);
    WinsdkApi("GetLastActivePopup", WinCc::Stdcall, {
        {"hWnd", HWND_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "hWnd"));
    };

    // BOOL GetPhysicalCursorPos(LPPOINT lpPoint);
    WinsdkApi("GetPhysicalCursorPos", WinCc::Stdcall, {
        {"lpPoint", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO: bug? return value doesn't look like a valid pointer  (verbatim)
        return 1;
    };

    // int GetSystemMetrics(int nIndex);
    WinsdkApi("GetSystemMetrics", WinCc::Stdcall, {
        {"nIndex", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto info = api_get_int(get_param(params, "nIndex"));

        static const std::map<std::uint64_t, std::uint64_t> sizes{
            {SM_CXICON, 32}, {SM_CYICON, 32}, {SM_CXVSCROLL, 4}, {SM_CYHSCROLL, 300},
        };
        const auto it = sizes.find(info);
        if (it == sizes.end()) {
            throw QlErrorNotImplemented("API not implemented");
        }
        return it->second;
    };

    // HDC GetDC(HWND hWnd);
    WinsdkApi("GetDC", WinCc::Stdcall, {
        {"hWnd", HWND_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Maybe we should really emulate the handling of screens and windows.
        // Is going to be a pain  (verbatim)
        return 0xD10C;
    };

    // int GetDeviceCaps(HDC hdc, int index);
    WinsdkApi("GetDeviceCaps", WinCc::Stdcall, {
        {"hdc", PVOID_},
        {"index", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // int ReleaseDC(HWND hWnd, HDC hDC);
    WinsdkApi("ReleaseDC", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"hDC", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // DWORD GetSysColor(int nIndex);
    WinsdkApi("GetSysColor", WinCc::Stdcall, {
        {"nIndex", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // HBRUSH GetSysColorBrush(int nIndex);
    WinsdkApi("GetSysColorBrush", WinCc::Stdcall, {
        {"nIndex", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xD10C;
    };

    // HCURSOR LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName);
    WinsdkApi("LoadCursorA", WinCc::Stdcall, {
        {"hInstance", HINSTANCE_},
        {"lpCursorName", LPCSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xD10C;
    };

    // HCURSOR LoadCursorFromFileA(LPCSTR lpFileName);
    WinsdkApi("LoadCursorFromFileA", WinCc::Stdcall, {
        {"lpFileName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        Handle handle;
        w(ql).handle_manager().append(handle);
        return handle.id;
    };

    // HCURSOR LoadCursorFromFileW(LPCSTR lpFileName);
    WinsdkApi("LoadCursorFromFileW", WinCc::Stdcall, {
        {"lpFileName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        Handle handle;
        w(ql).handle_manager().append(handle);
        return handle.id;
    };

    // UINT GetOEMCP();
    WinsdkApi("GetOEMCP", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return OEM_US;
    };

    // int LoadStringW(HINSTANCE hInstance, UINT uID, LPSTR lpBuffer,
    //     int cchBufferMax);
    WinsdkApi("LoadStringW", WinCc::Stdcall, {
        {"hInstance", HINSTANCE_},
        {"uID", UINT_},
        {"lpBuffer", LPWSTR_},
        {"cchBufferMax", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dst = api_get_int(get_param(params, "lpBuffer"));
        const auto max_len = api_get_int(get_param(params, "cchBufferMax"));

        // FIXME: should not be hardcoded  (verbatim)
        std::string s("AAAABBBBCCCCDDDD", 16);
        s.push_back('\0');

        if (max_len != 0) {
            if (s.size() >= static_cast<std::size_t>(max_len)) {
                s = s.substr(0, static_cast<std::size_t>(max_len)) + '\0';
            }
            const auto wide = [&] {
                std::vector<std::uint8_t> bytes;
                for (const char c : s) {
                    bytes.push_back(static_cast<std::uint8_t>(c));
                    bytes.push_back(0);
                }
                return bytes;
            }();
            ql.mem().write(dst, wide);
        }

        // should not count the \x00 byte  (verbatim)
        return s.size() - 1;
    };

    // int LoadStringA(HINSTANCE hInstance, UINT uID, LPSTR lpBuffer,
    //     int cchBufferMax);
    WinsdkApi("LoadStringA", WinCc::Stdcall, {
        {"hInstance", HINSTANCE_},
        {"uID", UINT_},
        {"lpBuffer", LPSTR_},
        {"cchBufferMax", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dst = api_get_int(get_param(params, "lpBuffer"));
        const auto max_len = api_get_int(get_param(params, "cchBufferMax"));

        std::string s("AAAABBBBCCCCDDDD", 16);
        s.push_back('\0');

        if (max_len != 0) {
            if (s.size() >= static_cast<std::size_t>(max_len)) {
                s = s.substr(0, static_cast<std::size_t>(max_len)) + '\0';
            }
            ql.mem().write(dst, std::vector<std::uint8_t>(s.begin(), s.end()));
        }

        return s.size() - 1;
    };

    // BOOL MessageBeep(UINT uType);
    WinsdkApi("MessageBeep", WinCc::Stdcall, {
        {"uType", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod,
    //     DWORD dwThreadId);
    WinsdkApi("SetWindowsHookExA", WinCc::Stdcall, {
        {"idHook", INT_},
        {"lpfn", PVOID_},
        {"hmod", HINSTANCE_},
        {"dwThreadId", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Should hook a procedure to a dll  (verbatim)
        return api_get_int(get_param(params, "lpfn"));
    };

    // BOOL UnhookWindowsHookEx(HHOOK hhk);
    WinsdkApi("UnhookWindowsHookEx", WinCc::Stdcall, {
        {"hhk", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL ShowWindow(HWND hWnd, int nCmdShow);
    WinsdkApi("ShowWindow", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"nCmdShow", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // return value depends on sample goal (evasion on just display error)
        return 1;
    };

    // HICON LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName);
    WinsdkApi("LoadIconA", WinCc::Stdcall, {
        {"hInstance", HINSTANCE_},
        {"lpIconName", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto name = api_get_int(get_param(params, "lpIconName"));
        // the dlls/const.py IDI_* set (the windows.h macro collisions on
        // _WIN32 ride the literals; APPLICATION 32512, ASTERISK 32516,
        // ERROR 32513, EXCLAMATION 32515, HAND 32513, INFORMATION 32516,
        // QUESTION 32514, SHIELD 32518, WARNING 32515, WINLOGO 32517)
        static const std::map<std::uint64_t, int> icons{
            {32512, 1}, {32513, 1}, {32514, 1}, {32515, 1},
            {32516, 1}, {32517, 1}, {32518, 1},
        };
        return icons.count(name) != 0 ? 1u : 0u;
    };

    // HICON LoadIconW(HINSTANCE hInstance, LPCWSTR lpIconName);
    WinsdkApi("LoadIconW", WinCc::Stdcall, {
        {"hInstance", HINSTANCE_},
        {"lpIconName", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto name = api_get_int(get_param(params, "lpIconName"));
        // the dlls/const.py IDI_* set (the windows.h macro collisions on
        // _WIN32 ride the literals; APPLICATION 32512, ASTERISK 32516,
        // ERROR 32513, EXCLAMATION 32515, HAND 32513, INFORMATION 32516,
        // QUESTION 32514, SHIELD 32518, WARNING 32515, WINLOGO 32517)
        static const std::map<std::uint64_t, int> icons{
            {32512, 1}, {32513, 1}, {32514, 1}, {32515, 1},
            {32516, 1}, {32517, 1}, {32518, 1},
        };
        return icons.count(name) != 0 ? 1u : 0u;
    };

    // BOOL IsWindow(HWND hWnd);
    WinsdkApi("IsWindow", WinCc::Stdcall, {
        {"hWnd", HWND_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // LRESULT SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
    WinsdkApi("SendMessageA", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"Msg", UINT_},
        {"wParam", ULONG_PTR_},
        {"lParam", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO don't know how to get right return value  (verbatim)
        return 0xD10C;
    };

    // LRESULT DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam,
    //     LPARAM lParam);
    WinsdkApi("DefWindowProcA", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"Msg", UINT_},
        {"wParam", ULONG_PTR_},
        {"lParam", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xD10C;
    };

    // DWORD CharLowerBuffA(LPSTR lpsz, DWORD cchLength);
    WinsdkApi("CharLowerBuffA", WinCc::Stdcall, {
        {"lpsz", LPSTR_},
        {"cchLength", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_buffer = api_get_int(get_param(params, "lpsz"));
        const auto cch_length = api_get_int(get_param(params, "cchLength"));

        auto data = ql.mem().read(lp_buffer, static_cast<std::size_t>(cch_length));
        for (auto& c : data) {
            c = static_cast<std::uint8_t>(std::tolower(c));
        }
        ql.mem().write(lp_buffer, data);

        return data.size();
    };

    // DWORD CharLowerBuffW(LPWSTR lpsz, DWORD cchLength);
    WinsdkApi("CharLowerBuffW", WinCc::Stdcall, {
        {"lpsz", LPWSTR_},
        {"cchLength", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_buffer = api_get_int(get_param(params, "lpsz"));
        const auto cch_length = api_get_int(get_param(params, "cchLength"));

        // the utf-16le units: the ASCII range folds in place (the upstream
        // decode/encode walk keeps the byte count identical)
        auto data = ql.mem().read(lp_buffer, static_cast<std::size_t>(cch_length) * 2);
        for (std::size_t k = 0; k + 1 < data.size(); k += 2) {
            if (data[k] >= 'A' && data[k] <= 'Z') {
                data[k] = static_cast<std::uint8_t>(data[k] - 'A' + 'a');
            }
        }
        ql.mem().write(lp_buffer, data);

        return data.size() / 2;
    };

    // LPSTR CharLowerA(LPSTR lpsz);
    WinsdkApi("CharLowerA", WinCc::Stdcall, {
        {"lpsz", LPSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lpsz = api_get_int(get_param(params, "lpsz"));

        if ((lpsz >> 16) > 0) {
            auto value = QlOsUtils::read_cstring(ql, lpsz);
            for (auto& c : value) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            ql.mem().write(lpsz, std::vector<std::uint8_t>(value.begin(), value.end()));
            return value.size();
        }
        // the single-char form: the low 16 bits ride the character
        const auto value = static_cast<char>(lpsz & 0xffff);
        const auto lowered = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
        return static_cast<std::uint8_t>(lowered);
    };

    // LPWSTR CharNextW(LPCWSTR lpsz);
    WinsdkApi("CharNextW", WinCc::Stdcall, {
        {"lpsz", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto addr = api_get_int(get_param(params, "lpsz"));
        const auto s = QlOsUtils::read_wstring(ql, addr);

        // return a pointer to the next non-null char  (verbatim; the +1 = the
        // byte quirk kept)
        return s.empty() ? addr : addr + 1;
    };

    // LPWSTR CharNextA(LPCSTR lpsz);
    WinsdkApi("CharNextA", WinCc::Stdcall, {
        {"lpsz", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto addr = api_get_int(get_param(params, "lpsz"));
        const auto s = QlOsUtils::read_cstring(ql, addr);

        return s.empty() ? addr : addr + 1;
    };

    // LPWSTR CharPrevW(LPCWSTR lpszStart, LPCWSTR lpszCurrent);
    WinsdkApi("CharPrevW", WinCc::Stdcall, {
        {"lpszStart", PVOID_},
        {"lpszCurrent", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto start = api_get_int(get_param(params, "lpszStart"));
        const auto current = api_get_int(get_param(params, "lpszCurrent"));

        // cannot go back beyond start pointer  (verbatim; the charlen 2)
        if (current < start + 2) {
            return start;
        }
        return current - 2;
    };

    // LPWSTR CharPrevA(LPCSTR lpszStart, LPCSTR lpszCurrent);
    WinsdkApi("CharPrevA", WinCc::Stdcall, {
        {"lpszStart", PVOID_},
        {"lpszCurrent", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto start = api_get_int(get_param(params, "lpszStart"));
        const auto current = api_get_int(get_param(params, "lpszCurrent"));

        if (current < start + 1) {
            return start;
        }
        return current - 1;
    };

    // int WINAPIV wsprintfW(LPWSTR, LPCWSTR, ...); — the CDECL
    WinsdkApi("wsprintfW", WinCc::Cdecl, {
        {"Buffer", PVOID_},
        {"Format", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buffer = api_get_int(get_param(params, "Buffer"));
        auto format = api_get_string(ql, get_param(params, "Format"));

        const std::vector<int> slots{os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        std::size_t cursor = 0;
        const auto pull = [&args, &cursor]() -> std::uint64_t {
            return cursor < args.size() ? args[cursor++] : 0;
        };

        return QlOsUtils::sprintf(ql, buffer, format, pull, true).count;
    };

    // HWND GetForegroundWindow();
    WinsdkApi("GetForegroundWindow", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xF02E620D;  // recognizable magic value  (verbatim)
    };

    // BOOL MoveWindow(HWND hWnd, int X, int Y, int nWidth, int nHeight,
    //     BOOL bRepaint);
    WinsdkApi("MoveWindow", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"X", INT_},
        {"Y", INT_},
        {"nWidth", INT_},
        {"nHeight", INT_},
        {"bRepaint", BOOL_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // int GetKeyboardType(int nTypeFlag);
    WinsdkApi("GetKeyboardType", WinCc::Stdcall, {
        {"nTypeFlag", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto tf = api_get_int(get_param(params, "nTypeFlag"));

        // 0: Keyboard Type, 1: Keyboard subtype, 2: num func keys
        // (the wine table)
        static const std::uint64_t kbtypes[] = {7, 0, 12};
        return tf < 3 ? kbtypes[tf] : 0u;
    };

    // int wvsprintfA(LPTSTR lpOutput, LPCTSTR lpFormat, va_list ArgList);
    // — the verbatim None body (the original CRT body keeps running)
    WinsdkApi("wvsprintfA", WinCc::Cdecl, {
        {"lpOutput", PVOID_},
        {"lpFormat", PVOID_},
        {"ArgList", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // int wsprintfA(char *buffer, const char *format, ...); — the CDECL
    WinsdkApi("wsprintfA", WinCc::Cdecl, {
        {"Buffer", LPSTR_},
        {"Format", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buffer = api_get_int(get_param(params, "Buffer"));
        auto format = api_get_string(ql, get_param(params, "Format"));

        const std::vector<int> slots{os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        std::size_t cursor = 0;
        const auto pull = [&args, &cursor]() -> std::uint64_t {
            return cursor < args.size() ? args[cursor++] : 0;
        };

        return QlOsUtils::sprintf(ql, buffer, format, pull, false).count;
    };

    // int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption,
    //     UINT uType);
    WinsdkApi("MessageBoxW", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"lpText", LPCWSTR_},
        {"lpCaption", LPCWSTR_},
        {"uType", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto utype = api_get_int(get_param(params, "uType"));

        const auto buttons = utype & 0x0000000f;

        // we strive to return a positive result when possible. if there is an
        // "ok", "yes" or "continue" button, press it  (verbatim)
        static const std::map<std::uint64_t, std::uint64_t> press{
            {MB_OK, IDOK},
            {MB_OKCANCEL, IDOK},
            {MB_ABORTRETRYIGNORE, IDABORT},
            {MB_YESNOCANCEL, IDYES},
            {MB_YESNO, IDYES},
            {MB_RETRYCANCEL, IDCANCEL},
            {MB_CANCELTRYCONTINUE, IDCONTINUE},
        };
        const auto it = press.find(buttons);
        return it != press.end() ? it->second : 0u;
    };

    // int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
    WinsdkApi("MessageBoxA", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"lpText", LPCSTR_},
        {"lpCaption", LPCSTR_},
        {"uType", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto utype = api_get_int(get_param(params, "uType"));
        const auto buttons = utype & 0x0000000f;
        static const std::map<std::uint64_t, std::uint64_t> press{
            {MB_OK, IDOK},
            {MB_OKCANCEL, IDOK},
            {MB_ABORTRETRYIGNORE, IDABORT},
            {MB_YESNOCANCEL, IDYES},
            {MB_YESNO, IDYES},
            {MB_RETRYCANCEL, IDCANCEL},
            {MB_CANCELTRYCONTINUE, IDCONTINUE},
        };
        const auto it = press.find(buttons);
        return it != press.end() ? it->second : 0u;
    };

    // BOOL GetCursorPos(LPPOINT lpPoint);
    WinsdkApi("GetCursorPos", WinCc::Stdcall, {
        {"lpPoint", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_point = api_get_int(get_param(params, "lpPoint"));

        // TODO: maybe we can add it to the profile too  (verbatim)
        // the Point(50, 50) image: the x/y i32 pairs
        std::string image(8, '\0');
        image[0] = 50;
        image[4] = 50;
        ql.mem().write(lp_point, std::vector<std::uint8_t>(image.begin(), image.end()));

        return 0;
    };

    // HANDLE CreateActCtxW(PCACTCTXW pActCtx);
    WinsdkApi("CreateActCtxW", WinCc::Stdcall, {
        {"pActCtx", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO: maybe is necessary to really create this  (verbatim)
        Handle handle(std::nullopt, nullptr, "actctx");
        w(ql).handle_manager().append(handle);

        return handle.id;
    };

    // DWORD GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
    WinsdkApi("GetWindowThreadProcessId", WinCc::Stdcall, {
        {"hWnd", HWND_},
        {"lpdwProcessId", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto target = api_get_int(get_param(params, "hWnd"));
        auto& os = w(ql);

        const auto pid = os.profile().get_int("KERNEL", "pid");
        const auto shell_pid = os.profile().get_int("KERNEL", "shell_pid");

        std::uint64_t answer = 0;
        if (target == pid || target == shell_pid) {
            answer = os.profile().get_int("KERNEL", "parent_pid");
        } else {
            throw QlErrorNotImplemented("API not implemented");
        }

        const auto dst = api_get_int(get_param(params, "lpdwProcessId"));
        if (dst != 0) {
            ql.mem().write_ptr(dst, answer, 4);
        }

        return answer;
    };

    // HWND GetShellWindow();
    WinsdkApi("GetShellWindow", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).profile().get_int("KERNEL", "shell_pid");
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kUser32Registered = [] {
    qiling::os::win::register_user32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_USER32_CPP
