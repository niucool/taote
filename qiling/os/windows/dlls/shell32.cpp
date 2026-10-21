// Ported from qiling/os/windows/dlls/shell32.py — the SHGetFileInfo pair (the
// large-icon ride), the ShellExecute pair (a fresh READY thread rides the
// handle manager; the struct write-back carries hInstApp 33 + the handle id),
// and the special-folder walk (the CSIDL_COMMON_APPDATA profile path).
#ifndef QILING_OS_WINDOWS_DLLS_SHELL32_CPP
#define QILING_OS_WINDOWS_DLLS_SHELL32_CPP

#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/thread.hpp"
#include "qiling/os/windows/windows.hpp"

#include <filesystem>

#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// shell32.py _SHGetFileInfo
std::uint64_t sh_get_file_info_body(Qiling& ql, const ResolvedParams& params) {
    const auto uflags = api_get_int(get_param(params, "uFlags"));

    if (uflags == SHGFI_LARGEICON) {
        // TODO: is this a valid DWORD_PTR ?  (verbatim)
        return 1;
    }

    throw QlErrorNotImplemented("API not implemented");
}

// shell32.py _ShellExecute: log the command parts, spawn a READY thread and
// register its handle
Handle shell_execute_body(Qiling& ql, const ResolvedParams& params, bool wide) {
    const auto read_opt = [&](std::uint64_t ptr) {
        return ptr != 0 ? (wide ? QlOsUtils::read_wstring(ql, ptr) : QlOsUtils::read_cstring(ql, ptr))
                        : std::string();
    };

    const auto read_field = [&](const char* name) -> std::string {
        const auto& p = get_param(params, name);
        if (const auto* s = std::get_if<std::string>(&p.second)) {
            return *s;  // the resolved WSTRING placeholders ride decoded
        }
        return read_opt(api_get_int(p));
    };

    const auto verb = read_field("lpOperation");
    const auto file = read_field("lpFile");
    const auto params_str = read_field("lpParameters");
    const auto directory = read_field("lpDirectory");
    (void)params_str;
    (void)directory;

    windows::QlWindowsThread process(&ql, windows::ThreadStatus::Ready);
    Handle handle(std::nullopt, &process);
    handle.owned = std::make_shared<windows::QlWindowsThread>(std::move(process));
    handle.obj = handle.owned.get();
    w(ql).handle_manager().append(handle);

    return handle;
}

}  // namespace

void register_shell32_family() {
    using namespace qiling::os::api;

    // DWORD_PTR SHGetFileInfoA(LPCSTR pszPath, DWORD dwFileAttributes,
    //     SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags);
    WinsdkApi("SHGetFileInfoA", WinCc::Stdcall, {
        {"pszPath", LPCSTR_},
        {"dwFileAttributes", DWORD_},
        {"psfi", PVOID_},
        {"cbFileInfo", UINT_},
        {"uFlags", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return sh_get_file_info_body(ql, params);
    };

    // DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, ...);
    WinsdkApi("SHGetFileInfoW", WinCc::Stdcall, {
        {"pszPath", LPCWSTR_},
        {"dwFileAttributes", DWORD_},
        {"psfi", PVOID_},
        {"cbFileInfo", UINT_},
        {"uFlags", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return sh_get_file_info_body(ql, params);
    };

    // BOOL ShellExecuteExW(SHELLEXECUTEINFOA *pExecInfo);
    WinsdkApi("ShellExecuteExW", WinCc::Stdcall, {
        {"pExecInfo", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto p_exec_info = api_get_int(get_param(params, "pExecInfo"));

        // the .ref() ride: the handler reads the guest struct fields through
        // the documented offsets
        auto& mem = ql.mem();
        const auto hwnd = mem.read_ptr(p_exec_info + SHELLEXECUTEINFO_OFF_HWND, 8);
        const auto lp_verb = mem.read_ptr(p_exec_info + SHELLEXECUTEINFO_OFF_LPVERB, 8);
        const auto lp_file = mem.read_ptr(p_exec_info + SHELLEXECUTEINFO_OFF_LPFILE, 8);
        const auto n_show = mem.read_ptr(p_exec_info + SHELLEXECUTEINFO_OFF_NSHOW, 4);

        const std::uint64_t lp_verb_v = lp_verb;
        const std::uint64_t lp_file_v = lp_file;
        const std::uint64_t n_show_v = n_show;
        ResolvedParams local{
            {"lpOperation", lp_verb_v},
            {"lpFile", lp_file_v},
            {"lpParameters", std::uint64_t{0}},
            {"lpDirectory", std::uint64_t{0}},
            {"nShowCmd", n_show_v},
        };
        (void)hwnd;
        const auto handle = shell_execute_body(ql, local, true);

        // Write results
        mem.write_ptr(p_exec_info + SHELLEXECUTEINFO_OFF_HINSTAPP, 33, 8);
        mem.write_ptr(p_exec_info + SHELLEXECUTEINFO_OFF_HPROCESS, handle.id, 8);

        return 1;
    };

    // HINSTANCE ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile,
    //     LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd);
    WinsdkApi("ShellExecuteW", WinCc::Stdcall, {
        {"hwnd", HWND_},
        {"lpOperation", PVOID_},
        {"lpFile", PVOID_},
        {"lpParameters", PVOID_},
        {"lpDirectory", PVOID_},
        {"nShowCmd", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        shell_execute_body(ql, params, true);

        return 33;
    };

    // BOOL SHGetSpecialFolderPathW(HWND hwnd, LPWSTR pszPath, int csidl,
    //     BOOL fCreate);
    // pszPath is an OUT buffer: the reference types it LPWSTR (a pointer), not
    // LPCWSTR (an input string). With the input type the resolver turned the
    // argument into its *content* and api_get_int answered 0, so the handler
    // wrote the wide path to address 0 — measured as GandCrab's admin run
    // dying 24 ms in with "failed to write memory (uc_err 7 at 0x0 (50 bytes))"
    // from this handler's ql.mem().write.
    WinsdkApi("SHGetSpecialFolderPathW", WinCc::Stdcall, {
        {"hwnd", HWND_},
        {"pszPath", LPWSTR_},
        {"csidl", INT_},
        {"fCreate", BOOL_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto directory_id = api_get_int(get_param(params, "csidl"));
        const auto dst = api_get_int(get_param(params, "pszPath"));

        if (directory_id == CSIDL_COMMON_APPDATA) {
            auto& os = w(ql);
            const auto path = os.userprofile() + "\\AppData\\";

            const std::size_t slash = path.find("C:\\");
            const auto appdata_dir = slash == std::string::npos
                ? path
                : path.substr(slash + 3);
            std::string emulated;
            for (const char c : appdata_dir) {
                emulated.push_back(c == '\\' ? '/' : c);
            }
            const auto path_emulated = std::filesystem::path(ql.rootfs()) / std::filesystem::path(emulated);

            const auto wide = [&] {
                std::vector<std::uint8_t> bytes;
                for (const char c : path + '\0') {
                    bytes.push_back(static_cast<std::uint8_t>(c));
                    bytes.push_back(0);
                }
                return bytes;
            }();
            ql.mem().write(dst, wide);

            // FIXME: Somehow winodws path is wrong  (verbatim)
            std::error_code ec;
            if (!std::filesystem::exists(path_emulated, ec)) {
                std::filesystem::create_directories(path_emulated, ec);
                if (ec) {
                    // the os.makedirs failed ride (the verbatim debug note)
                }
            }
        } else {
            throw QlErrorNotImplemented("API not implemented");
        }

        return 1;
    };

    // HINSTANCE ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile,
    //     LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd); — the ANSI
    // twin (the shell surface rides the handle-manager stub)
    WinsdkApi("ShellExecuteA", WinCc::Stdcall, {
        {"hwnd", HWND_},
        {"lpOperation", LPCSTR_},
        {"lpFile", LPCSTR_},
        {"lpParameters", LPCSTR_},
        {"lpDirectory", LPCSTR_},
        {"nShowCmd", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        shell_execute_body(ql, params, false);
        return 33;  // SE_ERR_NOASSOC rides >32 (the success shape)
    };

    // HRESULT SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD
    //                          dwFlags, LPSTR pszPath); — the folder text
    // rides the profile identities (the CSIDL_WINDOWS shape)
    WinsdkApi("SHGetFolderPathA", WinCc::Stdcall, {
        {"hwnd", HWND_},
        {"csidl", INT_},
        {"hToken", PVOID_},
        {"dwFlags", DWORD_},
        {"pszPath", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto csidl = static_cast<int>(api_get_int(get_param(params, "csidl")));
        const auto psz_path = api_get_int(get_param(params, "pszPath"));

        // the CSIDL values (shlobj.h): the profile-known shapes only
        std::string folder;
        if (csidl == 0x24) {       // CSIDL_WINDOWS
            folder = w(ql).windir();
        } else if (csidl == 0x26) {  // CSIDL_PROGRAM_FILES
            folder = "C:\\Program Files";
        } else if (csidl == 0x1a) {  // CSIDL_APPDATA
            folder = w(ql).userprofile() + "\\AppData\\Roaming";
        }

        if (folder.empty()) {
            w(ql).set_last_error(0x80004005u >> 0);  // E_FAIL shape
            return static_cast<std::uint64_t>(0x80004005u);
        }
        if (psz_path != 0) {
            ql.mem().write(psz_path, std::vector<std::uint8_t>(folder.begin(), folder.end()));
            ql.mem().write_ptr(psz_path + folder.size(), 0, 1);
        }
        return S_OK;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kShell32Registered = [] {
    qiling::os::win::register_shell32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_SHELL32_CPP
