// Ported from qiling/os/windows/dlls/kernel32/handleapi.py — the handle
// management family (DuplicateHandle/CloseHandle/SetHandleInformation). The
// @winsdkapi decorators map onto register_handleapi_family(); the bodies ride
// the verbatim upstream walks. The family self-registers at static-init and
// can be re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_handleapi_family() {
    using namespace qiling::os::api;

    // BOOL DuplicateHandle(
    //   HANDLE   hSourceProcessHandle,
    //   HANDLE   hSourceHandle,
    //   HANDLE   hTargetProcessHandle,
    //   LPHANDLE lpTargetHandle,
    //   DWORD    dwDesiredAccess,
    //   BOOL     bInheritHandle,
    //   DWORD    dwOptions
    // );
    WinsdkApi("DuplicateHandle", WinCc::Stdcall, {
        {"hSourceProcessHandle", HANDLE_},
        {"hSourceHandle", HANDLE_},
        {"hTargetProcessHandle", HANDLE_},
        {"lpTargetHandle", LPHANDLE_},
        {"dwDesiredAccess", DWORD_},
        {"bInheritHandle", BOOL_},
        {"dwOptions", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // TODO for how we manage handle, i think this doesn't work (verbatim)
        const auto content = api_get_int(get_param(params, "hSourceHandle"));
        const auto dst = api_get_int(get_param(params, "lpTargetHandle"));

        ql.mem().write_ptr(dst, content);

        return 1;
    };

    // BOOL CloseHandle(
    //   HANDLE hObject
    // );
    WinsdkApi("CloseHandle", WinCc::Stdcall, {
        {"hObject", HANDLE_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto value = api_get_int(get_param(params, "hObject"));
        auto& win = ql.os<os::windows::QlOsWindows>();
        const auto* handle = win.handle_manager().get(value);

        if (handle == nullptr) {
            win.set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }

        if (handle->permissions.has_value() && (*handle->permissions & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0) {
            // FIXME: add error (verbatim)
            return 0;
        }

        // if this a file handle, close it (handle.py: the IO objects close
        // here; the port's Handle carries a bare obj pointer — the fd-close
        // ride lands with the fileapi family slice)
        win.handle_manager().delete_handle(value);

        return 1;
    };

    // BOOL SetHandleInformation(
    //   HANDLE hObject,
    //   DWORD  dwMask,
    //   DWORD  dwFlags
    // );
    WinsdkApi("SetHandleInformation", WinCc::Stdcall, {
        {"hObject", HANDLE_},
        {"dwMask", DWORD_},
        {"dwFlags", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto val = api_get_int(get_param(params, "hObject"));
        auto& win = ql.os<os::windows::QlOsWindows>();
        auto* handle = win.handle_manager().get(val);
        handle->permissions = static_cast<std::uint32_t>(api_get_int(get_param(params, "dwFlags")));

        return 1;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kHandleapiRegistered = [] {
    register_handleapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
