// Ported from qiling/os/windows/dlls/kernel32/synchapi.py — the
// synchronization family (the critical-section pass bodies, the wait trio
// over the thread waitfor lists, the mutex/event named-object bodies over
// the Mutex struct, and the SRW no-op set). The @winsdkapi decorators map
// onto register_synchapi_family(); the bodies ride the verbatim upstream
// walks. The family self-registers at static-init and can be re-seeded after
// ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/thread.hpp"
#include "qiling/os/windows/windows.hpp"

#include <memory>
#include <string>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the shared __OpenMutex body (the upstream module-level helper)
std::optional<std::uint64_t> open_mutex_body(Qiling& ql, const ResolvedParams& params) {
    const auto lp_name = api_get_string(ql, get_param(params, "lpName"));

    if (lp_name.empty()) {
        return 0;
    }

    // The name can have a "Global" or "Local" prefix to explicitly open an
    // object in the global or session namespace. It can also have no prefix
    std::string type_str;
    std::string name;
    const auto sep = lp_name.find('\\');
    if (sep != std::string::npos) {
        type_str = lp_name.substr(0, sep);
        name = lp_name.substr(sep + 1);
    } else {
        name = lp_name;
    }

    auto* handle = w(ql).handle_manager().search(name);

    if (type_str == "Global") {
        // if is global is a Windows lock. We always return a valid handle
        // because we have no way to emulate them
        // example sample: Gandcrab e42431d37561cc695de03b85e8e99c9e31321742
        if (handle == nullptr) {
            return 0xD10C;
        }

        auto* mutex = static_cast<Mutex*>(handle->obj);

        if (mutex->isFree()) {
            mutex->lock();
        } else {
            throw QlErrorNotImplemented("API not implemented");
        }
    } else {
        if (handle == nullptr) {
            // If a named mutex does not exist, the function fails and
            // GetLastError returns ERROR_FILE_NOT_FOUND.
            w(ql).set_last_error(ERROR_FILE_NOT_FOUND);
            return 0;
        }

        throw QlErrorNotImplemented("API not implemented");
    }

    return std::nullopt;
}

// the shared __CreateMutex body
std::optional<std::uint64_t> create_mutex_body(Qiling& ql, const ResolvedParams& params) {
    const auto lp_name = api_get_string(ql, get_param(params, "lpName"));
    const auto owning = api_get_int(get_param(params, "bInitialOwner"));

    if (lp_name.empty()) {
        return 0;
    }

    std::string type_str;
    std::string name;
    const auto sep = lp_name.find('\\');
    if (sep != std::string::npos) {
        type_str = lp_name.substr(0, sep);
        name = lp_name.substr(sep + 1);
    } else {
        name = lp_name;
    }

    auto* handle = w(ql).handle_manager().search(name);

    if (handle != nullptr) {
        // ql.os.last_error = ERROR_ALREADY_EXISTS  (verbatim: commented out)
        return 0;
    }

    auto mutex = std::make_shared<Mutex>(name, type_str);

    if (owning) {
        mutex->lock();
    }

    Handle new_handle(std::nullopt, mutex.get(), name);
    new_handle.owned = mutex;  // the ownership rides the handle slot
    new_handle.obj_type = typeid(*mutex);
    w(ql).handle_manager().append(new_handle);

    return new_handle.id;
}

// the shared __CreateEvent body
std::optional<std::uint64_t> create_event_body(Qiling& ql, const ResolvedParams& params) {
    const auto lp_name = api_get_string(ql, get_param(params, "lpName"));
    const auto initial_state = api_get_int(get_param(params, "bInitialState"));

    std::string type_str;
    std::string name;
    if (!lp_name.empty()) {
        // Implementation seems similar enough to Mutex to just use it
        const auto sep = lp_name.find('\\');
        if (sep != std::string::npos) {
            type_str = lp_name.substr(0, sep);
            name = lp_name.substr(sep + 1);
        } else {
            name = lp_name;
        }
        auto* handle = w(ql).handle_manager().search(name);

        if (handle != nullptr) {
            w(ql).set_last_error(ERROR_ALREADY_EXISTS);
            return handle->id;
        }
    } else {
        // TODO: should be None instead of empty strings?  (verbatim)
        type_str = "";
        name = "";
    }

    auto mutex = std::make_shared<Mutex>(name, type_str);

    if (initial_state) {
        mutex->lock();
    }

    Handle new_handle(std::nullopt, mutex.get(), name);
    new_handle.owned = mutex;
    new_handle.obj_type = typeid(*mutex);
    w(ql).handle_manager().append(new_handle);

    return new_handle.id;
}

}  // namespace

void register_synchapi_family() {
    using namespace qiling::os::api;

    // void Sleep(
    //  DWORD dwMilliseconds
    // );
    WinsdkApi("Sleep", WinCc::Stdcall, {
        {"dwMilliseconds", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // time.sleep(params["dwMilliseconds"] * 10**(-3))  (verbatim: pass)
        // with the virtual clock on, the passthrough becomes a clock advance -
        // no host second is spent, and the guest's own measurement of elapsed
        // time stays honest (PLAN_PARITY Phase 5.4)
        auto& win = w(ql);
        if (win.virtual_clock()) {
            win.advance_virtual_time(static_cast<std::uint32_t>(api_get_int(get_param(params, "dwMilliseconds"))));
        }
        return std::nullopt;
    };

    // void EnterCriticalSection(
    //  LPCRITICAL_SECTION lpCriticalSection
    // );
    WinsdkApi("EnterCriticalSection", WinCc::Stdcall, {
        {"lpCriticalSection", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void LeaveCriticalSection(
    //  LPCRITICAL_SECTION lpCriticalSection
    // );
    WinsdkApi("LeaveCriticalSection", WinCc::Stdcall, {
        {"lpCriticalSection", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void DeleteCriticalSection(
    //   LPCRITICAL_SECTION lpCriticalSection
    // );
    WinsdkApi("DeleteCriticalSection", WinCc::Stdcall, {
        {"lpCriticalSection", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void InitializeCriticalSection(
    //   LPCRITICAL_SECTION lpCriticalSection
    // );
    WinsdkApi("InitializeCriticalSection", WinCc::Stdcall, {
        {"lpCriticalSection", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL InitializeCriticalSectionEx(
    //   LPCRITICAL_SECTION lpCriticalSection,
    //   DWORD              dwSpinCount,
    //   DWORD              Flags
    // );
    WinsdkApi("InitializeCriticalSectionEx", WinCc::Stdcall, {
        {"lpCriticalSection", LPVOID_},
        {"dwSpinCount", DWORD_},
        {"Flags", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL InitializeCriticalSectionAndSpinCount(
    //  LPCRITICAL_SECTION lpCriticalSection,
    //  DWORD              dwSpinCount
    // );
    WinsdkApi("InitializeCriticalSectionAndSpinCount", WinCc::Stdcall, {
        {"lpCriticalSection", LPVOID_},
        {"dwSpinCount", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // DWORD WaitForSingleObject(
    //   HANDLE hHandle,
    //   DWORD  dwMilliseconds
    // );
    WinsdkApi("WaitForSingleObject", WinCc::Stdcall, {
        {"hHandle", HANDLE_},
        {"dwMilliseconds", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_handle = api_get_int(get_param(params, "hHandle"));
        auto* handle = w(ql).handle_manager().get(h_handle);

        if (handle != nullptr) {
            auto* target_thread = static_cast<os::windows::QlWindowsThread*>(handle->obj);
            w(ql).thread_manager().cur_thread()->waitfor(*target_thread);
        }

        return 0;
    };

    // DWORD WaitForSingleObjectEx(
    //   HANDLE hHandle,
    //   DWORD  dwMilliseconds
    //   BOOL   bAlertable
    // );
    WinsdkApi("WaitForSingleObjectEx", WinCc::Stdcall, {
        {"hHandle", HANDLE_},
        {"dwMilliseconds", DWORD_},
        {"bAlertable", BOOL_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_handle = api_get_int(get_param(params, "hHandle"));
        auto* handle = w(ql).handle_manager().get(h_handle);

        if (handle != nullptr) {
            auto* target_thread = static_cast<os::windows::QlWindowsThread*>(handle->obj);
            w(ql).thread_manager().cur_thread()->waitfor(*target_thread);
        }

        return 0;
    };

    // DWORD WaitForMultipleObjects(
    //   DWORD        nCount,
    //   const HANDLE *lpHandles,
    //   BOOL         bWaitAll,
    //   DWORD        dwMilliseconds
    // );
    WinsdkApi("WaitForMultipleObjects", WinCc::Stdcall, {
        {"nCount", DWORD_},
        {"lpHandles", LPVOID_},
        {"bWaitAll", BOOL_},
        {"dwMilliseconds", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto n_count = api_get_int(get_param(params, "nCount"));
        const auto lp_handles = api_get_int(get_param(params, "lpHandles"));
        const auto ps = ql.arch().pointersize();

        for (std::uint64_t i = 0; i < n_count; ++i) {
            const auto handle_value = ql.unpack(std::string_view(
                    reinterpret_cast<const char*>(ql.mem().read(lp_handles + i * ps, ps).data()), ps));

            if (handle_value != 0) {
                auto* thread = static_cast<os::windows::QlWindowsThread*>(
                    w(ql).handle_manager().get(handle_value)->obj);
                w(ql).thread_manager().cur_thread()->waitfor(*thread);
            }
        }

        return 0;
    };

    // HANDLE OpenMutexW(
    //   DWORD   dwDesiredAccess,
    //   BOOL    bInheritHandle,
    //   LPCWSTR lpName
    // );
    WinsdkApi("OpenMutexW", WinCc::Stdcall, {
        {"dwDesiredAccess", DWORD_},
        {"bInheritHandle", BOOL_},
        {"lpName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return open_mutex_body(ql, params);
    };

    // HANDLE OpenMutexA(
    //   DWORD   dwDesiredAccess,
    //   BOOL    bInheritHandle,
    //   LPCSTR lpName
    // );
    WinsdkApi("OpenMutexA", WinCc::Stdcall, {
        {"dwDesiredAccess", DWORD_},
        {"bInheritHandle", BOOL_},
        {"lpName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return open_mutex_body(ql, params);
    };

    // HANDLE CreateMutexW(
    //   LPSECURITY_ATTRIBUTES lpMutexAttributes,
    //   BOOL                  bInitialOwner,
    //   LPCWSTR               lpName
    // );
    WinsdkApi("CreateMutexW", WinCc::Stdcall, {
        {"lpMutexAttributes", LPVOID_},
        {"bInitialOwner", BOOL_},
        {"lpName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return create_mutex_body(ql, params);
    };

    // HANDLE CreateMutexA(
    //   LPSECURITY_ATTRIBUTES lpMutexAttributes,
    //   BOOL                  bInitialOwner,
    //   LPCSTR               lpName
    // );
    WinsdkApi("CreateMutexA", WinCc::Stdcall, {
        {"lpMutexAttributes", LPVOID_},
        {"bInitialOwner", BOOL_},
        {"lpName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return create_mutex_body(ql, params);
    };

    // BOOL ReleaseMutex(
    //   HANDLE hMutex
    // );
    WinsdkApi("ReleaseMutex", WinCc::Stdcall, {
        {"hMutex", HANDLE_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_mutex = api_get_int(get_param(params, "hMutex"));
        auto* handle = w(ql).handle_manager().get(h_mutex);

        if (handle == nullptr) {
            w(ql).set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }

        if (handle->obj == nullptr || handle->obj_type != typeid(Mutex)) {
            // (the python: not mutex or not isinstance(mutex, Mutex); the
            // port captures the typeid at the handle registration)
            return 0;
        }

        auto* mutex = static_cast<Mutex*>(handle->obj);

        if (mutex->isFree()) {
            w(ql).set_last_error(ERROR_NOT_OWNER);
            return 0;
        }

        // FIXME: Only the owner is allowed to do this!  (verbatim)
        mutex->unlock();
        return 1;
    };

    // HANDLE CreateEventA(
    //  LPSECURITY_ATTRIBUTES lpEventAttributes,
    //  BOOL                  bManualReset,
    //  BOOL                  bInitialState,
    //  LPCSTR                lpName
    // );
    WinsdkApi("CreateEventA", WinCc::Stdcall, {
        {"lpEventAttributes", LPVOID_},
        {"bManualReset", BOOL_},
        {"bInitialState", BOOL_},
        {"lpName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return create_event_body(ql, params);
    };

    // HANDLE CreateEventW(
    //  LPSECURITY_ATTRIBUTES lpEventAttributes,
    //  BOOL                  bManualReset,
    //  BOOL                  bInitialState,
    //  LPCWSTR               lpName
    // );
    WinsdkApi("CreateEventW", WinCc::Stdcall, {
        {"lpEventAttributes", LPVOID_},
        {"bManualReset", BOOL_},
        {"bInitialState", BOOL_},
        {"lpName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return create_event_body(ql, params);
    };

    WinsdkApi("TryAcquireSRWLockExclusive", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("TryAcquireSRWLockShared", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // void InitializeSRWLock(
    //  PSRWLOCK SRWLock
    // );
    WinsdkApi("InitializeSRWLock", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // void AcquireSRWLockExclusive(
    //   PSRWLOCK SRWLock
    // );
    WinsdkApi("AcquireSRWLockExclusive", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // void AcquireSRWLockShared(
    //   PSRWLOCK SRWLock
    // );
    WinsdkApi("AcquireSRWLockShared", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // void ReleaseSRWLockExclusive(
    //   PSRWLOCK SRWLock
    // );
    WinsdkApi("ReleaseSRWLockExclusive", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // void ReleaseSRWLockShared(
    //   PSRWLOCK SRWLock
    // );
    WinsdkApi("ReleaseSRWLockShared", WinCc::Stdcall, {
        {"SRWLock", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kSynchapiRegistered = [] {
    qiling::os::win::register_synchapi_family();
    return true;
}();
}  // namespace
