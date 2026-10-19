// Ported from qiling/os/windows/dlls/kernel32/processthreadsapi.py — the
// process/thread family (the ExitProcess/GetStartupInfo pair, the TLS cycle,
// the GetCurrent* quartet, the CreateThread walk over the thread manager,
// the token pair over the Token struct, and the pass-through bodies). The
// @winsdkapi decorators map onto register_processthreadsapi_family(); the
// bodies ride the verbatim upstream walks. The family self-registers at
// static-init and can be re-seeded after ApiRegistry::clear() (the test
// isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/thread.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the GetStartupInfo shared body (the upstream _GetStartupInfo): fills the
// STARTUPINFO struct at lpStartupInfo and returns the STATUS_SUCCESS
std::optional<std::uint64_t> get_startup_info_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto lp_startup_info = api_get_int(get_param(params, "lpStartupInfo"));
    (void)wide;

    auto* os = static_cast<os::windows::QlOsWindows*>(&ql.os());

    // TODO: fill out with real / configurable values rather than bogus /
    // fixed ones (verbatim)
    //
    // the desktop title alloc: 'QilingDesktop\x00' — 14 latin1 bytes, 28
    // utf-16le bytes; the pointer is stored without the content write (the
    // upstream allocates but never writes the buffer, verbatim)
    const char desktop_title[] = "QilingDesktop";
    const auto title_len = wide ? (sizeof(desktop_title) * 2) : sizeof(desktop_title);
    const auto desktop_addr = os->heap().alloc(title_len);

    const auto bits = ql.arch().bits();
    const std::size_t sui_size = bits == 64 ? STARTUPINFO_SIZE_64 : STARTUPINFO_SIZE_32;
    std::string sui(sui_size, '\0');
    write_startup_info(sui.data(), bits, desktop_addr, 0x40,
                       STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE);
    ql.mem().write(lp_startup_info, std::vector<std::uint8_t>(sui.begin(), sui.end()));

    return STATUS_SUCCESS;
}

// the token-shared body (the upstream hook_OpenProcessToken/hook_OpenThreadToken)
std::optional<std::uint64_t> open_token_body(Qiling& ql, const ResolvedParams& params) {
    const auto token_pointer = api_get_int(get_param(params, "TokenHandle"));

    auto* os = static_cast<os::windows::QlOsWindows*>(&ql.os());
    auto token = std::make_unique<Token>(ql);

    Handle new_handle(std::nullopt, token.get());
    auto* handle_ptr = &new_handle;

    // the token outlives the call: park the ownership on the os (the python
    // side rides the handle-manager reference)
    static thread_local std::vector<std::unique_ptr<Token>> token_park;
    token_park.push_back(std::move(token));

    os->handle_manager().append(*handle_ptr);
    ql.mem().write_ptr(token_pointer, handle_ptr->id);

    return 1;
}

}  // namespace

void register_processthreadsapi_family() {
    using namespace qiling::os::api;

    // void ExitProcess(
    //   UINT uExitCode
    // );
    WinsdkApi("ExitProcess", WinCc::Stdcall, {
        {"uExitCode", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        ql.emu_stop();
        return std::nullopt;
    };

    // VOID WINAPI GetStartupInfoA(
    //   _Out_ LPSTARTUPINFO lpStartupInfo
    // );
    WinsdkApi("GetStartupInfoA", WinCc::Stdcall, {
        {"lpStartupInfo", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_startup_info_body(ql, params, false);
    };

    // VOID WINAPI GetStartupInfoW(
    //   _Out_ LPSTARTUPINFO lpStartupInfo
    // );
    WinsdkApi("GetStartupInfoW", WinCc::Stdcall, {
        {"lpStartupInfo", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_startup_info_body(ql, params, true);
    };

    // DWORD TlsAlloc();
    WinsdkApi("TlsAlloc", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        auto* cur = w(ql).thread_manager().cur_thread();
        const auto idx = cur->tls_index();
        cur->bump_tls_index();
        cur->set_tls(idx, 0);

        return idx;
    };

    // DWORD TlsFree(
    //  DWORD dwTlsIndex
    // );
    WinsdkApi("TlsFree", WinCc::Stdcall, {
        {"dwTlsIndex", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto idx = api_get_int(get_param(params, "dwTlsIndex"));
        auto* cur = w(ql).thread_manager().cur_thread();

        if (!cur->has_tls(idx)) {
            w(ql).set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        cur->erase_tls(idx);
        return 1;
    };

    // LPVOID TlsGetValue(
    //  DWORD dwTlsIndex
    // );
    WinsdkApi("TlsGetValue", WinCc::Stdcall, {
        {"dwTlsIndex", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto idx = api_get_int(get_param(params, "dwTlsIndex"));
        auto* cur = w(ql).thread_manager().cur_thread();

        if (!cur->has_tls(idx)) {
            w(ql).set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        // api explicity clears last error on success:
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue
        w(ql).set_last_error(0);
        return *cur->get_tls(idx);
    };

    // BOOL TlsSetValue(
    //   DWORD  dwTlsIndex,
    //   LPVOID lpTlsValue
    // );
    WinsdkApi("TlsSetValue", WinCc::Stdcall, {
        {"dwTlsIndex", DWORD_},
        {"lpTlsValue", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto idx = api_get_int(get_param(params, "dwTlsIndex"));
        const auto lp_tls_value = api_get_int(get_param(params, "lpTlsValue"));
        auto* cur = w(ql).thread_manager().cur_thread();

        if (!cur->has_tls(idx)) {
            w(ql).set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        cur->set_tls(idx, lp_tls_value);
        return 1;
    };

    // DWORD GetCurrentThreadId(
    // );
    WinsdkApi("GetCurrentThreadId", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).thread_manager().cur_thread()->get_id();
    };

    // DWORD GetCurrentProcessId(
    // );
    WinsdkApi("GetCurrentProcessId", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Let's return a valid value
        return w(ql).pid();
    };

    // BOOL IsProcessorFeaturePresent(
    //   DWORD ProcessorFeature
    // );
    WinsdkApi("IsProcessorFeaturePresent", WinCc::Stdcall, {
        {"ProcessorFeature", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto feature = api_get_int(get_param(params, "ProcessorFeature"));
        (void)ql;

        // the upstream const.py pins 0x17; the winnt.h macro preempts the name with
        // the decimal 17 on _WIN32 (the upstream shape rides the python constant)
        if (feature == KAPI_PF_XSAVE_ENABLED_UPSTREAM) {
            // it seems like unicorn can't recognize the instruction
            return 0;
        }

        return 1;
    };

    // HANDLE CreateThread(
    //   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    //   SIZE_T                  dwStackSize,
    //   LPTHREAD_START_ROUTINE  lpStartAddress,
    //   __drv_aliasesMem LPVOID lpParameter,
    //   DWORD                   dwCreationFlags,
    //   LPDWORD                 lpThreadId
    // );
    WinsdkApi("CreateThread", WinCc::Stdcall, {
        {"lpThreadAttributes", LPVOID_},
        {"dwStackSize", LPVOID_},
        {"lpStartAddress", LPVOID_},
        {"lpParameter", LPVOID_},
        {"dwCreationFlags", DWORD_},
        {"lpThreadId", LPDWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
#ifdef CREATE_SUSPENDED
#undef CREATE_SUSPENDED
#endif
        constexpr std::uint32_t CREATE_SUSPENDED = 0x00000004;

        const auto dw_stack_size = api_get_int(get_param(params, "dwStackSize"));
        const auto lp_start_address = api_get_int(get_param(params, "lpStartAddress"));
        const auto lp_parameter = api_get_int(get_param(params, "lpParameter"));
        const auto dw_creation_flags = api_get_int(get_param(params, "dwCreationFlags"));

        windows::ThreadStatus thread_status;
        if (dw_creation_flags & CREATE_SUSPENDED) {
            thread_status = windows::ThreadStatus::Ready;
        } else {
            thread_status = windows::ThreadStatus::Running;
        }

        // create new thread
        auto* os = static_cast<os::windows::QlOsWindows*>(&ql.os());
        auto new_thread = windows::QlWindowsThread::create(&ql, dw_stack_size, lp_start_address, lp_parameter, thread_status);

        // append the new thread to ThreadManager
        os->thread_manager().append(std::move(new_thread));

        // create thread handle
        Handle new_handle(std::nullopt, os->thread_manager().threads().back());
        os->handle_manager().append(new_handle);

        // set lpThreadId
        // FIXME: Temporary fix for the crash
        // if lpThreadId != 0:
        // ql.mem.write_ptr(lpThreadId, thread_id)  (verbatim)

        // set thread handle
        return new_handle.id;
    };

    // void ExitThread(
    //   DWORD dwExitCode
    // );
    WinsdkApi("ExitThread", WinCc::Stdcall, {
        {"dwExitCode", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        //ql.emu_stop()  (verbatim: the pass body)
        return std::nullopt;
    };

    // HANDLE GetCurrentProcess(
    // );
    WinsdkApi("GetCurrentProcess", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // FIXME: should return handle, not pid  (verbatim)
        return w(ql).pid();
    };

    // BOOL TerminateProcess(
    //   HANDLE hProcess,
    //   UINT   uExitCode
    // );
    WinsdkApi("TerminateProcess", WinCc::Stdcall, {
        {"hProcess", HANDLE_},
        {"uExitCode", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Samples will try to kill other process! We don't want to always stop!
        const auto process = api_get_int(get_param(params, "hProcess"));

        if (process == w(ql).pid()) {
            ql.emu_stop();
        }

        return 1;
    };

    // HANDLE GetCurrentThread();
    WinsdkApi("GetCurrentThread", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).thread_manager().cur_thread()->get_id();
    };

    // HANDLE OpenProcess(
    //   DWORD dwDesiredAccess,
    //   BOOL  bInheritHandle,
    //   DWORD dwProcessId
    // );
    WinsdkApi("OpenProcess", WinCc::Stdcall, {
        {"dwDesiredAccess", DWORD_},
        {"bInheritHandle", BOOL_},
        {"dwProcessId", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto proc = api_get_int(get_param(params, "dwProcessId"));
        auto& os = w(ql);

        // If the specified process is the System Process (0x00000000),
        // the function fails and the last error code is ERROR_INVALID_PARAMETER
        if (proc == 0) {
            os.set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        //  If the specified process is the Idle process or one of the CSRSS
        //  processes, this function fails and the last error code is
        //  ERROR_ACCESS_DENIED because their access restrictions prevent
        //  user-level code from opening them.
        const auto csrss = os.profile().get_int("PROCESSES", "csrss.exe");
        if (proc == csrss) {
            os.set_last_error(ERROR_ACCESS_DENIED);
            return 0;
        }

        return 0xD10C;
    };

    // BOOL OpenProcessToken(
    //   HANDLE  ProcessHandle,
    //   DWORD   DesiredAccess,
    //   PHANDLE TokenHandle
    // );
    WinsdkApi("OpenProcessToken", WinCc::Stdcall, {
        {"ProcessHandle", HANDLE_},
        {"DesiredAccess", DWORD_},
        {"TokenHandle", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return open_token_body(ql, params);
    };

    // BOOL GetThreadContext(
    //   HANDLE    hThread,
    //   LPCONTEXT lpContext
    // );
    WinsdkApi("GetThreadContext", WinCc::Stdcall, {
        {"hThread", HANDLE_},
        {"lpContext", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL OpenThreadToken(
    //   HANDLE  ThreadHandle,
    //   DWORD   DesiredAccess,
    //   BOOL    OpenAsSelf,
    //   PHANDLE TokenHandle
    // );
    WinsdkApi("OpenThreadToken", WinCc::Stdcall, {
        {"ThreadHandle", HANDLE_},
        {"DesiredAccess", DWORD_},
        {"OpenAsSelf", BOOL_},
        {"TokenHandle", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return open_token_body(ql, params);
    };

    // BOOL GetThreadTimes(
    //   HANDLE     hThread,
    //   LPFILETIME lpCreationTime,
    //   LPFILETIME lpExitTime,
    //   LPFILETIME lpKernelTime,
    //   LPFILETIME lpUserTime
    // );
    WinsdkApi("GetThreadTimes", WinCc::Stdcall, {
        {"hThread", HANDLE_},
        {"lpCreationTime", LPVOID_},
        {"lpExitTime", LPVOID_},
        {"lpKernelTime", LPVOID_},
        {"lpUserTime", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kProcessthreadsapiRegistered = [] {
    qiling::os::win::register_processthreadsapi_family();
    return true;
}();
}  // namespace
