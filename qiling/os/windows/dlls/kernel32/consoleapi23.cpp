// Ported from qiling/os/windows/dlls/kernel32/consoleapi2.py,
// consoleapi3.py, and psapi.py — the remaining console stubs, the console
// window handle, and the psapi stub. The @winsdkapi decorators map onto
// register_consoleapi2/3_psapi_families(); the bodies ride the verbatim
// upstream walks. The families self-register at static-init and can be
// re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

// consoleapi2.py
void register_consoleapi2_family() {
    using namespace qiling::os::api;

    // BOOL WINAPI SetConsoleTitle(
    //   _In_ LPCTSTR lpConsoleTitle
    // );
    WinsdkApi("SetConsoleTitleW", WinCc::Stdcall, {
        {"lpConsoleTitle", LPCTSTR_W_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL WINAPI GetConsoleScreenBufferInfo(
    //   _In_  HANDLE                      hConsoleOutput,
    //   _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
    // );
    WinsdkApi("GetConsoleScreenBufferInfo", WinCc::Stdcall, {
        {"hConsoleOutput", PVOID_},
        {"lpConsoleScreenBufferInfo", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Todo should we really?  (verbatim)
        return 1;
    };

    // BOOL WINAPI SetConsoleTextAttribute(
    //   _In_ HANDLE hConsoleOutput,
    //   _In_ WORD   wAttributes
    // );
    WinsdkApi("SetConsoleTextAttribute", WinCc::Stdcall, {
        {"hConsoleOutput", PVOID_},
        {"wAttributes", WORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };
}

// consoleapi3.py
void register_consoleapi3_family() {
    using namespace qiling::os::api;

    // HWND WINAPI GetConsoleWindow(void);
    WinsdkApi("GetConsoleWindow", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        Handle handle(std::nullopt, nullptr, "console_window");
        w(ql).handle_manager().append(handle);

        return handle.id;
    };
}

// psapi.py
void register_psapi_family() {
    using namespace qiling::os::api;

    // BOOL GetModuleInformation(
    //   HANDLE       hProcess,
    //   HMODULE      hModule,
    //   LPMODULEINFO lpmodinfo,
    //   DWORD        cb
    // );
    WinsdkApi("K32GetModuleInformation", WinCc::Stdcall, {
        {"hProcess", PVOID_},
        {"hModule", HMODULE_},
        {"lpmodinfo", PVOID_},
        {"cb", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO  (verbatim)
        return 0;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kConsole23PsapiRegistered = [] {
    register_consoleapi2_family();
    register_consoleapi3_family();
    register_psapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
