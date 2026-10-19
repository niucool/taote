// Ported from qiling/os/windows/dlls/kernel32/consoleapi.py — the console
// family (GetConsoleMode). The @winsdkapi decorators map onto
// register_consoleapi_family(); the bodies ride the verbatim upstream walks
// (the lpMode no-write quirk included). The family self-registers at
// static-init and can be re-seeded after ApiRegistry::clear() (the test
// isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_consoleapi_family() {
    using namespace qiling::os::api;

    // BOOL WINAPI GetConsoleMode(
    //   _In_  HANDLE  hConsoleHandle,
    //   _Out_ LPDWORD lpMode
    // );
    WinsdkApi("GetConsoleMode", WinCc::Stdcall, {
        {"hConsoleHandle", PVOID_},
        {"lpMode", LPDWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // the verbatim body: the 1 return with NO write into lpMode (the
        // caller reads the un-initialized cell — the upstream shape)
        return 1;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kConsoleapiRegistered = [] {
    register_consoleapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
