// Ported from qiling/os/windows/dlls/kernel32/tlhelp32.py — the toolhelp
// snapshot family. The @winsdkapi decorators map onto
// register_tlhelp32_family(); the bodies ride the verbatim upstream walks
// (the TH32CS_SNAPPROCESS gate, the 0xD10C handle, and the Process32NextW
// module-global call counter included). The family self-registers at
// static-init and can be re-seeded after ApiRegistry::clear() (the test
// isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <spdlog/spdlog.h>

namespace qiling {
namespace os {
namespace win {

void register_tlhelp32_family() {
    using namespace qiling::os::api;

    // HANDLE CreateToolhelp32Snapshot(
    //   DWORD dwFlags,
    //   DWORD th32ProcessID
    // );
    WinsdkApi("CreateToolhelp32Snapshot", WinCc::Stdcall, {
        {"dwFlags", DWORD_},
        {"th32ProcessID", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // TODO thinking about implementing an handler, gonna see if is
        // really necessary  (verbatim)
        const auto flag = api_get_int(get_param(params, "dwFlags"));

        if (flag != TH32CS_SNAPPROCESS) {
            throw QlErrorNotImplemented("API not implemented");
        }

        ql.log().debug("The target is checking every process!");

        return 0xD10C;
    };

    // BOOL Process32FirstW(
    //   HANDLE            hSnapshot,
    //   LPPROCESSENTRY32W lppe
    // );
    WinsdkApi("Process32FirstW", WinCc::Stdcall, {
        {"hSnapshot", PVOID_},
        {"lppe", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL Process32NextW(
    //   HANDLE            hSnapshot,
    //   LPPROCESSENTRY32W lppe
    // );
    WinsdkApi("Process32NextW", WinCc::Stdcall, {
        {"hSnapshot", PVOID_},
        {"lppe", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // the verbatim module-global counter: the first two calls ride 1,
        // then the 0 (the FIXME workaround comment rides verbatim)
        static std::uint64_t call_count = 0;
        ++call_count;

        // FIXME: this is an undocumented workaround, probably to satisfy one
        // of the samples. better implement that as an ad-hoc hook there
        return static_cast<std::uint64_t>(call_count < 3);
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kTlhelp32Registered = [] {
    register_tlhelp32_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
