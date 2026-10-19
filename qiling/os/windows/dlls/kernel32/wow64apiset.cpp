// Ported from qiling/os/windows/dlls/kernel32/wow64apiset.py — the WOW64
// family (IsWow64Process). The @winsdkapi decorators map onto
// register_wow64apiset_family(); the bodies ride the verbatim upstream walks
// (the 32-bit NotImplemented raise and the x64 FALSE byte write included).
// The family self-registers at static-init and can be re-seeded after
// ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_wow64apiset_family() {
    using namespace qiling::os::api;

    // BOOL IsWow64Process(
    //   HANDLE hProcess,
    //   PBOOL  Wow64Process
    // );
    WinsdkApi("IsWow64Process", WinCc::Stdcall, {
        {"hProcess", PVOID_},
        {"Wow64Process", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto wow64_process = api_get_int(get_param(params, "Wow64Process"));

        if (ql.arch().bits() != 32) {
            throw QlErrorNotImplemented("API not implemented");
        }

        // false = b'\x00'  (verbatim; the true spelling stays commented)
        ql.mem().write(wow64_process, std::vector<std::uint8_t>{0});

        return 1;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kWow64apisetRegistered = [] {
    register_wow64apiset_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
