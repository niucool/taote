// Ported from qiling/os/windows/dlls/kernel32/interlockedapi.py — the
// interlocked family (the SLIST header initialization). The @winsdkapi
// decorators map onto register_interlockedapi_family(); the bodies ride the
// verbatim upstream walks. The family self-registers at static-init and can
// be re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_interlockedapi_family() {
    using namespace qiling::os::api;

    // void InitializeSListHead(
    //   PSLIST_HEADER ListHead
    // );
    WinsdkApi("InitializeSListHead", WinCc::Stdcall, {
        {"ListHead", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto list_head = api_get_int(get_param(params, "ListHead"));

        // the verbatim shape: the handle id IS the ListHead address (the
        // obj = [] rides the empty list placeholder)
        Handle handle(static_cast<std::uint64_t>(list_head));
        w(ql).handle_manager().append(handle);

        return 0;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kInterlockedapiRegistered = [] {
    register_interlockedapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
