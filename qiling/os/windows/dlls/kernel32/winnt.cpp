// Ported from qiling/os/windows/dlls/kernel32/winnt.py — the interlocked
// LONG family and the VerSetConditionMask builder. The @winsdkapi
// decorators map onto register_winnt_family(); the bodies ride the verbatim
// upstream walks. The family self-registers at static-init and can be
// re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_winnt_family() {
    using namespace qiling::os::api;

    // LONG InterlockedExchange(
    //  LONG volatile *Target,
    //  LONG          Value
    // );
    WinsdkApi("InterlockedExchange", WinCc::Stdcall, {
        {"Target", PVOID_},
        {"Value", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto target = api_get_int(get_param(params, "Target"));
        const auto value = api_get_int(get_param(params, "Value"));

        const auto old = ql.mem().read_ptr(target, 4);
        ql.mem().write_ptr(target, value, 4);

        return old;
    };

    // LONG InterlockedIncrement(
    //  LONG volatile *Target,
    // );
    WinsdkApi("InterlockedIncrement", WinCc::Stdcall, {
        {"Target", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto target = api_get_int(get_param(params, "Target"));

        auto value = ql.mem().read_ptr(target, 4);
        value = (value + 1) % (1ull << 32);  // increase and handle overflow
        ql.mem().write_ptr(target, value, 4);

        return value;
    };

    // LONG InterlockedDecrement(
    //  LONG volatile *Target,
    // );
    WinsdkApi("InterlockedDecrement", WinCc::Stdcall, {
        {"Target", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto target = api_get_int(get_param(params, "Target"));

        const auto value = ql.mem().read_ptr(target, 4);
        const auto next = (value + ((1ull << 32) - 1)) % (1ull << 32);  // decrease and handle underflow
        ql.mem().write_ptr(target, next, 4);

        return next;
    };

    // NTSYSAPI ULONGLONG VerSetConditionMask(
    //   ULONGLONG ConditionMask,
    //   DWORD     TypeMask,
    //   BYTE      Condition
    // );
    WinsdkApi("VerSetConditionMask", WinCc::Stdcall, {
        {"ConditionMask", ULONGLONG_},
        {"TypeMask", DWORD_},
        {"Condition", BYTE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // see: https://docs.microsoft.com/en-us/windows/win32/sysinfo/verifying-the-system-version
        auto condition_mask = api_get_int(get_param(params, "ConditionMask"));
        const auto type_mask = api_get_int(get_param(params, "TypeMask"));
        auto condition = api_get_int(get_param(params, "Condition"));

        condition &= VER_CONDITION_MASK;

        if (condition) {
            for (int i = 0; i < 8; ++i) {
                if (type_mask & (1ull << i)) {
                    condition_mask |= static_cast<std::uint64_t>(condition) << (i * VER_NUM_BITS_PER_CONDITION_MASK);
                }
            }
        }

        return condition_mask;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kWinntRegistered = [] {
    register_winnt_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
