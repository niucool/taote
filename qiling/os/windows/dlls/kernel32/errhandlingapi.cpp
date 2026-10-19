// Ported from qiling/os/windows/dlls/kernel32/errhandlingapi.py — the error
// handling family (the last-error cycle, the unhandled-exception filter, the
// vectored-exception interrupt hooks, SetErrorMode, and the passthru
// RaiseException). The @winsdkapi decorators map onto
// register_errhandlingapi_family(); the bodies ride the verbatim upstream
// walks (the 0x3/0x2d interrupt stubs and the x86-only RaiseException
// dispatch included). The family self-registers at static-init and can be
// re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/const.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

#include <memory>
#include <string>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the exec_standard_into body (the intno 0x3 stub): the pointer/double
// pointer pair on the heap, eax = the double pointer, esi = the handler
int exec_standard_into(Qiling& ql, std::uint64_t user_data) {
    // FIXME: probably this works only with al-khaser.  (verbatim)
    const auto pointer = w(ql).heap().alloc(0x4);
    // the value has just to be different from 0x80000003
    ql.mem().write_ptr(pointer, 0, 4);
    const auto double_pointer = w(ql).heap().alloc(0x4);
    ql.mem().write_ptr(double_pointer, static_cast<std::int64_t>(pointer), 4);

    ql.arch().regs().write("eax", double_pointer);
    ql.arch().regs().write("esi", user_data);

    return 0;
}

// the exec_into_0x2d body (the intno 0x2d stub): the stack dance rebuilding
// the (arg, ret, func) triple
int exec_into_0x2d(Qiling& ql, std::uint64_t user_data) {
    // we read where this hook is supposed to return
    const auto ret = ql.stack_pop();

    // https://github.com/LordNoteworthy/al-khaser/wiki/Anti-Debugging-Tricks#interrupt-0x2d
    const auto pointer = w(ql).heap().alloc(0x4);
    // the value has just to be different from 0x80000003
    ql.mem().write_ptr(pointer, 0, 4);
    const auto double_pointer = w(ql).heap().alloc(0x4);
    ql.mem().write_ptr(double_pointer, static_cast<std::int64_t>(pointer), 4);

    // arg
    ql.stack_push(double_pointer);
    // ret
    ql.stack_push(ret);
    // func
    ql.stack_push(user_data);

    return 0;
}

}  // namespace

void register_errhandlingapi_family() {
    using namespace qiling::os::api;

    // LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
    //   LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
    // );
    WinsdkApi("SetUnhandledExceptionFilter", WinCc::Stdcall, {
        {"lpTopLevelExceptionFilter", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto addr = api_get_int(get_param(params, "lpTopLevelExceptionFilter"));
        auto* handle = w(ql).handle_manager().search("TopLevelExceptionHandler");

        if (handle == nullptr) {
            Handle new_handle(std::nullopt, reinterpret_cast<void*>(addr), "TopLevelExceptionHandler");
            w(ql).handle_manager().append(new_handle);
            return 0;
        }

        const auto prev_filter = reinterpret_cast<std::uint64_t>(handle->obj);
        handle->obj = reinterpret_cast<void*>(addr);
        return prev_filter;
    };

    // _Post_equals_last_error_ DWORD GetLastError();
    WinsdkApi("GetLastError", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).last_error();
    };

    // void SetLastError(
    //  DWORD dwErrCode
    // );
    WinsdkApi("SetLastError", WinCc::Stdcall, {
        {"dwErrCode", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).set_last_error(static_cast<std::uint32_t>(api_get_int(get_param(params, "dwErrCode"))));
        return std::nullopt;
    };

    // UINT SetErrorMode(
    //   UINT uMode
    // );
    WinsdkApi("SetErrorMode", WinCc::Stdcall, {
        {"uMode", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO maybe this need a better implementation  (verbatim)
        return 0;
    };

    // PVOID AddVectoredExceptionHandler(
    //   ULONG                       First,
    //   PVECTORED_EXCEPTION_HANDLER Handler
    // );
    WinsdkApi("AddVectoredExceptionHandler", WinCc::Stdcall, {
        {"First", DWORD_},
        {"Handler", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto addr = api_get_int(get_param(params, "Handler"));

        // the interrupts 0x2d, 0x3 must be hooked  (verbatim)
        // the verbatim leak: the upstream drops the 0x3 hook's python
        // reference on the reassignment with no __del__ remove, so its
        // registration outlives the removable handle — the port releases
        // the RAII handle deliberately
        auto* leaked = new HookRet(ql.hook_intno([&ql, addr](std::uint32_t intno) -> int {
            return exec_standard_into(ql, addr);
        }, 0x3));
        (void)leaked;

        auto hook = std::make_shared<HookRet>(ql.hook_intno([&ql, addr](std::uint32_t intno) -> int {
            return exec_into_0x2d(ql, addr);
        }, 0x2d));
        Handle handle(std::nullopt, hook.get());
        handle.owned = hook;
        w(ql).handle_manager().append(handle);

        return handle.id;
    };

    // ULONG RemoveVectoredExceptionHandler(
    //   PVOID Handle
    // );
    WinsdkApi("RemoveVectoredExceptionHandler", WinCc::Stdcall, {
        {"Handle", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto id = api_get_int(get_param(params, "Handle"));
        auto* handle = w(ql).handle_manager().get(id);
        auto* hook = static_cast<HookRet*>(handle->obj);
        hook->remove();

        return 0;
    };

    // VOID RaiseException(
    //   DWORD     dwExceptionCode,
    //   DWORD     dwExceptionFlags,
    //   DWORD     nNumberOfArguments,
    //   CONST ULONG_PTR* lpArguments
    // );
    WinsdkApi("RaiseException", WinCc::Stdcall, {
        {"dwExceptionCode", DWORD_},
        {"dwExceptionFlags", DWORD_},
        {"nNumberOfArguments", DWORD_},
        {"lpArguments", LPVOID_},
    }, true) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // On x86_64, RaiseException will call RtlRaiseException,
        // which calls the exception dispatcher directly. The native
        // exception dispatching code mostly works correctly
        // for software exceptions, so we shall simply continue
        // through to the native dispatcher in this case.  (verbatim)
        if (ql.arch().type() != QL_ARCH::X86) {
            return std::nullopt;
        }

        // On x86, the situation is different. RtlRaiseException
        // will call ZwRaiseException, which uses a syscall.
        // However, Qiling doesn't really support Windows syscalls
        // right now.  (verbatim comment tail rides the walk below)
        const auto n_number_of_arguments = api_get_int(get_param(params, "nNumberOfArguments"));
        const auto lp_arguments = api_get_int(get_param(params, "lpArguments"));

        auto* handle = w(ql).handle_manager().search("TopLevelExceptionHandler");

        if (handle == nullptr) {
            ql.log().warn("RaiseException: top level exception handler not found");
            return std::nullopt;
        }

        const auto exception_handler = reinterpret_cast<std::uint64_t>(handle->obj);
        std::vector<std::pair<int, std::uint64_t>> args;
        if (lp_arguments != 0) {
            for (std::uint64_t i = 0; i < n_number_of_arguments; ++i) {
                args.emplace_back(PARAM_INTN, ql.mem().read_ptr(lp_arguments + i * ql.arch().pointersize()));
            }
        }

        w(ql).fcall().call_native(exception_handler, args, std::nullopt);
        return std::nullopt;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kErrhandlingapiRegistered = [] {
    register_errhandlingapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
