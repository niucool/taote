// The ucrt (api-ms-win-crt-*) family — the UCRT startup surface the MSVC /
// UCRT-linked binaries ride (the api-ms-win-crt-runtime/stdio/heap/convert/
// locale/math redirect stubs). The upstream qiling serves these through the
// real ucrtbase.dll; the stub-dll hosts bind the names through the shared
// name-keyed registry, so the surface registers once here and serves every
// api-ms-win-crt-* / ucrtbase image. The bodies mirror the msvcrt family
// shapes (the UCRT is the msvcrt lineage).
#ifndef QILING_OS_WINDOWS_DLLS_UCRT_CPP
#define QILING_OS_WINDOWS_DLLS_UCRT_CPP

#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <cstring>
#include <string>

namespace qiling {
namespace os {
namespace win {

void register_ucrt_family() {
    using namespace qiling::os::api;

    // int _initialize_narrow_environment(void); — the env setup is a no-op
    // (the __getmainargs shape already carries the env arrays)
    WinsdkApi("_initialize_narrow_environment", WinCc::Cdecl, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _configure_narrow_argv(int mode); — the argv walk is a no-op (the
    // __p___argc/__p___argv cells answer the pointers)
    WinsdkApi("_configure_narrow_argv", WinCc::Cdecl, {
        {"mode", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // _initterm / _initterm_e deliberately have NO handlers here (the
    // upstream's shape: msvcrt.py never hooks them either). The initializer
    // walk must execute the CRT's real body:
    //   * real-dll rootfs — the call lands on the real ucrtbase code and walks
    //     the table, which is what constructs the C++ statics (std::cout in
    //     msvcp140's DllMain) the vendor fixtures need. A no-op hook intercepts
    //     that walk and leaves the statics unconstructed (the operator<< crash).
    //   * stub rootfs — the call lands on the synthesized 0xC3 cell and answers
    //     immediately (no walk; _initterm_e's cell is seeded to answer 0, the
    //     answer the retired no-op hook gave, so the startup keeps taking the
    //     success path).

    // int _crt_atexit(_PVFV function); — the registration succeeds (the
    // teardown list never runs: the exit path stops the emulation)
    WinsdkApi("_crt_atexit", WinCc::Cdecl, {
        {"function", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _register_onexit_t(onexit_t function); (the _onexit_t shapes)
    WinsdkApi("_register_onexit_function", WinCc::Cdecl, {
        {"table", PVOID_},
        {"function", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _initialize_onexit_table(_onexit_table_t*); 
    WinsdkApi("_initialize_onexit_table", WinCc::Cdecl, {
        {"table", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _execute_onexit_table(_onexit_table_t*);
    WinsdkApi("_execute_onexit_table", WinCc::Cdecl, {
        {"table", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _register_thread_local_exe_atexit_callback(_PVFV function);
    WinsdkApi("_register_thread_local_exe_atexit_callback", WinCc::Cdecl, {
        {"function", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _cexit(void); — the teardown flush is a no-op
    WinsdkApi("_c_exit", WinCc::Cdecl, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void terminate(void); — the abort shape (the verbatim devblog comment
    // rides the abort handler; the exit code rides STATUS_FATAL_APP_EXIT)
    WinsdkApi("terminate", WinCc::Cdecl, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        w(ql).set_exit_code(3);  // the abort() exit convention
        ql.emu_stop();
        return std::nullopt;
    };

    // int _controlfp_s(unsigned int* current, unsigned int newValue, unsigned
    //                   int mask); — the control-word probe (the 0x8001f cell
    // rides the _controlfp shape)
    WinsdkApi("_controlfp_s", WinCc::Cdecl, {
        {"current", PVOID_},
        {"newValue", PVOID_},
        {"mask", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto cur = api_get_int(get_param(params, "current"));
        if (cur != 0) {
            ql.mem().write_ptr(cur, 0x8001f, 4);
        }
        return 0;
    };

    // int _set_new_mode(int mode);
    WinsdkApi("_set_new_mode", WinCc::Cdecl, {
        {"mode", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _configthreadlocale(int type);
    WinsdkApi("_configthreadlocale", WinCc::Cdecl, {
        {"type", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void __setusermatherr(void (*usermatherr)(void)); — void
    WinsdkApi("__setusermatherr", WinCc::Cdecl, {
        {"usermatherr", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // errno_t _set_fmode(int mode);
    WinsdkApi("_set_fmode", WinCc::Cdecl, {
        {"mode", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int atoi(const char* str); — the base-10 walk (the strtol narrow shape)
    WinsdkApi("atoi", WinCc::Cdecl, {
        {"str", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_string(ql, get_param(params, "str"));
        try {
            return static_cast<std::uint64_t>(std::stoi(s));
        } catch (const std::invalid_argument&) {
            return 0;
        } catch (const std::out_of_range&) {
            return 0;
        }
    };

    // FILE* __acrt_iob_func(unsigned index); — the stdio table probe (the
    // stdin/stdout/stderr cells ride the handle ids 0/1/2)
    WinsdkApi("__acrt_iob_func", WinCc::Cdecl, {
        {"index", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "index"));
    };

    // int __std_type_info_destroy_list(void); — the teardown no-op
    WinsdkApi("__std_type_info_destroy_list", WinCc::Cdecl, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // the data-exception cells ride the __C_specific_handler registration
    // (the msvcrt slice covers _except_handler4_common / _XcptFilter /
    // _except_handler3 / __C_specific_handler)
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kUcrtRegistered = [] {
    qiling::os::win::register_ucrt_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_UCRT_CPP
