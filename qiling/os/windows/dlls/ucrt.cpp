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

    // FILE* __acrt_iob_func(unsigned index);
    //
    // Deliberately NO handler. Answering the *index* (as the retired handler
    // did, so that "stdout" was the literal 1) works only for code that treats
    // the FILE* as an opaque token. MSVC's own C++ runtime dereferences it:
    // msvcp140's filebuf constructor calls
    //     _get_stream_buffer_pointers(stdout, &base, &ptr, &count)
    // so that it can wrap the C stream. Real ucrtbase then reads the FILE
    // structure at 0x1, finds garbage and writes garbage back through the out
    // params — measured on the Windows 11 x86 tree: the three pointers came
    // back as 0x1 and were stored into the filebuf's get/put slots, so the
    // first `operator<<` loaded 0x1 as a pointer and died (UC_ERR_READ_UNMAPPED
    // at msvcp140+0xf12a); the x64 fixture shows the same 0x1 in
    // basic_ios<char>'s streambuf slot. Upstream qiling hooks this name nowhere
    // and passes both, because ucrtbase's own DllMain builds the real FILE
    // objects and the export answers a real pointer. On a stub rootfs the
    // synthesized cell answers 0, which is what the retired handler's callers
    // did with the index anyway (an opaque token, never dereferenced).

    // ---- the locale-state accessors -------------------------------------
    //
    // The UCRT exposes its per-thread locale state through accessor functions
    // that return *pointers* into CRT storage:
    //
    //   int*            ___lc_codepage_func(void);
    //   int*            ___lc_collate_cp_func(void);
    //   char**          ___lc_locale_name_func(void);
    //   unsigned int*   ___mb_cur_max_func(void);
    //   unsigned short** __pctype_func(void);
    //
    // Windows 7 predates the Universal CRT, so a Win7 rootfs exports none of
    // them and an MSVC-2015 binary's CRT bootstrap (msvcp140's DllMain) binds
    // them to nothing. An answer-0 stub is *not* a substitute: each caller
    // dereferences the result immediately, e.g.
    //
    //   call ___lc_locale_name_func
    //   mov  0x8(%rax),%rcx        ; the LC_CTYPE name slot
    //
    // which faults at 0x8 when the answer is NULL (measured at msvcp140+0x1c44
    // against rootfs-win7). Hand back real guest cells holding the C locale:
    // zeroed scalars (codepage 0, mb_cur_max filled from the entry below) and a
    // NULL-terminated locale-name table, which is what the C locale means — the
    // CRT's `if (name) free(name)` guards then take their null branch.
    //
    // __pctype_func is the one that is dereferenced twice (`*(*p + ch)`), so it
    // gets a real 256-entry table rather than a NULL.
    struct LocaleState {
        std::optional<std::uint64_t> codepage;
        std::optional<std::uint64_t> collate_cp;
        std::optional<std::uint64_t> mb_cur_max;
        std::optional<std::uint64_t> locale_names;
        std::optional<std::uint64_t> pctype;
        std::optional<std::uint64_t> ctype_table;
    };
    static LocaleState locale;

    const auto locale_cell = [](Qiling& ql, std::optional<std::uint64_t>& slot,
                                std::uint64_t size) -> std::uint64_t {
        if (!slot.has_value()) {
            slot = ql.os<os::windows::QlOsWindows>().heap().alloc(size);
            ql.mem().write(*slot, std::vector<std::uint8_t>(static_cast<std::size_t>(size), 0));
        }
        return *slot;
    };

    // int* ___lc_codepage_func(void);
    WinsdkApi("___lc_codepage_func", WinCc::Cdecl, {}) =
        [&locale, &locale_cell](Qiling& ql, std::uint64_t,
                                const ResolvedParams&) -> std::optional<std::uint64_t> {
        return locale_cell(ql, locale.codepage, 4);
    };

    // int* ___lc_collate_cp_func(void);
    WinsdkApi("___lc_collate_cp_func", WinCc::Cdecl, {}) =
        [&locale, &locale_cell](Qiling& ql, std::uint64_t,
                                const ResolvedParams&) -> std::optional<std::uint64_t> {
        return locale_cell(ql, locale.collate_cp, 4);
    };

    // unsigned int* ___mb_cur_max_func(void); — 1 for the C locale
    WinsdkApi("___mb_cur_max_func", WinCc::Cdecl, {}) =
        [&locale, &locale_cell](Qiling& ql, std::uint64_t,
                                const ResolvedParams&) -> std::optional<std::uint64_t> {
        const auto cell = locale_cell(ql, locale.mb_cur_max, 4);
        ql.mem().write_ptr(cell, 1, 4);
        return cell;
    };

    // char** ___lc_locale_name_func(void); — LC_MIN..LC_MAX slots, all NULL
    // ("C"), so the callers' `if (name)` guards skip their free/replace paths
    WinsdkApi("___lc_locale_name_func", WinCc::Cdecl, {}) =
        [&locale, &locale_cell](Qiling& ql, std::uint64_t,
                                const ResolvedParams&) -> std::optional<std::uint64_t> {
        return locale_cell(ql, locale.locale_names, 6 * ql.arch().pointersize());
    };

    // unsigned short** __pctype_func(void); — a real table behind the pointer,
    // because the caller indexes it twice
    WinsdkApi("__pctype_func", WinCc::Cdecl, {}) =
        [&locale, &locale_cell](Qiling& ql, std::uint64_t,
                                const ResolvedParams&) -> std::optional<std::uint64_t> {
        const auto cell = locale_cell(ql, locale.pctype, ql.arch().pointersize());
        if (!locale.ctype_table.has_value()) {
            locale.ctype_table = ql.os<os::windows::QlOsWindows>().heap().alloc(256 * 2);
            std::vector<std::uint8_t> table(256 * 2, 0);
            for (std::size_t i = 0; i < 256; ++i) {
                // the C-locale ctype flags: the CRT only tests them, so the
                // zero table ("no category") is the conservative shape
                table[i * 2] = 0;
                table[i * 2 + 1] = 0;
            }
            ql.mem().write(*locale.ctype_table, table);
        }
        ql.mem().write_ptr(cell, *locale.ctype_table);
        return cell;
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
