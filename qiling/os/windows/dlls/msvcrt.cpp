// Ported from qiling/os/windows/dlls/msvcrt.py — the CRT surface. The python
// module decorates ~40 handlers with @winsdkapi (mostly CDECL); the C++ port
// registers them through the shared WinsdkApi engine at static-init time.
#ifndef QILING_OS_WINDOWS_DLLS_MSVCRT_CPP
#define QILING_OS_WINDOWS_DLLS_MSVCRT_CPP

#include "qiling/core.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

#include <algorithm>
#include <ctime>

#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// ---- the shared walks (msvcrt.py __alloc_strings_array / __getmainargs) ----

// __alloc_strings_array: allocate and populate an array of strings and return
// its address (the pointer array + the packed item bytes + the trailing null)
std::uint64_t alloc_strings_array(Qiling& ql, const std::vector<std::string>& items, bool wide) {
    auto& heap = w(ql).heap();
    const std::size_t ps = ql.arch().pointersize();

    const std::size_t nitems = items.size();

    // allocate room for pointers to items and a trailing null pointer
    const auto p_array = heap.alloc((nitems + 1) * ps);

    // encode all arguments into bytes (the utf-16le / utf-8 enc choice; the
    // x00 terminator rides each item)
    std::vector<std::vector<std::uint8_t>> items_bytes;
    items_bytes.reserve(nitems);
    std::size_t total = 0;
    for (const auto& item : items) {
        std::vector<std::uint8_t> bytes;
        for (const char c : item) {
            bytes.push_back(static_cast<std::uint8_t>(c));
            if (wide) {
                bytes.push_back(0);
            }
        }
        bytes.push_back(0);
        if (wide) {
            bytes.push_back(0);
        }
        total += bytes.size();
        items_bytes.push_back(std::move(bytes));
    }

    // allocate room for the items
    auto p_items_bytes = heap.alloc(total);

    for (std::size_t i = 0; i < items_bytes.size(); ++i) {
        const auto& item = items_bytes[i];

        // write argument data
        ql.mem().write(p_items_bytes, item);

        // write pointer to argument data into the argv array
        ql.mem().write_ptr(p_array + (i * ps), p_items_bytes);

        p_items_bytes += item.size();
    }

    // write trailing null pointer
    ql.mem().write_ptr(p_array + (nitems * ps), 0);

    return p_array;
}

std::uint64_t getmainargs_body(Qiling& ql, const ResolvedParams& params, bool wide) {
    const auto argc = static_cast<std::uint64_t>(ql.argv().size());
    const std::vector<std::string> argv(ql.argv().begin(), ql.argv().end());
    std::vector<std::string> env;
    env.reserve(ql.env().size());
    for (const auto& [k, v] : ql.env()) {
        env.push_back(k + "=" + v);
    }

    const auto argv_addr = alloc_strings_array(ql, argv, wide);
    const auto env_addr = alloc_strings_array(ql, env, wide);

    // write out parameters
    ql.mem().write_ptr(api_get_int(get_param(params, "_Argc")), argc, 4);
    ql.mem().write_ptr(api_get_int(get_param(params, "_Argv")), argv_addr);
    ql.mem().write_ptr(api_get_int(get_param(params, "_Env")), env_addr);

    return 0;
}

// the variadic pull ladders (msvcrt.py hook_printf / hook_sprintf shapes; the
// port's read_ellipsis is the count-bounded variant of the upstream infinite
// generator, hence the pre-scan)

// msvcrt.py hook_sprintf / __stdio_common_vsprintf: the va_list pointer-chain
// walk riding the utils.py va_list generator; the upd_args(params) ride is
// inert (the params dict dies after the hook returns)
std::uint64_t sprintf_body(Qiling& ql, std::uint64_t buff, const std::string& format, std::uint64_t arglist,
                           bool wstring) {
    auto ptr = arglist;
    const auto va_args = [&, ptr]() mutable -> std::uint64_t {
        const auto v = ql.mem().read_ptr(ptr);
        ptr += ql.arch().pointersize();
        return v;
    };

    const auto result = QlOsUtils::sprintf(ql, buff, format, va_args, wstring);
    return result.count;
}

// the direct-imported variadic shape: the args ride the pre-pulled ellipsis
// slots (the readEllipsis walk in the handler)
std::uint64_t sprintf_body(Qiling& ql, std::uint64_t buff, const std::string& format,
                           const std::vector<std::uint64_t>& args, bool wstring) {
    std::size_t cursor = 0;
    const auto va_args = [&args, &cursor]() -> std::uint64_t {
        return cursor < args.size() ? args[cursor++] : 0;
    };

    const auto result = QlOsUtils::sprintf(ql, buff, format, va_args, wstring);
    return result.count;
}

// msvcrt.py __stdio_common_vsprintf (the _vsnprintf/_vswprintf/_vsnwprintf
// variants share the body; the TODO: take _BufferCount into account verbatim
// comment rides)
std::uint64_t stdio_vsprintf_body(Qiling& ql, const ResolvedParams& params, bool wstring) {
    const auto buff = api_get_int(get_param(params, "_Buffer"));
    auto format = api_get_string(ql, get_param(params, "_Format"));
    const auto arglist = api_get_int(get_param(params, "_ArgList"));

    return sprintf_body(ql, buff, format, arglist, wstring);
}

// msvcrt.py hook_printf / hook_wprintf: the readEllipsis walk over the
// pre-pulled slots
std::uint64_t printf_body(Qiling& ql, const std::string& format, const std::vector<std::uint64_t>& args,
                          bool wstring) {
    std::size_t cursor = 0;
    const auto pull = [&args, &cursor]() -> std::uint64_t {
        return cursor < args.size() ? args[cursor++] : 0;
    };

    const auto result = QlOsUtils::printf(ql, format, pull, wstring);
    return result.count;
}

// the va_list pointer-chain pull + the stdout render (the
// __stdio_common_vfprintf/_vfwprintf body: the TODO: take _Stream into
// account verbatim comment rides)
std::uint64_t stdio_vfprintf_body(Qiling& ql, const ResolvedParams& params, bool wstring) {
    auto format = api_get_string(ql, get_param(params, "_Format"));
    const auto arglist = api_get_int(get_param(params, "_ArgList"));

    auto ptr = arglist;
    const auto va_args = [&, ptr]() mutable -> std::uint64_t {
        const auto v = ql.mem().read_ptr(ptr);
        ptr += ql.arch().pointersize();
        return v;
    };

    const auto result = QlOsUtils::printf(ql, format, va_args, wstring);
    return result.count;
}

}  // namespace

void register_msvcrt_family() {
    using namespace qiling::os::api;

    // void __set_app_type(int at);
    WinsdkApi("__set_app_type", WinCc::Cdecl, {
        {"at", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;  // the verbatim `pass` rides the None result (the no-op)
    };

    // int __getmainargs(int * _Argc, char *** _Argv, char *** _Env,
    //                   int _DoWildCard, _startupinfo * _StartInfo);
    WinsdkApi("__getmainargs", WinCc::Cdecl, {
        {"_Argc", PVOID_},
        {"_Argv", PVOID_},
        {"_Env", PVOID_},
        {"_DoWildCard", INT_},
        {"_StartInfo", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return getmainargs_body(ql, params, false);
    };

    // int __wgetmainargs(...); — the wide flavour
    WinsdkApi("__wgetmainargs", WinCc::Cdecl, {
        {"_Argc", PVOID_},
        {"_Argv", PVOID_},
        {"_Env", PVOID_},
        {"_DoWildCard", INT_},
        {"_StartInfo", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return getmainargs_body(ql, params, true);
    };

    // int* __p__fmode();
    WinsdkApi("__p__fmode", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                   const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).heap().alloc(ql.arch().pointersize());
    };

    // int* __p__commode();
    WinsdkApi("__p__commode", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                     const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).heap().alloc(ql.arch().pointersize());
    };

    // char** __p__acmdln();
    WinsdkApi("__p__acmdln", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                    const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO: use values calculated at __getmainargs  (verbatim)
        const auto* iat = static_cast<loader::QlLoaderPE&>(ql.loader()).import_address_table_at("msvcrt.dll");
        if (iat == nullptr) {
            // the verbatim rides the python KeyError (the import_address_table
            // dict miss); the port raises through the shared error ladder
            throw QlErrorBase("msvcrt.dll is not in the import address table");
        }
        const auto addr = iat->lookup("_acmdln");
        if (addr == 0) {
            throw QlErrorBase("_acmdln is not in the msvcrt.dll import address table");
        }
        return addr;
    };

    // wchar_t ** __p__wcmdln();
    WinsdkApi("__p__wcmdln", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                    const ResolvedParams&) -> std::optional<std::uint64_t> {
        const auto* iat = static_cast<loader::QlLoaderPE&>(ql.loader()).import_address_table_at("msvcrt.dll");
        if (iat == nullptr) {
            throw QlErrorBase("msvcrt.dll is not in the import address table");
        }
        const auto addr = iat->lookup("_wcmdln");
        if (addr == 0) {
            throw QlErrorBase("_wcmdln is not in the msvcrt.dll import address table");
        }
        return addr;
    };

    // unsigned int _controlfp(unsigned int new, unsigned int mask);
    WinsdkApi("_controlfp", WinCc::Cdecl, {
        {"new", UINT_},
        {"mask", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0x8001f;
    };

    // int atexit(void (__cdecl *func)(void)); — the port answers success
    // (the registered list never runs: exit() stops the emulation before the
    // teardown; the upstream passthru needs the real CRT body, unavailable on
    // the stub-dll hosts)
    WinsdkApi("atexit", WinCc::Cdecl, {
        {"func", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // char*** __p__environ(void)
    WinsdkApi("__p__environ", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                     const ResolvedParams&) -> std::optional<std::uint64_t> {
        auto& heap = w(ql).heap();
        const std::size_t ps = ql.arch().pointersize();
        const auto& env = ql.env();

        const auto ret = heap.alloc(ps * env.size());

        std::size_t i = 0;
        for (const auto& [k, v] : env) {
            const std::string entry = k + "=" + v + '\0';
            const auto p_entry = heap.alloc(entry.size());
            ql.mem().write(p_entry, std::vector<std::uint8_t>(entry.begin(), entry.end()));

            const auto pp_entry = heap.alloc(ps);
            ql.mem().write_ptr(pp_entry, p_entry);
            ql.mem().write_ptr(ret + i * ps, pp_entry);
            ++i;
        }

        return ret;
    };

    // int puts(const char *str);
    WinsdkApi("puts", WinCc::Cdecl, {
        {"str", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const std::string s = api_get_string(ql, get_param(params, "str")) + '\n';

        w(ql).stdout_stream().write(std::vector<std::uint8_t>(s.begin(), s.end()));

        return s.size();
    };

    // void _cexit( void );
    WinsdkApi("_cexit", WinCc::Cdecl, {}) = [](Qiling&, std::uint64_t,
                                               const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;  // the verbatim `pass`
    };

    // void exit(int const status);
    WinsdkApi("exit", WinCc::Cdecl, {
        {"status", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        ql.emu_stop();
        return std::nullopt;
    };

    // void _exit(int status); / void _Exit(int status); — the immediate
    // termination shape (no atexit walk)
    WinsdkApi("_exit", WinCc::Cdecl, {
        {"status", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto status = api_get_int(get_param(params, "status"));
        w(ql).set_exit_code(static_cast<int>(status));
        ql.emu_stop();
        return std::nullopt;
    };

    WinsdkApi("_Exit", WinCc::Cdecl, {
        {"status", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto status = api_get_int(get_param(params, "status"));
        w(ql).set_exit_code(static_cast<int>(status));
        ql.emu_stop();
        return std::nullopt;
    };

    // int _XcptFilter(unsigned long xcpt, struct _EXCEPTION_POINTERS*);
    // — the CRT exception filter: the port answers EXCEPTION_EXECUTE_HANDLER
    // (1) so the except block runs (the SEH dispatch machinery lands with its
    // slice)
    WinsdkApi("_XcptFilter", WinCc::Cdecl, {
        {"exception", PVOID_},
        {"exception_pointers", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // int _except_handler3(PEXCEPTION_RECORD, _EXCEPTION_REGISTRATION_RECORD*,
    //                      PCONTEXT, void*);
    //
    // The pre-EH4 MSVC walker: the registration chain is {Next, Handler,
    // ScopeTable, TryLevel} with a PLAIN scope-table pointer (no cookie, no
    // 16-byte header — unlike EH4) and 12-byte {EnclosingLevel, FilterFunc,
    // HandlerAddress} records indexed by the current TryLevel. The walk
    // records the frames for the dispatch (QlOsWindows::seh_continue) and
    // answers EXCEPTION_CONTINUE_SEARCH.
    WinsdkApi("_except_handler3", WinCc::Cdecl, {
        {"exception_record", PVOID_},
        {"establisher_frame", PVOID_},
        {"context_record", PVOID_},
        {"dispatcher_context", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto establisher = api_get_int(get_param(params, "establisher_frame"));
        auto& os = w(ql);
        os.seh_clear_frames();

        for (int depth = 0; depth < 32; ++depth) {
            if (establisher == 0 || establisher == 0xffffffffull ||
                establisher < 0x1000 || establisher >= 0xfffff000) {
                break;
            }

            std::uint64_t next = 0;
            std::int32_t trylevel = -1;
            std::uint32_t scope_table = 0;
            try {
                next = ql.mem().read_ptr(establisher, 4);
                scope_table = static_cast<std::uint32_t>(ql.mem().read_ptr(establisher + 8, 4));
                trylevel = static_cast<std::int32_t>(
                    static_cast<std::uint32_t>(ql.mem().read_ptr(establisher + 12, 4)));
            } catch (...) {
                break;
            }
            if (scope_table < 0x1000 || scope_table >= 0xfffff000) {
                break;
            }

            // -1 (0xffffffff) = no active scope; -2 = the outermost
            if (trylevel == -2) {
                trylevel = 0;
            }
            if (trylevel >= 0) {
                const auto record_addr = static_cast<std::uint64_t>(scope_table) +
                                         static_cast<std::uint64_t>(trylevel) * 12;
                try {
                    qiling::os::windows::SehScopeRecord scope;
                    scope.enclosing_level = static_cast<std::uint32_t>(ql.mem().read_ptr(record_addr, 4));
                    scope.filter = static_cast<std::uint32_t>(ql.mem().read_ptr(record_addr + 4, 4));
                    scope.handler = static_cast<std::uint32_t>(ql.mem().read_ptr(record_addr + 8, 4));
                    os.seh_record_frame(establisher, scope);
                } catch (...) {
                    break;
                }
            }

            establisher = next;
        }

        return qiling::os::windows::kExceptionContinueSearch;
    };

    // int _except_handler4_common(
    //     unsigned *Cookie, void (*FrameFunc)(void),
    //     PEXCEPTION_RECORD, _EXCEPTION_REGISTRATION_RECORD *Establisher,
    //     PCONTEXT, void *DispatcherContext);
    //
    // The MSVC EH4 runtime: walk the registration chain from the establisher
    // outward, decode each frame's cookie-encoded scope table and record
    // the current TryLevel's scope record ({EnclosingLevel, FilterFunc,
    // HandlerAddress}) into the os SEH state — the dispatch walk
    // (QlOsWindows::seh_continue) then calls the filters / the __except
    // blocks. Answers EXCEPTION_CONTINUE_SEARCH: the frames carry the
    // decision (pegasus msvcrt.cpp _except_handler4_common, verbatim shape)
    WinsdkApi("_except_handler4_common", WinCc::Cdecl, {
        {"cookie_ptr", PVOID_},
        {"frame_func", PVOID_},
        {"exception_record", PVOID_},
        {"establisher_frame", PVOID_},
        {"context_record", PVOID_},
        {"dispatcher_context", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto cookie_ptr = api_get_int(get_param(params, "cookie_ptr"));
        auto establisher = api_get_int(get_param(params, "establisher_frame"));

        std::uint32_t cookie = 0;
        try {
            cookie = static_cast<std::uint32_t>(ql.mem().read_ptr(cookie_ptr, 4));
        } catch (...) {
            return qiling::os::windows::kExceptionContinueSearch;
        }

        auto& os = w(ql);
        os.seh_clear_frames();

        // the EH4 registration layout: {Next, Handler, ScopeTable ^ cookie,
        // TryLevel} — the scope table: the 16-byte {GSCookieOffset,
        // GSCookieXOROffset, EHCookieOffset, EHCookieXOROffset} header then
        // the 12-byte records; the walk stops at the chain end sentinel or
        // the first frame the guest memory does not carry
        for (int depth = 0; depth < 32; ++depth) {
            if (establisher == 0 || establisher == 0xffffffffull ||
                establisher < 0x1000 || establisher >= 0xfffff000) {
                break;
            }

            std::uint64_t next = 0;
            std::uint32_t scope_table = 0;
            std::int32_t trylevel = -1;
            try {
                next = ql.mem().read_ptr(establisher, 4);
                const auto encoded_scope = static_cast<std::uint32_t>(ql.mem().read_ptr(establisher + 8, 4));
                const auto trylevel_raw = static_cast<std::int32_t>(
                    static_cast<std::uint32_t>(ql.mem().read_ptr(establisher + 12, 4)));

                scope_table = encoded_scope ^ cookie;
                if (scope_table < 0x1000 || scope_table >= 0xfffff000) {
                    break;  // a bogus decode: stop the walk
                }

                // the current TryLevel: -1 = no active scope, -2 = the
                // outermost (pegasus maps it to the record 0)
                trylevel = trylevel_raw;
                if (trylevel == -2) {
                    trylevel = 0;
                }
            } catch (...) {
                break;  // the frame outside the guest memory: stop
            }

            if (trylevel >= 0) {
                const auto record_addr = static_cast<std::uint64_t>(scope_table) + 16 +
                                         static_cast<std::uint64_t>(trylevel) * 12;
                try {
                    qiling::os::windows::SehScopeRecord scope;
                    scope.enclosing_level = static_cast<std::uint32_t>(ql.mem().read_ptr(record_addr, 4));
                    scope.filter = static_cast<std::uint32_t>(ql.mem().read_ptr(record_addr + 4, 4));
                    scope.handler = static_cast<std::uint32_t>(ql.mem().read_ptr(record_addr + 8, 4));
                    os.seh_record_frame(establisher, scope);
                } catch (...) {
                    // the record outside the mapped scope table: stop
                    break;
                }
            }

            establisher = next;
        }

        // the frames carry the decision; the walk resumes at the sentinel
        return qiling::os::windows::kExceptionContinueSearch;
    };

    // LONG __C_specific_handler(PEXCEPTION_RECORD, PEXCEPTION_FRAME, ...);
    WinsdkApi("__C_specific_handler", WinCc::Cdecl, {
        {"exception_record", PVOID_},
        {"establisher_frame", PVOID_},
        {"context_record", PVOID_},
        {"dispatcher_context", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return qiling::os::windows::kExceptionContinueSearch;
    };

    // char*** __cdecl __p___argv (void);
    WinsdkApi("__p___argv", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                   const ResolvedParams&) -> std::optional<std::uint64_t> {
        auto& heap = w(ql).heap();
        const std::size_t ps = ql.arch().pointersize();

        // allocate argv pointers array
        const auto& argv = ql.argv();
        const auto p_argv = heap.alloc(ps * argv.size());

        for (std::size_t i = 0; i < argv.size(); ++i) {
            const std::string entry = argv[i] + '\0';
            const auto p_entry = heap.alloc(entry.size());
            ql.mem().write(p_entry, std::vector<std::uint8_t>(entry.begin(), entry.end()));
            ql.mem().write_ptr(p_argv + i * ps, p_entry);
        }

        const auto ret = heap.alloc(ps);
        ql.mem().write_ptr(ret, p_argv);

        return ret;
    };

    // char*** __cdecl __p___initenv (void) — the address of the CRT's
    // __initenv global (the environment block pointer cell). The old-MSVC
    // startup stores the __getmainargs environment through it
    // (`*__p___initenv() = env`), so the cell has to exist and stay stable
    WinsdkApi("__p___initenv", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                      const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).ensure_env_cell();
    };

    // int* __p___argc(void)
    WinsdkApi("__p___argc", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                                   const ResolvedParams&) -> std::optional<std::uint64_t> {
        const auto ret = w(ql).heap().alloc(ql.arch().pointersize());
        ql.mem().write_ptr(ret, static_cast<std::uint64_t>(ql.argv().size()));
        return ret;
    };

    // the ucrtbase rider: _get_initial_narrow_environment (the upstream
    // passthru needs the real CRT body; the port answers the env strings
    // array — the same shape __getmainargs builds)
    WinsdkApi("_get_initial_narrow_environment", WinCc::Cdecl, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
            std::vector<std::string> env;
            env.reserve(ql.env().size());
            for (const auto& [k, v] : ql.env()) {
                env.push_back(k + "=" + v);
            }
            return alloc_strings_array(ql, env, false);
        };

    // the printf family (the sprintf/printf/wprintf + the __stdio_common
    // walkers) lands in the sub-slice 2 with the QlOsUtils::count_va_pulls
    // helper.

    // int sprintf ( char * str, const char * format, ... ); — the
    // direct-imported variadic walk: the named slots (the buff, the format)
    // consume their native slots, the varargs continue from there (the
    // readEllipsis shape, the same pull the printf family rides)
    WinsdkApi("sprintf", WinCc::Cdecl, {
        {"buff", PVOID_},
        {"format", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buff = api_get_int(get_param(params, "buff"));
        // NOTE: the verbatim `if format == 0: format = "(null)"` rides the
        // py2 str/int comparison quirk — inert in the py3 (the decoded string
        // never equals the int 0); the port keeps the raw walk
        auto format = api_get_string(ql, get_param(params, "format"));

        const std::vector<int> slots{os::PARAM_INTN, os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        return sprintf_body(ql, buff, format, args, false);
    };

    // int printf(const char *format, ...)
    WinsdkApi("printf", WinCc::Cdecl, {
        {"format", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto format = api_get_string(ql, get_param(params, "format"));

        // the fcall readEllipsis: each named param skips one native slot; the
        // pull count comes from the format walk (the port's bounded variant
        // of the upstream infinite generator)
        const std::vector<int> slots{os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        return printf_body(ql, format, args, false);
    };

    // int wprintf(const wchar_t *format, ...)
    WinsdkApi("wprintf", WinCc::Cdecl, {
        {"format", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto format = api_get_string(ql, get_param(params, "format"));

        const std::vector<int> slots{os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        return printf_body(ql, format, args, true);
    };

    // the __stdio_common family (the ucrtbase printf machinery): the buffer
    // flavours share the sprintf walk, the stream flavours the stdout walk;
    // the "_s" versions are aliases to their non-"_s" counterparts (verbatim)
    WinsdkApi("__stdio_common_vfprintf", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Stream", PVOID_},
        {"_Format", LPCSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vfprintf_body(ql, params, false);
    };

    WinsdkApi("__stdio_common_vfwprintf", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Stream", PVOID_},
        {"_Format", LPCWSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vfprintf_body(ql, params, true);
    };

    // the _vsprintf flavour: the _Buffer/_BufferCount/_Format/_Locale/_ArgList
    // (the TODO: take _BufferCount into account verbatim comment rides)
    WinsdkApi("__stdio_common_vsprintf", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_Format", LPCSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, false);
    };

    // the _vsnprintf flavour: the _MaxCount joins (the verbatim extra param)
    WinsdkApi("__stdio_common_vsnprintf", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_MaxCount", PVOID_},
        {"_Format", LPCSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, false);
    };

    WinsdkApi("__stdio_common_vswprintf", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_Format", LPCWSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, true);
    };

    WinsdkApi("__stdio_common_vsnwprintf", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_MaxCount", PVOID_},
        {"_Format", LPCWSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, true);
    };

    // all the "_s" versions are aliases to their non-"_s" counterparts
    // (verbatim); the port rides the same bodies
    WinsdkApi("__stdio_common_vfprintf_s", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Stream", PVOID_},
        {"_Format", LPCSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vfprintf_body(ql, params, false);
    };

    WinsdkApi("__stdio_common_vfwprintf_s", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Stream", PVOID_},
        {"_Format", LPCWSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vfprintf_body(ql, params, true);
    };

    WinsdkApi("__stdio_common_vsprintf_s", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_Format", LPCSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, false);
    };

    WinsdkApi("__stdio_common_vsnprintf_s", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_MaxCount", PVOID_},
        {"_Format", LPCSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, false);
    };

    WinsdkApi("__stdio_common_vswprintf_s", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_Format", LPCWSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, true);
    };

    WinsdkApi("__stdio_common_vsnwprintf_s", WinCc::Cdecl, {
        {"_Options", PARAM_INT64},
        {"_Buffer", PVOID_},
        {"_BufferCount", PVOID_},
        {"_MaxCount", PVOID_},
        {"_Format", LPCWSTR_},
        {"_Locale", DWORD_},
        {"_ArgList", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return stdio_vsprintf_body(ql, params, true);
    };

    // int __lconv_init(void);
    WinsdkApi("__lconv_init", WinCc::Cdecl, {}) = [](Qiling&, std::uint64_t,
                                                     const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // size_t __strncnt(const char *str, size_t maxsize);
    WinsdkApi("__strncnt", WinCc::Cdecl, {
        {"str", PVOID_},
        {"maxsize", PVOID_},  // the SIZE_T (the const.py PARAM_INTN; the port
                              // rides the raw-int resolver)
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_int(get_param(params, "str"));
        const auto maxsize = api_get_int(get_param(params, "maxsize"));

        auto data = ql.mem().read(s, static_cast<std::size_t>(maxsize));

        // a simple hack to make sure a null terminator is found at most at
        // 'maxsize'  (verbatim)
        data.push_back(0);
        const auto it = std::find(data.begin(), data.end(), std::uint8_t{0});
        return static_cast<std::uint64_t>(it - data.begin());
    };

    // size_t strlen(const char *str);
    WinsdkApi("strlen", WinCc::Cdecl, {
        {"str", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_string(ql, get_param(params, "str"));

        return s.empty() ? 0 : static_cast<std::uint64_t>(s.size());
    };

    // int strncmp(const char *string1, const char *string2, size_t count);
    WinsdkApi("strncmp", WinCc::Cdecl, {
        {"string1", LPCSTR_},
        {"string2", LPCSTR_},
        {"count", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto& s1 = api_get_string(ql, get_param(params, "string1"));
        const auto& s2 = api_get_string(ql, get_param(params, "string2"));
        const auto count = api_get_int(get_param(params, "count"));

        const auto string1 = s1.substr(0, static_cast<std::size_t>(count));
        const auto string2 = s2.substr(0, static_cast<std::size_t>(count));

        if (string1 == string2) {
            return 0;
        }
        return string1 > string2 ? 1 : static_cast<std::uint64_t>(-1);
    };

    // the malloc/free family: the upstream rides the passthru (the native
    // CRT bodies run inside the real msvcrt.dll); the stub-dll hosts have no
    // native bodies, so the port answers through the emulated heap — the
    // same QlMemoryHeap the kernel32 HeapAlloc family shares
    WinsdkApi("_malloc_base", WinCc::Cdecl, {
        {"size", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto size = api_get_int(get_param(params, "size"));
        return w(ql).heap().alloc(size);
    };

    // void* malloc(unsigned int size)
    WinsdkApi("malloc", WinCc::Cdecl, {
        {"size", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto size = api_get_int(get_param(params, "size"));
        return w(ql).heap().alloc(size);
    };

    // void* __cdecl _realloc_base(void* block, size_t size);
    WinsdkApi("_realloc_base", WinCc::Cdecl, {
        {"block", PVOID_},
        {"size", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto block = api_get_int(get_param(params, "block"));
        const auto size = api_get_int(get_param(params, "size"));

        auto& heap = w(ql).heap();
        const auto fresh = heap.alloc(size);
        if (block != 0 && fresh != 0) {
            const auto old_size = heap.size(block);
            const auto n = std::min<std::uint64_t>(old_size, size);
            if (n != 0) {
                ql.mem().write(fresh, ql.mem().read(block, n));
            }
            heap.free(block);
        }
        return fresh;
    };

    WinsdkApi("_free_base", WinCc::Cdecl, {
        {"address", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).heap().free(api_get_int(get_param(params, "address")));
        return 0;
    };

    // void* free(void *address)
    WinsdkApi("free", WinCc::Cdecl, {
        {"address", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).heap().free(api_get_int(get_param(params, "address")));
        return 0;
    };

    // _onexit_t _onexit(_onexit_t function);
    WinsdkApi("_onexit", WinCc::Cdecl, {
        {"function", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto function = api_get_int(get_param(params, "function"));

        const auto addr = w(ql).heap().alloc(ql.arch().pointersize());
        ql.mem().write_ptr(addr, function);

        return addr;
    };

    // _onexit_t __dllonexit(_onexit_t func, _PVFV ** pbegin, _PVFV ** pend);
    WinsdkApi("__dllonexit", WinCc::Stdcall, {
        {"function", PVOID_},
        {"pbegin", PVOID_},
        {"pend", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto function = api_get_int(get_param(params, "function"));

        if (function != 0) {
            const auto addr = w(ql).heap().alloc(ql.arch().pointersize());
            ql.mem().write_ptr(addr, function);
            return addr;
        }

        return 0;
    };

    // void *memcpy(void *dest, const void *src, size_t count); — the guest
    // copy (the upstream rides the native body through the passthru)
    WinsdkApi("memcpy", WinCc::Cdecl, {
        {"dest", PVOID_},
        {"src", PVOID_},
        {"count", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dest = api_get_int(get_param(params, "dest"));
        const auto src = api_get_int(get_param(params, "src"));
        const auto count = api_get_int(get_param(params, "count"));

        if (count != 0) {
            ql.mem().write(dest, ql.mem().read(src, count));
        }
        return dest;
    };

    // void *memset(void *dest, int c, size_t count);
    WinsdkApi("memset", WinCc::Cdecl, {
        {"dest", PVOID_},
        {"c", INT_},
        {"count", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dest = api_get_int(get_param(params, "dest"));
        const auto c = api_get_int(get_param(params, "c")) & 0xff;
        const auto count = api_get_int(get_param(params, "count"));

        if (count != 0) {
            ql.mem().write(dest, std::vector<std::uint8_t>(static_cast<std::size_t>(count),
                                                           static_cast<std::uint8_t>(c)));
        }
        return dest;
    };

    // void *memmove(void *dest, const void *src, size_t num);
    WinsdkApi("memmove", WinCc::Cdecl, {
        {"dest", PVOID_},
        {"src", PVOID_},
        {"num", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dest = api_get_int(get_param(params, "dest"));
        const auto src = api_get_int(get_param(params, "src"));
        const auto num = api_get_int(get_param(params, "num"));

        if (num != 0) {
            ql.mem().write(dest, ql.mem().read(src, num));
        }
        return dest;
    };

    // the calloc family: the zero-filled heap walk
    WinsdkApi("_calloc_base", WinCc::Cdecl, {
        {"num", PVOID_},
        {"size", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto num = api_get_int(get_param(params, "num"));
        const auto size = api_get_int(get_param(params, "size"));

        const auto total = num * size;
        const auto addr = w(ql).heap().alloc(total);
        if (addr != 0 && total != 0) {
            ql.mem().write(addr, std::vector<std::uint8_t>(static_cast<std::size_t>(total), 0));
        }
        return addr;
    };

    // void *calloc(size_t num, size_t size);
    WinsdkApi("calloc", WinCc::Cdecl, {
        {"num", PVOID_},
        {"size", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto num = api_get_int(get_param(params, "num"));
        const auto size = api_get_int(get_param(params, "size"));

        const auto total = num * size;
        const auto addr = w(ql).heap().alloc(total);
        if (addr != 0 && total != 0) {
            ql.mem().write(addr, std::vector<std::uint8_t>(static_cast<std::size_t>(total), 0));
        }
        return addr;
    };

    // int _ismbblead(unsigned int c);
    WinsdkApi("_ismbblead", WinCc::Cdecl, {
        {"c", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO check if is CDECL or not  (verbatim)
        // If locale is utf-8 always return 0
        // (the LOCALE["default"] = LOCALE_EN_US; the 0x1004 cell reads
        // "utf-8" so the ride always lands the 0)
        const auto& loc = LOCALE_EN_US;
        if (loc.at(0x1004) == "utf-8") {
            return 0;
        }

        throw QlErrorNotImplemented("API not implemented");
    };

    // errno_t _wfopen_s(FILE** pFile, const wchar_t *filename,
    //                   const wchar_t *mode);
    WinsdkApi("_wfopen_s", WinCc::Cdecl, {
        {"pFile", PVOID_},
        {"filename", LPCWSTR_},
        {"mode", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto p_file = api_get_int(get_param(params, "pFile"));
        const auto filename = api_get_string(ql, get_param(params, "filename"));
        const auto mode = api_get_string(ql, get_param(params, "mode"));

        auto f = w(ql).fs_mapper()->open(filename, mode);

        Handle new_handle(std::nullopt, f.get());
        // the python Handle keeps the mapped object alive via the reference;
        // the port parks it in the type-erased ownership slot
        new_handle.owned = f;
        w(ql).handle_manager().append(new_handle);

        ql.mem().write_ptr(p_file, new_handle.id);

        return 1;
    };

    // FILE* fopen(const char* path, const char* mode); — the CRT stdio
    // surface over the fs mapper (the _wfopen_s shape: the QlFile parked in
    // the handle manager, the FILE* rides the handle id)
    WinsdkApi("fopen", WinCc::Cdecl, {
        {"path", LPCSTR_},
        {"mode", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto path = api_get_string(ql, get_param(params, "path"));
        const auto mode = api_get_string(ql, get_param(params, "mode"));

        auto f = w(ql).fs_mapper()->open(path, mode);

        Handle new_handle(std::nullopt, f.get());
        new_handle.owned = f;
        w(ql).handle_manager().append(new_handle);
        return new_handle.id;
    };

    // size_t fread(void* buffer, size_t size, size_t count, FILE* stream);
    WinsdkApi("fread", WinCc::Cdecl, {
        {"buffer", PVOID_},
        {"size", PVOID_},
        {"count", PVOID_},
        {"stream", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buffer = api_get_int(get_param(params, "buffer"));
        const auto size = api_get_int(get_param(params, "size"));
        const auto count = api_get_int(get_param(params, "count"));
        const auto stream = api_get_int(get_param(params, "stream"));

        const auto* handle = w(ql).handle_manager().get(stream);
        if (handle == nullptr || handle->obj == nullptr) {
            return 0;
        }
        auto* f = static_cast<QlFile*>(handle->obj);

        const auto want = static_cast<std::size_t>(size * count);
        const auto data = f->read(want);
        if (!data.empty()) {
            ql.mem().write(buffer, data);
        }
        return data.size() / (size != 0 ? static_cast<std::uint64_t>(size) : 1);
    };

    // int fclose(FILE* stream);
    WinsdkApi("fclose", WinCc::Cdecl, {
        {"stream", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto stream = api_get_int(get_param(params, "stream"));

        auto* handle = w(ql).handle_manager().get(stream);
        if (handle == nullptr) {
            return -1;
        }
        if (handle->obj != nullptr) {
            static_cast<QlFile*>(handle->obj)->close();
        }
        w(ql).handle_manager().delete_handle(stream);
        return 0;
    };

    // int fseek(FILE* stream, long offset, int origin);
    WinsdkApi("fseek", WinCc::Cdecl, {
        {"stream", PVOID_},
        {"offset", PVOID_},
        {"origin", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto stream = api_get_int(get_param(params, "stream"));
        const auto offset = api_get_int(get_param(params, "offset"));
        const auto origin = api_get_int(get_param(params, "origin"));

        const auto* handle = w(ql).handle_manager().get(stream);
        if (handle == nullptr || handle->obj == nullptr) {
            return -1;
        }
        static_cast<QlFile*>(handle->obj)->lseek(offset, static_cast<int>(origin));
        return 0;
    };

    // int system(const char* command); — no host shell rides the emulator;
    // the walk answers success with no side effects
    WinsdkApi("system", WinCc::Cdecl, {
        {"command", LPCSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int _snprintf(char* buffer, size_t count, const char* format, ...);
    // — the sprintf walk with the count cap (the terminator rides inside
    // count; the caller sees the truncated length)
    WinsdkApi("_snprintf", WinCc::Cdecl, {
        {"buff", PVOID_},
        {"count", PVOID_},
        {"format", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buff = api_get_int(get_param(params, "buff"));
        const auto count = api_get_int(get_param(params, "count"));
        auto format = api_get_string(ql, get_param(params, "format"));

        const std::vector<int> slots{os::PARAM_INTN, os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        const auto written = sprintf_body(ql, buff, format, args, false);
        if (count != 0 && written >= count) {
            // truncate: force the terminator inside the count window
            ql.mem().write_ptr(buff + (count - 1), 0, 1);
            return static_cast<std::uint64_t>(count - 1);
        }
        return written;
    };

    // time_t time(time_t *destTime);
    WinsdkApi("_time64", WinCc::Cdecl, {
        {"destTime", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dst = api_get_int(get_param(params, "destTime"));

        const auto time_wasted = static_cast<std::uint64_t>(std::time(nullptr));

        if (dst != 0) {
            ql.mem().write_ptr(dst, time_wasted, 8);
        }

        return time_wasted;
    };

    // void abort( void );
    WinsdkApi("abort", WinCc::Cdecl, {}) = [](Qiling& ql, std::uint64_t,
                                              const ResolvedParams&) -> std::optional<std::uint64_t> {
        // During testing, it was found that programs terminating abnormally
        // via abort() terminated with exit code=STATUS_STACK_BUFFER_OVERRUN.
        // According to Microsoft's devblog, this does not necessarily mean
        // that a stack buffer overrun occurred. Rather, it can indicate
        // abnormal program termination in a variety of situations, including
        // abort(). (verbatim comment)
        // https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655
        w(ql).set_exit_code(static_cast<int>(STATUS_STACK_BUFFER_OVERRUN));

        ql.emu_stop();
        return std::nullopt;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kMsvcrtRegistered = [] {
    qiling::os::win::register_msvcrt_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_MSVCRT_CPP
