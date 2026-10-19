// Ported from qiling/os/windows/dlls/kernel32/winbase.py — the legacy
// kernel32 surface (the _l file family, the verbatim stubs, the Local/Global
// heap family, the lstr family, the VerifyVersionInfo walk, the name
// queries, and the private-profile pair). Ported in sub-slices; this TU
// carries the full register_winbase_family(). The @winsdkapi decorators map
// onto the WinsdkApi registrations; the bodies ride the verbatim upstream
// walks. The family self-registers at static-init and can be re-seeded
// after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <algorithm>
#include <cstdio>
#include <cctype>
#include <functional>
#include <string>

#include "qiling/profiles/inireader.hpp"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

// the CRT I/O spellings differ between MSVC and POSIX (the python os module
// papers over this; the port keeps the shims local to the consumers)
#if defined(_WIN32)
#define QL_CRT_READ ::_read
#define QL_CRT_WRITE ::_write
#define QL_CRT_LSEEK ::_lseek
#else
#define QL_CRT_READ ::read
#define QL_CRT_WRITE ::write
#define QL_CRT_LSEEK ::lseek
#endif

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

constexpr int kLseekSet = 0;  // the CRT SEEK_SET (the python os.SEEK_SET)

// the verbatim mode-string build for _lcreat (the weird append preserved:
// the python mode "w+b" grows to "w+br+b" when the hidden bit rides)
std::string lcreat_mode(std::uint64_t attribute) {
    std::string mode = "w+b";
    if (attribute & 2) {
        mode += "r+b";
    }
    return mode;
}

// the OSVERSIONINFOEX[A|W] field read (structs.py make_os_version_info_ex:
// the default-aligned ctypes layout — the dw fields @4..16, the szCSDVersion
// char/wchar[128] @20, the w fields after it — 156/284 bytes total)
struct OsVerExFields {
    std::uint32_t dw_major = 0;
    std::uint32_t dw_minor = 0;
    std::uint32_t dw_build = 0;
    std::uint32_t dw_platform_id = 0;
    std::uint16_t w_sp_major = 0;
    std::uint16_t w_sp_minor = 0;
    std::uint16_t w_suite_mask = 0;
    std::uint8_t w_product_type = 0;
};

OsVerExFields read_os_ver_ex(Qiling& ql, std::uint64_t addr, const bool wide) {
    OsVerExFields f;
    f.dw_major = static_cast<std::uint32_t>(ql.mem().read_ptr(addr + 4, 4));
    f.dw_minor = static_cast<std::uint32_t>(ql.mem().read_ptr(addr + 8, 4));
    f.dw_build = static_cast<std::uint32_t>(ql.mem().read_ptr(addr + 12, 4));
    f.dw_platform_id = static_cast<std::uint32_t>(ql.mem().read_ptr(addr + 16, 4));
    const auto sp = addr + (wide ? 276 : 148);
    f.w_sp_major = static_cast<std::uint16_t>(ql.mem().read_ptr(sp, 2));
    f.w_sp_minor = static_cast<std::uint16_t>(ql.mem().read_ptr(sp + 2, 2));
    f.w_suite_mask = static_cast<std::uint16_t>(ql.mem().read_ptr(sp + 4, 2));
    f.w_product_type = static_cast<std::uint8_t>(ql.mem().read_ptr(sp + 6, 1));
    return f;
}

// the shared __VerifyVersionInfo body (the verbatim criteria walk)
std::optional<std::uint64_t> verify_version_info_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    // see: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow
    const auto lp_version_information = api_get_int(get_param(params, "lpVersionInformation"));
    const auto dw_type_mask = api_get_int(get_param(params, "dwTypeMask"));
    const auto dwl_condition_mask = api_get_int(get_param(params, "dwlConditionMask"));

    const auto asked = read_os_ver_ex(ql, lp_version_information, wide);

    // reading emulated os version info from profile
    // FIXME: read the necessary information from KUSER_SHARED_DATA instead
    // (verbatim)
    OsVerExFields emul;
    emul.dw_major = static_cast<std::uint32_t>(ql.profile().get_int("SYSTEM", "majorVersion"));
    emul.dw_minor = static_cast<std::uint32_t>(ql.profile().get_int("SYSTEM", "minorVersion"));
    emul.dw_build = 0;             // verbatim
    emul.dw_platform_id = 0;       // verbatim
    emul.w_sp_major = static_cast<std::uint16_t>(ql.profile().get_int("SYSTEM", "VER_SERVICEPACKMAJOR"));
    emul.w_sp_minor = 0;           // verbatim
    emul.w_suite_mask = 0;         // verbatim
    emul.w_product_type = static_cast<std::uint8_t>(ql.profile().get_int("SYSTEM", "productType"));

    // check criteria by the order they should be evaluated. the online
    // microsoft documentation only specify the first five, so not sure about
    // the other three.  (verbatim comment)
    const std::pair<int, std::function<std::uint64_t(const OsVerExFields&)>> checks[] = {
        {1, [](const OsVerExFields& f) { return f.dw_major; }},      // VER_MAJORVERSION
        {0, [](const OsVerExFields& f) { return f.dw_minor; }},      // VER_MINORVERSION
        {2, [](const OsVerExFields& f) { return f.dw_build; }},      // VER_BUILDNUMBER
        {5, [](const OsVerExFields& f) { return f.w_sp_major; }},    // VER_SERVICEPACKMAJOR
        {4, [](const OsVerExFields& f) { return f.w_sp_minor; }},    // VER_SERVICEPACKMINOR
        {3, [](const OsVerExFields& f) { return f.dw_platform_id; }},  // VER_PLATFORMID
        {6, [](const OsVerExFields& f) { return f.w_suite_mask; }},  // VER_SUITENAME
        {7, [](const OsVerExFields& f) { return f.w_product_type; }},  // VER_PRODUCT_TYPE
    };

    bool res = true;

    for (const auto& [bit, getter] : checks) {
        if (!(dw_type_mask & (1ull << bit))) {
            continue;
        }
        const auto asked_val = getter(asked);
        const auto emuld = getter(emul);

        // extract the condition code for the required field
        const auto cond = (static_cast<std::uint64_t>(dwl_condition_mask) >> (bit * VER_NUM_BITS_PER_CONDITION_MASK)) & VER_CONDITION_MASK;

        // special case for VER_SUITENAME
        if (bit == 6) {
            // the python dict lookup: a cond outside {AND, OR} raises the
            // KeyError (unhandled — the barrier)
            if (cond == VER_AND) {
                // all members of b must be present  (verbatim comment)
                res &= (emuld & asked_val) == asked_val;
            } else if (cond == VER_OR) {
                // at least one member of b must be present
                res &= (emuld & asked_val) != 0;
            } else {
                throw QlErrorBase("VER_SUITENAME cond KeyError");
            }
        } else {
            // cond operates as a bitmask, so multiple 'if' statements are
            // appropriately used here. do not turn this into an 'elif'
            // construct.  (verbatim comment)
            if ((cond & VER_GREATER) && (emuld > asked_val)) {
                return 1;
            }

            if ((cond & VER_LESS) && (emuld < asked_val)) {
                return 1;
            }

            if (cond & VER_EQUAL) {
                res &= (emuld == asked_val);
            }
        }
    }

    if (!res) {
        w(ql).set_last_error(ERROR_OLD_WIN_VERSION);
    }

    return res ? 1 : 0;
}

// the shared __GetUserName body
std::optional<std::uint64_t> get_user_name_body(Qiling& ql, const ResolvedParams& params, const bool wstring) {
    const auto lp_buffer = api_get_int(get_param(params, "lpBuffer"));
    const auto pcb_buffer = api_get_int(get_param(params, "pcbBuffer"));

    const auto username_value = ql.profile().get("USER", "username").value_or("");
    const std::string username_src = username_value + std::string(1, char(0));
    std::string username;
    if (wstring) {
        for (const char c : username_src) {
            username.push_back(c);
            username.push_back('\0');
        }
    } else {
        username = username_src;
    }

    const auto max_size = ql.mem().read_ptr(pcb_buffer, 4);
    ql.mem().write_ptr(pcb_buffer, username.size(), 4);

    if (username.size() > max_size) {
        w(ql).set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    ql.mem().write(lp_buffer, std::vector<std::uint8_t>(username.begin(), username.end()));
    return 1;
}

// the shared __GetComputerName body
std::optional<std::uint64_t> get_computer_name_body(Qiling& ql, const ResolvedParams& params, const bool wstring) {
    const auto lp_buffer = api_get_int(get_param(params, "lpBuffer"));
    const auto n_size = api_get_int(get_param(params, "nSize"));

    const auto computer_value = ql.profile().get("SYSTEM", "computername").value_or("");
    const std::string computer_src = computer_value + std::string(1, char(0));
    std::string computer;
    if (wstring) {
        for (const char c : computer_src) {
            computer.push_back(c);
            computer.push_back('\0');
        }
    } else {
        computer = computer_src;
    }

    const auto max_size = ql.mem().read_ptr(n_size, 4);
    ql.mem().write_ptr(n_size, computer.size(), 4);

    if (computer.size() > max_size) {
        w(ql).set_last_error(ERROR_BUFFER_OVERFLOW);
        return 0;
    }

    ql.mem().write(lp_buffer, std::vector<std::uint8_t>(computer.begin(), computer.end()));
    return 1;
}

}  // namespace

void register_winbase_family() {
    using namespace qiling::os::api;

    // ---- sub-slice 1: the _l file family + the verbatim stubs ----

    // HFILE _lclose(
    //   HFILE hFile
    // );
    WinsdkApi("_lclose", WinCc::Stdcall, {
        {"hFile", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto fileno = static_cast<std::int64_t>(api_get_int(get_param(params, "hFile")));

        if (fileno < 0) {
            return static_cast<std::uint64_t>(HFILE_ERROR);
        }

#ifdef _WIN32
        _close(static_cast<int>(fileno));
#else
        ::close(static_cast<int>(fileno));
#endif

        return static_cast<std::uint64_t>(fileno);
    };

    // HFILE _lcreat(
    //   LPCSTR lpPathName,
    //   int    iAttribute
    // );
    WinsdkApi("_lcreat", WinCc::Stdcall, {
        {"lpPathName", LPCSTR_},
        {"iAttribute", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto path = api_get_string(ql, get_param(params, "lpPathName"));
        const auto attribute = api_get_int(get_param(params, "iAttribute"));

        // There are 4 access bits, we don't care about hidden or system
        // (verbatim walk; the mapper raises QlErrorBase where the python
        // builtins.open raises FileNotFoundError — both ride the
        // ERROR_FILE_NOT_FOUND arm here)
        try {
            const auto f = w(ql).fs_mapper()->open(path, lcreat_mode(attribute));
#ifdef _WIN32
            return static_cast<std::uint64_t>(_dup(f->fileno()));
#else
            return static_cast<std::uint64_t>(dup(f->fileno()));
#endif
        } catch (const QlErrorBase&) {
            w(ql).set_last_error(ERROR_FILE_NOT_FOUND);
            return static_cast<std::uint64_t>(-1);
        }
    };

    // HFILE _lopen(
    //   LPCSTR lpPathName,
    //   int    iReadWrite
    // );
    WinsdkApi("_lopen", WinCc::Stdcall, {
        {"lpPathName", LPCSTR_},
        {"iReadWrite", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto path = api_get_string(ql, get_param(params, "lpPathName"));
        const auto read_write = api_get_int(get_param(params, "iReadWrite"));

        // access mask DesiredAccess  (verbatim)
        std::string mode;
        if (read_write & (OF_WRITE | OF_READWRITE)) {
            mode += "wb";
        } else {
            mode += "r";
        }

        try {
            const auto f = w(ql).fs_mapper()->open(path, mode);
#ifdef _WIN32
            return static_cast<std::uint64_t>(_dup(f->fileno()));
#else
            return static_cast<std::uint64_t>(dup(f->fileno()));
#endif
        } catch (const QlErrorBase&) {
            w(ql).set_last_error(ERROR_FILE_NOT_FOUND);
            return static_cast<std::uint64_t>(-1);
        }
    };

    // UINT _lread(
    //   HFILE  hFile,
    //   LPVOID lpBuffer,
    //   UINT   uBytes
    // );
    WinsdkApi("_lread", WinCc::Stdcall, {
        {"hFile", INT_},
        {"lpBuffer", PVOID_},
        {"uBytes", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto fileno = static_cast<std::int64_t>(api_get_int(get_param(params, "hFile")));
        const auto buffer = api_get_int(get_param(params, "lpBuffer"));
        const auto u_bytes = static_cast<std::size_t>(api_get_int(get_param(params, "uBytes")));

        if (fileno < 0) {
            return static_cast<std::uint64_t>(HFILE_ERROR);
        }

        std::vector<std::uint8_t> buf(u_bytes, 0);
        const auto n = QL_CRT_READ(static_cast<int>(fileno), buf.data(), static_cast<unsigned>(u_bytes));
        if (n < 0) {
            // the python os.read raises OSError (unhandled — the barrier)
            throw QlErrorBase("os.read failed");
        }
        buf.resize(static_cast<std::size_t>(n));
        ql.mem().write(buffer, buf);

        return static_cast<std::uint64_t>(n);
    };

    // LONG _llseek(
    //   HFILE hFile,
    //   LONG  lOffset,
    //   int   iOrigin
    // );
    WinsdkApi("_llseek", WinCc::Stdcall, {
        {"hFile", INT_},
        {"lOffset", INT_},
        {"iOrigin", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto fileno = static_cast<std::int64_t>(api_get_int(get_param(params, "hFile")));
        const auto offset = static_cast<std::int64_t>(api_get_int(get_param(params, "lOffset")));
        const auto origin = static_cast<int>(api_get_int(get_param(params, "iOrigin")));

        if (fileno < 0) {
            return static_cast<std::uint64_t>(HFILE_ERROR);
        }

        return static_cast<std::uint64_t>(QL_CRT_LSEEK(static_cast<int>(fileno), static_cast<long>(offset), origin));
    };

    // UINT _lwrite(
    //   HFILE hFile,
    //   LPCCH lpBuffer,
    //   UINT  uBytes
    // );
    WinsdkApi("_lwrite", WinCc::Stdcall, {
        {"hFile", INT_},
        {"lpBuffer", PVOID_},
        {"uBytes", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto fileno = static_cast<std::int64_t>(api_get_int(get_param(params, "hFile")));
        const auto buffer = api_get_int(get_param(params, "lpBuffer"));
        const auto u_bytes = static_cast<std::size_t>(api_get_int(get_param(params, "uBytes")));

        if (fileno < 0) {
            return static_cast<std::uint64_t>(HFILE_ERROR);
        }

        const auto wbuf = ql.mem().read(buffer, u_bytes);
        const auto n = QL_CRT_WRITE(static_cast<int>(fileno), wbuf.data(), static_cast<unsigned>(u_bytes));
        if (n < 0) {
            // the python os.write raises OSError (unhandled — the barrier)
            throw QlErrorBase("os.write failed");
        }

        return static_cast<std::uint64_t>(n);
    };

    // __analysis_noreturn VOID FatalExit(
    //   int ExitCode
    // );
    WinsdkApi("FatalExit", WinCc::Stdcall, {
        {"ExitCode", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        ql.emu_stop();
        return std::nullopt;
    };

    // UINT WinExec(
    //   LPCSTR lpCmdLine,
    //   UINT   uCmdShow
    // );
    WinsdkApi("WinExec", WinCc::Stdcall, {
        {"lpCmdLine", LPCSTR_},
        {"uCmdShow", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 33;
    };

    // UINT SetHandleCount(
    //   UINT uNumber
    // );
    WinsdkApi("SetHandleCount", WinCc::Stdcall, {
        {"uNumber", UINT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "uNumber"));
    };

    // HRSRC FindResourceA(
    //   HMODULE hModule,
    //   LPCSTR  lpName,
    //   LPCSTR  lpType
    // );
    WinsdkApi("FindResourceA", WinCc::Stdcall, {
        {"hModule", PVOID_},
        {"lpName", LPCSTR_},
        {"lpType", LPCSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Retrieve a resource
        // Name e Type can be int or strings, this can be a problem
        //
        // TODO i don't know how to implement this, the return 0 is to
        // simulate an error  (verbatim)
        return 0;
    };

    // BOOL IsBadReadPtr(
    //   const VOID *lp,
    //   UINT_PTR   ucb
    // );
    WinsdkApi("IsBadReadPtr", WinCc::Stdcall, {
        {"lp", PVOID_},
        {"ucb", DWORD_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Check read permission for size of memory
        return 0;  // ACCESS_TRUE  (verbatim)
    };

    // BOOL IsBadWritePtr(
    //   const VOID *lp,
    //   UINT_PTR   ucb
    // );
    WinsdkApi("IsBadWritePtr", WinCc::Stdcall, {
        {"lp", PVOID_},
        {"ucb", DWORD_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Check write permission for size of memory
        return 0;  // ACCESS_TRUE  (verbatim)
    };

    // ---- sub-slice 2: the Local/Global heap family + the lstr family ----

    // DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
    //   UINT   uFlags,
    //   SIZE_T uBytes
    // );
    WinsdkApi("LocalAlloc", WinCc::Stdcall, {
        {"uFlags", UINT_},
        {"uBytes", DWORD_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto u_bytes = api_get_int(get_param(params, "uBytes"));
        return w(ql).heap().alloc(u_bytes);
    };

    // DECLSPEC_ALLOCATOR HLOCAL LocalReAlloc(
    //   _Frees_ptr_opt_ HLOCAL hMem,
    //   SIZE_T                 uBytes,
    //   UINT                   uFlags
    // );
    WinsdkApi("LocalReAlloc", WinCc::Stdcall, {
        {"hMem", PVOID_},
        {"uBytes", DWORD_PTR_},
        {"uFlags", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // the inline verbatim (the windows.h LMEM_MODIFY macro preempts the
        // local spelling, so the value rides inline here)
        constexpr std::uint64_t kLmemModify = 0x80;

        const auto h_mem = api_get_int(get_param(params, "hMem"));
        const auto u_bytes = api_get_int(get_param(params, "uBytes"));
        const auto u_flags = api_get_int(get_param(params, "uFlags"));

        if (u_flags & kLmemModify) {
            throw QlErrorNotImplemented("");
        }

        w(ql).heap().free(h_mem);
        return w(ql).heap().alloc(u_bytes);
    };

    // HLOCAL LocalFree(
    //   _Frees_ptr_opt_ HLOCAL hMem
    // );
    WinsdkApi("LocalFree", WinCc::Stdcall, {
        {"hMem", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).heap().free(api_get_int(get_param(params, "hMem")));
        return 0;
    };

    // UINT SetHandleCount handled above (the verbatim passthrough)

    // LPVOID GlobalLock(
    //  HGLOBAL hMem
    // );
    WinsdkApi("GlobalLock", WinCc::Stdcall, {
        {"hMem", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "hMem"));
    };

    // LPVOID GlobalUnlock(
    //  HGLOBAL hMem
    // );
    WinsdkApi("GlobalUnlock", WinCc::Stdcall, {
        {"hMem", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
    //  UINT   uFlags,
    //  SIZE_T dwBytes
    // );
    WinsdkApi("GlobalAlloc", WinCc::Stdcall, {
        {"uFlags", UINT_},
        {"dwBytes", DWORD_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_bytes = api_get_int(get_param(params, "dwBytes"));
        return w(ql).heap().alloc(dw_bytes);
    };

    // HGLOBAL GlobalFree(
    //   _Frees_ptr_opt_ HGLOBAL hMem
    // );
    WinsdkApi("GlobalFree", WinCc::Stdcall, {
        {"hMem", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).heap().free(api_get_int(get_param(params, "hMem")));
        return 0;
    };

    // HGLOBAL GlobalHandle(
    //   LPCVOID pMem
    // );
    WinsdkApi("GlobalHandle", WinCc::Stdcall, {
        {"pMem", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "pMem"));
    };

    // LPSTR lstrcpynA(
    //   LPSTR  lpString1,
    //   LPCSTR lpString2,
    //   int    iMaxLength
    // );
    WinsdkApi("lstrcpynA", WinCc::Stdcall, {
        {"lpString1", LPSTR_},
        {"lpString2", LPCSTR_},
        {"iMaxLength", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Copy String2 into String for max iMaxLength chars  (verbatim)
        const auto dst = api_get_int(get_param(params, "lpString1"));
        auto src = api_get_string(ql, get_param(params, "lpString2"));
        const auto max_length = api_get_int(get_param(params, "iMaxLength"));

        if (static_cast<std::int64_t>(src.size()) > max_length) {
            src.resize(static_cast<std::size_t>(max_length));
        }

        ql.mem().write(dst, std::vector<std::uint8_t>(src.begin(), src.end()));

        return dst;
    };

    // LPSTR lstrcpynW(
    //   LPWSTR  lpString1,
    //   LPCWSTR lpString2,
    //   int     iMaxLength
    // );
    WinsdkApi("lstrcpynW", WinCc::Stdcall, {
        {"lpString1", LPWSTR_},
        {"lpString2", LPCWSTR_},
        {"iMaxLength", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Copy String2 into String for max iMaxLength chars  (verbatim)
        const auto dst = api_get_int(get_param(params, "lpString1"));
        auto src = api_get_string(ql, get_param(params, "lpString2"));
        const auto max_length = api_get_int(get_param(params, "iMaxLength"));

        if (static_cast<std::int64_t>(src.size()) > max_length) {
            src.resize(static_cast<std::size_t>(max_length));
        }

        ql.mem().write(dst, std::vector<std::uint8_t>(src.begin(), src.end()));

        return dst;
    };

    // LPSTR lstrcpyA(
    //   LPSTR  lpString1,
    //   LPCSTR lpString2,
    // );
    WinsdkApi("lstrcpyA", WinCc::Stdcall, {
        {"lpString1", LPSTR_},
        {"lpString2", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Copy String2 into String  (verbatim)
        const auto dst = api_get_int(get_param(params, "lpString1"));
        const auto src = api_get_string(ql, get_param(params, "lpString2"));

        ql.mem().write(dst, std::vector<std::uint8_t>(src.begin(), src.end()));

        return dst;
    };

    // LPSTR lstrcpyW(
    //   LPWSTR  lpString1,
    //   LPCWSTR lpString2,
    // );
    WinsdkApi("lstrcpyW", WinCc::Stdcall, {
        {"lpString1", LPWSTR_},
        {"lpString2", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Copy String2 into String  (verbatim)
        const auto dst = api_get_int(get_param(params, "lpString1"));
        const auto src = api_get_string(ql, get_param(params, "lpString2"));

        ql.mem().write(dst, std::vector<std::uint8_t>(src.begin(), src.end()));

        return dst;
    };

    // LPSTR lstrcatA(
    //   LPSTR  lpString1,
    //   LPCSTR lpString2
    // );
    WinsdkApi("lstrcatA", WinCc::Stdcall, {
        {"lpString1", LPSTR_},
        {"lpString2", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Copy String2 into String  (verbatim)
        const auto dst = api_get_int(get_param(params, "lpString1"));
        const auto src = api_get_string(ql, get_param(params, "lpString2"));

        // string_base = ql.os.utils.read_cstring(dst) — the base rides the
        // MEMORY read at the dst (the LPSTR param stays raw), verbatim
        const auto string_base = QlOsUtils::read_cstring(ql, dst);

        const std::string result = string_base + src + std::string(1, char(0));
        ql.mem().write(dst, std::vector<std::uint8_t>(result.begin(), result.end()));

        return dst;
    };

    // LPSTR lstrcatW(
    //   LPWSTR  lpString1,
    //   LPCWSTR lpString2
    // );
    WinsdkApi("lstrcatW", WinCc::Stdcall, {
        {"lpString1", LPWSTR_},
        {"lpString2", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // Copy String2 into String  (verbatim)
        const auto dst = api_get_int(get_param(params, "lpString1"));
        const auto src = api_get_string(ql, get_param(params, "lpString2"));

        // string_base = ql.os.utils.read_wstring(dst) — the utf-16le memory
        // read (verbatim); the result re-encodes utf-16le
        const auto string_base = QlOsUtils::read_wstring(ql, dst);

        const std::string result = string_base + src + std::string(1, char(0));
        std::string encoded;
        encoded.reserve(result.size() * 2);
        for (const char c : result) {
            encoded.push_back(c);
            encoded.push_back('\0');
        }
        ql.mem().write(dst, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));

        return dst;
    };

    // the shared __lstrlen body (the empty string rides the 0)
    // int lstrlenA(LPCSTR lpString);
    WinsdkApi("lstrlenA", WinCc::Stdcall, {
        {"lpString", LPCSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = get_param(params, "lpString");
        const auto& str = std::get<std::string>(s.second);
        return str.empty() ? 0 : str.size();
    };

    // int lstrlenW(
    //   LPCWSTR lpString
    // );
    WinsdkApi("lstrlenW", WinCc::Stdcall, {
        {"lpString", LPCWSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = get_param(params, "lpString");
        const auto& str = std::get<std::string>(s.second);
        return str.empty() ? 0 : str.size();
    };

    // the shared __lstrcmp/__lstrcmpi bodies (the verbatim cmp walk; the
    // case-insensitive pair lowercases both sides)
    const auto lstrcmp_body = [](const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s1 = get_param(params, "lpString1");
        const auto s2 = get_param(params, "lpString2");
        const auto& str1 = std::get<std::string>(s1.second);
        const auto& str2 = std::get<std::string>(s2.second);
        return static_cast<std::uint64_t>((str1 > str2) - (str1 < str2));
    };
    const auto lstrcmpi_body = [](const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto str1 = std::get<std::string>(get_param(params, "lpString1").second);
        auto str2 = std::get<std::string>(get_param(params, "lpString2").second);
        std::transform(str1.begin(), str1.end(), str1.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(str2.begin(), str2.end(), str2.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return static_cast<std::uint64_t>((str1 > str2) - (str1 < str2));
    };
    // the KernelApi handler slot takes the full 3-arg shape; the helpers
    // keep the params-only body and ride through the adapter lambdas
    const auto lstrcmp_handler = [lstrcmp_body](Qiling&, std::uint64_t, const ResolvedParams& p) {
        return lstrcmp_body(p);
    };
    const auto lstrcmpi_handler = [lstrcmpi_body](Qiling&, std::uint64_t, const ResolvedParams& p) {
        return lstrcmpi_body(p);
    };

    // int lstrcmpiW(
    //   LPCWSTR lpString1,
    //   LPCWSTR lpString2
    // );
    WinsdkApi("lstrcmpiW", WinCc::Stdcall, {
        {"lpString1", LPCWSTR_},
        {"lpString2", LPCWSTR_},
    }) = lstrcmpi_handler;

    // int lstrcmpiA(
    //   LPCSTR lpString1,
    //   LPCSTR lpString2
    // );
    WinsdkApi("lstrcmpiA", WinCc::Stdcall, {
        {"lpString1", LPCSTR_},
        {"lpString2", LPCSTR_},
    }) = lstrcmpi_handler;

    // int lstrcmpW(
    //   LPCWSTR lpString1,
    //   LPCWSTR lpString2
    // );
    WinsdkApi("lstrcmpW", WinCc::Stdcall, {
        {"lpString1", LPCWSTR_},
        {"lpString2", LPCWSTR_},
    }) = lstrcmp_handler;

    // int lstrcmpA(
    //   LPCSTR lpString1,
    //   LPCSTR lpString2
    // );
    WinsdkApi("lstrcmpA", WinCc::Stdcall, {
        {"lpString1", LPCSTR_},
        {"lpString2", LPCSTR_},
    }) = lstrcmp_handler;

    // ---- sub-slice 3: VerifyVersionInfo, the name queries, the profile ini ----

    // BOOL VerifyVersionInfoW(
    //   LPOSVERSIONINFOEXW lpVersionInformation,
    //   DWORD              dwTypeMask,
    //   DWORDLONG          dwlConditionMask
    // );
    WinsdkApi("VerifyVersionInfoW", WinCc::Stdcall, {
        {"lpVersionInformation", PVOID_},
        {"dwTypeMask", DWORD_},
        {"dwlConditionMask", DWORDLONG_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return verify_version_info_body(ql, params, true);
    };

    // BOOL VerifyVersionInfoA(
    //   LPOSVERSIONINFOEXA lpVersionInformation,
    //   DWORD              dwTypeMask,
    //   DWORDLONG          dwlConditionMask
    // );
    WinsdkApi("VerifyVersionInfoA", WinCc::Stdcall, {
        {"lpVersionInformation", PVOID_},
        {"dwTypeMask", DWORD_},
        {"dwlConditionMask", DWORDLONG_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return verify_version_info_body(ql, params, false);
    };

    // BOOL GetUserNameW(
    //   LPWSTR  lpBuffer,
    //   LPDWORD pcbBuffer
    // );
    WinsdkApi("GetUserNameW", WinCc::Stdcall, {
        {"lpBuffer", LPWSTR_},
        {"pcbBuffer", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_user_name_body(ql, params, true);
    };

    // BOOL GetUserNameA(
    //   LPCSTR  lpBuffer,
    //   LPDWORD pcbBuffer
    // );
    WinsdkApi("GetUserNameA", WinCc::Stdcall, {
        {"lpBuffer", LPSTR_},
        {"pcbBuffer", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_user_name_body(ql, params, false);
    };

    // BOOL GetComputerNameW(
    //   LPWSTR  lpBuffer,
    //   LPDWORD nSize
    // );
    WinsdkApi("GetComputerNameW", WinCc::Stdcall, {
        {"lpBuffer", LPWSTR_},
        {"nSize", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_computer_name_body(ql, params, true);
    };

    // BOOL GetComputerNameA(
    //   LPCSTR  lpBuffer,
    //   LPDWORD nSize
    // );
    WinsdkApi("GetComputerNameA", WinCc::Stdcall, {
        {"lpBuffer", LPSTR_},
        {"nSize", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_computer_name_body(ql, params, false);
    };

    // DWORD GetPrivateProfileStringA(
    //   LPCSTR lpAppName,
    //   LPCSTR lpKeyName,
    //   LPCSTR lpDefault,
    //   LPSTR  lpReturnedString,
    //   DWORD  nSize,
    //   LPCSTR lpFileName
    // );
    WinsdkApi("GetPrivateProfileStringA", WinCc::Stdcall, {
        {"lpAppName", LPCSTR_},
        {"lpKeyName", LPCSTR_},
        {"lpDefault", LPCSTR_},
        {"lpReturnedString", LPSTR_},
        {"nSize", DWORD_},
        {"lpFileName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto app_name = api_get_string(ql, get_param(params, "lpAppName"));
        const auto key_name = api_get_string(ql, get_param(params, "lpKeyName"));
        const auto default_value = api_get_string(ql, get_param(params, "lpDefault"));
        const auto returned = api_get_int(get_param(params, "lpReturnedString"));
        const auto n_size = api_get_int(get_param(params, "nSize"));
        const auto file_name = api_get_string(ql, get_param(params, "lpFileName"));

        IniConfig config;
        try {
            // TODO: this doesn't seem to be safe  (verbatim — the raw host
            // open, no fs_mapper ride)
            if (!config.read(file_name)) {
                // the python open() FileNotFoundError rides the except arm
                w(ql).set_last_error(ERROR_OLD_WIN_VERSION);
                return 0;
            }
        } catch (const QlErrorBase&) {
            // the parse errors propagate in the python (outside the try);
            // the port's IniConfig raises the QlErrorBase from read() — the
            // unhandled barrier matches
            throw;
        }

        std::string value;
        if (config.has_section(app_name) && config.has_option(app_name, key_name)) {
            value = config.get(app_name, key_name).value();
        } else {
            value = default_value;
        }

        const auto write_len = static_cast<std::int64_t>(value.size()) < n_size - 1
            ? value.size()
            : static_cast<std::size_t>(n_size > 0 ? n_size - 1 : 0);

        std::string out = value.substr(0, write_len);
        out.push_back('\0');
        ql.mem().write(returned, std::vector<std::uint8_t>(out.begin(), out.end()));

        return write_len;
    };

    // BOOL WritePrivateProfileStringA(
    //   LPCSTR lpAppName,
    //   LPCSTR lpKeyName,
    //   LPCSTR lpString,
    //   LPCSTR lpFileName
    // );
    WinsdkApi("WritePrivateProfileStringA", WinCc::Stdcall, {
        {"lpAppName", LPCSTR_},
        {"lpKeyName", LPCSTR_},
        {"lpString", LPCSTR_},
        {"lpFileName", LPCSTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // the verbatim pass
        return std::nullopt;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kWinbaseRegistered = [] {
    register_winbase_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
