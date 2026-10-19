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
#include <string>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
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
        const auto n = ::_read(static_cast<int>(fileno), buf.data(), static_cast<unsigned>(u_bytes));
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

        return static_cast<std::uint64_t>(::_lseek(static_cast<int>(fileno), static_cast<long>(offset), origin));
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
        const auto n = ::_write(static_cast<int>(fileno), wbuf.data(), static_cast<unsigned>(u_bytes));
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
