// Ported from qiling/os/windows/dlls/kernel32/winbase.py — the legacy
// kernel32 surface (the _l file family, the verbatim stubs, the Local/Global
// heap family, the lstr family, the VerifyVersionInfo walk, the name
// queries, and the private-profile pair). Ported in sub-slices; this TU
// carries the full register_winbase_family(). The @winsdkapi decorators map
// onto the WinsdkApi registrations; the bodies ride the verbatim upstream
// walks. The family self-registers at static-init and can be re-seeded
// after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <cstdio>
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
