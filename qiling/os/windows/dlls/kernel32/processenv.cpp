// Ported from qiling/os/windows/dlls/kernel32/processenv.py — the process
// environment family (GetStdHandle, the GetCommandLine pair, the environment
// block getters, ExpandEnvironmentStringsW, and the flat-0 variable
// getters). The @winsdkapi decorators map onto register_processenv_family();
// the bodies ride the verbatim upstream walks (the double-NUL GetCommandLineA
// quirk and the bytes-vs-TCHAR nSize compare included). The family
// self-registers at static-init and can be re-seeded after
// ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

}  // namespace

void register_processenv_family() {
    using namespace qiling::os::api;

    // HANDLE WINAPI GetStdHandle(
    //   _In_ DWORD nStdHandle
    // );
    WinsdkApi("GetStdHandle", WinCc::Stdcall, {
        {"nStdHandle", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // the verbatim passthrough: the pseudo-handle rides back untouched
        return api_get_int(get_param(params, "nStdHandle"));
    };

    // LPSTR GetCommandLineA(
    // );
    WinsdkApi("GetCommandLineA", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // the verbatim quirk: the loader cmdline already carries its trailing
        // NUL and the upstream appends a second one
        const auto& cmdline = static_cast<loader::QlLoaderPE&>(ql.loader()).cmdline();
        const std::size_t len = cmdline.size() + 1;
        const auto addr = w(ql).heap().alloc(len);

        std::vector<std::uint8_t> buf(cmdline.begin(), cmdline.end());
        buf.push_back('\0');
        ql.mem().write(addr, buf);

        return addr;
    };

    // LPSTR GetCommandLineW(
    // );
    WinsdkApi("GetCommandLineW", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // cmdline.decode('ascii').encode('utf-16le') — the already-NUL
        // terminated cmdline re-encoded wide (the utf-16le NUL terminator
        // inside the buffer; no extra append)
        const auto& cmdline = static_cast<loader::QlLoaderPE&>(ql.loader()).cmdline();
        std::string ascii(cmdline.begin(), cmdline.end());
        std::string wide;
        wide.reserve(ascii.size() * 2);
        for (const char c : ascii) {
            wide.push_back(c);
            wide.push_back('\0');
        }
        const auto addr = w(ql).heap().alloc(wide.size());
        ql.mem().write(addr, std::vector<std::uint8_t>(wide.begin(), wide.end()));

        return addr;
    };

    // LPWCH GetEnvironmentStrings(
    // );
    WinsdkApi("GetEnvironmentStrings", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // envstr = b"\x00" (verbatim: the empty block is a single NUL)
        const auto addr = w(ql).heap().alloc(1);
        ql.mem().write(addr, std::vector<std::uint8_t>{0});
        return addr;
    };

    // LPWCH GetEnvironmentStringsW(
    // );
    WinsdkApi("GetEnvironmentStringsW", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // envstr = b"\x00\x00" (verbatim: the wide empty block is two NULs)
        const auto addr = w(ql).heap().alloc(2);
        ql.mem().write(addr, std::vector<std::uint8_t>{0, 0});
        return addr;
    };

    // BOOL FreeEnvironmentStringsW(
    //   LPWCH penv
    // );
    WinsdkApi("FreeEnvironmentStringsW", WinCc::Stdcall, {
        {"penv", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // DWORD ExpandEnvironmentStringsW(
    //   LPCWSTR lpSrc,
    //   LPWSTR  lpDst,
    //   DWORD   nSize
    // );
    WinsdkApi("ExpandEnvironmentStringsW", WinCc::Stdcall, {
        {"lpSrc", LPCWSTR_},
        {"lpDst", LPWSTR_},
        {"nSize", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto src = api_get_string(ql, get_param(params, "lpSrc"));
        const auto dst = api_get_int(get_param(params, "lpDst"));
        const auto size = api_get_int(get_param(params, "nSize"));

        // the verbatim marker walk: lmarker/rmarker ride the '%' positions,
        // the keys resolve through the profile PATH section, the unknown keys
        // keep their %KEY% spelling
        std::string work = src;
        std::size_t pos = 0;
        while (pos < work.size()) {
            const auto lmarker = work.find('%', pos);
            // the verbatim quirk: an absent lmarker searches the rmarker
            // from 0 (lmarker + 1 == 0)
            const auto rmarker = work.find('%', lmarker == std::string::npos ? 0 : lmarker + 1);

            if (lmarker == std::string::npos || rmarker == std::string::npos) {
                break;
            }

            const auto key = work.substr(lmarker + 1, rmarker - lmarker - 1);
            const auto val = ql.profile().get("PATH", key);
            std::string repl = val.value_or("%" + key + "%");
            if (val.has_value()) {
                // src.replace(f'%{key}%', val, 1) — the FIRST occurrence,
                // wherever it sits relative to lmarker (verbatim)
                const std::string needle = "%" + key + "%";
                const auto at = work.find(needle);
                if (at != std::string::npos) {
                    work.replace(at, needle.size(), repl);
                }
            }

            // pos = rmarker + len(val) — the pre-replacement rmarker plus the
            // replacement length (the stale-index verbatim walk)
            pos = rmarker + repl.size();
        }

        // result = (src + '\x00').encode('utf-16le')
        std::string encoded;
        encoded.reserve((work.size() + 1) * 2);
        for (const char c : work) {
            encoded.push_back(c);
            encoded.push_back('\0');
        }
        encoded.push_back('\0');
        encoded.push_back('\0');

        // the verbatim compare: the nSize rides as BYTES here (the Win32
        // semantic is TCHARs; the upstream quirk is preserved)
        if (encoded.size() <= static_cast<std::size_t>(size)) {
            ql.mem().write(dst, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));
        }

        return encoded.size();
    };

    // DWORD GetEnvironmentVariableA(
    //   LPCSTR lpName,
    //   LPSTR  lpBuffer,
    //   DWORD  nSize
    // );
    WinsdkApi("GetEnvironmentVariableA", WinCc::Stdcall, {
        {"lpName", LPCSTR_},
        {"lpBuffer", LPSTR_},
        {"nSize", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // DWORD GetEnvironmentVariableW(
    //   LPCWSTR lpName,
    //   LPWSTR  lpBuffer,
    //   DWORD   nSize
    // );
    WinsdkApi("GetEnvironmentVariableW", WinCc::Stdcall, {
        {"lpName", LPCWSTR_},
        {"lpBuffer", LPWSTR_},
        {"nSize", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kProcessenvRegistered = [] {
    register_processenv_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
