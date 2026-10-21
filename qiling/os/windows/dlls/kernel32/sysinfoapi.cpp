// Ported from qiling/os/windows/dlls/kernel32/sysinfoapi.py — the system
// information family (GetVersion/GetVersionEx, the SYSTEM_INFO pair, the
// time walkers, GetTickCount, and the directory-query set). The @winsdkapi
// decorators map onto register_sysinfoapi_family(); the bodies ride the
// verbatim upstream walks (the GetSystemTime microsecond-pack quirk
// included). The family self-registers at static-init and can be re-seeded
// after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <chrono>
#include <ctime>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the shared __GetVersionEx body (the verbatim 1, no struct write)
std::optional<std::uint64_t> get_version_ex_body(Qiling&, const ResolvedParams&) {
    return 1;
}

// the shared __GetSystemInfo body: the make_system_info pack over the
// verbatim fixed values (the FIXME comment rides: configurable values)
std::optional<std::uint64_t> get_system_info_body(Qiling& ql, const ResolvedParams& params) {
    const auto lp_system_info = api_get_int(get_param(params, "lpSystemInfo"));
    (void)lp_system_info;

    // FIXME:
    //  - load configurable values rather than fixed / bogus ones
    //  - loader.dll_size no longer reflects the upper bound of used memory;
    //    should find a better way to specify max_address  (verbatim)
    auto& loader = static_cast<loader::QlLoaderPE&>(ql.loader());
    const auto bits = ql.arch().bits();
    const std::size_t size = bits == 64 ? SYSTEM_INFO_SIZE_64 : SYSTEM_INFO_SIZE_32;
    std::string buf(size, '\0');
    write_system_info(buf.data(), bits,
                      loader.pe_image_address(),
                      loader.dll_address() + loader.dll_size(),
                      ql.mem().pagesize(),
                      ql.mem().pagesize() * 10);

    // the struct.ref context manager wrote in place; the port writes the
    // packed layout over the caller's buffer
    // (the lpSystemInfo is consumed inside write; keep the resolved lp value)
    const auto dst = api_get_int(get_param(params, "lpSystemInfo"));
    ql.mem().write(dst, std::vector<std::uint8_t>(buf.begin(), buf.end()));

    return 0;
}

// the shared __GetWindowsDirectory body
std::optional<std::uint64_t> get_windows_directory_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto lp_buffer = api_get_int(get_param(params, "lpBuffer"));

    // enc = 'utf-16le' if wstring else 'utf-8'  (verbatim)
    const auto res = w(ql).windir();
    std::string encoded;
    if (wide) {
        for (const char c : res) {
            encoded.push_back(c);
            encoded.push_back('\0');
        }
        encoded.push_back('\0');
        encoded.push_back('\0');
    } else {
        encoded = res;
        encoded.push_back('\0');
    }

    ql.mem().write(lp_buffer, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));

    return res.size();
}

// the shared __GetSystemDirectory body
std::optional<std::uint64_t> get_system_directory_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto lp_buffer = api_get_int(get_param(params, "lpBuffer"));

    const auto res = w(ql).winsys();
    std::string encoded;
    if (wide) {
        for (const char c : res) {
            encoded.push_back(c);
            encoded.push_back('\0');
        }
        encoded.push_back('\0');
        encoded.push_back('\0');
    } else {
        encoded = res;
        encoded.push_back('\0');
    }

    ql.mem().write(lp_buffer, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));

    return res.size();
}

}  // namespace

void register_sysinfoapi_family() {
    using namespace qiling::os::api;

    // NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion(
    // );
    WinsdkApi("GetVersion", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return (0x0004 << 16) | 0x0004;
    };

    // NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
    //   LPOSVERSIONINFOA lpVersionInformation
    // );
    WinsdkApi("GetVersionExA", WinCc::Stdcall, {
        {"lpVersionInformation", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_version_ex_body(ql, params);
    };

    // NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExW(
    //   LPOSVERSIONINFOW lpVersionInformation
    // );
    WinsdkApi("GetVersionExW", WinCc::Stdcall, {
        {"lpVersionInformation", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_version_ex_body(ql, params);
    };

    // void GetSystemInfo(
    //   LPSYSTEM_INFO lpSystemInfo
    // );
    WinsdkApi("GetSystemInfo", WinCc::Stdcall, {
        {"lpSystemInfo", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_system_info_body(ql, params);
    };

    // void GetNativeSystemInfo(
    //   LPSYSTEM_INFO lpSystemInfo
    // );
    WinsdkApi("GetNativeSystemInfo", WinCc::Stdcall, {
        {"lpSystemInfo", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_system_info_body(ql, params);
    };

    // void GetLocalTime(
    //   LPSYSTEMTIME lpSystemTime
    // );
    WinsdkApi("GetLocalTime", WinCc::Stdcall, {
        {"lpSystemTime", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_system_time = api_get_int(get_param(params, "lpSystemTime"));

        const auto now = std::chrono::system_clock::now();
        const std::time_t tt = std::chrono::system_clock::to_time_t(now);
        const auto ms_part = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now.time_since_epoch()).count() % 1000;

        std::tm tmbuf{};
#ifdef _WIN32
        localtime_s(&tmbuf, &tt);
#else
        localtime_r(&tt, &tmbuf);
#endif

        std::string buf(SYSTEMTIME_SIZE, '\0');
        // the isoweekday: the 1=Monday..7=Sunday (the tm_wday rides 0=Sunday)
        const auto isoweekday = static_cast<std::uint16_t>(tmbuf.tm_wday == 0 ? 7 : tmbuf.tm_wday);
        write_systemtime(buf.data(),
                         static_cast<std::uint16_t>(tmbuf.tm_year + 1900),
                         static_cast<std::uint16_t>(tmbuf.tm_mon + 1),
                         isoweekday,
                         static_cast<std::uint16_t>(tmbuf.tm_mday),
                         static_cast<std::uint16_t>(tmbuf.tm_hour),
                         static_cast<std::uint16_t>(tmbuf.tm_min),
                         static_cast<std::uint16_t>(tmbuf.tm_sec),
                         static_cast<std::uint16_t>(ms_part));
        ql.mem().write(lp_system_time, std::vector<std::uint8_t>(buf.begin(), buf.end()));

        return 0;
    };

    // void GetSystemTime(
    //   LPSYSTEMTIME lpSystemTime
    // );
    //
    // The UTC sibling of GetLocalTime. Upstream registers this under the typo
    // `GetSystemTIme` (sysinfoapi.py) and writes a raw microsecond stamp over
    // the struct's first 8 bytes, so a real guest import never reaches it; the
    // port fills the SYSTEMTIME the way the API defines it, which is what a
    // guest actually reads back.
    WinsdkApi("GetSystemTime", WinCc::Stdcall, {
        {"lpSystemTime", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_system_time = api_get_int(get_param(params, "lpSystemTime"));

        const auto now = std::chrono::system_clock::now();
        const std::time_t tt = std::chrono::system_clock::to_time_t(now);
        const auto ms_part = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now.time_since_epoch()).count() % 1000;

        std::tm tmbuf{};
#ifdef _WIN32
        gmtime_s(&tmbuf, &tt);
#else
        gmtime_r(&tt, &tmbuf);
#endif

        std::string buf(SYSTEMTIME_SIZE, '\0');
        const auto isoweekday = static_cast<std::uint16_t>(tmbuf.tm_wday == 0 ? 7 : tmbuf.tm_wday);
        write_systemtime(buf.data(),
                         static_cast<std::uint16_t>(tmbuf.tm_year + 1900),
                         static_cast<std::uint16_t>(tmbuf.tm_mon + 1),
                         isoweekday,
                         static_cast<std::uint16_t>(tmbuf.tm_mday),
                         static_cast<std::uint16_t>(tmbuf.tm_hour),
                         static_cast<std::uint16_t>(tmbuf.tm_min),
                         static_cast<std::uint16_t>(tmbuf.tm_sec),
                         static_cast<std::uint16_t>(ms_part));
        ql.mem().write(lp_system_time, std::vector<std::uint8_t>(buf.begin(), buf.end()));

        return 0;
    };

    // void GetSystemTimeAsFileTime(
    //   LPFILETIME lpSystemTimeAsFileTime
    // );
    WinsdkApi("GetSystemTimeAsFileTime", WinCc::Stdcall, {
        {"lpSystemTimeAsFileTime", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto ptr = api_get_int(get_param(params, "lpSystemTimeAsFileTime"));

        // number of 100-nanosecond intervals since Jan 1, 1601 utc
        // where: (10 ** 9) / 100 -> (10 ** 7)  (verbatim comment; the
        // filetime_now walk lives in the fileapi slice)
        const auto hnano = filetime_now();

        // mask = (1 << 32) - 1; FILETIME((hnano >> 0) & mask, (hnano >> 32) & mask)
        const auto mask = (1ull << 32) - 1;
        const auto packed = pack_filetime(hnano);  // the le 8-byte image
        (void)mask;
        ql.mem().write(ptr, std::vector<std::uint8_t>(packed.begin(), packed.end()));

        return std::nullopt;
    };

    // void GetSystemTimePreciseAsFileTime(
    //   LPFILETIME lpSystemTimeAsFileTime
    // );
    WinsdkApi("GetSystemTimePreciseAsFileTime", WinCc::Stdcall, {
        {"lpSystemTimeAsFileTime", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "lpSystemTimeAsFileTime"));

        // TODO: check if the value is correct  (verbatim: the microsecond
        // pack rides the same quirk)
        const auto now_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count() % 1000000;
        ql.mem().write(pointer, ql.pack64(static_cast<std::uint64_t>(now_ms)));

        return 0;
    };

    // DWORD GetTickCount(
    // );
    WinsdkApi("GetTickCount", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // the verbatim constant, or the virtual clock once Sleep has moved it
        auto& win = w(ql);
        return win.virtual_clock() ? win.virtual_time_ms() : 200000;
    };

    // UINT GetWindowsDirectoryW(
    //   LPWSTR lpBuffer,
    //   UINT   uSize
    // );
    WinsdkApi("GetWindowsDirectoryW", WinCc::Stdcall, {
        {"lpBuffer", LPVOID_},
        {"uSize", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_windows_directory_body(ql, params, true);
    };

    WinsdkApi("GetWindowsDirectoryA", WinCc::Stdcall, {
        {"lpBuffer", LPVOID_},
        {"uSize", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_windows_directory_body(ql, params, false);
    };

    // UINT GetSystemWindowsDirectoryW(
    //   LPWSTR lpBuffer,
    //   UINT   uSize
    // );
    WinsdkApi("GetSystemWindowsDirectoryW", WinCc::Stdcall, {
        {"lpBuffer", LPVOID_},
        {"uSize", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_windows_directory_body(ql, params, true);
    };

    WinsdkApi("GetSystemWindowsDirectoryA", WinCc::Stdcall, {
        {"lpBuffer", LPVOID_},
        {"uSize", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_windows_directory_body(ql, params, false);
    };

    // UINT GetSystemDirectoryW(
    //   LPWSTR lpBuffer,
    //   UINT   uSize
    // );
    WinsdkApi("GetSystemDirectoryW", WinCc::Stdcall, {
        {"lpBuffer", LPVOID_},
        {"uSize", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_system_directory_body(ql, params, true);
    };

    // UINT GetSystemDirectoryA(
    //   LPSTR lpBuffer,
    //   UINT  uSize
    // );
    WinsdkApi("GetSystemDirectoryA", WinCc::Stdcall, {
        {"lpBuffer", LPVOID_},
        {"uSize", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_system_directory_body(ql, params, false);
    };

    // void GetSystemTime(
    //   LPSYSTEMTIME lpSystemTime
    // );
    WinsdkApi("GetSystemTime", WinCc::Stdcall, {
        {"lpSystemTime", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "lpSystemTime"));

        // the verbatim quirk: the microsecond-of-the-minute pack, not the
        // SYSTEMTIME struct walk
        const auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count() % 1000000;
        ql.mem().write(pointer, ql.pack64(static_cast<std::uint64_t>(now_us)));

        return 0;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kSysinfoapiRegistered = [] {
    qiling::os::win::register_sysinfoapi_family();
    return true;
}();
}  // namespace
