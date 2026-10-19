// Ported from qiling/os/windows/dlls/oleaut32.py — the BSTR allocation family
// (the upstream module is flagged VERY experimental; the heap walks are
// verbatim, including the odd single-byte-per-BSTR-cell allocations).
#ifndef QILING_OS_WINDOWS_DLLS_OLEAUT32_CPP
#define QILING_OS_WINDOWS_DLLS_OLEAUT32_CPP

#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the utf-16le encode of the (decoded) string: the BMP char pairs (the
// upstream `s.encode("utf-16le")` ride for the latin-1 subset)
std::string to_utf16le(const std::string& s) {
    std::string out;
    out.reserve(s.size() * 2);
    for (const char c : s) {
        out.push_back(c);
        out.push_back('\0');
    }
    return out;
}

void write_utf16le(Qiling& ql, std::uint64_t addr, const std::string& s) {
    const auto bytes = to_utf16le(s);
    ql.mem().write(addr, std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

}  // namespace

void register_oleaut32_family() {
    using namespace qiling::os::api;

    // BSTR SysAllocStringLen(const OLECHAR *strIn, UINT ui);
    WinsdkApi("SysAllocStringLen", WinCc::Stdcall, {
        {"strIn", OLECHAR_},
        {"ui", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto& str_in = api_get_string(ql, get_param(params, "strIn"));
        const auto ui = api_get_int(get_param(params, "ui"));

        const auto addr = w(ql).heap().alloc(ui + 1);

        if (!str_in.empty()) {
            write_utf16le(ql, addr, str_in.substr(0, static_cast<std::size_t>(ui)));
        }

        return addr;
    };

    // void SysFreeString(BSTR bstrString);
    WinsdkApi("SysFreeString", WinCc::Stdcall, {
        {"bstrString", BSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto bstr_string = api_get_int(get_param(params, "bstrString"));

        if (bstr_string != 0) {
            w(ql).heap().free(bstr_string);
        }

        return 0;  // the verbatim no-return ride (the None)
    };

    // UINT SysStringLen(BSTR pbstr);
    WinsdkApi("SysStringLen", WinCc::Stdcall, {
        {"pbstr", BSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // the upstream rides the RESOLVED string (`0 if string == 0` is the
        // py2 quirk — the empty decode answers 0 either way)
        const auto& s = api_get_string(ql, get_param(params, "pbstr"));
        return s.size();
    };

    // INT SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, UINT len);
    WinsdkApi("SysReAllocStringLen", WinCc::Stdcall, {
        {"pbstr", PVOID_},
        {"psz", OLECHAR_},
        {"len", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto& content = api_get_string(ql, get_param(params, "psz"));
        const auto size = api_get_int(get_param(params, "len"));

        const auto addr = w(ql).heap().alloc(size + 1);

        write_utf16le(ql, addr, content.substr(0, static_cast<std::size_t>(size)));
        ql.mem().write_ptr(api_get_int(get_param(params, "pbstr")), addr);

        return 1;
    };

    // BSTR SysAllocString(const OLECHAR *psz);
    WinsdkApi("SysAllocString", WinCc::Stdcall, {
        {"psz", OLECHAR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto& s = api_get_string(ql, get_param(params, "psz"));

        if (s.empty()) {
            return 0;
        }

        const auto addr = w(ql).heap().alloc(s.size() + 1);
        write_utf16le(ql, addr, s);

        return addr;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kOleaut32Registered = [] {
    qiling::os::win::register_oleaut32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_OLEAUT32_CPP
