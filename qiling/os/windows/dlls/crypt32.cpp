// Ported from qiling/os/windows/dlls/crypt32.py — the CryptStringToBinary
// pair (the base64 -> the wide-text decode; the upstream only implements the
// CRYPT_STRING_BASE64 flavour, everything else raises).
#ifndef QILING_OS_WINDOWS_DLLS_CRYPT32_CPP
#define QILING_OS_WINDOWS_DLLS_CRYPT32_CPP

#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the b64 decode table (the python base64.b64decode ride; the port walks the
// standard alphabet, ignoring the '=' pads)
int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

std::string b64_decode(const std::string& src) {
    std::string out;
    int acc = 0;
    int bits = 0;
    for (const char c : src) {
        if (c == '=') {
            break;
        }
        const int v = b64_val(c);
        if (v < 0) {
            continue;  // the upstream b64decode would reject; the port keeps
                       // the tolerant walk (the fixture inputs are clean)
        }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xff));
        }
    }
    return out;
}

// the utf-16le -> utf-8 (the narrow) decode over the decoded bytes — the
// upstream `base64.b64decode(string_src).decode("utf-16le")` ride (the latin-1
// subset renders back the same; the port walks the pairs into the BMP chars)
std::string utf16le_decode(const std::string& bytes) {
    std::string out;
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        const auto cu = static_cast<std::uint16_t>(static_cast<std::uint8_t>(bytes[i]) |
                                                   (static_cast<std::uint8_t>(bytes[i + 1]) << 8));
        if (cu < 0x80) {
            out.push_back(static_cast<char>(cu));
            continue;
        }
        if (cu < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cu >> 6)));
            out.push_back(static_cast<char>(0x80 | (cu & 0x3F)));
            continue;
        }
        out.push_back(static_cast<char>(0xE0 | (cu >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cu >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cu & 0x3F)));
    }
    return out;
}

std::string utf8_to_utf16le_bytes(const std::string& s) {
    // the upstream `bytes(output, encoding="utf-16le")` write-back ride: the
    // BMP pairs (the fixture inputs stay inside the latin-1 subset so the
    // per-char pairs round-trip the decoded text)
    std::vector<std::uint8_t> out;
    std::size_t i = 0;
    while (i < s.size()) {
        std::uint32_t cp = static_cast<std::uint8_t>(s[i]);
        std::size_t len = 1;
        if ((cp & 0xE0) == 0xC0 && i + 1 < s.size()) {
            cp = ((cp & 0x1F) << 6) | (static_cast<std::uint8_t>(s[i + 1]) & 0x3F);
            len = 2;
        } else if ((cp & 0xF0) == 0xE0 && i + 2 < s.size()) {
            cp = ((cp & 0x0F) << 12) | ((static_cast<std::uint8_t>(s[i + 1]) & 0x3F) << 6) |
                 (static_cast<std::uint8_t>(s[i + 2]) & 0x3F);
            len = 3;
        }
        i += len;
        out.push_back(static_cast<std::uint8_t>(cp & 0xff));
        out.push_back(static_cast<std::uint8_t>(cp >> 8));
    }
    return {out.begin(), out.end()};
}

// crypt32.py _CryptStringToBinary
std::uint64_t crypt_string_to_binary_body(Qiling& ql, const ResolvedParams& params) {
    const auto flag_src = api_get_int(get_param(params, "dwFlags"));
    const auto& string_src = api_get_string(ql, get_param(params, "pszString"));
    const auto size_src = api_get_int(get_param(params, "cchString"));
    const auto size_dst_pointer = api_get_int(get_param(params, "pcbBinary"));
    const auto string_dst = api_get_int(get_param(params, "pbBinary"));
    const auto flag_dst = api_get_int(get_param(params, "pdwFlags"));

    const auto size_dst = ql.mem().read_ptr(size_dst_pointer, 4);

    if (size_dst != 0 && size_dst < size_src) {
        throw QlErrorNotImplemented("API not implemented");
    }

    if (flag_src == CRYPT_STRING_BASE64) {
        // Had a padding error, hope this always works  (verbatim)
        std::string padded = string_src;
        const auto add_pad = 4 - (padded.size() % 4);
        if (add_pad != 4) {
            padded.append(static_cast<std::size_t>(add_pad), '=');
        }
        auto output = utf16le_decode(b64_decode(padded));
        output += '\0';

        if (string_dst == 0) {
            // Only wants the length
            return output.size();
        }
        if (flag_dst != 0) {
            // Is optional
            ql.mem().write_ptr(flag_dst, flag_src, 4);
        }

        // Write size
        ql.mem().write_ptr(size_dst_pointer, output.size(), 4);

        // Write result (the utf-16le encode of the decoded text — the
        // upstream `bytes(output, encoding="utf-16le")` ride)
        const auto wide_out = utf8_to_utf16le_bytes(output);
        ql.mem().write(string_dst, std::vector<std::uint8_t>(wide_out.begin(), wide_out.end()));
        return 1;
    }

    throw QlErrorNotImplemented("API not implemented");
}

}  // namespace

void register_crypt32_family() {
    using namespace qiling::os::api;

    // BOOL CryptStringToBinaryA(LPCSTR pszString, DWORD cchString,
    //     DWORD dwFlags, BYTE *pbBinary, DWORD *pcbBinary, DWORD *pdwSkip,
    //     DWORD *pdwFlags);
    WinsdkApi("CryptStringToBinaryA", WinCc::Stdcall, {
        {"pszString", LPCSTR_},
        {"cchString", DWORD_},
        {"dwFlags", DWORD_},
        {"pbBinary", PVOID_},
        {"pcbBinary", PVOID_},
        {"pdwSkip", PVOID_},
        {"pdwFlags", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return crypt_string_to_binary_body(ql, params);
    };

    // BOOL CryptStringToBinaryW(LPCWSTR pszString, ...); — the wide flavour
    WinsdkApi("CryptStringToBinaryW", WinCc::Stdcall, {
        {"pszString", LPCWSTR_},
        {"cchString", DWORD_},
        {"dwFlags", DWORD_},
        {"pbBinary", PVOID_},
        {"pcbBinary", PVOID_},
        {"pdwSkip", PVOID_},
        {"pdwFlags", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return crypt_string_to_binary_body(ql, params);
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kCrypt32Registered = [] {
    qiling::os::win::register_crypt32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_CRYPT32_CPP
