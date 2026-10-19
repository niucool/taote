// Ported from qiling/os/windows/dlls/kernel32/stringapiset.py — the string
// conversion family (GetStringType*, WideCharToMultiByte,
// MultiByteToWideChar, the CompareString pair). The @winsdkapi decorators
// map onto register_stringapiset_family(); the bodies ride the verbatim
// upstream walks. The python-codec layer (str.encode/decode over the
// codepage names) maps onto the in-TU codec helpers below: the internal
// text form is the codepoint sequence (the python str analogue), the
// utf-16le/ascii/utf-8/mbcs codecs are implemented directly, and the
// unsupported codecs fall back to cp1252 through the verbatim availability
// probe. The family self-registers at static-init and can be re-seeded
// after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// ---- the codec helpers (the python str/bytes codec surface) ----
// the internal text form = the codepoint sequence (the python str analogue)

constexpr std::uint32_t kCp1252Error = 0x110000;  // the sentinel: unmappable

// the cp1252 special-cases (the 0x80-0x9F band; the undefined slots keep
// the C1 identity per the python cp1252 codec)
std::uint32_t cp1252_decode_byte(std::uint8_t b) {
    static const std::uint32_t kSpecial[32] = {
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
        0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
        0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
        0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
    };
    if (b >= 0x80 && b <= 0x9F) {
        return kSpecial[b - 0x80];
    }
    return b;
}

std::uint32_t cp1252_encode_cp(std::uint32_t cp) {
    for (std::uint32_t b = 0x80; b <= 0x9F; ++b) {
        if (cp1252_decode_byte(static_cast<std::uint8_t>(b)) == cp) {
            return b;
        }
    }
    if (cp <= 0x7F || (cp >= 0xA0 && cp <= 0xFF)) {
        return cp;
    }
    return kCp1252Error;
}

// the utf-16le pair walk (the surrogate pairs; the decode never fails)
std::u32string decode_utf16le(const std::uint8_t* data, std::size_t len) {
    std::u32string out;
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        std::uint32_t u = static_cast<std::uint16_t>(data[i] | (data[i + 1] << 8));
        if (u >= 0xD800 && u <= 0xDBFF && i + 3 < len) {
            const std::uint32_t lo = static_cast<std::uint16_t>(data[i + 2] | (data[i + 3] << 8));
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                out.push_back(0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
                i += 2;
                continue;
            }
        }
        out.push_back(u);
    }
    return out;
}

std::string encode_utf16le(const std::u32string& cps) {
    std::string out;
    for (const std::uint32_t cp : cps) {
        if (cp >= 0x10000) {
            const auto v = static_cast<std::uint32_t>(cp - 0x10000);
            const auto hi = static_cast<std::uint16_t>(0xD800 + (v >> 10));
            const auto lo = static_cast<std::uint16_t>(0xDC00 + (v & 0x3FF));
            out.push_back(static_cast<char>(hi & 0xFF));
            out.push_back(static_cast<char>(hi >> 8));
            out.push_back(static_cast<char>(lo & 0xFF));
            out.push_back(static_cast<char>(lo >> 8));
        } else {
            out.push_back(static_cast<char>(cp & 0xFF));
            out.push_back(static_cast<char>(cp >> 8));
        }
    }
    return out;
}

// the utf-8 encode/decode
std::string encode_utf8(const std::u32string& cps) {
    std::string out;
    for (const std::uint32_t cp : cps) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

// the strict decode: throws on the invalid input (the python strict
// UnicodeDecodeError propagates through the handler barrier verbatim)
std::u32string decode_utf8(const std::uint8_t* data, std::size_t len) {
    std::u32string out;
    for (std::size_t i = 0; i < len;) {
        const auto b = data[i];
        std::uint32_t cp = 0;
        std::size_t cont = 0;
        if (b < 0x80) {
            cp = b;
            cont = 0;
        } else if ((b & 0xE0) == 0xC0) {
            cp = b & 0x1F;
            cont = 1;
        } else if ((b & 0xF0) == 0xE0) {
            cp = b & 0x0F;
            cont = 2;
        } else if ((b & 0xF8) == 0xF0) {
            cp = b & 0x07;
            cont = 3;
        } else {
            throw QlErrorBase("invalid utf-8 byte");
        }
        if (i + cont > len - 1) {
            throw QlErrorBase("truncated utf-8 sequence");
        }
        for (std::size_t k = 1; k <= cont; ++k) {
            if ((data[i + k] & 0xC0) != 0x80) {
                throw QlErrorBase("invalid utf-8 continuation");
            }
            cp = (cp << 6) | (data[i + k] & 0x3F);
        }
        i += cont + 1;
        out.push_back(cp);
    }
    return out;
}

// the codec dispatch (the __encoding_name availability probe verbatim)
bool codec_supported(const std::string& encname) {
    return encname == "mbcs" || encname == "utf-16" || encname == "utf-16be" ||
           encname == "ascii" || encname == "utf-8" || encname == "cp1252";
}

std::string encoding_name(std::uint64_t codepage) {
    // the mapping of special codepage values to encodings  (verbatim)
    std::string encname;
    switch (codepage) {
    case 0:      // CP_ACP
    case 3:      // CP_THREAD_ACP
        encname = "mbcs";
        break;
    case 1:      // CP_OEMCP
        encname = "oem";
        break;
    case 1200:   // CP_UTF16
        encname = "utf-16";
        break;
    case 1201:   // CP_UTF16BE
        encname = "utf-16be";
        break;
    case 20127:  // CP_ASCII
        encname = "ascii";
        break;
    case 65000:  // CP_UTF7
        encname = "utf-7";
        break;
    case 65001:  // CP_UTF8
        encname = "utf-8";
        break;
    default:
        encname = "cp" + std::to_string(codepage);
        break;
    }

    // the encoding might break on the hosting system; test it and
    // fallback to windows-1252 ('western') if it fails  (verbatim probe)
    // the port's codec surface: the oem/utf-7/other-cpNNN codecs are not
    // implemented, so they fall back to the cp1252 (the documented
    // deviation from the python codec surface)
    return codec_supported(encname) ? encname : "cp1252";
}

// the decode: the bytes -> the codepoints (the strict — the M2W decode
// carries no errors arg upstream)
std::u32string decode_bytes(const std::string& encname, const std::uint8_t* data, std::size_t len) {
    if (encname == "mbcs" || encname == "cp1252") {
        std::u32string out;
        for (std::size_t i = 0; i < len; ++i) {
            out.push_back(cp1252_decode_byte(data[i]));
        }
        return out;
    }
    if (encname == "ascii") {
        std::u32string out;
        for (std::size_t i = 0; i < len; ++i) {
            if (data[i] > 0x7F) {
                throw QlErrorBase("'ascii' codec can't decode byte");
            }
            out.push_back(data[i]);
        }
        return out;
    }
    if (encname == "utf-8") {
        return decode_utf8(data, len);
    }
    if (encname == "utf-16" || encname == "utf-16be") {
        // the utf-16 rides the BOM (the LE default); the utf-16be is the
        // fixed big-endian
        bool be = encname == "utf-16be";
        std::size_t off = 0;
        if (encname == "utf-16" && len >= 2) {
            if (data[0] == 0xFF && data[1] == 0xFE) {
                off = 2;  // the LE BOM
            } else if (data[0] == 0xFE && data[1] == 0xFF) {
                be = true;
                off = 2;  // the BE BOM
            }
        }
        std::u32string out;
        for (std::size_t i = off; i + 1 < len; i += 2) {
            const std::uint32_t u = be
                ? static_cast<std::uint32_t>((data[i] << 8) | data[i + 1])
                : static_cast<std::uint32_t>(data[i] | (data[i + 1] << 8));
            out.push_back(u);
        }
        return out;
    }
    throw QlErrorBase("unknown codec: " + encname);
}

// the encode: the codepoints -> the bytes (the errors: the strict throws,
// the replace rides the '?' substitution per the python byte-codec)
std::string encode_bytes(const std::string& encname, const std::u32string& cps, bool strict) {
    if (encname == "mbcs" || encname == "cp1252") {
        std::string out;
        for (const std::uint32_t cp : cps) {
            const auto b = cp1252_encode_cp(cp);
            if (b == kCp1252Error) {
                if (strict) {
                    throw QlErrorBase("'mbcs' codec can't encode character");
                }
                out.push_back('?');
            } else {
                out.push_back(static_cast<char>(b));
            }
        }
        return out;
    }
    if (encname == "ascii") {
        std::string out;
        for (const std::uint32_t cp : cps) {
            if (cp > 0x7F) {
                if (strict) {
                    throw QlErrorBase("'ascii' codec can't encode character");
                }
                out.push_back('?');
            } else {
                out.push_back(static_cast<char>(cp));
            }
        }
        return out;
    }
    if (encname == "utf-8") {
        return encode_utf8(cps);
    }
    if (encname == "utf-16") {
        // the python 'utf-16' encode rides the BOM + the LE pairs
        std::string le = encode_utf16le(cps);
        std::string out;
        out.push_back('\xFF');
        out.push_back('\xFE');
        out += le;
        return out;
    }
    if (encname == "utf-16be") {
        std::string out;
        for (const std::uint32_t cp : cps) {
            if (cp >= 0x10000) {
                const auto v = static_cast<std::uint32_t>(cp - 0x10000);
                const auto hi = static_cast<std::uint16_t>(0xD800 + (v >> 10));
                const auto lo = static_cast<std::uint16_t>(0xDC00 + (v & 0x3FF));
                out.push_back(static_cast<char>(hi >> 8));
                out.push_back(static_cast<char>(hi & 0xFF));
                out.push_back(static_cast<char>(lo >> 8));
                out.push_back(static_cast<char>(lo & 0xFF));
            } else {
                out.push_back(static_cast<char>(cp >> 8));
                out.push_back(static_cast<char>(cp & 0xFF));
            }
        }
        return out;
    }
    throw QlErrorBase("unknown codec: " + encname);
}

// the python str/bytes ordering over the codepoint sequences
// (the windows/utils.py cmp: (a > b) - (a < b))
int cmp_str(const std::u32string& a, const std::u32string& b) {
    if (a > b) {
        return 1;
    }
    if (a < b) {
        return -1;
    }
    return 0;
}

// the shared __CompareString body
std::optional<std::uint64_t> compare_string_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto lp_string1 = api_get_string(ql, get_param(params, "lpString1"));
    const auto lp_string2 = api_get_string(ql, get_param(params, "lpString2"));
    const auto cch_count1 = api_get_int(get_param(params, "cchCount1"));
    const auto cch_count2 = api_get_int(get_param(params, "cchCount2"));

    // the resolved strings ride the resolver output (the A = the raw cstring
    // bytes, the W = the utf-8 text); both normalize to the codepoints, then
    // the cchCount slices keep the count semantics
    std::u32string s1;
    std::u32string s2;
    if (wide) {
        const auto w1 = decode_utf8(reinterpret_cast<const std::uint8_t*>(lp_string1.data()), lp_string1.size());
        const auto w2 = decode_utf8(reinterpret_cast<const std::uint8_t*>(lp_string2.data()), lp_string2.size());
        s1 = (cch_count1 > 0) ? w1.substr(0, static_cast<std::size_t>(cch_count1)) : w1;
        s2 = (cch_count2 > 0) ? w2.substr(0, static_cast<std::size_t>(cch_count2)) : w2;
    } else {
        for (const auto c : lp_string1) {
            s1.push_back(static_cast<std::uint8_t>(c));
        }
        for (const auto c : lp_string2) {
            s2.push_back(static_cast<std::uint8_t>(c));
        }
        if (cch_count1 > 0 && static_cast<std::size_t>(cch_count1) < s1.size()) {
            s1.resize(static_cast<std::size_t>(cch_count1));
        }
        if (cch_count2 > 0 && static_cast<std::size_t>(cch_count2) < s2.size()) {
            s2.resize(static_cast<std::size_t>(cch_count2));
        }
    }
    return cmp_str(s1, s2);
}

}  // namespace

void register_stringapiset_family() {
    using namespace qiling::os::api;

    // BOOL GetStringTypeW(
    //   DWORD                         dwInfoType,
    //   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
    //   int                           cchSrc,
    //   LPWORD                        lpCharType
    // );
    WinsdkApi("GetStringTypeW", WinCc::Stdcall, {
        {"dwInfoType", DWORD_},
        {"lpSrcStr", PVOID_},
        {"cchSrc", INT_},
        {"lpCharType", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO: implement  (verbatim)
        return 1;
    };

    //  BOOL GetStringTypeExA
    //  (
    //   LCID   locale,
    //   DWORD  type,
    //   LPCSTR src,
    //   INT    count,
    //   LPWORD chartype
    //  )
    WinsdkApi("GetStringTypeExA", WinCc::Stdcall, {
        {"Locale", LCID_},
        {"dwInfoType", DWORD_},
        {"lpSrcStr", LPCSTR_},
        {"cchSrc", INT_},
        {"lpCharType", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO: implement  (verbatim)
        return 1;
    };

    // int WideCharToMultiByte(
    //   UINT                               CodePage,
    //   DWORD                              dwFlags,
    //   _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
    //   int                                cchWideChar,
    //   LPSTR                              lpMultiByteStr,
    //   int                                cbMultiByte,
    //   LPCCH                              lpDefaultChar,
    //   LPBOOL                             lpUsedDefaultChar
    // );
    WinsdkApi("WideCharToMultiByte", WinCc::Stdcall, {
        {"CodePage", UINT_},
        {"dwFlags", DWORD_},
        {"lpWideCharStr", PVOID_},
        {"cchWideChar", INT_},
        {"lpMultiByteStr", LPSTR_},
        {"cbMultiByte", INT_},
        {"lpDefaultChar", PVOID_},
        {"lpUsedDefaultChar", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto code_page = api_get_int(get_param(params, "CodePage"));
        const auto dw_flags = api_get_int(get_param(params, "dwFlags"));
        const auto lp_wide_char_str = api_get_int(get_param(params, "lpWideCharStr"));
        const auto cch_wide_char = api_get_int(get_param(params, "cchWideChar"));
        const auto lp_multi_byte_str = api_get_int(get_param(params, "lpMultiByteStr"));
        const auto cb_multi_byte = api_get_int(get_param(params, "cbMultiByte"));

        if (cch_wide_char == 0) {
            // TODO: set last error  (verbatim)
            return 0;
        }

        std::vector<std::uint8_t> wc_bytes;
        if (cch_wide_char == 0xFFFFFFFFull) {
            // -1 indicates the string is null-terminated. the string is
            // read along with its null-terminator  (verbatim; the INT param
            // rides the raw register value, the sentinel = 0xffffffff)
            auto addr = lp_wide_char_str;
            while (true) {
                const auto ch = ql.mem().read(addr, 2);
                wc_bytes.insert(wc_bytes.end(), ch.begin(), ch.end());
                addr += 2;
                if (ch[0] == 0 && ch[1] == 0) {
                    break;
                }
            }
        } else {
            // read exactly cbMultiByte bytes. that may or may not include
            // a null-terminator  (verbatim)
            wc_bytes = ql.mem().read(lp_wide_char_str, static_cast<std::size_t>(cch_wide_char) * 2);
        }

        const auto decoded = decode_utf16le(wc_bytes.data(), wc_bytes.size());

        const auto encname = encoding_name(code_page);
        const bool strict = (dw_flags & WC_ERR_INVALID_CHARS) != 0;

        try {
            const auto encoded = encode_bytes(encname, decoded, strict);

            if (cb_multi_byte == 0) {
                return encoded.size();
            }

            if (lp_multi_byte_str == 0) {
                return 0;
            }

            const auto n = std::min(encoded.size(), static_cast<std::size_t>(cb_multi_byte));
            ql.mem().write(lp_multi_byte_str, std::vector<std::uint8_t>(encoded.begin(), encoded.begin() + n));

            return std::min<std::uint64_t>(encoded.size(), static_cast<std::uint64_t>(cb_multi_byte));
        } catch (const QlErrorBase&) {
            // the python UnicodeEncodeError walk (verbatim)
            w(ql).set_last_error(ERROR_NO_UNICODE_TRANSLATION);
            return 0;
        }
    };

    // int MultiByteToWideChar(
    //  UINT                              CodePage,
    //  DWORD                             dwFlags,
    //  _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
    //  int                               cbMultiByte,
    //  LPWSTR                            lpWideCharStr,
    //  int                               cchWideChar
    // );
    WinsdkApi("MultiByteToWideChar", WinCc::Stdcall, {
        {"CodePage", UINT_},
        {"dwFlags", DWORD_},
        {"lpMultiByteStr", PVOID_},
        {"cbMultiByte", INT_},
        {"lpWideCharStr", LPWSTR_},
        {"cchWideChar", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto code_page = api_get_int(get_param(params, "CodePage"));
        const auto lp_multi_byte_str = api_get_int(get_param(params, "lpMultiByteStr"));
        const auto cb_multi_byte = api_get_int(get_param(params, "cbMultiByte"));
        const auto lp_wide_char_str = api_get_int(get_param(params, "lpWideCharStr"));
        const auto cch_wide_char = api_get_int(get_param(params, "cchWideChar"));

        if (cb_multi_byte == 0) {
            // TODO: set last error  (verbatim)
            return 0;
        }

        std::vector<std::uint8_t> mb_bytes;
        if (cb_multi_byte == 0xFFFFFFFFull) {
            // -1 indicates the string is null-terminated. the string is
            // read along with its null-terminator  (verbatim; the INT param
            // rides the raw register value, the sentinel = 0xffffffff)
            auto addr = lp_multi_byte_str;
            while (true) {
                const auto ch = ql.mem().read(addr, 1);
                mb_bytes.insert(mb_bytes.end(), ch.begin(), ch.end());
                addr += 1;
                if (ch[0] == 0) {
                    break;
                }
            }
        } else {
            mb_bytes = ql.mem().read(lp_multi_byte_str, static_cast<std::size_t>(cb_multi_byte));
        }

        // use specified code page to translate bytes into string
        const auto encname = encoding_name(code_page);
        // the python decode carries no errors arg (the strict; the invalid
        // input propagates the UnicodeDecodeError through the handler — the
        // QlErrorBase rides the same barrier)
        const auto decoded = decode_bytes(encname, mb_bytes.data(), mb_bytes.size());

        // this is a dry-run; just return the amount of chars
        if (cch_wide_char == 0) {
            return decoded.size();
        }

        if (lp_wide_char_str == 0) {
            return 0;
        }

        auto sliced = decoded;
        if (static_cast<std::size_t>(cch_wide_char) < sliced.size()) {
            sliced.resize(static_cast<std::size_t>(cch_wide_char));
        }
        const auto wide = encode_utf16le(sliced);
        ql.mem().write(lp_wide_char_str, std::vector<std::uint8_t>(wide.begin(), wide.end()));

        return std::min<std::uint64_t>(decoded.size(), static_cast<std::uint64_t>(cch_wide_char));
    };

    // int CompareStringA(
    //   LCID   Locale,
    //   DWORD  dwCmpFlags,
    //   PCNZCH lpString1,
    //   int    cchCount1,
    //   PCNZCH lpString2,
    //   int    cchCount2
    // );
    WinsdkApi("CompareStringA", WinCc::Stdcall, {
        {"Locale", LCID_},
        {"dwCmpFlags", DWORD_},
        {"lpString1", PCNZCH_},
        {"cchCount1", INT_},
        {"lpString2", PCNZCH_},
        {"cchCount2", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return compare_string_body(ql, params, false);
    };

    // int CompareStringW(
    //   LCID   Locale,
    //   DWORD  dwCmpFlags,
    //   PCNZWCH lpString1,
    //   int    cchCount1,
    //   PCNZWCH lpString2,
    //   int    cchCount2
    // );
    WinsdkApi("CompareStringW", WinCc::Stdcall, {
        {"Locale", LCID_},
        {"dwCmpFlags", DWORD_},
        {"lpString1", PCNZWCH_},
        {"cchCount1", INT_},
        {"lpString2", PCNZWCH_},
        {"cchCount2", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return compare_string_body(ql, params, true);
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kStringapisetRegistered = [] {
    register_stringapiset_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
