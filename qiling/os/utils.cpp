// Ported from qiling/os/utils.py - see the header note. The read_string walk
// steps charlen-sized units until the NUL unit or maxlen; the printf engine
// parses %[flags][width][.precision][size]type and formats inline.
#include "qiling/os/utils.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace os {

std::string QlOsUtils::read_string(Qiling& ql, std::uint64_t address, int charlen, int maxlen) {
    std::string data;
    int strlen = 0;
    // a pointer into the null canary page is never a real guest string; the
    // emulation keeps the first page unmapped and windows would fault it
    // anyway, while a taote-side read would kill the run before the guest
    // ever sees the bad pointer (the argv startup's bogus _Format=1 slot)
    if (address < 0x1000) {
        return data;
    }
    while (true) {
        const auto unit = ql.mem().read(address, static_cast<std::size_t>(charlen));
        bool is_terminator = true;
        for (const auto b : unit) {
            if (b != 0) {
                is_terminator = false;
                break;
            }
        }
        if (is_terminator) {
            break;
        }

        data.append(reinterpret_cast<const char*>(unit.data()), unit.size());
        ++strlen;

        if (strlen == maxlen) {
            break;
        }
        address += static_cast<std::uint64_t>(charlen);
    }

    // the decoded string feeds the stats log (utils.py read_string)
    ql.os().stats().log_string(data);
    return data;
}

std::string QlOsUtils::read_wstring(Qiling& ql, std::uint64_t address, int maxlen) {
    // utils.py read_wstring: utf-16le — the walk collects the raw 2-byte
    // units, then decodes them as utf-16le (the upstream's data.decode):
    // the plain ranges map 1:1, the surrogate pairs combine, and the lone
    // surrogates fall back to backslashreplace escapes
    std::string raw;
    int strlen = 0;

    while (true) {
        const auto unit = ql.mem().read(address, 2);
        bool is_terminator = unit[0] == 0 && unit[1] == 0;
        if (is_terminator) {
            break;
        }

        raw.append(reinterpret_cast<const char*>(unit.data()), 2);
        ++strlen;

        if (strlen == maxlen) {
            break;
        }
        address += 2;
    }

    // utf-16le -> utf-8: combine the surrogate pairs, encode the rest as
    // utf-8 (1-3 bytes); the invalid sequences render backslashreplace-style
    std::string out;
    for (std::size_t i = 0; i < raw.size(); i += 2) {
        const auto lo = static_cast<std::uint16_t>(static_cast<std::uint8_t>(raw[i]));
        const auto hi = static_cast<std::uint16_t>(static_cast<std::uint8_t>(raw[i + 1]));
        const auto cu = static_cast<std::uint32_t>(lo | (hi << 8));
        if (cu < 0x80) {
            out.push_back(static_cast<char>(cu));
            continue;
        }
        // the surrogate range: the high surrogate takes the next unit as its
        // low half (the pair -> the astral codepoint); a lone half renders
        // backslashreplace-style (the upstream's errors='backslashreplace')
        if (cu >= 0xD800 && cu <= 0xDFFF) {
            if (cu <= 0xDBFF && i + 3 < raw.size() + 1 && i + 2 < raw.size()) {
                const auto lo2 = static_cast<std::uint16_t>(static_cast<std::uint8_t>(raw[i + 2]));
                const auto hi2 = static_cast<std::uint16_t>(static_cast<std::uint8_t>(raw[i + 3]));
                const auto cu2 = static_cast<std::uint32_t>(lo2 | (hi2 << 8));
                if (cu2 >= 0xDC00 && cu2 <= 0xDFFF) {
                    const auto cp = 0x10000 + ((static_cast<std::uint32_t>(cu - 0xD800) << 10) |
                                               static_cast<std::uint32_t>(cu2 - 0xDC00));
                    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    i += 2;  // the low surrogate consumed
                    continue;
                }
            }
            // the lone surrogate: backslashreplace escape (the upstream's
            // errors='backslashreplace' renders \uXXXX)
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04X", cu);
            out.append(buf);
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

std::string QlOsUtils::read_cstring(Qiling& ql, std::uint64_t address, int maxlen) {
    return read_string(ql, address, 1, maxlen);
}

std::string QlOsUtils::read_guid(Qiling& ql, std::uint64_t address) {
    const auto raw = ql.mem().read(address, 16);

    // python UUID(bytes_le=...): the first three fields are little-endian,
    // the last two big-endian; the canonical text renders them hyphenated
    const auto be = [&raw](std::size_t off, std::size_t len) -> std::uint64_t {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < len; ++i) {
            v = (v << 8) | raw[off + i];
        }
        return v;
    };
    const auto d1 = static_cast<std::uint32_t>(raw[0]) | (static_cast<std::uint32_t>(raw[1]) << 8) |
                    (static_cast<std::uint32_t>(raw[2]) << 16) | (static_cast<std::uint32_t>(raw[3]) << 24);
    const auto d2 = static_cast<std::uint32_t>(raw[4]) | (static_cast<std::uint32_t>(raw[5]) << 8);

    char out[40];
    std::snprintf(out, sizeof(out), "%08x-%04x-%04llx-%02llx%02llx-%012llx",
                  d1, d2,
                  static_cast<unsigned long long>(be(6, 2)),
                  static_cast<unsigned long long>(raw[8]),
                  static_cast<unsigned long long>(raw[9]),
                  static_cast<unsigned long long>(be(10, 6)));
    return out;
}

namespace {

// the manual string conversion: the precision truncates, the width pads
// (the '-' flag left-aligns)
std::string format_string_arg(const std::string& s, const std::string& flags, const std::string& width,
                              const std::string& prec) {
    std::string out = s;
    if (!prec.empty()) {
        const auto limit = static_cast<std::size_t>(std::stoul(prec));
        if (out.size() > limit) {
            out.resize(limit);
        }
    }
    if (!width.empty()) {
        const auto w = static_cast<std::size_t>(std::stoul(width));
        if (out.size() < w) {
            const std::string pad(w - out.size(), ' ');
            if (flags.find('-') != std::string::npos) {
                out += pad;
            } else {
                out = pad + out;
            }
        }
    }
    return out;
}

// the numeric conversion through the host snprintf (the flags/width/precision
// carry over into the C spec)
std::string format_numeric_arg(char type, const std::string& flags, const std::string& width,
                               const std::string& prec, const std::string& size, std::uint64_t arg) {
    std::string spec = "%" + flags + width;
    if (!prec.empty()) {
        spec += "." + prec;
    }
    spec += size;
    spec += type;

    // the size modifier selects the promoted width; the l/ll/I64 forms widen
    const bool wide = (size == "l" || size == "ll" || size == "I64" || size == "j" || size == "z" || size == "t");

    char buf[128];
    if (type == 'd' || type == 'i') {
        if (wide) {
            std::snprintf(buf, sizeof(buf), spec.c_str(), static_cast<long long>(arg));
        } else {
            std::snprintf(buf, sizeof(buf), spec.c_str(), static_cast<int>(arg));
        }
    } else if (type == 'c') {
        std::snprintf(buf, sizeof(buf), spec.c_str(), static_cast<int>(arg & 0xff));
    } else if (type == 'a' || type == 'A' || type == 'e' || type == 'E' || type == 'f' || type == 'F' ||
               type == 'g' || type == 'G') {
        // the upstream quirk: the slot value promotes as an integer (the
        // real-double varargs ride the xmm registers upstream too)
        std::snprintf(buf, sizeof(buf), spec.c_str(), static_cast<double>(arg));
    } else {
        // o u x X
        if (wide) {
            std::snprintf(buf, sizeof(buf), spec.c_str(), static_cast<unsigned long long>(arg));
        } else {
            std::snprintf(buf, sizeof(buf), spec.c_str(), static_cast<unsigned int>(arg));
        }
    }
    return buf;
}

}  // namespace

std::pair<std::string, std::vector<std::uint64_t>> QlOsUtils::common_printf(Qiling& ql, const std::string& format,
                                                                            const ArgPuller& va_args,
                                                                            bool wstring) {
    std::string out;
    std::vector<std::uint64_t> orig_args;

    const auto read_str = [&](std::uint64_t addr) {
        // the %s of a null pointer renders "(null)" (the printf semantics;
        // the argv-walk fixtures index past the array tail and the read at
        // 0 would fault the emulation)
        if (addr == 0) {
            return std::string("(null)");
        }
        return wstring ? read_wstring(ql, addr) : read_cstring(ql, addr);
    };

    std::size_t i = 0;
    const std::size_t n = format.size();
    while (i < n) {
        if (format[i] != '%') {
            out += format[i++];
            continue;
        }
        ++i;
        if (i >= n) {
            out += '%';
            break;
        }
        if (format[i] == '%') {
            out += '%';
            ++i;
            continue;
        }

        // %[flags][width][.precision][size]type
        std::string flags;
        while (i < n && std::string_view("-+0 #").find(format[i]) != std::string_view::npos) {
            flags += format[i++];
        }

        std::string width;
        if (i < n && format[i] == '*') {
            width = std::to_string(va_args());
            orig_args.push_back(0);  // the recorded slot (the puller owns the value)
            ++i;
        } else {
            while (i < n && std::isdigit(static_cast<unsigned char>(format[i]))) {
                width += format[i++];
            }
        }

        std::string prec;
        if (i < n && format[i] == '.') {
            ++i;
            if (i < n && format[i] == '*') {
                prec = std::to_string(va_args());
                orig_args.push_back(0);
                ++i;
            } else {
                while (i < n && std::isdigit(static_cast<unsigned char>(format[i]))) {
                    prec += format[i++];
                }
            }
        }

        std::string size;
        while (i < n) {
            // hh | ll | I32 | I64 | [hjltwzIL]
            if (format.compare(i, 2, "hh") == 0) {
                size += "hh";
                i += 2;
            } else if (format.compare(i, 2, "ll") == 0) {
                size += "ll";
                i += 2;
            } else if (format.compare(i, 3, "I32") == 0) {
                size += "I32";
                i += 3;
            } else if (format.compare(i, 3, "I64") == 0) {
                size += "I64";
                i += 3;
            } else if (std::string_view("hjltwzIL").find(format[i]) != std::string_view::npos) {
                size += format[i++];
            } else {
                break;
            }
        }

        if (i >= n) {
            break;
        }
        const char type = format[i++];

        const auto arg = va_args();
        orig_args.push_back(arg);

        if (type == 's') {
            out += format_string_arg(read_str(arg), flags, width, prec);
        } else if (type == 'S') {
            // the flipped string width (the __common_printf S branch)
            const auto flipped = !wstring;
            const auto s = flipped ? read_wstring(ql, arg) : read_cstring(ql, arg);
            out += format_string_arg(s, flags, width, prec);
        } else if (type == 'Z') {
            // ANSI_STRING / UNICODE_STRING share the layout; the Buffer sits
            // at offset 8 in both the 32- and the 64-bit forms
            const auto buffer = static_cast<std::uint64_t>(ql.mem().read_ptr(arg + 8, 8));
            out += format_string_arg(read_str(buffer), flags, width, prec);
        } else if (type == 'p') {
            // the pointer: #x (the __common_printf p branch)
            out += format_numeric_arg('x', flags + "#", width, prec, size, arg);
        } else {
            out += format_numeric_arg(type, flags, width, prec, size, arg);
        }
    }

    return {out, orig_args};
}

QlOsUtils::PrintfResult QlOsUtils::printf(Qiling& ql, const std::string& format, const ArgPuller& va_args,
                                          bool wstring) {
    auto [out, args] = common_printf(ql, format, va_args, wstring);

    ql.os().stdout_stream().write({out.begin(), out.end()});

    return {out.size(), args};
}

// the format pre-scan (the port's bounded read_ellipsis call sites): each %
// conversion + each * width/precision consumes one variadic slot. The walk
// skips the flags, the numeric width/precision, and the length modifiers
// (hjltwzIL/hh/ll/I32/I64); the %% escape consumes none.
std::size_t QlOsUtils::count_va_pulls(const std::string& body) {
    std::size_t pulls = 0;
    for (std::size_t k = 0; k + 1 < body.size(); ++k) {
        if (body[k] != '%') {
            continue;
        }
        std::size_t j = k + 1;
        if (j >= body.size()) {
            break;
        }
        if (body[j] == '%') {
            k = j;
            continue;
        }
        while (j < body.size() && std::string_view("-+0 #").find(body[j]) != std::string_view::npos) {
            ++j;
        }
        if (j < body.size() && body[j] == '*') {
            ++pulls;
            ++j;
        } else {
            while (j < body.size() && std::isdigit(static_cast<unsigned char>(body[j]))) {
                ++j;
            }
        }
        if (j < body.size() && body[j] == '.') {
            ++j;
            if (j < body.size() && body[j] == '*') {
                ++pulls;
                ++j;
            } else {
                while (j < body.size() && std::isdigit(static_cast<unsigned char>(body[j]))) {
                    ++j;
                }
            }
        }
        while (j < body.size() && (std::string_view("hjltwzIL").find(body[j]) != std::string_view::npos ||
                                   body.compare(j, 2, "hh") == 0 || body.compare(j, 2, "ll") == 0 ||
                                   body.compare(j, 3, "I32") == 0 || body.compare(j, 3, "I64") == 0)) {
            j += (body.compare(j, 3, "I32") == 0 || body.compare(j, 3, "I64") == 0) ? 3 : 1;
        }
        if (j < body.size()) {
            ++pulls;
            k = j;
        }
    }
    return pulls;
}

QlOsUtils::PrintfResult QlOsUtils::sprintf(Qiling& ql, std::uint64_t buff, const std::string& format,
                                           const ArgPuller& va_args, bool wstring) {
    auto [out, args] = common_printf(ql, format, va_args, wstring);

    // the enc choice: utf-16le for the wide form, utf-8 otherwise
    if (wstring) {
        std::vector<std::uint8_t> bytes;
        for (const char c : out) {
            bytes.push_back(static_cast<std::uint8_t>(c));
            bytes.push_back(0);
        }
        bytes.push_back(0);
        bytes.push_back(0);
        ql.mem().write(buff, bytes);
    } else {
        std::vector<std::uint8_t> bytes{out.begin(), out.end()};
        bytes.push_back(0);
        ql.mem().write(buff, bytes);
    }

    return {out.size(), args};
}

}  // namespace os
}  // namespace qiling
