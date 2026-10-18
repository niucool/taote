// Ported from qiling/os/utils.py — QlOsUtils. The string readers
// (read_string/read_cstring/read_wstring/read_guid) and the printf engine
// (__common_printf/printf/sprintf). The format walk is a single pass: the
// upstream translates the guest specifiers into the python %-operator form
// and re-applies them; the port formats each conversion inline (the same
// output, one pass — the documented structural deviation).
//
// Deviation note: the C format plumbing (the snprintf specs) covers the
// numeric conversions; %s reads the guest string directly (the C snprintf
// cannot take it). The float conversions follow the upstream quirk of
// reading the variadic slot as an integer and letting the conversion
// promote it.
#ifndef QILING_OS_UTILS_HPP
#define QILING_OS_UTILS_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace qiling {

class Qiling;

namespace os {

class QlOsUtils {
public:
    static constexpr const char* ELLIPSIS_PREF = "__qlva_";

    // utils.py read_string: the char-width-stepped, NUL-terminated read
    // (charlen 2 for the wide form); backslashreplace decode degrades to a
    // raw byte copy for the latin-1 subset
    static std::string read_string(Qiling& ql, std::uint64_t address, int charlen, int maxlen = 0);

    // utils.py read_wstring: utf-16le
    static std::string read_wstring(Qiling& ql, std::uint64_t address, int maxlen = 0);

    // utils.py read_cstring: latin1
    static std::string read_cstring(Qiling& ql, std::uint64_t address, int maxlen = 0);

    // utils.py read_guid: the bytes_le uuid in its canonical text form
    static std::string read_guid(Qiling& ql, std::uint64_t address);

    // the printf result: the written length + the consumed variadic values
    // in call order (the __dup recording)
    struct PrintfResult {
        std::size_t count = 0;
        std::vector<std::uint64_t> orig_args;
    };

    // the va_args puller yields the next variadic slot (the fcall.py
    // readEllipsis generator / the utils.py va_list generator analogue)
    using ArgPuller = std::function<std::uint64_t()>;

    // utils.py printf: render to the os stdout (utf-8)
    static PrintfResult printf(Qiling& ql, const std::string& format, const ArgPuller& va_args,
                               bool wstring = false);

    // utils.py sprintf: render (+NUL) into the guest buffer
    static PrintfResult sprintf(Qiling& ql, std::uint64_t buff, const std::string& format,
                                const ArgPuller& va_args, bool wstring = false);

private:
    // __common_printf: the format walk; returns the rendered text
    static std::pair<std::string, std::vector<std::uint64_t>> common_printf(
        Qiling& ql, const std::string& format, const ArgPuller& va_args, bool wstring);
};

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_UTILS_HPP
