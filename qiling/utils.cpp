#include "qiling/utils.hpp"

#include <array>
#include <charconv>
#include <limits>
#include <stdexcept>

namespace qiling {

namespace {

constexpr bool ascii_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

constexpr char ascii_lower_char(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Casefolds and resolves the alias table, mirroring utils.py __name_to_enum:
// mapping.get(aliases.get(key) or key).
template <typename E, std::size_t NA, std::size_t NN>
std::optional<E> name_to_enum(std::string_view name,
                              const std::array<std::pair<std::string_view, std::string_view>, NA>& aliases,
                              const std::array<std::pair<std::string_view, E>, NN>& names) {
    const std::string key = ascii_casefold(name);
    std::string_view resolved = key;
    for (const auto& [alias, target] : aliases) {
        if (key == alias) {
            resolved = target;
            break;
        }
    }
    return detail::lookup(resolved, names);
}

}  // namespace

// ---- string helpers ----

std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && ascii_space(s.front())) s.remove_prefix(1);
    while (!s.empty() && ascii_space(s.back())) s.remove_suffix(1);
    return s;
}

std::string ascii_casefold(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) out.push_back(ascii_lower_char(c));
    return out;
}

// int(s, 0) analogue. Grammar: [ws] [sign] (0x hex | 0o oct | 0b bin | dec) [ws],
// with single '_' separators allowed strictly between digits (PEP 515). Decimal
// with leading zeros is rejected (int('010', 0) -> ValueError; '0' itself is fine).
std::int64_t parse_int_base0(std::string_view sv) {
    auto fail = []() -> std::int64_t {
        throw std::invalid_argument("invalid literal for int() with base 0");
    };

    sv = trim(sv);
    if (sv.empty()) fail();

    bool negative = false;
    if (sv.front() == '+' || sv.front() == '-') {
        negative = sv.front() == '-';
        sv.remove_prefix(1);
    }

    int base = 10;
    if (sv.size() >= 2 && sv[0] == '0') {
        switch (ascii_lower_char(sv[1])) {
            case 'x': base = 16; sv.remove_prefix(2); break;
            case 'o': base = 8;  sv.remove_prefix(2); break;
            case 'b': base = 2;  sv.remove_prefix(2); break;
            default: break;
        }
    }

    if (sv.empty()) fail();  // bare sign or bare prefix

    const auto digit_ok = [base](char c) {
        const char d = ascii_lower_char(c);
        if (d >= '0' && d <= '9') return (d - '0') < base;
        if (d >= 'a' && d <= 'f') return (10 + d - 'a') < base;
        return false;
    };

    // Validate digits/underscores and copy digits without separators.
    std::string digits;
    digits.reserve(sv.size());
    for (std::size_t i = 0; i < sv.size(); ++i) {
        const char c = sv[i];
        if (c == '_') {
            // must sit strictly between two digits
            if (i == 0 || i + 1 >= sv.size() || !digit_ok(sv[i - 1]) || !digit_ok(sv[i + 1])) fail();
            continue;
        }
        if (!digit_ok(c)) fail();
        digits.push_back(c);
    }
    if (digits.empty()) fail();

    // int('010', 0) -> ValueError: decimal (no base prefix) may not have leading zeros
    if (base == 10 && digits.size() > 1 && digits.front() == '0') fail();

    unsigned long long magnitude = 0;
    const auto* first = digits.data();
    const auto* last = first + digits.size();
    const auto conv = std::from_chars(first, last, magnitude, base);
    if (conv.ec == std::errc::result_out_of_range || conv.ptr != last) fail();

    constexpr auto umax = std::numeric_limits<unsigned long long>::max();
    (void)umax;
    constexpr unsigned long long pos_max = static_cast<unsigned long long>(std::numeric_limits<std::int64_t>::max());
    constexpr unsigned long long neg_max = pos_max + 1ull;  // |INT64_MIN|

    if (negative) {
        if (magnitude > neg_max) fail();
        if (magnitude == neg_max) return std::numeric_limits<std::int64_t>::min();
        return -static_cast<std::int64_t>(magnitude);
    }
    if (magnitude > pos_max) fail();
    return static_cast<std::int64_t>(magnitude);
}

// ---- name -> enum conversion (utils.py; case-insensitive, with the same aliases) ----

std::optional<QL_OS> os_convert(std::string_view name) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 1> aliases{{
        {"darwin", "macos"},
    }};
    return name_to_enum(name, aliases, os_name_table);
}

std::optional<QL_ARCH> arch_convert(std::string_view name) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 3> aliases{{
        {"amd64", "x8664"},
        {"x86_64", "x8664"},
        {"riscv32", "riscv"},
    }};
    return name_to_enum(name, aliases, arch_name_table);
}

std::optional<QL_DEBUGGER> debugger_convert(std::string_view name) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 0> aliases{};
    return name_to_enum(name, aliases, debugger_name_table);
}

}  // namespace qiling
