#include <set>
#include "qiling/profiles/inireader.hpp"

#include <fstream>
#include <iterator>
#include <sstream>

#include "qiling/utils.hpp"

namespace qiling {

namespace {

// Full-line comments only: '#' or ';' as the first non-whitespace character
// (configparser's inline_comment_prefixes default is None — no inline comments).
bool is_comment_or_empty(std::string_view line) noexcept {
    const auto t = trim(line);
    return t.empty() || t.front() == '#' || t.front() == ';';
}

std::string parse_error(const std::string& source, std::size_t lineno, std::string_view what) {
    return source + ":" + std::to_string(lineno) + ": " + std::string(what);
}

}  // namespace

void IniConfig::read_string(std::string_view text, const std::string& source) {
    std::string current;      // current section name (verbatim case)
    bool in_section = false;  // options before any section are an error

    // the strict=True duplicate-section check applies WITHIN one read call
    // (the python config.read of a second file merges into the existing
    // sections — the user-config override ride over the base profile)
    std::set<std::string> seen_this_read;

    std::size_t lineno = 0;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t eol = text.find('\n', pos);
        const std::string_view raw = (eol == std::string_view::npos) ? text.substr(pos) : text.substr(pos, eol - pos);
        ++lineno;
        pos = (eol == std::string_view::npos) ? text.size() + 1 : eol + 1;

        const std::string_view line = trim(raw);
        if (is_comment_or_empty(line)) continue;

        // section header: '[name]' — SECTCRE requires the whole line to be the header
        if (line.front() == '[') {
            if (line.size() < 3 || line.back() != ']') {
                throw QlErrorBase(parse_error(source, lineno, "unterminated section header"));
            }
            const std::string_view name = trim(line.substr(1, line.size() - 2));
            if (name.empty()) {
                throw QlErrorBase(parse_error(source, lineno, "empty section name"));
            }
            current = std::string(name);
            // strict=True: duplicate sections are rejected (within this read;
            // the cross-file merges fold into the existing section map)
            if (!seen_this_read.insert(current).second) {
                throw QlErrorBase(parse_error(source, lineno, "duplicate section [" + current + "]"));
            }
            sections_.try_emplace(current, std::map<std::string, std::string>{});
            in_section = true;
            continue;
        }

        // option line: 'name <sep> value' — OPTCRE's lazy option match means the
        // first '=' or ':' on the line wins
        const std::size_t eq = line.find('=');
        const std::size_t colon = line.find(':');
        std::size_t sep = std::string_view::npos;
        if (eq != std::string_view::npos && colon != std::string_view::npos) sep = std::min(eq, colon);
        else if (eq != std::string_view::npos) sep = eq;
        else sep = colon;

        if (sep == std::string_view::npos) {
            // configparser would treat this as a possible continuation; this port
            // has no continuation lines (documented deviation) — it is an error
            throw QlErrorBase(parse_error(source, lineno, "unparsable line (no '=' or ':' delimiter)"));
        }
        if (!in_section) {
            throw QlErrorBase(parse_error(source, lineno, "option line before any section header"));
        }

        const std::string_view key = trim(line.substr(0, sep));
        if (key.empty()) {
            throw QlErrorBase(parse_error(source, lineno, "empty option name"));
        }
        const std::string_view value = trim(line.substr(sep + 1));

        // optionxform=str.lower: keys stored lowercase; duplicate options rejected
        auto& options = sections_.at(current);
        if (!options.emplace(ascii_casefold(key), std::string(value)).second) {
            throw QlErrorBase(parse_error(source, lineno, "duplicate option '" + ascii_casefold(key) +
                                                          "' in section [" + current + "]"));
        }
    }
}

bool IniConfig::read(const std::filesystem::path& file) {
    std::error_code ec;
    if (!std::filesystem::exists(file, ec)) return false;  // configparser.read skips missing files

    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    read_string(text, file.string());
    return true;
}

std::vector<std::string> IniConfig::sections() const {
    std::vector<std::string> out;
    out.reserve(sections_.size());
    for (const auto& [name, _] : sections_) out.push_back(name);
    return out;
}

std::vector<std::string> IniConfig::option_keys(std::string_view section) const {
    const auto it = sections_.find(section);
    std::vector<std::string> out;
    if (it == sections_.end()) {
        return out;
    }
    out.reserve(it->second.size());
    for (const auto& [key, _] : it->second) out.push_back(key);
    return out;
}

bool IniConfig::has_section(std::string_view section) const { return sections_.find(section) != sections_.end(); }

bool IniConfig::has_option(std::string_view section, std::string_view key) const {
    const auto it = sections_.find(section);
    if (it == sections_.end()) return false;
    return it->second.find(ascii_casefold(key)) != it->second.end();
}

std::optional<std::string> IniConfig::get(std::string_view section, std::string_view key) const {
    const auto it = sections_.find(section);
    if (it == sections_.end()) {
        throw QlErrorBase("No section: '" + std::string(section) + "'");  // NoSectionError analogue
    }
    const auto opt = it->second.find(ascii_casefold(key));
    if (opt == it->second.end()) return std::nullopt;
    return opt->second;
}

std::int64_t IniConfig::get_int(std::string_view section, std::string_view key) const {
    const auto value = get(section, key);
    if (!value.has_value()) {
        throw QlErrorBase("No option '" + ascii_casefold(key) + "' in section: '" + std::string(section) + "'");
    }
    // mirrors profile_setup's int_converter = partial(int, base=0); a malformed
    // value surfaces as std::invalid_argument (the ValueError analogue)
    return parse_int_base0(*value);
}

std::uint64_t IniConfig::get_uint(std::string_view section, std::string_view key) const {
    const auto value = get(section, key);
    if (!value.has_value()) {
        throw QlErrorBase("No option '" + ascii_casefold(key) + "' in section: '" + std::string(section) + "'");
    }
    return parse_uint_base0(*value);
}

}  // namespace qiling
