// C++-only: tiny INI reader for .ql profiles — the configparser subset those files
// use (PORT_PLAN.md 5.10; in-tree, no dependency).
//
// Interpolation audit (PORT_PLAN.md OQ 8, resolved 2026-10-17): grep over
// qiling/profiles/*.ql shows no '%' anywhere, so no profile uses interpolation.
// '%' is therefore treated literally, which is behavior-identical to Python's
// BasicInterpolation on the profile corpus.
//
// Semantics kept for parity with configparser (strict=True, optionxform=str.lower):
//   - full-line comments start with '#' or ';' (after optional leading whitespace)
//   - empty lines are ignored
//   - section headers are '[name]' (case-sensitive; the name may not be empty)
//   - option lines are 'name <sep> value' with sep in {=, :} — the first delimiter
//     on the line wins (mirrors OPTCRE's lazy option match)
//   - keys are lowercased both when stored and when looked up (optionxform), so key
//     lookups are case-insensitive; section lookups stay case-sensitive
//   - values keep their case; only surrounding whitespace is stripped
//   - empty values are allowed
//   - duplicate sections/options are rejected (strict=True)
//   - read() ignores missing files and returns false, like configparser.read
//
// Documented deviations (unreachable from the shipped profiles):
//   - no continuation lines: an unparsable non-comment line raises
//   - no interpolation, no DEFAULT section (see the audit note above)
#ifndef QILING_PROFILES_INIREADER_HPP
#define QILING_PROFILES_INIREADER_HPP

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {

class IniConfig {
public:
    // Parses `text`. Malformed input raises QlErrorBase with a `source:line` prefix
    // (the configparser.Error analogue).
    void read_string(std::string_view text, const std::string& source = "<string>");

    // Parses `file`. Returns false when the file does not exist (configparser.read
    // skips missing files silently). Parse errors raise like read_string.
    bool read(const std::filesystem::path& file);

    std::vector<std::string> sections() const;
    bool has_section(std::string_view section) const;

    // the section's option keys in the stored (lowercased) order
    std::vector<std::string> option_keys(std::string_view section) const;

    // Python raises NoSectionError for a missing section; this port throws QlErrorBase.
    // A missing option returns std::nullopt (the caller decides on fallback).
    bool has_option(std::string_view section, std::string_view key) const;
    std::optional<std::string> get(std::string_view section, std::string_view key) const;

    // Base-0 integer conversion, mirroring profile_setup's int(base=0) converter.
    // A missing option raises QlErrorBase (NoOptionError analogue); a malformed
    // integer raises std::invalid_argument (ValueError analogue).
    std::int64_t get_int(std::string_view section, std::string_view key) const;
    // the unsigned sibling (address-domain values above 2^63, e.g. the
    // vsyscall page); parse_uint_base0 backs it
    std::uint64_t get_uint(std::string_view section, std::string_view key) const;

private:
    // section name (verbatim) -> option map (lowercased key -> value)
    std::map<std::string, std::map<std::string, std::string>, std::less<>> sections_;
};

}  // namespace qiling

#endif  // QILING_PROFILES_INIREADER_HPP
