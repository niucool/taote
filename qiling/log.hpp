// Ported from qiling/log.py — spdlog-backed logging with the Python surface
// (PORT_PLAN.md 5.11): named loggers, level filter (QL_VERBOSE -> level), regex
// message filter, the '[!]'/'[=]'/'[+]'/'[x]' level tags, and colored/plain
// formatters. Not ported (Python-internal): the logging._srcfile/logThreads
// speed knobs (spdlog needs no equivalent).
//
// The Qiling back-reference used by QlBaseFormatter for the thread tag is wired
// in Phase 3 when the composition root exists; until then the thread tag is empty.
#ifndef QILING_LOG_HPP
#define QILING_LOG_HPP

#include <cstdio>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>

#include "qiling/const.hpp"

namespace qiling {
namespace log {

// log.py: QL_INSTANCE_ID = 114514 — the first logger is named qiling114514.
inline constexpr unsigned long long QL_INSTANCE_ID = 114514;

// log.py: FMT_STR = '%(levelname)s\t%(message)s' with the level-tag formatter —
// rendered as "<tag> \t<msg>", e.g. "[!] \twarning text".
inline constexpr const char* FMT_PATTERN = "%* \t%v";  // '*' is the custom level-tag flag

// log.py: class COLOR (verbatim escape sequences)
namespace color {
inline constexpr const char* CRIMSON = "\x1b[31m";
inline constexpr const char* RED = "\x1b[91m";
inline constexpr const char* GREEN = "\x1b[92m";
inline constexpr const char* YELLOW = "\x1b[93m";
inline constexpr const char* BLUE = "\x1b[94m";
inline constexpr const char* MAGENTA = "\x1b[95m";
inline constexpr const char* DEFAULT = "\x1b[39m";
}  // namespace color

// log.py: QlBaseFormatter.__level_tag; the colored variant mirrors
// QlColoredFormatter (warning yellow, info blue, debug magenta, critical crimson,
// error red — see color:: above).
std::string level_tag(spdlog::level::level_enum level, bool colored);

// log.py: resolve_logger_level — QL_VERBOSE -> logger level (verbatim mapping,
// including DISABLED -> critical, which only silences everything below critical).
spdlog::level::level_enum resolve_logger_level(QL_VERBOSE verbose);

// Builds a pattern formatter with the qiling level-tag flag and the pinned
// "\n" eol (Python StreamHandler terminator — identical on every platform).
// Used by make_formatter and by regex_filter_sink::set_pattern_ so every qiling
// logging path keeps the same terminator.
std::unique_ptr<spdlog::formatter> make_pattern_formatter(const std::string& pattern, bool colored);

// Builds the qiling pattern formatter ("<tag> \t<msg>", tag colored when colored).
std::unique_ptr<spdlog::formatter> make_formatter(bool colored);

// ---- logging devices (log.py: FileLike streams vs str paths) ----

struct LogDevice {
    enum class Kind { Stdout, Stderr, File };
    Kind kind = Kind::Stdout;
    std::filesystem::path path;
};

inline LogDevice stdout_device() { return {}; }
inline LogDevice stderr_device() { return {LogDevice::Kind::Stderr, {}}; }
inline LogDevice file_device(std::filesystem::path p) { return {LogDevice::Kind::File, std::move(p)}; }

// log.py: RegexFilter — filters on the raw (fmt-argument-formatted) message with
// re.match semantics (anchored at the start). This is what core.py attaches as
// `ql.filter` (core.py:472).
class RegexFilter {
public:
    RegexFilter() = default;
    explicit RegexFilter(const std::string& pattern) { update_filter(pattern); }

    void update_filter(const std::string& pattern);
    // Python raises AttributeError when the filter is used before update_filter();
    // this port degrades to "no match" instead (documented C++-only behavior).
    bool match(std::string_view msg) const;

private:
    std::regex re_;
    bool has_ = false;
};

// Sink wrapper that applies a RegexFilter to a device sink — the addFilter analogue
// for composing filtered loggers. The filter sees msg.payload, i.e. the message
// after fmt-argument substitution but before pattern decoration, exactly like
// Python's RegexFilter.filter(record) seeing record.getMessage().
class regex_filter_sink final : public spdlog::sinks::base_sink<spdlog::details::null_mutex> {
public:
    regex_filter_sink(std::shared_ptr<spdlog::sinks::sink> inner, RegexFilter filter);

    void update_filter(const std::string& pattern);

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override;
    void flush_() override;
    void set_pattern_(const std::string& pattern) override;
    void set_formatter_(std::unique_ptr<spdlog::formatter> formatter) override;

private:
    std::shared_ptr<spdlog::sinks::sink> inner_;
    RegexFilter filter_;
};

// log.py: setup_logger — named loggers ("qiling<N>", incrementing from
// QL_INSTANCE_ID), per-device sinks, colored/plain formatter per device
// tty-ness, NO_COLOR honored, level preset from QL_VERBOSE::DEFAULT (verbatim —
// verbosity adjustments happen elsewhere in Python too).
std::shared_ptr<spdlog::logger> setup_logger(const std::vector<LogDevice>& devs,
                                             bool plain = false,
                                             std::shared_ptr<spdlog::logger> override_logger = nullptr);

}  // namespace log
}  // namespace qiling

#endif  // QILING_LOG_HPP
