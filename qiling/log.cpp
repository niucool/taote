#include "qiling/log.hpp"

#include <atomic>
#include <cstdlib>

#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/stdout_sinks.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace qiling {
namespace log {

namespace {

// spdlog custom pattern flag ('*') rendering the qiling level tag — the
// QlBaseFormatter/QlColoredFormatter get_level_tag analogue.
class level_tag_flag final : public spdlog::custom_flag_formatter {
public:
    explicit level_tag_flag(bool colored) : colored_(colored) {}

    void format(const spdlog::details::log_msg& msg, const std::tm&, spdlog::memory_buf_t& dest) override {
        const std::string tag = level_tag(msg.level, colored_);
        dest.append(tag.data(), tag.data() + tag.size());
    }

    std::unique_ptr<custom_flag_formatter> clone() const override {
        return spdlog::details::make_unique<level_tag_flag>(colored_);
    }

private:
    bool colored_;
};

// log.py __is_color_terminal: isatty + platform color support. The POSIX branch
// uses curses there (colors > 0); here we approximate with TERM != "dumb" —
// documented deviation; NO_COLOR and `plain` are honored by the caller either way.
bool stream_supports_color(int fd, [[maybe_unused]] const void* stream_handle) {
#if defined(_WIN32)
    if (_isatty(fd) == 0) return false;
    DWORD mode = 0;
    auto* handle = const_cast<void*>(stream_handle);
    return GetConsoleMode(handle, &mode) != 0 && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    if (isatty(fd) == 0) return false;
    const char* term = std::getenv("TERM");
    return term != nullptr && std::string_view(term) != "dumb";
#endif
}

bool device_supports_color(const LogDevice& dev) {
    switch (dev.kind) {
        case LogDevice::Kind::Stdout:
#if defined(_WIN32)
            return stream_supports_color(_fileno(stdout), reinterpret_cast<void*>(_get_osfhandle(_fileno(stdout))));
#else
            return stream_supports_color(fileno(stdout), nullptr);
#endif
        case LogDevice::Kind::Stderr:
#if defined(_WIN32)
            return stream_supports_color(_fileno(stderr), reinterpret_cast<void*>(_get_osfhandle(_fileno(stderr))));
#else
            return stream_supports_color(fileno(stderr), nullptr);
#endif
        case LogDevice::Kind::File:
            return false;  // FileHandler streams are never color terminals
    }
    return false;
}

}  // namespace

// log.py: QlBaseFormatter.__level_tag (plain) and QlColoredFormatter (colored).
// spdlog's trace/off levels have no Python-logging counterpart; they map to "[?]"
// (documented C++-only behavior — the Python dict lookup would raise KeyError).
std::string level_tag(spdlog::level::level_enum level, bool colored) {
    std::string_view tag;
    std::string_view color_code;
    switch (level) {
        case spdlog::level::warn:     tag = "[!]"; color_code = color::YELLOW;  break;
        case spdlog::level::info:     tag = "[=]"; color_code = color::BLUE;    break;
        case spdlog::level::debug:    tag = "[+]"; color_code = color::MAGENTA; break;
        case spdlog::level::critical: tag = "[x]"; color_code = color::CRIMSON; break;
        case spdlog::level::err:      tag = "[x]"; color_code = color::RED;     break;
        default:                      tag = "[?]"; color_code = color::DEFAULT; break;
    }
    if (!colored) return std::string(tag);
    std::string out;
    out.reserve(color_code.size() + tag.size() + std::string_view(color::DEFAULT).size());
    out.append(color_code).append(tag).append(color::DEFAULT);
    return out;
}

// log.py: resolve_logger_level (verbatim mapping — DISABLED maps to CRITICAL,
// which silences only sub-critical output, exactly like Python).
spdlog::level::level_enum resolve_logger_level(QL_VERBOSE verbose) {
    using L = spdlog::level::level_enum;
    switch (verbose) {
        case QL_VERBOSE::DISABLED: return L::critical;
        case QL_VERBOSE::OFF:      return L::warn;
        case QL_VERBOSE::DEFAULT:  return L::info;
        case QL_VERBOSE::DEBUG:    return L::debug;
        case QL_VERBOSE::DISASM:   return L::debug;
        case QL_VERBOSE::DUMP:     return L::debug;
    }
    return L::info;
}

std::unique_ptr<spdlog::formatter> make_pattern_formatter(const std::string& pattern, bool colored) {
    // Python logging appends '\n' (StreamHandler.terminator) on every platform;
    // pin the eol explicitly (spdlog's default is "\r\n" on Windows).
    auto formatter = std::make_unique<spdlog::pattern_formatter>(spdlog::pattern_time_type::local, std::string("\n"));
    formatter->add_flag<level_tag_flag>('*', colored).set_pattern(pattern);
    return formatter;
}

std::unique_ptr<spdlog::formatter> make_formatter(bool colored) {
    // Python: FMT_STR = '%(levelname)s\t%(message)s' with the level-tag formatter
    return make_pattern_formatter(FMT_PATTERN, colored);
}

// ---- RegexFilter (log.py) ----

void RegexFilter::update_filter(const std::string& pattern) {
    re_ = std::regex(pattern);
    has_ = true;
}

bool RegexFilter::match(std::string_view msg) const {
    if (!has_) return false;  // Python raises AttributeError; this port degrades to no-match
    // re.match semantics: anchored at the start of the string
    return std::regex_search(msg.begin(), msg.end(), re_, std::regex_constants::match_continuous);
}

// ---- regex_filter_sink ----

regex_filter_sink::regex_filter_sink(std::shared_ptr<spdlog::sinks::sink> inner, RegexFilter filter)
    : inner_(std::move(inner)), filter_(std::move(filter)) {}

void regex_filter_sink::update_filter(const std::string& pattern) { filter_.update_filter(pattern); }

void regex_filter_sink::sink_it_(const spdlog::details::log_msg& msg) {
    // the filter sees msg.payload — the message after fmt-argument substitution but
    // before pattern decoration, like Python's RegexFilter seeing record.getMessage()
    if (filter_.match(std::string_view{msg.payload.data(), msg.payload.size()})) inner_->log(msg);
}

void regex_filter_sink::flush_() {
    if (inner_) inner_->flush();
}

void regex_filter_sink::set_pattern_(const std::string& pattern) {
    // set_pattern is a C++-only sink convenience (Python handlers always carry the
    // Ql formatter). Rebuild through make_pattern_formatter so the pinned "\n" eol
    // convention is preserved on the forwarded sink.
    inner_->set_formatter(make_pattern_formatter(pattern, /*colored=*/false));
}

void regex_filter_sink::set_formatter_(std::unique_ptr<spdlog::formatter> formatter) {
    inner_->set_formatter(std::move(formatter));
}

// ---- setup_logger (log.py) ----

std::shared_ptr<spdlog::logger> setup_logger(const std::vector<LogDevice>& devs, bool plain,
                                             std::shared_ptr<spdlog::logger> override_logger) {
    // if there is an override logger, use it as-is
    if (override_logger) return override_logger;

    static std::atomic<unsigned long long> instance_counter{QL_INSTANCE_ID};
    const auto id = instance_counter.fetch_add(1ull);
    const std::string name = "qiling" + std::to_string(id);

    std::vector<std::shared_ptr<spdlog::sinks::sink>> sinks;
    sinks.reserve(devs.size());

    // adhere to the NO_COLOR convention (see: https://no-color.org/)
    const char* no_color_env = std::getenv("NO_COLOR");
    const bool no_color = (no_color_env != nullptr && *no_color_env != '\0') || plain;

    for (const auto& dev : devs) {
        std::shared_ptr<spdlog::sinks::sink> sink;
        switch (dev.kind) {
            case LogDevice::Kind::Stdout:
                sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
                break;
            case LogDevice::Kind::Stderr:
                sink = std::make_shared<spdlog::sinks::stderr_sink_mt>();
                break;
            case LogDevice::Kind::File:
                sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(dev.path.string(), true);
                break;
        }
        sink->set_formatter(make_formatter(!no_color && device_supports_color(dev)));
        sinks.push_back(std::move(sink));
    }

    // logdevs == [] attaches a NullHandler — logging is silent and safe
    if (sinks.empty()) sinks.push_back(std::make_shared<spdlog::sinks::null_sink_mt>());

    // a named logger (never the root logger); propagation does not exist in spdlog
    auto logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
    logger->set_level(resolve_logger_level(QL_VERBOSE::DEFAULT));
    return logger;
}

}  // namespace log
}  // namespace qiling
