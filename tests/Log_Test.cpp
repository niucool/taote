// Log suite — PORT_PLAN.md §10 Phase 0 tests (the qiling/log.py surface:
// resolve_logger_level mapping, level tags, named loggers, level + regex filters).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <spdlog/sinks/base_sink.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/stdout_sinks.h>

#include "qiling/log.hpp"

namespace {

// Test sink capturing formatted lines and raw levels.
class CollectingSink final : public spdlog::sinks::base_sink<spdlog::details::null_mutex> {
public:
    std::vector<std::string> lines;
    std::vector<spdlog::level::level_enum> levels;

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        levels.push_back(msg.level);
        spdlog::memory_buf_t buf;
        formatter_->format(msg, buf);
        lines.emplace_back(buf.data(), buf.size());
    }
    void flush_() override {}
};

}  // namespace

TEST(LogLevels, ResolveLoggerLevel) {
    using L = spdlog::level::level_enum;
    using qiling::QL_VERBOSE;
    // verbatim mapping from log.py (DISABLED maps to critical, not spdlog's off)
    EXPECT_EQ(qiling::log::resolve_logger_level(QL_VERBOSE::DISABLED), L::critical);
    EXPECT_EQ(qiling::log::resolve_logger_level(QL_VERBOSE::OFF), L::warn);
    EXPECT_EQ(qiling::log::resolve_logger_level(QL_VERBOSE::DEFAULT), L::info);
    EXPECT_EQ(qiling::log::resolve_logger_level(QL_VERBOSE::DEBUG), L::debug);
    EXPECT_EQ(qiling::log::resolve_logger_level(QL_VERBOSE::DISASM), L::debug);
    EXPECT_EQ(qiling::log::resolve_logger_level(QL_VERBOSE::DUMP), L::debug);
}

TEST(LogTags, LevelTags) {
    using namespace qiling::log;
    using L = spdlog::level::level_enum;
    // verbatim QlBaseFormatter.__level_tag
    EXPECT_EQ(level_tag(L::info, false), "[=]");
    EXPECT_EQ(level_tag(L::warn, false), "[!]");
    EXPECT_EQ(level_tag(L::debug, false), "[+]");
    EXPECT_EQ(level_tag(L::critical, false), "[x]");
    EXPECT_EQ(level_tag(L::err, false), "[x]");
}

TEST(LogTags, ColoredLevelTags) {
    using namespace qiling::log;
    using L = spdlog::level::level_enum;
    // verbatim QlColoredFormatter color assignments
    EXPECT_EQ(level_tag(L::info, true), std::string(color::BLUE) + "[=]" + color::DEFAULT);
    EXPECT_EQ(level_tag(L::warn, true), std::string(color::YELLOW) + "[!]" + color::DEFAULT);
    EXPECT_EQ(level_tag(L::debug, true), std::string(color::MAGENTA) + "[+]" + color::DEFAULT);
    EXPECT_EQ(level_tag(L::critical, true), std::string(color::CRIMSON) + "[x]" + color::DEFAULT);
    EXPECT_EQ(level_tag(L::err, true), std::string(color::RED) + "[x]" + color::DEFAULT);
}

TEST(LogFormatter, PatternRendersTagAndMessage) {
    // log.py FMT_STR + the level-tag formatter: "[tag] \tmessage"
    auto sink = std::make_shared<CollectingSink>();
    sink->set_formatter(qiling::log::make_formatter(false));
    spdlog::logger lg("test_pattern", sink);
    lg.set_level(spdlog::level::info);
    lg.warn("hello {}", 42);
    ASSERT_EQ(sink->lines.size(), 1u);
    EXPECT_EQ(sink->lines[0], "[!] \thello 42\n");
}

TEST(LogFormatter, ColoredPatternEmbedsAnsi) {
    auto sink = std::make_shared<CollectingSink>();
    sink->set_formatter(qiling::log::make_formatter(true));
    spdlog::logger lg("test_colored", sink);
    lg.set_level(spdlog::level::info);
    lg.info("colored");
    ASSERT_EQ(sink->lines.size(), 1u);
    const std::string& line = sink->lines[0];
    EXPECT_NE(line.find(qiling::log::color::BLUE), std::string::npos);
    EXPECT_NE(line.find("[=]"), std::string::npos);
    EXPECT_NE(line.find(qiling::log::color::DEFAULT), std::string::npos);
    EXPECT_NE(line.find("colored"), std::string::npos);
}

TEST(LogNamed, InstanceIdsIncrement) {
    // log.py: logger name is qiling{QL_INSTANCE_ID}, incrementing per
    // setup_logger call. The absolute ids depend on how many loggers earlier
    // suites created (the process-wide counter is shared), so the assertions
    // check the increment relation rather than fixed names.
    const auto first = qiling::log::setup_logger({qiling::log::stdout_device()});
    const auto second = qiling::log::setup_logger({qiling::log::stdout_device()});
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_NE(first->name(), second->name());
    EXPECT_EQ(first->name().rfind("qiling", 0), 0u);
    EXPECT_EQ(second->name().rfind("qiling", 0), 0u);
    const unsigned long long first_id = std::stoull(first->name().substr(6));
    const unsigned long long second_id = std::stoull(second->name().substr(6));
    EXPECT_EQ(second_id, first_id + 1);
}

TEST(LogNamed, OverrideLoggerIsUsedAsIs) {
    // log.py: an override logger is used as-is, without reconfiguration
    auto custom = std::make_shared<spdlog::logger>("custom", std::make_shared<spdlog::sinks::null_sink_mt>());
    const auto result = qiling::log::setup_logger({}, false, custom);
    EXPECT_EQ(result, custom);
    EXPECT_EQ(custom->name(), "custom");
}

TEST(LogNamed, EmptyDeviceListUsesNullHandler) {
    // log.py: logdevs == [] attaches a NullHandler — logging must be silent and safe
    const auto logger = qiling::log::setup_logger({});
    ASSERT_NE(logger, nullptr);
    EXPECT_NO_THROW(logger->info("into the void"));
}

TEST(LogLevels, OffSuppressesInfoButShowsWarnings) {
    auto sink = std::make_shared<CollectingSink>();
    auto lg = std::make_shared<spdlog::logger>("test_off", sink);
    lg->set_level(qiling::log::resolve_logger_level(qiling::QL_VERBOSE::OFF));
    lg->info("hidden");
    lg->warn("shown");
    ASSERT_EQ(sink->lines.size(), 1u);
    EXPECT_NE(sink->lines[0].find("shown"), std::string::npos);
}

TEST(LogRegex, MatchesAtStartLikeReMatch) {
    qiling::log::RegexFilter f;
    // unset filter: Python raises AttributeError; this port degrades to no-match
    EXPECT_FALSE(f.match("hello"));
    f.update_filter("^hello");
    EXPECT_TRUE(f.match("hello world"));
    EXPECT_FALSE(f.match("say hello"));
    f.update_filter("hello");  // re.match anchors at the start even without ^
    EXPECT_TRUE(f.match("hello again"));
    EXPECT_FALSE(f.match("say hello"));
}

TEST(LogRegex, SinkFilteringPassesOnlyMatchingPayloads) {
    auto inner = std::make_shared<CollectingSink>();
    auto filtered = std::make_shared<qiling::log::regex_filter_sink>(inner, qiling::log::RegexFilter("^hello"));
    spdlog::logger lg("test_filtered", filtered);
    lg.set_level(spdlog::level::trace);
    lg.info("hello there");
    lg.info("say hello");
    lg.warn("hello again");
    // the filter sees the raw payload (fmt-arg formatted, pre-pattern) like
    // Python's RegexFilter seeing record.getMessage()
    ASSERT_EQ(inner->lines.size(), 2u);
}

TEST(LogRegex, SinkPatternForwardsToInner) {
    auto inner = std::make_shared<CollectingSink>();
    auto filtered = std::make_shared<qiling::log::regex_filter_sink>(inner, qiling::log::RegexFilter("^hi"));
    filtered->set_pattern("%v");
    spdlog::logger lg("test_forward", filtered);
    lg.set_level(spdlog::level::info);
    lg.info("hi there");
    ASSERT_EQ(inner->lines.size(), 1u);
    EXPECT_EQ(inner->lines[0], "hi there\n");
}
