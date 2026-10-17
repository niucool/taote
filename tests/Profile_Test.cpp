// Profile suite — PORT_PLAN.md §10 Phase 0 tests (the tiny INI reader against the
// bundled .ql profiles; exit criterion: parses to the same key/value structure the
// Python configparser yields — including optionxform's lowercased keys and the
// base-0 int converter from profile_setup).
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>

#include "qiling/profiles/inireader.hpp"

namespace {

std::filesystem::path profile(const char* name) {
    return std::filesystem::path(QILING_SOURCE_DIR) / "qiling" / "profiles" / name;
}

}  // namespace

TEST(IniConfig, ParsesWindowsProfile) {
    qiling::IniConfig cfg;
    ASSERT_TRUE(cfg.read(profile("windows.ql")));

    for (const char* section : {"OS64", "OS32", "CODE", "KERNEL", "MISC", "SYSTEM", "PROCESSES", "USER", "PATH", "REGISTRY"}) {
        EXPECT_TRUE(cfg.has_section(section)) << "missing section: " << section;
    }
    EXPECT_FALSE(cfg.has_section("NoSuchSection"));

    // values are strings; whitespace-stripped; case preserved
    EXPECT_EQ(cfg.get("OS64", "heap_address").value_or("MISSING"), "0x500000000");
    EXPECT_EQ(cfg.get("MISC", "current_path").value_or("MISSING"), "C:\\");

    // optionxform=str.lower: stored lowercase, lookups case-insensitive
    EXPECT_TRUE(cfg.has_option("SYSTEM", "ver_servicepackmajor"));
    EXPECT_TRUE(cfg.has_option("SYSTEM", "VER_SERVICEPACKMAJOR"));
    EXPECT_EQ(cfg.get("SYSTEM", "MajorVersion").value_or("MISSING"), "10");

    // the commented duplicate KI_USER_SHARED_DATA line is a comment; active line wins
    EXPECT_EQ(cfg.get("OS64", "ki_user_shared_data").value_or("MISSING"), "0x7ffe0000");

    EXPECT_EQ(cfg.get("SYSTEM", "computername").value_or("MISSING"), "qilingpc");
    EXPECT_EQ(cfg.get("USER", "username").value_or("MISSING"), "Qiling");
    EXPECT_EQ(cfg.get("PATH", "windir").value_or("MISSING"), "Windows");
    EXPECT_EQ(cfg.get("PROCESSES", "csrss.exe").value_or("MISSING"), "1239");
}

TEST(IniConfig, ParsesLinuxProfile) {
    qiling::IniConfig cfg;
    ASSERT_TRUE(cfg.read(profile("linux.ql")));

    for (const char* section : {"CODE", "OS64", "OS32", "KERNEL", "MISC", "NETWORK"}) {
        EXPECT_TRUE(cfg.has_section(section)) << "missing section: " << section;
    }
    EXPECT_EQ(cfg.get("KERNEL", "uid").value_or("MISSING"), "1000");
    EXPECT_EQ(cfg.get("KERNEL", "gid").value_or("MISSING"), "1000");
    EXPECT_EQ(cfg.get("MISC", "current_path").value_or("MISSING"), "/");
    EXPECT_EQ(cfg.get("NETWORK", "bindtolocalhost").value_or("MISSING"), "True");
    EXPECT_EQ(cfg.get("NETWORK", "ipv6").value_or("MISSING"), "False");
    EXPECT_EQ(cfg.get("OS64", "load_address").value_or("MISSING"), "0x555555554000");
}

TEST(IniConfig, GetIntUsesBase0Conversion) {
    // mirrors profile_setup's int_converter = partial(int, base=0)
    qiling::IniConfig cfg;
    ASSERT_TRUE(cfg.read(profile("windows.ql")));
    EXPECT_EQ(cfg.get_int("OS64", "heap_address"), 0x500000000LL);
    EXPECT_EQ(cfg.get_int("OS64", "heap_size"), 0x5000000LL);
    EXPECT_EQ(cfg.get_int("OS32", "heap_address"), 0x5000000LL);
    EXPECT_EQ(cfg.get_int("CODE", "ram_size"), 0xa00000LL);
    EXPECT_EQ(cfg.get_int("SYSTEM", "majorversion"), 10);
    EXPECT_EQ(cfg.get_int("KERNEL", "pid"), 1996);

    qiling::IniConfig lcfg;
    ASSERT_TRUE(lcfg.read(profile("linux.ql")));
    EXPECT_EQ(lcfg.get_int("CODE", "ram_size"), 0xa00000LL);
    EXPECT_EQ(lcfg.get_int("KERNEL", "uid"), 1000);
}

TEST(IniConfig, StrictParsingRejectsMalformedInput) {
    qiling::IniConfig cfg;
    EXPECT_THROW(cfg.read_string("[A]\n[A]\nx = 1\n"), qiling::QlErrorBase);      // duplicate section
    EXPECT_THROW(cfg.read_string("[A]\nx = 1\nx = 2\n"), qiling::QlErrorBase);    // duplicate option (strict)
    EXPECT_THROW(cfg.read_string("x = 1\n"), qiling::QlErrorBase);                // option before any section
    EXPECT_THROW(cfg.read_string("[A\nx = 1\n"), qiling::QlErrorBase);            // unterminated section header
    EXPECT_THROW(cfg.read_string("[A]\ngarbage line\n"), qiling::QlErrorBase);    // unparsable line (documented deviation: no continuations)
    EXPECT_THROW(cfg.read_string("[A]\n= novaluekey\n"), qiling::QlErrorBase);    // empty option name
}

TEST(IniConfig, EmptyValuesAndColonDelimiter) {
    qiling::IniConfig cfg;
    cfg.read_string("[S]\nempty =\nspaced =    \nkey: colon value\n");
    EXPECT_TRUE(cfg.has_option("S", "empty"));
    EXPECT_EQ(cfg.get("S", "empty").value_or("MISSING"), "");
    EXPECT_EQ(cfg.get("S", "spaced").value_or("MISSING"), "");
    EXPECT_EQ(cfg.get("S", "key").value_or("MISSING"), "colon value");
}

TEST(IniConfig, MissingFileIsIgnoredLikeConfigparserRead) {
    qiling::IniConfig cfg;
    EXPECT_FALSE(cfg.read(profile("does_not_exist.ql")));
}

TEST(IniConfig, SectionLookupIsCaseSensitive) {
    qiling::IniConfig cfg;
    cfg.read_string("[Section]\nkey = value\n");
    EXPECT_TRUE(cfg.has_section("Section"));
    EXPECT_FALSE(cfg.has_section("section"));
    EXPECT_THROW(static_cast<void>(cfg.get("section", "key")), qiling::QlErrorBase);  // NoSectionError analogue
    EXPECT_FALSE(cfg.get("Section", "nosuchkey").has_value());
    EXPECT_THROW(static_cast<void>(cfg.get_int("Section", "nosuchkey")), qiling::QlErrorBase);  // NoOptionError analogue
}

TEST(IniConfig, GetIntMalformedValueThrowsInvalidArgument) {
    // mirrors ValueError from int(v, 0) surfacing through the getint converter
    qiling::IniConfig cfg;
    cfg.read_string("[S]\nbad = not_a_number\n");
    EXPECT_THROW(static_cast<void>(cfg.get_int("S", "bad")), std::invalid_argument);
}
