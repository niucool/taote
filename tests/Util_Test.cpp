// Util suite — PORT_PLAN.md §10 Phase 0 tests (qiling/utils.py Phase 0 subset:
// string helpers + name->enum conversions, mirroring const.py's casefolded maps).
#include <gtest/gtest.h>

#include <optional>
#include <stdexcept>
#include <string>

#include "qiling/utils.hpp"

namespace {

template <typename E>
std::optional<E> some(E value) {
    return value;
}

}  // namespace

TEST(UtilConvert, OsConvert) {
    using qiling::QL_OS;
    EXPECT_EQ(qiling::os_convert("Linux"), some(QL_OS::LINUX));
    EXPECT_EQ(qiling::os_convert("LINUX"), some(QL_OS::LINUX));
    EXPECT_EQ(qiling::os_convert("windows"), some(QL_OS::WINDOWS));
    EXPECT_EQ(qiling::os_convert("macos"), some(QL_OS::MACOS));
    EXPECT_EQ(qiling::os_convert("darwin"), some(QL_OS::MACOS));   // alias (utils.py)
    EXPECT_EQ(qiling::os_convert("Darwin"), some(QL_OS::MACOS));   // alias, case-insensitive
    EXPECT_EQ(qiling::os_convert("qnx"), some(QL_OS::QNX));
    EXPECT_EQ(qiling::os_convert("bogus"), std::nullopt);
    EXPECT_EQ(qiling::os_convert(""), std::nullopt);
}

TEST(UtilConvert, ArchConvert) {
    using qiling::QL_ARCH;
    EXPECT_EQ(qiling::arch_convert("x86"), some(QL_ARCH::X86));
    EXPECT_EQ(qiling::arch_convert("X86"), some(QL_ARCH::X86));
    EXPECT_EQ(qiling::arch_convert("amd64"), some(QL_ARCH::X8664));   // alias (utils.py)
    EXPECT_EQ(qiling::arch_convert("x86_64"), some(QL_ARCH::X8664));  // alias (utils.py)
    EXPECT_EQ(qiling::arch_convert("riscv32"), some(QL_ARCH::RISCV));  // alias (utils.py)
    EXPECT_EQ(qiling::arch_convert("ARM"), some(QL_ARCH::ARM));
    EXPECT_EQ(qiling::arch_convert("ARM64"), some(QL_ARCH::ARM64));
    EXPECT_EQ(qiling::arch_convert("ppc"), some(QL_ARCH::PPC));
    EXPECT_EQ(qiling::arch_convert("riscv64"), some(QL_ARCH::RISCV64));
    EXPECT_EQ(qiling::arch_convert("nosucharch"), std::nullopt);
}

TEST(UtilConvert, DebuggerConvert) {
    using qiling::QL_DEBUGGER;
    EXPECT_EQ(qiling::debugger_convert("gdb"), some(QL_DEBUGGER::GDB));
    EXPECT_EQ(qiling::debugger_convert("GDB"), some(QL_DEBUGGER::GDB));
    EXPECT_EQ(qiling::debugger_convert("IDAPRO"), some(QL_DEBUGGER::IDAPRO));
    EXPECT_EQ(qiling::debugger_convert("qdb"), some(QL_DEBUGGER::QDB));
    EXPECT_EQ(qiling::debugger_convert("windbg"), std::nullopt);
}

TEST(UtilConvert, ArchOsConvert) {
    // const.py: arch_os_map has a single entry — CORTEX_M implies MCU
    EXPECT_EQ(qiling::arch_os_convert(qiling::QL_ARCH::CORTEX_M), some(qiling::QL_OS::MCU));
    EXPECT_EQ(qiling::arch_os_convert(qiling::QL_ARCH::X86), std::nullopt);
    EXPECT_EQ(qiling::arch_os_convert(qiling::QL_ARCH::X8664), std::nullopt);
    EXPECT_EQ(qiling::arch_os_convert(qiling::QL_ARCH::ARM64), std::nullopt);
}

TEST(UtilStrings, Trim) {
    EXPECT_EQ(qiling::trim("  a b  "), "a b");
    EXPECT_EQ(qiling::trim("\t\nhello\r\n"), "hello");
    EXPECT_EQ(qiling::trim("   "), "");
    EXPECT_EQ(qiling::trim(""), "");
    EXPECT_EQ(qiling::trim("plain"), "plain");
}

TEST(UtilStrings, Casefold) {
    EXPECT_EQ(qiling::ascii_casefold("HeLLo_X86"), "hello_x86");
    EXPECT_EQ(qiling::ascii_casefold(""), "");
}

TEST(UtilInt, Base0Parsing) {
    EXPECT_EQ(qiling::parse_int_base0("0"), 0);
    EXPECT_EQ(qiling::parse_int_base0("10"), 10);
    EXPECT_EQ(qiling::parse_int_base0("0x500000000"), 0x500000000LL);
    EXPECT_EQ(qiling::parse_int_base0("0X10"), 16);   // uppercase prefix
    EXPECT_EQ(qiling::parse_int_base0("-0x10"), -16);
    EXPECT_EQ(qiling::parse_int_base0("+0x10"), 16);
    EXPECT_EQ(qiling::parse_int_base0("0o17"), 15);
    EXPECT_EQ(qiling::parse_int_base0("0b1010"), 10);
    EXPECT_EQ(qiling::parse_int_base0("1_0"), 10);    // PEP 515 separators
    EXPECT_EQ(qiling::parse_int_base0("0x5_0"), 80);
    EXPECT_EQ(qiling::parse_int_base0(" 0x10 "), 16);  // surrounding whitespace tolerated
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("010")), std::invalid_argument);   // int('010', 0) -> ValueError
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("abc")), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("")), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("1_")), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("_1")), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("0x")), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(qiling::parse_int_base0("9223372036854775808")), std::invalid_argument);  // INT64_MAX + 1
    EXPECT_EQ(qiling::parse_int_base0("-9223372036854775808"), INT64_MIN);
}
