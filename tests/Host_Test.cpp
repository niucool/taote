// Host suite — PORT_PLAN.md §10 Phase 2 (the qiling/host.py surface).
#include <gtest/gtest.h>

#include "qiling/host.hpp"

using namespace qiling;

TEST(QlHost, OsMatchesPlatform) {
    QlHost host;
    const auto os = host.os();

#if defined(_WIN32)
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::WINDOWS);
#elif defined(__APPLE__)
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::MACOS);
#elif defined(__linux__)
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::LINUX);
#endif

    // cached: a second query returns the same value
    EXPECT_EQ(host.os(), os);
}

TEST(QlHost, ArchMatchesPlatform) {
    QlHost host;
    const auto arch = host.arch();

#if defined(_M_X64) || defined(__x86_64__)
    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::X8664);
#elif defined(_M_ARM64) || defined(__aarch64__)
    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::ARM64);
#endif

    EXPECT_EQ(host.arch(), arch);
}
