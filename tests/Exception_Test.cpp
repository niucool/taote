// Exception suite — PORT_PLAN.md §10 Phase 0 (the QlError* hierarchy ported
// verbatim from qiling/exception.py, including the QlSyscallError rendering).
#include <gtest/gtest.h>

#include <string>
#include <type_traits>

#include "qiling/exception.hpp"

TEST(QlError, DerivedCatchableAsBase) {
    try {
        throw qiling::QlErrorFileNotFound("no such file: /rootfs/bin/hello");
    } catch (const qiling::QlErrorBase& e) {
        EXPECT_STREQ(e.what(), "no such file: /rootfs/bin/hello");
        SUCCEED();
        return;
    }
    FAIL() << "not caught as QlErrorBase";
}

TEST(QlError, CatchableAsStdException) {
    try {
        throw qiling::QlErrorNotImplemented("sys_socket");
    } catch (const std::exception& e) {
        EXPECT_STREQ(e.what(), "sys_socket");
        SUCCEED();
        return;
    }
    FAIL() << "not caught as std::exception";
}

TEST(QlError, MessageCarriesThroughWhat) {
    EXPECT_STREQ(qiling::QlErrorOsType("unknown os").what(), "unknown os");
    EXPECT_STREQ(qiling::QlErrorArch("bad arch").what(), "bad arch");
    EXPECT_STREQ(qiling::QlMemoryMappedError("overlap").what(), "overlap");
}

TEST(QlError, SyscallErrorRendersErrnoPrefixVerbatim) {
    // exception.py __str__: "[ Errno " + str(self.errno) + "] " + self.msg
    const qiling::QlSyscallError e(13, "Permission denied");
    EXPECT_STREQ(e.what(), "[ Errno 13] Permission denied");
    EXPECT_EQ(e.errno_value(), 13);
}

TEST(QlError, SyscallErrorCatchableAsBase) {
    try {
        throw qiling::QlSyscallError(2, "No such file or directory");
    } catch (const qiling::QlErrorBase& e) {
        EXPECT_STREQ(e.what(), "[ Errno 2] No such file or directory");
        SUCCEED();
        return;
    }
    FAIL() << "not caught as QlErrorBase";
}

TEST(QlError, HierarchyShapesAreVerbatim) {
    // exception.py defines both QlErrorSyscallError (plain subclass) and
    // QlSyscallError (errno-carrying); both carry over.
    EXPECT_TRUE((std::is_base_of_v<qiling::QlErrorBase, qiling::QlErrorSyscallError>));
    EXPECT_TRUE((std::is_base_of_v<qiling::QlErrorBase, qiling::QlSyscallError>));
    EXPECT_TRUE((std::is_base_of_v<qiling::QlErrorBase, qiling::QlErrorNotImplemented>));
    EXPECT_TRUE((std::is_base_of_v<std::runtime_error, qiling::QlErrorBase>));
    EXPECT_TRUE((std::is_base_of_v<std::exception, qiling::QlErrorBase>));
}

TEST(QlError, PlainSubclassesInheritConstructors) {
    // `using QlErrorBase::QlErrorBase` — construct from std::string and from literal
    EXPECT_STREQ(qiling::QlErrorModuleNotFound(std::string("m1")).what(), "m1");
    EXPECT_STREQ(qiling::QlErrorJsonDecode("bad json").what(), "bad json");
}
