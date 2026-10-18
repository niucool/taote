// KernelApi handler suite — the registry surface + the functional handlers
// (kernel_api.py's memcpy/memset/kmalloc/strlen behaviour, exercised through
// the direct handler invocation).
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/posix/kernel_api.hpp"
#include "qiling/os/posix/posix.hpp"

using namespace qiling;
using qiling::os::posix::KernelApiRegistry;

namespace {

void seed_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

}  // namespace

TEST(KernelApiHandlers, RegistryCarriesUpstreamSurface) {
    // the kernel_api.py handler names verbatim
    EXPECT_NE(KernelApiRegistry::instance().find("kmalloc"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("kfree"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("memcpy"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("memset"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("_copy_to_user"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("_copy_from_user"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("strlen"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("strstr"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("proc_create"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("prepare_creds"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("__x86_indirect_thunk_rax"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("sys_read"), nullptr);

    // the thunk thunks are passthru
    EXPECT_TRUE(KernelApiRegistry::instance().find("__x86_indirect_thunk_rax")->passthru);

    // the prepare_creds non-NULL creds constant
    const auto* creds = KernelApiRegistry::instance().find("prepare_creds");
    ASSERT_NE(creds, nullptr);
}

TEST(KernelApiHandlers, MemsetHandlerWritesBytes) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    constexpr std::uint64_t addr = 0x1002000;
    ql.mem().write(addr, std::vector<std::uint8_t>(8, 0));

    const auto* entry = KernelApiRegistry::instance().find("memset");
    ASSERT_NE(entry, nullptr);

    const std::uint64_t pc = 0;
    const std::vector<std::pair<std::string, std::uint64_t>> params{
        {"dest", addr}, {"c", 0xAB}, {"count", 8}};

    const auto result = entry->handler(ql, pc, params);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, addr);

    const auto got = ql.mem().read(addr, 8);
    for (const auto byte : got) {
        EXPECT_EQ(byte, 0xAB);
    }
}

TEST(KernelApiHandlers, CopyToUserHandlerMarshals) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs2";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    // the kernel-side buffer carries the marker; the user buffer is mapped
    constexpr std::uint64_t kbuf = 0x1002000;
    constexpr std::uint64_t ubuf = 0x1002100;
    ql.mem().write(kbuf, std::vector<std::uint8_t>{'H', 'I', '!', 0});
    ql.mem().write(ubuf, std::vector<std::uint8_t>(4, 0));

    const auto* entry = KernelApiRegistry::instance().find("_copy_to_user");
    ASSERT_NE(entry, nullptr);

    const std::vector<std::pair<std::string, std::uint64_t>> params{
        {"ubuf", ubuf}, {"kbuf", kbuf}, {"count", 4}};

    const auto result = entry->handler(ql, 0, params);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0);

    const auto got = ql.mem().read(ubuf, 4);
    EXPECT_EQ(got[0], 'H');
    EXPECT_EQ(got[1], 'I');
    EXPECT_EQ(got[2], '!');
}

TEST(KernelApiHandlers, StrlenHandlerCountsGuestString) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs3";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    const char* msg = "hello kernel";
    const std::size_t msg_len = 12;
    constexpr std::uint64_t addr = 0x1002000;
    ql.mem().write(addr, std::vector<std::uint8_t>{msg, msg + msg_len + 1});

    const auto* entry = KernelApiRegistry::instance().find("strlen");
    ASSERT_NE(entry, nullptr);

    const std::vector<std::pair<std::string, std::uint64_t>> params{
        {"str", addr}};

    const auto result = entry->handler(ql, 0, params);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, msg_len);
}
