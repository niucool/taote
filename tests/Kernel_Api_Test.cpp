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
#include "qiling/os/filestruct.hpp"
#include <fstream>
#include <iterator>

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
    const qiling::os::posix::ResolvedParams params{
        {"dest", addr}, {"c", 0xABull}, {"count", 8ull}};

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

    const qiling::os::posix::ResolvedParams params{
        {"ubuf", ubuf}, {"kbuf", kbuf}, {"count", 4ull}};

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

    const qiling::os::posix::ResolvedParams params{
        {"str", addr}};

    const auto result = entry->handler(ql, 0, params);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, msg_len);
}

// hook_printk: the level-tagged format renders through the printf engine; the
// variadic args pull through the fcall ellipsis slots (rsi = the first
// vararg on the amd64 cc)
TEST(KernelApiHandlers, PrintkRendersFormatWithArgs) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    // the captured stdout file
    const auto cap_path = rootfs / "printk_cap.txt";
    auto captured = qiling::QlFile::open_mode(cap_path.string(), "w+");
    ql.os().set_stdout(captured);

    constexpr std::uint64_t fmt_addr = 0x1002000;
    const std::string fmt = "<4>count %d hex %x";
    ql.mem().write(fmt_addr, std::vector<std::uint8_t>{fmt.begin(), fmt.end()});
    ql.mem().write(fmt_addr + fmt.size(), std::vector<std::uint8_t>{0});

    // the varargs: rsi = 42 (the %d), rdx = 0xBEEF (the %x)
    ql.arch().regs().write("rsi", 42);
    ql.arch().regs().write("rdx", 0xBEEF);

    const auto* entry = KernelApiRegistry::instance().find("printk");
    ASSERT_NE(entry, nullptr);

    const qiling::os::posix::ResolvedParams params{
        {"format", fmt_addr}};

    const auto result = entry->handler(ql, 0, params);
    ASSERT_TRUE(result.has_value());

    // the return: the rendered length (the upstream count); the upstream
    // format[2:] strip keeps the '>' (the <4> prefix loses two chars, verbatim)
    const std::string expected = "KERN_WARNING >count 42 hex beef";
    EXPECT_EQ(*result, expected.size());

    // the stdout carries the level-tagged rendering
    captured->close();
    std::ifstream in(cap_path, std::ios::binary);
    const std::string got{(std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()};
    EXPECT_EQ(got, expected);
}

// the resolver machinery: the placeholder-typed params (the STRING alias)
// resolve onto the string readers through the os.py resolvers table; the
// plain-int entries stay raw and the zero pointer resolves to the raw int
// (the `ptr and` guard, verbatim)
TEST(KernelApiResolve, StringPlaceholderResolvesThroughResolvers) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs4";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    constexpr std::uint64_t str_addr = 0x1002000;
    const std::string guest = "resolved-by-resolver";
    ql.mem().write(str_addr, std::vector<std::uint8_t>{guest.begin(), guest.end()});
    ql.mem().write(str_addr + guest.size(), std::vector<std::uint8_t>{0});

    const qiling::os::posix::KernelApiParams proto{{"fmt", qiling::os::posix::K_STRING}, {"count", qiling::os::posix::K_SIZE_T}};
    const std::vector<std::uint64_t> raw{str_addr, 7};

    const auto resolved = ql.os().resolve_named_params(proto, raw);
    ASSERT_EQ(resolved.size(), 2u);

    // the STRING entry carries the guest string
    const auto* str_value = std::get_if<std::string>(&resolved[0].second);
    ASSERT_NE(str_value, nullptr);
    EXPECT_EQ(*str_value, guest);

    // the plain-int entry stays raw
    const auto* int_value = std::get_if<std::uint64_t>(&resolved[1].second);
    ASSERT_NE(int_value, nullptr);
    EXPECT_EQ(*int_value, 7u);
}

TEST(KernelApiResolve, ZeroStringPointerStaysRaw) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs5";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    const qiling::os::posix::KernelApiParams proto{{"fmt", qiling::os::posix::K_STRING}};
    const std::vector<std::uint64_t> raw{0};

    // os.py: `ptr and read_cstring(ptr)` - the null pointer resolves to the
    // raw int, no read
    const auto resolved = ql.os().resolve_named_params(proto, raw);
    ASSERT_EQ(resolved.size(), 1u);
    const auto* int_value = std::get_if<std::uint64_t>(&resolved[0].second);
    ASSERT_NE(int_value, nullptr);
    EXPECT_EQ(*int_value, 0u);
}

// the end-to-end dispatch: the string handler receives the RESOLVED string
// (not the pointer) when invoked through the fcall layer
TEST(KernelApiResolve, StrlenViaFcallReceivesResolvedString) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_kapi_rootfs6";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    const char* msg = "dispatch-resolved";
    const std::string guest{msg};
    constexpr std::uint64_t addr = 0x1002000;
    ql.mem().write(addr, std::vector<std::uint8_t>{guest.begin(), guest.end()});
    ql.mem().write(addr + guest.size(), std::vector<std::uint8_t>{0});

    // the dispatch path: the resolve reads through the fcall layer (the rdi
    // slot carries the string pointer), the handler sees the string
    ql.arch().regs().write("rdi", addr);
    const auto* entry = KernelApiRegistry::instance().find("strlen");
    ASSERT_NE(entry, nullptr);

    const auto resolved = ql.os().resolve_named_params(entry->params);
    ASSERT_EQ(resolved.size(), 1u);
    const auto* str_value = std::get_if<std::string>(&resolved[0].second);
    ASSERT_NE(str_value, nullptr);
    EXPECT_EQ(*str_value, guest);
}
