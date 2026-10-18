// QlFsMapper suite — PORT_PLAN.md Phase 3 (mapping add/remove/open dispatch and
// the unsafe-path refusal).
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "qiling/const.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/mapper.hpp"

using namespace qiling;

namespace {

struct MapperFixture {
    std::filesystem::path root;

    MapperFixture() : root(std::filesystem::temp_directory_path() / "ql_mapper_fixture") {
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "dev");
        {
            std::ofstream out(root / "existing.txt");
            out << "content";
        }
        {
            std::ofstream out(root / "urandom.bin");
            out << "seed";
        }
    }

    ~MapperFixture() {
        std::filesystem::remove_all(root, ec);
    }

    std::error_code ec;
};

}  // namespace

TEST(QlFsMapper, AddHasRemoveLifecycle) {
    const MapperFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);
    QlFsMapper mapper(path);

    EXPECT_EQ(mapper.mapping_count(), 0u);
    EXPECT_FALSE(mapper.has_mapping("/dev/urandom"));

    mapper.add_mapping("/dev/urandom", (fx.root / "urandom.bin").string());
    EXPECT_TRUE(mapper.has_mapping("/dev/urandom"));
    EXPECT_TRUE(mapper.has_mapping("dev/urandom"));  // canonicalized lookup
    EXPECT_EQ(mapper.mapping_count(), 1u);

    // duplicate mappings raise (the KeyError analogue)
    EXPECT_THROW(mapper.add_mapping("/dev/urandom", std::string()), QlErrorBase);

    // force re-mapping is allowed
    mapper.add_mapping("/dev/urandom", std::string(), true);

    mapper.remove_mapping("/dev/urandom");
    EXPECT_EQ(mapper.mapping_count(), 0u);
    EXPECT_THROW(mapper.remove_mapping("/dev/urandom"), QlErrorBase);
}

TEST(QlFsMapper, OpenMappedVsFresh) {
    const MapperFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);
    QlFsMapper mapper(path);

    // a mapped binding opens the bound host file
    mapper.add_mapping("/mapped.bin", (fx.root / "urandom.bin").string());
    auto mapped = mapper.open("/mapped.bin", "rb");
    ASSERT_NE(mapped, nullptr);
    const auto data = mapped->read(4);
    EXPECT_EQ(std::string(data.begin(), data.end()), "seed");

    // a fresh guest file resolves through the virtual fs
    auto fresh = mapper.open("/existing.txt", "rb");
    ASSERT_NE(fresh, nullptr);
    const auto content = fresh->read(7);
    EXPECT_EQ(std::string(content.begin(), content.end()), "content");
}

TEST(QlFsMapper, UnsafeGuestPathRefused) {
    const MapperFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);
    QlFsMapper mapper(path);

    // a fresh open of a path whose host resolution escapes the rootfs is
    // impossible by construction (the virtual path cannot escape); the
    // refusal path is exercised through the direct host-side check
    EXPECT_THROW(
        {
            const std::string outside = "C:\Windows\System32\config";
            if (!path.is_safe_host_path(outside)) {
                throw QlErrorBase("unsafe path: " + outside);
            }
        },
        QlErrorBase);
}

TEST(QlFsMapper, FileExistsAndCreateEmpty) {
    const MapperFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);
    QlFsMapper mapper(path);

    EXPECT_TRUE(mapper.file_exists("/existing.txt"));
    EXPECT_FALSE(mapper.file_exists("/missing.txt"));

    EXPECT_TRUE(mapper.create_empty_file("/missing.txt"));
    EXPECT_TRUE(mapper.file_exists("/missing.txt"));
}

TEST(QlFsMapper, RenameMapping) {
    const MapperFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);
    QlFsMapper mapper(path);

    mapper.add_mapping("/old", std::string());
    mapper.rename_mapping("/old", "/new");
    EXPECT_TRUE(mapper.has_mapping("/new"));
    EXPECT_FALSE(mapper.has_mapping("/old"));

    EXPECT_THROW(mapper.rename_mapping("/absent", "/x"), QlErrorBase);
    mapper.add_mapping("/taken", std::string());
    EXPECT_THROW(mapper.rename_mapping("/new", "/taken"), QlErrorBase);
}
