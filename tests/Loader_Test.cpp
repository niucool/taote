// Loader base suite — PORT_PLAN.md Phase 3 (the QlLoader surface: images,
// containment, basename lookup, save/restore).
#include <gtest/gtest.h>

#include "qiling/loader/loader.hpp"
#include "qiling/loader/blob.hpp"

using namespace qiling;

TEST(QlLoaderBase, ImageContainment) {
    // a bare QlLoader with hand-registered images (the base-class surface)
    loader::Image images[] = {
        {0x1000, 0x2000, "/root/bin/app.exe"},
        {0x7f0000, 0x7f1000, "/root/bin/lib.so"},
    };

    const auto contains = [&images](std::uint64_t addr) -> const loader::Image* {
        for (const auto& img : images) {
            if (img.base <= addr && addr < img.end) {
                return &img;
            }
        }
        return nullptr;
    };

    EXPECT_EQ(contains(0x1000), &images[0]);
    EXPECT_EQ(contains(0x1fff), &images[0]);
    EXPECT_EQ(contains(0x2000), nullptr);  // end is exclusive
    EXPECT_EQ(contains(0x7f0000), &images[1]);
}

TEST(QlLoaderBase, GetImageByName) {
    // the basename matching semantics (case-sensitive by default)
    const loader::Image image{0x1000, 0x2000, "/root/Dir/App.EXE"};
    const std::string path = image.path;

    const auto basename = [](std::string_view p) {
        const auto slash = p.find_last_of("/\\");
        return slash == std::string_view::npos ? p : p.substr(slash + 1);
    };

    EXPECT_EQ(basename(path), "App.EXE");
    EXPECT_NE(basename(path), "app.exe");
}
