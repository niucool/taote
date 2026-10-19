// QlOsPath suite — PORT_PLAN.md §5.6 / Phase 3 exit criteria (the traversal
// test pass: `..`, absolute-guest escapes and symlinks stay inside the rootfs).
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "qiling/const.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/path.hpp"

using namespace qiling;

namespace {

// a rootfs fixture: root/bin/a.txt, root/var/tmp, plus a symlink escape when
// the host supports creating one
struct PathFixture {
    std::filesystem::path root;

    PathFixture() : root(std::filesystem::temp_directory_path() / "ql_path_fixture") {
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "bin");
        std::filesystem::create_directories(root / "var" / "tmp");
        {
            std::ofstream out(root / "bin" / "a.txt");
            out << "hello";
        }

        std::error_code ec;
        std::filesystem::create_directory_symlink("..", root / "var" / "escape", ec);
        symlink_ok = !ec;
    }

    ~PathFixture() {
        std::filesystem::remove_all(root, ec_storage);
    }

    bool symlink_ok = false;
    std::error_code ec_storage;
};

}  // namespace

TEST(QlOsPath, PosixAbsolutePathOfRelativePaths) {
    const PathFixture fx;
    QlOsPath path(fx.root.string(), "/tmp", QL_OS::LINUX);

    EXPECT_EQ(path.virtual_abspath("file.txt"), "/tmp/file.txt");
    // pathlib keeps mid-path parent refs (only leading ones are stripped)
    EXPECT_EQ(path.virtual_abspath("sub/../other"), "/tmp/sub/../other");
}

TEST(QlOsPath, ParentRefsCirculateBackToRoot) {
    const PathFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);

    // referencing root's parent directory circles back to root (path.py
    // __strip_parent_refs)
    EXPECT_EQ(path.virtual_abspath("../../etc/passwd"), "/etc/passwd");
    EXPECT_EQ(path.virtual_abspath("../../../deep/path"), "/deep/path");
}

TEST(QlOsPath, WindowsFlavorPaths) {
    const PathFixture fx;
    QlOsPath path(fx.root.string(), "C:\Windows", QL_OS::WINDOWS);

    EXPECT_TRUE(path.is_virtual_abspath("C:\Program Files"));
    EXPECT_FALSE(path.is_virtual_abspath("Program Files"));
    EXPECT_EQ(path.virtual_abspath("Program Files"), "C:/Windows/Program Files");
    // pathlib keeps the parent refs behind the cwd component (they resolve
    // later, during virtual_to_host_path); only leading refs are stripped
    EXPECT_EQ(path.virtual_abspath("' + b'..' + bs*2 + b'..' + bs*2 + b'..' + bs*2 + b'Boot"), "C:/Windows/' + b'..' + bs*2 + b'..' + bs*2 + b'..' + bs*2 + b'Boot");
}

TEST(QlOsPath, HostPathStaysInsideRootfs) {
    const PathFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);

    // a plain guest file maps inside rootfs
    const auto host = path.virtual_to_host_path("/bin/a.txt");
    EXPECT_EQ(host, (fx.root / "bin" / "a.txt").string());
    EXPECT_TRUE(path.is_safe_host_path(host));

    // an absolute guest path that climbs out of the rootfs stays inside:
    // the virtual path can never escape, so neither can the host path
    const auto host2 = path.virtual_to_host_path("../../../../../../etc/shadow");
    EXPECT_TRUE(path.is_safe_host_path(host2));

    // a host path outside rootfs is unsafe
    EXPECT_FALSE(path.is_safe_host_path("C:\Windows\System32"));
    EXPECT_FALSE(path.is_safe_host_path("/usr"));
}

TEST(QlOsPath, HostToVirtualRoundTrip) {
    const PathFixture fx;
    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);

    EXPECT_EQ(path.host_to_virtual_path((fx.root / "bin" / "a.txt").string()), "/bin/a.txt");
    EXPECT_THROW(path.host_to_virtual_path("C:\\outside"), QlErrorBase);
}

TEST(QlOsPath, SymlinkEscapeIsContained) {
    const PathFixture fx;
    if (!fx.symlink_ok) {
        GTEST_SKIP() << "symlink creation unavailable on this host";
    }

    QlOsPath path(fx.root.string(), "/", QL_OS::LINUX);

    // var/escape -> '..': resolving it keeps the host path inside rootfs
    const auto host = path.virtual_to_host_path("/var/escape/bin");
    EXPECT_TRUE(path.is_safe_host_path(host));
}
