// Windows_Registry suite — the registry manager slice (os/windows/registry.py:
// RegConf diff store, RegistryManager read/write flows, QlWinStats access
// records). The hive-file parsing (the python-registry dependency) defers;
// RegHive's no-op write/create/delete semantics port verbatim.
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/stats.hpp"
#include "qiling/os/windows/registry.hpp"
#include "qiling/os/windows/windows.hpp"

using qiling::os::registry::RegConf;
using qiling::os::RegType;
using namespace qiling;

namespace {

std::filesystem::path ensure_dir(const std::string& name) {
    const auto base = std::filesystem::temp_directory_path() / name;
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    return base;
}

}  // namespace

// ---- RegConf: the json diff store ----

TEST(Registry, RegConfRoundTrip) {
    const auto dir = ensure_dir("ql_reg_conf");
    const auto fname = dir / "diff.json";

    RegConf conf(fname.string());
    EXPECT_FALSE(conf.exists("HKEY_CURRENT_USER\\Software\\Qiling"));

    conf.create("HKEY_CURRENT_USER\\Software\\Qiling");
    EXPECT_TRUE(conf.exists("HKEY_CURRENT_USER\\Software\\Qiling"));

    conf.write("HKEY_CURRENT_USER\\Software\\Qiling", "Version", static_cast<int>(RegType::RegSZ), "2.0");
    conf.write("HKEY_CURRENT_USER\\Software\\Qiling", "Magic", static_cast<int>(RegType::RegDWord), 42);

    const auto [sz_type, sz_value] = conf.read("HKEY_CURRENT_USER\\Software\\Qiling", "Version", static_cast<int>(RegType::RegSZ));
    EXPECT_EQ(sz_type, static_cast<int>(RegType::RegSZ));
    EXPECT_EQ(std::get<std::string>(*sz_value), "2.0");

    const auto [dw_type, dw_value] = conf.read("HKEY_CURRENT_USER\\Software\\Qiling", "Magic", static_cast<int>(RegType::RegDWord));
    EXPECT_EQ(dw_type, static_cast<int>(RegType::RegDWord));
    EXPECT_EQ(std::get<std::int64_t>(*dw_value), 42);

    // the unrecorded subkey reads back as (none, none)
    const auto [miss_type, miss_value] = conf.read("HKEY_CURRENT_USER\\Software\\Qiling", "Missing", static_cast<int>(RegType::RegSZ));
    EXPECT_FALSE(miss_type.has_value());
    EXPECT_FALSE(miss_value.has_value());

    conf.save(fname.string());

    // the reload round-trips through the json file
    RegConf reloaded(fname.string());
    EXPECT_TRUE(reloaded.exists("HKEY_CURRENT_USER\\Software\\Qiling"));
    const auto [rt_type, rt_value] = reloaded.read("HKEY_CURRENT_USER\\Software\\Qiling", "Version", static_cast<int>(RegType::RegSZ));
    EXPECT_EQ(std::get<std::string>(*rt_value), "2.0");

    // delete removes the subkey entry
    reloaded.delete_entry("HKEY_CURRENT_USER\\Software\\Qiling", "Magic");
    const auto [gone_type, gone_value] = reloaded.read("HKEY_CURRENT_USER\\Software\\Qiling", "Magic", static_cast<int>(RegType::RegDWord));
    EXPECT_FALSE(gone_type.has_value());
}

// ---- RegistryManager ----

TEST(Registry, ManagerWriteReadSaveThroughMem) {
    const auto rootfs = ensure_dir("ql_reg_mgr_rootfs");
    std::filesystem::create_directories(rootfs / "Windows" / "registry");

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};  // the shellcode path skips the hive-dir demand
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql{options};

    auto& manager = static_cast<os::windows::QlOsWindows&>(ql.os()).registry_manager();

    // stage a REG_SZ value in guest memory (the utf-8 narrow form)
    const std::string payload = "2.0";
    const std::uint64_t addr = 0x200000;
    ql.mem().map(addr, 0x1000);
    ql.mem().write(addr, std::vector<std::uint8_t>{payload.begin(), payload.end()});

    manager.write("HKEY_CURRENT_USER\\Software\\Qiling", "Version", static_cast<int>(RegType::RegSZ),
                  addr, payload.size(), false);

    const auto [type, value] = manager.read("HKEY_CURRENT_USER\\Software\\Qiling", "Version", static_cast<int>(RegType::RegSZ));
    ASSERT_TRUE(type.has_value());
    EXPECT_EQ(*type, static_cast<int>(RegType::RegSZ));
    EXPECT_EQ(std::get<std::string>(*value), "2.0");

    manager.save();

    // the diff file landed under the rootfs registry dir
    const auto diff = rootfs / "registry" / (ql.targetname() + "_diff.json");
    EXPECT_TRUE(std::filesystem::exists(diff));
}

TEST(Registry, ManagerMissingHiveDirRaises) {
    const auto rootfs = ensure_dir("ql_reg_mgr_nohive");

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    // the container path (no shellcode) demands the hive directory: the os
    // ctor's own manager raises during construction
    EXPECT_THROW((Qiling{options}), QlErrorFileNotFound);
}

TEST(Registry, AccessRecordsLandInWinStats) {
    const auto rootfs = ensure_dir("ql_reg_mgr_stats");
    std::filesystem::create_directories(rootfs / "Windows" / "registry");

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql{options};

    auto& manager = static_cast<os::windows::QlOsWindows&>(ql.os()).registry_manager();
    manager.exists("HKEY_CURRENT_USER\\Software\\Qiling");
    manager.read("HKEY_CURRENT_USER\\Software\\Qiling", "Version", static_cast<int>(RegType::RegSZ));

    const auto& stats = static_cast<const QlWinStats&>(ql.os().stats());
    const auto& accesses = stats.registry();
    EXPECT_EQ(accesses.count("HKEY_CURRENT_USER\\Software\\Qiling"), 1u);
    EXPECT_GE(accesses.at("HKEY_CURRENT_USER\\Software\\Qiling").size(), 2u);
}
