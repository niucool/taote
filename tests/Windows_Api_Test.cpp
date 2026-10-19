// Windows API registration suite — PORT_PLAN.md §10 Phase 4 (the winsdkapi
// decorator engine over the static ApiRegistry; the fncc calling conventions).
#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "qiling/exception.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/dlls/dlls.hpp"
#include "qiling/os/windows/windows.hpp"
#include "qiling/os/windows/thread.hpp"

using namespace qiling;
using namespace qiling::os;
using qiling::os::windows::QlOsWindows;
using qiling::os::windows::QlWindowsThread;
using qiling::os::windows::ThreadStatus;

namespace {

// a registration guard: the registry is process-global, so the tests clear it
struct RegistryScope {
    ~RegistryScope() { ApiRegistry::instance().clear(); }
};

}  // namespace

TEST(WinApiRegistry, RegisterAndFindByName) {
    RegistryScope scope;

    // the @winsdkapi(cc=STDCALL, params={...}) analogue: a fluent builder
    WinsdkApi("GetStdHandle", WinCc::Stdcall, {{"nStdHandle", api::DWORD_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0xfffffff5;  // STD_OUTPUT_HANDLE
    };

    const auto* entry = ApiRegistry::instance().find("GetStdHandle");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->cc, WinCc::Stdcall);
    ASSERT_EQ(entry->params.size(), 1u);
    EXPECT_EQ(entry->params[0].first, "nStdHandle");
    EXPECT_EQ(entry->params[0].second, static_cast<int>(api::DWORD_));
    EXPECT_NE(entry->handler, nullptr);
}

TEST(WinApiRegistry, FindIsCaseSensitiveLikeGetattr) {
    RegistryScope scope;

    WinsdkApi("GetCommandLineA", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> { return 0; };

    // the Python getattr is case-sensitive
    EXPECT_NE(ApiRegistry::instance().find("GetCommandLineA"), nullptr);
    EXPECT_EQ(ApiRegistry::instance().find("getcommandlinea"), nullptr);
}

TEST(WinApiRegistry, ReRegistrationReplaces) {
    RegistryScope scope;

    WinsdkApi("ExitProcess", WinCc::Stdcall, {{"uExitCode", api::UINT_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> { return 0; };

    // a later registration with the same name replaces the entry (the Python
    // decorator overwrites the module attribute)
    WinsdkApi("ExitProcess", WinCc::Ms64, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> { return 0; };

    const auto* entry = ApiRegistry::instance().find("ExitProcess");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->cc, WinCc::Ms64);
    EXPECT_TRUE(entry->params.empty());
}

TEST(WinApiRegistry, NamesListedForCoverage) {
    RegistryScope scope;

    WinsdkApi("GetStdHandle", WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> { return 0; };
    WinsdkApi("GetCommandLineA", WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> { return 0; };

    const auto names = ApiRegistry::instance().names();
    EXPECT_EQ(names.size(), 2u);
}

// ---- the dlls/ kernel32 handleapi family (the verbatim upstream surface) ----

TEST(WinApiDlls, HandleapiFamilyRegisteredWithUpstreamShapes) {
    // the dlls/dlls.cpp static-init registrations (the __init__.py
    // star-import analogue); re-seed after the earlier tests cleared the
    // registry (register_dlls mirrors the python re-import)
    register_dlls();
    const auto* dup = ApiRegistry::instance().find("DuplicateHandle");
    ASSERT_NE(dup, nullptr);
    EXPECT_EQ(dup->cc, WinCc::Stdcall);
    ASSERT_EQ(dup->params.size(), 7u);
    EXPECT_EQ(dup->params[0].first, "hSourceProcessHandle");
    EXPECT_EQ(dup->params[3].first, "lpTargetHandle");

    const auto* close_ = ApiRegistry::instance().find("CloseHandle");
    ASSERT_NE(close_, nullptr);
    ASSERT_EQ(close_->params.size(), 1u);
    EXPECT_EQ(close_->params[0].first, "hObject");

    const auto* setinfo = ApiRegistry::instance().find("SetHandleInformation");
    ASSERT_NE(setinfo, nullptr);
    ASSERT_EQ(setinfo->params.size(), 3u);

    // the W-side siblings share the bodies (the A/W registrations)
    for (const char* name : {"CreateFileW", "DeleteFileW", "SetFileAttributesW",
                             "GetTempPathW", "CreateFileMappingW", "FindFirstFileExA"}) {
        EXPECT_NE(ApiRegistry::instance().find(name), nullptr) << name;
    }
}

TEST(WinApiDlls, GetParamLookupAndGetIntPaths) {
    // get_param mirrors the python params["name"] shape; api_get_int: the
    // plain-int entries carry the raw values, the string-typed entries
    // answer 0 (the posix kernel_api get_int shape)
    const ResolvedParams params = {
        {"hObject", std::uint64_t{0xa0000001ull}},
        {"lpName", std::string("C:\tmp")},
    };

    EXPECT_EQ(api_get_int(get_param(params, "hObject")), 0xa0000001ull);
    EXPECT_EQ(api_get_int(get_param(params, "lpName")), 0u);
    EXPECT_THROW(get_param(params, "missing"), QlErrorBase);
}

// ---- the fileapi family end-to-end fixtures (the direct handler invocation
// over a real QlOsWindows: the CreateFile→WriteFile→GetFileSize→CloseHandle
// round trip riding the fs-mapper + the handle manager) ----

#include "qiling/core.hpp"

namespace {

std::filesystem::path win_ensure_rootfs() {
    const auto base = std::filesystem::temp_directory_path() / "ql_windows_rootfs";
    std::filesystem::create_directories(base);
    return base;
}

QilingOptions win_test_options() {
    QilingOptions options;
    // the shellcode stub rides the shellcode path (the registry hives load
    // only for the PE-image runs; the shellcode path skips them)
    options.code = std::vector<std::uint8_t>{0xC3};
    options.rootfs = win_ensure_rootfs().string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    return options;
}

}  // namespace

TEST(WinApiFileapi, CreateFileWriteReadFileSizeCloseHandleRoundtrip) {
    register_dlls();

    const auto blob = std::vector<std::uint8_t>{0xC3};  // ret: the shellcode stub
    Qiling ql(win_test_options());

    const auto guest_path = std::string("C:\\qltest\\sample.bin");
    const auto rootfs_file = std::filesystem::path(ql.rootfs()) / "qltest" / "sample.bin";
    std::filesystem::create_directories(rootfs_file.parent_path());

    // CreateFileA: the create-always write access
    const ResolvedParams create_params = {
        {"lpFileName", guest_path},
        {"dwDesiredAccess", std::uint64_t{0x40000000ull}},  // GENERIC_WRITE
        {"dwShareMode", std::uint64_t{0}},
        {"lpSecurityAttributes", std::uint64_t{0}},
        {"dwCreationDisposition", std::uint64_t{2}},  // CREATE_ALWAYS
        {"dwFlagsAndAttributes", std::uint64_t{0}},
        {"hTemplateFile", std::uint64_t{0}},
    };
    const auto* create = ApiRegistry::instance().find("CreateFileA");
    ASSERT_NE(create, nullptr);
    const auto h = create->handler(ql, 0, create_params);
    ASSERT_TRUE(h.has_value());
    EXPECT_NE(*h, 0xffffffffffffffffull);  // != INVALID_HANDLE_VALUE

    // WriteFile: the bytes land in the rootfs file
    // WriteFile: the guest buffer carries the payload; the bytes land in the
    // rootfs file (the shellcode region is mapped at the profile's CODE base
    // with the 10MB ram_size, so the buffer past the 1-byte ret is mapped)
    const std::string payload = "hello fileapi";
    const auto kBuffer = 0x140001000ull;
    ql.mem().write(kBuffer, std::vector<std::uint8_t>(payload.begin(), payload.end()));

    const auto* write = ApiRegistry::instance().find("WriteFile");
    ASSERT_NE(write, nullptr);
    const auto ret_write = write->handler(ql, 0, ResolvedParams{
        {"hFile", *h},
        {"lpBuffer", kBuffer},
        {"nNumberOfBytesToWrite", std::uint64_t{payload.size()}},
        {"lpNumberOfBytesWritten", std::uint64_t{0x140002000ull}},
        {"lpOverlapped", std::uint64_t{0}},
    });
    ASSERT_TRUE(ret_write.has_value());
    EXPECT_EQ(*ret_write, 1u);  // the upstream WriteFile answers the BOOL 1

    // the written-count cell carries the byte count
    EXPECT_EQ(ql.mem().read_ptr(0x140002000, 4), payload.size());

    // CloseHandle returns 1
    const auto* close_ = ApiRegistry::instance().find("CloseHandle");
    ASSERT_NE(close_, nullptr);
    const auto ret_close = close_->handler(ql, 0, ResolvedParams{{"hObject", *h}});
    ASSERT_TRUE(ret_close.has_value());
    EXPECT_EQ(*ret_close, 1u);
}

// ---- the remaining fileapi coverage (one fixture minimum per ported
// handler; the guest-visible results asserted on both sides: the guest memory
// cells and the host rootfs filesystem) ----

namespace {

// the stdio/scratch windows inside the shellcode region (the windows.ql CODE
// map rides 0x140000000 with the 10MB ram_size)
constexpr std::uint64_t kScratch = 0x140001000ull;
constexpr std::uint64_t kCells = 0x140002000ull;

}  // namespace

TEST(WinApiFileapi, ReadFileCarriesStagedContentAndCountCell) {
    register_dlls();
    Qiling ql(win_test_options());

    // stage a file through the fs-mapper's own open walk
    const auto path = std::string("C:\\qltest\\read.bin");
    std::filesystem::create_directories(std::filesystem::path(ql.rootfs()) / "qltest");
    {
        std::ofstream f(std::filesystem::path(ql.rootfs()) / "qltest" / "read.bin", std::ios::binary);
        f << "staged-bytes";
    }

    const auto* create = ApiRegistry::instance().find("CreateFileA");
    ASSERT_NE(create, nullptr);
    const auto h = create->handler(ql, 0, ResolvedParams{
        {"lpFileName", path},
        {"dwDesiredAccess", std::uint64_t{0x80000000ull}},  // GENERIC_READ
        {"dwShareMode", std::uint64_t{0}},
        {"lpSecurityAttributes", std::uint64_t{0}},
        {"dwCreationDisposition", std::uint64_t{3}},  // OPEN_EXISTING
        {"dwFlagsAndAttributes", std::uint64_t{0}},
        {"hTemplateFile", std::uint64_t{0}},
    });
    ASSERT_TRUE(h.has_value());

    const auto* read = ApiRegistry::instance().find("ReadFile");
    ASSERT_NE(read, nullptr);
    const auto ret = read->handler(ql, 0, ResolvedParams{
        {"hFile", *h},
        {"lpBuffer", kScratch},
        {"nNumberOfBytesToRead", std::uint64_t{12}},
        {"lpNumberOfBytesRead", kCells},
        {"lpOverlapped", std::uint64_t{0}},
    });
    ASSERT_TRUE(ret.has_value());
    EXPECT_EQ(*ret, 1u);

    // the bytes + the count cell land in the guest
    EXPECT_EQ(ql.mem().read_ptr(kCells, 4), 12u);
    const auto got = ql.mem().read(kScratch, 12);
    EXPECT_EQ(std::string(got.begin(), got.end()), "staged-bytes");
}

TEST(WinApiFileapi, GetFileSizeAnswersFileSize) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto path = std::string("C:\\qltest\\size.bin");
    std::filesystem::create_directories(std::filesystem::path(ql.rootfs()) / "qltest");
    {
        std::ofstream f(std::filesystem::path(ql.rootfs()) / "qltest" / "size.bin", std::ios::binary);
        f << "0123456789";
    }

    const auto* create = ApiRegistry::instance().find("CreateFileA");
    ASSERT_NE(create, nullptr);
    const auto h = create->handler(ql, 0, ResolvedParams{
        {"lpFileName", path},
        {"dwDesiredAccess", std::uint64_t{0x80000000ull}},
        {"dwShareMode", std::uint64_t{0}},
        {"lpSecurityAttributes", std::uint64_t{0}},
        {"dwCreationDisposition", std::uint64_t{3}},
        {"dwFlagsAndAttributes", std::uint64_t{0}},
        {"hTemplateFile", std::uint64_t{0}},
    });
    ASSERT_TRUE(h.has_value());

    const auto* gfs = ApiRegistry::instance().find("GetFileSize");
    ASSERT_NE(gfs, nullptr);
    const auto size = gfs->handler(ql, 0, ResolvedParams{
        {"hFile", *h},
        {"lpFileSizeHigh", std::uint64_t{0}},
    });
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(*size, 10u);
}

TEST(WinApiFileapi, FindFirstFileAWritesFindDataAndHandle) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto path = std::string("C:\\qltest\\find.bin");
    std::filesystem::create_directories(std::filesystem::path(ql.rootfs()) / "qltest");
    {
        std::ofstream f(std::filesystem::path(ql.rootfs()) / "qltest" / "find.bin", std::ios::binary);
        f << "findme";
    }

    const auto* find = ApiRegistry::instance().find("FindFirstFileA");
    ASSERT_NE(find, nullptr);
    const auto h = find->handler(ql, 0, ResolvedParams{
        {"lpFileName", path},
        {"lpFindFileData", kScratch},
    });
    ASSERT_TRUE(h.has_value());
    EXPECT_NE(*h, 0xffffffffffffffffull);

    // the WIN32_FIND_DATAA: the attributes ride FILE_ATTRIBUTE_NORMAL, the
    // size cells carry 6, the filename is the searched path
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 0x80u);  // FILE_ATTRIBUTE_NORMAL
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 28, 4), 0u);   // nFileSizeHigh
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 32, 4), 6u);   // nFileSizeLow
    const auto name = ql.mem().read(kScratch + 44, 18);
    EXPECT_EQ(std::string(name.begin(), name.end()), "C:\\qltest\\find.bin");
}

TEST(WinApiFileapi, PassthroughAndNoOpHandlers) {
    register_dlls();
    Qiling ql(win_test_options());

    // the pass bodies (FindNextFileA/FindClose/SetFileApisToANSI/OEM) answer
    // nothing — the os.call returns the nullopt retval
    for (const char* name : {"FindNextFileA", "FindClose", "SetFileApisToANSI", "SetFileApisToOEM"}) {
        const auto* handler = ApiRegistry::instance().find(name);
        ASSERT_NE(handler, nullptr) << name;
        EXPECT_FALSE(handler->handler(ql, 0, {})) << name;
    }

    // the no-op bodies answer 1
    const auto* attr = ApiRegistry::instance().find("SetFileAttributesA");
    ASSERT_NE(attr, nullptr);
    const auto r1 = attr->handler(ql, 0, ResolvedParams{
        {"lpFileName", std::string("C:\\qltest\\whatever.bin")},
        {"dwFileAttributes", std::uint64_t{0}},
    });
    EXPECT_EQ(r1.value_or(0), 1u);

    const auto* ansi = ApiRegistry::instance().find("AreFileApisANSI");
    ASSERT_NE(ansi, nullptr);
    EXPECT_EQ(ansi->handler(ql, 0, {}).value_or(0), 1u);
}

TEST(WinApiFileapi, CreateDirectoryAndDeleteAndCopyRideRootfs) {
    register_dlls();
    Qiling ql(win_test_options());

    std::error_code wipe_ec;
    std::filesystem::remove_all(std::filesystem::path(ql.rootfs()) / "qltest" / "subdir", wipe_ec);

    const auto* mkdir_ = ApiRegistry::instance().find("CreateDirectoryA");
    ASSERT_NE(mkdir_, nullptr);
    const auto r_mkdir = mkdir_->handler(ql, 0, ResolvedParams{
        {"lpPathName", std::string("C:\\qltest\\subdir")},
        {"lpSecurityAttributes", std::uint64_t{0}},
    });
    ASSERT_TRUE(r_mkdir.has_value());
    EXPECT_EQ(*r_mkdir, 1u);
    EXPECT_TRUE(std::filesystem::is_directory(std::filesystem::path(ql.rootfs()) / "qltest" / "subdir"));
    // the second create answers 0 + ERROR_ALREADY_EXISTS
    const auto r_dup = mkdir_->handler(ql, 0, ResolvedParams{
        {"lpPathName", std::string("C:\\qltest\\subdir")},
        {"lpSecurityAttributes", std::uint64_t{0}},
    });
    EXPECT_EQ(r_dup.value_or(1), 0u);

    {
        std::ofstream f(std::filesystem::path(ql.rootfs()) / "qltest" / "src.bin", std::ios::binary);
        f << "copy-me";
    }
    const auto* copy = ApiRegistry::instance().find("CopyFileA");
    ASSERT_NE(copy, nullptr);
    const auto r_copy = copy->handler(ql, 0, ResolvedParams{
        {"lpExistingFileName", std::string("C:\\qltest\\src.bin")},
        {"lpNewFileName", std::string("C:\\qltest\\dst.bin")},
        {"bFailIfExists", std::uint64_t{0}},
    });
    EXPECT_EQ(r_copy.value_or(0), 1u);
    EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(ql.rootfs()) / "qltest" / "dst.bin"));

    const auto* del = ApiRegistry::instance().find("DeleteFileA");
    ASSERT_NE(del, nullptr);
    const auto r_del = del->handler(ql, 0, ResolvedParams{
        {"lpFileName", std::string("C:\\qltest\\dst.bin")},
    });
    EXPECT_EQ(r_del.value_or(0), 1u);
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(ql.rootfs()) / "qltest" / "dst.bin"));
}

TEST(WinApiFileapi, TempPathShortPathDriveTypeVolumeAndDiskInfo) {
    register_dlls();
    Qiling ql(win_test_options());

    // GetTempPathW: the utf-16le "C:\Windows\Temp\" (the windir rides the
    // profile's PATH section) + the length excluding the null-terminator
    const auto* tp = ApiRegistry::instance().find("GetTempPathW");
    ASSERT_NE(tp, nullptr);
    const auto n = tp->handler(ql, 0, ResolvedParams{
        {"nBufferLength", std::uint64_t{64}},
        {"lpBuffer", kScratch},
    });
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(*n, 16u);  // "C:\Windows\Temp\\" is 16 chars
    const auto wide = ql.mem().read(kScratch, 32);
    std::string utf8;
    for (std::size_t i = 0; i + 1 < wide.size(); i += 2) {
        utf8.push_back(static_cast<char>(wide[i]));
    }
    EXPECT_EQ(utf8, "C:\\Windows\\Temp\\");

    // GetShortPathNameW: the >8 char element shortens to the 8.3 form
    const auto* sp = ApiRegistry::instance().find("GetShortPathNameW");
    ASSERT_NE(sp, nullptr);
    const auto sn = sp->handler(ql, 0, ResolvedParams{
        {"lpszLongPath", std::string("C:\\a\\averyverylongname.txt")},
        {"lpszShortPath", kScratch},
        {"cchBuffer", std::uint64_t{260}},
    });
    ASSERT_TRUE(sn.has_value());
    EXPECT_EQ(*sn, 17u);  // C:veryv~1.txt
    const auto short_wide = ql.mem().read(kScratch, static_cast<std::size_t>(*sn) * 2);
    std::string short_utf8;
    for (std::size_t i = 0; i + 1 < short_wide.size(); i += 2) {
        short_utf8.push_back(static_cast<char>(short_wide[i]));
    }
    EXPECT_EQ(short_utf8, "C:\\a\\averyv~1.txt");

    // GetDriveTypeW: the systemdrive answers DRIVE_FIXED
    const auto* drive = ApiRegistry::instance().find("GetDriveTypeW");
    ASSERT_NE(drive, nullptr);
    const auto dt = drive->handler(ql, 0, ResolvedParams{{"lpRootPathName", std::string("C:\\")}});
    ASSERT_TRUE(dt.has_value());
    EXPECT_EQ(*dt, 3u);  // DRIVE_FIXED

    // GetVolumeInformationW: the profile VOLUME cells land
    const auto* vol = ApiRegistry::instance().find("GetVolumeInformationW");
    ASSERT_NE(vol, nullptr);
    const auto r_vol = vol->handler(ql, 0, ResolvedParams{
        {"lpRootPathName", std::string("C:\\")},
        {"lpVolumeNameBuffer", kScratch},
        {"nVolumeNameSize", std::uint64_t{64}},
        {"lpVolumeSerialNumber", std::uint64_t{0}},
        {"lpMaximumComponentLength", kCells},
        {"lpFileSystemFlags", std::uint64_t{0}},
        {"lpFileSystemNameBuffer", kScratch + 64},
        {"nFileSystemNameSize", std::uint64_t{32}},
    });
    ASSERT_TRUE(r_vol.has_value());
    EXPECT_EQ(*r_vol, 1u);
    EXPECT_EQ(ql.mem().read_ptr(kCells, 2), 255u);  // lpMaximumComponentLength
    const auto volname = ql.mem().read(kScratch, 14);
    std::string volname_s;
    for (std::size_t i = 0; i + 1 < volname.size(); i += 2) {
        volname_s.push_back(static_cast<char>(volname[i]));
    }
    EXPECT_EQ(volname_s, "Volume1");

    // GetDiskFreeSpaceW: the VOLUME geometry cells land
    const auto* disk = ApiRegistry::instance().find("GetDiskFreeSpaceW");
    ASSERT_NE(disk, nullptr);
    const auto r_disk = disk->handler(ql, 0, ResolvedParams{
        {"lpRootPathName", std::string("C:\\")},
        {"lpSectorsPerCluster", kScratch},
        {"lpBytesPerSector", kScratch + 4},
        {"lpNumberOfFreeClusters", kScratch + 8},
        {"lpTotalNumberOfClusters", kScratch + 12},
    });
    ASSERT_TRUE(r_disk.has_value());
    EXPECT_EQ(*r_disk, 0u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 10u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 4, 4), 512u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 8, 4), 12345u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 12, 4), 65536u);
}

TEST(WinApiFileapi, PageFileMappingRoundTrip) {
    register_dlls();
    Qiling ql(win_test_options());

    // CreateFileMappingA over INVALID_HANDLE_VALUE: the page-file-backed
    // FileMappingMem flavour
    const auto* create_map = ApiRegistry::instance().find("CreateFileMappingA");
    ASSERT_NE(create_map, nullptr);
    const auto hmap = create_map->handler(ql, 0, ResolvedParams{
        {"hFile", 0xffffffffffffffffull},
        {"lpFileMappingAttributes", std::uint64_t{0}},
        {"flProtect", std::uint64_t{0x04}},  // PAGE_READWRITE
        {"dwMaximumSizeHigh", std::uint64_t{0}},
        {"dwMaximumSizeLow", std::uint64_t{0x1000}},
        {"lpName", std::string("QL_MAPPING_TEST")},
    });
    ASSERT_TRUE(hmap.has_value());
    EXPECT_NE(*hmap, 0xffffffffffffffffull);

    // the named lookup rides the search path (the second create returns the
    // existing handle)
    const auto hmap2 = create_map->handler(ql, 0, ResolvedParams{
        {"hFile", 0xffffffffffffffffull},
        {"lpFileMappingAttributes", std::uint64_t{0}},
        {"flProtect", std::uint64_t{0x04}},
        {"dwMaximumSizeHigh", std::uint64_t{0}},
        {"dwMaximumSizeLow", std::uint64_t{0x1000}},
        {"lpName", std::string("QL_MAPPING_TEST")},
    });
    ASSERT_TRUE(hmap2.has_value());
    // the upstream FileMapping shape: the INVALID_HANDLE_VALUE branch creates
    // a fresh mapping without the name dedup (the search rides the file-backed
    // else branch only, verbatim)
    EXPECT_NE(*hmap2, *hmap);

    // MapViewOfFile: the heap-backed view lands inside the mapping
    const auto* map_view = ApiRegistry::instance().find("MapViewOfFile");
    ASSERT_NE(map_view, nullptr);
    const auto view = map_view->handler(ql, 0, ResolvedParams{
        {"hFileMappingObject", *hmap},
        {"dwDesiredAccess", std::uint64_t{0x06}},  // FILE_MAP_WRITE|READ
        {"dwFileOffsetHigh", std::uint64_t{0}},
        {"dwFileOffsetLow", std::uint64_t{0}},
        {"dwNumberOfBytesToMap", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(view.has_value());
    EXPECT_NE(*view, 0u);

    // UnmapViewOfFile frees the view + deletes the handle
    const auto* unmap = ApiRegistry::instance().find("UnmapViewOfFile");
    ASSERT_NE(unmap, nullptr);
    const auto r_unmap = unmap->handler(ql, 0, ResolvedParams{{"lpBaseAddress", *view}});
    ASSERT_TRUE(r_unmap.has_value());
    EXPECT_EQ(*r_unmap, 1u);

    // the second unmap answers 0 for the deleted view handle
    const auto r_unmap2 = unmap->handler(ql, 0, ResolvedParams{{"lpBaseAddress", *view}});
    EXPECT_EQ(r_unmap2.value_or(1), 0u);
}

TEST(WinApiProcessthreads, GetCurrentQuartetAndIds) {
    register_dlls();
    Qiling ql(win_test_options());

    // GetCurrentProcessId: the profile KERNEL pid (windows.ql: 1996)
    const auto* pid = ApiRegistry::instance().find("GetCurrentProcessId");
    ASSERT_NE(pid, nullptr);
    const auto r_pid = pid->handler(ql, 0, {});
    ASSERT_TRUE(r_pid.has_value());
    EXPECT_EQ(*r_pid, 1996u);

    // GetCurrentProcess: the FIXME-verbatim pid return
    const auto* proc = ApiRegistry::instance().find("GetCurrentProcess");
    ASSERT_NE(proc, nullptr);
    const auto r_proc = proc->handler(ql, 0, {});
    ASSERT_TRUE(r_proc.has_value());
    EXPECT_EQ(*r_proc, 1996u);

    // GetCurrentThreadId / GetCurrentThread: the main thread's static id
    const auto* tid = ApiRegistry::instance().find("GetCurrentThreadId");
    ASSERT_NE(tid, nullptr);
    const auto* thr = ApiRegistry::instance().find("GetCurrentThread");
    ASSERT_NE(thr, nullptr);
    const auto expected_tid = ql.os<QlOsWindows>().thread_manager().cur_thread()->get_id();
    const auto r_tid = tid->handler(ql, 0, {});
    const auto r_thr = thr->handler(ql, 0, {});
    ASSERT_TRUE(r_tid.has_value());
    ASSERT_TRUE(r_thr.has_value());
    EXPECT_EQ(*r_tid, expected_tid);
    EXPECT_EQ(*r_thr, expected_tid);
}

TEST(WinApiProcessthreads, TlsCycleAllocSetGetFree) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* alloc_ = ApiRegistry::instance().find("TlsAlloc");
    ASSERT_NE(alloc_, nullptr);
    const auto idx = alloc_->handler(ql, 0, {});
    ASSERT_TRUE(idx.has_value());
    EXPECT_EQ(*idx, 0u);  // the fresh thread's first slot

    const auto* set_ = ApiRegistry::instance().find("TlsSetValue");
    ASSERT_NE(set_, nullptr);
    const auto r_set = set_->handler(ql, 0, ResolvedParams{
        {"dwTlsIndex", *idx},
        {"lpTlsValue", std::uint64_t{0x1234}},
    });
    ASSERT_TRUE(r_set.has_value());
    EXPECT_EQ(*r_set, 1u);

    const auto* get_ = ApiRegistry::instance().find("TlsGetValue");
    ASSERT_NE(get_, nullptr);
    const auto r_get = get_->handler(ql, 0, ResolvedParams{{"dwTlsIndex", *idx}});
    ASSERT_TRUE(r_get.has_value());
    EXPECT_EQ(*r_get, 0x1234u);
    // the api explicitly clears the last error on success (verbatim comment)
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0u);

    // TlsFree releases the slot; the second free flags ERROR_INVALID_PARAMETER
    const auto* free_ = ApiRegistry::instance().find("TlsFree");
    ASSERT_NE(free_, nullptr);
    const auto r_free = free_->handler(ql, 0, ResolvedParams{{"dwTlsIndex", *idx}});
    ASSERT_TRUE(r_free.has_value());
    EXPECT_EQ(*r_free, 1u);

    ql.os<QlOsWindows>().set_last_error(0);
    const auto r_free2 = free_->handler(ql, 0, ResolvedParams{{"dwTlsIndex", *idx}});
    ASSERT_TRUE(r_free2.has_value());
    EXPECT_EQ(*r_free2, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x57u);  // ERROR_INVALID_PARAMETER
}

TEST(WinApiProcessthreads, TlsSetValueOnUnallocatedSlotFlagsError) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* set_ = ApiRegistry::instance().find("TlsSetValue");
    ASSERT_NE(set_, nullptr);
    const auto r = set_->handler(ql, 0, ResolvedParams{
        {"dwTlsIndex", std::uint64_t{7}},
        {"lpTlsValue", std::uint64_t{0}},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x57u);  // ERROR_INVALID_PARAMETER
}

TEST(WinApiProcessthreads, GetStartupInfoPacksStructFields) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* si = ApiRegistry::instance().find("GetStartupInfoA");
    ASSERT_NE(si, nullptr);
    const auto r = si->handler(ql, 0, ResolvedParams{{"lpStartupInfo", kScratch}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);  // STATUS_SUCCESS

    // the x64 STARTUPINFO layout (104 bytes): the cb, the dw fields, the
    // stdio handles, and the flags
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 104u);                      // cb
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 40, 4), 100u);                 // dwXSize
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 44, 4), 100u);                 // dwYSize
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 48, 4), 132u);                 // dwXCountChars
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 52, 4), 128u);                 // dwYCountChars
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 56, 4), 0xffu);                // dwFillAttribute
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 60, 4), 0x40u);                // dwFlags
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 64, 2), 1u);                   // wShowWindow
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 80, 4), 0xfffffff6u);          // hStdInput
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 88, 4), 0xfffffff5u);          // hStdOutput
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 96, 4), 0xfffffff4u);          // hStdError

    // the W sibling shares the body (the registration coverage)
    EXPECT_NE(ApiRegistry::instance().find("GetStartupInfoW"), nullptr);
}

TEST(WinApiProcessthreads, CreateThreadSuspendedPreparesContext) {
    register_dlls();
    Qiling ql(win_test_options());

#ifdef CREATE_SUSPENDED
#undef CREATE_SUSPENDED
#endif
    constexpr std::uint32_t CREATE_SUSPENDED = 0x00000004;
    constexpr std::uint64_t kStart = 0x140003000ull;
    constexpr std::uint64_t kParam = 0x12345678ull;

    const auto* ct = ApiRegistry::instance().find("CreateThread");
    ASSERT_NE(ct, nullptr);
    const auto r = ct->handler(ql, 0, ResolvedParams{
        {"lpThreadAttributes", std::uint64_t{0}},
        {"dwStackSize", std::uint64_t{0x10000}},
        {"lpStartAddress", kStart},
        {"lpParameter", kParam},
        {"dwCreationFlags", CREATE_SUSPENDED},
        {"lpThreadId", std::uint64_t{0}},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_NE(*r, 0u);

    // the thread handle resolves to a READY-status thread whose saved context
    // rides the start address and the RCX parameter
    auto& os = ql.os<QlOsWindows>();
    auto* handle = os.handle_manager().get(*r);
    ASSERT_NE(handle, nullptr);
    auto* thread = static_cast<QlWindowsThread*>(handle->obj);
    ASSERT_NE(thread, nullptr);
    EXPECT_EQ(thread->status(), ThreadStatus::Ready);
    const auto& saved = thread->saved_context();
    const auto rip = saved.find("rip");
    const auto rcx = saved.find("rcx");
    ASSERT_NE(rip, saved.end());
    ASSERT_NE(rcx, saved.end());
    EXPECT_EQ(rip->second, kStart);
    EXPECT_EQ(rcx->second, kParam);
}

TEST(WinApiProcessthreads, IsProcessorFeaturePresentXsaveExcluded) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* pf = ApiRegistry::instance().find("IsProcessorFeaturePresent");
    ASSERT_NE(pf, nullptr);

    const auto r_xsave = pf->handler(ql, 0, ResolvedParams{{"ProcessorFeature", std::uint64_t{0x17}}});
    ASSERT_TRUE(r_xsave.has_value());
    EXPECT_EQ(*r_xsave, 0u);  // the PF_XSAVE_ENABLED verbatim 0

    const auto r_other = pf->handler(ql, 0, ResolvedParams{{"ProcessorFeature", std::uint64_t{1}}});
    ASSERT_TRUE(r_other.has_value());
    EXPECT_EQ(*r_other, 1u);
}

TEST(WinApiProcessthreads, OpenProcessTokenWritesHandle) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* tok = ApiRegistry::instance().find("OpenProcessToken");
    ASSERT_NE(tok, nullptr);
    const auto r = tok->handler(ql, 0, ResolvedParams{
        {"ProcessHandle", 0xffffffffffffffffull},
        {"DesiredAccess", std::uint64_t{0}},
        {"TokenHandle", kCells},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 1u);

    // the token handle landed at the caller's PHANDLE cell
    const auto written = ql.mem().read_ptr(kCells, 8);
    EXPECT_NE(written, 0u);
}

TEST(WinApiProcessthreads, OpenThreadTokenWritesHandle) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* tok = ApiRegistry::instance().find("OpenThreadToken");
    ASSERT_NE(tok, nullptr);
    const auto r = tok->handler(ql, 0, ResolvedParams{
        {"ThreadHandle", 0xffffffffffffffffull},
        {"DesiredAccess", std::uint64_t{0}},
        {"OpenAsSelf", std::uint64_t{0}},
        {"TokenHandle", kCells},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 1u);
    EXPECT_NE(ql.mem().read_ptr(kCells, 8), 0u);
}

TEST(WinApiProcessthreads, OpenProcessGuardsCsrssAndZero) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* op = ApiRegistry::instance().find("OpenProcess");
    ASSERT_NE(op, nullptr);

    // the pid 0: the ERROR_INVALID_PARAMETER shape
    auto r0 = op->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"dwProcessId", std::uint64_t{0}},
    });
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(*r0, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x57u);

    // the csrss.exe pid (the profile: 1239): the ERROR_ACCESS_DENIED shape
    ql.os<QlOsWindows>().set_last_error(0);
    auto rc = op->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"dwProcessId", std::uint64_t{1239}},
    });
    ASSERT_TRUE(rc.has_value());
    EXPECT_EQ(*rc, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x5u);

    // any other pid answers the fixed 0xD10C
    auto ro = op->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"dwProcessId", std::uint64_t{4242}},
    });
    ASSERT_TRUE(ro.has_value());
    EXPECT_EQ(*ro, 0xD10Cu);
}

TEST(WinApiProcessthreads, PassThroughBodiesReturnOne) {
    register_dlls();
    Qiling ql(win_test_options());

    // GetThreadContext / GetThreadTimes: the verbatim 1 bodies
    const auto* ctx = ApiRegistry::instance().find("GetThreadContext");
    ASSERT_NE(ctx, nullptr);
    const auto r_ctx = ctx->handler(ql, 0, ResolvedParams{{"hThread", 0xffffffffffffffffull}, {"lpContext", kCells}});
    ASSERT_TRUE(r_ctx.has_value());
    EXPECT_EQ(*r_ctx, 1u);

    const auto* times = ApiRegistry::instance().find("GetThreadTimes");
    ASSERT_NE(times, nullptr);
    const auto r_times = times->handler(ql, 0, ResolvedParams{
        {"hThread", 0xffffffffffffffffull},
        {"lpCreationTime", std::uint64_t{0}},
        {"lpExitTime", std::uint64_t{0}},
        {"lpKernelTime", std::uint64_t{0}},
        {"lpUserTime", std::uint64_t{0}},
    });
    ASSERT_TRUE(r_times.has_value());
    EXPECT_EQ(*r_times, 1u);

    // ExitThread: the verbatim pass body (the no-op, the no-crash)
    const auto* exit_thread = ApiRegistry::instance().find("ExitThread");
    ASSERT_NE(exit_thread, nullptr);
    const auto r_exit = exit_thread->handler(ql, 0, ResolvedParams{{"dwExitCode", std::uint64_t{0}}});
    EXPECT_FALSE(r_exit.has_value());
}

TEST(WinApiProcessthreads, ExitProcessAndTerminateProcessStopEmulation) {
    register_dlls();

    // ExitProcess: the emu_stop body
    {
        Qiling ql(win_test_options());
        const auto* exit_ = ApiRegistry::instance().find("ExitProcess");
        ASSERT_NE(exit_, nullptr);
        const auto r = exit_->handler(ql, 0, ResolvedParams{{"uExitCode", std::uint64_t{0}}});
        EXPECT_FALSE(r.has_value());
        EXPECT_EQ(ql.emu_state(), QL_STATE::STOPPED);
    }

    // TerminateProcess over the self pid: the emu_stop body
    {
        Qiling ql(win_test_options());
        const auto* term = ApiRegistry::instance().find("TerminateProcess");
        ASSERT_NE(term, nullptr);
        const auto r = term->handler(ql, 0, ResolvedParams{
            {"hProcess", std::uint64_t{1996}},
            {"uExitCode", std::uint64_t{0}},
        });
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(*r, 1u);
        EXPECT_EQ(ql.emu_state(), QL_STATE::STOPPED);
    }

    // TerminateProcess over a foreign pid: the plain 1 (no stop)
    {
        Qiling ql(win_test_options());
        const auto* term = ApiRegistry::instance().find("TerminateProcess");
        const auto r = term->handler(ql, 0, ResolvedParams{
            {"hProcess", std::uint64_t{4242}},
            {"uExitCode", std::uint64_t{0}},
        });
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(*r, 1u);
    }
}

TEST(WinApiSynchapi, PassThroughAndCriticalSectionBodies) {
    register_dlls();
    Qiling ql(win_test_options());

    // Sleep: the verbatim pass body (the commented time.sleep)
    const auto* sleep_ = ApiRegistry::instance().find("Sleep");
    ASSERT_NE(sleep_, nullptr);
    EXPECT_FALSE(sleep_->handler(ql, 0, ResolvedParams{{"dwMilliseconds", std::uint64_t{100}}}).has_value());

    // the critical-section pass set: the Enter/Leave/Delete answer 0, the
    // Initialize trio answers 1
    const auto* enter = ApiRegistry::instance().find("EnterCriticalSection");
    ASSERT_NE(enter, nullptr);
    auto r = enter->handler(ql, 0, ResolvedParams{{"lpCriticalSection", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    r = ApiRegistry::instance().find("LeaveCriticalSection")->handler(ql, 0, ResolvedParams{{"lpCriticalSection", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    r = ApiRegistry::instance().find("DeleteCriticalSection")->handler(ql, 0, ResolvedParams{{"lpCriticalSection", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    r = ApiRegistry::instance().find("InitializeCriticalSection")->handler(ql, 0, ResolvedParams{{"lpCriticalSection", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 1u);

    r = ApiRegistry::instance().find("InitializeCriticalSectionEx")->handler(ql, 0, ResolvedParams{
        {"lpCriticalSection", kCells}, {"dwSpinCount", std::uint64_t{0}}, {"Flags", std::uint64_t{0}}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 1u);

    r = ApiRegistry::instance().find("InitializeCriticalSectionAndSpinCount")->handler(ql, 0, ResolvedParams{
        {"lpCriticalSection", kCells}, {"dwSpinCount", std::uint64_t{0}}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 1u);

    // the SRW no-op set: the initialize/acquire/release/try pair all return
    // nothing (the void upstream bodies)
    const auto* srw = ApiRegistry::instance().find("InitializeSRWLock");
    ASSERT_NE(srw, nullptr);
    EXPECT_FALSE(srw->handler(ql, 0, ResolvedParams{{"SRWLock", kCells}}).has_value());
    EXPECT_NE(ApiRegistry::instance().find("AcquireSRWLockExclusive"), nullptr);
    EXPECT_NE(ApiRegistry::instance().find("AcquireSRWLockShared"), nullptr);
    EXPECT_NE(ApiRegistry::instance().find("ReleaseSRWLockExclusive"), nullptr);
    EXPECT_NE(ApiRegistry::instance().find("ReleaseSRWLockShared"), nullptr);
    EXPECT_NE(ApiRegistry::instance().find("TryAcquireSRWLockExclusive"), nullptr);
    EXPECT_NE(ApiRegistry::instance().find("TryAcquireSRWLockShared"), nullptr);

    // the SRW try-pair bodies: the verbatim pass (the no return value)
    const auto* try_ex = ApiRegistry::instance().find("TryAcquireSRWLockExclusive");
    const auto* try_sh = ApiRegistry::instance().find("TryAcquireSRWLockShared");
    EXPECT_FALSE(try_ex->handler(ql, 0, ResolvedParams{{"SRWLock", kCells}}).has_value());
    EXPECT_FALSE(try_sh->handler(ql, 0, ResolvedParams{{"SRWLock", kCells}}).has_value());
}

TEST(WinApiSynchapi, WaitForSingleObjectRidesWaitforList) {
    register_dlls();
    Qiling ql(win_test_options());

    // the wait target: the CreateThread handle (the obj = the QlWindowsThread)
    const auto* ct = ApiRegistry::instance().find("CreateThread");
    ASSERT_NE(ct, nullptr);
    const auto thread_handle = ct->handler(ql, 0, ResolvedParams{
        {"lpThreadAttributes", std::uint64_t{0}},
        {"dwStackSize", std::uint64_t{0x10000}},
        {"lpStartAddress", std::uint64_t{0x140003000ull}},
        {"lpParameter", std::uint64_t{0}},
        {"dwCreationFlags", std::uint64_t{4}},  // CREATE_SUSPENDED
        {"lpThreadId", std::uint64_t{0}},
    });
    ASSERT_TRUE(thread_handle.has_value());

    const auto* wait = ApiRegistry::instance().find("WaitForSingleObject");
    ASSERT_NE(wait, nullptr);
    const auto r = wait->handler(ql, 0, ResolvedParams{
        {"hHandle", *thread_handle},
        {"dwMilliseconds", std::uint64_t{0}},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);  // the verbatim 0 return

    // the cur_thread's waitfor list now holds the target thread
    auto& os = ql.os<QlOsWindows>();
    const auto* cur = os.thread_manager().cur_thread();
    ASSERT_EQ(cur->has_waitfor(), true);

    // the Ex sibling rides the same waitfor walk (the bAlertable param
    // unread, verbatim)
    const auto* wait_ex = ApiRegistry::instance().find("WaitForSingleObjectEx");
    ASSERT_NE(wait_ex, nullptr);
    const auto r_ex = wait_ex->handler(ql, 0, ResolvedParams{
        {"hHandle", *thread_handle},
        {"dwMilliseconds", std::uint64_t{0}},
        {"bAlertable", std::uint64_t{0}},
    });
    ASSERT_TRUE(r_ex.has_value());
    EXPECT_EQ(*r_ex, 0u);
}

TEST(WinApiSynchapi, WaitForMultipleObjectsWalksHandleArray) {
    register_dlls();
    Qiling ql(win_test_options());

    // two suspended worker threads + the guest handle array at kCells
    const auto* ct = ApiRegistry::instance().find("CreateThread");
    ASSERT_NE(ct, nullptr);
    std::array<std::uint64_t, 2> handles{};
    for (auto& h : handles) {
        const auto r = ct->handler(ql, 0, ResolvedParams{
            {"lpThreadAttributes", std::uint64_t{0}},
            {"dwStackSize", std::uint64_t{0x10000}},
            {"lpStartAddress", std::uint64_t{0x140003000ull}},
            {"lpParameter", std::uint64_t{0}},
            {"dwCreationFlags", std::uint64_t{4}},
            {"lpThreadId", std::uint64_t{0}},
        });
        ASSERT_TRUE(r.has_value());
        h = *r;
    }
    ql.mem().write_ptr(kCells, handles[0]);
    ql.mem().write_ptr(kCells + 8, handles[1]);

    const auto* wait_multi = ApiRegistry::instance().find("WaitForMultipleObjects");
    ASSERT_NE(wait_multi, nullptr);
    const auto r = wait_multi->handler(ql, 0, ResolvedParams{
        {"nCount", std::uint64_t{2}},
        {"lpHandles", kCells},
        {"bWaitAll", std::uint64_t{1}},
        {"dwMilliseconds", std::uint64_t{0}},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    // both threads landed on the cur_thread's waitfor list
    const auto* cur = ql.os<QlOsWindows>().thread_manager().cur_thread();
    // (the waitfor list holds 2 entries; the has_waitfor checks liveness —
    // the suspended threads are not terminated so the wait is live)
    EXPECT_EQ(cur->has_waitfor(), true);
}

TEST(WinApiSynchapi, CreateMutexLifecycleVerbatim) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* create_a = ApiRegistry::instance().find("CreateMutexA");
    ASSERT_NE(create_a, nullptr);

    // the named mutex, unowned
    const auto h1 = create_a->handler(ql, 0, ResolvedParams{
        {"lpMutexAttributes", std::uint64_t{0}},
        {"bInitialOwner", std::uint64_t{0}},
        {"lpName", std::string("QL_MUTEX")},
    });
    ASSERT_TRUE(h1.has_value());
    EXPECT_NE(*h1, 0u);

    // the second create with the same name: the verbatim commented
    // ERROR_ALREADY_EXISTS (the return 0, the last error untouched)
    const auto h2 = create_a->handler(ql, 0, ResolvedParams{
        {"lpMutexAttributes", std::uint64_t{0}},
        {"bInitialOwner", std::uint64_t{0}},
        {"lpName", std::string("QL_MUTEX")},
    });
    ASSERT_TRUE(h2.has_value());
    EXPECT_EQ(*h2, 0u);

    // the nameless create: the verbatim return 0
    const auto h3 = create_a->handler(ql, 0, ResolvedParams{
        {"lpMutexAttributes", std::uint64_t{0}},
        {"bInitialOwner", std::uint64_t{0}},
        {"lpName", std::string("")},
    });
    ASSERT_TRUE(h3.has_value());
    EXPECT_EQ(*h3, 0u);

    // the owned create + the release round trip
    const auto h4 = create_a->handler(ql, 0, ResolvedParams{
        {"lpMutexAttributes", std::uint64_t{0}},
        {"bInitialOwner", std::uint64_t{1}},
        {"lpName", std::string("QL_OWNED")},
    });
    ASSERT_TRUE(h4.has_value());
    EXPECT_NE(*h4, 0u);

    const auto* release = ApiRegistry::instance().find("ReleaseMutex");
    ASSERT_NE(release, nullptr);
    const auto r_rel = release->handler(ql, 0, ResolvedParams{{"hMutex", *h4}});
    ASSERT_TRUE(r_rel.has_value());
    EXPECT_EQ(*r_rel, 1u);

    // the second release: the mutex is free now -> the ERROR_NOT_OWNER shape
    ql.os<QlOsWindows>().set_last_error(0);
    const auto r_rel2 = release->handler(ql, 0, ResolvedParams{{"hMutex", *h4}});
    ASSERT_TRUE(r_rel2.has_value());
    EXPECT_EQ(*r_rel2, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x120u);  // ERROR_NOT_OWNER

    // the release over an unknown handle: the ERROR_INVALID_HANDLE shape
    ql.os<QlOsWindows>().set_last_error(0);
    const auto r_bad = release->handler(ql, 0, ResolvedParams{{"hMutex", std::uint64_t{0xdeadbeef}}});
    ASSERT_TRUE(r_bad.has_value());
    EXPECT_EQ(*r_bad, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x6u);

    // the W sibling shares the body
    EXPECT_NE(ApiRegistry::instance().find("CreateMutexW"), nullptr);
}

TEST(WinApiSynchapi, OpenMutexGuardsAndGlobalShape) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* open_a = ApiRegistry::instance().find("OpenMutexA");
    ASSERT_NE(open_a, nullptr);

    // the empty name: the verbatim return 0
    auto r = open_a->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"lpName", std::string("")},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    // the missing named mutex: the ERROR_FILE_NOT_FOUND + the 0
    r = open_a->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"lpName", std::string("QL_NOPE")},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x2u);  // ERROR_FILE_NOT_FOUND

    // the Local-prefix variant rides the same not-found walk
    r = open_a->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"lpName", std::string("Local\\QL_NOPE")},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);
}

TEST(WinApiSynchapi, OpenMutexGlobalReturnsFixedHandle) {
    register_dlls();
    Qiling ql(win_test_options());

    // the Global-prefix open over the missing name: the verbatim 0xD10C
    // ("we always return a valid handle because we have no way to emulate
    // them" — the Gandcrab sample)
    const auto* open_a = ApiRegistry::instance().find("OpenMutexA");
    ASSERT_NE(open_a, nullptr);
    const auto r = open_a->handler(ql, 0, ResolvedParams{
        {"dwDesiredAccess", std::uint64_t{0}},
        {"bInheritHandle", std::uint64_t{0}},
        {"lpName", std::string("Global\\QL_GLOBAL")},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0xD10Cu);

    // the W sibling shares the body
    EXPECT_NE(ApiRegistry::instance().find("OpenMutexW"), nullptr);
}

TEST(WinApiSynchapi, CreateEventNamedAndAnonymous) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* create_a = ApiRegistry::instance().find("CreateEventA");
    ASSERT_NE(create_a, nullptr);

    // the named event, the initial state locked
    const auto h1 = create_a->handler(ql, 0, ResolvedParams{
        {"lpEventAttributes", std::uint64_t{0}},
        {"bManualReset", std::uint64_t{1}},
        {"bInitialState", std::uint64_t{1}},
        {"lpName", std::string("QL_EVENT")},
    });
    ASSERT_TRUE(h1.has_value());
    EXPECT_NE(*h1, 0u);

    // the second create with the same name: the ERROR_ALREADY_EXISTS + the
    // existing handle id (the verbatim shape)
    ql.os<QlOsWindows>().set_last_error(0);
    const auto h2 = create_a->handler(ql, 0, ResolvedParams{
        {"lpEventAttributes", std::uint64_t{0}},
        {"bManualReset", std::uint64_t{1}},
        {"bInitialState", std::uint64_t{0}},
        {"lpName", std::string("QL_EVENT")},
    });
    ASSERT_TRUE(h2.has_value());
    EXPECT_EQ(*h2, *h1);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0xb7u);  // ERROR_ALREADY_EXISTS

    // the anonymous event: the fresh handle (the name = the empty string)
    const auto h3 = create_a->handler(ql, 0, ResolvedParams{
        {"lpEventAttributes", std::uint64_t{0}},
        {"bManualReset", std::uint64_t{0}},
        {"bInitialState", std::uint64_t{0}},
        {"lpName", std::string("")},
    });
    ASSERT_TRUE(h3.has_value());
    EXPECT_NE(*h3, 0u);
    EXPECT_NE(*h3, *h1);

    // the W sibling shares the body
    EXPECT_NE(ApiRegistry::instance().find("CreateEventW"), nullptr);
}

TEST(WinApiHeapapi, HeapLifecycleAllocWriteFreeValidate) {
    register_dlls();
    Qiling ql(win_test_options());

    // HeapCreate: the verbatim alloc over the initial size
    const auto* create = ApiRegistry::instance().find("HeapCreate");
    ASSERT_NE(create, nullptr);
    const auto hheap = create->handler(ql, 0, ResolvedParams{
        {"flOptions", std::uint64_t{0}},
        {"dwInitialSize", std::uint64_t{0x1000}},
        {"dwMaximumSize", std::uint64_t{0}},
    });
    ASSERT_TRUE(hheap.has_value());
    EXPECT_NE(*hheap, 0u);

    // HeapAlloc: the plain alloc, the writable memory
    const auto* alloc = ApiRegistry::instance().find("HeapAlloc");
    ASSERT_NE(alloc, nullptr);
    const auto p1 = alloc->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap},
        {"dwFlags", std::uint64_t{0}},
        {"dwBytes", std::uint64_t{0x40}},
    });
    ASSERT_TRUE(p1.has_value());
    EXPECT_NE(*p1, 0u);
    ql.mem().write_ptr(*p1, 0x4142);

    // HeapAlloc with HEAP_ZERO_MEMORY: the range reads back zero
    const auto p2 = alloc->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap},
        {"dwFlags", std::uint64_t{0x8}},  // HEAP_ZERO_MEMORY
        {"dwBytes", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(p2.has_value());
    EXPECT_NE(*p2, 0u);
    for (std::uint64_t off = 0; off < 0x100; off += 0x20) {
        ASSERT_EQ(ql.mem().read(*p2 + off, 8), std::vector<std::uint8_t>(8, 0)) << "offset " << off;
    }

    // HeapSize: the allocated size rides back
    const auto* size_ = ApiRegistry::instance().find("HeapSize");
    ASSERT_NE(size_, nullptr);
    const auto sz = size_->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}}, {"lpMem", *p1}});
    ASSERT_TRUE(sz.has_value());
    EXPECT_EQ(*sz, 0x40u);

    // HeapValidate: the in-use chunk validates, the freed one does not
    const auto* validate = ApiRegistry::instance().find("HeapValidate");
    ASSERT_NE(validate, nullptr);
    const auto v1 = validate->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}}, {"lpMem", *p1}});
    ASSERT_TRUE(v1.has_value());
    EXPECT_EQ(*v1, 1u);

    const auto* free_ = ApiRegistry::instance().find("HeapFree");
    ASSERT_NE(free_, nullptr);
    const auto f1 = free_->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}}, {"lpMem", *p1}});
    ASSERT_TRUE(f1.has_value());
    EXPECT_EQ(*f1, 1u);

    const auto v2 = validate->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}}, {"lpMem", *p1}});
    ASSERT_TRUE(v2.has_value());
    EXPECT_EQ(*v2, 0u);

    // GetProcessHeap: the heap start address
    const auto* gph = ApiRegistry::instance().find("GetProcessHeap");
    ASSERT_NE(gph, nullptr);
    const auto ph = gph->handler(ql, 0, {});
    ASSERT_TRUE(ph.has_value());
    EXPECT_EQ(*ph, ql.os<QlOsWindows>().heap().start_address());

    // HeapSetInformation: the verbatim 1
    const auto* setinfo = ApiRegistry::instance().find("HeapSetInformation");
    ASSERT_NE(setinfo, nullptr);
    const auto si = setinfo->handler(ql, 0, ResolvedParams{
        {"HeapHandle", std::uint64_t{0}},
        {"HeapInformationClass", std::uint64_t{0}},
        {"HeapInformation", std::uint64_t{0}},
        {"HeapInformationLength", std::uint64_t{0}},
    });
    ASSERT_TRUE(si.has_value());
    EXPECT_EQ(*si, 1u);
}

TEST(WinApiHeapapi, HeapReAllocRoundTripPreservesContent) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* create = ApiRegistry::instance().find("HeapCreate");
    ASSERT_NE(create, nullptr);
    const auto hheap = create->handler(ql, 0, ResolvedParams{
        {"flOptions", std::uint64_t{0}},
        {"dwInitialSize", std::uint64_t{0x1000}},
        {"dwMaximumSize", std::uint64_t{0}},
    });
    ASSERT_TRUE(hheap.has_value());

    const auto* alloc = ApiRegistry::instance().find("HeapAlloc");
    ASSERT_NE(alloc, nullptr);
    const auto p = alloc->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}}, {"dwBytes", std::uint64_t{0x20}}});
    ASSERT_TRUE(p.has_value());

    // stage the recognizable content then grow
    const std::vector<std::uint8_t> payload(0x10, 0x5a);
    ql.mem().write(*p, payload);

    const auto* realloc = ApiRegistry::instance().find("HeapReAlloc");
    ASSERT_NE(realloc, nullptr);
    const auto grown = realloc->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}},
        {"lpMem", *p}, {"dwBytes", std::uint64_t{0x80}}});
    ASSERT_TRUE(grown.has_value());
    EXPECT_NE(*grown, 0u);
    // the first 0x10 bytes carry over (the verbatim old-data walk)
    EXPECT_EQ(ql.mem().read(*grown, 0x10), payload);

    // the null base: the verbatim HeapAlloc ride
    const auto fresh = realloc->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}},
        {"lpMem", std::uint64_t{0}}, {"dwBytes", std::uint64_t{0x10}}});
    ASSERT_TRUE(fresh.has_value());
    EXPECT_NE(*fresh, 0u);

    // the zero new size: the verbatim free + the 0 return
    const auto shrunk = realloc->handler(ql, 0, ResolvedParams{
        {"hHeap", *hheap}, {"dwFlags", std::uint64_t{0}},
        {"lpMem", *grown}, {"dwBytes", std::uint64_t{0}}});
    ASSERT_TRUE(shrunk.has_value());
    EXPECT_EQ(*shrunk, 0u);
}
