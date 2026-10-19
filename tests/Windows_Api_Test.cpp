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
#include "qiling/loader/pe.hpp"

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

TEST(WinApiMemoryapi, VirtualAllocFreeProtectQueryVerbatim) {
    register_dlls();
    Qiling ql(win_test_options());

    // VirtualAlloc: the verbatim heap-alloc ride
    const auto* alloc = ApiRegistry::instance().find("VirtualAlloc");
    ASSERT_NE(alloc, nullptr);
    const auto base = alloc->handler(ql, 0, ResolvedParams{
        {"lpAddress", std::uint64_t{0}},
        {"dwSize", std::uint64_t{0x1000}},
        {"flAllocationType", std::uint64_t{0x1000}},  // MEM_COMMIT
        {"flProtect", std::uint64_t{0x40}},
    });
    ASSERT_TRUE(base.has_value());
    EXPECT_NE(*base, 0u);
    ql.mem().write_ptr(*base, 0x4142);

    // VirtualProtect: the verbatim 1
    const auto* protect = ApiRegistry::instance().find("VirtualProtect");
    ASSERT_NE(protect, nullptr);
    const auto pr = protect->handler(ql, 0, ResolvedParams{
        {"lpAddress", *base},
        {"dwSize", std::uint64_t{0x1000}},
        {"flNewProtect", std::uint64_t{0x04}},
        {"lpflOldProtect", std::uint64_t{0}},
    });
    ASSERT_TRUE(pr.has_value());
    EXPECT_EQ(*pr, 1u);

    // VirtualQuery over the allocated chunk: the MBI pack rides the
    // pointer-sized stride (7 fields: the base, the alloc base, the
    // EXECUTE_READ_WRITE, the size, the MEM_COMMIT, the protect, the
    // MEM_MAPPED)
    const auto* query = ApiRegistry::instance().find("VirtualQuery");
    ASSERT_NE(query, nullptr);
    const auto q = query->handler(ql, 0, ResolvedParams{
        {"lpAddress", *base + 0x10},
        {"lpBuffer", kCells},
        {"dwLength", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(q.has_value());
    const auto ps = ql.arch().pointersize();
    EXPECT_EQ(*q, ps * 7u);
    EXPECT_EQ(ql.mem().read_ptr(kCells, 8), *base);        // BaseAddress
    EXPECT_EQ(ql.mem().read_ptr(kCells + 8, 8), *base);    // AllocationBase
    EXPECT_EQ(ql.mem().read_ptr(kCells + 16, 4), 0x40u);   // AllocationProtect
    EXPECT_EQ(ql.mem().read_ptr(kCells + 24, 8), 0x1000u); // RegionSize
    EXPECT_EQ(ql.mem().read_ptr(kCells + 32, 4), 0x1000u); // State (MEM_COMMIT)
    EXPECT_EQ(ql.mem().read_ptr(kCells + 40, 4), 0x40u);   // Protect
    EXPECT_EQ(ql.mem().read_ptr(kCells + 48, 4), 0x40000u);// Type (MEM_MAPPED)

    // VirtualQuery over an unallocated address: the ERROR_INVALID_PARAMETER
    // + the 0 (the verbatim page-not-found walk)
    ql.os<QlOsWindows>().set_last_error(0);
    const auto qb = query->handler(ql, 0, ResolvedParams{
        {"lpAddress", std::uint64_t{0x70000000}},
        {"lpBuffer", kCells},
        {"dwLength", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(qb.has_value());
    EXPECT_EQ(*qb, 0u);
    EXPECT_EQ(ql.os<QlOsWindows>().last_error(), 0x57u);

    // VirtualFree: the verbatim free + the 1
    const auto* free_ = ApiRegistry::instance().find("VirtualFree");
    ASSERT_NE(free_, nullptr);
    const auto f = free_->handler(ql, 0, ResolvedParams{
        {"lpAddress", *base},
        {"dwSize", std::uint64_t{0}},
        {"dwFreeType", std::uint64_t{0x4000}},  // MEM_RELEASE
    });
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(*f, 1u);
}

// ---- the libloaderapi fixtures: the PE-mode helpers ----

// the minimal PE64 builder carrying an export table: the export directory
// rides the .text page after the code stub; the export "MinFunc" resolves to
// the entry code (the rva 0x1000)
static std::vector<std::uint8_t> build_minimal_pe64_with_exports() {
    std::vector<std::uint8_t> pe(0x800, 0);
    auto put16 = [&](std::size_t off, std::uint16_t v) {
        pe[off] = static_cast<std::uint8_t>(v);
        pe[off + 1] = static_cast<std::uint8_t>(v >> 8);
    };
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            pe[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            pe[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };

    pe[0] = 'M';
    pe[1] = 'Z';
    put32(0x3c, 0x80);
    put32(0x80, 0x00004550);
    put16(0x84, 0x8664);
    put16(0x86, 1);
    put16(0x94, 0xf0);
    put16(0x96, 0x22);

    constexpr std::size_t OH = 0x98;
    put16(OH + 0, 0x20b);
    put32(OH + 16, 0x1000);
    put32(OH + 20, 0x1000);
    put64(OH + 24, 0x140000000);
    put32(OH + 32, 0x1000);
    put32(OH + 36, 0x200);
    put32(OH + 56, 0x2000);
    put32(OH + 60, 0x400);
    put16(OH + 68, 2);
    put32(OH + 76, 0x200);
    put32(OH + 80, 0x1000);
    put32(OH + 84, 0x100000);
    put32(OH + 88, 0x1000);

    // the export data directory (the index 0): the rva + the size
    constexpr std::uint32_t kExportDirRaw = 0x240;  // inside .text raw space
    constexpr std::uint32_t kExportDirRva = 0x1000 + (kExportDirRaw - 0x200);
    put32(OH + 112, kExportDirRva);
    put32(OH + 116, 40);

    // the .text section header
    const std::size_t sect = 0x98 + 0xf0;
    pe[sect + 0] = '.';
    pe[sect + 1] = 't';
    pe[sect + 2] = 'e';
    pe[sect + 3] = 'x';
    pe[sect + 4] = 't';
    put32(sect + 8, 0x1000);
    put32(sect + 12, 0x1000);
    put32(sect + 16, 0x600);   // the raw size covers the export structures
    put32(sect + 20, 0x200);
    put32(sect + 36, 0x60000020);

    // the code stub: ret
    pe[0x200] = 0xC3;

    // the export structures at the fixed raw offsets (the rva = raw - 0x200 + 0x1000)
    const auto rva_of = [](std::uint32_t raw) { return 0x1000 + (raw - 0x200); };

    // the name strings
    const std::string dll_name = "MINPE.dll";
    for (std::size_t i = 0; i < dll_name.size(); ++i) {
        pe[0x2a0 + i] = static_cast<std::uint8_t>(dll_name[i]);
    }
    pe[0x2a0 + dll_name.size()] = 0;
    const std::string func_name = "MinFunc";
    for (std::size_t i = 0; i < func_name.size(); ++i) {
        pe[0x2c0 + i] = static_cast<std::uint8_t>(func_name[i]);
    }
    pe[0x2c0 + func_name.size()] = 0;

    // the IMAGE_EXPORT_DIRECTORY at kExportDirRaw
    put32(kExportDirRaw + 0, 0);        // Characteristics
    put32(kExportDirRaw + 4, 0);        // TimeDateStamp
    put16(kExportDirRaw + 8, 0);        // MajorVersion
    put16(kExportDirRaw + 10, 0);       // MinorVersion
    put32(kExportDirRaw + 12, rva_of(0x2a0));  // Name rva
    put32(kExportDirRaw + 16, 1);       // Base
    put32(kExportDirRaw + 20, 1);       // NumberOfFunctions
    put32(kExportDirRaw + 24, 1);       // NumberOfNames
    put32(kExportDirRaw + 28, rva_of(0x2b8));  // AddressOfFunctions
    put32(kExportDirRaw + 32, rva_of(0x2c8));  // AddressOfNames
    put32(kExportDirRaw + 36, rva_of(0x2d0));  // AddressOfNameOrdinals

    // the EAT: the function rva (the code stub)
    put32(0x2b8, 0x1000);
    // the names array: the "MinFunc" rva
    put32(0x2c8, rva_of(0x2c0));
    // the ordinals: the index 0 (the ordinal 1 after the base)
    put16(0x2d0, 0);

    return pe;
}

TEST(WinApiLibloader, GetProcAddressSelfModuleByNameAndOrdinal) {
    register_dlls();

    const auto pe = build_minimal_pe64_with_exports();
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_libloader_rootfs";
    std::filesystem::create_directories(rootfs / "Windows" / "registry");
    const auto exe_path = rootfs / "minpe_test.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    auto& loader = static_cast<loader::QlLoaderPE&>(ql.loader());
    ASSERT_EQ(loader.pe_image_address(), 0x140000000u);

    const auto* gp = ApiRegistry::instance().find("GetProcAddress");
    ASSERT_NE(gp, nullptr);

    // stage the "MinFunc" name in the guest scratch
    const std::string name = "MinFunc";
    ql.mem().write(kScratch, std::vector<std::uint8_t>(name.begin(), name.end()));
    ql.mem().write(kScratch + name.size(), std::vector<std::uint8_t>{0});

    // the by-name walk over the self module's export table
    const auto by_name = gp->handler(ql, 0, ResolvedParams{
        {"hModule", 0x140000000ull},
        {"lpProcName", kScratch},
    });
    ASSERT_TRUE(by_name.has_value());
    EXPECT_EQ(*by_name, 0x140001000ull);  // the image base + the code rva

    // the ordinal walk (the ordinal 1 after the base)
    const auto by_ord = gp->handler(ql, 0, ResolvedParams{
        {"hModule", 0x140000000ull},
        {"lpProcName", std::uint64_t{1}},
    });
    ASSERT_TRUE(by_ord.has_value());
    EXPECT_EQ(*by_ord, 0x140001000ull);

    // the unknown name: the 0
    const std::string missing = "Nope";
    ql.mem().write(kScratch + 0x20, std::vector<std::uint8_t>(missing.begin(), missing.end()));
    ql.mem().write(kScratch + 0x20 + missing.size(), std::vector<std::uint8_t>{0});
    const auto miss = gp->handler(ql, 0, ResolvedParams{
        {"hModule", 0x140000000ull},
        {"lpProcName", kScratch + 0x20},
    });
    ASSERT_TRUE(miss.has_value());
    EXPECT_EQ(*miss, 0u);
}

TEST(WinApiLibloader, GetModuleHandleBasenameAndNull) {
    register_dlls();

    const auto pe = build_minimal_pe64_with_exports();
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_libloader_rootfs";
    std::filesystem::create_directories(rootfs / "Windows" / "registry");
    const auto exe_path = rootfs / "minpe_test.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    // the null module name: the pe_image_address
    const auto* gh = ApiRegistry::instance().find("GetModuleHandleA");
    ASSERT_NE(gh, nullptr);
    const auto r0 = gh->handler(ql, 0, ResolvedParams{{"lpModuleName", std::string("")}});
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(*r0, 0x140000000u);

    // the basename walk (the casefolded match)
    const auto r1 = gh->handler(ql, 0, ResolvedParams{{"lpModuleName", std::string("minpe_test.exe")}});
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0x140000000u);

    // the missing module: the 0
    const auto r2 = gh->handler(ql, 0, ResolvedParams{{"lpModuleName", std::string("ghost.dll")}});
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0u);

    // the Ex sibling writes the handle out
    const auto* ghx = ApiRegistry::instance().find("GetModuleHandleExW");
    ASSERT_NE(ghx, nullptr);
    constexpr std::uint64_t kPeCell = 0x140001800ull;  // inside the mapped image
    const auto r3 = ghx->handler(ql, 0, ResolvedParams{
        {"dwFlags", std::uint64_t{0}},
        {"lpModuleName", std::string("minpe_test.exe")},
        {"phModule", kPeCell},
    });
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(*r3, 0x140000000u);
    EXPECT_EQ(ql.mem().read_ptr(kPeCell, 8), 0x140000000u);
}

TEST(WinApiLibloader, GetModuleFileNameNarrowsAndEncodes) {
    register_dlls();

    const auto pe = build_minimal_pe64_with_exports();
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_libloader_rootfs";
    std::filesystem::create_directories(rootfs / "Windows" / "registry");
    const auto exe_path = rootfs / "minpe_test.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    const auto* gfn_a = ApiRegistry::instance().find("GetModuleFileNameA");
    ASSERT_NE(gfn_a, nullptr);
    const auto r_a = gfn_a->handler(ql, 0, ResolvedParams{
        {"hModule", 0x140000000ull},
        {"lpFilename", kScratch},
        {"nSize", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(r_a.has_value());

    // the A form: the virtual path (the rootfs-rebased); the upstream
    // truncates to nSize-1 + the nul and returns min(len, nSize)
    std::string got_a(reinterpret_cast<const char*>(ql.mem().read(kScratch, *r_a).data()), *r_a);
    EXPECT_NE(got_a.find("minpe_test.exe"), std::string::npos);

    // the W form: the utf-16le units decode to the same path
    const auto* gfn_w = ApiRegistry::instance().find("GetModuleFileNameW");
    ASSERT_NE(gfn_w, nullptr);
    const auto r_w = gfn_w->handler(ql, 0, ResolvedParams{
        {"hModule", 0x140000000ull},
        {"lpFilename", kScratch + 0x200},
        {"nSize", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(r_w.has_value());
    const auto wide = ql.mem().read(kScratch + 0x200, *r_w * 2);
    std::string wide_narrow;
    for (std::size_t i = 0; i + 1 < wide.size(); i += 2) {
        wide_narrow.push_back(static_cast<char>(wide[i]));
    }
    EXPECT_EQ(wide_narrow, got_a);
}

TEST(WinApiLibloader, LoadLibraryAndFreeLibraryPassBodies) {
    register_dlls();

    const auto pe = build_minimal_pe64_with_exports();
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_libloader_rootfs";
    std::filesystem::create_directories(rootfs / "Windows" / "registry");
    const auto exe_path = rootfs / "minpe_test.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }
    // the stub dll: a valid but import-free PE the load_dll can map (the
    // System32 parent dir must exist for the ofstream to land the file)
    std::filesystem::create_directories(rootfs / "Windows" / "System32");
    const auto dll_path = rootfs / "Windows" / "System32" / "qldll.dll";
    {
        const auto dll_pe = build_minimal_pe64_with_exports();
        std::ofstream out(dll_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(dll_pe.data()), static_cast<std::streamsize>(dll_pe.size()));
        ASSERT_TRUE(out.good());
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    // LoadLibraryA: the dll base (the PE image base 0x140000000 is taken by
    // the main image, so the dll lands on the profile dll_address)
    const auto* load = ApiRegistry::instance().find("LoadLibraryA");
    ASSERT_NE(load, nullptr);
    const auto h1 = load->handler(ql, 0, ResolvedParams{{"lpLibFileName", std::string("qldll.dll")}});
    ASSERT_TRUE(h1.has_value());
    EXPECT_NE(*h1, 0u);

    // the second load rides the already-loaded check (the same base)
    const auto h2 = load->handler(ql, 0, ResolvedParams{{"lpLibFileName", std::string("qldll.dll")}});
    ASSERT_TRUE(h2.has_value());
    EXPECT_EQ(*h2, *h1);

    // GetProcAddress over the loaded dll: the MinFunc export resolves
    const auto* gp = ApiRegistry::instance().find("GetProcAddress");
    ASSERT_NE(gp, nullptr);
    const std::string fname = "MinFunc";
    ql.mem().write(kScratch + 0x40, std::vector<std::uint8_t>(fname.begin(), fname.end()));
    ql.mem().write(kScratch + 0x40 + fname.size(), std::vector<std::uint8_t>{0});
    const auto proc = gp->handler(ql, 0, ResolvedParams{
        {"hModule", *h1},
        {"lpProcName", kScratch + 0x40},
    });
    ASSERT_TRUE(proc.has_value());
    EXPECT_NE(*proc, 0u);

    // the LoadLibraryExA/W + the FreeLibrary + the DisableThreadLibraryCalls
    // ride their pass bodies
    const auto* load_ex = ApiRegistry::instance().find("LoadLibraryExA");
    ASSERT_NE(load_ex, nullptr);
    const auto hex = load_ex->handler(ql, 0, ResolvedParams{
        {"lpLibFileName", std::string("qldll.dll")},
        {"hFile", std::uint64_t{0}},
        {"dwFlags", std::uint64_t{0}},
    });
    ASSERT_TRUE(hex.has_value());
    EXPECT_EQ(*hex, *h1);

    const auto* free_ = ApiRegistry::instance().find("FreeLibrary");
    ASSERT_NE(free_, nullptr);
    const auto fr = free_->handler(ql, 0, ResolvedParams{{"hLibModule", *h1}});
    ASSERT_TRUE(fr.has_value());
    EXPECT_EQ(*fr, 1u);

    const auto* dtl = ApiRegistry::instance().find("DisableThreadLibraryCalls");
    ASSERT_NE(dtl, nullptr);
    const auto dt = dtl->handler(ql, 0, ResolvedParams{{"hLibModule", *h1}});
    ASSERT_TRUE(dt.has_value());
    EXPECT_EQ(*dt, 1u);
}

TEST(WinApiLibloader, ResourceAndDefaultDirsBodies) {
    register_dlls();
    Qiling ql(win_test_options());

    // the LoadResource/LockResource identity bodies
    const auto* load_res = ApiRegistry::instance().find("LoadResource");
    ASSERT_NE(load_res, nullptr);
    const auto lr = load_res->handler(ql, 0, ResolvedParams{
        {"hModule", std::uint64_t{0x1234}}, {"hResInfo", kCells}});
    ASSERT_TRUE(lr.has_value());
    EXPECT_EQ(*lr, kCells);

    const auto* lock_res = ApiRegistry::instance().find("LockResource");
    ASSERT_NE(lock_res, nullptr);
    const auto lk = lock_res->handler(ql, 0, ResolvedParams{{"hResData", kCells}});
    ASSERT_TRUE(lk.has_value());
    EXPECT_EQ(*lk, kCells);

    // the SizeofResource: the verbatim 0x8
    const auto* sizeof_res = ApiRegistry::instance().find("SizeofResource");
    ASSERT_NE(sizeof_res, nullptr);
    const auto sz = sizeof_res->handler(ql, 0, ResolvedParams{
        {"hModule", std::uint64_t{0}}, {"hResInfo", std::uint64_t{0}}});
    ASSERT_TRUE(sz.has_value());
    EXPECT_EQ(*sz, 0x8u);

    // the SetDefaultDllDirectories: the plain value rides the verbatim 1
    const auto* sdd = ApiRegistry::instance().find("SetDefaultDllDirectories");
    ASSERT_NE(sdd, nullptr);
    const auto ok = sdd->handler(ql, 0, ResolvedParams{{"DirectoryFlags", std::uint64_t{0x100}}});
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(*ok, 1u);

    // the LOAD_LIBRARY_SEARCH_USER_DIRS value raises the NotImplemented
    EXPECT_THROW(
        sdd->handler(ql, 0, ResolvedParams{{"DirectoryFlags", std::uint64_t{0x400}}}),
        QlErrorNotImplemented);
}

TEST(WinApiSysinfo, GetVersionAndVersionExVerbatim) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* ver = ApiRegistry::instance().find("GetVersion");
    ASSERT_NE(ver, nullptr);
    const auto r = ver->handler(ql, 0, {});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, ((0x0004ull << 16) | 0x0004ull));

    // the GetVersionEx pair: the verbatim 1 (no struct write, verbatim)
    const auto* vex_a = ApiRegistry::instance().find("GetVersionExA");
    ASSERT_NE(vex_a, nullptr);
    const auto ra = vex_a->handler(ql, 0, ResolvedParams{{"lpVersionInformation", kCells}});
    ASSERT_TRUE(ra.has_value());
    EXPECT_EQ(*ra, 1u);

    const auto* vex_w = ApiRegistry::instance().find("GetVersionExW");
    ASSERT_NE(vex_w, nullptr);
    const auto rw = vex_w->handler(ql, 0, ResolvedParams{{"lpVersionInformation", kCells}});
    ASSERT_TRUE(rw.has_value());
    EXPECT_EQ(*rw, 1u);
}

TEST(WinApiSysinfo, GetSystemInfoPacksCtypesLayout) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* info = ApiRegistry::instance().find("GetSystemInfo");
    ASSERT_NE(info, nullptr);
    const auto r = info->handler(ql, 0, ResolvedParams{{"lpSystemInfo", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);  // the void body rides the 0 return

    // the x64 SYSTEM_INFO layout (48 bytes): the verbatim values
    EXPECT_EQ(ql.mem().read_ptr(kCells + 0, 4), 0u);        // dwOemId
    EXPECT_EQ(ql.mem().read_ptr(kCells + 4, 4), 0x1000u);   // dwPageSize
    // the shellcode mode: the pe_image_address rides 0 (the loader never
    // loaded an image); the PE-mode rides the real base
    EXPECT_EQ(ql.mem().read_ptr(kCells + 8, 8), 0ull);  // lpMinimumApplicationAddress
    EXPECT_EQ(ql.mem().read_ptr(kCells + 24, 8), 0x3ull);   // dwActiveProcessorMask
    EXPECT_EQ(ql.mem().read_ptr(kCells + 32, 4), 0x4u);     // dwNumberOfProcessors
    EXPECT_EQ(ql.mem().read_ptr(kCells + 36, 4), 0x24au);   // dwProcessorType
    EXPECT_EQ(ql.mem().read_ptr(kCells + 40, 4), 0xa000u); // dwAllocationGranularity (the pagesize*10)
    EXPECT_EQ(ql.mem().read_ptr(kCells + 44, 2), 0x6u);     // wProcessorLevel
    EXPECT_EQ(ql.mem().read_ptr(kCells + 46, 2), 0x4601u);  // wProcessorRevision

    // the lpMaximumApplicationAddress = the dll_address + the dll_size
    auto& loader = static_cast<loader::QlLoaderPE&>(ql.loader());
    EXPECT_EQ(ql.mem().read_ptr(kCells + 16, 8),
              loader.dll_address() + loader.dll_size());

    // the native sibling shares the body
    EXPECT_NE(ApiRegistry::instance().find("GetNativeSystemInfo"), nullptr);
}

TEST(WinApiSysinfo, GetLocalTimeAndTickCount) {
    register_dlls();
    Qiling ql(win_test_options());

    // GetLocalTime: the SYSTEMTIME struct walk over the wall clock
    const auto* lt = ApiRegistry::instance().find("GetLocalTime");
    ASSERT_NE(lt, nullptr);
    const auto r = lt->handler(ql, 0, ResolvedParams{{"lpSystemTime", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    const auto year = ql.mem().read_ptr(kCells + 0, 2);
    const auto month = ql.mem().read_ptr(kCells + 2, 2);
    const auto dow = ql.mem().read_ptr(kCells + 4, 2);
    EXPECT_GE(year, 2020u);   // the wall clock is live
    EXPECT_LE(year, 2100u);
    EXPECT_GE(month, 1u);
    EXPECT_LE(month, 12u);
    EXPECT_GE(dow, 1u);       // the isoweekday: the 1=Monday..7=Sunday
    EXPECT_LE(dow, 7u);

    // GetTickCount: the verbatim 200000
    const auto* tick = ApiRegistry::instance().find("GetTickCount");
    ASSERT_NE(tick, nullptr);
    const auto t = tick->handler(ql, 0, {});
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(*t, 200000u);
}

TEST(WinApiSysinfo, GetSystemTimeAsFileTimeEpochWalk) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* ft = ApiRegistry::instance().find("GetSystemTimeAsFileTime");
    ASSERT_NE(ft, nullptr);
    const auto r = ft->handler(ql, 0, ResolvedParams{{"lpSystemTimeAsFileTime", kCells}});
    EXPECT_FALSE(r.has_value());  // the void body (the no return)

    // the 8-byte FILETIME: the 100ns ticks since the 1601 epoch; the value
    // must exceed the 2020 wall-clock lower bound (2020-01-01 in the 1601
    // epoch ~ 0x01d5bb0f...) and stay plausibly small
    const auto hnano = ql.mem().read_ptr(kCells, 8);
    EXPECT_GT(hnano, 132000000000000000ull);   // 2019-01-01
    EXPECT_LT(hnano, 135000000000000000ull);   // 2100-01-01

    // the Precise sibling: the verbatim microsecond-pack quirk (the raw u64
    // = the microsecond-of-the-minute, NOT a filetime)
    const auto* precise = ApiRegistry::instance().find("GetSystemTimePreciseAsFileTime");
    ASSERT_NE(precise, nullptr);
    const auto rp = precise->handler(ql, 0, ResolvedParams{{"lpSystemTimeAsFileTime", kCells + 0x40}});
    ASSERT_TRUE(rp.has_value());
    EXPECT_EQ(*rp, 0u);  // the verbatim return 0 (the precise body returns)
    const auto quirky = ql.mem().read_ptr(kCells + 0x40, 8);
    EXPECT_LT(quirky, 1000000ull);  // the microseconds within one minute
}

TEST(WinApiSysinfo, DirectoryQueriesRideProfilePaths) {
    register_dlls();
    Qiling ql(win_test_options());

    // the GetWindowsDirectory pair: the windir + the NUL, the utf-16le for W
    const auto* wd_w = ApiRegistry::instance().find("GetWindowsDirectoryW");
    ASSERT_NE(wd_w, nullptr);
    const auto rw = wd_w->handler(ql, 0, ResolvedParams{
        {"lpBuffer", kScratch}, {"uSize", std::uint64_t{0x100}}});
    ASSERT_TRUE(rw.has_value());

    const auto windir = ql.os<QlOsWindows>().windir();
    EXPECT_EQ(*rw, windir.size());
    const auto units = ql.mem().read(kScratch, windir.size() * 2 + 2);
    std::string decoded_w;
    for (std::size_t i = 0; i + 1 < units.size(); i += 2) {
        decoded_w.push_back(static_cast<char>(units[i]));
    }
    // the encoded buffer: the path + the utf-16le nul terminator
    EXPECT_EQ(decoded_w, windir + std::string(1, char(0)));
    EXPECT_EQ(decoded_w.back(), char(0));

    // the A form: the utf-8 (the latin-1 identity) bytes
    const auto* wd_a = ApiRegistry::instance().find("GetWindowsDirectoryA");
    ASSERT_NE(wd_a, nullptr);
    const auto ra = wd_a->handler(ql, 0, ResolvedParams{
        {"lpBuffer", kScratch + 0x100}, {"uSize", std::uint64_t{0x100}}});
    ASSERT_TRUE(ra.has_value());
    EXPECT_EQ(*ra, windir.size());
    const auto narrow = ql.mem().read(kScratch + 0x100, windir.size() + 1);
    EXPECT_EQ(std::string(narrow.begin(), narrow.end()), windir + std::string(1, char(0)));

    // the GetSystemWindowsDirectory pair: the same windir body (the shared
    // __GetWindowsDirectory, verbatim)
    EXPECT_NE(ApiRegistry::instance().find("GetSystemWindowsDirectoryW"), nullptr);
    EXPECT_NE(ApiRegistry::instance().find("GetSystemWindowsDirectoryA"), nullptr);
    const auto* swd = ApiRegistry::instance().find("GetSystemWindowsDirectoryA");
    const auto rswd = swd->handler(ql, 0, ResolvedParams{
        {"lpBuffer", kScratch + 0x200}, {"uSize", std::uint64_t{0x100}}});
    ASSERT_TRUE(rswd.has_value());
    EXPECT_EQ(*rswd, windir.size());

    // the GetSystemDirectory pair: the winsys
    const auto* sd_w = ApiRegistry::instance().find("GetSystemDirectoryW");
    ASSERT_NE(sd_w, nullptr);
    const auto winsys = ql.os<QlOsWindows>().winsys();
    const auto rsd = sd_w->handler(ql, 0, ResolvedParams{
        {"lpBuffer", kScratch + 0x300}, {"uSize", std::uint64_t{0x100}}});
    ASSERT_TRUE(rsd.has_value());
    EXPECT_EQ(*rsd, winsys.size());
    const auto units_sd = ql.mem().read(kScratch + 0x300, winsys.size() * 2 + 2);
    std::string decoded_sd;
    for (std::size_t i = 0; i + 1 < units_sd.size(); i += 2) {
        decoded_sd.push_back(static_cast<char>(units_sd[i]));
    }
    EXPECT_EQ(decoded_sd, winsys + std::string(1, char(0)));

    // the A sibling
    const auto* sd_a = ApiRegistry::instance().find("GetSystemDirectoryA");
    ASSERT_NE(sd_a, nullptr);
    const auto rsda = sd_a->handler(ql, 0, ResolvedParams{
        {"lpBuffer", kScratch + 0x400}, {"uSize", std::uint64_t{0x100}}});
    ASSERT_TRUE(rsda.has_value());
    EXPECT_EQ(*rsda, winsys.size());
    const auto narrow_sd = ql.mem().read(kScratch + 0x400, winsys.size() + 1);
    EXPECT_EQ(std::string(narrow_sd.begin(), narrow_sd.end()), winsys + std::string(1, char(0)));
}

TEST(WinApiSysinfo, GetSystemTimeMicrosecondPackQuirk) {
    register_dlls();
    Qiling ql(win_test_options());

    // GetSystemTime: the verbatim pack64 of the microsecond-of-the-minute
    // (NOT a SYSTEMTIME struct write — the upstream quirk rides verbatim)
    const auto* st = ApiRegistry::instance().find("GetSystemTime");
    ASSERT_NE(st, nullptr);
    const auto r = st->handler(ql, 0, ResolvedParams{{"lpSystemTime", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    const auto quirky = ql.mem().read_ptr(kCells, 8);
    EXPECT_LT(quirky, 1000000ull);  // the microseconds within one minute
}

TEST(WinApiProcessenv, GetStdHandlePassthroughReturnsStdHandle) {
    register_dlls();
    Qiling ql(win_test_options());

    // the verbatim body: the pseudo-handle rides back untouched
    const auto* gh = ApiRegistry::instance().find("GetStdHandle");
    ASSERT_NE(gh, nullptr);

    const auto r_out = gh->handler(ql, 0, ResolvedParams{{"nStdHandle", 0xFFFFFFF6ull}});
    ASSERT_TRUE(r_out.has_value());
    EXPECT_EQ(*r_out, 0xFFFFFFF6ull);  // the STD_OUTPUT_HANDLE pseudo-handle

    const auto r_in = gh->handler(ql, 0, ResolvedParams{{"nStdHandle", 0ull}});
    ASSERT_TRUE(r_in.has_value());
    EXPECT_EQ(*r_in, 0ull);
}

TEST(WinApiProcessenv, GetCommandLineAWritesDoubleNulTail) {
    register_dlls();

    // the PE-image mode: the cmdline rides the real target path
    const auto pe = build_minimal_pe64_with_exports();
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_processenv_rootfs";
    std::filesystem::create_directories(rootfs / "Windows" / "registry");
    const auto exe_path = rootfs / "minpe_test.exe";
    {
        std::ofstream out(exe_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    QilingOptions options;
    options.argv = {exe_path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::WINDOWS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    // the port's cmdline composition (the loader's concern): the basename +
    // the trailing NUL — the handler's shape (the second NUL, the wide
    // encode) is what rides under test here
    const auto& cmdline_vec = static_cast<loader::QlLoaderPE&>(ql.loader()).cmdline();
    const std::string target(cmdline_vec.begin(), cmdline_vec.end() - 1);
    ASSERT_EQ(target, "minpe_test.exe");

    // the A form: the cmdline (already NUL-terminated) + the verbatim second NUL
    const auto* gca = ApiRegistry::instance().find("GetCommandLineA");
    ASSERT_NE(gca, nullptr);
    const auto ra = gca->handler(ql, 0, {});
    ASSERT_TRUE(ra.has_value());
    const auto buf_a = ql.mem().read(*ra, target.size() + 2);
    std::string got_a(buf_a.begin(), buf_a.end());
    EXPECT_EQ(got_a, target + std::string(2, char(0)));

    // the W form: the utf-16le of the already-terminated cmdline (a single
    // wide NUL inside the buffer — no extra append, the verbatim asymmetry)
    const auto* gcw = ApiRegistry::instance().find("GetCommandLineW");
    ASSERT_NE(gcw, nullptr);
    const auto rw = gcw->handler(ql, 0, {});
    ASSERT_TRUE(rw.has_value());
    const auto buf_w = ql.mem().read(*rw, (target.size() + 1) * 2);
    std::string got_w;
    for (std::size_t i = 0; i + 1 < buf_w.size(); i += 2) {
        got_w.push_back(static_cast<char>(buf_w[i]));
    }
    EXPECT_EQ(got_w, target + std::string(1, char(0)));  // the cmdline's own NUL rides wide
    EXPECT_EQ(buf_w[buf_w.size() - 1], 0);  // the trailing wide NUL
}

TEST(WinApiProcessenv, GetEnvironmentStringsWritesEmptyBlocks) {
    register_dlls();
    Qiling ql(win_test_options());

    // the A block: envstr = b"\x00" — the empty block is a single NUL
    const auto* ge = ApiRegistry::instance().find("GetEnvironmentStrings");
    ASSERT_NE(ge, nullptr);
    const auto r = ge->handler(ql, 0, {});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(ql.mem().read(*r, 1), std::vector<std::uint8_t>{0});

    // the W block: envstr = b"\x00\x00" — two NULs
    const auto* gew = ApiRegistry::instance().find("GetEnvironmentStringsW");
    ASSERT_NE(gew, nullptr);
    const auto rw = gew->handler(ql, 0, {});
    ASSERT_TRUE(rw.has_value());
    EXPECT_EQ(ql.mem().read(*rw, 2), (std::vector<std::uint8_t>{0, 0}));

    // the free body rides the verbatim 1
    const auto* fe = ApiRegistry::instance().find("FreeEnvironmentStringsW");
    ASSERT_NE(fe, nullptr);
    const auto rf = fe->handler(ql, 0, ResolvedParams{{"penv", *rw}});
    ASSERT_TRUE(rf.has_value());
    EXPECT_EQ(*rf, 1u);
}

TEST(WinApiProcessenv, ExpandEnvironmentStringsResolvesProfileVars) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* ee = ApiRegistry::instance().find("ExpandEnvironmentStringsW");
    ASSERT_NE(ee, nullptr);

    // %windir% resolves through the profile PATH section ("Windows")
    const auto r1 = ee->handler(ql, 0, ResolvedParams{
        {"lpSrc", std::string("%windir%\\system32")},
        {"lpDst", kScratch},
        {"nSize", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 34ull);  // ("Windows\\system32" + NUL) * 2 bytes

    std::string got1;
    const auto wide1 = ql.mem().read(kScratch, *r1);
    for (std::size_t i = 0; i + 1 < wide1.size(); i += 2) {
        got1.push_back(static_cast<char>(wide1[i]));
    }
    EXPECT_EQ(got1, "Windows\\system32" + std::string(1, char(0)));

    // the unknown key keeps its %KEY% spelling (the verbatim val = f'%{key}%')
    const auto r2 = ee->handler(ql, 0, ResolvedParams{
        {"lpSrc", std::string("%GhostKey%")},
        {"lpDst", kScratch + 0x100},
        {"nSize", std::uint64_t{0x100}},
    });
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 22ull);  // ("%GhostKey%" + NUL) * 2

    std::string got2;
    const auto wide2 = ql.mem().read(kScratch + 0x100, *r2);
    for (std::size_t i = 0; i + 1 < wide2.size(); i += 2) {
        got2.push_back(static_cast<char>(wide2[i]));
    }
    EXPECT_EQ(got2, "%GhostKey%" + std::string(1, char(0)));
}

TEST(WinApiProcessenv, ExpandEnvironmentStringsSizeGuardSkipsWrite) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* ee = ApiRegistry::instance().find("ExpandEnvironmentStringsW");
    ASSERT_NE(ee, nullptr);

    // the verbatim quirk: the nSize compare rides BYTES, not TCHARs; a
    // short buffer skips the write but the full byte length still returns
    ql.mem().write(kScratch, std::vector<std::uint8_t>(0x40, 0x7E));  // the ~ sentinel
    const auto r = ee->handler(ql, 0, ResolvedParams{
        {"lpSrc", std::string("%windir%")},
        {"lpDst", kScratch},
        {"nSize", std::uint64_t{8}},  // < ("Windows" + NUL) * 2 = 16
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 16ull);

    const auto sent = ql.mem().read(kScratch, 0x40);
    EXPECT_EQ(sent[0], 0x7E);  // untouched
    EXPECT_EQ(sent[15], 0x7E);
}

TEST(WinApiProcessenv, GetEnvironmentVariableReturnsZeroFlat) {
    register_dlls();
    Qiling ql(win_test_options());

    // the verbatim bodies: the flat 0, no buffer write
    const auto* eva = ApiRegistry::instance().find("GetEnvironmentVariableA");
    ASSERT_NE(eva, nullptr);
    ql.mem().write(kCells, std::vector<std::uint8_t>(8, 0x7E));
    const auto ra = eva->handler(ql, 0, ResolvedParams{
        {"lpName", std::string("PATH")},
        {"lpBuffer", kCells},
        {"nSize", std::uint64_t{8}},
    });
    ASSERT_TRUE(ra.has_value());
    EXPECT_EQ(*ra, 0u);
    EXPECT_EQ(ql.mem().read(kCells, 8)[0], 0x7E);  // untouched

    const auto* evw = ApiRegistry::instance().find("GetEnvironmentVariableW");
    ASSERT_NE(evw, nullptr);
    const auto rw = evw->handler(ql, 0, ResolvedParams{
        {"lpName", std::string("PATH")},
        {"lpBuffer", kCells},
        {"nSize", std::uint64_t{8}},
    });
    ASSERT_TRUE(rw.has_value());
    EXPECT_EQ(*rw, 0u);
}

TEST(WinApiInterlocked, InitializeSListHeadRegistersHandleAtAddress) {
    register_dlls();
    Qiling ql(win_test_options());

    // the verbatim body: the handle id IS the ListHead address (the obj = []
    // placeholder), the return rides the 0
    const auto* ih = ApiRegistry::instance().find("InitializeSListHead");
    ASSERT_NE(ih, nullptr);
    const auto r = ih->handler(ql, 0, ResolvedParams{{"ListHead", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);

    // the handle manager answers at the ListHead id
    auto& os = ql.os<QlOsWindows>();
    const auto* h = os.handle_manager().get(kCells);
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(h->id, kCells);
}

TEST(WinApiErrhandling, LastErrorCycleAndFilterSwap) {
    register_dlls();
    Qiling ql(win_test_options());

    // the SetLastError/GetLastError cycle
    const auto* sle = ApiRegistry::instance().find("SetLastError");
    ASSERT_NE(sle, nullptr);
    const auto rs = sle->handler(ql, 0, ResolvedParams{{"dwErrCode", 0x57ull}});
    EXPECT_FALSE(rs.has_value());  // the void body

    const auto* gle = ApiRegistry::instance().find("GetLastError");
    ASSERT_NE(gle, nullptr);
    const auto rg = gle->handler(ql, 0, {});
    ASSERT_TRUE(rg.has_value());
    EXPECT_EQ(*rg, 0x57u);

    // the SetErrorMode rides the verbatim 0
    const auto* sem = ApiRegistry::instance().find("SetErrorMode");
    ASSERT_NE(sem, nullptr);
    const auto rm = sem->handler(ql, 0, ResolvedParams{{"uMode", 0x4ull}});
    ASSERT_TRUE(rm.has_value());
    EXPECT_EQ(*rm, 0u);

    // the first filter call registers under the canonical name and returns 0
    const auto* suf = ApiRegistry::instance().find("SetUnhandledExceptionFilter");
    ASSERT_NE(suf, nullptr);
    const auto r1 = suf->handler(ql, 0, ResolvedParams{{"lpTopLevelExceptionFilter", 0x2000ull}});
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0u);

    // the second call returns the previous filter and swaps the obj
    const auto r2 = suf->handler(ql, 0, ResolvedParams{{"lpTopLevelExceptionFilter", 0x3000ull}});
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x2000u);

    auto& os = ql.os<QlOsWindows>();
    const auto* h = os.handle_manager().search("TopLevelExceptionHandler");
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(reinterpret_cast<std::uint64_t>(h->obj), 0x3000u);
}

TEST(WinApiErrhandling, VectoredExceptionAddAndRemoveRideHandleManager) {
    register_dlls();
    Qiling ql(win_test_options());

    const auto* add = ApiRegistry::instance().find("AddVectoredExceptionHandler");
    ASSERT_NE(add, nullptr);
    const auto r = add->handler(ql, 0, ResolvedParams{
        {"First", 0ull},
        {"Handler", 0x4000ull},
    });
    ASSERT_TRUE(r.has_value());
    EXPECT_NE(*r, 0u);  // the handle id

    auto& os = ql.os<QlOsWindows>();
    auto* h = os.handle_manager().get(*r);
    ASSERT_NE(h, nullptr);
    // the verbatim shape: the handle obj IS the 0x2d HookRet (not the handler
    // address — the upstream Handle(obj=hook) rides the hook object)
    ASSERT_NE(h->obj, nullptr);
    ASSERT_NE(h->owned, nullptr);  // the HookRet stays alive via the owned slot

    // the Remove body unregisters the 0x2d hook (the handle rides the
    // HookRet) and returns the verbatim 0
    const auto* rem = ApiRegistry::instance().find("RemoveVectoredExceptionHandler");
    ASSERT_NE(rem, nullptr);
    const auto rr = rem->handler(ql, 0, ResolvedParams{{"Handle", *r}});
    ASSERT_TRUE(rr.has_value());
    EXPECT_EQ(*rr, 0u);
}

TEST(WinApiErrhandling, RaiseExceptionPassthruOnX64) {
    register_dlls();
    Qiling ql(win_test_options());

    // the x8664 path: the passthru continues into the native dispatcher (the
    // verbatim comment ride); the handler returns no value
    const auto* re = ApiRegistry::instance().find("RaiseException");
    ASSERT_NE(re, nullptr);
    const auto r = re->handler(ql, 0, ResolvedParams{
        {"dwExceptionCode", 0xE0000001ull},
        {"dwExceptionFlags", 0ull},
        {"nNumberOfArguments", 0ull},
        {"lpArguments", 0ull},
    });
    EXPECT_FALSE(r.has_value());
}

TEST(WinApiProfileapi, QueryPerformancePairRideVerbatimShapes) {
    register_dlls();
    Qiling ql(win_test_options());

    // the counter: the verbatim 0 with NO write into the caller's cell
    ql.mem().write(kCells, std::vector<std::uint8_t>(8, 0x7E));
    const auto* qpc = ApiRegistry::instance().find("QueryPerformanceCounter");
    ASSERT_NE(qpc, nullptr);
    const auto r = qpc->handler(ql, 0, ResolvedParams{{"lpPerformanceCount", kCells}});
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);
    EXPECT_EQ(ql.mem().read_ptr(kCells, 8), 0x7E7E7E7E7E7E7E7Eull);  // untouched

    // the frequency: the verbatim 10000000 write + the 1 return
    const auto* qpf = ApiRegistry::instance().find("QueryPerformanceFrequency");
    ASSERT_NE(qpf, nullptr);
    const auto rf = qpf->handler(ql, 0, ResolvedParams{{"lpFrequency", kCells + 0x100}});
    ASSERT_TRUE(rf.has_value());
    EXPECT_EQ(*rf, 1u);
    EXPECT_EQ(ql.mem().read_ptr(kCells + 0x100, 8), 10000000ull);
}
