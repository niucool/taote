// Ported from qiling/os/windows/dlls/kernel32/fileapi.py — the file I/O
// family. The @winsdkapi decorators map onto register_fileapi_family(); the
// bodies ride the verbatim upstream walks over the fs-mapper/path/handle
// surfaces. The CreateFileMapping/MapViewOfFile trio rides the FileMapping
// classes (the page-file-backed memory flavour + the file-backed mem-hook
// flavour) exactly as the upstream does.
#include "qiling/core.hpp"
#include "qiling/os/mapper.hpp"
#include "qiling/os/path.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <chrono>
#include <filesystem>

namespace qiling {
namespace os {
namespace win {

namespace {

// the resolved params arrive through the os.call orchestration; the handlers
// read via the named accessors (the python params["name"] shape)
windows::QlOsWindows& w(Qiling& ql) { return ql.os<os::windows::QlOsWindows>(); }

// the INVALID_HANDLE_VALUE sentinel: the windows.h macro rides (HANDLE)-1 on
// _WIN32 (the pointer-width -1); the const.hpp u64 spelling applies elsewhere.
// The call sites compare the raw u64 param against the all-ones pattern.
constexpr std::uint64_t kInvalidHandleValue = 0xffffffffffffffffull;

// windows.py hook_FindFirstFileA: the guest-relative time origin (Jan 1 1601)
// in 100ns ticks — where: (10 ** 9) / 100 -> (10 ** 7)
std::uint64_t filetime_now() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    // 11644473600 seconds between 1601-01-01 and 1970-01-01
    return static_cast<std::uint64_t>(ns) / 100 + 116444736000000000ull;
}

// latin-1 widened to the utf-16le units (the upstream .encode('utf-16le') over
// the decoded path)
std::string encode_utf16le(std::string_view s) {
    std::string out;
    out.reserve(s.size() * 2);
    for (const char c : s) {
        out.push_back(c);
        out.push_back('\0');
    }
    return out;
}

void write_utf16le_cell(Qiling& ql, std::uint64_t at, std::string_view s) {
    auto encoded = encode_utf16le(s);
    encoded.push_back('\0');
    encoded.push_back('\0');
    ql.mem().write(at, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));
}

}  // namespace

// ---- the FileMapping classes (fileapi.py FileMappingMem/FileMappingFile) ----

namespace {

// mapping backed my page file, for which we simply use memory. no need to do
// anything really (verbatim)
struct FileMapping {
    virtual ~FileMapping() = default;
};

struct FileMappingMem : FileMapping {};

class FileMappingFile final : public FileMapping {
public:
    FileMappingFile(std::shared_ptr<QlFsMappedObject> fobj, Qiling& ql) : fobj_(std::move(fobj)), ql_(&ql) {}

    std::uint64_t get_file_size() {
        // fileapi.py __seek_temporary: the seek walks run against the current
        // position and restore it
        const auto fpos = fobj_->tell();
        const auto size = fobj_->lseek(0, 2);  // os.SEEK_END
        fobj_->lseek(fpos, 0);                 // os.SEEK_SET
        return size;
    }

    void inc_file_size(std::uint64_t addendum) {
        const auto fpos = fobj_->tell();
        fobj_->lseek(0, 2);  // os.SEEK_END
        fobj_->write(std::vector<std::uint8_t>(static_cast<std::size_t>(addendum), 0));
        fobj_->lseek(fpos, 0);
    }

    std::vector<std::uint8_t> read(std::uint64_t offset, std::uint64_t size) {
        const auto fpos = fobj_->tell();
        fobj_->lseek(offset, 0);
        auto data = fobj_->read(static_cast<std::size_t>(size));
        fobj_->lseek(fpos, 0);
        return data;
    }

    void write(std::uint64_t offset, const std::vector<std::uint8_t>& data) {
        const auto fpos = fobj_->tell();
        fobj_->lseek(offset, 0);
        fobj_->write(data);
        fobj_->lseek(fpos, 0);
    }

    void map_view(Qiling& ql, std::uint64_t fbase, std::uint64_t lbound, std::uint64_t ubound) {
        // __read_mapview: fetch the corresponding file part into memory.
        // FIXME: that triggers the write hook, and may be problematic for
        // read-only ranges (verbatim)
        read_hook_ = ql.hook_mem_read(
            [this, fbase, lbound](int, std::uint64_t addr, std::uint32_t size, std::int64_t) -> int {
                const auto data = read(fbase + (addr - lbound), size);
                ql_->mem().write(addr, data);
                return 0;
            },
            lbound, ubound);

        // __write_mapview: write data back to the corresponding file part
        write_hook_ = ql.hook_mem_write(
            [this, fbase, lbound](int, std::uint64_t addr, std::uint32_t size, std::int64_t value) -> int {
                std::string packed;
                switch (size) {
                    case 1: packed.assign(1, static_cast<char>(value)); break;
                    case 2: packed = ql_->pack16(static_cast<std::uint64_t>(value)); break;
                    case 4: packed = ql_->pack32(static_cast<std::uint64_t>(value)); break;
                    default: packed = ql_->pack64(static_cast<std::uint64_t>(value)); break;
                }
                write(fbase + (addr - lbound),
                      std::vector<std::uint8_t>(packed.begin(), packed.end()));
                return 0;
            },
            lbound, ubound);
    }

    void unmap_view() {
        if (read_hook_.obj() != nullptr) {
            read_hook_.remove();
        }
        if (write_hook_.obj() != nullptr) {
            write_hook_.remove();
        }
        read_hook_ = HookRet();
        write_hook_ = HookRet();
        ql_ = nullptr;
    }

private:
    std::shared_ptr<QlFsMappedObject> fobj_;
    Qiling* ql_ = nullptr;
    HookRet read_hook_;
    HookRet write_hook_;
};

// the _GetTempPath walk (fileapi.py _GetTempPath, the wide/narrow flavour)
std::uint64_t get_temp_path_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    // ntpath.join(ql.os.windir, 'Temp')
    const std::string vtmpdir = w(ql).windir() + "\\Temp";
    const auto htmpdir = w(ql).path()->virtual_to_host_path(vtmpdir);

    if (w(ql).path()->is_safe_host_path(htmpdir)) {
        std::error_code ec;
        if (!std::filesystem::exists(htmpdir, ec)) {
            std::filesystem::create_directories(htmpdir, ec);
        }
    }

    const auto nBufferLength = api_get_int(get_param(params, "nBufferLength"));
    const auto lpBuffer = api_get_int(get_param(params, "lpBuffer"));

    // temp dir path has to end with a path separator; the returned length
    // does not include the null-terminator
    const auto tmpdir = vtmpdir + "\\";
    auto cstr = wide ? encode_utf16le(tmpdir) : std::string(tmpdir);
    cstr.push_back('\0');
    if (wide) {
        cstr.push_back('\0');
    }

    if (nBufferLength >= cstr.size()) {
        ql.mem().write(lpBuffer, std::vector<std::uint8_t>(cstr.begin(), cstr.end()));
    }

    return tmpdir.size();
}

// the _CreateFileMapping walk shared by the A/W entries
std::optional<std::uint64_t> create_file_mapping_body(Qiling& ql, const ResolvedParams& params) {
    const auto hFile = api_get_int(get_param(params, "hFile"));
    const auto dwMaximumSizeHigh = api_get_int(get_param(params, "dwMaximumSizeHigh"));
    const auto dwMaximumSizeLow = api_get_int(get_param(params, "dwMaximumSizeLow"));
    // the placeholder-typed lpName arrives decoded for both the A/W spellings
    // (the resolve_named_params ride); the upstream reads params["lpName"]
    const auto lpName = api_get_string(ql, get_param(params, "lpName"));

    const auto req_size = (dwMaximumSizeHigh << 32) | dwMaximumSizeLow;

    if (hFile == kInvalidHandleValue) {
        auto fm_handle_owned = std::shared_ptr<void>(new FileMappingMem());
        Handle fm_handle;
        fm_handle.obj = fm_handle_owned.get();
        fm_handle.owned = fm_handle_owned;
        if (!lpName.empty()) {
            fm_handle.name = lpName;
        }
        w(ql).handle_manager().append(fm_handle);
        return fm_handle.id;
    }

    // look for an existing mapping handle with the same name
    if (!lpName.empty()) {
        const auto* existing_handle = w(ql).handle_manager().search(lpName);
        if (existing_handle != nullptr) {
            return existing_handle->id;
        }
    }

    const auto* fhandle = w(ql).handle_manager().get(hFile);
    if (fhandle == nullptr) {
        return 0;
    }

    // wrap the opened file with an accessor class; the underlying file stays
    // alive via the source handle's owned slot, the wrapper rides its own
    // shared_ptr (the python FileMappingFile(fhandle.obj) reference shape)
    auto fm_owned = std::shared_ptr<FileMappingFile>(
        new FileMappingFile(std::shared_ptr<QlFsMappedObject>(
                                static_cast<QlFsMappedObject*>(fhandle->obj), [](QlFsMappedObject*) {}),
                            ql));
    const auto fsize = fm_owned->get_file_size();

    // if requeted mapping is size is larger than the file size, enlarge it
    if (req_size > fsize) {
        fm_owned->inc_file_size(req_size - fsize);
    }

    Handle fm_handle;
    fm_handle.obj = fm_owned.get();
    fm_handle.owned = fm_owned;
    if (!lpName.empty()) {
        fm_handle.name = lpName;
    }
    w(ql).handle_manager().append(fm_handle);

    return fm_handle.id;
}

}  // namespace

void register_fileapi_family() {
    using namespace qiling::os::api;

    // DWORD GetFileType(HANDLE hFile);
    WinsdkApi("GetFileType", WinCc::Stdcall, {
        {"hFile", HANDLE_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto hFile = api_get_int(get_param(params, "hFile"));

        const auto* handle = w(ql).handle_manager().get(hFile);
        if (handle == nullptr) {
            throw QlErrorNotImplemented("API not implemented");
        }

        // technically is not always a type_char but.. almost
        return FILE_TYPE_CHAR;
    };

    // the FindFirstFileA/ExA bodies (the ExA carries the unused search args)
    const auto find_first_file_body = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto filename = api_get_string(ql, get_param(params, "lpFileName"));
        const auto pointer = api_get_int(get_param(params, "lpFindFileData"));

        if (filename.empty()) {
            return kInvalidHandleValue;
        }

        if (filename.size() >= WIN_MAX_PATH) {
            return ERROR_INVALID_PARAMETER;
        }

        // Check if path exists
        std::shared_ptr<QlFsMappedObject> f;
        std::uint64_t filesize = 0;
        try {
            f = w(ql).fs_mapper()->open(filename, "r");
            filesize = std::filesystem::file_size(f->name());
        } catch (const std::filesystem::filesystem_error&) {
            w(ql).set_last_error(ERROR_FILE_NOT_FOUND);
            return kInvalidHandleValue;
        }

        // Create a handle for the path
        Handle new_handle;
        new_handle.obj = f.get();
        new_handle.owned = f;
        w(ql).handle_manager().append(new_handle);

        // calculate file time (fileapi.py: the 100ns ticks since 1601)
        const auto hnano = filetime_now();

        char fdata[WIN32_FIND_DATAA_SIZE];
        write_win32_find_dataa(fdata, FILE_ATTRIBUTE_NORMAL, hnano, filesize, filename);
        ql.mem().write(pointer, std::vector<std::uint8_t>(fdata, fdata + WIN32_FIND_DATAA_SIZE));

        return new_handle.id;
    };

    // HANDLE FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
    WinsdkApi("FindFirstFileA", WinCc::Stdcall, {
        {"lpFileName", LPCSTR_},
        {"lpFindFileData", LPHANDLE_},
    }) = find_first_file_body;

    // HANDLE FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS
    // fInfoLevelId, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD
    // dwAdditionalFlags);
    WinsdkApi("FindFirstFileExA", WinCc::Stdcall, {
        {"lpFileName", LPCSTR_},
        {"fInfoLevelId", DWORD_},
        {"lpFindFileData", LPHANDLE_},
        {"fSearchOp", DWORD_},
        {"lpSearchFilter", LPVOID_},
        {"dwAdditionalFlags", DWORD_},
    }) = find_first_file_body;

    // BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
    WinsdkApi("FindNextFileA", WinCc::Stdcall, {
        {"hFindFile", HANDLE_},
        {"lpFindFileData", LPHANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;  // pass (verbatim)
    };

    // BOOL FindClose(HANDLE hFindFile);
    WinsdkApi("FindClose", WinCc::Stdcall, {
        {"hFindFile", HANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;  // pass (verbatim)
    };

    // BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    //               LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    WinsdkApi("ReadFile", WinCc::Stdcall, {
        {"hFile", HANDLE_},
        {"lpBuffer", LPVOID_},
        {"nNumberOfBytesToRead", DWORD_},
        {"lpNumberOfBytesRead", LPDWORD_},
        {"lpOverlapped", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto hFile = api_get_int(get_param(params, "hFile"));
        const auto lpBuffer = api_get_int(get_param(params, "lpBuffer"));
        const auto nNumberOfBytesToRead = api_get_int(get_param(params, "nNumberOfBytesToRead"));
        const auto lpNumberOfBytesRead = api_get_int(get_param(params, "lpNumberOfBytesRead"));

        auto& win = w(ql);
        const auto* handle = win.handle_manager().get(hFile);

        if (handle == nullptr) {
            win.set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }

        const auto data = static_cast<QlFsMappedObject*>(handle->obj)->read(static_cast<std::size_t>(nNumberOfBytesToRead));

        ql.mem().write(lpBuffer, data);
        ql.mem().write_ptr(lpNumberOfBytesRead, static_cast<std::int64_t>(data.size()), 4);

        return 1;
    };

    // BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD
    // nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED
    // lpOverlapped);
    WinsdkApi("WriteFile", WinCc::Stdcall, {
        {"hFile", HANDLE_},
        {"lpBuffer", LPVOID_},
        {"nNumberOfBytesToWrite", DWORD_},
        {"lpNumberOfBytesWritten", LPDWORD_},
        {"lpOverlapped", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto hFile = api_get_int(get_param(params, "hFile"));
        const auto lpBuffer = api_get_int(get_param(params, "lpBuffer"));
        const auto nNumberOfBytesToWrite = api_get_int(get_param(params, "nNumberOfBytesToWrite"));
        const auto lpNumberOfBytesWritten = api_get_int(get_param(params, "lpNumberOfBytesWritten"));

        auto& win = w(ql);
        const auto* handle = win.handle_manager().get(hFile);

        if (handle == nullptr) {
            win.set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }

        const auto data = ql.mem().read(lpBuffer, static_cast<std::size_t>(nNumberOfBytesToWrite));

        if (hFile == STD_OUTPUT_HANDLE || hFile == STD_ERROR_HANDLE) {
            win.stats().log_string(std::string(data.begin(), data.end()));
        }

        const auto written = static_cast<QlFsMappedObject*>(handle->obj)->write(data);
        ql.mem().write_ptr(lpNumberOfBytesWritten, static_cast<std::int64_t>(written), 4);

        return 1;
    };

    // the _CreateFile walk (fileapi.py _CreateFile) shared by the A/W entries
    const auto create_file_body = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s_lpFileName = api_get_string(ql, get_param(params, "lpFileName"));
        const auto dwDesiredAccess = api_get_int(get_param(params, "dwDesiredAccess"));
        const auto dwCreationDisposition = api_get_int(get_param(params, "dwCreationDisposition"));

        // access mask DesiredAccess
        const auto perm_write = dwDesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA);
        const auto perm_read = dwDesiredAccess & (GENERIC_READ | FILE_READ_DATA);

        // TODO: unused (verbatim)
        (void)(dwDesiredAccess & (GENERIC_EXECUTE | FILE_EXECUTE));

        // only open file if it exists. error otherwise
        const auto open_existing = (dwCreationDisposition == OPEN_EXISTING) ||
                                   (dwCreationDisposition == TRUNCATE_EXISTING);

        // check if the file exists (TODO: race condition if file is
        // deleted/reated, verbatim)
        const auto file_exists = w(ql).fs_mapper()->file_exists(s_lpFileName);

        if (open_existing && !file_exists) {
            // the CreationDisposition wants a file to exist; it does not
            w(ql).set_last_error(ERROR_FILE_NOT_FOUND);
            return kInvalidHandleValue;
        }

        if (dwCreationDisposition == CREATE_NEW && file_exists) {
            // only create a file if it does not exist. if it does, error
            w(ql).set_last_error(ERROR_FILE_EXISTS);
        }

        const auto truncate = (dwCreationDisposition == CREATE_ALWAYS) ||
                              (dwCreationDisposition == TRUNCATE_EXISTING);

        std::string mode;
        if (perm_read != 0 && perm_write == 0) {
            // read only
            mode = "rb";
        } else if (perm_write != 0 && perm_read == 0) {
            // Write only: TODO: fopen modes do not allow for write only
            // access. Likely need to use os.open instead. (verbatim)
            if ((truncate && !open_existing) || (truncate && open_existing && file_exists)) {
                // create a new file or truncate an existing one
                mode = "wb";
            } else {
                // read/write, do not create. do not truncatd (verbatim)
                mode = "rb+";
            }
        } else if (perm_read != 0 && perm_write != 0) {
            // Note that this ignores exec access mask (verbatim)
            mode = "rb+";
        } else {
            // This is probably an invalid access mask (verbatim, TODO: add
            // error code)
            return kInvalidHandleValue;
        }

        std::shared_ptr<QlFsMappedObject> f;
        try {
            // we should have exited by now if the file doesn't exist
            if (!file_exists && mode != "wb") {
                if (!w(ql).fs_mapper()->create_empty_file(s_lpFileName)) {
                    // could not create a new file; bail out. TODO: set
                    // last_error (verbatim)
                    return kInvalidHandleValue;
                }
            }

            f = w(ql).fs_mapper()->open(s_lpFileName, mode);
            if (truncate && mode != "wb") {
                // redundant if mode is wb (verbatim)
                std::error_code ec;
                std::filesystem::resize_file(f->name(), 0, ec);
            }

            if (dwCreationDisposition == CREATE_ALWAYS) {
                // we overwrote the file.
                w(ql).set_last_error(ERROR_ALREADY_EXISTS);
            }

            if (dwCreationDisposition == OPEN_ALWAYS) {
                w(ql).set_last_error(ERROR_ALREADY_EXISTS);
            }
        } catch (const QlErrorBase&) {
            // Creation disposition determines what happens when the file
            // doesn't exist
            w(ql).set_last_error(ERROR_FILE_NOT_FOUND);
            return kInvalidHandleValue;
        }

        Handle new_handle;
        new_handle.obj = f.get();
        new_handle.owned = f;
        w(ql).handle_manager().append(new_handle);

        return new_handle.id;
    };

    // HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD
    // dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD
    // dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    WinsdkApi("CreateFileA", WinCc::Stdcall, {
        {"lpFileName", LPCSTR_},
        {"dwDesiredAccess", DWORD_},
        {"dwShareMode", DWORD_},
        {"lpSecurityAttributes", LPVOID_},
        {"dwCreationDisposition", DWORD_},
        {"dwFlagsAndAttributes", DWORD_},
        {"hTemplateFile", HANDLE_},
    }) = create_file_body;

    // HANDLE CreateFileW(LPCWSTR lpFileName, ... the W-side signature);
    WinsdkApi("CreateFileW", WinCc::Stdcall, {
        {"lpFileName", LPCWSTR_},
        {"dwDesiredAccess", DWORD_},
        {"dwShareMode", DWORD_},
        {"lpSecurityAttributes", LPVOID_},
        {"dwCreationDisposition", DWORD_},
        {"dwFlagsAndAttributes", DWORD_},
        {"hTemplateFile", HANDLE_},
    }) = create_file_body;

    // DWORD GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer);
    WinsdkApi("GetTempPathW", WinCc::Stdcall, {
        {"nBufferLength", DWORD_},
        {"lpBuffer", LPWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_temp_path_body(ql, params, true);
    };

    // DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
    WinsdkApi("GetTempPathA", WinCc::Stdcall, {
        {"nBufferLength", DWORD_},
        {"lpBuffer", LPSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_temp_path_body(ql, params, false);
    };

    // DWORD GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath,
    //                         DWORD cchBuffer);
    WinsdkApi("GetShortPathNameW", WinCc::Stdcall, {
        {"lpszLongPath", LPCWSTR_},
        {"lpszShortPath", LPWSTR_},
        {"cchBuffer", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lpszLongPath = api_get_string(ql, get_param(params, "lpszLongPath"));
        const auto lpszShortPath = api_get_int(get_param(params, "lpszShortPath"));
        const auto cchBuffer = api_get_int(get_param(params, "cchBuffer"));

        // the 8.3 shorten walk (fileapi.py __shorten)
        const auto shorten = [](const std::string& p) -> std::string {
            const auto dot = p.rfind('.');
            const auto name = dot == std::string::npos ? p : p.substr(0, dot);
            const auto ext = dot == std::string::npos ? std::string() : p.substr(dot);
            if (name.size() > 8) {
                return name.substr(0, 6) + "~1" + ext;
            }
            return name + ext;
        };

        std::string shortpath;
        std::size_t start = 0;
        while (start < lpszLongPath.size()) {
            const auto sep = lpszLongPath.find('\\', start);
            const auto end = sep == std::string::npos ? lpszLongPath.size() : sep;
            if (!shortpath.empty()) {
                shortpath += '\\';
            }
            shortpath += shorten(lpszLongPath.substr(start, end - start));
            if (sep == std::string::npos) {
                break;
            }
            start = sep + 1;
        }

        if (shortpath.size() > cchBuffer) {
            return shortpath.size() + 1;
        }

        if (lpszShortPath != 0) {
            write_utf16le_cell(ql, lpszShortPath, shortpath);
        }

        // on succes, return chars count excluding null-term
        return shortpath.size();
    };

    // BOOL GetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR
    // lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,
    // LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR
    // lpFileSystemNameBuffer, DWORD nFileSystemNameSize);
    WinsdkApi("GetVolumeInformationW", WinCc::Stdcall, {
        {"lpRootPathName", LPCWSTR_},
        {"lpVolumeNameBuffer", LPWSTR_},
        {"nVolumeNameSize", DWORD_},
        {"lpVolumeSerialNumber", LPDWORD_},
        {"lpMaximumComponentLength", LPDWORD_},
        {"lpFileSystemFlags", LPDWORD_},
        {"lpFileSystemNameBuffer", LPWSTR_},
        {"nFileSystemNameSize", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto root = api_get_string(ql, get_param(params, "lpRootPathName"));

        if (root.empty()) {
            throw QlErrorNotImplemented("API not implemented");
        }

        const auto pt_volume_name = api_get_int(get_param(params, "lpVolumeNameBuffer"));
        if (pt_volume_name != 0) {
            // TODO implement (verbatim)
            write_utf16le_cell(ql, pt_volume_name, ql.profile().get("VOLUME", "name").value_or(""));
        }

        const auto lpMaximumComponentLength = api_get_int(get_param(params, "lpMaximumComponentLength"));
        if (lpMaximumComponentLength != 0) {
            ql.mem().write_ptr(lpMaximumComponentLength, 255, 2);
        }

        const auto pt_serial_number = api_get_int(get_param(params, "lpVolumeSerialNumber"));
        if (pt_serial_number != 0) {
            // TODO maybe has to be int (verbatim)
            write_utf16le_cell(ql, pt_serial_number, ql.profile().get("VOLUME", "serial_number").value_or(""));
        }

        const auto pt_system_type = api_get_int(get_param(params, "lpFileSystemNameBuffer"));
        const auto pt_flag = api_get_int(get_param(params, "lpFileSystemFlags"));

        if (pt_flag != 0) {
            // TODO implement (verbatim)
            ql.mem().write_ptr(pt_flag, 0x00020000, 4);
        }

        if (pt_system_type != 0) {
            write_utf16le_cell(ql, pt_system_type, ql.profile().get("VOLUME", "type").value_or(""));
        }

        return 1;
    };

    // UINT GetDriveTypeW(LPCWSTR lpRootPathName);
    WinsdkApi("GetDriveTypeW", WinCc::Stdcall, {
        {"lpRootPathName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto path = api_get_string(ql, get_param(params, "lpRootPathName"));

        if (path.empty()) {
            throw QlErrorNotImplemented("API not implemented");
        }

        if (path == std::string(ql.profile().get("PATH", "systemdrive").value_or(""))) {
            return DRIVE_FIXED;
        }

        // TODO add configuration for drives (verbatim)
        return DRIVE_NO_ROOT_DIR;
    };

    // BOOL GetDiskFreeSpaceW(LPCWSTR lpRootPathName, LPDWORD
    // lpSectorsPerCluster, LPDWORD lpBytesPerSector, LPDWORD
    // lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);
    WinsdkApi("GetDiskFreeSpaceW", WinCc::Stdcall, {
        {"lpRootPathName", LPCWSTR_},
        {"lpSectorsPerCluster", LPDWORD_},
        {"lpBytesPerSector", LPDWORD_},
        {"lpNumberOfFreeClusters", LPDWORD_},
        {"lpTotalNumberOfClusters", LPDWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto path = api_get_string(ql, get_param(params, "lpRootPathName"));

        if (path == std::string(ql.profile().get("PATH", "systemdrive").value_or(""))) {
            const auto pt_sectors = api_get_int(get_param(params, "lpSectorsPerCluster"));
            const auto pt_bytes = api_get_int(get_param(params, "lpBytesPerSector"));
            const auto pt_free_clust = api_get_int(get_param(params, "lpNumberOfFreeClusters"));
            const auto pt_total_clust = api_get_int(get_param(params, "lpTotalNumberOfClusters"));

            const auto sectors = ql.pack32(ql.profile().get_int("VOLUME", "sectors_per_cluster"));
            const auto bytes = ql.pack32(ql.profile().get_int("VOLUME", "bytes_per_sector"));
            const auto free_clust = ql.pack32(ql.profile().get_int("VOLUME", "number_of_free_clusters"));
            const auto total_clust = ql.pack32(ql.profile().get_int("VOLUME", "number_of_clusters"));

            ql.mem().write(pt_sectors, std::vector<std::uint8_t>(sectors.begin(), sectors.end()));
            ql.mem().write(pt_bytes, std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
            ql.mem().write(pt_free_clust, std::vector<std::uint8_t>(free_clust.begin(), free_clust.end()));
            ql.mem().write(pt_total_clust, std::vector<std::uint8_t>(total_clust.begin(), total_clust.end()));
        } else {
            throw QlErrorNotImplemented("API not implemented");
        }

        return 0;
    };

    // BOOL CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES
    // lpSecurityAttributes);
    WinsdkApi("CreateDirectoryA", WinCc::Stdcall, {
        {"lpPathName", LPCSTR_},
        {"lpSecurityAttributes", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lpPathName = api_get_string(ql, get_param(params, "lpPathName"));

        const auto dst = w(ql).path()->virtual_to_host_path(lpPathName);

        if (!w(ql).path()->is_safe_host_path(dst)) {
            w(ql).set_last_error(ERROR_GEN_FAILURE);
            return 0;
        }

        std::error_code ec;
        if (std::filesystem::exists(dst, ec)) {
            w(ql).set_last_error(ERROR_ALREADY_EXISTS);
            return 0;
        }

        std::filesystem::create_directory(dst, ec);

        return 1;
    };

    // DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
    WinsdkApi("GetFileSize", WinCc::Stdcall, {
        {"hFile", HANDLE_},
        {"lpFileSizeHigh", LPDWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto hFile = api_get_int(get_param(params, "hFile"));

        const auto* handle = w(ql).handle_manager().get(hFile);

        if (handle == nullptr) {
            w(ql).set_last_error(ERROR_INVALID_HANDLE);
            return static_cast<std::uint64_t>(-1);  // INVALID_FILE_SIZE
        }

        try {
            return std::filesystem::file_size(static_cast<QlFsMappedObject*>(handle->obj)->name());
        } catch (...) {
            w(ql).set_last_error(ERROR_INVALID_HANDLE);
            return static_cast<std::uint64_t>(-1);  // INVALID_FILE_SIZE
        }
    };

    // HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES
    // lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh,
    // DWORD dwMaximumSizeLow, LPCSTR lpName);
    WinsdkApi("CreateFileMappingA", WinCc::Stdcall, {
        {"hFile", HANDLE_},
        {"lpFileMappingAttributes", LPVOID_},
        {"flProtect", DWORD_},
        {"dwMaximumSizeHigh", DWORD_},
        {"dwMaximumSizeLow", DWORD_},
        {"lpName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return create_file_mapping_body(ql, params);
    };

    // HANDLE CreateFileMappingW(... the W-side lpName);
    WinsdkApi("CreateFileMappingW", WinCc::Stdcall, {
        {"hFile", HANDLE_},
        {"lpFileMappingAttributes", LPVOID_},
        {"flProtect", DWORD_},
        {"dwMaximumSizeHigh", DWORD_},
        {"dwMaximumSizeLow", DWORD_},
        {"lpName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return create_file_mapping_body(ql, params);
    };

    // LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
    //                       DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
    //                       SIZE_T dwNumberOfBytesToMap);
    WinsdkApi("MapViewOfFile", WinCc::Stdcall, {
        {"hFileMappingObject", HANDLE_},
        {"dwDesiredAccess", DWORD_},
        {"dwFileOffsetHigh", DWORD_},
        {"dwFileOffsetLow", DWORD_},
        {"dwNumberOfBytesToMap", DWORD_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto hFileMappingObject = api_get_int(get_param(params, "hFileMappingObject"));
        const auto dwFileOffsetHigh = api_get_int(get_param(params, "dwFileOffsetHigh"));
        const auto dwFileOffsetLow = api_get_int(get_param(params, "dwFileOffsetLow"));
        const auto dwNumberOfBytesToMap = api_get_int(get_param(params, "dwNumberOfBytesToMap"));

        auto& handles = w(ql).handle_manager();
        const auto* fm_handle = handles.get(hFileMappingObject);

        if (fm_handle == nullptr) {
            return 0;
        }

        auto* fmobj = static_cast<FileMapping*>(fm_handle->obj);

        // the respective file mapping hFile was set to INVALID_HANDLE_VALUE
        // (that is, mapping is backed by page file)
        std::uint64_t mapview = 0;
        if (dynamic_cast<FileMappingMem*>(fmobj) != nullptr) {
            mapview = w(ql).heap().alloc(dwNumberOfBytesToMap);

            if (mapview == 0) {
                return 0;
            }
        } else {
            auto* fmfile = static_cast<FileMappingFile*>(fmobj);
            const auto offset = (dwFileOffsetHigh << 32) | dwFileOffsetLow;
            const auto mapview_size = dwNumberOfBytesToMap != 0
                                          ? dwNumberOfBytesToMap
                                          : (fmfile->get_file_size() - offset);

            if (mapview_size < 1) {
                return 0;
            }

            mapview = w(ql).heap().alloc(mapview_size);

            if (mapview == 0) {
                return 0;
            }

            // read content from file but retain original position. not sure
            // this is actually required since all accesses to this memory
            // area are monitored and relect file content rather than what is
            // currently in memory (verbatim)
            const auto data = fmfile->read(offset, mapview_size);
            ql.mem().write(mapview, data);

            fmfile->map_view(ql, offset, mapview, mapview + mapview_size - 1);
        }

        // although file views are not strictly handles, it would be easier to
        // manage them as such (verbatim)
        Handle view_handle{mapview, fmobj};
        handles.append(view_handle);

        return mapview;
    };

    // BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);
    WinsdkApi("UnmapViewOfFile", WinCc::Stdcall, {
        {"lpBaseAddress", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lpBaseAddress = api_get_int(get_param(params, "lpBaseAddress"));

        auto& handles = w(ql).handle_manager();
        const auto* fv_handle = handles.get(lpBaseAddress);

        if (fv_handle != nullptr) {
            if (auto* fmfile = dynamic_cast<FileMappingFile*>(static_cast<FileMapping*>(fv_handle->obj))) {
                fmfile->unmap_view();
            }

            w(ql).heap().free(lpBaseAddress);
            handles.delete_handle(fv_handle->id);

            return 1;
        }

        return 0;
    };

    // BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL
    // bFailIfExists);
    WinsdkApi("CopyFileA", WinCc::Stdcall, {
        {"lpExistingFileName", LPCSTR_},
        {"lpNewFileName", LPCSTR_},
        {"bFailIfExists", BOOL_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lpExistingFileName = api_get_string(ql, get_param(params, "lpExistingFileName"));
        const auto lpNewFileName = api_get_string(ql, get_param(params, "lpNewFileName"));
        const auto bFailIfExists = api_get_int(get_param(params, "bFailIfExists"));

        const auto src = w(ql).path()->virtual_to_host_path(lpExistingFileName);
        const auto dst = w(ql).path()->virtual_to_host_path(lpNewFileName);

        if (!w(ql).path()->is_safe_host_path(src) || !w(ql).path()->is_safe_host_path(dst)) {
            w(ql).set_last_error(ERROR_GEN_FAILURE);
            return 0;
        }

        if (bFailIfExists != 0 && std::filesystem::exists(dst)) {
            w(ql).set_last_error(ERROR_FILE_EXISTS);
            return 0;
        }

        std::error_code ec;
        std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);

        return 1;
    };

    // BOOL SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
    WinsdkApi("SetFileAttributesA", WinCc::Stdcall, {
        {"lpFileName", LPCSTR_},
        {"dwFileAttributes", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);
    WinsdkApi("SetFileAttributesW", WinCc::Stdcall, {
        {"lpFileName", LPCWSTR_},
        {"dwFileAttributes", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL AreFileApisANSI();
    WinsdkApi("AreFileApisANSI", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO make this coherent with SetFileApisToANSI/OEM calls (verbatim)
        return 1;
    };

    // void SetFileApisToANSI();
    WinsdkApi("SetFileApisToANSI", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;  // pass
    };

    // void SetFileApisToOEM();
    WinsdkApi("SetFileApisToOEM", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;  // pass
    };

    // the _DeleteFile walk shared by the A/W entries
    const auto delete_file_body = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lpFileName = api_get_string(ql, get_param(params, "lpFileName"));

        const auto dst = w(ql).path()->virtual_to_host_path(lpFileName);

        if (!w(ql).path()->is_safe_host_path(dst)) {
            w(ql).set_last_error(ERROR_GEN_FAILURE);
            return 0;
        }

        try {
            std::filesystem::remove(dst);
        } catch (const std::filesystem::filesystem_error&) {
            return 0;
        }

        return 1;
    };

    // BOOL DeleteFileA(LPCSTR lpFileName);
    WinsdkApi("DeleteFileA", WinCc::Stdcall, {
        {"lpFileName", LPCSTR_},
    }) = delete_file_body;

    // BOOL DeleteFileW(LPCWSTR lpFileName);
    WinsdkApi("DeleteFileW", WinCc::Stdcall, {
        {"lpFileName", LPCWSTR_},
    }) = delete_file_body;
}

}  // namespace win
}  // namespace os
}  // namespace qiling
