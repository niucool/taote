#include "qiling/os/filestruct.hpp"

#include <cerrno>
#include <fcntl.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include <sys/stat.h>

// portable stdio extensions (MSVC names; POSIX equivalents below)
#if defined(_WIN32)
#define QL_FILENO ::_fileno
#define QL_FSEEK ::_fseeki64
#define QL_FTELL ::_ftelli64
#define QL_CRT_OPEN(path, flags, pmode) ::_open(path, flags, pmode)
#define QL_CRT_FDOPEN ::_fdopen
#define QL_CRT_CLOSE ::_close
#define QL_CRT_READ ::_read
#define QL_CRT_WRITE ::_write
#define QL_CRT_DUP ::_dup
#define QL_CRT_PIPE(fds, size, textmode) ::_pipe(fds, size, textmode)
#define QL_O_BINARY _O_BINARY
#else
#define QL_FILENO ::fileno
#define QL_FSEEK ::fseeko
#define QL_FTELL ::ftello
#define QL_CRT_OPEN(path, flags, pmode) ::open(path, flags, pmode)
#define QL_CRT_FDOPEN ::fdopen
#define QL_CRT_CLOSE ::close
#define QL_CRT_READ ::read
#define QL_CRT_WRITE ::write
#define QL_CRT_DUP ::dup
#define QL_CRT_PIPE(fds, size, textmode) ::pipe(fds)
#define QL_O_BINARY 0
#endif

namespace qiling {

namespace {
// posix/const.py: AT_FDCWD (the cwd-relative dirfd marker) — the host-side
// fstatat passing convention
constexpr int kATFDCWD = -100;
}  // namespace

// ---- QlFsMappedObject (os/mapper.py base) ----

std::vector<std::uint8_t> QlFsMappedObject::read(std::size_t) {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: read");
}

std::size_t QlFsMappedObject::write(const std::vector<std::uint8_t>&) {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: write");
}

int QlFsMappedObject::fileno() {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: fileno");
}

std::uint64_t QlFsMappedObject::lseek(std::uint64_t, int) {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: lseek");
}

void QlFsMappedObject::close() {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: close");
}

std::vector<std::uint8_t> QlFsMappedObject::fstat() {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: fstat");
}

std::uint64_t QlFsMappedObject::ioctl(std::uint64_t, std::uint64_t) {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: ioctl");
}

std::uint64_t QlFsMappedObject::tell() {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: tell");
}

std::shared_ptr<QlFsMappedObject> QlFsMappedObject::dup() {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: dup");
}

std::vector<std::uint8_t> QlFsMappedObject::readline(std::uint8_t) {
    throw QlErrorNotImplemented("QlFsMappedObject method not implemented: readline");
}

const std::string& QlFsMappedObject::name() const {
    throw QlErrorNotImplemented("QlFsMappedObject property not implemented: name");
}

int QlFsMappedObject::fcntl(int, int) {
    // the base no-op: the windows host has no fcntl (the QlFile override
    // tracks the flags; the QlPipe swallows, the python fcntl returns None)
    return 0;
}

// ---- QlFile ----

std::shared_ptr<QlFile> QlFile::open(const std::string& path, int host_flags, int guest_mode) {
    // the flags arrive already mapped through ql_open_flag_mapping (fcntl.py
    // __do_open maps before the fs_mapper open) — the constants below are the
    // HOST spellings, passed straight to the host open so the create /
    // excl / trunc / append semantics stay exact
#if defined(_WIN32)
    int pmode = _S_IREAD | _S_IWRITE;
    if ((guest_mode & 0x80) == 0) {
        // the guest mode without the owner-write bit (e.g. 0o444) denies the
        // host write bit (os.open passes the mode through)
        pmode = _S_IREAD;
    }
#else
    // the POSIX host passes the guest mode straight (the os.open shape; the
    // kernel applies the umask)
    const int pmode = guest_mode;
#endif

    const int fd = QL_CRT_OPEN(path.c_str(), host_flags, pmode);
    if (fd == -1) {
        // fcntl.py __do_open catches the typed python os errors; the CRT
        // errno maps onto the same vocabulary
        switch (errno) {
            case ENOENT:
                throw QlErrorFileNotFound("file not found: " + path);
            case EEXIST:
                throw QlErrorFileExists("file exists: " + path);
            case EISDIR:
                throw QlErrorIsADirectory("is a directory: " + path);
            case EACCES:
            case EPERM:
                throw QlErrorAccessDenied("access denied: " + path);
            default:
                throw QlErrorBase("failed to open: " + path);
        }
    }

    // the stdio mode off the host flags (glibc's fdopen validates the access
    // mode against the fd — the MSVC one never checks, which is why the
    // hardcoded "rb+" survived upstream; the stream mode shapes after the
    // open flags so the two hosts agree)
    const char* stdio_mode = "rb";
    switch (host_flags & O_ACCMODE) {
        case O_WRONLY:
            stdio_mode = (host_flags & O_APPEND) ? "ab" : "wb";
            break;
        case O_RDWR:
            stdio_mode = (host_flags & O_APPEND) ? "ab+" : "rb+";
            break;
        default:
            break;
    }
    std::FILE* stream = QL_CRT_FDOPEN(fd, stdio_mode);
    if (stream == nullptr) {
        QL_CRT_CLOSE(fd);
        throw QlErrorBase("fdopen failed: " + path);
    }

    auto file = std::shared_ptr<QlFile>(new QlFile(path, stream, true));
    file->open_flags_ = host_flags;
    return file;
}

std::shared_ptr<QlFile> QlFile::open_mode(const std::string& path, std::string_view mode) {
    // map the Python-style mode string onto the stdio mode
    bool write = false, append = false, update = false;
    for (const char c : mode) {
        switch (c) {
            case 'w': write = true; break;
            case 'a': append = true; break;
            case '+': update = true; break;
            default: break;  // 'r' is the default and 'b' is the stdio default
        }
    }

    const char* stdio_mode = "rb";
    if (update) {
        stdio_mode = append ? "ab+" : (write ? "w+b" : "r+b");
    } else if (write) {
        stdio_mode = "wb";
    } else if (append) {
        stdio_mode = "ab";
    }

    std::FILE* f = std::fopen(path.c_str(), stdio_mode);
    if (f == nullptr) {
        throw QlErrorBase("failed to open: " + path);
    }
    return std::shared_ptr<QlFile>(new QlFile(path, f, true));
}

QlFile::QlFile(std::string path, std::FILE* file, bool owned)
    : path_(std::move(path)), file_(file), owned_(owned) {}

QlFile::~QlFile() {
    if (owned_ && file_ != nullptr) {
        std::fclose(file_);
    // file_ is invalid after this; clear it to keep close() idempotent
        file_ = nullptr;
        closed_ = true;
    }
}

std::vector<std::uint8_t> QlFile::read(std::size_t read_len) {
    if (file_ == nullptr) {
        throw QlErrorBase("read on a closed file");
    }
    std::vector<std::uint8_t> out(read_len);
    const std::size_t got = std::fread(out.data(), 1, read_len, file_);
    out.resize(got);
    return out;
}

std::size_t QlFile::write(const std::vector<std::uint8_t>& write_buf) {
    if (file_ == nullptr) {
        throw QlErrorBase("write on a closed file");
    }
    return std::fwrite(write_buf.data(), 1, write_buf.size(), file_);
}

int QlFile::fileno() {
    if (file_ == nullptr) {
        throw QlErrorBase("fileno on a closed file");
    }
    return QL_FILENO(file_);
}

QlFileStat host_fstat_fd(int host_fd) {
#if defined(_WIN32)
    struct _stat64 st{};
    if (::_fstat64(host_fd, &st) != 0) {
        throw QlErrorBase("fstat failed");
    }
#else
    struct stat st{};
    if (::fstat(host_fd, &st) != 0) {
        throw QlErrorBase("fstat failed");
    }
#endif
    QlFileStat out;
    out.dev = static_cast<std::uint64_t>(st.st_dev);
    out.ino = static_cast<std::uint64_t>(st.st_ino);
    out.mode = static_cast<std::uint32_t>(st.st_mode);
    out.nlink = static_cast<std::uint32_t>(st.st_nlink);
    out.uid = static_cast<std::uint32_t>(st.st_uid);
    out.gid = static_cast<std::uint32_t>(st.st_gid);
    out.rdev = static_cast<std::uint64_t>(st.st_rdev);
    out.size = static_cast<std::uint64_t>(st.st_size);
    out.atime = static_cast<std::int64_t>(st.st_atime);
    out.mtime = static_cast<std::int64_t>(st.st_mtime);
    out.ctime = static_cast<std::int64_t>(st.st_ctime);
#ifdef _WIN32
    out.blksize = 0;
    out.blocks = 0;
#else
    out.blksize = static_cast<std::int64_t>(st.st_blksize);
    out.blocks = static_cast<std::int64_t>(st.st_blocks);
#endif
    return out;
}

bool host_stat_path(const std::filesystem::path& host_path, bool follow_symlinks,
                    QlFileStat& out, int* out_errno) {
    return host_statat(host_path, kATFDCWD, follow_symlinks, out, out_errno);
}

bool host_statat(const std::filesystem::path& host_path, int host_dirfd, bool follow_symlinks,
                 QlFileStat& out, int* out_errno) {
    errno = 0;
#if defined(_WIN32)
    if (host_dirfd != kATFDCWD && host_dirfd != -1) {
        // the MSVC CRT has no fstatat — the verbatim Python shape raises
        // NotImplementedError for the dir_fd stats on win32; the -1 sentinel
        // is transform_path's no-dirfd marker (the plain-path stat)
        throw QlErrorNotImplemented("host_statat: the dir_fd stats are POSIX-only");
    }
    struct _stat64 st{};
    if (::_wstat64(host_path.wstring().c_str(), &st) != 0) {
        if (out_errno != nullptr) {
            *out_errno = errno;
        }
        return false;
    }
#else
    struct stat st{};
    const int stat_flags = follow_symlinks ? 0 : AT_SYMLINK_NOFOLLOW;
    if (::fstatat(host_dirfd, host_path.c_str(), &st, stat_flags) != 0) {
        if (out_errno != nullptr) {
            *out_errno = errno;
        }
        return false;
    }
#endif
    out.dev = static_cast<std::uint64_t>(st.st_dev);
    out.ino = static_cast<std::uint64_t>(st.st_ino);
    out.mode = static_cast<std::uint32_t>(st.st_mode);
    out.nlink = static_cast<std::uint32_t>(st.st_nlink);
    out.uid = static_cast<std::uint32_t>(st.st_uid);
    out.gid = static_cast<std::uint32_t>(st.st_gid);
    out.rdev = static_cast<std::uint64_t>(st.st_rdev);
    out.size = static_cast<std::uint64_t>(st.st_size);
    out.atime = static_cast<std::int64_t>(st.st_atime);
    out.mtime = static_cast<std::int64_t>(st.st_mtime);
    out.ctime = static_cast<std::int64_t>(st.st_ctime);
#ifdef _WIN32
    out.blksize = 0;
    out.blocks = 0;
#else
    out.blksize = static_cast<std::int64_t>(st.st_blksize);
    out.blocks = static_cast<std::int64_t>(st.st_blocks);
#endif
    return true;
}

std::uint64_t QlFile::lseek(std::uint64_t lseek_offset, int lseek_origin) {
    if (file_ == nullptr) {
        // the dir-fd case (the getdents fd): the scan gate rides the
        // dir_scan_done flag instead of the file cursor; the no-op seek
        // mirrors the upstream's seek-to-END on the dir fd
        return 0;
    }
    if (QL_FSEEK(file_, static_cast<std::int64_t>(lseek_offset), lseek_origin) != 0) {
        throw QlErrorBase("lseek failed");
    }
    return static_cast<std::uint64_t>(QL_FTELL(file_));
}

void QlFile::close() {
    if (closed_) {
        return;
    }
    if (file_ != nullptr) {
        std::fclose(file_);
        file_ = nullptr;
    }
    closed_ = true;
}

std::uint64_t QlFile::tell() {
    return lseek(0, SEEK_CUR);
}

std::shared_ptr<QlFsMappedObject> QlFile::dup() {
    if (file_ == nullptr) {
        throw QlErrorBase("dup on a closed file");
    }
    // stdio lacks a portable dup; reopen the path (documented deviation from
    // the fd-based Python dup — Phase 5's fd layer revisits this)
    std::FILE* f = std::fopen(path_.c_str(), "rb+");
    if (f == nullptr) {
        throw QlErrorBase("dup failed to reopen: " + path_);
    }
    return std::shared_ptr<QlFsMappedObject>(new QlFile(path_, f, true));
}

std::vector<std::uint8_t> QlFile::readline(std::uint8_t end) {
    if (file_ == nullptr) {
        throw QlErrorBase("readline on a closed file");
    }
    std::vector<std::uint8_t> out;
    int c;
    while ((c = std::fgetc(file_)) != EOF) {
        out.push_back(static_cast<std::uint8_t>(c));
        if (c == end) {
            break;
        }
    }
    return out;
}

void PersistentQlFile::close() {
    // silently dropped (filestruct.py PersistentQlFile.close)
}

int QlFile::fcntl(int fcntl_cmd, int fcntl_arg) {
    // fcntl.py F_GETFL: the real host-side flags; F_SETFL re-records them
    // (the actual host mutation — O_NONBLOCK etc. — has no windows fcntl)
    if (fcntl_cmd == 3) {  // F_GETFL
        return open_flags_;
    }
    if (fcntl_cmd == 4) {  // F_SETFL
        open_flags_ = fcntl_arg;
    }
    return 0;
}

// ---- QlPipe (os/posix/filestruct.py ql_pipe) ----

std::pair<std::shared_ptr<QlPipe>, std::shared_ptr<QlPipe>> QlPipe::open() {
    int fds[2] = {-1, -1};
    if (QL_CRT_PIPE(fds, 4096, QL_O_BINARY) != 0) {
        throw QlErrorBase("pipe creation failed");
    }
    return {std::shared_ptr<QlPipe>(new QlPipe(fds[0])),
            std::shared_ptr<QlPipe>(new QlPipe(fds[1]))};
}

std::vector<std::uint8_t> QlPipe::read(std::size_t read_len) {
    std::vector<std::uint8_t> out(read_len, 0);
    const auto n = QL_CRT_READ(fd_, out.data(), static_cast<unsigned>(read_len));
    out.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
    return out;
}

std::size_t QlPipe::write(const std::vector<std::uint8_t>& write_buf) {
    const auto n = QL_CRT_WRITE(fd_, write_buf.data(), static_cast<unsigned>(write_buf.size()));
    return n > 0 ? static_cast<std::size_t>(n) : 0;
}

int QlPipe::fileno() {
    return fd_;
}

void QlPipe::close() {
    if (fd_ != -1) {
        QL_CRT_CLOSE(fd_);
        fd_ = -1;
    }
}

std::uint64_t QlPipe::ioctl(std::uint64_t, std::uint64_t) {
    // the python ql_pipe.ioctl swallows every failure (returns None)
    return 0;
}

std::shared_ptr<QlFsMappedObject> QlPipe::dup() {
    return std::shared_ptr<QlPipe>(new QlPipe(QL_CRT_DUP(fd_)));
}

int QlPipe::fcntl(int, int) {
    // the python ql_pipe.fcntl swallows every failure (returns None)
    return 0;
}

}  // namespace qiling
