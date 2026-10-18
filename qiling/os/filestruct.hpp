// Ported from qiling/os/filestruct.py — the QlFsMappedObject interface and the
// host-file implementations (ql_file / PersistentQlFile).
//
// Deviations: Python's ql_file wraps a POSIX fd with os.read/os.write/lseek and
// an fcntl/ioctl passthrough (the latter is a no-op outside POSIX anyway). The
// C++ port uses the C stdio layer (portable across the host targets); fcntl/
// ioctl degrade to QlErrorNotImplemented until the POSIX syscall slice (Phase 5)
// introduces an fd-based variant.
#ifndef QILING_OS_FILESTRUCT_HPP
#define QILING_OS_FILESTRUCT_HPP

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {

// os/mapper.py QlFsMappedObject — the interface every mapped object implements.
// Ported verbatim; unimplemented methods raise QlErrorNotImplemented (the
// Python NotImplementedError analogue).
class QlFsMappedObject {
public:
    virtual ~QlFsMappedObject() = default;

    virtual std::vector<std::uint8_t> read(std::size_t expected_len);
    virtual std::size_t write(const std::vector<std::uint8_t>& buffer);
    virtual int fileno();
    virtual std::uint64_t lseek(std::uint64_t lseek_offset, int lseek_origin);
    virtual void close();
    virtual std::vector<std::uint8_t> fstat();
    virtual std::uint64_t ioctl(std::uint64_t ioctl_cmd, std::uint64_t ioctl_arg);
    virtual std::uint64_t tell();
    virtual std::shared_ptr<QlFsMappedObject> dup();
    virtual std::vector<std::uint8_t> readline(std::uint8_t end = '\n');
    virtual const std::string& name() const;

    // fcntl.py: the close_on_exec flag rides any mapped object (the Python
    // sets it dynamically via setattr and reads it back with getattr-default)
    bool close_on_exec = false;

    // fcntl.py ql_syscall_fcntl F_GETFL/F_SETFL: the host fcntl call. The
    // base no-ops (the windows host has no fcntl); QlFile records the flags.
    virtual int fcntl(int fcntl_cmd, int fcntl_arg);
};

// os/filestruct.py ql_file — a host file wrapped in the mapped-object interface
class QlFile : public QlFsMappedObject {
public:
    // filestruct.py ql_file.open(path, flags, mode): mode is the guest-side
    // (POSIX) mode value; the host open honors the create flag only
    static std::shared_ptr<QlFile> open(const std::string& path, int guest_flags, int guest_mode);

    // opens through a Python-style mode string ("r", "w+", "ab", ...)
    static std::shared_ptr<QlFile> open_mode(const std::string& path, std::string_view mode);

    // wraps an already-open host stream (the stdin/stdout/stderr case)
    explicit QlFile(std::string path, std::FILE* file, bool owned);
    ~QlFile() override;

    std::vector<std::uint8_t> read(std::size_t read_len) override;
    std::size_t write(const std::vector<std::uint8_t>& write_buf) override;
    int fileno() override;
    std::uint64_t lseek(std::uint64_t lseek_offset, int lseek_origin) override;
    void close() override;
    std::uint64_t tell() override;
    std::shared_ptr<QlFsMappedObject> dup() override;
    std::vector<std::uint8_t> readline(std::uint8_t end) override;
    const std::string& name() const override { return path_; }

    // fcntl.py F_GETFL/F_SETFL: the open flags ride the object (the host
    // spellings; recorded at open time)
    int fcntl(int fcntl_cmd, int fcntl_arg) override;

    bool closed() const noexcept { return closed_; }

    // informational fields for syscall mmap (filestruct.py) — the public
    // accessors ride the mman family's flush-on-unmap flow
    void set_map_shared(bool shared) { is_map_shared_ = shared; }
    void set_mapped_offset(std::int64_t off) { mapped_offset_ = off; }

    // the getdents scan gate: the upstream gates on the dir fd's tell()
    // (the seek-to-END marks the scan done); the _WIN32 host cannot seek a
    // directory FILE*, so the port tracks the scan with this flag alongside
    // the verbatim seek
    void set_dir_scan_done(bool done) { dir_scan_done_ = done; }
    bool dir_scan_done() const { return dir_scan_done_; }
    bool is_map_shared() const { return is_map_shared_; }
    std::int64_t mapped_offset() const { return mapped_offset_; }

private:
    std::string path_;
    std::FILE* file_ = nullptr;
    bool owned_ = true;
    bool closed_ = false;

    // informational fields for syscall mmap (filestruct.py)
    bool is_map_shared_ = false;
    std::int64_t mapped_offset_ = -1;
    bool dir_scan_done_ = false;

    // the host open flags (fcntl.py F_GETFL: the real host-side flags)
    int open_flags_ = 0;
};
// os/posix/filestruct.py ql_pipe — the host-pipe pair wrapped in the
// mapped-object interface (the read/write/close/dup over the CRT fds)
class QlPipe final : public QlFsMappedObject {
public:
    // ql_pipe.open(): the host os.pipe() pair
    static std::pair<std::shared_ptr<QlPipe>, std::shared_ptr<QlPipe>> open();

    std::vector<std::uint8_t> read(std::size_t read_len) override;
    std::size_t write(const std::vector<std::uint8_t>& write_buf) override;
    int fileno() override;
    void close() override;
    std::uint64_t ioctl(std::uint64_t ioctl_cmd, std::uint64_t ioctl_arg) override;
    std::shared_ptr<QlFsMappedObject> dup() override;
    const std::string& name() const override { return name_; }

    // the python ql_pipe.fcntl swallows every failure (returns None); the
    // port degrades to a 0
    int fcntl(int fcntl_cmd, int fcntl_arg) override;

private:
    explicit QlPipe(int fd) : fd_(fd) {}

    int fd_ = -1;
    std::string name_ = "pipe";
};

// os/filestruct.py PersistentQlFile — close() is a silent no-op (the emulated
// program must not close shared host resources such as stdout)
class PersistentQlFile final : public QlFile {
public:
    explicit PersistentQlFile(std::string path, std::FILE* file)
        : QlFile(std::move(path), file, false) {}

    void close() override;
};

// filestruct.py Fstat(fd): the host fstat snapshot (the port-side helper;
// the os/arch packings live with their consumers)
struct QlFileStat {
    std::uint64_t dev = 0;
    std::uint64_t ino = 0;
    std::uint32_t mode = 0;
    std::uint32_t nlink = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint64_t rdev = 0;
    std::uint64_t size = 0;
    std::int64_t atime = 0;
    std::int64_t mtime = 0;
    std::int64_t ctime = 0;
    std::int64_t blksize = 0;
    std::int64_t blocks = 0;
};

// the host fstat over an already-open descriptor (the caller's QlFile::fileno)
QlFileStat host_fstat_fd(int host_fd);

// stat.py Stat/Lstat: the host path stat — follow_symlinks selects the
// following stat (Stat) over the symlink-targeted lstat (Lstat); returns
// false with *out_errno set on the host failure (the OSError branch);
// the _WIN32 deviation: the MSVC CRT has no lstat, so the no-follow request
// collapses onto _wstat64 (the fixture targets are regular files where
// both behave identically)
bool host_stat_path(const std::filesystem::path& host_path, bool follow_symlinks,
                    QlFileStat& out, int* out_errno);

// the *at variant (transform_path's dirfd branch): the host stat relative to
// an already-open descriptor — the POSIX fstatat(host_dirfd, path, follow ?
// 0 : AT_SYMLINK_NOFOLLOW); the _WIN32 deviation: the MSVC CRT has no
// fstatat, so only the AT_FDCWD-ish requests resolve (the real-dirfd
// requests throw QlErrorNotImplemented, mirroring Python's win32 dir_fd
// NotImplementedError)
bool host_statat(const std::filesystem::path& host_path, int host_dirfd, bool follow_symlinks,
                 QlFileStat& out, int* out_errno);

}  // namespace qiling

#endif  // QILING_OS_FILESTRUCT_HPP
