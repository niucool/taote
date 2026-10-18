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

private:
    std::string path_;
    std::FILE* file_ = nullptr;
    bool owned_ = true;
    bool closed_ = false;

    // informational fields for syscall mmap (filestruct.py)
    bool is_map_shared_ = false;
    std::int64_t mapped_offset_ = -1;

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

}  // namespace qiling

#endif  // QILING_OS_FILESTRUCT_HPP
