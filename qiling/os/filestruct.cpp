#include "qiling/os/filestruct.hpp"

#include <sys/stat.h>

// portable stdio extensions (MSVC names; POSIX equivalents below)
#if defined(_WIN32)
#define QL_FILENO ::_fileno
#define QL_FSEEK ::_fseeki64
#define QL_FTELL ::_ftelli64
#else
#define QL_FILENO ::fileno
#define QL_FSEEK ::fseeko
#define QL_FTELL ::ftello
#endif

namespace qiling {

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

// ---- QlFile ----

std::shared_ptr<QlFile> QlFile::open(const std::string& path, int host_flags, int guest_mode) {
    // the flags arrive already mapped through ql_open_flag_mapping (fcntl.py
    // __do_open maps before the fs_mapper open) — the constants below are the
    // HOST (windows CRT) spellings: O_RDONLY=0, O_WRONLY=1, O_RDWR=2,
    // O_CREAT=0x100, O_TRUNC=0x200, O_APPEND=0x8
    constexpr int HOST_RDONLY = 0;
    constexpr int HOST_WRONLY = 1;
    constexpr int HOST_RDWR = 2;
    constexpr int HOST_CREAT = 0x100;      // _O_CREAT
    constexpr int HOST_TRUNC = 0x200;      // _O_TRUNC
    constexpr int HOST_APPEND = 0x8;       // _O_APPEND

    const char* mode = nullptr;
    const int access = host_flags & 3;
    if (access == HOST_RDONLY) {
        mode = "rb";
    } else if (access == HOST_WRONLY) {
        mode = (host_flags & HOST_APPEND) ? "ab" : ((host_flags & (HOST_TRUNC | HOST_CREAT)) ? "wb" : "r+b");
    } else if (access == HOST_RDWR) {
        mode = (host_flags & HOST_APPEND) ? "ab+"
             : ((host_flags & (HOST_TRUNC | HOST_CREAT)) ? "w+b" : "r+b");
    } else {
        throw QlErrorBase("invalid host open flags");
    }
    (void)guest_mode;  // the permission bits only matter for the host create

    std::FILE* f = std::fopen(path.c_str(), mode);
    if (f == nullptr) {
        throw QlErrorBase("failed to open: " + path);
    }

    return std::shared_ptr<QlFile>(new QlFile(path, f, true));
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

std::uint64_t QlFile::lseek(std::uint64_t lseek_offset, int lseek_origin) {
    if (file_ == nullptr) {
        throw QlErrorBase("lseek on a closed file");
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

}  // namespace qiling
