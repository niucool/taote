// os/disk.py — the QlDisk implementation

#include "qiling/os/disk.hpp"

#include <stdexcept>

namespace qiling {
namespace os {

namespace {

// the portable large seek (the filestruct.cpp QL_FSEEK split, duplicated
// here to keep the disk TU standalone)
#if defined(_WIN32)
inline int disk_seek(std::FILE* fp, std::int64_t off, int whence) {
    return ::_fseeki64(fp, off, whence);
}
inline std::int64_t disk_tell(std::FILE* fp) {
    return ::_ftelli64(fp);
}
#else
inline int disk_seek(std::FILE* fp, std::int64_t off, int whence) {
    return ::fseeko(fp, static_cast<off_t>(off), whence);
}
inline std::int64_t disk_tell(std::FILE* fp) {
    return ::ftello(fp);
}
#endif

}  // namespace

QlDisk::QlDisk(const std::string& host_path, const std::string& drive_path, int n_cylinders, int n_heads,
               int sector_size)
    : drive_path_(drive_path), n_heads_(n_heads), n_cylinders_(n_cylinders), sector_size_(sector_size) {
    // disk.py: open(host_path, "rb+")
    fp_ = std::fopen(host_path.c_str(), "rb+");
    if (fp_ == nullptr) {
        throw QlErrorBase("qldisk: cannot open " + host_path);
    }

    // disk.py ctor: lseek(0, 2) then the size probe; the sector count floors
    lseek(0, 2);
    filesize_ = static_cast<std::uint64_t>(disk_tell(fp_));
    n_sectors_ = static_cast<int>((filesize_ - 1) / static_cast<std::uint64_t>(sector_size_) + 1);
}

QlDisk::~QlDisk() {
    // disk.py __del__: close only when still open
    if (fp_ != nullptr) {
        std::fclose(fp_);
        fp_ = nullptr;
    }
}

std::vector<std::uint8_t> QlDisk::read(std::size_t expected_len) {
    std::vector<std::uint8_t> buf(expected_len);
    const auto got = std::fread(buf.data(), 1, expected_len, fp_);
    buf.resize(got);
    return buf;
}

std::size_t QlDisk::write(const std::vector<std::uint8_t>& buffer) {
    return std::fwrite(buffer.data(), 1, buffer.size(), fp_);
}

std::uint64_t QlDisk::lseek(std::uint64_t offset, int origin) {
    disk_seek(fp_, static_cast<std::int64_t>(offset), origin);
    return static_cast<std::uint64_t>(disk_tell(fp_));
}

std::uint64_t QlDisk::tell() {
    return static_cast<std::uint64_t>(disk_tell(fp_));
}

void QlDisk::close() {
    if (fp_ != nullptr) {
        std::fclose(fp_);
        fp_ = nullptr;
    }
}

std::uint64_t QlDisk::lba(int cylinder, int head, int sector) const {
    // disk.py: (cylinder * n_heads + head) * n_sectors + sector - 1
    return (static_cast<std::uint64_t>(cylinder) * static_cast<std::uint64_t>(n_heads_) +
            static_cast<std::uint64_t>(head)) *
               static_cast<std::uint64_t>(n_sectors_) +
           static_cast<std::uint64_t>(sector) - 1;
}

std::vector<std::uint8_t> QlDisk::read_sectors(std::uint64_t lba, int cnt) {
    lseek(sector_size_ * lba, 0);
    return read(static_cast<std::size_t>(sector_size_) * static_cast<std::size_t>(cnt));
}

std::size_t QlDisk::write_sectors(std::uint64_t lba, int cnt, const std::vector<std::uint8_t>& buffer) {
    // disk.py: buffer[:sector_size * cnt]
    const auto want = static_cast<std::size_t>(sector_size_) * static_cast<std::size_t>(cnt);
    auto slice = buffer;
    if (slice.size() > want) {
        slice.resize(want);
    }
    lseek(sector_size_ * lba, 0);
    return write(slice);
}

std::vector<std::uint8_t> QlDisk::read_chs(int cylinder, int head, int sector, int cnt) {
    return read_sectors(lba(cylinder, head, sector), cnt);
}

std::size_t QlDisk::write_chs(int cylinder, int head, int sector, int cnt, const std::vector<std::uint8_t>& buffer) {
    return write_sectors(lba(cylinder, head, sector), cnt, buffer);
}

}  // namespace os
}  // namespace qiling
