// os/disk.py — open a host file as an emulated disk (the QlDisk CHS/LBA
// wrapper over QlFsMappedObject; the int13h handler's backing store)
//
// Note: CHS and LBA support is very limited since a raw file doesn't contain
// enough information. We simply assume that it is a disk with 1 head,
// 1 cylinder and (filesize/512) sectors.

#pragma once

#include <cstdio>
#include <string>

#include "qiling/os/filestruct.hpp"

namespace qiling {
namespace os {

class QlDisk final : public QlFsMappedObject {
public:
    // disk.py QlDisk.__init__(host_path, drive_path, n_cylinders=1,
    // n_heads=1, sector_size=512)
    QlDisk(const std::string& host_path, const std::string& drive_path, int n_cylinders = 1, int n_heads = 1,
           int sector_size = 512);
    ~QlDisk() override;

    // ---- the QlFsMappedObject surface ----

    std::vector<std::uint8_t> read(std::size_t expected_len) override;
    std::size_t write(const std::vector<std::uint8_t>& buffer) override;
    std::uint64_t lseek(std::uint64_t offset, int origin) override;
    std::uint64_t tell() override;
    void close() override;

    // ---- the QlDisk surface ----

    std::uint64_t filesize() const noexcept { return filesize_; }
    int n_heads() const noexcept { return n_heads_; }
    int n_cylinders() const noexcept { return n_cylinders_; }
    int n_sectors() const noexcept { return n_sectors_; }
    int sector_size() const noexcept { return sector_size_; }
    const std::string& drive_path() const noexcept { return drive_path_; }

    // disk.py lba(cylinder, head, sector): the CHS triple to the LBA index
    std::uint64_t lba(int cylinder, int head, int sector) const;

    // disk.py read_sectors(lba, cnt)
    std::vector<std::uint8_t> read_sectors(std::uint64_t lba, int cnt);

    // disk.py write_sectors(lba, cnt, buffer)
    std::size_t write_sectors(std::uint64_t lba, int cnt, const std::vector<std::uint8_t>& buffer);

    // disk.py read_chs(cylinder, head, sector, cnt)
    std::vector<std::uint8_t> read_chs(int cylinder, int head, int sector, int cnt);

    // disk.py write_chs(cylinder, head, sector, cnt, buffer)
    std::size_t write_chs(int cylinder, int head, int sector, int cnt, const std::vector<std::uint8_t>& buffer);

private:
    std::string drive_path_;
    std::FILE* fp_ = nullptr;
    int n_heads_ = 1;
    int n_cylinders_ = 1;
    int sector_size_ = 512;
    std::uint64_t filesize_ = 0;
    int n_sectors_ = 0;
};

}  // namespace os
}  // namespace qiling
