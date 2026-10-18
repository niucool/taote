// The posix stat-packing family (the stat.py port) — the layout tables +
// the ctypes-shape packer, asserted byte-exactly against the upstream
// structures (the QNXARM 72-byte 18-cell image the qnx io_stat rides, the
// ARM64 u64 tail alignment, the linux x86-64 144-byte image, the dispatch).
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "qiling/const.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/posix/stat.hpp"

using namespace qiling;
using namespace qiling::os;

namespace {

qiling::QlFileStat sample_info() {
    qiling::QlFileStat info;
    info.dev = 0x11223344;
    info.ino = 0xAABBCCDD11223344ull;
    info.mode = 0x81A4;  // the regular file 0644
    info.nlink = 3;
    info.uid = 1000;
    info.gid = 1001;
    info.rdev = 0x55667788;
    info.size = 0x1234;
    info.atime = 1700000000;
    info.mtime = 1700000001;
    info.ctime = 1700000002;
    info.blksize = 0x1000;
    info.blocks = 0x123;
    return info;
}

std::uint32_t cell32(const std::vector<std::uint8_t>& bytes, std::size_t off) {
    return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[off + 2]) << 16) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24);
}

}  // namespace

// stat.py QNXARMStat: the _pack_=4 18-cell layout, 72 bytes, the hi cells
// zero, the duplicated blksize/blocks columns verbatim
TEST(StatPack, QnxArmLayoutMatchesUpstreamCells) {
    const auto bytes = posix::pack_stat_struct(sample_info(), posix::get_stat_layout(QL_OS::QNX, QL_ARCH::ARM));
    ASSERT_EQ(bytes.size(), 72u);

    EXPECT_EQ(cell32(bytes, 0), 0x11223344u);         // st_ino's low cell
    EXPECT_EQ(cell32(bytes, 4), 0u);                  // st_ino_hi must be zero
    EXPECT_EQ(cell32(bytes, 8), 0x1234u);             // st_size
    EXPECT_EQ(cell32(bytes, 12), 0u);                 // st_size_hi must be zero
    EXPECT_EQ(cell32(bytes, 16), 0x11223344u);        // st_dev
    EXPECT_EQ(cell32(bytes, 20), 0x55667788u);        // st_rdev
    EXPECT_EQ(cell32(bytes, 24), 1000u);              // st_uid
    EXPECT_EQ(cell32(bytes, 28), 1001u);              // st_gid
    EXPECT_EQ(cell32(bytes, 32), 1700000001u);        // st_mtime
    EXPECT_EQ(cell32(bytes, 36), 1700000000u);        // st_atime
    EXPECT_EQ(cell32(bytes, 40), 1700000002u);        // st_ctime
    EXPECT_EQ(cell32(bytes, 44), 0x81A4u);            // st_mode
    EXPECT_EQ(cell32(bytes, 48), 3u);                 // st_nlink
    EXPECT_EQ(cell32(bytes, 52), 0x1000u);            // st_blksize
    EXPECT_EQ(cell32(bytes, 56), 0x123u);             // st_blocks
    EXPECT_EQ(cell32(bytes, 60), 0x1000u);            // the duplicated st_blksize
    EXPECT_EQ(cell32(bytes, 64), 0x123u);             // the duplicated st_blocks
    EXPECT_EQ(cell32(bytes, 68), 0u);                 // st_blocks_hi must be zero
}

// stat.py QNXARM64Stat: the u64 ino/size head, the u32 middle, the u64
// st_blocks tail re-aligning to offset 64 (72 bytes total)
TEST(StatPack, QnxArm64LayoutPadsBeforeTheU64Tail) {
    const auto bytes = posix::pack_stat_struct(sample_info(), posix::get_stat_layout(QL_OS::QNX, QL_ARCH::ARM64));
    ASSERT_EQ(bytes.size(), 72u);

    const auto rd64 = [&bytes](std::size_t off) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(bytes[off + i]) << (8 * i);
        }
        return v;
    };
    EXPECT_EQ(rd64(0), 0xAABBCCDD11223344ull);        // st_ino (u64)
    EXPECT_EQ(rd64(8), 0x1234u);                      // st_size (u64)
    EXPECT_EQ(cell32(bytes, 16), 0x11223344u);        // st_dev
    EXPECT_EQ(cell32(bytes, 60), 0x1000u);            // the second st_blksize (u32)
    EXPECT_EQ(rd64(64), 0x123u);                      // the trailing u64 st_blocks
}

// stat.py LinuxX8664Stat: the 144-byte image, the ns cells and the
// __unused/__pad0 spacers zero
TEST(StatPack, LinuxX8664LayoutMatchesTheSysvImage) {
    const auto bytes = posix::pack_stat_struct(sample_info(), posix::get_stat_layout(QL_OS::LINUX, QL_ARCH::X8664));
    ASSERT_EQ(bytes.size(), 144u);

    const auto rd64 = [&bytes](std::size_t off) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(bytes[off + i]) << (8 * i);
        }
        return v;
    };
    EXPECT_EQ(rd64(0), 0x11223344u);                  // st_dev
    EXPECT_EQ(rd64(8), 0xAABBCCDD11223344ull);        // st_ino
    EXPECT_EQ(rd64(16), 3u);                          // st_nlink
    EXPECT_EQ(cell32(bytes, 24), 0x81A4u);            // st_mode
    EXPECT_EQ(cell32(bytes, 36), 0u);                 // __pad0
    EXPECT_EQ(rd64(40), 0x55667788u);                 // st_rdev
    EXPECT_EQ(rd64(48), 0x1234u);                     // st_size
    EXPECT_EQ(rd64(72), 1700000000u);                 // st_atime
    EXPECT_EQ(rd64(80), 0u);                          // st_atime_ns (the snapshot carries none)
    EXPECT_EQ(rd64(120), 0u);                         // __unused[0..2] all zero
}

// stat.py get_stat_struct: the QNX arm pair dispatches to the right tables;
// the untabled combos fall through to the linux x86 image (the upstream
// fallback), and the tabled-but-absent shapes raise
TEST(StatPack, DispatchRidesTheUpstreamLadder) {
    EXPECT_EQ(posix::get_stat_layout(QL_OS::QNX, QL_ARCH::ARM).cells.size(), 18u);
    EXPECT_EQ(posix::get_stat_layout(QL_OS::QNX, QL_ARCH::ARM64).cells.size(), 15u);
    EXPECT_EQ(posix::get_stat_layout(QL_OS::LINUX, QL_ARCH::X86).cells.size(), 18u);
    // the fallback: the untabled os answers the linux x86 image verbatim
    EXPECT_EQ(posix::get_stat_layout(QL_OS::DOS, QL_ARCH::X86).cells.size(), 18u);
    // the linux 32-bit arm table is not ported yet
    EXPECT_THROW(posix::get_stat_layout(QL_OS::LINUX, QL_ARCH::ARM), qiling::QlErrorNotImplemented);
}
