// Ported from qiling/os/posix/syscall/stat.py — the guest stat-layout
// family. The upstream models each ABI's stat image as a ctypes Structure
// with a _pack_ value; the port models it as a cell list (the source field,
// the width) plus the pack constant, and the packer applies the
// min(width, pack) alignment per cell (the ctypes _pack_ rule) — the bytes
// land identically. The tables carry the upstream field spellings verbatim,
// including the duplicate-key quirks (the QNX st_blksize/st_blocks
// repetition, the x86 ns cells that StatBase.__getitem__ answers 0 for).
#pragma once

#include <cstdint>
#include <vector>

#include "qiling/const.hpp"
#include "qiling/os/filestruct.hpp"

namespace qiling {
namespace os {
namespace posix {

// the source cell in the host stat snapshot (filestruct.hpp QlFileStat) —
// Zero is the ctypes zero-cell for the fields the snapshot never carries
// (the *_hi cells, the ns cells, the __unused paddings); StatxMask is the
// hardcoded STATX_BASIC_STATS mask; the *Major/*Minor cells apply the
// glibc makedev splits
enum class StatSrc {
    Dev, Ino, Mode, Nlink, Uid, Gid, Rdev, Size,
    Atime, Mtime, Ctime, Blksize, Blocks,
    StatxMask, RdevMajor, RdevMinor, DevMajor, DevMinor,
    Zero,
};

struct StatCell {
    StatSrc src;
    std::uint32_t width;  // the c_uint16/c_uint32/c_uint64 cell width
    bool as_statx_time = false;  // the statx timestamp cells (the float32
                                 // bit-pattern conversion — stat.py
                                 // statx_convert_timestamp verbatim)
};

struct StatLayout {
    std::uint32_t pack;  // the ctypes _pack_ value
    std::vector<StatCell> cells;
};

// stat.py get_stat_struct: the per-OS/arch dispatch; the untabled shapes
// raise QlErrorNotImplemented (the tables land with their dialect slices)
const StatLayout& get_stat_layout(QL_OS os, QL_ARCH arch);

// stat.py get_stat64_struct + pack_stat64_struct: the stat64-family packing
// (the lstat/stat64/fstatat64 rides); the verbatim ladder has no x8664
// branch — the 64-bit linux falls through to the LinuxX86Stat64 table (the
// upstream warns; the warning rides the caller with the Qiling logger)
const StatLayout& get_stat64_layout(QL_OS os, QL_ARCH arch);

// stat.py ql_syscall_statx: the statx buffer layout — the verbatim choice
// rides the arch bitness (the 64-bit hosts take the Statx64 image, the
// 32-bit the Statx32); the mask is the hardcoded STATX_BASIC_STATS and the
// timestamps ride the float32 bit-pattern conversion
const StatLayout& get_statx_layout(int bits);

// stat.py __common_pack_stat_struct + pack_stat_struct: the host snapshot
// stamped over the layout, the alignment padding per the ctypes _pack_ rule
std::vector<std::uint8_t> pack_stat_struct(const QlFileStat& info, const StatLayout& layout);

}  // namespace posix
}  // namespace os
}  // namespace qiling
