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
// (the *_hi cells, the ns cells, the __unused paddings)
enum class StatSrc {
    Dev, Ino, Mode, Nlink, Uid, Gid, Rdev, Size,
    Atime, Mtime, Ctime, Blksize, Blocks,
    Zero,
};

struct StatCell {
    StatSrc src;
    std::uint32_t width;  // the c_uint16/c_uint32/c_uint64 cell width
};

struct StatLayout {
    std::uint32_t pack;  // the ctypes _pack_ value
    std::vector<StatCell> cells;
};

// stat.py get_stat_struct: the per-OS/arch dispatch; the untabled shapes
// raise QlErrorNotImplemented (the tables land with their dialect slices)
const StatLayout& get_stat_layout(QL_OS os, QL_ARCH arch);

// stat.py __common_pack_stat_struct + pack_stat_struct: the host snapshot
// stamped over the layout, the alignment padding per the ctypes _pack_ rule
std::vector<std::uint8_t> pack_stat_struct(const QlFileStat& info, const StatLayout& layout);

}  // namespace posix
}  // namespace os
}  // namespace qiling
