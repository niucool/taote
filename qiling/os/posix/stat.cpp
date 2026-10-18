#include "qiling/os/posix/stat.hpp"

#include <array>
#include <stdexcept>

#include "qiling/exception.hpp"
#include <cstring>

namespace qiling {
namespace os {
namespace posix {

namespace {

// the glibc makedev splits (the stat.py major/minor helpers verbatim)
std::uint64_t statx_major(std::uint64_t dev) {
    return ((dev >> 8) & 0xfff) | ((dev >> 32) & ~0xfffull);
}

std::uint64_t statx_minor(std::uint64_t dev) {
    return (dev & 0xff) | ((dev >> 12) & ~0xffull);
}

// the host snapshot cell as a u64 (the int(info[field]) cast — the value
// truncates to the cell width at pack time, the two's-complement bytes are
// the same for the signed and the unsigned ctypes cells)
std::uint64_t source_value(const QlFileStat& info, StatSrc src) {
    switch (src) {
        case StatSrc::Dev:
            return info.dev;
        case StatSrc::Ino:
            return info.ino;
        case StatSrc::Mode:
            return info.mode;
        case StatSrc::Nlink:
            return info.nlink;
        case StatSrc::Uid:
            return info.uid;
        case StatSrc::Gid:
            return info.gid;
        case StatSrc::Rdev:
            return info.rdev;
        case StatSrc::Size:
            return info.size;
        case StatSrc::Atime:
            return static_cast<std::uint64_t>(info.atime);
        case StatSrc::Mtime:
            return static_cast<std::uint64_t>(info.mtime);
        case StatSrc::Ctime:
            return static_cast<std::uint64_t>(info.ctime);
        case StatSrc::Blksize:
            return static_cast<std::uint64_t>(info.blksize);
        case StatSrc::Blocks:
            return static_cast<std::uint64_t>(info.blocks);
        case StatSrc::StatxMask:
            return 0x07ff;  // STATX_BASIC_STATS (the hardcoded mask verbatim)
        case StatSrc::RdevMajor:
            return statx_major(info.rdev);
        case StatSrc::RdevMinor:
            return statx_minor(info.rdev);
        case StatSrc::DevMajor:
            return statx_major(info.dev);
        case StatSrc::DevMinor:
            return statx_minor(info.dev);
        case StatSrc::Zero:
        default:
            return 0;
    }
}

}  // namespace

// ---- the layout tables (stat.py, the field lists verbatim) ----

namespace {

// stat.py QNXARMStat (_pack_=4): ino, ino_hi(0), size, size_hi(0), dev,
// rdev, uid, gid, mtime, atime, ctime, mode, nlink, blksize, blocks,
// blksize, blocks, blocks_hi(0) — the duplicated blksize/blocks cells are
// the upstream verbatim
const StatLayout& qnx_arm_stat() {
    static const StatLayout layout{4, {
        {StatSrc::Ino, 4}, {StatSrc::Zero, 4},   // st_ino, st_ino_hi
        {StatSrc::Size, 4}, {StatSrc::Zero, 4},  // st_size, st_size_hi
        {StatSrc::Dev, 4}, {StatSrc::Rdev, 4},
        {StatSrc::Uid, 4}, {StatSrc::Gid, 4},
        {StatSrc::Mtime, 4}, {StatSrc::Atime, 4}, {StatSrc::Ctime, 4},
        {StatSrc::Mode, 4}, {StatSrc::Nlink, 4},
        {StatSrc::Blksize, 4}, {StatSrc::Blocks, 4},
        {StatSrc::Blksize, 4}, {StatSrc::Blocks, 4},
        {StatSrc::Zero, 4},                      // st_blocks_hi
    }};
    return layout;
}

// stat.py QNXARM64Stat (_pack_=8): the u64 ino/size head, the u32 middle and
// the u64 st_blocks tail (the trailing c_uint64 re-alignment is the upstream
// verbatim — the cell lands at offset 64)
const StatLayout& qnx_arm64_stat() {
    static const StatLayout layout{8, {
        {StatSrc::Ino, 8}, {StatSrc::Size, 8},
        {StatSrc::Dev, 4}, {StatSrc::Rdev, 4},
        {StatSrc::Uid, 4}, {StatSrc::Gid, 4},
        {StatSrc::Mtime, 4}, {StatSrc::Atime, 4}, {StatSrc::Ctime, 4},
        {StatSrc::Mode, 4}, {StatSrc::Nlink, 4},
        {StatSrc::Blksize, 4}, {StatSrc::Blocks, 4},
        {StatSrc::Blksize, 4}, {StatSrc::Blocks, 8},
    }};
    return layout;
}

// stat.py LinuxX86Stat (_pack_=4): the ns cells and the __unused tail answer
// 0 through StatBase.__getitem__ (the snapshot never carries them)
const StatLayout& linux_x86_stat() {
    static const StatLayout layout{4, {
        {StatSrc::Dev, 4}, {StatSrc::Ino, 4},
        {StatSrc::Mode, 2}, {StatSrc::Nlink, 2},
        {StatSrc::Uid, 2}, {StatSrc::Gid, 2},
        {StatSrc::Rdev, 4}, {StatSrc::Size, 4},
        {StatSrc::Blksize, 4}, {StatSrc::Blocks, 4},
        {StatSrc::Atime, 4}, {StatSrc::Zero, 4},   // st_atime_ns
        {StatSrc::Mtime, 4}, {StatSrc::Zero, 4},   // st_mtime_ns
        {StatSrc::Ctime, 4}, {StatSrc::Zero, 4},   // st_ctime_ns
        {StatSrc::Zero, 4}, {StatSrc::Zero, 4},    // __unused4, __unused5
    }};
    return layout;
}

// stat.py LinuxX8664Stat (_pack_=8): the __pad0 spacer and the
// __unused[3] tail (24 zero bytes)
const StatLayout& linux_x86_64_stat() {
    static const StatLayout layout{8, {
        {StatSrc::Dev, 8}, {StatSrc::Ino, 8}, {StatSrc::Nlink, 8},
        {StatSrc::Mode, 4}, {StatSrc::Uid, 4}, {StatSrc::Gid, 4},
        {StatSrc::Zero, 4},                        // __pad0
        {StatSrc::Rdev, 8}, {StatSrc::Size, 8},
        {StatSrc::Blksize, 8}, {StatSrc::Blocks, 8},
        {StatSrc::Atime, 8}, {StatSrc::Zero, 8},   // st_atime_ns
        {StatSrc::Mtime, 8}, {StatSrc::Zero, 8},   // st_mtime_ns
        {StatSrc::Ctime, 8}, {StatSrc::Zero, 8},   // st_ctime_ns
        {StatSrc::Zero, 8}, {StatSrc::Zero, 8}, {StatSrc::Zero, 8},  // __unused[3]
    }};
    return layout;
}

// stat.py LinuxX86Stat64 (_pack_=4): the i386 stat64 image — the byte-array
// pads and the trailing u64 st_ino (the cells answer 0 where the snapshot
// never carries the field)
const StatLayout& linux_x86_stat64() {
    static const StatLayout layout{4, {
        {StatSrc::Dev, 8},
        {StatSrc::Zero, 4},                        // __pad0[4]
        {StatSrc::Ino, 4},                         // __st_ino
        {StatSrc::Mode, 4}, {StatSrc::Nlink, 4},
        {StatSrc::Uid, 4}, {StatSrc::Gid, 4},
        {StatSrc::Rdev, 8},
        {StatSrc::Zero, 4},                        // __pad3[4]
        {StatSrc::Size, 8},
        {StatSrc::Blksize, 4}, {StatSrc::Blocks, 8},
        {StatSrc::Atime, 4}, {StatSrc::Zero, 4},   // st_atime_ns
        {StatSrc::Mtime, 4}, {StatSrc::Zero, 4},   // st_mtime_ns
        {StatSrc::Ctime, 4}, {StatSrc::Zero, 4},   // st_ctime_ns
        {StatSrc::Ino, 8},                         // st_ino (u64 tail)
    }};
    return layout;
}

}  // namespace

// stat.py get_stat64_struct: the verbatim ladder — the QNX branch rides the
// same ARM64 stat64 shape for both arm widths; the linux ladder carries
// only the x86 table and the x8664 falls through it (the upstream's
// "Unrecognized arch && os" warn rides the caller with the logger)
const StatLayout& get_stat64_layout(QL_OS os, QL_ARCH arch) {
    if (os == QL_OS::QNX) {
        if (arch == QL_ARCH::ARM || arch == QL_ARCH::ARM64) {
            return qnx_arm64_stat();
        }
        throw QlErrorNotImplemented("qnx stat64: the ARM-EB table lands with its slice");
    }
    if (os == QL_OS::LINUX && arch == QL_ARCH::X86) {
        return linux_x86_stat64();
    }
    // the verbatim fallback: "Unrecognized arch && os ... Fallback to Linux x86."
    return linux_x86_stat64();
}

// stat.py Statx64 (_pack_=4): the 256-byte statx image — the hardcoded
// STATX_BASIC_STATS mask, the unset attributes/btime/pads as the zero
// cells, and the timestamps riding the float32 bit-pattern conversion
const StatLayout& statx64_layout() {
    static const StatLayout layout{4, {
        {StatSrc::StatxMask, 4},                   // stx_mask = 0x7ff
        {StatSrc::Blksize, 4},                     // stx_blksize
        {StatSrc::Zero, 8},                        // stx_attributes (unset)
        {StatSrc::Nlink, 4}, {StatSrc::Uid, 4}, {StatSrc::Gid, 4},
        {StatSrc::Mode, 2}, {StatSrc::Zero, 2},    // __statx_pad1
        {StatSrc::Ino, 8}, {StatSrc::Size, 8}, {StatSrc::Blocks, 8},
        {StatSrc::Zero, 8},                        // stx_attributes_mask
        {StatSrc::Atime, 8, true}, {StatSrc::Zero, 8},   // stx_atime + the nsec
        {StatSrc::Zero, 8}, {StatSrc::Zero, 8},    // stx_btime (unset)
        {StatSrc::Ctime, 8, true}, {StatSrc::Zero, 8},   // stx_ctime + the nsec
        {StatSrc::Mtime, 8, true}, {StatSrc::Zero, 8},   // stx_mtime + the nsec
        {StatSrc::RdevMajor, 4}, {StatSrc::RdevMinor, 4},
        {StatSrc::DevMajor, 4}, {StatSrc::DevMinor, 4},
        {StatSrc::Zero, 8}, {StatSrc::Zero, 8}, {StatSrc::Zero, 8}, {StatSrc::Zero, 8},
        {StatSrc::Zero, 8}, {StatSrc::Zero, 8}, {StatSrc::Zero, 8},
        {StatSrc::Zero, 8}, {StatSrc::Zero, 8}, {StatSrc::Zero, 8},
        {StatSrc::Zero, 8}, {StatSrc::Zero, 8}, {StatSrc::Zero, 8},
        {StatSrc::Zero, 8},                        // __statx_pad2 (u64 * 14)
    }};
    return layout;
}

// stat.py Statx32 (_pack_=8): the 32-bit-arch image — the timestamps ride
// the 12-byte StatxTimestamp32 cells
const StatLayout& statx32_layout() {
    static const StatLayout layout{8, {
        {StatSrc::StatxMask, 4}, {StatSrc::Blksize, 4}, {StatSrc::Zero, 4},
        {StatSrc::Nlink, 4}, {StatSrc::Uid, 4}, {StatSrc::Gid, 4},
        {StatSrc::Mode, 2}, {StatSrc::Zero, 2},
        {StatSrc::Ino, 4}, {StatSrc::Size, 4}, {StatSrc::Blocks, 4},
        {StatSrc::Zero, 4},
        {StatSrc::Atime, 4, true}, {StatSrc::Zero, 8},   // atime: sec + nsec + pad
        {StatSrc::Zero, 12},                             // btime (unset)
        {StatSrc::Ctime, 4, true}, {StatSrc::Zero, 8},
        {StatSrc::Mtime, 4, true}, {StatSrc::Zero, 8},
        {StatSrc::RdevMajor, 4}, {StatSrc::RdevMinor, 4},
        {StatSrc::DevMajor, 4}, {StatSrc::DevMinor, 4},
        {StatSrc::Zero, 4}, {StatSrc::Zero, 4}, {StatSrc::Zero, 4}, {StatSrc::Zero, 4},
        {StatSrc::Zero, 4}, {StatSrc::Zero, 4}, {StatSrc::Zero, 4}, {StatSrc::Zero, 4},
        {StatSrc::Zero, 4}, {StatSrc::Zero, 4}, {StatSrc::Zero, 4}, {StatSrc::Zero, 4},
        {StatSrc::Zero, 4}, {StatSrc::Zero, 4},           // __statx_pad2 (u32 * 14)
    }};
    return layout;
}

// stat.py ql_syscall_statx's inline choice: the arch bitness picks the image
// (the os never enters the decision)
const StatLayout& get_statx_layout(int bits) {
    return bits == 32 ? statx32_layout() : statx64_layout();
}

const StatLayout& get_stat_layout(QL_OS os, QL_ARCH arch) {
    // stat.py get_stat_struct: the verbatim ladder — QNX first (the only
    // dialect with a live consumer so far), then the linux x86 pair, the
    // untabled dialects raise (their tables land with their slices)
    if (os == QL_OS::QNX) {
        if (arch == QL_ARCH::ARM64) {
            return qnx_arm64_stat();
        }
        if (arch == QL_ARCH::ARM) {
            return qnx_arm_stat();
        }
        throw QlErrorNotImplemented("qnx stat: the ARM-EB table lands with its slice");
    }
    if (os == QL_OS::LINUX) {
        if (arch == QL_ARCH::X8664) {
            return linux_x86_64_stat();
        }
        if (arch == QL_ARCH::X86) {
            return linux_x86_stat();
        }
        throw QlErrorNotImplemented("linux stat: the mips/arm/riscv/ppc tables land with their slices");
    }
    // stat.py: "Unrecognized arch && os ... Fallback to Linux x86." — the
    // warning rides the fstat-syscall slice (it holds the Qiling logger)
    return linux_x86_stat();
}

std::vector<std::uint8_t> pack_stat_struct(const QlFileStat& info, const StatLayout& layout) {
    // __common_pack_stat_struct: each field lands at its ctypes offset —
    // the alignment per cell is min(width, _pack_), the struct size rounds
    // up to the max cell alignment (the ctypes bytes(stat) semantics)
    std::vector<std::uint8_t> out;
    std::uint32_t offset = 0;
    std::uint32_t max_align = 1;
    const auto put = [&out](std::uint64_t v, std::uint32_t width) {
        for (std::uint32_t i = 0; i < width; ++i) {
            out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
        }
    };
    for (const auto& cell : layout.cells) {
        const auto align = cell.width < layout.pack ? cell.width : layout.pack;
        if (align > max_align) {
            max_align = align;
        }
        while (offset % align != 0) {
            out.push_back(0);
            ++offset;
        }
        if (cell.as_statx_time) {
            // stat.py statx_convert_timestamp: struct.pack('f', x) then
            // unpack('i') — the IEEE-754 float32 BIT PATTERN of the value
            // (the verbatim quirk); the int32 view sign-extends into the
            // wider tv_sec cells (the c_int64 assignment semantics)
            const float f = static_cast<float>(static_cast<double>(source_value(info, cell.src)));
            std::int32_t bits = 0;
            std::memcpy(&bits, &f, 4);
            put(static_cast<std::uint64_t>(static_cast<std::int64_t>(bits)), cell.width);
        } else {
            const auto bits = cell.width * 8;
            const auto mask = bits >= 64 ? ~0ull : ((1ull << bits) - 1);
            put(source_value(info, cell.src) & mask, cell.width);
        }
        offset += cell.width;
    }
    while (offset % max_align != 0) {
        out.push_back(0);
        ++offset;
    }
    return out;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
