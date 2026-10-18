// Ported from qiling/os/posix/syscall/mman.py — the mmap family. The
// boundary walk, the flag semantics, the flush-on-unmap flow and the
// errno returns mirror the upstream line by line.
#include "qiling/os/posix/mman.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>

#include "qiling/exception.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"
#include "qiling/loader/elf.hpp"

namespace qiling {
namespace os {
namespace posix {

namespace {

// const.py linux_mmap_flags (the x86/arm shape: the MAP_ANONYMOUS 0x20)
constexpr MmapFlags kLinuxMmapFlags{0, 0x1, 0x2, 0x10, 0x20, 0x00100000, 0x04000000};
// const.py mips_mmap_flags (the mips arm: the MAP_ANONYMOUS 0x800 shape)
constexpr MmapFlags kMipsMmapFlags{0, 0x1, 0x2, 0x10, 0x800, 0x00100000, 0x04000000};
// const.py freebsd_mmap_flags (the MAP_ANONYMOUS 0x1000 shape; the
// MAP_FIXED_NOREPLACE rides MAP_EXCL — the verbatim alias)
constexpr MmapFlags kFreebsdMmapFlags{0, 0x1, 0x2, 0x10, 0x1000, 0x00004000, 0};
// const.py macos_mmap_flags (the MAP_ANONYMOUS 0x1000 shape)
constexpr MmapFlags kMacosMmapFlags{0, 0x1, 0x2, 0x10, 0x1000, 0, 0};
// const.py qnx_mmap_flags (the verbatim "FIXME: only for arm?" note rides
// the upstream select)
constexpr MmapFlags kQnxMmapFlags{0, 0x1, 0x2, 0x10, 0x00010000, 0, 0};

// the errno constants (posix/const.py)
constexpr std::int64_t kEinval = -22;
constexpr std::int64_t kEbadf = -9;
constexpr std::int64_t kEnomem = -12;
constexpr std::int64_t kEexist = -17;

std::string basename_of(const std::string& name) {
    // the upstream keys os.path.basename(fname) after the bytes-decode
    return std::filesystem::path(name).filename().string();
}

std::string hex_of(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

}  // namespace

MmapFlags select_mmap_flags(QL_OS os, QL_ARCH arch) {
    // __select_mmap_flags: the osflags dict verbatim — the mips arm keys on
    // the arch inside the LINUX entry
    switch (os) {
        case QL_OS::LINUX:
            return arch == QL_ARCH::MIPS ? kMipsMmapFlags : kLinuxMmapFlags;
        case QL_OS::FREEBSD:
            return kFreebsdMmapFlags;
        case QL_OS::MACOS:
            return kMacosMmapFlags;
        case QL_OS::QNX:
            return kQnxMmapFlags;
        default:
            return kLinuxMmapFlags;
    }
}

std::optional<std::int64_t> syscall_mmap_impl(Qiling& ql, std::uint64_t addr, std::uint64_t length,
                                              std::uint64_t prot, std::uint64_t flags, std::int64_t fd,
                                              std::int64_t pgoffset, int ver) {
    // the api_name tuple ('old_mmap', 'mmap', 'mmap2')[ver] prefixes the
    // upstream's debug logs only — no behavioral ride
    (void)ver;

    const auto pagesize = ql.mem().pagesize();
    const auto mapping_size = ql.mem().align_up(length + (addr & (pagesize - 1)));

    // the mmap_flags class built over the osflags table: only the fields
    // the impl reads matter here
    const auto mm = select_mmap_flags(ql.os().type(), ql.arch().type());

    // if mapping is fixed, use the base address as-is
    if ((flags & (mm.fixed | mm.fixed_noreplace)) != 0) {
        // on non-QNX systems, base must be aligned to page boundary
        if ((addr & (pagesize - 1)) != 0 && ql.os().type() != QL_OS::QNX) {
            return kEinval;
        }
    } else {
        // the base as a hint, always at/above the loader's mmap address
        const auto* elf = dynamic_cast<const loader::QlLoaderELF*>(&ql.loader());
        const auto mmap_address = elf != nullptr ? elf->mmap_address() : 0;
        addr = ql.mem().find_free_space(mapping_size, std::max(addr, mmap_address));
    }

    // on non-QNX systems addr is already aligned to page boundary
    const auto lbound = ql.mem().align(addr);
    const auto ubound = lbound + mapping_size;

    if ((flags & mm.fixed_noreplace) != 0) {
        if (!ql.mem().is_available(lbound, mapping_size)) {
            return kEexist;
        }
    } else if ((flags & mm.fixed) != 0) {
        // the fixed mapping unmaps the overlapping range first
        ql.mem().unmap_between(lbound, ubound);
    }

    std::string label = "[mmap anonymous]";
    std::vector<std::uint8_t> data;
    if ((flags & mm.anonymous) == 0) {
        // the file-backed mapping: the as_signed-then-NR_OPEN-then-None fd
        // walk (the negative fds fall out of the range check — the verbatim
        // -EBADF)
        if (fd < 0 || fd >= QlFileDes::NR_OPEN) {
            return kEbadf;
        }
        auto* f = dynamic_cast<QlFile*>(fd_get(ql, fd).get());
        if (f == nullptr) {
            return kEbadf;
        }

        // the flush-on-unmap properties ride the file
        f->set_map_shared((flags & mm.shared) != 0);
        f->set_mapped_offset(pgoffset);

        f->lseek(static_cast<std::uint64_t>(pgoffset), 0 /* SEEK_SET */);
        data = f->read(static_cast<std::size_t>(length));
        label = "[mmap] " + basename_of(f->name());
    }

    try {
        // map first as writeable so the data can land, protect afterwards
        ql.mem().map(lbound, mapping_size, UC_PROT_ALL, label);
    } catch (const QlMemoryMappedError&) {
        // "out of memory" — the verbatim -ENOMEM
        return kEnomem;
    }

    if (!data.empty()) {
        ql.mem().write(addr, data);
    }
    ql.mem().protect(lbound, mapping_size, static_cast<int>(prot));

    return static_cast<std::int64_t>(addr);
}

std::optional<std::int64_t> syscall_mmap(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_mmap(ql, addr, length, prot, flags, fd, pgoffset)
    return syscall_mmap_impl(ql, params[0], params[1], params[2], params[3],
                             static_cast<std::int64_t>(params[4]),
                             static_cast<std::int64_t>(params[5]), 1);
}

std::optional<std::int64_t> syscall_mmap2(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_mmap2: the pgoffset scales by the pagesize off-QNX
    auto pgoffset = static_cast<std::int64_t>(params[5]);
    if (ql.os().type() != QL_OS::QNX) {
        pgoffset *= static_cast<std::int64_t>(ql.mem().pagesize());
    }
    return syscall_mmap_impl(ql, params[0], params[1], params[2], params[3],
                             static_cast<std::int64_t>(params[4]), pgoffset, 2);
}

std::optional<std::int64_t> syscall_old_mmap(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_old_mmap: the ia32-compat struct form (the six 4-byte args
    // riding the memory block at the pointer)
    const auto args = params[0];
    const auto addr = ql.mem().read_ptr(args + 0 * 4, 4);
    const auto length = ql.mem().read_ptr(args + 1 * 4, 4);
    const auto prot = ql.mem().read_ptr(args + 2 * 4, 4);
    const auto flags = ql.mem().read_ptr(args + 3 * 4, 4);
    const auto fd = ql.mem().read_ptr(args + 4 * 4, 4);
    const auto offset = ql.mem().read_ptr(args + 5 * 4, 4);
    return syscall_mmap_impl(ql, addr, length, prot, flags, static_cast<std::int64_t>(fd),
                             static_cast<std::int64_t>(offset), 0);
}

std::optional<std::int64_t> syscall_munmap(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_munmap: find addr's enclosing [mmap] range; "nothing to
    // do; cannot munmap what was not originally mmapped" still returns 0
    const auto addr = params[0];
    const auto length = params[1];

    const auto mapinfo = ql.mem().get_mapinfo();
    const auto it = std::find_if(mapinfo.begin(), mapinfo.end(), [&](const auto& entry) {
        const auto& label = std::get<3>(entry);
        // the verbatim prefix check ('[mmap]' and '[mmap anonymous]')
        return std::get<0>(entry) <= addr && addr < std::get<1>(entry) &&
               (label.rfind("[mmap]", 0) == 0 || label.rfind("[mmap anonymous]", 0) == 0);
    });
    if (it == mapinfo.end()) {
        return 0;
    }

    // extract the file name by removing the boxed prefix
    const std::string label = std::get<3>(*it);
    const std::size_t close_at = label.find(']');
    std::string fname = close_at == std::string::npos ? std::string{} : label.substr(close_at + 1);
    if (!fname.empty() && fname.front() == ' ') {
        fname.erase(0, 1);
    }

    if (!fname.empty()) {
        // find the fd that was originally mmapped (the basename match); the
        // already-closed fd case just skips the flush
        for (int fd = 0; fd < QlFileDes::NR_OPEN; ++fd) {
            auto* f = dynamic_cast<QlFile*>(fd_get(ql, fd).get());
            if (f == nullptr) {
                continue;
            }
            if (basename_of(f->name()) == fname) {
                // the flush rides the shared/private flag captured at mmap
                if (f->is_map_shared()) {
                    f->lseek(static_cast<std::uint64_t>(f->mapped_offset()), 0 /* SEEK_SET */);
                    f->write(ql.mem().read(addr, length));
                }
                break;
            }
        }
    }

    // munmap allows the length to exceed the mapped range: clip to the
    // original ubound
    const auto lbound = ql.mem().align(addr);
    const auto ubound = std::min(ql.mem().align_up(addr + length), std::get<1>(*it));
    ql.mem().unmap(lbound, ubound - lbound);

    return 0;
}

std::optional<std::int64_t> syscall_mprotect(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_mprotect: the protect failure surfaces the verbatim
    // "Error: change protection at: ..." mapped-error
    try {
        ql.mem().protect(params[0], params[1], static_cast<int>(params[2]));
        return 0;
    } catch (const QlMemoryMappedError&) {
        throw QlMemoryMappedError("Error: change protection at: " + hex_of(params[0]) + " - " +
                                  hex_of(params[0] + params[1] - 1));
    }
}

std::optional<std::int64_t> syscall_madvise(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_madvise: only MADV_DONTNEED does anything — the zero-fill
    constexpr std::uint64_t kMadvDontneed = 4;
    if (params[2] == kMadvDontneed) {
        ql.mem().write(params[0], std::vector<std::uint8_t>(static_cast<std::size_t>(params[1]), 0));
    }
    return 0;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
