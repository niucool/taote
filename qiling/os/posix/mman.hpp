// Ported from qiling/os/posix/syscall/mman.py — the mmap family (the
// syscall_mmap_impl + the mmap/mmap2/old_mmap/munmap/mprotect/madvise
// handlers). The per-OS flag tables ride const.py's Flag classes verbatim;
// the dispatch keys on (QL_OS, QL_ARCH) exactly like the upstream's
// __select_mmap_flags.
#pragma once

#include "qiling/core.hpp"
#include <cstdint>
#include <optional>
#include <vector>

namespace qiling {
namespace os {
namespace posix {

// const.py linux_mmap_flags (the default linux shape; the mips arm rides
// mips_mmap_flags per the select)
struct MmapFlags {
    std::uint32_t file = 0;
    std::uint32_t shared = 0;
    std::uint32_t priv = 0;
    std::uint32_t fixed = 0;
    std::uint32_t anonymous = 0;
    std::uint32_t fixed_noreplace = 0;
    std::uint32_t uninitialized = 0;
};

// const.py __select_mmap_flags: the os/arch dispatch (the mips arm keys on
// the arch; the tables carry only the fields the impl reads — the unused
// upstream flags stay in their classes verbatim but are not consumed)
MmapFlags select_mmap_flags(QL_OS os, QL_ARCH arch);

// mman.py syscall_mmap_impl: the shared mmap body (the verbatim boundary
// walk + the ANON/file branches + the map-then-protect shape)
std::optional<std::int64_t> syscall_mmap_impl(Qiling& ql, std::uint64_t addr, std::uint64_t length,
                                              std::uint64_t prot, std::uint64_t flags, std::int64_t fd,
                                              std::int64_t pgoffset, int ver);

std::optional<std::int64_t> syscall_mmap(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_mmap2(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_old_mmap(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_munmap(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_mprotect(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_madvise(Qiling& ql, const std::vector<std::uint64_t>& params);

}  // namespace posix
}  // namespace os
}  // namespace qiling
