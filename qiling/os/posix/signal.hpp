// Ported from qiling/os/posix/syscall/signal.py — the signal-family
// surface (rt_sigaction / rt_sigprocmask / signal). The sigaction struct
// layouts mirror the per-arch ctypes classes verbatim; the frame machinery
// (the actual signal delivery) lands with its own slice.
#pragma once

#include "qiling/core.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

// glibc's <signal.h> aliases sa_handler onto the sigaction union member via
// macro (transitively visible through many host headers); the guest struct
// keeps the upstream field name, so drop the alias — the port never touches
// the host struct sigaction members
#ifdef sa_handler
#undef sa_handler
#endif
#ifdef sa_sigaction
#undef sa_sigaction
#endif

namespace qiling {
namespace os {
namespace posix {

// posix/const.py NSIG (the signal count)
inline constexpr int kNSig = 32;

// signal.py __make_sigaction: the per-arch sigaction layouts. The handler
// and the sigaction pointer share a slot (the FIXME'd-out union — the
// upstream refers to the inner field as 'sa_handler' regardless).
struct GuestSigaction {
    std::uint64_t sa_handler = 0;   // the union'd handler slot (the native width)
    std::uint64_t sa_mask = 0;      // the sigset (the native width off-mips)
    std::uint64_t sa_flags = 0;
    std::uint64_t sa_restorer = 0;

    // the field order per arch: the x86/ARM families put the mask second,
    // the x8664 puts it last (the verbatim table)
    static std::size_t guest_size(QL_ARCH arch);
    // the field write order for the load/save (the ctypes field order)
    static void load_from(QL_ARCH arch, Qiling& ql, std::uint64_t addr, GuestSigaction& out);
    static void save_to(QL_ARCH arch, Qiling& ql, std::uint64_t addr, const GuestSigaction& v);
};

std::optional<std::int64_t> syscall_rt_sigaction(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_rt_sigprocmask(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_signal(Qiling& ql, const std::vector<std::uint64_t>& params);

}  // namespace posix
}  // namespace os
}  // namespace qiling
