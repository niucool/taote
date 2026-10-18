// Ported from qiling/os/posix/syscall/signal.py — the signal-family
// handlers. The sigaction struct rides the per-arch ctypes layouts (the
// field ORDER differs per arch, the widths ride the native pointer size);
// the mask state lives on the os.
#include "qiling/os/posix/signal.hpp"

#include <cstring>

#include "qiling/os/os.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/memory.hpp"

namespace qiling {
namespace os {
namespace posix {

namespace {

// the native field width (the native_type = the pointer size per arch)
std::uint32_t native_width(QL_ARCH arch) {
    switch (arch) {
        case QL_ARCH::X8664:
            return 8;
        case QL_ARCH::X86:
        case QL_ARCH::ARM:
        case QL_ARCH::ARM64:
          return 4;
        default:
            // the mips/cortex_m tables land with their slices
            return 8;
    }
}

// the u64/u32 LE reads (the widths ride the native type)
std::uint64_t read_native(Qiling& ql, std::uint64_t addr, std::uint32_t width) {
    const auto raw = ql.mem().read(addr, width);
    std::uint64_t v = 0;
    std::memcpy(&v, raw.data(), width);
    return v;
}

void write_native(Qiling& ql, std::uint64_t addr, std::uint32_t width, std::uint64_t v) {
    std::vector<std::uint8_t> raw(width, 0);
    std::memcpy(raw.data(), &v, width);
    ql.mem().write(addr, raw);
}

}  // namespace

std::size_t GuestSigaction::guest_size(QL_ARCH arch) {
    return native_width(arch) * 4;
}

void GuestSigaction::load_from(QL_ARCH arch, Qiling& ql, std::uint64_t addr, GuestSigaction& out) {
    const auto w = native_width(arch);
    // the field orders (the ctypes _fields_ verbatim): the x8664 puts the
    // mask last; the x86 and the ARM families put the mask second
    switch (arch) {
        case QL_ARCH::X8664:
            out.sa_handler = read_native(ql, addr, w);
            out.sa_flags = read_native(ql, addr + w, w);
            out.sa_restorer = read_native(ql, addr + 2 * w, w);
            out.sa_mask = read_native(ql, addr + 3 * w, w);
            break;
        case QL_ARCH::X86:
        case QL_ARCH::ARM:
        case QL_ARCH::ARM64:
        default:
            out.sa_handler = read_native(ql, addr, w);
            out.sa_mask = read_native(ql, addr + w, w);
            out.sa_flags = read_native(ql, addr + 2 * w, w);
            out.sa_restorer = read_native(ql, addr + 3 * w, w);
            break;
    }
}

void GuestSigaction::save_to(QL_ARCH arch, Qiling& ql, std::uint64_t addr, const GuestSigaction& v) {
    const auto w = native_width(arch);
    switch (arch) {
        case QL_ARCH::X8664:
            write_native(ql, addr, w, v.sa_handler);
            write_native(ql, addr + w, w, v.sa_flags);
            write_native(ql, addr + 2 * w, w, v.sa_restorer);
            write_native(ql, addr + 3 * w, w, v.sa_mask);
            break;
        case QL_ARCH::X86:
        case QL_ARCH::ARM:
        case QL_ARCH::ARM64:
        default:
            write_native(ql, addr, w, v.sa_handler);
            write_native(ql, addr + w, w, v.sa_mask);
            write_native(ql, addr + 2 * w, w, v.sa_flags);
            write_native(ql, addr + 3 * w, w, v.sa_restorer);
            break;
    }
}

std::optional<std::int64_t> syscall_rt_sigaction(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // rt_sigaction(signum, act, oldact)
    const auto signum = static_cast<int>(params[0]);
    const auto act = params[1];
    const auto oldact = params[2];

    constexpr int kSigKill = 9;
    constexpr int kSigStop = 19;

    if (signum < 0 || signum >= kNSig || signum == kSigKill || signum == kSigStop) {
        return -1;  // EINVAL
    }

    const auto arch = ql.arch().type();
    auto& os = ql.os<posix::QlOsPosix>();

    if (oldact != 0) {
        // the old record: the registered handler or the default-constructed
        GuestSigaction old;
        if (const auto* cur = os.sig_action(signum)) {
            old = *cur;
        }
        GuestSigaction::save_to(arch, ql, oldact, old);
    }

    if (act != 0) {
        GuestSigaction next;
        GuestSigaction::load_from(arch, ql, act, next);
        os.set_sig_action(signum, std::move(next));
    }

    return 0;
}

std::optional<std::int64_t> syscall_rt_sigprocmask(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // __sigprocmask(how, newset, oldset): the how constants (the mips arm
    // rides its own table with its slice)
    constexpr std::uint64_t kSigBlock = 0;
    constexpr std::uint64_t kSigUnblock = 1;
    constexpr std::uint64_t kSigSetmask = 2;
    constexpr int kSigKill = 9;
    constexpr int kSigStop = 19;

    const auto how = params[0];
    const auto newset = params[1];
    const auto oldset = params[2];

    auto& os = ql.os<posix::QlOsPosix>();

    if (oldset != 0) {
        // the verbatim quirk: the old mask writes to NEWSET (the upstream
        // line rides ql.mem.write_ptr(newset, ...) — NOT oldset)
        ql.mem().write_ptr(newset, os.blocked_signals());
    }

    if (newset != 0) {
        const auto set_mask = ql.mem().read_ptr(newset);

        if (how == kSigBlock) {
            os.set_blocked_signals(os.blocked_signals() | set_mask);
        } else if (how == kSigUnblock) {
            os.set_blocked_signals(os.blocked_signals() & ~set_mask);
        } else if (how == kSigSetmask) {
            os.set_blocked_signals(set_mask);
        } else {
            return -1;  // EINVAL
        }

        // silently drop the attempts to block SIGKILL and SIGSTOP
        os.set_blocked_signals(os.blocked_signals() &
                               ~((std::uint64_t{1} << kSigKill) | (std::uint64_t{1} << kSigStop)));
    }

    return 0;
}

std::optional<std::int64_t> syscall_signal(Qiling&, const std::vector<std::uint64_t>&) {
    // ql_syscall_signal: the verbatim no-op stub
    return 0;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
