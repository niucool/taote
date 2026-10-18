// Ported from qiling/os/macos/kernel_api/kernel_api.py — the XNU
// kernel-function handlers. The passthru stub bodies port verbatim (the
// upstream's empty `return` bodies — the guest's own stub code executes for
// the passthru entries); the real-bodied handlers port explicitly. The
// ev_manager-dependent handlers (proc_name, proc_find, kauth_getuid/getgid,
// kauth_cred_setuidgid) defer with the events/policy subsystem slices.
#include "qiling/os/macos/kernel_api.hpp"

#include <chrono>

#include "qiling/core.hpp"
#include "qiling/os/posix/kernel_api.hpp"
#include "qiling/os/utils.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

// the posix kernel_api.cpp get_int shape (the raw u64 out of the variant)
std::uint64_t get_int(const std::pair<std::string, FcallValue>& p) {
    if (const auto* v = std::get_if<std::uint64_t>(&p.second)) {
        return *v;
    }
    return 0;
}

const FcallValue& find_param(const ResolvedParams& params, const char* name) {
    static const FcallValue zero{static_cast<std::uint64_t>(0)};
    for (const auto& [n, v] : params) {
        if (n == name) {
            return v;
        }
    }
    return zero;
}

// kernel_api.py hook__suulong: the uword into the guest cell, return 0
std::optional<std::uint64_t> syscall_kapi_suulong(Qiling& ql, std::uint64_t, const ResolvedParams& params) {
    const auto addr = get_int({"addr", find_param(params, "addr")});
    const auto uword = get_int({"uword", find_param(params, "uword")});
    ql.mem().write(addr, {static_cast<std::uint8_t>(uword), static_cast<std::uint8_t>(uword >> 8),
                          static_cast<std::uint8_t>(uword >> 16), static_cast<std::uint8_t>(uword >> 24),
                          static_cast<std::uint8_t>(uword >> 32), static_cast<std::uint8_t>(uword >> 40),
                          static_cast<std::uint8_t>(uword >> 48), static_cast<std::uint8_t>(uword >> 56)});
    return 0;
}

// kernel_api.py hook__fuulong: the u64 read back from the guest cell
std::optional<std::uint64_t> syscall_kapi_fuulong(Qiling& ql, std::uint64_t, const ResolvedParams& params) {
    const auto addr = get_int({"addr", find_param(params, "addr")});
    const auto data = ql.mem().read(addr, 8);
    std::uint64_t out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(data[static_cast<std::size_t>(i)]) << (8 * i);
    }
    return out;
}

// kernel_api.py hook__read_random / hook__read_erandom: the 0xdeadbeaf
// stamp into the caller's buffer (no return)
std::optional<std::uint64_t> syscall_kapi_read_random(Qiling& ql, std::uint64_t, const ResolvedParams& params) {
    const auto buf = get_int({"buf", find_param(params, "buf")});
    ql.mem().write(buf, {0xaf, 0xbe, 0xad, 0xde});  // pack32(0xdeadbeaf)
    return std::nullopt;
}

std::optional<std::uint64_t> syscall_kapi_read_erandom(Qiling& ql, std::uint64_t, const ResolvedParams& params) {
    return syscall_kapi_read_random(ql, 0, params);
}

// kernel_api.py hook__clock_get_calendar_microtime: the wall clock into the
// two cells — the tv_sec = the epoch seconds, the tv_usec = the upstream's
// `int(round(now * 1000))` (the MILLISECONDS arithmetic — the oddity is
// verbatim)
std::optional<std::uint64_t> syscall_kapi_clock_get_calendar_microtime(Qiling& ql, std::uint64_t,
                                                                       const ResolvedParams& params) {
    const auto now = std::chrono::duration_cast<std::chrono::duration<double>>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    const auto sec = static_cast<std::uint64_t>(now);
    const auto usec = static_cast<std::uint64_t>(now * 1000.0);
    const auto write_u64 = [&ql](std::uint64_t at, std::uint64_t v) {
        ql.mem().write(at, {static_cast<std::uint8_t>(v), static_cast<std::uint8_t>(v >> 8),
                            static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 24),
                            static_cast<std::uint8_t>(v >> 32), static_cast<std::uint8_t>(v >> 40),
                            static_cast<std::uint8_t>(v >> 48), static_cast<std::uint8_t>(v >> 56)});
    };
    write_u64(get_int({"tv_sec", find_param(params, "tv_sec")}), sec);
    write_u64(get_int({"tv_usec", find_param(params, "tv_usec")}), usec);
    return std::nullopt;
}

// kernel_api.py hook__proc_selfpid: the fixed 0x1337
std::optional<std::uint64_t> syscall_kapi_proc_selfpid(Qiling&, std::uint64_t, const ResolvedParams&) {
    return 0x1337;
}

// kernel_api.py hook__proc_selfppid: the fixed 0x13371337
std::optional<std::uint64_t> syscall_kapi_proc_selfppid(Qiling&, std::uint64_t, const ResolvedParams&) {
    return 0x13371337;
}

// kernel_api.py hook__msleep / hook__kernel_thread_start: the 0 stubs
std::optional<std::uint64_t> syscall_kapi_msleep(Qiling&, std::uint64_t, const ResolvedParams&) {
    return 0;
}

std::optional<std::uint64_t> syscall_kapi_kernel_thread_start(Qiling&, std::uint64_t, const ResolvedParams&) {
    return 0;
}

// kernel_api.py hook__vfs_context_proc: the identity (the ctx passes back)
std::optional<std::uint64_t> syscall_kapi_vfs_context_proc(Qiling&, std::uint64_t, const ResolvedParams& params) {
    return static_cast<std::uint64_t>(get_int({"ctx", find_param(params, "ctx")}));
}

// the passthru stub: the empty body (the upstream's `return` — the guest's
// own stub code runs for the passthru entries)
std::optional<std::uint64_t> kapi_stub(Qiling&, std::uint64_t, const ResolvedParams&) {
    return std::nullopt;
}

}  // namespace

KernelApiRegistry& KernelApiRegistry::instance() {
    static KernelApiRegistry registry;
    return registry;
}

void KernelApiRegistry::register_api(KernelApiEntry entry) {
    entries_[entry.name] = std::move(entry);
}

const KernelApiEntry* KernelApiRegistry::find(const std::string& name) const {
    const auto it = entries_.find(name);
    return it == entries_.end() ? nullptr : &it->second;
}

void KernelApiRegistry::clear() {
    entries_.clear();
}

KernelApi::KernelApi(std::string name, KernelApiParams params, bool passthru) {
    entry_.name = std::move(name);
    entry_.params = std::move(params);
    entry_.passthru = passthru;
}

void KernelApi::operator=(KernelApiHandler handler) {
    entry_.handler = std::move(handler);
    KernelApiRegistry::instance().register_api(std::move(entry_));
}

// the kernel_api.py module registrations (the verbatim surface: 111 entries)
namespace {

void register_macos_kernel_api() {
    static const bool done = [] {
#include "qiling/os/macos/kernel_api_registry.inc"
        return true;
    }();
    (void)done;
}

const bool registered = (register_macos_kernel_api(), true);

}  // namespace

}  // namespace macos
}  // namespace os
}  // namespace qiling
