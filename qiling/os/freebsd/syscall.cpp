// Ported from qiling/os/freebsd/syscall.py — the freebsd-specific handlers.
// The clock_gettime/sysarch/sigprocmask/__sysctl are the freebsd shapes; the
// __getcwd/fstatat delegate to the posix implementations verbatim.
#include "qiling/os/freebsd/syscall.hpp"

#include <chrono>

#include "qiling/arch/x86.hpp"
#include "qiling/os/path.hpp"
#include "qiling/os/posix/syscall.hpp"
#include <cstring>

#include "qiling/core.hpp"
#include "qiling/os/freebsd/const.hpp"
#include "qiling/os/freebsd/map_syscall.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/utils.hpp"

namespace qiling {
namespace os {
namespace freebsd {

// posix/const.py ENOENT (the sysctl NAME2OID miss returns it)
constexpr std::int64_t kENOENT = 2;

namespace {

// the freebsd timespec layout: the tv_sec=u64, the tv_nsec=i64, the 8-byte
// packing (the _pack_ = 8)
struct Timespec {
    std::uint64_t tv_sec;
    std::int64_t tv_nsec;
};
static_assert(sizeof(Timespec) == 16, "timespec layout");

constexpr int IA32_FS_BASE_MSR = 0xC0000100;

// syscall.py FREEBSD_OSRELDATE — see const.hpp for the provenance note
constexpr int kOsreldate = FREEBSD_OSRELDATE;

std::optional<std::int64_t> syscall_clock_gettime(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // syscall.py ql_syscall_clock_gettime: the wall clock into the caller's
    // timespec (the freebsd layout); the nsec field carries the usec-resolution
    // fraction (the upstream's *1e6 arithmetic, verbatim)
    const auto tp = params[1];

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    const auto usecs = std::chrono::duration_cast<std::chrono::microseconds>(now).count() % 1000000;

    const Timespec ts{static_cast<std::uint64_t>(secs), static_cast<std::int64_t>(usecs) * 1000};

    std::vector<std::uint8_t> buf(sizeof(Timespec));
    std::memcpy(buf.data(), &ts, sizeof(Timespec));
    ql.mem().write(tp, buf);
    return 0;
}

std::optional<std::int64_t> syscall_sysarch(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // syscall.py ql_syscall_sysarch: the "wild guess" — the parms land in the
    // FS base MSR (the verbatim shape; the op is ignored)
    const auto parms = params[1];
    dynamic_cast<QlArchIntel&>(ql.arch()).msr().write(IA32_FS_BASE_MSR, parms);
    return 0;
}

std::optional<std::int64_t> syscall_sigprocmask(Qiling&, const std::vector<std::uint64_t>&) {
    // syscall.py ql_syscall_sigprocmask: the debug log + the success
    return 0;
}

std::optional<std::int64_t> syscall_getcwd(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // posix.py ql_syscall_getcwd (syscall.py delegates __getcwd to it): the
    // cwd bytes + the NUL at path_buff, the return = the written length
    const auto path_buff = params[0];

    const std::string cwd = ql.os().path()->cwd();
    std::vector<std::uint8_t> bytes(cwd.begin(), cwd.end());
    bytes.push_back(0);
    ql.mem().write(path_buff, bytes);

    return static_cast<std::int64_t>(bytes.size());
}

std::optional<std::int64_t> syscall_fstatat(Qiling&, const std::vector<std::uint64_t>&) {
    // syscall.py ql_syscall_fstatat delegates to the posix's newfstatat; the
    // posix stat module defers with its slice
    throw QlErrorNotImplemented("freebsd fstatat: the posix newfstatat delegate lands with the stat module slice");
}

std::optional<std::int64_t> syscall_sysctl(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // syscall.py ql_syscall___sysctl: the vecs walk, the NAME2OID and the
    // KERN.OSRELDATE paths (verbatim)
    const auto name = params[0];
    const auto namelen = static_cast<std::size_t>(params[1]);
    const auto old = params[2];
    const auto oldlenp = params[3];
    const auto new_arg = params[4];

    std::vector<std::int64_t> vecs;
    vecs.reserve(namelen);
    for (std::size_t i = 0; i < namelen; ++i) {
        vecs.push_back(static_cast<std::int64_t>(ql.mem().read_ptr(name + i * 4, 4)));
    }

    if (vecs[0] == CTL_SYSCTL) {
        if (vecs[1] == CTL_SYSCTL_NAME2OID) {
            // write the oid to old and oldlenp; the oids resolve from the name
            // (the upstream implements only hw.pagesizes — verbatim)
            const auto sysctl_name = QlOsUtils::read_cstring(ql, new_arg);
            std::vector<std::int64_t> out_vecs;
            std::int64_t out_len = 0;
            if (sysctl_name == "hw.pagesizes") {
                out_vecs = {CTL_HW, HW_PAGESIZE};
                out_len = 2;
            }

            for (std::size_t i = 0; i < out_vecs.size(); ++i) {
                ql.mem().write_ptr(old + i * 4, static_cast<std::uint64_t>(out_vecs[i]), 4);
            }
            if (oldlenp != 0) {
                ql.mem().write_ptr(oldlenp, static_cast<std::uint64_t>(out_len), 4);
            }
        }
        return -kENOENT;
    }

    if (vecs[0] == CTL_KERN) {
        if (vecs[1] == KERN_OSRELDATE) {
            if (old == 0 || oldlenp == 0) {
                return -1;
            }
            // ignore the oldlenp check (verbatim)
            ql.mem().write_ptr(old, static_cast<std::uint64_t>(kOsreldate), 4);
            return 0;
        }
    }
    return 0;
}

}  // namespace

void register_freebsd_syscalls() {
    auto& registry = posix::SyscallRegistry::instance();

    // syscall.py's freebsd table: the deltas over the posix set ride here; the
    // shared names (exit/write/...) resolve through the posix registrations
    registry.register_syscall({"clock_gettime", {PARAM_INTN, PARAM_PTRX}, syscall_clock_gettime});
    registry.register_syscall({"sysarch", {PARAM_INTN, PARAM_PTRX}, syscall_sysarch});
    registry.register_syscall({"sigprocmask", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_sigprocmask});
    registry.register_syscall({"__getcwd", {PARAM_PTRX, PARAM_INTN}, syscall_getcwd});
    registry.register_syscall({"fstatat", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_INTN}, syscall_fstatat});
    registry.register_syscall({"__sysctl", {PARAM_PTRX, PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_PTRX, PARAM_INTN},
                               syscall_sysctl});
}

}  // namespace freebsd
}  // namespace os
}  // namespace qiling
