// Ported from qiling/os/qnx/syscall.py — the QNX kernel-call handlers. The
// slice carries the channel_create and the thread_destroy (the qnx exit
// path); the message/sync/interrupt families land with their fixtures.
#include "qiling/os/qnx/syscall.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/qnx.hpp"
#include "qiling/os/qnx/structs.hpp"

#include <array>
#include <chrono>
#include <cstring>

namespace qiling {
namespace os {
namespace qnx {

namespace {

// types.py clock_types (lib/c/public/time.h)
constexpr int kClockRealtime = 0;

// syscall.py's nanosecond wall clock (the time_ns() shape)
std::uint64_t time_ns() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// syscall.py ql_syscall_channel_create: the flags are ignored; the new
// channel id is handed out from the running counter
std::optional<std::int64_t> syscall_channel_create(Qiling& ql, const std::vector<std::uint64_t>& params) {
    (void)params;  // flags

    auto& os = static_cast<QlOsQnx&>(ql.os());
    const auto chid = os.next_channel_id();
    return static_cast<std::int64_t>(chid);
}
// syscall.py ql_syscall_sys_cpupage_get: the cpupage cell reads (the
// CPUPAGE_ADDR / CPUPAGE_PLS / CPUPAGE_SYSPAGE indexes)
std::optional<std::int64_t> syscall_sys_cpupage_get(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto index = params[0];
    auto& os = static_cast<QlOsQnx&>(ql.os());

    // CPUPAGE_ADDR
    if (index == 0xffffffff) {
        return static_cast<std::int64_t>(os.cpupage_addr());
    }
    // CPUPAGE_PLS
    if (index == 1) {
        return static_cast<std::int64_t>(ql.mem().read_ptr(os.cpupage_addr() + 4, 4));
    }
    // CPUPAGE_SYSPAGE
    if (index == 2) {
        return static_cast<std::int64_t>(os.syspage_addr());
    }

    ql.log().warn("ql_syscall_sys_cpupage_get (index " + std::to_string(index) + ") not implemented");
    return std::nullopt;
}

// syscall.py ql_syscall_sys_cpupage_set: the CPUPAGE_PLS write
std::optional<std::int64_t> syscall_sys_cpupage_set(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto index = params[0];
    const auto value = params[1];
    auto& os = static_cast<QlOsQnx&>(ql.os());

    // CPUPAGE_PLS
    if (index == 1) {
        ql.mem().write_ptr(os.cpupage_addr() + 4, value, 4);
        return EOK;
    }

    ql.log().warn("ql_syscall_sys_cpupage_get (index " + std::to_string(index) + ") not implemented");
    return std::nullopt;
}

// syscall.py ql_syscall_connect_attach: the nd/flags sanity pins (the
// ND_LOCAL_NODE + the CLOEXEC shape), then the coid comes off the side-
// channel or the plain counter
std::optional<std::int64_t> syscall_connect_attach(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto nd = params[0];
    const auto pid = params[1];
    const auto chid = params[2];
    const auto index = params[3];
    const auto flags = params[4];

    if (nd != static_cast<std::uint64_t>(ND_LOCAL_NODE) || flags != 0x1) {
        throw QlErrorBase("qnx connect_attach: the nd/flags parameters are wrong (the ND_LOCAL_NODE + "
                          "_NTO_COF_CLOEXEC shape is the supported one)");
    }

    auto& os = static_cast<QlOsQnx&>(ql.os());
    const auto coid = os.alloc_connection_id((index & NTO_SIDE_CHANNEL) != 0,
                                             static_cast<std::uint32_t>(pid),
                                             static_cast<std::uint32_t>(chid));
    return static_cast<std::int64_t>(coid);
}

// syscall.py ql_syscall_connect_detach: the connection must exist and ride
// no file descriptor; the coid is removed
std::optional<std::int64_t> syscall_connect_detach(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto coid = static_cast<std::uint32_t>(params[0]);
    auto& connections = static_cast<QlOsQnx&>(ql.os()).connections();

    const auto it = connections.find(coid);
    if (it == connections.end()) {
        throw QlErrorBase("qnx connect_detach: the connection id must exist in the connections mapping");
    }
    if (it->second.fd.has_value()) {
        throw QlErrorBase("qnx connect_detach: the file descriptor has to be closed properly");
    }
    connections.erase(it);
    return 0;
}

// syscall.py ql_syscall_connect_flags: the pid/coid/mask sanity pins (the
// FD_CLOEXEC shape); the flags change is a no-op
std::optional<std::int64_t> syscall_connect_flags(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto pid = params[0];
    const auto coid = static_cast<std::uint32_t>(params[1]);
    const auto mask = params[2];

    if (pid != 0) {
        throw QlErrorBase("qnx connect_flags: is it possible to change the flags of another process?");
    }
    auto& connections = static_cast<QlOsQnx&>(ql.os()).connections();
    if (connections.find(coid) == connections.end()) {
        throw QlErrorBase("qnx connect_flags: the connection id must exist in the connections mapping");
    }
    if (mask != 0x1) {
        throw QlErrorBase("qnx connect_flags: is the mask always FD_CLOEXEC?");
    }
    return 0;
}

// syscall.py ql_syscall_connect_client_info (source: openqnx
// services/system/ker/ker_connect.c): the scoid -1 means the calling
// process; the record is <nd, pid, 0, 0> with the zero creds standing for
// the super-user
std::optional<std::int64_t> syscall_connect_client_info(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto scoid = params[0];
    const auto info = params[1];

    if (scoid != 0xffffffff) {
        throw QlErrorNotImplemented("qnx connect_client_info: other processes are not implemented");
    }

    auto& os = static_cast<QlOsQnx&>(ql.os());
    const auto pid32 = static_cast<std::uint32_t>(os.pid());
    const std::array<std::uint8_t, 16> record = {
        0x00, 0x00, 0x00, 0x00,  // nd = ND_LOCAL_NODE (u32)
        static_cast<std::uint8_t>(pid32 & 0xff),
        static_cast<std::uint8_t>((pid32 >> 8) & 0xff),
        static_cast<std::uint8_t>((pid32 >> 16) & 0xff),
        static_cast<std::uint8_t>((pid32 >> 24) & 0xff),  // pid (i32)
        0x00, 0x00, 0x00, 0x00,  // ruid (i32, the zero creds)
        0x00, 0x00, 0x00, 0x00,  // the trailing cell (u32)
    };
    ql.mem().write(info, std::vector<std::uint8_t>(record.begin(), record.end()));
    return 0;
}

// syscall.py ql_syscall_sync_create (source: openqnx
// services/system/ker/ker_sync.c): the mutex-free type stamps the
// NONRECURSIVE count and the type as the owner; the attr tweaks (the
// recursive/errorcheck bits) apply when the caller passes _sync_attr
std::optional<std::int64_t> syscall_sync_create(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto type = static_cast<std::uint32_t>(params[0]);
    const auto syncp = params[1];
    const auto attrp = params[2];

    std::uint32_t count = NTO_SYNC_NONRECURSIVE;
    if (type != NTO_SYNC_MUTEX_FREE) {
        ql.log().warn("sync_create: sync type not implemented");
        return EINVAL;
    }

    if (attrp != 0) {
        SyncAttr attr{};
        auto bytes = ql.mem().read(attrp, sizeof(attr));
        std::memcpy(&attr, bytes.data(), sizeof(attr));
        if ((attr.flags & PTHREAD_RECURSIVE_MASK) != PTHREAD_RECURSIVE_DISABLE) {
            count &= ~NTO_SYNC_NONRECURSIVE;
        }
        if ((attr.flags & PTHREAD_ERRORCHECK_DISABLE) != 0) {
            count |= NTO_SYNC_NOERRORCHECK;
        }
    }

    Sync sync{};
    auto bytes = ql.mem().read(syncp, sizeof(sync));
    std::memcpy(&sync, bytes.data(), sizeof(sync));
    sync.count = static_cast<std::int32_t>(count);
    sync.owner = type;
    const auto* raw = reinterpret_cast<const std::uint8_t*>(&sync);
    ql.mem().write(syncp, std::vector<std::uint8_t>(raw, raw + sizeof(sync)));
    return EOK;
}

// syscall.py ql_syscall_sync_mutex_lock: the stub — the mutex owner adopts
// the caller's TLS owner cell (the upstream's "proper mutexes" TODO, verbatim)
std::optional<std::int64_t> syscall_sync_mutex_lock(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto syncp = params[0];  // the lock's first (and only) kernel arg
    auto& os = static_cast<QlOsQnx&>(ql.os());

    Sync sync{};
    auto bytes = ql.mem().read(syncp, sizeof(sync));
    std::memcpy(&sync, bytes.data(), sizeof(sync));

    ThreadLocalStorage tls{};
    auto tls_bytes = ql.mem().read(os.cpupage_tls_addr(), sizeof(tls));
    std::memcpy(&tls, tls_bytes.data(), sizeof(tls));

    sync.owner = tls.owner;
    const auto* raw = reinterpret_cast<const std::uint8_t*>(&sync);
    ql.mem().write(syncp, std::vector<std::uint8_t>(raw, raw + sizeof(sync)));
    return EOK;
}

// syscall.py ql_syscall_sync_mutex_unlock: the stub — the owner resets to
// the mutex-free cell
std::optional<std::int64_t> syscall_sync_mutex_unlock(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto syncp = params[0];  // the unlock's first (and only) kernel arg

    Sync sync{};
    auto bytes = ql.mem().read(syncp, sizeof(sync));
    std::memcpy(&sync, bytes.data(), sizeof(sync));

    sync.owner = NTO_SYNC_MUTEX_FREE;
    const auto* raw = reinterpret_cast<const std::uint8_t*>(&sync);
    ql.mem().write(syncp, std::vector<std::uint8_t>(raw, raw + sizeof(sync)));
    return EOK;
}

// syscall.py ql_syscall_thread_destroy: the (-1, -1, status) request
// terminates the process with the status as the exit code
std::optional<std::int64_t> syscall_thread_destroy(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto tid = params[0];
    const auto priority = params[1];
    const auto status = params[2];

    // Requested to terminate all threads in the current process
    if (tid == 0xffffffff && priority == 0xffffffff) {
        ql.os().set_exit_code(static_cast<int>(status));
        ql.os().stop();
        // the upstream returns EOK after the stop; the port's stop unwinds
        // the emulation first, so the return register stays untouched (the
        // posix exit shape)
        return std::nullopt;
    }
    return EOK;
}

// syscall.py ql_syscall_clock_cycles: the core's free-running 64-bit counter
// — simplified to the nanosecond wall clock (the upstream's note, verbatim)
std::optional<std::int64_t> syscall_clock_cycles(Qiling& ql, const std::vector<std::uint64_t>& params) {
    (void)params;
    return static_cast<std::int64_t>(time_ns());
}

// syscall.py ql_syscall_clock_time (source: openqnx
// lib/c/support/_syspage_time.c): the CLOCK_REALTIME read writes the
// nanosecond wall clock into the caller's 8-byte cell; the set-time path
// warns and returns -1, the unknown ids raise
std::optional<std::int64_t> syscall_clock_time(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto id = params[0];
    const auto new_ptr = params[1];
    const auto old_ptr = params[2];

    // the port's clock_types cover 0..4 (CLOCK_REALTIME..CLOCK_THREAD_CPUTIME_ID)
    if (id > 4) {
        throw QlErrorNotImplemented("qnx clock_time: unknown clock id " + std::to_string(id));
    }
    if (id != kClockRealtime) {
        throw QlErrorNotImplemented("qnx clock_time: clock type " + std::to_string(id) + " not implemented");
    }
    // set time
    if (new_ptr != 0) {
        ql.log().warn("syscall_clock_time: set time not supported");
        return -1;
    }
    // get time
    if (old_ptr != 0) {
        ql.mem().write_ptr(old_ptr, time_ns(), 8);
    }

    return 0;
}

}  // namespace

void register_qnx_syscalls() {
    auto& registry = posix::SyscallRegistry::instance();

    registry.register_syscall({"channel_create", {PARAM_INTN}, syscall_channel_create});
    // clock_cycles: the special 0xFE000000 kercall id (the kercalls.h base)
    registry.register_syscall({"clock_cycles", {}, syscall_clock_cycles});
    registry.register_syscall({"clock_time", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_clock_time});
    registry.register_syscall({"sys_cpupage_get", {PARAM_INTN}, syscall_sys_cpupage_get});
    registry.register_syscall({"sys_cpupage_set", {PARAM_INTN, PARAM_INTN}, syscall_sys_cpupage_set});
    registry.register_syscall({"connect_attach",
                               {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_connect_attach});
    registry.register_syscall({"connect_detach", {PARAM_INTN}, syscall_connect_detach});
    registry.register_syscall({"connect_client_info", {PARAM_INTN, PARAM_PTRX, PARAM_INTN},
                               syscall_connect_client_info});
    registry.register_syscall({"connect_flags", {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_connect_flags});
    registry.register_syscall({"sync_create", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_sync_create});
    registry.register_syscall({"sync_mutex_lock", {PARAM_PTRX}, syscall_sync_mutex_lock});
    registry.register_syscall({"sync_mutex_unlock", {PARAM_PTRX}, syscall_sync_mutex_unlock});
    registry.register_syscall({"thread_destroy", {PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_thread_destroy});
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
