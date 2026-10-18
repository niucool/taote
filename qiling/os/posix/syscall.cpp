#include "qiling/os/posix/syscall.hpp"

#include <algorithm>

#include "qiling/os/posix/posix.hpp"
#include "qiling/loader/loader.hpp"

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/memory.hpp"

namespace qiling {
namespace os {
namespace posix {

SyscallRegistry& SyscallRegistry::instance() {
    static SyscallRegistry registry;
    return registry;
}

void SyscallRegistry::register_syscall(SyscallEntry entry) {
    entries_[entry.name] = std::move(entry);
}

const SyscallEntry* SyscallRegistry::find(const std::string& name) const {
    const auto it = entries_.find(name);
    return it == entries_.end() ? nullptr : &it->second;
}

std::vector<std::string> SyscallRegistry::names() const {
    std::vector<std::string> out;
    out.reserve(entries_.size());
    for (const auto& [name, _] : entries_) {
        out.push_back(name);
    }
    return out;
}

void SyscallRegistry::clear() {
    entries_.clear();
}

// ---- the built-in unistd syscalls (os/posix/syscall/unistd.py) ----

namespace {

// posix/const.py: NR_OPEN and the errno spellings used below
constexpr int NR_OPEN = 1024;
constexpr std::int64_t kEBADF = 9;
constexpr std::int64_t kEFAULT = 14;

// unistd.py get_opened_fd — the fd bounds check only (the fd table wires the
// QlFile objects in the posix os layer)
bool fd_in_range(std::int64_t fd) {
    return fd >= 0 && fd < NR_OPEN;
}

std::optional<std::int64_t> syscall_exit(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_exit: child_process/_exit and the multithread
    // scheduling branches land with their slices; the plain path stops
    const auto code = static_cast<int>(params.empty() ? 0 : params[0]);
    ql.os().set_exit_code(code);
    ql.os().stop();
    return std::nullopt;
}

std::optional<std::int64_t> syscall_exit_group(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_exit_group: unimplemented without multithreading —
    // falls through to the plain exit semantics
    return syscall_exit(ql, params);
}

std::optional<std::int64_t> syscall_write(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_write: EBADF when the fd has no backing file; the
    // stdin/stdout/stderr handles route through the os streams
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];
    const auto count = params[2];

    if (!fd_in_range(fd)) {
        return -kEBADF;
    }
    if (!ql.mem().is_mapped(buf, count)) {
        return -kEFAULT;
    }

    const auto data = ql.mem().read(buf, count);

    switch (fd) {
        case 1:
            ql.os().stdout_stream().write(data);
            return static_cast<std::int64_t>(data.size());
        case 2:
            ql.os().stderr_stream().write(data);
            return static_cast<std::int64_t>(data.size());
        default:
            // the open-file fd table lands with the file-based syscall slice
            return -kEBADF;
    }
}

std::optional<std::int64_t> syscall_read(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];
    const auto count = params[2];

    if (!fd_in_range(fd)) {
        return -kEBADF;
    }
    if (!ql.mem().is_mapped(buf, count)) {
        return -kEFAULT;
    }

    if (fd == 0) {
        const auto data = ql.os().stdin_stream().read(count);
        ql.mem().write(buf, data);
        return static_cast<std::int64_t>(data.size());
    }

    return -kEBADF;
}

std::optional<std::int64_t> syscall_uname(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_uname: a fixed utsname buffer
    const auto buf = params[0];

    // the field width is 65 bytes per arch word size (utsname.nodename etc.)
    const std::string sysname = "Linux";
    const std::string nodename = "localhost";
    const std::string release = "5.4.0";
    const std::string version = "#1 SMP Qiling";
    const std::string machine = ql.arch().bits() == 64 ? "x86_64" : "i686";

    const auto field = std::max<std::uint64_t>(65, 0);
    const auto put = [&](std::uint64_t off, std::string_view text) {
        std::vector<std::uint8_t> raw(field, 0);
        std::copy(text.begin(), text.end(), raw.begin());
        ql.mem().write(buf + off, raw);
    };

    put(0 * field, sysname);
    put(1 * field, nodename);
    put(2 * field, release);
    put(3 * field, version);
    put(4 * field, machine);
    (void)field;

    return 0;
}

// ---- the unistd identity/credential set (unistd.py) ----

// unistd.py __getuid/__setuid and friends: the profile identity, the setters
// mutate it (the TODO: security checks comment, verbatim)
std::optional<std::int64_t> syscall_getuid(Qiling& ql, const std::vector<std::uint64_t>&) {
    return ql.os<posix::QlOsPosix>().uid();
}

std::optional<std::int64_t> syscall_setuid(Qiling& ql, const std::vector<std::uint64_t>& params) {
    ql.os<posix::QlOsPosix>().set_uid(static_cast<int>(params[0]));
    return 0;
}

std::optional<std::int64_t> syscall_getgid(Qiling& ql, const std::vector<std::uint64_t>&) {
    return ql.os<posix::QlOsPosix>().gid();
}

std::optional<std::int64_t> syscall_setgid(Qiling& ql, const std::vector<std::uint64_t>& params) {
    ql.os<posix::QlOsPosix>().set_gid(static_cast<int>(params[0]));
    return 0;
}

// unistd.py: the zero-return stubs (seteuid/setgroups/setresuid/setresgid/
// capget/capset/alarm/nice/issetugid)
std::optional<std::int64_t> syscall_return_zero(Qiling&, const std::vector<std::uint64_t>&) {
    return 0;
}

// unistd.py: the fixed identity constants (getpid = 0x512, getppid = 0x1024,
// verbatim)
std::optional<std::int64_t> syscall_getpid(Qiling&, const std::vector<std::uint64_t>&) {
    return 0x512;
}

std::optional<std::int64_t> syscall_getppid(Qiling&, const std::vector<std::uint64_t>&) {
    return 0x1024;
}

std::optional<std::int64_t> syscall_brk(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_brk: grow/shrink the program break around the
    // loader's brk; the plain path returns the current break
    const auto inp = params.empty() ? 0 : params[0];
    auto& loader = ql.loader();

    if (inp != 0) {
        const auto cur_brk = loader.brk_address;
        const auto new_brk = ql.mem().align_up(inp);

        if (new_brk > cur_brk) {
            ql.mem().map(cur_brk, new_brk - cur_brk, UC_PROT_ALL, "[brk]");
        } else if (new_brk < cur_brk) {
            ql.mem().unmap(new_brk, cur_brk - new_brk);
        }

        loader.brk_address = new_brk;
    }

    return static_cast<std::int64_t>(loader.brk_address);
}

std::optional<std::int64_t> syscall_close(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_close: the fd-table lookup (the fd[0..2] std
    // streams close through the os streams; the opened-file entries land
    // with the file-descriptor slice)
    const auto fd = static_cast<std::int64_t>(params[0]);

    if (!fd_in_range(fd)) {
        return -kEBADF;
    }
    if (fd >= 3) {
        return -kEBADF;  // no backing entry in this slice
    }

    switch (fd) {
        case 0: ql.os().stdin_stream().close(); break;
        case 1: ql.os().stdout_stream().close(); break;
        case 2: ql.os().stderr_stream().close(); break;
        default: break;
    }
    return 0;
}

}  // namespace

void register_builtin_syscalls() {
    auto& registry = SyscallRegistry::instance();

    // the unistd set used by the smoke fixtures; the remaining modules port
    // with their slices (PORT_PLAN.md Phase 5)
    registry.register_syscall({"exit", {PARAM_INTN}, syscall_exit});
    registry.register_syscall({"exit_group", {PARAM_INTN}, syscall_exit_group});
    registry.register_syscall({"read", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_read});
    registry.register_syscall({"write", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_write});
    registry.register_syscall({"uname", {PARAM_PTRX}, syscall_uname});

    // the unistd identity/credential set (unistd.py)
    registry.register_syscall({"getuid", {}, syscall_getuid});
    registry.register_syscall({"setuid", {PARAM_INTN}, syscall_setuid});
    registry.register_syscall({"getuid32", {}, syscall_getuid});
    registry.register_syscall({"setuid32", {PARAM_INTN}, syscall_setuid});
    registry.register_syscall({"getgid", {}, syscall_getgid});
    registry.register_syscall({"setgid", {PARAM_INTN}, syscall_setgid});
    registry.register_syscall({"getgid32", {}, syscall_getgid});
    registry.register_syscall({"setgid32", {PARAM_INTN}, syscall_setgid});
    registry.register_syscall({"geteuid", {}, syscall_getuid});      // unistd.py: ql.os.euid
    registry.register_syscall({"seteuid", {}, syscall_return_zero});
    registry.register_syscall({"getegid", {}, syscall_getgid});      // unistd.py: ql.os.egid
    registry.register_syscall({"issetugid", {}, syscall_return_zero});
    registry.register_syscall({"setgroups", {PARAM_INTN, PARAM_PTRX}, syscall_return_zero});
    registry.register_syscall({"setresuid", {}, syscall_return_zero});
    registry.register_syscall({"setresgid", {}, syscall_return_zero});
    registry.register_syscall({"capget", {PARAM_PTRX, PARAM_PTRX}, syscall_return_zero});
    registry.register_syscall({"capset", {PARAM_PTRX, PARAM_PTRX}, syscall_return_zero});
    registry.register_syscall({"getpid", {}, syscall_getpid});
    registry.register_syscall({"getppid", {}, syscall_getppid});
    registry.register_syscall({"alarm", {PARAM_INTN}, syscall_return_zero});
    registry.register_syscall({"nice", {PARAM_INTN}, syscall_return_zero});
    registry.register_syscall({"setsid", {}, syscall_getpid});       // unistd.py: os.getpid()
    registry.register_syscall({"kill", {PARAM_INTN, PARAM_INTN}, syscall_return_zero});  // the sig dispatch lands with the signal slice
    registry.register_syscall({"set_tid_address", {PARAM_PTRX}, syscall_getpid});
    registry.register_syscall({"brk", {PARAM_INTN}, syscall_brk});
    registry.register_syscall({"close", {PARAM_INTN}, syscall_close});
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
