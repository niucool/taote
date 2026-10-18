#include "qiling/os/posix/syscall.hpp"

#include <algorithm>

#include "qiling/os/posix/posix.hpp"
#include "qiling/os/posix/const_mapping.hpp"
#include "qiling/loader/loader.hpp"

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/linux/thread.hpp"
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

// the fd-table lookup over the posix os layer (the unistd.py os.fd[fd] shape;
// nullptr when out of range or empty) — shared with the delegating dialects
// (the qnx message.py imports the posix syscall helpers verbatim)
std::shared_ptr<QlFsMappedObject> fd_get(Qiling& ql, std::int64_t fd) {
    if (fd < 0 || fd >= posix::QlFileDes::NR_OPEN) {
        return nullptr;
    }
    return ql.os<posix::QlOsPosix>().fd().at(static_cast<int>(fd));
}

namespace {

// posix/const.py: NR_OPEN and the errno spellings used below
constexpr int NR_OPEN = 1024;
constexpr std::int64_t kEBADF = 9;
constexpr std::int64_t kEFAULT = 14;
constexpr std::int64_t kEMFILE = 24;
constexpr std::int64_t kENOENT = 2;
constexpr std::int64_t kEISDIR = 21;
constexpr std::int64_t kEEXIST = 17;
constexpr std::int64_t kEACCES = 13;
constexpr std::int64_t kEINVAL = 22;

// QlFile objects in the posix os layer)
bool fd_in_range(std::int64_t fd) {
    return fd >= 0 && fd < NR_OPEN;
}

// empty)
std::string read_cstring(Qiling& ql, std::uint64_t addr);

std::optional<std::int64_t> syscall_exit(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_exit: the child-process and the multithread
    // branches; the plain path stops
    const auto code = static_cast<int>(params.empty() ? 0 : params[0]);

    if (ql.os().thread_management() != nullptr) {
        // the multithread branch (_sched_cb_exit): terminate the current
        // thread through the scheduler; the main thread's stop ends the world
        auto* td = ql.os().thread_management()->cur_thread();
        ql.emu_stop();
        if (td != nullptr) {
            td->set_sched_cb([&ql, td, code] {
                ql.os().thread_management()->stop_thread(td);
                td->set_exit_code(code);
            });
        }
        return std::nullopt;
    }

    ql.os().set_exit_code(code);
    ql.os().stop();
    return std::nullopt;
}

std::optional<std::int64_t> syscall_exit_group(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // the multithread branch shares the _sched_cb_exit shape (unistd.py
    // ql_syscall_exit_group); the plain path falls through to the exit
    return syscall_exit(ql, params);
}

std::optional<std::int64_t> syscall_write(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_write: the fd-table lookup; the std streams (the
    // fd[0..2] PersistentQlFiles) and the opened files share the path
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];
    const auto count = params[2];

    auto* f = fd_get(ql, fd).get();
    if (f == nullptr) {
        return -kEBADF;
    }
    if (!ql.mem().is_mapped(buf, count)) {
        return -kEFAULT;
    }

    const auto data = ql.mem().read(buf, count);
    return static_cast<std::int64_t>(f->write(data));
}

std::optional<std::int64_t> syscall_read(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];
    const auto count = params[2];

    auto* f = fd_get(ql, fd).get();
    if (f == nullptr) {
        return -kEBADF;
    }
    if (!ql.mem().is_mapped(buf, count)) {
        return -kEFAULT;
    }

    const auto data = f->read(count);
    ql.mem().write(buf, data);
    return static_cast<std::int64_t>(data.size());
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

// ---- fcntl.py __do_open: the next free fd slot + the mapped open ----

std::optional<std::int64_t> do_open(Qiling& ql, const std::string& absvpath, int flags, int mode) {
    (void)mode;  // the mode value passes through to the fs layer

    // look for the next available fd slot (fcntl.py, verbatim)
    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    int idx = -1;
    for (int i = 0; i < static_cast<int>(fd_table.size()); ++i) {
        if (fd_table.at(i) == nullptr) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        return -kEMFILE;
    }

    // translate the emulated open flags into the host flags (const_mapping.py)
    const auto mapped = ql_open_flag_mapping(ql.arch().type(), flags);

    try {
        auto* fs = ql.os<posix::QlOsPosix>().fs_mapper();
        if (fs == nullptr) {
            throw QlErrorBase("no fs mapper");
        }
        auto file = fs->open_ql_file(absvpath, mapped, mode);
        fd_table.set(idx, std::move(file));
    } catch (const QlErrorFileNotFound&) {
        return -kENOENT;
    } catch (const QlErrorFileExists&) {
        return -kEEXIST;
    } catch (const QlErrorIsADirectory&) {
        return -kEISDIR;
    } catch (const QlErrorAccessDenied&) {
        return -kEACCES;
    } catch (const QlErrorBase&) {
        // fcntl.py: the unclassified os errors collapse onto ENOENT
        return -kENOENT;
    }

    return idx;
}

std::optional<std::int64_t> syscall_open(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // fcntl.py ql_syscall_open: the virtual path, the flag mapping, the open
    const auto filename = params[0];
    const auto flags = static_cast<int>(params[1]);
    const auto mode = static_cast<int>(params[2]);

    const auto vpath = read_cstring(ql, filename);
    return do_open(ql, vpath, flags, mode);
}

std::optional<std::int64_t> syscall_creat(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // fcntl.py ql_syscall_creat: O_WRONLY | O_CREAT | O_TRUNC
    const auto filename = params[0];
    const auto mode = static_cast<int>(params[1]);

    const auto vpath = read_cstring(ql, filename);
    const int flags = LinuxX86OpenFlags::O_WRONLY | LinuxX86OpenFlags::O_CREAT | LinuxX86OpenFlags::O_TRUNC;
    return do_open(ql, vpath, flags, mode);
}

std::optional<std::int64_t> syscall_close(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_close: close the backing object and clear the slot
    const auto fd = static_cast<std::int64_t>(params[0]);

    auto f = fd_get(ql, fd);
    if (f == nullptr) {
        return -kEBADF;
    }

    f->close();
    ql.os<posix::QlOsPosix>().fd().set(static_cast<int>(fd), nullptr);
    return 0;
}

std::optional<std::int64_t> syscall_lseek(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_lseek: the 32-bit signed offset
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto offset = static_cast<std::int64_t>(static_cast<std::int32_t>(params[1]));
    const auto origin = static_cast<int>(params[2]);

    auto* f = fd_get(ql, fd).get();
    if (f == nullptr) {
        return -kEBADF;
    }

    return static_cast<std::int64_t>(f->lseek(static_cast<std::uint64_t>(offset), origin));
}

std::optional<std::int64_t> syscall__llseek(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall__llseek: the high/low offset composition + the
    // result write
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto off_hi = params[1];
    const auto off_lo = params[2];
    const auto result = params[3];
    const auto whence = static_cast<int>(params[4]);

    auto* f = fd_get(ql, fd).get();
    if (f == nullptr) {
        return -kEBADF;
    }

    const auto offset = static_cast<std::int64_t>((off_hi << 32) | (off_lo & 0xFFFFFFFFu));
    try {
        const auto ret = f->lseek(static_cast<std::uint64_t>(offset), whence);
        ql.mem().write_ptr(result, static_cast<std::int64_t>(ret), 8);
    } catch (const QlErrorBase&) {
        return -1;
    }
    return 0;
}

std::optional<std::int64_t> syscall_dup(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_dup: the first free slot for the duplicated object
    const auto oldfd = static_cast<std::int64_t>(params[0]);

    auto f = fd_get(ql, oldfd);
    if (f == nullptr) {
        return -kEBADF;
    }

    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    for (int i = 0; i < static_cast<int>(fd_table.size()); ++i) {
        if (fd_table.at(i) == nullptr) {
            fd_table.set(i, f->dup());
            return i;
        }
    }
    return -kEMFILE;
}

std::optional<std::int64_t> syscall_dup2(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_dup2: the specific target slot (the occupied
    // target closes silently)
    const auto oldfd = static_cast<std::int64_t>(params[0]);
    const auto newfd = static_cast<std::int64_t>(params[1]);

    auto f = fd_get(ql, oldfd);
    if (f == nullptr) {
        return -kEBADF;
    }
    if (!fd_in_range(newfd)) {
        return -kEBADF;
    }

    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    fd_table.set(static_cast<int>(newfd), f->dup());
    return newfd;
}

std::optional<std::int64_t> syscall_dup3(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_dup3: the target slot with the flags (the EINVAL
    // self-dup guard, the O_CLOEXEC propagation)
    const auto oldfd = static_cast<std::int64_t>(params[0]);
    const auto newfd = static_cast<std::int64_t>(params[1]);
    const auto flags = static_cast<int>(params[2]);

    constexpr int O_CLOEXEC = 02000000;
    if (oldfd == newfd) {
        return -kEINVAL;
    }

    auto f = fd_get(ql, oldfd);
    if (f == nullptr) {
        return -kEBADF;
    }
    if (!fd_in_range(newfd)) {
        return -kEBADF;
    }

    auto newf = f->dup();
    if ((flags & O_CLOEXEC) != 0) {
        newf->close_on_exec = true;
    }

    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    fd_table.set(static_cast<int>(newfd), std::move(newf));
    return newfd;
}

std::optional<std::int64_t> syscall_pipe(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py ql_syscall_pipe: the host-pipe pair into the fd table; the
    // result fds land in the guest buffer (the MIPS v1 quirk lands with its
    // arch slice)
    const auto pipefd = params[0];

    auto rd_wd = QlPipe::open();

    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    int idx1 = -1, idx2 = -1;
    for (int i = 0; i < NR_OPEN; ++i) {
        if (fd_table.at(i) == nullptr) {
            if (idx1 == -1) {
                idx1 = i;
            } else {
                idx2 = i;
                break;
            }
        }
    }
    if (idx1 == -1 || idx2 == -1) {
        return -kEMFILE;
    }

    fd_table.set(idx1, std::move(rd_wd.first));
    fd_table.set(idx2, std::move(rd_wd.second));

    ql.mem().write_ptr(pipefd + 0, idx1, 4);
    ql.mem().write_ptr(pipefd + 4, idx2, 4);
    return 0;
}

std::optional<std::int64_t> syscall_pipe2(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // unistd.py registers pipe2 through the same body (the flags handling
    // unistd pipe body is shared verbatim)
    (void)params;
    return syscall_pipe(ql, params);
}

std::optional<std::int64_t> syscall_fcntl(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // fcntl.py ql_syscall_fcntl: F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto cmd = static_cast<int>(params[1]);
    const auto arg = static_cast<int>(params[2]);

    constexpr int F_DUPFD = 0;
    constexpr int F_GETFD = 1;
    constexpr int F_SETFD = 2;
    constexpr int F_GETFL = 3;
    constexpr int F_SETFL = 4;
    constexpr int FD_CLOEXEC = 1;

    auto f = fd_get(ql, fd);
    if (f == nullptr) {
        return -kEBADF;
    }

    switch (cmd) {
        case F_DUPFD: {
            if (!fd_in_range(arg)) {
                return -kEINVAL;
            }
            auto& fd_table = ql.os<posix::QlOsPosix>().fd();
            for (int idx = static_cast<int>(arg); idx < NR_OPEN; ++idx) {
                if (fd_table.at(idx) == nullptr) {
                    fd_table.set(idx, f->dup());
                    return idx;
                }
            }
            return -kEMFILE;
        }
        case F_GETFD:
            return f->close_on_exec ? 1 : 0;
        case F_SETFD:
            f->close_on_exec = (arg & FD_CLOEXEC) != 0;
            return 0;
        case F_GETFL:
            return f->fcntl(cmd, arg);
        case F_SETFL: {
            const auto mapped = ql_open_flag_mapping(ql.arch().type(), arg);
            f->fcntl(cmd, mapped);
            return 0;
        }
        default:
            return -kEINVAL;
    }
}

std::optional<std::int64_t> syscall_fcntl64(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // fcntl.py ql_syscall_fcntl64: the degraded x86-32 form (the out-of-range
    // fd returns -1, F_GETFL/F_GETFD return 2, everything else 0)
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto cmd = static_cast<int>(params[1]);
    const auto arg = static_cast<int>(params[2]);

    constexpr int F_DUPFD = 0;
    if (!fd_in_range(fd)) {
        return -1;
    }
    auto f = fd_get(ql, fd);
    if (f == nullptr) {
        return -1;
    }

    if (cmd == F_DUPFD) {
        if (!fd_in_range(arg)) {
            return -1;
        }
        auto& fd_table = ql.os<posix::QlOsPosix>().fd();
        for (int idx = static_cast<int>(arg); idx < NR_OPEN; ++idx) {
            if (fd_table.at(idx) == nullptr) {
                fd_table.set(idx, f->dup());
                return idx;
            }
        }
        return -1;
    }
    if (cmd == 3) {   // F_GETFL
        return 2;
    }
    if (cmd == 4) {   // F_SETFL
        return 0;
    }
    if (cmd == 1) {   // F_GETFD
        return 2;
    }
    if (cmd == 2) {   // F_SETFD
        return 0;
    }
    return 0;
}

std::optional<std::int64_t> syscall_flock(Qiling&, const std::vector<std::uint64_t>&) {
    // fcntl.py ql_syscall_flock: should always return 0 (the comment, verbatim)
    return 0;
}

// ---- the futex dispatch (os/posix/syscall/futex.py) ----

// futex.py ql_syscall_futex: the FUTEX_* op constants (the PRIVATE_FLAG
// masks out of the op comparison, verbatim)
std::optional<std::int64_t> syscall_futex(Qiling& ql, const std::vector<std::uint64_t>& params) {
    constexpr int FUTEX_WAIT = 0;
    constexpr int FUTEX_WAKE = 1;
    constexpr int FUTEX_WAIT_BITSET = 9;
    constexpr int FUTEX_WAKE_BITSET = 10;
    constexpr int FUTEX_PRIVATE_FLAG = 128;

    const auto uaddr = params[0];
    const auto op_raw = static_cast<int>(params[1]);
    const auto val = static_cast<std::uint32_t>(params[2]);
    const auto val3 = params.size() > 5 ? static_cast<std::uint32_t>(params[5]) : 0xffffffffu;
    const auto op = op_raw & (FUTEX_PRIVATE_FLAG - 1);

    std::fflush(stderr);
    auto* futexm = ql.os().futexm();
    auto* tm = ql.os().thread_management();
    if (futexm == nullptr || tm == nullptr || tm->cur_thread() == nullptr) {
        return 0;
    }
    auto* cur = tm->cur_thread();

    if (op == FUTEX_WAIT) {
        return futexm->futex_wait(ql, uaddr, *cur, val);
    }
    if (op == FUTEX_WAIT_BITSET) {
        return futexm->futex_wait(ql, uaddr, *cur, val, val3);
    }
    if (op == FUTEX_WAKE) {
        return futexm->futex_wake(ql, uaddr, *cur, static_cast<int>(val));
    }
    if (op == FUTEX_WAKE_BITSET) {
        return futexm->futex_wake(ql, uaddr, *cur, static_cast<int>(val), val3);
    }

    // the unhandled op: the debug + the emu stop (futex.py, verbatim shape)
    ql.emu_stop();
    return 0;
}

// futex.py ql_syscall_set_robust_list: the current thread's robust-list
// bookkeeping
std::optional<std::int64_t> syscall_set_robust_list(Qiling& ql, const std::vector<std::uint64_t>& params) {
    auto* tm = ql.os().thread_management();
    if (tm != nullptr && tm->cur_thread() != nullptr) {
        tm->cur_thread()->set_robust_list(params[0], params[1]);
    }
    return 0;
}

// sched.py ql_syscall_sched_yield: the emu stop plus the yield callback (the
// gevent sleep(0) analogue: the driver loop reschedules the thread)
std::optional<std::int64_t> syscall_sched_yield(Qiling& ql, const std::vector<std::uint64_t>&) {
    auto* tm = ql.os().thread_management();
    if (tm != nullptr && tm->cur_thread() != nullptr) {
        ql.emu_stop();
        // the default sched_cb: give up control (thread.py _default_sched_cb)
        tm->cur_thread()->set_sched_cb([] {});
    }
    return 0;
}

// ---- the clone dispatch (os/posix/syscall/sched.py) ----

std::optional<std::int64_t> syscall_clone(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // sched.py ql_syscall_clone: the flag constants (verbatim)
    constexpr std::uint64_t CLONE_VM = 0x00000100;
    constexpr std::uint64_t CLONE_CHILD_SETTID = 0x01000000;
    constexpr std::uint64_t CLONE_CHILD_CLEARTID = 0x00200000;

    const auto flags = params[0];
    const auto child_stack = params[1];
    const auto parent_tidptr = params[2];
    // the raw 4th/5th params; the x86-64 swap below relabels them (the
    // python's newtls/child_tidptr swap - the raw clone order is flags,
    // stack, ptid, ctid, tls)
    auto newtls = params[4];
    auto child_tidptr = params[3];

    // Shared virtual memory (sched.py, verbatim branch shape)
    if ((flags & CLONE_VM) == 0) {
        // sched.py: the fork path - the windows branch constructs a
        // multiprocessing.Process object without ever starting it and runs
        // the child code in the caller's greenlet (a broken placeholder); the
        // port surfaces the fork as not-implemented (the documented deviation)
        throw QlErrorNotImplemented(
            "clone without CLONE_VM (fork emulation) is not supported on this host");
    }

    auto* tm = ql.os().thread_management();
    if (tm == nullptr || tm->cur_thread() == nullptr) {
        // the python would AttributeError on the missing management
        return -kEINVAL;
    }

    std::uint64_t set_child_tid_addr = 0;
    if ((flags & CLONE_CHILD_SETTID) != 0) {
        set_child_tid_addr = child_tidptr;
    }

    // the child's start: the instruction after the syscall (the x86-64
    // syscall insn = 2 bytes, the upstream's +2)
    const std::uint64_t after_syscall = ql.arch().regs().arch_pc() + 2;

    auto th = os::linux::QlLinuxThread::spawn(&ql, after_syscall,
                                          ql.os().exit_point(), nullptr, set_child_tid_addr);
    const auto th_id = static_cast<std::int64_t>(th->get_id());

    if ((flags & 0x00100000) != 0 && parent_tidptr != 0) {
        // CLONE_PARENT_SETTID: the parent's tid pointer write
        ql.mem().write_ptr(parent_tidptr, th_id, 4);
    }

    // the parent's context snapshot; the pc advances past the clone syscall
    // so the parent's resume continues after it (the unicorn's INSN-hook pc
    // still points at the syscall)
    ql.arch().regs().set_arch_pc(after_syscall);
    const auto parent_ctx = ql.arch().save();

    // the new tls (sched.py: CLONE_SETTLS)
    if ((flags & 0x00080000) != 0) {
        th->set_thread_tls(newtls);
    }

    if ((flags & CLONE_CHILD_CLEARTID) != 0) {
        th->set_clear_child_tid_address(child_tidptr);
    }

    // the child's context: the pc past the clone syscall, the child's stack
    // and the child's return value 0 (the child resumes after the syscall)
    ql.arch().regs().set_arch_pc(after_syscall);
    ql.arch().regs().set_arch_sp(child_stack);
    ql.os<posix::QlOsPosix>().syscall_abi_mut().set_return_value(0);
    th->save();

    // the parent's context back (sched.py: ql.restore(ctx))
    ql.arch().restore(*parent_ctx);

    // the pinned TB semantics (the TbSemantics probe): the unicorn post-hook
    // advance adds the hooked instruction's size onto the live pc, even when
    // the hook stopped the emu or set the pc itself. The in-hook restore
    // leaves the live pc at after_syscall, so the advance would land the
    // parent's slice-end pc at after_syscall + 2 (mid-instruction). The
    // pre-advance compensation makes the post-advance land on after_syscall.
    ql.arch().regs().set_arch_pc(after_syscall - 2);

    // register the thread + break the parent's slice (the add-thread event
    // lands through the management; the upstream sets the dead stop_event
    // fields nothing consumes)
    tm->add_thread(std::move(th));
    ql.emu_stop();

    return th_id;
}

std::optional<std::int64_t> syscall_clone3(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // sched.py ql_syscall_clone3: the clone_args struct (all __aligned_u64)
    //   0:flags 8:pidfd 16:child_tid 24:parent_tid 32:exit_signal
    //   40:stack 48:stack_size 56:tls
    const auto cl_args = params[0];

    const auto flags = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 0, 8));
    const auto child_tid = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 16, 8));
    const auto parent_tid = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 24, 8));
    const auto exit_signal = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 32, 8));
    const auto stack = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 40, 8));
    const auto stack_size = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 48, 8));
    const auto tls = static_cast<std::uint64_t>(ql.mem().read_ptr(cl_args + 56, 8));

    // the legacy clone takes the highest stack address; clone3 gives the
    // base + size (the upstream translation, verbatim)
    const std::uint64_t child_stack = stack != 0 ? stack + stack_size : 0;

    // clone3 keeps the exit signal in its own field; the legacy clone packs
    // it into the low CSIGNAL byte of the flags
    const auto merged_flags = flags | (exit_signal & 0xff);

    // clone3 hands the already-logical args; on the x86-64 the pre-swap
    // cancels the clone's newtls/child_tidptr swap (the upstream shape)
    if (ql.arch().type() == QL_ARCH::X8664) {
        // the clone reads (flags, stack, parent_tid, the 4th, the 5th) and
        // swaps the 4th/5th; feed the logical values in the swapped order
        const std::vector<std::uint64_t> args{merged_flags, child_stack, parent_tid, tls, child_tid};
        return syscall_clone(ql, args);
    }
    const std::vector<std::uint64_t> args{merged_flags, child_stack, parent_tid, child_tid, tls};
    return syscall_clone(ql, args);
}

// unistd.py read_cstring (os/utils.py read_cstring): the char-stepped NUL
// scan (the log_string record lands with the string-slice)
std::string read_cstring(Qiling& ql, std::uint64_t addr) {
    std::string out;
    for (std::uint64_t cur = addr;; ++cur) {
        const auto ch = ql.mem().read(cur, 1);
        if (ch.empty() || ch[0] == 0) {
            break;
        }
        out.push_back(static_cast<char>(ch[0]));
    }
    return out;
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

    // the fd-table set (fcntl.py + unistd.py)
    registry.register_syscall({"open", {PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_open});
    registry.register_syscall({"openat", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_open});
    registry.register_syscall({"creat", {PARAM_PTRX, PARAM_INTN}, syscall_creat});
    registry.register_syscall({"lseek", {PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_lseek});
    registry.register_syscall({"_llseek", {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall__llseek});
    registry.register_syscall({"dup", {PARAM_INTN}, syscall_dup});
    registry.register_syscall({"dup2", {PARAM_INTN, PARAM_INTN}, syscall_dup2});
    registry.register_syscall({"dup3", {PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_dup3});
    registry.register_syscall({"pipe", {PARAM_PTRX}, syscall_pipe});
    registry.register_syscall({"pipe2", {PARAM_PTRX, PARAM_INTN}, syscall_pipe2});
    registry.register_syscall({"fcntl", {PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_fcntl});
    registry.register_syscall({"fcntl64", {PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_fcntl64});
    registry.register_syscall({"flock", {PARAM_INTN, PARAM_INTN}, syscall_flock});

    // the futex dispatch (os/posix/syscall/futex.py) + the yield (sched.py)
    registry.register_syscall({"futex", {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_futex});
    registry.register_syscall({"set_robust_list", {PARAM_INTN, PARAM_INTN}, syscall_set_robust_list});
    registry.register_syscall({"sched_yield", {}, syscall_sched_yield});

    // the clone dispatch (os/posix/syscall/sched.py) + clone3
    registry.register_syscall({"clone", {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_clone});
    registry.register_syscall({"clone3", {PARAM_PTRX, PARAM_INTN}, syscall_clone3});
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
