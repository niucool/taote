#include <cstdio>
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/posix/mman.hpp"
#include "qiling/os/posix/signal.hpp"
#include "qiling/os/posix/socket.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>

#include "qiling/os/posix/posix.hpp"
#include "qiling/os/posix/const_mapping.hpp"
#include "qiling/loader/loader.hpp"

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/posix/stat.hpp"
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

std::optional<std::int64_t> do_close(Qiling& ql, std::int64_t fd) {
    // unistd.py ql_syscall_close: close the backing object and clear the slot
    auto f = fd_get(ql, fd);
    if (f == nullptr) {
        return -9;
    }

    f->close();
    ql.os<posix::QlOsPosix>().fd().set(static_cast<int>(fd), nullptr);
    return 0;
}

namespace {

// posix/const.py: NR_OPEN and the errno spellings used below
constexpr int NR_OPEN = 1024;
constexpr std::int64_t kEBADF = 9;
constexpr std::int64_t kEIO = 5;
// posix/const.py: the *at-family dirfd/flag constants
constexpr std::int64_t kATFDCWD = -100;
constexpr std::uint64_t kATEMPTYPATH = 0x1000;
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

// stat.py __do_fstat + ql_syscall_fstat: the fd range check, the fd-table
// lookup, the fstat snapshot, the packing via the stat family (the
// get_stat_struct dispatch rides the os/arch); the OSError branch maps to
// -EIO verbatim, and the fstat == -1 branch writes nothing
std::optional<std::int64_t> syscall_fstat(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];

    // stat.py: "if fd not in range(NR_OPEN): return -EBADF"
    if (fd < 0 || fd >= QlFileDes::NR_OPEN) {
        return -kEBADF;
    }
    auto* f = fd_get(ql, fd).get();
    if (f == nullptr) {
        return -kEBADF;
    }

    try {
        const auto info = host_fstat_fd(f->fileno());
        if (info.size != static_cast<std::uint64_t>(-1)) {
            const auto data = pack_stat_struct(info, get_stat_layout(ql.os().type(), ql.arch().type()));
            ql.mem().write(buf, data);
        }
    } catch (const QlErrorBase&) {
        // the OSError branch verbatim
        return -kEIO;
    }
    return 0;
}

// stat.py statFamily: the cstring path, the transform to the host path, the
// host stat (Stat) or lstat (Lstat) — the OSError branch answers -errno —
// and the packing through the stat family (the struct_func choice: the
// plain stat rides pack_stat_struct, the lstat/stat64 ride the
// pack_stat64_struct family verbatim)
std::optional<std::int64_t> stat_family(Qiling& ql, std::uint64_t path_ptr, std::uint64_t buf,
                                        bool follow_symlinks, bool pack64) {
    const auto vpath = read_cstring(ql, path_ptr);
    // stat.py transform_to_real_path: the host resolution + the safety check
    // (the PermissionError branch propagates, the verbatim shape)
    const auto hpath = ql.os().path()->virtual_to_host_path(vpath);
    if (!ql.os().path()->is_safe_host_path(hpath)) {
        throw QlErrorBase("unsafe path: " + hpath);
    }

    QlFileStat info{};
    int host_errno = 0;
    if (!host_stat_path(hpath, follow_symlinks, info, &host_errno)) {
        // stat.py: "except OSError as e: return -e.errno"
        return -host_errno;
    }

    const auto& layout = pack64 ? get_stat64_layout(ql.os().type(), ql.arch().type())
                                : get_stat_layout(ql.os().type(), ql.arch().type());
    ql.mem().write(buf, pack_stat_struct(info, layout));
    return 0;
}

// int stat(const char *path, struct stat *buf); — stat.py ql_syscall_stat
std::optional<std::int64_t> syscall_stat(Qiling& ql, const std::vector<std::uint64_t>& params) {
    return stat_family(ql, params[0], params[1], /*follow_symlinks=*/true, /*pack64=*/false);
}

// int lstat(const char *path, struct stat64 *buf); — stat.py ql_syscall_lstat
// (the pack_stat64_struct choice is the verbatim quirk)
std::optional<std::int64_t> syscall_lstat(Qiling& ql, const std::vector<std::uint64_t>& params) {
    return stat_family(ql, params[0], params[1], /*follow_symlinks=*/false, /*pack64=*/true);
}

// stat.py transform_path: the dirfd/path/flags resolution — the absolute
// path joins the rootfs directly (the os.path.join verbatim), the AT_FDCWD
// relative path resolves through the path manager, the empty path with
// AT_EMPTY_PATH names the open fd, and the plain relative path rides the
// open directory fd (the host fstatat dirfd); the fall-through (the
// negative/unknown dirfd with a non-empty path) mirrors the upstream's
// implicit None return — the port throws so the emulation stops visibly
std::pair<int, std::string> transform_path(Qiling& ql, std::uint64_t dirfd_raw, std::uint64_t path_ptr,
                                           std::uint64_t flags) {
    // the unpack32s verbatim: the dirfd truncates to the 32-bit signed cell
    const auto dirfd = static_cast<int>(static_cast<std::int32_t>(dirfd_raw & 0xffffffffu));
    const auto path = read_cstring(ql, path_ptr);

    if (!path.empty() && path.front() == '/') {
        // os.path.join(ql.rootfs, path.lstrip('/'))
        return {-1, (std::filesystem::path(ql.rootfs()) / path.substr(1)).string()};
    }
    if (dirfd == kATFDCWD) {
        return {-1, ql.os().path()->virtual_to_host_path(path)};
    }
    if (path.empty() && (flags & kATEMPTYPATH) != 0) {
        auto* f = fd_get(ql, dirfd).get();
        if (f == nullptr) {
            // the upstream's fd[dirfd].name AttributeError → the emulation stop
            throw QlErrorBase("transform_path: the AT_EMPTY_PATH fd is not open");
        }
        return {-1, f->name()};
    }
    if (dirfd > 0 && dirfd < NR_OPEN) {
        auto* f = fd_get(ql, dirfd).get();
        if (f == nullptr) {
            throw QlErrorBase("transform_path: the dirfd is not open");
        }
        return {f->fileno(), path};
    }
    // the verbatim fall-through: transform_path returns None and the caller
    // crashes — the port stops the emulation instead
    throw QlErrorBase("transform_path: the dirfd/path pair fell through the ladder");
}

// stat.py ql_syscall_newfstatat / ql_syscall_fstatat64: the *at stat family —
// the transform, then the host statat; the pack choice: newfstatat rides
// pack_stat_struct, fstatat64 rides pack_stat64_struct. The
// AT_SYMLINK_NOFOLLOW flag is ignored verbatim (the upstream's os.stat
// always follows; only AT_EMPTY_PATH reaches the transform)
std::optional<std::int64_t> fstatat_family(Qiling& ql, std::uint64_t dirfd_raw, std::uint64_t path_ptr,
                                           std::uint64_t buf, std::uint64_t flags, bool pack64) {
    const auto [host_dirfd, host_path] = transform_path(ql, dirfd_raw, path_ptr, flags);

    QlFileStat info{};
    int host_errno = 0;
    if (!host_statat(host_path, host_dirfd, /*follow_symlinks=*/true, info, &host_errno)) {
        return -host_errno;
    }

    const auto& layout = pack64 ? get_stat64_layout(ql.os().type(), ql.arch().type())
                                : get_stat_layout(ql.os().type(), ql.arch().type());
    ql.mem().write(buf, pack_stat_struct(info, layout));
    return 0;
}

std::optional<std::int64_t> syscall_newfstatat(Qiling& ql, const std::vector<std::uint64_t>& params) {
    return fstatat_family(ql, params[0], params[1], params[2], params[3], /*pack64=*/false);
}

std::optional<std::int64_t> syscall_fstatat64(Qiling& ql, const std::vector<std::uint64_t>& params) {
    return fstatat_family(ql, params[0], params[1], params[2], params[3], /*pack64=*/true);
}

// stat.py ql_syscall_statx: the (dirfd, path, flags, mask, buf) ABI — the
// transform rides transform_path, the host stat follows (os.stat), the
// image rides the Statx tables with the float32-bit timestamps and the
// hardcoded STATX_BASIC_STATS mask; the catch-all Exception branch answers
// -1 verbatim (not -errno)
std::optional<std::int64_t> syscall_statx(Qiling& ql, const std::vector<std::uint64_t>& params) {
    try {
        const auto [host_dirfd, host_path] = transform_path(ql, params[0], params[1], params[3]);

        QlFileStat info{};
        int host_errno = 0;
        if (!host_statat(host_path, host_dirfd, /*follow_symlinks=*/true, info, &host_errno)) {
            // the OSError rides the catch-all below (the verbatim -1, NOT
            // -errno — the statx try wraps the Stat, unlike newfstatat's
            // -errno branch)
            throw QlErrorBase("statx: the host stat failed");
        }

        // the ts cells ride the float32 bit-pattern conversion (the verbatim
        // struct.pack('f', x) / unpack('i') round trip)
        const auto data = pack_stat_struct(info, get_statx_layout(ql.arch().bits()));
        ql.mem().write(params[4], data);
        return 0;
    } catch (const std::exception&) {
        // stat.py: "except Exception as e: regreturn = -1"
        return -1;
    }
}

// stat.py ql_syscall_statfs / ql_syscall_fstatfs: the verbatim stub — the
// buffer fills with 96 copies of the ASCII '0' (the b"0" * (12*8) quirk —
// 0x30 bytes, NOT NULs), the path/fd arguments are ignored entirely, and a
// failed write answers -1
std::optional<std::int64_t> syscall_statfs_family(Qiling& ql, const std::vector<std::uint64_t>& params) {
    try {
        ql.mem().write(params[1], std::vector<std::uint8_t>(12 * 8, '0'));
        return 0;
    } catch (...) {
        return -1;
    }
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
    // unistd.py ql_syscall_close
    return do_close(ql, static_cast<std::int64_t>(params[0]));
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

// ---- the directory-read surface (unistd.py: access/readlink/chdir/getcwd/
// getdents) ----

// unistd.py ql_syscall_access: the exists check over the safe host path
std::optional<std::int64_t> syscall_access(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto vpath = read_cstring(ql, params[0]);
    const auto hpath = ql.os().path()->virtual_to_host_path(vpath);

    if (!ql.os().path()->is_safe_host_path(hpath)) {
        throw QlErrorBase("unsafe path: " + hpath);
    }

    return std::filesystem::exists(hpath) ? 0 : -2;  // -ENOENT
}

// unistd.py ql_syscall_getcwd: the cwd bytes + the NUL; the length rides the
// return (the path_buffsize argument is ignored verbatim)
std::optional<std::int64_t> syscall_getcwd(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto cwd = ql.os().path()->cwd();
    std::vector<std::uint8_t> bytes(cwd.begin(), cwd.end());
    bytes.push_back(0);
    ql.mem().write(params[0], bytes);
    return static_cast<std::int64_t>(bytes.size());
}

// unistd.py ql_syscall_chdir: the safe host path must be a directory; the
// cwd lands as the virtual absolute path
std::optional<std::int64_t> syscall_chdir(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto vpath = read_cstring(ql, params[0]);
    const auto hpath = ql.os().path()->virtual_to_host_path(vpath);

    if (!ql.os().path()->is_safe_host_path(hpath)) {
        throw QlErrorBase("unsafe path: " + hpath);
    }

    const auto absvpath = ql.os().path()->virtual_abspath(vpath);

    std::error_code ec;
    if (std::filesystem::is_directory(hpath, ec)) {
        ql.os().path_mut()->set_cwd(absvpath);
        return 0;
    }
    return -2;  // -ENOENT
}

// unistd.py __do_readlink: the procfs pseudo files resolve first; the real
// paths answer "we do not really know how to emulated links" — an existing
// path reads as the empty target (the FIXME verbatim)
std::int64_t do_readlink(Qiling& ql, const std::string& absvpath, std::uint64_t outbuf) {
    std::optional<std::string> target;

    if (absvpath == "/proc/self/exe") {
        // raises when the binary is not under rootfs (the upstream note)
        target = ql.os().path()->host_to_virtual_path(ql.path());
    } else if (absvpath == "/proc/self/cwd") {
        target = ql.os().path()->cwd();
    } else if (absvpath == "/proc/self/root") {
        target = ql.os().path()->root();
    } else {
        const auto hpath = ql.os().path()->virtual_to_host_path(absvpath);
        if (!ql.os().path()->is_safe_host_path(hpath)) {
            throw QlErrorBase("unsafe path: " + hpath);
        }
        if (std::filesystem::exists(hpath)) {
            target = "";
        }
    }

    if (!target.has_value()) {
        return -2;  // -ENOENT
    }

    if (!target->empty()) {
        std::vector<std::uint8_t> bytes(target->begin(), target->end());
        bytes.push_back(0);
        ql.mem().write(outbuf, bytes);
    }
    return static_cast<std::int64_t>(target->size());
}

std::optional<std::int64_t> syscall_readlink(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto vpath = read_cstring(ql, params[0]);
    const auto absvpath = ql.os().path()->virtual_abspath(vpath);
    return do_readlink(ql, absvpath, params[1]);
}

// unistd.py virtual_abspath_at: the dirfd resolution — the absolute virtual
// paths survive as-is; AT_FDCWD rides the cwd; the real dirfds ride the
// opened fd's host name mapped back to virtual
std::optional<std::int64_t> syscall_readlinkat(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto vpath = read_cstring(ql, params[1]);

    std::string absvpath;
    if (ql.os().path()->is_virtual_abspath(vpath)) {
        absvpath = vpath;
    } else {
        // the as_signed walk (the 32-bit workaround verbatim)
        const auto dirfd = static_cast<std::int32_t>(params[0] & 0xffffffffu);
        if (dirfd == -100) {  // AT_FDCWD
            absvpath = ql.os().path()->virtual_abspath_from(ql.os().path()->cwd(), vpath);
        } else {
            auto* f = dynamic_cast<QlFile*>(fd_get(ql, dirfd).get());
            if (f == nullptr) {
                return -9;  // -EBADF
            }
            std::error_code ec;
            if (!std::filesystem::is_directory(f->name(), ec)) {
                return -20;  // -ENOTDIR
            }
            absvpath = ql.os().path()->virtual_abspath_from(ql.os().path()->host_to_virtual_path(f->name()), vpath);
        }
    }

    return do_readlink(ql, absvpath, params[2]);
}

// unistd.py __getdents_common: the buffer walk (the tell()==0 gate — the
// second call answers 0; the '.'/'..' chain first; the alignment math and
// the getdents/getdents64 layout split verbatim)
std::int64_t getdents_common(Qiling& ql, std::int64_t fd, std::uint64_t dirp, std::uint64_t count, bool is_64) {
    (void)count;

    auto* f = dynamic_cast<QlFile*>(fd_get(ql, fd).get());
    if (f == nullptr) {
        return -9;  // -EBADF
    }
    if (f->tell() != 0 || f->dir_scan_done()) {
        // the seek past the scan marks the end-of-file for the dir fd (the
        // _WIN32 dir FILE* cannot seek, so the scan-done flag rides along)
        return 0;
    }

    const auto n = is_64 ? 8 : ql.arch().pointersize();

    // the type map (the methods_constants_d verbatim)
    const auto type_of = [](const std::filesystem::directory_entry& ent) -> std::uint8_t {
        std::error_code ec;
        if (ent.is_directory(ec)) return 0x4;
        if (ent.is_regular_file(ec)) return 0x8;
        if (ent.is_symlink(ec)) return 0xa;
        if (ent.is_block_file(ec)) return 0x6;
        if (ent.is_character_file(ec)) return 0x2;
        if (ent.is_fifo(ec)) return 0x1;
        if (ent.is_socket(ec)) return 0xc;
        return 0x0;  // DT_UNKNOWN
    };

    const auto pack = [&](std::uint64_t v, std::uint32_t width) {
        std::vector<std::uint8_t> out(width, 0);
        for (std::uint32_t i = 0; i < width; ++i) {
            out[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
        }
        return out;
    };

    std::uint64_t p = dirp;
    std::int64_t total_size = 0;

    // emit one record at the running cursor: the fields write immediately
    // (the upstream walks the fields list the same way)

    // the '.'/'..' chain rides ahead of the scandir results (the itertools
    // chain verbatim; the inodes ride stat())
    std::vector<std::pair<std::string, std::uint64_t>> predefs;
    {
        const auto base = std::filesystem::path(f->name());
        for (const char* name : {".", ".."}) {
            QlFileStat info{};
            int host_errno = 0;
            host_stat_path(base / name, /*follow_symlinks=*/true, info, &host_errno);
            predefs.emplace_back(name, info.ino);
        }
    }

    auto emit = [&](const std::string& name, std::uint64_t d_ino, std::uint8_t d_type) {
        const std::string d_name = name + std::string(1, '\0');
        // the kernel rounds each record up to the d_ino alignment (the
        // ALIGN(reclen, sizeof(long)) comment verbatim)
        const std::uint64_t unaligned_reclen = n + n + 2 + d_name.size() + 1;
        const std::uint64_t d_reclen = (unaligned_reclen + (n - 1)) & ~(n - 1);

        // compose the whole record, then one write (the incremental-field
        // walk kept tripping on the mem-write re-entrancy)
        std::vector<std::uint8_t> rec;
        rec.reserve(static_cast<std::size_t>(d_reclen));
        const auto put = [&](const std::vector<std::uint8_t>& b) {
            rec.insert(rec.end(), b.begin(), b.end());
        };

        if (is_64) {
            // getdents64: the d_type rides BEFORE d_name, so the trailing
            // pad bytes are inert
            put(pack(d_ino, static_cast<std::uint32_t>(n)));
            put(pack(0, static_cast<std::uint32_t>(n)));  // d_off = 0
            put(pack(d_reclen, 2));
            put({d_type});
            put(std::vector<std::uint8_t>(d_name.begin(), d_name.end()));
            rec.resize(d_reclen, 0);
        } else {
            // legacy linux_dirent: the d_type rides the record's LAST byte,
            // so the alignment padding goes between d_name and d_type
            const std::uint64_t pad = d_reclen - unaligned_reclen;
            put(pack(d_ino, static_cast<std::uint32_t>(n)));
            put(pack(0, static_cast<std::uint32_t>(n)));
            put(pack(d_reclen, 2));
            put(std::vector<std::uint8_t>(d_name.begin(), d_name.end()));
            put(std::vector<std::uint8_t>(pad, 0));
            put({d_type});
        }

        ql.mem().write(p, rec);
        total_size += static_cast<std::int64_t>(d_reclen);
        p += d_reclen;
    };

    for (const auto& [name, ino] : predefs) {
        emit(name, ino, 0x4);  // the directories map DT_DIR
    }

    std::error_code scan_ec;
    std::filesystem::directory_iterator it(f->name(), scan_ec);
    if (!scan_ec) {
        for (const auto& ent : it) {
            QlFileStat info{};
            int host_errno = 0;
            host_stat_path(ent.path(), /*follow_symlinks=*/true, info, &host_errno);
            emit(ent.path().filename().string(), info.ino, type_of(ent));
        }
    }

    // mark as end of file for dir_fd (the verbatim seek)
    f->lseek(0, 2 /* SEEK_END */);
    f->set_dir_scan_done(true);

    return total_size;
}

std::optional<std::int64_t> syscall_getdents(Qiling& ql, const std::vector<std::uint64_t>& params) {
    return getdents_common(ql, static_cast<std::int64_t>(params[0]), params[1], params[2], /*is_64=*/false);
}

std::optional<std::int64_t> syscall_getdents64(Qiling& ql, const std::vector<std::uint64_t>& params) {
    return getdents_common(ql, static_cast<std::int64_t>(params[0]), params[1], params[2], /*is_64=*/true);
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
    // BISECT cycle 3 (b2): the parent's in-hook uc_context save removed for
    // the deletion bisect — restore together with the matching restore when
    // the study closes
    // const auto parent_ctx = ql.arch().save();

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

    // BISECT: the child ctx's pc as saved
    std::fprintf(stderr, "[clone] child_ctx_pc=%llx parent_after=%llx\n",
                 static_cast<unsigned long long>(after_syscall),
                 static_cast<unsigned long long>(after_syscall));

    // the parent's context back (sched.py: ql.restore(ctx))
    // BISECT cycle 3 (b2): the parent's in-hook uc_context restore removed
    // together with the matching save — restore when the study closes
    // ql.arch().restore(*parent_ctx);

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
    registry.register_syscall({"fstat", {PARAM_INTN, PARAM_PTRX}, syscall_fstat});
    // stat.py ql_syscall_stat / ql_syscall_lstat (+ the *64 variants — the
    // x86/ARM tables map those ids; the x8664 maps stat/lstat at 4/6)
    registry.register_syscall({"stat", {PARAM_PTRX, PARAM_PTRX}, syscall_stat});
    registry.register_syscall({"lstat", {PARAM_PTRX, PARAM_PTRX}, syscall_lstat});
    registry.register_syscall({"stat64", {PARAM_PTRX, PARAM_PTRX}, syscall_stat});
    registry.register_syscall({"lstat64", {PARAM_PTRX, PARAM_PTRX}, syscall_lstat});
    // the *at family (stat.py ql_syscall_newfstatat / ql_syscall_fstatat64 —
    // the (dirfd, path, buf, flags) ABI; newfstatat is the x8664 id 262,
    // fstatat64 rides the x86/arm tables)
    registry.register_syscall({"newfstatat", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_INTN}, syscall_newfstatat});
    registry.register_syscall({"fstatat64", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_INTN}, syscall_fstatat64});
    // stat.py ql_syscall_statx — the (dirfd, path, flags, mask, buf) ABI
    registry.register_syscall({"statx", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_PTRX}, syscall_statx});
    // stat.py ql_syscall_statfs / ql_syscall_fstatfs — the verbatim stub
    registry.register_syscall({"statfs", {PARAM_PTRX, PARAM_PTRX}, syscall_statfs_family});
    registry.register_syscall({"fstatfs", {PARAM_INTN, PARAM_PTRX}, syscall_statfs_family});
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
    // the directory-read surface (unistd.py: access/readlink/readlinkat/
    // chdir/getcwd/getdents/getdents64)
    registry.register_syscall({"access", {PARAM_PTRX, PARAM_INTN}, syscall_access});
    registry.register_syscall({"getcwd", {PARAM_PTRX, PARAM_INTN}, syscall_getcwd});
    registry.register_syscall({"chdir", {PARAM_PTRX}, syscall_chdir});
    registry.register_syscall({"readlink", {PARAM_PTRX, PARAM_PTRX, PARAM_INTN}, syscall_readlink});
    registry.register_syscall({"readlinkat", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_INTN}, syscall_readlinkat});
    registry.register_syscall({"getdents", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_getdents});
    registry.register_syscall({"getdents64", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_getdents64});
    // mman.py: the mmap family (the shared impl; the x86 tables map
    // old_mmap at 90 / mmap2 at 192, the x8664 maps mmap at 9)
    registry.register_syscall({"mmap", {PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_mmap});
    registry.register_syscall({"mmap2", {PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_mmap2});
    registry.register_syscall({"old_mmap", {PARAM_PTRX}, syscall_old_mmap});
    registry.register_syscall({"munmap", {PARAM_PTRX, PARAM_INTN}, syscall_munmap});
    registry.register_syscall({"mprotect", {PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_mprotect});
    registry.register_syscall({"madvise", {PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_madvise});
    // signal.py: the sigaction family (the signal syscall rides the verbatim
    // 0 stub; the sigset width rides the native type)
    registry.register_syscall({"rt_sigaction", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_rt_sigaction});
    registry.register_syscall({"rt_sigprocmask", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_rt_sigprocmask});
    registry.register_syscall({"signal", {PARAM_INTN, PARAM_PTRX}, syscall_signal});
    // socket.py: the socket/shutdown core (the connect/bind/listen/accept
    // and the send/recv families land with their sub-slices)
    registry.register_syscall({"socket", {PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_socket});
    registry.register_syscall({"shutdown", {PARAM_INTN, PARAM_INTN}, syscall_shutdown});
    // the connect/bind/listen/accept family (the sockaddr parse rides the
    // SockaddrView walk; the unix paths ride the rootfs transform)
    registry.register_syscall({"connect", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_connect});
    registry.register_syscall({"bind", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_bind});
    registry.register_syscall({"listen", {PARAM_INTN, PARAM_INTN}, syscall_listen});
    registry.register_syscall({"accept", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_accept});
    // the send/recv family (the recv/send/sendto/recvfrom quartet)
    registry.register_syscall({"recv", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_recv});
    registry.register_syscall({"send", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_send});
    // the sendto/recvfrom quartet: the STREAM sockets and the NULL addr
    // ride the send/recv bodies verbatim
    registry.register_syscall({"sendto", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_sendto});
    registry.register_syscall({"recvfrom", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_recvfrom});
    // the socketpair ride (the AF_UNIX pairs; the loopback accept walk on
    // the _WIN32 host)
    registry.register_syscall({"socketpair", {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_PTRX}, syscall_socketpair});

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
