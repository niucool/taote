// Ported from qiling/os/macos/syscall.py — the macos-specific handlers.
// The first slice: the mach self-trap family (mach_reply_port 0x1a,
// thread_self_trap 0x1b, task_self_trap 0x1c, host_self_trap 0x1d) + the
// simple stubs (csops, getentropy). The message-trap family (mach_msg_trap
// 0x1f) rides the mach_msg/subsystems ports.
#include "qiling/os/macos/syscall.hpp"

#include <cstdio>
#include <cstring>

#include "qiling/core.hpp"
#include "qiling/os/macos/const.hpp"
#include "qiling/os/macos/macos.hpp"
#include "qiling/os/macos/mach_msg.hpp"
#include "qiling/os/macos/kernel_func.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

// syscall.py ql_syscall_mach_reply_port: the reply port rides the seeded
// MachPort (the upstream's MachPort(2187) from loader/macho.py)
std::optional<std::int64_t> syscall_mach_reply_port(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_mach_port().name);
}

// syscall.py ql_syscall_thread_self_trap: the thread's port name
std::optional<std::int64_t> syscall_thread_self_trap(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(get_thread_port(os_macos.macho_thread()));
}

// syscall.py ql_syscall_task_self_trap: the task id
std::optional<std::int64_t> syscall_task_self_trap(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_task().id);
}

// syscall.py ql_syscall_host_self_trap: the host port name
std::optional<std::int64_t> syscall_host_self_trap(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_port_manager().host_port.name);
}

// syscall.py ql_syscall_csops: the (CS_ENFORCEMENT | CS_GET_TASK_ALLOW)
// flag into the caller's 4-byte cell, KERN_SUCCESS
std::optional<std::int64_t> syscall_csops(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto useraddr = params[2];
    const std::uint32_t flag = CS_ENFORCEMENT | CS_GET_TASK_ALLOW;
    const std::array<std::uint8_t, 4> bytes = {
        static_cast<std::uint8_t>(flag), static_cast<std::uint8_t>(flag >> 8),
        static_cast<std::uint8_t>(flag >> 16), static_cast<std::uint8_t>(flag >> 24)};
    ql.mem().write(useraddr, std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_getentropy: the no-op stub returning KERN_SUCCESS
// (the buffer stays untouched, verbatim)
std::optional<std::int64_t> syscall_getentropy(Qiling&, const std::vector<std::uint64_t>&) {
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_kernelrpc_mach_vm_allocate_trap: the bump allocator
// off the task's min_offset — the region maps, zeroes, advances the cursor
// and writes the allocated address into the caller's *addr cell
std::optional<std::int64_t> syscall_kernelrpc_mach_vm_allocate_trap(Qiling& ql,
                                                                    const std::vector<std::uint64_t>& params) {
    const auto addr = params[1];
    const auto size = params[2];

    auto& os_macos = dynamic_cast<QlOsMacos&>(ql.os());
    const auto mmap_address = os_macos.macho_task().min_offset;
    const auto mmap_end = page_align_end(mmap_address + size, PAGE_SIZE);

    ql.mem().map(mmap_address, mmap_end - mmap_address, UC_PROT_ALL, "[mach-vm-alloc]");
    ql.mem().write(mmap_address, std::vector<std::uint8_t>(mmap_end - mmap_address, 0));
    os_macos.macho_task_mut().min_offset = mmap_end;
    ql.mem().write(addr, {static_cast<std::uint8_t>(mmap_address), static_cast<std::uint8_t>(mmap_address >> 8),
                          static_cast<std::uint8_t>(mmap_address >> 16), static_cast<std::uint8_t>(mmap_address >> 24),
                          static_cast<std::uint8_t>(mmap_address >> 32), static_cast<std::uint8_t>(mmap_address >> 40),
                          static_cast<std::uint8_t>(mmap_address >> 48), static_cast<std::uint8_t>(mmap_address >> 56)});
    return 0;
}

// syscall.py ql_syscall_kernelrpc_mach_vm_deallocate_trap: the no-op stub
// returning KERN_SUCCESS
std::optional<std::int64_t> syscall_kernelrpc_mach_vm_deallocate_trap(Qiling&, const std::vector<std::uint64_t>&) {
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_kernelrpc_mach_vm_map_trap: the vmmap cursor walk
// (the mask alignment verbatim) + the page-aligned map + the *addr write
std::optional<std::int64_t> syscall_kernelrpc_mach_vm_map_trap(Qiling& ql,
                                                               const std::vector<std::uint64_t>& params) {
    const auto address = params[1];
    const auto size = params[2];
    const auto mask = params[3];

    auto& os_macos = dynamic_cast<QlOsMacos&>(ql.os());
    auto vmmap_end = os_macos.macho_vmmap_end();
    if ((vmmap_end & mask) > 0) {
        vmmap_end -= vmmap_end & mask;
        vmmap_end += mask + 1;
    }

    const auto vmmap_address = page_align_end(vmmap_end, PAGE_SIZE);
    const auto vmmap_end_page = page_align_end(vmmap_address + size, PAGE_SIZE);

    os_macos.set_macho_vmmap_end(vmmap_end_page);
    ql.mem().map(vmmap_address, vmmap_end_page - vmmap_address, UC_PROT_ALL, "[mach-vm-map]");
    ql.mem().write(address, {static_cast<std::uint8_t>(vmmap_address), static_cast<std::uint8_t>(vmmap_address >> 8),
                             static_cast<std::uint8_t>(vmmap_address >> 16), static_cast<std::uint8_t>(vmmap_address >> 24),
                             static_cast<std::uint8_t>(vmmap_address >> 32), static_cast<std::uint8_t>(vmmap_address >> 40),
                             static_cast<std::uint8_t>(vmmap_address >> 48), static_cast<std::uint8_t>(vmmap_address >> 56)});
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_kernelrpc_mach_port_deallocate_trap: the log-only
// no-op (no return)
std::optional<std::int64_t> syscall_kernelrpc_mach_port_deallocate_trap(Qiling&, const std::vector<std::uint64_t>&) {
    return std::nullopt;
}

// syscall.py ql_syscall_kernelrpc_mach_port_mod_refs_trap: the `pass` stub
std::optional<std::int64_t> syscall_kernelrpc_mach_port_mod_refs_trap(Qiling&, const std::vector<std::uint64_t>&) {
    return std::nullopt;
}

// syscall.py ql_syscall_kernelrpc_mach_port_construct_trap: the `pass` stub
std::optional<std::int64_t> syscall_kernelrpc_mach_port_construct_trap(Qiling&, const std::vector<std::uint64_t>&) {
    return std::nullopt;
}

// macos/utils.py set_eflags_cf: the CF bit (bit 0) set to the target
std::uint64_t set_eflags_cf(Qiling& ql, std::uint64_t target_cf) {
    const auto flags = ql.arch().regs().read("eflags") & 0xfffffffe;
    const auto out = flags | target_cf;
    ql.arch().regs().write("eflags", out);
    return out;
}

// syscall.py ql_syscall_sysctl / sysctlbyname: the KERN_SUCCESS stubs (the
// x8664 table carries sysctl=202 only; the sysctlbyname entry is arm64-only
// in the upstream table)
std::optional<std::int64_t> syscall_sysctl(Qiling&, const std::vector<std::uint64_t>&) {
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_poll: the KERN_SUCCESS stub
std::optional<std::int64_t> syscall_poll(Qiling&, const std::vector<std::uint64_t>&) {
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_shared_region_check_np: the "not ready every time"
// stub — the raw EINVAL (22)
std::optional<std::int64_t> syscall_shared_region_check_np(Qiling&, const std::vector<std::uint64_t>&) {
    return EINVAL;
}

// syscall.py ql_syscall_proc_info: the PROC_INFO_CALL_PIDINFO +
// PROC_PIDREGIONPATHINFO path writes the "/usr/lib/dyld" path at buff+248
// (the kernel_func.py ProcRegionWithPathInfo.write_info verbatim); the
// other shapes fall through with no return
std::optional<std::int64_t> syscall_proc_info(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto callnum = params[0];
    const auto buff = params[4];

    if (callnum == PROC_INFO_CALL_PIDINFO) {
        const auto flavor = params[2];
        if (flavor == PROC_PIDREGIONPATHINFO) {
            const std::string path = "/usr/lib/dyld";
            std::vector<std::uint8_t> bytes(path.begin(), path.end());
            ql.mem().write(buff + 248, bytes);
        }
    }
    return std::nullopt;
}

// syscall.py ql_syscall_csrctl: the stub returning 1
std::optional<std::int64_t> syscall_csrctl(Qiling&, const std::vector<std::uint64_t>&) {
    return 1;
}

// syscall.py ql_syscall_terminate_with_payload: the emu stops and
// KERN_SUCCESS rides rax (the upstream calls emu_stop then returns)
std::optional<std::int64_t> syscall_terminate_with_payload(Qiling& ql, const std::vector<std::uint64_t>&) {
    ql.emu_stop();
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_abort_with_payload: the KERN_SUCCESS stub (no stop)
std::optional<std::int64_t> syscall_abort_with_payload(Qiling&, const std::vector<std::uint64_t>&) {
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_write_nocancel: the write through the fd table; the
// verbatim quirk: the body computes regreturn but the final statement is
// `return 0` — the write lands and the caller always sees 0
std::optional<std::int64_t> syscall_write_nocancel(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];
    const auto count = params[2];

    try {
        const auto data = ql.mem().read(buf, count);
        auto* f = ql.os<posix::QlOsPosix>().fd().at(static_cast<int>(fd)).get();
        if (f != nullptr) {
            f->write(data);
        }
    } catch (...) {
        // the upstream's bare except (the raise rides the DEBUG verbosity)
    }
    return 0;
}

// syscall.py ql_syscall_open_nocancel: the open machinery (the port
// delegates to the posix open entry — the path transform matches the
// upstream's transform_to_relative_path + fs_mapper shape)
std::optional<std::int64_t> syscall_open_nocancel(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto* open_entry = posix::SyscallRegistry::instance().find("open");
    if (open_entry == nullptr) {
        throw QlErrorBase("open_nocancel: the posix open delegate is missing");
    }
    return static_cast<std::int64_t>(open_entry->handler(ql, params).value_or(
        static_cast<std::uint64_t>(-1)));
}

// syscall.py ql_syscall_bsdthread_register: the CF clears and the fixed
// pthread magic rides rax (the upstream's 0x00000000400000df verbatim)
std::optional<std::int64_t> syscall_bsdthread_register(Qiling& ql, const std::vector<std::uint64_t>&) {
    set_eflags_cf(ql, 0x0);
    return 0x00000000400000df;
}

// syscall.py ql_syscall_thread_selfid: the seeded macho thread's id
std::optional<std::int64_t> syscall_thread_selfid(Qiling& ql, const std::vector<std::uint64_t>&) {
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    return static_cast<std::int64_t>(os_macos.macho_thread().id);
}

// syscall.py ql_syscall_thread_fast_set_cthread_self64: the mdep shim — the
// tsd base into IA32_GS_BASE_MSR (x86_const.py), KERN_SUCCESS
std::optional<std::int64_t> syscall_thread_fast_set_cthread_self64(Qiling& ql,
                                                                   const std::vector<std::uint64_t>& params) {
    const auto u_info_addr = params[0];
    dynamic_cast<QlArchIntel&>(ql.arch()).msr().write(IA32_GS_BASE_MSR, u_info_addr);
    return KERN_SUCCESS;
}


// syscall.py ql_syscall_access_macos: the ENOENT/KERN_SUCCESS over the fs
// isexists (the raw errno value rides rax — the macos handlers return the
// numbers directly, unlike the posix negative-errno convention)
std::optional<std::int64_t> syscall_access_macos(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto path = params[0];
    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    const auto path_str = QlOsUtils::read_cstring(ql, path);
    if (!os_macos.macho_fs().isexists(path_str)) {
        return ENOENT;
    }
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_sigprocmask: the log-only no-op (no return — the
// upstream body ends without returning, so rax stays untouched)
std::optional<std::int64_t> syscall_sigprocmask(Qiling&, const std::vector<std::uint64_t>&) {
    return std::nullopt;
}

// syscall.py ql_syscall_fcntl64_macos: the fixed cmd table (GETFL/GETFD
// answer 2, SETFL/SETFD 0, ADDFILESIGS_RETURN writes the 0xefffffff blob)
std::optional<std::int64_t> syscall_fcntl64_macos(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto cmd = static_cast<std::uint32_t>(params[1]);
    const auto arg = params[2];

    std::int64_t regreturn = 0;
    if (cmd == F_GETFL) {
        regreturn = 2;
    } else if (cmd == F_SETFL) {
        regreturn = 0;
    } else if (cmd == F_GETFD) {
        regreturn = 2;
    } else if (cmd == F_SETFD) {
        regreturn = 0;
    } else if (cmd == F_ADDFILESIGS_RETURN) {
        const std::array<std::uint8_t, 4> blob = {0xff, 0xff, 0xff, 0xef};  // pack32(0xefffffff)
        ql.mem().write(arg, std::vector<std::uint8_t>(blob.begin(), blob.end()));
        regreturn = 0;
    }
    return regreturn;
}

// syscall.py ql_syscall_pread: seek + read through the fd table, the data
// into buf, the CF cleared, nbyte returned
std::optional<std::int64_t> syscall_pread(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto fd = static_cast<std::int64_t>(params[0]);
    const auto buf = params[1];
    const auto nbyte = static_cast<std::size_t>(params[2]);
    const auto offset = params[3];

    if (fd >= 0 && fd <= MAX_FD_SIZE) {
        auto f = ql.os<posix::QlOsPosix>().fd().at(static_cast<int>(fd));
        if (f != nullptr) {
            f->lseek(offset, SEEK_SET);
            const auto data = f->read(nbyte);
            ql.mem().write(buf, data);
        }
    }
    set_eflags_cf(ql, 0x0);
    return static_cast<std::int64_t>(nbyte);
}

// syscall.py ql_syscall_getattrlist: the 24-byte attrlist unpack + the
// commonattr walk + the length-prefixed write into the caller's buffer
std::optional<std::int64_t> syscall_getattrlist(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto path = params[0];
    const auto alist = params[1];
    const auto attribute_buffer = params[2];
    const auto buffer_size = params[3];

    auto u16 = [&](std::uint64_t at) {
        const auto b = ql.mem().read(at, 2);
        return static_cast<std::uint32_t>(b[0]) | static_cast<std::uint32_t>(b[1]) << 8;
    };
    auto u32 = [&](std::uint64_t at) {
        const auto b = ql.mem().read(at, 4);
        return static_cast<std::uint32_t>(b[0]) | static_cast<std::uint32_t>(b[1]) << 8 |
               static_cast<std::uint32_t>(b[2]) << 16 | static_cast<std::uint32_t>(b[3]) << 24;
    };
    const auto commonattr = u32(alist + 4);

    const auto& os_macos = dynamic_cast<const QlOsMacos&>(ql.os());
    const auto path_str = QlOsUtils::read_cstring(ql, path);

    std::vector<std::uint8_t> attr;
    if (commonattr != 0) {
        attr = os_macos.macho_fs().get_common_attr(path_str, commonattr);
        if (attr.empty()) {
            // the upstream raises QlErrorSyscallError("Error File Not Exist")
            throw QlErrorSyscallError("Error File Not Exist " + path_str);
        }
    }

    const auto attr_len = static_cast<std::uint32_t>(attr.size() + 4);
    std::vector<std::uint8_t> packed;
    packed.reserve(4 + attr.size());
    for (int i = 0; i < 4; ++i) {
        packed.push_back(static_cast<std::uint8_t>(attr_len >> (8 * i)));
    }
    packed.insert(packed.end(), attr.begin(), attr.end());

    if (packed.size() > buffer_size) {
        return 1;
    }
    ql.mem().write(attribute_buffer, packed);
    set_eflags_cf(ql, 0x0);
    return KERN_SUCCESS;
}

// syscall.py ql_syscall_getrlimit: the rlp writes (the upstream writes both
// cells AT rlp — the second overwrites the first, verbatim) and NO return
// in the success path (rax untouched; the EINVAL range check rides the
// upstream's odd `which & _RLIMIT_POSIX_FLAG` masking verbatim)
std::optional<std::int64_t> syscall_getrlimit(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto rlp = params[1];
    const auto which = static_cast<std::uint32_t>(params[0]) & 0x1000;  // _RLIMIT_POSIX_FLAG
    if (which >= 9) {  // RLIM_NLIMITS
        return EINVAL;
    }
    ql.mem().write(rlp, std::vector<std::uint8_t>{0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});  // rlim_cur
    ql.mem().write(rlp, std::vector<std::uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F});  // rlim_max
    return std::nullopt;
}

// syscall.py ql_syscall_mach_msg_trap(ql, args, opt, ssize, rsize, rname,
// timeout): read the message at args with ssize, then the port-manager
// dispatch (the reply overwrites the request buffer in place). NOTE: the
// upstream parses NO MACH_SEND/MACH_RCV flags — the opt argument is only
// logged; every trap rides the id dispatch verbatim
std::optional<std::int64_t> syscall_mach_msg_trap(Qiling& ql, const std::vector<std::uint64_t>& params) {
    const auto args = params[0];
    const auto ssize = params[2];
    auto& os_macos = dynamic_cast<QlOsMacos&>(ql.os());
    MachMsg mach_msg;
    mach_msg.read_msg_from_mem(ql, args, ssize);
    os_macos.deal_with_msg(mach_msg, args);
    return KERN_SUCCESS;
}

}  // namespace

void register_macos_syscalls() {
    auto& registry = posix::SyscallRegistry::instance();
    registry.register_syscall({"mach_reply_port", {}, syscall_mach_reply_port});
    registry.register_syscall({"thread_self_trap", {}, syscall_thread_self_trap});
    registry.register_syscall({"task_self_trap", {}, syscall_task_self_trap});
    registry.register_syscall({"host_self_trap", {}, syscall_host_self_trap});
    registry.register_syscall({"mach_msg_trap",
                               {PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN,
                                PARAM_INTN},
                               syscall_mach_msg_trap});
    registry.register_syscall({"csops", {PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_csops});
    registry.register_syscall({"getentropy", {PARAM_PTRX, PARAM_INTN}, syscall_getentropy});
    registry.register_syscall({"access_macos", {PARAM_PTRX, PARAM_INTN}, syscall_access_macos});
    registry.register_syscall({"sigprocmask", {PARAM_INTN, PARAM_PTRX, PARAM_PTRX}, syscall_sigprocmask});
    registry.register_syscall({"fcntl64_macos", {PARAM_INTN, PARAM_INTN, PARAM_INTN}, syscall_fcntl64_macos});
    registry.register_syscall({"pread", {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_pread});
    registry.register_syscall({"getattrlist", {PARAM_PTRX, PARAM_PTRX, PARAM_PTRX, PARAM_INTN, PARAM_INTN},
                               syscall_getattrlist});
    registry.register_syscall({"getrlimit", {PARAM_INTN, PARAM_PTRX}, syscall_getrlimit});
    registry.register_syscall({"kernelrpc_mach_vm_allocate_trap",
                               {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN},
                               syscall_kernelrpc_mach_vm_allocate_trap});
    registry.register_syscall({"kernelrpc_mach_vm_deallocate_trap",
                               {PARAM_INTN, PARAM_PTRX, PARAM_INTN},
                               syscall_kernelrpc_mach_vm_deallocate_trap});
    registry.register_syscall({"kernelrpc_mach_vm_map_trap",
                               {PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_kernelrpc_mach_vm_map_trap});
    registry.register_syscall({"kernelrpc_mach_port_deallocate_trap", {}, syscall_kernelrpc_mach_port_deallocate_trap});
    registry.register_syscall({"kernelrpc_mach_port_mod_refs_trap",
                               {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN},
                               syscall_kernelrpc_mach_port_mod_refs_trap});
    registry.register_syscall({"bsdthread_register",
                               {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN},
                               syscall_bsdthread_register});
    registry.register_syscall({"thread_selfid", {}, syscall_thread_selfid});
    registry.register_syscall({"thread_fast_set_cthread_self64", {PARAM_PTRX}, syscall_thread_fast_set_cthread_self64});
    registry.register_syscall({"sysctl", {PARAM_PTRX, PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_PTRX, PARAM_INTN},
                               syscall_sysctl});
    registry.register_syscall({"poll", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_poll});
    registry.register_syscall({"shared_region_check_np", {PARAM_PTRX, PARAM_PTRX}, syscall_shared_region_check_np});
    registry.register_syscall({"proc_info",
                               {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_INTN},
                               syscall_proc_info});
    registry.register_syscall({"csrctl", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_csrctl});
    registry.register_syscall({"terminate_with_payload",
                               {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_INTN, PARAM_PTRX},
                               syscall_terminate_with_payload});
    registry.register_syscall({"abort_with_payload",
                               {PARAM_INTN, PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_PTRX, PARAM_INTN},
                               syscall_abort_with_payload});
    registry.register_syscall({"write_nocancel", {PARAM_INTN, PARAM_PTRX, PARAM_INTN}, syscall_write_nocancel});
    registry.register_syscall({"open_nocancel", {PARAM_PTRX, PARAM_INTN, PARAM_INTN}, syscall_open_nocancel});
    registry.register_syscall({"kernelrpc_mach_port_construct_trap",
                               {PARAM_INTN, PARAM_INTN, PARAM_PTRX, PARAM_PTRX},
                               syscall_kernelrpc_mach_port_construct_trap});
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
