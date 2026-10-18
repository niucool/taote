// Ported from qiling/os/macos/macos.py — the macos dialect. The load() sets
// up the GDT/segments (the x86_utils.py GDTManager + SegmentManager64 shape,
// ported compactly — the same shape as the freebsd dialect per the upstream's
// per-dialect repetition) and installs the syscall entry hook.
#include "qiling/os/macos/macos.hpp"

#include <array>

#include "qiling/core.hpp"
#include "qiling/os/macos/map_syscall.hpp"
#include "qiling/os/macos/syscall.hpp"
#include "qiling/os/macos/kernel_func.hpp"
#include "qiling/os/macos/kernel_api.hpp"
#include "qiling/loader/macho.hpp"

#include "qiling/cc/intel.hpp"
#include "qiling/os/fcall.hpp"
#include <unicorn/x86.h>

namespace qiling {
namespace os {
namespace macos {

namespace {

// x86_const.py: the GDT constants + the access/flag/selector bits (the same
// shape as the freebsd dialect — the upstream repeats it per os.py dialect)
constexpr std::uint64_t kGdtAddr = 0x30000;
constexpr std::uint64_t kGdtLimit = 0x1000;

constexpr std::uint8_t kADataW = 1 << 1;
constexpr std::uint8_t kACode = 1 << 3;
constexpr std::uint8_t kADescData = 1 << 4;
constexpr std::uint8_t kADescCode = 1 << 4;
constexpr std::uint8_t kAPriv3 = 0b11 << 5;
constexpr std::uint8_t kAPresent = 1 << 7;

constexpr std::uint8_t kFLong = 1 << 1;
constexpr std::uint8_t kFGranularity = 1 << 3;

// x86_utils.py GDTManager: the entry encoder (the base 8+24 bits, the limit
// 4+16 bits, the access byte, the 4 flag bits)
std::array<std::uint8_t, 8> make_gdt_entry(std::uint64_t base, std::uint32_t limit, std::uint8_t access,
                                           std::uint8_t flags) {
    const auto base_hi = (base >> 24) & 0xff;
    const auto base_lo = base & 0xffffff;
    const auto limit_hi = (limit >> 16) & 0xf;
    const auto limit_lo = limit & 0xffff;

    const std::uint64_t entry = static_cast<std::uint64_t>(base_hi) << 56 | static_cast<std::uint64_t>(flags) << 52 |
                                static_cast<std::uint64_t>(limit_hi) << 48 |
                                static_cast<std::uint64_t>(access) << 40 | static_cast<std::uint64_t>(base_lo) << 16 |
                                limit_lo;
    std::array<std::uint8_t, 8> out{};
    for (int i = 0; i < 8; ++i) {
        out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((entry >> (8 * i)) & 0xff);
    }
    return out;
}

// x86_utils.py GDTManager.make_selector: the index << 3 | the TI=GDT | the rpl
std::uint16_t make_selector(std::uint16_t idx, std::uint8_t rpl) {
    return static_cast<std::uint16_t>((idx << 3) | rpl);
}

}  // namespace

QlOsMacos::QlOsMacos(Qiling* ql) : QlOsPosix(ql) {
    // macos.py __init__: the macosx64 convention for the fcall layer (the
    // first 6 args in regs, the same regs as the posix amd64 — the distinct
    // class keeps the upstream's explicit intent)
    set_fcall(std::make_unique<QlFunctionCall>(std::make_unique<cc::macosx64>(ql->arch())));

    // loader/macho.py seeds the mach surfaces on the QlOs (the MachPort(2187)
    // + the manager + the task + the thread); the port seeds them here until
    // the Mach-O loader slice lands (the deviation note in mach_port.hpp)
    macho_mach_port_ = std::make_unique<MachPort>(MachPort{2187});
    macho_port_manager_ = std::make_unique<MachPortManager>();
    macho_port_manager_->my_port = *macho_mach_port_;  // the upstream's
    // MachPortManager(ql, my_port) — the my_port is NOT the host_port (the
    // host_port stays the fixed 0x303)
    macho_task_ = std::make_unique<MachoTask>();
    macho_thread_ = std::make_unique<MachoThread>();
    macho_fs_ = std::make_unique<FileSystem>(*ql);
    // the MIG servers (the upstream seeds them in loader/macho.py run();
    // the port seeds here with the same deviation note as the mach surfaces)
    macho_host_server_ = std::make_unique<MachHostServer>(*ql);
    macho_task_server_ = std::make_unique<MachTaskServer>(*ql);

    // macos.py __init__: self.ev_manager = QlMacOSEvManager(self.ql);
    // self.policy_manager = QlMacOSPolicy(self.ql, self.ev_manager). The
    // current_proc = ql.argv[0] seed rides the fixture (the port's Qiling
    // carries no argv member — set_proc fills it)
    ev_manager_ = std::make_unique<QlEvManager>(*ql);
    policy_manager_ = std::make_unique<QlOsPolicy>(*ql, *ev_manager_);

    register_macos_syscalls();
    load();
}

void QlOsMacos::load() {
    // macos.py load (the X8664 branch; the ARM64 branch rides the arm64
    // slice — the upstream's enable_vfp + the intno-2/7 hooks):
    // the GDT/segment setup + the syscall entry hook
    auto& arch = ql().arch();
    auto& mem = ql().mem();

    // x86_utils.py GDTManager: map the GDT region and publish it via GDTR
    if (!mem.is_available(kGdtAddr, kGdtLimit)) {
        throw QlErrorBase("cannot map GDT, memory location is taken");
    }
    mem.map(kGdtAddr, kGdtLimit, UC_PROT_ALL, "[GDT]");

    uc_x86_mmr gdtr{};
    gdtr.base = kGdtAddr;
    gdtr.limit = static_cast<std::uint16_t>(kGdtLimit - 1);
    uc_reg_write(&arch.uc(), UC_X86_REG_GDTR, &gdtr);

    // SegmentManager64.setup_cs_ds_ss_es(base=0, size=4 << 30): the cs rides
    // the sixth GDT slot (the code access + the long bit), the ss the fifth
    // (the data access + the granularity); the ds/es stay unset (the upstream
    // commented them out, verbatim)
    constexpr std::uint32_t kSegSize = 4 << 30;
    const auto cs_access =
        static_cast<std::uint8_t>(kAPresent | kAPriv3 | kADescCode | kACode | (1 << 1) /* CODE_R */);
    const auto cs_sel = make_selector(6, static_cast<std::uint8_t>((cs_access >> 5) & 0b11));
    {
        const auto entry = make_gdt_entry(0, kSegSize - 1, cs_access, kFLong);
        mem.write(kGdtAddr + 6 * 8, std::vector<std::uint8_t>(entry.begin(), entry.end()));
    }
    arch.regs().write("cs", cs_sel);

    const auto ds_access =
        static_cast<std::uint8_t>(kAPresent | kAPriv3 | kADescData | kADataW | (0 << 2) /* the direction unset */);
    const auto ss_sel = make_selector(5, static_cast<std::uint8_t>((ds_access >> 5) & 0b11));
    {
        const auto entry = make_gdt_entry(0, kSegSize - 1, ds_access, kFGranularity);
        mem.write(kGdtAddr + 5 * 8, std::vector<std::uint8_t>(entry.begin(), entry.end()));
    }
    arch.regs().write("ss", ss_sel);

    // the syscall entry hook (macos.py: ql.hook_insn(hook_syscall, SYSCALL);
    // hook_syscall = load_syscall)
    install_syscall_hooks();

    // macos.py load does not install the kernel-api hook here — the
    // loader/macho.py run() does (self.ql.hook_code(hook_kernel_api) on the
    // driver path). The port installs it here (the shellcode fixtures ride
    // run(); the deviation note: the upstream hooks on the kext path only)
    enable_kernel_api_hooks();
}

void QlOsMacos::hook_kernel_api(std::uint64_t address, std::uint32_t size) {
    (void)size;

    // hook.py hook_kernel_api: the stub-address dispatch rides the loader's
    // import_symbols (the QlLoaderMachO symbol walk)
    const auto* loader_macho = dynamic_cast<const loader::macho::QlLoaderMachO*>(&ql().loader());
    if (loader_macho == nullptr) {
        return;
    }
    const auto* imported = loader_macho->import_symbols_at(address);
    if (imported == nullptr) {
        return;
    }
    // the macho C symbols carry the leading underscore (the upstream's
    // getattr rides hook_<name> with the raw symbol — the port's registry
    // keys are the unprefixed names, so one underscore strips here)
    std::string api_name = imported->name;
    if (!api_name.empty() && api_name[0] == '_') {
        api_name.erase(0, 1);
    }

    // the user override runs raw with (ql, address, api_name) — no param
    // resolution (hook.py, verbatim)
    if (const auto* user = find_user_api(api_name)) {
        (*user)(ql(), address, api_name);
        return;
    }

    const auto* entry = KernelApiRegistry::instance().find(api_name);
    if (entry == nullptr) {
        // hook.py: a warning; the debug_stop surfaces QlErrorSyscallNotFound
        if (ql().debug_stop()) {
            throw QlErrorSyscallNotFound("MacOS kernel API implementation not found: " + api_name);
        }
        return;
    }

    // the @macos_kernel_api wrapper body (fncc.py): the os.call with the
    // passthru + the onenter/onexit user hooks; the placeholder-typed params
    // resolve through the resolvers table
    const auto* entry_ptr = entry;
    auto* self_ql = &ql();
    const auto func = [entry_ptr, self_ql](std::uint64_t pc,
                                           const std::vector<std::pair<std::string, std::uint64_t>>& raw)
        -> std::optional<std::uint64_t> {
        std::vector<std::uint64_t> values;
        values.reserve(raw.size());
        for (const auto& [name, value] : raw) {
            (void)name;
            values.push_back(value);
        }
        return entry_ptr->handler(*self_ql, pc, self_ql->os().resolve_named_params(entry_ptr->params, values));
    };
    call(address, api_name, func, entry->params, {}, {}, entry->passthru);
}

std::string_view QlOsMacos::map_syscall(QL_ARCH archtype, unsigned num) const {
    // map_syscall.py get_syscall_mapper: the MACOS x8664 table (the macos
    // numbers) with the LIBSYSTEM fixup (0x2000000 <= n < 0x3000000 maps to
    // n - 0x2000000); the non-x8664 arches fall back to the posix tables
    if (archtype == QL_ARCH::X8664) {
        if (num >= 0x2000000 && num <= 0x3000000) {
            num -= 0x2000000;
        }
        for (const auto& [id, name] : x8664_syscall_table) {
            if (id == num) {
                return name;
            }
        }
        return {};
    }
    return QlOsPosix::map_syscall(archtype, num);
}

void QlOsMacos::run() {
    // macos.py run: the kext machinery (the savedrip stack push + the
    // hook_ret address hooks over the loader's kext surface) rides the
    // Mach-O kernel-loader slice; the plain branches are the posix run shape.
    // loader/macho.py run() also seeds macho_vmmap_end from the profile's
    // vmmap_trap_address — read here (the profile loads after the os
    // construction; the qnx prelude reads its keys on the same pattern)
    macho_vmmap_end_ = static_cast<std::uint64_t>(profile().get_int("OS64", "vmmap_trap_address"));
    try {
        QlOsPosix::run();
    } catch (...) {
        // macos.py: the UcError path clears RUN before the raise/return
        RUN = false;
        throw;
    }
    // macos.py: the normal return clears RUN (the post-run emits queue for
    // the trigger drain)
    RUN = false;
}

// mach_port.py MachPortManager.deal_with_msg: the msgh_id dispatch with the
// reply written back over the request buffer (in place)
void QlOsMacos::deal_with_msg(const MachMsg& msg, std::uint64_t addr) {
    MachMsg out_msg;
    switch (msg.header.msgh_id) {
    case 200:
        // host info
        out_msg = macho_host_server_->host_info(msg.header, msg.content);
        break;
    case 206:
        out_msg = macho_host_server_->host_get_clock_service(msg.header, msg.content);
        break;
    case 3418:
        out_msg = macho_task_server_->semaphore_create(msg.header, msg.content);
        break;
    case 3409:
        out_msg = macho_task_server_->get_special_port(msg.header, msg.content);
        break;
    default:
        // "Error Mach Msgid {} can not handled" + the upstream's Exception
        throw QlErrorBase("Mach Msgid Not Found");
    }
    out_msg.write_msg_to_mem(*ql_, addr);
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
