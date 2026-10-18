// Ported from qiling/os/macos/macos.py — the macos dialect. The load() sets
// up the GDT/segments (the x86_utils.py GDTManager + SegmentManager64 shape,
// ported compactly — the same shape as the freebsd dialect per the upstream's
// per-dialect repetition) and installs the syscall entry hook.
#include "qiling/os/macos/macos.hpp"

#include <array>

#include "qiling/core.hpp"
#include "qiling/os/macos/map_syscall.hpp"
#include "qiling/os/macos/syscall.hpp"

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
    QlOsPosix::run();
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
