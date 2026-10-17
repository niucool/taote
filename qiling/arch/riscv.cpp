#include "qiling/arch/riscv.hpp"

#include <unicorn/riscv.h>
#include <unicorn/unicorn.h>

namespace qiling {

namespace {

using RegMap = QlRegisterManager::RegMap;

// riscv_const.py reg_map: x0..x31 + the ABI aliases + pc
RegMap reg_map() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("x" + std::to_string(i), UC_RISCV_REG_X0 + i);

    // aliases (unicorn maps them onto the x registers)
    m.emplace("zero", UC_RISCV_REG_ZERO);
    m.emplace("ra", UC_RISCV_REG_RA);
    m.emplace("sp", UC_RISCV_REG_SP);
    m.emplace("gp", UC_RISCV_REG_GP);
    m.emplace("tp", UC_RISCV_REG_TP);
    m.emplace("t0", UC_RISCV_REG_T0);
    m.emplace("t1", UC_RISCV_REG_T1);
    m.emplace("t2", UC_RISCV_REG_T2);
    m.emplace("s0", UC_RISCV_REG_S0);
    m.emplace("fp", UC_RISCV_REG_FP);   // alias of s0 (riscv_const.py: "fp": UC_RISCV_REG_FP)
    m.emplace("s1", UC_RISCV_REG_S1);
    for (int i = 0; i <= 7; ++i) m.emplace("a" + std::to_string(i), UC_RISCV_REG_A0 + i);
    for (int i = 2; i <= 11; ++i) m.emplace("s" + std::to_string(i), UC_RISCV_REG_S2 + (i - 2));
    m.emplace("pc", UC_RISCV_REG_PC);

    return m;
}

// riscv_const.py reg_csr_map (the full CSR surface; spot-checked in tests)
RegMap reg_csr_map() {
    RegMap m{
        {"ustatus", UC_RISCV_REG_USTATUS}, {"uie", UC_RISCV_REG_UIE}, {"utvec", UC_RISCV_REG_UTVEC},
        {"uscratch", UC_RISCV_REG_USCRATCH}, {"uepc", UC_RISCV_REG_UEPC}, {"ucause", UC_RISCV_REG_UCAUSE},
        {"utval", UC_RISCV_REG_UTVAL}, {"uip", UC_RISCV_REG_UIP},
        {"fflags", UC_RISCV_REG_FFLAGS}, {"frm", UC_RISCV_REG_FRM}, {"fcsr", UC_RISCV_REG_FCSR},
        {"cycle", UC_RISCV_REG_CYCLE}, {"time", UC_RISCV_REG_TIME}, {"instret", UC_RISCV_REG_INSTRET},
        {"mcycle", UC_RISCV_REG_MCYCLE}, {"minstret", UC_RISCV_REG_MINSTRET},
        {"mcycleh", UC_RISCV_REG_MCYCLEH}, {"minstreth", UC_RISCV_REG_MINSTRETH},
        {"mvendorid", UC_RISCV_REG_MVENDORID}, {"marchid", UC_RISCV_REG_MARCHID},
        {"mimpid", UC_RISCV_REG_MIMPID}, {"mhartid", UC_RISCV_REG_MHARTID},
        {"mstatus", UC_RISCV_REG_MSTATUS}, {"misa", UC_RISCV_REG_MISA},
        {"medeleg", UC_RISCV_REG_MEDELEG}, {"mideleg", UC_RISCV_REG_MIDELEG},
        {"mie", UC_RISCV_REG_MIE}, {"mtvec", UC_RISCV_REG_MTVEC},
        {"mcounteren", UC_RISCV_REG_MCOUNTEREN}, {"mstatush", UC_RISCV_REG_MSTATUSH},
        {"mscratch", UC_RISCV_REG_MSCRATCH}, {"mepc", UC_RISCV_REG_MEPC},
        {"mcause", UC_RISCV_REG_MCAUSE}, {"mtval", UC_RISCV_REG_MTVAL}, {"mip", UC_RISCV_REG_MIP},
        {"mbadaddr", UC_RISCV_REG_MBADADDR},
        {"sstatus", UC_RISCV_REG_SSTATUS}, {"sedeleg", UC_RISCV_REG_SEDELEG}, {"sideleg", UC_RISCV_REG_SIDELEG},
        {"sie", UC_RISCV_REG_SIE}, {"stvec", UC_RISCV_REG_STVEC}, {"scounteren", UC_RISCV_REG_SCOUNTEREN},
        {"sscratch", UC_RISCV_REG_SSCRATCH}, {"sepc", UC_RISCV_REG_SEPC},
        {"scause", UC_RISCV_REG_SCAUSE}, {"stval", UC_RISCV_REG_STVAL}, {"sip", UC_RISCV_REG_SIP},
        {"sbadaddr", UC_RISCV_REG_SBADADDR}, {"sptbr", UC_RISCV_REG_SPTBR}, {"satp", UC_RISCV_REG_SATP},
        {"hstatus", UC_RISCV_REG_HSTATUS}, {"hedeleg", UC_RISCV_REG_HEDELEG}, {"hideleg", UC_RISCV_REG_HIDELEG},
        {"hie", UC_RISCV_REG_HIE}, {"hcounteren", UC_RISCV_REG_HCOUNTEREN},
        {"htval", UC_RISCV_REG_HTVAL}, {"hip", UC_RISCV_REG_HIP}, {"htinst", UC_RISCV_REG_HTINST},
        {"hgatp", UC_RISCV_REG_HGATP}, {"htimedelta", UC_RISCV_REG_HTIMEDELTA},
        {"htimedeltah", UC_RISCV_REG_HTIMEDELTAH},
    };
    // hpmcounter3..31 (+ the ...h high halves)
    for (int i = 3; i <= 31; ++i) {
        m.emplace("hpmcounter" + std::to_string(i), UC_RISCV_REG_HPMCOUNTER3 + (i - 3));
m.emplace("hpmcounter" + std::to_string(i) + "h", UC_RISCV_REG_HPMCOUNTER3H + (i - 3));
    }
    // timeh / instreth / cycleh
    m.emplace("cycleh", UC_RISCV_REG_CYCLEH);
    m.emplace("timeh", UC_RISCV_REG_TIMEH);
    m.emplace("instreth", UC_RISCV_REG_INSTRETH);
    return m;
}

// riscv_const.py reg_float_map (f0..f31)
RegMap reg_float_map() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("f" + std::to_string(i), UC_RISCV_REG_F0 + i);
    return m;
}

template <typename... Rest>
RegMap merge(RegMap base, Rest... rest) {
    (base.merge(std::move(rest)), ...);
    return base;
}

}  // namespace

QlArchRISCV::QlArchRISCV(Qiling* ql, std::optional<RISCV_CPU_MODEL> cputype)
    : QlArchRISCV(ql, 32, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype)) : std::nullopt) {}

QlArchRISCV::QlArchRISCV(Qiling* ql, int bits, std::optional<std::uint32_t> cputype)
    : QlArch(ql, cputype), bits_(bits) {
    const uc_mode mode = bits == 64 ? UC_MODE_RISCV64 : UC_MODE_RISCV32;

    uc_engine* raw = nullptr;
    if (uc_open(UC_ARCH_RISCV, mode, &raw) != UC_ERR_OK) {
        throw QlErrorArch("failed to initialize unicorn riscv");
    }
    uc_.reset(raw);

    if (cputype.has_value()) {
        // uc_cpu_riscv32 / uc_cpu_riscv64 share the value space
        const int model = bits == 64 ? static_cast<int>(static_cast<uc_cpu_riscv64>(*cputype))
                                     : static_cast<int>(static_cast<uc_cpu_riscv32>(*cputype));
        if (uc_ctl(uc_.get(), UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), model) != UC_ERR_OK) {
            throw QlErrorArch("failed to set cpu model");
        }
    }

    regs_ = QlRegisterManager(*uc_, merge(reg_map(), reg_csr_map(), reg_float_map()), "pc", "sp");
    // riscv.py: capstone CS_ARCH_RISCV with the compressed extension
    cs_ = Cs(CS_ARCH_RISCV, static_cast<cs_mode>((mode == UC_MODE_RISCV64 ? CS_MODE_RISCV64 : CS_MODE_RISCV32) | CS_MODE_RISCVC));
}

QlRegisterManager& QlArchRISCV::regs() { return *regs_; }

Cs& QlArchRISCV::disassembler() { return *cs_; }

Ks& QlArchRISCV::assembler() {
    // riscv.py, verbatim: "Keystone does not yet support riscv"
    throw QlErrorNotImplemented("Keystone does not yet support riscv");
}

void QlArchRISCV::enable_float() {
    // riscv.py enable_float: regs.mstatus |= MSTATUS.FS_DIRTY
    const auto mstatus = regs().read("mstatus");
    regs().write("mstatus", mstatus | static_cast<std::uint64_t>(MSTATUS::FS_DIRTY));
}

void QlArchRISCV::init_context() {
    // riscv.py init_context: pc = 0x08000000 (pure register op)
    regs().write("pc", 0x08000000);
}

QlArchRISCV64::QlArchRISCV64(Qiling* ql, std::optional<RISCV64_CPU_MODEL> cputype)
    : QlArchRISCV(ql, 64, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype)) : std::nullopt) {}

}  // namespace qiling
