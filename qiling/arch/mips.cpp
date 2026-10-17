#include "qiling/arch/mips.hpp"

#include <unicorn/mips.h>
#include <unicorn/unicorn.h>

namespace qiling {

namespace {

using RegMap = QlRegisterManager::RegMap;

// mips_const.py reg_map: numeric r0..r31 + the aliases + hi/lo + cp0 regs
RegMap reg_map() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("r" + std::to_string(i), UC_MIPS_REG_0 + i);

    // aliases
    m.emplace("pc", UC_MIPS_REG_PC);
    m.emplace("zero", UC_MIPS_REG_ZERO);
    m.emplace("at", UC_MIPS_REG_AT);
    m.emplace("v0", UC_MIPS_REG_V0);
    m.emplace("v1", UC_MIPS_REG_V1);
    m.emplace("a0", UC_MIPS_REG_A0);
    m.emplace("a1", UC_MIPS_REG_A1);
    m.emplace("a2", UC_MIPS_REG_A2);
    m.emplace("a3", UC_MIPS_REG_A3);
    m.emplace("t0", UC_MIPS_REG_T0);
    m.emplace("t1", UC_MIPS_REG_T1);
    m.emplace("t2", UC_MIPS_REG_T2);
    m.emplace("t3", UC_MIPS_REG_T3);
    m.emplace("t4", UC_MIPS_REG_T4);
    m.emplace("t5", UC_MIPS_REG_T5);
    m.emplace("t6", UC_MIPS_REG_T6);
    m.emplace("t7", UC_MIPS_REG_T7);
    m.emplace("s0", UC_MIPS_REG_S0);
    m.emplace("s1", UC_MIPS_REG_S1);
    m.emplace("s2", UC_MIPS_REG_S2);
    m.emplace("s3", UC_MIPS_REG_S3);
    m.emplace("s4", UC_MIPS_REG_S4);
    m.emplace("s5", UC_MIPS_REG_S5);
    m.emplace("s6", UC_MIPS_REG_S6);
    m.emplace("s7", UC_MIPS_REG_S7);
    m.emplace("t8", UC_MIPS_REG_T8);
    m.emplace("t9", UC_MIPS_REG_T9);
    m.emplace("k0", UC_MIPS_REG_K0);
    m.emplace("k1", UC_MIPS_REG_K1);
    m.emplace("gp", UC_MIPS_REG_GP);
    m.emplace("sp", UC_MIPS_REG_SP);
    m.emplace("fp", UC_MIPS_REG_FP);
    m.emplace("s8", UC_MIPS_REG_S8);
    m.emplace("ra", UC_MIPS_REG_RA);

    m.emplace("hi", UC_MIPS_REG_HI);
    m.emplace("lo", UC_MIPS_REG_LO);

    m.emplace("cp0_config3", UC_MIPS_REG_CP0_CONFIG3);
    m.emplace("cp0_userlocal", UC_MIPS_REG_CP0_USERLOCAL);
    m.emplace("cp0_status", UC_MIPS_REG_CP0_STATUS);

    return m;
}

}  // namespace

QlArchMIPS::QlArchMIPS(Qiling* ql, std::optional<MIPS_CPU_MODEL> cputype, QL_ENDIAN endian)
    : QlArch(ql, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype)) : std::nullopt),
      endian_(endian) {
    const uc_mode mode = static_cast<uc_mode>(UC_MODE_MIPS32 |
        (endian == QL_ENDIAN::EB ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN));

    uc_engine* raw = nullptr;
    if (uc_open(UC_ARCH_MIPS, mode, &raw) != UC_ERR_OK) {
        throw QlErrorArch("failed to initialize unicorn mips");
    }
    uc_.reset(raw);

    if (cputype.has_value()) {
        const auto model = static_cast<uc_cpu_mips32>(*cputype);
        if (uc_ctl(uc_.get(), UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), model) != UC_ERR_OK) {
            throw QlErrorArch("failed to set cpu model");
        }
    }

    regs_ = QlRegisterManager(*uc_, reg_map(), "pc", "sp");
    cs_ = Cs(CS_ARCH_MIPS, static_cast<cs_mode>(CS_MODE_MIPS32 |
        (endian == QL_ENDIAN::EB ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN)));
    ks_ = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 |
        (endian == QL_ENDIAN::EB ? KS_MODE_BIG_ENDIAN : KS_MODE_LITTLE_ENDIAN));
}

QlRegisterManager& QlArchMIPS::regs() { return *regs_; }

Cs& QlArchMIPS::disassembler() { return *cs_; }

Ks& QlArchMIPS::assembler() { return *ks_; }

}  // namespace qiling
