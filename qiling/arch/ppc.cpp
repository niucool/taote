#include "qiling/arch/ppc.hpp"

#include <unicorn/ppc.h>
#include <unicorn/unicorn.h>

namespace qiling {

namespace {

using RegMap = QlRegisterManager::RegMap;

// ppc_const.py reg_map (+ reg_float_map is the f0..f31 set below)
RegMap reg_map() {
    RegMap m{
        {"pc", UC_PPC_REG_PC},
        {"cr", UC_PPC_REG_CR0}, {"lr", UC_PPC_REG_LR},
        {"xer", UC_PPC_REG_XER}, {"ctr", UC_PPC_REG_CTR}, {"msr", UC_PPC_REG_MSR},
    };
    for (int i = 0; i <= 31; ++i) m.emplace("r" + std::to_string(i), UC_PPC_REG_0 + i);
    return m;
}

// ppc_const.py reg_float_map (f0..f31)
RegMap reg_float_map() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("f" + std::to_string(i), UC_PPC_REG_FPR0 + i);
    return m;
}

template <typename... Rest>
RegMap merge(RegMap base, Rest... rest) {
    (base.merge(std::move(rest)), ...);
    return base;
}

}  // namespace

QlArchPPC::QlArchPPC(Qiling* ql, std::optional<PPC_CPU_MODEL> cputype)
    : QlArch(ql, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype)) : std::nullopt) {
    uc_engine* raw = nullptr;
    if (uc_open(UC_ARCH_PPC, static_cast<uc_mode>(UC_MODE_PPC32 + UC_MODE_BIG_ENDIAN), &raw) != UC_ERR_OK) {
        throw QlErrorArch("failed to initialize unicorn ppc");
    }
    uc_.reset(raw);

    if (cputype.has_value()) {
        const auto model = static_cast<uc_cpu_ppc>(*cputype);
        if (uc_ctl(uc_.get(), UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), model) != UC_ERR_OK) {
            throw QlErrorArch("failed to set cpu model");
        }
    }

    regs_ = QlRegisterManager(*uc_, merge(reg_map(), reg_float_map()), "pc", "r1");
    cs_ = Cs(CS_ARCH_PPC, static_cast<cs_mode>(CS_MODE_32 + CS_MODE_BIG_ENDIAN));
    ks_ = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN);
}

QlRegisterManager& QlArchPPC::regs() { return *regs_; }

Cs& QlArchPPC::disassembler() { return *cs_; }

Ks& QlArchPPC::assembler() { return *ks_; }

void QlArchPPC::enable_float() {
    // ppc.py enable_float: regs.msr |= ppc_const.MSR.FP
    const auto msr = regs().read("msr");
    regs().write("msr", msr | static_cast<std::uint64_t>(MSR::FP));
}

}  // namespace qiling
