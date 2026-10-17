#include "qiling/arch/arm64.hpp"

#include <unicorn/arm64.h>
#include <unicorn/unicorn.h>

namespace qiling {

namespace {

using RegMap = QlRegisterManager::RegMap;

RegMap reg_map() {
    RegMap m{
        {"x0", UC_ARM64_REG_X0},  {"x1", UC_ARM64_REG_X1},  {"x2", UC_ARM64_REG_X2},  {"x3", UC_ARM64_REG_X3},
        {"x4", UC_ARM64_REG_X4},  {"x5", UC_ARM64_REG_X5},  {"x6", UC_ARM64_REG_X6},  {"x7", UC_ARM64_REG_X7},
        {"x8", UC_ARM64_REG_X8},  {"x9", UC_ARM64_REG_X9},  {"x10", UC_ARM64_REG_X10}, {"x11", UC_ARM64_REG_X11},
        {"x12", UC_ARM64_REG_X12}, {"x13", UC_ARM64_REG_X13}, {"x14", UC_ARM64_REG_X14}, {"x15", UC_ARM64_REG_X15},
        {"x16", UC_ARM64_REG_X16}, {"x17", UC_ARM64_REG_X17}, {"x18", UC_ARM64_REG_X18}, {"x19", UC_ARM64_REG_X19},
        {"x20", UC_ARM64_REG_X20}, {"x21", UC_ARM64_REG_X21}, {"x22", UC_ARM64_REG_X22}, {"x23", UC_ARM64_REG_X23},
        {"x24", UC_ARM64_REG_X24}, {"x25", UC_ARM64_REG_X25}, {"x26", UC_ARM64_REG_X26}, {"x27", UC_ARM64_REG_X27},
        {"x28", UC_ARM64_REG_X28}, {"x29", UC_ARM64_REG_X29}, {"x30", UC_ARM64_REG_X30},
        {"sp", UC_ARM64_REG_SP},  {"pc", UC_ARM64_REG_PC},  {"lr", UC_ARM64_REG_LR},
        {"cpacr_el1", UC_ARM64_REG_CPACR_EL1}, {"pstate", UC_ARM64_REG_PSTATE},
    };
    return m;
}

// reg_map_b / reg_map_d / reg_map_h / reg_map_q / reg_map_s / reg_map_w — the
// narrow-view names are <suffix><index> (b0..b31, w0..w30; arm64_const.py)
RegMap reg_map_suffixed() {
    RegMap m;
    constexpr std::string_view prefix[6] = {"b", "d", "h", "q", "s", "w"};
    const int bases[6] = {UC_ARM64_REG_B0, UC_ARM64_REG_D0, UC_ARM64_REG_H0, UC_ARM64_REG_Q0, UC_ARM64_REG_S0, UC_ARM64_REG_W0};
    const int max_index[6] = {31, 31, 31, 31, 31, 30};  // w31 does not exist (SP alias)
    for (int s = 0; s < 6; ++s) {
        for (int i = 0; i <= max_index[s]; ++i) {
            m.emplace(std::string(prefix[s]) + std::to_string(i), bases[s] + i);
        }
    }
    return m;
}

// reg_map_v (v0..v31, 128-bit views)
RegMap reg_map_v() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("v" + std::to_string(i), UC_ARM64_REG_V0 + i);
    return m;
}

// arm64_const.py reg_map_fp
RegMap reg_map_fp() {
    return {
        {"fpcr", UC_ARM64_REG_FPCR},
        {"fpsr", UC_ARM64_REG_FPSR},
    };
}

// arm64_const.py reg_cpr
QlCpr64Manager::RegMap reg_cpr() {
    using D = QlCpr64Manager::Desc;
    return {
        {"TPIDR_EL0",   D{3, 3, 13, 0, 2}},
        {"TPIDRRO_EL0", D{3, 3, 13, 0, 3}},
        {"TPIDR_EL1",   D{3, 0, 13, 0, 4}},
        {"ELR_EL1",     D{3, 0,  4, 0, 1}},
        {"ELR_EL2",     D{3, 4,  4, 0, 1}},
        {"ELR_EL3",     D{3, 6,  4, 0, 1}},
        {"SP_EL0",      D{3, 0,  4, 1, 0}},
        {"SP_EL1",      D{3, 4,  4, 1, 0}},
        {"SP_EL2",      D{3, 6,  4, 1, 0}},
        {"TTBR0_EL1",   D{3, 0,  2, 0, 0}},
        {"TTBR1_EL1",   D{3, 0,  2, 0, 1}},
        {"ESR_EL1",     D{3, 0,  5, 2, 0}},
        {"ESR_EL2",     D{3, 4,  5, 2, 0}},
        {"ESR_EL3",     D{3, 6,  5, 2, 0}},
        {"FAR_EL1",     D{3, 0,  6, 0, 0}},
        {"FAR_EL2",     D{3, 4,  6, 0, 0}},
        {"FAR_EL3",     D{3, 6,  6, 0, 0}},
        {"PAR_EL1",     D{3, 0,  7, 4, 0}},
        {"MAIR_EL1",    D{3, 0, 10, 2, 0}},
        {"VBAR_EL1",    D{3, 0, 12, 0, 0}},
        {"VBAR_EL2",    D{3, 4, 12, 0, 0}},
        {"VBAR_EL3",    D{3, 6, 12, 0, 0}},
    };
}

template <typename... Rest>
RegMap merge(RegMap base, Rest... rest) {
    (base.merge(std::move(rest)), ...);
    return base;
}

}  // namespace

QlArchARM64::QlArchARM64(Qiling* ql, std::optional<ARM64_CPU_MODEL> cputype)
    : QlArch(ql, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype)) : std::nullopt) {
    uc_engine* raw = nullptr;
    if (uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &raw) != UC_ERR_OK) {
        throw QlErrorArch("failed to initialize unicorn arm64");
    }
    uc_.reset(raw);

    if (cputype.has_value()) {
        const auto model = static_cast<uc_cpu_arm64>(*cputype);
        if (uc_ctl(uc_.get(), UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), model) != UC_ERR_OK) {
            throw QlErrorArch("failed to set cpu model");
        }
    }

    regs_ = QlRegisterManager(*uc_, merge(reg_map(), reg_map_suffixed(), reg_map_v(), reg_map_fp()), "pc", "sp");
    cpr_ = QlCpr64Manager(*uc_, reg_cpr());
}

QlRegisterManager& QlArchARM64::regs() { return *regs_; }

Cs& QlArchARM64::disassembler() {
    if (!cs_.has_value()) cs_ = Cs(CS_ARCH_ARM64, CS_MODE_ARM);
    return *cs_;
}

Ks& QlArchARM64::assembler() {
    if (!ks_.has_value()) ks_ = Ks(KS_ARCH_ARM64, KS_MODE_ARM);
    return *ks_;
}

QlCpr64Manager& QlArchARM64::cpr() { return *cpr_; }

void QlArchARM64::enable_vfp() {
    // arm64.py enable_vfp: cpacr_el1 |= (0b11 << 20)
    const auto cpacr = regs().read("cpacr_el1");
    regs().write("cpacr_el1", cpacr | (0b11 << 20));
}

}  // namespace qiling
