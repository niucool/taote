#include "qiling/arch/x86.hpp"

#include <unicorn/unicorn.h>

#include "qiling/arch/utils.hpp"

namespace qiling {

// ---- register maps (the x86_const.py reg_map_* tables, resolved against
// unicorn's UC_X86_REG_* constants; D3 dissolves the const module) ----

namespace {

using RegMap = QlRegisterManager::RegMap;

// x86_const.py reg_map_8
RegMap reg_map_8() {
    return {
        {"ah", UC_X86_REG_AH}, {"al", UC_X86_REG_AL}, {"ch", UC_X86_REG_CH}, {"cl", UC_X86_REG_CL},
        {"dh", UC_X86_REG_DH}, {"dl", UC_X86_REG_DL}, {"bh", UC_X86_REG_BH}, {"bl", UC_X86_REG_BL},
    };
}

// reg_map_16
RegMap reg_map_16() {
    return {
        {"ax", UC_X86_REG_AX}, {"cx", UC_X86_REG_CX}, {"dx", UC_X86_REG_DX}, {"bx", UC_X86_REG_BX},
        {"sp", UC_X86_REG_SP}, {"bp", UC_X86_REG_BP}, {"si", UC_X86_REG_SI}, {"di", UC_X86_REG_DI},
        {"ip", UC_X86_REG_IP},
    };
}

// reg_map_32
RegMap reg_map_32() {
    return {
        {"eax", UC_X86_REG_EAX}, {"ecx", UC_X86_REG_ECX}, {"edx", UC_X86_REG_EDX}, {"ebx", UC_X86_REG_EBX},
        {"esp", UC_X86_REG_ESP}, {"ebp", UC_X86_REG_EBP}, {"esi", UC_X86_REG_ESI}, {"edi", UC_X86_REG_EDI},
        {"eip", UC_X86_REG_EIP},
    };
}

// reg_map_64
RegMap reg_map_64() {
    RegMap m{
        {"rax", UC_X86_REG_RAX}, {"rbx", UC_X86_REG_RBX}, {"rcx", UC_X86_REG_RCX}, {"rdx", UC_X86_REG_RDX},
        {"rsi", UC_X86_REG_RSI}, {"rdi", UC_X86_REG_RDI}, {"rbp", UC_X86_REG_RBP}, {"rsp", UC_X86_REG_RSP},
    };
    for (int i = 8; i <= 15; ++i) {
        m.emplace("r" + std::to_string(i), UC_X86_REG_R8 + (i - 8));
    }
    m.emplace("rip", UC_X86_REG_RIP);
    return m;
}

// reg_map_seg_base
RegMap reg_map_seg_base() {
    return {
        {"fsbase", UC_X86_REG_FS_BASE},
        {"gsbase", UC_X86_REG_GS_BASE},
    };
}

// reg_map_64_b / reg_map_64_w / reg_map_64_d (r8..r15 narrow views)
RegMap reg_map_64_suffixed() {
    RegMap m;
    constexpr std::string_view suffixes[3] = {"b", "w", "d"};
    const int bases[3] = {UC_X86_REG_R8B, UC_X86_REG_R8W, UC_X86_REG_R8D};
    for (int s = 0; s < 3; ++s) {
        for (int i = 8; i <= 15; ++i) {
            m.emplace("r" + std::to_string(i) + std::string(suffixes[s]), bases[s] + (i - 8));
        }
    }
    return m;
}

// reg_map_cr (cr0..cr4)
RegMap reg_map_cr() {
    return {
        {"cr0", UC_X86_REG_CR0}, {"cr1", UC_X86_REG_CR1}, {"cr2", UC_X86_REG_CR2},
        {"cr3", UC_X86_REG_CR3}, {"cr4", UC_X86_REG_CR4},
    };
}

// reg_map_cr_64 (cr8)
RegMap reg_map_cr_64() {
    return {
        {"cr8", UC_X86_REG_CR8},
    };
}

// reg_map_dr
RegMap reg_map_dr() {
    RegMap m;
    for (int i = 0; i <= 7; ++i) {
        m.emplace("dr" + std::to_string(i), UC_X86_REG_DR0 + i);
    }
    return m;
}

// reg_map_st
RegMap reg_map_st() {
    RegMap m;
    for (int i = 0; i <= 7; ++i) {
        m.emplace("st" + std::to_string(i), UC_X86_REG_ST0 + i);
    }
    return m;
}

// reg_map_misc
RegMap reg_map_misc() {
    return {
        {"eflags", UC_X86_REG_EFLAGS}, {"cs", UC_X86_REG_CS}, {"ss", UC_X86_REG_SS},
        {"ds", UC_X86_REG_DS},         {"es", UC_X86_REG_ES}, {"fs", UC_X86_REG_FS},
        {"gs", UC_X86_REG_GS},
    };
}

// reg_map_xmm (xmm0..xmm7; the 64-bit extension is reg_map_xmm_64)
RegMap reg_map_xmm() {
    RegMap m;
    for (int i = 0; i <= 7; ++i) {
        m.emplace("xmm" + std::to_string(i), UC_X86_REG_XMM0 + i);
    }
    return m;
}

// reg_map_xmm_64 (xmm8..xmm31)
RegMap reg_map_xmm_64() {
    RegMap m;
    for (int i = 8; i <= 31; ++i) {
        m.emplace("xmm" + std::to_string(i), UC_X86_REG_XMM0 + i);
    }
    return m;
}

// reg_map_ymm (ymm0..ymm7)
RegMap reg_map_ymm() {
    RegMap m;
    for (int i = 0; i <= 7; ++i) {
        m.emplace("ymm" + std::to_string(i), UC_X86_REG_YMM0 + i);
    }
    return m;
}

// reg_map_ymm_64 (ymm8..ymm31)
RegMap reg_map_ymm_64() {
    RegMap m;
    for (int i = 8; i <= 31; ++i) {
        m.emplace("ymm" + std::to_string(i), UC_X86_REG_YMM0 + i);
    }
    return m;
}

// reg_map_zmm (zmm0..zmm31)
RegMap reg_map_zmm() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) {
        m.emplace("zmm" + std::to_string(i), UC_X86_REG_ZMM0 + i);
    }
    return m;
}

RegMap merge(RegMap base) {
    return base;  // fold helper
}

template <typename... Rest>
RegMap merge(RegMap base, RegMap next, Rest... rest) {
    base.merge(next);
    return merge(std::move(base), std::move(rest)...);
}

template <typename... Maps>
RegMap merged_maps(Maps... maps) {
    return merge(std::move(maps)...);
}

}  // namespace

// ---- QlArchIntel ----

QlArchIntel::QlArchIntel(Qiling* ql, int bits, std::optional<X86_CPU_MODEL> cputype)
    : QlArch(ql, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype))
                                     : std::nullopt),
      bits_(bits) {
    const uc_mode mode = bits == 16 ? UC_MODE_16 : (bits == 32 ? UC_MODE_32 : UC_MODE_64);

    uc_engine* raw = nullptr;
    if (uc_open(UC_ARCH_X86, mode, &raw) != UC_ERR_OK) {
        throw QlErrorArch("failed to initialize unicorn x86 (mode " + std::to_string(bits) + ")");
    }
    uc_.reset(raw);

    if (cputype.has_value()) {
        const auto model = static_cast<uc_cpu_x86>(*cputype);
        if (uc_ctl(uc_.get(), UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), model) != UC_ERR_OK) {
            throw QlErrorArch("failed to set cpu model");
        }
    }

    cs_ = Cs(CS_ARCH_X86, mode == UC_MODE_16 ? CS_MODE_16 : (mode == UC_MODE_32 ? CS_MODE_32 : CS_MODE_64));
    ks_ = Ks(KS_ARCH_X86, mode == UC_MODE_16 ? KS_MODE_16 : (mode == UC_MODE_32 ? KS_MODE_32 : KS_MODE_64));
    msr_.emplace(*uc_);
}

QlMsrManager& QlArchIntel::msr() {
    // x86.py cached_property msr
    return *msr_;
}

// ---- QlArchA8086 (bits = 16; regs_map = 8 + 16 + misc) ----

QlArchA8086::QlArchA8086(Qiling* ql, std::optional<X86_CPU_MODEL> cputype)
    : QlArchIntel(ql, 16, cputype) {
    regs_ = QlRegisterManager(*uc_, merged_maps(reg_map_8(), reg_map_16(), reg_map_misc()), "ip", "sp");
}

QlRegisterManager& QlArchA8086::regs() { return *regs_; }

Cs& QlArchA8086::disassembler() { return *cs_; }

Ks& QlArchA8086::assembler() { return *ks_; }

// ---- QlArchX86 (bits = 32; the full merged map except 64-bit-only families) ----

QlArchX86::QlArchX86(Qiling* ql, std::optional<X86_CPU_MODEL> cputype)
    : QlArchIntel(ql, 32, cputype) {
    regs_ = QlRegisterManager(*uc_,
                              merged_maps(reg_map_8(), reg_map_16(), reg_map_32(), reg_map_cr(), reg_map_dr(),
                                          reg_map_st(), reg_map_misc(), reg_map_xmm(), reg_map_ymm(),
                                          reg_map_seg_base()),
                              "eip", "esp");
}

QlRegisterManager& QlArchX86::regs() { return *regs_; }

Cs& QlArchX86::disassembler() { return *cs_; }

Ks& QlArchX86::assembler() { return *ks_; }

// ---- QlArchX8664 (bits = 64; the full merged map) ----

QlArchX8664::QlArchX8664(Qiling* ql, std::optional<X86_CPU_MODEL> cputype)
    : QlArchIntel(ql, 64, cputype) {
    regs_ = QlRegisterManager(*uc_,
                              merged_maps(reg_map_8(), reg_map_16(), reg_map_32(), reg_map_64(), reg_map_cr(),
                                          reg_map_cr_64(), reg_map_dr(), reg_map_st(), reg_map_misc(),
                                          reg_map_64_suffixed(), reg_map_seg_base(), reg_map_xmm(),
                                          reg_map_xmm_64(), reg_map_ymm(), reg_map_ymm_64(), reg_map_zmm()),
                              "rip", "rsp");
}

QlRegisterManager& QlArchX8664::regs() { return *regs_; }

Cs& QlArchX8664::disassembler() { return *cs_; }

Ks& QlArchX8664::assembler() { return *ks_; }

}  // namespace qiling
