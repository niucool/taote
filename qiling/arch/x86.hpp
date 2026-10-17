// Ported from qiling/arch/x86.py — QlArchIntel base and the per-mode x86
// classes (QlArchA8086 / QlArchX86 / QlArchX8664). Const modules are replaced
// by the engine headers (decision D3): the register maps are the mapping glue
// over unicorn's UC_X86_REG_* constants and live in x86.cpp.
#ifndef QILING_ARCH_X86_HPP
#define QILING_ARCH_X86_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/utils.hpp"

namespace qiling {

class QlArchIntel : public QlArch {
public:
    // bits selects the unicorn mode (16/32/64); cputype is an optional
    // X86_CPU_MODEL applied via uc_ctl_set_cpu_model (x86.py ctl_set_cpu_model).
    QlArchIntel(Qiling* ql, int bits, std::optional<X86_CPU_MODEL> cputype = std::nullopt);

    int bits() const noexcept override { return bits_; }

    uc_engine& uc() override { return *uc_; }

    QL_ENDIAN endian() const noexcept override { return QL_ENDIAN::EL; }

protected:
    int bits_;
    UcHandle uc_;
    std::optional<QlRegisterManager> regs_;
    std::optional<Cs> cs_;
    std::optional<Ks> ks_;
};

class QlArchA8086 final : public QlArchIntel {
public:
    explicit QlArchA8086(Qiling* ql = nullptr, std::optional<X86_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::A8086; }

    QlRegisterManager& regs() override;
    Cs& disassembler() override;
    Ks& assembler() override;
};

class QlArchX86 final : public QlArchIntel {
public:
    explicit QlArchX86(Qiling* ql = nullptr, std::optional<X86_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::X86; }

    QlRegisterManager& regs() override;
    Cs& disassembler() override;
    Ks& assembler() override;
};

class QlArchX8664 final : public QlArchIntel {
public:
    explicit QlArchX8664(Qiling* ql = nullptr, std::optional<X86_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::X8664; }

    QlRegisterManager& regs() override;
    Cs& disassembler() override;
    Ks& assembler() override;
};

}  // namespace qiling

#endif  // QILING_ARCH_X86_HPP
