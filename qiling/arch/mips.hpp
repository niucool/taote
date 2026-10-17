// Ported from qiling/arch/mips.py — QlArchMIPS (MIPS32, either endianness).
#ifndef QILING_ARCH_MIPS_HPP
#define QILING_ARCH_MIPS_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/utils.hpp"

namespace qiling {

class QlArchMIPS : public QlArch {
public:
    // Python: __init__(ql, *, cputype, endian) — endian is required there
    QlArchMIPS(Qiling* ql, std::optional<MIPS_CPU_MODEL> cputype = std::nullopt,
               QL_ENDIAN endian = QL_ENDIAN::EL);

    QL_ARCH type() const noexcept override { return QL_ARCH::MIPS; }
    int bits() const noexcept override { return 32; }

    uc_engine& uc() override { return *uc_; }
    QlRegisterManager& regs() override;
    Cs& disassembler() override;
    Ks& assembler() override;

    // mips.py: endian is the initialization value (verbatim property)
    QL_ENDIAN endian() const noexcept override { return endian_; }

private:
    QL_ENDIAN endian_;
    UcHandle uc_;
    std::optional<QlRegisterManager> regs_;
    std::optional<Cs> cs_;
    std::optional<Ks> ks_;
};

}  // namespace qiling

#endif  // QILING_ARCH_MIPS_HPP
