// Ported from qiling/arch/arm64.py — QlArchARM64 (AArch64).
#ifndef QILING_ARCH_ARM64_HPP
#define QILING_ARCH_ARM64_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/arch/cpr.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/utils.hpp"

namespace qiling {

class QlArchARM64 : public QlArch {
public:
    explicit QlArchARM64(Qiling* ql = nullptr, std::optional<ARM64_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::ARM64; }
    int bits() const noexcept override { return 64; }

    uc_engine& uc() override { return *uc_; }
    QlRegisterManager& regs() override;
    Cs& disassembler() override;
    Ks& assembler() override;
    QL_ENDIAN endian() const noexcept override { return QL_ENDIAN::EL; }

    // Coprocessor Registers (arm64.py cpr)
    QlCpr64Manager& cpr();

    // arm64.py enable_vfp: cpacr_el1 |= (0b11 << 20)
    void enable_vfp();

private:
    UcHandle uc_;
    std::optional<QlRegisterManager> regs_;
    std::optional<QlCpr64Manager> cpr_;
    std::optional<Cs> cs_;
    std::optional<Ks> ks_;
};

}  // namespace qiling

#endif  // QILING_ARCH_ARM64_HPP
