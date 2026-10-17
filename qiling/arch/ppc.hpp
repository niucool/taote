// Ported from qiling/arch/ppc.py — QlArchPPC (PPC32, big-endian), including the
// MSR flag table from ppc_const.py (no capstone upstream; Qiling-specific).
#ifndef QILING_ARCH_PPC_HPP
#define QILING_ARCH_PPC_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/utils.hpp"

namespace qiling {

// ppc_const.py: class MSR (IntEnum) — the flag bits used by enable_float.
// The full table ports verbatim; only FP (and its neighbours) are exercised
// before the bare-metal path resumes.
enum class MSR : std::uint64_t {
    SF = 1ull << 63,
    TAG = 1ull << 62,
    ISF = 1ull << 61,
    HV = 1ull << 60,
    TS0 = 1ull << 34,
    TS1 = 1ull << 33,
    TM = 1ull << 32,
    CM = 1ull << 31,
    ICM = 1ull << 30,
    GS = 1ull << 28,
    UCLE = 1ull << 26,
    VR = 1ull << 25,
    SPE = 1ull << 25,
    AP = 1ull << 23,
    VSX = 1ull << 23,
    SA = 1ull << 22,
    KEY = 1ull << 19,
    POW = 1ull << 18,
    TGPR = 1ull << 17,
    CE = 1ull << 17,
    ILE = 1ull << 16,
    EE = 1ull << 15,
    PR = 1ull << 14,
    FP = 1ull << 13,
    ME = 1ull << 12,
    FE0 = 1ull << 11,
    SE = 1ull << 10,
    DWE = 1ull << 10,
    UBLE = 1ull << 10,
    BE = 1ull << 9,
    DE = 1ull << 9,
    FE1 = 1ull << 8,
    AL = 1ull << 7,
    EP = 1ull << 6,
    IR = 1ull << 5,
    DR = 1ull << 4,
    IS = 1ull << 5,
    DS = 1ull << 4,
    PE = 1ull << 3,
    PX = 1ull << 2,
    PMM = 1ull << 2,
    RI = 1ull << 1,
    LE = 1ull << 0,
};

class QlArchPPC : public QlArch {
public:
    explicit QlArchPPC(Qiling* ql = nullptr, std::optional<PPC_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::PPC; }
    int bits() const noexcept override { return 32; }

    uc_engine& uc() override { return *uc_; }
    QlRegisterManager& regs() override;
    Cs& disassembler() override;
    Ks& assembler() override;
    QL_ENDIAN endian() const noexcept override { return QL_ENDIAN::EB; }

    // ppc.py enable_float: regs.msr |= MSR.FP
    void enable_float();

private:
    UcHandle uc_;
    std::optional<QlRegisterManager> regs_;
    std::optional<Cs> cs_;
    std::optional<Ks> ks_;
};

}  // namespace qiling

#endif  // QILING_ARCH_PPC_HPP
