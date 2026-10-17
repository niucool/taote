// Ported from qiling/arch/riscv.py + riscv64.py — QlArchRISCV (RV32) and
// QlArchRISCV64. Keystone has no RISC-V backend, so assembler() degrades to
// QlErrorNotImplemented (verbatim behavior from riscv.py). The MSTATUS flag
// table from riscv_const.py carries over (Qiling-specific).
#ifndef QILING_ARCH_RISCV_HPP
#define QILING_ARCH_RISCV_HPP

#include <optional>

#include "qiling/arch/arch.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/utils.hpp"

namespace qiling {

// riscv_const.py: class MSTATUS (IntEnum) — FS field values used by enable_float.
enum class MSTATUS : std::uint64_t {
    FS_OFF = 0,
    FS_INITIAL = 1ull << 13,
    FS_CLEAN = 2ull << 13,
    FS_DIRTY = 3ull << 13,
};

class QlArchRISCV : public QlArch {
public:
    explicit QlArchRISCV(Qiling* ql, std::optional<RISCV_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::RISCV; }
    int bits() const noexcept override { return 32; }

    uc_engine& uc() override { return *uc_; }
    QlRegisterManager& regs() override;
    Cs& disassembler() override;

    // riscv.py: "Keystone does not yet support riscv"
    Ks& assembler() override;

    QL_ENDIAN endian() const noexcept override { return QL_ENDIAN::EL; }

    // riscv.py enable_float: regs.mstatus |= MSTATUS.FS_DIRTY
    void enable_float();

    // riscv.py init_context: pc = 0x08000000 (pure register op — usable now)
    void init_context();

protected:
    explicit QlArchRISCV(Qiling* ql, int bits, std::optional<std::uint32_t> cputype);

    int bits_;
    UcHandle uc_;
    std::optional<QlRegisterManager> regs_;
    std::optional<Cs> cs_;
};

// riscv64.py: QlArchRISCV64 — same surface, 64-bit mode.
class QlArchRISCV64 final : public QlArchRISCV {
public:
    explicit QlArchRISCV64(Qiling* ql = nullptr, std::optional<RISCV64_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::RISCV64; }
    int bits() const noexcept override { return 64; }
};

}  // namespace qiling

#endif  // QILING_ARCH_RISCV_HPP
