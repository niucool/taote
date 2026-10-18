// Ported from qiling/arch/arm.py — QlArchARM (ARM32 with endianness and Thumb
// initialization), plus the Cortex-M variant from qiling/arch/cortex_m.py.
//
// Cortex-M deferrals (documented, resume with the bare-metal path per
// PORT_PLAN.md §10 / OQ 9):
//   - the Python uc is a MultiTaskUnicorn (qiling/extensions/multitask.py); the
//     C++ port opens a plain unicorn instance until the fiber scheduler phase
//   - unicorn_exception_handler forwards to ql.hw.nvic — the hw peripheral tree
//     is deferred, so it degrades to QlErrorNotImplemented
// The QlInterruptContext RAII guard is ported; its enter/exit paths use
// stack_push/stack_pop and therefore require the Phase 2 memory manager.
#ifndef QILING_ARCH_ARM_HPP
#define QILING_ARCH_ARM_HPP

#include <map>
#include <optional>

#include <unicorn/unicorn.h>

#include "qiling/arch/arch.hpp"
#include "qiling/arch/cpr.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/utils.hpp"

// unicorn/unicorn.h pulls in windows.h on WIN32, and winnt.h defines
// `UNALIGNED` as __unaligned — a macro expansion would break the verbatim
// EXCP::UNALIGNED enumerator below (the errno_value() precedent). Nothing in
// this tree needs the winnt macro, so it is undef'd once here.
#ifdef UNALIGNED
#undef UNALIGNED
#endif

namespace qiling {

class QlArchARM : public QlArch {
public:
    // Python: __init__(ql, *, cputype, endian, thumb) — all required keywords in
    // Python; the C++ port defaults endian=EL, thumb=false for ergonomics.
    // extra_mode lets derived classes add UC_MODE_* bits (cortex_m.py adds
    // UC_MODE_MCLASS); applied on top of ARM + endianness + thumb.
    QlArchARM(Qiling* ql, std::optional<ARM_CPU_MODEL> cputype = std::nullopt,
              QL_ENDIAN endian = QL_ENDIAN::EL, bool thumb = false,
              int extra_mode = 0);

    // core.py emu_start: getattr(self.arch, '_init_thumb', False) -> begin |= 1
    std::uint64_t adjust_emu_start(std::uint64_t begin) const override {
        return init_thumb_ ? (begin | 1) : begin;
    }

    QL_ARCH type() const noexcept override { return QL_ARCH::ARM; }
    int bits() const noexcept override { return 32; }

    uc_engine& uc() override { return *uc_; }
    QlRegisterManager& regs() override;

    // arm.py: qiling.arm_get_tls_addr = 0xFFFF0FE0 (special address on which
    // unicorn resolves the TLS helper on ARM)
    static constexpr std::uint64_t kArmGetTlsAddr = 0xFFFF0FE0;

    // arm.py: is_thumb / effective_pc / endian read live CPSR bits (5 / 9)
    bool is_thumb() const;
    std::uint64_t effective_pc() const;
    QL_ENDIAN endian() const noexcept override;

    // Coprocessor Registers (arm.py cpr)
    QlCprManager& cpr();

    // disassembler/assembler pick the mode dynamically (thumb x endianness);
    // per-mode instances are cached (arm.py __cached_disasm/__cached_asm)
    Cs& disassembler() override;
    Ks& assembler() override;

    // set full access to cp10/cp11 and enable FPEXC.EN
    void enable_vfp();

protected:
    static std::uint32_t cs_mode_for(bool thumb, bool big_endian) noexcept;
    static int ks_mode_for(bool thumb, bool big_endian) noexcept;

    UcHandle uc_;

    // arm.py _init_endian/_init_thumb — the constructor mode bits, kept for
    // core.py's emu_start thumb adjustment
    QL_ENDIAN init_endian_ = QL_ENDIAN::EL;
    bool init_thumb_ = false;
    std::optional<QlRegisterManager> regs_;
    std::optional<QlCprManager> cpr_;
    std::map<int, Cs> cs_cache_;
    std::map<int, Ks> ks_cache_;

    // cortex_m.py cached disassembler/assembler (MCLASS mode)
    std::optional<Cs> cortex_cs_;
    std::optional<Ks> cortex_ks_;

private:
    std::uint32_t read_cpsr() const noexcept;
    std::uint64_t read_pc() const noexcept;
};

// ---- cortex_m_const.py: Qiling-specific tables (no capstone upstream) ----

// cortex_m_const.py: class IRQ (IntEnum)
enum class IRQ : int {
    NMI = -14,
    HARD_FAULT = -13,
    MEMORY_MANAGEMENT_FAULT = -12,
    BUS_FAULT = -11,
    USAGE_FAULT = -10,
    SVCALL = -5,
    PENDSV = -2,
    SYSTICK = -1,
    NOTHING = 0,
};

// cortex_m_const.py: class CONTROL (IntEnum)
enum class CONTROL : int { FPCA = 0b100, SPSEL = 0b010, PRIV = 0b001 };

// cortex_m_const.py: class EXC_RETURN (IntEnum)
enum class EXC_RETURN : unsigned {
    MASK = 0xfffffff0u,
    RETURN_SP = 0b0100u,
    RETURN_MODE = 0b1000u,
};

// cortex_m_const.py: class EXCP (IntEnum)
enum class EXCP : int {
    UDEF = 1,
    SWI = 2,
    PREFETCH_ABORT = 3,
    DATA_ABORT = 4,
    IRQ = 5,
    FIQ = 6,
    BKPT = 7,
    EXCEPTION_EXIT = 8,
    KERNEL_TRAP = 9,
    HVC = 11,
    HYP_TRAP = 12,
    SMC = 13,
    VIRQ = 14,
    VFIQ = 15,
    SEMIHOST = 16,
    NOCP = 17,
    INVSTATE = 18,
    STKOF = 19,
    LAZYFP = 20,
    LSERR = 21,
    UNALIGNED = 22,
};

// cortex_m.py: QlInterruptContext — RAII guard pushing/popping the exception
// frame around an interrupt handler (the ContextDecorator analogue).
class QlInterruptContext {
public:
    explicit QlInterruptContext(QlArchARM& arch) : arch_(arch) {}
    ~QlInterruptContext() { exit(); }

    // pushes xpsr, pc, lr, r12, r3, r2, r1, r0 (verbatim order); requires mem
    void enter();
    // restores the frame; EXC_RETURN handling requires mem
    void exit();

private:
    QlArchARM& arch_;
    bool entered_ = false;
};

// cortex_m.py: QlArchCORTEX_M — the M-profile ARM variant.
class QlArchCORTEX_M final : public QlArchARM {
public:
    explicit QlArchCORTEX_M(Qiling* ql = nullptr, std::optional<ARM_CPU_MODEL> cputype = std::nullopt);

    QL_ARCH type() const noexcept override { return QL_ARCH::CORTEX_M; }

    // cortex_m.py overrides: always thumb, always little-endian
    bool is_thumb() const noexcept { return true; }
    QL_ENDIAN endian() const noexcept override { return QL_ENDIAN::EL; }

    // cortex_m.py disassembler/assembler carry the MCLASS mode (cached)
    Cs& disassembler() override;
    Ks& assembler() override;

    bool is_handler_mode();
    bool using_psp();

    // cortex_m.py init_context (reads the vector table from emulated memory —
    // requires the Phase 2 memory manager)
    void init_context();

    // cortex_m.py unicorn_exception_handler forwards to ql.hw.nvic — deferred
    // with the bare-metal path
    void unicorn_exception_handler(int intno);
};

}  // namespace qiling

#endif  // QILING_ARCH_ARM_HPP
