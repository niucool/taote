// Ported from qiling/arch/arch.py — QlArch, the abstract CPU layer base
// (PORT_PLAN.md §10 Phase 1).
//
// Phase-1 note: the composition root (core.py / Qiling) lands in Phase 3; until
// then QlArch takes a nullable `Qiling*` (the Python `ql` argument) and the
// stack helpers that require `ql.mem` are declared but only usable once the
// facade exists (mirroring the Python boot order where arch is constructed
// before mem).
#ifndef QILING_ARCH_ARCH_HPP
#define QILING_ARCH_ARCH_HPP

#include <cstdint>
#include <memory>

#include <unicorn/unicorn.h>

#include "qiling/const.hpp"
#include "qiling/exception.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/arch/register.hpp"

namespace qiling {

class Qiling;

// RAII unicorn instance (uc_open/uc_close) — the Uc analogue.
struct UcDeleter {
    void operator()(uc_engine* uc) const noexcept;
};
using UcHandle = std::unique_ptr<uc_engine, UcDeleter>;

// RAII unicorn CPU context (uc_context_alloc/save/restore/free) — the UcContext
// analogue used by QlArch::save/restore.
class UcContext {
public:
    UcContext() noexcept = default;
    UcContext(uc_engine& uc, uc_context* ctx) noexcept;
    ~UcContext();
    UcContext(UcContext&& other) noexcept;
    UcContext& operator=(UcContext&& other) noexcept;
    UcContext(const UcContext&) = delete;
    UcContext& operator=(const UcContext&) = delete;

    uc_context* get() const noexcept { return ctx_; }

private:
    uc_engine* uc_ = nullptr;
    uc_context* ctx_ = nullptr;
};

class QlArch {
public:
    // Python: QlArch(ql, *, cputype=None). The cpu model value is stored numerically
    // (models.hpp enums cast to their UC_CPU_* values). Null ql is accepted until
    // the Phase 3 composition root wires the object graph.
    QlArch(Qiling* ql, std::optional<std::uint32_t> cputype = std::nullopt);
    virtual ~QlArch() = default;

    // ClassVar[QL_ARCH] / ClassVar[int] — the per-arch type and word size
    virtual QL_ARCH type() const noexcept = 0;
    virtual int bits() const noexcept = 0;

    // Get unicorn instance bound to arch.
    virtual uc_engine& uc() = 0;

    // Architectural registers.
    virtual QlRegisterManager& regs() = 0;

    int pointersize() const noexcept { return bits() / 8; }

    // Unicorn's CPU state save / restore (arch.py save/restore)
    std::unique_ptr<UcContext> save();
    void restore(const UcContext& saved_context);

    // Get disassembler instance bound to arch (the Cs analogue; qiling/arch/utils.hpp).
    virtual class Cs& disassembler() = 0;
    // Get assembler instance bound to arch (the Ks analogue).
    virtual class Ks& assembler() = 0;

    // Get processor endianness.
    virtual QL_ENDIAN endian() const noexcept = 0;

    // stack push/pop/read/write (arch.py) — require ql.mem (Phase 2 wiring);
    // throw QlErrorBase while the composition root has not attached a memory
    // manager. Declared for interface parity; exercised from Phase 2 tests.
    std::uint64_t stack_push(std::uint64_t value);
    std::uint64_t stack_pop();
    std::uint64_t stack_read(std::int64_t offset) const;
    void stack_write(std::int64_t offset, std::uint64_t value);

    // the cpu model value applied via uc_ctl_set_cpu_model (nullopt when default)
    const std::optional<std::uint32_t>& cpu() const noexcept { return cputype_; }

protected:
    Qiling* ql_;

private:
    std::optional<std::uint32_t> cputype_;
};

}  // namespace qiling

#endif  // QILING_ARCH_ARCH_HPP
