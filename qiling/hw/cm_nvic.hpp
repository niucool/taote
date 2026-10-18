// Ported from qiling/hw/intc/cm_nvic.py (CortexMNvic). The NVIC rides the
// 3616-byte register image laid out per the upstream ctypes struct: ISER@0(32),
// RESERVED0@32(96), ICER@128(32), RESERVED1@160(96), ISPR@256(32),
// RESERVED2@288(96), ICPR@384(32), RESERVED3@416(96), IABR@512(32),
// RESERVED4@544(224), IPR@768(240), RESERVED5@1008(2576), STIR@3584(32).
//
// The write walk is byte-at-a-time over the trigger registers (the ISER/ICER/
// ISPR/ICPR set-bit fires); the negative IRQn delegates to the scb entity.
// The step() sorts the pending interrupts by priority, applies the basepri/
// primask/faultmask gates and dispatches through the arch interrupt handler.
#pragma once

#ifndef QILING_HW_CM_NVIC_HPP
#define QILING_HW_CM_NVIC_HPP

#include "qiling/arch/arm.hpp"
#include "qiling/hw/cm_scb.hpp"

#include <functional>
#include <vector>

namespace qiling {
namespace hw {

class CortexMNvic final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 3616;

    // the register-region offsets (the upstream ctypes struct fields)
    static constexpr std::uint64_t kIserOffset = 0;     // ISER[8] u32
    static constexpr std::uint64_t kIserSize = 32;
    static constexpr std::uint64_t kIcerOffset = 128;   // ICER[8]
    static constexpr std::uint64_t kIsprOffset = 256;   // ISPR[8]
    static constexpr std::uint64_t kIcprOffset = 384;   // ICPR[8]
    static constexpr std::uint64_t kIprOffset = 768;    // IPR[240] u8
    static constexpr std::uint64_t kIprSize = 240;
    static constexpr std::uint64_t kStirOffset = 3584;  // STIR[8]

    CortexMNvic(Qiling& ql, const std::string& label);

    // ---- the IRQn walks (the non-negative ride the instance, the negative
    // delegate to the scb) ----

    void enable(int IRQn);
    void disable(int IRQn);
    std::uint64_t get_enable(int IRQn) const;
    void set_pending(int IRQn);
    void clear_pending(int IRQn);
    std::uint64_t get_pending(int IRQn) const;
    std::uint64_t get_priority(int IRQn) const;

    // cm_nvic.py step: the priority sort + the mask gates + the dispatch
    void step() override;

    std::vector<std::pair<std::uint64_t, std::uint64_t>> region() const override {
        // cm_nvic.py region: [(0, RESERVED5.offset), (STIR.offset, sizeof)]
        return {{0, 1008}, {kStirOffset, kStructSize}};
    }

    // the pending-interrupt queue (the upstream intrs list)
    const std::vector<int>& pending_interrupts() const noexcept { return intrs_; }

protected:
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override {
        // cm_nvic.py read (the @monitor() body): the plain memmove
        return QlPeripheral::read_body(offset, size);
    }

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    // the upstream: self.interrupt_handler = self.ql.arch.interrupt_handler
    // (the bound CORTEX_M handler; the nvic ctor validates the arch)
    std::function<void(int)> interrupt_handler_;
    std::vector<int> intrs_;

    // the IRQN_MAX / MASK / OFFSET derivations (the verbatim ctor arithmetic):
    // IRQN_MAX = ISER.size * 8 = 256; MASK = 256 // 8 - 1 = 31; OFFSET = 5
    static constexpr int kIrqnMax = 256;
    static constexpr int kMask = 31;
    static constexpr int kOffset = 5;

    // the mask helpers (the IRQn & MASK bit within the ISER[IRQn >> OFFSET])
    static constexpr int reg_index(int IRQn) noexcept { return IRQn >> kOffset; }
    static constexpr std::uint64_t reg_bit(int IRQn) noexcept { return 1ull << (IRQn & kMask); }

    // the upstream self.ql.hw.scb lookup (the AttributeError when absent)
    CortexMScb& scb();
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_CM_NVIC_HPP
