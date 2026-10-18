// Ported from qiling/hw/misc/cm_scb.py (CortexMScb) + hw/misc/cm4_scb.py
// (CortexM4Scb). The SCB carries the system-control-block register image; the
// negative-IRQn walks (enable/pending/priority) delegate here from the NVIC.
// The ICSR write with the PENDSVSET bit rides back into the nvic (the
// upstream's ql.hw.nvic entity lookup).
//
// The port's Type structure is the hand-laid 148-byte image (the upstream
// ctypes struct): CPUID@0, ICSR@4, VTOR@8, AIRCR@12, SCR@16, CCR@20,
// SHP@24(12), SHCSR@36, CFSR@40, HFSR@44, DFSR@48, MMFAR@52, BFAR@56,
// AFSR@60, PFR@64(16), DFR@80, ADR@84, MMFR@88(16), ISAR@104(20),
// RESERVED0@124(20), CPACR@144.
#pragma once

#ifndef QILING_HW_CM_SCB_HPP
#define QILING_HW_CM_SCB_HPP

#include "qiling/arch/arm.hpp"
#include "qiling/hw/peripheral.hpp"

namespace qiling {
namespace hw {

class CortexMNvic;  // the ICSR write path rides the nvic (the .cpp resolves)

// hw/misc/cm_scb.py CortexMScb
class CortexMScb : public QlPeripheral {
public:
    // the CM4 image size (the upstream ctypes.sizeof(CortexM4Scb.Type))
    static constexpr std::size_t kStructSize = 148;
    static constexpr std::uint64_t kIcsrOffset = 4;
    static constexpr std::uint64_t kShcsrOffset = 36;
    static constexpr std::uint64_t kShpOffset = 24;

    CortexMScb(Qiling& ql, const std::string& label) : QlPeripheral(ql, label, kStructSize) {}

    // ---- the negative-IRQn walks (called from the nvic) ----

    // cm_scb.py enable: the SHCSR fault-enable bits
    void enable(int IRQn) {
        if (IRQn == static_cast<int>(IRQ::USAGE_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 18));
        }
        if (IRQn == static_cast<int>(IRQ::BUS_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 17));
        }
        if (IRQn == static_cast<int>(IRQ::MEMORY_MANAGEMENT_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 16));
        }
    }

    void disable(int IRQn) {
        if (IRQn == static_cast<int>(IRQ::USAGE_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 18));
        }
        if (IRQn == static_cast<int>(IRQ::BUS_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 17));
        }
        if (IRQn == static_cast<int>(IRQ::MEMORY_MANAGEMENT_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 16));
        }
    }

    // cm_scb.py get_enable: the SHCSR bit or the default-enabled 1
    std::uint64_t get_enable(int IRQn) const {
        if (IRQn == static_cast<int>(IRQ::USAGE_FAULT)) {
            return (raw_read(kShcsrOffset, 4) >> 18) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::BUS_FAULT)) {
            return (raw_read(kShcsrOffset, 4) >> 17) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::MEMORY_MANAGEMENT_FAULT)) {
            return (raw_read(kShcsrOffset, 4) >> 16) & 1;
        }
        return 1;
    }

    // cm_scb.py set_pending: the ICSR set+clear pairs for NMI/PendSV/SysTick,
    // the SHCSR pending bits for the fault/svc families
    void set_pending(int IRQn) {
        if (IRQn == static_cast<int>(IRQ::NMI)) {
            const auto v = raw_read(kIcsrOffset, 4);
            raw_write(kIcsrOffset, 4, v | (1ull << 31));
        }
        if (IRQn == static_cast<int>(IRQ::PENDSV)) {
            const auto v = raw_read(kIcsrOffset, 4);
            raw_write(kIcsrOffset, 4, v | (3ull << 27));  // set-bit and clear-bit
        }
        if (IRQn == static_cast<int>(IRQ::SYSTICK)) {
            const auto v = raw_read(kIcsrOffset, 4);
            raw_write(kIcsrOffset, 4, v | (3ull << 25));  // set-bit and clear-bit
        }

        if (IRQn == static_cast<int>(IRQ::MEMORY_MANAGEMENT_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 13));
        }
        if (IRQn == static_cast<int>(IRQ::BUS_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 14));
        }
        if (IRQn == static_cast<int>(IRQ::USAGE_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 12));
        }
        if (IRQn == static_cast<int>(IRQ::SVCALL)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v | (1ull << 15));
        }
    }

    void clear_pending(int IRQn) {
        if (IRQn == static_cast<int>(IRQ::NMI)) {
            const auto v = raw_read(kIcsrOffset, 4);
            raw_write(kIcsrOffset, 4, v & ~(1ull << 31));
        }
        if (IRQn == static_cast<int>(IRQ::PENDSV)) {
            const auto v = raw_read(kIcsrOffset, 4);
            raw_write(kIcsrOffset, 4, v & ~(3ull << 27));
        }
        if (IRQn == static_cast<int>(IRQ::SYSTICK)) {
            const auto v = raw_read(kIcsrOffset, 4);
            raw_write(kIcsrOffset, 4, v & ~(3ull << 25));
        }

        if (IRQn == static_cast<int>(IRQ::MEMORY_MANAGEMENT_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 13));
        }
        if (IRQn == static_cast<int>(IRQ::BUS_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 14));
        }
        if (IRQn == static_cast<int>(IRQ::USAGE_FAULT)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 12));
        }
        if (IRQn == static_cast<int>(IRQ::SVCALL)) {
            const auto v = raw_read(kShcsrOffset, 4);
            raw_write(kShcsrOffset, 4, v & ~(1ull << 15));
        }
    }

    // cm_scb.py get_pending: the ICSR bits for NMI (31) / PendSV (28) /
    // SysTick (26), the SHCSR bits for the fault/svc families
    std::uint64_t get_pending(int IRQn) const {
        if (IRQn == static_cast<int>(IRQ::NMI)) {
            return (raw_read(kIcsrOffset, 4) >> 31) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::PENDSV)) {
            return (raw_read(kIcsrOffset, 4) >> 28) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::SYSTICK)) {
            return (raw_read(kIcsrOffset, 4) >> 26) & 1;
        }

        if (IRQn == static_cast<int>(IRQ::MEMORY_MANAGEMENT_FAULT)) {
            return (raw_read(kShcsrOffset, 4) >> 13) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::BUS_FAULT)) {
            return (raw_read(kShcsrOffset, 4) >> 14) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::USAGE_FAULT)) {
            return (raw_read(kShcsrOffset, 4) >> 12) & 1;
        }
        if (IRQn == static_cast<int>(IRQ::SVCALL)) {
            return (raw_read(kShcsrOffset, 4) >> 15) & 1;
        }
        return 0;
    }

    // cm_scb.py get_priority: the SHP byte at (IRQn & 0xf) - 4
    std::uint64_t get_priority(int IRQn) const {
        return raw_read(kShpOffset + static_cast<std::uint64_t>((IRQn & 0xf) - 4), 1);
    }

    // cm_scb.py write (the @monitor() body): the ICSR PENDSVSET rides back
    // into the nvic, then the plain store
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

protected:
    // cm4_scb.py __init__: the verbatim instance seed
    void seed_cm4_defaults() {
        raw_write(0, 4, 0x410FC241ull);      // CPUID
        raw_write(12, 4, 0xFA050000ull);     // AIRCR
        raw_write(20, 4, 0x00000200ull);     // CCR
    }
};

// hw/misc/cm4_scb.py CortexM4Scb — the CM4 image with the seeded defaults
class CortexM4Scb final : public CortexMScb {
public:
    CortexM4Scb(Qiling& ql, const std::string& label) : CortexMScb(ql, label) {
        seed_cm4_defaults();
    }
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_CM_SCB_HPP
