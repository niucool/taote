// The implementation half of cm_nvic.hpp (the hw/intc/cm_nvic.py walks).
#include "qiling/hw/cm_nvic.hpp"

#include "qiling/hw/hw.hpp"

#include <algorithm>

namespace qiling {
namespace hw {

CortexMNvic::CortexMNvic(Qiling& ql, const std::string& label) : QlPeripheral(ql, label, kStructSize) {
    // the upstream: self.interrupt_handler = self.ql.arch.interrupt_handler —
    // the bound CORTEX_M handler; the non-CORTEX_M arch degrades to a throw
    (void)dynamic_cast<QlArchCORTEX_M&>(ql.arch());
    interrupt_handler_ = [this](int intno) {
        static_cast<QlArchCORTEX_M&>(this->ql().arch()).interrupt_handler(intno);
    };
}

CortexMScb& CortexMNvic::scb() {
    // the upstream self.ql.hw.scb: the entity lookup (the AttributeError when
    // the scb peripheral is not registered)
    auto* scb = dynamic_cast<CortexMScb*>(ql().hw()->peripheral("scb"));
    if (scb == nullptr) {
        throw QlErrorBase("the nvic requires the scb peripheral (register it under the label 'scb')");
    }
    return *scb;
}

void CortexMNvic::enable(int IRQn) {
    if (IRQn >= 0) {
        const auto idx = static_cast<std::uint64_t>(reg_index(IRQn)) * 4;
        // the verbatim quirk: the enable sets the ICER bit too
        raw_write(kIserOffset + idx, 4, raw_read(kIserOffset + idx, 4) | reg_bit(IRQn));
        raw_write(kIcerOffset + idx, 4, raw_read(kIcerOffset + idx, 4) | reg_bit(IRQn));
    } else {
        scb().enable(IRQn);
    }
}

void CortexMNvic::disable(int IRQn) {
    if (IRQn >= 0) {
        const auto idx = static_cast<std::uint64_t>(reg_index(IRQn)) * 4;
        // the verbatim quirk: the clear mask is MASK ^ (1 << (IRQn & MASK))
        // (only the low 5 bits survive the AND — the upstream arithmetic)
        const auto clear_mask = static_cast<std::uint64_t>(kMask) ^ reg_bit(IRQn);
        raw_write(kIserOffset + idx, 4, raw_read(kIserOffset + idx, 4) & clear_mask);
        raw_write(kIcerOffset + idx, 4, raw_read(kIcerOffset + idx, 4) & clear_mask);
    } else {
        scb().disable(IRQn);
    }
}

std::uint64_t CortexMNvic::get_enable(int IRQn) const {
    if (IRQn >= 0) {
        const auto idx = static_cast<std::uint64_t>(reg_index(IRQn)) * 4;
        return (raw_read(kIserOffset + idx, 4) >> (IRQn & kMask)) & 1;
    }
    return const_cast<CortexMNvic*>(this)->scb().get_enable(IRQn);
}

void CortexMNvic::set_pending(int IRQn) {
    if (IRQn >= 0) {
        const auto idx = static_cast<std::uint64_t>(reg_index(IRQn)) * 4;
        raw_write(kIsprOffset + idx, 4, raw_read(kIsprOffset + idx, 4) | reg_bit(IRQn));
        raw_write(kIcprOffset + idx, 4, raw_read(kIcprOffset + idx, 4) | reg_bit(IRQn));
    } else {
        scb().set_pending(IRQn);
    }

    // cm_nvic.py: if self.get_enable(IRQn): self.intrs.append(IRQn)
    if (get_enable(IRQn) != 0) {
        intrs_.push_back(IRQn);
    }
}

void CortexMNvic::clear_pending(int IRQn) {
    if (IRQn >= 0) {
        const auto idx = static_cast<std::uint64_t>(reg_index(IRQn)) * 4;
        raw_write(kIsprOffset + idx, 4, raw_read(kIsprOffset + idx, 4) & ~reg_bit(IRQn));
        raw_write(kIcprOffset + idx, 4, raw_read(kIcprOffset + idx, 4) & ~reg_bit(IRQn));
    } else {
        scb().clear_pending(IRQn);
    }
}

std::uint64_t CortexMNvic::get_pending(int IRQn) const {
    if (IRQn >= 0) {
        // the verbatim quirk: the pending query reads the ISER, not the ISPR
        const auto idx = static_cast<std::uint64_t>(reg_index(IRQn)) * 4;
        return (raw_read(kIserOffset + idx, 4) >> (IRQn & kMask)) & 1;
    }
    return const_cast<CortexMNvic*>(this)->scb().get_pending(IRQn);
}

std::uint64_t CortexMNvic::get_priority(int IRQn) const {
    if (IRQn >= 0) {
        return raw_read(kIprOffset + static_cast<std::uint64_t>(IRQn), 1);
    }
    return const_cast<CortexMNvic*>(this)->scb().get_priority(IRQn);
}

void CortexMNvic::step() {
    if (intrs_.empty()) {
        return;
    }

    // the priority sort (the stable order for the equal priorities keeps the
    // arrival order — the upstream sort is stable)
    std::stable_sort(intrs_.begin(), intrs_.end(), [this](int a, int b) {
        return get_priority(a) < get_priority(b);
    });

    std::vector<int> postponed;
    const auto& regs = ql().arch().regs();

    while (!intrs_.empty()) {
        const int IRQn = intrs_.front();
        intrs_.erase(intrs_.begin());

        const auto basepri = regs.read("basepri") & 0xF0;
        if ((basepri != 0 && basepri <= get_priority(IRQn)) ||
            (IRQn > static_cast<int>(IRQ::HARD_FAULT) && (regs.read("primask") & 0x1)) ||
            (IRQn != static_cast<int>(IRQ::NMI) && (regs.read("faultmask") & 0x1))) {
            postponed.push_back(IRQn);
            continue;
        }

        clear_pending(IRQn);
        interrupt_handler_(IRQn);
    }

    intrs_ = std::move(postponed);
}

void CortexMNvic::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // cm_nvic.py write: the byte walk over the trigger registers; each set
    // bit in the written byte fires the trigger function with the IRQ number
    struct Trigger {
        std::uint64_t offset;
        void (CortexMNvic::*func)(int);
    };
    static const Trigger kTriggers[] = {
        {kIserOffset, &CortexMNvic::enable},
        {kIcerOffset, &CortexMNvic::disable},
        {kIsprOffset, &CortexMNvic::set_pending},
        {kIcprOffset, &CortexMNvic::clear_pending},
    };

    auto write_byte = [&](std::uint64_t ofs, std::uint8_t byte) {
        for (const auto& trig : kTriggers) {
            if (trig.offset <= ofs && ofs < trig.offset + kIserSize) {
                for (int i = 0; i < 8; ++i) {
                    if (((byte >> i) & 1) != 0) {
                        (this->*trig.func)(static_cast<int>(i + (ofs - trig.offset) * 8));
                    }
                }
                return;  // the verbatim for/else break
            }
        }

        // the IPR walk: the low nibble reserved
        if (kIprOffset <= ofs && ofs < kIprOffset + kIprSize) {
            byte &= 0xf0;  // IPR[3:0] reserved
        }

        raw_write(ofs, 1, byte);
    };

    for (std::uint64_t ofs = offset; ofs < offset + size; ++ofs) {
        write_byte(ofs, static_cast<std::uint8_t>(value & 0xff));
        value >>= 8;
    }
}

}  // namespace hw
}  // namespace qiling
