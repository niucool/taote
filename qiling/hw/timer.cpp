// Ported from qiling/hw/timer/timer.py + hw/timer/cm_systick.py (the
// implementation half of cm_systick.hpp).
#include "qiling/hw/cm_systick.hpp"
#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"

#include <cstring>

namespace qiling {
namespace hw {

void CortexMSysTick::step() {
    const auto ctrl = static_cast<std::uint32_t>(raw_read(0, 4));
    if (!(ctrl & systick_ctrl::ENABLE)) {
        return;
    }

    const auto val = static_cast<std::int64_t>(raw_read(8, 4));
    if (val <= 0) {
        const auto c = static_cast<std::uint32_t>(raw_read(0, 4));
        raw_write(0, 4, c | systick_ctrl::COUNTFLAG);
        raw_write(8, 4, raw_read(4, 4));  // VAL = LOAD
    } else {
        const auto next = static_cast<std::uint64_t>(val - ratio_);
        raw_write(8, 4, next);

        if (static_cast<std::int64_t>(next) <= 0) {
            // cm_systick.py: the TICKINT branch — the pending rides the
            // nvic entity (the negative IRQn delegates to the SCB inside)
            if ((static_cast<std::uint32_t>(raw_read(0, 4)) & systick_ctrl::TICKINT) != 0) {
                auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
                if (nvic != nullptr) {
                    dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(IRQ::SYSTICK));
                }
            }
        }
    }
}

}  // namespace hw
}  // namespace qiling
