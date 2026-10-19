// Ported from qiling/hw/timer/stm32f4xx_tim.py (STM32F4xxTim) and
// hw/timer/stm32f1xx_tim.py (the verbatim pass-through). The 21-register
// timer image; the step walks the CEN-enabled down/up count against the ARR
// with the prescaler division, the ARR match resets the CNT and rides the
// update interrupt (the DIER.UIE + the SR.UIF + the nvic pending).
#pragma once

#ifndef QILING_HW_STM32F4XX_TIM_HPP
#define QILING_HW_STM32F4XX_TIM_HPP

#include "qiling/hw/cm_systick.hpp"  // the QlTimerPeripheral base
#include "qiling/hw/const_stm32f4xx_tim.hpp"
#include "qiling/hw/hw.hpp"

#include <algorithm>

namespace qiling {
namespace hw {

class STM32F4xxTim : public QlTimerPeripheral {
public:
    // the 21 u32 fields (the CR1..OR layout per the upstream Type)
    static constexpr std::size_t kStructSize = 21 * 4;
    static constexpr std::uint64_t kCr1Offset = 0;
    static constexpr std::uint64_t kDierOffset = 12;
    static constexpr std::uint64_t kSrOffset = 16;
    static constexpr std::uint64_t kCntOffset = 36;
    static constexpr std::uint64_t kPscOffset = 40;
    static constexpr std::uint64_t kArrOffset = 44;

    STM32F4xxTim(Qiling& ql, const std::string& label, std::int64_t intn = -1, std::int64_t brk_intn = -1,
                 std::int64_t cc_intn = -1, std::int64_t trg_com_intn = -1, std::int64_t up_intn = -1)
        : QlTimerPeripheral(ql, label, kStructSize) {
        // the verbatim derived-interrupt chain: the absent slots ride intn
        intn_ = intn;
        brk_intn_ = brk_intn >= 0 ? brk_intn : intn;
        cc_intn_ = cc_intn >= 0 ? cc_intn : intn;
        trg_com_intn_ = trg_com_intn >= 0 ? trg_com_intn : intn;
        up_intn_ = up_intn >= 0 ? up_intn : intn;
    }

    // timer.py set_ratio override: the CNT + the prescale counter reset
    void set_ratio(std::uint64_t ratio) override {
        raw_write(kCntOffset, 4, 0);
        prescale_count_ = 0;
        QlTimerPeripheral::set_ratio(ratio);
    }

    // timer.py ratio override: the prescaler division (the rounded)
    std::uint64_t ratio() const noexcept override {
        const auto psc = raw_read(kPscOffset, 4);
        const auto div = psc + 1;
        return std::max((ratio_ + div / 2) / div, 1ull);
    }

    // timer.py prescale: the inverse division
    std::uint64_t prescale() const {
        const auto psc = raw_read(kPscOffset, 4);
        const auto q = (psc + 1 + ratio_ / 2) / ratio_;
        return q > 1 ? q - 1 : 0;
    }

    // timer.py read/write: the plain monitor bodies (the defaults ride)

    // timer.py send_update_interrupt: the DIER.UIE + the SR.UIF + the nvic
    void send_update_interrupt();

    // timer.py step: the CEN-gated count walk
    void step() override;

protected:
    std::int64_t intn_ = -1;
    std::int64_t brk_intn_ = -1;
    std::int64_t cc_intn_ = -1;
    std::int64_t trg_com_intn_ = -1;
    std::int64_t up_intn_ = -1;
    std::uint64_t prescale_count_ = 0;
};

// hw/timer/stm32f1xx_tim.py STM32F1xxTim — the verbatim pass-through
using STM32F1xxTim = STM32F4xxTim;

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F4XX_TIM_HPP
