// The implementation half of stm32f4xx_tim.hpp (the update interrupt + the
// step walk).
#include "qiling/hw/stm32f4xx_tim.hpp"

#include "qiling/hw/cm_nvic.hpp"

namespace qiling {
namespace hw {

void STM32F4xxTim::send_update_interrupt() {
    // timer.py send_update_interrupt: the absent up_intn or the disabled UIE
    // skips; the UIF sets and the nvic pends with the up_intn
    if (up_intn_ < 0) {
        return;
    }

    const auto dier = raw_read(kDierOffset, 4);
    if (!(dier & tim::dier::UIE)) {
        return;
    }

    const auto sr = raw_read(kSrOffset, 4);
    raw_write(kSrOffset, 4, sr | tim::sr::UIF);

    auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
    if (nvic != nullptr) {
        dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(up_intn_));
    }
}

void STM32F4xxTim::step() {
    // timer.py step: the CEN-gated count walk with the prescaler division
    if (!(raw_read(kCr1Offset, 4) & tim::cr1::CEN)) {
        return;
    }

    const auto cnt = raw_read(kCntOffset, 4);
    const auto arr = raw_read(kArrOffset, 4);

    if (cnt >= arr) {
        raw_write(kCntOffset, 4, 0);
        prescale_count_ = 0;
        send_update_interrupt();
    } else if (prescale_count_ == prescale()) {
        prescale_count_ = 0;
        raw_write(kCntOffset, 4, cnt + ratio());
    } else {
        ++prescale_count_;
    }
}

}  // namespace hw
}  // namespace qiling
