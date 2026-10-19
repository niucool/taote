// Ported from qiling/hw/intc/stm32f1xx_exti.py (STM32F1xxExti). The 24-byte
// image (IMR/EMR/RTSR/FTSR/SWIER/PR); the SWIER write rides the per-bit
// send_interrupt walk, the PR writes clear the pending + the SWIER bits, and
// the send_interrupt checks the IMR, sets the PR, mirrors the pin into the
// owning gpio port (the afio's exti mapping) and pends the nvic.
#pragma once

#ifndef QILING_HW_STM32F1XX_EXTI_HPP
#define QILING_HW_STM32F1XX_EXTI_HPP

#include "qiling/hw/peripheral.hpp"

#include <array>

namespace qiling {
namespace hw {

class STM32F1xxExti final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 24;
    static constexpr std::uint64_t kImrOffset = 0;
    static constexpr std::uint64_t kEmrOffset = 4;
    static constexpr std::uint64_t kRtsrOffset = 8;
    static constexpr std::uint64_t kFtsrOffset = 12;
    static constexpr std::uint64_t kSwierOffset = 16;
    static constexpr std::uint64_t kPrOffset = 20;
    static constexpr int kMaxLine = 20;

    // the per-line interrupt numbers (the upstream ctor kwargs: the exti0..4
    // single lines, the 9_5 and the 15_10 shared lines; the absent = -1)
    explicit STM32F1xxExti(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {
        intn_.fill(-1);
    }

    void set_line_intn(int line, std::int64_t intn) {
        if (line >= 0 && line < 16) {
            intn_[static_cast<std::size_t>(line)] = intn;
        }
    }

    void set_shared_intn(std::int64_t exti9_5, std::int64_t exti15_10) {
        for (int i = 5; i <= 9; ++i) {
            intn_[static_cast<std::size_t>(i)] = exti9_5;
        }
        for (int i = 10; i <= 15; ++i) {
            intn_[static_cast<std::size_t>(i)] = exti15_10;
        }
    }

    // exti.py read: the plain memmove (the defaults ride)

    // exti.py write: the SWIER per-bit walk + the PR clear walk
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // exti.py send_interrupt: the IMR gate + the PR set + the gpio mirror +
    // the nvic pending
    void send_interrupt(int index);

private:
    std::array<std::int64_t, 16> intn_;
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F1XX_EXTI_HPP
