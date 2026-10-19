// The implementation half of stm32f1xx_exti.hpp (the write walks + the
// send_interrupt ride).
#include "qiling/hw/stm32f1xx_exti.hpp"

#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"
#include "qiling/hw/stm32f1xx_gpio.hpp"

namespace qiling {
namespace hw {

void STM32F1xxExti::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kSwierOffset) {
        // exti.py: the SWIER write masked against the IMR and the 0x7ffff
        // reserved-high bits; the 0->1 transitions ride the send_interrupt
        const auto imr = raw_read(kImrOffset, 4);
        const auto swier = raw_read(kSwierOffset, 4);
        value = value & imr & 0x7ffff;
        for (int i = 0; i < kMaxLine; ++i) {
            if (((swier >> i) & 1) == 0 && ((value >> i) & 1) == 1) {
                send_interrupt(i);
            }
        }
    } else if (offset == kPrOffset) {
        // exti.py: the PR write clears the pending and the SWIER bits
        for (int i = 0; i < kMaxLine; ++i) {
            if ((value >> i) & 1) {
                const auto pr = raw_read(kPrOffset, 4);
                raw_write(kPrOffset, 4, pr & ~(1ull << i));
                const auto swier = raw_read(kSwierOffset, 4);
                raw_write(kSwierOffset, 4, swier & ~(1ull << i));
            }
        }
        return;
    }

    QlPeripheral::write_body(offset, size, value);
}

void STM32F1xxExti::send_interrupt(int index) {
    // exti.py send_interrupt: the IMR gate sets the PR, mirrors the pin into
    // the owning gpio port (the afio's EXTICR mapping) and pends the nvic
    if (!(index >= 0 && index < kMaxLine)) {
        return;
    }
    const auto imr = raw_read(kImrOffset, 4);
    if (!((imr >> index) & 1)) {
        return;
    }

    const auto pr = raw_read(kPrOffset, 4);
    raw_write(kPrOffset, 4, pr | (1ull << index));

    if (index < 16) {
        // the upstream: self.ql.hw.afio.exti(index).set_pin(index) — the
        // afio's EXTICR nibble resolves the owning gpio port and the line
        // mirrors into its pin; then the nvic pends with the line's intn
        auto* afio = ql().hw() != nullptr ? ql().hw()->peripheral("afio") : nullptr;
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (afio != nullptr) {
            auto* gpio_port = dynamic_cast<STM32F1xxAfio&>(*afio).exti(index);
            if (gpio_port != nullptr) {
                dynamic_cast<STM32F1xxGpio&>(*gpio_port).set_pin(index);
            }
        }
        if (nvic != nullptr) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_[static_cast<std::size_t>(index)]));
        }
    }
}

}  // namespace hw
}  // namespace qiling
