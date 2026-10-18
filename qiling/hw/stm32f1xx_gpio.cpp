// The implementation half of stm32f1xx_gpio.hpp (the write walks + the AFIO
// exti mapping).
#include "qiling/hw/stm32f1xx_gpio.hpp"

#include "qiling/hw/hw.hpp"

namespace qiling {
namespace hw {

void STM32F1xxGpio::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // gpio.py write: the IDR writes are ignored
    if (offset == kIdrOffset) {
        return;
    }

    if (offset == kBsrrOffset) {
        // the BSRR bit walk: the low half sets, the high half resets
        for (int i = 0; i < 32; ++i) {
            if (((value >> i) & 1) == 0) {
                continue;
            }
            if (i < 16) {
                set_pin(i);
            } else {
                reset_pin(i - 16);
            }
        }
        return;
    }

    if (offset == kOdrOffset) {
        // the ODR diff walk: the flips fire the pin hooks
        const auto old_odr = raw_read(kOdrOffset, 4);
        for (int i = 0; i < 16; ++i) {
            const auto new_bit = (value >> i) & 1;
            const auto old_bit = (old_odr >> i) & 1;

            if (new_bit != old_bit) {
                if (new_bit != 0) {
                    set_pin(i);
                } else {
                    reset_pin(i);
                }
            }
        }
        return;
    }

    QlPeripheral::write_body(offset, size, value);
}

QlPeripheral* STM32F1xxAfio::exti(int index) {
    // afio.py exti: the verbatim unmasked nibble shift — the port index from
    // the EXTICR nibble, the gpio{a..g} entity lookup (the upstream raises
    // IndexError on the out-of-range port — the port mirrors with a throw)
    const auto port_index = (raw_read(kExticrOffset + static_cast<std::uint64_t>(index / 4) * 4, 4) >>
                             ((index & 3) * 4));
    static const char* const kPortLetters = "abcdefg";
    if (port_index >= 7) {
        throw QlErrorBase("afio: the exti port index is out of range (" + std::to_string(port_index) + ")");
    }

    const std::string port_name = std::string("gpio") + kPortLetters[port_index];
    return ql().hw() != nullptr ? ql().hw()->peripheral(port_name) : nullptr;
}

}  // namespace hw
}  // namespace qiling
