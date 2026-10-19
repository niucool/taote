// The implementation half of gd32vf1xx.hpp (the Gpio OCTL/BOP walks; the
// remaining classes ride the base read/write).
#include "qiling/hw/gd32vf1xx.hpp"

#include <string>

namespace qiling {
namespace hw {

void Gd32vf1xxGpio::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // gpio.py: the OCTL write walks the per-bit transitions
    if (offset == kOct1Offset) {
        const auto octl = raw_read(kOct1Offset, 4);
        for (std::size_t i = 0; i < 16; ++i) {
            const auto new_bit = (value >> i) & 1;
            const auto old_bit = (octl >> i) & 1;
            if (new_bit != old_bit) {
                if (new_bit) {
                    set_pin(i);
                } else {
                    reset_pin(i);
                }
            }
        }
        return;
    }

    // gpio.py: the BOP write walks the low 16 set / the high 16 reset
    if (offset == kBopOffset) {
        for (std::size_t i = 0; i < 32; ++i) {
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

    QlPeripheral::write_body(offset, size, value);
}

void Gd32vf1xxGpio::set_pin(std::size_t i) {
    const auto octl = raw_read(kOct1Offset, 4);
    raw_write(kOct1Offset, 4, octl | (1ull << i));
    call_hook_set(i);
}

void Gd32vf1xxGpio::reset_pin(std::size_t i) {
    const auto octl = raw_read(kOct1Offset, 4);
    raw_write(kOct1Offset, 4, octl & ~(1ull << i));
    call_hook_reset(i);
}

std::uint32_t Gd32vf1xxGpio::pin(std::size_t index) const {
    return (static_cast<std::uint32_t>(raw_read(kOct1Offset, 4)) >> index) & 1;
}

}  // namespace hw
}  // namespace qiling
