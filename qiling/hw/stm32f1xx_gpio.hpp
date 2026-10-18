// Ported from qiling/hw/gpio/stm32f1xx_gpio.py (STM32F1xxGpio) and
// hw/gpio/stm32f1xx_afio.py (STM32F1xxAfio). The 28-byte GPIO image
// (CRL/CRH/IDR/ODR/BSRR/BRR/LCKR); the BSRR writes ride the per-bit
// set/reset walk, the ODR writes ride the diff walk firing the pin hooks,
// the IDR writes are ignored. The AFIO carries the EXTICR mapping walk
// (the exti(index) → the gpio port entity).
#pragma once

#ifndef QILING_HW_STM32F1XX_GPIO_HPP
#define QILING_HW_STM32F1XX_GPIO_HPP

#include "qiling/hw/gpio_hooks.hpp"
#include "qiling/hw/peripheral.hpp"

namespace qiling {
namespace hw {

// hw/gpio/stm32f1xx_gpio.py STM32F1xxGpio
class STM32F1xxGpio final : public QlPeripheral, public GpioHooks {
public:
    static constexpr std::size_t kStructSize = 28;
    static constexpr std::uint64_t kCrlOffset = 0;
    static constexpr std::uint64_t kCrhOffset = 4;
    static constexpr std::uint64_t kIdrOffset = 8;
    static constexpr std::uint64_t kOdrOffset = 12;
    static constexpr std::uint64_t kBsrrOffset = 16;
    static constexpr std::uint64_t kBrrOffset = 20;
    static constexpr std::uint64_t kLckrOffset = 24;

    explicit STM32F1xxGpio(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize), GpioHooks(16) {}

    // the monitor-decorated read body: the BSRR reads as 0
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override {
        if (offset == kBsrrOffset) {
            return 0;
        }
        return QlPeripheral::read_body(offset, size);
    }

    // the monitor-decorated write body: the IDR ignored, the BSRR bit walk,
    // the ODR diff walk (the hooks fire on the flips)
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // gpio.py set_pin: the ODR + the IDR bits + the set hook
    void set_pin(int i) {
        const auto odr = raw_read(kOdrOffset, 4);
        raw_write(kOdrOffset, 4, odr | (1ull << i));
        const auto idr = raw_read(kIdrOffset, 4);
        raw_write(kIdrOffset, 4, idr | (1ull << i));
        call_hook_set(static_cast<std::size_t>(i));
    }

    // gpio.py reset_pin: the ODR + the IDR bits + the reset hook
    void reset_pin(int i) {
        const auto odr = raw_read(kOdrOffset, 4);
        raw_write(kOdrOffset, 4, odr & ~(1ull << i));
        const auto idr = raw_read(kIdrOffset, 4);
        raw_write(kIdrOffset, 4, idr & ~(1ull << i));
        call_hook_reset(static_cast<std::size_t>(i));
    }

    // gpio.py pin: the ODR bit
    std::uint64_t pin(int index) const {
        return (raw_read(kOdrOffset, 4) >> index) & 1;
    }
};

// hw/gpio/stm32f1xx_afio.py STM32F1xxAfio — the EVCR/MAPR/EXTICR[4]/pad/MAPR2
// image (32 bytes); the exti(index) walks the EXTICR nibble to the gpio port
class STM32F1xxAfio final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 32;
    static constexpr std::uint64_t kEvcrOffset = 0;
    static constexpr std::uint64_t kMaprOffset = 4;
    static constexpr std::uint64_t kExticrOffset = 8;
    static constexpr std::uint64_t kMapr2Offset = 28;

    explicit STM32F1xxAfio(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}

    // afio.py exti: the gpio port entity owning the EXTI{index} mapping (the
    // verbatim unmasked nibble shift; the upstream raises IndexError on the
    // out-of-range port, the port mirrors with a throw)
    QlPeripheral* exti(int index);
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F1XX_GPIO_HPP
