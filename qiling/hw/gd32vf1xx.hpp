// Ported from qiling/hw/{char,gpio,spi,i2c,dma,math,misc,timer,intc}/
// gd32vf1xx_*.py (the GD32VF103 board's peripheral family). The classes ride
// the plain register images over the connectivity base (the usart/spi/i2c)
// and the plain QlPeripheral (the dma/crc/rcu/rtc/timer/eclic), with the
// Gpio carrying the OCTL/BOP pin walks.
#pragma once

#ifndef QILING_HW_GD32VF1XX_HPP
#define QILING_HW_GD32VF1XX_HPP

#include "qiling/hw/connectivity.hpp"
#include "qiling/hw/gpio_hooks.hpp"
#include "qiling/hw/peripheral.hpp"

namespace qiling {
namespace hw {

// char/gd32vf1xx_usart.py — the 28-byte image; the STAT seed 0xc0 (the TC|
// TXE bits)
class Gd32vf1xxUsart final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 28;

    Gd32vf1xxUsart(Qiling& ql, const std::string& label)
        : QlConnectivityPeripheral(ql, label, kStructSize) {
        raw_write(0x00, 4, 0xc0);  // the STAT
    }
};

// spi/gd32vf1xx_spi.py — the 18-byte image; the STAT seed 0x2 (the TBE) and
// the CRCPOLY seed 7
class Gd32vf1xxSpi final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 18;

    Gd32vf1xxSpi(Qiling& ql, const std::string& label)
        : QlConnectivityPeripheral(ql, label, kStructSize) {
        raw_write(0x08, 4, 0x2);  // the STAT (the TBE)
        raw_write(0x0c, 4, 0x7);  // the CRCPOLY
    }
};

// i2c/gd32vf1xx_i2c.py — the 18-byte image; the RT seed 0x2
class Gd32vf1xxI2c final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 18;

    Gd32vf1xxI2c(Qiling& ql, const std::string& label)
        : QlConnectivityPeripheral(ql, label, kStructSize) {
        raw_write(0x14, 4, 0x2);  // the RT
    }
};

// gpio/gd32vf1xx_gpio.py — the 28-byte image; the CTL0/CTL1 0x44444444
// seeds; the GpioHooks over 16 pins; the OCTL write walks the per-bit
// transitions, the BOP write walks the low 16 set / the high 16 reset
class Gd32vf1xxGpio final : public QlPeripheral, public GpioHooks {
public:
    static constexpr std::size_t kStructSize = 28;
    static constexpr std::uint64_t kCtl0Offset = 0x00;
    static constexpr std::uint64_t kCtl1Offset = 0x04;
    static constexpr std::uint64_t kIstatOffset = 0x08;
    static constexpr std::uint64_t kOct1Offset = 0x0C;  // the OCTL
    static constexpr std::uint64_t kBopOffset = 0x10;
    static constexpr std::uint64_t kBcOffset = 0x14;

    Gd32vf1xxGpio(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize), GpioHooks(16) {
        raw_write(kCtl0Offset, 4, 0x44444444);
        raw_write(kCtl1Offset, 4, 0x44444444);
        raw_write(kOct1Offset, 4, 0x44444444);
    }

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    void set_pin(std::size_t i);
    void reset_pin(std::size_t i);
    std::uint32_t pin(std::size_t index) const;
};

// dma/gd32vf1xx_dma.py — the plain 120-byte image
class Gd32vf1xxDma final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 120;

    Gd32vf1xxDma(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// math/gd32vf1xx_crc.py — the plain 12-byte image
class Gd32vf1xxCrc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 12;

    Gd32vf1xxCrc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// misc/gd32vf1xx_rcu.py — the plain 52-byte image
class Gd32vf1xxRcu final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 52;

    Gd32vf1xxRcu(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// timer/gd32vf1xx_rtc.py — the plain 40-byte image
class Gd32vf1xxRtc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 40;

    Gd32vf1xxRtc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// timer/gd32vf1xx_timer.py — the plain 44-byte image
class Gd32vf1xxTimer final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 44;

    Gd32vf1xxTimer(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// intc/gd32vf1xx_eclic.py — the plain 360-byte image (the CLICCFG/CLICINFO/
// MTH + the per-interrupt IP/IE/CTL bytes)
class Gd32vf1xxEclic final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 360;

    Gd32vf1xxEclic(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_GD32VF1XX_HPP
