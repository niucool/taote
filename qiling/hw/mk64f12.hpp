// Ported from qiling/hw/{char,gpio,spi,timer,analog,misc}/mk64f12_*.py (the
// MK64F12 Kinetis board's peripheral family) and hw/const/mk64f12_*.py.
// The struct sizes ride the upstream ctypes layouts.
#pragma once

#ifndef QILING_HW_MK64F12_HPP
#define QILING_HW_MK64F12_HPP

#include "qiling/hw/cm_systick.hpp"  // the QlTimerPeripheral base
#include "qiling/hw/connectivity.hpp"
#include "qiling/hw/gpio_hooks.hpp"
#include "qiling/hw/peripheral.hpp"

namespace qiling {
namespace hw {

// hw/const/mk64f12_uart.py
namespace mk64f12_uart {
namespace s1 {
inline constexpr std::uint32_t RDRF = 1u << 5;
inline constexpr std::uint32_t TC = 1u << 6;
inline constexpr std::uint32_t TDRE = 1u << 7;
}  // namespace s1

namespace c2 {
inline constexpr std::uint32_t RIE = 1u << 5;
}  // namespace c2

namespace pfifo {
inline constexpr std::uint32_t RXFE = 1u << 3;
}  // namespace pfifo
}  // namespace mk64f12_uart

// hw/const/mk64f12_port.py
namespace mk64f12_port {
namespace pcr {
inline constexpr std::uint32_t IRQC = 0xfu << 16;
}  // namespace pcr

// the InterruptMode table (the modes the send_interrupt walk answers)
enum class InterruptMode : std::uint32_t {
    InterruptOrDMADisabled = 0x0,
    DMARisingEdge = 0x1,
    DMAFallingEdge = 0x2,
    DMAEitherEdge = 0x3,
    FlagRisingEdge = 0x5,
    FlagFallingEdge = 0x6,
    FlagEitherEdge = 0x7,
    InterruptLogicZero = 0x8,
    InterruptRisingEdge = 0x9,
    InterruptFallingEdge = 0xA,
    InterruptEitherEdge = 0xB,
    InterruptLogicOne = 0xC,
};
}  // namespace mk64f12_port

// hw/const/mk64f12_spi.py
namespace mk64f12_spi {
namespace sr {
inline constexpr std::uint32_t RXCTR = 0xfu << 4;
inline constexpr std::uint32_t TFFF = 1u << 25;
inline constexpr std::uint32_t RFDF = 1u << 17;
}  // namespace sr

namespace pushr {
inline constexpr std::uint32_t TXDATA = 0xffffu << 0;
}  // namespace pushr
}  // namespace mk64f12_spi

// hw/const/mk64f12_mcg.py
namespace mk64f12_mcg {
namespace c1 {
inline constexpr std::uint32_t IREFS = 1u << 2;
inline constexpr std::uint32_t CLKS = 0x3u << 6;
inline constexpr std::uint32_t CLKS_Pos = 6;
}  // namespace c1

namespace s {
inline constexpr std::uint32_t CLKST = 0x3u << 2;
inline constexpr std::uint32_t IREFST = 1u << 4;
inline constexpr std::uint32_t PLLST = 1u << 5;
inline constexpr std::uint32_t LOCK0 = 1u << 6;
inline constexpr std::uint32_t CLKST_Pos = 2;
inline constexpr std::uint32_t IREFST_Pos = 4;
}  // namespace s

namespace c5 {
inline constexpr std::uint32_t PLLCLKEN0 = 1u << 6;
}  // namespace c5

namespace c6 {
inline constexpr std::uint32_t PLLS = 1u << 6;
}  // namespace c6
}  // namespace mk64f12_mcg

// hw/const/mk64f12_adc.py
namespace mk64f12_adc {
namespace sc1 {
inline constexpr std::uint32_t COCO = 1u << 7;
}  // namespace sc1

namespace sc3 {
inline constexpr std::uint32_t CAL = 1u << 7;
}  // namespace sc3
}  // namespace mk64f12_adc

// char/mk64f12_uart.py — the 32-byte image (the D at 0x7); the S1 seed
// TDRE|TC; the D write rides the output tube, the D read rides the RXFE/RCFIFO
// or the S1.RDRF clear + the input tube; the step walks the C2.RIE pend
class Mk64f12Uart final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 32;
    static constexpr std::uint64_t kDOffset = 0x07;

    Mk64f12Uart(Qiling& ql, const std::string& label, std::int64_t lon_intn = -1,
                std::int64_t rx_tx_intn = -1, std::int64_t err_intn = -1)
        : QlConnectivityPeripheral(ql, label, kStructSize),
          lon_intn_(lon_intn), rx_tx_intn_(rx_tx_intn), err_intn_(err_intn) {
        raw_write(0x04, 1, mk64f12_uart::s1::TDRE | mk64f12_uart::s1::TC);  // the S1 (the u8 field)
    }

    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;
    void step() override;

    std::int64_t rx_tx_intn() const noexcept { return rx_tx_intn_; }

private:
    std::int64_t lon_intn_;
    std::int64_t rx_tx_intn_;
    std::int64_t err_intn_;
};

// gpio/mk64f12_gpio.py — the 24-byte image (the PDOR/PSOR/PCOR/PTOR/PDIR/
// PDDR u32s); the PSOR/PCOR/PTOR writes loop all 32 pins verbatim (the
// upstream doesn't mask by the value); the pin rides the PDDR ? PDOR : PDIR
class Mk64f12Gpio final : public QlPeripheral, public GpioHooks {
public:
    static constexpr std::size_t kStructSize = 24;
    static constexpr std::uint64_t kPdorOffset = 0x00;
    static constexpr std::uint64_t kPsorOffset = 0x04;
    static constexpr std::uint64_t kPcorOffset = 0x08;
    static constexpr std::uint64_t kPtorOffset = 0x0C;
    static constexpr std::uint64_t kPdirOffset = 0x10;
    static constexpr std::uint64_t kPddrOffset = 0x14;

    Mk64f12Gpio(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), GpioHooks(32), intn_(intn) {}

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // gpio.py set_pin/reset_pin/pin; the port walk rides the label tail
    void set_pin(std::size_t i);
    void reset_pin(std::size_t i);
    std::uint32_t pin(std::size_t index) const;

    // gpio.py: the port lookup rides the label tail (the label "gpioa" →
    // the "porta" entity)
    QlPeripheral* port();

private:
    std::int64_t intn_;
};

// gpio/mk64f12_port.py — the 204-byte image (the PCR[32] + the GPCLR/GPCHR +
// the ISFR/DFER block); the send_interrupt walk rides the PCR.IRQC modes
class Mk64f12Port final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 204;
    static constexpr std::uint64_t kPcrOffset = 0x00;

    Mk64f12Port(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {}

    // port.py pin_interrupt_config / send_interrupt
    std::uint32_t pin_interrupt_config(std::size_t index) const;
    void send_interrupt(std::size_t index, std::uint32_t prev, std::uint32_t curr);

private:
    std::int64_t intn_;
};

// spi/mk64f12_spi.py — the 140-byte image; the POPR read clears the RFDF/
// RXCTR and rides the input tube; the PUSHR write rides the TXDATA; the CTAR
// write sets the SR.TFFF; the step walks the RFDF/RXCTR on the input
class Mk64f12Spi final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 140;
    static constexpr std::uint64_t kPoprOffset = 0x38;
    static constexpr std::uint64_t kPushrOffset = 0x34;
    static constexpr std::uint64_t kCtarOffset = 0x0C;

    Mk64f12Spi(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlConnectivityPeripheral(ql, label, kStructSize), intn_(intn) {}

    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;
    void step() override;

private:
    std::int64_t intn_;
};

// timer/mk64f12_ftm.py — the 156-byte image over the QlTimerPeripheral (the
// ratio base); the step walks the MODE.FTMEN + the SC.CLKS + the CNT/PS
class Mk64f12Ftm final : public QlTimerPeripheral {
public:
    static constexpr std::size_t kStructSize = 156;

    Mk64f12Ftm(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlTimerPeripheral(ql, label, kStructSize), intn_(intn) {}

    void step() override;

private:
    std::int64_t intn_;
};

// analog/mk64f12_adc.py — the 112-byte image (the SC1[2] pair at 0, the R
// pair with the 0x7ff seeds); the SC1 write is a no-op, the SC3.CAL rides the
// SC1 COCO bits
class Mk64f12Adc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 112;
    static constexpr std::uint64_t kSc1Offset = 0x00;   // the SC1[0]
    static constexpr std::uint64_t kSc1bOffset = 0x04;  // the SC1[1]
    static constexpr std::uint64_t kSc3Offset = 0x24;
    static constexpr std::uint64_t kR0Offset = 0x10;  // the DAT0/R0 pair rides the 0x7ff seeds

    Mk64f12Adc(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {
        raw_write(kR0Offset + 8, 4, 0x7ff);  // the R1 seed (the R0 rides the default 0x7ff? no —
                                             // the upstream seeds BOTH via the struct kwargs)
        raw_write(kR0Offset, 4, 0x7ff);
    }

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::int64_t intn_;
};

// misc/mk64f12_mcg.py — the 14-byte image; the C1/C5/C6 walks ride the S
// status bits
class Mk64f12Mcg final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 14;
    static constexpr std::uint64_t kC1Offset = 0x02;

    Mk64f12Mcg(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {}

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::int64_t intn_;
};

// misc/mk64f12_sim.py — the plain 4196-byte image
class Mk64f12Sim final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 4196;

    Mk64f12Sim(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {}

private:
    std::int64_t intn_;
};

// misc/mk64f12_smc.py — the plain 4-byte image
class Mk64f12Smc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 4;

    Mk64f12Smc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// misc/mk64f12_wdog.py — the plain 24-byte image
class Mk64f12Wdog final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 24;

    Mk64f12Wdog(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// timer/mk64f12_osc.py — the plain 1-byte image
class Mk64f12Osc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 1;

    Mk64f12Osc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// timer/mk64f12_rtc.py — the plain 40-byte image
class Mk64f12Rtc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 40;

    Mk64f12Rtc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_MK64F12_HPP
