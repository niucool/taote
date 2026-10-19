// Ported from qiling/hw/const/sam3xa_*.py (the bit tables the bodies walk)
// and the 12 implemented SAM3xa peripheral classes:
//   char/sam3xa_uart.py    (SAM3xaUart, the QlConnectivityPeripheral)
//   dma/sam3xa_pdc.py      (SAM3xaPdc, the plain struct)
//   misc/sam3xa_wdt.py     (SAM3xaWdt, the plain struct)
//   analog/sam3xa_adc.py   (SAM3xaAdc, the CHER/CHDR/CR-START walks)
//   analog/sam3xa_dac.py   (SAM3xaDac, the CDR write rides the EOC)
//   analog/sam3xa_pwm.py   (SAM3xaPwm, the plain struct)
//   flash/sam3xa_efc.py    (SAM3xaEfc, the plain struct)
//   gpio/sam3xa_pio.py     (SAM3xaPio, the SODR/CODR/PUER/PUDR pin walks)
//   power/sam3xa_pmc.py    (SAM3xaPmc, the clock-status write walks)
//   spi/sam3xa_spi.py      (SAM3xaSpi, the tube-paired RDR/TDR)
//   timer/sam3xa_tc.py     (SAM3xaTc, the plain struct)
//   char/sam3xa_uotghs.py  (SAM3xaUotghs, the CTRL/CLKUSABLE walk)
//
// The struct sizes ride the upstream ctypes layouts (computed: the uart 296,
// the pdc 40, the wdt 12, the adc 296, the dac 296, the pwm 768, the efc 16,
// the pio 236, the pmc 272, the spi 236, the tc 232, the uotghs 2096).
#pragma once

#ifndef QILING_HW_SAM3XA_HPP
#define QILING_HW_SAM3XA_HPP

#include "qiling/hw/connectivity.hpp"
#include "qiling/hw/gpio_hooks.hpp"
#include "qiling/hw/peripheral.hpp"

namespace qiling {
namespace hw {

// hw/const/sam3xa_uart.py
namespace sam3xa_uart {
namespace cr {
inline constexpr std::uint32_t RXEN = 1u << 4;
inline constexpr std::uint32_t TXEN = 1u << 6;
}  // namespace cr

namespace sr {
inline constexpr std::uint32_t RXRDY = 1u << 0;
inline constexpr std::uint32_t TXRDY = 1u << 1;
}  // namespace sr

namespace ier {
inline constexpr std::uint32_t RXRDY = 1u << 0;
}  // namespace ier
}  // namespace sam3xa_uart

// hw/const/sam3xa_adc.py
namespace sam3xa_adc {
namespace cr {
inline constexpr std::uint32_t START = 1u << 1;
}  // namespace cr

namespace isr {
inline constexpr std::uint32_t DRDY = 1u << 24;
}  // namespace isr
}  // namespace sam3xa_adc

// hw/const/sam3xa_dac.py
namespace sam3xa_dac {
namespace isr {
inline constexpr std::uint32_t EOC = 1u << 0;  // the EOC0 (the channel-0 shape)
}  // namespace isr
}  // namespace sam3xa_dac

// hw/const/sam3xa_pmc.py
namespace sam3xa_pmc {
namespace ckgr_mor {
inline constexpr std::uint32_t MOSCXTEN = 1u << 0;
inline constexpr std::uint32_t MOSCSEL = 1u << 24;
}  // namespace ckgr_mor

namespace sr {
inline constexpr std::uint32_t MOSCXTS = 1u << 0;
inline constexpr std::uint32_t LOCKA = 1u << 1;
inline constexpr std::uint32_t MCKRDY = 1u << 3;
inline constexpr std::uint32_t LOCKU = 1u << 6;
inline constexpr std::uint32_t MOSCSELS = 1u << 16;
}  // namespace sr

namespace mckr {
inline constexpr std::uint32_t CSS = 1u << 0;
}  // namespace mckr

namespace ckgr_pllar {
inline constexpr std::uint32_t ONE = 1u << 29;
}  // namespace ckgr_pllar

namespace ckgr_uckr {
inline constexpr std::uint32_t UPLLEN = 1u << 16;
}  // namespace ckgr_uckr
}  // namespace sam3xa_pmc

// hw/const/sam3xa_spi.py
namespace sam3xa_spi {
namespace sr {
inline constexpr std::uint32_t RDRF = 1u << 0;
inline constexpr std::uint32_t TDRE = 1u << 1;
}  // namespace sr

namespace tdr {
inline constexpr std::uint32_t TD = 0xffffu << 0;
}  // namespace tdr
}  // namespace sam3xa_spi

// hw/const/sam3xa_uotghs.py
namespace sam3xa_uotghs {
namespace sr {
inline constexpr std::uint32_t CLKUSABLE = 1u << 14;
}  // namespace sr
}  // namespace sam3xa_uotghs

// char/sam3xa_uart.py SAM3xaUart — the 296-byte image; the PDC block rides
// the same instance (the RPR..PTSR tail at 0x100)
class Sam3xaUart final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 296;
    static constexpr std::uint64_t kCrOffset = 0x00;
    static constexpr std::uint64_t kIerOffset = 0x08;
    static constexpr std::uint64_t kIdrOffset = 0x0C;
    static constexpr std::uint64_t kSrOffset = 0x14;
    static constexpr std::uint64_t kRhrOffset = 0x18;
    static constexpr std::uint64_t kThrOffset = 0x1C;
    static constexpr std::uint64_t kPdcBaseOffset = 0x100;

    Sam3xaUart(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlConnectivityPeripheral(ql, label, kStructSize), intn_(intn) {
        raw_write(kSrOffset, 4, sam3xa_uart::sr::TXRDY);
    }

    // uart.py read: the RHR read clears the RXRDY and rides the input tube
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;

    // uart.py write: the THR rides the output tube, the IDR/IER walk
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // uart.py step: the IER.RXRDY + the CR.RXEN + the input rides the
    // SR.RXRDY + the nvic pending
    void step() override;

private:
    std::int64_t intn_;
};

// dma/sam3xa_pdc.py — the plain 40-byte image
class Sam3xaPdc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 40;

    Sam3xaPdc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// misc/sam3xa_wdt.py — the plain 12-byte image
class Sam3xaWdt final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 12;

    Sam3xaWdt(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// flash/sam3xa_efc.py — the plain 16-byte image
class Sam3xaEfc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 16;

    Sam3xaEfc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// analog/sam3xa_pwm.py — the plain 768-byte image
class Sam3xaPwm final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 768;

    Sam3xaPwm(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// timer/sam3xa_tc.py — the plain 232-byte image
class Sam3xaTc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 232;

    Sam3xaTc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
};

// analog/sam3xa_adc.py — the 296-byte image (the LCDR 0xfff seed); the
// CHER/CHDR enable/disable walk + the CR.START riding the ISR.DRDY
class Sam3xaAdc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 296;
    static constexpr std::uint64_t kCrOffset = 0x00;
    static constexpr std::uint64_t kCherOffset = 0x10;
    static constexpr std::uint64_t kChdrOffset = 0x14;
    static constexpr std::uint64_t kLcdrOffset = 0x20;
    static constexpr std::uint64_t kIsrOffset = 0x30;

    Sam3xaAdc(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {
        raw_write(kLcdrOffset, 4, 0xfff);
    }

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::int64_t intn_;
};

// analog/sam3xa_dac.py — the 296-byte image; the CDR write rides the ISR.EOC
class Sam3xaDac final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 296;
    static constexpr std::uint64_t kCdrOffset = 0x20;
    static constexpr std::uint64_t kIsrOffset = 0x30;

    Sam3xaDac(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {}

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::int64_t intn_;
};

// gpio/sam3xa_pio.py — the 236-byte image; the GpioHooks over 32 pins; the
// PUER/SODR ride the set_pin loop, the PUDR/CODR ride the reset_pin loop
class Sam3xaPio final : public QlPeripheral, public GpioHooks {
public:
    static constexpr std::size_t kStructSize = 236;
    static constexpr std::uint64_t kPsrOffset = 0x08;
    static constexpr std::uint64_t kSodrOffset = 0x30;
    static constexpr std::uint64_t kCodrOffset = 0x34;
    static constexpr std::uint64_t kOdsrOffset = 0x38;
    static constexpr std::uint64_t kPdsrOffset = 0x3C;
    static constexpr std::uint64_t kPuerOffset = 0x64;
    static constexpr std::uint64_t kPudrOffset = 0x60;

    Sam3xaPio(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), GpioHooks(32), intn_(intn) {}

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // pio.py set_pin/reset_pin/pin over the PDSR
    void set_pin(std::size_t i);
    void reset_pin(std::size_t i);
    std::uint32_t pin(std::size_t index) const;

private:
    std::int64_t intn_;
};

// power/sam3xa_pmc.py — the 272-byte image; the write walk mirrors the
// oscillator/PLL status bits
class Sam3xaPmc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 272;
    static constexpr std::uint64_t kSrOffset = 0x68;

    // the explicit ctor: the using-declaration would bind the intn to the
    // QlPeripheral image_size parameter (the corruption the fixture caught)
    Sam3xaPmc(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlPeripheral(ql, label, kStructSize), intn_(intn) {}

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::int64_t intn_;
};

// spi/sam3xa_spi.py — the 236-byte image; the SR seed TDRE|RDRF and the RDR
// 0xff seed; the RDR read rides the input tube, the TDR write rides the
// output tube + the raw write
class Sam3xaSpi final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 236;
    static constexpr std::uint64_t kRdrOffset = 0x08;
    static constexpr std::uint64_t kTdrOffset = 0x0C;
    static constexpr std::uint64_t kSrOffset = 0x10;

    Sam3xaSpi(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlConnectivityPeripheral(ql, label, kStructSize), intn_(intn) {
        raw_write(kSrOffset, 4, sam3xa_spi::sr::TDRE | sam3xa_spi::sr::RDRF);
        raw_write(kRdrOffset, 4, 0xff);
    }

    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::int64_t intn_;
};

// char/sam3xa_uotghs.py — the 2096-byte image; the CTRL write without the
// OTGPADE rides the SR.CLKUSABLE
class Sam3xaUotghs final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 2096;
    static constexpr std::uint64_t kCtrlOffset = 0x800;
    static constexpr std::uint64_t kSrOffset = 0x804;

    Sam3xaUotghs(Qiling& ql, const std::string& label)
        : QlConnectivityPeripheral(ql, label, kStructSize) {}

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_SAM3XA_HPP
