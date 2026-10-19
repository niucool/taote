// The implementation half of mk64f12.hpp (the uart/gpio/port/spi/ftm/adc/mcg
// walks; the sim/smc/wdog/osc/rtc ride the plain base bodies).
#include "qiling/hw/mk64f12.hpp"

#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"

#include <algorithm>

namespace qiling {
namespace hw {

// ---- the UART ----

std::uint64_t Mk64f12Uart::read_body(std::uint64_t offset, std::uint32_t size) {
    if (offset == kDOffset) {
        const auto pfifo = raw_read(0x0C, 4);  // the PFIFO field
        if (pfifo & mk64f12_uart::pfifo::RXFE) {
            raw_write(0x1C, 2, 0);  // the RCFIFO clear
        } else {
            const auto s1 = raw_read(0x04, 1);
            raw_write(0x04, 1, s1 & ~mk64f12_uart::s1::RDRF);
        }
        return recv_from_user();
    }
    return QlConnectivityPeripheral::read_body(offset, size);
}

void Mk64f12Uart::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kDOffset) {
        send_to_user(value);
    } else {
        QlConnectivityPeripheral::write_body(offset, size, value);
    }
}

void Mk64f12Uart::step() {
    if (!has_input()) {
        return;
    }
    const auto pfifo = raw_read(0x0C, 4);
    if (pfifo & mk64f12_uart::pfifo::RXFE) {
        raw_write(0x1C, 2, 1);  // the RCFIFO = 1
    } else {
        const auto s1 = raw_read(0x04, 1);
        raw_write(0x04, 1, s1 | mk64f12_uart::s1::RDRF);
    }

    const auto c2 = raw_read(0x03, 1);
    if (c2 & mk64f12_uart::c2::RIE) {
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (nvic != nullptr && rx_tx_intn_ >= 0) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(rx_tx_intn_));
        }
    }
}

// ---- the GPIO ----

void Mk64f12Gpio::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // gpio.py: the PSOR/PCOR/PTOR writes loop all 32 pins verbatim (no mask)
    if (offset == kPsorOffset) {
        for (std::size_t i = 0; i < 32; ++i) {
            set_pin(i);
        }
        return;
    }
    if (offset == kPcorOffset) {
        for (std::size_t i = 0; i < 32; ++i) {
            reset_pin(i);
        }
        return;
    }
    if (offset == kPtorOffset) {
        for (std::size_t i = 0; i < 32; ++i) {
            if (pin(i)) {
                reset_pin(i);
            } else {
                set_pin(i);
            }
        }
        return;
    }
    QlPeripheral::write_body(offset, size, value);
}

void Mk64f12Gpio::set_pin(std::size_t i) {
    // gpio.py: the port interrupt walk + the PDDR select
    if (auto* port = this->port(); port != nullptr) {
        dynamic_cast<Mk64f12Port&>(*port).send_interrupt(i, pin(i), 1);
    }
    const auto pddr = raw_read(kPddrOffset, 4);
    if (pddr) {
        const auto pdor = raw_read(kPdorOffset, 4);
        raw_write(kPdorOffset, 4, pdor | (1ull << i));
    } else {
        const auto pdir = raw_read(kPdirOffset, 4);
        raw_write(kPdirOffset, 4, pdir | (1ull << i));
    }
    call_hook_set(i);
}

void Mk64f12Gpio::reset_pin(std::size_t i) {
    if (auto* port = this->port(); port != nullptr) {
        dynamic_cast<Mk64f12Port&>(*port).send_interrupt(i, pin(i), 0);
    }
    const auto pddr = raw_read(kPddrOffset, 4);
    if (pddr) {
        const auto pdor = raw_read(kPdorOffset, 4);
        raw_write(kPdorOffset, 4, pdor & ~(1ull << i));
    } else {
        const auto pdir = raw_read(kPdirOffset, 4);
        raw_write(kPdirOffset, 4, pdir & ~(1ull << i));
    }
    call_hook_reset(i);
}

std::uint32_t Mk64f12Gpio::pin(std::size_t index) const {
    const auto pddr = raw_read(kPddrOffset, 4);
    if (pddr) {
        return (static_cast<std::uint32_t>(raw_read(kPdorOffset, 4)) >> index) & 1;
    }
    return (static_cast<std::uint32_t>(raw_read(kPdirOffset, 4)) >> index) & 1;
}

QlPeripheral* Mk64f12Gpio::port() {
    // gpio.py: getattr(ql.hw, 'port' + label[-1]) — the label "gpioa" rides
    // the "porta" entity (the manager stores the lowercase labels)
    const auto& label = this->label();
    if (label.empty()) {
        return nullptr;
    }
    return ql().hw() != nullptr ? ql().hw()->peripheral("port" + label.substr(label.size() - 1)) : nullptr;
}

// ---- the PORT ----

std::uint32_t Mk64f12Port::pin_interrupt_config(std::size_t index) const {
    // port.py: (PCR[index] & PCR.IRQC) >> 16
    const auto pcr = raw_read(kPcrOffset + index * 4, 4);
    return (static_cast<std::uint32_t>(pcr) & mk64f12_port::pcr::IRQC) >> 16;
}

void Mk64f12Port::send_interrupt(std::size_t index, std::uint32_t prev, std::uint32_t curr) {
    using IM = mk64f12_port::InterruptMode;
    const auto config = pin_interrupt_config(index);
    const bool fire =
        (config == static_cast<std::uint32_t>(IM::InterruptLogicZero) && curr == 0) ||
        (config == static_cast<std::uint32_t>(IM::InterruptLogicOne) && curr == 1) ||
        (config == static_cast<std::uint32_t>(IM::InterruptRisingEdge) && curr == 1 && prev == 0) ||
        (config == static_cast<std::uint32_t>(IM::InterruptFallingEdge) && curr == 0 && prev == 1) ||
        (config == static_cast<std::uint32_t>(IM::InterruptEitherEdge) && curr != prev);
    if (!fire) {
        return;
    }
    auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
    if (nvic != nullptr && intn_ >= 0) {
        dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_));
    }
}

// ---- the SPI ----

std::uint64_t Mk64f12Spi::read_body(std::uint64_t offset, std::uint32_t size) {
    if (offset == kPoprOffset && has_input()) {
        const auto sr = raw_read(0x02, 4);  // the SR field
        raw_write(0x02, 4, sr & ~mk64f12_spi::sr::RFDF & ~mk64f12_spi::sr::RXCTR);
        return recv_from_user();
    }
    return QlConnectivityPeripheral::read_body(offset, size);
}

void Mk64f12Spi::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kPushrOffset) {
        send_to_user(value & mk64f12_spi::pushr::TXDATA);
    } else if (offset == kCtarOffset) {
        const auto sr = raw_read(0x02, 4);
        raw_write(0x02, 4, sr | mk64f12_spi::sr::TFFF);
    }
    QlConnectivityPeripheral::write_body(offset, size, value);
}

void Mk64f12Spi::step() {
    if (!has_input()) {
        return;
    }
    const auto sr = raw_read(0x02, 4);
    raw_write(0x02, 4, sr | mk64f12_spi::sr::RFDF | mk64f12_spi::sr::RXCTR);
}

// ---- the FTM ----

void Mk64f12Ftm::step() {
    // ftm.py: the MODE.FTMEN + the SC.CLKS + the CNT/PS walk
    const auto mode = raw_read(0x54, 4);  // the MODE field
    const auto sc = raw_read(0x00, 4);    // the SC field
    if ((mode & (1u << 0)) == 0 || (sc & (0x3u << 3)) == 0) {
        return;
    }
    const auto cnt = static_cast<std::int64_t>(raw_read(0x34, 4));  // the CNT field
    if (cnt <= 0) {
        const auto ps = sc & (0x7u << 0);
        raw_write(0x34, 4, 1000000 / (ps + 1));
    } else {
        const auto next = cnt - static_cast<std::int64_t>(ratio());
        raw_write(0x34, 4, static_cast<std::uint64_t>(std::max<std::int64_t>(next, 0)));
        if (next <= 0 && intn_ >= 0) {
            auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
            if (nvic != nullptr) {
                dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_));
            }
        }
    }
}

// ---- the ADC ----

void Mk64f12Adc::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // adc.py: the SC1 write is a no-op (the conversion-select walk lands
    // nothing); the SC3.CAL ride sets the SC1 COCO bits then self-clears
    if (offset == kSc1Offset || offset == kSc1bOffset) {
        return;
    }
    QlPeripheral::write_body(offset, size, value);

    if (offset == kSc3Offset) {
        if (value & mk64f12_adc::sc3::CAL) {
            const auto sc3 = raw_read(kSc3Offset, 4);
            raw_write(kSc3Offset, 4, sc3 & ~mk64f12_adc::sc3::CAL);
            const auto sc1 = raw_read(kSc1Offset, 4);
            raw_write(kSc1Offset, 4, sc1 | mk64f12_adc::sc1::COCO);
            const auto sc1b = raw_read(kSc1bOffset, 4);
            raw_write(kSc1bOffset, 4, sc1b | mk64f12_adc::sc1::COCO);
        }
    }
}

// ---- the MCG ----

void Mk64f12Mcg::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    namespace mcg = mk64f12_mcg;
    // mcg.py: the S field rides the u8 at 0x04
    const auto s_read = raw_read(0x04, 1);
    std::uint32_t s_new = s_read;
    if (offset == kC1Offset) {
        s_new &= ~(mcg::s::IREFST | mcg::s::CLKST);
        if (value & mcg::c1::IREFS) {
            s_new |= (1ull << mcg::s::IREFST_Pos);
        }
        const auto clock_source = value & mcg::c1::CLKS;
        if (clock_source == 0 && (s_read & mcg::s::PLLST)) {
            s_new |= mcg::s::CLKST;
        } else {
            s_new |= (clock_source >> mcg::c1::CLKS_Pos) << mcg::s::CLKST_Pos;
        }
    } else if (offset == 0x08) {  // the C5
        if (value & mcg::c5::PLLCLKEN0) {
            s_new |= mcg::s::LOCK0;
        }
    } else if (offset == 0x0A) {  // the C6
        if (value & mcg::c6::PLLS) {
            s_new |= mcg::s::PLLST | mcg::s::LOCK0;
        }
    }
    raw_write(0x04, 1, s_new);

    if (offset != kC1Offset && offset != 0x08 && offset != 0x0A) {
        QlPeripheral::write_body(offset, size, value);
    }
}

}  // namespace hw
}  // namespace qiling
