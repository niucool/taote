// The implementation half of sam3xa.hpp (the uart/spi/adc/dac/pio/pmc/uotghs
// walks; the plain-struct classes carry no overrides).
#include "qiling/hw/sam3xa.hpp"

#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"

namespace qiling {
namespace hw {

// ---- the UART ----

std::uint64_t Sam3xaUart::read_body(std::uint64_t offset, std::uint32_t size) {
    if (offset == kRhrOffset && has_input()) {
        const auto sr = raw_read(kSrOffset, 4);
        raw_write(kSrOffset, 4, sr & ~sam3xa_uart::sr::RXRDY);
        return recv_from_user();
    }
    return QlConnectivityPeripheral::read_body(offset, size);
}

void Sam3xaUart::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kThrOffset) {
        send_to_user(value);

    } else if (offset == kIdrOffset) {
        const auto ier = raw_read(kIerOffset, 4);
        raw_write(kIerOffset, 4, ier & ~static_cast<std::uint32_t>(value));
    } else if (offset == kIerOffset) {
        const auto ier = raw_read(kIerOffset, 4);
        raw_write(kIerOffset, 4, ier | static_cast<std::uint32_t>(value));
    } else {
        raw_write(offset, size, value);
    }
}

void Sam3xaUart::step() {
    const auto ier = raw_read(kIerOffset, 4);
    const auto cr = raw_read(kCrOffset, 4);
    if ((ier & sam3xa_uart::ier::RXRDY) && (cr & sam3xa_uart::cr::RXEN) && has_input()) {
        const auto sr = raw_read(kSrOffset, 4);
        raw_write(kSrOffset, 4, sr | sam3xa_uart::sr::RXRDY);
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (nvic != nullptr && intn_ >= 0) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_));
        }
    }
}

// ---- the ADC ----

void Sam3xaAdc::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kCherOffset) {
        const auto chsr = raw_read(kCherOffset, 4);
        raw_write(kCherOffset, 4, chsr | static_cast<std::uint32_t>(value));
    } else if (offset == kChdrOffset) {
        const auto chsr = raw_read(kCherOffset, 4);
        raw_write(kCherOffset, 4, chsr & ~static_cast<std::uint32_t>(value));
    } else if (offset == kCrOffset) {
        if (value & sam3xa_adc::cr::START) {
            const auto isr = raw_read(kIsrOffset, 4);
            raw_write(kIsrOffset, 4, isr | sam3xa_adc::isr::DRDY);
        }
        // the CR is write-only (the write clears the touched bits — the
        // verbatim fall-through lands nothing)
    } else {
        raw_write(offset, size, value);
    }
}

// ---- the DAC ----

void Sam3xaDac::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kCdrOffset) {
        const auto isr = raw_read(kIsrOffset, 4);
        raw_write(kIsrOffset, 4, isr | sam3xa_dac::isr::EOC);
    }
    raw_write(offset, size, value);
}

// ---- the PIO ----

void Sam3xaPio::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kPuerOffset || offset == kSodrOffset) {
        for (std::size_t i = 0; i < 32; ++i) {
            if ((value >> i) & 1) {
                set_pin(i);
            }
        }
        return;
    }

    if (offset == kPudrOffset || offset == kCodrOffset) {
        for (std::size_t i = 0; i < 32; ++i) {
            if ((value >> i) & 1) {
                reset_pin(i);
            }
        }
        return;
    }

    raw_write(offset, size, value);
}

void Sam3xaPio::set_pin(std::size_t i) {
    const auto pdsr = raw_read(kPdsrOffset, 4);
    raw_write(kPdsrOffset, 4, pdsr | (1ull << i));
    call_hook_set(i);
}

void Sam3xaPio::reset_pin(std::size_t i) {
    const auto pdsr = raw_read(kPdsrOffset, 4);
    raw_write(kPdsrOffset, 4, pdsr & ~(1ull << i));
    call_hook_reset(i);
}

std::uint32_t Sam3xaPio::pin(std::size_t index) const {
    return (static_cast<std::uint32_t>(raw_read(kPdsrOffset, 4)) >> index) & 1;
}

// ---- the PMC ----

void Sam3xaPmc::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    namespace pmc = sam3xa_pmc;
    if (offset == 0x20) {  // the CKGR_MOR
        const auto sr = raw_read(kSrOffset, 4);
        std::uint32_t set = 0;
        if (value & pmc::ckgr_mor::MOSCXTEN) {
            set |= pmc::sr::MOSCXTS;
        }
        if (value & pmc::ckgr_mor::MOSCSEL) {
            set |= pmc::sr::MOSCSELS;
        }
        raw_write(kSrOffset, 4, sr | set);
    } else if (offset == 0x30) {  // the MCKR
        if (value & pmc::mckr::CSS) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, sr | pmc::sr::MCKRDY);
        }
    } else if (offset == 0x28) {  // the CKGR_PLLAR
        if (value & pmc::ckgr_pllar::ONE) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, sr | pmc::sr::LOCKA);
        }
    } else if (offset == 0x1C) {  // the CKGR_UCKR
        if (value & pmc::ckgr_uckr::UPLLEN) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, sr | pmc::sr::LOCKU);
        }
    }
    raw_write(offset, size, value);
}

// ---- the SPI ----

std::uint64_t Sam3xaSpi::read_body(std::uint64_t offset, std::uint32_t size) {
    if (offset == kRdrOffset && has_input()) {
        return recv_from_user();
    }
    return QlConnectivityPeripheral::read_body(offset, size);
}

void Sam3xaSpi::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    if (offset == kTdrOffset) {
        send_to_user(value & sam3xa_spi::tdr::TD);
    }
    QlConnectivityPeripheral::write_body(offset, size, value);
}

// ---- the UOTGHS ----

void Sam3xaUotghs::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // uotghs.py: the CTRL write without the OTGPADE rides the CLKUSABLE
    if (offset == kCtrlOffset) {
        constexpr std::uint32_t kOttpade = 1u << 10;
        if ((value & kOttpade) == 0) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, sr | sam3xa_uotghs::sr::CLKUSABLE);
        }
    }
    raw_write(offset, size, value);
}

}  // namespace hw
}  // namespace qiling
