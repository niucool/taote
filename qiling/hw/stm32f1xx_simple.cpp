// The implementation half of stm32f1xx_simple.hpp (the Rcc step + the Adc
// CR2 walks + the bitband mem bridge).
#include "qiling/hw/stm32f1xx_simple.hpp"
#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"

#include <algorithm>
#include <cstring>

namespace qiling {
namespace hw {

void STM32F1xxRcc::step() {
    // rcc.py step: the rdyon tables — the CR (the HSI/HSE/PLL/PLLI2S pairs)
    // and the CFGR (the SWS/SW pairs) and the CSR (the LSIRDY/LSION pair);
    // the on-bits reflect into the ready bits
    struct Pair {
        std::uint64_t offset;
        std::uint32_t rdy;
        std::uint32_t on;
    };
    static const Pair kRdyon[] = {
        {kCrOffset, rcc::cr::HSIRDY, rcc::cr::HSION},
        {kCrOffset, rcc::cr::HSERDY, rcc::cr::HSEON},
        {kCrOffset, rcc::cr::PLLRDY, rcc::cr::PLLON},
        {kCrOffset, rcc::cr::PLLI2SRDY, rcc::cr::PLLI2SON},
        {kCfgrOffset, rcc::cfgr::SWS_0, rcc::cfgr::SW_0},
        {kCfgrOffset, rcc::cfgr::SWS_1, rcc::cfgr::SW_1},
        {kCsrOffset, rcc::csr::LSIRDY, rcc::csr::LSION},
    };

    for (const auto& [offset, rdy, on] : kRdyon) {
        const auto value = raw_read(offset, 4);
        const auto next = (value & on) ? (value | rdy) : (value & ~rdy);
        raw_write(offset, 4, next);
    }
}

void STM32F1xxAdc::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // adc.py write: the raw store first, then the CR2 self-clearing walks
    QlPeripheral::write_body(offset, size, value);

    if (offset == kCr2Offset) {
        if (value & adc::cr2::RSTCAL) {
            const auto cr2 = raw_read(kCr2Offset, 4);
            raw_write(kCr2Offset, 4, cr2 & ~adc::cr2::RSTCAL);
        }
        if (value & adc::cr2::CAL) {
            const auto cr2 = raw_read(kCr2Offset, 4);
            raw_write(kCr2Offset, 4, cr2 & ~adc::cr2::CAL);
        }
        if (value & adc::cr2::SWSTART) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, sr | adc::sr::EOS);
            const auto cr2 = raw_read(kCr2Offset, 4);
            raw_write(kCr2Offset, 4, cr2 & ~adc::cr2::SWSTART);
        }
    }
}

void STM32F1xxSpi::send_interrupt(std::int64_t intn) {
    auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
    if (nvic != nullptr && intn >= 0) {
        dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn));
    }
}

std::uint64_t STM32F1xxSpi::read_body(std::uint64_t offset, std::uint32_t size) {
    // spi.py read: the contain walk rides the DR read through the input tube
    if (contain(kDrOffset, 4, offset, size) && has_input()) {
        return recv_from_user();
    }
    return QlConnectivityPeripheral::read_body(offset, size);
}

void STM32F1xxSpi::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // spi.py write: the contain walk rides the DR write to the output tube,
    // the others store
    if (contain(kDrOffset, 4, offset, size)) {
        send_to_user(value);
        return;
    }
    QlConnectivityPeripheral::write_body(offset, size, value);
}

std::uint64_t CortexMBitband::read_body(std::uint64_t offset, std::uint32_t size) {
    // cm_bitband.py read: the aliased word read, the bit picked by the
    // (offset >> 2) & ((size * 8) - 1) walk
    const auto addr = bitband_addr(offset) & ~(static_cast<std::uint64_t>(size) - 1);
    const auto word = ql().mem().read(addr, size);
    const auto bitpos = (offset >> 2) & ((static_cast<std::uint64_t>(size) * 8) - 1);
    std::uint64_t value = 0;
    std::memcpy(&value, word.data(), std::min<std::size_t>(word.size(), sizeof(value)));
    return (value >> (bitpos & 7)) & 1;
}

void CortexMBitband::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // cm_bitband.py write: the aliased word read-modify-write on the bit
    const auto addr = bitband_addr(offset) & ~(static_cast<std::uint64_t>(size) - 1);
    const auto bitpos = (offset >> 2) & ((static_cast<std::uint64_t>(size) * 8) - 1);
    const auto mask = 1ull << (bitpos & 7);

    const auto word = ql().mem().read(addr, size);
    auto bytes = std::vector<std::uint8_t>(8, 0);
    std::memcpy(bytes.data(), word.data(), std::min<std::size_t>(word.size(), sizeof(word)));
    if (value & 1) {
        bytes[bitpos >> 3] |= static_cast<std::uint8_t>(mask);
    } else {
        bytes[bitpos >> 3] &= static_cast<std::uint8_t>(~mask);
    }
    ql().mem().write(addr, std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + size));
}

std::uint64_t MemoryRemap::read_body(std::uint64_t offset, std::uint32_t size) {
    // remap.py read: the mem-backed pass-through (int.from_bytes LE)
    const auto data = ql().mem().read(remap_base_ + offset, size);
    std::uint64_t value = 0;
    std::memcpy(&value, data.data(), std::min<std::size_t>(data.size(), sizeof(value)));
    return value;
}

void MemoryRemap::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // remap.py write: the mem-backed pass-through (value.to_bytes LE)
    std::vector<std::uint8_t> bytes(size, 0);
    std::memcpy(bytes.data(), &value, std::min<std::size_t>(size, sizeof(value)));
    ql().mem().write(remap_base_ + offset, bytes);
}

}  // namespace hw
}  // namespace qiling

namespace qiling {
namespace hw {

// ---- the STM32F4xxSpi ----

std::uint64_t STM32F4xxSpi::read_body(std::uint64_t offset, std::uint32_t size) {
    // spi.py read: the contain walk rides the DR read through the input tube,
    // the plain read stores the rest
    if (contain(kDrOffset, 4, offset, size) && has_input()) {
        return recv_from_user();
    }
    return QlConnectivityPeripheral::read_body(offset, size);
}

void STM32F4xxSpi::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // spi.py write: the SR/RXCRCR/TXCRCR writes ignored; the CR1/CR2/CRCPR/
    // I2SCFGR/I2SPR rides the RW_MASKs; the DR stores then rides the tube
    if (offset == kSrOffset || offset == kRxcrcrOffset || offset == kTxcrcrOffset) {
        return;
    }

    if (offset == kCr1Offset) {
        value &= stm32f4xx_spi::CR1_RW_MASK;
    } else if (offset == kCr2Offset) {
        value &= stm32f4xx_spi::CR2_RW_MASK;
    } else if (offset == kCrcprOffset) {
        value &= stm32f4xx_spi::CRCPR_CRCPOLY;
    } else if (offset == kI2scfgrOffset) {
        value &= stm32f4xx_spi::I2SCFGR_RW_MASK;
    } else if (offset == kI2sprOffset) {
        value &= stm32f4xx_spi::I2SPR_RW_MASK;
    }

    raw_write(offset, size, value);

    if (contain(kDrOffset, 4, offset, size)) {
        send_to_user(raw_read(kDrOffset, 4));
    }
}

void STM32F4xxSpi::send_interrupt() {
    if (intn_ >= 0) {
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (nvic != nullptr) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_));
        }
    }
}

}  // namespace hw
}  // namespace qiling
