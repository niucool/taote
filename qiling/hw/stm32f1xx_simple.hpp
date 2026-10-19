// Batch 1 of the board-profile peripheral classes (the simple register
// surfaces):
//   - STM32F1xxRcc  (hw/misc/stm32f1xx_rcc.py) — the 40-byte image + the
//     rdyon step walk (the on-bits reflect into the ready bits)
//   - STM32F1xxFlash (hw/flash/stm32f1xx_flash.py) — the plain register image
//   - STM32F1xxAdc  (hw/analog/stm32f1xx_adc.py) — the 80-byte image + the
//     CR2 self-clearing walks (the RSTCAL/CAL/SWSTART bits)
//   - STM32F1xxSpi  (hw/spi/stm32f1xx_spi.py) — the tube-paired 32-byte image
//     (the DR rides the input/output tubes + the send_interrupt)
//   - CortexMBitband (hw/mem/cm_bitband.py) — the bit-banding bridge over the
//     aliased region
//   - MemoryRemap   (hw/mem/remap.py) — the mem-backed pass-through region
//
// The Wwdg/Iwdg/Bkp/Pwr/Can/Usb/Crc/Rtc/Dbgmcu classes the stm32f103 board
// dict references do not exist upstream (the create's module lookup raises
// the QlErrorModuleFunctionNotFound and the peripheral is skipped with the
// warning) — the port mirrors the absence (the unregistered struct names
// degrade to null in the hw manager's create).
#pragma once

#ifndef QILING_HW_STM32F1XX_SIMPLE_HPP
#define QILING_HW_STM32F1XX_SIMPLE_HPP

#include "qiling/hw/connectivity.hpp"
#include "qiling/hw/const_stm32fxxx_rcc.hpp"

#include <array>

namespace qiling {
namespace hw {

namespace adc {
// hw/const/stm32f1xx_adc.py ADC_SR / ADC_CR2 (the bits the body walks)
namespace sr {
inline constexpr std::uint32_t AWD = 1u << 0;
inline constexpr std::uint32_t EOS = 1u << 1;
inline constexpr std::uint32_t JEOS = 1u << 2;
inline constexpr std::uint32_t JSTRT = 1u << 3;
inline constexpr std::uint32_t STRT = 1u << 4;
}  // namespace sr

namespace cr2 {
inline constexpr std::uint32_t ADON = 1u << 0;
inline constexpr std::uint32_t CONT = 1u << 1;
inline constexpr std::uint32_t CAL = 1u << 2;
inline constexpr std::uint32_t RSTCAL = 1u << 3;
inline constexpr std::uint32_t DMA = 1u << 8;
inline constexpr std::uint32_t ALIGN = 1u << 11;
inline constexpr std::uint32_t JSWSTART = 1u << 21;
inline constexpr std::uint32_t SWSTART = 1u << 22;
}  // namespace cr2
}  // namespace adc

// hw/misc/stm32f1xx_rcc.py STM32F1xxRcc — the 10-register image
class STM32F1xxRcc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 40;
    static constexpr std::uint64_t kCrOffset = 0;
    static constexpr std::uint64_t kCfgrOffset = 4;
    static constexpr std::uint64_t kCirOffset = 8;
    static constexpr std::uint64_t kApb2RstrOffset = 12;
    static constexpr std::uint64_t kApb1RstrOffset = 16;
    static constexpr std::uint64_t kAhbenrOffset = 20;
    static constexpr std::uint64_t kApb2EnrOffset = 24;
    static constexpr std::uint64_t kApb1EnrOffset = 28;
    static constexpr std::uint64_t kBdcrOffset = 32;
    static constexpr std::uint64_t kCsrOffset = 36;

    explicit STM32F1xxRcc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {
        // the verbatim instance seed
        raw_write(kCrOffset, 4, 0x00000083ull);
        raw_write(kAhbenrOffset, 4, 0x00000014ull);
        raw_write(kCsrOffset, 4, 0x0C000000ull);
    }

    // rcc.py step: the on-bits reflect into the ready bits (the CR and the
    // CFGR/CSR rdyon tables verbatim)
    void step() override;
};

// hw/flash/stm32f1xx_flash.py STM32F1xxFlash — the plain 36-byte image
class STM32F1xxFlash final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 36;

    explicit STM32F1xxFlash(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {}
    // the plain read/write monitor bodies (the defaults ride)
};

// hw/analog/stm32f1xx_adc.py STM32F1xxAdc — the 20-register image (80 bytes)
class STM32F1xxAdc final : public QlPeripheral {
public:
    static constexpr std::size_t kStructSize = 80;
    static constexpr std::uint64_t kSrOffset = 0;
    static constexpr std::uint64_t kCr2Offset = 8;
    static constexpr std::uint64_t kDrOffset = 76;

    explicit STM32F1xxAdc(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {
        // the verbatim instance seed: DR = 0x7ff
        raw_write(kDrOffset, 4, 0x7ff);
    }

    // adc.py write: the raw store first, then the CR2 self-clearing walks
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;
};

// hw/spi/stm32f1xx_spi.py STM32F1xxSpi — the 32-byte tube-paired image
class STM32F1xxSpi final : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 32;
    static constexpr std::uint64_t kCr1Offset = 0;
    static constexpr std::uint64_t kDrOffset = 12;

    explicit STM32F1xxSpi(Qiling& ql, const std::string& label)
        : QlConnectivityPeripheral(ql, label, kStructSize) {
        // the verbatim instance seed
        raw_write(0, 4, 0x00000000ull);   // CR1
        raw_write(4, 4, 0x00000000ull);   // CR2
        raw_write(8, 4, 0x0000000Bull);   // SR
        raw_write(12, 4, 0x0000000Cull);  // DR
        raw_write(16, 4, 0x00000007ull);  // CRCPR
        raw_write(20, 4, 0x00000000ull);  // RXCRCR
        raw_write(24, 4, 0x00000000ull);  // TXCRCR
        raw_write(28, 4, 0x00000000ull);  // I2SCFGR
    }

    // spi.py read: the DR read rides the input tube when available
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;

    // spi.py write: the DR write sends to the output tube, the others store
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // spi.py send_interrupt: the nvic pending with the peripheral's intn
    void send_interrupt(std::int64_t intn);
};

// hw/mem/cm_bitband.py CortexMBitband — the bit-banding bridge
class CortexMBitband final : public QlPeripheral {
public:
    CortexMBitband(Qiling& ql, const std::string& label, std::uint64_t base, std::uint64_t size)
        : QlPeripheral(ql, label, 0), bitband_base_(base), bitband_size_(size * 32) {}

    // cm_bitband.py _bitband_addr: the aliased address walk
    std::uint64_t bitband_addr(std::uint64_t offset) const {
        return bitband_base_ | ((offset & 0x1ffffffull) >> 5);
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> region() const override {
        return {{0, bitband_size_}};
    }

    // cm_bitband.py read/write: the aliased word walks (the .cpp)
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::uint64_t bitband_base_ = 0;
    std::uint64_t bitband_size_ = 0;
};

// hw/mem/remap.py MemoryRemap — the mem-backed pass-through region
class MemoryRemap final : public QlPeripheral {
public:
    MemoryRemap(Qiling& ql, const std::string& label, std::uint64_t base, std::uint64_t size)
        : QlPeripheral(ql, label, 0), remap_base_(base), remap_size_(size) {}

    std::vector<std::pair<std::uint64_t, std::uint64_t>> region() const override {
        return {{0, remap_size_}};
    }

    // remap.py read/write: the mem-backed pass-through (the .cpp)
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    std::uint64_t remap_base_ = 0;
    std::uint64_t remap_size_ = 0;
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F1XX_SIMPLE_HPP
