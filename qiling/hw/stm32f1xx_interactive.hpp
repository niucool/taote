// Ported from qiling/hw/const/stm32f1xx_dma.py (the DMA_CR/DMA tables) and
// qiling/hw/dma/stm32f1xx_dma.py (the Stream + the STM32F1xxDma). The DMA
// stream walks the CR/NDTR/PAR/MAR record, the step transfers one unit per
// slice (the mem read/write with the size alignments + the MINC/PINC
// increments), the last transfer clears the EN and rides the
// transfer_complete (the ISR TC bit + the nvic pending).
//
// Ported from qiling/hw/i2c/stm32f4xx_i2c.py (STM32F4xxI2c) and
// hw/i2c/stm32f1xx_i2c.py (the verbatim pass-through subclass). The 9-register
// image; the CR1 writes ride the START/STOP generation walks, the DR writes
// ride the master/slave data walks, the SR1/SR2 writes are ignored, the
// recorder history rides the SR1/SR2 pair-clear walk.
#pragma once

#ifndef QILING_HW_STM32F1XX_INTERACTIVE_HPP
#define QILING_HW_STM32F1XX_INTERACTIVE_HPP

#include "qiling/hw/connectivity.hpp"
#include "qiling/hw/peripheral.hpp"

#include <array>

namespace qiling {
namespace hw {

// hw/const/stm32f1xx_dma.py DMA_CR / DMA
namespace dma {
inline constexpr std::uint32_t EN = 1u << 0;
inline constexpr std::uint32_t TCIE = 1u << 1;
inline constexpr std::uint32_t HTIE = 1u << 2;
inline constexpr std::uint32_t TEIE = 1u << 3;
inline constexpr std::uint32_t DIR = 1u << 4;
inline constexpr std::uint32_t CIRC = 1u << 5;
inline constexpr std::uint32_t PINC = 1u << 6;
inline constexpr std::uint32_t MINC = 1u << 7;
inline constexpr std::uint32_t PSIZE_0 = 1u << 8;
inline constexpr std::uint32_t PSIZE_1 = 2u << 8;
inline constexpr std::uint32_t PSIZE = 0x3u << 8;
inline constexpr std::uint32_t MSIZE_0 = 1u << 10;
inline constexpr std::uint32_t MSIZE_1 = 2u << 10;
inline constexpr std::uint32_t MSIZE = 0x3u << 10;
inline constexpr std::uint32_t PL = 0x3u << 12;
inline constexpr std::uint32_t MEM2MEM = 1u << 14;

inline constexpr std::uint32_t PERIPH_TO_MEMORY = 0;
inline constexpr std::uint32_t MEMORY_TO_PERIPH = DIR;

inline constexpr std::uint32_t PDATAALIGN_BYTE = 0;
inline constexpr std::uint32_t PDATAALIGN_HALFWORD = PSIZE_0;
inline constexpr std::uint32_t PDATAALIGN_WORD = PSIZE_1;
inline constexpr std::uint32_t MDATAALIGN_BYTE = 0;
inline constexpr std::uint32_t MDATAALIGN_HALFWORD = MSIZE_0;
inline constexpr std::uint32_t MDATAALIGN_WORD = MSIZE_1;
}  // namespace dma

// dma.py Stream — the 20-byte channel record (CR/NDTR/PAR/MAR/RESERVED)
class DmaStream {
public:
    std::uint32_t cr = 0;
    std::uint32_t ndtr = 0;
    std::uint32_t par = 0;
    std::uint32_t mar = 0;
    std::uint32_t reserved = 0;

    bool enable() const { return (cr & dma::EN) != 0; }
    std::uint32_t transfer_direction() const { return cr & dma::DIR; }
    std::uint32_t transfer_peripheral_size() const;
    std::uint32_t transfer_memory_size() const;

    // dma.py Stream.step: the one-unit transfer; true rides the last unit
    bool step(QlMemoryManager& mem);
};

// dma.py STM32F1xxDma — the ISR/IFCR pair + the 8 streams
class STM32F1xxDma final : public QlPeripheral {public:
    static constexpr std::size_t kStructSize = 8 + 8 * 20;  // the ISR + the IFCR + the 8 streams
    static constexpr std::uint64_t kIsrOffset = 0;
    static constexpr std::uint64_t kIfcrOffset = 4;
    static constexpr std::uint64_t kStreamBaseOffset = 8;
    static constexpr std::size_t kStreamSize = 20;
    static constexpr std::size_t kStreamCount = 8;

    explicit STM32F1xxDma(Qiling& ql, const std::string& label)
        : QlPeripheral(ql, label, kStructSize) {
        intn_.fill(-1);
    }

    void set_stream_intn(std::size_t id, std::int64_t intn) {
        if (id < kStreamCount) {
            intn_[id] = intn;
        }
    }

    // dma.py read: the monitor(width=15) body (the plain memmove — the
    // defaults ride); the write: the ISR writes ignored, the IFCR clears
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // dma.py transfer_complete: the ISR TC bit + the nvic pending
    void transfer_complete(std::size_t id);

    // dma.py step: the enabled streams walk
    void step() override;

    // the raw stream access for the tests (the instance bytes back the stream)
    DmaStream stream(std::size_t id) const;

private:
    std::array<std::int64_t, kStreamCount> intn_;
};

// hw/const/stm32f4xx_i2c.py I2C_SR1 / I2C_SR2 / I2C_CR1 / I2C_OAR1 / I2C_CR2
// (the bits the bodies walk)
namespace i2c {
namespace sr1 {
inline constexpr std::uint32_t SB = 1u << 0;
inline constexpr std::uint32_t ADDR = 1u << 1;
inline constexpr std::uint32_t BTF = 1u << 2;
inline constexpr std::uint32_t ADD10 = 1u << 3;
inline constexpr std::uint32_t STOPF = 1u << 4;
inline constexpr std::uint32_t RXNE = 1u << 6;
inline constexpr std::uint32_t TXE = 1u << 7;
inline constexpr std::uint32_t AF = 1u << 10;
}  // namespace sr1

namespace sr2 {
inline constexpr std::uint32_t MSL = 1u << 0;
inline constexpr std::uint32_t TRA = 1u << 2;
}  // namespace sr2

namespace cr1 {
inline constexpr std::uint32_t PE = 1u << 0;
inline constexpr std::uint32_t START = 1u << 8;
inline constexpr std::uint32_t STOP = 1u << 9;
inline constexpr std::uint32_t ACK = 1u << 10;
inline constexpr std::uint32_t RW_MASK = PE | START | STOP | ACK;
}  // namespace cr1

namespace cr2 {
inline constexpr std::uint32_t ITEVTEN = 1u << 9;
inline constexpr std::uint32_t ITBUFEN = 1u << 10;
}  // namespace cr2

namespace oar1 {
inline constexpr std::uint32_t ADDMODE = 1u << 15;
}  // namespace oar1

namespace oar2 {
inline constexpr std::uint32_t ENDUAL = 1u << 0;
}  // namespace oar2

namespace dr {
inline constexpr std::uint32_t DR = 0xFFu << 0;
}  // namespace dr
}  // namespace i2c

// hw/i2c/stm32f4xx_i2c.py STM32F4xxI2c — the 9-register image (36 bytes);
// the STMB32F1xx subclass is the verbatim pass-through
// hw/i2c/stm32f1xx_i2c.py STM32F1xxI2c (the same register surface)
class STM32F4xxI2c : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 36;
    static constexpr std::uint64_t kCr1Offset = 0;
    static constexpr std::uint64_t kCr2Offset = 4;
    static constexpr std::uint64_t kOar1Offset = 8;
    static constexpr std::uint64_t kOar2Offset = 12;
    static constexpr std::uint64_t kDrOffset = 16;
    static constexpr std::uint64_t kSr1Offset = 20;
    static constexpr std::uint64_t kSr2Offset = 24;

    STM32F4xxI2c(Qiling& ql, const std::string& label, std::int64_t ev_intn = -1, std::int64_t er_intn = -1)
        : QlConnectivityPeripheral(ql, label, kStructSize, 2), ev_intn_(ev_intn), er_intn_(er_intn) {}

    // i2c.py read: the SR1/SR2 pair read clears the ADDR (the recorder walk)
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override;

    // i2c.py write: the SR writes ignored, the CR1 rides the START/STOP
    // generation, the DR rides the master/slave data walks
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

    // i2c.py send_event_interrupt: the CR2 ITEVTEN + the SR1 status walks
    void send_event_interrupt();

    // i2c.py generate_start/generate_stop/send_address/send_data walks
    void generate_start();
    void generate_stop();
    void send_address();
    void send_data();
    void fetch_device_address();

    // i2c.py is_master_mode/is_slave_mode/set_master_mode/set_slave_mode
    bool is_master_mode() const { return (raw_read(kSr2Offset, 4) & i2c::sr2::MSL) != 0; }
    bool is_slave_mode() const { return !is_master_mode(); }
    void set_master_mode() { const auto v = raw_read(kSr2Offset, 4); raw_write(kSr2Offset, 4, v | i2c::sr2::MSL); }
    void set_slave_mode() { const auto v = raw_read(kSr2Offset, 4); raw_write(kSr2Offset, 4, v & ~i2c::sr2::MSL); }

    bool is_7bit_mode() const;

    // the recorder history (the upstream AccessSequence over the read/write)
    AccessSequence history;

protected:
    std::int64_t ev_intn_ = -1;
    std::int64_t er_intn_ = -1;
};

// hw/i2c/stm32f1xx_i2c.py STM32F1xxI2c — the verbatim pass-through
using STM32F1xxI2c = STM32F4xxI2c;

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F1XX_INTERACTIVE_HPP
