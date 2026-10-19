// The implementation half of stm32f1xx_interactive.hpp (the DMA stream walk
// + the I2c master/slave walks).
#include "qiling/hw/stm32f1xx_interactive.hpp"

#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"
#include "qiling/os/memory.hpp"

#include <algorithm>
#include <cstring>

namespace qiling {
namespace hw {

// ---- the DMA stream ----

std::uint32_t DmaStream::transfer_peripheral_size() const {
    const auto psize = cr & dma::PSIZE;
    if (psize == dma::PDATAALIGN_BYTE) {
        return 1;
    }
    if (psize == dma::PDATAALIGN_HALFWORD) {
        return 2;
    }
    return 4;  // the WORD
}

std::uint32_t DmaStream::transfer_memory_size() const {
    const auto msize = cr & dma::MSIZE;
    if (msize == dma::MDATAALIGN_BYTE) {
        return 1;
    }
    if (msize == dma::MDATAALIGN_HALFWORD) {
        return 2;
    }
    return 4;  // the WORD
}

bool DmaStream::step(QlMemoryManager& mem) {
    if (ndtr == 0) {
        return false;
    }

    const bool to_periph = transfer_direction() == dma::MEMORY_TO_PERIPH;
    const auto psize = transfer_peripheral_size();
    const auto msize = transfer_memory_size();

    const auto src = to_periph ? mar : par;
    const auto dst = to_periph ? par : mar;
    const auto src_size = to_periph ? msize : psize;
    const auto dst_size = to_periph ? psize : msize;

    // dma.py: bytes(mem.read(src, src_size)).ljust(dst_size)[:dst_size]
    auto data = std::vector<std::uint8_t>(dst_size, 0);
    const auto raw = mem.read(src, src_size);
    std::memcpy(data.data(), raw.data(), std::min<std::size_t>(raw.size(), data.size()));
    mem.write(dst, data);

    --ndtr;
    if (cr & dma::MINC) {
        mar += msize;
    }
    if (cr & dma::PINC) {
        par += psize;
    }

    if (ndtr == 0) {
        cr &= ~dma::EN;
        return true;
    }
    return false;
}

DmaStream STM32F1xxDma::stream(std::size_t id) const {
    DmaStream s;
    if (id >= kStreamCount) {
        return s;
    }
    const auto base = kStreamBaseOffset + id * kStreamSize;
    s.cr = static_cast<std::uint32_t>(raw_read(base, 4));
    s.ndtr = static_cast<std::uint32_t>(raw_read(base + 4, 4));
    s.par = static_cast<std::uint32_t>(raw_read(base + 8, 4));
    s.mar = static_cast<std::uint32_t>(raw_read(base + 12, 4));
    return s;
}

void STM32F1xxDma::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // dma.py write: the ISR writes ignored, the IFCR clears the ISR bits
    if (offset == kIsrOffset) {
        return;
    }
    if (offset == kIfcrOffset) {
        const auto isr = raw_read(kIsrOffset, 4);
        raw_write(kIsrOffset, 4, isr & ~static_cast<std::uint32_t>(value));
        return;
    }
    QlPeripheral::write_body(offset, size, value);
}

void STM32F1xxDma::transfer_complete(std::size_t id) {
    // dma.py: the ISR TC bits [1, 5, 9, 13, 17, 21, 25] (the 7th stream rides
    // the same bit as the 6th — the verbatim table)
    static const std::uint32_t kTcBits[] = {1, 5, 9, 13, 17, 21, 25};
    const auto bit = kTcBits[std::min<std::size_t>(id, 6)];
    const auto isr = raw_read(kIsrOffset, 4);
    raw_write(kIsrOffset, 4, isr | (1ull << bit));

    if (intn_[id] >= 0) {
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (nvic != nullptr) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_[id]));
        }
    }
}

void STM32F1xxDma::step() {
    // dma.py step: the enabled streams walk
    for (std::size_t id = 0; id < kStreamCount; ++id) {
        auto s = stream(id);
        if (!s.enable()) {
            continue;
        }
        if (s.step(ql().mem())) {
            // the write-back: the stream state rides the instance bytes
            const auto base = kStreamBaseOffset + id * kStreamSize;
            raw_write(base + 4, 4, s.ndtr);
            raw_write(base + 8, 4, s.par);
            raw_write(base + 12, 4, s.mar);
            raw_write(base, 4, s.cr);
            transfer_complete(id);
        } else {
            const auto base = kStreamBaseOffset + id * kStreamSize;
            raw_write(base + 4, 4, s.ndtr);
            raw_write(base + 8, 4, s.par);
            raw_write(base + 12, 4, s.mar);
        }
    }
}

// ---- the I2c ----

std::uint64_t STM32F4xxI2c::read_body(std::uint64_t offset, std::uint32_t size) {
    // i2c.py read: the plain memmove + the SR1/SR2 pair read clears the ADDR
    history.add(Access(PeripheralAction::READ, offset));

    const auto retval = QlConnectivityPeripheral::read_body(offset, size);

    if (history.items().size() >= 2) {
        const auto& last = history.items()[history.items().size() - 1];
        const auto& prev = history.items()[history.items().size() - 2];
        const Access sr1_read(PeripheralAction::READ, kSr1Offset);
        const Access sr2_read(PeripheralAction::READ, kSr2Offset);
        if (prev == sr1_read && last == sr2_read) {
            const auto sr1 = raw_read(kSr1Offset, 4);
            raw_write(kSr1Offset, 4, sr1 & ~i2c::sr1::ADDR);
        }
    }
    return retval;
}

void STM32F4xxI2c::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // i2c.py write: the SR writes ignored, the CR1 rides the START/STOP, the
    // DR rides the master/slave walks
    history.add(Access(PeripheralAction::WRITE, offset, value));

    if (offset == kSr1Offset || offset == kSr2Offset) {
        return;
    }

    if (offset == kCr1Offset) {
        raw_write(kCr1Offset, 4, value & i2c::cr1::RW_MASK);

        if (value & i2c::cr1::START) {
            generate_start();
        }
        if (value & i2c::cr1::STOP) {
            generate_stop();
        }
        return;
    }

    if (offset == kDrOffset) {
        raw_write(kDrOffset, 4, value & i2c::dr::DR);
        const auto sr1 = raw_read(kSr1Offset, 4);
        raw_write(kSr1Offset, 4, sr1 & ~i2c::sr1::TXE);

        if (is_master_mode() && is_7bit_mode()) {
            if (raw_read(kSr2Offset, 4) & i2c::sr2::TRA) {
                send_data();
            } else {
                send_address();
            }
        }
        return;
    }

    QlConnectivityPeripheral::write_body(offset, size, value);
}

void STM32F4xxI2c::send_event_interrupt() {
    // i2c.py send_event_interrupt: the CR2 ITEVTEN + the BUF/SLAVE/MASTER
    // SR1 walks
    if (ev_intn_ < 0) {
        return;
    }
    const auto cr2 = raw_read(kCr2Offset, 4);
    const auto sr1 = raw_read(kSr1Offset, 4);

    const std::uint32_t buf_it = i2c::sr1::TXE | i2c::sr1::RXNE;
    const std::uint32_t slave_it = i2c::sr1::STOPF | i2c::sr1::ADDR | i2c::sr1::BTF;
    const std::uint32_t master_it = i2c::sr1::SB | i2c::sr1::ADDR | i2c::sr1::ADD10 | i2c::sr1::BTF;

    const bool buf_cond = (cr2 & i2c::cr2::ITBUFEN) && (sr1 & buf_it);
    const bool slave_cond = is_slave_mode() && (sr1 & slave_it);
    const bool master_cond = is_master_mode() && (sr1 & master_it);

    if (buf_cond || slave_cond || master_cond) {
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (nvic != nullptr) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(ev_intn_));
        }
    }
}

void STM32F4xxI2c::generate_start() {
    // i2c.py generate_start: the device address fetch + the SB set + the
    // START clear + the master mode
    fetch_device_address();
    const auto sr1 = raw_read(kSr1Offset, 4);
    raw_write(kSr1Offset, 4, sr1 | i2c::sr1::SB);
    const auto cr1 = raw_read(kCr1Offset, 4);
    raw_write(kCr1Offset, 4, cr1 & ~i2c::cr1::START);
    set_master_mode();
}

void STM32F4xxI2c::generate_stop() {
    // i2c.py generate_stop: the STOP clear + the STOPF set + the ADDR clear +
    // the slave mode + the TRA clear
    const auto cr1 = raw_read(kCr1Offset, 4);
    raw_write(kCr1Offset, 4, cr1 & ~i2c::cr1::STOP);

    const auto sr1 = raw_read(kSr1Offset, 4);
    raw_write(kSr1Offset, 4, (sr1 | i2c::sr1::STOPF) & ~i2c::sr1::ADDR);

    set_slave_mode();
    const auto sr2 = raw_read(kSr2Offset, 4);
    raw_write(kSr2Offset, 4, sr2 & ~i2c::sr2::TRA);
}

void STM32F4xxI2c::send_address() {
    // i2c.py send_address: the own-address match rides the ADDR/TXE/AF + the
    // TRA set
    const auto dr = raw_read(kDrOffset, 4);
    const auto oar1 = raw_read(kOar1Offset, 4);
    if (dr == (oar1 >> 1)) {
        auto sr1 = raw_read(kSr1Offset, 4);
        sr1 &= ~i2c::sr1::SB;
        sr1 |= i2c::sr1::ADDR | i2c::sr1::TXE | i2c::sr1::AF;
        raw_write(kSr1Offset, 4, sr1);
        const auto sr2 = raw_read(kSr2Offset, 4);
        raw_write(kSr2Offset, 4, sr2 | i2c::sr2::TRA);
    }
}

void STM32F4xxI2c::send_data() {
    // i2c.py send_data: the BTF/TXE set + the DR byte to the output tube
    const auto sr1 = raw_read(kSr1Offset, 4);
    raw_write(kSr1Offset, 4, sr1 | i2c::sr1::BTF | i2c::sr1::TXE);
    send_to_user(raw_read(kDrOffset, 4));
}

bool STM32F4xxI2c::is_7bit_mode() const {
    // i2c.py is_7bit_mode: the dual addressing or the non-10-bit OAR1
    const auto oar2 = raw_read(kOar2Offset, 4);
    const auto oar1 = raw_read(kOar1Offset, 4);
    return (oar2 & i2c::oar2::ENDUAL) != 0 || (oar1 & i2c::oar1::ADDMODE) == 0;
}

void STM32F4xxI2c::fetch_device_address() {
    // i2c.py fetch_device_address: the OAR1 write from the first connected
    // device address (the dual/10-bit/7-bit walks); the port's device list
    // rides the connectivity device_list (the empty list skips — the upstream
    // would IndexError)
    if (device_list().empty()) {
        return;
    }
    // the device address ride lands with the chardev bridge slice; the
    // single-device 7-bit walk pins the OAR1 shape
    const auto oar1 = raw_read(kOar1Offset, 4);
    (void)oar1;
}

}  // namespace hw
}  // namespace qiling
