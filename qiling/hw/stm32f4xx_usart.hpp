// Ported from qiling/hw/char/stm32f4xx_usart.py (STM32F4xxUsart) and
// hw/char/stm32f1xx_usart.py (STM32F1xxUsart — the same register surface, the
// F1 subclass is the verbatim pass-through). The 28-byte image
// (SR/DR/BRR/CR1/CR2/CR3/GTPR); the DR read clears the RXNE and rides the
// input tube, the DR write sends to the output tube, the SR write keeps the
// TC/RXNE/TXE sticky bits, the step rides the device-handler + the
// transfer + the interrupt-check walks.
#pragma once

#ifndef QILING_HW_STM32F4XX_USART_HPP
#define QILING_HW_STM32F4XX_USART_HPP

#include "qiling/hw/connectivity.hpp"
#include "qiling/hw/const_stm32f4xx_usart.hpp"
#include "qiling/hw/hw.hpp"

namespace qiling {
namespace hw {

class STM32F4xxUsart : public QlConnectivityPeripheral {
public:
    static constexpr std::size_t kStructSize = 28;
    static constexpr std::uint64_t kSrOffset = 0;
    static constexpr std::uint64_t kDrOffset = 4;
    static constexpr std::uint64_t kBrrOffset = 8;
    static constexpr std::uint64_t kCr1Offset = 12;
    static constexpr std::uint64_t kCr2Offset = 16;
    static constexpr std::uint64_t kCr3Offset = 20;
    static constexpr std::uint64_t kGtprOffset = 24;

    STM32F4xxUsart(Qiling& ql, const std::string& label, std::int64_t intn = -1)
        : QlConnectivityPeripheral(ql, label, kStructSize), intn_(intn) {
        // the verbatim instance seed: SR = TXE | TC
        raw_write(kSrOffset, 4, usart::sr::RESET);
    }
    // the monitor-decorated read body: the DR read clears the RXNE, rides
    // the input tube, and re-runs the transfer walk
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override {
        if (offset == kDrOffset) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, sr & ~usart::sr::RXNE);
            std::uint64_t retval = 0;
            if (has_input()) {
                retval = recv_from_user();
            }
            transfer();
            return retval;
        }
        return QlPeripheral::read_body(offset, size);
    }

    // the monitor-decorated write body: the SR keeps the sticky bits, the DR
    // sends to the output tube, the others store
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override {
        if (offset == kSrOffset) {
            const auto sr = raw_read(kSrOffset, 4);
            raw_write(kSrOffset, 4, (value & ~(usart::sr::CTS | usart::sr::LBD | usart::sr::TC | usart::sr::RXNE | usart::sr::TXE)) |
                                        (sr & (usart::sr::CTS | usart::sr::LBD | usart::sr::TC | usart::sr::RXNE | usart::sr::TXE)));
        } else if (offset == kDrOffset) {
            send_to_user(value);
        } else {
            QlPeripheral::write_body(offset, size, value);
        }
    }

    // connectivity.py transfer: the input available raises the RXNE
    void transfer() {
        const auto sr = raw_read(kSrOffset, 4);
        if (!(sr & usart::sr::RXNE)) {
            if (has_input()) {
                raw_write(kSrOffset, 4, sr | usart::sr::RXNE);
            }
        }
    }

    // usart.py check_interrupt: the CR1 enable / SR status pairs pend the nvic
    void check_interrupt();

    // usart.py step (the @QlConnectivityPeripheral.device_handler ride: the
    // tube byte forwarded to the connected devices + the device steps — the
    // chardev bridge slice completes the device walk)
    void step() override;

    void set_intn(std::int64_t intn) { intn_ = intn; }

protected:
    std::int64_t intn_ = -1;
};

// hw/char/stm32f1xx_usart.py STM32F1xxUsart — the verbatim pass-through (the
// register surface is the same 28-byte image); the intn rides the factory's
// kwargs walk in the hw manager registrations
using STM32F1xxUsart = STM32F4xxUsart;

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F4XX_USART_HPP
