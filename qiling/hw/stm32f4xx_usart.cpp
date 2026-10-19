// The implementation half of stm32f4xx_usart.hpp (the interrupt-check + the
// step walks).
#include "qiling/hw/stm32f4xx_usart.hpp"

#include "qiling/hw/cm_nvic.hpp"

namespace qiling {
namespace hw {

void STM32F4xxUsart::check_interrupt() {
    // usart.py check_interrupt: the (CR1 enable, SR status) pairs pend the
    // nvic with the peripheral's interrupt number
    if (intn_ < 0) {
        return;
    }

    const auto cr1 = raw_read(kCr1Offset, 4);
    const auto sr = raw_read(kSrOffset, 4);

    const bool peie_and_pe = (cr1 & usart::cr1::PEIE) && (sr & usart::sr::PE);
    const bool txeie_and_txe = (cr1 & usart::cr1::TXEIE) && (sr & usart::sr::TXE);
    const bool tcie_and_tc = (cr1 & usart::cr1::TCIE) && (sr & usart::sr::TC);
    const bool rxneie_and_rxne = (cr1 & usart::cr1::RXNEIE) && (sr & usart::sr::RXNE);
    const bool idleie_and_idle = (cr1 & usart::cr1::IDLEIE) && (sr & usart::sr::IDLE);

    if (peie_and_pe || txeie_and_txe || tcie_and_tc || rxneie_and_rxne || idleie_and_idle) {
        auto* nvic = ql().hw() != nullptr ? ql().hw()->peripheral("nvic") : nullptr;
        if (nvic != nullptr) {
            dynamic_cast<CortexMNvic&>(*nvic).set_pending(static_cast<int>(intn_));
        }
    }
}

void STM32F4xxUsart::step() {
    // usart.py step (the @device_handler ride): the output tube forwards one
    // byte to the connected devices and the devices step (the chardev bridge
    // slice completes the device walk — the port keeps the tube transfer);
    // then the transfer + the interrupt-check walks
    if (!device_list().empty()) {
        if (otube().readable()) {
            // the device bridge rides the chardev slice (the upstream sends
            // the byte to each connected device)
        }
    }

    transfer();
    check_interrupt();
}

}  // namespace hw
}  // namespace qiling
