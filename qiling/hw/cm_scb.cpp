// The implementation half of cm_scb.hpp: the ICSR write path (the PENDSVSET
// bit rides back into the nvic entity).
#include "qiling/hw/cm_scb.hpp"
#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/hw.hpp"

namespace qiling {
namespace hw {

void CortexMScb::write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    // cm_scb.py write: the ICSR PENDSVSET (bit 28) sets the PendSV pending
    // through the nvic entity
    if (offset == kIcsrOffset) {
        if (((value >> 28) & 1) != 0) {
            auto* nvic = dynamic_cast<CortexMNvic*>(ql().hw()->peripheral("nvic"));
            if (nvic != nullptr) {
                nvic->set_pending(static_cast<int>(IRQ::PENDSV));
            }
        }
    }

    QlPeripheral::write_body(offset, size, value);
}

}  // namespace hw
}  // namespace qiling
