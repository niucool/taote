// The implementation half of os/mcu.hpp (the mcu.py QlOsMcu walk).
#include "qiling/os/mcu.hpp"

#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"

#include <spdlog/spdlog.h>

namespace qiling {
namespace os {

QlOsMcu::QlOsMcu(Qiling* ql) : QlOs(ql) {
    runable_ = true;
}

void QlOsMcu::stop() {
    // mcu.py stop: emu_stop then runable = false (the while-loop exit)
    ql().emu_stop();
    runable_ = false;
}

void QlOsMcu::run() {
    auto& hw = *ql().hw();

    // mcu.py run() non-fast walk: while runable: emu_start(pc, 0, count=1);
    // hw.step(); counter++ — the fast-mode uc-task path lands with the
    // multitask slice (the fast_mode set throws here for now)
    if (fast_mode_) {
        throw QlErrorNotImplemented("the mcu fast mode lands with the uc task slice");
    }

    const auto count = ql().count();
    const auto end = exit_point();

    runable_ = true;
    counter_ = 0;
    while (runable_) {
        const auto current_address = [&] {
            // the effective_pc preference (the cortex_m.py walk)
            return ql().arch().regs().arch_pc();
        }();

        if (current_address == end) {
            break;
        }

        ql().emu_start(current_address, 0, 0, 1);
        hw.step();

        ++counter_;

        if (count != 0 && count == counter_) {
            break;
        }
    }
}

}  // namespace os
}  // namespace qiling
