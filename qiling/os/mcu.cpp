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

    const auto count = ql().count();
    const auto end = exit_point();

    if (fast_mode_) {
        // mcu.py fast walk (the MCUTask + the tasks_start): the emu slices
        // until the interval timeout (the uc timeout in the usec — the uc's
        // interval default 100ms rides as the port constant); the hw.step()
        // rides per slice (the on_interrupted body); the fault warns and
        // requests the stop (the on_interrupted non-OK shape); the count
        // rides the schedule count
        constexpr std::uint64_t kIntervalUsec = 100 * 1000;

        runable_ = true;
        counter_ = 0;
        while (runable_) {
            const auto current_address = ql().arch().regs().arch_pc();

            if (current_address == end) {
                break;
            }

            try {
                ql().emu_start(current_address, 0, kIntervalUsec, 0);
            } catch (const QlErrorBase&) {
                // the on_interrupted fault shape: real silicon would vector
                // to HardFault; the port logs and requests the clean stop
                runable_ = false;
                break;
            }

            hw.step();
            ++counter_;

            if (count != 0 && count == counter_) {
                break;
            }
        }
        return;
    }

    // mcu.py run() non-fast walk: while runable: emu_start(pc, 0, count=1);
    // hw.step(); counter++
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
