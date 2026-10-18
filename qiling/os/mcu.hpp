// Ported from qiling/os/mcu/mcu.py (QlOsMcu). The non-fast-mode walk runs
// the emu_start(count=1) slice per iteration and drives hw.step() between
// them (the os/mcu.py while-loop verbatim); the fast-mode uc-task path
// (MCUTask + tasks_start) lands with the multitask slice. The periphery
// (the console out, the profile reads) rides the QlOs base.
#pragma once

#ifndef QILING_OS_MCU_HPP
#define QILING_OS_MCU_HPP

#include "qiling/os/os.hpp"
#include "qiling/hw/hw.hpp"

namespace qiling {
namespace os {

class QlOsMcu final : public QlOs {
public:
    explicit QlOsMcu(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::MCU; }

    void run() override;

    // mcu.py stop: emu_stop + runable = false (the while-loop exit)
    void stop() override;

    bool runable() const noexcept { return runable_; }
    std::uint64_t counter() const noexcept { return counter_; }

private:
    bool runable_ = false;
    bool fast_mode_ = false;
    std::uint64_t counter_ = 0;
};

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MCU_HPP
