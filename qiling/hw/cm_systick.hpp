// Ported from qiling/hw/timer/timer.py (QlTimerPeripheral) and
// hw/timer/cm_systick.py (CortexMSysTick) + hw/timer/cm3_systick.py (the
// pass-through subclass). The SYSTICK_CTRL bit table rides
// hw/const/cm4_systick.py verbatim.
//
// The port's QlPeripheral hook walk replaces the @monitor() decorators: the
// subclass bodies land as read_body/write_body overrides (the base read/
// write run the ENTER/CALL/EXIT walk around them, the CALL intercept
// replacing the body — the decorator's if/else verbatim).
//
// The implementation bodies ride timer.cpp (the TICKINT branch needs the
// hw manager's full type, which cannot be included from the header without
// the hw.hpp <-> peripheral.hpp cycle).
#pragma once

#include "qiling/hw/peripheral.hpp"
#include "qiling/exception.hpp"

#include <cstring>

namespace qiling {
namespace hw {

// hw/const/cm4_systick.py SYSTICK_CTRL
namespace systick_ctrl {
inline constexpr std::uint32_t ENABLE = 1u << 0;
inline constexpr std::uint32_t TICKINT = 1u << 1;
inline constexpr std::uint32_t CLKSOURCE = 1u << 2;
inline constexpr std::uint32_t COUNTFLAG = 1u << 16;
inline constexpr std::uint32_t MASK = ENABLE | TICKINT | CLKSOURCE | COUNTFLAG;
}  // namespace systick_ctrl

// hw/timer/timer.py QlTimerPeripheral — the ratio + the extended snapshot
class QlTimerPeripheral : public QlPeripheral {
public:
    QlTimerPeripheral(Qiling& ql, std::string label, std::size_t image_size)
        : QlPeripheral(ql, std::move(label), image_size) {}

    virtual void set_ratio(std::uint64_t ratio) { ratio_ = ratio; }
    virtual std::uint64_t ratio() const noexcept { return ratio_; }

    // timer.py save: (ratio, bytes(instance)) — the pair rides the vector
    // header (the first 8 bytes carry the ratio)
    std::vector<std::uint8_t> save() const override {
        std::vector<std::uint8_t> out(sizeof(ratio_));
        std::memcpy(out.data(), &ratio_, sizeof(ratio_));
        const auto state = QlPeripheral::save();
        out.insert(out.end(), state.begin(), state.end());
        return out;
    }

    void restore(const std::vector<std::uint8_t>& data) override {
        if (data.size() < sizeof(ratio_)) {
            throw QlErrorBase("timer snapshot too short");
        }
        std::memcpy(&ratio_, data.data(), sizeof(ratio_));
        QlPeripheral::restore(std::vector<std::uint8_t>(data.begin() + sizeof(ratio_), data.end()));
    }

protected:
    std::uint64_t ratio_ = 1;
};

// hw/timer/cm_systick.py CortexMSysTick — the 4-register SYSTICK image
// (CTRL@0, LOAD@4, VAL@8, CALIB@12)
class CortexMSysTick : public QlTimerPeripheral {
public:
    CortexMSysTick(Qiling& ql, const std::string& label)
        : QlTimerPeripheral(ql, label, 16) {
        // the verbatim instance seed: CALIB = 0xC0000000
        raw_write(12, 4, 0xC0000000ull);
    }

    // cm_systick.py step: the downcount walk (the COUNTFLAG set + the LOAD
    // reload at zero; the TICKINT branch pends the nvic)
    void step() override;

    // cm_systick.py read (the @monitor() body): the CTRL read clears the
    // COUNTFLAG
    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override {
        if (offset == 0) {
            const auto c = static_cast<std::uint32_t>(raw_read(0, 4));
            raw_write(0, 4, c & ~systick_ctrl::COUNTFLAG);
        }
        return QlPeripheral::read_body(offset, size);
    }

    // cm_systick.py write (the @monitor() body): the reserved-bit masks +
    // the LOAD restart
    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override {
        if (offset == 0) {
            value &= systick_ctrl::MASK;
        } else {
            value &= 0xffffff;  // only the low-24 bits available
        }

        if (offset == 4) {
            raw_write(8, 4, value);  // VAL = the new LOAD (the restart)
        }

        QlPeripheral::write_body(offset, size, value);
    }
};

}  // namespace hw
}  // namespace qiling
