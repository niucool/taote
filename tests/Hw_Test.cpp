// The hw-groundwork suite: the QlHwManager + the QlPeripheral base + the
// QlPripheralHandler MMIO dispatch (qiling/hw/hw.py + peripheral.py). The
// fixture rides the host-side mmio access (uc routes the mem read/write
// through the mmio callbacks).
#include <gtest/gtest.h>

#include <string>

#include "qiling/core.hpp"
#include "qiling/hw/hw.hpp"
#include "qiling/hw/peripheral.hpp"
#include "qiling/exception.hpp"

using namespace qiling;

namespace {

// the minimal concrete peripheral: the 8-byte register image
// (CSR@0, DATA@4); the write to DATA latches, the read of DATA returns it,
// the read of CSR returns the write count (the step-able state)
class StubPeripheral final : public qiling::hw::QlPeripheral {
public:
    StubPeripheral(Qiling& ql, const std::string& label) : QlPeripheral(ql, label, 8) {}

    std::size_t struct_size() const noexcept { return 8; }

    std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) override {
        // CSR (offset 0) rides the write count; the DATA passes through
        if (offset == 0) {
            return writes_;
        }
        return QlPeripheral::read_body(offset, size);
    }

    void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override {
        QlPeripheral::write_body(offset, size, value);
        if (offset == 4) {
            ++writes_;
        }
    }

    void step() override { ++steps_; }

    std::uint64_t writes_ = 0;
    std::uint64_t steps_ = 0;
};

constexpr std::uint64_t kMmioBase = 0x40000000;  // the page-aligned mmio base

Qiling make_hw_ql() {
    QilingOptions options;
    options.code = {0x90};  // the nop stub (the mmio ride needs no guest run)
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    return Qiling(options);
}

}  // namespace

TEST(HwManager, CreateFindsAndDispatchesMmio) {
    auto ql = make_hw_ql();
    qiling::hw::QlHwManager hw(ql);

    hw.register_struct("stub", [](Qiling& q, const std::string& label) {
        return std::make_unique<StubPeripheral>(q, label);
    });
    auto* peripheral = hw.create("uart0", "stub", kMmioBase);
    ASSERT_NE(peripheral, nullptr);
    auto* stub = static_cast<StubPeripheral*>(peripheral);

    hw.setup_mmio(kMmioBase, 0x1000, "[stub-mmio]");

    // the find walk: the region lookup resolves the peripheral
    EXPECT_EQ(hw.find(kMmioBase), peripheral);
    EXPECT_EQ(hw.find(kMmioBase + 7), peripheral);
    EXPECT_EQ(hw.find(kMmioBase + 8), nullptr);
    EXPECT_EQ(peripheral->base(), kMmioBase);

    // the mmio write dispatch: the peripheral's write_body fires with the
    // region-relative offset
    ql.mem().write(kMmioBase + 4, std::vector<std::uint8_t>{0x11, 0x22, 0x33, 0x44});
    EXPECT_EQ(stub->writes_, 1u);
    EXPECT_EQ(ql.mem().read(kMmioBase + 4, 4)[0], 0x11);

    // the read rides back the latched register image
    EXPECT_EQ(ql.mem().read(kMmioBase + 4, 4)[1], 0x22);
}

TEST(HwManager, HookWalkEntersCallsExits) {
    auto ql = make_hw_ql();
    qiling::hw::QlHwManager hw(ql);

    hw.register_struct("stub", [](Qiling& q, const std::string& label) {
        return std::make_unique<StubPeripheral>(q, label);
    });
    auto* peripheral = hw.create("uart1", "stub", kMmioBase);
    ASSERT_NE(peripheral, nullptr);
    auto* stub = static_cast<StubPeripheral*>(peripheral);
    hw.setup_mmio(kMmioBase, 0x1000, "[stub-mmio-hooks]");

    int enters = 0, calls = 0, exits = 0;
    // the ENTER intercept rides around the body (the value passes)
    peripheral->hook_write([&](qiling::hw::QlPeripheral&, qiling::hw::PeripheralAction action,
                               std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        EXPECT_EQ(action, qiling::hw::PeripheralAction::WRITE);
        EXPECT_EQ(offset, 4u);
        EXPECT_EQ(size, 4u);
        EXPECT_EQ(value, 0xabcdef01u);
        ++enters;
        return 0;
    }, qiling::hw::QlPeripheralUtils::Intercept::ENTER);
    // the CALL intercept REPLACES the body (the monitor-decorator shape)
    peripheral->hook_write([&](qiling::hw::QlPeripheral&, qiling::hw::PeripheralAction,
                               std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        ++calls;
        peripheral->raw_write(offset, size, 0xdeadbeef);  // the replacement body
        return 0;
    }, qiling::hw::QlPeripheralUtils::Intercept::CALL);
    peripheral->hook_write([&](qiling::hw::QlPeripheral&, qiling::hw::PeripheralAction,
                               std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        ++exits;
        return 0;
    }, qiling::hw::QlPeripheralUtils::Intercept::EXIT);

    ql.mem().write(kMmioBase + 4, std::vector<std::uint8_t>{0x01, 0xef, 0xcd, 0xab});

    EXPECT_EQ(enters, 1);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(exits, 1);
    // the CALL body replaced the write — the DATA holds 0xdeadbeef (the LE
    // bytes) and the stub's own write_body never counted it
    EXPECT_EQ(ql.mem().read(kMmioBase + 4, 4)[0], 0xef);
    EXPECT_EQ(stub->writes_, 0u);
}

TEST(HwManager, NonMappedMmioRidesHandlerBuffer) {
    auto ql = make_hw_ql();
    qiling::hw::QlHwManager hw(ql);

    // the mmio region with NO peripheral: the handler's own buffer rides
    hw.setup_mmio(kMmioBase + 0x1000, 0x1000, "[bare-mmio]");

    ql.mem().write(kMmioBase + 0x1004, std::vector<std::uint8_t>{0x5a, 0xa5});
    const auto got = ql.mem().read(kMmioBase + 0x1004, 2);
    EXPECT_EQ(got[0], 0x5a);
    EXPECT_EQ(got[1], 0xa5);
}

TEST(HwManager, StepWalksPeripheralsAndSaveRestore) {
    auto ql = make_hw_ql();
    qiling::hw::QlHwManager hw(ql);

    hw.register_struct("stub", [](Qiling& q, const std::string& label) {
        return std::make_unique<StubPeripheral>(q, label);
    });
    auto* peripheral = hw.create("timer0", "stub", kMmioBase);
    ASSERT_NE(peripheral, nullptr);
    auto* stub = static_cast<StubPeripheral*>(peripheral);

    stub->write_body(4, 4, 1);
    hw.step();
    hw.step();
    EXPECT_EQ(stub->steps_, 2u);

    // the save/restore pair over the instance bytes
    const auto saved = peripheral->save();
    peripheral->write_body(4, 4, 7);
    EXPECT_EQ(peripheral->raw_read(4, 4), 7u);
    peripheral->restore(saved);
    EXPECT_EQ(peripheral->raw_read(4, 4), 1u);
}
