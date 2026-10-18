// The hw-groundwork suite: the QlHwManager + the QlPeripheral base + the
// QlPripheralHandler MMIO dispatch (qiling/hw/hw.py + peripheral.py). The
// fixture rides the host-side mmio access (uc routes the mem read/write
// through the mmio callbacks).
#include <gtest/gtest.h>

#include <string>

#include "qiling/core.hpp"
#include "qiling/hw/hw.hpp"
#include "qiling/hw/peripheral.hpp"
#include "qiling/hw/cm_systick.hpp"
#include "qiling/exception.hpp"

using namespace qiling;

namespace {

std::filesystem::path ensure_hw_rootfs() {
    const auto base = std::filesystem::temp_directory_path() / "ql_hw_rootfs";
    std::filesystem::create_directories(base);
    return base;
}

}  // namespace

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

TEST(HwManager, StepWalksPeripheralsAndSaveRestore) {    auto ql = make_hw_ql();
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

// the guest-side ride: the x86-64 blob stores the SYSTICK LOAD/CTRL through
// the mmio (the cpu load/store against the peripheral), the test drives the
// step walk, and the COUNTFLAG rides the read-clear
TEST(HwManager, GuestBlobStoresThroughMmioToSysTick) {
    const std::vector<std::uint8_t> code = {
        // mov eax, 3
        0xB8, 0x03, 0x00, 0x00, 0x00,
        // mov [0xE000E014], eax   -- the moffs store (the 8-byte abs64 LE)
        0xA3, 0x14, 0xE0, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00,
        // mov eax, 7
        0xB8, 0x07, 0x00, 0x00, 0x00,
        // mov [0xE000E010], eax
        0xA3, 0x10, 0xE0, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00,
        // exit(0)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };

    QilingOptions options;
    options.code = code;
    options.rootfs = ensure_hw_rootfs().string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    qiling::hw::QlHwManager hw(ql);
    hw.register_struct("cm3_systick", [](Qiling& q, const std::string& label) {
        return std::make_unique<qiling::hw::CortexMSysTick>(q, label);
    });
    auto* systick = hw.create("systick", "cm3_systick", 0xE000E010);
    ASSERT_NE(systick, nullptr);
    // the SYSTICK base is not page-aligned: the mmio map covers the containing
    // page while the peripheral keeps its verbatim 0xE000E010 base
    hw.setup_mmio(0xE000E000, 0x1000, "[systick-page]");

    auto tracer = ql.hook_mem_write_invalid([&](int access, std::uint64_t addr, std::uint32_t size, std::int64_t) -> int {
        std::fprintf(stderr, "[wfault] access=%d addr=%llx size=%u rip=%llx\n", access,
                     (unsigned long long)addr, size, (unsigned long long)ql.arch().regs().arch_pc());
        return 0;
    });
    (void)tracer;

    ql.run();

    // the guest stores landed: the LOAD cell carries 3, the CTRL the mask 7
    EXPECT_EQ(systick->raw_read(4, 4), 3u);
    EXPECT_EQ(systick->raw_read(0, 4), 7u);

    // the step walk: 3 -> 2 -> 1 -> 0 -> (the COUNTFLAG set + the reload to 3)
    hw.step();  // 3 -> 2
    hw.step();  // 2 -> 1
    EXPECT_EQ(systick->raw_read(8, 4), 1u);
    hw.step();  // 1 -> 0
    hw.step();  // the zero reload: COUNTFLAG | VAL = LOAD(3)
    EXPECT_EQ(systick->raw_read(0, 4),
              (qiling::hw::systick_ctrl::ENABLE | qiling::hw::systick_ctrl::TICKINT |
               qiling::hw::systick_ctrl::CLKSOURCE | qiling::hw::systick_ctrl::COUNTFLAG));
    EXPECT_EQ(systick->raw_read(8, 4), 3u);
}
