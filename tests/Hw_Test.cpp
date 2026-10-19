// The hw-groundwork suite: the QlHwManager + the QlPeripheral base + the
// QlPripheralHandler MMIO dispatch (qiling/hw/hw.py + peripheral.py). The
// fixture rides the host-side mmio access (uc routes the mem read/write
// through the mmio callbacks).
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/hw/hw.hpp"
#include "qiling/hw/peripheral.hpp"
#include "qiling/hw/cm_systick.hpp"
#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/cm_scb.hpp"
#include "qiling/hw/stm32f4xx_tim.hpp"
#include "qiling/hw/stm32f1xx_gpio.hpp"
#include "qiling/hw/stm32f4xx_usart.hpp"
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

    hw.register_struct("stub", [](Qiling& q, const std::string& label, const qiling::hw::QlHwManager::PeripheralKwargs&) {
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

    hw.register_struct("stub", [](Qiling& q, const std::string& label, const qiling::hw::QlHwManager::PeripheralKwargs&) {
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

    hw.register_struct("stub", [](Qiling& q, const std::string& label, const qiling::hw::QlHwManager::PeripheralKwargs&) {
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
        // mov eax, 5   -- CTRL = ENABLE|CLKSOURCE (no TICKINT: this fixture
        // carries no nvic, the upstream would raise on the set_pending walk)
        0xB8, 0x05, 0x00, 0x00, 0x00,
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
    hw.register_struct("cm3_systick", [](Qiling& q, const std::string& label, const qiling::hw::QlHwManager::PeripheralKwargs&) {
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

    // the guest stores landed: the LOAD cell carries 3, the CTRL the mask 5
    EXPECT_EQ(systick->raw_read(4, 4), 3u);
    EXPECT_EQ(systick->raw_read(0, 4), 5u);

    // the step walk: 3 -> 2 -> 1 -> 0 -> (the COUNTFLAG set + the reload to 3)
    hw.step();  // 3 -> 2
    hw.step();  // 2 -> 1
    EXPECT_EQ(systick->raw_read(8, 4), 1u);
    hw.step();  // 1 -> 0
    hw.step();  // the zero reload: COUNTFLAG | VAL = LOAD(3)
    EXPECT_EQ(systick->raw_read(0, 4),
              (qiling::hw::systick_ctrl::ENABLE | qiling::hw::systick_ctrl::CLKSOURCE |
               qiling::hw::systick_ctrl::COUNTFLAG));
    EXPECT_EQ(systick->raw_read(8, 4), 3u);
}

// ---- the intc slice: the CORTEX_M walk over the nvic/scb/systick trio ----

namespace {

// the ihex record builder (the proper LL/AAAA/TT + the two's-complement CC)
std::string ihex_line(std::uint16_t addr, std::uint8_t type, const std::vector<std::uint8_t>& data) {
    auto hex8 = [](std::uint32_t v, int width) {
        std::string out;
        for (int shift = (width - 1) * 4; shift >= 0; shift -= 4) {
            const auto nibble = (v >> shift) & 0xF;
            out += static_cast<char>(nibble < 10 ? '0' + nibble : 'A' + nibble - 10);
        }
        return out;
    };

    std::string body;
    body += hex8(data.size(), 2);
    body += hex8(addr, 4);
    body += hex8(type, 2);
    int sum = static_cast<int>(data.size()) + (addr >> 8) + (addr & 0xff) + type;
    for (const auto b : data) {
        body += hex8(b, 2);
        sum += b;
    }
    body += hex8((-sum) & 0xFF, 2);
    return ":" + body;
}

std::string write_ihex_fixture() {
    const auto base = std::filesystem::temp_directory_path() / "ql_hw_intc.hex";
    {
        std::ofstream out(base, std::ios::binary | std::ios::trunc);

        std::vector<std::uint8_t> vec(0x40, 0);
        const auto put32 = [&vec](std::size_t at, std::uint32_t v) {
            vec[at] = v & 0xff;
            vec[at + 1] = (v >> 8) & 0xff;
            vec[at + 2] = (v >> 16) & 0xff;
            vec[at + 3] = (v >> 24) & 0xff;
        };
        put32(0, 0x20000400);   // the initial MSP (inside the SRAM region)
        put32(4, 0x00000041);   // the reset handler (the thumb bit rides the lsb)
        put32(0x3C, 0x00001001);  // the SysTick handler (vector 15)

        // the main loop at 0x40: b . (the thumb 0xE7FE)
        std::vector<std::uint8_t> main_code = {0xFE, 0xE7};
        // the handler at 0x1000: movs r0,#42; movs r1,#0x20; lsls r1,r1,#24;
        // str r0,[r1]; bx lr (the marker store at 0x20000000)
        std::vector<std::uint8_t> handler = {0x2A, 0x20, 0x20, 0x21, 0x09, 0x06, 0x08, 0x60, 0x70, 0x47};

        out << ihex_line(0x0000, 0x00, vec) << "\n";
        out << ihex_line(0x0040, 0x00, main_code) << "\n";
        out << ihex_line(0x1000, 0x00, handler) << "\n";
        out << ":00000001FF\n";  // the EOF record
    }
    return base.string();
}

}  // namespace

// The TICKINT dispatch ride: the SysTick's downcount crosses zero with the
// TICKINT set, the pending rides the nvic (the SCB's ICSR internally), and the
// nvic step dispatches the vector[15] handler through the interrupt context.
TEST(HwManager, CortexMIntcDispatchesSysTickThroughNvic) {
    const auto hex_path = write_ihex_fixture();

    QilingOptions options;
    options.argv = {hex_path};
    options.rootfs = ensure_hw_rootfs().string();
    options.ostype = QL_OS::MCU;
    options.archtype = QL_ARCH::CORTEX_M;
    options.env = {
        {"FLASH", "memory;0x0;0x2000"},
        {"SRAM", "memory;0x20000000;0x1000"},
        {"PPB", "mmio;0xE000E000;0x1000"},
        {"SYSTICK", "core;cm3_systick;0xE000E010"},
        {"NVIC", "core;cm_nvic;0xE000E100"},
        {"SCB", "core;cm4_scb;0xE000ED00"},
    };
    Qiling ql(options);

    auto* systick = ql.hw()->peripheral("systick");
    auto* nvic = ql.hw()->peripheral("nvic");
    auto* scb = ql.hw()->peripheral("scb");
    ASSERT_NE(systick, nullptr);
    ASSERT_NE(nvic, nullptr);
    ASSERT_NE(scb, nullptr);

    // the load: LOAD=3, CTRL=ENABLE|TICKINT|CLKSOURCE
    systick->write(4, 4, 3);
    systick->write(0, 4, 7);

    // the bounded walk: the slices cross zero on the third step and the
    // dispatch rides the fourth hw.step()
    ql.run(std::nullopt, std::nullopt, 0, 12);

    // the handler stored 42 at the SRAM marker
    EXPECT_EQ(ql.mem().read_ptr(0x20000000, 4), 42u);
    // the pending cleared after the dispatch (the SCB's ICSR walk)
    EXPECT_EQ(dynamic_cast<qiling::hw::CortexMScb*>(scb)->get_pending(static_cast<int>(qiling::IRQ::SYSTICK)), 0u);
}

// ---- the board-profile slices: the STM32F1xx peripheral families ----

// The Gpio family: the guest x86-64 blob stores to the GPIOA BSRR (the set
// bits 0/1 + the reset bit 16+2) and the ODR through the mmio; the pin hooks
// fire on the flips.
TEST(HwManager, Stm32f1xxGpioBsrrOdrWalkRidesPinHooks) {
    const std::vector<std::uint8_t> code = {
        // mov eax, 3; mov [0x40010810], eax   -- the BSRR low half: the set the pins 0/1
        0xB8, 0x03, 0x00, 0x00, 0x00,
        0xA3, 0x10, 0x08, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00,
        // mov eax, 0x10000; mov [0x40010810], eax -- the BSRR high half: the reset the pin 0
        0xB8, 0x00, 0x00, 0x01, 0x00,
        0xA3, 0x10, 0x08, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00,
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
    auto* gpioa = hw.create("gpioa", "STM32F1xxGpio", 0x40010800);
    ASSERT_NE(gpioa, nullptr);
    // the PERIP mmio block rides the board's 1MB region (the stm32f103 env)
    hw.setup_mmio(0x40000000, 0x100000, "[perip]");

    // the hook markers ride the pins
    int set0 = 0, set1 = 0, reset0 = 0, reset1 = 0;
    auto* gpio = static_cast<qiling::hw::STM32F1xxGpio*>(gpioa);
    gpio->hook_set(0, [&] { ++set0; });
    gpio->hook_set(1, [&] { ++set1; });
    gpio->hook_reset(0, [&] { ++reset0; });
    gpio->hook_reset(1, [&] { ++reset1; });

    ql.run();

    // the BSRR walk: the low half set the pins 0/1, the high half reset the pin 0
    EXPECT_EQ(set0, 1);
    EXPECT_EQ(set1, 1);
    EXPECT_EQ(reset0, 1);
    EXPECT_EQ(gpio->pin(0), 0u);
    EXPECT_EQ(gpio->pin(1), 1u);
    // the BSRR reads as 0 (the write-only register)
    EXPECT_EQ(gpioa->read(16, 4), 0u);
    // the IDR write is ignored (the store to the IDR leaves the bits)
    gpio->write_body(8, 4, 0);
    EXPECT_EQ(gpio->pin(1), 1u);
    // the ODR diff walk: the store of 0 resets the set pins and fires the
    // reset hooks (the pin 0 was already low, only the pin 1 flips)
    gpio->write_body(12, 4, 0);
    EXPECT_EQ(gpio->pin(0), 0u);
    EXPECT_EQ(gpio->pin(1), 0u);
    EXPECT_EQ(reset1, 1);
}

// The Usart family: the usart rides the CORTEX_M env walk (the usart2 core
// item with the intn kwarg); the DR writes land in the output tube, the
// host-injected input rides the RXNE walk, and the RXNEIE/SR-RXNE pair pends
// the nvic through the check_interrupt walk.
TEST(HwManager, Stm32f1xxUsartTubesRideDrAndInterruptCheck) {
    const auto hex_path = write_ihex_fixture();

    QilingOptions options;
    options.argv = {hex_path};
    options.rootfs = ensure_hw_rootfs().string();
    options.ostype = QL_OS::MCU;
    options.archtype = QL_ARCH::CORTEX_M;
    options.env = {
        {"FLASH", "memory;0x0;0x2000"},
        {"SRAM", "memory;0x20000000;0x1000"},
        {"PPB", "mmio;0xE000E000;0x1000"},
        {"SYSTICK", "core;cm3_systick;0xE000E010"},
        {"NVIC", "core;cm_nvic;0xE000E100"},
        {"SCB", "core;cm4_scb;0xE000ED00"},
        {"USART2", "core;STM32F1xxUsart;0x40004400;intn=38"},
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto* usart2 = ql.hw()->peripheral("usart2");
    ASSERT_NE(usart2, nullptr);
    auto* usart = static_cast<qiling::hw::STM32F4xxUsart*>(usart2);

    // the DR write lands in the output tube
    usart->write_body(usart->kDrOffset, 4, 0x41);
    const auto out = usart->recv(4);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x41);

    // the host injects the input: the transfer walk raises the RXNE
    usart->send({0x62});
    usart->step();
    EXPECT_NE(usart->raw_read(usart->kSrOffset, 4) & qiling::hw::usart::sr::RXNE, 0u);

    auto* nvic = ql.hw()->peripheral("nvic");
    ASSERT_NE(nvic, nullptr);
    auto& nvic_ref = *static_cast<qiling::hw::CortexMNvic*>(nvic);

    // the CR1 RXNEIE + the SR RXNE: the check_interrupt pends the nvic (the
    // intn 38 = the USART2 IRQ on the stm32f103); the firmware enables the
    // IRQ through the ISER first (the nvic's set_pending only queues the
    // enabled interrupts)
    nvic_ref.enable(38);
    usart->write_body(usart->kCr1Offset, 4, qiling::hw::usart::cr1::RXNEIE);
    const auto before = nvic_ref.pending_interrupts().size();
    usart->check_interrupt();
    ASSERT_EQ(nvic_ref.pending_interrupts().size(), before + 1);
    EXPECT_EQ(nvic_ref.pending_interrupts().back(), 38);

    // the DR read drains the input tube and clears the RXNE
    const auto byte = usart->read(usart->kDrOffset, 4);
    EXPECT_EQ(byte, 0x62);
    EXPECT_EQ(usart->raw_read(usart->kSrOffset, 4) & qiling::hw::usart::sr::RXNE, 0u);
}

// The Tim family: the ARR/CNT walk under the CEN gate with the prescaler
// division; the ARR match rides the update interrupt (the DIER.UIE + the
// SR.UIF + the nvic pending with the up_intn).
TEST(HwManager, Stm32f1xxTimStepWalkPendsUpdateInterrupt) {
    const auto hex_path = write_ihex_fixture();

    QilingOptions options;
    options.argv = {hex_path};
    options.rootfs = ensure_hw_rootfs().string();
    options.ostype = QL_OS::MCU;
    options.archtype = QL_ARCH::CORTEX_M;
    options.env = {
        {"FLASH", "memory;0x0;0x2000"},
        {"SRAM", "memory;0x20000000;0x1000"},
        {"PPB", "mmio;0xE000E000;0x1000"},
        {"SYSTICK", "core;cm3_systick;0xE000E010"},
        {"NVIC", "core;cm_nvic;0xE000E100"},
        {"SCB", "core;cm4_scb;0xE000ED00"},
        {"TIM2", "core;STM32F1xxTim;0x40000000;intn=28;up_intn=28"},
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto* tim2 = static_cast<qiling::hw::STM32F4xxTim*>(ql.hw()->peripheral("tim2"));
    auto* nvic = static_cast<qiling::hw::CortexMNvic*>(ql.hw()->peripheral("nvic"));
    ASSERT_NE(tim2, nullptr);
    ASSERT_NE(nvic, nullptr);
    nvic->enable(28);

    // the ARR=3 + the CEN + the UIE: the count rides the prescaler walk
    tim2->write(tim2->kArrOffset, 4, 3);
    tim2->write(tim2->kDierOffset, 4, qiling::hw::tim::dier::UIE);
    tim2->write(tim2->kCr1Offset, 4, qiling::hw::tim::cr1::CEN);
    tim2->write(tim2->kCr1Offset, 4, qiling::hw::tim::cr1::CEN);
    tim2->write(tim2->kDierOffset, 4, qiling::hw::tim::dier::UIE);

    const auto before = nvic->pending_interrupts().size();

    tim2->step();  // the CNT 0 -> 1 (the prescale pass)
    EXPECT_EQ(tim2->raw_read(tim2->kCntOffset, 4), 1u);
    tim2->step();
    tim2->step();  // the CNT reaches the ARR
    tim2->step();  // the ARR match: the CNT reset + the UIF + the nvic pending

    EXPECT_EQ(tim2->raw_read(tim2->kCntOffset, 4), 0u);
    EXPECT_NE(tim2->raw_read(tim2->kSrOffset, 4) & qiling::hw::tim::sr::UIF, 0u);
    ASSERT_GT(nvic->pending_interrupts().size(), before);
    EXPECT_EQ(nvic->pending_interrupts().back(), 28);

    // the ratio rides the prescaler division: the PSC=1 halves the count rate
    tim2->write(tim2->kPscOffset, 4, 1);
    tim2->write(tim2->kCntOffset, 4, 0);
    tim2->step();
    EXPECT_EQ(tim2->raw_read(tim2->kCntOffset, 4), 0u);  // the prescale holds the CNT
}
