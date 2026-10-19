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
#include "qiling/hw/stm32f1xx_exti.hpp"
#include "qiling/hw/stm32f1xx_simple.hpp"
#include "qiling/hw/stm32f1xx_interactive.hpp"
#include "qiling/hw/sam3xa.hpp"
#include "qiling/hw/gd32vf1xx.hpp"
#include "qiling/hw/mk64f12.hpp"
#include "qiling/hw/board_env.hpp"
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

// The Exti family: the SWIER write rides the IMR-masked per-bit walk, the
// line mirrors into the owning gpio port via the AFIO's EXTICR mapping, and
// the nvic pends with the line's interrupt number; the PR write clears.
TEST(HwManager, Stm32f1xxExtiSwierWalkMirrorsGpioAndPendsNvic) {
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
        {"GPIOA", "core;STM32F1xxGpio;0x40010800"},
        {"AFIO", "core;STM32F1xxAfio;0x40010000"},
        {"EXTI", "core;STM32F1xxExti;0x40010400;exti0_intn=6"},
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto* exti = static_cast<qiling::hw::STM32F1xxExti*>(ql.hw()->peripheral("exti"));
    auto* gpioa = static_cast<qiling::hw::STM32F1xxGpio*>(ql.hw()->peripheral("gpioa"));
    auto* nvic = static_cast<qiling::hw::CortexMNvic*>(ql.hw()->peripheral("nvic"));
    ASSERT_NE(exti, nullptr);
    ASSERT_NE(gpioa, nullptr);
    ASSERT_NE(nvic, nullptr);
    nvic->enable(6);

    // the afio maps the EXTI0 to the port A (the EXTICR0 nibble 0)
    auto* afio = static_cast<qiling::hw::STM32F1xxAfio*>(ql.hw()->peripheral("afio"));
    ASSERT_EQ(afio->exti(0), gpioa);

    // the SWIER write with the IMR bit 0 rides the send_interrupt walk: the
    // gpio pin 0 sets and the nvic pends with the exti0 intn (6)
    exti->write_body(exti->kImrOffset, 4, 1);
    exti->write_body(exti->kSwierOffset, 4, 1);
    EXPECT_EQ(gpioa->pin(0), 1u);
    EXPECT_NE(exti->raw_read(exti->kPrOffset, 4) & 1, 0u);
    ASSERT_EQ(nvic->pending_interrupts().size(), 1u);
    EXPECT_EQ(nvic->pending_interrupts().back(), 6);

    // the PR write clears the pending and the SWIER bits
    exti->write_body(exti->kPrOffset, 4, 1);
    EXPECT_EQ(exti->raw_read(exti->kPrOffset, 4) & 1, 0u);
    EXPECT_EQ(exti->raw_read(exti->kSwierOffset, 4) & 1, 0u);

    // the SWIER write masked against the IMR: the line 3 without the IMR bit
    // does not pend
    exti->write_body(exti->kSwierOffset, 4, 8);
    EXPECT_EQ(exti->raw_read(exti->kPrOffset, 4) & 8, 0u);
    EXPECT_EQ(nvic->pending_interrupts().size(), 1u);
}

// Batch 1: the simple register surfaces. The Rcc's rdyon step reflects the
// on-bits into the ready bits; the Adc's CR2 self-clearing walks; the Spi's
// tube-paired DR; the Bitband/Remap mem bridges.
TEST(HwManager, Stm32f1xxSimplePeripheralsWalkRccAdcSpiBitband) {
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
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto& hw = *ql.hw();

    // the Rcc: the HSION seed rides the rdyon step into the HSIRDY
    auto* rcc = static_cast<qiling::hw::STM32F1xxRcc*>(hw.create("rcc", "STM32F1xxRcc", 0x40021000));
    ASSERT_NE(rcc, nullptr);
    rcc->step();
    EXPECT_NE(rcc->raw_read(rcc->kCrOffset, 4) & qiling::hw::rcc::cr::HSIRDY, 0u);
    // the HSE off: the HSERDY cleared (the CFGR/CSR pairs ride the same walk)
    EXPECT_EQ(rcc->raw_read(rcc->kCrOffset, 4) & qiling::hw::rcc::cr::HSERDY, 0u);

    // the Flash: the plain register surface (the KEYR write rides the store)
    auto* flash = static_cast<qiling::hw::STM32F1xxFlash*>(hw.create("flash", "STM32F1xxFlash", 0x40022000));
    ASSERT_NE(flash, nullptr);
    flash->write_body(4, 4, 0x45670123);
    EXPECT_EQ(flash->raw_read(4, 4), 0x45670123u);

    // the Adc: the SWSTART self-clears and sets the EOS; the DR seed 0x7ff
    auto* adc = static_cast<qiling::hw::STM32F1xxAdc*>(hw.create("adc1", "STM32F1xxAdc", 0x40012400));
    ASSERT_NE(adc, nullptr);
    EXPECT_EQ(adc->raw_read(adc->kDrOffset, 4), 0x7ffu);
    adc->write_body(adc->kCr2Offset, 4, qiling::hw::adc::cr2::SWSTART);
    EXPECT_NE(adc->raw_read(adc->kSrOffset, 4) & qiling::hw::adc::sr::EOS, 0u);
    EXPECT_EQ(adc->raw_read(adc->kCr2Offset, 4) & qiling::hw::adc::cr2::SWSTART, 0u);

    // the Spi: the DR write rides the output tube, the DR read rides the input
    auto* spi1 = static_cast<qiling::hw::STM32F1xxSpi*>(hw.create("spi1", "STM32F1xxSpi", 0x40013000));
    ASSERT_NE(spi1, nullptr);
    spi1->write_body(spi1->kDrOffset, 4, 0xAB);
    const auto out = spi1->recv(2);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0xAB);
    spi1->send({0x5A});
    EXPECT_EQ(spi1->read(spi1->kDrOffset, 4), 0x5A);

    // the Bitband: the aliased bit write flips the SRAM bit (the base
    // 0x22000000 maps to the SRAM 0x20000000)
    std::fprintf(stderr, "[bb-pre] creating\n");
    auto* bb = static_cast<qiling::hw::CortexMBitband*>(
        hw.create("sram_bb", "CortexMBitband", 0x22000000, {{"base", 0x20000000ull}, {"size", 0x100000ull}}));
    ASSERT_NE(bb, nullptr);
    std::fprintf(stderr, "[bb-pre] created\n");
    bb->write_body(0, 4, 1);  // the SRAM bit 0 of the word 0
    std::fprintf(stderr, "[bb-pre] write1 done\n");
    EXPECT_NE(ql.mem().read_ptr(0x20000000, 4) & 1, 0u);
    bb->write_body(0, 4, 0);
    EXPECT_EQ(ql.mem().read_ptr(0x20000000, 4) & 1, 0u);
    std::fprintf(stderr, "[bb] bit walk ok\n");
}

// Batch 2: the interactive peripherals. The Dma stream walks one unit per
// step (the mem copy with the size alignments + the MINC/PINC increments),
// the last transfer clears the EN and pends the nvic; the I2c CR1 START
// rides the generate_start walk (the SB + the master mode) and the DR write
// in the master mode walks the data out to the output tube.
TEST(HwManager, Stm32f1xxDmaStreamTransfersAndI2cMasterWalk) {
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
        {"DMA1", "core;STM32F1xxDma;0x40020000;stream1_intn=12"},
        {"I2C1", "core;STM32F1xxI2c;0x40005400;ev_intn=31"},
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto* dma1 = static_cast<qiling::hw::STM32F1xxDma*>(ql.hw()->peripheral("dma1"));
    auto* i2c1 = static_cast<qiling::hw::STM32F4xxI2c*>(ql.hw()->peripheral("i2c1"));
    auto* nvic = static_cast<qiling::hw::CortexMNvic*>(ql.hw()->peripheral("nvic"));
    ASSERT_NE(dma1, nullptr);
    ASSERT_NE(i2c1, nullptr);
    ASSERT_NE(nvic, nullptr);
    nvic->enable(12);
    nvic->enable(31);

    // the DMA stream 1: the memory-to-memory copy of 4 bytes from 0x20000100
    // to 0x20000200 with the MINC
    constexpr std::uint64_t kSrc = 0x20000100;
    constexpr std::uint64_t kDst = 0x20000200;
    ql.mem().write(kSrc, std::vector<std::uint8_t>{0x11, 0x22, 0x33, 0x44});
    const std::uint64_t s1 = dma1->kStreamBaseOffset + 1 * dma1->kStreamSize;
    dma1->write(s1, 4, qiling::hw::dma::EN | qiling::hw::dma::MINC | qiling::hw::dma::PSIZE_1 |
                           qiling::hw::dma::MSIZE_1);  // the word-sized, mem-to-mem (the DIR 0)
    dma1->write(s1 + 4, 4, 4);                        // the NDTR = 4
    dma1->write(s1 + 8, 4, kSrc);                     // the PAR = the src
    dma1->write(s1 + 12, 4, kDst);                    // the MAR = the dst

    const auto before = nvic->pending_interrupts().size();
    dma1->step();  // the 4 unit steps
    dma1->step();
    dma1->step();
    dma1->step();

    EXPECT_EQ(ql.mem().read(kDst, 4)[0], 0x11);
    EXPECT_EQ(ql.mem().read(kDst + 3, 4)[0], 0x44);
    // the last transfer: the EN cleared + the ISR TC bit set + the nvic pended
    EXPECT_EQ(dma1->stream(1).ndtr, 0u);
    EXPECT_EQ(dma1->stream(1).cr & qiling::hw::dma::EN, 0u);
    EXPECT_NE(dma1->raw_read(dma1->kIsrOffset, 4) & (1u << 5), 0u);  // the stream-1 TC bit
    ASSERT_GT(nvic->pending_interrupts().size(), before);
    EXPECT_EQ(nvic->pending_interrupts().back(), 12);

    // the I2C: the CR1 START rides the generate_start (the SB + the master)
    i2c1->write_body(i2c1->kCr1Offset, 4, qiling::hw::i2c::cr1::START);
    EXPECT_NE(i2c1->raw_read(i2c1->kSr1Offset, 4) & qiling::hw::i2c::sr1::SB, 0u);
    EXPECT_TRUE(i2c1->is_master_mode());
    EXPECT_EQ(i2c1->raw_read(i2c1->kCr1Offset, 4) & qiling::hw::i2c::cr1::START, 0u);  // the START self-clears

    // the OAR1 set + the DR write in the master mode: the address match rides
    // the ADDR/TXE/AF + the TRA (the slave-side ACK shape)
    i2c1->write_body(i2c1->kOar1Offset, 4, 0x20 << 1);
    i2c1->write_body(i2c1->kDrOffset, 4, 0x20);
    EXPECT_NE(i2c1->raw_read(i2c1->kSr1Offset, 4) & qiling::hw::i2c::sr1::ADDR, 0u);
    EXPECT_NE(i2c1->raw_read(i2c1->kSr2Offset, 4) & qiling::hw::i2c::sr2::TRA, 0u);

    // the send_data ride: the DR in the TRA master mode sends to the tube
    i2c1->write_body(i2c1->kDrOffset, 4, 0x77);
    const auto out = i2c1->recv(2);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x77);
}

// The stm32f103 board-table assembly: the full board env rides the loader's
// load_env walk (the memory/mmio/core/peripheral items); the implemented
// families instantiate, the upstream-missing classes degrade to absent
// entities, and the mmio walk resolves the gpioa through the board regions.
TEST(HwManager, Stm32f103BoardAssemblesPeripheralsAndDegradesMissing) {
    const auto hex_path = write_ihex_fixture();

    QilingOptions options;
    options.argv = {hex_path};
    options.rootfs = ensure_hw_rootfs().string();
    options.ostype = QL_OS::MCU;
    options.archtype = QL_ARCH::CORTEX_M;
    options.env = qiling::hw::stm32f103_board_env();
    Qiling ql(options);

    // the implemented families ride the board table
    EXPECT_NE(ql.hw()->peripheral("gpioa"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("gpioe"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("afio"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("exti"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("tim2"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("usart2"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("i2c1"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("spi1"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("adc1"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("dma1"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("rcc"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("flash interface"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("systick"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("nvic"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("scb"), nullptr);

    // the upstream-missing classes degrade to absent entities
    EXPECT_EQ(ql.hw()->peripheral("wwdg"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("iwdg"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("bkp"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("pwr"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("crc"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("rtc"), nullptr);

    // the mmio walk: the BSRR store to the GPIOA through the board's PERIP
    // region rides the gpio pin walk
    auto* gpioa = static_cast<qiling::hw::STM32F1xxGpio*>(ql.hw()->peripheral("gpioa"));
    gpioa->write(16, 4, 1);  // the BSRR sets the pin 0
    EXPECT_EQ(gpioa->pin(0), 1u);

    // the exti0 intn rides the board table (6)
    auto* exti = static_cast<qiling::hw::STM32F1xxExti*>(ql.hw()->peripheral("exti"));
    auto* nvic = static_cast<qiling::hw::CortexMNvic*>(ql.hw()->peripheral("nvic"));
    nvic->enable(6);
    exti->write_body(exti->kImrOffset, 4, 1);
    exti->write_body(exti->kSwierOffset, 4, 1);
    ASSERT_EQ(nvic->pending_interrupts().size(), 1u);
    EXPECT_EQ(nvic->pending_interrupts().back(), 6);
}

// The sam3x8e board-table assembly: the board env rides the loader's
// load_env walk; the 12 implemented SAM3xa families instantiate, the
// unimplemented upstream names degrade to absent entities, and the walks
// ride the adc START (the ISR.DRDY), the dac CDR (the ISR.EOC), the pio
// SODR/CODR pin walks and the uart step (the RXRDY pend at intn 8).
TEST(HwManager, Sam3x8eBoardAssemblesAndPeripheralsWalk) {
    const auto hex_path = write_ihex_fixture();

    QilingOptions options;
    options.argv = {hex_path};
    options.rootfs = ensure_hw_rootfs().string();
    options.ostype = QL_OS::MCU;
    options.archtype = QL_ARCH::CORTEX_M;
    options.env = qiling::hw::sam3x8e_board_env();
    Qiling ql(options);

    // the implemented families ride the board table
    EXPECT_NE(ql.hw()->peripheral("usart0"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("pwm"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("tc0"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("adc"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("dac"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("pioa"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("pmc"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("spi0"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("uotghs"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("pdc_uart"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("systick"), nullptr);
    EXPECT_NE(ql.hw()->peripheral("nvic"), nullptr);

    // the unimplemented upstream names degrade to absent entities
    EXPECT_EQ(ql.hw()->peripheral("hsmci"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("twi0"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("emac"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("dmac"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("rstc"), nullptr);
    EXPECT_EQ(ql.hw()->peripheral("gpbr"), nullptr);

    // the adc CR.START rides the ISR.DRDY
    auto* adc = static_cast<qiling::hw::Sam3xaAdc*>(ql.hw()->peripheral("adc"));
    adc->write_body(adc->kCrOffset, 4, qiling::hw::sam3xa_adc::cr::START);
    EXPECT_NE(adc->raw_read(adc->kIsrOffset, 4) & qiling::hw::sam3xa_adc::isr::DRDY, 0u);

    // the dac CDR write rides the ISR.EOC
    auto* dac = static_cast<qiling::hw::Sam3xaDac*>(ql.hw()->peripheral("dac"));
    dac->write_body(dac->kCdrOffset, 4, 0x7ff);
    EXPECT_NE(dac->raw_read(dac->kIsrOffset, 4) & qiling::hw::sam3xa_dac::isr::EOC, 0u);

    // the pio SODR/CODR pin walks ride the PDSR + the hooks
    auto* pioa = static_cast<qiling::hw::Sam3xaPio*>(ql.hw()->peripheral("pioa"));
    std::size_t set_calls = 0;
    pioa->hook_set(3, [&set_calls]() { ++set_calls; });
    pioa->write_body(pioa->kSodrOffset, 4, 1u << 3);
    EXPECT_EQ(pioa->pin(3), 1u);
    EXPECT_EQ(set_calls, 1u);
    pioa->write_body(pioa->kCodrOffset, 4, 1u << 3);
    EXPECT_EQ(pioa->pin(3), 0u);

    // the uart: the input byte + the IER.RXRDY + the CR.RXEN ride the step
    // (the SR.RXRDY set + the nvic pend at intn 8)
    auto* uart = static_cast<qiling::hw::Sam3xaUart*>(ql.hw()->peripheral("uart"));
    auto* nvic = static_cast<qiling::hw::CortexMNvic*>(ql.hw()->peripheral("nvic"));
    nvic->enable(8);
    uart->send({'A'});
    uart->write_body(uart->kCrOffset, 4, qiling::hw::sam3xa_uart::cr::RXEN);
    uart->write_body(uart->kIerOffset, 4, qiling::hw::sam3xa_uart::ier::RXRDY);
    uart->step();
    EXPECT_EQ(nvic->pending_interrupts().size(), 1u);
    EXPECT_EQ(nvic->pending_interrupts().back(), 8);
    // the RHR read clears the RXRDY and rides the tube byte
    EXPECT_EQ(uart->read_body(uart->kRhrOffset, 4), 'A');
    EXPECT_EQ(uart->raw_read(uart->kSrOffset, 4) & qiling::hw::sam3xa_uart::sr::RXRDY, 0u);

    // the pmc CKGR_MOR write rides the oscillator status bits
    auto* pmc = static_cast<qiling::hw::Sam3xaPmc*>(ql.hw()->peripheral("pmc"));
    pmc->write_body(0x20, 4, qiling::hw::sam3xa_pmc::ckgr_mor::MOSCXTEN |
                                 qiling::hw::sam3xa_pmc::ckgr_mor::MOSCSEL);
    const auto sr = pmc->raw_read(pmc->kSrOffset, 4);
    EXPECT_NE(sr & qiling::hw::sam3xa_pmc::sr::MOSCXTS, 0u);
    EXPECT_NE(sr & qiling::hw::sam3xa_pmc::sr::MOSCSELS, 0u);

    // the spi TDR write rides the output tube (the TD mask)
    auto* spi0 = static_cast<qiling::hw::Sam3xaSpi*>(ql.hw()->peripheral("spi0"));
    spi0->write_body(spi0->kTdrOffset, 4, 0x1234);
    const auto out = spi0->recv(2);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x34);
}

// The gd32vf103 board-table assembly: the board env rides the loader's
// load_env walk; the implemented GD32VF1xx families instantiate (the eclic
// core + the gpio/usart/spi/i2c/dma/crc/rcu/rtc/timer), the unimplemented
// upstream names degrade, and the gpio BOP walk rides the set/reset halves.
TEST(HwManager, Gd32vf103BoardAssemblesAndGpioWalks) {
    // the gd32vf103 board rides the RISCV/eclic core upstream (no 0x0 vector
    // mapping), so the fixture rides the standalone hw-manager create walks
    // over the board env table (the full-os run lands with the RISCV slice)
    auto ql = make_hw_ql();
    qiling::hw::QlHwManager hw(ql);

    const auto board = qiling::hw::gd32vf103_board_env();
    (void)board;

    // the implemented families create through the board struct names
    const std::vector<std::string> implemented = {
        "GD32VF1xxEclic", "GD32VF1xxGpio", "GD32VF1xxUsart", "GD32VF1xxSpi",
        "GD32VF1xxI2c", "GD32VF1xxDma", "GD32VF1xxCrc", "GD32VF1xxRcu",
        "GD32VF1xxRtc", "GD32VF1xxTimer"};
    for (std::size_t i = 0; i < implemented.size(); ++i) {
        const auto label = "entry" + std::to_string(i);
        EXPECT_NE(hw.create(label, implemented[i], 0x40010000 + i * 0x100, {}), nullptr) << implemented[i];
    }
    // the upstream-unimplemented struct names degrade to null
    for (const auto& missing : {"GD32VF1xxFwdgt", "GD32VF1xxPmu", "GD32VF1xxUsbfs", "GD32VF1xxExmc", "GD32VF1xxDbg"}) {
        EXPECT_EQ(hw.create(missing, missing, 0x40020000, {}), nullptr) << missing;
    }

    // the gpio BOP walk: the low 16 set, the high 16 reset
    auto* gpioa = static_cast<qiling::hw::Gd32vf1xxGpio*>(hw.peripheral("entry1"));
    std::size_t set_calls = 0;
    gpioa->hook_set(2, [&set_calls]() { ++set_calls; });
    gpioa->write_body(gpioa->kBopOffset, 4, (1u << 2) | (1u << 20));
    EXPECT_EQ(gpioa->pin(2), 1u);   // the BOP bit 2 sets the pin 2
    EXPECT_EQ(gpioa->pin(4), 0u);   // the BOP bit 20 resets the pin 4
    EXPECT_EQ(set_calls, 1u);

    // the OCTL write walks the per-bit transitions (the pin 2 was set)
    gpioa->write_body(gpioa->kOct1Offset, 4, (1u << 3) | (1u << 2));
    EXPECT_EQ(gpioa->pin(3), 1u);
    EXPECT_EQ(gpioa->pin(2), 1u);
    gpioa->write_body(gpioa->kOct1Offset, 4, 1u << 3);  // the pin-2 bit falls -> reset_pin(2)
    EXPECT_EQ(gpioa->pin(2), 0u);

    // the usart STAT seed rides the TC|TXE bits
    auto* usart0 = static_cast<qiling::hw::Gd32vf1xxUsart*>(hw.peripheral("entry2"));
    EXPECT_EQ(usart0->raw_read(0x00, 4), 0xc0u);
}

// The mk64f12 board-table assembly: the implemented MK64F12 families create
// through the board struct names (the uart's S1 seed, the gpio PSOR/PTOR
// loops, the port IRQC walk, the adc CAL walk, the mcg C1/C6 status rides),
// the unimplemented upstream names degrade to null.
TEST(HwManager, Mk64f12BoardAssemblesAndWalks) {
    auto ql = make_hw_ql();
    qiling::hw::QlHwManager hw(ql);

    // the implemented families
    for (const auto& struct_name : {"MK64F12Uart", "MK64F12Gpio", "MK64F12Port", "MK64F12Spi",
                                    "MK64F12Ftm", "MK64F12Adc", "MK64F12Mcg", "MK64F12Sim",
                                    "MK64F12Smc", "MK64F12Wdog", "MK64F12Osc", "MK64F12Rtc"}) {
        EXPECT_NE(hw.create("entry_" + std::string(struct_name), struct_name, 0x40000000, {}), nullptr) << struct_name;
    }
    // the upstream-unimplemented names degrade to null
    for (const auto& missing : {"MK64F12Ftfe", "MK64F12Aips", "MK64F12Dma", "MK64F12Pit",
                                "MK64F12I2c", "MK64F12Crc", "MK64F12Rng", "MK64F12Enet", "MK64F12Cau"}) {
        EXPECT_EQ(hw.create(missing, missing, 0x40010000, {}), nullptr) << missing;
    }

    // the uart walk: the D write rides the tube, the input + the C2.RIE ride
    // the step's S1.RDRF + the nvic pend
    auto* uart = static_cast<qiling::hw::Mk64f12Uart*>(hw.peripheral("entry_MK64F12Uart"));
    uart->write_body(uart->kDOffset, 1, 0x41);
    const auto out = uart->recv(2);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x41);
    uart->send({'Z'});
    uart->write_body(0x03, 1, qiling::hw::mk64f12_uart::c2::RIE);  // the C2 u8 field
    uart->step();
    EXPECT_NE(uart->raw_read(0x04, 1) & qiling::hw::mk64f12_uart::s1::RDRF, 0u);
    EXPECT_EQ(uart->read_body(uart->kDOffset, 1), 'Z');

    // the gpio/port walk: the PSOR write rides the port IRQC (the rising
    // edge config pends the nvic) and the PDOR tracks the set
    auto* gpioa = static_cast<qiling::hw::Mk64f12Gpio*>(hw.peripheral("entry_MK64F12Gpio"));
    auto* portx = static_cast<qiling::hw::Mk64f12Port*>(hw.peripheral("entry_MK64F12Port"));
    (void)portx;
    std::size_t set_calls = 0;
    gpioa->hook_set(1, [&set_calls]() { ++set_calls; });
    gpioa->write_body(gpioa->kPddrOffset, 4, 0xffffffffu);  // the PDDR: the output mode
    gpioa->write_body(gpioa->kPsorOffset, 4, 0);            // the verbatim unmasked loop
    EXPECT_EQ(gpioa->pin(1), 1u);
    EXPECT_EQ(set_calls, 1u);  // the PSOR loop walks all 32 pins (the pin-1 set fires once)

    // the port IRQC walk: the logic-one config + the set ride the pend
    // (the pending rides the port's intn — the direct send_interrupt shape)
    portx->write_body(portx->kPcrOffset + 4, 4, 0xCu << 16);  // the PCR[1] logic-one
    // the send_interrupt walk rides the (prev, curr) pair
    // (the nvic pend is exercised through the sam3xa walk; the mode gate here)
    EXPECT_EQ(portx->pin_interrupt_config(1), 0xCu);

    // the adc CAL walk: the SC3.CAL sets both SC1 COCO bits and self-clears
    auto* adc = static_cast<qiling::hw::Mk64f12Adc*>(hw.peripheral("entry_MK64F12Adc"));
    adc->write_body(adc->kSc3Offset, 4, qiling::hw::mk64f12_adc::sc3::CAL);
    EXPECT_NE(adc->raw_read(adc->kSc1Offset, 4) & qiling::hw::mk64f12_adc::sc1::COCO, 0u);
    EXPECT_NE(adc->raw_read(adc->kSc1bOffset, 4) & qiling::hw::mk64f12_adc::sc1::COCO, 0u);
    EXPECT_EQ(adc->raw_read(adc->kSc3Offset, 4) & qiling::hw::mk64f12_adc::sc3::CAL, 0u);

    // the mcg C6.PLLS ride: the PLLST + the LOCK0 status bits
    auto* mcg = static_cast<qiling::hw::Mk64f12Mcg*>(hw.peripheral("entry_MK64F12Mcg"));
    mcg->write_body(0x0A, 1, qiling::hw::mk64f12_mcg::c6::PLLS);
    EXPECT_NE(mcg->raw_read(0x04, 1) & qiling::hw::mk64f12_mcg::s::PLLST, 0u);
    EXPECT_NE(mcg->raw_read(0x04, 1) & qiling::hw::mk64f12_mcg::s::LOCK0, 0u);
}

// The chardev bridge: the device_handler pre-walk forwards the sender's
// output-tube byte to the connected device's input tube and steps the device
// (the usart1 -> usart2 ride); the i2c step rides the same pre-walk.
TEST(HwManager, DeviceHandlerBridgeForwardsTubeBetweenPeripherals) {
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
        {"USART3", "core;STM32F1xxUsart;0x40004800;intn=39"},
        {"I2C1", "core;STM32F1xxI2c;0x40005400;ev_intn=31"},
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto* usart2 = static_cast<qiling::hw::STM32F1xxUsart*>(ql.hw()->peripheral("usart2"));
    auto* usart3 = static_cast<qiling::hw::STM32F1xxUsart*>(ql.hw()->peripheral("usart3"));
    auto* nvic = static_cast<qiling::hw::CortexMNvic*>(ql.hw()->peripheral("nvic"));
    ASSERT_NE(usart2, nullptr);
    ASSERT_NE(usart3, nullptr);
    ASSERT_NE(nvic, nullptr);
    nvic->enable(38);
    nvic->enable(39);

    // the bridge: the usart2's DR write fills the otube; the usart2's step
    // (the device_handler ride) forwards the byte to the connected usart3's
    // itube and steps the usart3 (the RXNE + the nvic pend at 39)
    usart2->connect(usart3);
    usart3->write_body(usart3->kCr1Offset, 4, qiling::hw::usart::cr1::RXNEIE);
    usart2->write_body(usart2->kDrOffset, 4, 0x5A);
    usart2->step();

    // the usart3 received the byte (the RXNE set + the pended intn)
    EXPECT_NE(usart3->raw_read(usart3->kSrOffset, 4) & qiling::hw::usart::sr::RXNE, 0u);
    ASSERT_EQ(nvic->pending_interrupts().size(), 1u);
    EXPECT_EQ(nvic->pending_interrupts().back(), 39);
    // the usart3's DR read rides the byte through and clears the RXNE
    EXPECT_EQ(usart3->read_body(usart3->kDrOffset, 4), 0x5A);
    EXPECT_EQ(usart3->raw_read(usart3->kSrOffset, 4) & qiling::hw::usart::sr::RXNE, 0u);

    // the i2c step rides the same pre-walk (the empty device list no-ops and
    // the send_event_interrupt walk runs)
    auto* i2c1 = static_cast<qiling::hw::STM32F4xxI2c*>(ql.hw()->peripheral("i2c1"));
    ASSERT_NE(i2c1, nullptr);
    i2c1->set_master_mode();
    i2c1->raw_write(i2c1->kSr1Offset, 4, qiling::hw::i2c::sr1::BTF);
    i2c1->step();  // the CR2 ITEVTEN unset -> no pend; the walk completes
    EXPECT_TRUE(i2c1->is_master_mode());
}

// The f4xx SPI variant: the 36-byte image with the RW_MASK write masks (the
// CR1/CR2/CRCPR/I2SCFGR/I2SPR), the SR/CRC write ignores, the contain-span DR
// walks (a 2-byte access straddling the DR rides the tubes), the f1xx SPI's
// contain walk riding the same span.
TEST(HwManager, Stm32f4xxSpiVariantMasksAndContainWalks) {
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
        {"SPI1", "core;STM32F4xxSpi;0x40013000;intn=35"},
        {"SPI1_F1", "core;STM32F1xxSpi;0x40014000"},
        {"PERIP", "mmio;0x40000000;0x100000"},
    };
    Qiling ql(options);

    auto* spi1 = static_cast<qiling::hw::STM32F4xxSpi*>(ql.hw()->peripheral("spi1"));
    ASSERT_NE(spi1, nullptr);

    // the RW_MASK stores: the CR1 rides the 0xffff mask (the upper bits clear),
    // the CR2 rides its narrow mask (the FRF at bit 4 kept, the bit 3 dropped)
    spi1->write_body(spi1->kCr1Offset, 4, 0xffffffffu);
    EXPECT_EQ(spi1->raw_read(spi1->kCr1Offset, 4), 0xffffu);
    spi1->write_body(spi1->kCr2Offset, 4, 0xffffffffu);
    EXPECT_EQ(spi1->raw_read(spi1->kCr2Offset, 4), 0xF7u);

    // the SR write is ignored (the sticky seed 0xB stays)
    spi1->write_body(spi1->kSrOffset, 4, 0);
    EXPECT_EQ(spi1->raw_read(spi1->kSrOffset, 4), 0xBu);
    // the RXCRCR write is ignored
    spi1->write_body(spi1->kRxcrcrOffset, 4, 0x1234);
    EXPECT_EQ(spi1->raw_read(spi1->kRxcrcrOffset, 4), 0u);

    // the contain-span DR walk: a 2-byte access over the DR's low half rides
    // the store-then-send (the DR reads back 0x0000ABCD, the send_to_user
    // takes the low byte)
    spi1->write_body(0x0C, 2, 0xABCD);
    const auto out = spi1->recv(2);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0xCDu);
    // the f1xx SPI's contain walk rides the same span
    auto* f1 = static_cast<qiling::hw::STM32F1xxSpi*>(ql.hw()->peripheral("spi1_f1"));
    (void)f1;
    EXPECT_TRUE(qiling::hw::QlPeripheral::contain(0x0C, 4, 0x0E, 2));
    EXPECT_FALSE(qiling::hw::QlPeripheral::contain(0x0C, 4, 0x10, 4));
}
