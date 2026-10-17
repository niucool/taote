// Per-arch calling-convention suite — PORT_PLAN.md §10 Phase 1 (the qiling/cc
// arm/mips/ppc/riscv conventions: register files, return registers, and the
// lr/ra return-address surface; stack slots need the Phase 2 memory manager).
#include <gtest/gtest.h>

#include <stdexcept>

#include "qiling/cc/arm.hpp"
#include "qiling/cc/mips.hpp"
#include "qiling/cc/ppc.hpp"
#include "qiling/cc/riscv.hpp"
#include "qiling/arch/arm.hpp"
#include "qiling/arch/arm64.hpp"
#include "qiling/arch/mips.hpp"
#include "qiling/arch/ppc.hpp"
#include "qiling/arch/riscv.hpp"

using namespace qiling;

// ---- aarch64 (cc/arm.py) ----

TEST(CcArm64, SlotsAndReturn) {
    QlArchARM64 arch(nullptr);
    cc::aarch64 convention(arch);

    EXPECT_EQ(cc::aarch64::getNumSlots(64), 1);
    EXPECT_EQ(cc::aarch64::getNumSlots(128), 1);  // always 1 slot per arg

    convention.setReturnValue(0xfeedfacefeedfaceull);
    EXPECT_EQ(convention.getReturnValue(), 0xfeedfacefeedfaceull);
    EXPECT_EQ(arch.regs().read("x0"), 0xfeedfacefeedfaceull);
}

TEST(CcArm64, RegisterSlots) {
    QlArchARM64 arch(nullptr);
    cc::aarch64 convention(arch);

    for (int i = 0; i <= 7; ++i) {
        arch.regs().write("x" + std::to_string(i), 0x1000 + i);
    }
    for (int i = 0; i <= 7; ++i) {
        EXPECT_EQ(convention.getRawParam(i), 0x1000u + i) << "slot " << i;
    }

    convention.setRawParam(2, 0xbeef);
    EXPECT_EQ(arch.regs().read("x2"), 0xbeefu);

    // x0..x7 is the full register file: slot 8 is a stack slot (needs mem)
    EXPECT_THROW(static_cast<void>(convention.getRawParam(8)), QlErrorBase);
}

TEST(CcArm64, ReturnAddressInLr) {
    QlArchARM64 arch(nullptr);
    cc::aarch64 convention(arch);

    arch.regs().write("lr", 0x400000);
    EXPECT_EQ(convention.getReturnAddress(), 0x400000u);

    convention.setReturnAddress(0x400100);
    EXPECT_EQ(arch.regs().read("lr"), 0x400100u);

    // unwind is a no-op stub returning the current lr (arm.py, verbatim)
    EXPECT_EQ(convention.unwind(3), 0x400100u);
}

// ---- aarch32 (cc/arm.py) ----

TEST(CcArm32, RegisterSlots) {
    QlArchARM arch(nullptr);
    cc::aarch32 convention(arch);

    for (int i = 0; i <= 3; ++i) {
        arch.regs().write("r" + std::to_string(i), 0x20 + i);
    }
    for (int i = 0; i <= 3; ++i) {
        EXPECT_EQ(convention.getRawParam(i), 0x20u + i) << "slot " << i;
    }

    convention.setReturnValue(0xcafe);
    EXPECT_EQ(arch.regs().read("r0"), 0xcafeu);

    EXPECT_THROW(static_cast<void>(convention.getRawParam(4)), QlErrorBase);  // stack slot
    EXPECT_EQ(convention.getReturnAddress(), 0u);  // lr (untouched)
}

// ---- mipso32 (cc/mips.py) ----

TEST(CcMips, SlotsAndReturn) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EL);
    cc::mipso32 convention(arch);

    EXPECT_EQ(cc::mipso32::getNumSlots(32), 1);

    convention.setReturnValue(0x99);
    EXPECT_EQ(arch.regs().read("v0"), 0x99u);
    EXPECT_EQ(convention.getReturnValue(), 0x99u);

    // a0..a3 are the register args; slot 4 is the first stack slot (needs mem)
    arch.regs().write("a0", 1);
    arch.regs().write("a1", 2);
    arch.regs().write("a2", 3);
    arch.regs().write("a3", 4);
    EXPECT_EQ(convention.getRawParam(0), 1u);
    EXPECT_EQ(convention.getRawParam(3), 4u);
    EXPECT_THROW(static_cast<void>(convention.getRawParam(4)), QlErrorBase);
}

TEST(CcMips, ReturnAddressInRa) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EL);
    cc::mipso32 convention(arch);

    arch.regs().write("ra", 0x8000);
    EXPECT_EQ(convention.getReturnAddress(), 0x8000u);
    convention.setReturnAddress(0x9000);
    EXPECT_EQ(arch.regs().read("ra"), 0x9000u);
    EXPECT_EQ(convention.unwind(2), 0x9000u);
}

// ---- ppc (cc/ppc.py) ----

TEST(CcPpc, RegisterSlots) {
    QlArchPPC arch(nullptr);
    cc::ppc convention(arch);

    EXPECT_EQ(cc::ppc::getNumSlots(32), 1);

    for (int i = 3; i <= 8; ++i) {
        arch.regs().write("r" + std::to_string(i), 0x30 + i);
    }
    for (int i = 0; i <= 5; ++i) {
        EXPECT_EQ(convention.getRawParam(i), 0x30u + 3u + i) << "slot " << i;
    }

    convention.setReturnValue(0x77);
    EXPECT_EQ(arch.regs().read("r3"), 0x77u);

    EXPECT_THROW(static_cast<void>(convention.getRawParam(6)), QlErrorBase);  // stack slot

    arch.regs().write("lr", 0x10000);
    EXPECT_EQ(convention.getReturnAddress(), 0x10000u);
}

// ---- riscv (cc/riscv.py) ----

TEST(CcRiscv, RegisterSlots) {
    QlArchRISCV arch(nullptr);
    cc::riscv convention(arch);

    EXPECT_EQ(cc::riscv::getNumSlots(32), 1);

    for (int i = 0; i <= 5; ++i) {
        arch.regs().write("a" + std::to_string(i), 0x40 + i);
    }
    for (int i = 0; i <= 5; ++i) {
        EXPECT_EQ(convention.getRawParam(i), 0x40u + i) << "slot " << i;
    }

    convention.setReturnValue(0x88);
    EXPECT_EQ(arch.regs().read("a0"), 0x88u);

    EXPECT_THROW(static_cast<void>(convention.getRawParam(6)), QlErrorBase);  // stack slot

    arch.regs().write("ra", 0x20000);
    EXPECT_EQ(convention.getReturnAddress(), 0x20000u);
    convention.setReturnAddress(0x21000);
    EXPECT_EQ(arch.regs().read("ra"), 0x21000u);
}
