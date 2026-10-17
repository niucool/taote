// Cc suite — PORT_PLAN.md §10 Phase 1 (the qiling/cc surface: QlCC base,
// QlCommonBaseCC, and the Intel x86/x86-64 conventions from cc/intel.py).
// Stack-based slots are exercised fully once the memory manager lands (Phase 2);
// register slots, slot counts, and the return register are covered here.
#include <gtest/gtest.h>

#include <stdexcept>

#include "qiling/cc/intel.hpp"
#include "qiling/arch/x86.hpp"

using namespace qiling;

// ---- slot counts (cc/intel.py getNumSlots; verbatim arithmetic) ----

TEST(CcSlots, Intel64Counts64BitSlots) {
    EXPECT_EQ(cc::amd64::getNumSlots(64), 1);
    EXPECT_EQ(cc::amd64::getNumSlots(32), 1);   // max(argbits, 64) // 64
    EXPECT_EQ(cc::amd64::getNumSlots(128), 2);  // 128 // 64
}

TEST(CcSlots, Intel32Counts32BitSlots) {
    EXPECT_EQ(cc::QlCdecl::getNumSlots(32), 1);
    EXPECT_EQ(cc::QlCdecl::getNumSlots(16), 1);   // max(argbits, 32) // 32
    EXPECT_EQ(cc::QlCdecl::getNumSlots(64), 2);
}

// ---- return register per convention ----

TEST(CcReturn, Intel64UsesRax) {
    QlArchX8664 arch(nullptr);
    cc::amd64 cc(arch);

    cc.setReturnValue(0xdeadbeefcafeull);
    EXPECT_EQ(cc.getReturnValue(), 0xdeadbeefcafeull);
    EXPECT_EQ(arch.regs().read("rax"), 0xdeadbeefcafeull);
}

TEST(CcReturn, Intel32UsesEax) {
    QlArchX86 arch(nullptr);
    cc::QlCdecl cc(arch);

    cc.setReturnValue(0xcafeu);
    EXPECT_EQ(cc.getReturnValue(), 0xcafeu);
    EXPECT_EQ(arch.regs().read("eax"), 0xcafeu);
}

// ---- register-file argument slots (amd64: rdi, rsi, rdx, r10, r8, r9) ----

TEST(CcArgs, Amd64RegisterSlots) {
    QlArchX8664 arch(nullptr);
    cc::amd64 cc(arch);

    arch.regs().write("rdi", 0x1111);
    arch.regs().write("rsi", 0x2222);
    arch.regs().write("rdx", 0x3333);
    arch.regs().write("r10", 0x4444);
    arch.regs().write("r8", 0x5555);
    arch.regs().write("r9", 0x6666);

    EXPECT_EQ(cc.getRawParam(0), 0x1111u);
    EXPECT_EQ(cc.getRawParam(1), 0x2222u);
    EXPECT_EQ(cc.getRawParam(2), 0x3333u);
    EXPECT_EQ(cc.getRawParam(3), 0x4444u);  // r10, not rcx (POSIX convention)
    EXPECT_EQ(cc.getRawParam(4), 0x5555u);
    EXPECT_EQ(cc.getRawParam(5), 0x6666u);

    cc.setRawParam(3, 0xaabb);
    EXPECT_EQ(arch.regs().read("r10"), 0xaabbu);

    // beyond the register file, args live on the stack: slot 6 is a stack slot
    // (needs the memory manager — Phase 2), and slot 16 is out of range
    EXPECT_THROW(static_cast<void>(cc.getRawParam(6)), QlErrorBase);
    EXPECT_THROW(static_cast<void>(cc.getRawParam(16)), std::out_of_range);
    EXPECT_THROW(static_cast<void>(cc.getRawParam(17)), std::out_of_range);
}

TEST(CcArgs, Ms64RegisterSlots) {
    QlArchX8664 arch(nullptr);
    cc::ms64 cc(arch);

    arch.regs().write("rcx", 0xaaaa);
    arch.regs().write("rdx", 0xbbbb);
    arch.regs().write("r8", 0xcccc);
    arch.regs().write("r9", 0xdddd);

    EXPECT_EQ(cc.getRawParam(0), 0xaaaau);
    EXPECT_EQ(cc.getRawParam(1), 0xbbbbu);
    EXPECT_EQ(cc.getRawParam(2), 0xccccu);
    EXPECT_EQ(cc.getRawParam(3), 0xddddu);
    // slot 4 is a stack slot (shadow space lands with the Phase 2 memory manager)
    EXPECT_THROW(static_cast<void>(cc.getRawParam(4)), QlErrorBase);
}

TEST(CcArgs, ArgbitsMasking) {
    QlArchX8664 arch(nullptr);
    cc::amd64 cc(arch);

    arch.regs().write("rdi", 0xffffffffffffffffull);
    // getRawParam(slot, argbits) masks to argbits; argbits=0 means native width
    EXPECT_EQ(cc.getRawParam(0), 0xffffffffffffffffull);
    EXPECT_EQ(cc.getRawParam(0, 8), 0xffu);
    EXPECT_EQ(cc.getRawParam(0, 16), 0xffffu);

    cc.setRawParam(0, 0x1122334455667788ull, 32);
    // a 32-bit slot write masks the value to 32 bits (Python: value & (1<<32)-1);
    // the upper bits of the 64-bit register are not preserved
    EXPECT_EQ(arch.regs().read("rdi"), 0x55667788ull);
}

// ---- base-class NotImplemented surface (cc/__init__.py) ----

TEST(CcBase, UnimplementedInterfaceRaises) {
    QlArchX8664 arch(nullptr);
    cc::QlCC base(arch);

    EXPECT_THROW(static_cast<void>(base.getRawParam(0)), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.setRawParam(0, 1)), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.getReturnValue()), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.setReturnValue(1)), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.getReturnAddress()), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.setReturnAddress(1)), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.reserve(1)), QlErrorNotImplemented);
    EXPECT_THROW(static_cast<void>(base.unwind(1)), QlErrorNotImplemented);
}
