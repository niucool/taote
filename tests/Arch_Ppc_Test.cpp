// PPC suite — PORT_PLAN.md §10 Phase 1 (smoke-level bring-up of
// qiling/arch/ppc.py; disassembler only — keystone has no working PPC backend).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "qiling/arch/ppc.hpp"

using namespace qiling;

TEST(ArchPPC, BringUp) {
    QlArchPPC arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::PPC);
    EXPECT_EQ(arch.bits(), 32);
    EXPECT_EQ(arch.pointersize(), 4);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EB);  // ppc is big-endian only (ppc.py)
}

TEST(ArchPPC, RegsTable) {
    QlArchPPC arch(nullptr);
    auto& regs = arch.regs();

    regs.write("r5", 0x5555);
    EXPECT_EQ(regs.read("r5"), 0x5555u);

    for (const char* name : {"pc", "r0", "r31", "cr", "lr", "xer", "ctr", "msr", "f0", "f31"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    // the architectural stack pointer is r1 (ppc.py sp_reg='r1')
    EXPECT_NO_THROW(arch.regs().set_arch_sp(0x7ff0); static_cast<void>(arch.regs().read("r1")));
}

TEST(ArchPPC, DisasmCorpus) {
    QlArchPPC arch(nullptr);
    // li r3, 1 -> 0x38600001 (BE bytes 38 60 00 01)
    const auto insns = arch.disassembler().disasm(std::string_view("\x38\x60\x00\x01", 4), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "li");
    EXPECT_EQ(insns[0].op_str, "r3, 1");
}

TEST(ArchPPC, EnableFloat) {
    QlArchPPC arch(nullptr);
    arch.regs().write("msr", 0);
    arch.enable_float();
    EXPECT_EQ(arch.regs().read("msr") & static_cast<std::uint64_t>(MSR::FP), static_cast<std::uint64_t>(MSR::FP));
}

TEST(ArchPPC, MsrFlagsVerbatim) {
    // ppc_const.py MSR spot checks
    EXPECT_EQ(static_cast<std::uint64_t>(MSR::FP), 1ull << 13);
    EXPECT_EQ(static_cast<std::uint64_t>(MSR::PR), 1ull << 14);
    EXPECT_EQ(static_cast<std::uint64_t>(MSR::SF), 1ull << 63);
    EXPECT_EQ(static_cast<std::uint64_t>(MSR::LE), 1ull << 0);
}
