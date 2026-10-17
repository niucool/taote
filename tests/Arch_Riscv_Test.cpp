// RISCV suite — PORT_PLAN.md §10 Phase 1 (smoke-level bring-up of
// qiling/arch/riscv.py + riscv64.py; capstone disasm, keystone NotImplemented).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "qiling/arch/riscv.hpp"

using namespace qiling;

TEST(ArchRISCV, BringUp) {
    QlArchRISCV arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::RISCV);
    EXPECT_EQ(arch.bits(), 32);
    EXPECT_EQ(arch.pointersize(), 4);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);
}

TEST(ArchRISCV64, BringUp) {
    QlArchRISCV64 arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::RISCV64);
    EXPECT_EQ(arch.bits(), 64);
    EXPECT_EQ(arch.pointersize(), 8);
}

TEST(ArchRISCV, RegsTable) {
    QlArchRISCV arch(nullptr);
    auto& regs = arch.regs();

    // aliases observe the same storage (a0 == x10)
    regs.write("a0", 0xaaaa);
    EXPECT_EQ(regs.read("x10"), 0xaaaau);
    regs.write("x10", 0xbbbb);
    EXPECT_EQ(regs.read("a0"), 0xbbbbu);

    for (const char* name : {"zero", "ra", "sp", "gp", "tp", "t0", "t2", "s0", "fp", "s1",
                             "a0", "a7", "s2", "s11", "pc",
                             "mstatus", "misa", "mhartid", "mepc", "mcause", "sstatus",
                             "hpmcounter3", "hpmcounter31", "f0", "f31", "fflags", "fcsr"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    EXPECT_THROW(static_cast<void>(regs.read("eax")), std::out_of_range);
}

TEST(ArchRISCV, DisasmCorpus) {
    QlArchRISCV arch(nullptr);
    // addi a0, a0, 1 -> 0x00150513 (LE bytes 13 05 15 00)
    const auto insns = arch.disassembler().disasm(std::string_view("\x13\x05\x15\x00", 4), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "addi");
    EXPECT_EQ(insns[0].op_str, "a0, a0, 1");
}

TEST(ArchRISCV64, DisasmCorpus) {
    QlArchRISCV64 arch(nullptr);
    const auto insns = arch.disassembler().disasm(std::string_view("\x13\x05\x15\x00", 4), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "addi");
    EXPECT_EQ(insns[0].op_str, "a0, a0, 1");
}

TEST(ArchRISCV, AssemblerNotImplemented) {
    // riscv.py, verbatim: "Keystone does not yet support riscv"
    QlArchRISCV arch(nullptr);
    EXPECT_THROW(static_cast<void>(arch.assembler()), QlErrorNotImplemented);
}

TEST(ArchRISCV64, AssemblerNotImplemented) {
    QlArchRISCV64 arch(nullptr);
    EXPECT_THROW(static_cast<void>(arch.assembler()), QlErrorNotImplemented);
}

TEST(ArchRISCV, EnableFloatSetsFsDirty) {
    QlArchRISCV arch(nullptr);
    arch.regs().write("mstatus", 0);
    arch.enable_float();
    EXPECT_EQ(arch.regs().read("mstatus") & static_cast<std::uint64_t>(MSTATUS::FS_DIRTY),
              static_cast<std::uint64_t>(MSTATUS::FS_DIRTY));
}

TEST(ArchRISCV, InitContext) {
    QlArchRISCV arch(nullptr);
    arch.init_context();
    EXPECT_EQ(arch.regs().read("pc"), 0x08000000u);
}

TEST(ArchRISCV, MstatusFlagsVerbatim) {
    // riscv_const.py MSTATUS spot checks
    EXPECT_EQ(static_cast<std::uint64_t>(MSTATUS::FS_OFF), 0u);
    EXPECT_EQ(static_cast<std::uint64_t>(MSTATUS::FS_INITIAL), 1ull << 13);
    EXPECT_EQ(static_cast<std::uint64_t>(MSTATUS::FS_CLEAN), 2ull << 13);
    EXPECT_EQ(static_cast<std::uint64_t>(MSTATUS::FS_DIRTY), 3ull << 13);
}
