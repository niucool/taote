// MIPS suite — PORT_PLAN.md §10 Phase 1 (smoke-level bring-up of
// qiling/arch/mips.py, both endiannesses; disasm corpus byte-identical).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "qiling/arch/mips.hpp"

using namespace qiling;

namespace {

std::string_view as_bytes(const std::vector<std::uint8_t>& v) {
    return {reinterpret_cast<const char*>(v.data()), v.size()};
}

}  // namespace

TEST(ArchMIPS, BringUpLittleEndian) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EL);
    EXPECT_EQ(arch.type(), QL_ARCH::MIPS);
    EXPECT_EQ(arch.bits(), 32);
    EXPECT_EQ(arch.pointersize(), 4);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);
}

TEST(ArchMIPS, BringUpBigEndian) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EB);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EB);
}

TEST(ArchMIPS, RegsTable) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EL);
    auto& regs = arch.regs();

    // aliases observe the same storage as the numeric names (a0 == r4)
    regs.write("a0", 0x2222);
    EXPECT_EQ(regs.read("r4"), 0x2222u);
    regs.write("r4", 0x3333);
    EXPECT_EQ(regs.read("a0"), 0x3333u);

    for (const char* name : {"zero", "at", "v0", "v1", "t9", "gp", "sp", "fp", "s8", "ra",
                             "hi", "lo", "pc", "r31", "cp0_config3", "cp0_userlocal", "cp0_status"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    EXPECT_THROW(static_cast<void>(regs.read("rax")), std::out_of_range);
}

TEST(ArchMIPS, DisasmCorpusLittleEndian) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EL);
    // addiu v0, zero, 1 -> 0x24020001 (LE bytes 01 00 02 24)
    const auto insns = arch.disassembler().disasm(std::string_view("\x01\x00\x02\x24", 4), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "addiu");
    EXPECT_EQ(insns[0].op_str, "$v0, $zero, 1");
}

TEST(ArchMIPS, DisasmCorpusBigEndian) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EB);
    // the same instruction in big-endian byte order (24 02 00 01)
    const auto insns = arch.disassembler().disasm(std::string_view("\x24\x02\x00\x01", 4), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "addiu");
    EXPECT_EQ(insns[0].op_str, "$v0, $zero, 1");
}

TEST(ArchMIPS, AsmCorpus) {
    QlArchMIPS arch(nullptr, std::nullopt, QL_ENDIAN::EL);
    EXPECT_EQ(as_bytes(arch.assembler().assemble("nop")), std::string_view("\x00\x00\x00\x00", 4));
}
