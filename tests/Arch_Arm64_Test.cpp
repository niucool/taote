// ARM64 suite — PORT_PLAN.md §10 Phase 1 (smoke-level bring-up of
// qiling/arch/arm64.py; disasm/asm corpora byte-identical to the Python layer).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "qiling/arch/arm64.hpp"

using namespace qiling;
using namespace std::string_view_literals;

namespace {

std::string_view as_bytes(const std::vector<std::uint8_t>& v) {
    return {reinterpret_cast<const char*>(v.data()), v.size()};
}

}  // namespace

TEST(ArchARM64, BringUp) {
    QlArchARM64 arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::ARM64);
    EXPECT_EQ(arch.bits(), 64);
    EXPECT_EQ(arch.pointersize(), 8);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);
}

TEST(ArchARM64, RegsTable) {
    QlArchARM64 arch(nullptr);
    auto& regs = arch.regs();

    regs.write("x3", 0x3333);
    EXPECT_EQ(regs.read("x3"), 0x3333u);

    for (const char* name : {"x0", "x30", "sp", "pc", "lr", "cpacr_el1", "pstate",
                             "b0", "b31", "d0", "h0", "q0", "s0", "w0", "w30", "v0", "v31",
                             "fpcr", "fpsr"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    EXPECT_THROW(static_cast<void>(regs.read("eax")), std::out_of_range);
}

TEST(ArchARM64, DisasmCorpus) {
    QlArchARM64 arch(nullptr);

    // nop -> 1f 20 03 d5 ; ret -> c0 03 5f d6
    for (const auto& [bytes, mnemonic] : {std::pair{"\x1f\x20\x03\xd5"sv, "nop"sv},
                                          std::pair{"\xc0\x03\x5f\xd6"sv, "ret"sv}}) {
        const auto insns = arch.disassembler().disasm(bytes, 0x1000);
        ASSERT_EQ(insns.size(), 1u);
        EXPECT_EQ(insns[0].mnemonic, mnemonic);
        EXPECT_EQ(insns[0].op_str, "");
    }
}

TEST(ArchARM64, AsmCorpus) {
    QlArchARM64 arch(nullptr);

    // keystone's ARM64 backend requires the exact KS_MODE_LITTLE_ENDIAN mode
    // (ks.cpp), while arm64.py opens KS_MODE_ARM — the Python layer's
    // Ks(KS_ARCH_ARM64, KS_MODE_ARM) fails with KS_ERR_MODE the same way.
    // Mirrored verbatim; the capstone disassembler above carries the corpus.
    EXPECT_THROW(static_cast<void>(arch.assembler()), QlErrorArch);
}

TEST(ArchARM64, EnableVfp) {
    QlArchARM64 arch(nullptr);
    arch.regs().write("cpacr_el1", 0);
    arch.enable_vfp();
    EXPECT_EQ(arch.regs().read("cpacr_el1") & (0b11 << 20), 0b11ull << 20);
}

TEST(ArchARM64, CprNamedAccess) {
    QlArchARM64 arch(nullptr);
    // TPIDR_EL0 is (op0=3, op1=3, crn=13, crm=0, op2=2)
    const auto value = arch.cpr().read("TPIDR_EL0");
    arch.cpr().write("TPIDR_EL0", 0x1234);
    EXPECT_EQ(arch.cpr().read("TPIDR_EL0"), 0x1234u);
    EXPECT_NE(value, 0x1234u);
}
