// ARM + Cortex-M suites — PORT_PLAN.md §10 Phase 1 (smoke-level bring-up of
// qiling/arch/arm.py and cortex_m.py; disasm/asm corpora byte-identical to the
// Python layer's output on the same input).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "qiling/arch/arm.hpp"

using namespace qiling;

namespace {

std::string_view as_bytes(const std::vector<std::uint8_t>& v) {
    return {reinterpret_cast<const char*>(v.data()), v.size()};
}

}  // namespace

// ---- ARM bring-up and register surface ----

TEST(ArchARM, BringUp) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    EXPECT_EQ(arch.type(), QL_ARCH::ARM);
    EXPECT_EQ(arch.bits(), 32);
    EXPECT_EQ(arch.pointersize(), 4);
    // the live CPSR E bit is clear right after uc_open (CPSR = 0x400001d3)
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);
}

TEST(ArchARM, RegsTable) {
    QlArchARM arch(nullptr);
    auto& regs = arch.regs();

    regs.write("r5", 0x5555);
    EXPECT_EQ(regs.read("r5"), 0x5555u);

    for (const char* name : {"r0", "r12", "sp", "lr", "pc", "apsr", "cpsr", "spsr", "fpexc",
                             "d0", "d31", "fpscr", "q0", "q15", "s0", "s31"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    EXPECT_THROW(static_cast<void>(regs.read("rax")), std::out_of_range);
}

TEST(ArchARM, ThumbModeSwitching) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);

    // unicorn opens ARM with CPSR = 0x400001d3 (T=0, E=0); pin the mode explicitly
    arch.regs().write("cpsr", 0x13);  // SVC mode, T clear
    EXPECT_FALSE(arch.is_thumb());
    arch.regs().write("pc", 0x1000);
    EXPECT_EQ(arch.effective_pc(), 0x1000u);

    // setting the T bit (cortex_m / thumb entry) flips the mode
    arch.regs().write("cpsr", 0x20 | 0x13);
    EXPECT_TRUE(arch.is_thumb());
    EXPECT_EQ(arch.effective_pc(), 0x1001u);  // pc | 1
}

TEST(ArchARM, EndianIsLiveCpsrBit) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);

    arch.regs().write("cpsr", (1u << 9) | 0x13);  // E bit (unicorn preserves it)
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EB);
}

TEST(ArchARM, DisasmCorpus) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    arch.regs().write("cpsr", 0x13);  // pin ARM mode (T bit clear)

    // ARM: mov r0, r1 -> e1a00001 (LE bytes 01 00 a0 e1; explicit length — the
    // NUL in the middle would truncate a C-string-literal string_view)
    const auto insns = arch.disassembler().disasm(std::string_view("\x01\x00\xa0\xe1", 4), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "mov");
    EXPECT_EQ(insns[0].op_str, "r0, r1");
}

TEST(ArchARM, ThumbDisasmCorpus) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    arch.regs().write("cpsr", (1u << 5) | 0x13);  // thumb mode picks CS_MODE_THUMB

    // movs r2, #1 -> 0x2201 (capstone decodes rd = bits[10:8] = r2)
    const auto insns = arch.disassembler().disasm(std::string_view("\x01\x22", 2), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "movs");
    EXPECT_EQ(insns[0].op_str, "r2, #1");
}

TEST(ArchARM, AsmCorpus) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    arch.regs().write("cpsr", 0x13);  // pin ARM mode (KS_MODE_ARM)

    const auto bytes = arch.assembler().assemble("mov r0, r1");
    EXPECT_EQ(as_bytes(bytes), std::string_view("\x01\x00\xa0\xe1", 4));
}

TEST(ArchARM, ThumbAsmCorpus) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    arch.regs().write("cpsr", (1u << 5) | 0x13);  // thumb mode picks KS_MODE_THUMB

    // keystone's ARM mode table is exact-match (ks.cpp): the KS_MODE_ARM |
    // KS_MODE_THUMB combination has no entry, so ks_open fails — the Python
    // layer fails identically (KsError/KS_ERR_MODE) because arm.py builds the
    // same combination. Mirrored verbatim; pure KS_MODE_THUMB would work.
    EXPECT_THROW(static_cast<void>(arch.assembler()), QlErrorArch);
}

TEST(ArchARM, EnableVfp) {
    QlArchARM arch(nullptr, std::nullopt, QL_ENDIAN::EL, false);
    arch.enable_vfp();

    EXPECT_EQ(arch.regs().read("fpexc"), 1u << 30);
    // note: unicorn 2.1.4 treats the cp15 CPACR access through UC_ARM_REG_CP_REG
    // as a no-op — verified identical in the Python binding (cpr read-back 0);
    // the FPEXC part above is the persistent half of enable_vfp in both trees.
}

TEST(ArchARM, CprRoundTrip) {
    QlArchARM arch(nullptr);
    // TPIDRURO is (15, 0, 13, 0, 3, el=0); unicorn 2.1.4 persists this access in
    // both trees (verified against the Python binding's cpr_read/cpr_write)
    const auto before = arch.cpr().read("TPIDRURO");
    arch.cpr().write("TPIDRURO", 0x1234);
    EXPECT_EQ(arch.cpr().read("TPIDRURO"), 0x1234u);
    EXPECT_NE(before, 0x1234u);
}

// ---- Cortex-M (cortex_m.py) ----

TEST(ArchCortexM, BringUp) {
    QlArchCORTEX_M arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::CORTEX_M);
    EXPECT_EQ(arch.bits(), 32);
    EXPECT_TRUE(arch.is_thumb());
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);
}

TEST(ArchCortexM, RegsTable) {
    QlArchCORTEX_M arch(nullptr);
    for (const char* name : {"r0", "r12", "sp", "lr", "pc", "msp", "psp", "xpsr", "apsr",
                             "ipsr", "epsr", "primask", "faultmask", "basepri", "control",
                             "xpsr_nzcvqg"}) {
        EXPECT_NO_THROW(static_cast<void>(arch.regs().read(name))) << "missing register: " << name;
    }
}

TEST(ArchCortexM, HandlerModeDetection) {
    QlArchCORTEX_M arch(nullptr);
    EXPECT_FALSE(arch.is_handler_mode());  // ipsr == 0

    arch.regs().write("ipsr", 16);
    EXPECT_TRUE(arch.is_handler_mode());
    EXPECT_FALSE(arch.using_psp());  // handler mode ignores CONTROL.SPSEL

    arch.regs().write("ipsr", 0);
    arch.regs().write("control", static_cast<std::uint64_t>(CONTROL::SPSEL));
    EXPECT_TRUE(arch.using_psp());
}

TEST(ArchCortexM, DisasmCorpus) {
    QlArchCORTEX_M arch(nullptr);
    // movs r2, #1 -> 0x2201 (capstone decodes rd = bits[10:8] = r2)
    const auto insns = arch.disassembler().disasm(std::string_view("\x01\x22", 2), 0x1000);
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].mnemonic, "movs");
    EXPECT_EQ(insns[0].op_str, "r2, #1");
}

TEST(ArchCortexM, ExceptionHandlerIsDeferredWithBaremetal) {
    QlArchCORTEX_M arch(nullptr);
    EXPECT_THROW(arch.unicorn_exception_handler(2), QlErrorNotImplemented);
}
