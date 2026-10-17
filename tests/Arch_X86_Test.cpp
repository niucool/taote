// Arch suite — PORT_PLAN.md §10 Phase 1 (the qiling/arch/x86.py surface over the
// direct unicorn/capstone/keystone linkage, unicorn pinned 2.1.4 / D15):
// uc bring-up per mode, register maps, get/set (including the sub-register
// overlap views), disassembly and assembly corpora byte-identical to the Python
// layer's output on the same input, MSR access, and context save/restore.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "qiling/arch/msr.hpp"
#include "qiling/arch/x86.hpp"

using namespace qiling;

namespace {

// view keystone output bytes as a string_view for corpus comparison
std::string_view as_bytes(const std::vector<std::uint8_t>& v) {
    return {reinterpret_cast<const char*>(v.data()), v.size()};
}

}  // namespace

namespace {

// Fixed instruction corpora (assemble -> expect exact bytes; disassemble -> expect
// exact mnemonic/op strings). The Python layer's output on the same input is what
// Capstone/Keystone produce there; the byte-identical parity criterion.
struct DisasmCase {
    std::string_view bytes;
    std::string_view mnemonic;
    std::string_view operands;
};

constexpr DisasmCase x8664_disasm_corpus[] = {
    {"\x48\x89\xe0", "mov", "rax, rsp"},
    {"\x90", "nop", ""},
    {"\x0f\x05", "syscall", ""},
    {"\x48\xb8\x78\x56\x34\x12\x78\x56\x34\x12", "movabs", "rax, 0x1234567812345678"},
};

constexpr DisasmCase x8632_disasm_corpus[] = {
    {"\x55", "push", "ebp"},
    {"\x89\xe5", "mov", "ebp, esp"},
    {"\xc3", "ret", ""},
};

constexpr DisasmCase x8616_disasm_corpus[] = {
    {"\xcd\x80", "int", "0x80"},
};

struct AsmCase {
    std::string_view assembly;
    std::string_view bytes;
};

constexpr AsmCase x8664_asm_corpus[] = {
    {"mov rax, rsp", std::string_view("\x48\x89\xe0", 3)},
    {"ret", std::string_view("\xc3", 1)},
    {"nop", std::string_view("\x90", 1)},
    {"mov eax, 1", std::string_view("\xb8\x01\x00\x00\x00", 5)},
};

constexpr AsmCase x8632_asm_corpus[] = {
    {"push ebp", std::string_view("\x55", 1)},
    {"mov ebp, esp", std::string_view("\x89\xe5", 2)},
    {"ret", std::string_view("\xc3", 1)},
};

constexpr AsmCase x8616_asm_corpus[] = {
    {"int 0x80", std::string_view("\xcd\x80", 2)},
};

}  // namespace

// ---- per-mode bring-up: uc instance, endian, pointersize, pc/sp registers ----

TEST(ArchX8664, BringUp) {
    QlArchX8664 arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::X8664);
    EXPECT_EQ(arch.bits(), 64);
    EXPECT_EQ(arch.pointersize(), 8);
    EXPECT_EQ(arch.endian(), QL_ENDIAN::EL);

    arch.regs().write("rip", 0x140001000);
    EXPECT_EQ(arch.regs().read("rip"), 0x140001000u);
    EXPECT_EQ(arch.regs().arch_pc(), 0x140001000u);
}

TEST(ArchX86, BringUp) {
    QlArchX86 arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::X86);
    EXPECT_EQ(arch.bits(), 32);
    EXPECT_EQ(arch.pointersize(), 4);

    arch.regs().write("eip", 0x401000);
    EXPECT_EQ(arch.regs().read("eip"), 0x401000u);
    EXPECT_EQ(arch.regs().arch_pc(), 0x401000u);
}

TEST(ArchA8086, BringUp) {
    QlArchA8086 arch(nullptr);
    EXPECT_EQ(arch.type(), QL_ARCH::A8086);
    EXPECT_EQ(arch.bits(), 16);
    EXPECT_EQ(arch.pointersize(), 2);
}

// ---- register manager: naming, case-insensitivity, sub-register overlap ----

TEST(ArchX8664, RegsRoundTripAndOverlap) {
    QlArchX8664 arch(nullptr);
    auto& regs = arch.regs();

    // case-insensitive read/write (Python lowercases in __getattr__/read)
    regs.write("RAX", 0x123456789abcdef0ull);
    EXPECT_EQ(regs.read("rax"), 0x123456789abcdef0ull);
    EXPECT_EQ(regs.read("RAX"), 0x123456789abcdef0ull);

    // sub-register views observe the same storage (0x123456789abcdef0: the low
    // 32 bits are 0x9abcdef0, low 16 are 0xdef0, low 8 are 0xf0)
    EXPECT_EQ(regs.read("eax"), 0x9abcdef0u);
    EXPECT_EQ(regs.read("ax"), 0xdef0u);
    EXPECT_EQ(regs.read("al"), 0xf0u);

    // writing a narrow view updates the parent's low bits
    regs.write("ax", 0xaabbu);
    EXPECT_EQ(regs.read("rax"), 0x123456789abcaabbull);
}

TEST(ArchX8664, RegsTableCoverage) {
    QlArchX8664 arch(nullptr);
    auto& regs = arch.regs();

    // spot-check every family of the merged x86 reg maps (x86.py merges them all)
    for (const char* name : {"ah", "al", "ax", "eax", "rax", "r15", "r15b", "r15w", "r15d",
                             "cr0", "cr3", "cr8", "dr0", "dr7", "st0", "st7", "eflags",
                             "cs", "ss", "ds", "es", "fs", "gs", "fsbase", "gsbase",
                             "xmm0", "xmm15", "xmm31", "ymm0", "ymm31", "zmm0", "zmm31"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }

    EXPECT_THROW(static_cast<void>(regs.read("nosuchreg")), std::out_of_range);
}

TEST(ArchX86, RegsTableCoverage) {
    QlArchX86 arch(nullptr);
    auto& regs = arch.regs();

    for (const char* name : {"ah", "ax", "eax", "cr0", "cr3", "dr7", "st0", "eflags",
                             "cs", "fs", "xmm0", "xmm7", "ymm0", "ymm7"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    // 64-bit-only registers are absent from the 32-bit map
    EXPECT_THROW(static_cast<void>(regs.read("rax")), std::out_of_range);
    EXPECT_THROW(static_cast<void>(regs.read("zmm0")), std::out_of_range);
}

TEST(ArchA8086, RegsTableCoverage) {
    QlArchA8086 arch(nullptr);
    auto& regs = arch.regs();

    for (const char* name : {"ah", "ax", "ip", "sp", "bp", "eflags", "cs", "ds"}) {
        EXPECT_NO_THROW(static_cast<void>(regs.read(name))) << "missing register: " << name;
    }
    EXPECT_THROW(static_cast<void>(regs.read("eax")), std::out_of_range);
}

TEST(ArchX8664, ArchSpStackPointerRegister) {
    QlArchX8664 arch(nullptr);
    arch.regs().set_arch_sp(0x7ff000);
    EXPECT_EQ(arch.regs().arch_sp(), 0x7ff000u);
}

TEST(ArchX8664, SaveRestore) {
    QlArchX8664 arch(nullptr);
    arch.regs().write("rax", 0x1111);

    auto ctx = arch.save();
    arch.regs().write("rax", 0x2222);
    EXPECT_EQ(arch.regs().read("rax"), 0x2222u);

    arch.restore(*ctx);
    EXPECT_EQ(arch.regs().read("rax"), 0x1111u);
}

TEST(ArchX8664, CpuModelSelection) {
    QlArchX8664 arch(nullptr, X86_CPU_MODEL::INTEL_HASWELL);
    // the model is applied to the uc instance; reading it back via uc_ctl confirms
    EXPECT_EQ(arch.cpu(), static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_HASWELL));
}

TEST(ArchX86, CpuModelDefaultIsUnset) {
    QlArchX86 arch(nullptr);
    EXPECT_EQ(arch.cpu(), std::nullopt);
}

// ---- MSR manager (qiling/arch/msr.py) ----

TEST(ArchMsr, WriteThenRead) {
    QlArchX8664 arch(nullptr, X86_CPU_MODEL::GENERIC_QEMU64);
    QlMsrManager msr(arch.uc());

    // IA32_FS_BASE_MSR = 0xC0000100 (x86_const.py)
    constexpr std::uint64_t IA32_FS_BASE_MSR = 0xC0000100ull;
    msr.write(IA32_FS_BASE_MSR, 0x600000);
    EXPECT_EQ(msr.read(IA32_FS_BASE_MSR), 0x600000u);
}

// ---- capstone disassembly corpus (byte-identical parity) ----

TEST(ArchDisasm, X8664Corpus) {
    QlArchX8664 arch(nullptr);
    const auto& cs = arch.disassembler();

    for (const auto& c : x8664_disasm_corpus) {
        const auto insns = cs.disasm(c.bytes, 0x1000);
        ASSERT_EQ(insns.size(), 1u) << "bytes: " << c.bytes;
        EXPECT_EQ(insns[0].mnemonic, c.mnemonic);
        EXPECT_EQ(insns[0].op_str, c.operands);
    }
}

TEST(ArchDisasm, X8632Corpus) {
    QlArchX86 arch(nullptr);
    const auto& cs = arch.disassembler();

    for (const auto& c : x8632_disasm_corpus) {
        const auto insns = cs.disasm(c.bytes, 0x1000);
        ASSERT_EQ(insns.size(), 1u) << "bytes: " << c.bytes;
        EXPECT_EQ(insns[0].mnemonic, c.mnemonic);
        EXPECT_EQ(insns[0].op_str, c.operands);
    }
}

TEST(ArchDisasm, X8616Corpus) {
    QlArchA8086 arch(nullptr);
    for (const auto& c : x8616_disasm_corpus) {
        const auto insns = arch.disassembler().disasm(c.bytes, 0x1000);
        ASSERT_EQ(insns.size(), 1u);
        EXPECT_EQ(insns[0].mnemonic, c.mnemonic);
        EXPECT_EQ(insns[0].op_str, c.operands);
    }
}

// ---- keystone assembly corpus (byte-identical parity) ----

TEST(ArchAsm, X8664Corpus) {
    QlArchX8664 arch(nullptr);
    for (const auto& c : x8664_asm_corpus) {
        const auto bytes = arch.assembler().assemble(c.assembly);
        EXPECT_EQ(as_bytes(bytes), std::string_view(c.bytes)) << "assembly: " << c.assembly;
    }
}

TEST(ArchAsm, X8632Corpus) {
    QlArchX86 arch(nullptr);
    for (const auto& c : x8632_asm_corpus) {
        const auto bytes = arch.assembler().assemble(c.assembly);
        EXPECT_EQ(as_bytes(bytes), std::string_view(c.bytes)) << "assembly: " << c.assembly;
    }
}

TEST(ArchAsm, X8616Corpus) {
    QlArchA8086 arch(nullptr);
    for (const auto& c : x8616_asm_corpus) {
        const auto bytes = arch.assembler().assemble(c.assembly);
        EXPECT_EQ(as_bytes(bytes), std::string_view(c.bytes)) << "assembly: " << c.assembly;
    }
}
