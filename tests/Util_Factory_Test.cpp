// Component factories + emu-env guessing suite — PORT_PLAN.md §5.2 (utils.py
// select_* factories replacing getattr resolution) and ql_guess_emu_env.
//
// The factories are exercised without a Qiling instance (nullptr): the arch
// layer is Qiling*-independent, and the loader/os factories are only invoked
// for construction-eligibility checks here. The full composition-root wiring
// runs in Qiling_Test.cpp.
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <variant>
#include <vector>

#include "qiling/arch/models.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/arch/arm.hpp"
#include "qiling/arch/arm64.hpp"
#include "qiling/arch/mips.hpp"
#include "qiling/arch/ppc.hpp"
#include "qiling/arch/riscv.hpp"
#include "qiling/const.hpp"
#include "qiling/exception.hpp"
#include "qiling/utils.hpp"

using namespace qiling;

namespace {

// writes bytes to a unique temp file and returns its path
std::filesystem::path temp_bin(const std::string& tag, const std::vector<std::uint8_t>& bytes) {
    static int counter = 0;
    const auto dir = std::filesystem::temp_directory_path();
    const auto path = dir / ("ql_factory_test_" + tag + std::to_string(++counter) + ".bin");

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return path;
}

}  // namespace

// ---- select_arch: every arch instance constructs and surfaces its type ----

TEST(SelectArch, ProducesEveryArchType) {
    // cputype nullopt (the QL_CPU variant defaults to monostate)
    const QL_CPU ncpu = std::monostate{};

    const std::pair<QL_ARCH, QL_ARCH> cases[] = {
        {QL_ARCH::X86, QL_ARCH::X86},
        {QL_ARCH::X8664, QL_ARCH::X8664},
        {QL_ARCH::A8086, QL_ARCH::A8086},
        {QL_ARCH::ARM, QL_ARCH::ARM},
        {QL_ARCH::ARM64, QL_ARCH::ARM64},
        {QL_ARCH::MIPS, QL_ARCH::MIPS},
        {QL_ARCH::PPC, QL_ARCH::PPC},
        {QL_ARCH::RISCV, QL_ARCH::RISCV},
        {QL_ARCH::RISCV64, QL_ARCH::RISCV64},
        {QL_ARCH::CORTEX_M, QL_ARCH::CORTEX_M},
    };

    for (const auto& [archtype, expected] : cases) {
        const auto factory = select_arch(archtype, ncpu, QL_ENDIAN::EL, false);
        auto inst = factory(nullptr);
        ASSERT_NE(inst, nullptr) << static_cast<int>(archtype);
        EXPECT_EQ(inst->type(), expected) << static_cast<int>(archtype);
        EXPECT_EQ(inst->bits() % 8, 0u) << static_cast<int>(archtype);
    }
}

// ---- select_loader / select_os: BLOB available; other trees land in Phase 3+/5 ----

TEST(SelectLoader, BlobFactoryAvailable) {
    const auto factory = select_loader(QL_OS::BLOB, false);
    EXPECT_NE(factory, nullptr);
}

TEST(SelectLoader, NonBlobRaisesNotImplemented) {
    // PE landed with Phase 4; the ELF-backed oses (linux/freebsd/qnx) resolve
    // the QlLoaderELF; the DOS loader landed with the Phase 6 slice (the
    // COM/EXE/MBR branches); the remaining per-format loaders degrade
    for (const auto os : {QL_OS::MACOS, QL_OS::UEFI}) {
        EXPECT_THROW(select_loader(os, false), QlErrorNotImplemented) << static_cast<int>(os);
    }
}

TEST(SelectLoader, FreebsdResolvesElfLoader) {
    // the freebsd dialect rides the QlLoaderELF (the shellcode + the ET_EXEC
    // branches, the linux shape verbatim)
    const auto factory = select_loader(QL_OS::FREEBSD, false);
    EXPECT_NE(factory, nullptr);
}

TEST(SelectLoader, QnxResolvesElfLoader) {
    // the qnx dialect shares the ELF loader (the upstream's loader table maps
    // QNX to QlLoaderELF)
    const auto factory = select_loader(QL_OS::QNX, false);
    EXPECT_NE(factory, nullptr);
}

TEST(SelectOs, BlobFactoryAvailable) {
    const auto factory = select_os(QL_OS::BLOB);
    EXPECT_NE(factory, nullptr);
}

TEST(SelectOs, NonBlobRaisesNotImplemented) {
    // the qnx and dos dialects landed; the remaining os trees defer
    for (const auto os : {QL_OS::MACOS, QL_OS::UEFI}) {
        EXPECT_THROW(select_os(os), QlErrorNotImplemented) << static_cast<int>(os);
    }
}

TEST(SelectOs, FreebsdResolvesFreebsdOs) {
    const auto factory = select_os(QL_OS::FREEBSD);
    EXPECT_NE(factory, nullptr);
}

TEST(SelectOs, QnxResolvesQnxOs) {
    const auto factory = select_os(QL_OS::QNX);
    EXPECT_NE(factory, nullptr);
}

// ---- select_component: the memory manager factory over an arch's uc ----

TEST(SelectComponent, MemoryFactoryBuilds) {
    // the factory is registered through the composition root (core.cpp, where
    // the Qiling facade is complete); the surface mirrors select_component
    const auto factory = select_component_memory();
    EXPECT_NE(factory, nullptr);
}

// ---- select_debugger: option strings -> enum; actual debuggers land later ----

TEST(SelectDebugger, ConvertsOptionStrings) {
    EXPECT_EQ(debugger_convert("gdb"), QL_DEBUGGER::GDB);
    EXPECT_EQ(debugger_convert("qdb"), QL_DEBUGGER::QDB);
    EXPECT_FALSE(debugger_convert("bogus").has_value());
    // the option strings split on ':' inside select_debugger (utils.py); the
    // debugger instances land with the interactive-debugging slice, so the
    // factories degrade to nullptr after validating the head
    EXPECT_EQ(select_debugger(false), nullptr);
    EXPECT_EQ(select_debugger(true), nullptr);
    EXPECT_EQ(select_debugger(std::string("gdb")), nullptr);
    EXPECT_EQ(select_debugger(std::string("qdb:rr")), nullptr);
    EXPECT_THROW(select_debugger(std::string("bogus")), QlErrorArch);
}

// ---- ql_guess_emu_env over hand-rolled format sniffing ----

TEST(GuessEmuEnv, DetectsElf64Amd64) {
    // a minimal ELF64 little-endian header: EI_CLASS=2 (64), EI_DATA=1 (LSB),
    // EI_OSABI=0 (SYSV), e_machine=62 (EM_X86_64)
    std::vector<std::uint8_t> bytes(0x200, 0);
    bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 2;    // 64-bit
    bytes[5] = 1;    // LSB
    bytes[7] = 0;    // SYSV
    bytes[18] = 62;  // EM_X86_64 (little-endian e_machine at offset 18)

    const auto path = temp_bin("elf64", bytes);
    const auto [arch, os, endian] = ql_guess_emu_env(path.string());

    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::X8664);
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::LINUX);
    ASSERT_TRUE(endian.has_value());
    EXPECT_EQ(*endian, QL_ENDIAN::EL);
}

TEST(GuessEmuEnv, DetectsElf32ArmBigEndian) {
    std::vector<std::uint8_t> bytes(0x200, 0);
    bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 1;    // 32-bit
    bytes[5] = 2;    // MSB (big-endian)
    bytes[7] = 0;    // SYSV
    bytes[18] = 0;   // e_machine = 40 (EM_ARM), big-endian bytes: [0, 40]
    bytes[19] = 40;

    const auto path = temp_bin("elf32arm", bytes);
    const auto [arch, os, endian] = ql_guess_emu_env(path.string());

    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::ARM);
    ASSERT_TRUE(endian.has_value());
    EXPECT_EQ(*endian, QL_ENDIAN::EB);
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::LINUX);
}

TEST(GuessEmuEnv, DetectsQnxByInterpreter) {
    std::vector<std::uint8_t> bytes(0x200, 0);
    bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 2; bytes[5] = 1;
    bytes[18] = 62;
    // 'ldqnx.so' inside the first 0x200 bytes
    const char interp[] = "ldqnx.so.2";
    for (std::size_t i = 0; i < sizeof(interp) - 1; ++i) {
        bytes[0x40 + i] = static_cast<std::uint8_t>(interp[i]);
    }

    const auto path = temp_bin("qnx", bytes);
    const auto [arch, os, endian] = ql_guess_emu_env(path.string());

    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::QNX);
}

TEST(GuessEmuEnv, DetectsDostComByExtension) {
    std::vector<std::uint8_t> bytes = {0x90, 0x90, 0xC3};

    const auto dir = std::filesystem::temp_directory_path();
    const auto path = dir / "ql_factory_dos.DOS_COM";
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    const auto [arch, os, endian] = ql_guess_emu_env(path.string());
    std::filesystem::remove(path);

    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::A8086);
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::DOS);
    ASSERT_TRUE(endian.has_value());
    EXPECT_EQ(*endian, QL_ENDIAN::EL);
}

TEST(GuessEmuEnv, DetectsPeAmd64) {
    // a minimal PE: 'MZ' + e_lfanew at 0x3c pointing to a 'PE\0\0' signature,
    // COFF machine = 0x8664 (AMD64), optional header with subsystem 2 (GUI)
    std::vector<std::uint8_t> bytes(0x200, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    const std::uint32_t pe_offset = 0x80;
    for (int i = 0; i < 4; ++i) {
        bytes[0x3c + i] = static_cast<std::uint8_t>(pe_offset >> (8 * i));
    }
    bytes[pe_offset] = 'P'; bytes[pe_offset + 1] = 'E'; bytes[pe_offset + 2] = 0; bytes[pe_offset + 3] = 0;
    // COFF header machine (little-endian 0x8664)
    const std::uint16_t machine = 0x8664;
    for (int i = 0; i < 2; ++i) {
        bytes[pe_offset + 4 + i] = static_cast<std::uint8_t>(machine >> (8 * i));
    }
    // optional header magic at +24, subsystem at optional_header+68 = +92
    const std::uint16_t subsystem = 2;  // IMAGE_SUBSYSTEM_WINDOWS_GUI
    for (int i = 0; i < 2; ++i) {
        bytes[pe_offset + 92 + i] = static_cast<std::uint8_t>(subsystem >> (8 * i));
    }

    const auto path = temp_bin("pe64", bytes);
    const auto [arch, os, endian] = ql_guess_emu_env(path.string());

    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::X8664);
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::WINDOWS);
    ASSERT_TRUE(endian.has_value());
    EXPECT_EQ(*endian, QL_ENDIAN::EL);
}

TEST(GuessEmuEnv, DetectsMachoArm64) {
    // Mach-O 64 magic cffaedfe, cputype 12 (ARM64) at offset 4, byte 7 = 1 (64-bit)
    const std::vector<std::uint8_t> bytes = {
        0xcf, 0xfa, 0xed, 0xfe,
        0x0c, 0x00, 0x00, 0x01,
    };

    const auto path = temp_bin("macho", bytes);
    const auto [arch, os, endian] = ql_guess_emu_env(path.string());

    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, QL_ARCH::ARM64);
    ASSERT_TRUE(os.has_value());
    EXPECT_EQ(*os, QL_OS::MACOS);
    ASSERT_TRUE(endian.has_value());
    EXPECT_EQ(*endian, QL_ENDIAN::EL);
}

TEST(GuessEmuEnv, GarbageDegradesToEmptyGuess) {
    const std::vector<std::uint8_t> bytes(0x40, 0xAB);

    const auto path = temp_bin("garbage", bytes);
    const auto [arch, os, endian] = ql_guess_emu_env(path.string());

    EXPECT_FALSE(arch.has_value());
    EXPECT_FALSE(os.has_value());
    EXPECT_FALSE(endian.has_value());
}

TEST(GuessEmuEnv, MissingFileDegradesToEmptyGuess) {
    const auto [arch, os, endian] = ql_guess_emu_env("Z:/definitely/not/a/file.bin");
    EXPECT_FALSE(arch.has_value());
    EXPECT_FALSE(os.has_value());
    EXPECT_FALSE(endian.has_value());
}
