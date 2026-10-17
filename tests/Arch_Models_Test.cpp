// Arch models suite — PORT_PLAN.md §10 Phase 1 (the tests/test_cpu_models.py
// behaviour: every *_CPU_MODEL enum must stay in sync with Unicorn's constants).
// In C++ the sync check compiles down to static_asserts against the UC_CPU_*
// constants (D3: values verbatim, validated at translation time), plus a
// runtime uc_ctl round-trip.
#include <gtest/gtest.h>

#include <optional>

#include "qiling/arch/models.hpp"
#include "qiling/arch/x86.hpp"

using namespace qiling;

// ---- compile-time parity with the unicorn constants (test_cpu_models.py) ----

// x86_const: UC_CPU_X86_<name>
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::GENERIC_QEMU64) == UC_CPU_X86_QEMU64);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::GENERIC_KVM64) == UC_CPU_X86_KVM64);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::GENERIC_QEMU32) == UC_CPU_X86_QEMU32);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::GENERIC_KVM32) == UC_CPU_X86_KVM32);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::AMD_PHENOM) == UC_CPU_X86_PHENOM);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::AMD_ATHLON) == UC_CPU_X86_ATHLON);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::AMD_EPYC_ROME) == UC_CPU_X86_EPYC_ROME);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_CORE2DUO) == UC_CPU_X86_CORE2DUO);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_COREDUO) == UC_CPU_X86_COREDUO);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_486) == UC_CPU_X86_486);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_PENTIUM) == UC_CPU_X86_PENTIUM);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_PENTIUM3) == UC_CPU_X86_PENTIUM3);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_HASWELL) == UC_CPU_X86_HASWELL);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_SKYLAKE_CLIENT) == UC_CPU_X86_SKYLAKE_CLIENT);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_CASCADELAKE_SERVER) == UC_CPU_X86_CASCADELAKE_SERVER);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_ICELAKE_SERVER) == UC_CPU_X86_ICELAKE_SERVER);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_KNIGHTSMILL) == UC_CPU_X86_KNIGHTSMILL);
static_assert(static_cast<std::uint32_t>(X86_CPU_MODEL::INTEL_SNOWRIDGE) == UC_CPU_X86_SNOWRIDGE);

// arm_const: UC_CPU_ARM_<name>
static_assert(static_cast<std::uint32_t>(ARM_CPU_MODEL::ARM_926) == UC_CPU_ARM_926);
static_assert(static_cast<std::uint32_t>(ARM_CPU_MODEL::ARM_CORTEX_M0) == UC_CPU_ARM_CORTEX_M0);
static_assert(static_cast<std::uint32_t>(ARM_CPU_MODEL::ARM_CORTEX_A15) == UC_CPU_ARM_CORTEX_A15);
static_assert(static_cast<std::uint32_t>(ARM_CPU_MODEL::ARM_PXA270C5) == UC_CPU_ARM_PXA270C5);
static_assert(static_cast<std::uint32_t>(ARM_CPU_MODEL::ARM_MAX) == UC_CPU_ARM_MAX);

// arm64_const: UC_CPU_AARCH64_<name>
static_assert(static_cast<std::uint32_t>(ARM64_CPU_MODEL::ARM64_A57) == UC_CPU_ARM64_A57);
static_assert(static_cast<std::uint32_t>(ARM64_CPU_MODEL::ARM64_A53) == UC_CPU_ARM64_A53);
static_assert(static_cast<std::uint32_t>(ARM64_CPU_MODEL::ARM64_A72) == UC_CPU_ARM64_A72);
static_assert(static_cast<std::uint32_t>(ARM64_CPU_MODEL::ARM64_MAX) == UC_CPU_ARM64_MAX);

// riscv_const: UC_CPU_RISCV32_<name> / UC_CPU_RISCV64_<name>
static_assert(static_cast<std::uint32_t>(RISCV_CPU_MODEL::RISCV32_ANY) == UC_CPU_RISCV32_ANY);
static_assert(static_cast<std::uint32_t>(RISCV_CPU_MODEL::RISCV32_SIFIVE_E31) == UC_CPU_RISCV32_SIFIVE_E31);
static_assert(static_cast<std::uint32_t>(RISCV64_CPU_MODEL::RISCV64_ANY) == UC_CPU_RISCV64_ANY);
static_assert(static_cast<std::uint32_t>(RISCV64_CPU_MODEL::RISCV64_SIFIVE_U54) == UC_CPU_RISCV64_SIFIVE_U54);

// ---- runtime: the model actually reaches the uc instance ----

TEST(CpuModels, X86ModelReachesUnicorn) {
    QlArchX8664 arch(nullptr, X86_CPU_MODEL::INTEL_HASWELL);
    EXPECT_EQ(arch.cpu(), static_cast<std::uint32_t>(UC_CPU_X86_HASWELL));
}

TEST(CpuModels, X8632ModelReachesUnicorn) {
    QlArchX86 arch(nullptr, X86_CPU_MODEL::INTEL_CORE2DUO);
    EXPECT_EQ(arch.cpu(), static_cast<std::uint32_t>(UC_CPU_X86_CORE2DUO));
}

TEST(CpuModels, DefaultModelIsUnset) {
    QlArchX8664 arch(nullptr);
    EXPECT_EQ(arch.cpu(), std::nullopt);
}
