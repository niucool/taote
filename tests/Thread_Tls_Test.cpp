// The per-arch TLS variants (thread.py QlLinuxARMThread / QlLinuxARM64Thread
// / QlLinuxMIPS32Thread) and the spawn factory dispatch. The TLS surfaces:
// the ARM TPIDRURO coprocessor register, the ARM64 TPIDR_EL0, the MIPS32
// cp0_config3/cp0_userlocal pair.
#include <gtest/gtest.h>

#include <filesystem>

#include "qiling/core.hpp"
#include "qiling/loader/loader.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/arch/arm.hpp"
#include "qiling/arch/arm64.hpp"
#include "qiling/os/linux/thread.hpp"

using namespace qiling;

namespace {

Qiling make_arch_qiling(QL_ARCH archtype) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_tls_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.code = {0x90, 0xC3};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = archtype;
    return Qiling{options};
}

}  // namespace

// the spawn factory: the per-arch subclasses come back per the emulated arch
TEST(ThreadTls, SpawnFactoryDispatchesPerArch) {
    auto x86 = make_arch_qiling(QL_ARCH::X8664);
    auto arm = make_arch_qiling(QL_ARCH::ARM);
    auto arm64 = make_arch_qiling(QL_ARCH::ARM64);
    auto mips = make_arch_qiling(QL_ARCH::MIPS);

    auto tx = os::linux::QlLinuxThread::spawn(&x86, 0, 0);
    auto ta = os::linux::QlLinuxThread::spawn(&arm, 0, 0);
    auto t64 = os::linux::QlLinuxThread::spawn(&arm64, 0, 0);
    auto tm = os::linux::QlLinuxThread::spawn(&mips, 0, 0);

    EXPECT_NE(dynamic_cast<os::linux::QlLinuxX8664Thread*>(tx.get()), nullptr);
    EXPECT_NE(dynamic_cast<os::linux::QlLinuxARMThread*>(ta.get()), nullptr);
    EXPECT_NE(dynamic_cast<os::linux::QlLinuxARM64Thread*>(t64.get()), nullptr);
    EXPECT_NE(dynamic_cast<os::linux::QlLinuxMIPS32Thread*>(tm.get()), nullptr);
}

// the ARM thread's TLS rides the TPIDRURO coprocessor register
TEST(ThreadTls, ArmThreadTlsRoundTripsThroughTpidruro) {
    auto ql = make_arch_qiling(QL_ARCH::ARM);
    auto thread = os::linux::QlLinuxThread::spawn(&ql, 0, 0);
    auto* arm_thread = dynamic_cast<os::linux::QlLinuxARMThread*>(thread.get());
    ASSERT_NE(arm_thread, nullptr);

    arm_thread->set_thread_tls(0x1234000);
    EXPECT_EQ(arm_thread->tls(), 0x1234000);

    auto& arm_arch = dynamic_cast<QlArchARM&>(ql.arch());
    EXPECT_EQ(arm_arch.cpr().read("TPIDRURO"), 0x1234000);

    // the save/restore cycle keeps the tls value
    thread->save();
    arm_arch.cpr().write("TPIDRURO", 0);
    thread->restore();
    EXPECT_EQ(arm_thread->tls(), 0x1234000);
    EXPECT_EQ(arm_arch.cpr().read("TPIDRURO"), 0x1234000);
}


// the ARM64 thread's TLS rides the TPIDR_EL0 coprocessor register
TEST(ThreadTls, Arm64ThreadTlsRoundTripsThroughTpidrEl0) {
    auto ql = make_arch_qiling(QL_ARCH::ARM64);
    auto thread = os::linux::QlLinuxThread::spawn(&ql, 0, 0);
    auto* arm64_thread = dynamic_cast<os::linux::QlLinuxARM64Thread*>(thread.get());
    ASSERT_NE(arm64_thread, nullptr);

    arm64_thread->set_thread_tls(0x7fff0000);
    EXPECT_EQ(arm64_thread->tls(), 0x7fff0000);

    auto& arm64_arch = dynamic_cast<QlArchARM64&>(ql.arch());
    EXPECT_EQ(arm64_arch.cpr().read("TPIDR_EL0"), 0x7fff0000);
}

// the MIPS32 thread's TLS rides the cp0_userlocal register (CONFIG3_ULR set)
TEST(ThreadTls, MipsThreadTlsRoundTripsThroughCp0Userlocal) {
    auto ql = make_arch_qiling(QL_ARCH::MIPS);
    auto thread = os::linux::QlLinuxThread::spawn(&ql, 0, 0);
    auto* mips_thread = dynamic_cast<os::linux::QlLinuxMIPS32Thread*>(thread.get());
    ASSERT_NE(mips_thread, nullptr);

    mips_thread->set_thread_tls(0x7fff0000);
    EXPECT_EQ(mips_thread->tls(), 0x7fff0000);

    // the CONFIG3_ULR bit set (thread.py CONFIG3_ULR = 1 << 13)
    EXPECT_NE(ql.arch().regs().read("cp0_config3") & (1 << 13), 0u);
    EXPECT_EQ(ql.arch().regs().read("cp0_userlocal"), 0x7fff0000);
}

// the x86-64 thread keeps its FS_BASE MSR TLS surface
TEST(ThreadTls, X8664ThreadTlsRoundTripsThroughFsBase) {
    auto ql = make_arch_qiling(QL_ARCH::X8664);
    auto thread = os::linux::QlLinuxThread::spawn(&ql, 0, 0);
    auto* x86_thread = dynamic_cast<os::linux::QlLinuxX8664Thread*>(thread.get());
    ASSERT_NE(x86_thread, nullptr);

    x86_thread->set_thread_tls(0x7fff1000);
    EXPECT_EQ(ql.arch().regs().read("fsbase"), 0x7fff1000);
}
