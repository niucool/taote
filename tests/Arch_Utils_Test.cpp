// QlArchUtils tracing suite — PORT_PLAN.md §10 Phase 3 (the deferred unlocks:
// the get_base_and_name cache, the DISASM trace line, setup_output hooking)
// plus the CORTEX-M init_context vector-table reads that the Phase 2 memory
// manager unlocked.
#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "qiling/arch/arm.hpp"
#include "qiling/arch/utils.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"

using namespace qiling;

namespace {

// the blob facade harness (mirrors the Qiling_Test fixture: the CODE profile
// section is required when code is set)
std::filesystem::path ensure_rootfs() {
    const auto base = std::filesystem::temp_directory_path() / "ql_archutils_rootfs";
    std::filesystem::create_directories(base);
    return base;
}

QilingOptions trace_options(std::vector<std::uint8_t> code) {
    QilingOptions options;
    options.code = std::move(code);
    options.rootfs = ensure_rootfs().string();
    options.ostype = QL_OS::BLOB;
    options.archtype = QL_ARCH::X8664;

    const auto profile_path = ensure_rootfs() / "trace_profile.ql";
    if (!std::filesystem::exists(profile_path)) {
        std::ofstream out(profile_path);
        out << "[CODE]\n"
               "ram_size = 0xa00000\n"
               "load_address = 0x1000000\n"
               "entry_point = 0x1000000\n";
    }
    options.profile = profile_path.string();
    return options;
}

}  // namespace

TEST(QlArchUtils, GetBaseAndNameResolvesImage) {
    Qiling ql(trace_options({
        0x90, 0x90, 0x90, 0x90,
    }));

    // the blob image is registered as 'blob_code' at the load address
    const auto [base, name] = ql.arch().utils().get_base_and_name(0x1000000);
    EXPECT_EQ(base, 0x1000000u);
    // the map label is the blob loader's "[code]"; basename_of keeps it
    EXPECT_EQ(name, "[code]");
}

TEST(QlArchUtils, GetBaseAndNameUnmappedDegrades) {
    Qiling ql(trace_options({0x90}));

    // an address outside every region reports itself with a '-' name
    const auto [base, name] = ql.arch().utils().get_base_and_name(0xDEAD0000);
    EXPECT_EQ(base, 0xDEAD0000u);
    EXPECT_EQ(name, "-");
}

TEST(QlArchUtils, SetupOutputHooksCodeAtDisasm) {
    Qiling ql(trace_options({
        0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 0x2A
        0x90, 0x90, 0x90,
    }));

    // the DISASM verbosity installs the code tracer; running the blob through
    // it must not disturb the emulation
    ql.set_verbose(QL_VERBOSE::DISASM);
    ql.run();

    EXPECT_EQ(ql.arch().regs().read("rax"), 0x2Au);
}

TEST(QlArchUtils, SetupOutputRemovesHooksAtLowerVerbosity) {
    Qiling ql(trace_options({0x90, 0x90}));

    // toggling verbosity down drops the tracer (utils.py removes the hooks)
    ql.set_verbose(QL_VERBOSE::DISASM);
    ql.set_verbose(QL_VERBOSE::DEFAULT);
    ql.run();

    EXPECT_EQ(ql.emu_state(), QL_STATE::STOPPED);
}

// ---- CORTEX-M init_context (the deferred unlock) ----

TEST(CortexMInitContext, ReadsVectorTable) {
    QlArchCORTEX_M arch(nullptr);
    QlCoreStructs structs(QL_ENDIAN::EL, 32);
    QlMemoryManager mem(arch.uc(), structs, 32);
    arch.attach_memory(mem);

    // a vector table: [0] = initial MSP, [4] = reset handler
    mem.map(0x0, 0x1000, UC_PROT_ALL, "vtor");
    mem.write_ptr(0x0, 0x20001000, 4);
    mem.write_ptr(0x4, 0x08000101, 4);

    arch.init_context();

    EXPECT_EQ(arch.regs().read("msp"), 0x20001000u);
    // unicorn normalizes the thumb bit out of the stored pc (it lands in
    // xpsr.T on the write) - identical through the Python binding
    EXPECT_EQ(arch.regs().read("pc"), 0x08000100u);
    EXPECT_EQ(arch.regs().read("lr"), 0xffffffffu);
}

TEST(CortexMInitContext, RequiresMemoryManager) {
    QlArchCORTEX_M arch(nullptr);
    EXPECT_THROW(arch.init_context(), QlErrorBase);
}
