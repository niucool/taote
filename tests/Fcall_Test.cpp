// Fcall suite — PORT_PLAN.md §10 Phase 2 (the qiling/os/fcall.py surface over
// the amd64 convention: readParams/writeParams, the ellipsis reader, the call
// orchestration with on-enter/on-exit hooks, and call_native staging).
#include <gtest/gtest.h>

#include <string>

#include "qiling/arch/x86.hpp"
#include "qiling/cc/intel.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/os/memory.hpp"

using namespace qiling;

namespace {

struct FcallHarness {
    QlArchX8664 arch;
    QlCoreStructs structs{QL_ENDIAN::EL, 64};
    QlMemoryManager mem;
    cc::amd64 conv;
    QlFunctionCall fcall;

    FcallHarness()
        : arch(nullptr), mem(arch.uc(), structs, 64), conv(arch), fcall(conv) {
        // the stack helpers (stack_push in call/unwind) operate through the
        // attached memory manager
        arch.attach_memory(mem);
        mem.map(0x7FF000000ull, 0x100000, UC_PROT_ALL, "stack");
        arch.regs().write("rsp", 0x7FF000000ull + 0x80000);
    }
};

}  // namespace

TEST(Fcall, ReadParamsFromRegisters) {
    FcallHarness h;

    // amd64 register-file args: rdi, rsi, rdx, r10, r8, r9
    h.arch.regs().write("rdi", 0x1111);
    h.arch.regs().write("rsi", 0x2222);

    const auto values = h.fcall.read_params({os::PARAM_INTN, os::PARAM_INTN});
    ASSERT_EQ(values.size(), 2u);
    EXPECT_EQ(values[0], 0x1111u);
    EXPECT_EQ(values[1], 0x2222u);
}

TEST(Fcall, WriteParamsToRegisters) {
    FcallHarness h;

    h.fcall.write_params({{os::PARAM_INTN, 0xAAAA}, {os::PARAM_INTN, 0xBBBB}});

    EXPECT_EQ(h.arch.regs().read("rdi"), 0xAAAAu);
    EXPECT_EQ(h.arch.regs().read("rsi"), 0xBBBBu);

    // reading back through the same accessor round-trips
    const auto values = h.fcall.read_params({os::PARAM_INTN, os::PARAM_INTN});
    EXPECT_EQ(values[0], 0xAAAAu);
    EXPECT_EQ(values[1], 0xBBBBu);
}

TEST(Fcall, ReadEllipsisSkipsTypedSlots) {
    FcallHarness h;

    // 3 typed args occupy 3 native slots; the ellipsis follows
    h.arch.regs().write("rdi", 0x1);
    h.arch.regs().write("rsi", 0x2);
    h.arch.regs().write("rdx", 0x3);
    h.arch.regs().write("r10", 0x4);

    const auto extra = h.fcall.read_ellipsis({os::PARAM_INTN, os::PARAM_INTN, os::PARAM_INTN}, 2);
    ASSERT_EQ(extra.size(), 2u);
    EXPECT_EQ(extra[0], 0x4u);  // r10 is the 4th native slot
}

TEST(Fcall, CallSetsReturnValue) {
    FcallHarness h;

    int hook_calls = 0;
    const auto result = h.fcall.call(
        [&hook_calls](std::uint64_t pc, const std::vector<std::pair<std::string, std::uint64_t>>& params)
            -> std::optional<std::uint64_t> {
            ++hook_calls;
            EXPECT_EQ(params[0].second, 0x1u);
            EXPECT_EQ(params[1].second, 0x2u);
            return 0x5A5A;
        },
        {{"arg0", os::PARAM_INTN}, {"arg1", os::PARAM_INTN}},
        {{"arg0", 0x1}, {"arg1", 0x2}},
        nullptr, nullptr, false);

    EXPECT_EQ(hook_calls, 1);
    ASSERT_TRUE(result.retval.has_value());
    EXPECT_EQ(*result.retval, 0x5A5Au);
    // the return value lands in the return register (rax)
    EXPECT_EQ(h.arch.regs().read("rax"), 0x5A5Au);
    // the resolved params carry their types
    ASSERT_EQ(result.params.size(), 2u);
    EXPECT_EQ(result.params[0].name, "arg0");
    EXPECT_EQ(result.params[0].value, 0x1u);
    EXPECT_EQ(result.params[0].type, std::optional<int>(os::PARAM_INTN));
}

TEST(Fcall, CallOnEnterOverridesArgs) {
    FcallHarness h;

    bool saw_override = false;
    const auto result = h.fcall.call(
        [&saw_override](std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>& params)
            -> std::optional<std::uint64_t> {
            saw_override = params[0].second == 0xDEAD;
            return 0;
        },
        {{"arg0", os::PARAM_INTN}},
        {{"arg0", 0x1}},
        // the on-enter hook overrides the staged args (fcall.py: pc + params)
        [](std::uint64_t pc, const std::vector<std::pair<std::string, std::uint64_t>>&)
            -> std::optional<std::pair<std::uint64_t, std::vector<std::pair<std::string, std::uint64_t>>>> {
            std::vector<std::pair<std::string, std::uint64_t>> overridden;
            overridden.emplace_back("arg0", 0xDEAD);
            return std::make_pair(pc, std::move(overridden));
        },
        nullptr, false);

    EXPECT_TRUE(saw_override);
}

TEST(Fcall, CallOnExitOverridesReturnValue) {
    FcallHarness h;

    const auto result = h.fcall.call(
        [](std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>&)
            -> std::optional<std::uint64_t> { return 0x1; },
        {{"arg0", os::PARAM_INTN}},
        {{"arg0", 0x0}},
        nullptr,
        // the on-exit hook overrides the return value (fcall.py, verbatim)
        [](std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>&,
           std::optional<std::uint64_t>) -> std::optional<std::uint64_t> { return 0xBEEF; },
        false);

    ASSERT_TRUE(result.retval.has_value());
    EXPECT_EQ(*result.retval, 0xBEEFu);
}

TEST(Fcall, PassthruSkipsUnwind) {
    FcallHarness h;

    const auto result = h.fcall.call(
        [](std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>&)
            -> std::optional<std::uint64_t> { return 0; },
        {{"a", os::PARAM_INTN}, {"b", os::PARAM_INTN}},
        {{"a", 0x0}, {"b", 0x0}},
        nullptr, nullptr,
        /*passthru=*/true);

    // passthru leaves retaddr at -1 (the caller owns the frame)
    EXPECT_EQ(result.retaddr, -1);
}

TEST(Fcall, CallNativeStagesAndJumps) {
    FcallHarness h;

    h.mem.map(0x500000, 0x1000, UC_PROT_ALL);
    const std::string_view code = "\x90\xC3";  // nop; ret
    h.mem.write(0x500000, code);

    h.arch.regs().set_arch_sp(0x7ff000);
    h.mem.map(0x7fe000, 0x2000, UC_PROT_ALL);

    h.fcall.call_native(0x500000, {{os::PARAM_INTN, 0x77}}, 0x600000);

    // the pc points at the callee and the argument was staged
    EXPECT_EQ(h.arch.regs().arch_pc(), 0x500000u);
    EXPECT_EQ(h.arch.regs().read("rdi"), 0x77u);
    EXPECT_EQ(h.arch.regs().arch_sp(), 0x7ff000 - 1 * 8);  // one native slot reserved
}
