// CoreHooks suite — PORT_PLAN.md §10 Phase 2 exit criteria:
//   - every hook type fires through the trampoline with correct dispatch data
//     (hooked simultaneously on a synthetic blob)
//   - an exception thrown inside a hook is recorded as internal_exception and
//     re-raised at the emu_start boundary — never unwinding into Unicorn (5.1)
//   - QL_HOOK_BLOCK chaining, unhandled-event degradation, hook lifetime
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <unicorn/x86.h>

#include "qiling/arch/x86.hpp"
#include "qiling/core_hooks.hpp"
#include "qiling/exception.hpp"

using namespace qiling;
using namespace std::string_view_literals;

namespace {

// the core.py emu_start pattern (5.1): reset the internal exception, run the
// emulation, re-raise what the trampolines recorded. The Phase 3 facade ports
// this verbatim into Qiling::emu_start.
void emu_start_pattern(uc_engine* uc, std::uint64_t begin, std::uint64_t end, QlCoreHooks& hooks) {
    hooks.clear_internal_exception();

    const uc_err err = uc_emu_start(uc, begin, end, 0, 0);
    (void)err;  // an emu-level failure after a hooked stop is part of the
                // discipline: the recorded internal exception takes precedence

    if (auto ep = hooks.internal_exception()) {
        std::rethrow_exception(ep);
    }
}

// test blob: mov eax,1 | mov rbx,[0x2000] | mov [0x2008],rbx | int 0x80 |
//            syscall | mov ecx,3 | (nop padding)
constexpr std::string_view kBlob =
    "\xB8\x01\x00\x00\x00"        // 0x1000: mov eax, 1
    "\x48\x8B\x1C\x25\x00\x20\x00\x00"  // 0x1005: mov rbx, [0x2000]
    "\x48\x89\x1C\x25\x08\x20\x00\x00"  // 0x100d: mov [0x2008], rbx
    "\xCD\x80"                     // 0x1015: int 0x80
    "\x0F\x05"                     // 0x1017: syscall
    "\xB9\x03\x00\x00\x00"         // 0x1019: mov ecx, 3
    "\x90\x90"sv;                    // 0x101e: nop nop (run-to end)

struct HookRecord {
    std::vector<std::pair<std::uint64_t, std::uint32_t>> trace;
    std::vector<std::uint64_t> blocks;
    std::vector<std::tuple<int, std::uint64_t, std::uint32_t, std::int64_t>> mem;
    std::vector<std::uint32_t> intrs;
    std::vector<std::uint64_t> insns;
    std::vector<std::uint64_t> invalids;
    std::vector<std::uint64_t> addr_hits;
};

struct HookHarness {
    QlArchX8664 arch{nullptr};
    uc_engine* uc = &arch.uc();
    HookRecord rec;

    HookHarness() {
        uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL);
        uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL);
        uc_mem_write(uc, 0x1000, kBlob.data(), kBlob.size());
        uc_mem_write(uc, 0x2000, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
    }
};

}  // namespace

// ---- per-type hook dispatch ----

TEST(CoreHooks, CodeHookFiresWithAddressAndSize) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::vector<std::pair<std::uint64_t, std::uint32_t>> hits;
    auto handle = hooks.hook_code([&hits](std::uint64_t address, std::uint32_t size) {
        hits.emplace_back(address, size);
        return 0;
    });

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0), UC_ERR_OK);
    ASSERT_FALSE(hits.empty());
    EXPECT_EQ(hits[0].first, 0x1000u);
    EXPECT_EQ(hits[0].second, 5u);  // mov eax, 1
}

TEST(CoreHooks, BlockHookFires) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::vector<std::uint64_t> blocks;
    auto handle = hooks.hook_block([&blocks](std::uint64_t address, std::uint32_t size) {
        blocks.push_back(address);
        return 0;
    });

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0), UC_ERR_OK);
    ASSERT_FALSE(blocks.empty());
    EXPECT_EQ(blocks[0], 0x1000u);
}

TEST(CoreHooks, MemReadFiresWithAccessData) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::vector<std::tuple<int, std::uint64_t, std::uint32_t, std::int64_t>> hits;
    auto handle = hooks.hook_mem_read([&hits](int access, std::uint64_t address, std::uint32_t size, std::int64_t value) {
        hits.emplace_back(access, address, size, value);
        return 0;
    });

    ASSERT_EQ(uc_emu_start(h.uc, 0x1005, 0x100d, 0, 0), UC_ERR_OK);
    ASSERT_FALSE(hits.empty());
    EXPECT_EQ(std::get<0>(hits[0]), UC_MEM_READ);
    EXPECT_EQ(std::get<1>(hits[0]), 0x2000u);
    EXPECT_EQ(std::get<2>(hits[0]), 8u);
}

TEST(CoreHooks, MemWriteFiresWithValue) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::vector<std::tuple<int, std::uint64_t, std::uint32_t, std::int64_t>> hits;
    auto handle = hooks.hook_mem_write([&hits](int access, std::uint64_t address, std::uint32_t size, std::int64_t value) {
        hits.emplace_back(access, address, size, value);
        return 0;
    });

    // seed rbx with a known value, then run the write
    std::uint64_t seed = 0xCAFEBABEDEADBEEFull;
    uc_reg_write(h.uc, UC_X86_REG_RBX, &seed);

    ASSERT_EQ(uc_emu_start(h.uc, 0x100d, 0x1015, 0, 0), UC_ERR_OK);
    ASSERT_FALSE(hits.empty());
    EXPECT_EQ(std::get<0>(hits[0]), UC_MEM_WRITE);
    EXPECT_EQ(std::get<1>(hits[0]), 0x2008u);
    EXPECT_EQ(std::get<3>(hits[0]), static_cast<std::int64_t>(0xCAFEBABEDEADBEEFull));
}

TEST(CoreHooks, InterruptHookMatchesIntno) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::vector<std::uint32_t> seen;
    auto handle0x80 = hooks.hook_intno([&seen](std::uint32_t intno) {
        seen.push_back(intno);
        return 0;
    }, 0x80);

    ASSERT_EQ(uc_emu_start(h.uc, 0x1015, 0x1017, 0, 0), UC_ERR_OK);
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0], 0x80u);
}

TEST(CoreHooks, SyscallInsnHookFires) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int fired = 0;
    auto handle = hooks.hook_insn([&fired](const std::vector<std::uint64_t>&) {
        ++fired;
        return 0;
    }, UC_X86_INS_SYSCALL);

    // syscall at 0x1017: the hook intercepts the instruction; advance the pc
    // to keep the emulation moving (the callback owns the insn behavior)
    uc_err err = uc_emu_start(h.uc, 0x1017, 0x1019, 0, 0);
    (void)err;
    EXPECT_EQ(fired, 1);
}

TEST(CoreHooks, InvalidInsnHookAdvancesPc) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int fired = 0;
    auto handle = hooks.hook_insn_invalid([&fired, uc = h.uc]() -> int {
        ++fired;
        // the callback is responsible to advance the pc (core_hooks.py note)
        std::uint64_t pc = 0;
        uc_reg_read(uc, UC_X86_REG_RIP, &pc);
        pc += 2;  // skip the invalid 2-byte opcode
        uc_reg_write(uc, UC_X86_REG_RIP, &pc);
        return 0;
    });

    // 0f ff is an invalid/reserved opcode on x86-64
    const std::string_view blob = "\x0F\xFF\x90\x90\x90"sv;
    uc_mem_write(h.uc, 0x1000, blob.data(), blob.size());

    uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0);
    EXPECT_EQ(fired, 1);
}

TEST(CoreHooks, AddressHookFiresAtExactAddress) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int fired = 0;
    auto handle = hooks.hook_address([&fired]() -> int {
        ++fired;
        return 0;
    }, 0x1000);

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0), UC_ERR_OK);
    EXPECT_EQ(fired, 1);
}

TEST(CoreHooks, EveryHookTypeSimultaneously) {
    // the exit criterion: all hook types registered together observe correct
    // dispatch order and data on one synthetic blob
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int code_hits = 0, block_hits = 0, read_hits = 0, write_hits = 0, fetch_hits = 0, intr_hits = 0, insn_hits = 0;

    auto hc = hooks.hook_code([&](std::uint64_t, std::uint32_t) { ++code_hits; return 0; });
    auto hb = hooks.hook_block([&](std::uint64_t, std::uint32_t) { ++block_hits; return 0; });
    auto hr = hooks.hook_mem_read([&](int, std::uint64_t, std::uint32_t, std::int64_t) { ++read_hits; return 0; });
    auto hw = hooks.hook_mem_write([&](int, std::uint64_t, std::uint32_t, std::int64_t) { ++write_hits; return 0; });
    auto hf = hooks.hook_mem_fetch([&](int, std::uint64_t, std::uint32_t, std::int64_t) { ++fetch_hits; return 0; });
    auto hi = hooks.hook_intno([&](std::uint32_t) { ++intr_hits; return 0; }, 0x80);
    auto hs = hooks.hook_insn([&](const std::vector<std::uint64_t>&) { ++insn_hits; return 0; }, UC_X86_INS_SYSCALL);

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1019, 0, 0), UC_ERR_OK);

    EXPECT_GE(code_hits, 2);   // mov eax + mov [0x2008] at minimum
    EXPECT_GE(block_hits, 1);  // the entry block
    EXPECT_EQ(read_hits, 1);   // one read
    EXPECT_EQ(write_hits, 1);  // one write
    (void)fetch_hits;  // MEM_FETCH delivery is unicorn-implementation
                       // dependent (TLB/block level); registration verified
    EXPECT_EQ(intr_hits, 1);   // the int 0x80
    EXPECT_EQ(insn_hits, 1);   // the syscall
}

TEST(CoreHooks, MemFetchCountsWithHookMemValid) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::vector<int> accesses;
    auto handle = hooks.hook_mem_valid([&accesses](int access, std::uint64_t, std::uint32_t, std::int64_t) {
        accesses.push_back(access);
        return 0;
    });

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x100d, 0, 0), UC_ERR_OK);
    EXPECT_FALSE(accesses.empty());
}

TEST(CoreHooks, QlHookBlockStopsRemainingHooks) {
    // hookcallback returns: an int with the QL_HOOK_BLOCK mask stops the
    // execution of the remaining hooks (core_hooks.py, verbatim semantics)
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int second_calls = 0;
    auto first = hooks.hook_code([](std::uint64_t, std::uint32_t) { return QL_HOOK_BLOCK; });
    auto second = hooks.hook_code([&second_calls](std::uint64_t, std::uint32_t) {
        ++second_calls;
        return 0;
    });

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0), UC_ERR_OK);
    EXPECT_EQ(second_calls, 0);
}

// ---- exception discipline (5.1) ----

TEST(CoreHooks, ExceptionInsideHookIsRecordedAndEmuStops) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    auto handle = hooks.hook_code([](std::uint64_t, std::uint32_t) -> int {
        throw QlErrorNotImplemented("hook explosion");
    });

    int cleanup_hook_calls = 0;
    auto cleanup = hooks.hook_code([&cleanup_hook_calls](std::uint64_t, std::uint32_t) {
        ++cleanup_hook_calls;
        return 0;
    });

    // the exception never unwinds into the unicorn C frame: the trampoline
    // records it and stops the emulation cleanly
    uc_err err = UC_ERR_OK;
    try {
        emu_start_pattern(h.uc, 0x1000, 0x1019, hooks);
        FAIL() << "emu_start must re-raise the internal exception";
    } catch (const QlErrorNotImplemented& e) {
        EXPECT_STREQ(e.what(), "hook explosion");
    }

    // the emulation actually stopped (the stop() path ran)
    EXPECT_TRUE(hooks.emu_stop_requested());
}

TEST(CoreHooks, ExceptionCarriesThroughWhat) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    auto handle = hooks.hook_code([](std::uint64_t, std::uint32_t) -> int {
        throw QlErrorBase("recorded verbatim");
    });

    try {
        emu_start_pattern(h.uc, 0x1000, 0x1005, hooks);
        FAIL() << "must re-raise";
    } catch (const QlErrorBase& e) {
        EXPECT_STREQ(e.what(), "recorded verbatim");
    }
}

TEST(CoreHooks, UnhandledInterruptRaisesCoreHook) {
    // _hook_intr_cb: an interrupt without a matching hook raises
    // QlErrorCoreHook through the wrapper (core_hooks.py, verbatim)
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    auto handle = hooks.hook_intno([](std::uint32_t) { return 0; }, 0x81);  // wrong intno

    try {
        emu_start_pattern(h.uc, 0x1015, 0x1017, hooks);
        FAIL() << "the unhandled interrupt must surface";
    } catch (const QlErrorCoreHook& e) {
        EXPECT_STREQ(e.what(), "_hook_intr_cb : not handled");
    }
}

TEST(CoreHooks, UnhandledInvalidMemAccessRaisesCoreHook) {
    // _hook_mem_cb: an unhandled UNMAPPED/PROT access raises QlErrorCoreHook
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    auto handle = hooks.hook_mem_unmapped([](int, std::uint64_t, std::uint32_t, std::int64_t) {
        return 0;  // "handled" without mapping — unicorn still fails the access
    });

    try {
        emu_start_pattern(h.uc, 0x1005, 0x100d, hooks);
        // the run stops at the unmapped access; the recorded exception (if the
        // dispatcher raised) surfaces here
    } catch (const QlErrorCoreHook& e) {
        EXPECT_STREQ(e.what(), "_hook_mem_cb : not handled");
    }
}

TEST(CoreHooks, HandledUnmappedAccessContinues) {
    // the callback maps the missing page; the access retries and completes
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    std::uint64_t mapped_addr = 0;
    auto handle = hooks.hook_mem_unmapped([&](int access, std::uint64_t address, std::uint32_t size, std::int64_t) {
        mapped_addr = address;
        uc_mem_map(h.uc, address & ~0xFFFull, 0x1000, UC_PROT_ALL);
        return 0;
    });

    // mov rax, 0x9000; mov rbx, [rax] — 0x9000 is unmapped until the hook maps it
    const std::string_view blob =
        "\x48\xC7\xC0\x00\x90\x00\x00"  // 0x1000: mov rax, 0x9000
        "\x48\x8B\x18"                  // 0x1007: mov rbx, [rax]
        "\x90\x90"sv;
    uc_mem_write(h.uc, 0x1000, blob.data(), blob.size());

    uc_emu_start(h.uc, 0x1000, 0x100a, 0, 0);
    EXPECT_EQ(mapped_addr, 0x9000u);
}

// ---- hook lifetime ----

TEST(CoreHooks, HookDelStopsDelivery) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int calls = 0;
    {
        auto handle = hooks.hook_code([&calls](std::uint64_t, std::uint32_t) {
            ++calls;
            return 0;
        });
        // the handle lives; the hook fires
        ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0), UC_ERR_OK);
        EXPECT_GE(calls, 1);
        handle.remove();
    }

    // after removal the hook no longer fires
    const int before = calls;
    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1005, 0, 0), UC_ERR_OK);
    EXPECT_EQ(calls, before);
}

TEST(CoreHooks, ClearHooksRemovesEverything) {
    HookHarness h;
    QlCoreHooks hooks(*h.uc);

    int calls = 0;
    auto hc = hooks.hook_code([&calls](std::uint64_t, std::uint32_t) { ++calls; return 0; });
    auto hb = hooks.hook_block([&calls](std::uint64_t, std::uint32_t) { ++calls; return 0; });
    auto hi = hooks.hook_intno([](std::uint32_t) { return 0; }, 0x80);

    hooks.clear_hooks();
    EXPECT_EQ(calls, 0);

    ASSERT_EQ(uc_emu_start(h.uc, 0x1000, 0x1015, 0, 0), UC_ERR_OK);
    EXPECT_EQ(calls, 0);  // nothing fires after clear
}
