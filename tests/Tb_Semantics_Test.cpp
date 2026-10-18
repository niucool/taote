// Tb_Semantics suite — the unicorn TB-semantics study for the pc-drift issue
// (STATUS.md Phase 5, the open issue): the round that ends inside a TB
// continuing past the INSN-hook emu_stop lands past the syscall. The probes
// pin the exact behavior on the stock unicorn 2.x:
//
//   P1  the stop-inside-the-INSN-hook: does the TB tail (the instructions
//       after the syscall, same TB) execute, and where does the pc land
//   P2  the pc set inside the hook: does an explicit set_arch_pc survive the
//       deferred stop, or does the TB tail clobber it (the drift mechanism)
//   P3  the resume after the stop: a fresh emu_start from the landed pc —
//       does the hooked syscall re-fire (the TB re-entry)
//
// The findings are asserted so a unicorn bump that changes the semantics
// fails loudly.
#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <cstdio>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

using namespace std::string_view_literals;

namespace {

// the probe body: syscall | mov ecx,3 | mov edx,4 | nop nop
//   +0x00: 0F 05            syscall
//   +0x02: B9 03 00 00 00   mov ecx, 3
//   +0x07: BA 04 00 00 00   mov edx, 4
//   +0x0c: 90 90            nop nop (run-to end)
constexpr std::string_view kBody =
    "\x0F\x05"
    "\xB9\x03\x00\x00\x00"
    "\xBA\x04\x00\x00\x00"
    "\x90\x90"sv;

constexpr std::uint64_t kBase = 0x1000;
constexpr std::uint64_t kSyscall = kBase;         // +0x00
constexpr std::uint64_t kMovEcx = kBase + 2;      // +0x02
constexpr std::uint64_t kMovEdx = kBase + 7;      // +0x07
constexpr std::uint64_t kEnd = kBase + 0x0e;      // past the body

struct Probe {
    uc_engine* uc = nullptr;
    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    std::vector<std::uint64_t> code_trace;
    int code_count = 0;
    std::vector<std::uint64_t> syscall_fired;
    std::uint64_t pc_in_hook = 0;
    bool stop_in_hook = false;
    bool set_pc_in_hook = false;
    std::uint64_t pc_set_value = 0;

    ~Probe() {
        if (uc) {
            uc_close(uc);
        }
    }
};

void probe_code_hook(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    ++self->code_count;
    self->code_trace.push_back(address);
    std::fprintf(stderr, "[psize] 0x%llx size=%u\n", static_cast<unsigned long long>(address), size);
    if (self->code_count > 64) {
        // the runaway guard: the trace has seen enough, stop
        uc_emu_stop(uc);
    }
}

// the UC_HOOK_INSN callback for the x86 syscall: void (uc, user_data) - no
// address/size payload (the unicorn-2 uc_cb_insn_syscall_t shape)
void probe_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    self->pc_in_hook = pc;
    if (self->set_pc_in_hook) {
        uc_reg_write(uc, UC_X86_REG_RIP, &self->pc_set_value);
    }
    if (self->stop_in_hook) {
        uc_emu_stop(uc);
    }
}

Probe make_probe(bool stop_in_hook, bool set_pc_in_hook = false, std::uint64_t pc_set_value = 0) {
    Probe p;
    p.stop_in_hook = stop_in_hook;
    p.set_pc_in_hook = set_pc_in_hook;
    p.pc_set_value = pc_set_value;

    const uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    if (err != UC_ERR_OK) {
        p.uc = nullptr;
        return p;
    }
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);
    uc_mem_write(p.uc, kBase, kBody.data(), kBody.size());
    const std::uint64_t rsp = 0x7ff000;
    uc_reg_write(p.uc, UC_X86_REG_RSP, &rsp);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN,
                reinterpret_cast<void*>(probe_syscall_hook), &p, 1, 0, UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);
    return p;
}

std::uint64_t reg(uc_engine* uc, int id) {
    std::uint64_t v = 0;
    uc_reg_read(uc, id, &v);
    return v;
}

}  // namespace

// P1: the stop inside the INSN hook is IMMEDIATE — the probe disproves the
// earlier TB-boundary guess (STATUS.md pre-probe finding): the TB tail does
// NOT run past the stop, and the pc lands at the syscall + the syscall's
// size (the natural post-instruction advance), not at the TB end.
TEST(TbSemantics, StopInInsnHookIsImmediate) {
    auto p = make_probe(true);
    ASSERT_NE(p.uc, nullptr);

    const uc_err err = uc_emu_start(p.uc, kSyscall, kEnd, 0, 0);
    EXPECT_EQ(err, UC_ERR_OK);

    // the hook fired once, at the syscall
    ASSERT_EQ(p.syscall_fired.size(), 1u);
    EXPECT_EQ(p.syscall_fired[0], kSyscall);
    EXPECT_EQ(p.pc_in_hook, kSyscall);

    // the TB tail did NOT execute: the movs never ran
    EXPECT_EQ(reg(p.uc, UC_X86_REG_ECX), 0u);
    EXPECT_EQ(reg(p.uc, UC_X86_REG_EDX), 0u);

    // the pc landed at the syscall + the syscall's size (the natural advance)
    EXPECT_EQ(reg(p.uc, UC_X86_REG_RIP), kSyscall + 2);
}

// P2: the pc set inside the hook SURVIVES, but the hooked instruction's
// size is re-advanced onto it afterward: the effective resume pc =
// set_value + syscall_size. This is the drift mechanism pinned: a handler
// that redirects the pc (the clone child save, the futex wait redirect)
// inside the INSN hook must compensate for the post-advance (set the
// target minus the hooked instruction's length), or account for it at the
// resume.
TEST(TbSemantics, PcSetInHookGetsInsnSizeAdded) {
    // redirect to the mov-edx address; the effective pc should be the set
    // value + the syscall's size (2)
    auto p = make_probe(true, true, kMovEdx);
    ASSERT_NE(p.uc, nullptr);

    const uc_err err = uc_emu_start(p.uc, kSyscall, kEnd, 0, 0);
    EXPECT_EQ(err, UC_ERR_OK);

    // the TB tail did not run: the mov ecx never executed despite sitting
    // between the syscall and the redirect target
    EXPECT_EQ(reg(p.uc, UC_X86_REG_ECX), 0u);

    // the set survived + the hooked instruction's size re-added
    EXPECT_EQ(reg(p.uc, UC_X86_REG_RIP), kMovEdx + 2);
}

// P3: the resume after the stop — a fresh emu_start from the landed pc does
// NOT re-fire the hooked syscall (the stop consumed it). The syscall hook
// fires exactly once across the stop + the resume.
TEST(TbSemantics, ResumeAfterStopDoesNotRefireSyscall) {
    auto p = make_probe(true);
    ASSERT_NE(p.uc, nullptr);

    ASSERT_EQ(uc_emu_start(p.uc, kSyscall, kEnd, 0, 0), UC_ERR_OK);
    ASSERT_EQ(p.syscall_fired.size(), 1u);
    const auto landed = reg(p.uc, UC_X86_REG_RIP);

    // the resume from where the stop landed: the syscall is behind the pc,
    // the TB re-translation starts at the landed address
    if (landed < kEnd) {
        ASSERT_EQ(uc_emu_start(p.uc, landed, kEnd, 0, 0), UC_ERR_OK);
    }
    EXPECT_EQ(p.syscall_fired.size(), 1u);
}

// P4: the mid-TB restart with the absolute-addressing store — the clone
// test's exact shape: the phase 1 stops inside the syscall INSN hook, the
// phase 2 restarts at the syscall + 2 (mid-TB: the parent's TB covered the
// syscall AND the following instructions) with a redirected rax/sp, then
// branches and executes a C7 04 25 (mov dword [disp32], imm32) store.
// Reproduces the clone-child's UC_ERR_READ_UNMAPPED at the SIB byte.
TEST(TbSemantics, MidTbRestartThenAbsoluteStore) {
    auto p = make_probe(true);  // the phase-1 stop inside the syscall hook
    ASSERT_NE(p.uc, nullptr);

    // the store blob: syscall | test eax,eax | jz store_path | (the nops)
    //   +0x00: 0F 05                 syscall
    //   +0x02: 48 85 C0              test rax, rax
    //   +0x05: 74 07                 jz +7 (to +0x0e)
    //   +0x07: 90 90 90              nop nop nop
    //   +0x0a: EB FE                 jmp $ (the parent loop)
    //   +0x0c: 90 90                 (the pad)
    //   +0x0e: C7 04 25 00 20 00 01 2A 00 00 00   mov dword [0x1002000], 42
    //   +0x19: EB FE                 jmp $
    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90', '\x90',
        '\xEB', '\xFE',
        '\x90', '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    // the store target page
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint64_t kStoreAddr = 0x1002000;
    const std::uint64_t kBodyEnd = kBase + body.size();

    // phase 1: run to the syscall; the hook stops it there
    uc_emu_start(p.uc, kSyscall, kBodyEnd, 0, 0);

    // the diagnostic printout: the pc after the stop, the ecx/edx
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    const auto store_addr = reg(p.uc, UC_X86_REG_RBX);
    (void)store_addr;
    EXPECT_EQ(pc, kSyscall + 2);

    // phase 2: redirect like the clone child (the rax=0, the sp=the stack)
    const std::uint64_t zero = 0;
    const std::uint64_t child_sp = 0x1203000;
    uc_mem_map(p.uc, child_sp - 0x1000, 0x1000, UC_PROT_ALL);
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 0);

    // the store landed
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, kStoreAddr, got.data(), 4);
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P5: the mid-TB restart on a CACHED TB — the clone test's child shape: the
// first pass translates/executes the block from the syscall+2 (the parent's
// path), then the child restarts at the SAME address with a redirected rax
// and branches to the store. OBSERVED (the raw-unicorn reproduction): the
// taken-path store after the cached-TB mid-TB restart does not land.
// THE FIX DIRECTIONS, MEASURED: the uc_ctl tb flush before the restart was
// attempted here and does NOT cure the mis-execution (the store still
// skips). The remaining direction (the fresh-TB spawn starts) needs the
// child's first emu_start to begin on an address unicorn has never used as
// a begin, which the clone continuation semantics cannot provide. DISABLED_
// as the documented open question; see STATUS.md.
// P5 (re-run after the P7 bisect disproved the cached-TB theory): the
// runaway guard in make_probe's code hook (code_count > 64 -> uc_emu_stop)
// fired during phase 2's jmp$ loop, so the ORIGINAL P5 phase-3 stopped after
// one instruction — the "cached-TB mis-execution" was the guard, not the
// cache. This re-run defuses the guard for the phases after the syscall
// stop (stop_in_hook off after phase 1; the code hook stays for the
// observability) and asserts the taken-path store lands on the cached TB.
TEST(TbSemantics, MidTbRestartOnCachedTb) {
    auto p = make_probe(true);
    ASSERT_NE(p.uc, nullptr);

    std::string body{
        '\x0F', '\x05',                      // +0x00 syscall
        '\x48', '\x85', '\xC0',              // +0x02 test rax, rax
        '\x74', '\x07',                      // +0x05 jz +7 (to +0x0e)
        '\x90', '\x90', '\x90',              // +0x07 nops (the parent path)
        '\xEB', '\xFE',                      // +0x0a jmp $
        '\x90', '\x90',                      // +0x0c pad
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',  // +0x0e store
        '\xEB', '\xFE'};                     // +0x19 jmp $
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint64_t kBodyEnd = kBase + body.size();

    // phase 1: the syscall stops the slice (the cached TB from 0x0)
    uc_emu_start(p.uc, kBase, kBodyEnd, 0, 0);
    // defuse the guard + the stop for the phases after the syscall stop:
    // the syscall hook stays but the rax flow never re-enters it; the code
    // hook's runaway budget resets per phase
    p.stop_in_hook = false;

    // phase 2: the not-taken pass (rax=2001) — the TB from +0x02 caches
    const std::uint64_t child_tid = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &child_tid);
    p.code_count = 0;
    const uc_err err2 = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    (void)err2;

    // phase 3: the SAME begin address (the cached TB), the rax=0
    const std::uint64_t zero = 0;
    const std::uint64_t child_sp = 0x1203000;
    uc_mem_map(p.uc, child_sp - 0x1000, 0x1000, UC_PROT_ALL);
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    p.code_count = 0;
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P6: the instrumented P5 — the per-phase code traces printed to stderr so
// the mis-execution mechanism is observable. The phases: (1) the syscall
// stop (the TB from 0x00 cached), (2) the parent's second slice from +0x02
// (rax=2001, the not-taken path — the TB from +0x02 cached), (3) the child
// restart at +0x02 with rax=0 (the taken path expected: the jz to +0x0e and
// the store). The trace after each phase shows what executed; the child's
// trace tells whether the jz fell through (the stale-TB theory) or the TB
// never ran (the restart-refused theory).
static void probe_dump_trace(const char* tag, const std::vector<std::uint64_t>& trace) {
    std::fprintf(stderr, "[%s]", tag);
    for (const auto pc : trace) {
        std::fprintf(stderr, " 0x%llx", static_cast<unsigned long long>(pc));
    }
    std::fprintf(stderr, "\n");
}

TEST(TbSemantics, DISABLED_P6CachedTbRestartInstrumented) {
    auto p = make_probe(true);
    ASSERT_NE(p.uc, nullptr);

    std::string body{
        '\x0F', '\x05',                      // +0x00 syscall
        '\x48', '\x85', '\xC0',              // +0x02 test rax, rax
        '\x74', '\x07',                      // +0x05 jz +7 (to +0x0e)
        '\x90', '\x90', '\x90',              // +0x07 nops (the parent path)
        '\xEB', '\xFE',                      // +0x0a jmp $
        '\x90', '\x90',                      // +0x0c pad
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',  // +0x0e store
        '\xEB', '\xFE'};                     // +0x19 jmp $
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint64_t kBodyEnd = kBase + body.size();

    // phase 1: the syscall stop
    uc_emu_start(p.uc, kBase, kBodyEnd, 0, 0);
    probe_dump_trace("p6-phase1", p.code_trace);
    p.code_trace.clear();

    // phase 2: the parent's second slice (rax=2001, the not-taken path)
    const std::uint64_t child_tid = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &child_tid);
    uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    probe_dump_trace("p6-phase2", p.code_trace);
    const auto pc2 = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p6-phase2-end] pc=0x%llx\n", static_cast<unsigned long long>(pc2));
    p.code_trace.clear();

    // phase 3: the child restart at the SAME begin (rax=0, the taken path)
    const std::uint64_t zero = 0;
    const std::uint64_t child_sp = 0x1203000;
    uc_mem_map(p.uc, child_sp - 0x1000, 0x1000, UC_PROT_ALL);
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    probe_dump_trace("p6-phase3", p.code_trace);
    const auto pc3 = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p6-phase3-end] err=%s pc=0x%llx\n", uc_strerror(err),
                 static_cast<unsigned long long>(pc3));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p6-store] %u\n", static_cast<unsigned>(got[0]));
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P7: the poisoning bisect — what about phase 2 poisons phase 3? Three
// fresh-uc experiments, each phase-1 = the syscall stop, then a phase-2 run
// from +0x02 with a DIFFERENT exit cause, then the phase-3 child restart at
// +0x02 (rax=0, the taken path):
//   E1  the phase-2 exit = the natural until (until=0x100a, no count)
//   E2  the phase-2 exit = uc_emu_stop from a code hook at 0x100a
//   E3  the phase-2 exit = the count cap (the P5 shape, the known-failing
//       control)
// The store-lands answer per experiment isolates the exit-cause family that
// poisons the cached-TB restart.
struct P7Result {
    uc_err err = UC_ERR_OK;
    std::uint32_t store = 0;
    std::vector<std::uint64_t> trace;
    std::uint64_t pc = 0;
};

enum class P7Exit { Until, StopHook, Count };

static P7Result p7_run(P7Exit exit_kind) {
    P7Result out;
    Probe p;
    p.stop_in_hook = true;
    if (exit_kind == P7Exit::StopHook) {
        // the code hook uc_emu_stops at 0x100a (the jmp$ address) on the
        // phase-2 pass only
        p.code_count = 0;
    }
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);
    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90', '\x90',
        '\xEB', '\xFE',
        '\x90', '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);
    const std::uint64_t kBodyEnd = kBase + body.size();

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(probe_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);

    // the phase-2 stop-hook rides a dedicated UC_HOOK_CODE bound to 0x100a
    // (the address-bound hook stops the phase-2 pass; the guard flag keeps
    // it inert for the phase-3 pass)
    static bool p7_stop_armed = false;
    p7_stop_armed = (exit_kind == P7Exit::StopHook);
    static Probe* p7_owner = nullptr;
    p7_owner = &p;
    auto* stop_hook_fn = +[](uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
        (void)address;
        (void)size;
        auto* self = static_cast<Probe*>(user_data);
        self->code_trace.push_back(address);
        if (p7_stop_armed && address == kBase + 0x0a) {
            uc_emu_stop(uc);
        }
        if (self->code_trace.size() > 256) {
            uc_emu_stop(uc);
        }
    };
    uc_hook code_hook2 = 0;
    uc_hook_add(p.uc, &code_hook2, UC_HOOK_CODE, reinterpret_cast<void*>(stop_hook_fn), &p, 1, 0);

    // phase 1: the syscall stop
    uc_emu_start(p.uc, kBase, kBodyEnd, 0, 0);

    // phase 2: the not-taken pass (rax=2001)
    const std::uint64_t child_tid = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &child_tid);
    switch (exit_kind) {
    case P7Exit::Until:
        uc_emu_start(p.uc, kSyscall + 2, kBase + 0x0a, 0, 0);
        break;
    case P7Exit::StopHook:
        p7_stop_armed = true;
        uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 0);
        p7_stop_armed = false;
        break;
    case P7Exit::Count:
        uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
        break;
    }
    p.code_trace.clear();

    // phase 3: the child restart at the same begin (rax=0, the taken path)
    const std::uint64_t zero = 0;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    out.err = err;
    out.trace = p.code_trace;
    out.pc = reg(p.uc, UC_X86_REG_RIP);
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    out.store = got[0];
    uc_close(p.uc);
    p.uc = nullptr;
    return out;
}

TEST(TbSemantics, DISABLED_P7PoisoningBisect) {
    const auto e1 = p7_run(P7Exit::Until);
    std::fprintf(stderr, "[p7-E1-until] err=%s pc=0x%llx store=%u trace0=0x%llx n=%zu\n",
                 uc_strerror(e1.err), static_cast<unsigned long long>(e1.pc), e1.store,
                 e1.trace.empty() ? 0ull : static_cast<unsigned long long>(e1.trace[0]), e1.trace.size());

    const auto e2 = p7_run(P7Exit::StopHook);
    std::fprintf(stderr, "[p7-E2-stophook] err=%s pc=0x%llx store=%u trace0=0x%llx n=%zu\n",
                 uc_strerror(e2.err), static_cast<unsigned long long>(e2.pc), e2.store,
                 e2.trace.empty() ? 0ull : static_cast<unsigned long long>(e2.trace[0]), e2.trace.size());

    const auto e3 = p7_run(P7Exit::Count);
    std::fprintf(stderr, "[p7-E3-count] err=%s pc=0x%llx store=%u trace0=0x%llx n=%zu\n",
                 uc_strerror(e3.err), static_cast<unsigned long long>(e3.pc), e3.store,
                 e3.trace.empty() ? 0ull : static_cast<unsigned long long>(e3.trace[0]), e3.trace.size());
}

// P8: the corrected cached-TB model — the parent's TB from the syscall
// CONTINUES past the syscall inside the SAME pass (the INSN hook returns,
// unicorn advances into the body — the TB [0x00..0x0a] spans the syscall AND
// the body), so the +0x02 begin the child uses later sits INTERIOR to a
// cached TB (P5's phase-2 modeled the +0x02 TB as an emu_start BEGIN, which
// the clone never does). Phases: (1) emu_start(0x00) with the syscall hook
// NOT stopping — the TB continues through the not-taken loop (rax=2001);
// (2) the child emu_start(+0x02) with rax=0 — the taken path expected to
// reach the store.
TEST(TbSemantics, DISABLED_P8InsnContinuationCachedTb) {
    auto p = make_probe(true);
    p.stop_in_hook = false;  // the syscall hook records and returns — the
                             // TB continues past the syscall
    ASSERT_NE(p.uc, nullptr);

    std::string body{
        '\x0F', '\x05',                      // +0x00 syscall
        '\x48', '\x85', '\xC0',              // +0x02 test rax, rax
        '\x74', '\x07',                      // +0x05 jz +7 (to +0x0e)
        '\x90', '\x90', '\x90',              // +0x07 nops (the parent path)
        '\xEB', '\xFE',                      // +0x0a jmp $
        '\x90', '\x90',                      // +0x0c pad
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',  // +0x0e store
        '\xEB', '\xFE'};                     // +0x19 jmp $
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint64_t kBodyEnd = kBase + body.size();

    // phase 1: the parent's pass — the TB from 0x00 spans the syscall and
    // the not-taken body; the count caps the jmp$ loop
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, kBodyEnd, 0, 4096);

    // phase 2: the child's restart at +0x02 (interior to the cached TB),
    // rax=0 — the taken path to the store (the guard budget resets: the
    // phase-1 loop burned it — the pinned guard artifact)
    p.code_count = 0;
    p.code_trace.clear();
    const std::uint64_t zero = 0;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    probe_dump_trace("p8-phase2", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p8-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p8-store] %u\n", static_cast<unsigned>(got[0]));
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P9: the P8 shape plus the parent's pass ending via an INSN-hook stop (the
// futex-park shape — the only P7 variant untested) and the per-event hook
// size printed. The body: the clone syscall at +0x00 (the hook returns — the
// TB continues) and a second syscall at +0x0a whose INSN hook uc_emu_stops
// (the parent's park). The child then restarts at +0x02 (rax=0) and the
// taken-path store's hook size tells whether the INSN-stop poisons the
// taken-path entry decode.
TEST(TbSemantics, DISABLED_P9InsnStopPoisonsTakenEntry) {
    Probe p;
    p.stop_in_hook = false;  // the first syscall's hook: records, returns
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    //   +0x00: 0F 05                 syscall (the hook returns — the TB continues)
    //   +0x02: 48 85 C0              test rax, rax
    //   +0x05: 74 07                 jz +7 (to +0x0e)
    //   +0x07: 90 90                 nop nop
    //   +0x09: 0F 05                 syscall (the INSN hook stops — the park)
    //   +0x0b: 90 90                 nop nop
    //   +0x0d: (the pad)
    //   +0x0e: C7 04 25 00 20 00 01 2A 00 00 00   mov dword [0x1002000], 42
    //   +0x19: EB FE                 jmp $
    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint64_t kBodyEnd = kBase + body.size();

    // the INSN hook: the first syscall returns (pass 1), the second stops
    p.stop_in_hook = false;
    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(probe_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // phase 1: the parent (rax=2001) — the clone-syscall hook returns, the
    // body runs to the second syscall whose hook stops the pass
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, kBodyEnd, 0, 4096);
    probe_dump_trace("p9-phase1", p.code_trace);
    p.code_trace.clear();
    p.code_count = 0;

    // phase 2: the child restart at +0x02 (rax=0) — the taken path to the
    // store; the hook sizes print per event
    const std::uint64_t zero = 0;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    probe_dump_trace("p9-phase2", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p9-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p9-store] %u\n", static_cast<unsigned>(got[0]));
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P10: the P9 shape with the PORT's emu_start arguments — until =
// 0xffffffffffffffff (the port's thread-slice exit_point) and the code-hook
// sizes printed. The until changes unicorn's exit/translate path; the taken
// path's hook size at the store tells whether the until=MAX shape mis-decodes
// the taken entry.
TEST(TbSemantics, DISABLED_P10UntilMaxTakenEntry) {
    Probe p;
    p.stop_in_hook = false;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);

    p.stop_in_hook = false;
    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(probe_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // phase 1: the parent (rax=2001) — runs to the second syscall's stop
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);
    p.code_trace.clear();
    p.code_count = 0;

    // phase 2: the child restart at +0x02 (rax=0) — the PORT's argument shape
    const std::uint64_t zero = 0;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p10-phase2", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p10-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p10-store] %u\n", static_cast<unsigned>(got[0]));
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P11: the P10 shape plus the port's clone-handler RIP write inside the
// syscall INSN hook (the parent-compensation: set RIP = the syscall address
// so the post-hook +size re-add lands the parent on the continuation). The
// RIP write inside the hook is the one remaining port-side variable; if the
// child's taken-path entry at the store then mis-decodes (size=2, the
// mid-instruction walk) the clone fault reproduces raw.
static uc_engine* p11_uc = nullptr;
static void p11_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        // the clone shape: the handler writes RIP back to the syscall address
        // (the -2 compensation) INSIDE the hook; the post-hook re-add lands
        // the parent at the continuation
        uc_reg_write(uc, UC_X86_REG_RIP, &pc);
    } else {
        // the futex-park shape: the second syscall stops the parent pass
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P11HookRipWriteCachedTb) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p11_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // phase 1: the parent (rax=2001) — the clone hook writes RIP=+0x00 inside
    // the hook (the port's compensation), the TB continues to the park
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);
    p.code_trace.clear();
    p.code_count = 0;

    // phase 2: the child restart at +0x02 (rax=0) — the taken path
    const std::uint64_t zero = 0;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p11-phase2", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p11-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p11-store] %u\n", static_cast<unsigned>(got[0]));
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P12: the P11 shape plus the port's full uc_context_save/restore switch.
// The port's thread switch snapshots the parent with uc_context_save INSIDE
// the INSN hook (after the clone handler) and uc_context_restores the child
// before its slice — a mechanism the earlier probes never exercised. If the
// child's taken-path entry at the store mis-decodes (the size=2 hook event,
// the mid-instruction walk) the clone fault reproduces raw.
static uc_context* p12_child_ctx = nullptr;
static void p12_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        // the clone shape: the child's context snapshots (rax=0, the pc at
        // the continuation), then the parent's RIP compensation inside the
        // hook (the -2 + the re-add = the continuation)
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_context_alloc(uc, &p12_child_ctx);
        uc_context_save(uc, p12_child_ctx);  // the child's pc = the continuation
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        uc_reg_write(uc, UC_X86_REG_RIP, &pc);  // the -2 compensation
    } else {
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P12ContextSwitchTakenEntry) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p12_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // the parent's pass: the clone hook (the child ctx snapshot + the RIP
    // compensation) then the park at the second syscall
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);
    p.code_trace.clear();
    p.code_count = 0;

    // the child's slice: the context restore (rax=0, the pc at the
    // continuation) then emu_start at the continuation pc
    uc_context_restore(p.uc, p12_child_ctx);
    const std::uint64_t child_sp = 0x1203000;
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p12-phase2", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p12-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p12-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(p12_child_ctx);
    p12_child_ctx = nullptr;
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P13: the P12 shape plus the port's emu_stop INSIDE the clone hook (the
// port's handler stops the parent's pass right after the child snapshot —
// P12 let the parent continue to the second syscall). The child's slice then
// starts from a ctx saved inside a hook that ended its own emu_start.
static uc_context* p13_child_ctx = nullptr;
static void p13_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        // the port's clone shape: the child ctx (rax=0, the pc at the
        // continuation = the post-advance position), then the parent's RIP
        // compensation, then the stop INSIDE the hook
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_context_alloc(uc, &p13_child_ctx);
        uc_context_save(uc, p13_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        const std::uint64_t syscall_pc = kBase;  // the -2 compensation target
        uc_reg_write(uc, UC_X86_REG_RIP, &syscall_pc);
        uc_emu_stop(uc);
    } else {
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P13StopInCloneHook) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p13_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // the parent's pass: the clone hook stops it inside the hook
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);
    p.code_trace.clear();
    p.code_count = 0;

    // the child's slice: the ctx restore (rax=0, the pc at the continuation)
    // then emu_start at the continuation pc
    uc_context_restore(p.uc, p13_child_ctx);
    const std::uint64_t child_sp = 0x1203000;
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p13-phase2", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p13-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p13-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(p13_child_ctx);
    p13_child_ctx = nullptr;
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P14: the port's EXACT three-slice sequence — the shape P5's model missed:
// the TB at the restart address is created by an emu_start that ends via an
// INSN-hook stop INSIDE that TB (the port's parent slice 2: emu_start(+0x02)
// ran the not-taken loop and parked at the futex syscall inside the TB), and
// the child then re-enters the CACHED TB. P5's phase-2 ended via the count
// cap; P13's parent pass never entered +0x02. The hypothesis: the INSN-stop
// exit from the TB is what mis-pairs the hook sizes on the re-entry.
//   slice 1: emu_start(0x00) — the clone hook (the child ctx, the -2
//            compensation, the stop) — P13's shape
//   slice 2: emu_start(+0x02) rax=2001 — the not-taken loop to the +0x09
//            syscall whose INSN hook uc_emu_stops (the park INSIDE the TB)
//   slice 3: emu_start(+0x02) rax=0 — the CACHED TB — the jz TAKEN → the
//            store — the hook event's size at the store tells
static uc_context* p14_child_ctx = nullptr;
static void p14_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        // the clone hook: the child ctx (rax=0, the pc at the continuation),
        // the parent's -2 compensation, the stop inside the hook
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_context_alloc(uc, &p14_child_ctx);
        uc_context_save(uc, p14_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        const std::uint64_t syscall_pc = kBase;
        uc_reg_write(uc, UC_X86_REG_RIP, &syscall_pc);
        uc_emu_stop(uc);
    } else {
        // the futex-park hook: the stop inside the +0x02 TB
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P14InsnStopExitThenCachedReentry) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',                      // +0x00 syscall (the clone)
        '\x48', '\x85', '\xC0',              // +0x02 test rax, rax
        '\x74', '\x07',                      // +0x05 jz +7 (to +0x0e)
        '\x90', '\x90', '\x90',              // +0x07 nops (the parent path)
        '\x0F', '\x05',                      // +0x0a syscall (the park)
        '\x90', '\x90',                      // +0x0c nops
        '\x90', '\x90',                      // +0x0e pad to the store
        '\x90', '\x90',
        '\x90', '\x90',
        '\x90', '\x90',
        '\x90', '\x90',
        '\x90', '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',  // +0x1a store
        '\xEB', '\xFE'};                     // +0x25 jmp $
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p14_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // slice 1: the parent — the clone hook stops inside the hook
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);

    // slice 2: the parent again — emu_start(+0x02), the not-taken path, the
    // park at the +0x0a syscall INSIDE the +0x02 TB
    uc_context_restore(p.uc, p14_child_ctx);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    const auto pc2 = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p14-slice2-end] pc=0x%llx\n", static_cast<unsigned long long>(pc2));

    // slice 3: the child — the restored ctx (rax=0) re-enters the CACHED TB
    uc_context_restore(p.uc, p14_child_ctx);
    const std::uint64_t child_sp = 0x1203000;
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    p.code_trace.clear();
    p.code_count = 0;
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p14-slice3", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p14-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p14-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(p14_child_ctx);
    p14_child_ctx = nullptr;
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P15: the P13 shape plus the port's EXACT child-ctx save order — the port's
// clone handler sets the child's pc/sp via set_arch_pc/set_arch_sp INSIDE the
// INSN hook and THEN calls th->save() (uc_context_save) — so the snapshot
// carries the hook-modified internal state (any pending post-advance). P13's
// ctx was saved with the pc untouched. The hypothesis: the ctx captured
// inside the hook, after an in-hook pc write, replays a pending-advance
// state that mis-pairs the next taken-exit's size (+2 at the store).
//   clone hook: rax=0, set pc=+0x02, set sp, uc_context_save, the parent's
//               -2 RIP compensation, the stop
//   slice 2:    the parent emu_start(+0x02), the park at the +0x0a syscall
//   slice 3:    the child: uc_context_restore(child ctx) + emu_start(+0x02)
static uc_context* p15_child_ctx = nullptr;
static void p15_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        const std::uint64_t child_pc = kBase + 2;   // the port's set_arch_pc
        uc_reg_write(uc, UC_X86_REG_RIP, &child_pc);
        const std::uint64_t child_sp = 0x1203000;
        uc_reg_write(uc, UC_X86_REG_RSP, &child_sp);  // the port's set_arch_sp
        uc_context_alloc(uc, &p15_child_ctx);
        uc_context_save(uc, p15_child_ctx);           // the snapshot AFTER the
                                                      // in-hook pc/sp writes
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        const std::uint64_t syscall_pc = kBase;
        uc_reg_write(uc, UC_X86_REG_RIP, &syscall_pc);  // the -2 compensation
        uc_emu_stop(uc);
    } else {
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P15CtxSavedAfterInHookPcWrite) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p15_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // slice 1: the parent — the clone hook (the child ctx saved AFTER the
    // in-hook pc/sp writes) + the stop
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);

    // slice 2: the parent — emu_start(+0x02), the not-taken loop, the park
    // at the +0x0a syscall INSIDE the +0x02 TB
    uc_context_restore(p.uc, p15_child_ctx);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    const auto pc2 = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p15-slice2-end] pc=0x%llx\n", static_cast<unsigned long long>(pc2));

    // slice 3: the child — the ctx restore + emu_start at the continuation
    uc_context_restore(p.uc, p15_child_ctx);
    p.code_trace.clear();
    p.code_count = 0;
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p15-slice3", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p15-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p15-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(p15_child_ctx);
    p15_child_ctx = nullptr;
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// P16: the P15 shape plus the port's IN-HOOK GUEST-MEMORY ACCESS — the
// port's clone handler performs the CHILD_SETTID write (a uc_mem_write of
// the tid into the ctid word) INSIDE the INSN callback, and the futex park
// reads the ctid word INSIDE its callback. A mem access inside an INSN
// callback is the one operation class the earlier probes never exercised;
// if it corrupts the cached-TB state, the re-entry mis-pairs (the +2 at the
// store).
static uc_context* p16_child_ctx = nullptr;
static std::uint64_t p16_ctid = 0x1002000;  // the ctid word (the mapped page)
static void p16_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        const std::uint64_t child_pc = kBase + 2;
        uc_reg_write(uc, UC_X86_REG_RIP, &child_pc);
        const std::uint64_t child_sp = 0x1203000;
        uc_reg_write(uc, UC_X86_REG_RSP, &child_sp);
        // the port's CHILD_SETTID: the tid write INSIDE the hook
        const std::uint64_t tid = 0x2a;
        uc_mem_write(uc, p16_ctid, &tid, sizeof(tid));
        uc_context_alloc(uc, &p16_child_ctx);
        uc_context_save(uc, p16_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        const std::uint64_t syscall_pc = kBase;
        uc_reg_write(uc, UC_X86_REG_RIP, &syscall_pc);
        uc_emu_stop(uc);
    } else {
        // the futex park: the ctid read INSIDE the hook (the port's futex
        // wait reads the expected value)
        std::uint64_t v = 0;
        uc_mem_read(uc, p16_ctid, &v, sizeof(v));
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P16InHookMemAccess) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p16_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 1, 0);

    // slice 1: the parent — the clone hook with the in-hook mem write + the stop
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 4096);

    // slice 2: the parent — the not-taken loop, the park at +0x0a with the
    // in-hook mem read
    uc_context_restore(p.uc, p16_child_ctx);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    const auto pc2 = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p16-slice2-end] pc=0x%llx\n", static_cast<unsigned long long>(pc2));

    // slice 3: the child — the cached TB, the taken path to the store
    uc_context_restore(p.uc, p16_child_ctx);
    p.code_trace.clear();
    p.code_count = 0;
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, 0xffffffffffffffffull, 0, 4096);
    probe_dump_trace("p16-slice3", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p16-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p16-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(p16_child_ctx);
    p16_child_ctx = nullptr;
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}

// the raw-unicorn 16-bit INTR probe: int 0x21 in real mode with a UC_HOOK_INTR
// handler — pins whether the 16-bit int + hook combination is emulatable at
// the raw level (the dos fixture rides the same path)
static void probe16_intr_hook(uc_engine* uc, std::uint32_t intno, void* user_data) {
    (void)intno;
    (void)user_data;
    // emulate the leaf: read AH, stop when 0x4c
    std::uint16_t ah = 0;
    std::uint32_t tmp = 0;
    uc_reg_read(uc, UC_X86_REG_AH, &tmp);
    ah = static_cast<std::uint16_t>(tmp);
    if (ah == 0x4c) {
        uc_emu_stop(uc);
    }
}

// P18: the P16 shape with ONLY the code hook's registration range changed -
// the port's test tracer rides UC_HOOK_CODE as a RANGED hook (begin=0,
// end=0xffffffffffff, the facade hook_code(cb, 0, huge) shape) while every
// raw probe used the global sentinel (begin=1, end=0). Unicorn generates
// different TB instrumentation for ranged vs global code hooks; if the
// ranged registration reproduces the port's taken-entry size-lag (the store
// event firing with the jz's size and the pc walking into the store), the
// port-side fix is the facade's default hook range.
static uc_context* p18_child_ctx = nullptr;
static void p18_syscall_hook(uc_engine* uc, void* user_data) {
    auto* self = static_cast<Probe*>(user_data);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    self->syscall_fired.push_back(pc);
    if (pc == kBase) {
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        const std::uint64_t child_pc = kBase + 2;
        uc_reg_write(uc, UC_X86_REG_RIP, &child_pc);
        const std::uint64_t child_sp = 0x1203000;
        uc_reg_write(uc, UC_X86_REG_RSP, &child_sp);
        const std::uint64_t tid = 0x2a;
        uc_mem_write(uc, p16_ctid, &tid, sizeof(tid));
        uc_context_alloc(uc, &p18_child_ctx);
        uc_context_save(uc, p18_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        const std::uint64_t syscall_pc = kBase;
        uc_reg_write(uc, UC_X86_REG_RIP, &syscall_pc);
        uc_emu_stop(uc);
    } else {
        std::uint64_t v = 0;
        uc_mem_read(uc, p16_ctid, &v, sizeof(v));
        uc_emu_stop(uc);
    }
}

TEST(TbSemantics, DISABLED_P18RangedCodeHookTakenEntry) {
    Probe p;
    uc_open(UC_ARCH_X86, UC_MODE_64, &p.uc);
    uc_mem_map(p.uc, kBase, 0x1000, UC_PROT_ALL);

    std::string body{
        '\x0F', '\x05',
        '\x48', '\x85', '\xC0',
        '\x74', '\x07',
        '\x90', '\x90', '\x90',
        '\x0F', '\x05',
        '\x90', '\x90',
        '\x90',
        '\xC7', '\x04', '\x25', '\x00', '\x20', '\x00', '\x01', '\x2A', '\x00', '\x00', '\x00',
        '\xEB', '\xFE'};
    uc_mem_write(p.uc, kBase, body.data(), body.size());
    uc_mem_map(p.uc, 0x1002000, 0x1000, UC_PROT_ALL);
    uc_mem_map(p.uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook_add(p.uc, &p.insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p18_syscall_hook), &p, 1, 0,
                UC_X86_INS_SYSCALL);
    // THE P18 DELTA: the code hook registered RANGED (begin=0, end=huge) —
    // the port's facade hook_code(cb, 0, 0xffffffffffff) shape — not the
    // global sentinel the earlier probes used
    uc_hook_add(p.uc, &p.code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(probe_code_hook), &p, 0,
                0xffffffffffffull);

    // the port's three-slice interleave (the P16 sequence verbatim)
    const std::uint64_t parent_rax = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax);
    uc_emu_start(p.uc, kBase, 0xffffffffffffffffull, 0, 32337);

    uc_context_restore(p.uc, p18_child_ctx);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(p.uc, kBase + 2, 0xffffffffffffffffull, 0, 32337);

    uc_context_restore(p.uc, p18_child_ctx);
    p.code_trace.clear();
    p.code_count = 0;
    const uc_err err = uc_emu_start(p.uc, kBase + 2, 0xffffffffffffffffull, 0, 32337);
    probe_dump_trace("p18-child", p.code_trace);
    const auto pc = reg(p.uc, UC_X86_REG_RIP);
    std::fprintf(stderr, "[p18-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[p18-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(p18_child_ctx);
    p18_child_ctx = nullptr;
}

TEST(TbSemantics, DISABLED_RealModeIntHookRawProbe) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_16, &uc), UC_ERR_OK);

    // map the low megabyte; the blob rides at 0x76a0 (the cs=0x75a, ip=0x100
    // profile entry)
    ASSERT_EQ(uc_mem_map(uc, 0, 0x100000, UC_PROT_ALL), UC_ERR_OK);

    const std::vector<std::uint8_t> blob = {0xB4, 0x4C, 0xCD, 0x21};  // mov ah,4c | int 21h
    const std::uint64_t base = 0x76a0;
    uc_mem_write(uc, base, blob.data(), blob.size());

    std::uint32_t cs = 0x75a, ds = 0x75a, es = 0x75a, ss = 0x75a, ip = 0x100, sp = 0xfffe;
    uc_reg_write(uc, UC_X86_REG_CS, &cs);
    uc_reg_write(uc, UC_X86_REG_DS, &ds);
    uc_reg_write(uc, UC_X86_REG_ES, &es);
    uc_reg_write(uc, UC_X86_REG_SS, &ss);
    uc_reg_write(uc, UC_X86_REG_IP, &ip);
    uc_reg_write(uc, UC_X86_REG_SP, &sp);

    uc_hook intr_hook = 0;
    ASSERT_EQ(uc_hook_add(uc, &intr_hook, UC_HOOK_INTR, reinterpret_cast<void*>(probe16_intr_hook), nullptr, 1, 0),
              UC_ERR_OK);

    const uc_err err = uc_emu_start(uc, base, 0, 0, 0);
    EXPECT_EQ(err, UC_ERR_OK) << "uc_strerror: " << uc_strerror(err);

    uc_close(uc);
}
