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
    (void)size;
    ++self->code_count;
    self->code_trace.push_back(address);
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
// taken-path store after the cached-TB mid-TB restart does not land — the
// unicorn re-enters the cached TB in a state that mis-executes the branch.
// DISABLED_: the behavior is the documented open question (STATUS.md); the
// fix directions are the fresh-TB starts for the spawned threads or the tb
// cache flush on the spawn.
TEST(TbSemantics, DISABLED_MidTbRestartOnCachedTb) {
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

    // the parent pass: the syscall stops the slice (the cached TB from 0x0)
    uc_emu_start(p.uc, kBase, kBodyEnd, 0, 0);

    // the parent's second slice: the mid-TB restart at the syscall+2 — this
    // pass CACHES the TB starting at the syscall+2 (the not-taken path)
    const std::uint64_t child_tid = 2001;
    uc_reg_write(p.uc, UC_X86_REG_RAX, &child_tid);
    const uc_err err2 = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    std::fprintf(stderr, "[P5] phase2 err=%d pc=%llx\n", err2, (unsigned long long)reg(p.uc, UC_X86_REG_RIP));
    (void)err2;

    // the child pass: the SAME begin address (the cached TB), the rax=0
    const std::uint64_t zero = 0;
    const std::uint64_t child_sp = 0x1203000;
    uc_mem_map(p.uc, child_sp - 0x1000, 0x1000, UC_PROT_ALL);
    uc_reg_write(p.uc, UC_X86_REG_RAX, &zero);
    uc_reg_write(p.uc, UC_X86_REG_RSP, &child_sp);
    const uc_err err = uc_emu_start(p.uc, kSyscall + 2, kBodyEnd, 0, 4096);
    std::fprintf(stderr, "[P5] phase3 err=%d pc=%llx\n", err, (unsigned long long)reg(p.uc, UC_X86_REG_RIP));

    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(p.uc, 0x1002000, got.data(), 4);
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(got[0], 42);
}
