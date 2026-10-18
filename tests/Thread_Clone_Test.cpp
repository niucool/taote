// The clone/clone3 slice (os/posix/syscall/sched.py) - the CLONE_VM thread
// spawn through the management, the CHILD_SETTID/CHILD_CLEARTID handling and
// the futex-based join. The non-CLONE_VM fork path is a documented deviation
// (the upstream windows Process() placeholder constructs the multiprocessing
// object without ever starting it and runs the child code in the caller's
// greenlet; the port surfaces it as not-implemented).
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <vector>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "qiling/core.hpp"
#include "qiling/os/linux/linux.hpp"
#include "qiling/os/linux/thread.hpp"

using namespace qiling;

namespace {

// sched.py: the clone flag constants
constexpr std::uint64_t CLONE_VM = 0x00000100;
constexpr std::uint64_t CLONE_FS = 0x00000200;
constexpr std::uint64_t CLONE_FILES = 0x00000400;
constexpr std::uint64_t CLONE_SIGHAND = 0x00000800;
constexpr std::uint64_t CLONE_THREAD = 0x00010000;
constexpr std::uint64_t CLONE_CHILD_SETTID = 0x01000000;
constexpr std::uint64_t CLONE_CHILD_CLEARTID = 0x00200000;

constexpr std::uint64_t kXaddr = 0x1002000;    // the futex/ctid word
constexpr std::uint64_t kChildStack = 0x1203000;

// the shared body: the clone + the join flow. The parent (rax != 0) waits on
// the ctid futex word (the value read fresh each round, the glibc
// lll_wait_tid shape); the child (rax == 0) stores 42, wakes the futex and
// exits - its _on_stop zeroes the ctid and wakes the parent.
//
//   00: 48 C7 C7 xx*4        mov rdi, FLAGS
//   07: 48 C7 C6 xx*4        mov rsi, CHILD_STACK
//   0E: 31 D2                xor edx, edx
//   10: 49 C7 C2 xx*4        mov r10, CTID
//   17: 45 31 C0             xor r8d, r8d
//   1A: 48 C7 C0 38 00 00 00 mov rax, 56 (clone)
//   21: 0F 05                syscall
//   23: 48 85 C0             test rax, rax
//   26: 74 10                jz child_path (to 0x38)
//   -- parent_wait (0x28):
//   28: 44 8B 0C 25 00 20 00 01   mov r9d, [X]        (the ctid value)
//   30: 45 85 C9                  test r9d, r9d
//   33: 74 0F                     jz parent_done (to 0x44)
//   35: 48 C7 C7 00 20 00 01      mov rdi, X
//   3C: 31 F6                     xor esi, esi        (FUTEX_WAIT)
//   3E: 4C 89 CA                  mov rdx, r9         (the expected value)
//   41: 45 31 D2                  xor r10d, r10d
//   44: 48 C7 C0 CA 00 00 00      mov rax, 202 (futex)
//   4B: 0F 05                     syscall
//   4D: 48 85 C0                  test rax, rax
//   50: 74 08                     jz parent_done (to 0x5A)
//   52: EB D4                     jmp parent_wait (to 0x28)
//   54: 90 90 90 90               (the alignment pad)
//   -- parent_done (0x58):
//   58: 48 C7 C0 E7 00 00 00      mov rax, 231 (exit_group)
//   5F: 48 C7 C7 2A 00 00 00      mov rdi, 42
//   66: 0F 05                     syscall
//   -- child_path (0x68):
//   68: 48 C7 C0 3C 00 00 00      mov rax, 60 (exit)
//   6F: 48 C7 C7 00 00 00 00      mov rdi, 0
//   76: 0F 05                     syscall
//   78: EB FE                     jmp $   (the TB pad)
const std::vector<std::uint8_t>& join_body() {
    static const std::vector<std::uint8_t> code = {
        //   00: mov rdi, FLAGS ; 07: mov rsi, CHILD_STACK ; 0E: xor edx, edx
        //   10: mov r10, CTID ; 17: xor r8d, r8d ; 1A: mov rax, 56 (clone)
        //   21: syscall ; 23: test rax, rax ; 26: jz child (0x67)
        //   28: parent_wait: the join loop (the glibc lll_wait_tid shape)
        //   55: parent_done: exit_group(42)  --  67: child: store 42, wake, exit
        0x48, 0xC7, 0xC7, 0x00, 0x01, 0x21, 0x01,          // 00: mov rdi, FLAGS
        0x48, 0xC7, 0xC6, 0x00, 0x30, 0x20, 0x01,          // 07: mov rsi, CHILD_STACK
        0x31, 0xD2,                                         // 0E: xor edx, edx
        0x49, 0xC7, 0xC2, 0x00, 0x20, 0x00, 0x01,          // 10: mov r10, CTID
        0x45, 0x31, 0xC0,                                   // 17: xor r8d, r8d
        0x48, 0xC7, 0xC0, 0x38, 0x00, 0x00, 0x00,          // 1A: mov rax, 56 (clone)
        0x0F, 0x05,                                         // 21: syscall
        0x48, 0x85, 0xC0,                                   // 23: test rax, rax
        0x74, 0x3F,                                         // 26: jz +0x3f -> child (0x67)
        // parent_wait (0x28):
        0x44, 0x8B, 0x0C, 0x25, 0x00, 0x20, 0x00, 0x01,    // 28: mov r9d, [X] (the ctid value)
        0x45, 0x85, 0xC9,                                   // 30: test r9d, r9d
        0x74, 0x20,                                         // 33: jz +0x20 -> parent_done (0x55)
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,          // 36: mov rdi, X
        0x31, 0xF6,                                         // 3D: xor esi, esi (FUTEX_WAIT)
        0x4C, 0x89, 0xCA,                                   // 3F: mov rdx, r9 (the expected value)
        0x45, 0x31, 0xD2,                                   // 42: xor r10d, r10d
        0x48, 0xC7, 0xC0, 0xCA, 0x00, 0x00, 0x00,          // 45: mov rax, 202 (futex)
        0x0F, 0x05,                                         // 4C: syscall
        0x48, 0x85, 0xC0,                                   // 4E: test rax, rax
        0xEB, 0xD6,                                         // 50: jmp parent_wait (0x28)
                                                                    // (both the EAGAIN and the woken
                                                                    //  paths re-check the ctid - the
                                                                    //  glibc join shape)
        0x90, 0x90, 0x90,                                   // 52: (the alignment pads; the
                                                            //  3rd lands parent_done at 0x55
                                                            //  and the store at 0x67)
        // parent_done (0x55):
        0x48, 0xC7, 0xC0, 0xE7, 0x00, 0x00, 0x00,          // 56: mov rax, 231 (exit_group)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // 5D: mov rdi, 42
        0x0F, 0x05,                                         // 64: syscall
        0xEB, 0xFE,                                         // 66: jmp $ (the TB pad)
        // child_path (0x67):
        0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01, 0x2A, 0x00, 0x00, 0x00,
                                                            // 67: mov dword [0x1002000], 42
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,          // 72: mov rdi, 0x1002000
        0xBE, 0x01, 0x00, 0x00, 0x00,                       // 79: mov esi, 1 (FUTEX_WAKE)
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,          // 7E: mov rdx, 1 (the count)
        0x48, 0xC7, 0xC0, 0xCA, 0x00, 0x00, 0x00,          // 85: mov rax, 202 (futex)
        0x0F, 0x05,                                         // 8C: syscall
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,          // 8E: mov rax, 60 (exit)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,          // 95: mov rdi, 0
        0x0F, 0x05,                                         // 9C: syscall
        0xEB, 0xFE,                                         // 9E: jmp $ (the TB pad)
    };
    return code;
}



}  // namespace

// the clone(CLONE_VM...) spawn: the child takes the clone-continuation pc,
// stores 42, wakes the futex and exits; its _on_stop zeroes the ctid word
// and wakes the futex waiter (the parent); the parent's join loop observes
// the zero and exits with 42
// RESOLVED (the (b13) delta bisect, superseding the whole misfire study): the
// long-standing "taken-exit code-hook mis-fire" (the taken-entry UC_HOOK_CODE
// firing size=2 at the store, the pc walking mid-instruction into
// UC_ERR_READ_UNMAPPED) was NEVER an engine behavior - the join blob's child
// jz (0x74 0x3f at 0x26) targeted 0x67 while the 11-byte store sat at 0x66
// (the parent-path instructions were one byte shorter than the comment's
// claimed offsets), so the child's taken jump landed one byte INTO the store
// and executed the misaligned bytes; unicorn was faithfully executing what
// was written. The same arithmetic error had propagated into the (b12)/(b12b)
// ladder probes (their pad rows fell short of the claimed 0x4d store offset),
// which manufactured the misleading "C++ misfires / python is clean"
// divergence and the candidate-upstream-issue trail. With every blob's pad
// rows mechanically aligned to the jz targets, all the ladder probes (b10,
// b11, b12, b12b) run CLEAN (the taken-entry fires size=11, the store lands
// 42) and this test is re-enabled and passes. The lesson (the fixture
// discipline): every hand-built blob's store offset must be verified
// mechanically against its jz displacement before a probe run is trusted.
TEST(ThreadClone, CloneSpawnsChildAndJoinWakes) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_clone_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.code = join_body();
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    options.multithread = true;
    Qiling ql(options);

    // the ctid word starts at the tid value the CHILD_SETTID will write;
    // pre-store a non-zero sentinel so the join loop's first read differs
    ql.mem().write_ptr(kXaddr, 0xdeadbeef, 4);

    // TEMPORARY DIAGNOSTIC: the code tracer riding the x8664 hook_code path;
    // the HookRet stays alive for the run (the RAII handle unregisters on
    // destruction — the pinned facade gotcha)
    static thread_local std::vector<std::uint64_t> trace;
    trace.clear();
    const auto tracer = ql.hook_code([](std::uint64_t address, std::uint32_t size) -> int {
        trace.push_back(address);
        std::fprintf(stderr, "[ctrace] 0x%llx size=%u\n", static_cast<unsigned long long>(address), size);
        if (trace.size() > 400) {
            return 1;  // the stop
        }
        return 0;
    }, 0, 0xffffffffffffull);
    (void)tracer;

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);

    // the ctid word was zeroed by the child's _on_stop
    EXPECT_EQ(ql.mem().read_ptr(kXaddr, 4), 0);
}

// ---- the (b8) raw-engine bisect probe: the port's own engine and mappings
// (ql.arch().uc() + the blob the failing fixture loads), driven entirely with
// plain uc_* calls — the (b6b) minimal dispatcher restored to the full
// three-slice interleave (the clone's hook does the child-ctx dance + the
// compensation + the stop, the futex's hook parks, the slices ride
// uc_emu_start/uc_context_restore). No QlLinuxThread, no management, no
// facade hooks, no install_syscall_hooks. If the misfire reproduces here,
// the delta lives in the port's engine/mappings (NOT the management); if it
// stays clean while the port's run misfires, the delta is in the management
// or the slice machinery — instrument run_ready next.
static uc_context* r9_child_ctx = nullptr;
static int r9_count = 0;
static void r9_code_cb(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    (void)user_data;
    ++r9_count;
    std::fprintf(stderr, "[r9e] 0x%llx size=%u\n", static_cast<unsigned long long>(address), size);
    if (r9_count > 400) {
        uc_emu_stop(uc);
    }
}
static void r9_insn_cb(uc_engine* uc, void* user_data) {
    (void)user_data;
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    std::fprintf(stderr, "[r9-insn] pc=%llx rax=%llx\n", static_cast<unsigned long long>(pc),
                 static_cast<unsigned long long>(rax));
    if (rax == 56) {
        // the minimal clone dispatcher: the child's regs (rax=0, rip=after,
        // rsp=child), the child's ctx saved from the mutated state, the
        // parent's rax, the compensation (the syscall's pc), the stop
        const std::uint64_t after = pc + 2;
        const std::uint64_t zero = 0;
        const std::uint64_t child_sp = 0x1203000;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_reg_write(uc, UC_X86_REG_RIP, &after);
        uc_reg_write(uc, UC_X86_REG_RSP, &child_sp);
        uc_context_alloc(uc, &r9_child_ctx);
        uc_context_save(uc, r9_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        uc_reg_write(uc, UC_X86_REG_RIP, &pc);
        uc_emu_stop(uc);
    } else {
        // the futex park: the in-hook read + the stop + the return value
        std::uint64_t v = 0;
        uc_mem_read(uc, 0x1002000, &v, sizeof(v));
        uc_emu_stop(uc);
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
    }
}

TEST(ThreadClone, DISABLED_BisectRawEngineInterleave) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_clone_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.code = join_body();
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    options.multithread = true;
    Qiling ql(options);  // the port's engine + the mappings — never run()

    ql.mem().write_ptr(kXaddr, 0xdeadbeef, 4);

    uc_engine* uc = &ql.arch().uc();
    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(r9_insn_cb), nullptr, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(r9_code_cb), nullptr, 1, 0);

    // slice1: the parent's setup + the clone (the hook parks the parent's slice)
    const std::uint64_t rsp = 0x1203000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_emu_start(uc, 0x11ff000, 0xffffffffffffffffull, 0, 32337);

    // slice2: the parent's resume — the not-taken loop, the futex park
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(uc, 0x11ff023, 0xffffffffffffffffull, 0, 32337);

    // slice3: the child — the cached TB at 0x23, the taken jz, the store
    r9_count = 0;
    uc_context_restore(uc, r9_child_ctx);
    const uc_err err = uc_emu_start(uc, 0x11ff023, 0xffffffffffffffffull, 0, 32337);
    const auto pc = [&uc] {
        std::uint64_t v = 0;
        uc_reg_read(uc, UC_X86_REG_RIP, &v);
        return v;
    }();
    std::fprintf(stderr, "[r9-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[r9-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(r9_child_ctx);
    r9_child_ctx = nullptr;
}


// ---- the (b9) standalone-harness bisect: the P19 harness (a fresh uc_open
// + the hand mappings) running the PORT'S OWN join blob. If the misfire
// reproduces here, the trigger is the blob shape itself (the taken-entry
// into the 11-byte store) — a raw-unicorn behavior the port must handle;
// if it stays clean, the delta is in the port's engine state (the loader's
// mappings/permissions) — bisect the mapping details next.
// ---- the (b10) minimal-blob bisect: the standalone harness + a MINIMAL
// join-shaped blob — the clone's syscall, the test, the jz TAKEN DIRECTLY
// into the 11-byte store (no nop padding at the taken target, unlike the
// P19 blob whose taken target was a 1-byte nop and fired CLEAN). If this
// misfires, the trigger is the taken-entry-into-the-multi-byte-instruction
// shape itself — a raw-unicorn behavior the port's blob authoring (and any
// guest code shaped like it) must account for.
static void r9b_body(uc_engine* uc) {
    // slice1: the parent's setup + the clone
    const std::uint64_t rsp = 0x1203000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_emu_start(uc, 0x11ff000, 0xffffffffffffffffull, 0, 32337);
    // slice2: the parent's resume — the not-taken loop, the futex park
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(uc, 0x11ff023, 0xffffffffffffffffull, 0, 32337);
    // slice3: the child — the cached TB at 0x23, the taken jz, the store
    r9_count = 0;
    uc_context_restore(uc, r9_child_ctx);
    const uc_err err = uc_emu_start(uc, 0x11ff023, 0xffffffffffffffffull, 0, 32337);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::fprintf(stderr, "[r9b-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[r9b-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(r9_child_ctx);
    r9_child_ctx = nullptr;
}

TEST(ThreadClone, DISABLED_BisectStandaloneHarnessPortBlob) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    uc_mem_map(uc, 0x11ff000, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, 0x11ff000, join_body().data(), join_body().size());
    uc_mem_map(uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint32_t sentinel = 0xdeadbeef;
    uc_mem_write(uc, 0x1002000, &sentinel, sizeof(sentinel));
    uc_mem_map(uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(r9_insn_cb), nullptr, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(r9_code_cb), nullptr, 1, 0);

    r9b_body(uc);
    uc_close(uc);
}


TEST(ThreadClone, DISABLED_BisectMinimalTakenEntryStore) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    uc_mem_map(uc, 0x11ff000, 0x1000, UC_PROT_ALL);
    // the minimal join shape: the clone's syscall, the test, the jz TAKEN
    // directly into the 11-byte store (the taken target = the store itself)
    const std::vector<std::uint8_t> blob = {
        0x48, 0xC7, 0xC0, 0x38, 0x00, 0x00, 0x00,          // 00: mov rax, 56
        0x0F, 0x05,                                        // 07: syscall (the clone)
        0x48, 0x85, 0xC0,                                  // 09: test rax, rax
        0x74, 0x07,                                        // 0c: jz +7 -> 0x15 (the store)
        0xB8, 0xCA, 0x00, 0x00, 0x00,                      // 0e: mov eax, 202
        0x0F, 0x05,                                        // 13: syscall (the park)
        0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01, 0x2A, 0x00, 0x00, 0x00,
                                                           // 15: mov dword [0x1002000], 42
        0xEB, 0xFE,                                        // 20: jmp $
    };
    uc_mem_write(uc, 0x11ff000, blob.data(), blob.size());
    uc_mem_map(uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint32_t sentinel = 0xdeadbeef;
    uc_mem_write(uc, 0x1002000, &sentinel, sizeof(sentinel));
    uc_mem_map(uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(r9_insn_cb), nullptr, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(r9_code_cb), nullptr, 1, 0);

    // slice1: the parent's setup + the clone
    const std::uint64_t rsp = 0x1203000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_emu_start(uc, 0x11ff000, 0xffffffffffffffffull, 0, 32337);
    // slice2: the parent's resume at the post-clone continuation (0x09) —
    // the test (rax=2001, not taken), the futex park
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    // slice3: the child — the test (rax=0), the jz TAKEN, the store at 0x15
    r9_count = 0;
    uc_context_restore(uc, r9_child_ctx);
    const uc_err err = uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::fprintf(stderr, "[r9b-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[r9b-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(r9_child_ctx);
    r9_child_ctx = nullptr;
    uc_close(uc);
}

// ---- the (b11) ladder rung 1: the b10 blob + the parent's LOOP TRAVERSAL —
// the parent's path gains the loop stub (the mov r9d [X] / the test r9d /
// the jz-to-continue) between the jcc and the park, so the parent's slice2
// traverses a longer TB with the loop body before parking. ONE feature over
// the clean b10.
static uc_context* r9b_child_ctx = nullptr;
static int r9b_count = 0;
static void r9b_code_cb(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    (void)user_data;
    (void)address;
    (void)size;
    ++r9b_count;
}
static void r9b_insn_cb(uc_engine* uc, void* user_data) {
    (void)user_data;
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    if (rax == 56) {
        const std::uint64_t after = pc + 2;
        const std::uint64_t zero = 0;
        const std::uint64_t child_sp = 0x1203000;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_reg_write(uc, UC_X86_REG_RIP, &after);
        uc_reg_write(uc, UC_X86_REG_RSP, &child_sp);
        uc_context_alloc(uc, &r9b_child_ctx);
        uc_context_save(uc, r9b_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        uc_reg_write(uc, UC_X86_REG_RIP, &pc);
        uc_emu_stop(uc);
    } else {
        std::uint64_t v = 0;
        uc_mem_read(uc, 0x1002000, &v, sizeof(v));
        uc_emu_stop(uc);
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
    }
}
TEST(ThreadClone, DISABLED_BisectRung1LoopTraversal) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    uc_mem_map(uc, 0x11ff000, 0x1000, UC_PROT_ALL);
    const std::vector<std::uint8_t> blob = {
        0x48, 0xC7, 0xC0, 0x38, 0x00, 0x00, 0x00,          // 00: mov rax, 56
        0x0F, 0x05,                                        // 07: syscall (the clone)
        0x48, 0x85, 0xC0,                                  // 09: test rax, rax
        0x74, 0x16,                                        // 0c: jz +0x16 -> 0x24 (the store)
        0x44, 0x8B, 0x0C, 0x25, 0x00, 0x20, 0x00, 0x01,    // 0e: mov r9d, [0x1002000]
        0x45, 0x85, 0xC9,                                  // 16: test r9d, r9d
        0x74, 0x03,                                        // 19: jz +3 -> 0x1e (the syscall)
        0xB8, 0xCA, 0x00, 0x00, 0x00,                      // 1b: mov eax, 202
        0x0F, 0x05,                                        // 20: syscall (the park)
        0xEB, 0xFE,                                        // 22: jmp $
        0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01, 0x2A, 0x00, 0x00, 0x00,
                                                           // 24: mov dword [0x1002000], 42
        0xEB, 0xFE,                                        // 2f: jmp $
    };
    uc_mem_write(uc, 0x11ff000, blob.data(), blob.size());
    uc_mem_map(uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint32_t sentinel = 0xdeadbeef;
    uc_mem_write(uc, 0x1002000, &sentinel, sizeof(sentinel));
    uc_mem_map(uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(r9b_insn_cb), nullptr, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(r9b_code_cb), nullptr, 1, 0);

    const std::uint64_t rsp = 0x1203000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_emu_start(uc, 0x11ff000, 0xffffffffffffffffull, 0, 32337);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    r9b_count = 0;
    uc_context_restore(uc, r9b_child_ctx);
    const uc_err err = uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::fprintf(stderr, "[r9be-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[r9be-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(r9b_child_ctx);
    r9b_child_ctx = nullptr;
    uc_close(uc);
}

// ---- the (b12) ladder rung 2: the b11 blob with the jz's displacement
// STRETCHED to the join blob's 0x3f shape (the taken target far away, the
// parent's path padded to fill). ONE feature over the clean b11.
static void r9b_insn_cb2(uc_engine* uc, void* user_data) {
    (void)user_data;
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    std::fprintf(stderr, "[r9c-insn] pc=%llx rax=%llx\n", static_cast<unsigned long long>(pc),
                 static_cast<unsigned long long>(rax));
    if (rax == 56) {
        const std::uint64_t after = pc + 2;
        const std::uint64_t zero = 0;
        const std::uint64_t child_sp = 0x1203000;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
        uc_reg_write(uc, UC_X86_REG_RIP, &after);
        uc_reg_write(uc, UC_X86_REG_RSP, &child_sp);
        uc_context_alloc(uc, &r9b_child_ctx);
        uc_context_save(uc, r9b_child_ctx);
        const std::uint64_t parent_rax = 2001;
        uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax);
        uc_reg_write(uc, UC_X86_REG_RIP, &pc);
        uc_emu_stop(uc);
    } else {
        std::uint64_t v = 0;
        uc_mem_read(uc, 0x1002000, &v, sizeof(v));
        uc_emu_stop(uc);
        const std::uint64_t zero = 0;
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);
    }
}
TEST(ThreadClone, DISABLED_BisectRung2LongDisplacement) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    uc_mem_map(uc, 0x11ff000, 0x1000, UC_PROT_ALL);
    const std::vector<std::uint8_t> blob = {
        0x48, 0xC7, 0xC0, 0x38, 0x00, 0x00, 0x00,          // 00: mov rax, 56
        0x0F, 0x05,                                        // 07: syscall (the clone)
        0x48, 0x85, 0xC0,                                  // 09: test rax, rax
        0x74, 0x3F,                                        // 0c: jz +0x3f -> 0x4d (the store)
        0x44, 0x8B, 0x0C, 0x25, 0x00, 0x20, 0x00, 0x01,    // 0e: mov r9d, [0x1002000]
        0x45, 0x85, 0xC9,                                  // 16: test r9d, r9d
        0x74, 0x03,                                        // 19: jz +3 -> 0x1e (the syscall)
        0xB8, 0xCA, 0x00, 0x00, 0x00,                      // 1b: mov eax, 202
        0x0F, 0x05,                                        // 20: syscall (the park)
        0xEB, 0xFE,                                        // 22: jmp $
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // 24..: the pad (the store lands at 0x4d)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90,                                                          // 4c
        0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01, 0x2A, 0x00, 0x00, 0x00,
                                                           // 4d: mov dword [0x1002000], 42
        0xEB, 0xFE,                                        // 58: jmp $
    };
    uc_mem_write(uc, 0x11ff000, blob.data(), blob.size());
    uc_mem_map(uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint32_t sentinel = 0xdeadbeef;
    uc_mem_write(uc, 0x1002000, &sentinel, sizeof(sentinel));
    uc_mem_map(uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(r9b_insn_cb2), nullptr, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(r9b_code_cb), nullptr, 1, 0);

    const std::uint64_t rsp = 0x1203000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_emu_start(uc, 0x11ff000, 0xffffffffffffffffull, 0, 32337);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    r9b_count = 0;
    uc_context_restore(uc, r9b_child_ctx);
    const uc_err err = uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::fprintf(stderr, "[r9c-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[r9c-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(r9b_child_ctx);
    r9b_child_ctx = nullptr;
    uc_close(uc);
}


// ---- the (b12b) rung 2 narrowing: the b12 blob MINUS the loop stub — the
// parent's path = just the futex setup + the park, the jz still carries the
// 0x3f displacement. Isolates whether the long displacement alone triggers
// the misfire (vs the loop traversal it replaced).
TEST(ThreadClone, DISABLED_BisectRung2bNoStubLongDisp) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    uc_mem_map(uc, 0x11ff000, 0x1000, UC_PROT_ALL);
    const std::vector<std::uint8_t> blob = {
        0x48, 0xC7, 0xC0, 0x38, 0x00, 0x00, 0x00,          // 00: mov rax, 56
        0x0F, 0x05,                                        // 07: syscall (the clone)
        0x48, 0x85, 0xC0,                                  // 09: test rax, rax
        0x74, 0x3F,                                        // 0c: jz +0x3f -> 0x4d (the store)
        0xB8, 0xCA, 0x00, 0x00, 0x00,                      // 0e: mov eax, 202
        0x0F, 0x05,                                        // 13: syscall (the park)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // 15: the pad (0x38 wide, the store lands at 0x4d)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                           // 4c
        0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01, 0x2A, 0x00, 0x00, 0x00,
                                                           // 4d: mov dword [0x1002000], 42
        0xEB, 0xFE,                                        // 58: jmp $
    };
    uc_mem_write(uc, 0x11ff000, blob.data(), blob.size());
    uc_mem_map(uc, 0x1002000, 0x1000, UC_PROT_ALL);
    const std::uint32_t sentinel = 0xdeadbeef;
    uc_mem_write(uc, 0x1002000, &sentinel, sizeof(sentinel));
    uc_mem_map(uc, 0x1202000, 0x2000, UC_PROT_ALL);

    uc_hook insn_hook = 0;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(r9b_insn_cb), nullptr, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(r9b_code_cb), nullptr, 1, 0);

    const std::uint64_t rsp = 0x1203000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_emu_start(uc, 0x11ff000, 0xffffffffffffffffull, 0, 32337);
    const std::uint64_t parent_rax2 = 2001;
    uc_reg_write(uc, UC_X86_REG_RAX, &parent_rax2);
    uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    r9b_count = 0;
    uc_context_restore(uc, r9b_child_ctx);
    const uc_err err = uc_emu_start(uc, 0x11ff009, 0xffffffffffffffffull, 0, 32337);
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    std::fprintf(stderr, "[r9b2-end] err=%s pc=0x%llx\n", uc_strerror(err), static_cast<unsigned long long>(pc));
    std::vector<std::uint8_t> got(4, 0);
    uc_mem_read(uc, 0x1002000, got.data(), 4);
    std::fprintf(stderr, "[r9b2-store] %u\n", static_cast<unsigned>(got[0]));
    uc_context_free(r9b_child_ctx);
    r9b_child_ctx = nullptr;
    uc_close(uc);
}

// the clone without CLONE_VM (the fork path) is not implemented on this host
TEST(ThreadClone, ForkPathSurfacesNotImplemented) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_clone_rootfs";
    std::filesystem::create_directories(rootfs);

    // mov rdi, CLONE_FS only (no VM); syscall; exit
    const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x00, 0x02, 0x00, 0x00,          // mov rdi, 0x200 (CLONE_FS)
        0x48, 0xC7, 0xC6, 0x00, 0x30, 0x20, 0x01,          // mov rsi, 0x1203000
        0x31, 0xD2,                                         // xor edx, edx
        0x49, 0xC7, 0xC2, 0x00, 0x20, 0x00, 0x01,          // mov r10, X
        0x45, 0x31, 0xC0,                                   // xor r8d, r8d
        0x48, 0xC7, 0xC0, 0x38, 0x00, 0x00, 0x00,          // mov rax, 56
        0x0F, 0x05,                                         // syscall
        0x48, 0xC7, 0xC0, 0xE7, 0x00, 0x00, 0x00,          // mov rax, 231
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,          // mov rdi, 42
        0x0F, 0x05,                                         // syscall
    };

    QilingOptions options;
    options.code = code;
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    options.multithread = true;
    Qiling ql(options);

    bool raised = false;
    try {
        ql.run();
    } catch (const QlErrorNotImplemented&) {
        raised = true;
    }
    EXPECT_TRUE(raised);
}
