// P17 — the raw replication of the uefi address-hook dispatch shape
// (tests/Uefi_Test.cpp EventFamilyCreateSignalCheckClose): a guest blob with
// TWO call sites (call A then call B, mimicking the check1/check2 pair) both
// calling the SAME hooked cell. Inside the address-hook callback the handler
// does exactly what the port's dispatch_service + QlOs::call do:
//   1. stack_pop (read [rsp] via uc_mem_read, then RSP += 8 — the fcall
//      unwind)
//   2. uc_reg_write(RIP, retaddr) — the QlOs::call set_arch_pc(retaddr)
//   and returns 0 (no emu_stop — the uefi path never stops the emulation).
// The cell carries the port's install_service_table content: the field
// address itself (the pointer bytes), NOT executable stub code.
// The question: does the second call's dispatch mis-pair (the +size walk)?
#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

namespace {

constexpr std::uint64_t kBase = 0x1000;
constexpr std::uint64_t kCell = 0x4000200;
constexpr std::uint64_t kStack = 0x1203000;

// the hook context: the per-call record the raw handler fills
struct P17Record {
    std::vector<std::uint64_t> call_pcs;
    std::vector<std::uint64_t> retaddrs;
    int fire_count = 0;
};

// the code hook (the [ucode]-equivalent tracer from the uefi diagnostic run)
void p17_code_hook(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    auto* rec = static_cast<P17Record*>(user_data);
    (void)size;
    rec->fire_count++;
    std::fprintf(stderr, "[ucode] 0x%llx\n", static_cast<unsigned long long>(address));
    if (rec->fire_count > 200) {
        uc_emu_stop(uc);
    }
}

// the address-hook callback: the port's dispatch_service shape — the stack
// pop (the fcall unwind) then the RIP write (the QlOs::call set_arch_pc)
void p17_addr_hook(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    auto* rec = static_cast<P17Record*>(user_data);
    (void)address;
    (void)size;
    rec->fire_count++;
    std::uint64_t rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    std::uint64_t retaddr = 0;
    uc_mem_read(uc, rsp, &retaddr, sizeof(retaddr));
    uc_reg_write(uc, UC_X86_REG_RSP, &(rsp += 8));  // the stack_pop
    uc_reg_write(uc, UC_X86_REG_RIP, &retaddr);     // the set_arch_pc(retaddr)
    rec->retaddrs.push_back(retaddr);
    std::fprintf(stderr, "[addr-hook] fired at %#llx retaddr=%#llx\n", static_cast<unsigned long long>(address),
                 static_cast<unsigned long long>(retaddr));
}

// the syscall INSN hook (the port's kernel-side INSN hook shape — present in
// the clone's failing path; the probe's variant uses it to stop after the
// second call)
void p17_syscall_hook(uc_engine* uc, void* user_data) {
    std::uint64_t pc = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    uc_emu_stop(uc);
}

}  // namespace

TEST(TbSemantics, DISABLED_P17FcallUnwindInAddressHook) {
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);

    // the guest blob: the two call sites ride the same hooked cell
    //   +0x00: 48 C7 C2 00 20 40 00   mov rdx, 0x402000 (the scratch)
    //   +0x07: 48 C7 C1 01 00 00 00   mov rcx, 1        (the arg)
    //   +0x0e: 4c 8b 15 f8 0e 00 00   mov r10, [rip+0xef8] -> the cell
    //   +0x15: 41 ff d2               call r10           (the call A)
    //   +0x18: 48 a3 30 10 00 01 00 00 00 00   mov [0x1001030], rax (the status A)
    //   +0x22: 48 8b 0d f4 0e 00 00   mov rcx, [rip+0xef4]
    //   +0x29: 4c 8b 15 e5 0e 00 00   mov r10, [rip+0xee5]
    //   +0x30: 41 ff d2               call r10           (the call B)
    //   +0x33: 48 a3 40 10 00 01 00 00 00 00   mov [0x1001040], rax (the status B)
    //   +0x3d: 48 c7 c0 3c 00 00 00   mov rax, 60 (exit)
    //   +0x44: 0f 05                  syscall
    std::string body;
    auto emit = [&body](std::initializer_list<char> bytes) {
        for (char b : bytes) {
            body.push_back(b);
        }
    };
    // rdx and rcx (the args); the addresses are the rip-relative forms
    emit({'\x48', '\xC7', '\xC2', '\x00', '\x20', '\x40', '\x00'});   // +0x00 mov rdx, 0x402000
    emit({'\x48', '\xC7', '\xC1', '\x01', '\x00', '\x00', '\x00'});   // +0x07 mov rcx, 1
    // +0x0e mov r10, [rip+disp32] -> the cell at 0x4000200; the disp = the
    // cell - (0x1000 + 0x0e + 7)
    {
        const std::int32_t disp = static_cast<std::int32_t>(0x4000200 - (kBase + 0x0e + 7));
        emit({'\x4C', '\x8B', '\x15'});
        for (int i = 0; i < 4; ++i) {
            body.push_back(static_cast<char>((static_cast<std::uint32_t>(disp) >> (8 * i)) & 0xff));
        }
    }
    emit({'\x41', '\xFF', '\xD2'});                                   // +0x15 call r10
    // +0x18 mov [0x1001030], rax (the moffs store)
    emit({'\x48', '\xA3', '\x30', '\x10', '\x00', '\x01', '\x00', '\x00', '\x00', '\x00'});
    // +0x22 mov rcx, 2 (the second call's arg)
    emit({'\x48', '\xC7', '\xC1', '\x02', '\x00', '\x00', '\x00'});
    // +0x29 mov r10, [rip+disp32]
    {
        const std::int32_t disp = static_cast<std::int32_t>(0x4000200 - (kBase + 0x29 + 7));
        emit({'\x4C', '\x8B', '\x15'});
        for (int i = 0; i < 4; ++i) {
            body.push_back(static_cast<char>((static_cast<std::uint32_t>(disp) >> (8 * i)) & 0xff));
        }
    }
    emit({'\x41', '\xFF', '\xD2'});                                   // +0x30 call r10
    // +0x33 mov [0x1001040], rax
    emit({'\x48', '\xA3', '\x40', '\x10', '\x00', '\x01', '\x00', '\x00', '\x00', '\x00'});
    emit({'\x48', '\xC7', '\xC0', '\x2A', '\x00', '\x00', '\x00'});   // +0x3d mov rax, 42
    emit({'\x0F', '\x05'});                                           // +0x44 syscall (the exit)

    uc_mem_map(uc, kBase, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, kBase, body.data(), body.size());
    uc_mem_map(uc, 0x1001000, 0x1000, UC_PROT_ALL);   // the status cells
    uc_mem_map(uc, kCell & ~0xfffull, 0x1000, UC_PROT_ALL);  // the gBS page
    uc_mem_map(uc, kStack - 0x1000, 0x2000, UC_PROT_ALL);

    // the cell's content: the pointer bytes (the port's
    // install_service_table shape — the field address written verbatim)
    const std::uint64_t cell_value = kCell;
    uc_mem_write(uc, kCell, &cell_value, sizeof(cell_value));

    P17Record rec;
    uc_hook code_hook = 0;
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(p17_code_hook), &rec, 1, 0);
    uc_hook addr_hook = 0;
    // the port's shape: the UC_HOOK_CODE bound to the cell address exactly
    uc_hook_add(uc, &addr_hook, UC_HOOK_CODE, reinterpret_cast<void*>(p17_addr_hook), &rec, kCell, kCell);
    uc_hook insn_hook = 0;
    uc_hook_add(uc, &insn_hook, UC_HOOK_INSN, reinterpret_cast<void*>(p17_syscall_hook), &rec, 1, 0,
                UC_X86_INS_SYSCALL);

    const std::uint64_t sp = kStack + 0x1000;
    uc_reg_write(uc, UC_X86_REG_RSP, &sp);

    const uc_err err = uc_emu_start(uc, kBase, 0xffffffffffffffffull, 0, 4096);
    std::fprintf(stderr, "[p17-end] err=%s\n", uc_strerror(err));
    for (const auto ra : rec.retaddrs) {
        std::fprintf(stderr, "[p17-retaddr] %#llx\n", static_cast<unsigned long long>(ra));
    }
    // the statuses
    std::uint64_t st_a = 0, st_b = 0;
    uc_mem_read(uc, 0x1001030, &st_a, sizeof(st_a));
    uc_mem_read(uc, 0x1001040, &st_b, sizeof(st_b));
    std::fprintf(stderr, "[p17-status] A=%#llx B=%#llx\n", static_cast<unsigned long long>(st_a),
                 static_cast<unsigned long long>(st_b));
    uc_close(uc);
    EXPECT_EQ(err, UC_ERR_OK);
    EXPECT_EQ(st_a, 1u);
    EXPECT_EQ(st_b, 2u);
}
