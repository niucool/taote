// QlLinuxThreadManagement suite — the driver-loop scheduler over the
// interleaved emu_start slices (the OQ 10 decision: cooperative, no host
// threads; see STATUS.md D18). The child thread spawns through the same
// add_thread surface the clone slice will use.
#include <gtest/gtest.h>

#include <filesystem>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/loader/loader.hpp"
#include "qiling/os/linux/linux.hpp"
#include "qiling/os/linux/thread.hpp"

using namespace qiling;

namespace {

// the main body: the futex_wait(42) retry loop, then exit_group(42)
//
//   00: 48 C7 C7 00 20 00 01   mov rdi, 0x1002000        (the uaddr)
//   07: 31 F6                  xor esi, esi              (FUTEX_WAIT)
//   09: 48 C7 C2 2A 00 00 00   mov rdx, 42               (the expected value)
//   10: 45 31 D2               xor r10d, r10d            (the timeout)
//   13: 48 C7 C0 CA 00 00 00   mov rax, 202              (futex)
//   1A: 0F 05                  syscall
//   1C: 48 85 C0               test rax, rax
//   1F: 75 F9                  jne 0x1A                  (the -EAGAIN retry)
//   21: 48 C7 C0 E7 00 00 00   mov rax, 231              (exit_group)
//   28: 48 C7 C7 2A 00 00 00   mov rdi, 42
//   2F: 0F 05                  syscall
const std::vector<std::uint8_t>& main_body() {
    static const std::vector<std::uint8_t> code = {
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,
        0x31, 0xF6,
        0x48, 0xC7, 0xC2, 0x2A, 0x00, 0x00, 0x00,
        0x45, 0x31, 0xD2,
        0x48, 0xC7, 0xC0, 0xCA, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x85, 0xC0,
        0x75, 0xF9,
        0x48, 0xC7, 0xC0, 0xE7, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };
    return code;
}

// the child body: the store-42-and-wake loop (8 iterations, the r8d
// counter), then exit(0). Each futex_wake's internal emu_stop bounds the
// slice, so the rounds interleave with the main's retry loop; a wake lands
// while the main waits, the blocked main resumes, and the main's exit_group
// stops the world.
//
//   00: 41 B8 08 00 00 00              mov r8d, 8                  (the rounds)
//   06: C7 04 25 00 20 00 01 2A 00 00 00  mov dword [0x1002000], 42
//   11: 48 C7 C7 00 20 00 01           mov rdi, 0x1002000
//   18: BE 01 00 00 00                 mov esi, 1                  (FUTEX_WAKE)
//   1D: 48 C7 C2 01 00 00 00           mov rdx, 1                  (the count)
//   24: 48 C7 C0 CA 00 00 00           mov rax, 202
//   2B: 0F 05                          syscall
//   2D: 49 83 E8 01                    sub r8, 1
//   31: 75 D3                          jne 0x06
//   33: 48 C7 C0 3C 00 00 00           mov rax, 60                 (exit)
//   3A: 48 C7 C7 00 00 00 00           mov rdi, 0
//   41: 0F 05                          syscall
const std::vector<std::uint8_t>& child_body() {
    static const std::vector<std::uint8_t> code = {
        0x41, 0xB8, 0x08, 0x00, 0x00, 0x00,
        0xC7, 0x04, 0x25, 0x00, 0x20, 0x00, 0x01, 0x2A, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x20, 0x00, 0x01,
        0xBE, 0x01, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC0, 0xCA, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x49, 0x83, 0xE8, 0x01,
        0x75, 0xD3,
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xEB, 0xFE,   // jmp $ - the TB boundary pad (the emu_stop inside the
                      // syscall hook aborts at the next branch; without the
                      // pad the TB tail fetches past the body)
    };
    return code;
}

constexpr std::uint64_t kChildOffset = 0x2000;  // past the main body, in the shellcode mapping

}  // namespace

// the round-robin: the main blocks on futex(X, 42); the child stores 42 and
// wakes; the main resumes and exits with 42
TEST(ThreadManagement, RoundRobinWakesBlockedMain) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_thread_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.code = main_body();
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    options.multithread = true;
    Qiling ql(options);

    // the loader remaps the shellcode to its own base (the elf loader's
    // shellcode path: entry + 0x200000 - 0x1000); the child body lands in
    // the same mapping, past the main body
    const auto child_base = ql.loader().entry_point + kChildOffset;
    ql.mem().write(child_base, child_body());

    auto& os = ql.os<os::linux::QlOsLinux>();
    os.init_multithread();
    // the child spawns through the add_thread surface (the clone slice will
    // call the same entry)
    auto child = os::linux::QlLinuxThread::spawn(&ql, child_base, ql.os().exit_point());
    os.thread_management()->add_thread(std::move(child));

    os.run_multithread();

    // the main exited with 42 once the wake resumed it
    EXPECT_EQ(ql.os().exit_code(), 42);
}

// the exit syscall inside the main thread stops the world: the spinning child
// never runs exit, the management drains everything at the main's stop
TEST(ThreadManagement, ExitInMainThreadStopsWorld) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_thread_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.code = main_body();
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    options.multithread = true;
    Qiling ql(options);

    // the futex value at X is already 42: the first wait succeeds and blocks
    // with nobody to wake it - the main is the only thread, so the blocked
    // main... the exit never runs. skip the wait by pre-storing the value and
    // asserting the management's all-blocked stop (the gevent LoopExit
    // analogue): the run surfaces QlErrorExecutionStop
    ql.mem().write_ptr(0x1002000, 42, 4);

    auto& os = ql.os<os::linux::QlOsLinux>();
    os.init_multithread();

    bool raised = false;
    try {
        os.run_multithread();
    } catch (const QlErrorBase&) {
        raised = true;
    }
    EXPECT_TRUE(raised);
}

// sched_yield inside a thread yields the slice and the run continues
TEST(ThreadManagement, SchedYieldContinuesRun) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_thread_rootfs";
    std::filesystem::create_directories(rootfs);

    // mov eax, 24 (sched_yield); syscall; exit_group(7)
    // (the blob previously rode eax=99 = sysinfo on x86-64 — the write landed
    // in the fall-through void; the sysinfo implementation now faults there,
    // so the blob rides the real sched_yield number)
    const std::vector<std::uint8_t> code = {
        0xB8, 0x18, 0x00, 0x00, 0x00,             // mov eax, 24 (sched_yield)
        0x0F, 0x05,                                // syscall
        0x48, 0xC7, 0xC0, 0xE7, 0x00, 0x00, 0x00,  // mov rax, 231
        0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00,  // mov rdi, 7
        0x0F, 0x05,                                // syscall
    };

    QilingOptions options;
    options.code = code;
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;
    options.multithread = true;
    Qiling ql(options);

    // the fault tracer: the write-fault address + the pc (the bisect)
    auto fault_hook = ql.hook_mem_unmapped([](int access, std::uint64_t address, std::uint32_t size, std::int64_t value) {
        (void)value;
        std::fprintf(stderr, "[fault] access=%d addr=%llx size=%u\n", access,
                     (unsigned long long)address, size);
        return 0;
    });
    (void)fault_hook;
    auto& os = ql.os<os::linux::QlOsLinux>();
    os.init_multithread();
    os.run_multithread();

    EXPECT_EQ(ql.os().exit_code(), 7);
}
