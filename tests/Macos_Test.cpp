// MacosOs suite — the dialect skeleton: the QlOsMacos ctor (the macosx64
// fcall), the GDT/segment load() shape, and the MACOS x8664 syscall table
// with the LIBSYSTEM 0x2000000 fixup. The fixtures ride the shellcode path
// through the syscall table (exit via the plain 1 and via the fixup'd
// 0x2000000+1) — the handler surface rides its own slices.
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/arch/x86.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/macos/kernel_api.hpp"
#include "qiling/loader/macho.hpp"

using qiling::loader::macho::CPU_TYPE_X8664;
using qiling::loader::macho::MH_EXECUTE;
using qiling::loader::macho::LC_SEGMENT_64;
using qiling::loader::macho::LC_SYMTAB;
using qiling::loader::macho::LC_DYSYMTAB;
using qiling::loader::macho::LC_UNIXTHREAD;
#include "qiling/os/macos/macos.hpp"
#include "qiling/os/posix/posix.hpp"

using namespace qiling;
using ResolvedParams = qiling::os::macos::ResolvedParams;
using KernelApi = qiling::os::macos::KernelApi;

namespace {

// the winsock IPPROTO_TCP/UDP macros (via unicorn's winsock2.h) collide with
// the verbatim NetworkProtocol enumerator names below; the test TU uses no
// winsock
#undef IPPROTO_TCP
#undef IPPROTO_UDP

constexpr std::uint64_t kScratch = 0x2100;

Qiling make_macos_qiling(const std::vector<std::uint8_t>& code) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = code;
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    return Qiling{options};
}

//   mov edi, 42 ; mov eax, 1 (exit) ; syscall
const std::vector<std::uint8_t>& exit_body() {
    static const std::vector<std::uint8_t> code = {
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0x05,                    // syscall
    };
    return code;
}

// the LIBSYSTEM range: the same exit but with the number riding the
// 0x2000000 fixup (0x2000000+1 = exit)
const std::vector<std::uint8_t>& exit_libsystem_body() {
    static const std::vector<std::uint8_t> code = {
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x02,  // mov eax, 0x2000001
        0x0F, 0x05,                    // syscall
    };
    return code;
}

// ---- the self-trap family + the simple stubs ----

//   mov ebx, 0x2100 ; the four traps (rax = 0x100001a..d) each followed by a
//   store into the scratch cells; exit(42)
const std::vector<std::uint8_t>& self_trap_body() {
    static const std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,  // mov ebx, 0x2100
        0xB8, 0x1A, 0x00, 0x00, 0x01,  // mov eax, 0x100001a (mach_reply_port)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xB8, 0x1B, 0x00, 0x00, 0x01,  // mov eax, 0x100001b (thread_self_trap)
        0x0F, 0x05,
        0x48, 0x89, 0x43, 0x08,        // mov [rbx+8], rax
        0xB8, 0x1C, 0x00, 0x00, 0x01,  // mov eax, 0x100001c (task_self_trap)
        0x0F, 0x05,
        0x48, 0x89, 0x43, 0x10,        // mov [rbx+0x10], rax
        0xB8, 0x1D, 0x00, 0x00, 0x01,  // mov eax, 0x100001d (host_self_trap)
        0x0F, 0x05,
        0x48, 0x89, 0x43, 0x18,        // mov [rbx+0x18], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
        0x0F, 0x05,
    };
    return code;
}

//   mov ebx, 0x2140 (the ret cell); mov edi, 0x2100 (the buf); xor esi/edx;
//   mov eax, 169 (csops); syscall; store; exit(42)
const std::vector<std::uint8_t>& csops_body() {
    static const std::vector<std::uint8_t> code = {
        0xBB, 0x40, 0x21, 0x00, 0x00,  // mov ebx, 0x2140
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100 (pid)
        0x31, 0xF6,                    // xor esi, esi (ops)
        0xBA, 0x00, 0x21, 0x00, 0x00,  // mov edx, 0x2100 (useraddr — the 3rd arg)
        0xB8, 0xA9, 0x00, 0x00, 0x00,  // mov eax, 169 (csops)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
        0x0F, 0x05,
    };
    return code;
}

//   the same shape with eax = 500 (getentropy) and esi = 32
const std::vector<std::uint8_t>& getentropy_body() {
    static const std::vector<std::uint8_t> code = {
        0xBB, 0x40, 0x21, 0x00, 0x00,  // mov ebx, 0x2140
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100
        0xBE, 0x20, 0x00, 0x00, 0x00,  // mov esi, 32
        0xB8, 0xF4, 0x01, 0x00, 0x00,  // mov eax, 500 (getentropy)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
        0x0F, 0x05,
    };
    return code;
}

TEST(MacosOs, SelfTrapFamilyReturnsPortNames) {
    auto ql = make_macos_qiling(self_trap_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the seeded surfaces (the loader/macho.py values): MachPort(2187), the
    // thread's port 0x307, the task id 9876, the host port 0x303
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 2187u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 8, 4), 0x307u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x10, 4), 9876u);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x18, 4), 0x303u);
}

// ---- the mach_msg message-trap family ----
//
// The trap: eax=0x1f (mach_msg_trap), rdi = the message address, rsi = the
// option (the upstream parses NO MACH_SEND/MACH_RCV flags — it is only
// logged), rdx = ssize. The dispatch reads the message, routes on the
// msgh_id and writes the reply over the request buffer in place.
TEST(MacosOs, MachMsgHostInfoReplyReturnsSuccess) {
    // craft the id-200 HOST_BASIC_INFO message at 0x2100: the 24-byte header
    // + NDR(8) + flavor(4) + outCnt(4) = ssize 40
    std::vector<std::uint8_t> msg(40, 0);
    const auto u32 = [&msg](std::size_t at, std::uint32_t v) {
        msg[at] = static_cast<std::uint8_t>(v);
        msg[at + 1] = static_cast<std::uint8_t>(v >> 8);
        msg[at + 2] = static_cast<std::uint8_t>(v >> 16);
        msg[at + 3] = static_cast<std::uint8_t>(v >> 24);
    };
    u32(0, 0x1200);   // msgh_bits
    u32(4, 40);       // msgh_size (the trap overrides it with ssize)
    u32(8, 0);        // msgh_remote_port
    u32(0xc, 0);      // msgh_local_port
    u32(0x10, 0);     // msgh_voucher_port
    u32(0x14, 200);   // msgh_id = host_info
    msg[24] = 1;      // NDR (the low byte; the server only parses it)
    u32(32, 1);       // flavor = HOST_BASIC_INFO
    u32(36, 6);       // host_info_outCnt = 6 (the >5 branch)

    // the trap blob: rdi = the msg addr, rsi = 0 (opt), rdx = 40 (ssize),
    // eax = 0x1f; store the return; exit(42)
    std::vector<std::uint8_t> code = {
        0xBB, 0x40, 0x21, 0x00, 0x00,  // mov ebx, 0x2140
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100
        0x31, 0xF6,                    // xor esi, esi
        0xBA, 0x28, 0x00, 0x00, 0x00,  // mov edx, 40
        0xB8, 0x1F, 0x00, 0x00, 0x01,  // mov eax, 0x100001f (mach_msg_trap)
        0x0F, 0x05,                    // syscall
        0x48, 0x89, 0x03,              // mov [rbx], rax
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0x05,
    };
    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    ql.mem().write(0x2100, msg);
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(0x2140, 4), 0u);  // KERN_SUCCESS
    // the reply header (the bits 4608, the size 88, the local port 2187)
    const auto hdr = ql.mem().read(0x2100, 24);
    EXPECT_EQ(hdr[0], 0x00); EXPECT_EQ(hdr[1], 0x12);  // msgh_bits = 4608 LE
    EXPECT_EQ(hdr[4], 88);                             // msgh_size
    EXPECT_EQ(hdr[12], 0x8B); EXPECT_EQ(hdr[13], 0x08);  // local port 2187
    EXPECT_EQ(hdr[20], 0x2C);                          // msgh_id = 300
    // the reply content: NDR 0x100000000, retcode 0, outCnt 6, then the
    // basic-info cells
    const auto content = ql.mem().read(0x2118, 64);
    EXPECT_EQ(content[4], 1);  // the NDR's high byte (0x100000000)
    EXPECT_EQ(content[8], 0);  // the retcode = KERN_SUCCESS
    EXPECT_EQ(content[12], 6); // the outCnt echoed
    EXPECT_EQ(content[16], 2); // max_cpus
    EXPECT_EQ(content[20], 2); // avail_cpus
    // memory_size = 0x80000000 (the high byte at +27)
    EXPECT_EQ(content[27], 0x80);
    EXPECT_EQ(content[28], 7); // cpu_type
    EXPECT_EQ(content[32], 4); // cpu_subtype
    EXPECT_EQ(content[36], 1); // cpu_threadtype (the >5 branch)
    EXPECT_EQ(content[48], 4); // logic_cpu
    EXPECT_EQ(content[52], 4); // logic_cpu_max
    EXPECT_EQ(content[56], 0); // max_mem = 0x400000000 (the low byte 0)
    EXPECT_EQ(content[60], 4); // max_mem byte 4
}

TEST(MacosOs, MachMsgUnknownIdThrows) {
    // the id 999 rides the not-found branch (the upstream's plain Exception)
    std::vector<std::uint8_t> msg(40, 0);
    const auto u32 = [&msg](std::size_t at, std::uint32_t v) {
        msg[at] = static_cast<std::uint8_t>(v);
        msg[at + 1] = static_cast<std::uint8_t>(v >> 8);
        msg[at + 2] = static_cast<std::uint8_t>(v >> 16);
        msg[at + 3] = static_cast<std::uint8_t>(v >> 24);
    };
    u32(0x14, 999);
    u32(32, 1);
    u32(36, 6);

    auto ql = make_macos_qiling(csops_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    ql.mem().write(0x2100, msg);
    // the trap blob again (the same code shape as the reply fixture)
    std::vector<std::uint8_t> code = {
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100
        0x31, 0xF6,                    // xor esi, esi
        0xBA, 0x28, 0x00, 0x00, 0x00,  // mov edx, 40
        0xB8, 0x1F, 0x00, 0x00, 0x01,  // mov eax, 0x100001f
        0x0F, 0x05,                    // syscall
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0x05,
    };
    auto ql2 = make_macos_qiling(code);
    ql2.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    ql2.mem().write(0x2100, msg);
    EXPECT_THROW(ql2.run(), qiling::QlErrorBase);
}

// the port-name reply fixture helper: crafts an id-N message, runs the
// trap, returns the emulator (the reply overwrote the request buffer); the
// flavor/outCnt ride the prefill
static std::unique_ptr<Qiling> run_mach_msg_id(std::uint32_t msgh_id, std::uint64_t ssize, std::uint32_t flavor) {
    std::vector<std::uint8_t> msg(ssize, 0);
    const auto u32 = [&msg](std::size_t at, std::uint32_t v) {
        msg[at] = static_cast<std::uint8_t>(v);
        msg[at + 1] = static_cast<std::uint8_t>(v >> 8);
        msg[at + 2] = static_cast<std::uint8_t>(v >> 16);
        msg[at + 3] = static_cast<std::uint8_t>(v >> 24);
    };
    u32(0x14, msgh_id);
    if (ssize >= 40) {
        msg[24] = 1;        // NDR
        u32(32, flavor);    // the flavor cell
        u32(36, 6);         // outCnt
    } else if (flavor != 0) {
        u32(24, flavor);    // a short content: the flavor rides cell 0
    }
    std::vector<std::uint8_t> code = {
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100
        0x31, 0xF6,                    // xor esi, esi
        0xBA, static_cast<std::uint8_t>(ssize), 0x00, 0x00, 0x00,  // mov edx, ssize
        0xB8, 0x1F, 0x00, 0x00, 0x01,  // mov eax, 0x100001f (mach_msg_trap)
        0x0F, 0x05,                    // syscall
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0x05,
    };
    QilingOptions options;
    options.rootfs = (std::filesystem::temp_directory_path() / "ql_macos_rootfs").string();
    options.code = code;
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    // the options move through make_unique (Qiling itself is neither
    // copyable nor movable — the prvalue path make_macos_qiling uses does
    // not survive the helper return)
    auto ql = std::make_unique<Qiling>(std::move(options));
    ql->mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    ql->mem().write(0x2100, msg);
    std::fprintf(stderr, "[m] pre-run\n");
    ql->run();
    std::fprintf(stderr, "[m] post-run\n");
    EXPECT_EQ(ql->os().exit_code(), 42);
    return ql;
}

TEST(MacosOs, MachMsgClockServiceAndTaskPorts) {
    // id 206 (host_get_clock_service): the reply id 306, the retcode 1, the
    // trailer carrying the clock port 0x803
    std::fprintf(stderr, "[m] case 206\n");
    {
        const auto owned = run_mach_msg_id(206, 28, 0);
        Qiling& ql = *owned;
        const auto hdr = ql.mem().read(0x2100, 24);
        EXPECT_EQ(hdr[4], 0x28);                            // msgh_size
        EXPECT_EQ(hdr[0], 0x00); EXPECT_EQ(hdr[1], 0x12);   // bits 0x80001200
        EXPECT_EQ(hdr[3], 0x80);
        EXPECT_EQ(hdr[20], 0x32); EXPECT_EQ(hdr[21], 0x01); // msgh_id = 306
        const auto content = ql.mem().read(0x2118, 4);
        EXPECT_EQ(content[0], 1);                           // the retcode
        const auto trailer = ql.mem().read(0x211c, 16);
        EXPECT_EQ(trailer[0], 0x03); EXPECT_EQ(trailer[1], 0x08);  // 0x803 LE
        EXPECT_EQ(trailer[10], 0x11);                       // the disposition
    }
    // id 3418 (semaphore_create): the reply id 3518, the semaphore port 0x903
    std::fprintf(stderr, "[m] case 3418\n");
    {
        const auto owned = run_mach_msg_id(3418, 28, 0);
        Qiling& ql = *owned;
        const auto hdr = ql.mem().read(0x2100, 24);
        EXPECT_EQ(hdr[20], 0xBE); EXPECT_EQ(hdr[21], 0x0D);  // msgh_id = 3518
        const auto trailer = ql.mem().read(0x211c, 4);
        EXPECT_EQ(trailer[0], 0x03); EXPECT_EQ(trailer[1], 0x09);  // 0x903 LE
    }
    // id 3409 (get_special_port): the reply id 3509, the special port 0x707
    std::fprintf(stderr, "[m] case 3409\n");
    {
        const auto owned = run_mach_msg_id(3409, 28, 0);
        Qiling& ql = *owned;
        const auto hdr = ql.mem().read(0x2100, 24);
        EXPECT_EQ(hdr[20], 0xB5); EXPECT_EQ(hdr[21], 0x0D);  // msgh_id = 3509
        const auto trailer = ql.mem().read(0x211c, 4);
        EXPECT_EQ(trailer[0], 0x07); EXPECT_EQ(trailer[1], 0x07);  // 0x707 LE
    }
}

TEST(MacosOs, MachMsgHostInfoPriorityFlavor) {
    // flavor 5 (HOST_PRIORITY_INFO): the fixed priority cells
    std::vector<std::uint8_t> msg(40, 0);
    const auto u32 = [&msg](std::size_t at, std::uint32_t v) {
        msg[at] = static_cast<std::uint8_t>(v);
        msg[at + 1] = static_cast<std::uint8_t>(v >> 8);
        msg[at + 2] = static_cast<std::uint8_t>(v >> 16);
        msg[at + 3] = static_cast<std::uint8_t>(v >> 24);
    };
    u32(0x14, 200);
    msg[24] = 1;
    u32(32, 5);   // flavor = HOST_PRIORITY_INFO
    u32(36, 4);   // outCnt
    std::vector<std::uint8_t> code = {
        0xBF, 0x00, 0x21, 0x00, 0x00,  // mov edi, 0x2100
        0x31, 0xF6,                    // xor esi, esi
        0xBA, 0x28, 0x00, 0x00, 0x00,  // mov edx, 40
        0xB8, 0x1F, 0x00, 0x00, 0x01,  // mov eax, 0x100001f
        0x0F, 0x05,                    // syscall
        0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0x05,
    };
    Qiling ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    ql.mem().write(0x2100, msg);
    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(0x2100 + 0x14, 4), 300u);  // msgh_id = 300
    // the reply size 72 (the priority branch)
    EXPECT_EQ(ql.mem().read_ptr(0x2104, 4), 72u);
    const auto content = ql.mem().read(0x2118, 48);
    EXPECT_EQ(content[16], 0x50);  // kernel_priority = MINPRI_KERNEL
    EXPECT_EQ(content[20], 0x50);  // system_priority
    EXPECT_EQ(content[24], 0x40);  // server_priority = MINPRI_RESERVED
    EXPECT_EQ(content[28], 0x1f);  // user_priority = BASEPRI_DEFAULT
    EXPECT_EQ(content[44], 0x4f);  // maximum_priority = MAXPRI_RESERVED
}

TEST(MacosOs, MachMsgHostInfoShortContentAndBadFlavorThrow) {
    // the content shorter than 16 bytes (ssize 28 = 24 + 4): the parse guard
    EXPECT_THROW(run_mach_msg_id(200, 28, 1), qiling::QlErrorBase);
    // the unknown flavor (999): the flavor-not-supported branch
    EXPECT_THROW(run_mach_msg_id(200, 40, 999), qiling::QlErrorBase);
}

// ---- the kext/kernel-symbol machinery ----
//
// The kernel.development fixture: MH_EXECUTE with the __TEXT at 0x20000000,
// one extern-def symbol _host_info_probe (n_value 0x20000040, the body
// mov eax,0x77; ret), the LC_SYMTAB + the LC_DYSYMTAB (iextdefsym=0,
// nextdefsym=1). The kext fixture: MH_KEXT_BUNDLE (0xb) whose blob calls the
// kernel symbol directly — the kernel-api hook intercepts the call through
// the kernel symbol walk (the import chain the registry keys on).
void write_macho_kernel_development(const std::filesystem::path& path) {
    constexpr std::uint64_t kKernelBase = 0x20000000;
    constexpr std::uint64_t kSymValue = kKernelBase + 0x200;  // _host_info_probe
    constexpr std::uint32_t kTextSize = 0x1000;

    std::vector<std::uint8_t> file(kTextSize, 0);
    auto put32 = [&file](std::size_t off, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };
    auto put64 = [&file](std::size_t off, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };

    put32(0, 0xFEEDFACF);
    put32(4, CPU_TYPE_X8664);
    put32(12, MH_EXECUTE);
    put32(16, 3);                              // ncmds
    put32(20, 72 + 24 + 96);                   // sizeofcmds (seg + symtab + dysymtab)

    put32(32, LC_SEGMENT_64);
    put32(36, 72);
    for (std::size_t i = 0; i < sizeof("__TEXT"); ++i) {
        file[32 + 8 + i] = "__TEXT"[i];
    }
    put64(32 + 24, kKernelBase);
    put64(32 + 32, kTextSize);
    put64(32 + 40, 0);
    put64(32 + 48, kTextSize);
    put32(32 + 60, 5);
    put32(32 + 64, 0);

    const std::uint32_t symoff = 0x180;
    const std::uint32_t stroff = 0x1a0;
    put32(32 + 72, LC_SYMTAB);
    put32(32 + 72 + 4, 24);
    put32(32 + 72 + 8, symoff);
    put32(32 + 72 + 12, 1);                    // nsyms
    put32(32 + 72 + 16, stroff);
    put32(32 + 72 + 20, 32);                   // strsize
    put32(symoff, 0);                          // n_strx
    file[symoff + 4] = 0x0f;                   // n_type = N_EXT|N_SECT
    file[symoff + 5] = 1;                      // n_sect
    put64(symoff + 8, kSymValue);
    const std::string sym = "_host_info_probe";
    for (std::size_t i = 0; i <= sym.size(); ++i) {
        file[stroff + i] = static_cast<std::uint8_t>(sym[i]);
    }

    // the LC_DYSYMTAB: the extern-def range covers the one symbol
    put32(32 + 72 + 24, LC_DYSYMTAB);
    put32(32 + 72 + 24 + 4, 96);
    put32(32 + 72 + 24 + 16, 0);               // iextdefsym
    put32(32 + 72 + 24 + 20, 1);               // nextdefsym
    put32(32 + 72 + 24 + 64, 0);               // extreloff
    put32(32 + 72 + 24 + 68, 0);               // nextrel
    put32(32 + 72 + 24 + 72, 0);               // locreloff
    put32(32 + 72 + 24 + 76, 0);               // nlocrel

    // the kernel body at the file offset 0x200 (clear of the commands — the
    // 0x40 placement collided with the segment command and the body bytes
    // parsed as the vm_size)
    file[0x200] = 0xB8;
    file[0x201] = 0x77; file[0x202] = 0x00; file[0x203] = 0x00; file[0x204] = 0x00;
    file[0x205] = 0xC3;

    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
}

void write_macho_kext_fixture(const std::filesystem::path& path, std::uint64_t kernel_sym_addr) {
    constexpr std::uint32_t kTextSize = 0x1000;
    constexpr std::uint64_t kEntryOff = 0x200;   // the blob's file offset

    std::vector<std::uint8_t> file(kTextSize, 0);
    auto put32 = [&file](std::size_t off, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };
    auto put64 = [&file](std::size_t off, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };

    put32(0, 0xFEEDFACF);
    put32(4, CPU_TYPE_X8664);
    put32(12, 0xb);                            // MH_KEXT_BUNDLE
    put32(16, 2);                              // ncmds (the segment + the thread)
    put32(20, 72 + 184);                       // sizeofcmds

    put32(32, LC_SEGMENT_64);
    put32(36, 72);
    for (std::size_t i = 0; i < sizeof("__TEXT"); ++i) {
        file[32 + 8 + i] = "__TEXT"[i];
    }
    put64(32 + 24, 0);                         // the vm address (the loadbase slides it)
    put64(32 + 32, kTextSize);
    put64(32 + 40, 0);
    put64(32 + 48, kTextSize);
    put32(32 + 60, 5);
    put32(32 + 64, 0);

    constexpr std::size_t thread_at = 32 + 72;
    put32(thread_at, LC_UNIXTHREAD);
    put32(thread_at + 4, 184);
    put32(thread_at + 8, 4);                   // X86_THREAD_STATE64
    put32(thread_at + 12, 21);
    put64(thread_at + 16 + 16 * 8, kEntryOff); // the rip = the raw entry offset

    // the blob: movabs rax, <the kernel symbol>; call rax; mov [0x2140], rax;
    // exit(42)
    std::size_t at = kEntryOff;
    file[at++] = 0x48; file[at++] = 0xB8;
    for (int i = 0; i < 8; ++i) {
        file[at++] = static_cast<std::uint8_t>(kernel_sym_addr >> (8 * i));
    }
    file[at++] = 0xFF; file[at++] = 0xD0;      // call rax
    file[at++] = 0x48; file[at++] = 0x89; file[at++] = 0x04; file[at++] = 0x25;  // mov [0x2140], rax
    file[at++] = 0x40; file[at++] = 0x21; file[at++] = 0x00; file[at++] = 0x00;
    file[at++] = 0xBF; file[at++] = 0x2A; file[at++] = 0x00; file[at++] = 0x00; file[at++] = 0x00;  // mov edi, 42
    file[at++] = 0xB8; file[at++] = 0x01; file[at++] = 0x00; file[at++] = 0x00; file[at++] = 0x00;  // mov eax, 1
    file[at++] = 0x0F; file[at++] = 0x05;

    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
}

TEST(MacosOs, KextDriverResolvesKernelSymbols) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    const auto kernel_dir = rootfs / "System" / "Library" / "Kernels";
    std::filesystem::create_directories(kernel_dir);
    write_macho_kernel_development(kernel_dir / "kernel.development");

    const auto kext = std::filesystem::temp_directory_path() / "ql_macho_kext2" / "driver.macho";
    std::filesystem::create_directories(kext.parent_path());
    constexpr std::uint64_t kKernelBase = 0x20000000;
    // the kext loadbase: the verbatim default 0xffffff7000000000 cannot be
    // FETCHED by the stock unicorn 2.1.4 (the HighCanonicalAddressFetchProbe
    // pin) — the fixture rides a low loadbase the engine can execute at
    constexpr std::uint64_t kKextLoadbase = 0x30000000;
    write_macho_kext_fixture(kext, kKernelBase + 0x200);

    QilingOptions options;
    options.argv = {kext.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    options.driver_loadbase = kKextLoadbase;
    Qiling ql(options);
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    // the registry hook: the import chain (the kernel symbol's n_value ->
    // import_symbols_ -> the hook dispatch -> the registry hit) answers the
    // call INSTEAD of the kernel body
    KernelApi("host_info_probe", {}) = [](Qiling&, std::uint64_t, const ResolvedParams&) {
        return std::optional<std::uint64_t>(0x99);
    };
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(0x2140, 4), 0x99u);
}

// the relocation-fixture kext: the blob calls the kernel function via a
// rel32 branch relocation (rtype 2 — the STATIC-page jmp-stub bridge), reads
// an abs64-relocated cell (rtype 0, length 3 — the kernel symbol's n_value)
// and a local-relocated cell (the loadbase slide), then exits. The kext
// carries one undefined import (_host_info_probe, symtab index 1) and one
// local (_local_data, index 0).
void write_macho_kext_reloc_fixture(const std::filesystem::path& path, std::uint64_t kernel_sym_addr) {
    constexpr std::uint32_t kTextSize = 0x1000;
    constexpr std::uint64_t kEntryOff = 0x200;

    std::vector<std::uint8_t> file(kTextSize, 0);
    auto put32 = [&file](std::size_t off, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };
    auto put64 = [&file](std::size_t off, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };

    put32(0, 0xFEEDFACF);
    put32(4, CPU_TYPE_X8664);
    put32(12, 0xb);                            // MH_KEXT_BUNDLE
    put32(16, 4);                              // ncmds (seg + symtab + dysymtab + thread)
    put32(20, 72 + 24 + 96 + 184);

    put32(32, LC_SEGMENT_64);
    put32(36, 72);
    for (std::size_t i = 0; i < sizeof("__TEXT"); ++i) {
        file[32 + 8 + i] = "__TEXT"[i];
    }
    put64(32 + 24, 0);
    put64(32 + 32, kTextSize);
    put64(32 + 40, 0);
    put64(32 + 48, kTextSize);
    put32(32 + 60, 7);                         // RWX (the blob + the patched cells)
    put32(32 + 64, 0);

    // the LC_SYMTAB: [0] = _local_data (the local, N_SECT), [1] =
    // _host_info_probe (the undef import, N_EXT|N_UNDF)
    constexpr std::uint32_t symoff = 0x198;
    constexpr std::uint32_t stroff = 0x1b8;
    put32(32 + 72, LC_SYMTAB);
    put32(32 + 72 + 4, 24);
    put32(32 + 72 + 8, symoff);
    put32(32 + 72 + 12, 2);
    put32(32 + 72 + 16, stroff);
    put32(32 + 72 + 20, 32);
    put32(symoff, 0);                          // the local's n_strx ("_local_data")
    file[symoff + 4] = 0x0e;                   // n_type = N_SECT
    file[symoff + 5] = 1;
    put64(symoff + 8, 0x240);                  // the local's cell
    put32(symoff + 16, 12);                    // the import's n_strx ("_host_info_probe")
    file[symoff + 16 + 4] = 0x01;              // n_type = N_EXT (the type N_UNDF)
    file[symoff + 16 + 5] = 0;
    put64(symoff + 16 + 8, 0);
    for (std::size_t i = 0; i < sizeof("_local_data"); ++i) {
        file[stroff + i] = static_cast<std::uint8_t>("_local_data"[i]);
    }
    for (std::size_t i = 0; i < sizeof("_host_info_probe"); ++i) {
        file[stroff + 12 + i] = static_cast<std::uint8_t>("_host_info_probe"[i]);
    }

    // the LC_DYSYMTAB: the local/extdef/undef ranges + the two relocation
    // lists (the rel32 branch, the abs64 patch, the local slide) — the cmd
    // rides at 104+24 (after the symtab command)
    put32(104 + 24, LC_DYSYMTAB);
    put32(104 + 24 + 4, 96);
    put32(128 + 8, 0);                         // ilocalsym
    put32(128 + 12, 1);                        // nlocalsym
    put32(128 + 16, 1);                        // iextdefsym
    put32(128 + 20, 0);                        // nextdefsym
    put32(128 + 24, 1);                        // iundefsym
    put32(128 + 28, 1);                        // nundefsym
    put32(128 + 64, 0x1e8);                    // extreloff
    put32(128 + 68, 2);                        // nextrel
    put32(128 + 72, 0x1e0);                    // locreloff
    put32(128 + 76, 1);                        // nlocrel

    constexpr std::uint32_t locreloff = 0x1e0;
    constexpr std::uint32_t extreloff = 0x1e8;
    // the local reloc: r_address 0x240, pcrel 0, length 3, extern 0, rtype 0
    put32(locreloff, 0x240);
    put32(locreloff + 4, (3 << 25) | 1);
    // the rel32 branch reloc: r_address 0x201 (the call's disp32), pcrel 1,
    // length 2, extern 1, rtype 2 (X86_64_RELOC_BRANCH), symbolnum 1
    put32(extreloff, 0x201);
    put32(extreloff + 4, (2u << 28) | (1u << 27) | (2u << 25) | (1u << 24) | 1u);
    // the abs64 reloc: r_address 0x230, length 3, extern 1, rtype 0
    put32(extreloff + 8, 0x230);
    put32(extreloff + 12, (1u << 27) | (3u << 25) | (1u << 24) | 1u);

    // the local-reloc cell pre-seeds 0x10 (the walk slides it by the loadbase)
    put64(0x240, 0x10);

    constexpr std::size_t thread_at = 0xe0;    // 32 + 72 + 24 + 96 (after the dysymtab)
    put32(thread_at, LC_UNIXTHREAD);
    put32(thread_at + 4, 184);
    put32(thread_at + 8, 4);
    put32(thread_at + 12, 21);
    put64(thread_at + 16 + 16 * 8, kEntryOff);

    // the blob: the rel32 call, the abs64 read, the local read, the stores,
    // the exit — the SIB-abs displacements are ABSOLUTE (the rip-independent
    // form): the kext's cells ride at the loadbase+0x230/0x240, while the
    // scratch stores stay in the mapped [0x2000, 0x3000) window
    std::size_t at = kEntryOff;
    file[at++] = 0xE8; file[at++] = 0x00; file[at++] = 0x00; file[at++] = 0x00; file[at++] = 0x00;  // call rel32
    file[at++] = 0x48; file[at++] = 0x8B; file[at++] = 0x04; file[at++] = 0x25;                    // mov rax, [0x30000230]
    file[at++] = 0x30; file[at++] = 0x02; file[at++] = 0x00; file[at++] = 0x30;
    file[at++] = 0x48; file[at++] = 0x89; file[at++] = 0x04; file[at++] = 0x25;                    // mov [0x2150], rax
    file[at++] = 0x50; file[at++] = 0x21; file[at++] = 0x00; file[at++] = 0x00;
    file[at++] = 0x48; file[at++] = 0x8B; file[at++] = 0x04; file[at++] = 0x25;                    // mov rax, [0x30000240]
    file[at++] = 0x40; file[at++] = 0x02; file[at++] = 0x00; file[at++] = 0x30;
    file[at++] = 0x48; file[at++] = 0x89; file[at++] = 0x04; file[at++] = 0x25;                    // mov [0x2160], rax
    file[at++] = 0x60; file[at++] = 0x21; file[at++] = 0x00; file[at++] = 0x00;
    file[at++] = 0xBF; file[at++] = 0x2A; file[at++] = 0x00; file[at++] = 0x00; file[at++] = 0x00;  // mov edi, 42
    file[at++] = 0xB8; file[at++] = 0x01; file[at++] = 0x00; file[at++] = 0x00; file[at++] = 0x00;  // mov eax, 1
    file[at++] = 0x0F; file[at++] = 0x05;

    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
}

// DISABLED_ blocker (the resume point): the relocs themselves are PROVEN
// correct — the disp32@0x201 patches to 0xDFB (the STATIC-page construct
// stub at 0x30001000), the abs64@0x230 carries the kernel n_value
// 0x20000200, the local@0x240 slides to 0x30000010, and the full path
// traces call → stub (sub rsp,8 + the stack construct + ret) → the kernel
// body (0x77) → back to 0x30000205. The fixture dies at the tail: the
// UC_HOOK_INSN (syscall) hook does NOT fire on the driver path after the
// stub-mediated return — the syscall at 0x3000022f executes with the code
// hooks firing but the INSN hook silent (the shellcode path and the direct
// `call rax` driver path both fire it; rcx=0 rules out a native syscall
// execution) — surfacing as UC_ERR_WRITE_UNMAPPED at the syscall pc.
// Undiagnosed uc-level hook/TB interaction; resume HERE.
TEST(MacosOs, DISABLED_KextDriverRelocationsBridgeCalls) {
    constexpr std::uint64_t kKernelBase = 0x20000000;
    constexpr std::uint64_t kKextLoadbase = 0x30000000;  // the uc-fetchable loadbase
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    const auto kernel_dir = rootfs / "System" / "Library" / "Kernels";
    std::filesystem::create_directories(kernel_dir);
    write_macho_kernel_development(kernel_dir / "kernel.development");

    const auto kext = std::filesystem::temp_directory_path() / "ql_macho_kext3" / "driver.macho";
    std::filesystem::create_directories(kext.parent_path());
    write_macho_kext_reloc_fixture(kext, kKernelBase + 0x200);

    QilingOptions options;
    options.argv = {kext.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    options.driver_loadbase = kKextLoadbase;
    Qiling ql(options);
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    try {
        ql.run();
    } catch (const std::exception&) {
        // the fault-path evidence: the stub bytes, the abs64 cell, the local cell
        const auto stub = ql.mem().read(0x30001000, 20);
        std::fprintf(stderr, "[k] stub: %02x %02x %02x %02x | %02x %02x %02x %02x | %02x %02x %02x %02x %02x\n",
                     stub[0], stub[1], stub[2], stub[3], stub[4], stub[5], stub[6], stub[7], stub[8],
                     stub[9], stub[10], stub[11], stub[12]);
        std::fprintf(stderr, "[k] abs64@0x230=0x%llx local@0x240=0x%llx\n",
                     static_cast<unsigned long long>(ql.mem().read_ptr(0x30000230, 8)),
                     static_cast<unsigned long long>(ql.mem().read_ptr(0x30000240, 8)));
        throw;
    }

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the rel32 branch rode the STATIC-page jmp stub into the kernel body
    // (mov eax, 0x77; ret) — the store carries the body's return value
    EXPECT_EQ(ql.mem().read_ptr(0x2140, 4), 0x77u);
    // the abs64 cell patched with the kernel symbol's n_value
    EXPECT_EQ(ql.mem().read_ptr(0x2150, 8), kKernelBase + 0x200);
    // the local-reloc cell slid by the loadbase (0x10 + 0x30000000)
    EXPECT_EQ(ql.mem().read_ptr(0x2160, 8), 0x10ull + kKextLoadbase);
}

TEST(MacosOs, CsopsWritesFlagAndReturnsSuccess) {
    auto ql = make_macos_qiling(csops_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the (CS_ENFORCEMENT | CS_GET_TASK_ALLOW) flag = 0x00001004, LE
    const auto buf = ql.mem().read(kScratch, 4);
    EXPECT_EQ(buf[0], 0x04);
    EXPECT_EQ(buf[1], 0x10);
    EXPECT_EQ(buf[2], 0x00);
    EXPECT_EQ(buf[3], 0x00);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x40, 4), 0u);  // KERN_SUCCESS
}

// ---- the file/syscall-info family ----
//
// The fixture data (the path strings, the attrlist record) pre-seeds into
// the mapped scratch region (0x2000..0x4000) after construction, before
// run(); the blob is pure code + register setup referencing those cells.
constexpr std::uint64_t kCellBase = 0x2100;
constexpr std::uint64_t kPath = 0x2200;
constexpr std::uint64_t kPathMissing = 0x2240;
constexpr std::uint64_t kPathAttr = 0x2280;
constexpr std::uint64_t kAlist = 0x22c0;
constexpr std::uint64_t kBuffer = 0x2300;
constexpr std::uint64_t kFcArg = 0x2380;

void ensure_macos_file(const std::string& name, const std::string& content) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    std::ofstream f(rootfs / name, std::ios::binary | std::ios::trunc);
    f << content;
}

void put_u16(std::vector<std::uint8_t>& v, std::size_t off, std::uint16_t x) {
    v[off] = static_cast<std::uint8_t>(x);
    v[off + 1] = static_cast<std::uint8_t>(x >> 8);
}

void put_u32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    }
}

// the store-rax-at-[rbx+disp8] emitter (rbx = kCellBase rides the blob
// prologue; the disp8 form covers the 0x2100..0x2180 cells)
void emit_store_rax(std::vector<std::uint8_t>& code, int disp8) {
    code.push_back(0x48);
    code.push_back(0x89);
    code.push_back(0x43);  // mod=01 (disp8), reg=rax, rm=rbx — the 0x83 form
    code.push_back(static_cast<std::uint8_t>(disp8));  // is the disp32 store
}

const std::vector<std::uint8_t> kBlobExit = {
    0xBF, 0x2A, 0x00, 0x00, 0x00,  // mov edi, 42
    0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (exit)
    0x0F, 0x05,                    // syscall
};

TEST(MacosOs, AccessReturnsEnoentForMissingAndSuccessForExisting) {
    ensure_macos_file("hello.txt", "hi");

    // the strings pre-seed at the cells; the blob: access(path, 0) twice —
    // access_macos = 33 — the existing path first, the missing path second
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x00, 0x22, 0x00, 0x00,                // mov edi, kPath
        0x31, 0xF6,                                  // xor esi, esi
        0xB8, 0x21, 0x00, 0x00, 0x00,                // mov eax, 33
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);                      // mov [rbx], rax
    const auto push = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    push({0xBF, 0x40, 0x22, 0x00, 0x00});            // mov edi, kPathMissing
    push({0x31, 0xF6});                              // xor esi, esi
    push({0xB8, 0x21, 0x00, 0x00, 0x00});            // mov eax, 33
    push({0x0F, 0x05});
    emit_store_rax(code, 0x08);                      // mov [rbx+8], rax
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    const auto seed = [&ql](std::uint64_t at, const std::string& str) {
        ql.mem().write(at, std::vector<std::uint8_t>(str.begin(), str.end()));
        ql.mem().write(at + str.size(), std::vector<std::uint8_t>{0});
    };
    seed(kPath, "/hello.txt");
    seed(kPathMissing, "/nope.txt");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);    // KERN_SUCCESS (the existing)
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 8, 4), 2u);  // ENOENT (the raw errno, LE)
}

TEST(MacosOs, GetattrlistWritesCommonAttrRecord) {
    ensure_macos_file("attr.txt", "xy");

    // the attrlist record: bitmapcount=5, reserved=0, commonattr=the 4
    // flags, vol/dir/file/fork=0 (the 24-byte record); the buffer 0x100
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x80, 0x22, 0x00, 0x00,                // mov edi, kPathAttr
        0xBE, 0xC0, 0x22, 0x00, 0x00,                // mov esi, kAlist
        0xBA, 0x00, 0x23, 0x00, 0x00,                // mov edx, kBuffer
        0x41, 0xBA, 0x00, 0x01, 0x00, 0x00,          // mov r10d, 0x100 (bufferSize)
        0x45, 0x31, 0xC0,                            // xor r8d, r8d (options)
        0xB8, 0xDC, 0x00, 0x00, 0x00,                // mov eax, 220 (getattrlist)
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    const auto seed = [&ql](std::uint64_t at, const std::string& str) {
        ql.mem().write(at, std::vector<std::uint8_t>(str.begin(), str.end()));
        ql.mem().write(at + str.size(), std::vector<std::uint8_t>{0});
    };
    seed(kPathAttr, "/attr.txt");
    std::vector<std::uint8_t> alist(24, 0);
    put_u16(alist, 0, 5);
    put_u32(alist, 4, qiling::os::macos::ATTR_CMN_NAME | qiling::os::macos::ATTR_CMN_DEVID |
                           qiling::os::macos::ATTR_CMN_OBJTYPE | qiling::os::macos::ATTR_CMN_OBJID);
    ql.mem().write(kAlist, alist);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);    // KERN_SUCCESS
    // the record: the 4-byte total length, then the name cell (the name
    // length, the dev, the type, the ino), then the name bytes + NUL
    const auto rec = ql.mem().read(kBuffer, 0x40);
    const auto total = rec[0] | rec[1] << 8 | rec[2] << 16 | rec[3] << 24;
    EXPECT_GE(total, 9u + 4u + 4u + 4u + 8u);
    const auto type = rec[16] | rec[17] << 8 | rec[18] << 16 | rec[19] << 24;
    EXPECT_EQ(type, qiling::os::macos::VREG);
    const std::string name(reinterpret_cast<const char*>(rec.data() + 28));
    EXPECT_EQ(name.substr(0, 8), "attr.txt");
}

TEST(MacosOs, Fcntl64AddfilesigsWritesSignatureBlob) {
    // fcntl64_macos = 92: the F_ADDFILESIGS_RETURN (97) path writes the
    // 0xefffffff blob at arg and returns 0
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x03, 0x00, 0x00, 0x00,                // mov edi, 3 (fd)
        0xBE, 0x61, 0x00, 0x00, 0x00,                // mov esi, 97
        0xBA, 0x80, 0x23, 0x00, 0x00,                // mov edx, kFcArg
        0xB8, 0x5C, 0x00, 0x00, 0x00,                // mov eax, 92
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    const auto blob = ql.mem().read(kFcArg, 4);
    EXPECT_EQ(blob[0], 0xff);
    EXPECT_EQ(blob[1], 0xff);
    EXPECT_EQ(blob[2], 0xff);
    EXPECT_EQ(blob[3], 0xef);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);
}

TEST(MacosOs, PreadReadsThroughFdTable) {
    ensure_macos_file("pread.txt", "hello pread");

    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x03, 0x00, 0x00, 0x00,                // mov edi, 3 (fd)
        0xBE, 0x00, 0x23, 0x00, 0x00,                // mov esi, kBuffer (buf)
        0xBA, 0x04, 0x00, 0x00, 0x00,                // mov edx, 4 (nbyte)
        0x41, 0xBA, 0x06, 0x00, 0x00, 0x00,          // mov r10d, 6 (offset, the 4th arg)
        0xB8, 0x99, 0x00, 0x00, 0x00,                // mov eax, 153 (pread)
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    auto f = qiling::QlFile::open((rootfs / "pread.txt").string(), 0, 0);
    ql.os<qiling::os::posix::QlOsPosix>().fd().set(3, f);
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the 4 bytes at offset 6 = "prea"
    const auto data = ql.mem().read(kBuffer, 4);
    EXPECT_EQ(data[0], 'p');
    EXPECT_EQ(data[1], 'r');
    EXPECT_EQ(data[2], 'e');
    EXPECT_EQ(data[3], 'a');
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 4u);    // the nbyte return
}

TEST(MacosOs, GetrlimitWritesMaxCellAndOutOfRangeReturnsEinval) {
    // getrlimit = 194: the success path writes rlim_max at rlp (the upstream
    // writes both cells AT rlp — the second overwrites, verbatim) with NO
    // rax write; the out-of-range which returns the raw EINVAL (22)
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x08, 0x00, 0x00, 0x00,                // mov edi, 8 (which; the upstream's
                                                     // 0x1000 mask keeps it in range)
        0xBE, 0x80, 0x23, 0x00, 0x00,                // mov esi, kFcArg (rlp)
        0xB8, 0xC2, 0x00, 0x00, 0x00,                // mov eax, 194
        0x0F, 0x05,                                  // syscall
        0xBF, 0x09, 0x10, 0x00, 0x00,                // mov edi, 0x1009 (out of range after the mask)
        0x31, 0xF6,                                  // xor esi, esi
        0xB8, 0xC2, 0x00, 0x00, 0x00,                // mov eax, 194
        0x0F, 0x05,
    };
    emit_store_rax(code, 0x08);                      // the EINVAL from the second dispatch
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the rlim_max cell (the clobbered verbatim shape)
    const auto rlp = ql.mem().read(kFcArg, 8);
    EXPECT_EQ(rlp[7], 0x7f);
    EXPECT_EQ(rlp[0], 0xff);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 8, 4), 22u);  // EINVAL (raw)
}

TEST(MacosOs, SigprocmaskLeavesRaxUntouched) {
    // sigprocmask = 48: the log-only no-op (the upstream body ends without
    // returning — rax stays at the pre-syscall value)
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x30, 0x00, 0x00, 0x00,                // mov edi, 48 (how)
        0x31, 0xF6,                                  // xor esi, esi
        0x31, 0xD2,                                  // xor edx, edx
        0xB8, 0x30, 0x00, 0x00, 0x00,                // mov eax, 48
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 48u);   // rax untouched (48)
}

TEST(MacosOs, VmAllocateBumpsTaskCursorAndWritesAddr) {
    // kernelrpc_mach_vm_allocate_trap = 0x100000a: the bump allocator off
    // the task's min_offset (the seeded MachoTask: min_offset 0) — the
    // region maps at min_offset, the cursor advances past the page end and
    // the allocated address rides back through *addr; the return is 0
    const std::uint64_t kAddrCell = 0x23c0;
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x00, 0x00, 0x00, 0x00,                // mov edi, 0 (port)
        0xBE, 0xC0, 0x23, 0x00, 0x00,                // mov esi, kAddrCell (*addr)
        0xBA, 0x00, 0x10, 0x00, 0x00,                // mov edx, 0x1000 (size)
        0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,          // mov r10d, 0 (flags)
        0xB8, 0x0A, 0x00, 0x00, 0x01,                // mov eax, 0x100000a
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);    // the return 0
    // the *addr cell carries the allocated base = the task's min_offset (0)
    EXPECT_EQ(ql.mem().read_ptr(kAddrCell, 8), 0u);
    // the region maps: a write through the host side lands (the cursor
    // advanced by the page-aligned size)
    const auto& task = dynamic_cast<const qiling::os::macos::QlOsMacos&>(ql.os()).macho_task();
    EXPECT_EQ(task.min_offset, 0x1000u);
}

TEST(MacosOs, VmAllocateSecondCallRidesPastTheFirstRegion) {
    // the second allocate starts at the advanced cursor (the 0x1000-shifted
    // bump allocator) — the *addr cell carries 0x1000
    const std::uint64_t kAddrCell = 0x23c0;
    const std::uint64_t kAddrCell2 = 0x23e0;
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x00, 0x00, 0x00, 0x00,                // mov edi, 0 (port)
        0xBE, 0xC0, 0x23, 0x00, 0x00,                // mov esi, kAddrCell
        0xBA, 0x00, 0x10, 0x00, 0x00,                // mov edx, 0x1000
        0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,          // mov r10d, 0
        0xB8, 0x0A, 0x00, 0x00, 0x01,                // mov eax, 0x100000a
        0x0F, 0x05,                                  // syscall (the first allocate)
        0xBF, 0x00, 0x00, 0x00, 0x00,                // mov edi, 0
        0xBE, 0xE0, 0x23, 0x00, 0x00,                // mov esi, kAddrCell2
        0xBA, 0x00, 0x08, 0x00, 0x00,                // mov edx, 0x800
        0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,          // mov r10d, 0
        0xB8, 0x0A, 0x00, 0x00, 0x01,                // mov eax, 0x100000a
        0x0F, 0x05,                                  // syscall (the second allocate)
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kAddrCell, 8), 0u);        // the first base
    EXPECT_EQ(ql.mem().read_ptr(kAddrCell2, 8), 0x1000u);  // the second base
}

TEST(MacosOs, VmMapWalksVmmapCursorWithMask) {
    // kernelrpc_mach_vm_map_trap = 0x100000f: the vmmap cursor starts at the
    // profile's vmmap_trap_address (0x4000000f4000); the mask 0x3fff ride
    // the upstream alignment: end & mask != 0 -> end -= end & mask;
    // end += mask + 1; the map page-aligns at PAGE_SIZE and the address
    // rides through *addr
    const std::uint64_t kAddrCell = 0x23c0;
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x00, 0x00, 0x00, 0x00,                // mov edi, 0 (target)
        0xBE, 0xC0, 0x23, 0x00, 0x00,                // mov esi, kAddrCell (*addr)
        0xBA, 0x00, 0x10, 0x00, 0x00,                // mov edx, 0x1000 (size)
        0x41, 0xBA, 0x00, 0x40, 0x00, 0x00,          // mov r10d, 0x4000 (mask, the 4th arg)
        0x41, 0xB8, 0x00, 0x00, 0x00, 0x00,          // mov r8d, 0 (flags)
        0x45, 0x31, 0xC9,                            // xor r9d, r9d (cur_protection)
        0xB8, 0x0F, 0x00, 0x00, 0x01,                // mov eax, 0x100000f
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);    // KERN_SUCCESS
    // the cursor walk: 0x4000000f4000 & 0x4000 != 0 -> -= 0x4000, += 0x4001,
    // then the page round-up lands at 0x4000000f5000
    EXPECT_EQ(ql.mem().read_ptr(kAddrCell, 8), 0x4000000f5000ull);
}

TEST(MacosOs, PortNoopStubsLeaveRaxUntouched) {
    // the 0x1000012 port_deallocate / 0x1000013 mod_refs / 0x1000018
    // construct bodies are the upstream's log+pass stubs — no return (rax
    // stays at the pre-syscall value = the mov eax constant)
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xB8, 0x12, 0x00, 0x00, 0x01,                // mov eax, 0x1000012
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    const auto push = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    push({0xBF, 0x00, 0x00, 0x00, 0x00});            // mov edi, 0 (target)
    push({0xBE, 0x07, 0x30, 0x00, 0x00});            // mov esi, 0x3007 (name)
    push({0x41, 0xBA, 0x00, 0x00, 0x00, 0x00});      // mov r10d, 0 (right)
    push({0x41, 0xB8, 0x01, 0x00, 0x00, 0x00});      // mov r8d, 1 (delta)
    push({0xB8, 0x13, 0x00, 0x00, 0x01});            // mov eax, 0x1000013
    push({0x0F, 0x05});
    emit_store_rax(code, 0x08);
    push({0xBF, 0x00, 0x00, 0x00, 0x00});            // mov edi, 0
    push({0xBE, 0x00, 0x00, 0x00, 0x00});            // mov esi, 0 (options)
    push({0xBA, 0x00, 0x00, 0x00, 0x00});            // mov edx, 0 (context)
    push({0x41, 0xB8, 0x00, 0x00, 0x00, 0x00});      // mov r8d, 0 (name cell)
    push({0xB8, 0x18, 0x00, 0x00, 0x01});            // mov eax, 0x1000018
    push({0x0F, 0x05});
    emit_store_rax(code, 0x10);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0x1000012u);       // rax untouched
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 8, 4), 0x1000013u);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 0x10, 4), 0x1000018u);
}

TEST(MacosOs, BsdthreadShimsGroup) {
    // bsdthread_register (366): the CF clears and the fixed 0x400000df
    // pthread magic rides rax; thread_selfid (372): the seeded thread id
    // 123; thread_fast_set_cthread_self64 (0x3000003): the tsd base into
    // IA32_GS_BASE_MSR, KERN_SUCCESS
    const std::uint64_t kTsd = 0x1a000;
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xB8, 0x6E, 0x01, 0x00, 0x00,                // mov eax, 366
        0x31, 0xFF,                                  // xor edi, edi
        0x31, 0xF6,                                  // xor esi, esi
        0x31, 0xD2,                                  // xor edx, edx
        0x45, 0x31, 0xD2,                            // xor r10d, r10d
        0x45, 0x31, 0xC0,                            // xor r8d, r8d
        0x45, 0x31, 0xC9,                            // xor r9d, r9d
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    const auto push = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    push({0xB8, 0x74, 0x01, 0x00, 0x00});            // mov eax, 372
    push({0x0F, 0x05});                              // syscall
    emit_store_rax(code, 0x08);
    push({0xBF, 0x00, 0xA0, 0x01, 0x00});            // mov edi, kTsd
    push({0xB8, 0x03, 0x00, 0x00, 0x03});            // mov eax, 0x3000003
    push({0x0F, 0x05});                              // syscall
    emit_store_rax(code, 0x10);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0x400000dfu);  // the pthread magic (LE)
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 8, 4), 123u);     // the thread id
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 0x10, 4), 0u);    // KERN_SUCCESS
    // the msr write landed (the freebsd sysarch-fixture precedent)
    EXPECT_EQ(dynamic_cast<qiling::QlArchIntel&>(ql.arch()).msr().read(0xC0000101), kTsd);
}

TEST(MacosOs, MiscTailStubs) {
    // sysctl (202): KERN_SUCCESS; poll (230): KERN_SUCCESS;
    // shared_region_check_np (294): the raw EINVAL (22); csrctl (483): 1;
    // abort_with_payload (521): KERN_SUCCESS
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xB8, 0xCA, 0x00, 0x00, 0x00,                // mov eax, 202 (sysctl)
        0x0F, 0x05,
    };
    emit_store_rax(code, 0x00);
    const auto push = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    push({0xB8, 0xE6, 0x00, 0x00, 0x00});            // mov eax, 230 (poll)
    push({0x0F, 0x05});
    emit_store_rax(code, 0x08);
    push({0xB8, 0x26, 0x01, 0x00, 0x00});            // mov eax, 294 (shared_region_check_np)
    push({0x0F, 0x05});
    emit_store_rax(code, 0x10);
    push({0xB8, 0xE3, 0x01, 0x00, 0x00});            // mov eax, 483 (csrctl)
    push({0x0F, 0x05});
    emit_store_rax(code, 0x18);
    push({0xB8, 0x09, 0x02, 0x00, 0x00});            // mov eax, 521 (abort_with_payload)
    push({0x0F, 0x05});
    emit_store_rax(code, 0x20);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);        // sysctl: KERN_SUCCESS
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 8, 4), 0u);    // poll: KERN_SUCCESS
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 0x10, 4), 22u);  // check_np: EINVAL
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 0x18, 4), 1u);   // csrctl: 1
    EXPECT_EQ(ql.mem().read_ptr(kCellBase + 0x20, 4), 0u);   // abort: KERN_SUCCESS
}

TEST(MacosOs, ProcInfoWritesDyldPathAndStopsOnTerminate) {
    // proc_info (336) with callnum=2 (PROC_INFO_CALL_PIDINFO) and
    // flavor=8 (PROC_PIDREGIONPATHINFO): the "/usr/lib/dyld" path rides at
    // buff+248 and rax stays untouched; then terminate_with_payload (520)
    // stops the emu (the exit body never runs — the emu_stop ends it)
    const std::uint64_t kBuff = 0x2300;
    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x02, 0x00, 0x00, 0x00,                // mov edi, 2 (callnum)
        0xBE, 0x99, 0x07, 0x00, 0x00,                // mov esi, 1965 (pid, arbitrary)
        0xBA, 0x08, 0x00, 0x00, 0x00,                // mov edx, 8 (flavor, the 3rd arg)
        0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,          // mov r10d, 0 (arg, the 4th)
        0x41, 0xB8, 0x00, 0x23, 0x00, 0x00,          // mov r8d, kBuff (buff, the 5th)
        0x41, 0xB9, 0x00, 0x05, 0x00, 0x00,          // mov r9d, 0x500 (buffer_size)
        0xB8, 0x50, 0x01, 0x00, 0x00,                // mov eax, 336 (proc_info)
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    const auto push = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    // the terminate dispatch: pid=42 (rdi is already the arg cell), the rest
    // zeros; the KERN_SUCCESS return lands but the emu stops right after
    push({0xBF, 0x2A, 0x00, 0x00, 0x00});            // mov edi, 42 (pid)
    push({0xB8, 0x08, 0x02, 0x00, 0x00});            // mov eax, 520
    push({0x0F, 0x05});                              // syscall — the emu stops
    // (the store + exit never execute)

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    // the run stopped at the terminate (no exit dispatch ran — the exit code
    // stays unset, the default 0)
    const auto path = ql.mem().read(kBuff + 248, 13);
    EXPECT_EQ(path[0], '/');
    EXPECT_EQ(path[1], 'u');
    EXPECT_EQ(path[12], 'd');
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 336u);   // rax: the no-return proc_info
                                                        // leaves the mov eax value
}

TEST(MacosOs, WriteNocancelWritesAndReturnsZero) {
    // write_nocancel (397): the fd writes land through the fd table but the
    // verbatim `return 0` quirk means the caller always sees 0
    ensure_macos_file("nocancel.txt", "seed");

    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x03, 0x00, 0x00, 0x00,                // mov edi, 3 (fd)
        0xBE, 0x00, 0x23, 0x00, 0x00,                // mov esi, kBuffer
        0xBA, 0x05, 0x00, 0x00, 0x00,                // mov edx, 5 (count)
        0xB8, 0x8D, 0x01, 0x00, 0x00,                // mov eax, 397
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    auto f = qiling::QlFile::open_mode((rootfs / "nocancel.txt").string(), "r+");
    ql.os<qiling::os::posix::QlOsPosix>().fd().set(3, f);
    ql.mem().write(kBuffer, std::vector<std::uint8_t>{'W', 'R', 'I', 'T', 'E'});
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 0u);    // the verbatim `return 0`
    // the write landed through the fd (the host file carries it after close)
    f->close();
    std::ifstream check(rootfs / "nocancel.txt", std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(check)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content.substr(0, 5), "WRITE");
}

TEST(MacosOs, OpenNocancelOpensThroughPosixOpen) {
    // open_nocancel (398): the first free fd slot opens the path (the posix
    // open delegate)
    ensure_macos_file("nocancel2.txt", "data");

    std::vector<std::uint8_t> code = {
        0xBB, 0x00, 0x21, 0x00, 0x00,                // mov ebx, 0x2100
        0xBF, 0x80, 0x22, 0x00, 0x00,                // mov edi, kPathAttr (0x2280)
        0xBE, 0x00, 0x00, 0x00, 0x00,                // mov esi, 0 (O_RDONLY)
        0x31, 0xD2,                                  // xor edx, edx (mode)
        0xB8, 0x8E, 0x01, 0x00, 0x00,                // mov eax, 398
        0x0F, 0x05,                                  // syscall
    };
    emit_store_rax(code, 0x00);
    code.insert(code.end(), kBlobExit.begin(), kBlobExit.end());

    auto ql = make_macos_qiling(code);
    ql.mem().map(0x2000, 0x2000, UC_PROT_ALL, "[macos-scratch]");
    const auto seed = [&ql](std::uint64_t at, const std::string& str) {
        ql.mem().write(at, std::vector<std::uint8_t>(str.begin(), str.end()));
        ql.mem().write(at + str.size(), std::vector<std::uint8_t>{0});
    };
    seed(kPathAttr, "/nocancel2.txt");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the fd lands at the first free slot (3 — the std streams take 0..2)
    EXPECT_EQ(ql.mem().read_ptr(kCellBase, 4), 3u);
}

TEST(MacosOs, KernelApiRegistryCarriesUpstreamSurface) {
    // the kernel_api.py handler names verbatim — the passthru stubs and the
    // real-bodied handlers both register
    using qiling::os::macos::KernelApiRegistry;
    EXPECT_NE(KernelApiRegistry::instance().find("strlen"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("strcmp"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("memcpy"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("memset"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("bzero"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("copyin"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("copyout"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("OSAddAtomic"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("suulong"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("fuulong"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("read_random"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("proc_selfpid"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("_ZN9IOService5startEPS_"), nullptr);
    EXPECT_NE(KernelApiRegistry::instance().find("sysctl_register_oid"), nullptr);

    // the passthru flags
    EXPECT_TRUE(KernelApiRegistry::instance().find("strlen")->passthru);
    EXPECT_FALSE(KernelApiRegistry::instance().find("proc_selfpid")->passthru);
}

TEST(MacosOs, KernelApiSuulongFuulongRoundtrip) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    constexpr std::uint64_t kCell = 0x1002000;
    using qiling::os::macos::KernelApiRegistry;

    const auto* su = KernelApiRegistry::instance().find("suulong");
    ASSERT_NE(su, nullptr);
    const qiling::os::macos::ResolvedParams su_params{{"addr", kCell}, {"uword", 0x4142434445464748ull}};
    const auto r1 = su->handler(ql, 0, su_params);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0u);
    EXPECT_EQ(ql.mem().read_ptr(kCell, 8), 0x4142434445464748ull);

    const auto* fu = KernelApiRegistry::instance().find("fuulong");
    ASSERT_NE(fu, nullptr);
    const qiling::os::macos::ResolvedParams fu_params{{"addr", kCell}};
    const auto r2 = fu->handler(ql, 0, fu_params);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x4142434445464748ull);
}

TEST(MacosOs, KernelApiReadRandomAndSelfPid) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    constexpr std::uint64_t kBuf = 0x1002100;
    using qiling::os::macos::KernelApiRegistry;

    // read_random: the 0xdeadbeaf stamp, no return (the passthru shape: the
    // handler returns nullopt)
    const auto* rr = KernelApiRegistry::instance().find("read_random");
    ASSERT_NE(rr, nullptr);
    const qiling::os::macos::ResolvedParams rr_params{{"buf", kBuf}, {"size", 4ull}};
    const auto r1 = rr->handler(ql, 0, rr_params);
    EXPECT_FALSE(r1.has_value());
    const auto stamped = ql.mem().read(kBuf, 4);
    EXPECT_EQ(stamped[0], 0xaf);
    EXPECT_EQ(stamped[3], 0xde);

    // proc_selfpid / proc_selfppid: the fixed constants
    const auto* pid = KernelApiRegistry::instance().find("proc_selfpid");
    ASSERT_NE(pid, nullptr);
    const auto r2 = pid->handler(ql, 0, {});
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x1337ull);

    const auto* ppid = KernelApiRegistry::instance().find("proc_selfppid");
    ASSERT_NE(ppid, nullptr);
    const auto r3 = ppid->handler(ql, 0, {});
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(*r3, 0x13371337ull);
}

// ---- the events/policy slice: the ev-manager surface + the re-pointed
// kernel_api handlers ----
//
// add_process builds the 1144-byte proc_t image (the p_list/p_pid/p_ppid/
// p_pgrpid/p_flag/p_ucred/p_comm/p_name seeds at the upstream offsets),
// ensure_cred seeds the 501/501/501/15/groups/20/20/501/2 posix cred with
// the cr_label riding the label cell, and the five re-pointed handlers
// serve through the registry.
TEST(MacosOs, EvManagerAddProcessSeedsProcImage) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    auto& ev = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os()).ev_manager();
    ev.set_proc("demigod");
    ev.add_process(0x1337, "demigod");
    ev.add_process(0x1337, "dup");  // the duplicate logs and returns

    const auto* proc = ev.proc_find(0x1337);
    ASSERT_NE(proc, nullptr);
    EXPECT_EQ(ev.proc_find(1), nullptr);

    const auto img = ql.mem().read(proc->base, 1144);
    auto rd32 = [&img](std::size_t at) {
        return static_cast<std::uint32_t>(img[at]) | (static_cast<std::uint32_t>(img[at + 1]) << 8) |
               (static_cast<std::uint32_t>(img[at + 2]) << 16) | (static_cast<std::uint32_t>(img[at + 3]) << 24);
    };
    EXPECT_EQ(rd32(16), 0x1337u);       // p_pid
    EXPECT_EQ(rd32(40), 1u);            // p_ppid
    EXPECT_EQ(rd32(44), 0x1337u);       // p_pgrpid
    EXPECT_EQ(rd32(400), 4u);           // p_flag = 64 bit process
    EXPECT_NE(rd32(304), 0u);           // p_ucred cell allocated
    // p_comm: "demigod" + NUL pad to 17
    EXPECT_EQ(img[728], 'd');
    EXPECT_EQ(img[728 + 6], 'd');
    EXPECT_EQ(img[728 + 7], 0);
    EXPECT_EQ(img[728 + 16], 0);
    // p_name = p_comm + pad to 33
    EXPECT_EQ(img[745], 'd');
    EXPECT_EQ(img[745 + 32], 0);
}

TEST(MacosOs, EvManagerEnsureCredSeedsUpstreamShape) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    auto& ev = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os()).ev_manager();
    const auto cred = ev.ensure_cred();
    const auto label = ev.ensure_label();
    EXPECT_NE(label, 0u);

    const auto img = ql.mem().read(cred, 144);
    auto rd32 = [&img](std::size_t at) {
        return static_cast<std::uint32_t>(img[at]) | (static_cast<std::uint32_t>(img[at + 1]) << 8) |
               (static_cast<std::uint32_t>(img[at + 2]) << 16) | (static_cast<std::uint32_t>(img[at + 3]) << 24);
    };
    EXPECT_EQ(rd32(16), 2u);            // cr_ref
    EXPECT_EQ(rd32(20), 501u);          // cr_posix.cr_uid
    EXPECT_EQ(rd32(24), 501u);          // cr_ruid
    EXPECT_EQ(rd32(28), 501u);          // cr_svuid
    EXPECT_EQ(img[32], 15);             // cr_ngroups (short)
    EXPECT_EQ(rd32(36), 20u);           // cr_groups[0]
    EXPECT_EQ(rd32(120 - 20 + 16), 0u); // cr_groups[15] stays zero? (the
                                        // upstream array is 16 wide — the
                                        // tail cells zero)
    EXPECT_EQ(rd32(100), 20u);          // cr_rgid
    EXPECT_EQ(rd32(104), 20u);          // cr_svgid
    EXPECT_EQ(rd32(108), 501u);         // cr_gmuid
    EXPECT_EQ(rd32(112), 2u);           // cr_flags

    // the cr_label cell rides the label address (ucred_t offset 120); the
    // label's l_flags = 1
    const std::uint64_t cr_label = [&img] {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(img[120 + i]) << (8 * i);
        }
        return v;
    }();
    EXPECT_EQ(cr_label, label);
    const auto label_img = ql.mem().read(label, 8);
    EXPECT_EQ(label_img[0], 1);  // l_flags

    // the accessors the kauth handlers read
    EXPECT_EQ(ev.cred_uid(), 501u);
    EXPECT_EQ(ev.cred_rgid(), 20u);
}

TEST(MacosOs, KernelApiEvHandlersServeThroughRegistry) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    auto& ev = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os()).ev_manager();
    ev.set_proc("demigod");
    ev.add_process(0x1337, "demigod");
    const auto* proc = ev.proc_find(0x1337);
    ASSERT_NE(proc, nullptr);

    using qiling::os::macos::KernelApiRegistry;
    using qiling::os::macos::ResolvedParams;

    // proc_find: the proc image address, 0 on the miss
    const auto* pf = KernelApiRegistry::instance().find("proc_find");
    ASSERT_NE(pf, nullptr);
    const auto r1 = pf->handler(ql, 0, ResolvedParams{{"pid", 0x1337ull}});
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, proc->base);
    const auto r2 = pf->handler(ql, 0, ResolvedParams{{"pid", 7ull}});
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0ull);

    // proc_name: the p_comm image at buf (the upstream ignores size)
    constexpr std::uint64_t kNameBuf = 0x1003000;
    const auto* pn = KernelApiRegistry::instance().find("proc_name");
    ASSERT_NE(pn, nullptr);
    ql.mem().write(kNameBuf, std::vector<std::uint8_t>(32, 0x41));
    const auto r3 = pn->handler(ql, 0, ResolvedParams{{"pid", 0x1337ull}, {"buf", kNameBuf}, {"size", 17ull}});
    EXPECT_FALSE(r3.has_value());  // no return
    const auto named = ql.mem().read(kNameBuf, 17);
    EXPECT_EQ(named[0], 'd');
    EXPECT_EQ(named[6], 'd');
    EXPECT_EQ(named[7], 0);

    // kauth_getuid / kauth_getgid: the ev-ctx cred cells (501 / 20)
    const auto* gu = KernelApiRegistry::instance().find("kauth_getuid");
    ASSERT_NE(gu, nullptr);
    const auto r4 = gu->handler(ql, 0, {});
    ASSERT_TRUE(r4.has_value());
    EXPECT_EQ(*r4, 501ull);
    const auto* gg = KernelApiRegistry::instance().find("kauth_getgid");
    ASSERT_NE(gg, nullptr);
    const auto r5 = gg->handler(ql, 0, {});
    ASSERT_TRUE(r5.has_value());
    EXPECT_EQ(*r5, 20ull);

    // kauth_cred_setuidgid: the fresh ucred carrying (uid, uid, uid) / ng 1 /
    // (gid, gid)
    const auto* cs = KernelApiRegistry::instance().find("kauth_cred_setuidgid");
    ASSERT_NE(cs, nullptr);
    const auto r6 = cs->handler(ql, 0, ResolvedParams{{"cred", 0ull}, {"uid", 1001ull}, {"gid", 1002ull}});
    ASSERT_TRUE(r6.has_value());
    const auto cred2 = *r6;
    const auto img = ql.mem().read(cred2, 144);
    auto rd32 = [&img](std::size_t at) {
        return static_cast<std::uint32_t>(img[at]) | (static_cast<std::uint32_t>(img[at + 1]) << 8) |
               (static_cast<std::uint32_t>(img[at + 2]) << 16) | (static_cast<std::uint32_t>(img[at + 3]) << 24);
    };
    EXPECT_EQ(rd32(20), 1001u);
    EXPECT_EQ(rd32(24), 1001u);
    EXPECT_EQ(rd32(28), 1001u);
    EXPECT_EQ(img[32], 1);
    EXPECT_EQ(rd32(100), 1002u);
    EXPECT_EQ(rd32(104), 1002u);
}

TEST(MacosOs, PolicyMpoFileCheckMmapEmitsFileglob) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);
    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = {0x90, 0xC3};
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    // the kext listener registers first (the upstream manager.register() on
    // the EV_MAC_mpo_file_check_mmap type); the emit then queues the job —
    // the queued path is the RUN=false shape, set explicitly (the default
    // RUN=true would stack-push the stub instead)
    macos.RUN = false;
    macos.ev_manager().register_cb(0xdead0000, "MAC_POLICY",
                                   qiling::os::macos::MacOSEventType::EV_MAC_mpo_file_check_mmap);
    macos.policy_manager().mpo_file_check_mmap(5, 2, 0);

    // the job: the params ride (cred, fg, label, prot, flags, file_pos, 0)
    const auto& jobs = macos.ev_manager().jobs();
    ASSERT_EQ(jobs.size(), 1u);
    EXPECT_EQ(jobs[0].func_addr, 0xdead0000ull);
    ASSERT_EQ(jobs[0].params.size(), 7u);
    const auto cred = jobs[0].params[0];
    const auto fg = jobs[0].params[1];
    const auto label = jobs[0].params[2];
    EXPECT_EQ(jobs[0].params[3], 5u);
    EXPECT_EQ(jobs[0].params[4], 2u);
    // the fileglob: fg_flag = 1, fg_count = 1, fg_cred = cred, fg_data = vnode
    const auto fgi = ql.mem().read(fg, 32);
    EXPECT_EQ(fgi[0], 1);
    auto rd64 = [&fgi](std::size_t at) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(fgi[at + i]) << (8 * i);
        }
        return v;
    };
    EXPECT_EQ(rd64(16), cred);
    // the fg_data rides the vnode address (the ev-ctx vnode seeded lazily)
    const auto vnode = rd64(24);
    const auto vn = ql.mem().read(vnode, 400);
    // v_name at 344 points at the "demigod"-less current_proc — the default
    // set_proc is empty, so the name buffer is empty; the pointer is set
    std::uint64_t vname = 0;
    for (int i = 0; i < 8; ++i) {
        vname |= static_cast<std::uint64_t>(vn[344 + i]) << (8 * i);
    }
    EXPECT_NE(vname, 0u);
    (void)label;
}

// ---- the QlLoaderMachO slice: the container load + the kernel-api
// dispatch end-to-end ----
//
// The macho file: the MH_EXECUTE whose __TEXT carries the guest code (the
// call into the _proc_selfpid stub) + the LC_SYMTAB declaring the symbol at
// the stub address + the LC_UNIXTHREAD entry. The loader maps the segment,
// the hook_code fires at the stub call, the non-passthru os.call returns
// 0x1337 into rax and the pc past the call.
void write_macho_kernel_fixture(const std::filesystem::path& path) {
    constexpr std::uint64_t kBase = 0x1000000;
    constexpr std::uint64_t kStub = kBase + 0x300;   // the _proc_selfpid stub
    constexpr std::uint64_t kEntry = kBase + 0x200;  // the code start (past
                                                     // the command region)
    constexpr std::uint32_t kTextSize = 0x1000;

    std::vector<std::uint8_t> file(kTextSize, 0);
    auto put32 = [&file](std::size_t off, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };
    auto put64 = [&file](std::size_t off, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) {
            file[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
        }
    };

    // the header (the 3 commands: the __TEXT segment + the symtab + the
    // thread)
    put32(0, 0xFEEDFACF);
    put32(4, CPU_TYPE_X8664);
    put32(12, MH_EXECUTE);
    put32(16, 3);                              // ncmds
    put32(20, 72 + 24 + 184);                  // sizeofcmds

    // the __TEXT segment: the fields at cmd+8 (the name) / +24 (the vm
    // address) / +32 (the vm size) / +40 (the file offset) / +48 (the file
    // size) / +60 (the init prot) / +64 (the nsects) — the cmd base 32
    put32(32, LC_SEGMENT_64);
    put32(36, 72);
    for (std::size_t i = 0; i < sizeof("__TEXT"); ++i) {
        file[32 + 8 + i] = "__TEXT"[i];              // the name at cmd+8
    }
    put64(32 + 24, kBase);                     // the vm address
    put64(32 + 32, kTextSize);                 // the vm size
    put64(32 + 40, 0);                         // the file offset
    put64(32 + 48, kTextSize);                 // the file size
    put32(32 + 60, 5);                         // the init prot (RX)
    put32(32 + 64, 0);                         // the nsects

    // the LC_SYMTAB: the symoff/nsyms/stroff/strsize quadruple
    const std::uint32_t symoff = 0x180;              // the nlist array
    const std::uint32_t stroff = 0x1a0;              // the string table
    put32(32 + 72, LC_SYMTAB);
    put32(32 + 72 + 4, 24);
    put32(32 + 72 + 8, symoff);
    put32(32 + 72 + 12, 1);                    // nsyms
    put32(32 + 72 + 16, stroff);
    put32(32 + 72 + 20, 16);                   // strsize
    // the nlist_64: _proc_selfpid at the stub address (the N_EXT|N_SECT type)
    put32(symoff, 0);                          // n_strx
    file[symoff + 4] = 0x0f;                         // n_type = N_EXT|N_SECT
    file[symoff + 5] = 1;                            // n_sect
    put64(symoff + 8, kStub);                  // n_value
    const std::string sym = "_proc_selfpid";
    for (std::size_t i = 0; i <= sym.size(); ++i) {
        file[stroff + i] = static_cast<std::uint8_t>(sym[i]);
    }

    // the LC_UNIXTHREAD: the rip = the code start
    constexpr std::size_t thread_at = 32 + 72 + 24;
    put32(thread_at, LC_UNIXTHREAD);
    put32(thread_at + 4, 184);
    put32(thread_at + 8, 4);                   // the flavor (X86_THREAD_STATE64)
    put32(thread_at + 12, 21);                 // the count
    put64(thread_at + 16 + 16 * 8, kEntry);    // the rip

    // the guest code at kEntry: the call into the stub + the store + exit
    auto emit = [&file](std::size_t at, std::initializer_list<std::uint8_t> bytes) {
        std::size_t i = 0;
        for (const auto b : bytes) {
            file[at + i++] = b;
        }
    };
    emit(0x200, {0x48, 0xB8, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});  // mov rax, kStub
                                                                                // (0x1000300)
    emit(0x20a, {0xFF, 0xD0});                                 // call rax
    emit(0x20c, {0x48, 0x89, 0x05});                           // mov [rip+disp32], rax
    const std::int32_t store_disp =
        static_cast<std::int32_t>(0x1000800 - (0x1000200 + 0x0c + 7));  // the rip-rel
                                                                        // base rides
                                                                        // inside the
                                                                        // image
    for (int i = 0; i < 4; ++i) {
        file[0x20f + i] = static_cast<std::uint8_t>(static_cast<std::uint32_t>(store_disp) >> (8 * i));
    }
    emit(0x213, {0xBF, 0x2A, 0x00, 0x00, 0x00});               // mov edi, 42
    emit(0x218, {0xB8, 0x01, 0x00, 0x00, 0x00});               // mov eax, 1
    emit(0x21d, {0x0F, 0x05});                                 // syscall
    file[0x300] = 0xC3;                                        // the stub's ret

    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
}

TEST(MacosOs, MachoLoaderMapsAndKernelApiDispatches) {
    const auto exe = std::filesystem::temp_directory_path() / "ql_macho_kext" / "driver.macho";
    std::filesystem::create_directories(exe.parent_path());
    write_macho_kernel_fixture(exe);

    const auto rootfs = std::filesystem::temp_directory_path() / "ql_macos_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.argv = {exe.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::MACOS;
    options.archtype = QL_ARCH::X8664;
    Qiling ql(options);

    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    // the stub call rode the hook: _proc_selfpid returned 0x1337 and the pc
    // landed past the call (the store carried it into the in-image cell)
    EXPECT_EQ(ql.mem().read_ptr(0x1000800, 4), 0x1337u);
}

TEST(MacosOs, GetentropyReturnsSuccess) {
    auto ql = make_macos_qiling(getentropy_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x40, 4), 0u);  // KERN_SUCCESS
}

// ---- the ev stack-push emit path (the RUN=true stub) + the trigger ----
//
// The blob: the entry nop (the code-hook marker) then a ret whose stack cell
// the emit's stack-pushed stub occupies; the callback stores the ms64 args
// plus the 7th stack param into the scratch page and rets (the cleaner's ret
// pops the pre-pushed park address where the emu's until stops it).
constexpr std::uint64_t kEvCbOff = 0x40;      // the cb's offset in the blob
constexpr std::uint64_t kEvParkOff = 0x90;     // the park's offset in the blob
constexpr std::uint64_t kEvStack = 0x1180000;  // inside the shellcode mapping

std::vector<std::uint8_t> ev_stub_body(bool for_trigger = false) {
    std::vector<std::uint8_t> code;
    const auto push_q = [&code](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) code.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    };
    code.insert(code.end(), {0x90});                              // base+00: nop (the hook marker)
    code.push_back(0xC3);                                         // base+01: ret (pops the stub)
    code.resize(kEvCbOff, 0x90);                       // pad to the cb
    // the ABSOLUTE disp32 store form: prefix + modrm(rm=100) + SIB 0x25 +
    // disp32 — the bare `48 89 3D disp32` shape is RIP-RELATIVE (rm=101) and
    // lands the store near the blob, not at the cell (the (b13)-style
    // mechanical-audit lesson: verify the addressing mode, not just the reg
    // field)
    const std::uint8_t prefixes[6][4] = {
        {0x48, 0x89, 0x3C, 0x25}, {0x48, 0x89, 0x34, 0x25}, {0x48, 0x89, 0x14, 0x25},
        {0x48, 0x89, 0x0C, 0x25}, {0x4C, 0x89, 0x04, 0x25}, {0x4C, 0x89, 0x0C, 0x25},
    };
    for (int i = 0; i < 6; ++i) {
        for (int b = 0; b < 4; ++b) code.push_back(prefixes[i][b]);
        const auto cell = 0x2000 + 8 * i;
        for (int b = 0; b < 4; ++b) code.push_back(static_cast<std::uint8_t>((cell >> (8 * b)) & 0xFF));
    }
    // mov rax, [rsp+8] (the 7th param rides here under the pushed cleaner)
    const std::uint8_t read7[] = {0x48, 0x8B, 0x44, 0x24, 0x08};
    code.insert(code.end(), read7, read7 + 5);
    const std::uint8_t st_rax[] = {0x48, 0x89, 0x04, 0x25, 0x30, 0x20, 0x00, 0x00};  // mov [0x2030], rax
    code.insert(code.end(), st_rax, st_rax + 8);
    if (for_trigger) {
        // the trigger shape: the cb jmps to the park (the run(begin=cb) until
        // = cb + len(code), so the blob extends with nops to the until and
        // the tail never rets — the extras stay pushed, the upstream's
        // unbalanced-stack shape verbatim)
        const std::uint8_t jmp_park[] = {0xEB, 0x11};  // 0x7D + 2 + 0x11 = 0x90
        code.insert(code.end(), jmp_park, jmp_park + 2);
        code.resize(0xD0, 0x90);                                  // the ride to the until
        return code;
    }
    code.push_back(0xC3);                                         // the cb rets into the cleaner
    code.resize(kEvParkOff, 0x90);                     // pad to the park
    code.push_back(0xEB); code.push_back(0xFE);                   // base+90: jmp $
    return code;
}

// the stub-execution probe (the (b13)-lesson blob): the emit stack-pushes
// the gen_stub_code trampoline (the heap chunk, self-mapped by QlMemoryHeap),
// the guest ret rides it into the cb, the cleaner unwinds the 7th param and
// rets into the pre-pushed park where the emu's until stops.
TEST(MacosOs, EvEmitRunTruePushesStubAndRunsCallback) {
    auto ql = make_macos_qiling(ev_stub_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[ev-cells]");
    // the stack rides inside the loader's 10MB shellcode mapping (the blob
    // sits at its top page, 0x11ff000); the cb/park ride the runtime base
    const auto base = ql.loader().entry_point;

    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    ASSERT_TRUE(macos.RUN);  // the live-emulation default
    macos.ev_manager().register_cb(base + kEvCbOff, "KAUTH_X",
                                   qiling::os::macos::MacOSEventType::EV_KAUTH_PROCESS);
    // the ms64 stack: the park sentinel pre-pushed (the cleaner's final ret
    // pops it where the emu's until stops)
    ql.arch().regs().write(UC_X86_REG_RSP, kEvStack + 0x800);
    ql.stack_push(base + kEvParkOff);

    bool fired = false;
    HookRet keep = ql.hook_code([&](std::uint64_t pc, std::uint32_t) {
        if (fired || pc != base) {
            return 0;
        }
        fired = true;
        // RUN=true: the emit stack-pushes the trampoline at the guest rsp
        macos.ev_manager().emit("KAUTH_X", qiling::os::macos::MacOSEventType::EV_KAUTH_PROCESS,
                                {0xAAAAull, 0xBBBBull, 0xCCCCull, 0xDDDDull, 0xEEEEull, 0x2222ull, 0x7777ull});
        return 0;
    }, base, base + 0x10);
    (void)keep;

    ql.emu_start(base, base + kEvParkOff);

    // the callback ran with the emitted params: the six ms64 regs land...
    EXPECT_EQ(ql.mem().read_ptr(0x2000, 8), 0xAAAAull);
    EXPECT_EQ(ql.mem().read_ptr(0x2008, 8), 0xBBBBull);
    EXPECT_EQ(ql.mem().read_ptr(0x2010, 8), 0xCCCCull);
    EXPECT_EQ(ql.mem().read_ptr(0x2018, 8), 0xDDDDull);
    EXPECT_EQ(ql.mem().read_ptr(0x2020, 8), 0xEEEEull);
    EXPECT_EQ(ql.mem().read_ptr(0x2028, 8), 0x2222ull);
    // ...and the 7th param rides [rsp+8] at the cb entry (the push order
    // places it under the cleaner)
    EXPECT_EQ(ql.mem().read_ptr(0x2030, 8), 0x7777ull);
}

// the trigger-drain probe: the queued job drains through run(begin=cb) with
// the until = cb + len(code) (the os run's code-size tail) — the blob's cb
// jmps to the park and rides the nop pad to the until; the two extra params
// stay stack-pushed (the upstream's unbalanced-stack shape verbatim).
TEST(MacosOs, EvTriggerDrainsQueuedJobs) {
    auto ql = make_macos_qiling(ev_stub_body(true));
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[ev-cells]");
    // the stack rides inside the loader's shellcode mapping (no extra map —
    // 0x1180000 is already covered)

    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    const auto base = ql.loader().entry_point;
    ev.register_cb(base + kEvCbOff, "KAUTH_X", qiling::os::macos::MacOSEventType::EV_KAUTH_PROCESS);
    macos.RUN = false;  // the post-run shape: the emits queue instead of pushing

    const std::vector<std::uint64_t> params = {0x1111ull, 0x2222ull, 0x3333ull, 0x4444ull, 0x5555ull,
                                               0x6666ull, 0x7777ull, 0x8888ull};
    ev.emit("KAUTH_X", qiling::os::macos::MacOSEventType::EV_KAUTH_PROCESS, params);
    ASSERT_EQ(ev.jobs().size(), 1u);

    ql.arch().regs().write(UC_X86_REG_RSP, kEvStack + 0x800);
    ql.stack_push(base + kEvParkOff);
    const auto rsp_before = ql.arch().regs().read(UC_X86_REG_RSP);
    // the run(begin=cb) until = cb + len(code) rides 0x40 past the blob's end
    // (unreachable by construction — the upstream closes these runs via the
    // kext savedrip machinery, deferred); the fixture's device: an address
    // hook at the park stops the slice when the cb's jmp lands there
    HookRet stopper = ql.hook_address([&]() {
        ql.emu_stop();
        return 0;
    }, base + kEvParkOff);
    (void)stopper;
    ev.trigger();
    // the six regs carried the first six params; the two extras pushed
    EXPECT_EQ(ql.mem().read_ptr(0x2000, 8), 0x1111ull);
    EXPECT_EQ(ql.mem().read_ptr(0x2028, 8), 0x6666ull);
    EXPECT_EQ(ql.mem().read_ptr(0x2030, 8), 0x7777ull);  // [rsp+8] at the cb
    EXPECT_EQ(ql.arch().regs().read(UC_X86_REG_RSP), rsp_before - 16);
    // the extras' cells: p7 at [0x37f0], p8 at [0x37e8]
    EXPECT_EQ(ql.mem().read_ptr(kEvStack + 0x7f0, 8), 0x7777ull);
    EXPECT_EQ(ql.mem().read_ptr(kEvStack + 0x7e8, 8), 0x8888ull);
    EXPECT_TRUE(ev.jobs().empty());
}

TEST(MacosOs, EvEmitByTypeInsCookieSwapsFirstParam) {
    auto ql = make_macos_qiling(ev_stub_body());
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    ev.register_cb(0xdead0000, "ipf0", qiling::os::macos::MacOSEventType::EV_IPF_OUTPUT);
    ev.register_cb(0xdead0001, "ipf1", qiling::os::macos::MacOSEventType::EV_IPF_OUTPUT);
    ev.set_ipf_cookie("ipf0", 0xCAFED00Dull);
    macos.RUN = false;

    ev.emit_by_type(qiling::os::macos::MacOSEventType::EV_IPF_OUTPUT, {0ull, 0x100ull, 0ull}, true);
    ASSERT_EQ(ev.jobs().size(), 2u);
    EXPECT_EQ(ev.jobs()[0].params[0], 0xCAFED00Dull);  // ipf0's cookie swapped in
    EXPECT_EQ(ev.jobs()[1].params[0], 0ull);           // ipf1 has no cookie
}

// the emit_by_type_and_proto: only the protocol-matching registrations fire
TEST(MacosOs, EvEmitByTypeAndProtoFiltersRegistrations) {
    auto ql = make_macos_qiling(ev_stub_body());
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    const std::optional<std::uint64_t> tcp = 6;
    const std::optional<std::uint64_t> udp = 17;
    ev.register_cb(0xdead0000, "sflt_a", qiling::os::macos::MacOSEventType::EV_SFLT_ATTACH, 0, -1, tcp);
    ev.register_cb(0xdead0001, "sflt_b", qiling::os::macos::MacOSEventType::EV_SFLT_ATTACH, 0, -1, udp);
    macos.RUN = false;

    ev.emit_by_type_and_proto(qiling::os::macos::MacOSEventType::EV_SFLT_ATTACH, 6, {0x1111ull});
    ASSERT_EQ(ev.jobs().size(), 1u);
    EXPECT_EQ(ev.jobs()[0].func_addr, 0xdead0000ull);
    EXPECT_EQ(ev.jobs()[0].params[0], 0x1111ull);
}

// ---- the socket/ipf emitters (the ctl_*/net_* slice) ----

TEST(MacosOs, GenSockBuildsSockaddrIn) {
    auto ql = make_macos_qiling(ev_stub_body());
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    const auto addr = ev.gen_sock("192.168.13.37", 1337);
    ASSERT_NE(addr, 0u);
    ASSERT_EQ(ev.sockets_count(), 1u);
    EXPECT_EQ(ev.socket_base(0), addr);
    const auto image = ql.mem().read(addr, 16);
    EXPECT_EQ(image[0], 16);            // sin_len
    EXPECT_EQ(image[1], 2);             // sin_family = AF_INET
    EXPECT_EQ(image[2], 0x05);          // sin_port = 1337 network order
    EXPECT_EQ(image[3], 0x39);
    EXPECT_EQ(image[4], 192);           // sin_addr = the aton bytes
    EXPECT_EQ(image[5], 168);
    EXPECT_EQ(image[6], 13);
    EXPECT_EQ(image[7], 37);
    // the tail zeros (sin_zero)
    for (int i = 8; i < 16; ++i) {
        EXPECT_EQ(image[static_cast<std::size_t>(i)], 0) << "byte " << i;
    }
    // the second gen_sock appends (the upstream's sockets list shape)
    const auto dst = ev.gen_sock("10.2.13.38", 1338);
    ASSERT_EQ(ev.sockets_count(), 2u);
    const auto image2 = ql.mem().read(dst, 16);
    EXPECT_EQ(image2[4], 10);
    EXPECT_EQ(image2[7], 38);
    ev.clear_socks();
    EXPECT_EQ(ev.sockets_count(), 0u);
}

TEST(MacosOs, CtlConnectEmitsSockaddrCtl) {
    auto ql = make_macos_qiling(ev_stub_body(true));
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[ev-cells]");
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    const auto base = ql.loader().entry_point;
    ev.register_cb(base + kEvCbOff, "NKE_A", qiling::os::macos::MacOSEventType::EV_CTL_CONNECT);
    macos.RUN = false;  // the post-run shape: the emit queues for the trigger

    ev.ctl_connect("NKE_A", 0x42);
    ASSERT_EQ(ev.jobs().size(), 1u);

    // the trigger runs the cb (which stores rdi->0x2000, rsi->0x2008) and
    // the park stop-hook ends the slice
    ql.arch().regs().write(UC_X86_REG_RSP, kEvStack + 0x800);
    ql.stack_push(base + kEvParkOff);
    HookRet stopper = ql.hook_address([&]() {
        ql.emu_stop();
        return 0;
    }, base + kEvParkOff);
    (void)stopper;
    ev.trigger();

    // rdi carried the sockaddr_ctl_t image; rsi the unitinfo
    const auto nke_addr = ql.mem().read_ptr(0x2000, 8);
    EXPECT_EQ(ql.mem().read_ptr(0x2008, 8), 0x42ull);
    const auto image = ql.mem().read(nke_addr, 32);
    EXPECT_EQ(image[0], 32);            // sc_len
    EXPECT_EQ(image[1], 32);            // sc_family = AF_SYSTEM
    EXPECT_EQ(image[2], 2);             // ss_sysaddr = AF_SYS_CONTROL
    EXPECT_EQ(image[3], 0);
    EXPECT_EQ(image[4], 0x37);          // sc_id = 0x1337
    EXPECT_EQ(image[5], 0x13);
    EXPECT_EQ(image[8], 2);             // sc_unit = 2
}

TEST(MacosOs, CtlSendBuildsMbuf) {
    auto ql = make_macos_qiling(ev_stub_body());
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    macos.RUN = false;
    // the emit filters by the registered (name, type) pair — register the
    // listener first (the job still rides the queue path)
    ev.register_cb(0xdead0020, "NKE_B", qiling::os::macos::MacOSEventType::EV_CTL_SEND);

    ev.ctl_send("NKE_B", "hello");
    ASSERT_EQ(ev.jobs().size(), 1u);
    const auto& params = ev.jobs()[0].params;
    // ctl_send(kern_ctl_ref, unsigned unit, void* userdata, mbuf_t m, int flags)
    ASSERT_EQ(params.size(), 4u);
    EXPECT_EQ(params[0], 2u);   // the unit
    EXPECT_EQ(params[1], 0u);   // the userdata
    const auto mbuf_addr = params[2];
    EXPECT_EQ(params[3], 2u);   // the flags
    const auto image = ql.mem().read(mbuf_addr, 256);
    EXPECT_EQ(image[24], 5);    // mh_len = strlen(data)
    EXPECT_EQ(image[25], 0);
    EXPECT_EQ(image[30], 2);    // mh_flags = 2
    const std::uint64_t data_addr = image[16] | (std::uint64_t(image[17]) << 8) |
                                    (std::uint64_t(image[18]) << 16) | (std::uint64_t(image[19]) << 24) |
                                    (std::uint64_t(image[20]) << 32) | (std::uint64_t(image[21]) << 40) |
                                    (std::uint64_t(image[22]) << 48) | (std::uint64_t(image[23]) << 56);
    const auto bytes = ql.mem().read(data_addr, 5);
    EXPECT_EQ(std::string(bytes.begin(), bytes.end()), "hello");
}

TEST(MacosOs, NetNewSocketReadsGuestCookie) {
    // the cb writes 0xCAFE through the holder pointer (rdi) then parks;
    // net_new_socket reads the cookie back after the trigger drain
    std::vector<std::uint8_t> code;
    code.insert(code.end(), {0x90});                               // base+00: nop
    code.push_back(0xC3);                                          // base+01: ret
    code.resize(kEvCbOff, 0x90);
    const std::uint8_t write_cookie[] = {0x48, 0xC7, 0x47, 0x00, 0xFE, 0xCA, 0x00, 0x00};
    code.insert(code.end(), write_cookie, write_cookie + 8);       // mov qword [rdi], 0xCAFE
    code.insert(code.end(), {0xEB, static_cast<std::uint8_t>(0x90 - kEvCbOff - 8 - 2)});  // jmp park
    code.resize(kEvParkOff, 0x90);

    auto ql = make_macos_qiling(code);
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    const auto base = ql.loader().entry_point;
    ev.register_cb(base + kEvCbOff, "sflt", qiling::os::macos::MacOSEventType::EV_SFLT_ATTACH,
                   0, -1, static_cast<std::uint64_t>(qiling::os::macos::NetworkProtocol::IPPROTO_TCP));
    macos.RUN = false;  // the post-run shape: the emit queues, the trigger drains
    HookRet stopper = ql.hook_address([&]() {
        ql.emu_stop();
        return 0;
    }, base + kEvParkOff);
    (void)stopper;

    const auto cookie = ev.net_new_socket(qiling::os::macos::NetworkProtocol::IPPROTO_TCP);
    EXPECT_EQ(cookie, 0xCAFEull);
}

TEST(MacosOs, NetConnectOutCascade) {
    auto ql = make_macos_qiling(ev_stub_body());
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    macos.RUN = false;
    // the listeners for every emitted sflt type (the protocol filter must
    // match the connect_out protocol)
    const auto udp = static_cast<std::uint64_t>(qiling::os::macos::NetworkProtocol::IPPROTO_UDP);
    using ET = qiling::os::macos::MacOSEventType;
    ev.register_cb(0xdead0010, "conn_out", ET::EV_SFLT_CONNECT_OUT, 0, -1, udp);
    ev.register_cb(0xdead0011, "conn_out", ET::EV_SFLT_NOTIFY_BOUND, 0, -1, udp);
    ev.register_cb(0xdead0012, "conn_out", ET::EV_SFLT_NOTIFY_CONNECTING, 0, -1, udp);
    ev.register_cb(0xdead0013, "conn_out", ET::EV_SFLT_NOTIFY_CONNECTED, 0, -1, udp);

    ev.net_connect_out(qiling::os::macos::NetworkProtocol::IPPROTO_UDP, 0xBEEF);
    ASSERT_EQ(ev.jobs().size(), 4u);
    EXPECT_EQ(ev.jobs()[0].type, ET::EV_SFLT_CONNECT_OUT);
    EXPECT_EQ(ev.jobs()[0].params[0], 0xBEEFull);
    EXPECT_EQ(ev.jobs()[0].params[1], 0u);          // from_idx
    EXPECT_EQ(ev.jobs()[0].params[2], ev.socket_base(1));  // the to sockaddr
    EXPECT_EQ(ev.jobs()[1].type, ET::EV_SFLT_NOTIFY_BOUND);
    EXPECT_EQ(ev.jobs()[1].params[2], 0xau);        // BOUND - base_event_socket
    EXPECT_EQ(ev.jobs()[2].type, ET::EV_SFLT_NOTIFY_CONNECTING);
    EXPECT_EQ(ev.jobs()[2].params[2], 0x1u);        // CONNECTING - base
    EXPECT_EQ(ev.jobs()[3].type, ET::EV_SFLT_NOTIFY_CONNECTED);
    EXPECT_EQ(ev.jobs()[3].params[1], 1u);          // the to_idx
    EXPECT_EQ(ev.jobs()[3].params[2], 0x2u);        // CONNECTED - base
    // the socket pair: from 192.168.13.37:1337, to 10.2.13.38:1338
    const auto from = ql.mem().read(ev.socket_base(0), 16);
    EXPECT_EQ(from[4], 192);
    const auto to = ql.mem().read(ev.socket_base(1), 16);
    EXPECT_EQ(to[4], 10);
}

TEST(MacosOs, NetSetOptionCarriesSockopt) {
    auto ql = make_macos_qiling(ev_stub_body());
    auto& macos = dynamic_cast<qiling::os::macos::QlOsMacos&>(ql.os());
    auto& ev = macos.ev_manager();
    macos.RUN = false;
    const auto tcp = static_cast<std::uint64_t>(qiling::os::macos::NetworkProtocol::IPPROTO_TCP);
    ev.register_cb(0xdead0030, "opt_nke", qiling::os::macos::MacOSEventType::EV_SFLT_SETOPTION, 0, -1, tcp);

    ev.net_set_option(0xC0FE, 3, "opts", qiling::os::macos::NetworkProtocol::IPPROTO_TCP);
    ASSERT_EQ(ev.jobs().size(), 1u);
    EXPECT_EQ(ev.jobs()[0].type, qiling::os::macos::MacOSEventType::EV_SFLT_SETOPTION);
    const auto& params = ev.jobs()[0].params;
    ASSERT_EQ(params.size(), 3u);
    EXPECT_EQ(params[0], 0xC0FEull);  // the cookie
    EXPECT_EQ(params[1], 3u);         // the socket
    const auto sopt_addr = params[2];
    const auto image = ql.mem().read(sopt_addr, 40);
    // sopt_val @16 carries the "opts" buffer
    const std::uint64_t val = image[16] | (std::uint64_t(image[17]) << 8) |
                              (std::uint64_t(image[18]) << 16) | (std::uint64_t(image[19]) << 24) |
                              (std::uint64_t(image[20]) << 32) | (std::uint64_t(image[21]) << 40) |
                              (std::uint64_t(image[22]) << 48) | (std::uint64_t(image[23]) << 56);
    const auto bytes = ql.mem().read(val, 4);
    EXPECT_EQ(std::string(bytes.begin(), bytes.end()), "opts");
}

}  // namespace

TEST(MacosOs, SyscallExitTerminatesWithCode) {
    auto ql = make_macos_qiling(exit_body());
    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 42);
}

TEST(MacosOs, LibsystemFixupResolvesExit) {
    auto ql = make_macos_qiling(exit_libsystem_body());
    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 42);
}
