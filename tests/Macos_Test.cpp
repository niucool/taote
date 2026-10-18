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
#include "qiling/os/macos/macos.hpp"
#include "qiling/os/posix/posix.hpp"

using namespace qiling;

namespace {

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

TEST(MacosOs, GetentropyReturnsSuccess) {
    auto ql = make_macos_qiling(getentropy_body());
    ql.mem().map(0x2000, 0x1000, UC_PROT_ALL, "[macos-scratch]");  // the page-aligned base (the 0x2100 cells ride inside)
    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kScratch + 0x40, 4), 0u);  // KERN_SUCCESS
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
