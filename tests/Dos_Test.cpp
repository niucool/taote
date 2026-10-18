// tests/Dos_Test.cpp — the dos dialect fixtures (the COM/MBR loader rides +
// the interrupt dispatch)

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "qiling/core.hpp"
#include "qiling/os/dos/dos.hpp"
#include "qiling/os/filestruct.hpp"

using namespace qiling;

namespace {

constexpr const char* kDosRootfs = "ql_dos_rootfs";

// the classic "HI" COM shape: int 21h ah=09 (the string print) then ah=4c
// (the graceful exit); the string rides at the blob offset 0x0d so
// ds:dx = 0x75A0 + 0x10d hits it (the cs=0x75A profile entry: the base
// 0x76A0 carries ip=0x100)
std::vector<std::uint8_t> make_hi_com() {
    return {
        0xBA, 0x0D, 0x01,  // mov dx, 0x010d
        0xB4, 0x09,        // mov ah, 09
        0xCD, 0x21,        // int 21h
        0xB4, 0x4C,        // mov ah, 4c
        0xCD, 0x21,        // int 21h
        0xEB, 0xFE,        // jmp $ (the dead tail)
        'H', 'I', '$',
    };
}

Qiling make_dos_qiling(const std::vector<std::uint8_t>& com) {
    const auto rootfs = std::filesystem::temp_directory_path() / kDosRootfs;
    std::filesystem::create_directories(rootfs);

    const auto com_path = rootfs / "HI.DOS_COM";
    std::ofstream f(com_path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(com.data()), static_cast<std::streamsize>(com.size()));
    f.close();

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.argv = {com_path.string()};
    options.ostype = QL_OS::DOS;
    options.archtype = QL_ARCH::A8086;
    return Qiling{options};
}

}  // namespace

// the COM run with the user-defined (intno, ah) api hooks: the upstream
// test_dos shape — the ENTER hook on (0x21, 0x4c) and the EXIT hook on
// (0x21, 0x09) both fire, and the emulation terminates through the leaf 4c
TEST(DosOs, ComRunsWithUserApiHooks) {
    auto ql = make_dos_qiling(make_hi_com());

    bool onenter = false;
    bool onexit = false;

    auto& os = static_cast<os::dos::QlOsDos&>(ql.os());
    os.set_int_api(0x21, 0x09, [&onexit](Qiling&) { onexit = true; }, QL_INTERCEPT::EXIT);
    os.set_int_api(0x21, 0x4c, [&onenter](Qiling&) { onenter = true; }, QL_INTERCEPT::ENTER);

    ql.run();

    EXPECT_TRUE(onenter);
    EXPECT_TRUE(onexit);
}

// the int 1Ah clock services: ah=02 returns the RTC time in BCD (the
// hour/minute/second cells with dl=0 and the CF clear) and ah=00 returns the
// elapsed ticks with al=0 (the ah=06 unsupported shape sets the CF — not
// driven here, the ah=02/00 rides pin the table)
//   00: B4 02           mov ah, 02
//   02: CD 1A           int 1ah
//   04: 88 2E 30 01     mov [0x0130], ch
//   08: 88 2E 32 01     mov [0x0132], cl
//   0C: 88 36 34 01     mov [0x0134], dh
//   10: 88 1E 36 01     mov [0x0136], dl
//   14: B4 00           mov ah, 00
//   16: CD 1A           int 1ah
//   18: A2 38 01        mov [0x0138], al
//   1B: B4 4C CD 21     the exit
TEST(DosOs, ClockServicesReturnBcdTimeAndTicks) {
    const std::vector<std::uint8_t> com = {
        0xB4, 0x02,        // mov ah, 02
        0xCD, 0x1A,        // int 1ah
        0x88, 0x2E, 0x30, 0x01,  // mov [0x0130], ch
        0x88, 0x0E, 0x32, 0x01,  // mov [0x0132], cl (modrm reg=CL=0x0E)
        0x88, 0x36, 0x34, 0x01,  // mov [0x0134], dh
        0x88, 0x16, 0x36, 0x01,  // mov [0x0136], dl
        0xB4, 0x00,        // mov ah, 00
        0xCD, 0x1A,        // int 1ah
        0xA2, 0x38, 0x01,  // mov [0x0138], al
        0xB4, 0x4C,        // mov ah, 4c
        0xCD, 0x21,        // int 21h
    };
    auto ql = make_dos_qiling(com);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    const auto data_base = 0x75A0 + 0x130;
    // the RTC time: the BCD cells decode into the valid ranges and the
    // dl always-0 cell
    const auto ch = ql.mem().read_ptr(data_base + 0, 1);
    const auto cl = ql.mem().read_ptr(data_base + 2, 1);
    const auto dh = ql.mem().read_ptr(data_base + 4, 1);
    const auto dl = ql.mem().read_ptr(data_base + 6, 1);
    EXPECT_LT(ch, 0x24u);
    EXPECT_LT(ch & 0x0f, 0x0au);
    EXPECT_LT(cl, 0x60u);
    EXPECT_LT(cl & 0x0f, 0x0au);
    EXPECT_LT(dh, 0x60u);
    EXPECT_LT(dh & 0x0f, 0x0au);
    EXPECT_EQ(dl, 0u);
    // the ticks read: al=0 (the midnight rollover flag), the cx:dx pair
    // carries the elapsed ticks
    EXPECT_EQ(ql.mem().read_ptr(data_base + 8, 1), 0u);
}

// the int 19h MBR boot ride: the MBR image loads at 0x7C00 (the loader's
// MBR branch: cs=0, ip=0x7c00, dx=0x80, the QlDisk mapping); the MBR stores
// dl, bumps the pass counter and re-boots through int 19h once (the reload
// reads the same file back through the QlDisk), then exits through
// int 21h ah=4c on the second pass
//   MBR: mov [0x0130], dl | mov al, [0x0132] | inc al | mov [0x0132], al |
//        cmp al, 2 | je done | int 19h | done: mov ah,4c | int 21h
TEST(DosOs, MbrBootRebootsThroughInt19) {
    const std::vector<std::uint8_t> mbr_code = {
        0x88, 0x16, 0x30, 0x01,  // mov [0x0130], dl (modrm reg=DL=0x16)
        0xA0, 0x32, 0x01,        // mov al, [0x0132]
        0xFE, 0xC0,              // inc al
        0xA2, 0x32, 0x01,        // mov [0x0132], al
        0x3C, 0x02,              // cmp al, 2
        0x74, 0x04,              // je done (+4)
        0xCD, 0x19,              // int 19h
        0xEB, 0x00,              // jmp over (unreached on pass 1)
        0xB4, 0x4C,              // done: mov ah, 4c
        0xCD, 0x21,              // int 21h
    };
    std::vector<std::uint8_t> mbr(512, 0x90);
    std::copy(mbr_code.begin(), mbr_code.end(), mbr.begin());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    const auto rootfs = std::filesystem::temp_directory_path() / kDosRootfs;
    std::filesystem::create_directories(rootfs);
    const auto mbr_path = rootfs / "DISK.DOS_MBR";
    {
        std::ofstream f(mbr_path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(mbr.data()), static_cast<std::streamsize>(mbr.size()));
    }

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.argv = {mbr_path.string()};
    options.ostype = QL_OS::DOS;
    options.archtype = QL_ARCH::A8086;
    Qiling ql{options};

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the dl marker (the BIOS-to-MBR handoff value) and the two passes
    EXPECT_EQ(ql.mem().read_ptr(0x130, 1), 0x80u);
    EXPECT_EQ(ql.mem().read_ptr(0x132, 1), 2u);
}

// the int 13h LBA read (ah=42) over the mapped drive: the MBR sets up the
// DAP (cnt=1, offset=0x0600, lba=1) and reads the sector 1 of the disk
// image (the loader maps the .DOS_MBR file itself as drive 0x80) into the
// 0x0600 buffer; the marker pattern proves the QlDisk ride
//   MBR: mov si, 0x0500 | mov ah, 0x42 | int 13h | mov [0x0138], ah |
//        mov ah, 4c | int 21h
TEST(DosOs, Int13LbaReadRidesQlDisk) {
    const std::vector<std::uint8_t> mbr_code = {
        0xBE, 0x00, 0x05,        // mov si, 0x0500 (the DAP)
        0xB4, 0x42,              // mov ah, 0x42
        0xCD, 0x13,              // int 13h
        0x88, 0x26, 0x38, 0x01,  // mov [0x0138], ah
        0xB4, 0x4C,              // mov ah, 4c
        0xCD, 0x21,              // int 21h
    };
    std::vector<std::uint8_t> mbr(512, 0x90);
    std::copy(mbr_code.begin(), mbr_code.end(), mbr.begin());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    std::vector<std::uint8_t> sector1(512, 0x00);
    const std::string marker = "LBA1-MARKER";
    std::copy(marker.begin(), marker.end(), sector1.begin());

    const auto rootfs = std::filesystem::temp_directory_path() / kDosRootfs;
    std::filesystem::create_directories(rootfs);
    const auto mbr_path = rootfs / "DISK.DOS_MBR";
    {
        std::ofstream f(mbr_path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(mbr.data()), static_cast<std::streamsize>(mbr.size()));
        f.write(reinterpret_cast<const char*>(sector1.data()), static_cast<std::streamsize>(sector1.size()));
    }

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.argv = {mbr_path.string()};
    options.ostype = QL_OS::DOS;
    options.archtype = QL_ARCH::A8086;
    Qiling ql{options};

    // the DAP at 0x0500: size=0x10, reserved=0, cnt=1, offset=0x0600,
    // segment=0, lba=1
    const std::vector<std::uint8_t> dap = {0x10, 0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00,
                                           0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ql.mem().write(0x500, dap);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the read status: ah=0 (the no-error)
    EXPECT_EQ(ql.mem().read_ptr(0x138, 1), 0u);
    // the sector-1 marker landed at the 0x0600 buffer
    const auto got = ql.mem().read(0x600, marker.size());
    EXPECT_EQ(std::string(got.begin(), got.end()), marker);
}

// the int 15h APM shutdown request: ah=0x53 al=0x07 bx=1 cx=3 stops the
// emulation (the upstream "Emulation Stop" shape); the run returns without
// reaching the trailing self-loop
//   00: B8 07 53     mov ax, 0x5307
//   03: BB 01 00     mov bx, 1
//   06: B9 03 00     mov cx, 3
//   09: CD 15        int 15h
//   0B: EB FE        jmp $ (never reached)
TEST(DosOs, Int15ApmShutdownStops) {
    const std::vector<std::uint8_t> com = {
        0xB8, 0x07, 0x53,  // mov ax, 0x5307
        0xBB, 0x01, 0x00,  // mov bx, 1
        0xB9, 0x03, 0x00,  // mov cx, 3
        0xCD, 0x15,        // int 15h
        0xEB, 0xFE,        // jmp $
    };
    auto ql = make_dos_qiling(com);

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
}

// the int 16h blocking key read (ah=00) over the injected stdin: the 'A'
// byte rides al (the ascii range) with the 'A' scancode 0x1e in ah (the
// SCANCODES table); the poll leaf (ah=01) degrades to the documented
// NotImplemented (the non-blocking console read is a curses shape)
//   00: B4 00        mov ah, 00
//   02: CD 16        int 16h
//   04: 88 26 30 01  mov [0x0130], ah
//   08: A2 32 01     mov [0x0132], al
//   0B: B4 4C CD 21  the exit
TEST(DosOs, Int16ReadKeyRidesInjectedStdin) {
    const std::vector<std::uint8_t> com = {
        0xB4, 0x00,              // mov ah, 00
        0xCD, 0x16,              // int 16h
        0x88, 0x26, 0x30, 0x01,  // mov [0x0130], ah
        0xA2, 0x32, 0x01,        // mov [0x0132], al
        0xB4, 0x4C,              // mov ah, 4c
        0xCD, 0x21,              // int 21h
    };
    auto ql = make_dos_qiling(com);

    // the injected stdin carries the 'A' keypress
    const auto rootfs = std::filesystem::temp_directory_path() / kDosRootfs;
    const auto key_path = rootfs / "keys.txt";
    {
        std::ofstream f(key_path, std::ios::binary);
        f << 'A';
    }
    static_cast<os::dos::QlOsDos&>(ql.os()).set_stdin(QlFile::open_mode(key_path.string(), "rb"));

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 0);
    // the key: al='A' (0x41), ah=0x1e (the 'A' scancode); the stores ride
    // ds=0x75A (the COM entry) - the linear cells sit at 0x75A0+0x130
    EXPECT_EQ(ql.mem().read_ptr(0x75A0 + 0x132, 1), 0x41u);
    EXPECT_EQ(ql.mem().read_ptr(0x75A0 + 0x130, 1), 0x1Eu);
}
