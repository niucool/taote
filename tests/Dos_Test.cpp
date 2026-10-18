// tests/Dos_Test.cpp — the dos dialect fixtures (the COM/MBR loader rides +
// the interrupt dispatch)

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include "qiling/core.hpp"
#include "qiling/os/dos/dos.hpp"

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
        0x88, 0x2E, 0x32, 0x01,  // mov [0x0132], cl
        0x88, 0x36, 0x34, 0x01,  // mov [0x0134], dh
        0x88, 0x1E, 0x36, 0x01,  // mov [0x0136], dl
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
