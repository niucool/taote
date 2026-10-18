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
