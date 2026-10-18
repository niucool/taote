// QlOsQnx suite — the qnx.py dialect over the posix base, ported per the
// upstream's os/qnx/ shape:
//   - the QlOsQnx(QlOsPosix) with the QNX type and the ARM32 kernel-entry
//     hook (the interrupt 2) + the R12 id-register ABI override
//   - the kercalls table dispatch (the ARM numbers, not the linux ones)
//   - the fixture-driven flows mirror the posix test style (the code blob +
//     the data region + the exit-code/memory assertions)
#include <gtest/gtest.h>

#include <filesystem>

#include "qiling/core.hpp"
#include "qiling/os/qnx/qnx.hpp"

using namespace qiling;

namespace {

// the fixture body: channel_create() then thread_destroy(-1, -1, 42) —
// the channel id rides R0 into the scratch word, the exit code comes from
// the thread_destroy status (qnx.py's exit path)
//   00: mov r1, #0x2000     ; the scratch pointer
//   04: mov r12, #35        ; channel_create
//   08: swi 0
//   0C: str r0, [r1]        ; record the returned channel id
//   10: mvn r0, #0          ; tid = -1
//   14: mvn r1, #0          ; priority = -1
//   18: mov r2, #42         ; status
//   1C: mov r12, #47        ; thread_destroy
//   20: swi 0
constexpr std::uint64_t kScratch = 0x2000;

const std::vector<std::uint8_t>& channel_exit_body() {
    static const std::vector<std::uint8_t> code = {
        0x02, 0x1A, 0xA0, 0xE3,  // 00: mov r1, #0x2000
        0x23, 0xC0, 0xA0, 0xE3,  // 04: mov r12, #35
        0x00, 0x00, 0x00, 0xEF,  // 08: swi 0
        0x00, 0x00, 0x81, 0xE5,  // 0C: str r0, [r1]
        0x00, 0x00, 0xE0, 0xE3,  // 10: mvn r0, #0
        0x00, 0x10, 0xE0, 0xE3,  // 14: mvn r1, #0
        0x2A, 0x20, 0xA0, 0xE3,  // 18: mov r2, #42
        0x2F, 0xC0, 0xA0, 0xE3,  // 1C: mov r12, #47
        0x00, 0x00, 0x00, 0xEF,  // 20: swi 0
    };
    return code;
}

Qiling make_qnx_qiling(const std::vector<std::uint8_t>& code) {
    const auto rootfs = std::filesystem::temp_directory_path() / "ql_qnx_rootfs";
    std::filesystem::create_directories(rootfs);

    QilingOptions options;
    options.rootfs = rootfs.string();
    options.code = code;
    options.ostype = QL_OS::QNX;
    options.archtype = QL_ARCH::ARM;
    return Qiling{options};
}

}  // namespace

// the channel_create + the thread_destroy exit flow: the first channel id is
// 1 (the upstream ctor seeds channel_id = 1) and the thread_destroy
// (-1, -1, status) terminates with the status as the exit code
TEST(QnxOs, ChannelCreateThenThreadDestroyExitsWithStatus) {
    auto ql = make_qnx_qiling(channel_exit_body());

    ql.mem().map(kScratch, 0x1000, UC_PROT_ALL, "[qnx-scratch]");

    ql.run();

    EXPECT_EQ(ql.os().exit_code(), 42);
    EXPECT_EQ(ql.mem().read_ptr(kScratch, 4), 1u);
}
