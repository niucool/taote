// Qiling facade suite — PORT_PLAN.md §10 Phase 3 (core.py composition root):
// the ctor assembly, the blob loader + os glue end-to-end, patching, and the
// save/restore aggregation.
#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/os.hpp"
#include "qiling/loader/blob.hpp"

using namespace qiling;

#define NL "\n"

namespace {

// the rootfs the facade validates (a plain directory)
std::filesystem::path temp_rootfs() {
    static const std::filesystem::path dir = [] {
        const auto base = std::filesystem::temp_directory_path() / "ql_facade_rootfs";
        std::filesystem::create_directories(base);
        return base;
    }();
    return dir;
}

QilingOptions blob_options(std::vector<std::uint8_t> code) {
    // shellcode execution names the arch explicitly (core.py: the guesser has
    // no container to sniff, so blob users pass archtype like the Python
    // Qiling(code=..., ostype=..., archtype=...) examples)
    QilingOptions options;
    options.code = std::move(code);
    options.rootfs = temp_rootfs().string();
    options.ostype = QL_OS::BLOB;
    options.archtype = QL_ARCH::X8664;

    // a minimal profile with the CODE section (there is no bundled blob.ql,
    // mirroring the Python profiles/ tree; os.py getint calls require it)
    const auto profile_path = temp_rootfs() / "blob_profile.ql";
    if (!std::filesystem::exists(profile_path)) {
        std::ofstream out(profile_path);
        out << "[CODE]" NL
               "ram_size = 0xa00000" NL
               "load_address = 0x1000000" NL
               "entry_point = 0x1000000" NL;
    }
    options.profile = profile_path.string();
    return options;
}

}  // namespace

// ---- ctor validation (core.py argv/rootfs checks) ----

TEST(QilingCtor, MissingRootfsRaises) {
    QilingOptions options;
    options.code = {0x90};
    options.rootfs = (temp_rootfs() / "definitely-missing").string();
    EXPECT_THROW(Qiling{options}, QlErrorFileNotFound);
}

TEST(QilingCtor, ArchWithoutOsGuessesOsFromArch) {
    // arch given, os omitted: the guesser fills the os from the file sniff —
    // with no file to sniff (shellcode), the resolution degrades (core.py
    // raises QlErrorOsType when ostype stays unset)
    QilingOptions options = blob_options({0x90});
    options.archtype = QL_ARCH::X8664;
    options.ostype = std::nullopt;
    EXPECT_THROW(Qiling{options}, QlErrorOsType);
}

TEST(QilingCtor, UnknownOsDegradesToQlErrorOsType) {
    // shellcode with no arch and no guessable format: arch stays unset
    // (core.py raises QlErrorArch — 'Unknown or unsupported architecture')
    QilingOptions options = blob_options({0x90});
    options.archtype = std::nullopt;
    EXPECT_THROW(Qiling{options}, QlErrorArch);
}

TEST(QilingCtor, CodeAndArgvAreMutuallyExclusive) {
    QilingOptions options = blob_options({0x90});
    options.argv = {"something.bin"};
    EXPECT_THROW(Qiling{options}, QlErrorBase);
}

// ---- the blob path end-to-end (core.py run + loader.run + os.run) ----

TEST(QilingFacade, BlobRunsToCompletion) {
    QilingOptions options = blob_options({
        0xB8, 0x5A, 0x5A, 0x00, 0x00,  // mov eax, 0x5A5A
        0xBB, 0x2A, 0x00, 0x00, 0x00,  // mov ebx, 0x2A
        0x90, 0x90,                    // nops up to the explicit exit
    });

    Qiling ql{options};
    ASSERT_EQ(ql.os().type(), QL_OS::BLOB);

    ql.run();

    // the emulation ran the blob in the [load_address, +ram) region
    EXPECT_EQ(ql.arch().regs().read("rax"), 0x5A5Au);
    EXPECT_EQ(ql.arch().regs().read("rbx"), 0x2Au);
    EXPECT_EQ(ql.emu_state(), QL_STATE::STOPPED);
}

TEST(QilingFacade, PatchAppliesBeforeRun) {
    // the blob is nop sleds; the patch turns it into `xor eax, eax`
    QilingOptions options = blob_options({0x90, 0x90, 0x90, 0x90});
    Qiling ql{options};

    ql.patch(0, {0x31, 0xC0, 0x90, 0x90});
    ql.run();

    EXPECT_EQ(ql.arch().regs().read("rax"), 0u);
}

TEST(QilingFacade, SaveRestoreRoundTrip) {
    QilingOptions options = blob_options({
        0xB8, 0x11, 0x11, 0x11, 0x11,  // mov eax, 0x11111111
        0x90, 0x90, 0x90, 0x90,
    });
    Qiling ql{options};
    ql.run();

    const auto saved = ql.save(true, true, false);
    ASSERT_TRUE(saved.reg.has_value());
    ASSERT_TRUE(saved.mem.has_value());

    // clobber the register + memory, then restore
    ql.arch().regs().write("rax", 0xDEADull);
    ql.mem().write(0x1000000, std::vector<std::uint8_t>{0xEE, 0xEE, 0xEE, 0xEE});
    ql.restore(saved);

    EXPECT_EQ(ql.arch().regs().read("rax"), 0x11111111ull);
    EXPECT_EQ(ql.mem().read(0x1000000, 4), (std::vector<std::uint8_t>{0xB8, 0x11, 0x11, 0x11}));
}

TEST(QilingFacade, LoaderImagesPopulated) {
    QilingOptions options = blob_options({0x90, 0x90});
    Qiling ql{options};

    // the blob loader registers the code region as an image
    const auto* image = ql.loader().find_containing_image(0x1000000);
    ASSERT_NE(image, nullptr);
    EXPECT_EQ(image->path, "blob_code");
    EXPECT_EQ(ql.loader().get_image_by_name("blob_code"), image);
}

TEST(QilingFacade, StackHelpersThroughFacade) {
    QilingOptions options = blob_options({0x90, 0x90});
    Qiling ql{options};

    // the facade delegates to the arch stack helpers (ql.stack_push parity)
    const auto pushed_at = ql.stack_push(0x41424344ull);
    EXPECT_EQ(pushed_at, ql.loader().init_sp - 8);
    EXPECT_EQ(ql.stack_read(0), 0x41424344ull);
    EXPECT_EQ(ql.stack_pop(), 0x41424344ull);
}
