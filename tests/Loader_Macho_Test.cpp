// LoaderMacho — the LC_SEGMENT_64 walk: the fixture builds a minimal
// in-memory macho blob with one __TEXT segment (one __text section carrying
// content) and asserts the Segment/Section collection; an unknown command
// riding the walk must be skipped by its declared cmd_size.
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/loader/macho.hpp"

using namespace qiling::loader::macho;

namespace {

constexpr std::uint64_t kTextVmAddr = 0x100000000ull;
constexpr std::uint32_t kTextFileSize = 0x400;

void put32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    }
}

void put64(std::vector<std::uint8_t>& v, std::size_t off, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    }
}

void put_name(std::vector<std::uint8_t>& v, std::size_t off, const std::string& name) {
    for (std::size_t i = 0; i < 16 && i < name.size(); ++i) {
        v[off + i] = static_cast<std::uint8_t>(name[i]);
    }
}

// the fixture blob: the 32-byte header [+ one unknown 16-byte command] + one
// LC_SEGMENT_64 (one section) + the section content at the segment's file
// offset
std::vector<std::uint8_t> build_blob(const std::vector<std::uint8_t>& content, bool with_unknown_cmd,
                                     const std::vector<std::uint8_t>& extra_cmd = {}) {
    const std::size_t unk_size = with_unknown_cmd ? 16 : 0;
    const std::size_t text_cmd = 32 + unk_size;
    const std::size_t seg_cmd_size = 72 + 0x50;      // the segment's own size
    const std::uint32_t content_off = static_cast<std::uint32_t>(text_cmd + seg_cmd_size + extra_cmd.size());

    std::vector<std::uint8_t> v(static_cast<std::size_t>(content_off) + content.size(), 0);
    put32(v, 0, 0xFEEDFACF);
    put32(v, 4, CPU_TYPE_X8664);
    put32(v, 8, 3);
    put32(v, 12, MH_EXECUTE);
    put32(v, 16, (with_unknown_cmd ? 1u : 0u) + (extra_cmd.empty() ? 0u : 1u) + 1u);  // ncmds
    put32(v, 20, static_cast<std::uint32_t>(unk_size + seg_cmd_size + extra_cmd.size()));

    if (with_unknown_cmd) {
        put32(v, 32, 0x42);                          // an unknown cmd id
        put32(v, 36, static_cast<std::uint32_t>(unk_size));
    }

    put32(v, text_cmd, LC_SEGMENT_64);
    put32(v, text_cmd + 4, static_cast<std::uint32_t>(seg_cmd_size));
    put_name(v, text_cmd + 8, "__TEXT");
    put64(v, text_cmd + 24, kTextVmAddr);            // the vm address
    put64(v, text_cmd + 32, kTextFileSize);          // the vm size
    put64(v, text_cmd + 40, content_off);            // the file offset
    put64(v, text_cmd + 48, content.size());         // the file size
    put32(v, text_cmd + 56, 7);                      // the max prot
    put32(v, text_cmd + 60, 5);                      // the init prot
    put32(v, text_cmd + 64, 1);                      // nsects
    put32(v, text_cmd + 68, 0);                      // the flags

    // the one section record (0x50 stride; the name/segname/addr/size/offset
    // prefix + the reserved walk)
    std::size_t s = text_cmd + 72;
    put_name(v, s, "__text");
    put_name(v, s + 16, "__TEXT");
    put64(v, s + 32, kTextVmAddr + content_off);
    put64(v, s + 40, content.size());
    put32(v, s + 48, content_off);
    put32(v, s + 52, 4);                             // the align 2^4

    if (!extra_cmd.empty()) {
        std::copy(extra_cmd.begin(), extra_cmd.end(), v.begin() + static_cast<std::ptrdiff_t>(text_cmd + 72 + 0x50));
    }
    std::copy(content.begin(), content.end(), v.begin() + static_cast<std::ptrdiff_t>(content_off));
    return v;
}

void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

// LC_UNIXTHREAD: cmd + size + flavor + count, then the X86_THREAD_STATE64
// state (the 16 GPRs then rip rflags cs fs gs — the rip is the state index
// 16); the count is 21 u64s
std::vector<std::uint8_t> thread_cmd(std::uint64_t entry) {
    std::vector<std::uint8_t> v(184, 0);
    put32(v, 0, LC_UNIXTHREAD);
    put32(v, 4, 184);
    put32(v, 8, X86_THREAD_STATE64);
    put32(v, 12, 21);
    put64(v, 16 + 16 * 8, entry);
    return v;
}

// LC_MAIN: cmd + size + the entry offset + the stack size
std::vector<std::uint8_t> main_cmd(std::uint64_t entry_offset, std::uint64_t stack_size) {
    std::vector<std::uint8_t> v(24, 0);
    put32(v, 0, LC_MAIN);
    put32(v, 4, 24);
    put64(v, 8, entry_offset);
    put64(v, 16, stack_size);
    return v;
}

}  // namespace

TEST(LoaderMacho, Segment64CollectsSegmentAndSection) {
    const std::vector<std::uint8_t> code = {0x48, 0x31, 0xC0, 0xC3};
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "seg.macho";
    write_file(path, build_blob(code, false));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    ASSERT_EQ(image.segments().size(), 1u);

    const Segment& seg = image.segments()[0];
    EXPECT_EQ(seg.name, "__TEXT");
    EXPECT_EQ(seg.vm_address, kTextVmAddr);
    EXPECT_EQ(seg.vm_size, static_cast<std::uint64_t>(kTextFileSize));
    EXPECT_EQ(seg.file_size, code.size());
    ASSERT_EQ(seg.content.size(), code.size());
    EXPECT_EQ(seg.content, code);

    ASSERT_EQ(seg.sections.size(), 1u);
    const Section& sec = seg.sections[0];
    EXPECT_EQ(sec.name, "__text");
    EXPECT_EQ(sec.segment_name, "__TEXT");
    EXPECT_EQ(sec.address, kTextVmAddr + (32 + 72 + 0x50));
    EXPECT_EQ(sec.size, code.size());
    EXPECT_EQ(sec.content, code);
}

TEST(LoaderMacho, HeaderMagicAndCpuType) {
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "hdr.macho";
    write_file(path, build_blob({}, false));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    EXPECT_EQ(image.header().magic, 0xFEEDFACF);
    EXPECT_EQ(image.header().cpu_type, CPU_TYPE_X8664);
    EXPECT_EQ(image.header().file_type, MH_EXECUTE);
    EXPECT_EQ(image.header().lc_num, 1u);
}

TEST(LoaderMacho, BadMagicDegradesToInvalid) {
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "bad.macho";
    write_file(path, build_blob({}, false));

    // the corrupted magic degrades to invalid
    std::vector<std::uint8_t> bytes(32, 0);
    put32(bytes, 0, 0x41414141);
    put32(bytes, 4, CPU_TYPE_X8664);
    write_file(path, bytes);

    MachoImage image(path);
    EXPECT_FALSE(image.valid());
}

TEST(LoaderMacho, WrongCpuTypeDegradesToInvalid) {
    std::vector<std::uint8_t> bytes(32, 0);
    put32(bytes, 0, 0xFEEDFACF);
    put32(bytes, 4, 12);  // not the x8664 CPU type
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "arm.macho";
    write_file(path, bytes);

    MachoImage image(path);
    EXPECT_FALSE(image.valid());
}

TEST(LoaderMacho, UnknownCommandsAreSkipped) {
    const std::vector<std::uint8_t> code = {0x90, 0xC3};
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "skip.macho";
    write_file(path, build_blob(code, true));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    ASSERT_EQ(image.segments().size(), 1u);
    EXPECT_EQ(image.segments()[0].name, "__TEXT");
    ASSERT_EQ(image.segments()[0].content, code);
}

// the X86_THREAD_STATE64 entry ride
constexpr std::uint64_t kThreadEntry = 0x1000000f0;

// the big-endian u32 writer for the fat-container fields
void put_be32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    v[off] = static_cast<std::uint8_t>(x >> 24);
    v[off + 1] = static_cast<std::uint8_t>(x >> 16);
    v[off + 2] = static_cast<std::uint8_t>(x >> 8);
    v[off + 3] = static_cast<std::uint8_t>(x);
}

// the fat wrapper: the CAFEBABE magic (big-endian on disk), the arch_num,
// the 20-byte FatInfo records, then the thin blobs at their offsets
std::vector<std::uint8_t> build_fat(const std::vector<std::uint8_t>& arm_blob,
                                    const std::vector<std::uint8_t>& x64_blob) {
    const std::size_t header_size = 8 + 2 * 20;  // magic + arch_num + 2 records
    std::vector<std::uint8_t> v(header_size + arm_blob.size() + x64_blob.size(), 0);
    // the on-disk magic 0xCAFEBABE reads 0xBEBAFECA as the LE u32 (the
    // MAGIC_FAT[0] constant)
    put_be32(v, 0, 0xCAFEBABE);
    put_be32(v, 4, 2);  // arch_num
    // slice 0: the ARM64 decoy (the getBinary scan skips it — the x8664
    // pass runs first)
    const std::size_t arm_off = header_size;
    put_be32(v, 8, 0x0100000C);
    put_be32(v, 12, 0);
    put_be32(v, 16, static_cast<std::uint32_t>(arm_off));
    put_be32(v, 20, static_cast<std::uint32_t>(arm_blob.size()));
    put_be32(v, 24, 12);  // align 2**12
    // slice 1: the x8664 pick
    const std::size_t x64_off = arm_off + arm_blob.size();
    put_be32(v, 28, 0x01000007);
    put_be32(v, 32, 0x30);
    put_be32(v, 36, static_cast<std::uint32_t>(x64_off));
    put_be32(v, 40, static_cast<std::uint32_t>(x64_blob.size()));
    put_be32(v, 44, 12);
    std::copy(arm_blob.begin(), arm_blob.end(), v.begin() + static_cast<std::ptrdiff_t>(arm_off));
    std::copy(x64_blob.begin(), x64_blob.end(), v.begin() + static_cast<std::ptrdiff_t>(x64_off));
    return v;
}

TEST(LoaderMacho, UnixThreadCarriesEntry) {
    const std::vector<std::uint8_t> code = {0x48, 0x31, 0xC0, 0xC3};
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "thread.macho";
    write_file(path, build_blob(code, false, thread_cmd(kThreadEntry)));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    ASSERT_TRUE(image.has_unixthread());
    EXPECT_EQ(image.thread_flavor(), X86_THREAD_STATE64);
    ASSERT_TRUE(image.unixthread_entry().has_value());
    EXPECT_EQ(*image.unixthread_entry(), kThreadEntry);
}

TEST(LoaderMacho, MainCarriesEntryOffset) {
    const std::vector<std::uint8_t> code = {0x48, 0x31, 0xC0, 0xC3};
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "main.macho";
    write_file(path, build_blob(code, false, main_cmd(0x200, 0x10000)));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    ASSERT_TRUE(image.has_main());
    EXPECT_EQ(image.main_entry_offset(), 0x200u);
    EXPECT_EQ(image.main_stack_size(), 0x10000u);
    EXPECT_FALSE(image.has_unixthread());
}

// the fat container: the CAFEBABE magic, the decoy ARM64 slice first, the
// x8664 slice re-parsed (the verbatim getBinary ignores the archtype and
// scans x8664 first)
TEST(LoaderMacho, FatContainerReparsesTheMatchingSlice) {
    const std::vector<std::uint8_t> code = {0x48, 0x31, 0xC0, 0xC3};
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "fat.macho";
    write_file(path, build_fat({0xDE, 0xAD, 0xBE, 0xEF},  // the arm64 decoy body
                               build_blob(code, false, thread_cmd(kThreadEntry))));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    // the re-parsed slice header rides the thin blob's fields
    EXPECT_EQ(image.header().magic, 0xFEEDFACF);
    EXPECT_EQ(image.header().cpu_type, CPU_TYPE_X8664);
    EXPECT_EQ(image.header().file_type, MH_EXECUTE);
    // both raw slice records survived the walk
    ASSERT_EQ(image.fat_slices().size(), 2u);
    EXPECT_EQ(image.fat_slices()[0].cpu_type, 0x0100000Cu);
    EXPECT_EQ(image.fat_slices()[1].cpu_type, CPU_TYPE_X8664);
    EXPECT_EQ(image.fat_slices()[1].offset % 4, 0u);  // the align sanity
    // the segment parse rode the re-sliced container
    ASSERT_EQ(image.segments().size(), 1u);
    EXPECT_EQ(image.segments()[0].name, "__TEXT");
    ASSERT_EQ(image.segments()[0].content, code);
    // the unixthread entry rode the re-parsed load commands
    ASSERT_TRUE(image.has_unixthread());
    EXPECT_EQ(image.unixthread_entry(), kThreadEntry);
}

// the fat container with no matching slice degrades to the invalid image
// (the deviation: the upstream would crash on the None slice)
TEST(LoaderMacho, FatContainerWithoutMatchDegradesToInvalid) {
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "fat_nomatch.macho";
    std::vector<std::uint8_t> v(8 + 20 + 8, 0);
    put_be32(v, 0, 0xCAFEBABE);
    put_be32(v, 4, 1);
    put_be32(v, 8, 0x00000007);  // the 32-bit x86 cpu type — no x8664/arm64
    put_be32(v, 12, 0);
    put_be32(v, 16, 28);
    put_be32(v, 20, 8);
    put_be32(v, 24, 12);
    write_file(path, v);

    MachoImage image(path);
    EXPECT_FALSE(image.valid());
}
