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
std::vector<std::uint8_t> build_blob(const std::vector<std::uint8_t>& content, bool with_unknown_cmd) {
    const std::size_t unk_size = with_unknown_cmd ? 16 : 0;
    const std::size_t text_cmd = 32 + unk_size;
    const std::size_t text_cmd_size = 72 + 0x50;     // the 1 section
    const std::uint32_t content_off = static_cast<std::uint32_t>(text_cmd + text_cmd_size);

    std::vector<std::uint8_t> v(static_cast<std::size_t>(content_off) + content.size(), 0);
    put32(v, 0, 0xFEEDFACF);
    put32(v, 4, CPU_TYPE_X8664);
    put32(v, 8, 3);
    put32(v, 12, MH_EXECUTE);
    put32(v, 16, with_unknown_cmd ? 2u : 1u);        // ncmds
    put32(v, 20, static_cast<std::uint32_t>(unk_size + text_cmd_size));

    if (with_unknown_cmd) {
        put32(v, 32, 0x42);                          // an unknown cmd id
        put32(v, 36, static_cast<std::uint32_t>(unk_size));
    }

    put32(v, text_cmd, LC_SEGMENT_64);
    put32(v, text_cmd + 4, static_cast<std::uint32_t>(text_cmd_size));
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

    std::copy(content.begin(), content.end(), v.begin() + static_cast<std::ptrdiff_t>(content_off));
    return v;
}

void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
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
