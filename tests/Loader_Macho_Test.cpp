// LoaderMacho smoke suite — the skeleton parse: the ctor runs parseFile()
// and the header magic/CPU-type checks gate validity (the load-command and
// data stages land with their slices).
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#include "qiling/loader/macho.hpp"

using qiling::loader::macho::CPU_TYPE_X8664;
using qiling::loader::macho::MH_EXECUTE;
using qiling::loader::macho::MachoImage;

namespace {

void put32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    }
}

std::vector<std::uint8_t> minimal_header(std::uint32_t magic, std::uint32_t cpu_type) {
    std::vector<std::uint8_t> v(32, 0);
    put32(v, 0, magic);
    put32(v, 4, cpu_type);
    put32(v, 8, 3);                // the subtype
    put32(v, 12, MH_EXECUTE);
    put32(v, 16, 2);               // the ncmds
    put32(v, 20, 144);             // the sizeofcmds
    return v;
}

void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

TEST(LoaderMacho, HeaderMagicAndCpuType) {
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "hello.macho";
    write_file(path, minimal_header(0xFEEDFACF, CPU_TYPE_X8664));

    MachoImage image(path);
    ASSERT_TRUE(image.valid());
    EXPECT_EQ(image.header().magic, 0xFEEDFACF);
    EXPECT_EQ(image.header().cpu_type, CPU_TYPE_X8664);
    EXPECT_EQ(image.header().file_type, MH_EXECUTE);
    EXPECT_EQ(image.header().lc_num, 2u);
}

TEST(LoaderMacho, BadMagicDegradesToInvalid) {
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "bad.macho";
    write_file(path, minimal_header(0x41414141, CPU_TYPE_X8664));

    MachoImage image(path);
    EXPECT_FALSE(image.valid());
}

TEST(LoaderMacho, WrongCpuTypeDegradesToInvalid) {
    const auto path = std::filesystem::temp_directory_path() / "ql_macho_test" / "arm.macho";
    write_file(path, minimal_header(0xFEEDFACF, 12));

    MachoImage image(path);
    EXPECT_FALSE(image.valid());
}
