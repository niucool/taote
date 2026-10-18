// Ported from qiling/loader/macho_parser/ — the hand-rolled Mach-O container
// parser (the upstream parses the raw bytes with struct.unpack; there is no
// external parsing dependency in the upstream's macho_parser, so the port is
// hand-rolled too — unlike elf.py's pyelftools → LIEF mapping, decision D17
// applies only where the upstream itself carries the dependency).
//
//   MachoParser(path, arch)  -> MachoImage (the parsed container; the ctor
//                               runs parseFile() exactly like the upstream:
//                               parseHeader -> parseLoadCommand -> parseData)
//   parser.py parseHeader    -> MachoImage::parse_header (the magic dispatch:
//                               MAGIC_64 -> the 64-bit header, MAGIC_FAT ->
//                               the FatHeader slice, else invalid)
//   header.py BinaryHeader   -> MachoImage::Header (the verbatim fields)
//
// The load-command walk and the data slice land in the following slices;
// parseFile()'s later stages return false (unparsed) until then.
#ifndef QILING_LOADER_MACHO_HPP
#define QILING_LOADER_MACHO_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace qiling {
namespace loader {
namespace macho {

// macho_parser/const.py (the verbatim tables)
constexpr std::uint32_t MAGIC_64[] = {0xFEEDFACF, 0xCFFAEDFE};
constexpr std::uint32_t MAGIC_FAT[] = {0xBEBAFECA, 0xCAFEBABE};

constexpr std::uint32_t CPU_ARCH_ABI64 = 0x01000000;
constexpr std::uint32_t CPU_TYPE_X8664 = CPU_ARCH_ABI64 | 7;
constexpr std::uint32_t MH_EXECUTE = 0x2;

// header.py BinaryHeader (the 64-bit shape; the 32-byte header with the
// reserved cell)
struct Header {
    std::uint32_t magic = 0;
    std::uint32_t cpu_type = 0;
    std::uint32_t cpu_subtype = 0;
    std::uint32_t file_type = 0;
    std::uint32_t lc_num = 0;
    std::uint32_t lc_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t reserved = 0;
};

// parser.py MachoParser — the container parse (the skeleton: the header +
// the magic/CPU checks; the load-command/data stages land next)
class MachoImage {
public:
    explicit MachoImage(const std::filesystem::path& path);

    bool valid() const { return header_.magic != 0; }
    const Header& header() const { return header_; }

private:
    bool parse_header();

    std::vector<std::uint8_t> binary_file_;
    Header header_;
};

}  // namespace macho
}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_MACHO_HPP
