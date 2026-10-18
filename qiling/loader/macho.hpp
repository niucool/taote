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
#include <optional>
#include <string>
#include <vector>

namespace qiling {
namespace loader {
namespace macho {

// macho_parser/const.py (the verbatim tables)
constexpr std::uint32_t MAGIC_64[] = {0xFEEDFACF, 0xCFFAEDFE};
constexpr std::uint32_t MAGIC_FAT[] = {0xBEBAFECA, 0xCAFEBABE};

constexpr std::uint32_t LC_SEGMENT_64 = 0x19;
constexpr std::uint32_t LC_UNIXTHREAD = 0x5;
constexpr std::uint32_t LC_MAIN = 0x80000028;

constexpr std::uint32_t X86_THREAD_STATE64 = 0x00000004;

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

// data.py Section (the content slice rides data.py's data[offset:+size])
struct Section {
    std::string name;
    std::string segment_name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint32_t offset = 0;
    std::uint32_t alignment = 0;
    std::vector<std::uint8_t> content;
};

// data.py Segment (data.py Segment.__init__ verbatim: the fields off the
// LoadSegment64 command + the content slice + the parsed sections)
struct Segment {
    std::string name;
    std::uint64_t vm_address = 0;
    std::uint64_t vm_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint32_t max_vm_protection = 0;
    std::uint32_t init_vm_protection = 0;
    std::uint32_t flags = 0;
    std::vector<std::uint8_t> content;
    std::vector<Section> sections;
};

// parser.py MachoParser — the container parse (the header + the load-command
// walk: LC_SEGMENT_64 collects the segments/sections; the non-segment
// commands are skipped by their cmd_size until their slices land)
class MachoImage {
public:
    explicit MachoImage(const std::filesystem::path& path);

    bool valid() const { return header_.magic != 0; }
    const Header& header() const { return header_; }

    const std::vector<Segment>& segments() const { return segments_; }

    // loadcommand.py LoadUnixThread (the flavor + the state entry; the
    // X86_THREAD_STATE64 ride: the entry = the rip, the 16th state slot)
    bool has_unixthread() const { return has_unixthread_; }
    std::uint32_t thread_flavor() const { return thread_flavor_; }
    const std::optional<std::uint64_t>& unixthread_entry() const { return unixthread_entry_; }

    // loadcommand.py LoadMain (the entry offset + the stack size)
    bool has_main() const { return has_main_; }
    std::uint64_t main_entry_offset() const { return main_entry_offset_; }
    std::uint64_t main_stack_size() const { return main_stack_size_; }

private:
    bool parse_header();
    bool parse_load_command();

    std::vector<std::uint8_t> binary_file_;
    Header header_;
    std::vector<Segment> segments_;

    bool has_unixthread_ = false;
    std::uint32_t thread_flavor_ = 0;
    std::optional<std::uint64_t> unixthread_entry_;

    bool has_main_ = false;
    std::uint64_t main_entry_offset_ = 0;
    std::uint64_t main_stack_size_ = 0;
};

}  // namespace macho
}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_MACHO_HPP
