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
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "qiling/loader/loader.hpp"

namespace qiling {
namespace loader {
namespace macho {

// macho_parser/const.py (the verbatim tables)
constexpr std::uint32_t MAGIC_64[] = {0xFEEDFACF, 0xCFFAEDFE};
constexpr std::uint32_t MAGIC_FAT[] = {0xBEBAFECA, 0xCAFEBABE};

constexpr std::uint32_t LC_SEGMENT_64 = 0x19;
constexpr std::uint32_t LC_UNIXTHREAD = 0x5;
constexpr std::uint32_t LC_MAIN = 0x80000028;
constexpr std::uint32_t LC_SYMTAB = 0x2;

// nlist.h: the symbol-type bits (the N_SECT|N_EXT external-defined shape)
constexpr std::uint8_t N_EXT = 0x1;
constexpr std::uint8_t N_TYPE = 0xe;
constexpr std::uint8_t N_SECT = 0xe;

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

// one load command (the parsed cmd_id/cmd_size pair + its file offset)
struct Command {
    std::uint32_t cmd_id = 0;
    std::uint32_t cmd_size = 0;
    std::size_t offset = 0;
};

// nlist.h nlist_64 (the symbol-table entry)
struct Symbol {
    std::uint32_t n_strx = 0;
    std::uint8_t n_type = 0;
    std::uint8_t n_sect = 0;
    std::uint16_t n_desc = 0;
    std::uint64_t n_value = 0;
};

// parser.py MachoParser — the container parse (the header + the load-command
// walk: LC_SEGMENT_64 collects the segments/sections; LC_SYMTAB carries the
// symbol/string tables for the kernel-api dispatch)
class MachoImage {
public:
    explicit MachoImage(const std::filesystem::path& path);

    bool valid() const { return header_.magic != 0; }
    const Header& header() const { return header_; }

    const std::vector<Segment>& segments() const { return segments_; }
    const std::vector<Command>& commands() const { return commands_; }

    // loadcommand.py LC_SYMTAB (the symoff/nsyms/stroff/strsize quadruple);
    // the empty vector when the file carries no symbol table
    const std::vector<Symbol>& symbols() const { return symbols_; }
    std::string string_at(std::uint32_t strx) const;

private:
    bool parse_header();
    bool parse_load_command();

    std::vector<std::uint8_t> binary_file_;
    Header header_;
    std::vector<Segment> segments_;
    std::vector<Command> commands_;
    std::vector<Symbol> symbols_;
    std::string binary_path_;

    bool has_symtab_ = false;
    std::uint32_t symoff_ = 0;
    std::uint32_t nsyms_ = 0;
    std::uint32_t stroff_ = 0;
    std::uint32_t strsize_ = 0;

    bool has_unixthread_ = false;
    std::uint32_t thread_flavor_ = 0;
    std::optional<std::uint64_t> unixthread_entry_;

    bool has_main_ = false;
    std::uint64_t main_entry_offset_ = 0;
    std::uint64_t main_stack_size_ = 0;

public:
    // loadcommand.py LoadUnixThread (the flavor + the state entry; the
    // X86_THREAD_STATE64 ride: the entry = the rip, the 16th state slot)
    bool has_unixthread() const { return has_unixthread_; }
    std::uint32_t thread_flavor() const { return thread_flavor_; }
    const std::optional<std::uint64_t>& unixthread_entry() const { return unixthread_entry_; }

    // loadcommand.py LoadMain (the entry offset + the stack size)
    bool has_main() const { return has_main_; }
    std::uint64_t main_entry_offset() const { return main_entry_offset_; }
    std::uint64_t main_stack_size() const { return main_stack_size_; }
};

// loader/macho.py QlLoaderMACHO — the macho x8664 loader. Sub-slice 1: the
// segment mapping (the loadMacho three-pass shape), the entry (the
// LC_UNIXTHREAD/LC_MAIN + the __PAGEZERO offset) and the shellcode branch;
// the loadDriver path (the kernel parse + the LC_DYSYMTAB relocation walk)
// lands with its own slice — the import_symbols here ride the file's own
// LC_SYMTAB (the deviation note: the upstream derives them from the kernel
// symbol walk).
class QlLoaderMachO final : public QlLoader {
public:
    explicit QlLoaderMachO(Qiling* ql, std::string dyld_path = {});

    void run() override;

    // hook.py: the stub-address -> the api name lookup (the kernel-api
    // dispatch gate); the ImportSymbol shape mirrors the QlLoaderELF's
    struct ImportSymbol {
        std::uint64_t address;
        std::string name;
    };

    const ImportSymbol* import_symbols_at(std::uint64_t address) const {
        const auto it = import_symbols_.find(address);
        return it == import_symbols_.end() ? nullptr : &it->second;
    }

    // loader.py: the kext/driver flags the os layer reads
    const std::string& kext_name() const { return kext_name_; }
    bool is_driver() const { return is_driver_; }

private:
    void load_macho();
    void load_segment(const Segment& seg, std::uint64_t slide);

    std::string dyld_path_;
    std::string kext_name_;
    bool is_driver_ = false;
    std::uint64_t binary_entry_ = 0;
    std::uint64_t vm_end_addr_ = 0;
    std::map<std::uint64_t, ImportSymbol> import_symbols_;
};


}  // namespace macho
}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_MACHO_HPP
