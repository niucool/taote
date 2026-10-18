// Ported from qiling/loader/macho_parser/parser.py — the MachoImage parse
// (the skeleton: the ctor runs parseFile(); parseHeader is real, the
// load-command/data stages land with their slices).
#include "qiling/loader/macho.hpp"

#include <cstring>
#include <fstream>

namespace qiling {
namespace loader {
namespace macho {

namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return {};
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>{});
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& v, std::size_t off) {
    std::uint32_t x = 0;
    std::memcpy(&x, v.data() + off, 4);
    return x;
}

}  // namespace

MachoImage::MachoImage(const std::filesystem::path& path) {
    binary_file_ = read_file(path);
    if (!binary_file_.empty() && parse_header()) {
        // parseLoadCommand/parseData land with the following slices
    }
}

// parser.py parseHeader: the magic dispatch — MAGIC_64 -> the 64-bit
// BinaryHeader, else invalid (the fat branch lands with its slice)
bool MachoImage::parse_header() {
    const std::uint32_t magic = get_u32(binary_file_, 0);
    bool is_64 = false;
    for (std::uint32_t m : MAGIC_64) {
        if (magic == m) {
            is_64 = true;
            break;
        }
    }
    if (!is_64) {
        return false;
    }

    // the little-endian unpack of the 32-byte 64-bit header
    header_.magic = magic;
    header_.cpu_type = get_u32(binary_file_, 4);
    header_.cpu_subtype = get_u32(binary_file_, 8);
    header_.file_type = get_u32(binary_file_, 12);
    header_.lc_num = get_u32(binary_file_, 16);
    header_.lc_size = get_u32(binary_file_, 20);
    header_.flags = get_u32(binary_file_, 24);
    header_.reserved = get_u32(binary_file_, 28);

    // the CPU-type check (the upstream keys the arch via ql.arch.type; the
    // skeleton pins the x8664 container only)
    if (header_.cpu_type != CPU_TYPE_X8664) {
        header_ = Header{};
        return false;
    }
    return true;
}

}  // namespace macho
}  // namespace loader
}  // namespace qiling
