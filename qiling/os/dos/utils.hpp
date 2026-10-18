// os/dos/utils.py — the DOS helpers

#pragma once

#include <cstdint>
#include <string>

#include "qiling/core.hpp"

namespace qiling {
namespace os {
namespace dos {

// utils.py BIN2BCD(val): binary to packed BCD over four decimal digits
inline std::uint64_t bin2bcd(int val) {
    return ((val / 1) % 10 << 0) + ((val / 10) % 10 << 4) + ((val / 100) % 10 << 8) + ((val / 1000) % 10 << 12);
}

// utils.py BCD2BIN(val)
inline int bcd2bin(std::uint64_t val) {
    return ((val >> 0) & 0xf) * 1 + ((val >> 4) & 0xf) * 10 + ((val >> 8) & 0xf) * 100 + ((val >> 12) & 0xf) * 1000;
}

// utils.py linaddr(seg, off): the segmented to the 20-bit linear conversion
inline std::uint64_t linaddr(std::uint64_t seg, std::uint64_t off) {
    return (seg << 4) + off;
}

// utils.py read_dos_string(ql, address): the '$'-terminated ascii string
std::string read_dos_string(Qiling& ql, std::uint64_t address);

// utils.py read_dos_string_from_ds_dx(ql)
std::string read_dos_string_from_ds_dx(Qiling& ql);

}  // namespace dos
}  // namespace os
}  // namespace qiling
