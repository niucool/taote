// Ported from qiling/os/windows/structs.cpp — the WIN32_FIND_DATAA writer
// (structs.py make_win32_find_data(archbits, wide=False), the ANSI flavour).
#include "qiling/os/windows/structs.hpp"

#include <cstring>

namespace qiling {
namespace os {
namespace win {

void write_win32_find_dataa(char* dst, std::uint32_t attributes, std::uint64_t filetime_hnano,
                            std::uint64_t filesize, const std::string& filename) {
    std::memset(dst, 0, WIN32_FIND_DATAA_SIZE);

    const auto put32 = [&dst](std::size_t off, std::uint32_t v) {
        dst[off] = static_cast<char>(v & 0xff);
        dst[off + 1] = static_cast<char>((v >> 8) & 0xff);
        dst[off + 2] = static_cast<char>((v >> 16) & 0xff);
        dst[off + 3] = static_cast<char>((v >> 24) & 0xff);
    };

    const auto ftime = pack_filetime(filetime_hnano);
    const auto put64 = [&dst, &ftime](std::size_t off) {
        std::memcpy(dst + off, ftime.data(), 8);
    };

    put32(WIN32_FIND_DATAA_OFF_ATTRIBUTES, attributes);
    put64(WIN32_FIND_DATAA_OFF_CTIME);
    put64(WIN32_FIND_DATAA_OFF_ATIME);
    put64(WIN32_FIND_DATAA_OFF_WTIME);
    put32(WIN32_FIND_DATAA_OFF_SIZE_HIGH, static_cast<std::uint32_t>(filesize >> 32));
    put32(WIN32_FIND_DATAA_OFF_SIZE_LOW, static_cast<std::uint32_t>(filesize & 0xffffffff));
    // dwReserved0/1 + cAlternateFileName + dwFileType/dwCreatorType/
    // wFinderFlags stay zero (the upstream writes the explicit zeros)

    // cFileName: the ANSI name (NUL-padded, c_char * MAX_PATH); the upstream
    // assigns the raw filename — the ctypes truncates at MAX_PATH
    const auto n = std::min<std::size_t>(filename.size(), WIN_MAX_PATH - 1);
    std::memcpy(dst + WIN32_FIND_DATAA_OFF_FILENAME, filename.data(), n);
}

}  // namespace win
}  // namespace os
}  // namespace qiling
