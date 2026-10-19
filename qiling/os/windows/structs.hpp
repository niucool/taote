// Ported from qiling/os/windows/structs.py — the pieces the fileapi family
// needs. The Python side builds ctypes.Struct classes and drives them through
// the .ref() context manager; the C++ port packs the same field layout with
// the documented byte offsets (the little-endian, naturally-aligned layout
// matches the ctypes default). More structs port as their consumer families
// land.
#ifndef QILING_OS_WINDOWS_STRUCTS_HPP
#define QILING_OS_WINDOWS_STRUCTS_HPP

#include <cstdint>
#include <string>

namespace qiling {
namespace os {
namespace win {

// const.py MAX_PATH
inline constexpr std::size_t WIN_MAX_PATH = 260;

// FILETIME — 8 bytes, little-endian (structs.py FILETIME: dwLowDateTime u32,
// dwHighDateTime i32). Packed as a raw u64 little-endian value.
inline std::string pack_filetime(std::uint64_t hnano) {
    std::string out(8, '\0');
    out[0] = static_cast<char>(hnano & 0xff);
    out[1] = static_cast<char>((hnano >> 8) & 0xff);
    out[2] = static_cast<char>((hnano >> 16) & 0xff);
    out[3] = static_cast<char>((hnano >> 24) & 0xff);
    out[4] = static_cast<char>((hnano >> 32) & 0xff);
    out[5] = static_cast<char>((hnano >> 40) & 0xff);
    out[6] = static_cast<char>((hnano >> 48) & 0xff);
    out[7] = static_cast<char>((hnano >> 56) & 0xff);
    return out;
}

// WIN32_FIND_DATAA (structs.py make_win32_find_data(archbits, wide=False)):
// the ANSI layout, all offsets verified against the ctypes field order
// (dwFileAttributes u32, the 3 FILETIMEs, nFileSizeHigh/Low u32, the reserved
// pair, cFileName[MAX_PATH=260], cAlternateFileName[14], dwFileType u32,
// dwCreatorType u32, wFinderFlags u16 — 328 bytes total)
inline constexpr std::size_t WIN32_FIND_DATAA_SIZE = 328;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_ATTRIBUTES = 0;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_CTIME = 4;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_ATIME = 12;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_WTIME = 20;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_SIZE_HIGH = 28;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_SIZE_LOW = 32;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_RESERVED0 = 36;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_RESERVED1 = 40;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_FILENAME = 44;
inline constexpr std::size_t WIN32_FIND_DATAA_OFF_ALTNAME = 44 + WIN_MAX_PATH;  // 304

// fills dst (>= WIN32_FIND_DATAA_SIZE bytes) with the populated structure
void write_win32_find_dataa(char* dst, std::uint32_t attributes, std::uint64_t filetime_hnano,
                            std::uint64_t filesize, const std::string& filename);

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_STRUCTS_HPP
