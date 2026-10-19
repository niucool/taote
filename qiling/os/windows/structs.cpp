// Ported from qiling/os/windows/structs.cpp — the WIN32_FIND_DATAA writer
// (structs.py make_win32_find_data(archbits, wide=False), the ANSI flavour).
#include "qiling/os/windows/structs.hpp"

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

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

void write_startup_info(char* dst, int bits, std::uint64_t lp_desktop, std::uint32_t dw_flags,
                        std::uint64_t h_std_input, std::uint64_t h_std_output, std::uint64_t h_std_error) {
    const auto put16 = [&dst](std::size_t off, std::uint16_t v) {
        dst[off] = static_cast<char>(v & 0xff);
        dst[off + 1] = static_cast<char>((v >> 8) & 0xff);
    };
    const auto put32 = [&dst](std::size_t off, std::uint32_t v) {
        dst[off] = static_cast<char>(v & 0xff);
        dst[off + 1] = static_cast<char>((v >> 8) & 0xff);
        dst[off + 2] = static_cast<char>((v >> 16) & 0xff);
        dst[off + 3] = static_cast<char>((v >> 24) & 0xff);
    };
    const auto put_ptr = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t i = 0; i < static_cast<std::size_t>(bits / 8); ++i) {
            dst[off + i] = static_cast<char>((v >> (i * 8)) & 0xff);
        }
    };

    // the ctypes default-aligned layout (struct.py make_startup_info): the
    // pointer fields align to the pointer width. x64: cb@0, lpReserved@8,
    // lpDesktop@16, lpTitle@24, the dw fields @32..60, wShowWindow@64,
    // cbReserved2@66, lpReserved2@72, hStdInput@80, hStdOutput@88,
    // hStdError@96. x86: the pointers 4 bytes, the same order.
    const auto ps = static_cast<std::size_t>(bits / 8);
    const std::size_t total = ps == 8 ? STARTUPINFO_SIZE_64 : STARTUPINFO_SIZE_32;
    std::memset(dst, 0, total);

    put32(0, static_cast<std::uint32_t>(total));  // cb
    std::size_t off = 4;
    // align up to the pointer width
    off = (off + ps - 1) / ps * ps;
    put_ptr(off, 0);  // lpReserved
    off += ps;
    put_ptr(off, lp_desktop);
    off += ps;
    put_ptr(off, 0);  // lpTitle
    off += ps;
    put32(off, 0);         // dwX
    put32(off + 4, 0);     // dwY
    put32(off + 8, 100);   // dwXSize
    put32(off + 12, 100);  // dwYSize
    put32(off + 16, 132);  // dwXCountChars
    put32(off + 20, 128);  // dwYCountChars
    put32(off + 24, 0xff);  // dwFillAttribute
    put32(off + 28, dw_flags);
    off += 32;
    put16(off, 1);       // wShowWindow
    put16(off + 2, 0);   // cbReserved2
    off += 4;
    // align up to the pointer width
    off = (off + ps - 1) / ps * ps;
    put_ptr(off, 0);  // lpReserved2
    off += ps;
    put_ptr(off, h_std_input);
    off += ps;
    put_ptr(off, h_std_output);
    off += ps;
    put_ptr(off, h_std_error);
}

std::string make_sid_bytes(std::uint32_t subauthority) {
    // make_sid(1): Revision u8 @0, SubAuthorityCount u8 @1, the 6-byte
    // IdentifierAuthority (the Value u32 big-endian + the 2-byte pad) @2,
    // SubAuthority[0] u32 LE @8
    std::string sid(12, '\0');
    sid[0] = '\x01';  // Revision
    sid[1] = '\x01';  // SubAuthorityCount
    sid[2] = '\x00';
    sid[3] = '\x00';
    sid[4] = '\x00';
    sid[5] = '\x01';  // IdentifierAuthority.Value = 1 (big-endian)
    sid[6] = '\x00';
    sid[7] = '\x00';
    sid[8] = static_cast<char>(subauthority & 0xff);
    sid[9] = static_cast<char>((subauthority >> 8) & 0xff);
    sid[10] = static_cast<char>((subauthority >> 16) & 0xff);
    sid[11] = static_cast<char>((subauthority >> 24) & 0xff);
    return sid;
}

Token::Token(Qiling& ql) {
    // TODO find a GOOD reference paper for the values (verbatim)
    auto* os = static_cast<os::windows::QlOsWindows*>(&ql.os());

    struct_[static_cast<std::uint32_t>(TokenInformationClass::TokenUIAccess)] = ql.pack(0x1);
    struct_[static_cast<std::uint32_t>(TokenInformationClass::TokenGroups)] = ql.pack(0x1);

    // still not sure why 0x1234 executes gandcrab as admin, but 544 no. No
    // idea (see sid refs for the values) (verbatim)
    const bool root = os->profile().get("SYSTEM", "permission").value_or("") == "root";
    const auto subauths = root ? 0x1234u : 545u;

    const auto sid_struct = make_sid_bytes(subauths);
    const auto sid_addr = os->heap().alloc(sid_struct.size());
    ql.mem().write(sid_addr, std::vector<std::uint8_t>(sid_struct.begin(), sid_struct.end()));

    // handle = Handle(obj=sid_obj, id=sid_addr) (verbatim: the explicit id)
    Handle sid_handle(sid_addr, nullptr);
    os->handle_manager().append(sid_handle);
    struct_[static_cast<std::uint32_t>(TokenInformationClass::TokenIntegrityLevel)] = ql.pack(sid_addr);
}

const std::string& Token::get(std::uint32_t value) const {
    const auto it = struct_.find(value);
    if (it == struct_.end()) {
        throw QlErrorNotImplemented("API not implemented");
    }
    return it->second;
}

}  // namespace win
}  // namespace os
}  // namespace qiling
