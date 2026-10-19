// Ported from qiling/os/windows/structs.py — the pieces the fileapi family
// needs. The Python side builds ctypes.Struct classes and drives them through
// the .ref() context manager; the C++ port packs the same field layout with
// the documented byte offsets (the little-endian, naturally-aligned layout
// matches the ctypes default). More structs port as their consumer families
// land.
#ifndef QILING_OS_WINDOWS_STRUCTS_HPP
#define QILING_OS_WINDOWS_STRUCTS_HPP

#include <cstdint>
#include <map>
#include <string>

namespace qiling {

class Qiling;

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

// ---- SYSTEMTIME (structs.py SYSTEMTIME) ----
// the 16-byte layout: the 8 u16 fields in order (wYear, wMonth, wDayOfWeek,
// wDay, wHour, wMinute, wSecond, wMilliseconds)
inline constexpr std::size_t SYSTEMTIME_SIZE = 16;

void write_systemtime(char* dst, std::uint16_t year, std::uint16_t month, std::uint16_t day_of_week,
                      std::uint16_t day, std::uint16_t hour, std::uint16_t minute, std::uint16_t second,
                      std::uint16_t milliseconds);

// ---- SYSTEM_INFO (structs.py make_system_info(archbits)) ----
// the ctypes default-aligned layout: the union dword @0, the dwPageSize @4,
// the pointer fields aligned to the pointer width. x64: 48 bytes; x86: 36.
inline constexpr std::size_t SYSTEM_INFO_SIZE_64 = 48;
inline constexpr std::size_t SYSTEM_INFO_SIZE_32 = 36;

void write_system_info(char* dst, int bits, std::uint64_t pe_image_address, std::uint64_t dll_upper_bound,
                       std::uint64_t page_size, std::uint64_t allocation_granularity);

// ---- Mutex (structs.py Mutex) ----
// the sync-object record the synchapi family parks on the handle: the name,
// the namespace prefix (''/'Global'), and the locked state. The CreateEvent
// flavour reuses the same class (the upstream comment: "similar enough to
// Mutex to just use it")
class Mutex {
public:
    Mutex(std::string name, std::string type)
        : name_(std::move(name)), locked_(false), type_(std::move(type)) {}

    void lock() { locked_ = true; }
    void unlock() { locked_ = false; }
    bool isFree() const { return !locked_; }

    const std::string& name() const noexcept { return name_; }
    const std::string& type() const noexcept { return type_; }
    bool locked() const noexcept { return locked_; }

private:
    std::string name_;
    bool locked_ = false;
    std::string type_;
};

// ---- STARTUPINFO (structs.py make_startup_info(archbits)) ----
// the default-aligned ctypes shape: the pointers ride the arch bits. x64:
// cb@0, lpReserved@8, lpDesktop@16, lpTitle@24, dwX@32, dwY@36, dwXSize@40,
// dwYSize@44, dwXCountChars@48, dwYCountChars@52, dwFillAttribute@56,
// dwFlags@60, wShowWindow@64, cbReserved2@66, lpReserved2@72, hStdInput@80,
// hStdOutput@88, hStdError@96 — 104 bytes total. x86: the pointers 4 bytes,
// the same order — 68 bytes total.
inline constexpr std::size_t STARTUPINFO_SIZE_64 = 104;
inline constexpr std::size_t STARTUPINFO_SIZE_32 = 68;

void write_startup_info(char* dst, int bits, std::uint64_t lp_desktop, std::uint32_t dw_flags,
                        std::uint64_t h_std_input, std::uint64_t h_std_output, std::uint64_t h_std_error);

// ---- Token (structs.py Token) ----
// the lazily-populated TokenInformationClass payload map; the ctor seeds
// TokenUIAccess/TokenGroups with pack(0x1) and TokenIntegrityLevel with a
// freshly-built SID (the root check rides the profile SYSTEM permission)
class Token {
public:
    // structs.py Token.TokenInformationClass (the subset the emulated APIs
    // touch; the full 49-value enum ports verbatim)
    enum class TokenInformationClass : std::uint32_t {
        TokenUser = 1,
        TokenGroups = 2,
        TokenPrivileges = 3,
        TokenOwner = 4,
        TokenPrimaryGroup = 5,
        TokenDefaultDacl = 6,
        TokenSource = 7,
        TokenType = 8,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenRestrictedSids = 11,
        TokenSessionId = 12,
        TokenGroupsAndPrivileges = 13,
        TokenSessionReference = 14,
        TokenSandBoxInert = 15,
        TokenAuditPolicy = 16,
        TokenOrigin = 17,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
        TokenElevation = 20,
        TokenHasRestrictions = 21,
        TokenAccessInformation = 22,
        TokenVirtualizationAllowed = 23,
        TokenVirtualizationEnabled = 24,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenMandatoryPolicy = 27,
        TokenLogonSid = 28,
        TokenIsAppContainer = 29,
        TokenCapabilities = 30,
        TokenAppContainerSid = 31,
        TokenAppContainerNumber = 32,
        TokenUserClaimAttributes = 33,
        TokenDeviceClaimAttributes = 34,
        TokenRestrictedUserClaimAttributes = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups = 37,
        TokenRestrictedDeviceGroups = 38,
        TokenSecurityAttributes = 39,
        TokenIsRestricted = 40,
        TokenProcessTrustLevel = 41,
        TokenPrivateNameSpace = 42,
        TokenSingletonAttributes = 43,
        TokenBnoIsolation = 44,
        TokenChildProcessFlags = 45,
        TokenIsLessPrivilegedAppContainer = 46,
        TokenOriginatingProcessTrustLevel = 48,
        MaxTokenInfoClass = 49
    };

    explicit Token(Qiling& ql);

    // Token.get(value): the packed bytes for the info class; the missing
    // entry raises (the upstream QlErrorNotImplemented shape rides the
    // caller)
    const std::string& get(std::uint32_t value) const;

private:
    std::map<std::uint32_t, std::string> struct_;
};

// structs.py make_sid(auth_count=1): the packed 12-byte SID image
// (Revision u8 @0, SubAuthorityCount u8 @1, the 6-byte IdentifierAuthority
// big-endian image @2, SubAuthority[0] u32 LE @8). The subauthority rides
// 0x1234 for the root profile, 545 otherwise (the verbatim FIXME shape).
std::string make_sid_bytes(std::uint32_t subauthority);

}  // namespace win
}  // namespace os
}  // namespace qiling

// ---- shell32/wsock32 struct images (structs.py make_shellex_info / 
// make_hostent; the 64-bit byte-offset layouts, the naturally-aligned
// little-endian cells) ----

namespace qiling {
namespace os {
namespace win {

// SHELLEXECUTEINFO (make_shellex_info(64)): cbSize u32@0, fMask u32@4,
// hwnd ptr@8, lpVerb@16, lpFile@24, lpParameters@32, lpDirectory@40,
// nShow i32@48, hInstApp@56, lpIDList@64, lpClass@72, hkeyClass@80,
// dwHotKey u32@88, DUMMYUNIONNAME ptr@96, hProcess@104 (112 bytes)
inline constexpr std::size_t SHELLEXECUTEINFO_SIZE = 112;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_CBSIZE = 0;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_HWND = 8;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_LPVERB = 16;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_LPFILE = 24;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_LPPARAMETERS = 32;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_LPDIRECTORY = 40;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_NSHOW = 48;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_HINSTAPP = 56;
inline constexpr std::size_t SHELLEXECUTEINFO_OFF_HPROCESS = 104;

// HOSTENT (make_hostent(64)): h_name@0, h_aliases@8, h_addrtype i16@16,
// h_length i16@18, h_addr_list@24 (32 bytes)
inline constexpr std::size_t HOSTENT_SIZE = 32;
inline constexpr std::size_t HOSTENT_OFF_HNAME = 0;
inline constexpr std::size_t HOSTENT_OFF_HALIASES = 8;
inline constexpr std::size_t HOSTENT_OFF_HADDRTYPE = 16;
inline constexpr std::size_t HOSTENT_OFF_HLENGTH = 18;
inline constexpr std::size_t HOSTENT_OFF_HADDRLIST = 24;

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_STRUCTS_HPP
