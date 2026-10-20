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

// TEB (make_teb(64), the get_aligned_struct walk): the 13 native pointers
// then the tail — CurrentSEH@0, StackBase@8, StackLimit@16, SubSystemTib@24,
// FiberData@32, ArbitraryDataSlot@40, TebAddress@48, EnvironmentPointer@56,
// ProcessID@64, ThreadID@72, RpcHandle@80, TlsAddress@88, PebAddress@96,
// LastError i32@104, CriticalSectionsCount i32@108,
// CsrClientThreadAddress@112, Win32ThreadInfo@120, Win32ClientInfo[124]@128,
// ReservedWow64@256, CurrentLocale i32@264, FpSwStatusReg i32@268,
// ReservedOS[216]@272 (488 bytes)
inline constexpr std::size_t TEB_SIZE = 488;
inline constexpr std::size_t TEB_OFF_CURRENT_SEH = 0;
inline constexpr std::size_t TEB_OFF_STACK_BASE = 8;
inline constexpr std::size_t TEB_OFF_STACK_LIMIT = 16;
inline constexpr std::size_t TEB_OFF_SUB_SYSTEM_TIB = 24;
inline constexpr std::size_t TEB_OFF_FIBER_DATA = 32;
inline constexpr std::size_t TEB_OFF_ARBITRARY_DATA_SLOT = 40;
inline constexpr std::size_t TEB_OFF_TEB_ADDRESS = 48;
inline constexpr std::size_t TEB_OFF_ENVIRONMENT_POINTER = 56;
inline constexpr std::size_t TEB_OFF_PROCESS_ID = 64;
inline constexpr std::size_t TEB_OFF_THREAD_ID = 72;
inline constexpr std::size_t TEB_OFF_RPC_HANDLE = 80;
inline constexpr std::size_t TEB_OFF_TLS_ADDRESS = 88;
inline constexpr std::size_t TEB_OFF_PEB_ADDRESS = 96;
inline constexpr std::size_t TEB_OFF_LAST_ERROR = 104;
inline constexpr std::size_t TEB_OFF_CRITICAL_SECTIONS_COUNT = 108;
inline constexpr std::size_t TEB_OFF_CSR_CLIENT_THREAD_ADDRESS = 112;
inline constexpr std::size_t TEB_OFF_WIN32_THREAD_INFO = 120;
inline constexpr std::size_t TEB_OFF_WIN32_CLIENT_INFO = 128;
inline constexpr std::size_t TEB_OFF_RESERVED_WOW64 = 256;
inline constexpr std::size_t TEB_OFF_CURRENT_LOCALE = 264;
inline constexpr std::size_t TEB_OFF_FP_SW_STATUS_REG = 268;
inline constexpr std::size_t TEB_OFF_RESERVED_OS = 272;

// PEB (make_peb(64), padded to the 0x7c8 expected size): InheritedAddressSpace
// u8@0, ReadImageFileExecOptions u8@1, BeingDebugged u8@2, BitField u8@3,
// Mutant@8, ImageBaseAddress@16, LdrAddress@24, ProcessParameters@32,
// SubSystemData@40, ProcessHeap@48, FastPebLock@56, AtlThunkSListPtr@64,
// IFEOKey@72, CrossProcessFlags i32@80, KernelCallbackTable@88,
// SystemReserved i32@96, AtlThunkSListPtr32 i32@100, ApiSetMap@104,
// TlsExpansionCounter i32@112, TlsBitmap@120, TlsBitmapBits[2]@128,
// ReadOnlySharedMemoryBase@136, SharedData@144, ReadOnlyStaticServerData@152,
// AnsiCodePageData@160, OemCodePageData@168, UnicodeCaseTableData@176,
// NumberOfProcessors i32@184, NtGlobalFlag i32@188,
// CriticalSectionTimeout@192, _padding to 0x7c8
inline constexpr std::size_t PEB_SIZE = 0x7c8;
inline constexpr std::size_t PEB_OFF_INHERITED_ADDRESS_SPACE = 0;
inline constexpr std::size_t PEB_OFF_READ_IMAGE_FILE_EXEC_OPTIONS = 1;
inline constexpr std::size_t PEB_OFF_BEING_DEBUGGED = 2;
inline constexpr std::size_t PEB_OFF_BIT_FIELD = 3;
inline constexpr std::size_t PEB_OFF_MUTANT = 8;
inline constexpr std::size_t PEB_OFF_IMAGE_BASE_ADDRESS = 16;
inline constexpr std::size_t PEB_OFF_LDR_ADDRESS = 24;
inline constexpr std::size_t PEB_OFF_PROCESS_PARAMETERS = 32;
inline constexpr std::size_t PEB_OFF_SUB_SYSTEM_DATA = 40;
inline constexpr std::size_t PEB_OFF_PROCESS_HEAP = 48;
inline constexpr std::size_t PEB_OFF_FAST_PEB_LOCK = 56;
inline constexpr std::size_t PEB_OFF_ATL_THUNK_SLIST_PTR = 64;
inline constexpr std::size_t PEB_OFF_IFEO_KEY = 72;
inline constexpr std::size_t PEB_OFF_CROSS_PROCESS_FLAGS = 80;
inline constexpr std::size_t PEB_OFF_KERNEL_CALLBACK_TABLE = 88;
inline constexpr std::size_t PEB_OFF_SYSTEM_RESERVED = 96;
inline constexpr std::size_t PEB_OFF_ATL_THUNK_SLIST_PTR32 = 100;
inline constexpr std::size_t PEB_OFF_API_SET_MAP = 104;
inline constexpr std::size_t PEB_OFF_TLS_EXPANSION_COUNTER = 112;
inline constexpr std::size_t PEB_OFF_TLS_BITMAP = 120;
inline constexpr std::size_t PEB_OFF_TLS_BITMAP_BITS = 128;
inline constexpr std::size_t PEB_OFF_READONLY_SHARED_MEMORY_BASE = 136;
inline constexpr std::size_t PEB_OFF_SHARED_DATA = 144;
inline constexpr std::size_t PEB_OFF_READONLY_STATIC_SERVER_DATA = 152;
inline constexpr std::size_t PEB_OFF_ANSI_CODE_PAGE_DATA = 160;
inline constexpr std::size_t PEB_OFF_OEM_CODE_PAGE_DATA = 168;
inline constexpr std::size_t PEB_OFF_UNICODE_CASE_TABLE_DATA = 176;
inline constexpr std::size_t PEB_OFF_NUMBER_OF_PROCESSORS = 184;
inline constexpr std::size_t PEB_OFF_NT_GLOBAL_FLAG = 188;
inline constexpr std::size_t PEB_OFF_CRITICAL_SECTION_TIMEOUT = 192;

// PEB_LDR_DATA (make_ldr_data(64)): Length u32@0, Initialized u32@4,
// SsHandle@8, InLoadOrderModuleList@16, InMemoryOrderModuleList@32,
// InInitializationOrderModuleList@48, EntryInProgress@64,
// ShutdownInProgress@72, selfShutdownThreadId@80 (88 bytes)
inline constexpr std::size_t LDR_DATA_SIZE = 88;
inline constexpr std::size_t LDR_DATA_OFF_LENGTH = 0;
inline constexpr std::size_t LDR_DATA_OFF_INITIALIZED = 4;
inline constexpr std::size_t LDR_DATA_OFF_SS_HANDLE = 8;
inline constexpr std::size_t LDR_DATA_OFF_IN_LOAD_ORDER = 16;
inline constexpr std::size_t LDR_DATA_OFF_IN_MEMORY_ORDER = 32;
inline constexpr std::size_t LDR_DATA_OFF_IN_INITIALIZATION_ORDER = 48;
inline constexpr std::size_t LDR_DATA_OFF_ENTRY_IN_PROGRESS = 64;
inline constexpr std::size_t LDR_DATA_OFF_SHUTDOWN_IN_PROGRESS = 72;
inline constexpr std::size_t LDR_DATA_OFF_SELF_SHUTDOWN_THREAD_ID = 80;

// LDR_DATA_TABLE_ENTRY (make_ldr_data_table_entry(64))
inline constexpr std::size_t LDR_ENTRY_SIZE = 304;
inline constexpr std::size_t LDR_ENTRY_OFF_IN_LOAD_ORDER_LINKS = 0;
inline constexpr std::size_t LDR_ENTRY_OFF_IN_MEMORY_ORDER_LINKS = 16;
inline constexpr std::size_t LDR_ENTRY_OFF_IN_INITIALIZATION_ORDER_LINKS = 32;
inline constexpr std::size_t LDR_ENTRY_OFF_DLL_BASE = 48;
inline constexpr std::size_t LDR_ENTRY_OFF_ENTRY_POINT = 56;
inline constexpr std::size_t LDR_ENTRY_OFF_SIZE_OF_IMAGE = 64;
inline constexpr std::size_t LDR_ENTRY_OFF_FULL_DLL_NAME = 72;
inline constexpr std::size_t LDR_ENTRY_OFF_BASE_DLL_NAME = 88;
inline constexpr std::size_t LDR_ENTRY_OFF_FLAGS = 104;
inline constexpr std::size_t LDR_ENTRY_OFF_OBSOLETE_LOAD_COUNT = 112;
inline constexpr std::size_t LDR_ENTRY_OFF_TLS_INDEX = 114;
inline constexpr std::size_t LDR_ENTRY_OFF_HASH_LINKS = 120;

// UNICODE_STRING (make_unicode_string(64)): Length u16@0, MaximumLength u16@2,
// Buffer@8 (16 bytes)
inline constexpr std::size_t UNICODE_STRING_SIZE = 16;
inline constexpr std::size_t UNICODE_STRING_OFF_LENGTH = 0;
inline constexpr std::size_t UNICODE_STRING_OFF_MAXIMUM_LENGTH = 2;
inline constexpr std::size_t UNICODE_STRING_OFF_BUFFER = 8;

// ---- the loader's own structures, both word sizes ----------------------
//
// Everything above is the 64-bit column. Upstream builds these from
// make_teb/make_peb/make_ldr_data/make_ldr_data_table_entry/make_unicode_string
// (bits), so a 32-bit guest gets smaller structures with 4-byte pointer
// fields - and because the LDR entries and their name buffers are *heap*
// allocations, using the 64-bit sizes on an x86 guest shifts every later heap
// chunk (found on PMA 16-01, where taote's first guest allocation landed 0x280
// before the reference's and a packed sample read a byte of a pointer).
struct LoaderLayout {
    std::size_t teb_size;
    std::size_t peb_size;
    std::size_t ldr_data_size;
    std::size_t ldr_entry_size;
    std::size_t unicode_string_size;
    std::size_t unicode_string_off_buffer;
    std::size_t entry_off_in_load_order_links;
    std::size_t entry_off_in_memory_order_links;
    std::size_t entry_off_in_initialization_order_links;
    std::size_t entry_off_dll_base;
    std::size_t entry_off_full_dll_name;
    std::size_t entry_off_base_dll_name;
    // the TEB fields the loader seeds (the x86 column puts the PEB pointer at
    // 0x30 - fs:[0x30] is what a guest reads, and a wrong cell there makes
    // every anti-debug PEB peek read garbage)
    std::size_t teb_off_stack_base;
    std::size_t teb_off_stack_limit;
    std::size_t teb_off_teb_address;
    std::size_t teb_off_peb_address;
    std::size_t teb_off_last_error;
    // the PEB fields it seeds
    std::size_t peb_off_image_base_address;
    std::size_t peb_off_ldr_address;
    std::size_t peb_off_process_parameters;
    std::size_t peb_off_process_heap;
    std::size_t peb_off_number_of_processors;
    // the PEB_LDR_DATA order-list heads
    std::size_t ldr_data_off_in_load_order;
    std::size_t ldr_data_off_in_memory_order;
    std::size_t ldr_data_off_in_initialization_order;
};

constexpr LoaderLayout loader_layout(const int bits) {
    if (bits == 32) {
        return LoaderLayout{420, 1148, 48, 156, 8, 4, 0, 8, 16, 24, 36, 44,
                            4, 8, 24, 48, 52,
                            8, 12, 16, 24, 100,
                            12, 20, 28};
    }
    return LoaderLayout{TEB_SIZE, PEB_SIZE, LDR_DATA_SIZE, LDR_ENTRY_SIZE, UNICODE_STRING_SIZE,
                        UNICODE_STRING_OFF_BUFFER,
                        LDR_ENTRY_OFF_IN_LOAD_ORDER_LINKS,
                        LDR_ENTRY_OFF_IN_MEMORY_ORDER_LINKS,
                        LDR_ENTRY_OFF_IN_INITIALIZATION_ORDER_LINKS,
                        LDR_ENTRY_OFF_DLL_BASE,
                        LDR_ENTRY_OFF_FULL_DLL_NAME,
                        LDR_ENTRY_OFF_BASE_DLL_NAME,
                        TEB_OFF_STACK_BASE, TEB_OFF_STACK_LIMIT, TEB_OFF_TEB_ADDRESS,
                        TEB_OFF_PEB_ADDRESS, TEB_OFF_LAST_ERROR,
                        PEB_OFF_IMAGE_BASE_ADDRESS, PEB_OFF_LDR_ADDRESS,
                        PEB_OFF_PROCESS_PARAMETERS, PEB_OFF_PROCESS_HEAP,
                        PEB_OFF_NUMBER_OF_PROCESSORS,
                        LDR_DATA_OFF_IN_LOAD_ORDER, LDR_DATA_OFF_IN_MEMORY_ORDER,
                        LDR_DATA_OFF_IN_INITIALIZATION_ORDER};
}

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_STRUCTS_HPP
