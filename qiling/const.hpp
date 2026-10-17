// Ported from qiling/const.py — enum and constant surface, values verbatim
// (PORT_PLAN.md §9: enum.Enum -> enum class; class names carry over unchanged so
// either tree can be grepped for the counterpart).
//
// Header-only: this module is pure enums/constants (mirror-layout rule 1).
#ifndef QILING_CONST_HPP
#define QILING_CONST_HPP

#include <array>
#include <cstddef>
#include <optional>
#include <string_view>
#include <utility>

namespace qiling {

enum class QL_ENDIAN : int { EL = 1, EB = 2 };

enum class QL_ARCH : int {
    X86 = 101,
    X8664 = 102,
    ARM = 103,
    ARM64 = 105,
    MIPS = 106,
    A8086 = 107,
    CORTEX_M = 109,
    RISCV = 110,
    RISCV64 = 111,
    PPC = 112,
};

enum class QL_OS : int {
    LINUX = 201,
    FREEBSD = 202,
    MACOS = 203,
    WINDOWS = 204,
    UEFI = 205,
    DOS = 206,
    QNX = 208,
    MCU = 209,
    BLOB = 210,
};

enum class QL_VERBOSE : int {
    DISABLED = -1,  // turn off all the output
    OFF = 0,        // output only warnings
    DEFAULT = 1,    // output warnings and Qiling execute process information
    DEBUG = 4,      // output all logs above and debug information, include syscall information
    DISASM = 10,    // output all assembly instructions during Qiling execution
    DUMP = 20,      // output any log Qiling can, include instructions and registers
};

enum class QL_DEBUGGER : int { GDB = 1, IDAPRO = 2, QDB = 3 };

enum class QL_INTERCEPT : int { CALL = 1, ENTER = 2, EXIT = 3 };

// Python: enum.Flag. Bit operators are provided below.
enum class QL_STOP : unsigned { NONE = 0, STACK_POINTER = 1u << 0, EXIT_TRAP = 1u << 1 };

constexpr QL_STOP operator|(QL_STOP a, QL_STOP b) noexcept {
    return static_cast<QL_STOP>(static_cast<unsigned>(a) | static_cast<unsigned>(b));
}
constexpr QL_STOP operator&(QL_STOP a, QL_STOP b) noexcept {
    return static_cast<QL_STOP>(static_cast<unsigned>(a) & static_cast<unsigned>(b));
}
constexpr QL_STOP operator^(QL_STOP a, QL_STOP b) noexcept {
    return static_cast<QL_STOP>(static_cast<unsigned>(a) ^ static_cast<unsigned>(b));
}
constexpr QL_STOP operator~(QL_STOP a) noexcept { return static_cast<QL_STOP>(~static_cast<unsigned>(a)); }

// `value & bits` truthiness analogue (Python Flag.__bool__ on the intersection).
constexpr bool flag_set(QL_STOP value, QL_STOP bits) noexcept {
    return (static_cast<unsigned>(value) & static_cast<unsigned>(bits)) != 0;
}

enum class QL_STATE : int { NOT_SET = 0, STARTED = 1, STOPPED = 2 };

inline constexpr int QL_HOOK_BLOCK = 0b0001;
inline constexpr int QL_CALL_BLOCK = 0b0010;

// Python: QL_OS_POSIX / QL_OS_BAREMETAL (Final tuples)
inline constexpr std::array<QL_OS, 4> QL_OS_POSIX{QL_OS::LINUX, QL_OS::FREEBSD, QL_OS::MACOS, QL_OS::QNX};
inline constexpr std::array<QL_OS, 1> QL_OS_BAREMETAL{QL_OS::MCU};

inline bool is_posix_os(QL_OS os) noexcept {
    for (const auto candidate : QL_OS_POSIX) {
        if (candidate == os) return true;
    }
    return false;
}

inline bool is_baremetal_os(QL_OS os) noexcept { return os == QL_OS::MCU; }

// ---- casefolded name lookup (mirrors const.py __casefold_enum; enum names are ASCII,
// so an ASCII-insensitive comparison reproduces str.casefold() exactly for them) ----

namespace detail {

constexpr unsigned char ascii_lower(unsigned char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c - 'A' + 'a') : c;
}

inline bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(static_cast<unsigned char>(a[i])) != ascii_lower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

template <typename E, std::size_t N>
std::optional<E> lookup(std::string_view name, const std::array<std::pair<std::string_view, E>, N>& table) {
    for (const auto& [key, value] : table) {
        if (iequals(name, key)) return value;
    }
    return std::nullopt;
}

}  // namespace detail

// ---- casefolded enum maps (const.py: endian_map, arch_map, os_map, verbose_map,
// debugger_map). Case-insensitive; no aliases here — alias tables live in utils.py
// and are applied by os_convert/arch_convert. ----

inline constexpr std::array<std::pair<std::string_view, QL_ENDIAN>, 2> endian_name_table{{
    {"el", QL_ENDIAN::EL},
    {"eb", QL_ENDIAN::EB},
}};

inline constexpr std::array<std::pair<std::string_view, QL_ARCH>, 10> arch_name_table{{
    {"x86", QL_ARCH::X86},
    {"x8664", QL_ARCH::X8664},
    {"arm", QL_ARCH::ARM},
    {"arm64", QL_ARCH::ARM64},
    {"mips", QL_ARCH::MIPS},
    {"a8086", QL_ARCH::A8086},
    {"cortex_m", QL_ARCH::CORTEX_M},
    {"riscv", QL_ARCH::RISCV},
    {"riscv64", QL_ARCH::RISCV64},
    {"ppc", QL_ARCH::PPC},
}};

inline constexpr std::array<std::pair<std::string_view, QL_OS>, 9> os_name_table{{
    {"linux", QL_OS::LINUX},
    {"freebsd", QL_OS::FREEBSD},
    {"macos", QL_OS::MACOS},
    {"windows", QL_OS::WINDOWS},
    {"uefi", QL_OS::UEFI},
    {"dos", QL_OS::DOS},
    {"qnx", QL_OS::QNX},
    {"mcu", QL_OS::MCU},
    {"blob", QL_OS::BLOB},
}};

inline constexpr std::array<std::pair<std::string_view, QL_VERBOSE>, 6> verbose_name_table{{
    {"disabled", QL_VERBOSE::DISABLED},
    {"off", QL_VERBOSE::OFF},
    {"default", QL_VERBOSE::DEFAULT},
    {"debug", QL_VERBOSE::DEBUG},
    {"disasm", QL_VERBOSE::DISASM},
    {"dump", QL_VERBOSE::DUMP},
}};

inline constexpr std::array<std::pair<std::string_view, QL_DEBUGGER>, 3> debugger_name_table{{
    {"gdb", QL_DEBUGGER::GDB},
    {"idapro", QL_DEBUGGER::IDAPRO},
    {"qdb", QL_DEBUGGER::QDB},
}};

inline std::optional<QL_ENDIAN> endian_from_name(std::string_view name) { return detail::lookup(name, endian_name_table); }
inline std::optional<QL_ARCH> arch_from_name(std::string_view name) { return detail::lookup(name, arch_name_table); }
inline std::optional<QL_OS> os_from_name(std::string_view name) { return detail::lookup(name, os_name_table); }
inline std::optional<QL_VERBOSE> verbose_from_name(std::string_view name) { return detail::lookup(name, verbose_name_table); }
inline std::optional<QL_DEBUGGER> debugger_from_name(std::string_view name) { return detail::lookup(name, debugger_name_table); }

// arch_os_map: QL_ARCH -> implied QL_OS; the only entry is CORTEX_M -> MCU (const.py)
constexpr std::optional<QL_OS> arch_os_map(QL_ARCH arch) {
    return arch == QL_ARCH::CORTEX_M ? std::optional<QL_OS>(QL_OS::MCU) : std::nullopt;
}

}  // namespace qiling

#endif  // QILING_CONST_HPP
