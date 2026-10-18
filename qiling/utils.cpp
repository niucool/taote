#include "qiling/utils.hpp"

#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <tuple>

#include "qiling/arch/x86.hpp"
#include "qiling/os/freebsd/freebsd.hpp"
#include "qiling/os/macos/macos.hpp"
#include "qiling/loader/macho.hpp"
#include "qiling/os/qnx/qnx.hpp"
#include "qiling/os/dos/dos.hpp"
#include "qiling/loader/dos.hpp"
#include "qiling/os/mcu.hpp"
#include "qiling/os/uefi/uefi.hpp"
#include "qiling/loader/pe_uefi.hpp"
#include "qiling/loader/mcu.hpp"
#include "qiling/arch/arm.hpp"
#include "qiling/arch/arm64.hpp"
#include "qiling/arch/mips.hpp"
#include "qiling/arch/ppc.hpp"
#include "qiling/arch/riscv.hpp"
#include "qiling/exception.hpp"
#include "qiling/loader/blob.hpp"
#include "qiling/os/blob/blob.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/linux/linux.hpp"
#include "qiling/os/windows/windows.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/loader/elf.hpp"

namespace qiling {

namespace {

constexpr bool ascii_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

constexpr char ascii_lower_char(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Casefolds and resolves the alias table, mirroring utils.py __name_to_enum:
// mapping.get(aliases.get(key) or key).
template <typename E, std::size_t NA, std::size_t NN>
std::optional<E> name_to_enum(std::string_view name,
                              const std::array<std::pair<std::string_view, std::string_view>, NA>& aliases,
                              const std::array<std::pair<std::string_view, E>, NN>& names) {
    const std::string key = ascii_casefold(name);
    std::string_view resolved = key;
    for (const auto& [alias, target] : aliases) {
        if (key == alias) {
            resolved = target;
            break;
        }
    }
    return detail::lookup(resolved, names);
}

}  // namespace

// ---- string helpers ----

std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && ascii_space(s.front())) s.remove_prefix(1);
    while (!s.empty() && ascii_space(s.back())) s.remove_suffix(1);
    return s;
}

std::string ascii_casefold(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) out.push_back(ascii_lower_char(c));
    return out;
}

// int(s, 0) analogue. Grammar: [ws] [sign] (0x hex | 0o oct | 0b bin | dec) [ws],
// with single '_' separators allowed strictly between digits (PEP 515). Decimal
// with leading zeros is rejected (int('010', 0) -> ValueError; '0' itself is fine).
// The shared scanner returns the magnitude as unsigned long long; the typed
// wrappers apply the range checks (int64 for the signed analogue, uint64 for
// the address-domain sibling).
namespace {
std::tuple<unsigned long long, bool, bool> parse_int_base0_impl(std::string_view sv) {
    auto fail = []() -> std::tuple<unsigned long long, bool, bool> {
        throw std::invalid_argument("invalid literal for int() with base 0");
    };

    sv = trim(sv);
    if (sv.empty()) fail();

    bool negative = false;
    if (sv.front() == '+' || sv.front() == '-') {
        negative = sv.front() == '-';
        sv.remove_prefix(1);
    }

    int base = 10;
    if (sv.size() >= 2 && sv[0] == '0') {
        switch (ascii_lower_char(sv[1])) {
            case 'x': base = 16; sv.remove_prefix(2); break;
            case 'o': base = 8;  sv.remove_prefix(2); break;
            case 'b': base = 2;  sv.remove_prefix(2); break;
            default: break;
        }
    }

    if (sv.empty()) fail();  // bare sign or bare prefix

    const auto digit_ok = [base](char c) {
        const char d = ascii_lower_char(c);
        if (d >= '0' && d <= '9') return (d - '0') < base;
        if (d >= 'a' && d <= 'f') return (10 + d - 'a') < base;
        return false;
    };

    // Validate digits/underscores and copy digits without separators.
    std::string digits;
    digits.reserve(sv.size());
    for (std::size_t i = 0; i < sv.size(); ++i) {
        const char c = sv[i];
        if (c == '_') {
            // must sit strictly between two digits
            if (i == 0 || i + 1 >= sv.size() || !digit_ok(sv[i - 1]) || !digit_ok(sv[i + 1])) fail();
            continue;
        }
        if (!digit_ok(c)) fail();
        digits.push_back(c);
    }
    if (digits.empty()) fail();

    // int('010', 0) -> ValueError: decimal (no base prefix) may not have leading zeros
    if (base == 10 && digits.size() > 1 && digits.front() == '0') fail();

    unsigned long long magnitude = 0;
    const auto* first = digits.data();
    const auto* last = first + digits.size();
    const auto conv = std::from_chars(first, last, magnitude, base);
    if (conv.ec == std::errc::result_out_of_range || conv.ptr != last) fail();

    return {magnitude, negative, true};
}
}  // namespace

std::int64_t parse_int_base0(std::string_view sv) {
    const auto [magnitude, negative, ok] = parse_int_base0_impl(sv);

    constexpr unsigned long long pos_max = static_cast<unsigned long long>(std::numeric_limits<std::int64_t>::max());
    constexpr unsigned long long neg_max = pos_max + 1ull;  // |INT64_MIN|

    if (negative) {
        if (magnitude > neg_max) throw std::invalid_argument("invalid literal for int() with base 0");
        if (magnitude == neg_max) return std::numeric_limits<std::int64_t>::min();
        return -static_cast<std::int64_t>(magnitude);
    }
    if (magnitude > pos_max) throw std::invalid_argument("invalid literal for int() with base 0");
    return static_cast<std::int64_t>(magnitude);
}

std::uint64_t parse_uint_base0(std::string_view sv) {
    const auto [magnitude, negative, ok] = parse_int_base0_impl(sv);
    if (negative) {
        throw std::invalid_argument("invalid literal for int() with base 0");
    }
    return magnitude;
}

// ---- name -> enum conversion (utils.py; case-insensitive, with the same aliases) ----

std::optional<QL_OS> os_convert(std::string_view name) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 1> aliases{{
        {"darwin", "macos"},
    }};
    return name_to_enum(name, aliases, os_name_table);
}

std::optional<QL_ARCH> arch_convert(std::string_view name) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 3> aliases{{
        {"amd64", "x8664"},
        {"x86_64", "x8664"},
        {"riscv32", "riscv"},
    }};
    return name_to_enum(name, aliases, arch_name_table);
}

std::optional<QL_DEBUGGER> debugger_convert(std::string_view name) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 0> aliases{};
    return name_to_enum(name, aliases, debugger_name_table);
}

// ---- component factories (utils.py select_* — PORT_PLAN.md 5.2) ----

// helpers extracting the per-arch optional model out of the QL_CPU variant
namespace {

template <typename Model>
std::optional<Model> cpu_model_of(const QL_CPU& cpu) {
    if (const auto* p = std::get_if<Model>(&cpu)) {
        return *p;
    }
    return std::nullopt;
}

}  // namespace

ArchFactory select_arch(QL_ARCH archtype, const QL_CPU& cputype, QL_ENDIAN endian, bool thumb) {
    switch (archtype) {
        case QL_ARCH::A8086:
            return [cpu = cpu_model_of<X86_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchA8086>(ql, cpu);
            };
        case QL_ARCH::X86:
            return [cpu = cpu_model_of<X86_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchX86>(ql, cpu);
            };
        case QL_ARCH::X8664:
            return [cpu = cpu_model_of<X86_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchX8664>(ql, cpu);
            };
        case QL_ARCH::ARM:
            // arm.py binds endian + thumb kwargs
            return [cpu = cpu_model_of<ARM_CPU_MODEL>(cputype), endian, thumb](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchARM>(ql, cpu, endian, thumb);
            };
        case QL_ARCH::ARM64:
            return [cpu = cpu_model_of<ARM64_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchARM64>(ql, cpu);
            };
        case QL_ARCH::MIPS:
            // mips.py binds the endian kwarg
            return [cpu = cpu_model_of<MIPS_CPU_MODEL>(cputype), endian](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchMIPS>(ql, cpu, endian);
            };
        case QL_ARCH::PPC:
            return [cpu = cpu_model_of<PPC_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchPPC>(ql, cpu);
            };
        case QL_ARCH::RISCV:
            return [cpu = cpu_model_of<RISCV_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchRISCV>(ql, cpu);
            };
        case QL_ARCH::RISCV64:
            return [cpu = cpu_model_of<RISCV64_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchRISCV64>(ql, cpu);
            };
        case QL_ARCH::CORTEX_M:
            return [cpu = cpu_model_of<ARM_CPU_MODEL>(cputype)](Qiling* ql) -> std::unique_ptr<QlArch> {
                return std::make_unique<QlArchCORTEX_M>(ql, cpu);
            };
    }

    throw QlErrorArch("Unknown or unsupported architecture");
}

LoaderFactory select_loader(QL_OS ostype, bool libcache) {
    (void)libcache;  // consumed by the PE loader (Phase 3+)

    switch (ostype) {
        case QL_OS::BLOB:
            return [](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::QlLoaderBLOB>(ql);
            };
        case QL_OS::WINDOWS:
            return [libcache](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::QlLoaderPE>(ql, libcache);
            };
        case QL_OS::LINUX:
        case QL_OS::FREEBSD:
        case QL_OS::QNX:
            // QlLoaderELF covers both paths: the shellcode branch (the
            // loader/elf.py `if self.ql.code` blob mapping) and the ET_EXEC/
            // ET_DYN container parsing. The freebsd dialect shares it; the
            // qnx loaders land with their phases.
            return [](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::QlLoaderELF>(ql);
            };
        case QL_OS::MACOS:
            // the macos loader is its own container (macho.py QlLoaderMACHO);
            // the shellcode branch mirrors the ELF shape
            return [](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::macho::QlLoaderMachO>(ql);
            };
        case QL_OS::DOS:
            return [](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::QlLoaderDOS>(ql);
            };
        case QL_OS::UEFI:
            return [](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::QlLoaderPE_UEFI>(ql);
            };
        case QL_OS::MCU:
            return [](Qiling* ql) -> std::unique_ptr<loader::QlLoader> {
                return std::make_unique<loader::QlLoaderMCU>(ql);
            };
        default:
            // the remaining per-format loaders (ELF/Mach-O/DOS/UEFI/...) land
            // with their phases; until then the module lookup degrades
            throw QlErrorNotImplemented("loader for this os type is not implemented");
    }
}

OsFactory select_os(QL_OS ostype) {
    switch (ostype) {
        case QL_OS::BLOB:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<QlOsBlob>(ql);
            };
        case QL_OS::WINDOWS:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::windows::QlOsWindows>(ql);
            };
        case QL_OS::LINUX:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::linux::QlOsLinux>(ql);
            };
        case QL_OS::FREEBSD:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::freebsd::QlOsFreebsd>(ql);
            };
        case QL_OS::QNX:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::qnx::QlOsQnx>(ql);
            };
        case QL_OS::MACOS:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::macos::QlOsMacos>(ql);
            };
        case QL_OS::DOS:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::dos::QlOsDos>(ql);
            };
        case QL_OS::UEFI:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::uefi::QlOsUefi>(ql);
            };
        case QL_OS::MCU:
            return [](Qiling* ql) -> std::unique_ptr<QlOs> {
                return std::make_unique<os::QlOsMcu>(ql);
            };
        default:
            throw QlErrorNotImplemented("os layer for this os type is not implemented");
    }
}

std::function<QlDebugger*(Qiling*)> select_debugger(std::variant<bool, std::string> options) {
    if (std::holds_alternative<bool>(options)) {
        // false/None degrade to no debugger; true is an alias for "gdb"
        if (!std::get<bool>(options)) {
            return nullptr;
        }
        options = std::string("gdb");
    }

    // resolve the option string ("gdb", "qdb", "qdb:rr", "gdb:0.0.0.0:1234"):
    // the head before the first ':' names the debugger (select.py splits on
    // ':' and passes the rest as the debugger kwargs)
    const auto& option = std::get<std::string>(options);
    const auto colon = option.find(':');
    const std::string head = colon == std::string::npos ? option : option.substr(0, colon);

    if (debugger_convert(head).has_value()) {
        // debugger instances land with the interactive-debugging slice
        return nullptr;
    }

    throw QlErrorArch("Unknown or unsupported debugger");
}

// ---- emu-env guessing (utils.py ql_guess_emu_env) ----

namespace {

// __emu_env_from_pathname: extension and .kext probes
EmuEnvGuess emu_env_from_pathname(const std::filesystem::path& path) {
    std::error_code ec;

    const auto name = path.string();
    const std::string_view suffix(".kext");
    const bool is_kext = name.size() >= suffix.size() &&
        name.compare(name.size() - suffix.size(), suffix.size(), suffix.data(), suffix.size()) == 0;

    if (std::filesystem::is_directory(path, ec) && is_kext) {
        return EmuEnvGuess{QL_ARCH::X8664, QL_OS::MACOS, QL_ENDIAN::EL};
    }

    if (std::filesystem::is_regular_file(path, ec)) {
        const auto ext = path.extension().string();
        if (ext == ".DOS_COM" || ext == ".DOS_MBR" || ext == ".DOS_EXE") {
            return EmuEnvGuess{QL_ARCH::A8086, QL_OS::DOS, QL_ENDIAN::EL};
        }
    }

    return {};
}

// reads the first `count` bytes of a file (nullopt on I/O failure)
std::optional<std::vector<std::uint8_t>> read_head(const std::filesystem::path& path, std::size_t count) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> bytes(count);
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(count));
    bytes.resize(static_cast<std::size_t>(in.gcount()));
    return bytes;
}

// __emu_env_from_elf: the hand-rolled EI header sniff (no elffile dependency)
EmuEnvGuess emu_env_from_elf(const std::vector<std::uint8_t>& blob) {
    // e_ident offsets per the gabi4 ch4.eheader.html table
    constexpr std::uint8_t ELFCLASS32 = 1;
    constexpr std::uint8_t ELFCLASS64 = 2;
    constexpr std::uint8_t ELFDATA2LSB = 1;
    constexpr std::uint8_t ELFDATA2MSB = 2;

    constexpr std::uint16_t EM_386 = 3;
    constexpr std::uint16_t EM_MIPS = 8;
    constexpr std::uint16_t EM_PPC = 20;
    constexpr std::uint16_t EM_ARM = 40;
    constexpr std::uint16_t EM_X86_64 = 62;
    constexpr std::uint16_t EM_AARCH64 = 183;
    constexpr std::uint16_t EM_RISCV = 243;

    if (blob.size() < 20 || !(blob[0] == 0x7f && blob[1] == 'E' && blob[2] == 'L' && blob[3] == 'F')) {
        return {};
    }

    const std::uint8_t ei_class = blob[4];
    const std::uint8_t ei_data = blob[5];
    const std::uint8_t ei_osabi = blob[7];

    QL_ENDIAN archendian{};
    std::optional<QL_ARCH> archtype;
    std::optional<QL_OS> ostype;

    const bool little = ei_data == ELFDATA2LSB;
    if (!little && ei_data != ELFDATA2MSB) {
        return {};
    }
    archendian = little ? QL_ENDIAN::EL : QL_ENDIAN::EB;

    // e_machine lives at offset 18 (2 bytes, in the file's own endianness)
    const std::uint16_t machine = little
        ? static_cast<std::uint16_t>(blob[18] | (blob[19] << 8))
        : static_cast<std::uint16_t>((blob[18] << 8) | blob[19]);

    const bool is32 = ei_class == ELFCLASS32;
    const bool is64 = ei_class == ELFCLASS64;
    if (!is32 && !is64) {
        return {};
    }

    // per-class machine tables (utils.py machines32/machines64)
    if (is32) {
        switch (machine) {
            case EM_386:   archtype = QL_ARCH::X86; break;
            case EM_MIPS:  archtype = QL_ARCH::MIPS; break;
            case EM_ARM:   archtype = QL_ARCH::ARM; break;
            case EM_RISCV: archtype = QL_ARCH::RISCV; break;
            case EM_PPC:   archtype = QL_ARCH::PPC; break;
            default: break;
        }
    } else {
        switch (machine) {
            case EM_X86_64:  archtype = QL_ARCH::X8664; break;
            case EM_AARCH64: archtype = QL_ARCH::ARM64; break;
            case EM_RISCV:   archtype = QL_ARCH::RISCV64; break;
            default: break;
        }
    }

    // ei_osabi table (utils.py abis)
    switch (ei_osabi) {
        case 0:    // ELFOSABI_SYSV
        case 3:    // ELFOSABI_LINUX
        case 64:   // ELFOSABI_ARM_AEABI
        case 97:   // ELFOSABI_ARM
            ostype = QL_OS::LINUX;
            break;
        case 9:    // ELFOSABI_FREEBSD
            ostype = QL_OS::FREEBSD;
            break;
        case 255:  // ELFOSABI_STANDALONE
            ostype = QL_OS::BLOB;
            break;
        default:
            break;
    }

    // qnx detection: fuzzy look for the interpreter name in the first 0x200 bytes
    if (ostype == QL_OS::LINUX) {
        constexpr std::string_view interp = "ldqnx.so";
        const auto* begin = reinterpret_cast<const char*>(blob.data());
        const std::string_view head{begin, blob.size()};
        if (head.find(interp) != std::string_view::npos) {
            ostype = QL_OS::QNX;
        }
    }

    return EmuEnvGuess{archtype, ostype, archendian};
}

// __emu_env_from_macho: the 32-byte ident sniff
EmuEnvGuess emu_env_from_macho(const std::vector<std::uint8_t>& blob) {
    if (blob.size() < 8) {
        return {};
    }

    const bool sig32 = blob[0] == 0xce && blob[1] == 0xfa && blob[2] == 0xed && blob[3] == 0xfe;
    const bool sig64 = blob[0] == 0xcf && blob[1] == 0xfa && blob[2] == 0xed && blob[3] == 0xfe;
    const bool fat = blob[0] == 0xca && blob[1] == 0xfe && blob[2] == 0xba && blob[3] == 0xbe;

    if (!(sig32 || sig64 || fat)) {
        return {};
    }

    EmuEnvGuess guess;
    guess.ostype = QL_OS::MACOS;

    // ident[4] = cputype (LSB), ident[7] = the 64-bit flag (Python ident[7] == 0x01)
    if (blob[4] == 0x07 && blob[7] == 0x01) {
        guess.endian = QL_ENDIAN::EL;
        guess.arch = QL_ARCH::X8664;
    } else if (blob[4] == 0x0c && blob[7] == 0x01) {
        guess.endian = QL_ENDIAN::EL;
        guess.arch = QL_ARCH::ARM64;
    }

    return guess;
}

// __emu_env_from_pe: the hand-rolled MZ/PE sniff (pefile-free)
EmuEnvGuess emu_env_from_pe(const std::vector<std::uint8_t>& blob) {
    if (blob.size() < 0x40 + 4 || blob[0] != 'M' || blob[1] != 'Z') {
        return {};
    }

    const std::uint32_t pe_offset = static_cast<std::uint32_t>(blob[0x3c]) |
                                    (static_cast<std::uint32_t>(blob[0x3d]) << 8) |
                                    (static_cast<std::uint32_t>(blob[0x3e]) << 16) |
                                    (static_cast<std::uint32_t>(blob[0x3f]) << 24);

    // the PE signature and COFF machine field must fit
    if (pe_offset > blob.size() || blob.size() - pe_offset < 4 + 20) {
        return {};
    }
    if (blob[pe_offset] != 'P' || blob[pe_offset + 1] != 'E' || blob[pe_offset + 2] != 0 || blob[pe_offset + 3] != 0) {
        return {};
    }

    const std::uint16_t machine = static_cast<std::uint16_t>(blob[pe_offset + 4] | (blob[pe_offset + 5] << 8));

    EmuEnvGuess guess;
    guess.endian = QL_ENDIAN::EL;

    switch (machine) {
        case 0x014c: guess.arch = QL_ARCH::X86; break;      // IMAGE_FILE_MACHINE_I386
        case 0x8664: guess.arch = QL_ARCH::X8664; break;    // IMAGE_FILE_MACHINE_AMD64
        case 0x01c0: guess.arch = QL_ARCH::ARM; break;      // IMAGE_FILE_MACHINE_ARM
        case 0x01c4: guess.arch = QL_ARCH::ARM; break;      // IMAGE_FILE_MACHINE_THUMB
        case 0xAA64: guess.arch = QL_ARCH::ARM64; break;    // IMAGE_FILE_MACHINE_ARM64
        default:
            return {};  // unknown machine: the Python mapper.get returns None
    }

    // optional header subsystem: magic at +24, subsystem at +24+68 (PE32/PE32+ agree)
    const std::uint16_t subsystem = static_cast<std::uint16_t>(blob[pe_offset + 92] | (blob[pe_offset + 93] << 8));
    constexpr std::uint16_t efi_subsystems[] = {10, 11, 12, 14, 13, 15, 16};  // APPLICATION, BOOT_SERVICE_DRIVER,
                                                              // RUNTIME_DRIVER, ROM, plus the OBSOLETE trio
    bool is_uefi = false;
    for (const auto sub : efi_subsystems) {
        if (subsystem == sub) {
            is_uefi = true;
            break;
        }
    }
    guess.ostype = is_uefi ? QL_OS::UEFI : QL_OS::WINDOWS;

    return guess;
}

}  // namespace

EmuEnvGuess ql_guess_emu_env(const std::string& path) {
    const std::filesystem::path fspath(path);

    // guessing-methods order: pathname, elf, macho, pe — first decisive win
    if (const auto guess = emu_env_from_pathname(fspath); guess.arch.has_value()) {
        return guess;
    }

    // the ELF sniff reads 0x200 bytes (the Python reader does the same; the
    // fuzzy qnx interpreter check consumes the remainder)
    const auto blob = read_head(fspath, 0x200);
    if (!blob) {
        return {};
    }

    if (const auto guess = emu_env_from_elf(*blob); guess.arch.has_value()) {
        return guess;
    }
    if (const auto guess = emu_env_from_macho(*blob); guess.arch.has_value()) {
        return guess;
    }
    if (const auto guess = emu_env_from_pe(*blob); guess.arch.has_value()) {
        return guess;
    }

    return {};
}

}  // namespace qiling
