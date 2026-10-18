// Ported from qiling/utils.py — Phase 0 subset (PORT_PLAN.md §10 Phase 0):
// string/path helpers and the name -> enum conversions. The component factories
// (select_arch/select_os/select_loader/...) that replace utils.py's getattr
// resolution land in Phase 3 (PORT_PLAN.md 5.2); the emu-env guessing functions
// land with the loaders.
#ifndef QILING_UTILS_HPP
#define QILING_UTILS_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "qiling/const.hpp"
#include "qiling/arch/models.hpp"

namespace qiling {

class Qiling;
class QlArch;
class QlOs;
class QlMemoryManager;
namespace hw { class QlHwManager; }

namespace loader { class QlLoader; }

class QlDebugger;  // the gdb/qdb stub surface (lands with Phase 6)

// ---- component factories (utils.py select_* — PORT_PLAN.md 5.2) ----
// Python resolves implementation classes via getattr(module, name) and binds
// constructor kwargs with functools.partial. The C++ ports return callable
// factories instead: the composition root invokes them with the Qiling* once
// the object graph is being assembled.

using ArchFactory = std::function<std::unique_ptr<QlArch>(Qiling*)>;
using LoaderFactory = std::function<std::unique_ptr<loader::QlLoader>(Qiling*)>;
using OsFactory = std::function<std::unique_ptr<QlOs>(Qiling*)>;

// select_arch(archtype, cputype, endian, thumb) — binds the per-arch kwargs
ArchFactory select_arch(QL_ARCH archtype, const QL_CPU& cputype, QL_ENDIAN endian, bool thumb);

// select_loader(ostype, libcache) — only the BLOB loader exists until the
// per-format loader slices land (PE in Phase 3, ELF in Phase 5); anything else
// degrades to QlErrorNotImplemented, mirroring the Python module-miss behavior.
LoaderFactory select_loader(QL_OS ostype, bool libcache);

// select_os(ostype) — same degradation policy as select_loader
OsFactory select_os(QL_OS ostype);

// select_component(component_type, component_name) — generic registry lookup
// used by core.py for os/memory and hw/hw. The returned factory takes the
// owning Qiling* (the C++ components derive their sub-handles from it).
std::function<std::unique_ptr<QlMemoryManager>(Qiling*)> select_component_memory();

// select_debugger(options) — options: false/none degrade to nullptr; true is
// an alias for "gdb"; "gdb[:host:port]" and "qdb[:rr]" resolve via
// debugger_convert. Debugger instances land with the interactive-debugging
// slice; the factory currently always yields nullptr after validating the
// option string (QlErrorArch on unknown names, like debugger_convert).
std::function<QlDebugger*(Qiling*)> select_debugger(std::variant<bool, std::string> options);

// ---- emu-env guessing (utils.py ql_guess_emu_env + the private sniffers) ----

// The (arch, os, endian) triple ql_guess_emu_env returns; nullopt fields mean
// "not determined" exactly like the Python None fields.
struct EmuEnvGuess {
    std::optional<QL_ARCH> arch;
    std::optional<QL_OS> ostype;
    std::optional<QL_ENDIAN> endian;
};

// guesses the emulated environment from the target file (pathname extension,
// then ELF / Mach-O / PE sniffing, mirroring the Python guessing-methods order).
// A missing file degrades to empty guesses (the Python open() failure path).
EmuEnvGuess ql_guess_emu_env(const std::string& path);

// ---- string helpers (utils.py general-purpose functions) ----

// str.strip() semantics (ASCII whitespace)
std::string_view trim(std::string_view s) noexcept;

// ASCII casefold — Qiling enum/flag names are ASCII, so this mirrors str.casefold()
std::string ascii_casefold(std::string_view s);

// int(s, 0) analogue: optional sign, 0x/0o/0b prefixes (any case), '_' digit
// separators between digits (PEP 515 style). Leading zeros not followed by a base
// prefix are rejected, mirroring int('010', 0) raising ValueError.
// Throws std::invalid_argument on malformed or out-of-range input.
std::int64_t parse_int_base0(std::string_view s);

// The unsigned sibling for the address-domain profile values above 2^63 (the
// vsyscall page): the same grammar, positive magnitudes up to 2^64-1; a sign
// raises std::invalid_argument. profile.py's int is unbounded; C++ splits the
// signed/unsigned domains -- the documented deviation.
std::uint64_t parse_uint_base0(std::string_view s);

// ---- name -> enum conversion (utils.py; case-insensitive, with the same aliases) ----

// utils.os_convert; alias: darwin -> macos
std::optional<QL_OS> os_convert(std::string_view name);

// utils.arch_convert; aliases: amd64/x86_64 -> x8664, riscv32 -> riscv
std::optional<QL_ARCH> arch_convert(std::string_view name);

// utils.debugger_convert
std::optional<QL_DEBUGGER> debugger_convert(std::string_view name);

// utils.arch_os_convert (backed by const.py's arch_os_map: only CORTEX_M -> MCU)
inline std::optional<QL_OS> arch_os_convert(QL_ARCH arch) { return arch_os_map(arch); }

}  // namespace qiling

#endif  // QILING_UTILS_HPP
