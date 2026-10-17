// Ported from qiling/utils.py — Phase 0 subset (PORT_PLAN.md §10 Phase 0):
// string/path helpers and the name -> enum conversions. The component factories
// (select_arch/select_os/select_loader/...) that replace utils.py's getattr
// resolution land in Phase 3 (PORT_PLAN.md 5.2); the emu-env guessing functions
// land with the loaders.
#ifndef QILING_UTILS_HPP
#define QILING_UTILS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "qiling/const.hpp"

namespace qiling {

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
