// Ported from qiling/arch/utils.py — general purpose helpers used by qiling.arch.
// This Phase 1 slice ports the standalone `assembler()` factory and the RAII
// capstone/keystone engine wrappers (`Cs`/`Ks` analogues) that the arch classes
// return from their disassembler/assembler properties.
//
// The QlArchUtils tracing helpers (disassembler hook, setup_output) depend on the
// hook engine and QlMemoryManager and land in Phase 2 (PORT_PLAN.md §10).
#ifndef QILING_ARCH_UTILS_HPP
#define QILING_ARCH_UTILS_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "qiling/const.hpp"
#include "qiling/core_hooks_types.hpp"

namespace qiling {

class Qiling;
class HookRet;

// ---- capstone wrapper (the Python capstone `Cs` binding analogue) ----

class Cs {
public:
    struct Insn {
        std::uint64_t address;
        std::uint16_t size;
        std::string mnemonic;
        std::string op_str;
    };

    Cs(cs_arch arch, cs_mode mode);
    ~Cs();
    Cs(const Cs&) = delete;
    Cs& operator=(const Cs&) = delete;
    Cs(Cs&&) noexcept;
    Cs& operator=(Cs&&) noexcept;

    // Cs.disasm: decode a byte buffer at `address` (all successfully decoded
    // instructions, stopping at an invalid one)
    std::vector<Insn> disasm(std::string_view bytes, std::uint64_t address) const;

private:
    csh handle_ = 0;
};

// ---- keystone wrapper (the keystone-engine `Ks` binding analogue) ----

class Ks {
public:
    Ks(ks_arch arch, int mode);
    ~Ks();
    Ks(const Ks&) = delete;
    Ks& operator=(const Ks&) = delete;
    Ks(Ks&&) noexcept;
    Ks& operator=(Ks&&) noexcept;

    // Ks.asm: assemble the statement list into machine bytes. Throws
    // QlErrorBase on an assembly error (the KsError analogue).
    std::vector<std::uint8_t> assemble(std::string_view assembly) const;

private:
    ks_engine* handle_ = nullptr;
};

// used by qltool prior to ql instantiation. to get an assembler object after ql
// instantiation, use the appropriate ql.arch method (utils.py docstring, verbatim)
Ks assembler(QL_ARCH arch, QL_ENDIAN endianness, bool is_thumb);

// ---- QlArchUtils (arch/utils.py: the disassembly-trace helpers) ----
// These depend on the hook engine and the memory manager (both live in Phase
// 2); the instance is owned by the composition root and wired by the facade.

std::string basename_of(std::string_view path);

class QlArchUtils {
public:
    explicit QlArchUtils(Qiling& ql);
    ~QlArchUtils();

    // get_base_and_name (utils.py, lru_cache(maxsize=64)): the containing
    // image's base address and basename, coalescing consecutive map regions
    // that share a label; ('addr', '-') when no region matches
    std::pair<std::uint64_t, std::string> get_base_and_name(std::uint64_t addr);

    // disassembler (utils.py): the QL_VERBOSE.DISASM instruction trace line
    void disassembler(Qiling& ql, std::uint64_t address, std::uint32_t size);

    // setup_output (utils.py): at >= DISASM hook the code tracer; at >= DUMP
    // also hook the basic-block tracer
    void setup_output(QL_VERBOSE verbosity);

    // unregisters the installed hooks (the RAII teardown; the composition
    // root calls this before the uc engine closes)
    void shutdown();

public:
    // exposed for the owning QlArch dtor (the hooks must drop before the
    // QlCoreHooks base is torn down)
    Qiling& ql_;
    std::optional<HookRet> disasm_hook_;
    std::optional<HookRet> block_hook_;
    std::map<std::uint64_t, std::pair<std::uint64_t, std::string>> base_cache_;
};

}  // namespace qiling

#endif  // QILING_ARCH_UTILS_HPP
