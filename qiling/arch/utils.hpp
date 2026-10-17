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
#include <string>
#include <string_view>
#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "qiling/const.hpp"

namespace qiling {

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

}  // namespace qiling

#endif  // QILING_ARCH_UTILS_HPP
