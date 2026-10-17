// Ported from qiling/arch/register.py — QlRegisterManager exposes named access
// to the CPU registers of a particular architecture (ql.arch.regs).
//
// Python maps `__getattr__`/`__setattr__` for attribute-style access
// (`ql.arch.regs.rax = 5`); C++ mirrors that with read/write overloads taking a
// (case-insensitive) register name or a unicorn register id.
#ifndef QILING_ARCH_REGISTER_HPP
#define QILING_ARCH_REGISTER_HPP

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

#include <unicorn/unicorn.h>

namespace qiling {

class QlRegisterManager {
public:
    using RegMap = std::map<std::string, int, std::less<>>;

    // Initialize the registers manager.
    //   uc: initialized unicorn instance (not owned)
    //   regs_map: register names mapped to their unicorn definitions
    //   pc_reg / sp_reg: names of the architectural program counter / stack pointer
    QlRegisterManager(uc_engine& uc, RegMap regs_map, std::string_view pc_reg, std::string_view sp_reg);

    // read a register value by name (case-insensitive); unknown names throw
    // std::out_of_range (the KeyError analogue)
    std::uint64_t read(std::string_view name) const;
    void write(std::string_view name, std::uint64_t value);

    // read/write by unicorn register id (write does not mutate the manager)
    std::uint64_t read(int regid) const;
    void write(int regid, std::uint64_t value) const;

    // register_mapping (verbatim name): name -> unicorn register id
    const RegMap& register_mapping() const noexcept { return register_mapping_; }

    // save CPU context: every mapped register -> value
    std::map<std::string, std::uint64_t> save() const;

    // restore CPU context (only the entries present in `context` are written)
    void restore(const std::map<std::string, std::uint64_t>& context) const;

    // architectural program counter
    std::uint64_t arch_pc() const;
    void set_arch_pc(std::uint64_t value);

    // architectural stack pointer
    std::uint64_t arch_sp() const;
    void set_arch_sp(std::uint64_t value);

private:
    RegMap::const_iterator find(std::string_view name) const;

    uc_engine* uc_;
    RegMap register_mapping_;
    int uc_pc_;
    int uc_sp_;
};

}  // namespace qiling

#endif  // QILING_ARCH_REGISTER_HPP
