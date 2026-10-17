// Ported from qiling/arch/cpr.py + cpr64.py — access to the ARM coprocessor
// registers. Unicorn 2.x surfaces both flavors through a single register id
// carrying a payload struct:
//   aarch32 : UC_ARM_REG_CP_REG   with uc_arm_cp_reg  {cp, is64, sec, crn, crm, opc1, opc2, val}
//   arm64   : UC_ARM64_REG_CP_REG with uc_arm64_cp_reg {crn, crm, op0, op1, op2, val}
// (the Python binding wraps the same structs in its Uc.cpr_read/cpr_write).
#ifndef QILING_ARCH_CPR_HPP
#define QILING_ARCH_CPR_HPP

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

#include <unicorn/unicorn.h>

namespace qiling {

// ---- aarch32 coprocessor registers (cpr.py) ----

class QlCprManager {
public:
    // descriptor tuple (cpr.py _CPR_T): (coproc, opc1, crn, crm, opc2, el, is_64)
    struct Desc {
        int coproc;
        int opc1;
        int crn;
        int crm;
        int opc2;
        int el;
        bool is_64;
    };
    using RegMap = std::map<std::string, Desc, std::less<>>;

    QlCprManager(uc_engine& uc, RegMap regs_map);

    // named access (case-insensitive); unknown names throw std::out_of_range.
    // write does not mutate the manager (restore() const-calls it).
    std::uint64_t read(std::string_view name) const;
    void write(std::string_view name, std::uint64_t value) const;

    // raw access (cpr.py read/write; `el` maps onto the unicorn `sec` field)
    std::uint64_t read(int coproc, int opc1, int crn, int crm, int opc2, int el, bool is_64) const;
    void write(int coproc, int opc1, int crn, int crm, int opc2, int el, bool is_64, std::uint64_t value) const;

    // register_mapping (verbatim name)
    const RegMap& register_mapping() const noexcept { return register_mapping_; }

    // save/restore every mapped coprocessor register
    std::map<std::string, std::uint64_t> save() const;
    void restore(const std::map<std::string, std::uint64_t>& context) const;

private:
    uc_engine* uc_;
    RegMap register_mapping_;
};

// ---- arm64 coprocessor registers (cpr64.py) ----

class QlCpr64Manager {
public:
    // descriptor tuple (cpr64.py _CPR_T): (op0, op1, crn, crm, op2)
    struct Desc {
        int op0;
        int op1;
        int crn;
        int crm;
        int op2;
    };
    using RegMap = std::map<std::string, Desc, std::less<>>;

    QlCpr64Manager(uc_engine& uc, RegMap regs_map);

    std::uint64_t read(std::string_view name) const;
    void write(std::string_view name, std::uint64_t value) const;

    // raw access (cpr64.py read/write)
    std::uint64_t read(int op0, int op1, int crn, int crm, int op2) const;
    void write(int op0, int op1, int crn, int crm, int op2, std::uint64_t value) const;

    const RegMap& register_mapping() const noexcept { return register_mapping_; }

    std::map<std::string, std::uint64_t> save() const;
    void restore(const std::map<std::string, std::uint64_t>& context) const;

private:
    uc_engine* uc_;
    RegMap register_mapping_;
};

}  // namespace qiling

#endif  // QILING_ARCH_CPR_HPP
