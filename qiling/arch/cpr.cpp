#include "qiling/arch/cpr.hpp"

#include <stdexcept>

#include <unicorn/arm.h>
#include <unicorn/arm64.h>
#include <unicorn/unicorn.h>

#include "qiling/exception.hpp"

namespace qiling {

namespace {

// bounds mirrors from the Python binding's check_maxbits asserts (cpr.py/cpr64.py)
void assert_bits(std::uint64_t value, int bits, const char* what) {
    const auto limit = (bits >= 64) ? ~std::uint64_t{0} : ((1ull << bits) - 1);
    if ((value & ~limit) != 0) {
        throw QlErrorBase(std::string("coprocessor access: ") + what + " out of range");
    }
}

}  // namespace

// ---- QlCprManager (cpr.py) ----

QlCprManager::QlCprManager(uc_engine& uc, RegMap regs_map) : uc_(&uc), register_mapping_(std::move(regs_map)) {}

std::uint64_t QlCprManager::read(int coproc, int opc1, int crn, int crm, int opc2, int el, bool is_64) const {
    assert_bits(coproc, 4, "coproc");
    assert_bits(opc1, 3, "opc1");
    assert_bits(crn, 4, "crn");
    assert_bits(crm, 4, "crm");
    assert_bits(opc2, 3, "opc2");
    assert_bits(el, 2, "el");  // unicorn currently supports only EL0 and EL1

    uc_arm_cp_reg payload{};
    payload.cp = static_cast<std::uint32_t>(coproc);
    payload.is64 = is_64 ? 1u : 0u;
    payload.sec = static_cast<std::uint32_t>(el);
    payload.crn = static_cast<std::uint32_t>(crn);
    payload.crm = static_cast<std::uint32_t>(crm);
    payload.opc1 = static_cast<std::uint32_t>(opc1);
    payload.opc2 = static_cast<std::uint32_t>(opc2);

    if (uc_reg_read(uc_, UC_ARM_REG_CP_REG, &payload) != UC_ERR_OK) {
        throw QlErrorArch("failed to read coprocessor register");
    }
    return payload.val;
}

void QlCprManager::write(int coproc, int opc1, int crn, int crm, int opc2, int el, bool is_64, std::uint64_t value) const {
    assert_bits(coproc, 4, "coproc");
    assert_bits(opc1, 3, "opc1");
    assert_bits(crn, 4, "crn");
    assert_bits(crm, 4, "crm");
    assert_bits(opc2, 3, "opc2");
    assert_bits(el, 2, "el");

    uc_arm_cp_reg payload{};
    payload.cp = static_cast<std::uint32_t>(coproc);
    payload.is64 = is_64 ? 1u : 0u;
    payload.sec = static_cast<std::uint32_t>(el);
    payload.crn = static_cast<std::uint32_t>(crn);
    payload.crm = static_cast<std::uint32_t>(crm);
    payload.opc1 = static_cast<std::uint32_t>(opc1);
    payload.opc2 = static_cast<std::uint32_t>(opc2);
    payload.val = value;

    if (uc_reg_write(uc_, UC_ARM_REG_CP_REG, &payload) != UC_ERR_OK) {
        throw QlErrorArch("failed to write coprocessor register");
    }
}

std::uint64_t QlCprManager::read(std::string_view name) const {
    const auto it = register_mapping_.find(name);
    if (it == register_mapping_.end()) {
        throw std::out_of_range("unknown coprocessor register: " + std::string(name));
    }
    const auto& d = it->second;
    return read(d.coproc, d.opc1, d.crn, d.crm, d.opc2, d.el, d.is_64);
}

void QlCprManager::write(std::string_view name, std::uint64_t value) const {
    const auto it = register_mapping_.find(name);
    if (it == register_mapping_.end()) {
        throw std::out_of_range("unknown coprocessor register: " + std::string(name));
    }
    const auto& d = it->second;
    write(d.coproc, d.opc1, d.crn, d.crm, d.opc2, d.el, d.is_64, value);
}

std::map<std::string, std::uint64_t> QlCprManager::save() const {
    std::map<std::string, std::uint64_t> out;
    for (const auto& [name, d] : register_mapping_) {
        out.emplace(name, read(d.coproc, d.opc1, d.crn, d.crm, d.opc2, d.el, d.is_64));
    }
    return out;
}

void QlCprManager::restore(const std::map<std::string, std::uint64_t>& context) const {
    for (const auto& [name, value] : context) {
        const auto it = register_mapping_.find(name);
        if (it != register_mapping_.end()) {
            const auto& d = it->second;
            write(d.coproc, d.opc1, d.crn, d.crm, d.opc2, d.el, d.is_64, value);
        }
    }
}

// ---- QlCpr64Manager (cpr64.py) ----

QlCpr64Manager::QlCpr64Manager(uc_engine& uc, RegMap regs_map) : uc_(&uc), register_mapping_(std::move(regs_map)) {}

std::uint64_t QlCpr64Manager::read(int op0, int op1, int crn, int crm, int op2) const {
    assert_bits(op0, 2, "op0");
    assert_bits(op1, 3, "op1");
    assert_bits(crn, 4, "crn");
    assert_bits(crm, 4, "crm");
    assert_bits(op2, 3, "op2");

    uc_arm64_cp_reg payload{};
    payload.crn = static_cast<std::uint32_t>(crn);
    payload.crm = static_cast<std::uint32_t>(crm);
    payload.op0 = static_cast<std::uint32_t>(op0);
    payload.op1 = static_cast<std::uint32_t>(op1);
    payload.op2 = static_cast<std::uint32_t>(op2);

    if (uc_reg_read(uc_, UC_ARM64_REG_CP_REG, &payload) != UC_ERR_OK) {
        throw QlErrorArch("failed to read coprocessor register");
    }
    return payload.val;
}

void QlCpr64Manager::write(int op0, int op1, int crn, int crm, int op2, std::uint64_t value) const {
    assert_bits(op0, 2, "op0");
    assert_bits(op1, 3, "op1");
    assert_bits(crn, 4, "crn");
    assert_bits(crm, 4, "crm");
    assert_bits(op2, 3, "op2");

    uc_arm64_cp_reg payload{};
    payload.crn = static_cast<std::uint32_t>(crn);
    payload.crm = static_cast<std::uint32_t>(crm);
    payload.op0 = static_cast<std::uint32_t>(op0);
    payload.op1 = static_cast<std::uint32_t>(op1);
    payload.op2 = static_cast<std::uint32_t>(op2);
    payload.val = value;

    if (uc_reg_write(uc_, UC_ARM64_REG_CP_REG, &payload) != UC_ERR_OK) {
        throw QlErrorArch("failed to write coprocessor register");
    }
}

std::uint64_t QlCpr64Manager::read(std::string_view name) const {
    const auto it = register_mapping_.find(name);
    if (it == register_mapping_.end()) {
        throw std::out_of_range("unknown coprocessor register: " + std::string(name));
    }
    const auto& d = it->second;
    return read(d.op0, d.op1, d.crn, d.crm, d.op2);
}

void QlCpr64Manager::write(std::string_view name, std::uint64_t value) const {
    const auto it = register_mapping_.find(name);
    if (it == register_mapping_.end()) {
        throw std::out_of_range("unknown coprocessor register: " + std::string(name));
    }
    const auto& d = it->second;
    write(d.op0, d.op1, d.crn, d.crm, d.op2, value);
}

std::map<std::string, std::uint64_t> QlCpr64Manager::save() const {
    std::map<std::string, std::uint64_t> out;
    for (const auto& [name, d] : register_mapping_) {
        out.emplace(name, read(d.op0, d.op1, d.crn, d.crm, d.op2));
    }
    return out;
}

void QlCpr64Manager::restore(const std::map<std::string, std::uint64_t>& context) const {
    for (const auto& [name, value] : context) {
        const auto it = register_mapping_.find(name);
        if (it != register_mapping_.end()) {
            const auto& d = it->second;
            write(d.op0, d.op1, d.crn, d.crm, d.op2, value);
        }
    }
}

}  // namespace qiling
