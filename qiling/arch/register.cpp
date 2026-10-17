#include "qiling/arch/register.hpp"

#include <algorithm>
#include <stdexcept>

#include "qiling/exception.hpp"
#include "qiling/utils.hpp"

namespace qiling {

QlRegisterManager::QlRegisterManager(uc_engine& uc, RegMap regs_map, std::string_view pc_reg, std::string_view sp_reg)
    : uc_(&uc), register_mapping_(std::move(regs_map)) {
    const auto pc_it = register_mapping_.find(pc_reg);
    const auto sp_it = register_mapping_.find(sp_reg);
    if (pc_it == register_mapping_.end() || sp_it == register_mapping_.end()) {
        throw QlErrorArch("pc/sp register not found in the registers map");
    }
    uc_pc_ = pc_it->second;
    uc_sp_ = sp_it->second;
}

QlRegisterManager::RegMap::const_iterator QlRegisterManager::find(std::string_view name) const {
    // Python lowercases the name (attributes and read(); __getattr__/__setattr__ do
    // name.lower()). Enum names are ASCII so ascii_casefold mirrors str.lower().
    return register_mapping_.find(ascii_casefold(name));
}

std::uint64_t QlRegisterManager::read(std::string_view name) const {
    const auto it = find(name);
    if (it == register_mapping_.end()) {
        throw std::out_of_range("unknown register: " + std::string(name));
    }
    return read(it->second);
}

void QlRegisterManager::write(std::string_view name, std::uint64_t value) {
    const auto it = find(name);
    if (it == register_mapping_.end()) {
        throw std::out_of_range("unknown register: " + std::string(name));
    }
    write(it->second, value);
}

std::uint64_t QlRegisterManager::read(int regid) const {
    std::uint64_t value = 0;
    if (uc_reg_read(uc_, regid, &value) != UC_ERR_OK) {
        throw QlErrorArch("failed to read register id " + std::to_string(regid));
    }
    return value;
}

void QlRegisterManager::write(int regid, std::uint64_t value) const {
    if (uc_reg_write(uc_, regid, &value) != UC_ERR_OK) {
        throw QlErrorArch("failed to write register id " + std::to_string(regid));
    }
}

std::map<std::string, std::uint64_t> QlRegisterManager::save() const {
    std::map<std::string, std::uint64_t> out;
    for (const auto& [name, regid] : register_mapping_) {
        out.emplace(name, read(regid));
    }
    return out;
}

void QlRegisterManager::restore(const std::map<std::string, std::uint64_t>& context) const {
    for (const auto& [name, value] : context) {
        const auto it = register_mapping_.find(name);
        if (it != register_mapping_.end()) write(it->second, value);
    }
}

std::uint64_t QlRegisterManager::arch_pc() const { return read(uc_pc_); }

void QlRegisterManager::set_arch_pc(std::uint64_t value) { write(uc_pc_, value); }

std::uint64_t QlRegisterManager::arch_sp() const { return read(uc_sp_); }

void QlRegisterManager::set_arch_sp(std::uint64_t value) { write(uc_sp_, value); }

}  // namespace qiling
