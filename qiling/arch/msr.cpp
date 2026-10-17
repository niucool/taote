#include "qiling/arch/msr.hpp"

#include "qiling/exception.hpp"

#include <cstdio>
#include <string>

namespace qiling {

std::uint64_t QlMsrManager::read(std::uint32_t msr) const {
    uc_x86_msr payload{msr, 0};
    if (uc_reg_read(&uc_, UC_X86_REG_MSR, &payload) != UC_ERR_OK) {
        char hex[16];
        std::snprintf(hex, sizeof(hex), "%x", msr);
        throw QlErrorArch(std::string("failed to read MSR 0x") + hex);
    }
    return payload.value;
}

void QlMsrManager::write(std::uint32_t msr, std::uint64_t value) {
    uc_x86_msr payload{msr, value};
    if (uc_reg_write(&uc_, UC_X86_REG_MSR, &payload) != UC_ERR_OK) {
        throw QlErrorArch("failed to write MSR");
    }
}

}  // namespace qiling
