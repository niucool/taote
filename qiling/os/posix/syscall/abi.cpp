#include "qiling/os/posix/syscall/abi.hpp"

#include <stdexcept>

#include <unicorn/arm.h>
#include <unicorn/arm64.h>
#include <unicorn/mips.h>
#include <unicorn/ppc.h>
#include <unicorn/riscv.h>
#include <unicorn/x86.h>

namespace qiling {
namespace os {
namespace posix {

std::uint64_t QlSyscallABI::get_id() const {
    return arch_.regs().read(id_reg());
}

void QlSyscallABI::set_return_value(std::uint64_t value) {
    arch_.regs().write(ret_reg(), value);
}

std::vector<std::uint64_t> QlSyscallABI::get_params(std::size_t count) const {
    const auto& regs = arg_regs();

    // abi/__init__.py get_params: a ValueError analogue when the requested
    // count exceeds the defined slots
    if (count > regs.size()) {
        throw QlErrorBase("requested more arguments than the abi defines");
    }

    std::vector<std::uint64_t> values;
    values.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        values.push_back(arch_.regs().read(regs[i]));
    }
    return values;
}

// ---- abi/intel.py ----

int QlSyscallABIIntel32::id_reg() const { return UC_X86_REG_EAX; }

const std::vector<int>& QlSyscallABIIntel32::arg_regs() const {
    static const std::vector<int> regs{
        UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
    };
    return regs;
}

int QlSyscallABIIntel32::ret_reg() const { return UC_X86_REG_EAX; }

int QlSyscallABIIntel64::id_reg() const { return UC_X86_REG_RAX; }

const std::vector<int>& QlSyscallABIIntel64::arg_regs() const {
    static const std::vector<int> regs{
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9,
    };
    return regs;
}

int QlSyscallABIIntel64::ret_reg() const { return UC_X86_REG_RAX; }

// ---- abi/arm.py ----

int QlSyscallABIArm::id_reg() const { return UC_ARM_REG_R7; }

const std::vector<int>& QlSyscallABIArm::arg_regs() const {
    static const std::vector<int> regs{
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
    };
    return regs;
}

int QlSyscallABIArm::ret_reg() const { return UC_ARM_REG_R0; }

int QlSyscallABIArm64::id_reg() const { return UC_ARM64_REG_X8; }

const std::vector<int>& QlSyscallABIArm64::arg_regs() const {
    static const std::vector<int> regs{
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
    };
    return regs;
}

int QlSyscallABIArm64::ret_reg() const { return UC_ARM64_REG_X0; }

// the factory (posix.py __get_syscall_mapper's abi selection)
std::unique_ptr<QlSyscallABI> make_syscall_abi(QL_ARCH archtype, QlArch& arch) {
    switch (archtype) {
        case QL_ARCH::X86:
            return std::make_unique<QlSyscallABIIntel32>(arch);
        case QL_ARCH::X8664:
            return std::make_unique<QlSyscallABIIntel64>(arch);
        case QL_ARCH::ARM:
        case QL_ARCH::CORTEX_M:
            return std::make_unique<QlSyscallABIArm>(arch);
        case QL_ARCH::ARM64:
            return std::make_unique<QlSyscallABIArm64>(arch);
        default:
            throw QlErrorArch("unsupported syscall abi architecture");
    }
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
