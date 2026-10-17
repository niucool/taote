#include "qiling/cc/intel.hpp"

#include <unicorn/x86.h>

namespace qiling {
namespace cc {

// ---- QlIntelBaseCC (cc/intel.py) ----

std::uint64_t QlIntelBaseCC::getReturnAddress() {
    // return address lives at the top of the stack
    return arch_.stack_read(0);
}

void QlIntelBaseCC::setReturnAddress(std::uint64_t addr) {
    arch_.stack_push(addr);
}

std::uint64_t QlIntelBaseCC::unwind(int nslots) {
    // no cleanup; just pop out the return address
    (void)nslots;
    return arch_.stack_pop();
}

// ---- QlIntel32::getRawParam/setRawParam (64-bit args span two slots) ----

std::uint64_t QlIntel32::getRawParam(int slot, int argbits) {
    if (argbits == 64) {
        const auto lo = QlCommonBaseCC::getRawParam(slot);
        const auto hi = QlCommonBaseCC::getRawParam(slot + 1);
        return (hi << 32) | lo;
    }
    return QlCommonBaseCC::getRawParam(slot, argbits);
}

void QlIntel32::setRawParam(int slot, std::uint64_t value, int argbits) {
    if (argbits == 64) {
        QlCommonBaseCC::setRawParam(slot, value & 0xffffffffull);
        QlCommonBaseCC::setRawParam(slot + 1, value >> 32);
        return;
    }
    QlCommonBaseCC::setRawParam(slot, value, argbits);
}

// ---- per-convention register files (make_arg_list results, sentinel 0 = stack) ----

amd64::amd64(QlArch& arch) : QlIntel64(arch) {
    retreg_ = UC_X86_REG_RAX;
    // POSIX x86-64: rdi, rsi, rdx, r10, r8, r9
    fill_argregs(argregs_, {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9});
}

ms64::ms64(QlArch& arch) : QlIntel64(arch) {
    retreg_ = UC_X86_REG_RAX;
    // Windows x86-64: rcx, rdx, r8, r9 + a 4-item shadow space
    fill_argregs(argregs_, {UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9});
    shadow_ = 4;
}

macosx64::macosx64(QlArch& arch) : QlIntel64(arch) {
    retreg_ = UC_X86_REG_RAX;
    // macOS x86-64: rdi, rsi, rdx, rcx, r8, r9
    fill_argregs(argregs_, {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9});
}

QlCdecl::QlCdecl(QlArch& arch) : QlIntel32(arch) {
    retreg_ = UC_X86_REG_EAX;
    // all arguments on the stack
    fill_argregs(argregs_, {});
}

QlStdcall::QlStdcall(QlArch& arch) : QlIntel32(arch) {
    retreg_ = UC_X86_REG_EAX;
    // all arguments on the stack
    fill_argregs(argregs_, {});
}

std::uint64_t QlStdcall::unwind(int nslots) {
    const auto retaddr = QlIntelBaseCC::unwind(nslots);
    arch_.regs().set_arch_sp(arch_.regs().arch_sp() + static_cast<std::uint64_t>(nslots * asize_));
    return retaddr;
}

}  // namespace cc
}  // namespace qiling
