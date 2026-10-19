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
    // the stdcall callee cleans its stack arguments: pop the return address,
    // then bump the sp past the argument slots (upstream intel.py stdcall.
    // unwind, verbatim)
    const auto retaddr = QlIntelBaseCC::unwind(nslots);
    // the guest callers disagree on who cleans the stack args: the real MSVC
    // binaries rely on the callee-side pop, while TCC-built bins (the pegasus
    // sample family) emit cdecl-style `add esp, N` at every call site. Peek
    // the instruction at the return address: an `add esp, imm` there means
    // the caller cleans, so the callee-side pop must be skipped
    bool caller_cleans = false;
    if (retaddr != 0) {
        try {
            const auto unit = arch().memory()->read(retaddr, 6);
            if (unit.size() >= 3 && unit[0] == 0x83 && unit[1] == 0xC4) {
                caller_cleans = true;  // add esp, imm8
            } else if (unit.size() >= 6 && unit[0] == 0x81 && unit[1] == 0xC4) {
                caller_cleans = true;  // add esp, imm32
            }
        } catch (...) {
            // the unmapped return address: keep the verbatim callee pop
        }
    }
    if (!caller_cleans) {
        arch().regs().set_arch_sp(arch().regs().arch_sp() + static_cast<std::uint64_t>(nslots) * 4);
    }
    return retaddr;
}

}  // namespace cc
}  // namespace qiling
