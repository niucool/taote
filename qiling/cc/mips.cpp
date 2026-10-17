#include "qiling/cc/mips.hpp"

#include <unicorn/mips.h>

namespace qiling {
namespace cc {

mipso32::mipso32(QlArch& arch) : QlCommonBaseCC(arch) {
    retreg_ = UC_MIPS_REG_V0;
    // a0..a3, with the 4-slot o32 shadow area
    fill_argregs(argregs_, {UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3});
    shadow_ = 4;
    retaddr_on_stack_ = 0;  // _retaddr_on_stack = False
}

std::uint64_t mipso32::getReturnAddress() {
    return arch_.regs().read("ra");
}

void mipso32::setReturnAddress(std::uint64_t addr) {
    arch_.regs().write("ra", addr);
}

std::uint64_t mipso32::unwind(int nslots) {
    // TODO: stack frame unwiding? (mips.py, verbatim comment)
    (void)nslots;
    return arch_.regs().read("ra");
}

}  // namespace cc
}  // namespace qiling
