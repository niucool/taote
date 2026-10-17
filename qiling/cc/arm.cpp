#include "qiling/cc/arm.hpp"

#include <unicorn/arm.h>
#include <unicorn/arm64.h>

namespace qiling {
namespace cc {

std::uint64_t QlArmBaseCC::getReturnAddress() {
    // the return address lives in lr (arm.py)
    return arch_.regs().read("lr");
}

void QlArmBaseCC::setReturnAddress(std::uint64_t addr) {
    arch_.regs().write("lr", addr);
}

std::uint64_t QlArmBaseCC::unwind(int nslots) {
    // TODO: cleanup? (arm.py, verbatim comment)
    (void)nslots;
    return getReturnAddress();
}

aarch64::aarch64(QlArch& arch) : QlArmBaseCC(arch) {
    retreg_ = UC_ARM64_REG_X0;
    // x0..x7
    fill_argregs(argregs_, {UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7});
    retaddr_on_stack_ = 0;  // _retaddr_on_stack = False
}

aarch32::aarch32(QlArch& arch) : QlArmBaseCC(arch) {
    retreg_ = UC_ARM_REG_R0;
    // r0..r3
    fill_argregs(argregs_, {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3});
    retaddr_on_stack_ = 0;  // _retaddr_on_stack = False
}

}  // namespace cc
}  // namespace qiling
