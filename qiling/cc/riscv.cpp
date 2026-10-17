#include "qiling/cc/riscv.hpp"

#include <unicorn/riscv.h>

namespace qiling {
namespace cc {

riscv::riscv(QlArch& arch) : QlCommonBaseCC(arch) {
    retreg_ = UC_RISCV_REG_A0;
    // a0..a5
    fill_argregs(argregs_, {UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2,
                            UC_RISCV_REG_A3, UC_RISCV_REG_A4, UC_RISCV_REG_A5});
    retaddr_on_stack_ = 0;  // the return address lives in ra
}

std::uint64_t riscv::getReturnAddress() {
    return arch_.regs().read("ra");
}

void riscv::setReturnAddress(std::uint64_t addr) {
    arch_.regs().write("ra", addr);
}

}  // namespace cc
}  // namespace qiling
