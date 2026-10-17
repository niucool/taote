#include "qiling/cc/ppc.hpp"

#include <unicorn/ppc.h>

namespace qiling {
namespace cc {

ppc::ppc(QlArch& arch) : QlCommonBaseCC(arch) {
    retreg_ = UC_PPC_REG_3;
    // r3..r8
    fill_argregs(argregs_, {UC_PPC_REG_3, UC_PPC_REG_4, UC_PPC_REG_5, UC_PPC_REG_6, UC_PPC_REG_7, UC_PPC_REG_8});
    retaddr_on_stack_ = 0;  // the return address lives in lr
}

std::uint64_t ppc::getReturnAddress() {
    return arch_.regs().read("lr");
}

void ppc::setReturnAddress(std::uint64_t addr) {
    arch_.regs().write("lr", addr);
}

}  // namespace cc
}  // namespace qiling
