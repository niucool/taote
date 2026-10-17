// Ported from qiling/cc/ppc.py — the PPC calling convention.
#ifndef QILING_CC_PPC_HPP
#define QILING_CC_PPC_HPP

#include "qiling/cc/cc.hpp"

namespace qiling {
namespace cc {

// Default calling convention for PPC: first 6 arguments in r3..r8, the rest on
// the stack; the return address lives in lr.
class ppc : public QlCommonBaseCC {
public:
    explicit ppc(QlArch& arch);

    static int getNumSlots(int argbits) {
        (void)argbits;
        return 1;
    }

    std::uint64_t getReturnAddress() override;
    void setReturnAddress(std::uint64_t addr) override;
};

}  // namespace cc
}  // namespace qiling

#endif  // QILING_CC_PPC_HPP
