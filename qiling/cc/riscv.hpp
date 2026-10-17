// Ported from qiling/cc/riscv.py — the RISC-V calling convention.
#ifndef QILING_CC_RISCV_HPP
#define QILING_CC_RISCV_HPP

#include "qiling/cc/cc.hpp"

namespace qiling {
namespace cc {

// Default calling convention for RISC-V: first 6 arguments in a0..a5, the rest
// on the stack; the return address lives in ra.
class riscv : public QlCommonBaseCC {
public:
    explicit riscv(QlArch& arch);

    static int getNumSlots(int argbits) {
        (void)argbits;
        return 1;
    }

    std::uint64_t getReturnAddress() override;
    void setReturnAddress(std::uint64_t addr) override;
};

}  // namespace cc
}  // namespace qiling

#endif  // QILING_CC_RISCV_HPP
