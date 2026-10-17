// Ported from qiling/cc/mips.py — the MIPS o32 calling convention.
#ifndef QILING_CC_MIPS_HPP
#define QILING_CC_MIPS_HPP

#include "qiling/cc/cc.hpp"

namespace qiling {
namespace cc {

// Calling convention used by MIPS o32: first 4 arguments in a0..a3, with a
// 4-slot caller-reserved shadow area; the return address lives in ra.
class mipso32 : public QlCommonBaseCC {
public:
    explicit mipso32(QlArch& arch);

    static int getNumSlots(int argbits) {
        (void)argbits;
        return 1;
    }

    std::uint64_t getReturnAddress() override;
    void setReturnAddress(std::uint64_t addr) override;
    std::uint64_t unwind(int nslots) override;
};

}  // namespace cc
}  // namespace qiling

#endif  // QILING_CC_MIPS_HPP
