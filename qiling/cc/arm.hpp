// Ported from qiling/cc/arm.py — the ARM calling conventions
// (QlArmBaseCC, aarch64, aarch32).
#ifndef QILING_CC_ARM_HPP
#define QILING_CC_ARM_HPP

#include "qiling/cc/cc.hpp"

namespace qiling {
namespace cc {

// Calling convention base class for ARM-based systems. Supports arguments
// passing over registers and stack; the return address lives in lr.
class QlArmBaseCC : public QlCommonBaseCC {
public:
    using QlCommonBaseCC::QlCommonBaseCC;

    std::uint64_t getReturnAddress() override;
    void setReturnAddress(std::uint64_t addr) override;
    std::uint64_t unwind(int nslots) override;
};

// Default calling convention for ARM64.
class aarch64 : public QlArmBaseCC {
public:
    explicit aarch64(QlArch& arch);

    static int getNumSlots(int argbits) {
        (void)argbits;
        return 1;
    }
};

// Default calling convention for ARM32.
class aarch32 : public QlArmBaseCC {
public:
    explicit aarch32(QlArch& arch);

    static int getNumSlots(int argbits) {
        (void)argbits;
        return 1;
    }
};

}  // namespace cc
}  // namespace qiling

#endif  // QILING_CC_ARM_HPP
