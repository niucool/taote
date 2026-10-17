// Ported from qiling/cc/__init__.py — the calling-convention base classes
// (QlCC, QlCommonBaseCC). The per-arch conventions live beside this file
// (intel.hpp, arm.hpp, ...).
//
// Python `IndexError` from __access_param maps to std::out_of_range;
// `NotImplementedError` on the unimplemented base interface maps to
// QlErrorNotImplemented (the framework's own analogue).
#ifndef QILING_CC_CC_HPP
#define QILING_CC_CC_HPP

#include <cstdint>

#include "qiling/exception.hpp"
#include "qiling/arch/arch.hpp"

namespace qiling {
namespace cc {

class QlCC {
public:
    // Initialize a calling convention instance.
    explicit QlCC(QlArch& arch) : arch_(arch) {}
    virtual ~QlCC() = default;

    // Get the number of slots allocated for an argument of width `argbits`.
    static int getNumSlots(int argbits) {
        (void)argbits;
        throw QlErrorNotImplemented("QlCC::getNumSlots");
    }

    // Read a value of native size from the specified argument slot.
    virtual std::uint64_t getRawParam(int slot, int argbits = 0) {
        (void)slot;
        (void)argbits;
        throw QlErrorNotImplemented("QlCC::getRawParam");
    }

    // Replace the value in the specified argument slot.
    virtual void setRawParam(int slot, std::uint64_t value, int argbits = 0) {
        (void)slot;
        (void)value;
        (void)argbits;
        throw QlErrorNotImplemented("QlCC::setRawParam");
    }

    // Get / set the function return value.
    virtual std::uint64_t getReturnValue() {
        throw QlErrorNotImplemented("QlCC::getReturnValue");
    }
    virtual void setReturnValue(std::uint64_t value) {
        (void)value;
        throw QlErrorNotImplemented("QlCC::setReturnValue");
    }

    // Get / set the function return address.
    virtual std::uint64_t getReturnAddress() {
        throw QlErrorNotImplemented("QlCC::getReturnAddress");
    }
    virtual void setReturnAddress(std::uint64_t addr) {
        (void)addr;
        throw QlErrorNotImplemented("QlCC::setReturnAddress");
    }

    // Reserve slots for function arguments (stage a new frame).
    virtual void reserve(int nslots) {
        (void)nslots;
        throw QlErrorNotImplemented("QlCC::reserve");
    }

    // Unwind frame and return the function return address.
    virtual std::uint64_t unwind(int nslots) {
        (void)nslots;
        throw QlErrorNotImplemented("QlCC::unwind");
    }

protected:
    QlArch& arch_;
};

// QlCommonBaseCC implements parameter access through both registers and the
// stack; the extending class is responsible to implement the rest.
class QlCommonBaseCC : public QlCC {
public:
    explicit QlCommonBaseCC(QlArch& arch)
        : QlCC(arch), asize_(arch.pointersize()) {}

    std::uint64_t getRawParam(int slot, int argbits = 0) override;
    void setRawParam(int slot, std::uint64_t value, int argbits = 0) override;
    std::uint64_t getReturnValue() override;
    void setReturnValue(std::uint64_t value) override;
    void reserve(int nslots) override;

protected:
    // make_arg_list: fill the per-convention register file; 0 (UC_X86_REG_INVALID-style
    // sentinel) marks a stack slot
    static constexpr int kMaxArgs = 16;
    using ArgRegs = int[kMaxArgs];

    static void fill_argregs(ArgRegs dst, std::initializer_list<int> regs);

    int argregs(int index) const;
    int first_stack_slot_index() const;

    int retreg_ = 0;
    ArgRegs argregs_ = {};
    int shadow_ = 0;
    // Python _retaddr_on_stack class attribute (QlCommonBaseCC: True; the ARM /
    // MIPS conventions flip it to False since the return address lives in a reg)
    int retaddr_on_stack_ = 1;
    int asize_ = 0;
};

}  // namespace cc
}  // namespace qiling

#endif  // QILING_CC_CC_HPP
