#include "qiling/cc/cc.hpp"

#include <stdexcept>

#include <initializer_list>

namespace qiling {
namespace cc {

void QlCommonBaseCC::fill_argregs(ArgRegs dst, std::initializer_list<int> regs) {
    for (int i = 0; i < kMaxArgs; ++i) dst[i] = 0;
    int i = 0;
    for (const int reg : regs) dst[i++] = reg;
}

int QlCommonBaseCC::argregs(int index) const {
    if (index < 0 || index >= kMaxArgs) {
        // Python: IndexError(f'tried to access arg {index}, but only '
        //                    f'{len(self._argregs) - 1} args are supported')
        throw std::out_of_range("tried to access arg " + std::to_string(index) +
                                ", but only " + std::to_string(kMaxArgs - 1) + " args are supported");
    }
    return argregs_[index];
}

int QlCommonBaseCC::first_stack_slot_index() const {
    for (int i = 0; i < kMaxArgs; ++i) {
        if (argregs_[i] == 0) return i;  // the first stack (None) slot
    }
    return kMaxArgs;
}

std::uint64_t QlCommonBaseCC::getRawParam(int slot, int argbits) {
    const int reg = argregs(slot);
    const std::uint64_t value = (reg == 0)
        ? arch_.stack_read(static_cast<std::int64_t>((1 + shadow_ + (slot - first_stack_slot_index())) * asize_))
        : arch_.regs().read(reg);

    const auto mask = (argbits != 0) ? static_cast<std::uint64_t>((1ull << argbits) - 1) : ~std::uint64_t{0};
    return value & mask;
}

void QlCommonBaseCC::setRawParam(int slot, std::uint64_t value, int argbits) {
    const int reg = argregs(slot);
    const auto mask = (argbits != 0) ? static_cast<std::uint64_t>((1ull << argbits) - 1) : ~std::uint64_t{0};
    const auto masked = value & mask;

    if (reg == 0) {
        arch_.stack_write(static_cast<std::int64_t>((1 + shadow_ + (slot - first_stack_slot_index())) * asize_), masked);
    } else {
        arch_.regs().write(reg, masked);
    }
}

std::uint64_t QlCommonBaseCC::getReturnValue() { return arch_.regs().read(retreg_); }

void QlCommonBaseCC::setReturnValue(std::uint64_t value) { arch_.regs().write(retreg_, value); }

void QlCommonBaseCC::reserve(int nslots) {
    if (nslots >= kMaxArgs) {
        throw QlErrorBase("too many slots");
    }

    // count how many slots should be reserved on the stack
    int stack_slots = 0;
    for (int i = 0; i < nslots; ++i) {
        if (argregs_[i] == 0) ++stack_slots;
    }

    arch_.regs().set_arch_sp(arch_.regs().arch_sp() - static_cast<std::uint64_t>((shadow_ + stack_slots) * asize_));
}

}  // namespace cc
}  // namespace qiling
