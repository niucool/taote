// Ported from qiling/arch/msr.py — QlMsrManager enables access to Intel MSRs.
// Unicorn 2.x surfaces MSRs through the UC_X86_REG_MSR register id carrying a
// uc_x86_msr {rid, value} payload (no separate msr_read/write C API).
#ifndef QILING_ARCH_MSR_HPP
#define QILING_ARCH_MSR_HPP

#include <cstdint>

#include <unicorn/unicorn.h>

namespace qiling {

class QlMsrManager {
public:
    // Enables access to Intel MSR. The uc instance is not owned (weakref.proxy
    // in Python); the caller must keep it alive.
    explicit QlMsrManager(uc_engine& uc) : uc_(uc) {}

    // Read a model-specific register value.
    std::uint64_t read(std::uint32_t msr) const;

    // Write a model-specific register value.
    void write(std::uint32_t msr, std::uint64_t value);

private:
    uc_engine& uc_;
};

}  // namespace qiling

#endif  // QILING_ARCH_MSR_HPP
