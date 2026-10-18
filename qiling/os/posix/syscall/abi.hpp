// Ported from qiling/os/posix/syscall/abi/ — the per-architecture syscall ABI
// (QlSyscallABI + the Intel32/Intel64/ARM/Mips/PPC/RISCV derivatives). The
// register-id tables mirror the Python class attributes verbatim.
#ifndef QILING_OS_POSIX_SYSCALL_ABI_HPP
#define QILING_OS_POSIX_SYSCALL_ABI_HPP

#include <cstdint>
#include <memory>
#include <vector>

#include "qiling/arch/arch.hpp"

#include "qiling/arch/arch.hpp"

namespace qiling {

class QlArch;

namespace loader { class QlLoader; }

namespace os {
namespace posix {

class QlSyscallABI {
public:
    explicit QlSyscallABI(QlArch& arch) : arch_(arch) {}
    virtual ~QlSyscallABI() = default;

    // get_id — the syscall number register
    std::uint64_t get_id() const;

    // get_params — the first `count` argument registers (the mips O32
    // override reads the stack args beyond the 4 registers)
    virtual std::vector<std::uint64_t> get_params(std::size_t count) const;

    // set_return_value
    virtual void set_return_value(std::uint64_t value);

protected:
    virtual int id_reg() const = 0;
    virtual const std::vector<int>& arg_regs() const = 0;
    virtual int ret_reg() const = 0;

    QlArch& arch_;
};

// abi/intel.py
class QlSyscallABIIntel32 final : public QlSyscallABI {
public:
    using QlSyscallABI::QlSyscallABI;

protected:
    int id_reg() const override;
    const std::vector<int>& arg_regs() const override;
    int ret_reg() const override;
};

class QlSyscallABIIntel64 final : public QlSyscallABI {
public:
    using QlSyscallABI::QlSyscallABI;

protected:
    int id_reg() const override;
    const std::vector<int>& arg_regs() const override;
    int ret_reg() const override;
};

// abi/arm.py
class QlSyscallABIArm final : public QlSyscallABI {
public:
    using QlSyscallABI::QlSyscallABI;

protected:
    int id_reg() const override;
    const std::vector<int>& arg_regs() const override;
    int ret_reg() const override;
};

class QlSyscallABIArm64 final : public QlSyscallABI {
public:
    using QlSyscallABI::QlSyscallABI;

protected:
    int id_reg() const override;
    const std::vector<int>& arg_regs() const override;
    int ret_reg() const override;
};

// abi/mips.py QlMipsO32 - the O32 passes the first 4 args in a0-a3 and the
// rest on the stack; the return convention: the error flag rides a3
// (a negative value inverts onto a3=1 / v0=-value)
class QlSyscallABIMipsO32 final : public QlSyscallABI {
public:
    using QlSyscallABI::QlSyscallABI;

    std::vector<std::uint64_t> get_params(std::size_t count) const override;
    void set_return_value(std::uint64_t value) override;

protected:
    int id_reg() const override;
    const std::vector<int>& arg_regs() const override;
    int ret_reg() const override;
};

// the factory mirroring posix.py __get_syscall_mapper's arch selection
std::unique_ptr<QlSyscallABI> make_syscall_abi(QL_ARCH archtype, QlArch& arch);

}  // namespace posix
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_POSIX_SYSCALL_ABI_HPP
