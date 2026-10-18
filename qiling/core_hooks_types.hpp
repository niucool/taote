// Ported from qiling/core_hooks_types.py — the hook callback shapes and the
// hook objects (Hook / HookAddr / HookIntr / HookRet).
//
// The Python callback Protocols take the Qiling facade as their first
// parameter and an optional trailing user_data. In the C++ port the callbacks
// are std::function objects: the facade and the user_data are captured by the
// closure at registration time, so the std::function signatures carry only the
// event arguments (PORT_PLAN.md §7 construct mapping). Return value: an int
// with the QL_HOOK_BLOCK mask set blocks the execution of remaining hooks; 0
// stands for Python's None.
#ifndef QILING_CORE_HOOKS_TYPES_HPP
#define QILING_CORE_HOOKS_TYPES_HPP

#include <any>
#include <cstdint>
#include <functional>
#include <memory>

#include "qiling/const.hpp"

namespace qiling {

class QlCoreHooks;

// ---- callback shapes (core_hooks_types.py Protocols) ----

// TraceHookCallback: code and block hooks (address, size)
using TraceHookCallback = std::function<int(std::uint64_t address, std::uint32_t size)>;

// MemHookCallback: memory access hooks (access, address, size, value)
using MemHookCallback = std::function<int(int access, std::uint64_t address, std::uint32_t size, std::int64_t value)>;

// InterruptHookCallback: interrupt hooks (intno)
using InterruptHookCallback = std::function<int(std::uint32_t intno)>;

// InvalidInsnHookCallback: invalid instruction hooks ()
using InvalidInsnHookCallback = std::function<int()>;

// AddressHookCallback: address hooks ()
using AddressHookCallback = std::function<int()>;

// InsnHookCallback: instruction hooks. The argument list differs based on the
// instruction type (unicorn passes arch-specific payloads); the C++ port
// dispatches a generic argument vector, and the typed wrappers (syscall, in,
// out, cpuid) land with the OS layers that consume them.
using InsnHookCallback = std::function<int(const std::vector<std::uint64_t>& args)>;

// ---- hook objects (core_hooks_types.py) ----

class HookAddr;

class Hook {
public:
    Hook() = default;
    Hook(TraceHookCallback callback, std::uint64_t begin_ = 1, std::uint64_t end_ = 0);
    Hook(MemHookCallback callback, std::uint64_t begin_ = 1, std::uint64_t end_ = 0);
    Hook(InterruptHookCallback callback, std::uint64_t begin_ = 1, std::int64_t end_ = -1);
    Hook(InvalidInsnHookCallback callback, std::uint64_t begin_ = 1, std::uint64_t end_ = 0);

    virtual ~Hook() = default;

    // core_hooks_types.py bound_check: (end < begin) or (begin <= pc <= end) or
    // (begin <= (pc + size - 1) <= end)
    bool bound_check(std::uint64_t pc, std::uint64_t size = 1) const noexcept;

    // core_hooks_types.py check: per-family match predicate (HookIntr overrides)
    virtual bool check(std::uint64_t arg) const noexcept { (void)arg; return true; }

    // the family callbacks; exactly one is set per registration (Python stores
    // one callable the same way)
    TraceHookCallback trace;
    MemHookCallback mem;
    InterruptHookCallback intr;
    InvalidInsnHookCallback invalid_insn;
    AddressHookCallback addr_cb;
    InsnHookCallback insn;

    // user_data (Python: appended as a trailing argument; the C++ port
    // captures it in the closure — kept for introspection parity)
    std::any user_data;

    std::uint64_t begin = 1;
    std::int64_t end = 0;
};

// HookAddr: intercept execution from a certain memory address (begin = end =
// address); the bound check degenerates to the exact address
class HookAddr final : public Hook {
public:
    HookAddr(AddressHookCallback callback, std::uint64_t address, std::any user_data = {});

    std::uint64_t addr = 0;
};

// HookIntr: intercept a specific interrupt (intno == -1 intercepts any);
// check() matches the interrupt number
class HookIntr final : public Hook {
public:
    HookIntr(InterruptHookCallback callback, int intno, std::any user_data = {});

    bool check(std::uint64_t intno) const noexcept override;

    int intno = 0;
};

// HookRet: the registration handle. Destroying it unregisters the hook (5.1
// RAII hook handles); release() detaches without unregistering.
class HookRet {
public:
    HookRet() = default;
    HookRet(QlCoreHooks* hooks, std::uint64_t hook_type, std::shared_ptr<Hook> obj);
    ~HookRet();

    HookRet(HookRet&& other) noexcept;
    HookRet& operator=(HookRet&& other) noexcept;
    HookRet(const HookRet&) = delete;
    HookRet& operator=(const HookRet&) = delete;

    // Unregister the hook explicitly (core_hooks_types.py HookRet.remove).
    void remove();

    // Detach without unregistering (the registration outlives this handle).
    void release() noexcept;

    const std::shared_ptr<Hook>& obj() const noexcept { return obj_; }
    std::uint64_t type() const noexcept { return type_; }

private:
    QlCoreHooks* hooks_ = nullptr;
    std::uint64_t type_ = 0;
    std::shared_ptr<Hook> obj_;
};

}  // namespace qiling

#endif  // QILING_CORE_HOOKS_TYPES_HPP
