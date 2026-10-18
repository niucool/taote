// Ported from qiling/core_hooks.py — the hook engine (part of the core.py
// Qiling class).
//
// Design (PORT_PLAN.md 5.1):
//   - One trampoline per UC hook signature (code/intr/mem-valid/mem-invalid/
//     insn-invalid/insn/addr), not per callback. Each trampoline receives a
//     heap-allocated context (the engine instance + packed dispatch argument)
//     and dispatches into the per-type dispatcher, which fans out to the
//     registered user callbacks — exactly one uc-level hook per event type,
//     serving every user hook registered for it.
//   - No exception may cross a Unicorn C frame: every trampoline wraps its
//     dispatch in try/catch (the `hookcallback` wrapper analogue, verbatim
//     semantics: ql.stop(); ql._internal_exception = ex), records the
//     exception as the internal exception and stops the emulation cleanly.
//     The composition root's emu_start (core.py:743) re-raises it after
//     uc_emu_start returns.
//   - Hook handles are RAII: destroying a HookRet unregisters the hook
//     (release() detaches for fire-and-forget registrations).
//
// Callback surface (core_hooks_types.py Protocols): the Python Protocols take
// the Qiling facade as their first parameter; in the C++ port the callbacks
// are std::function objects and the facade / user_data are captured at
// registration time (the C++ translation of the duck-typed callback shape).
#ifndef QILING_CORE_HOOKS_HPP
#define QILING_CORE_HOOKS_HPP

#include <any>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include <unicorn/unicorn.h>

#include "qiling/const.hpp"
#include "qiling/core_hooks_types.hpp"

namespace qiling {

// Don't assume self is Qiling (core_hooks.py, verbatim): the mixin is composed
// into the emulation facade; until the facade lands (Phase 3), stop() degrades
// to the plain emulation stop.

// the trampoline context: the engine instance + the packed dispatch argument
// (core_hooks.py pack_data = (self, hook_type / insn_type / address-range key))
struct HookCtx {
    QlCoreHooks* self;
    std::uint64_t type;
};
class QlCoreHooks {
public:
    explicit QlCoreHooks(uc_engine& uc);

    // deferred-init ctor for the composition root: Qiling derives from
    // QlCoreHooks but constructs the arch (and thus the uc handle) mid-ctor,
    // mirroring the Python `QlCoreHooks.__init__(self, self.uc)` call order
    QlCoreHooks() = default;
    void init(uc_engine& uc) { h_uc_ = &uc; }
    virtual ~QlCoreHooks();

    QlCoreHooks(const QlCoreHooks&) = delete;
    QlCoreHooks& operator=(const QlCoreHooks&) = delete;

    // ---- hook registration surface (core_hooks.py) ----

    // Intercept assembly instructions before they get executed.
    HookRet hook_code(TraceHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept landings in new basic blocks in a specified range.
    HookRet hook_block(TraceHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept illegal accesses to unmapped memory in a specified range.
    HookRet hook_mem_unmapped(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept illegal reading attempts from a specified range.
    HookRet hook_mem_read_invalid(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept illegal writing attempts to a specified range.
    HookRet hook_mem_write_invalid(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept illegal code fetching attempts from a specified range.
    HookRet hook_mem_fetch_invalid(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept benign memory accesses (reads, writes and fetches).
    HookRet hook_mem_valid(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept invalid memory accesses (invalid reads, writes and fetches).
    HookRet hook_mem_invalid(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept benign memory reads from a specified range.
    HookRet hook_mem_read(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept benign memory writes to a specified range.
    HookRet hook_mem_write(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept benign code fetches from a specified range.
    HookRet hook_mem_fetch(MemHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept execution from a certain memory address.
    HookRet hook_address(AddressHookCallback callback, std::uint64_t address);

    // Intercept interrupts; intno == -1 intercepts any interrupt.
    HookRet hook_intno(InterruptHookCallback callback, int intno);

    // TODO: remove; this is a special case of hook_intno(-1) (core_hooks.py, verbatim)
    HookRet hook_intr(InterruptHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept execution of a certain instruction type within a range; the
    // per-arch argument marshalling lands with the OS layers that consume the
    // typed payloads (Phase 4+).
    HookRet hook_insn(InsnHookCallback callback, std::uint64_t insn_type, std::uint64_t begin = 1,
                      std::uint64_t end = 0);

    // Intercept opcodes unicorn does not recognize; the callback is responsible
    // to advance the pc register, if needed.
    HookRet hook_insn_invalid(InvalidInsnHookCallback callback, std::uint64_t begin = 1, std::uint64_t end = 0);

    // Intercept certain emulation events within a specified range; the hook
    // type is a bitmap and may encode multiple events with one callback
    // (core_hooks.py ql_hook; the overload set carries the per-family callback
    // shapes the Python version passes dynamically)
    HookRet ql_hook(std::uint64_t hook_type, TraceHookCallback callback, std::uint64_t begin = 1,
                    std::uint64_t end = 0);
    HookRet ql_hook(std::uint64_t hook_type, MemHookCallback callback, std::uint64_t begin = 1,
                    std::uint64_t end = 0);
    HookRet ql_hook(std::uint64_t hook_type, InterruptHookCallback callback, std::uint64_t begin = 1,
                    std::uint64_t end = 0);
    HookRet ql_hook(std::uint64_t hook_type, InvalidInsnHookCallback callback, std::uint64_t begin = 1,
                    std::uint64_t end = 0);

    // Unregister an existing hook and release its resources.
    void hook_del(const HookRet& hret);

    // remove all hooks and release the underlying unicorn handles
    void clear_hooks();
    void clear_ql_hooks();

    // ---- exception discipline (the hookcallback wrapper surface) ----

    // core.py:373 — the exception caught by the trampoline during a hook; the
    // composition root's emu_start re-raises it after uc_emu_start returns
    // (5.1). Reset by emu_start before emulation begins.
    const std::exception_ptr& internal_exception() const noexcept { return internal_exception_; }
    void clear_internal_exception() noexcept { internal_exception_ = nullptr; }

    // core.py stop(): the plain path stops the emulator; the composition root
    // overrides it for the multithread / baremetal dispatch (Phases 4+)
    virtual void stop();

    // core.py emu_stop(): uc.emu_stop(); the QL_STATE tracking is the
    // facade's (Phase 3)
    void emu_stop();

    // the emulation stop state, mirrored from emu_stop/stop (core.py tracks
    // QL_STATE on the facade; the engine keeps the raw flag for the plain case)
    bool emu_stop_requested() const noexcept { return emu_stop_requested_; }

    // ---- engine internals (core_hooks.py underscore-prefixed methods) ----
    // called from the static C trampolines (qiling/core_hooks.cpp)

    // the hookcallback wrapper tail (core_hooks.py: ql.stop();
    // ql._internal_exception = ex)
    void internal_exception_from_hook(std::exception_ptr ep);

    // dispatcher fan-out (core_hooks.py dispatchers)
    void dispatch_intr(int intno, std::uint64_t hook_type);
    void dispatch_trace(std::uint64_t hook_type, std::uint64_t address, std::uint32_t size);
    bool dispatch_mem(std::uint64_t hook_type, int access, std::uint64_t address, std::uint32_t size,
                      std::int64_t value);
    bool dispatch_insn_invalid(std::uint64_t hook_type);
    void dispatch_insn(std::uint64_t insn_type, const std::vector<std::uint64_t>& args);
    void dispatch_addr(std::uint64_t address, std::uint32_t size);

private:
    // _ql_hook_internal: register a per-type dispatcher with the uc engine
    uc_hook hook_internal(std::uint64_t hook_type, void* trampoline, std::uint64_t begin, std::uint64_t end,
                          std::uint64_t context_arg, std::uint64_t insn_arg = 0, bool has_insn_arg = false);

    // _ql_hook: decompose the hook-type bitmap and register the hook
    void ql_hook_impl(std::uint64_t hook_type, std::shared_ptr<Hook> hook);

    // the UC_HOOK_INSN bound check reads the architectural pc; the composition
    // root wires the provider (Phase 3: ql.arch.regs.arch_pc). Without it the
    // check degrades to "always inside the range" (the default 1..0 range).
    void set_pc_reader(std::function<std::uint64_t()> reader) { pc_reader_ = std::move(reader); }

    uc_engine* h_uc_ = nullptr;

    // registries (core_hooks.py _hook / _hook_fuc / _insn_hook / _insn_hook_fuc /
    // _addr_hook / _addr_hook_fuc). The trampoline contexts are owned by a flat
    // list — one per event type (≤ the number of UC_HOOK_* types), released in
    // clear_hooks / the destructor.
    std::map<std::uint64_t, std::vector<std::shared_ptr<Hook>>> hook_;
    std::map<std::uint64_t, uc_hook> hook_fuc_;
    std::map<std::uint64_t, std::vector<std::shared_ptr<Hook>>> insn_hook_;
    std::map<std::uint64_t, uc_hook> insn_hook_fuc_;
    std::map<std::uint64_t, std::vector<std::shared_ptr<HookAddr>>> addr_hook_;
    std::map<std::uint64_t, uc_hook> addr_hook_fuc_;
    std::vector<std::unique_ptr<HookCtx>> hook_contexts_;

    std::exception_ptr internal_exception_;
    std::function<std::uint64_t()> pc_reader_;
    bool emu_stop_requested_ = false;
};

}  // namespace qiling

#endif  // QILING_CORE_HOOKS_HPP
