#include "qiling/core_hooks.hpp"

#include <cstdio>
#include <cstdlib>

#include <algorithm>

#include <unicorn/unicorn.h>

#include "qiling/exception.hpp"

namespace qiling {

// ---- hookcallback (core_hooks.py) ----
//
// Python wraps every dispatcher callback in `hookcallback(ql, callback)`: the
// wrapper catches any exception, calls ql.stop() and records it as
// ql._internal_exception. The C++ translation is the trampoline try/catch:
// the exception never crosses the unicorn C frame (undefined behavior per
// 5.1); it is recorded on the engine and the emulation is stopped cleanly.
// emu_start (core.py:743) re-raises what was recorded, after uc_emu_start
// returns.

namespace {

// ---- one trampoline per UC hook signature ----

void trampoline_trace(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        ctx->self->dispatch_trace(ctx->type, address, size);
    } catch (...) {
        // hookcallback: ql.stop(); ql._internal_exception = ex
        ctx->self->internal_exception_from_hook(std::current_exception());
    }
}

void trampoline_intr(uc_engine* uc, std::uint32_t intno, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        ctx->self->dispatch_intr(static_cast<int>(intno), ctx->type);
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
    }
}

// valid memory events (MEM_READ / MEM_WRITE / MEM_FETCH / MEM_READ_AFTER):
// uc_cb_hookmem_t
void trampoline_mem_valid(uc_engine* uc, uc_mem_type access, std::uint64_t address, std::uint32_t size,
                          std::int64_t value, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        ctx->self->dispatch_mem(ctx->type, static_cast<int>(access), address, size, value);
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
    }
}

// invalid memory events (UNMAPPED / PROT): uc_cb_eventmem_t — returns whether
// the access was handled; core_hooks.py's _hook_mem_cb raises QlErrorCoreHook
// for an unhandled invalid access, which the wrapper records
bool trampoline_mem_invalid(uc_engine* uc, uc_mem_type access, std::uint64_t address, std::uint32_t size,
                            std::int64_t value, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        return ctx->self->dispatch_mem(ctx->type, static_cast<int>(access), address, size, value);
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
        return false;  // stop the emulation at the invalid access
    }
}

bool trampoline_insn_invalid(uc_engine* uc, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        return ctx->self->dispatch_insn_invalid(ctx->type);
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
        return false;
    }
}

// UC_HOOK_INSN: unicorn delivers the per-arch payload through dedicated
// callback shapes (x86 syscall: void(uc, user_data), etc.). The generic
// dispatcher receives whatever the per-arch trampoline marshals; the typed
// argument marshalling lands with the OS layers that consume it (Phase 4+).
void trampoline_insn(uc_engine* uc, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        ctx->self->dispatch_insn(ctx->type, {});
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
    }
}

// native-ranged code hook: unicorn already enforced the begin/end range, so
// the callback runs directly — no bound_check loop over unrelated hooks
void trampoline_trace_ranged(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<RangedTraceCtx*>(user_data);
    // a global hook (winapi dispatch / scheduler) that returned QL_HOOK_BLOCK
    // for this address already fired (the global dispatcher registers first),
    // so the remaining hooks are suppressed — the same break the in-list loop
    // would have taken
    if (ctx->self->trace_blocked()) {
        return;
    }
    try {
        const int ret = ctx->hook->trace ? ctx->hook->trace(address, size) : 0;
        (void)ret;  // a native hook has no sibling list to block
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
    }
}

// address hooks are a special case of UC_HOOK_CODE with the callback bound to
// a single address (core_hooks.py _ql_hook_addr_internal)
void trampoline_addr(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<HookCtx*>(user_data);
    try {
        ctx->self->dispatch_addr(address, size);
    } catch (...) {
        ctx->self->internal_exception_from_hook(std::current_exception());
    }
}

}  // namespace

// ---- Hook (core_hooks_types.py) ----

bool Hook::bound_check(std::uint64_t pc, std::uint64_t size) const noexcept {
    // core_hooks_types.py bound_check: (end < begin) or (begin <= pc <= end) or
    //                                   (begin <= (pc + size - 1) <= end)
    const auto b = static_cast<std::uint64_t>(begin);
    const auto e = static_cast<std::uint64_t>(end);
    return (end < begin) || (b <= pc && pc <= e) || (b <= (pc + size - 1) && (pc + size - 1) <= e);
}

HookAddr::HookAddr(AddressHookCallback callback, std::uint64_t address, std::any user_data_) {
    addr_cb = std::move(callback);
    user_data = std::move(user_data_);
    begin = address;
    end = static_cast<std::int64_t>(address);
    addr = address;
}

HookIntr::HookIntr(InterruptHookCallback callback, int intno_, std::any user_data_)
    : intno(intno_) {
    intr = std::move(callback);
    user_data = std::move(user_data_);
    begin = 0;
    end = -1;
}

bool HookIntr::check(std::uint64_t arg) const noexcept {
    // core_hooks_types.py HookIntr.check: (intno < 0) or (self.intno == intno)
    return (intno < 0) || (static_cast<std::uint64_t>(intno) == arg);
}

// ---- HookRet ----

HookRet::HookRet(QlCoreHooks* hooks, std::uint64_t hook_type, std::shared_ptr<Hook> obj)
    : hooks_(hooks), type_(hook_type), obj_(std::move(obj)) {}

HookRet::~HookRet() {
    // 5.1 RAII hook handles: destroying the handle unregisters the hook
    if (hooks_ != nullptr) {
        hooks_->hook_del(*this);
        hooks_ = nullptr;
    }
}

HookRet::HookRet(HookRet&& other) noexcept
    : hooks_(other.hooks_), type_(other.type_), obj_(std::move(other.obj_)) {
    other.hooks_ = nullptr;
}

HookRet& HookRet::operator=(HookRet&& other) noexcept {
    if (this != &other) {
        if (hooks_ != nullptr) hooks_->hook_del(*this);
        hooks_ = other.hooks_;
        type_ = other.type_;
        obj_ = std::move(other.obj_);
        other.hooks_ = nullptr;
    }
    return *this;
}

void HookRet::remove() {
    if (hooks_ != nullptr) {
        hooks_->hook_del(*this);
        hooks_ = nullptr;
    }
}

void HookRet::release() noexcept { hooks_ = nullptr; }

// ---- QlCoreHooks (core_hooks.py) ----

QlCoreHooks::QlCoreHooks(uc_engine& uc) : h_uc_(&uc) {}

QlCoreHooks::~QlCoreHooks() {
    // release every underlying unicorn handle and trampoline context; the
    // registries are emptied first so pending HookRet handles become detached
    clear_hooks();
}

void QlCoreHooks::stop() {
    // core.py stop(): the plain path stops the emulator; the composition root
    // overrides for the multithread / baremetal dispatch (Phases 4+ / OQ 9)
    emu_stop();
}

void QlCoreHooks::emu_stop() {
    // core.py emu_stop(): uc.emu_stop(); the QL_STATE tracking is the facade's
    emu_stop_requested_ = true;
    uc_emu_stop(h_uc_);
}

void QlCoreHooks::internal_exception_from_hook(std::exception_ptr ep) {
    // core_hooks.py hookcallback: ql.stop(); ql._internal_exception = ex
    stop();
    internal_exception_ = std::move(ep);
}

// ---- dispatchers (core_hooks.py) ----
//
// The dispatchers' unhandled-event exceptions propagate into the trampoline
// try/catch, which records them (the Python dispatchers rely on the
// hookcallback wrapper for the same effect).

void QlCoreHooks::dispatch_intr(int intno, std::uint64_t hook_type) {
    bool handled = false;

    const auto it = hook_.find(hook_type);
    if (it != hook_.end()) {
        // the hooks list might change from within a hook method; iterating
        // over a copy is the safer practice (core_hooks.py, verbatim note)
        const auto hooks_list = it->second;

        for (const auto& hook : hooks_list) {
            if (hook->check(static_cast<std::uint64_t>(intno))) {
                handled = true;
                const int ret = hook->intr ? hook->intr(static_cast<std::uint32_t>(intno)) : 0;

                if ((ret & QL_HOOK_BLOCK) != 0) {
                    break;
                }
            }
        }
    }

    if (!handled) {
        throw QlErrorCoreHook("_hook_intr_cb : not handled");
    }
}

void QlCoreHooks::dispatch_trace(std::uint64_t hook_type, std::uint64_t address, std::uint32_t size) {
    trace_blocked_ = false;
    const auto it = hook_.find(hook_type);
    if (it != hook_.end()) {
        const auto hooks_list = it->second;

        for (const auto& hook : hooks_list) {
            if (hook->bound_check(address, size)) {
                const int ret = hook->trace ? hook->trace(address, size) : 0;

                if ((ret & QL_HOOK_BLOCK) != 0) {
                    trace_blocked_ = true;
                    break;
                }
            }
        }
    }
}

bool QlCoreHooks::dispatch_mem(std::uint64_t hook_type, int access, std::uint64_t address, std::uint32_t size,
                               std::int64_t value) {
    bool handled = false;

    const auto it = hook_.find(hook_type);
    if (it != hook_.end()) {
        const auto hooks_list = it->second;

        for (const auto& hook : hooks_list) {
            if (hook->bound_check(address, size)) {
                handled = true;
                const int ret = hook->mem ? hook->mem(access, address, size, value) : 0;

                if ((ret & QL_HOOK_BLOCK) != 0) {
                    break;
                }
            }
        }
    }

    if (!handled && (hook_type & (UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_PROT)) != 0) {
        throw QlErrorCoreHook("_hook_mem_cb : not handled");
    }

    return true;
}

bool QlCoreHooks::dispatch_insn_invalid(std::uint64_t hook_type) {
    (void)hook_type;
    bool handled = false;

    const auto it = hook_.find(UC_HOOK_INSN_INVALID);
    if (it != hook_.end()) {
        const auto hooks_list = it->second;

        for (const auto& hook : hooks_list) {
            handled = true;
            const int ret = hook->invalid_insn ? hook->invalid_insn() : 0;

            if ((ret & QL_HOOK_BLOCK) != 0) {
                break;
            }
        }
    }

    if (!handled) {
        throw QlErrorCoreHook("_hook_insn_invalid_cb : not handled");
    }

    return true;
}

void QlCoreHooks::dispatch_insn(std::uint64_t insn_type, const std::vector<std::uint64_t>& args) {
    const auto it = insn_hook_.find(insn_type);
    if (it != insn_hook_.end()) {
        const auto hooks_list = it->second;

        for (const auto& hook : hooks_list) {
            if (hook->bound_check(pc_reader_ ? pc_reader_() : 0)) {
                if (hook->insn) {
                    // _hook_insn_cb: the callback may return a (block, retval)
                    // pair to override the instruction behavior; the typed
                    // overrides land with the OS layers (Phase 4+)
                    const int ret = hook->insn(args);

                    if ((ret & QL_HOOK_BLOCK) != 0) {
                        break;
                    }
                }
            }
        }
    }
}

void QlCoreHooks::dispatch_addr(std::uint64_t address, std::uint32_t size) {
    (void)size;
    const auto it = addr_hook_.find(address);
    if (it != addr_hook_.end()) {
        const auto hooks_list = it->second;

        for (const auto& hook : hooks_list) {
            const int ret = hook->addr_cb ? hook->addr_cb() : 0;

            if ((ret & QL_HOOK_BLOCK) != 0) {
                break;
            }
        }
    }
}

// ---- registration (core_hooks.py _ql_hook_internal / _ql_hook) ----

uc_hook QlCoreHooks::hook_internal(std::uint64_t hook_type, void* trampoline, std::uint64_t begin, std::uint64_t end,
                                   std::uint64_t context_arg, std::uint64_t insn_arg, bool has_insn_arg) {
    // _ql_hook_internal: register the per-type dispatcher with the uc engine;
    // the trampoline context is (self, hook_type / insn_type)
    uc_hook handle = 0;
    uc_err err;

    // the trampoline context carries (self, dispatch argument) — the pack_data
    // of core_hooks.py; it is owned by hook_contexts_ until clear_hooks
    auto ctx = std::make_unique<HookCtx>(HookCtx{this, context_arg});

    if (has_insn_arg) {
        // UC_HOOK_INSN carries the instruction id as the trailing hook_add
        // argument (core_hooks.py: hook_add(t, _callback, pack, 1, 0, ins_t))
        err = uc_hook_add(h_uc_, &handle, static_cast<int>(hook_type), trampoline, ctx.get(), begin, end, insn_arg);
    } else {
        err = uc_hook_add(h_uc_, &handle, static_cast<int>(hook_type), trampoline, ctx.get(), begin, end);
    }

    if (err != UC_ERR_OK) {
        throw QlErrorCoreHook("failed to add hook (uc_err " + std::to_string(static_cast<int>(err)) + ")");
    }
    hook_contexts_.emplace_back(std::move(ctx));
    return handle;
}

void QlCoreHooks::ql_hook_impl(std::uint64_t hook_type, std::shared_ptr<Hook> hook) {
    // A bounded-range UC_HOOK_CODE becomes its own native uc hook: unicorn
    // enforces the range, so out-of-range instructions never reach the
    // trampoline and the per-instruction dispatch loop skips the hook
    // entirely. The criterion mirrors bound_check's always-fire shape: a hook
    // with end < begin (the default 1..0, or an explicit begin..0) covers the
    // whole space and stays in the global list, as does an explicit full range
    // (0..0xffffffffffffffff).
    const bool native_ranged =
        (hook_type == UC_HOOK_CODE || hook_type == UC_HOOK_BLOCK) &&
        (hook->end >= static_cast<std::int64_t>(hook->begin)) &&
        (hook->end < static_cast<std::int64_t>(0xffffffffffffffffull));
    if (native_ranged) {
        auto ctx = std::make_unique<RangedTraceCtx>();
        ctx->self = this;
        ctx->hook = hook;
        uc_hook handle = 0;
        const auto err = uc_hook_add(h_uc_, &handle, static_cast<int>(hook_type),
                                     reinterpret_cast<void*>(trampoline_trace_ranged), ctx.get(),
                                     hook->begin, static_cast<std::uint64_t>(hook->end));
        if (err != UC_ERR_OK) {
            throw QlErrorCoreHook("failed to add ranged code hook (uc_err " + std::to_string(static_cast<int>(err)) + ")");
        }
        ranged_code_.emplace(hook.get(), RangedCodeEntry{handle, std::move(ctx)});
        return;
    }

    // _ql_hook: decompose the hook-type bitmap over the per-type handlers;
    // a compound type (e.g. UC_HOOK_MEM_UNMAPPED) appends the same hook to
    // every matching type list (core_hooks.py processes all matching bits)
    struct TypeHandler {
        std::uint64_t type;
        void* trampoline;
    };

    const TypeHandler type_handlers[] = {
        {UC_HOOK_INTR, reinterpret_cast<void*>(trampoline_intr)},
        {UC_HOOK_CODE, reinterpret_cast<void*>(trampoline_trace)},
        {UC_HOOK_BLOCK, reinterpret_cast<void*>(trampoline_trace)},
        {UC_HOOK_MEM_READ_UNMAPPED, reinterpret_cast<void*>(trampoline_mem_invalid)},
        {UC_HOOK_MEM_WRITE_UNMAPPED, reinterpret_cast<void*>(trampoline_mem_invalid)},
        {UC_HOOK_MEM_FETCH_UNMAPPED, reinterpret_cast<void*>(trampoline_mem_invalid)},
        {UC_HOOK_MEM_READ_PROT, reinterpret_cast<void*>(trampoline_mem_invalid)},
        {UC_HOOK_MEM_WRITE_PROT, reinterpret_cast<void*>(trampoline_mem_invalid)},
        {UC_HOOK_MEM_FETCH_PROT, reinterpret_cast<void*>(trampoline_mem_invalid)},
        {UC_HOOK_MEM_READ, reinterpret_cast<void*>(trampoline_mem_valid)},
        {UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(trampoline_mem_valid)},
        {UC_HOOK_MEM_FETCH, reinterpret_cast<void*>(trampoline_mem_valid)},
        {UC_HOOK_MEM_READ_AFTER, reinterpret_cast<void*>(trampoline_mem_valid)},
        {UC_HOOK_INSN_INVALID, reinterpret_cast<void*>(trampoline_insn_invalid)},
    };

    for (const auto& handler : type_handlers) {
        if ((hook_type & handler.type) == 0) {
            continue;
        }

        if (hook_fuc_.find(handler.type) == hook_fuc_.end()) {
            // the first hook for this type registers the uc-level dispatcher;
            // the uc hook always watches the entire space (begin=1, end=0) and
            // the per-hook ranges are enforced by Hook::bound_check
            auto ctx = std::make_unique<HookCtx>(HookCtx{this, handler.type});
            const uc_hook handle = hook_internal(handler.type, handler.trampoline, 1, 0, handler.type);
            hook_fuc_[handler.type] = handle;
        }
        hook_[handler.type].push_back(std::move(hook));
    }
}

HookRet QlCoreHooks::ql_hook(std::uint64_t hook_type, TraceHookCallback callback, std::uint64_t begin,
                             std::uint64_t end) {
    auto hook = std::make_shared<Hook>();
    hook->trace = std::move(callback);
    hook->begin = begin;
    hook->end = static_cast<std::int64_t>(end);
    ql_hook_impl(hook_type, hook);
    return HookRet(this, hook_type, hook);
}

HookRet QlCoreHooks::ql_hook(std::uint64_t hook_type, MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    auto hook = std::make_shared<Hook>();
    hook->mem = std::move(callback);
    hook->begin = begin;
    hook->end = static_cast<std::int64_t>(end);
    ql_hook_impl(hook_type, hook);
    return HookRet(this, hook_type, hook);
}

HookRet QlCoreHooks::ql_hook(std::uint64_t hook_type, InterruptHookCallback callback, std::uint64_t begin,
                             std::uint64_t end) {
    auto hook = std::make_shared<Hook>();
    hook->intr = std::move(callback);
    hook->begin = begin;
    hook->end = static_cast<std::int64_t>(end);
    ql_hook_impl(hook_type, hook);
    return HookRet(this, hook_type, hook);
}

HookRet QlCoreHooks::ql_hook(std::uint64_t hook_type, InvalidInsnHookCallback callback, std::uint64_t begin,
                             std::uint64_t end) {
    auto hook = std::make_shared<Hook>();
    hook->invalid_insn = std::move(callback);
    hook->begin = begin;
    hook->end = static_cast<std::int64_t>(end);
    ql_hook_impl(hook_type, hook);
    return HookRet(this, hook_type, hook);
}

HookRet QlCoreHooks::hook_code(TraceHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_CODE, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_block(TraceHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_BLOCK, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_unmapped(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_UNMAPPED, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_read_invalid(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_READ_INVALID, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_write_invalid(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_WRITE_INVALID, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_fetch_invalid(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_FETCH_INVALID, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_valid(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_VALID, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_invalid(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_INVALID, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_read(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_READ, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_write(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_WRITE, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_mem_fetch(MemHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_MEM_FETCH, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_insn(InsnHookCallback callback, std::uint64_t insn_type, std::uint64_t begin,
                               std::uint64_t end) {
    // _insn_hook family: one uc hook per instruction type, carrying the insn
    // id as the trailing hook_add argument
    auto hook = std::make_shared<Hook>();
    hook->insn = std::move(callback);
    hook->begin = begin;
    hook->end = static_cast<std::int64_t>(end);

    if (insn_hook_fuc_.find(insn_type) == insn_hook_fuc_.end()) {
        auto ctx = std::make_unique<HookCtx>(HookCtx{this, insn_type});
        const uc_hook handle =
            hook_internal(UC_HOOK_INSN, reinterpret_cast<void*>(trampoline_insn), 1, 0, insn_type, insn_type, true);
        insn_hook_fuc_[insn_type] = handle;
        hook_contexts_.emplace_back(std::move(ctx));
    }
    insn_hook_[insn_type].push_back(std::move(hook));

    return HookRet(this, UC_HOOK_INSN, hook);
}

HookRet QlCoreHooks::hook_insn_invalid(InvalidInsnHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    return ql_hook(UC_HOOK_INSN_INVALID, std::move(callback), begin, end);
}

HookRet QlCoreHooks::hook_intno(InterruptHookCallback callback, int intno) {
    // HookIntr carries the intno for the check() match (core_hooks_types.py);
    // the UC_HOOK_INTR registration goes through the shared _ql_hook fan-out
    auto hook = std::make_shared<HookIntr>(std::move(callback), intno);
    ql_hook_impl(UC_HOOK_INTR, hook);
    return HookRet(this, UC_HOOK_INTR, hook);
}

HookRet QlCoreHooks::hook_intr(InterruptHookCallback callback, std::uint64_t begin, std::uint64_t end) {
    // TODO: remove; this is a special case of hook_intno(-1) (core_hooks.py)
    auto hook = std::make_shared<HookIntr>(std::move(callback), -1);
    (void)begin;
    (void)end;
    ql_hook_impl(UC_HOOK_INTR, hook);
    return HookRet(this, UC_HOOK_INTR, hook);
}

HookRet QlCoreHooks::hook_address(AddressHookCallback callback, std::uint64_t address) {
    auto hook = std::make_shared<HookAddr>(std::move(callback), address);

    if (addr_hook_fuc_.find(address) == addr_hook_fuc_.end()) {
        auto ctx = std::make_unique<HookCtx>(HookCtx{this, address});
        const uc_hook handle =
            hook_internal(UC_HOOK_CODE, reinterpret_cast<void*>(trampoline_addr), address, address, address);
        addr_hook_fuc_[address] = handle;
        hook_contexts_.emplace_back(std::move(ctx));
    }
    addr_hook_[address].push_back(std::move(hook));

    // note: assuming 0 is not a valid hook type (core_hooks.py)
    return HookRet(this, 0, hook);
}

// ---- removal ----

void QlCoreHooks::hook_del(const HookRet& hret) {
    const Hook* h = hret.obj().get();
    if (h == nullptr) {
        return;
    }
    const std::uint64_t hook_type = hret.type();

    // __remove: drop the hook from the type list; when the list empties,
    // release the underlying uc handle
    const auto remove_from = [&](std::uint64_t key, auto& hooks_map, std::map<std::uint64_t, uc_hook>& handles_map) {
        auto hit = hooks_map.find(key);
        if (hit == hooks_map.end()) {
            return;
        }
        auto& hooks_list = hit->second;

        const auto found = std::find_if(hooks_list.begin(), hooks_list.end(),
                                        [h](const std::shared_ptr<Hook>& entry) { return entry.get() == h; });
        if (found == hooks_list.end()) {
            return;
        }

        hooks_list.erase(found);

        if (hooks_list.empty()) {
            uc_hook_del(h_uc_, handles_map.find(key)->second);
            handles_map.erase(key);
            hooks_map.erase(hit);
        }
    };

    // address hooks are a special case of UC_HOOK_CODE and should be handled
    // separately (core_hooks.py, verbatim note)
    if (auto* hook_addr = dynamic_cast<const HookAddr*>(h); hook_addr != nullptr) {
        remove_from(hook_addr->addr, addr_hook_, addr_hook_fuc_);
        return;
    }

    // a bounded-range code/block hook was registered as its own native uc hook
    // (ranged_code_), not in hook_[type]
    if (hook_type == UC_HOOK_CODE || hook_type == UC_HOOK_BLOCK) {
        const auto rit = ranged_code_.find(h);
        if (rit != ranged_code_.end()) {
            uc_hook_del(h_uc_, rit->second.handle);
            ranged_code_.erase(rit);
            return;
        }
    }

    if (hook_type == UC_HOOK_INSN) {
        // the insn registry is keyed by the instruction type, which HookRet
        // does not carry; every insn_type list holding this hook drops it
        for (auto& [insn_type, hooks_list] : insn_hook_) {
            const auto found = std::find_if(hooks_list.begin(), hooks_list.end(),
                                            [h](const std::shared_ptr<Hook>& entry) { return entry.get() == h; });
            if (found != hooks_list.end()) {
                hooks_list.erase(found);
                if (hooks_list.empty()) {
                    uc_hook_del(h_uc_, insn_hook_fuc_.at(insn_type));
                    insn_hook_fuc_.erase(insn_type);
                    insn_hook_.erase(insn_type);
                }
                break;
            }
        }
        return;
    }

    const auto remove_one = [&](std::uint64_t key) { remove_from(key, hook_, hook_fuc_); };

    if ((hook_type & UC_HOOK_INTR) != 0) remove_one(UC_HOOK_INTR);
    if ((hook_type & UC_HOOK_CODE) != 0) remove_one(UC_HOOK_CODE);
    if ((hook_type & UC_HOOK_BLOCK) != 0) remove_one(UC_HOOK_BLOCK);
    if ((hook_type & UC_HOOK_MEM_READ_UNMAPPED) != 0) remove_one(UC_HOOK_MEM_READ_UNMAPPED);
    if ((hook_type & UC_HOOK_MEM_WRITE_UNMAPPED) != 0) remove_one(UC_HOOK_MEM_WRITE_UNMAPPED);
    if ((hook_type & UC_HOOK_MEM_FETCH_UNMAPPED) != 0) remove_one(UC_HOOK_MEM_FETCH_UNMAPPED);
    if ((hook_type & UC_HOOK_MEM_READ_PROT) != 0) remove_one(UC_HOOK_MEM_READ_PROT);
    if ((hook_type & UC_HOOK_MEM_WRITE_PROT) != 0) remove_one(UC_HOOK_MEM_WRITE_PROT);
    if ((hook_type & UC_HOOK_MEM_FETCH_PROT) != 0) remove_one(UC_HOOK_MEM_FETCH_PROT);
    if ((hook_type & UC_HOOK_MEM_READ) != 0) remove_one(UC_HOOK_MEM_READ);
    if ((hook_type & UC_HOOK_MEM_WRITE) != 0) remove_one(UC_HOOK_MEM_WRITE);
    if ((hook_type & UC_HOOK_MEM_FETCH) != 0) remove_one(UC_HOOK_MEM_FETCH);
    if ((hook_type & UC_HOOK_MEM_READ_AFTER) != 0) remove_one(UC_HOOK_MEM_READ_AFTER);
    if ((hook_type & UC_HOOK_INSN_INVALID) != 0) remove_one(UC_HOOK_INSN_INVALID);
}

void QlCoreHooks::clear_hooks() {
    // clear_hooks: release every uc handle, then wipe the registries
    for (const auto& [type, handle] : hook_fuc_) {
        uc_hook_del(h_uc_, handle);
    }
    for (const auto& [insn_type, handle] : insn_hook_fuc_) {
        uc_hook_del(h_uc_, handle);
    }
    for (const auto& [address, handle] : addr_hook_fuc_) {
        uc_hook_del(h_uc_, handle);
    }
    for (const auto& [h, entry] : ranged_code_) {
        (void)h;
        uc_hook_del(h_uc_, entry.handle);
    }
    clear_ql_hooks();
    hook_contexts_.clear();
}

void QlCoreHooks::clear_ql_hooks() {
    hook_.clear();
    hook_fuc_.clear();

    insn_hook_.clear();
    insn_hook_fuc_.clear();

    addr_hook_.clear();
    addr_hook_fuc_.clear();

    ranged_code_.clear();
}

}  // namespace qiling
