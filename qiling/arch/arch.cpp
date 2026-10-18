#include "qiling/arch/arch.hpp"

#include <unicorn/unicorn.h>

#include "qiling/os/memory.hpp"
#include "qiling/arch/utils.hpp"
#include <cstdio>\n"

namespace qiling {

void UcDeleter::operator()(uc_engine* uc) const noexcept { uc_close(uc); }

UcContext::UcContext(uc_engine& uc, uc_context* ctx) noexcept : uc_(&uc), ctx_(ctx) {}

UcContext::~UcContext() {
    if (ctx_ != nullptr) uc_context_free(ctx_);  // unicorn 2.1.x: frees without the uc handle
}

UcContext::UcContext(UcContext&& other) noexcept : uc_(other.uc_), ctx_(other.ctx_) {
    other.uc_ = nullptr;
    other.ctx_ = nullptr;
}

UcContext& UcContext::operator=(UcContext&& other) noexcept {
    if (this != &other) {
        if (ctx_ != nullptr) uc_context_free(ctx_);
        uc_ = other.uc_;
        ctx_ = other.ctx_;
        other.uc_ = nullptr;
        other.ctx_ = nullptr;
    }
    return *this;
}

QlArch::QlArch(Qiling* ql, std::optional<std::uint32_t> cputype) : ql_(ql), cputype_(cputype) {}

QlArch::~QlArch() {
    // the tracer hooks were released by shutdown_utils() (called from the
    // composition root while the uc engine is still open)
    delete utils_;
    utils_ = nullptr;
}

void QlArch::shutdown_utils() {
    // drops the tracer hooks (and releases their RAII handles) while the
    // derived class's uc engine is still open; called from the composition
    // root's dtor, mirroring the Python teardown ordering
    if (utils_ != nullptr) {
        utils_->shutdown();
    }
}

QlArchUtils& QlArch::utils() {
    // lazy construction (Python builds it eagerly in the ctor; the C++ port
    // defers until the composition root passes a complete facade)
    if (utils_ == nullptr) {
        utils_ = new QlArchUtils(*ql_);
    }
    return *utils_;
}

std::unique_ptr<UcContext> QlArch::save() {
    uc_context* raw = nullptr;
    if (uc_context_alloc(&uc(), &raw) != UC_ERR_OK) {
        throw QlErrorBase("failed to allocate unicorn context");
    }
    if (uc_context_save(&uc(), raw) != UC_ERR_OK) {
        uc_context_free(raw);
        throw QlErrorBase("failed to save unicorn context");
    }
    return std::unique_ptr<UcContext>(new UcContext(uc(), raw));
}

void QlArch::restore(const UcContext& saved_context) {
    if (uc_context_restore(&uc(), saved_context.get()) != UC_ERR_OK) {
        throw QlErrorBase("failed to restore unicorn context");
    }
}

// ---- stack helpers (arch.py) ----
//
// Python implements these against ql.mem (QlMemoryManager):
//   stack_push:  sp -= ptrsize; mem.write_ptr(sp, value)
//   stack_pop:   read_ptr(sp); sp += ptrsize
//   stack_read:  mem.read_ptr(sp + offset)
//   stack_write: mem.write_ptr(sp + offset, value)
// The manager is attached by the composition root (Phase 3 facade); direct
// users (the fcall layer) attach it explicitly.

void QlArch::attach_memory(QlMemoryManager& mem) noexcept {
    mem_ = &mem;
}

std::uint64_t QlArch::stack_push(std::uint64_t value) {
    if (mem_ == nullptr) {
        throw QlErrorBase("stack access requires the memory manager (attach_memory)");
    }
    const std::uint64_t ptrsize = bits() / 8;
    regs().set_arch_sp(regs().arch_sp() - ptrsize);
    mem_->write_ptr(regs().arch_sp(), static_cast<std::int64_t>(value), ptrsize);
    return regs().arch_sp();
}

std::uint64_t QlArch::stack_pop() {
    if (mem_ == nullptr) {
        throw QlErrorBase("stack access requires the memory manager (attach_memory)");
    }
    const std::uint64_t ptrsize = bits() / 8;
    const std::uint64_t value = mem_->read_ptr(regs().arch_sp(), ptrsize);
    regs().set_arch_sp(regs().arch_sp() + ptrsize);
    return value;
}

std::uint64_t QlArch::stack_read(std::int64_t offset) const {
    if (mem_ == nullptr) {
        throw QlErrorBase("stack access requires the memory manager (attach_memory)");
    }
    // regs() is non-const (the register manager mutates through cached uc
    // state); arch_sp() itself is a const query
    auto* self = const_cast<QlArch*>(this);
    return mem_->read_ptr(self->regs().arch_sp() + static_cast<std::uint64_t>(offset), bits() / 8);
}

void QlArch::stack_write(std::int64_t offset, std::uint64_t value) {
    if (mem_ == nullptr) {
        throw QlErrorBase("stack access requires the memory manager (attach_memory)");
    }
    mem_->write_ptr(regs().arch_sp() + static_cast<std::uint64_t>(offset), static_cast<std::int64_t>(value), bits() / 8);
}

}  // namespace qiling
