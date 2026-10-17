#include "qiling/arch/arch.hpp"

#include <unicorn/unicorn.h>

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
// Python implements these against ql.mem (QlMemoryManager). The memory manager
// lands in Phase 2 (PORT_PLAN.md §10); until the composition root attaches it,
// every stack access degrades to QlErrorBase instead of crashing.

namespace {

[[noreturn]] void stack_needs_mem() {
    throw QlErrorBase("stack access requires the memory manager (wired in Phase 2)");
}

}  // namespace

std::uint64_t QlArch::stack_push(std::uint64_t) {
    stack_needs_mem();
}

std::uint64_t QlArch::stack_pop() {
    stack_needs_mem();
}

std::uint64_t QlArch::stack_read(std::int64_t) const {
    stack_needs_mem();
}

void QlArch::stack_write(std::int64_t, std::uint64_t) {
    stack_needs_mem();
}

}  // namespace qiling
