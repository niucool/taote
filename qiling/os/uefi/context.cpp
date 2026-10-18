// os/uefi/context.py — the context implementations (the slice-1 shell)

#include "qiling/os/uefi/context.hpp"

namespace qiling {
namespace os {
namespace uefi {

void UefiContext::init_heap(std::uint64_t base, std::uint64_t size) {
    heap = std::make_unique<QlMemoryHeap>(ql_->mem(), base, base + size);
}

void UefiContext::init_stack(std::uint64_t base, std::uint64_t size) {
    ql_->mem().map(base, size, UC_PROT_ALL, "[stack]");
    top_of_stack = (base + size - 1) & ~(CPU_STACK_ALIGNMENT - 1);
}

void UefiContext::install_protocol(std::string_view guid, std::uint64_t handle, std::uint64_t address) {
    auto& per_handle = protocols[handle];
    per_handle[std::string(guid)] = address;
}

bool UefiContext::has_protocol(std::string_view guid, std::uint64_t handle) const {
    const auto it = protocols.find(handle);
    if (it == protocols.end()) {
        return false;
    }
    return it->second.count(std::string(guid)) != 0;
}

}  // namespace uefi
}  // namespace os
}  // namespace qiling
