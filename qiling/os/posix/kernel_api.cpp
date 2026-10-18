// Ported from qiling/os/linux/kernel_api/kernel_api.py — the builtin handlers
// the LKM path relies on. The slice carries the stubs load_driver wires into
// the import table (hook_sys_read/hook_sys_write/hook_sys_open, verbatim
// signatures); the richer kernel_api.py handlers (printk, kmalloc, ...) land
// with their slices.
#include "qiling/os/posix/kernel_api.hpp"

namespace qiling {
namespace os {
namespace posix {

KernelApiRegistry& KernelApiRegistry::instance() {
    static KernelApiRegistry registry;
    return registry;
}

void KernelApiRegistry::register_api(KernelApiEntry entry) {
    entries_[entry.name] = std::move(entry);
}

const KernelApiEntry* KernelApiRegistry::find(const std::string& name) const {
    const auto it = entries_.find(name);
    return it == entries_.end() ? nullptr : &it->second;
}

void KernelApiRegistry::clear() {
    entries_.clear();
}

KernelApi::KernelApi(std::string name, KernelApiParams params, bool passthru) {
    entry_.name = std::move(name);
    entry_.params = std::move(params);
    entry_.passthru = passthru;
}

void KernelApi::operator=(KernelApiHandler handler) {
    entry_.handler = std::move(handler);
    KernelApiRegistry::instance().register_api(entry_);
}

// ---- kernel_api.py: the sys_* stubs load_driver registers ----
// (registered at static-init inside an IIFE: the builder temporaries are
// expression statements, which namespace scope cannot carry directly)

namespace {

const bool kernel_api_builtins_registered = [] {
    // @linux_kernel_api(params={"fd": UINT, "buf": STRING, "count": SIZE_T})
    KernelApi("sys_read", {{"fd", K_UINT}, {"buf", K_STRING}, {"count", K_SIZE_T}}) =
        [](Qiling&, std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>&) {
            return std::optional<std::uint64_t>{0};
        };

    // @linux_kernel_api(params={"fd": UINT, "buf": STRING, "count": SIZE_T})
    KernelApi("sys_write", {{"fd", K_UINT}, {"buf", K_STRING}, {"count", K_SIZE_T}}) =
        [](Qiling&, std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>&) {
            return std::optional<std::uint64_t>{0};
        };

    // @linux_kernel_api(params={"pathname": STRING, "flags": UINT})
    KernelApi("sys_open", {{"pathname", K_STRING}, {"flags", K_UINT}}) =
        [](Qiling&, std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>&) {
            return std::optional<std::uint64_t>{0};
        };
    return true;
}();

}  // namespace

}  // namespace posix
}  // namespace os
}  // namespace qiling
