// Ported from qiling/os/linux/kernel_api/kernel_api.py — the builtin handler
// set the LKM path calls into. The stub shapes port verbatim (the passthru
// thunks, the zero-returns, the printk-style params). The printk printf
// plumbing (os.utils.printf + readEllipsis) defers with its slice.
#include "qiling/os/posix/kernel_api.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace os {
namespace posix {

// unistd.py read_cstring (os/utils.py read_cstring): the char-stepped NUL
// scan (the STRING param resolution machinery defers; the handlers deref the
// raw pointer values themselves)
namespace {
std::string read_cstring_helper(Qiling& ql, std::uint64_t addr) {
    std::string out;
    for (std::uint64_t cur = addr;; ++cur) {
        const auto ch = ql.mem().read(cur, 1);
        if (ch.empty() || ch[0] == 0) {
            break;
        }
        out.push_back(static_cast<char>(ch[0]));
    }
    return out;
}
}  // namespace

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

// ---- kernel_api.py: the rest of the handler set ----

const bool kernel_api_extended_registered = [] {
    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("__fentry__", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("mcount", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("___stack_chk_fail", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("mutex_lock_interruptible", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("mutex_unlock", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("kmalloc_caches", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{}; };

    // @linux_kernel_api(params={"size": SIZE_T, "flags": INT}) — the posix
    // heap (the kernel_api.py ql.heap.alloc; the posix heap is created lazily
    // on first use, the linux profile carries no heap fields)
    KernelApi("kmalloc", {{"size", K_SIZE_T}, {"flags", K_UINT}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto size = params.size() > 0 ? params[0].second : 0;
            auto& os = ql.os<posix::QlOsPosix>();
            const auto addr = os.heap().alloc(size);
            return std::optional<std::uint64_t>{addr};
        };

    // @linux_kernel_api(params={"dest": POINTER, "c": INT, "count": SIZE_T})
    KernelApi("memset", {{"dest", K_POINTER}, {"c", K_UINT}, {"count", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto dest = params[0].second;
            const auto c = static_cast<std::uint8_t>(params[1].second);
            const auto count = static_cast<std::size_t>(params[2].second);
            ql.mem().write(dest, std::vector<std::uint8_t>(count, c));
            return std::optional<std::uint64_t>{dest};
        };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("kmem_cache_alloc_trace", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("get_by_key", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("kfree", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{}; };

    // @linux_kernel_api(params={})
    KernelApi("misc_register", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("misc_deregister", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"Ptr": POINTER}) — the module's own metadata
    KernelApi("__this_module", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{}; };

    // @linux_kernel_api(params={"Ptr": POINTER})
    KernelApi("htable", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{}; };

    // @linux_kernel_api(params={"major": INT, "baseminor": INT, "count": INT,
    // "name": STRING, "fops": POINTER})
    KernelApi("__register_chrdev", {{"major", K_UINT}, {"baseminor", K_UINT}, {"count", K_UINT},
                                     {"name", K_STRING}, {"fops", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"major": INT, "name": STRING, "fops": POINTER})
    KernelApi("register_chrdev", {{"major", K_UINT}, {"name", K_STRING}, {"fops", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"name": STRING, "fops": POINTER, "owner": POINTER,
    // "umode": INT}) — the __ prefix (the create-class flow defers with the
    // device-model slice)
    KernelApi("__class_create", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"cls": POINTER})
    KernelApi("class_unregister", {{"Ptr", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"dev": POINTER})
    KernelApi("dev_get_flags", {{"dev", K_POINTER}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"buffer": POINTER, "format": STRING})
    KernelApi("sprintf", {{"buffer", K_POINTER}, {"format", K_STRING}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"str1": STRING, "str2": STRING})
    KernelApi("strcmp", {{"str1", K_STRING}, {"str2", K_STRING}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"str1": STRING, "str2": STRING, "count": SIZE_T})
    // — the upstream reads params["str"] (a KeyError away from working); the
    // port uses str1 (the documented fix)
    KernelApi("strncmp", {{"str1", K_STRING}, {"str2", K_STRING}, {"count", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto s1 = read_cstring_helper(ql, params[0].second);
            const auto s2 = read_cstring_helper(ql, params[1].second);
            const auto count = static_cast<std::size_t>(params[2].second);
            const auto sub1 = s1.substr(0, count);
            const auto sub2 = s2.substr(0, count);
            if (sub1 == sub2) return std::optional<std::uint64_t>{0};
            if (sub1 > sub2) return std::optional<std::uint64_t>{1};
            return std::optional<std::uint64_t>{static_cast<std::uint64_t>(-1)};
        };

    // @linux_kernel_api(params={"haystack": STRING, "needle": STRING})
    KernelApi("strstr", {{"haystack", K_STRING}, {"needle", K_STRING}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto haystack = read_cstring_helper(ql, params[0].second);
            const auto needle = read_cstring_helper(ql, params[1].second);
            const auto index = haystack.find(needle);
            if (index == std::string::npos) {
                return std::optional<std::uint64_t>{0};
            }
            return std::optional<std::uint64_t>{index};
        };

    // @linux_kernel_api(params={"str": STRING})
    KernelApi("strlen", {{"str", K_STRING}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto s = read_cstring_helper(ql, params[0].second);
            return std::optional<std::uint64_t>{s.size()};
        };

    // @linux_kernel_api(params={"s1": POINTER, "s2": POINTER, "size": SIZE_T})
    KernelApi("memcmp", {{"s1", K_POINTER}, {"s2", K_POINTER}, {"size", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto s1 = params[0].second;
            const auto s2 = params[1].second;
            const auto size = static_cast<std::size_t>(params[2].second);
            const auto a = ql.mem().read(s1, size);
            const auto b = ql.mem().read(s2, size);
            return std::optional<std::uint64_t>{a == b ? 1ull : 0ull};
        };

    // @linux_kernel_api(params={"str1": POINTER, "str2": POINTER, "base": INT})
    KernelApi("simple_strtol", {{"str1", K_POINTER}, {"str2", K_POINTER}, {"base", K_UINT}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={}) — the variable table
    KernelApi("pv_cpu_ops", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("sock_create", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("sock_release", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("filp_open", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("filp_close", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("PDE_DATA", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={}) — the wrapper-style hook_ prefixed names
    KernelApi("hook__kmalloc", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_raw_spin_lock_irqsave", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_raw_spin_unlock_irqrestore", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_current_task", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_prepare_kernel_cred", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_commit_creds", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_kallsyms_on_each_symbol", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_register_module_notifier", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_unregister_module_notifier", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    KernelApi("hook_kobject_del", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={}) — proc_create returns a non-NULL
    // proc_dir_entry (the 0x1000, verbatim)
    KernelApi("proc_create", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0x1000}; };

    KernelApi("remove_proc_entry", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"fd": UINT, "buf": STRING, "count": SIZE_T})
    KernelApi("sys_read", {{"fd", K_UINT}, {"buf", K_STRING}, {"count", K_SIZE_T}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"fd": UINT, "buf": STRING, "count": SIZE_T})
    KernelApi("sys_write", {{"fd", K_UINT}, {"buf", K_STRING}, {"count", K_SIZE_T}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"pathname": STRING, "flags": UINT})
    KernelApi("sys_open", {{"pathname", K_STRING}, {"flags", K_UINT}}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("make_kgid", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("make_kuid", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={}) — returns non-NULL creds (0x1000, verbatim)
    KernelApi("prepare_creds", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0x1000}; };

    // @linux_kernel_api(params={})
    KernelApi("commit_creds", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={})
    KernelApi("abort_creds", {}) =
        [](Qiling&, std::uint64_t, const auto&) { return std::optional<std::uint64_t>{0}; };

    // @linux_kernel_api(params={"dest": POINTER, "src": POINTER, "size": SIZE_T})
    KernelApi("memcpy", {{"dest", K_POINTER}, {"src", K_POINTER}, {"size", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto dest = params[0].second;
            const auto src = params[1].second;
            const auto size = static_cast<std::size_t>(params[2].second);
            ql.mem().write(dest, ql.mem().read(src, size));
            return std::optional<std::uint64_t>{dest};
        };

    // @linux_kernel_api(params={"dest": POINTER, "c": INT, "count": SIZE_T})
    KernelApi("memset", {{"dest", K_POINTER}, {"c", K_UINT}, {"count", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto dest = params[0].second;
            const auto c = static_cast<std::uint8_t>(params[1].second);
            const auto count = static_cast<std::size_t>(params[2].second);
            ql.mem().write(dest, std::vector<std::uint8_t>(count, c));
            return std::optional<std::uint64_t>{dest};
        };

    // @linux_kernel_api(params={"ubuf": POINTER, "kbuf": POINTER, "count": SIZE_T})
    KernelApi("_copy_to_user", {{"ubuf", K_POINTER}, {"kbuf", K_POINTER}, {"count", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto ubuf = params[0].second;
            const auto kbuf = params[1].second;
            const auto count = static_cast<std::size_t>(params[2].second);

            // if the user-mode buffer is not available, fail (the verbatim note)
            if (!ql.mem().is_mapped(ubuf, count)) {
                return std::optional<std::uint64_t>{count};
            }
            ql.mem().write(ubuf, ql.mem().read(kbuf, count));
            return std::optional<std::uint64_t>{0};
        };

    // @linux_kernel_api(params={"kbuf": POINTER, "ubuf": POINTER, "count": SIZE_T})
    KernelApi("_copy_from_user", {{"kbuf", K_POINTER}, {"ubuf", K_POINTER}, {"count", K_SIZE_T}}) =
        [](Qiling& ql, std::uint64_t, const auto& params) {
            const auto kbuf = params[0].second;
            const auto ubuf = params[1].second;
            const auto count = static_cast<std::size_t>(params[2].second);

            if (!ql.mem().is_mapped(ubuf, count)) {
                return std::optional<std::uint64_t>{count};
            }
            ql.mem().write(kbuf, ql.mem().read(ubuf, count));
            return std::optional<std::uint64_t>{0};
        };

    // @linux_kernel_api(params={"Ptr": POINTER}, passthru=True) — the retpoline
    // thunk: jump to rax (the pc reassignment, the passthru skips the epilogue)
    KernelApi("__x86_indirect_thunk_rax", {{"Ptr", K_POINTER}}, true) =
        [](Qiling& ql, std::uint64_t, const auto&) {
            ql.arch().regs().set_arch_pc(ql.arch().regs().read("rax"));
            return std::optional<std::uint64_t>{};
        };

    // @linux_kernel_api(params={"Ptr": POINTER}, passthru=True)
    KernelApi("__x86_indirect_thunk_r14", {{"Ptr", K_POINTER}}, true) =
        [](Qiling& ql, std::uint64_t, const auto&) {
            ql.arch().regs().set_arch_pc(ql.arch().regs().read("r14"));
            return std::optional<std::uint64_t>{};
        };

    return true;
}();

}  // namespace

}  // namespace posix
}  // namespace os
}  // namespace qiling
