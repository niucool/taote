#include "qiling/os/posix/posix.hpp"

#include "qiling/os/posix/kernel_api.hpp"
#include "qiling/loader/elf.hpp"

#include <unicorn/x86.h>
#include "qiling/loader/loader.hpp"


#include "qiling/core.hpp"
#include "qiling/cc/intel.hpp"
#include "qiling/cc/arm.hpp"
#include "qiling/cc/mips.hpp"
#include "qiling/cc/ppc.hpp"
#include "qiling/cc/riscv.hpp"
#include "qiling/os/posix/map_syscall.hpp"
#include "qiling/os/posix/syscall.hpp"

namespace qiling {
namespace os {
namespace posix {

namespace {

// map_syscall.py get_syscall_mapper: the per-arch number-to-name tables
std::string_view lookup_syscall_table(QL_ARCH arch, unsigned num) {
    const std::pair<unsigned, std::string_view>* table = nullptr;
    std::size_t count = 0;

    switch (arch) {
        case QL_ARCH::X8664:
            table = x8664_syscall_table.data();
            count = x8664_syscall_table.size();
            break;
        case QL_ARCH::X86:
            table = x86_syscall_table.data();
            count = x86_syscall_table.size();
            break;
        case QL_ARCH::ARM64:
            table = arm64_syscall_table.data();
            count = arm64_syscall_table.size();
            break;
        case QL_ARCH::ARM:
            table = arm_syscall_table.data();
            count = arm_syscall_table.size();
            break;
        case QL_ARCH::RISCV:
            table = riscv32_syscall_table.data();
            count = riscv32_syscall_table.size();
            break;
        case QL_ARCH::RISCV64:
            table = riscv64_syscall_table.data();
            count = riscv64_syscall_table.size();
            break;
        case QL_ARCH::PPC:
            table = ppc_syscall_table.data();
            count = ppc_syscall_table.size();
            break;
        default:
            break;
    }

    for (std::size_t i = 0; i < count; ++i) {
        if (table[i].first == num) {
            return table[i].second;
        }
    }
    return {};
}

}  // namespace

QlOsPosix::QlOsPosix(Qiling* ql) : QlOs(ql) {
    init_paths_if_managed();

    // posix.py: the KERNEL profile identity
    uid_ = static_cast<int>(profile().get_int("KERNEL", "uid"));
    euid_ = uid_;
    gid_ = static_cast<int>(profile().get_int("KERNEL", "gid"));
    egid_ = gid_;
    pid_ = static_cast<int>(profile().get_int("KERNEL", "pid"));

    // the syscall abi per arch
    syscall_abi_ = make_syscall_abi(ql->arch().type(), ql->arch());

    // fcall: the posix convention (the syscall layer goes through the abi, but
    // the os-level fcall remains available for API hooks)
    set_fcall(std::make_unique<QlFunctionCall>(make_cc_default(ql->arch().type(), ql->arch())));

    // posix.py: the std streams occupy fd[0..2] (the property setters, verbatim
    // — the constructor assigns them through the private members and updates
    // the table manually)
    fd_.set(0, stdin_);
    fd_.set(1, stdout_);
    fd_.set(2, stderr_);

    register_builtin_syscalls();
}

std::unique_ptr<cc::QlCC> QlOsPosix::make_cc_default(QL_ARCH archtype, QlArch& arch) {
    // the posix os layers use the arch's native convention for API calls
    switch (archtype) {
        case QL_ARCH::X86:
            return std::make_unique<cc::QlCdecl>(arch);
        case QL_ARCH::X8664:
            return std::make_unique<cc::amd64>(arch);
        case QL_ARCH::ARM:
        case QL_ARCH::CORTEX_M:
            return std::make_unique<cc::aarch32>(arch);
        case QL_ARCH::ARM64:
            return std::make_unique<cc::aarch64>(arch);
        case QL_ARCH::MIPS:
            return std::make_unique<cc::mipso32>(arch);
        case QL_ARCH::RISCV:
        case QL_ARCH::RISCV64:
            return std::make_unique<cc::riscv>(arch);
        case QL_ARCH::PPC:
            return std::make_unique<cc::ppc>(arch);
        default:
            throw QlErrorArch("unsupported posix architecture");
    }
}

void QlOsPosix::shutdown() {
    // release the os-owned hooks while the uc engine is alive (the
    // composition root calls this before the arch's uc handle closes)
    if (syscall_hook_.has_value()) {
        syscall_hook_->remove();
        syscall_hook_.reset();
    }
    if (kernel_api_hook_.has_value()) {
        kernel_api_hook_->remove();
        kernel_api_hook_.reset();
    }
}

void QlOsPosix::enable_kernel_api_hooks() {
    // elf.py run: self.ql.hook_code(hook_kernel_api)
    auto* self = this;
    kernel_api_hook_ = ql().hook_code([self](std::uint64_t address, std::uint32_t size) -> int {
        self->hook_kernel_api(address, size);
        return 0;
    });
}

void QlOsPosix::hook_kernel_api(std::uint64_t address, std::uint32_t size) {
    (void)size;

    // hook.py hook_kernel_api: call the kernel api at the stub address
    const auto* loader_elf = dynamic_cast<const loader::QlLoaderELF*>(&ql().loader());
    if (loader_elf == nullptr) {
        return;
    }
    const auto* imported = loader_elf->import_symbols_at(address);
    if (imported == nullptr) {
        return;
    }
    const auto& api_name = imported->name;

    // the user override runs raw with (ql, address, api_name) — no param
    // resolution (hook.py, verbatim)
    if (const auto* user = find_user_api(api_name)) {
        (*user)(ql(), address, api_name);
        return;
    }

    const auto* entry = KernelApiRegistry::instance().find(api_name);
    if (entry == nullptr) {
        // hook.py: a warning; the debug_stop surfaces raise
        // QlErrorSyscallNotFound
        if (ql().debug_stop()) {
            throw QlErrorSyscallNotFound("Linux kernel API implementation not found: " + api_name);
        }
        return;
    }

    // the @linux_kernel_api wrapper body: os.call(pc, func, params, onenter,
    // onexit, passthru)
    const auto* entry_ptr = entry;
    auto* self_ql = &ql();
    const auto func = [entry_ptr, self_ql](std::uint64_t pc,
                                           const std::vector<std::pair<std::string, std::uint64_t>>& params)
        -> std::optional<std::uint64_t> {
        return entry_ptr->handler(*self_ql, pc, params);
    };
    call(address, api_name, func, entry->params, {}, {}, entry->passthru);
}

void QlOsPosix::set_syscall(std::string_view name, SyscallHandler handler) {
    // posix.py set_syscall: the target name gets the ql_syscall_ prefix
    user_syscalls_[std::string(SYSCALL_PREF) + std::string(name)] = std::move(handler);
}

void QlOsPosix::run() {
    // linux.py load: the per-arch syscall entry hooks (x86-64 hooks the
    // `syscall` instruction; x86 hooks int 0x80; the other arches hook their
    // interrupt numbers)
    switch (ql().arch().type()) {
        case QL_ARCH::X8664: {
            auto* self = this;
            syscall_hook_ = ql().hook_insn([self](const std::vector<std::uint64_t>&) -> int {
                self->load_syscall();
                return 0;
            }, UC_X86_INS_SYSCALL);
            break;
        }
        case QL_ARCH::X86: {
            auto* self = this;
            syscall_hook_ = ql().hook_intno([self](std::uint32_t intno) -> int {
                self->load_syscall();
                return 0;
            }, 0x80);
            break;
        }
        default:
            break;  // the other arch hooks land with their slices
    }

    // the emulation entry comes from the loader (posix.py: ql.os.entry_point
    // set by the loader's run)
    const auto entry = ql().entry_point_set() ? ql().entry_point() : ql().loader().entry_point;
    const auto exit = ql().code().empty() ? exit_point_ : (entry + ql().code().size());

    try {
        ql().emu_start(entry, exit, ql().timeout(), ql().count());
    } catch (const QlErrorBase&) {
        emu_error();
        throw;
    }
}

void QlOsPosix::load_syscall() {
    // posix.py load_syscall: resolve the syscall by id through the per-arch
    // table, then dispatch through the user overrides, then the registry
    const auto syscall_id = syscall_abi_->get_id();
    const auto count = params_count_for_id(syscall_id, ql().arch().type());

    const auto raw_params = syscall_abi_->get_params(count);

    // resolve the syscall name (unknown ids keep the numeric spelling)
    const auto table_name = lookup_syscall_table(ql().arch().type(), static_cast<unsigned>(syscall_id));
    std::string syscall_name(table_name);

    // the user override (posix.py posix_syscall_hooks[QL_INTERCEPT.CALL])
    const auto user = user_syscalls_.find(std::string(SYSCALL_PREF) + syscall_name);
    if (user != user_syscalls_.end()) {
        const auto result = user->second(ql(), raw_params);
        if (result.has_value()) {
            syscall_abi_->set_return_value(static_cast<std::uint64_t>(*result));
        }
        return;
    }

    // the registry lookup (the os-specific and posix-generic tables collapse
    // into the single static registry in this port)
    const auto* entry = SyscallRegistry::instance().find(syscall_name);
    if (entry != nullptr) {
        // read the params per the registered signature's arity
        const auto params = syscall_abi_->get_params(entry->params.size());

        const auto result = entry->handler(ql(), params);
        if (result.has_value()) {
            syscall_abi_->set_return_value(static_cast<std::uint64_t>(*result));
        }

        // print + stats (posix.py tail)
        stats().log_api_call(ql().arch().regs().arch_pc(), syscall_name,
                             result.value_or(0), result.has_value(), 0);
        return;
    }

    // posix.py: not implemented (the debug_stop behavior lands with the
    // QlErrorSyscallNotFound slice)
}

std::size_t QlOsPosix::params_count_for_id(std::uint64_t, QL_ARCH) {
    // the dispatcher reads a fixed upper bound of argument slots; the handlers
    // receive the full raw vector (matching the Python `*params` unpacking,
    // where the hook signature picks its arity)
    return 6;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
