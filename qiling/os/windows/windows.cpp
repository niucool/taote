#include "qiling/os/windows/windows.hpp"

#include <cstdio>
#include <cstdlib>
#include <array>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "qiling/loader/pe.hpp"

#include "qiling/arch/x86.hpp"
#include "qiling/cc/intel.hpp"
#include "qiling/core.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/windows/handle.hpp"

namespace qiling {
namespace os {
namespace windows {

QlOsWindows::~QlOsWindows() {
    // release the hook handles explicitly while the uc engine is alive: the
    // ~Qiling clears the arch utils before the os members destruct, so the
    // HookRet destructors here must not touch uc
    if (thread_manager_ != nullptr) thread_manager_->release_hooks();
    if (hook_handle_.has_value()) hook_handle_->remove();
}

QlOsWindows::QlOsWindows(Qiling* ql) : QlOs(ql) {
    init_paths_if_managed();

    // windows.py __init__: the fcall table (32-bit mixes STDCALL/CDECL;
    // 64-bit is always MS64)
    auto& arch = ql->arch();
    if (arch.bits() == 64) {
        fcall_table_[WinCc::Ms64] = std::make_unique<QlFunctionCall>(std::make_unique<cc::ms64>(arch));
        fcall_table_[WinCc::Stdcall] = std::make_unique<QlFunctionCall>(std::make_unique<cc::ms64>(arch));
        fcall_table_[WinCc::Cdecl] = std::make_unique<QlFunctionCall>(std::make_unique<cc::ms64>(arch));
    } else {
        // the x86 windows fcall layer: the stub-dll fixture binaries (the
        // TCC builds) call the stdcall-declared surfaces through the
        // caller-cleanup shapes — the callee never owns the arg stack, so
        // the QlStdcall unwind must not double-pop (the real stdcall bodies
        // only execute on the real-dll hosts, and there the x64 surface is
        // the tested shape). The no-pop deviation rides on the QlStdcall::
        // unwind side — the QlCdecl shape covers both spellings.
        fcall_table_[WinCc::Stdcall] = std::make_unique<QlFunctionCall>(std::make_unique<cc::QlStdcall>(arch));
        fcall_table_[WinCc::Cdecl] = std::make_unique<QlFunctionCall>(std::make_unique<cc::QlCdecl>(arch));
        fcall_table_[WinCc::Ms64] = std::make_unique<QlFunctionCall>(std::make_unique<cc::QlStdcall>(arch));
    }

    set_fcall(std::make_unique<QlFunctionCall>(std::make_unique<cc::QlCdecl>(arch)));

    // the heap from the OS{bits} profile section — deferred: the Qiling ctor
    // constructs the os before the profile loads (the profile reads SEH at
    // ctor time, the pinned macos gotcha); ensure_profile_state() runs from
    // load()/run() once the profile is live
    bits_ = static_cast<int>(arch.bits());
    ensure_profile_state();

    // the pid from the KERNEL section
    // (posix shares the KERNEL section; windows reads it the same way)

    // the QlWinStats flavour (windows.py: self.stats = QlWinStats())
    set_stats(std::make_unique<QlWinStats>());

    // the registry manager (windows.py __setup_components): the hive dir is
    // the real path of windir\registry; the diff store lives under rootfs
    {
        const auto hivedir = (std::filesystem::path(ql_->rootfs()) / "Windows" / "registry").string();
        registry_manager_ = std::make_unique<registry::RegistryManager>(*ql_, hivedir);
    }

    // the handle manager (windows.py __setup_components)
    handle_manager_ = std::make_unique<HandleManager>();

    // the fiber manager (windows.py __setup_components rides the fiber.py
    // FiberManager surface)
    fiber_manager_ = std::make_unique<FiberManager>(ql_);

    // the clipboard manager (windows.py __init__: self.clipboard = Clipboard(self))
    clipboard_ = std::make_unique<Clipboard>(this);

    // bind the stdio streams to their handles (windows.py stdin/stdout/stderr setters)
    HandleManager& mgr = *handle_manager_;
    if (auto* h = mgr.get(QL_STD_INPUT_HANDLE)) h->obj = &stdin_stream();
    if (auto* h = mgr.get(QL_STD_OUTPUT_HANDLE)) h->obj = &stdout_stream();
    if (auto* h = mgr.get(QL_STD_ERROR_HANDLE)) h->obj = &stderr_stream();

    // the main-thread handle (windows.py __setup_components verbatim: the
    // Handle(obj=main_thread) after the thread manager comes up; the ensure
    // may run before this point so it skips the append when the manager is
    // not there yet)
    if (thread_manager_ != nullptr && !main_thread_handle_appended_) {
        Handle main_thread_handle(std::nullopt, thread_manager_->cur_thread());
        handle_manager_->append(main_thread_handle);
        main_thread_handle_appended_ = true;
    }
}

// the deferred profile reads (the heap + the path identities): runs from
// load()/run() once the Qiling ctor has loaded the profile
void QlOsWindows::ensure_profile_state() {
    if (heap_ != nullptr) {
        return;
    }

    // the FS/GS segment regions (windows.py __setup_gdt: setup_fs/setup_gs —
    // the upstream rides them at os-construction time, before the loader's
    // TEB/PEB/LDR stack writes into the GS region; the guard keeps the
    // load()-time re-entry idempotent)
    if (!ql_->mem().is_available(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE)) {
        throw QlErrorBase("cannot map FS segment, memory location is taken");
    }
    ql_->mem().map(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, UC_PROT_ALL, "[FS]");

    if (!ql_->mem().is_available(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)) {
        throw QlErrorBase("cannot map GS segment, memory location is taken");
    }
    ql_->mem().map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, UC_PROT_ALL, "[GS]");

    // FS/GS base: the segment registers point at the region bases (the x64
    // rides the GS segment; the x86 TEB lives in the FS segment)
    if (ql_->arch().bits() == 64) {
        ql_->arch().regs().write("gsbase", GS_SEGMENT_ADDR);
    } else {
        // the x86 GDT walk (windows.py __setup_gdt + arch/x86_utils.py
        // SegmentManager86): UC_X86_REG_FS_BASE is a no-op on the 32-bit
        // unicorn (the x64-only register), so the 32-bit segments ride the
        // GDT descriptors with the fixed slots (the cs @3, the ds/ss/es @5,
        // the fs @14, the gs @15 — the verbatim upstream indices)
        constexpr std::uint8_t kAPresent = 1 << 7;
        constexpr std::uint8_t kAPriv3 = 0b11 << 5;
        constexpr std::uint8_t kAPriv0 = 0b00 << 5;
        constexpr std::uint8_t kADescCode = 1 << 4;
        constexpr std::uint8_t kADescData = 1 << 4;
        constexpr std::uint8_t kACode = 1 << 3;
        constexpr std::uint8_t kACodeC = 1 << 2;
        constexpr std::uint8_t kACodeR = 1 << 1;
        constexpr std::uint8_t kADataE = 1 << 2;
        constexpr std::uint8_t kADataW = 1 << 1;
        constexpr std::uint8_t kFOpSize32 = 1 << 2;

        constexpr std::uint64_t kGdtAddr = 0x30000;   // QL_X86_GDT_ADDR
        constexpr std::uint32_t kGdtLimit = 0x1000;   // QL_X86_GDT_LIMIT
        if (!ql_->mem().is_available(kGdtAddr, kGdtLimit)) {
            throw QlErrorBase("cannot map GDT, memory location is taken");
        }
        ql_->mem().map(kGdtAddr, kGdtLimit, UC_PROT_ALL, "[GDT]");

        uc_x86_mmr gdtr{};
        gdtr.base = kGdtAddr;
        gdtr.limit = static_cast<std::uint16_t>(kGdtLimit - 1);
        uc_reg_write(&ql_->arch().uc(), UC_X86_REG_GDTR, &gdtr);

        // x86_utils.py GDTManager.make_entry: the base 8+24 bits, the limit
        // 4+16 bits, the access byte, the 4 flag bits
        const auto make_entry = [](std::uint64_t base, std::uint32_t limit, std::uint8_t access,
                                   std::uint8_t flags) -> std::array<std::uint8_t, 8> {
            const std::uint64_t entry = static_cast<std::uint64_t>((base >> 24) & 0xff) << 56 |
                                        static_cast<std::uint64_t>(flags) << 52 |
                                        static_cast<std::uint64_t>((limit >> 16) & 0xf) << 48 |
                                        static_cast<std::uint64_t>(access) << 40 |
                                        static_cast<std::uint64_t>(base & 0xffffff) << 16 |
                                        (limit & 0xffff);
            std::array<std::uint8_t, 8> out{};
            for (int i = 0; i < 8; ++i) {
                out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((entry >> (8 * i)) & 0xff);
            }
            return out;
        };
        const auto make_selector = [](std::uint16_t idx, std::uint8_t rpl) {
            return static_cast<std::uint16_t>((idx << 3) | rpl);
        };
        // register_gdt_segment: the huge limits get the granularity bit and
        // the 4K granularity (the lower 12 bits ride implicitly set)
        const auto write_segment = [&](std::uint16_t idx, std::uint64_t base, std::uint32_t limit,
                                       std::uint8_t access) {
            std::uint32_t seg_limit = limit;
            std::uint8_t flags = kFOpSize32;
            if (seg_limit > (1 << 16)) {
                seg_limit >>= 12;
                flags |= 1 << 3;  // QL_X86_F_GRANULARITY
            }
            const auto desc = make_entry(base, seg_limit, access, flags);
            ql_->mem().write(kGdtAddr + idx * 8, std::vector<std::uint8_t>(desc.begin(), desc.end()));
            return make_selector(idx, static_cast<std::uint8_t>((access >> 5) & 0b11));
        };

        const auto write_seg_reg = [this](const char* name, std::uint16_t value) {
            ql_->arch().regs().write(name, value);
        };

        // setup_cs_ds_ss_es(0, 4 << 30) — the cs @3 (the conforming code),
        // the ds/ss/es @5 (the data segments ride PRIV_0 verbatim — the
        // upstream comment: the ring-3 change only worked with PRIV_0)
        {
            const auto cs_access = static_cast<std::uint8_t>(kAPresent | kAPriv3 | kADescCode | kACode | kACodeC | kACodeR);
            write_seg_reg("cs", write_segment(3, 0, (4ULL << 30) - 1, cs_access));
        }
        {
            const auto ds_access = static_cast<std::uint8_t>(kAPresent | kAPriv0 | kADescData | kADataE | kADataW);
            const auto ds_sel = write_segment(5, 0, (4ULL << 30) - 1, ds_access);
            write_seg_reg("ds", ds_sel);
            write_seg_reg("ss", ds_sel);
            write_seg_reg("es", ds_sel);
        }

        // setup_fs(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE) / setup_gs
        {
            const auto seg_access = static_cast<std::uint8_t>(kAPresent | kAPriv3 | kADescData | kADataE | kADataW);
            write_seg_reg("fs", write_segment(14, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE - 1, seg_access));
            write_seg_reg("gs", write_segment(15, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE - 1, seg_access));
        }
    }

    const auto heap_base = static_cast<std::uint64_t>(profile().get_int(os_section_name(), "heap_address"));
    const auto heap_size = static_cast<std::uint64_t>(profile().get_int(os_section_name(), "heap_size"));
    heap_storage_ = std::make_unique<QlMemoryHeap>(ql_->mem(), heap_base, heap_base + heap_size);
    heap_ = heap_storage_.get();

    // the path identities (windows.py: systemdrive + windir + username)
    const auto sysdrv = profile().get("PATH", "systemdrive").value_or("C:");
    const auto windir = profile().get("PATH", "windir").value_or("\\Windows");
    const auto username = profile().get("USER", "username").value_or("user");

    windir_ = std::string(sysdrv) + std::string(windir);
    winsys_ = windir_ + "\\System32";
    userprofile_ = std::string(sysdrv) + "\\Users\\" + std::string(username);
    username_ = username;

    // windows.py __init__: self.pid = self.profile.getint('KERNEL', 'pid')
    pid_ = static_cast<std::uint32_t>(profile().get_int("KERNEL", "pid"));

    // windows.py __setup_components: the main thread + the thread manager +
    // the main-thread handle. install_hook defers to load(): the uc engine is
    // not wired until the QlCoreHooks init completes after the os
    // construction, and a hook_code registration at ctor time dereferences it
    auto main_thread = std::make_unique<QlWindowsThread>(ql_);
    auto mgr = std::make_unique<QlWindowsThreadManagement>(ql_, main_thread.get());
    mgr->append(std::move(main_thread));
    thread_manager_ = std::move(mgr);

    // more handle manager: the main-thread handle (windows.py verbatim:
    // Handle(obj=main_thread)). The ensure runs from the ctor head where the
    // handle manager does not exist yet; the ctor-side tail appends it right
    // after the manager comes up
    if (handle_manager_ != nullptr && !main_thread_handle_appended_) {
        Handle main_thread_handle(std::nullopt, thread_manager_->cur_thread());
        handle_manager_->append(main_thread_handle);
        main_thread_handle_appended_ = true;
    }

    // the winapi dispatch hook (windows.py: ql.hook_code(self.hook_winapi))
    // — the upstream rides it at os-construction time (the windows.py
    // __init__ calls self.load()); the explicit full-range bounds are the
    // pinned registration shape (the default begin=1/end=0 never fires)
    auto* self = this;
    hook_handle_ = ql_->hook_code([self](std::uint64_t address, std::uint32_t size) -> int {
        // the hang guard: the trace hook already runs per instruction, so the
        // instruction budget is free (pegasus's runaway-loop protection is the
        // config timeout; a counted budget is deterministic instead of wall
        // clock)
        // unicorn's own count limit stops at exactly `count` instructions
        // without reporting an error, so the guard trips on the boundary
        ++self->instructions_;
        const auto budget = self->ql_->count();
        if (budget != 0 && self->instructions_ >= budget) {
            self->instruction_budget_hit_ = true;
            self->ql_->emu_stop();
            return 1;
        }
        if (self->seh_check_cpu_exception(address)) {
            return 1;  // the exception was staged: the run loop restarts there
        }
        self->hook_winapi(address, size);
        return 0;
    }, 0, 0xffffffffffffffffull);

    // the SEH dispatch hook (seh.hpp): the x86 exception machinery rides a
    // raw unicorn mem-invalid hook — the ql-layer mem hooks always report
    // the fault handled (the upstream _hook_mem_cb contract expects the
    // callback to fix the state for the retry), while the SEH dispatch
    // needs the not-handled return so the run loop can restart at the
    // staged handler
    if (bits_ == 32 && seh_hook_ == 0) {
        if (seh_map_sentinel()) {
            uc_hook_add(&ql_->arch().uc(), &seh_hook_, UC_HOOK_MEM_INVALID,
                        reinterpret_cast<void*>(&seh_fault_trampoline), this, 1, 0);
        }
    }
}

// the __p___initenv cell: a zeroed pointer-sized guest cell the CRT stores
// the environment block pointer in (`*__p___initenv() = env`)
std::uint64_t QlOsWindows::ensure_env_cell() {
    if (env_cell_ == 0) {
        const auto ps = ql_->arch().pointersize();
        env_cell_ = heap_->alloc(ps);
        if (env_cell_ != 0) {
            ql_->mem().write(env_cell_, std::vector<std::uint8_t>(ps, 0));
        }
    }
    return env_cell_;
}

std::uint64_t QlOsWindows::thread_manager_ret_addr() const noexcept {
    // windows.py: os.thread_manager.thread_ret_addr (0 before the setup)
    return thread_manager_ == nullptr ? thread_ret_addr_ : thread_manager_->thread_ret_addr();
}

std::string_view QlOsWindows::os_section_name() const {
    // windows.py: OS{bits}
    return bits_ == 64 ? "OS64" : "OS32";
}

std::string_view QlOsWindows::bits_section() const noexcept {
    return bits_ == 64 ? "OS64" : "OS32";
}

void QlOsWindows::record_entry_point_error(std::string type, std::string message) {
    entry_point_errors_.push_back(EntryPointError{std::move(type), std::move(message)});
}

namespace {

// the emulation-error text -> the pegasus error["error"] vocabulary the
// reference PMA cases assert against
std::string classify_emulation_error(const std::string& text) {
    auto has = [&text](const char* needle) { return text.find(needle) != std::string::npos; };
    if (has("Invalid memory fetch") || has("failed to fetch") || has("non-executable memory")) return "invalid_fetch";
    if (has("Invalid memory write") || has("failed to write memory")) return "invalid_write";
    if (has("Invalid memory read") || has("failed to read memory")) return "invalid_read";
    if (has("Invalid memory access")) return "invalid_access";
    if (has("Unhandled CPU exception")) return "invalid_cpu_exception";
    if (has("Invalid instruction")) return "invalid_insn";
    if (has("max api count")) return "max_api_count";
    if (has("unsupported api")) return "unsupported_api";
    return "emu_error";
}

std::string lower_ascii(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

// the calling convention an unresolved import is answered through: the CRT
// family cleans its own frame on x86 (cdecl), everything else is stdcall, and
// a 64-bit guest is Ms64
WinCc default_cc_for(const std::string& name, std::size_t bits) {
    if (bits == 64) return WinCc::Ms64;
    const auto n = lower_ascii(name);
    if (n.rfind("msvcrt.", 0) == 0 || n.rfind("ucrtbase", 0) == 0 || n.rfind("api-ms-win-crt", 0) == 0 ||
        n.rfind("vcruntime", 0) == 0) {
        return WinCc::Cdecl;
    }
    return WinCc::Stdcall;
}

}  // namespace

void QlOsWindows::on_emulation_error(std::string_view message) {
    record_entry_point_error(classify_emulation_error(std::string(message)), std::string(message));
}

void QlOsWindows::set_stdin(std::shared_ptr<QlFile> stream) {
    QlOs::set_stdin(std::move(stream));
    if (auto* h = handle_manager_->get(QL_STD_INPUT_HANDLE)) h->obj = &stdin_stream();
}

void QlOsWindows::set_stdout(std::shared_ptr<QlFile> stream) {
    QlOs::set_stdout(std::move(stream));
    if (auto* h = handle_manager_->get(QL_STD_OUTPUT_HANDLE)) h->obj = &stdout_stream();
}

void QlOsWindows::set_stderr(std::shared_ptr<QlFile> stream) {
    QlOs::set_stderr(std::move(stream));
    if (auto* h = handle_manager_->get(QL_STD_ERROR_HANDLE)) h->obj = &stderr_stream();
}

QlFunctionCall& QlOsWindows::fcall_select(WinCc cc) {
    return *fcall_table_.at(cc);
}

void QlOsWindows::load() {
    // windows.py load: the GDT/segments (FS/GS regions) + the api dispatch hook
    ensure_profile_state();

    // the thread scheduler hook (windows.py __setup_components: the
    // QlWindowsThreadManagement ctor hooks the code stream; the port defers
    // the registration here where the uc engine is wired)
    if (thread_manager_ != nullptr) {
        thread_manager_->install_hook();
        thread_ret_addr_ = thread_manager_->thread_ret_addr();
    }

    auto& arch = ql().arch();
    auto& mem = ql().mem();

    // the FS/GS regions ride ensure_profile_state (the ctor-time map — the
    // upstream windows.py __init__ calls self.load() at construction); the
    // is_available guards keep this path idempotent
    if (!mem.is_available(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE)) {
        throw QlErrorBase("cannot map FS segment, memory location is taken");
    }
    if (!mem.is_available(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)) {
        throw QlErrorBase("cannot map GS segment, memory location is taken");
    }
    if (arch.bits() == 64) {
        arch.regs().write("gsbase", GS_SEGMENT_ADDR);
    }

    // the winapi dispatch hook rides ensure_profile_state (the ctor-time
    // registration — the load() body here stays for the direct callers only)
}

void QlOsWindows::hook_winapi(std::uint64_t address, std::uint32_t size) {
    (void)size;

    // windows.py hook_winapi: the import_symbols table maps the resolved
    // export address to the api identity; the resolved handler comes from
    // the ApiRegistry (the C++ static registration replacing the getattr
    // dispatch)
    const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql_->loader());

    const auto* imported = pe_loader.import_symbols_at(address);
    if (imported == nullptr) {
        return;
    }
    // the loader keys import_symbols_ by every loaded image's exports, so the
    // main image's own exports land in it too: a dll calling its own export is
    // not an import (answering it as one hijacks the call). Match the owning
    // module name instead of an address range — the x64 profiles map the
    // synthesized stub dlls at the image base itself
    if (lower_ascii(imported->dll) == lower_ascii(ql_->targetname())) {
        return;
    }

    const auto* api = ApiRegistry::instance().find(imported->name);

    // the max_api_count guard (pegasus cfg.max_api_count): a dispatch beyond
    // the budget ends the entry point instead of letting a runaway sample eat
    // the whole analysis
    const auto budget = ql_->max_api_count();
    if (budget != 0 && stats().api_count() >= budget) {
        record_entry_point_error("max_api_count",
                                 "max api count reached (" + std::to_string(budget) + ")");
        throw QlErrorBase("max api count reached (" + std::to_string(budget) + ")");
    }

    if (api == nullptr) {
        // the unsupported-import discipline: answer a zero return value through
        // the calling convention so the caller's frame stays balanced (the stub
        // export cell would answer whatever rax held, which is how an
        // unimplemented import turns into a stale-pointer store), and record
        // the name so the analysis surface can rank the gap
        stats().log_unsupported_api(imported->name);
        if (ql_->unsupported_api_policy() == QilingOptions::UnsupportedApiPolicy::Abort) {
            record_entry_point_error("unsupported_api", "unsupported api: " + imported->name);
            throw QlErrorBase("unsupported api: " + imported->name);
        }
        set_fcall_ptr(fcall_select(default_cc_for(imported->name, bits_)));
        fcall_->return_value(0, 0);
        return;
    }

    // select the calling convention for this call site and run the handler
    // through the os.call orchestration: the handler resolves through
    // resolve_named_params (the placeholder-typed entries decode to strings)
    // and the fcall call unwinds the frame (rax + the pc = the return
    // address) unless the handler stopped the emulation first
    set_fcall_ptr(fcall_select(api->cc));

    // the upstream's os.call(func, params, ...) resolution: the raw values
    // read through the cc apply the resolvers table (the placeholder-typed
    // entries decode to the guest strings) before the handler runs
    const auto proto = api->params;
    const auto handler = api->handler;
    auto* self = this;
    call(address, imported->name,
         [self, proto, handler](std::uint64_t pc, const QlFunctionCall::Params& raw) -> std::optional<std::uint64_t> {
             std::vector<std::uint64_t> rawvals;
             rawvals.reserve(raw.size());
             for (const auto& [n, v] : raw) {
                 (void)n;
                 rawvals.push_back(v);
             }
             return handler(*self->ql_, pc, self->resolve_named_params(proto, rawvals));
         },
         api->params, nullptr, nullptr, api->passthru);
}

void QlOsWindows::run() {
    // windows.py run: the explicit entry/exit overrides, then the emulation
    ensure_profile_state();
    init_sp_ = ql_->arch().regs().arch_sp();

    if (ql_->exit_point_set()) {
        set_exit_point(ql_->exit_point());
    }
    if (ql_->entry_point_set()) {
        ql_->loader().entry_point = ql_->entry_point();
    }

    const auto entry_point = ql_->loader().entry_point;
    const auto exit_point = ql_->code().empty()
        ? exit_point_
        : (entry_point + ql_->code().size());

    // the emulation with the SEH retarget loop: a dispatched guest fault
    // (seh.hpp) arms seh_retarget_ and lets emu_start surface the error; the
    // loop restarts at the staged target (the frame handler, the filter, the
    // __except block, or the CONTEXT resume pc). A fault with no retarget
    // is the ordinary failure path
    std::uint64_t begin = entry_point;
    while (true) {
        try {
            ql_->emu_start(begin, exit_point, ql_->timeout(), ql_->count());
            if (seh_retarget_ == 0) {
                break;
            }
            // a CPU-exception dispatch stopped the emulation cleanly (no
            // unicorn error to bubble up): restart at the staged target
            begin = seh_retarget_;
            seh_retarget_ = 0;
            continue;
        } catch (const QlErrorBase& e) {
            if (seh_retarget_ == 0) {
                // an unhandled access violation ends the guest the way Windows
                // does: the process exit code is STATUS_ACCESS_VIOLATION, and
                // the entry-point error record carries the class
                if (classify_emulation_error(e.what()).rfind("invalid_", 0) == 0) {
                    set_exit_code(static_cast<int>(0xC0000005u));
                }
                emu_error();
                throw;
            }
            drop_last_entry_point_error();
            begin = seh_retarget_;
            seh_retarget_ = 0;
        }
    }

    // the instruction budget ended the run without an emulation error: record
    // the guard in the same vocabulary (the reference PMA cases tolerate it)
    if (instruction_budget_hit_) {
        record_entry_point_error("timeout", "instruction budget reached (" +
                                                std::to_string(ql_->count()) + ")");
    }

    // windows.py run tail: persist the registry diff + the summary lines
    registry_manager_->save();
    for (const auto& entry : stats().summary()) {
        // windows.py: ql.log.debug(entry)
        (void)entry;
    }
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
