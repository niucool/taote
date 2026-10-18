#include "qiling/core.hpp"

#include "qiling/arch/arch.hpp"
#include "qiling/arch/utils.hpp"
#include "qiling/exception.hpp"
#include "qiling/host.hpp"
#include "qiling/log.hpp"
#include "qiling/loader/blob.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"
#include "qiling/profiles/inireader.hpp"
#include "qiling/snapshot.hpp"
#include "qiling/utils.hpp"

namespace qiling {

namespace {

// core.py: the profile lookup for shellcode execution
IniConfig profile_setup(QL_OS ostype, const std::optional<std::string>& user_config);

}  // namespace

Qiling::Qiling(const QilingOptions& options) {
    // ---- definition during ql=Qiling() (core.py) ----
    env_ = options.env;
    code_ = options.code;
    multithread_ = options.multithread;
    stop_options_ = options.stop;
    verbose_ = options.verbose;

    // ---- argv setup (core.py) ----
    if (!options.argv.empty()) {
        if (!code_.empty()) {
            throw QlErrorBase("argv and code are mutually execlusive");
        }

        // target binary must exist (core.py QlErrorFileNotFound)
        std::error_code ec;
        if (!std::filesystem::is_regular_file(options.argv[0], ec)) {
            throw QlErrorFileNotFound("Target binary not found: \"" + options.argv[0] + "\"");
        }
        argv_ = options.argv;
    } else {
        // an empty argv list means shellcode execution: the '' placeholder
        // keeps the 'path' api compatible
        argv_.emplace_back("");
    }

    // ---- rootfs setup (core.py) ----
    {
        std::error_code ec;
        const bool is_dir = std::filesystem::is_directory(options.rootfs, ec);
        if (!is_dir) {
            throw QlErrorFileNotFound("Target rootfs not found: \"" + options.rootfs + "\"");
        }
        rootfs_ = options.rootfs;
    }

    // ---- arch os setup (core.py) ----
    std::optional<QL_ARCH> archtype = options.archtype;
    std::optional<QL_OS> ostype = options.ostype;
    std::optional<QL_ENDIAN> endian = options.endian;

    if (!archtype.has_value()) {
        const auto guessed = ql_guess_emu_env(path());
        archtype = guessed.arch;

        if (!ostype.has_value()) {
            ostype = guessed.ostype;
        }
        if (!endian.has_value()) {
            endian = guessed.endian;
        }
    } else if (!ostype.has_value()) {
        ostype = arch_os_convert(*archtype);
    }

    if (!archtype.has_value()) {
        throw QlErrorArch("Unknown or unsupported architecture");
    }
    if (!ostype.has_value()) {
        throw QlErrorOsType("Unknown or unsupported operating system");
    }

    // endianness defaults to little; ignored for archs with fixed endianness
    if (!endian.has_value()) {
        endian = QL_ENDIAN::EL;
    }

    arch_ = select_arch(*archtype, options.cputype, *endian, options.thumb)(this);

    // once the arch is up: QlCoreStructs + QlCoreHooks (core.py init order)
    QlCoreStructs::init(arch().endian(), arch().bits());
    QlCoreHooks::init(arch().uc());

    // emulation has not started yet
    state_ = QL_STATE::NOT_SET;

    // ---- logger ----
    // log_devices defaults to stderr (core.py); the console/plain knobs
    // adjust the sink format
    log_ = log::setup_logger({log::LogDevice{log::LogDevice::Kind::Stderr}}, options.log_plain);
    (void)options.console;

    // ---- profile ----
    profile_default_ = profile_setup(*ostype, options.profile);
    profile_ = &profile_default_;

    // ---- loader ----
    loader_ = select_loader(*ostype, false)(this);

    // ---- components ----
    mem_ = select_component_memory()(this);
    os_ = select_os(*ostype)(this);

    // wire the arch stack helpers to the memory manager (the Python boot
    // order: arch is constructed before mem, and stack_push uses ql.mem)
    arch().attach_memory(*mem_);

    if (baremetal()) {
        // the hw manager lands with the bare-metal peripherals slice
        // (PORT_PLAN.md §10, OQ 9)
        hw_ = nullptr;
    }

    // run the loader
    loader().run();

    init_stop_guard();
}

Qiling::~Qiling() {
    std::fflush(stderr);
    // tear down the os-owned hooks and the tracer hooks while the uc engine
    // is alive: the C++ destruction order closes the arch's uc handle before
    // the QlCoreHooks base dtor runs, so anything touching uc at that point
    // would dangle
    if (os_ != nullptr) {
        os_->shutdown();
    }
    if (arch_ != nullptr) {
        arch_->shutdown_utils();
    }
    // release every remaining uc hook handle while the engine is alive (the
    // base-class dtor runs after the arch members have closed uc)
    clear_hooks();
}

bool Qiling::baremetal() const noexcept {
    // core.py: the os type membership in QL_OS_BAREMETAL (mcu)
    return os_ != nullptr && os_->type() == QL_OS::MCU;
}

std::string Qiling::targetname() const {
    // core.py: os.path.basename(self.path)
    const auto& p = path();
    const auto slash = p.find_last_of("/\\");
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

void Qiling::set_verbose(QL_VERBOSE v) {
    // core.py verbose.setter: the log level + the arch tracing hooks
    verbose_ = v;
    log().set_level(log::resolve_logger_level(v));
    arch().utils().setup_output(v);
}

// ---- patching ----

void Qiling::patch(std::uint64_t offset, const std::vector<std::uint8_t>& data, std::optional<std::string> target) {
    if (!target.has_value()) {
        patch_bin_.push_back({offset, data});
    } else {
        patch_lib_.push_back({offset, data, std::move(*target)});
    }
}

void Qiling::do_bin_patch() {
    const std::uint64_t ba = loader().load_address;

    for (const auto& [offset, data] : patch_bin_) {
        mem().write(ba + offset, data);
    }
}

void Qiling::do_lib_patch() {
    for (const auto& [offset, data, filename] : patch_lib_) {
        const auto ba = mem().get_lib_base(filename);

        if (!ba.has_value()) {
            throw QlErrorBase("Patch failed: there is no loaded library named \"" + filename + "\"");
        }

        mem().write(*ba + offset, data);
    }
}

// ---- emulation control ----

void Qiling::run(std::optional<std::uint64_t> begin, std::optional<std::uint64_t> end,
                 std::uint64_t timeout, std::uint64_t count) {
    // replace the original entry point, exit point, timeout and count
    entry_point_ = begin.value_or(0);
    exit_point_ = end.value_or(0);
    timeout_ = timeout;
    count_ = count;

    // debugger selection degrades until the debugging slice (core.py selects
    // and runs a debugger when one is configured)
    // debugger = select_debugger(self._debugger)

    // patch binary
    do_bin_patch();

    write_exit_trap();

    // emulate the binary
    os().run();
}

void Qiling::emu_start(std::uint64_t begin, std::uint64_t end, std::uint64_t timeout, std::uint64_t count) {
    // core.py: unicorn derives thumb mode from the pc lsb; the ARM port
    // propagates it via the same bit (core.py's _init_thumb getattr)
    begin = arch().adjust_emu_start(begin);

    // reset exception status before emulation starts
    clear_internal_exception();

    state_ = QL_STATE::STARTED;

    // effectively start the emulation; returns only after emu_stop (the
    // rethrow-after-uc_emu_start discipline — core.py:743)
    uc_engine& u = arch().uc();
    const uc_err err = uc_emu_start(&u, begin, end, timeout, count);
    if (err != UC_ERR_OK) {
        throw QlErrorBase(std::string("emulation error: ") + uc_strerror(err));
    }

    state_ = QL_STATE::STOPPED;

    // if an exception was raised during emulation, propagate it up
    if (internal_exception() != nullptr) {
        std::rethrow_exception(internal_exception());
    }
}

void Qiling::emu_stop() {
    uc_emu_stop(&arch().uc());
    state_ = QL_STATE::STOPPED;
}

void Qiling::stop() {
    // core.py stop: multithreaded / baremetal / plain paths
    if (multithread()) {
        // thread management lands with the guest-thread slices
        emu_stop();
    } else {
        emu_stop();
    }
}

// ---- stack delegation (core.py stack_push/pop/read/write) ----

std::uint64_t Qiling::stack_push(std::uint64_t data) { return arch().stack_push(data); }

std::uint64_t Qiling::stack_pop() { return arch().stack_pop(); }

std::uint64_t Qiling::stack_read(std::int64_t offset) { return arch().stack_read(offset); }

void Qiling::stack_write(std::int64_t offset, std::uint64_t data) { arch().stack_write(offset, data); }

// ---- fs mapper ----

void Qiling::add_fs_mapper(std::string_view ql_path, QlFsBinding binding) {
    os().map_fs_path(ql_path, std::move(binding));
}

void Qiling::remove_fs_mapper(std::string_view ql_path) {
    os().unmap_fs_path(ql_path);
}

// ---- exit trap (core.py _init_stop_guard / write_exit_trap) ----

void Qiling::init_stop_guard() {
    if (stop_options_ == QL_STOP::NONE) {
        return;
    }

    // allocate a guard page (needed in both cases: a negative stack pointer
    // still needs a return address, otherwise we end up at 0); kept away from
    // the heap (PE) so the heap can grow
    exit_trap_addr_ = mem().find_free_space(0x1000, 0x9000000, std::nullopt, 0x10);
    mem().map(exit_trap_addr_, 0x1000, UC_PROT_ALL, "[Stop guard page]");

    // stop on a negative stack pointer: a code hook checks the sp against the
    // initial sp (core.py _check_sp)
    if (flag_set(stop_options_, QL_STOP::STACK_POINTER)) {
        auto* self = this;
        sp_check_handle_ = hook_code([self](std::uint64_t, std::uint32_t) -> int {
            if (!self->loader().skip_exit_check) {
                if (self->initial_sp_ < self->arch().regs().arch_sp()) {
                    self->emu_stop();
                }
            }
            return 0;
        });
    }

    // stop when running into the exit trap address (core.py _exit_trap)
    if (flag_set(stop_options_, QL_STOP::EXIT_TRAP)) {
        auto* self = this;
        exit_trap_handle_ = hook_address([self]() -> int {
            self->emu_stop();
            return 0;
        }, exit_trap_addr_);
    }
}

void Qiling::write_exit_trap() {
    initial_sp_ = arch().regs().arch_sp();
    initial_sp_set_ = true;

    if (stop_options_ != QL_STOP::NONE) {
        if (!loader().skip_exit_check) {
            stack_write(0, exit_trap_addr_);
        }
        // else: the loader requested to skip exit_trap (core.py)
    }
}

// ---- snapshot aggregation (core.py save/restore) ----

QilingSavedState Qiling::save(bool reg, bool mem, bool cpu_context) {
    QilingSavedState saved;

    if (reg) {
        saved.reg = arch().regs().save();
    }

    if (cpu_context) {
        saved.cpu_context = std::shared_ptr<UcContext>(arch().save());
    }

    if (mem) {
        saved.mem = this->mem().save();
    }

    return saved;
}

void Qiling::restore(const QilingSavedState& saved_state) {
    // only restore the saved components; the rest remains intact (core.py)
    if (saved_state.mem.has_value()) {
        mem().restore(*saved_state.mem);
    }

    if (saved_state.cpu_context.has_value()) {
        arch().restore(**saved_state.cpu_context);
    }

    if (saved_state.reg.has_value()) {
        arch().regs().restore(*saved_state.reg);
    }
}

// ---- profile setup (utils.py profile_setup) ----

// utils.py select_component('os', 'memory'): the composition-root memory
// factory (defined here because the factory body needs the complete Qiling —
// the components derive their sub-handles from the facade)
std::function<std::unique_ptr<QlMemoryManager>(Qiling*)> select_component_memory() {
    return [](Qiling* ql) -> std::unique_ptr<QlMemoryManager> {
        return std::make_unique<QlMemoryManager>(ql->arch().uc(), *ql, ql->arch().bits(), 0x1000);
    };
}

namespace {

// the lowercase name of the os (os_name_table reverse lookup; the profile file
// name derives from it)
std::string_view os_profile_stem(QL_OS ostype) {
    switch (ostype) {
        case QL_OS::LINUX: return "linux";
        case QL_OS::FREEBSD: return "freebsd";
        case QL_OS::MACOS: return "macos";
        case QL_OS::WINDOWS: return "windows";
        case QL_OS::UEFI: return "uefi";
        case QL_OS::DOS: return "dos";
        case QL_OS::QNX: return "qnx";
        case QL_OS::MCU: return "mcu";
        case QL_OS::BLOB: return "blob";
    }
    return "blob";
}

IniConfig profile_setup(QL_OS ostype, const std::optional<std::string>& user_config) {
    IniConfig config;

    // read the default profile first (utils.py: qiling_home/profiles/<os>.ql)
    const std::filesystem::path profile_name =
        std::filesystem::path(os_profile_stem(ostype)).replace_extension(".ql");
#ifdef QILING_SOURCE_DIR
    const std::filesystem::path os_profile =
        std::filesystem::path(QILING_SOURCE_DIR) / "qiling" / "profiles" / profile_name;
    config.read(os_profile);
#else
    (void)profile_name;
#endif

    // a user-specified profile adds or overrides existing settings
    if (user_config.has_value()) {
        config.read(std::filesystem::path(*user_config));
    }

    return config;
}

}  // namespace

}  // namespace qiling
