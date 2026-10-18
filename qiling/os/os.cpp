#include "qiling/os/os.hpp"

#include "qiling/arch/arch.hpp"
#include "qiling/cc/cc.hpp"
#include "qiling/core.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/profiles/inireader.hpp"

namespace qiling {

namespace {

// os/os.py: the default exit point per bit width
std::uint64_t default_exit_point(int bits) {
    switch (bits) {
        case 16: return 0xfffff;             // 20bit address lane
        case 32: return 0x8fffffff;
        default: return 0xffffffffffffffff;  // 64
    }
}

// the console C streams (the FILE*-based stand-ins for PersistentQlFile)
std::FILE* stdin_file() { return stdin; }
std::FILE* stdout_file() { return stdout; }
std::FILE* stderr_file() { return stderr; }

}  // namespace

QlOs::QlOs(Qiling* ql) : ql_(ql) {
    // standard streams: the console trio wraps the host C streams (see the
    // header's deviation note); PersistentQlFile keeps the host from closing
    stdin_ = std::make_shared<PersistentQlFile>("stdin", stdin_file());
    stdout_ = std::make_shared<PersistentQlFile>("stdout", stdout_file());
    stderr_ = std::make_shared<PersistentQlFile>("stderr", stderr_file());

    console_out_ = std::make_shared<PersistentQlFile>("console", stdout_file());

    profile_ = &ql->profile();

    // default exit point
    exit_point_ = default_exit_point(ql->arch().bits());

    // os.py: shellcode entry configuration from the CODE profile section
    if (!ql->code().empty()) {
        load_address_ = static_cast<std::uint64_t>(profile_->get_int("CODE", "load_address"));
        entry_point_ = static_cast<std::uint64_t>(profile_->get_int("CODE", "entry_point"));
        code_ram_size_ = static_cast<std::uint64_t>(profile_->get_int("CODE", "ram_size"));
    }

    // os.py: user_defined_api tables per intercept kind
    user_defined_api_[QL_INTERCEPT::CALL] = {};
    user_defined_api_[QL_INTERCEPT::ENTER] = {};
    user_defined_api_[QL_INTERCEPT::EXIT] = {};

    // os.py: default fcall param resolving methods (the STRING/WSTRING/GUID
    // resolvers land with the syscall glue that defines their placeholders)
}

void QlOs::init_paths_if_managed() {
    // os.py ctor: the path helpers exist for the posix/windows/dos families
    // (called from the derived ctors — the C++ base ctor cannot dispatch the
    // virtual type() during construction)
    if (type() == QL_OS::LINUX || type() == QL_OS::FREEBSD || type() == QL_OS::MACOS ||
        type() == QL_OS::WINDOWS || type() == QL_OS::DOS || type() == QL_OS::QNX) {
        const std::string cwd = profile_->get("MISC", "current_path").value_or("/");
        path_ = std::make_unique<QlOsPath>(ql().rootfs(), cwd, type());
        fs_mapper_ = std::make_unique<QlFsMapper>(*path_);
    }
}

QlOs::~QlOs() = default;

void QlOs::set_fcall(std::unique_ptr<QlFunctionCall> fcall) {
    fcall_ = std::move(fcall);
}

void QlOs::stop() {
    // os.py stop: thread management lands with the guest-thread slices; the
    // default stops the emulation
    ql().emu_stop();
}

void QlOs::set_stdin(std::shared_ptr<QlFile> stream) {
    stdin_ = std::move(stream);
}

void QlOs::set_stdout(std::shared_ptr<QlFile> stream) {
    stdout_ = std::move(stream);
}

void QlOs::set_stderr(std::shared_ptr<QlFile> stream) {
    stderr_ = std::move(stream);
}

void QlOs::set_api(std::uint64_t target, void* handler, QL_INTERCEPT intercept) {
    user_defined_api_[intercept][std::to_string(target)] = handler;
}

void QlOs::set_api(std::string_view target, void* handler, QL_INTERCEPT intercept) {
    user_defined_api_[intercept][std::string(target)] = handler;
}

std::vector<std::uint64_t> QlOs::resolve_fcall_params(const std::vector<std::pair<std::string, int>>& params) const {
    // os.py resolve_fcall_params: read the raw values through the fcall layer
    // in proto order
    std::vector<int> types;
    types.reserve(params.size());
    for (const auto& [name, typ] : params) {
        (void)name;
        types.push_back(typ);
    }

    return fcall().read_params(types);
}

std::vector<std::string> QlOs::process_fcall_params(const std::vector<FcallArg>& targs) const {
    // os.py process_fcall_params: ints as hex, strings quoted by stringify
    std::vector<std::string> out;
    out.reserve(targs.size());

    for (const auto& targ : targs) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%#llx", static_cast<unsigned long long>(targ.value));
        out.push_back(targ.name + "=" + buf);
    }

    return out;
}

std::optional<std::uint64_t> QlOs::call(std::uint64_t pc, const std::string& name,
                                        const std::vector<std::pair<std::string, int>>& proto,
                                        const std::vector<std::uint64_t>& args_raw) {
    // os.py call: resolve the arguments, run the fcall orchestration, log the
    // syscall and set the pc back to the return address
    const auto resolved = resolve_fcall_params(proto);

    std::vector<std::pair<std::string, std::uint64_t>> args;
    args.reserve(args_raw.size());
    for (std::size_t i = 0; i < args_raw.size(); ++i) {
        args.emplace_back(i < proto.size() ? proto[i].first : "arg" + std::to_string(i), args_raw[i]);
    }

    // the fcall call() returns the CallResult; the OS-level wrapper only
    // forwards the orchestration (the hook invocation is handled by the
    // caller-provided closures in the Phase 4 syscall glue)
    const auto result = fcall().call(
        [&name](std::uint64_t, const std::vector<std::pair<std::string, std::uint64_t>>& params)
            -> std::optional<std::uint64_t> {
            (void)name;
            (void)params;
            return std::nullopt;  // no implementation: the api hook decides
        },
        proto, args, {}, {}, false);

    stats_.log_api_call(pc, name, result.retval.value_or(0), result.retval.has_value(), result.retaddr);

    // os.py: avoid modifying the pc when the emulation has stopped (unicorn
    // issue #1579)
    if (ql().emu_state() != QL_STATE::STOPPED) {
        ql().arch().regs().set_arch_pc(result.retaddr);
    }

    return result.retval;
}

void QlOs::emu_error() const {
    // os.py emu_error: dump the register context and the pc neighborhood
    QlArch& arch = ql().arch();

    for (const auto& [name, regid] : arch.regs().register_mapping()) {
        try {
            const auto value = arch.regs().read(regid);
            std::fprintf(stderr, "[!] %s: 0x%llx\n", name.c_str(),
                         static_cast<unsigned long long>(value));
        } catch (const QlErrorBase&) {
            std::fprintf(stderr, "[!] %s: n/a\n", name.c_str());
        }
    }

    const std::uint64_t pc = arch.regs().arch_pc();
    std::fprintf(stderr, "[!] PC = 0x%llx\n", static_cast<unsigned long long>(pc));
}

}  // namespace qiling
