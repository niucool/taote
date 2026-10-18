#include <cstdio>
#include <cstdint>

#include "qiling/os/os.hpp"

#include "qiling/os/linux/thread.hpp"

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
    stats_ = std::make_unique<QlOsStats>();
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

void QlOs::set_thread_management(std::unique_ptr<os::linux::QlLinuxThreadManagement> tm) {
    thread_management_ = std::move(tm);
}

void QlOs::set_futexm(std::unique_ptr<os::linux::QlLinuxFutexManagement> fm) {
    futexm_ = std::move(fm);
}

void QlOs::stop() {
    // os.py stop: the multithreaded path stops the world through the thread
    // management; the plain path stops the emulation
    if (ql().multithread() && thread_management_ != nullptr) {
        thread_management_->stop();
        return;
    }
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

void QlOs::set_api(std::uint64_t target, UserApiHandler handler, QL_INTERCEPT intercept) {
    user_defined_api_[intercept][std::to_string(target)] = std::move(handler);
}

void QlOs::set_api(std::string_view target, UserApiHandler handler, QL_INTERCEPT intercept) {
    user_defined_api_[intercept][std::string(target)] = std::move(handler);
}

const QlOs::UserApiHandler* QlOs::find_user_api(const std::string& name, QL_INTERCEPT intercept) const {
    const auto table = user_defined_api_.find(intercept);
    if (table == user_defined_api_.end()) {
        return nullptr;
    }
    const auto it = table->second.find(name);
    return it == table->second.end() ? nullptr : &it->second;
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

    const auto out = fcall().read_params(types);
    return out;
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

std::optional<std::uint64_t> QlOs::call(std::uint64_t pc, const std::string& name, const QlFunctionCall::CallHook& func,
                                        const std::vector<std::pair<std::string, int>>& proto,
                                        const QlFunctionCall::OnEnterHook& onenter,
                                        const QlFunctionCall::OnExitHook& onexit, bool passthru) {
    // os.py call: resolve the arguments according to their types, call the
    // hooked function through the fcall orchestration, post-process, print,
    // log, and set the pc to the return address
    const auto resolved = resolve_fcall_params(proto);

    std::vector<std::pair<std::string, std::uint64_t>> args;
    args.reserve(proto.size());
    for (std::size_t i = 0; i < proto.size(); ++i) {
        args.emplace_back(proto[i].first, i < resolved.size() ? resolved[i] : 0);
    }

    const auto result = fcall().call(func, proto, args, onenter, onexit, passthru);

    // post-process the argument values (the display strings); the TypedArg
    // triples map 1:1 onto the FcallArg shape the display resolver takes
    std::vector<FcallArg> targs;
    targs.reserve(result.params.size());
    for (const auto& t : result.params) {
        targs.push_back(FcallArg{t.name, t.type, t.value});
    }
    const auto pargs = process_fcall_params(targs);
    (void)pargs;  // the verbose print_function surface lands with its slice

    stats_->log_api_call(pc, name, result.retval.value_or(0), result.retval.has_value(), result.retaddr);

    // os.py: avoid modifying the pc when the emulation has stopped (unicorn
    // issue #1579)
    if (!passthru && ql().emu_state() != QL_STATE::STOPPED) {
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
