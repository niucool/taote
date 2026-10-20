// Ported from qiling/core.py — the Qiling facade (the composition root).
// Python: `class Qiling(QlCoreHooks, QlCoreStructs)`. The C++ port keeps the
// inheritance so `ql.hook_code(...)`, `ql.pack8(...)` and the emu-start
// discipline live on the facade exactly like upstream; the bases gain
// deferred-init ctors to mirror the Python mid-constructor `__init__` calls.
//
// The ctor performs the core.py assembly sequence verbatim: argv/rootfs
// validation, arch/os guessing, select_arch, profile setup, select_loader,
// select_component('os','memory'), select_os, loader.run(), stop-guard setup.
#ifndef QILING_CORE_HPP
#define QILING_CORE_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "qiling/const.hpp"
#include "qiling/core_hooks.hpp"
#include "qiling/core_struct.hpp"
#include "qiling/arch/models.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/mapper.hpp"
#include "qiling/arch/arch.hpp"
#include "qiling/profiles/inireader.hpp"
#include <spdlog/spdlog.h>

namespace qiling {

class QlArch;
class QlOs;
class UcContext;
namespace loader { class QlLoader; }
namespace os { class QlOsBlob; }

// core.py save/restore state (the saved_states dict analogue)
struct QilingSavedState {
    std::optional<std::map<std::string, std::uint64_t>> reg;
    std::optional<SavedMemory> mem;
    std::optional<std::shared_ptr<UcContext>> cpu_context;
};

// core.py Qiling.__init__ kwargs (the C++ parameter object)
struct QilingOptions {
    // the emulated program argv; an empty list means shellcode execution
    // (a '' placeholder is inserted, as in core.py)
    std::vector<std::string> argv;

    std::string rootfs = ".";

    // the program environment variables
    std::map<std::string, std::string> env;

    // the shellcode (mutually exclusive with argv, core.py)
    std::vector<std::uint8_t> code;

    std::optional<QL_OS> ostype;
    std::optional<QL_ARCH> archtype;
    QL_CPU cputype = std::monostate{};

    QL_VERBOSE verbose = QL_VERBOSE::DEFAULT;

    // a user profile path (None/default profile otherwise)
    std::optional<std::string> profile;

    bool console = true;
    bool log_plain = false;

    bool multithread = false;

    std::optional<std::string> filter;

    QL_STOP stop = QL_STOP::NONE;

    std::optional<QL_ENDIAN> endian;
    bool thumb = false;

    // the emulation guards (pegasus cfg.timeout / cfg.max_api_count): the
    // timeout is in seconds (0 = no limit), count caps executed instructions,
    // max_api_count caps dispatched API calls
    std::uint64_t timeout = 0;
    std::uint64_t count = 0;
    std::uint64_t max_api_count = 0;

    // PLAN_PARITY Phase 5.5 (deterministic replay): record every API dispatch's
    // answer to the first path, or re-check a run against that recording with
    // the second (both empty = off)
    std::string api_record_path;
    std::string api_replay_path;
    // serve the recorded answers instead of only verifying them (a served call
    // never runs its handler, so its guest-memory side effects do not happen;
    // the default is verify-only for exactly that reason)
    bool api_replay_serve = false;

    // an import whose name has no registered handler (and no rootfs module
    // implementing it): Continue answers a zero return value through the
    // calling convention so the guest's stack stays balanced, and records the
    // name as unsupported; Abort ends the entry point with an `unsupported_api`
    // error (pegasus's modules.functions_always_exist=False + debug_stop)
    enum class UnsupportedApiPolicy { Continue, Abort };
    UnsupportedApiPolicy unsupported_api_policy = UnsupportedApiPolicy::Continue;

    // the kext driver loadbase override (the macho loadDriver's loadbase
    // parameter; 0 means the verbatim default 0xffffff7000000000 — the stock
    // unicorn 2.1.4 cannot fetch there, so the fixture-driven paths pass a
    // low loadbase — see TbSemantics.HighCanonicalAddressFetchProbe)
    std::uint64_t driver_loadbase = 0;
};

class Qiling final : public QlCoreHooks, public QlCoreStructs {
public:
    explicit Qiling(const QilingOptions& options = {});
    ~Qiling() override;

    Qiling(const Qiling&) = delete;
    Qiling& operator=(const Qiling&) = delete;

    // ---- Qiling components (core.py properties) ----

    QlArch& arch() const noexcept { return *arch_; }
    QlMemoryManager& mem() const noexcept { return *mem_; }
    QlOs& os() const noexcept { return *os_; }

    // the typed os view (the syscall handlers downcast to their family)
    template <typename OsType>
    OsType& os() const { return static_cast<OsType&>(*os_); }
    loader::QlLoader& loader() const noexcept { return *loader_; }

    bool baremetal() const noexcept;  // the MCU os is retired to the hw-backup branch

    // the active profile (core.py profile property)
    IniConfig& profile() const noexcept { return *profile_; }

    // the instance logger (core.py log property — setup_logger(stderr))
    spdlog::logger& log() const noexcept { return *log_; }

    // ---- Qiling options (core.py properties) ----

    const std::vector<std::string>& argv() const noexcept { return argv_; }
    const std::string& rootfs() const noexcept { return rootfs_; }
    const std::map<std::string, std::string>& env() const noexcept { return env_; }
    // the mutable env access (the uefi rt.py variable store rides ql.env
    // verbatim; the GetVariable/SetVariable handlers mutate it)
    std::map<std::string, std::string>& env_mut() noexcept { return env_; }
    const std::vector<std::uint8_t>& code() const noexcept { return code_; }
    bool multithread() const noexcept { return multithread_; }
    QL_STOP stop_options() const noexcept { return stop_options_; }

    // the deterministic-replay store paths (empty = off)
    const std::string& api_record_path() const noexcept { return api_record_path_; }
    const std::string& api_replay_path() const noexcept { return api_replay_path_; }
    bool api_replay_serve() const noexcept { return api_replay_serve_; }
    QL_VERBOSE verbose() const noexcept { return verbose_; }
    void set_verbose(QL_VERBOSE v);

    // path/targetname (core.py properties)
    const std::string& path() const noexcept { return argv_.empty() ? placeholder_path_ : argv_[0]; }
    std::string targetname() const;

    QL_STATE emu_state() const noexcept { return state_; }

    // emulation entry overrides (core.py entry_point/exit_point/timeout/count:
    // None until run() replaces them; the C++ port tracks set-ness explicitly)
    bool entry_point_set() const noexcept { return entry_point_set_; }
    bool exit_point_set() const noexcept { return exit_point_set_; }
    std::uint64_t entry_point() const noexcept { return entry_point_; }
    std::uint64_t exit_point() const noexcept { return exit_point_; }
    std::uint64_t timeout() const noexcept { return timeout_; }
    std::uint64_t count() const noexcept { return count_; }

    // the emulation guards (options.max_api_count / unsupported_api_policy)
    std::uint64_t max_api_count() const noexcept { return max_api_count_; }
    QilingOptions::UnsupportedApiPolicy unsupported_api_policy() const noexcept {
        return unsupported_api_policy_;
    }
    void set_entry_point(std::uint64_t addr) { entry_point_ = addr; entry_point_set_ = true; }
    void set_exit_point(std::uint64_t addr) { exit_point_ = addr; exit_point_set_ = true; }

    // ---- patching (core.py patch/do_bin_patch/do_lib_patch) ----

    void patch(std::uint64_t offset, const std::vector<std::uint8_t>& data, std::optional<std::string> target = std::nullopt);
    void do_bin_patch();
    void do_lib_patch();

    // ---- emulation control ----

    // core.py run — the emulation entry (patches, exit trap, os.run)
    void run(std::optional<std::uint64_t> begin = std::nullopt, std::optional<std::uint64_t> end = std::nullopt,
             std::uint64_t timeout = 0, std::uint64_t count = 0);

    friend class os::QlOsBlob;  // blob run() touches the private entry/exit state

    // core.py emu_start — the rethrow-after-uc_emu_start discipline (core.py:727)
    void emu_start(std::uint64_t begin, std::uint64_t end, std::uint64_t timeout = 0, std::uint64_t count = 0);

    // core.py emu_stop / stop
    void emu_stop();
    void stop();

    // core.py debug_stop — raise on unimplemented kernel apis / syscalls
    bool debug_stop() const noexcept { return debug_stop_; }
    void set_debug_stop(bool value) noexcept { debug_stop_ = value; }

    // stack delegation (core.py stack_push/pop/read/write)
    std::uint64_t stack_push(std::uint64_t data);
    std::uint64_t stack_pop();
    std::uint64_t stack_read(std::int64_t offset);
    void stack_write(std::int64_t offset, std::uint64_t data);

    // core.py save/restore — the resumable snapshot state (the Python dict
    // surface; the byte-level serialization for file snapshots is covered by
    // the Snapshot suites)
    QilingSavedState save(bool reg = true, bool mem = true, bool cpu_context = false);
    void restore(const QilingSavedState& saved_state);

    // fs mapper delegation (core.py add_fs_mapper/remove_fs_mapper)
    void add_fs_mapper(std::string_view ql_path, QlFsBinding binding);
    void remove_fs_mapper(std::string_view ql_path);

    // exit trap (core.py _init_stop_guard/write_exit_trap)
    void init_stop_guard();
    void write_exit_trap();

private:
    std::vector<std::string> argv_;
    std::string placeholder_path_ = "";  // core.py: argv = [''] for shellcode
    std::string rootfs_;
    std::map<std::string, std::string> env_;
    std::vector<std::uint8_t> code_;

    bool multithread_ = false;
    QL_STOP stop_options_ = QL_STOP::NONE;
    std::string api_record_path_;
    std::string api_replay_path_;
    bool api_replay_serve_ = false;
    QL_VERBOSE verbose_ = QL_VERBOSE::DEFAULT;
    // the macho driver loadbase override (0 = the verbatim default)
    std::uint64_t driver_loadbase_ = 0;

public:
    std::uint64_t driver_loadbase() const noexcept { return driver_loadbase_; }

    std::unique_ptr<QlArch> arch_;
    std::unique_ptr<QlMemoryManager> mem_;
    std::unique_ptr<QlOs> os_;
    std::unique_ptr<loader::QlLoader> loader_;

    IniConfig profile_default_;
    IniConfig* profile_ = nullptr;
    std::shared_ptr<spdlog::logger> log_;

    QL_STATE state_ = QL_STATE::NOT_SET;
    bool debug_stop_ = false;

    // patching records (core.py _patch_bin/_patch_lib)
    struct BinPatch { std::uint64_t offset; std::vector<std::uint8_t> data; };
    std::vector<BinPatch> patch_bin_;
    struct LibPatch { std::uint64_t offset; std::vector<std::uint8_t> data; std::string filename; };
    std::vector<LibPatch> patch_lib_;

    bool debugger_ = false;
    std::uint64_t timeout_ = 0;
    std::uint64_t count_ = 0;
    std::uint64_t max_api_count_ = 0;
    QilingOptions::UnsupportedApiPolicy unsupported_api_policy_ = QilingOptions::UnsupportedApiPolicy::Continue;
    std::uint64_t entry_point_ = 0;
    bool entry_point_set_ = false;
    std::uint64_t exit_point_ = 0;
    bool exit_point_set_ = false;
    std::uint64_t initial_sp_ = 0;
    bool initial_sp_set_ = false;
    std::uint64_t exit_trap_addr_ = 0;
    std::optional<HookRet> sp_check_handle_;
    std::optional<HookRet> exit_trap_handle_;
};

}  // namespace qiling

#endif  // QILING_CORE_HPP
