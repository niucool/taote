// Ported from qiling/os/os.py — QlOs, the OS-layer base class (PORT_PLAN.md
// §10 Phase 3). The per-OS derivatives (windows/linux/...) derive from it in
// their own phases; the BLOB derivative (os/blob/blob.py) lands in this phase.
//
// Deviations:
//   - the standard streams surface as FILE*-based QlFile handles (Python probes
//     fileno()/buffer for embedded interpreters; the C++ host embedding story
//     is the console trio) — `set_std*` allows user replacement
//   - QlOsStats summary rendering is field-formatted rather than json.dumps
#ifndef QILING_OS_OS_HPP
#define QILING_OS_OS_HPP

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "qiling/const.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/os/mapper.hpp"
#include "qiling/os/stats.hpp"

namespace qiling {

class Qiling;
class QlFunctionCall;
class QlCC;
class IniConfig;

// os/os.py — TypedArg view of the fcall results (name/type/value)
struct FcallArg {
    std::string name;
    std::optional<int> type;
    std::uint64_t value;
};

class QlOs {
public:
    // os/os.py: resolvers map the placeholder param types (STRING/WSTRING/GUID)
    // to the reader that turns the raw pointer into the resolved value
    using Resolver = std::function<std::string(std::uint64_t)>;

    explicit QlOs(Qiling* ql);
    virtual ~QlOs();

    // ---- identity ----

    virtual QL_OS type() const noexcept = 0;

    // os.py save/restore — derivatives extend; the base carries nothing
    virtual void save() const {}
    virtual void restore() {}

    // os main method; derivatives must implement one of their own
    virtual void run() = 0;

    // releases the os-owned hooks while the uc engine is still open (the
    // C++ destruction order closes the arch's uc handle before the base
    // dtors run; the Python original leans on GC ordering)
    virtual void shutdown() {}

    // os.py stop — multithreaded derivatives install thread_management
    virtual void stop();

    // the path helpers exist for the path-managed os families; derived ctors
    // invoke this after their type is bound (the C++ base ctor cannot dispatch
    // the virtual type() during construction)
    void init_paths_if_managed();

    // the shellcode entry override (blob.py run: explicit entry point)
    void set_entry_point(std::uint64_t addr) noexcept { entry_point_ = addr; }
    // ---- properties ----

    QlFile& stdin_stream() const { return *stdin_; }
    QlFile& stdout_stream() const { return *stdout_; }
    QlFile& stderr_stream() const { return *stderr_; }
    void set_stdin(std::shared_ptr<QlFile> stream);
    void set_stdout(std::shared_ptr<QlFile> stream);
    void set_stderr(std::shared_ptr<QlFile> stream);

    // os.py root — derivatives override with the OS logic; the base is false
    virtual bool root() const noexcept { return false; }
    virtual void set_root(bool enabled) {
        (void)enabled;
        throw QlErrorNotImplemented("Running as root is not implemented for this OS");
    }

    int exit_code() const noexcept { return exit_code_; }
    void set_exit_code(int code) noexcept { exit_code_ = code; }

    // os.py last_error (the windows api surface; posix ignores it)
    std::uint32_t last_error() const noexcept { return last_error_; }
    void set_last_error(std::uint32_t code) noexcept { last_error_ = code; }

    QlOsStats& stats() noexcept { return stats_; }

    // the shellcode entry configuration (os.py ctor: the CODE profile section)
    std::uint64_t load_address() const noexcept { return load_address_; }
    std::uint64_t entry_point() const noexcept { return entry_point_; }
    std::uint64_t code_ram_size() const noexcept { return code_ram_size_; }

    // os.py exit_point — derived from the arch bit width unless overridden
    std::uint64_t exit_point() const noexcept { return exit_point_; }
    void set_exit_point(std::uint64_t addr) noexcept { exit_point_ = addr; }

    QlFunctionCall& fcall() const noexcept { return fcall_nonowning_ != nullptr ? *fcall_nonowning_ : *fcall_; }

    // the non-owning rebind (windows.py: self.fcall = self.fcall_select(cc)):
    // the instance stays owned by the caller; a later set_fcall clears it
    void set_fcall_ptr(QlFunctionCall& fcall) { fcall_nonowning_ = &fcall; }
    void set_fcall(std::unique_ptr<QlFunctionCall> fcall);

    // the profile the os layer reads its sections from (os.py self.profile)
    IniConfig& profile() const noexcept { return *profile_; }

    // fs_mapper / path — present only for the path-managed os types
    QlFsMapper* fs_mapper() const noexcept { return fs_mapper_.get(); }
    const QlOsPath* path() const noexcept { return path_.get(); }

    // core.py add_fs_mapper/remove_fs_mapper (the Qiling delegation targets)
    void map_fs_path(std::string_view ql_path, QlFsBinding binding) {
        if (fs_mapper_ == nullptr) {
            throw QlErrorBase("this os layer does not manage file system paths");
        }
        fs_mapper_->add_mapping(ql_path, std::move(binding));
    }

    void unmap_fs_path(std::string_view ql_path) {
        if (fs_mapper_ == nullptr) {
            throw QlErrorBase("this os layer does not manage file system paths");
        }
        fs_mapper_->remove_mapping(ql_path);
    }

    QlFsMappedObject& console_out() const noexcept { return *console_out_; }

    // ---- user-defined api surface (os.py set_api / user_defined_api) ----

    void set_api(std::uint64_t target, void* handler, QL_INTERCEPT intercept = QL_INTERCEPT::CALL);
    void set_api(std::string_view target, void* handler, QL_INTERCEPT intercept = QL_INTERCEPT::CALL);

    // resolve_fcall_params — name->type mapping resolved through the fcall
    // layer and the resolvers table; returns the resolved values in order
    std::vector<std::uint64_t> resolve_fcall_params(const std::vector<std::pair<std::string, int>>& params) const;

    // process_fcall_params — the display strings for the typed args
    std::vector<std::string> process_fcall_params(const std::vector<FcallArg>& targs) const;

    // os.py call — resolve, invoke through fcall, print, log to stats, set pc
    std::optional<std::uint64_t> call(std::uint64_t pc, const std::string& name,
                                      const std::vector<std::pair<std::string, int>>& proto,
                                      const std::vector<std::uint64_t>& args_raw);

    // os.py emu_error — dump the cpu context, the pc neighborhood and the map
    void emu_error() const;

    Qiling& ql() const noexcept { return *ql_; }

protected:
    Qiling* ql_;
    QL_OS type_ = QL_OS::BLOB;

    std::shared_ptr<QlFile> stdin_;
    std::shared_ptr<QlFile> stdout_;
    std::shared_ptr<QlFile> stderr_;
    std::shared_ptr<QlFsMappedObject> console_out_;

    QlOsStats stats_;
    std::unique_ptr<QlFunctionCall> fcall_;
    QlFunctionCall* fcall_nonowning_ = nullptr;

    bool child_processes_ = false;
    void* thread_management_ = nullptr;  // QlThread* (thread management slice)
    IniConfig* profile_ = nullptr;
    int exit_code_ = 0;
    std::uint32_t last_error_ = 0;

    std::uint64_t exit_point_ = 0;
    std::uint64_t load_address_ = 0;
    std::uint64_t entry_point_ = 0;
    std::uint64_t code_ram_size_ = 0;

    std::map<std::string, Resolver> resolvers_;
    std::map<QL_INTERCEPT, std::map<std::string, void*>> user_defined_api_;
    std::unique_ptr<QlOsPath> path_;
    std::unique_ptr<QlFsMapper> fs_mapper_;
};
}  // namespace qiling

#endif  // QILING_OS_OS_HPP
