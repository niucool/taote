// The posix syscall dispatch surface (os/posix/posix.py load_syscall +
// os/posix/syscall/unistd.py). The Python layer resolves hooks dynamically via
// `getattr(module, f'ql_syscall_{name}')` and reads the parameter list from the
// hook's signature; the C++ port replaces the dynamic resolution with a static
// registry (the fncc precedent): each syscall registers a name + parameter-type
// list + handler, and `load_syscall` resolves through the registry.
//
// This slice registers the minimal unistd set needed to run the posix smoke
// fixtures (exit/exit_group, read, write, brk, uname, uname-equivalents and
// the standard file-descriptor plumbing); the remaining modules port per the
// PORT_PLAN.md Phase 5 slices.
#ifndef QILING_OS_POSIX_SYSCALL_HPP
#define QILING_OS_POSIX_SYSCALL_HPP

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "qiling/const.hpp"
#include "qiling/os/filestruct.hpp"

namespace qiling {

class Qiling;

namespace os {
namespace posix {

// the syscall handler: receives the resolved parameter values; returns the
// syscall result (or nullopt to leave the return register untouched, mirroring
// the Python `None` return)
using SyscallHandler = std::function<std::optional<std::int64_t>(Qiling& ql, const std::vector<std::uint64_t>& params)>;

struct SyscallEntry {
    std::string name;       // the ql_syscall_{name} basename (without the prefix)
    std::vector<int> params;  // the parameter type list (os/const.hpp primitives)
    SyscallHandler handler;
};

// the syscall registry (both the os-specific and the posix-generic tables; the
// lookup order in posix.py is os-specific first, then posix)
class SyscallRegistry {
public:
    static SyscallRegistry& instance();

    void register_syscall(SyscallEntry entry);
    const SyscallEntry* find(const std::string& name) const;

    std::vector<std::string> names() const;
    void clear();

private:
    SyscallRegistry() = default;
    std::map<std::string, SyscallEntry> entries_;
};

// registers the built-in unistd syscalls (called once from the posix os layer)
void register_builtin_syscalls();

// the fd-table lookup over the posix os layer (the unistd.py os.fd[fd] shape;
// nullptr when out of range or empty) — shared with the delegating dialects
// (the qnx message.py imports the posix syscall helpers verbatim)
std::shared_ptr<QlFsMappedObject> fd_get(Qiling& ql, std::int64_t fd);

}  // namespace posix
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_POSIX_SYSCALL_HPP
