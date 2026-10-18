// Ported from qiling/os/linux/linux.py QlOsLinux — the Linux os family. The
// syscall dispatch hooks (the `syscall` insn for x86-64, int 0x80 for x86)
// live in the QlOsPosix base (the port absorbed the per-arch hook install
// into the shared run() path). The linux-specific extras land here: the
// /proc/self/* pseudo files (procfs.py), the futex management and the guest
// threads defer with their slices.
#include "qiling/os/linux/linux.hpp"

#include "qiling/core.hpp"
#include "qiling/loader/loader.hpp"
#include "qiling/os/linux/procfs.hpp"

namespace qiling {
namespace os {
namespace linux {

// procfs.py setup_procfs: the five self-file factories (a missing entry only
// means the user has not mapped it — the add respects the precedence)
void QlOsLinux::setup_procfs() {
    auto* fs = fs_mapper();
    if (fs == nullptr) {
        return;
    }

    const auto add = [fs](std::string_view vpath, auto producer) {
        if (!fs->has_mapping(vpath)) {
            fs->add_mapping(vpath, std::function<std::shared_ptr<QlFsMappedObject>()>(producer));
        }
    };

    add("/proc/self/auxv", [this]() -> std::shared_ptr<QlFsMappedObject> {
        return std::make_shared<FsMappedStream>("/proc/self/auxv", QlProcFS::self_auxv(*this));
    });
    add("/proc/self/cmdline", [this]() -> std::shared_ptr<QlFsMappedObject> {
        return std::make_shared<FsMappedStream>("/proc/self/cmdline", QlProcFS::self_cmdline(*this));
    });
    add("/proc/self/environ", [this]() -> std::shared_ptr<QlFsMappedObject> {
        return std::make_shared<FsMappedStream>("/proc/self/environ", QlProcFS::self_environ(*this));
    });
    add("/proc/self/exe", [this]() -> std::shared_ptr<QlFsMappedObject> {
        return std::make_shared<FsMappedStream>("/proc/self/exe", QlProcFS::self_exe(*this));
    });
    add("/proc/self/maps", [this]() -> std::shared_ptr<QlFsMappedObject> {
        return std::make_shared<FsMappedStream>("/proc/self/maps", QlProcFS::self_map(ql().mem()));
    });
}

void QlOsLinux::run() {
    // linux.py run: do not set up the procfs for the drivers and the shellcode
    if (ql_->code().empty() && !ql_->loader().is_driver) {
        setup_procfs();
    }

    QlOsPosix::run();
}

}  // namespace linux
}  // namespace os
}  // namespace qiling
