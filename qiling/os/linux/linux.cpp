// Ported from qiling/os/linux/linux.py QlOsLinux - the Linux os family. The
// per-arch syscall-hook installation lives in the QlOsPosix base (the port
// absorbed it into the shared run() path). The linux-specific extras land
// here: the /proc/self pseudo files (procfs.py), the futex management
// (futex.py), and the multithreaded run branch (thread.py - the OQ 10
// driver-loop scheduler, see the STATUS.md D18 decision).
#include "qiling/os/linux/linux.hpp"

#include "qiling/core.hpp"
#include "qiling/loader/loader.hpp"
#include "qiling/os/linux/futex.hpp"
#include "qiling/os/linux/procfs.hpp"
#include "qiling/os/linux/thread.hpp"

namespace qiling {
namespace os {
namespace linux {

void QlOsLinux::init_futexm() {
    // linux.py load: self.futexm = futex.QlLinuxFutexManagement()
    set_futexm(std::make_unique<QlLinuxFutexManagement>());
}

void QlOsLinux::init_multithread() {
    // linux.py run: thread_management = QlLinuxThreadManagement(self.ql);
    // idempotent so the pre-run thread injection (the clone slice's surface,
    // the test harnesses) survives the run() handoff
    if (thread_management() == nullptr) {
        set_thread_management(std::make_unique<QlLinuxThreadManagement>(ql()));
    }
}

void QlOsLinux::run_multithread() {
    // linux.py run: thread_management.run() (the loader pass + the main
    // spawn + the driver loop); the syscall entry hooks install here - the
    // driver-loop slices dispatch through the same registry as the
    // single-shot path
    init_multithread();
    install_syscall_hooks();
    thread_management()->run();
}

// procfs.py setup_procfs: the five self-file factories (a missing entry only
// means the user has not mapped it - the add respects the precedence)
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

    if (ql_->multithread()) {
        // linux.py run: start multithreading (the syscall hooks install first
        // - the driver-loop slices dispatch through the same registry)
        install_syscall_hooks();
        init_multithread();
        thread_management()->run();
        return;
    }

    QlOsPosix::run();
}

}  // namespace linux
}  // namespace os
}  // namespace qiling
