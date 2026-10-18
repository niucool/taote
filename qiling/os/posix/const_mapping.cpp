// Ported from qiling/os/posix/const_mapping.py ql_open_flag_mapping. The
// flag vocabulary is shared across the per-os tables (the names stay aligned)
// so the translation walks the linux table and re-maps onto the host table —
// the same logic as the Python's per-Flag loop, unrolled over the paired
// table rows.
#include "qiling/os/posix/const_mapping.hpp"

namespace qiling {
namespace os {
namespace posix {

namespace {

// the linux_x86_open_flags -> windows_x86_open_flags pairs (the rows are in
// the const.py declaration order; FLAG_UNSUPPORTED drops on either side)
constexpr int kLinuxFlagCount = 15;
constexpr int kLinuxFlags[kLinuxFlagCount] = {
    LinuxX86OpenFlags::O_RDONLY, LinuxX86OpenFlags::O_WRONLY, LinuxX86OpenFlags::O_RDWR,
    LinuxX86OpenFlags::O_NONBLOCK, LinuxX86OpenFlags::O_APPEND, LinuxX86OpenFlags::O_ASYNC,
    LinuxX86OpenFlags::O_SYNC, LinuxX86OpenFlags::O_NOFOLLOW, LinuxX86OpenFlags::O_CREAT,
    LinuxX86OpenFlags::O_TRUNC, LinuxX86OpenFlags::O_EXCL, LinuxX86OpenFlags::O_NOCTTY,
    LinuxX86OpenFlags::O_DIRECTORY, LinuxX86OpenFlags::O_BINARY, LinuxX86OpenFlags::O_LARGEFILE,
};
constexpr int kWindowsFlags[kLinuxFlagCount] = {
    WindowsX86OpenFlags::O_RDONLY, WindowsX86OpenFlags::O_WRONLY, WindowsX86OpenFlags::O_RDWR,
    WindowsX86OpenFlags::O_NONBLOCK, WindowsX86OpenFlags::O_APPEND, WindowsX86OpenFlags::O_ASYNC,
    WindowsX86OpenFlags::O_SYNC, WindowsX86OpenFlags::O_NOFOLLOW, WindowsX86OpenFlags::O_CREAT,
    WindowsX86OpenFlags::O_TRUNC, WindowsX86OpenFlags::O_EXCL, WindowsX86OpenFlags::O_NOCTTY,
    WindowsX86OpenFlags::O_DIRECTORY, WindowsX86OpenFlags::O_BINARY, WindowsX86OpenFlags::O_LARGEFILE,
};

}  // namespace

int ql_open_flag_mapping(QL_ARCH archtype, int flags) {
    // the port runs on the MSVC host (the host table = the windows one); the
    // non-x86 emulated tables land with their arch slices — the x86 tables
    // match linux_x86_open_flags
    (void)archtype;

    int ret = 0;

    for (int i = 0; i < kLinuxFlagCount; ++i) {
        const auto ef = kLinuxFlags[i];
        if (ef == FLAG_UNSUPPORTED) {
            continue;
        }
        if ((flags & ef) != 0) {
            const auto hf = kWindowsFlags[i];
            if (hf != FLAG_UNSUPPORTED) {
                ret |= hf;
            }
        }
    }

    // NOTE: not sure why this one is needed (const_mapping.py, verbatim)
    ret |= WindowsX86OpenFlags::O_BINARY;

    return ret;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
