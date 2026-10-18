// Ported from qiling/os/posix/const_mapping.py (the open-flags tables) and
// os/posix/const.py (the QlPrettyFlag classes). The port runs on the MSVC
// host, so the host-side table is the windows one (const_mapping.py picks the
// host table through ql.host; the #ifdef keeps the same effect).
#ifndef QILING_OS_POSIX_CONST_MAPPING_HPP
#define QILING_OS_POSIX_CONST_MAPPING_HPP

#include "qiling/const.hpp"

namespace qiling {
namespace os {
namespace posix {

// os/posix/const.py FLAG_UNSUPPORTED
inline constexpr int FLAG_UNSUPPORTED = -1;

// os/posix/const.py linux_x86_open_flags (the emulated side; the linux x86
// and x86-64 tables are identical)
struct LinuxX86OpenFlags {
    static constexpr int O_RDONLY = 0x000000;
    static constexpr int O_WRONLY = 0x000001;
    static constexpr int O_RDWR = 0x000002;
    static constexpr int O_NONBLOCK = 0x000800;
    static constexpr int O_APPEND = 0x000400;
    static constexpr int O_ASYNC = 0x002000;
    static constexpr int O_SYNC = 0x101000;
    static constexpr int O_NOFOLLOW = 0x020000;
    static constexpr int O_CREAT = 0x000040;
    static constexpr int O_TRUNC = 0x000200;
    static constexpr int O_EXCL = 0x000080;
    static constexpr int O_NOCTTY = 0x000100;
    static constexpr int O_DIRECTORY = 0x010000;
    static constexpr int O_BINARY = FLAG_UNSUPPORTED;
    static constexpr int O_LARGEFILE = FLAG_UNSUPPORTED;
};

// os/posix/const.py windows_x86_open_flags (the host side)
struct WindowsX86OpenFlags {
    static constexpr int O_RDONLY = 0x000000;
    static constexpr int O_WRONLY = 0x000001;
    static constexpr int O_RDWR = 0x000002;
    static constexpr int O_NONBLOCK = FLAG_UNSUPPORTED;
    static constexpr int O_APPEND = 0x000008;
    static constexpr int O_ASYNC = FLAG_UNSUPPORTED;
    static constexpr int O_SYNC = FLAG_UNSUPPORTED;
    static constexpr int O_NOFOLLOW = FLAG_UNSUPPORTED;
    static constexpr int O_CREAT = 0x000100;
    static constexpr int O_TRUNC = 0x000200;
    static constexpr int O_EXCL = 0x000400;
    static constexpr int O_NOCTTY = FLAG_UNSUPPORTED;
    static constexpr int O_DIRECTORY = FLAG_UNSUPPORTED;
    static constexpr int O_BINARY = 0x008000;
    static constexpr int O_LARGEFILE = FLAG_UNSUPPORTED;
};

// const_mapping.py ql_open_flag_mapping: translate the emulated open flags to
// the host open flags (the unsupported flags drop; the windows host forces
// the O_BINARY bit)
int ql_open_flag_mapping(QL_ARCH archtype, int flags);

}  // namespace posix
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_POSIX_CONST_MAPPING_HPP
