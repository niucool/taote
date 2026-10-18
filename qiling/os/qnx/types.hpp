// Ported from qiling/os/qnx/types.py — the QNX name/flag tables (the openqnx
// public headers). The maps mirror the python dicts verbatim.
#ifndef QILING_OS_QNX_TYPES_HPP
#define QILING_OS_QNX_TYPES_HPP

#include <cstdint>
#include <string_view>
#include <utility>

namespace qiling {
namespace os {
namespace qnx {

// types.py clock_types (lib/c/public/time.h)
inline const std::pair<unsigned, std::string_view> clock_types[] = {
    {0, "CLOCK_REALTIME"},          {1, "CLOCK_SOFTTIME"},
    {2, "CLOCK_MONOTONIC"},         {3, "CLOCK_PROCESS_CPUTIME_ID"},
    {4, "CLOCK_THREAD_CPUTIME_ID"},
};

// types.py lseek_whence (lib/c/public/unistd.h)
inline const std::pair<unsigned, std::string_view> lseek_whence[] = {
    {0, "SEEK_SET"},  // relative to start of file
    {1, "SEEK_CUR"},  // relative to current position
    {2, "SEEK_END"},  // relative to end of file
};

// types.py sysconf_conditions (lib/c/public/sys/conf.h)
inline constexpr std::int32_t SYSCONF_CONDITION_STR = 1 << 20;  // _CONF_STR
inline constexpr std::int32_t SYSCONF_CONDITION_NUM = 2 << 20;  // _CONF_NUM

// types.py sysconf_names (lib/c/public/conf.h)
inline const std::pair<int, std::string_view> sysconf_names[] = {
    {1, "_CS_PATH"},           // default path to find system utilities
    {2, "_CS_HOSTNAME"},       // Name of this node within the communications network
    {3, "_CS_RELEASE"},        // Current release level of this implementation
    {4, "_CS_VERSION"},        // Current release level of this implementation
    {5, "_CS_MACHINE"},        // Name of the hardware type on which this runs
    {6, "_CS_ARCHITECTURE"},   // Name of the instructions set architechure
    {7, "_CS_HW_SERIAL"},      // A serial number assiciated with the hardware
    {8, "_CS_HW_PROVIDER"},    // The name of the hardware manufacturers
    {9, "_CS_SRPC_DOMAIN"},    // the secure RPC domain
    {11, "_CS_SYSNAME"},       // Name of this implementation of the operating system
    {200, "_CS_LIBPATH"},      // default path for runtime to find standard shared objects
    {201, "_CS_DOMAIN"},       // Domain of this node within the communications network
    {202, "_CS_RESOLVE"},      // In memory /etc/resolve.conf
    {203, "_CS_TIMEZONE"},     // timezone string (TZ style)
    {204, "_CS_LOCALE"},       // locale string
};

// types.py sysconf_consts (lib/c/public/conf.h)
inline const std::pair<int, std::string_view> sysconf_consts[] = {
    {1, "_SC_ARG_MAX"},        {2, "_SC_CHILD_MAX"},     {3, "_SC_CLK_TCK"},
    {4, "_SC_NGROUPS_MAX"},    {5, "_SC_OPEN_MAX"},      {6, "_SC_JOB_CONTROL"},
    {7, "_SC_SAVED_IDS"},      {8, "_SC_VERSION"},       {9, "_SC_PASS_MAX"},
    {10, "_SC_LOGNAME_MAX"},   {11, "_SC_PAGESIZE"},     {12, "_SC_XOPEN_VERSION"},
    {13, "_SC_STREAM_MAX"},    // TODO: add 15 - 173 (the upstream note, verbatim)
};

// types.py sysconf_subtypes (services/system/public/sys/sysmsg.h)
inline const std::pair<unsigned, std::string_view> sysconf_subtypes[] = {
    {0, "_SYS_SUB_GET"},
    {1, "_SYS_SUB_SET"},
};

// types.py file_types (lib/c/public/sys/ftype.h)
inline const std::pair<unsigned, std::string_view> file_types[] = {
    {0, "_FTYPE_ANY"},   {1, "_FTYPE_FILE"},     {2, "_FTYPE_LINK"},   {3, "_FTYPE_SYMLINK"},
    {4, "_FTYPE_PIPE"},  {5, "_FTYPE_SHMEM"},    {6, "_FTYPE_MQUEUE"}, {7, "_FTYPE_SOCKET"},
    {8, "_FTYPE_SEM"},   {9, "_FTYPE_PHOTON"},   {10, "_FTYPE_DUMPER"}, {11, "_FTYPE_MOUNT"},
    {12, "_FTYPE_NAME"}, {13, "_FTYPE_TYMEM"},
};

// types.py io_connect_subtypes (lib/c/public/sys/iomsg.h)
inline const std::pair<unsigned, std::string_view> io_connect_subtypes[] = {
    {0, "_IO_CONNECT_COMBINE"},        // more than two iov_t
    {1, "_IO_CONNECT_COMBINE_CLOSE"},  // _IO_CONNECT_COMBINE with close-on-exec
    {2, "_IO_CONNECT_OPEN"},
    {3, "_IO_CONNECT_UNLINK"},
    {4, "_IO_CONNECT_RENAME"},
    {5, "_IO_CONNECT_MKNOD"},
    {6, "_IO_CONNECT_READLINK"},
    {7, "_IO_CONNECT_LINK"},
    {8, "_IO_CONNECT_RSVD_UNBLOCK"},
    {9, "_IO_CONNECT_MOUNT"},
};

// types.py io_connect_eflag (lib/c/public/sys/iomsg.h)
inline constexpr std::uint32_t IO_CONNECT_EFLAG_DIR = 0x01;    // path is a directory
inline constexpr std::uint32_t IO_CONNECT_EFLAG_DOT = 0x02;    // last component of path is . or ..
inline constexpr std::uint32_t IO_CONNECT_EFLAG_DOTDOT = 0x04; // last component is ..

// types.py file_stats (lib/c/public/sys/stat.h) — the S_IF* names collide
// with the sys/stat.h macros windows.h pulls in; define only when free
#ifndef S_IFIFO
inline constexpr std::uint32_t S_IFIFO = 0x1000; // FIFO
#endif
#ifndef S_IFCHR
inline constexpr std::uint32_t S_IFCHR = 0x2000; // Character special
#endif
#ifndef S_IFDIR
inline constexpr std::uint32_t S_IFDIR = 0x4000; // Directory
#endif
#ifndef S_IFNAM
inline constexpr std::uint32_t S_IFNAM = 0x5000; // Named file
#endif
#ifndef S_IFBLK
inline constexpr std::uint32_t S_IFBLK = 0x6000; // Block special
#endif
#ifndef S_IFREG
inline constexpr std::uint32_t S_IFREG = 0x8000; // Regular
#endif
#ifndef S_IFLNK
inline constexpr std::uint32_t S_IFLNK = 0xa000; // Symlink
#endif
#ifndef S_IFSOCK
inline constexpr std::uint32_t S_IFSOCK = 0xc000; // Socket
#endif

// types.py file_access (lib/c/public/sys/stat.h)
inline const std::pair<unsigned, std::string_view> file_access[] = {
    {000001, "_S_INSEM"},      // semaphore
    {000002, "_S_INSHD"},      // shared data
    {000003, "_S_INMQ"},       // message queue
    {000004, "_S_INTMO"},      // typed memory
    {040000, "_S_QNX_SPECIAL"},
};

// types.py file_sharing_modes (lib/c/public/share.h)
inline const std::pair<unsigned, std::string_view> file_sharing_modes[] = {
    {0x00, "SH_COMPAT"}, // compatibility
    {0x10, "SH_DENYRW"}, // deny read/write
    {0x20, "SH_DENYWR"}, // deny write
    {0x30, "SH_DENYRD"}, // deny read
    {0x40, "SH_DENYNO"}, // no deny
};

// types.py mem_ctrl_subtypes (services/system/public/sys/memmsg.h)
inline const std::pair<unsigned, std::string_view> mem_ctrl_subtypes[] = {
    {0, "MEM_CTRL_UNMAP"},   {1, "MEM_CTRL_PROTECT"}, {2, "MEM_CTRL_SYNC"},
    {3, "MEM_CTRL_LOCKALL"}, {4, "MEM_CTRL_UNLOCKALL"}, {5, "MEM_CTRL_LOCK"},
    {6, "MEM_CTRL_UNLOCK"},  {7, "MEM_CTRL_ADVISE"},
};

// types.py mmap_flags (lib/c/public/sys/mman.h)
inline constexpr std::uint32_t MMAP_MAP_SHARED = 0x00000001;
inline constexpr std::uint32_t MMAP_MAP_PRIVATE = 0x00000002;
inline constexpr std::uint32_t MMAP_MAP_FIXED = 0x00000010;
inline constexpr std::uint32_t MMAP_MAP_ELF = 0x00000020;
inline constexpr std::uint32_t MMAP_MAP_NOSYNCFILE = 0x00000040;
inline constexpr std::uint32_t MMAP_MAP_LAZY = 0x00000080;
inline constexpr std::uint32_t MMAP_MAP_STACK = 0x00001000;
inline constexpr std::uint32_t MMAP_MAP_BELOW = 0x00002000;
inline constexpr std::uint32_t MMAP_MAP_NOINIT = 0x00004000;
inline constexpr std::uint32_t MMAP_MAP_PHYS = 0x00010000;
inline constexpr std::uint32_t MMAP_MAP_NOX64K = 0x00020000;
inline constexpr std::uint32_t MMAP_MAP_BELOW16M = 0x00040000;
inline constexpr std::uint32_t MMAP_MAP_ANON = 0x00080000;
inline constexpr std::uint32_t MMAP_MAP_ANONYMOUS = 0x00080000;
inline constexpr std::uint32_t MMAP_MAP_SYSRAM = 0x01000000;

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_TYPES_HPP
