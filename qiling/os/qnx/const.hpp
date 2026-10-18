// Ported from qiling/os/qnx/const.py — the QNX kernel constants (the
// openqnx public headers).
#ifndef QILING_OS_QNX_CONST_HPP
#define QILING_OS_QNX_CONST_HPP

namespace qiling {
namespace os {
namespace qnx {

// Source: openqnx lib/c/public/pthread.h

// Mutexes
inline constexpr std::uint32_t NTO_SYNC_NONRECURSIVE = 0x80000000u;
inline constexpr std::uint32_t NTO_SYNC_NOERRORCHECK = 0x40000000u;
inline constexpr std::uint32_t NTO_SYNC_PRIOCEILING = 0x20000000u;
inline constexpr std::uint32_t NTO_SYNC_PRIONONE = 0x10000000u;
inline constexpr std::uint32_t NTO_SYNC_COUNTMASK = 0x00ffffffu;

inline constexpr std::uint32_t NTO_SYNC_MUTEX_FREE = 0x00000000u;  // 0 mutexes, and old cond, sem, spin
inline constexpr std::uint32_t NTO_SYNC_WAITING = 0x80000000u;     // Top bit used with mutexes
inline constexpr std::uint32_t NTO_SYNC_OWNER_MASK = 0x7fffffffu;  // Owner used with mutexes
inline constexpr std::uint32_t NTO_SYNC_INITIALIZER = 0xffffffffu;  // -1 count is 0=mutexes, 0(old),-5(new)=cond
inline constexpr std::uint32_t NTO_SYNC_DESTROYED = 0xfffffffeu;    // -2 mutexes, cond, sem, spin
inline constexpr std::uint32_t NTO_SYNC_NAMED_SEM = 0xfffffffdu;    // -3 sem (count is handle)
inline constexpr std::uint32_t NTO_SYNC_SEM = 0xfffffffcu;          // -4 sem (count is value)
inline constexpr std::uint32_t NTO_SYNC_COND = 0xfffffffbu;         // -5 cond (count is clockid)
inline constexpr std::uint32_t NTO_SYNC_SPIN = 0xfffffffau;     // -6 spin (count is internal)
inline constexpr std::uint32_t NTO_SYNC_DEAD = 0xffffff00u;         // -256 mutex (when a process dies with a mutex locked)

// PThread synchronization prototypes
inline constexpr int PTHREAD_PROCESSSHARED_MASK = 1;
inline constexpr int PTHREAD_PROCESS_PRIVATE = 0;
inline constexpr int PTHREAD_PROCESS_SHARED = 1;

inline constexpr int PTHREAD_RECURSIVE_MASK = 2;
inline constexpr int PTHREAD_RECURSIVE_DISABLE = 0;
inline constexpr int PTHREAD_RECURSIVE_ENABLE = 2;

inline constexpr int PTHREAD_ERRORCHECK_MASK = 4;
inline constexpr int PTHREAD_ERRORCHECK_ENABLE = 0;
inline constexpr int PTHREAD_ERRORCHECK_DISABLE = 4;

// POSIX error codes (EINVAL collides with the errno.h macro windows.h
// pulls in; define it only when not already a macro)
inline constexpr int EOK = 0;
#ifndef EINVAL
inline constexpr int EINVAL = 22;
#endif

// Source: openqnx services/system/public/sys/neutrino.h
inline constexpr std::uint32_t NTO_SIDE_CHANNEL = 0x40000000u;   // first side channel (2nd bit from the top)
inline constexpr std::uint32_t NTO_GLOBAL_CHANNEL = 0x40000000u; // global channel (2nd bit from the top)

inline constexpr std::uint32_t SYSMGR_PID = 1;                   // System Manager Process ID
inline constexpr std::uint32_t SYSMGR_CHID = 1;                  // System Manager Channel ID
inline constexpr std::uint32_t SYSMGR_COID = NTO_SIDE_CHANNEL;   // System Manager Connection ID

// Source: openqnx lib/c/public/sys/iomsg.h
inline constexpr std::uint32_t IO_FLAG_MASK = 0x03u;

// Source: openqnx lib/c/public/sys/mman.h
inline constexpr std::uint32_t PAGESIZE = 0x1000u;

// Source: openqnx lib/c/public/sys/netmgr.h
inline constexpr int ND_LOCAL_NODE = 0;  // Node Descriptor for the Local Node

// Source: openqnx lib/c/public/sys/stat.h (S_IFMT collides with the
// sys/stat.h macro windows.h pulls in; define it only when not already a
// macro)
#ifndef S_IFMT
inline constexpr std::uint32_t S_IFMT = 0xf000u;
#endif

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_CONST_HPP
