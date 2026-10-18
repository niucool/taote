// Ported from qiling/os/qnx/structs.py — the QNX memory-layout structures
// (the openqnx public headers). All the fields are 32-bit on the ARM target
// (the upstream's POINTER32 cells are c_uint32).
#ifndef QILING_OS_QNX_STRUCTS_HPP
#define QILING_OS_QNX_STRUCTS_HPP

#include <cstdint>

#include "qiling/os/qnx/const.hpp"

namespace qiling {
namespace os {
namespace qnx {

// structs.py _sync (openqnx lib/c/public/sys/target_nto.h)
struct Sync {
    std::int32_t count;   // 0  (0x00) int __count;
    std::uint32_t owner;  // 4  (0x04) unsigned __owner;
};
static_assert(sizeof(Sync) == 8, "the _sync layout");

// structs.py _sync_attr (openqnx lib/c/public/sys/target_nto.h)
struct SyncAttr {
    std::int32_t protocol;    // 0  (0x00) int __protocol;
    std::int32_t flags;       // 4  (0x04) int __flags;
    std::int32_t prioceiling; // 8  (0x08) int __prioceiling;
    std::int32_t clockid;     // 12 (0x0c) int __clockid;
    std::int32_t reserved1;   // 16 (0x10) int __reserved[0];
    std::int32_t reserved2;   // 20 (0x14)
    std::int32_t reserved3;   // 24 (0x18)
    std::int32_t reserved4;   // 28 (0x1c)
};
static_assert(sizeof(SyncAttr) == 32, "the _sync_attr layout");

// structs.py _thread_local_storage (openqnx lib/c/public/sys/target_nto.h)
// — the thread local storage sitting at the top of each thread's stack
struct ThreadLocalStorage {
    std::uint32_t exitfunc;    // 0  (0x00) void (*__exitfunc)(void *);
    std::uint32_t arg;         // 4  (0x04) void *__arg;
    std::uint32_t errptr;      // 8  (0x08) int *__errptr;
    std::int32_t errval;       // 12 (0x0c) int __errval;
    std::uint32_t flags;       // 16 (0x10) unsigned __flags;
    std::int32_t pid;          // 20 (0x14) int __pid;
    std::int32_t tid;          // 24 (0x18) int __tid;
    std::uint32_t owner;       // 28 (0x1c) unsigned __owner;
    std::uint32_t stackaddr;   // 32 (0x20) void *__stackaddr;
    std::uint32_t reserved1;   // 36 (0x24) unsigned __reserved1;
    std::uint32_t numkeys;     // 40 (0x28) unsigned __numkeys;
    std::uint32_t keydata;     // 44 (0x2c) void **__keydata;
    std::uint32_t cleanup;     // 48 (0x30) void *__cleanup;
    std::uint32_t fpuemu_data; // 52 (0x34) void *__fpuemu_data;
    std::uint32_t reserved2;   // 56 (0x38) void *__reserved2[0];
    std::uint32_t reserved3;   // 60 (0x3c) void *__reserved2[1];
};
static_assert(sizeof(ThreadLocalStorage) == 64, "the _thread_local_storage layout");

// kermacros.h SYNC_OWNER_BITS(pid, tid) — the owner cell for the sync structs
// (the WAITING top bit cleared)
inline std::uint32_t sync_owner_bits(std::uint32_t pid, std::uint32_t tid) {
    return ((pid << 16) | tid) & ~NTO_SYNC_WAITING;
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_STRUCTS_HPP
