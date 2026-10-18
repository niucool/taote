// Ported from qiling/os/macos/const.py — the used subset (the CS_* flags
// and the KERN return codes; the rest lands with its slice).
#ifndef QILING_OS_MACOS_CONST_HPP
#define QILING_OS_MACOS_CONST_HPP

#include <cstdint>

namespace qiling {
namespace os {
namespace macos {

// const.py KERN_SUCCESS
constexpr std::int64_t KERN_SUCCESS = 0;

// const.py CS_GET_TASK_ALLOW / CS_ENFORCEMENT (the verbatim values)
constexpr std::uint32_t CS_GET_TASK_ALLOW = 0x00000004;
constexpr std::uint32_t CS_ENFORCEMENT = 0x00001000;

// const.py MAX_FD_SIZE
constexpr int MAX_FD_SIZE = 0xFF;

// posix/const.py ENOENT (the macos access returns the raw errno value);
// the errno names are windows.h macros on MSVC (the qnx const precedent)
#ifndef ENOENT
constexpr std::int64_t ENOENT = 2;
#endif
#ifndef EINVAL
constexpr std::int64_t EINVAL = 22;
#endif

// const.py F_* (the fcntl64_macos command subset)
constexpr std::uint32_t F_GETFD = 1;
constexpr std::uint32_t F_SETFD = 2;
constexpr std::uint32_t F_GETFL = 3;
constexpr std::uint32_t F_SETFL = 4;
constexpr std::uint32_t F_ADDFILESIGS_RETURN = 97;

// const.py: the attrlist common-attr bits + the vnode types (the used subset)
constexpr std::uint32_t ATTR_CMN_NAME = 0x00000001;
constexpr std::uint32_t ATTR_CMN_DEVID = 0x00000002;
constexpr std::uint32_t ATTR_CMN_OBJTYPE = 0x00000008;
constexpr std::uint32_t ATTR_CMN_OBJID = 0x00000020;

constexpr std::uint32_t VREG = 1;
constexpr std::uint32_t VDIR = 2;
constexpr std::uint32_t VLNK = 5;

// const.py PAGE_SIZE
constexpr std::uint64_t PAGE_SIZE = 0x1000;

// const.py PROC_INFO_CALL_PIDINFO / PROC_PIDREGIONPATHINFO (the proc_info
// path branch)
constexpr std::uint32_t PROC_INFO_CALL_PIDINFO = 0x2;
constexpr std::uint32_t PROC_PIDREGIONPATHINFO = 8;

// x86_const.py IA32_GS_BASE_MSR (the thread_fast_set_cthread_self64 target)
constexpr std::uint32_t IA32_GS_BASE_MSR = 0xC0000101;

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_CONST_HPP
