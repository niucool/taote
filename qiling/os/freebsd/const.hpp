// Ported from qiling/os/freebsd/const.py — the freebsd sysctl identifiers
// (from FreeBSD /sys/sys/sysctl.h). Header-only: pure constants
// (mirror-layout rule 1).
#ifndef QILING_OS_FREEBSD_CONST_HPP
#define QILING_OS_FREEBSD_CONST_HPP

namespace qiling {
namespace os {
namespace freebsd {

// See __FreeBSD_version in /sys/sys/params.h — this value comes from
// FreeBSD stable/12 as of 2021.3.12
inline constexpr int FREEBSD_OSRELDATE = 1202505;

//
// Top-level identifiers
//
// Note(lazymio): CTL_SYSCTL doesn't exist in linux kernel!

inline constexpr int CTL_SYSCTL   = 0;  // "magic" numbers
inline constexpr int CTL_KERN     = 1;  // "high kernel": proc, limits
inline constexpr int CTL_VM       = 2;  // virtual memory
inline constexpr int CTL_VFS      = 3;  // filesystem, mount type is next
inline constexpr int CTL_NET      = 4;  // network, see socket.h
inline constexpr int CTL_DEBUG    = 5;  // debugging parameters
inline constexpr int CTL_HW       = 6;  // generic cpu/io
inline constexpr int CTL_MACHDEP  = 7;  // machine dependent
inline constexpr int CTL_USER     = 8;  // user-level
inline constexpr int CTL_P1003_1B = 9;  // POSIX 1003.1B

//
// CTL_SYSCTL identifiers
//

inline constexpr int CTL_SYSCTL_DEBUG      = 0;  // printf all nodes
inline constexpr int CTL_SYSCTL_NAME       = 1;  // string name of OID
inline constexpr int CTL_SYSCTL_NEXT       = 2;  // next OID, honoring CTLFLAG_SKIP
inline constexpr int CTL_SYSCTL_NAME2OID   = 3;  // int array of name
inline constexpr int CTL_SYSCTL_OIDFMT     = 4;  // OID's kind and format
inline constexpr int CTL_SYSCTL_OIDDESCR   = 5;  // OID's description
inline constexpr int CTL_SYSCTL_OIDLABEL   = 6;  // aggregation label
inline constexpr int CTL_SYSCTL_NEXTNOSKIP = 7;  // next OID, ignoring CTLFLAG_SKIP

//
// CTL_KERN identifiers (the used subset: the OSRELDATE path; the full list
// ported verbatim for the name-based dispatches)
//

inline constexpr int KERN_OSTYPE          = 1;
inline constexpr int KERN_OSRELEASE       = 2;
inline constexpr int KERN_OSREV           = 3;
inline constexpr int KERN_VERSION         = 4;
inline constexpr int KERN_MAXVNODES       = 5;
inline constexpr int KERN_MAXPROC         = 6;
inline constexpr int KERN_MAXFILES        = 7;
inline constexpr int KERN_ARGMAX          = 8;
inline constexpr int KERN_SECURELVL       = 9;
inline constexpr int KERN_HOSTNAME        = 10;
inline constexpr int KERN_HOSTID          = 11;
inline constexpr int KERN_CLOCKRATE       = 12;
inline constexpr int KERN_VNODE           = 13;
inline constexpr int KERN_PROC            = 14;
inline constexpr int KERN_FILE            = 15;
inline constexpr int KERN_PROF            = 16;
inline constexpr int KERN_POSIX1          = 17;
inline constexpr int KERN_NGROUPS         = 18;
inline constexpr int KERN_JOB_CONTROL     = 19;
inline constexpr int KERN_SAVED_IDS       = 20;
inline constexpr int KERN_BOOTTIME        = 21;
inline constexpr int KERN_NISDOMAINNAME   = 22;
inline constexpr int KERN_UPDATEINTERVAL  = 23;
inline constexpr int KERN_OSRELDATE       = 24;
inline constexpr int KERN_NTP_PLL         = 25;
inline constexpr int KERN_BOOTFILE        = 26;
inline constexpr int KERN_MAXFILESPERPROC = 27;
inline constexpr int KERN_MAXPROCPERUID   = 28;
inline constexpr int KERN_DUMPDEV         = 29;
inline constexpr int KERN_IPC             = 30;
inline constexpr int KERN_DUMMY           = 31;
inline constexpr int KERN_PS_STRINGS      = 32;
inline constexpr int KERN_USRSTACK        = 33;
inline constexpr int KERN_LOGSIGEXIT      = 34;
inline constexpr int KERN_IOV_MAX         = 35;
inline constexpr int KERN_HOSTUUID        = 36;
inline constexpr int KERN_ARND            = 37;
inline constexpr int KERN_MAXPHYS         = 38;

//
// CTL_HW identifiers (the used subset: the PAGESIZE NAME2OID path)
//

inline constexpr int HW_MACHINE      = 1;
inline constexpr int HW_MODEL        = 2;
inline constexpr int HW_NCPU         = 3;
inline constexpr int HW_BYTEORDER    = 4;
inline constexpr int HW_PHYSMEM      = 5;
inline constexpr int HW_USERMEM      = 6;
inline constexpr int HW_PAGESIZE     = 7;
inline constexpr int HW_DISKNAMES    = 8;
inline constexpr int HW_DISKSTATS    = 9;
inline constexpr int HW_FLOATINGPT   = 10;
inline constexpr int HW_MACHINE_ARCH = 11;
inline constexpr int HW_REALMEM      = 12;

}  // namespace freebsd
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_FREEBSD_CONST_HPP
