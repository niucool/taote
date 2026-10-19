// Ported from qiling/os/windows/dlls/ucrtbased.py — the upstream module is a
// star-import of msvcrt ("This dll is almost functionally identical to
// msvcrt, just use hooks from there"), which re-uses the already-registered
// msvcrt hooks; the C++ port needs no extra registration (the msvcrt family
// surface covers ucrtbased verbatim).
#ifndef QILING_OS_WINDOWS_DLLS_UCRTBASED_CPP
#define QILING_OS_WINDOWS_DLLS_UCRTBASED_CPP

namespace qiling {
namespace os {
namespace win {

// ucrtbased.py: `from qiling.os.windows.dlls.msvcrt import *` — the hook
// objects are the msvcrt ones; no additional registration entry
inline void register_ucrtbased_family() {}

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_DLLS_UCRTBASED_CPP
