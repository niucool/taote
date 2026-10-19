// Ported from qiling/os/windows/dlls/__init__.py + the __init__ star-imports
// (the registration driver). The Python package star-imports each dll module
// so the @winsdkapi decorators run at import time; the C++ port aggregates the
// family registration functions here (each family's static-init also runs on
// process start; register_dlls() re-seeds the surface after a clear, e.g. for
// the test isolation). New families append their register_*() call here.
#ifndef QILING_OS_WINDOWS_DLLS_DLLS_HPP
#define QILING_OS_WINDOWS_DLLS_DLLS_HPP

namespace qiling {
namespace os {

// re-seeds every dll family registration (the __init__.py star-import set)
void register_dlls();

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_DLLS_DLLS_HPP
