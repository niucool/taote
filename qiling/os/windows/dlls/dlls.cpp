// Ported from qiling/os/windows/dlls/__init__.py — the dll module loader.
// The Python package star-imports each dll module so the @winsdkapi
// decorators run at import time; the C++ port achieves the same by
// aggregating the family registration functions (each family TU also
// self-registers at static-init). New families append their register_*()
// call here.
#include "qiling/os/windows/dlls/dlls.hpp"

#include "qiling/os/windows/dlls/kernel32/fileapi.cpp"
#include "qiling/os/windows/dlls/kernel32/handleapi.cpp"
#include "qiling/os/windows/dlls/kernel32/processthreadsapi.cpp"
#include "qiling/os/windows/dlls/kernel32/synchapi.cpp"
#include "qiling/os/windows/dlls/kernel32/heapapi.cpp"
#include "qiling/os/windows/dlls/kernel32/memoryapi.cpp"
#include "qiling/os/windows/dlls/kernel32/libloaderapi.cpp"
#include "qiling/os/windows/dlls/kernel32/sysinfoapi.cpp"
#include "qiling/os/windows/dlls/kernel32/processenv.cpp"
#include "qiling/os/windows/dlls/kernel32/interlockedapi.cpp"
#include "qiling/os/windows/dlls/kernel32/errhandlingapi.cpp"
#include "qiling/os/windows/dlls/kernel32/profileapi.cpp"
#include "qiling/os/windows/dlls/kernel32/stringapiset.cpp"
#include "qiling/os/windows/dlls/kernel32/timezoneapi.cpp"

namespace qiling {
namespace os {

void register_dlls() {
    win::register_fileapi_family();
    win::register_handleapi_family();
    win::register_processthreadsapi_family();
    win::register_synchapi_family();
    win::register_heapapi_family();
    win::register_memoryapi_family();
    win::register_libloaderapi_family();
    win::register_sysinfoapi_family();
    win::register_processenv_family();
    win::register_interlockedapi_family();
    win::register_errhandlingapi_family();
    win::register_profileapi_family();
    win::register_stringapiset_family();
    win::register_timezoneapi_family();
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kDllsRegistered = [] {
    register_dlls();
    return true;
}();
}  // namespace

}  // namespace os
}  // namespace qiling
