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
#include "qiling/os/windows/dlls/kernel32/consoleapi.cpp"
#include "qiling/os/windows/dlls/kernel32/wow64apiset.cpp"
#include "qiling/os/windows/dlls/kernel32/debugapi.cpp"
#include "qiling/os/windows/dlls/kernel32/ioapiset.cpp"
#include "qiling/os/windows/dlls/kernel32/fibersapi.cpp"
#include "qiling/os/windows/dlls/kernel32/winnls.cpp"
#include "qiling/os/windows/dlls/kernel32/winbase.cpp"
#include "qiling/os/windows/dlls/kernel32/tlhelp32.cpp"
#include "qiling/os/windows/dlls/kernel32/winnt.cpp"
#include "qiling/os/windows/dlls/kernel32/consoleapi23.cpp"
#include "qiling/os/windows/dlls/ntdll.cpp"
#include "qiling/os/windows/dlls/advapi32.cpp"
#include "qiling/os/windows/dlls/msvcrt.cpp"
#include "qiling/os/windows/dlls/crypt32.cpp"
#include "qiling/os/windows/dlls/msi.cpp"
#include "qiling/os/windows/dlls/mscoree.cpp"
#include "qiling/os/windows/dlls/msvbvm60.cpp"
#include "qiling/os/windows/dlls/shlwapi.cpp"
#include "qiling/os/windows/dlls/oleaut32.cpp"
#include "qiling/os/windows/dlls/ole32.cpp"
#include "qiling/os/windows/dlls/ucrtbased.cpp"
#include "qiling/os/windows/dlls/wudplatform.cpp"
#include "qiling/os/windows/dlls/shell32.cpp"
#include "qiling/os/windows/dlls/wsock32.cpp"
#include "qiling/os/windows/dlls/wininet.cpp"

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
    win::register_consoleapi_family();
    win::register_wow64apiset_family();
    win::register_debugapi_family();
    win::register_ioapiset_family();
    win::register_fibersapi_family();
    win::register_winnls_family();
    win::register_winbase_family();
    win::register_tlhelp32_family();
    win::register_winnt_family();
    win::register_consoleapi2_family();
    win::register_consoleapi3_family();
    win::register_psapi_family();
    win::register_ntdll_family();
    win::register_advapi32_family();
    win::register_msvcrt_family();
    win::register_crypt32_family();
    win::register_msi_family();
    win::register_mscoree_family();
    win::register_msvbvm60_family();
    win::register_shlwapi_family();
    win::register_oleaut32_family();
    win::register_ole32_family();
    win::register_ucrtbased_family();
    win::register_wudplatform_family();
    win::register_shell32_family();
    win::register_wsock32_family();
    win::register_wininet_family();
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
