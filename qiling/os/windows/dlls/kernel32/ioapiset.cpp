// Ported from qiling/os/windows/dlls/kernel32/ioapiset.py — the IO control
// family (DeviceIoControl). The @winsdkapi decorators map onto
// register_ioapiset_family(); the bodies ride the verbatim upstream walks
// (the TODO verbatim 1 included). The family self-registers at static-init
// and can be re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_ioapiset_family() {
    using namespace qiling::os::api;

    // BOOL DeviceIoControl(
    //   HANDLE       hDevice,
    //   DWORD        dwIoControlCode,
    //   LPVOID       lpInBuffer,
    //   DWORD        nInBufferSize,
    //   LPVOID       lpOutBuffer,
    //   DWORD        nOutBufferSize,
    //   LPDWORD      lpBytesReturned,
    //   LPOVERLAPPED lpOverlapped
    // );
    WinsdkApi("DeviceIoControl", WinCc::Stdcall, {
        {"hDevice", PVOID_},
        {"dwIoControlCode", DWORD_},
        {"lpInBuffer", PVOID_},
        {"nInBufferSize", DWORD_},
        {"lpOutBuffer", PVOID_},
        {"nOutBufferSize", DWORD_},
        {"lpBytesReturned", LPDWORD_},
        {"lpOverlapped", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO implement operations. Did not find controlCodes values
        // (verbatim)
        return 1;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kIoapisetRegistered = [] {
    register_ioapiset_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
