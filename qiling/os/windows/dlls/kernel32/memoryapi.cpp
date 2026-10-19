// Ported from qiling/os/windows/dlls/kernel32/memoryapi.py — the virtual
// memory family (VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery) riding
// the QlMemoryHeap surface. The @winsdkapi decorators map onto
// register_memoryapi_family(); the bodies ride the verbatim upstream walks
// (the VirtualQuery MEMORY_BASIC_INFORMATION pack over the pointer-sized
// stride included). The family self-registers at static-init and can be
// re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>
#include <vector>

namespace qiling {
namespace os {
namespace win {

void register_memoryapi_family() {
    using namespace qiling::os::api;

    // LPVOID VirtualAlloc(
    //   LPVOID lpAddress,
    //   SIZE_T dwSize,
    //   DWORD  flAllocationType,
    //   DWORD  flProtect
    // );
    WinsdkApi("VirtualAlloc", WinCc::Stdcall, {
        {"lpAddress", LPVOID_},
        {"dwSize", LPVOID_},
        {"flAllocationType", DWORD_},
        {"flProtect", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_size = api_get_int(get_param(params, "dwSize"));

        return w(ql).heap().alloc(dw_size);
    };

    // BOOL VirtualFree(
    //   LPVOID lpAddress,
    //   SIZE_T dwSize,
    //   DWORD  dwFreeType
    // );
    WinsdkApi("VirtualFree", WinCc::Stdcall, {
        {"lpAddress", LPVOID_},
        {"dwSize", LPVOID_},
        {"dwFreeType", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_address = api_get_int(get_param(params, "lpAddress"));

        w(ql).heap().free(lp_address);

        return 1;
    };

    // BOOL VirtualProtect(
    //  LPVOID lpAddress,
    //  SIZE_T dwSize,
    //  DWORD  flNewProtect,
    //  PDWORD lpflOldProtect
    // );
    WinsdkApi("VirtualProtect", WinCc::Stdcall, {
        {"lpAddress", LPVOID_},
        {"dwSize", LPVOID_},
        {"flNewProtect", DWORD_},
        {"lpflOldProtect", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // SIZE_T VirtualQuery(
    //  LPCVOID                   lpAddress,
    //  PMEMORY_BASIC_INFORMATION lpBuffer,
    //  SIZE_T                    dwLength
    // );
    WinsdkApi("VirtualQuery", WinCc::Stdcall, {
        {"lpAddress", LPVOID_},
        {"lpBuffer", LPVOID_},
        {"dwLength", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // typedef struct _MEMORY_BASIC_INFORMATION {
        //   PVOID  BaseAddress;
        //   PVOID  AllocationBase;
        //   DWORD  AllocationProtect;
        //   SIZE_T RegionSize;
        //   DWORD  State;
        //   DWORD  Protect;
        //   DWORD  Type;
        // } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
        const auto lp_address = api_get_int(get_param(params, "lpAddress"));
        const auto mbi = api_get_int(get_param(params, "lpBuffer"));

        // find chunk,
        std::optional<std::uint64_t> base;
        std::optional<std::uint64_t> size;

        for (const auto& chunk : w(ql).heap().chunks()) {
            if (chunk.address <= lp_address && lp_address < chunk.address + chunk.size) {
                base = chunk.address;
                size = chunk.size;
                break;
            }
        }

        if (!base.has_value()) {
            // Page not found
            w(ql).set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }

        const auto values = std::vector<std::uint64_t>{
            *base,
            *base,
            0x40,      // EXECUTE_READ_WRITE
            *size,
            0x1000,    // MEM_COMMIT
            0x40,      // EXECUTE_READ_WRITE
            0x40000    // MEM_MAPPED
        };

        const auto ps = ql.arch().pointersize();
        for (std::size_t i = 0; i < values.size(); ++i) {
            ql.mem().write_ptr(mbi + i * ps, values[i]);
        }

        return ps * values.size();
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kMemoryapiRegistered = [] {
    qiling::os::win::register_memoryapi_family();
    return true;
}();
}  // namespace
