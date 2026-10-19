// Ported from qiling/os/windows/dlls/kernel32/heapapi.py — the heap family
// (HeapCreate/HeapAlloc/HeapReAlloc/HeapSize/HeapFree/HeapSetInformation/
// GetProcessHeap/HeapValidate) riding the QlMemoryHeap surface. The
// @winsdkapi decorators map onto register_heapapi_family(); the bodies ride
// the verbatim upstream walks (the HEAP_ZERO_MEMORY page-granularity zero
// walk included). The family self-registers at static-init and can be
// re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the shared __zero_mem: zero a memory range, but avoid hogging too much on
// host resources (the verbatim page-granularity walk)
void zero_mem(QlMemoryManager& mem, std::uint64_t ptr, std::uint64_t size) {
    const auto npages = size / mem.pagesize();
    const auto remainder = size % mem.pagesize();

    if (npages != 0) {
        const std::string zeros(mem.pagesize(), '\0');

        for (std::uint64_t i = 0; i < npages; ++i) {
            mem.write(ptr, std::vector<std::uint8_t>(zeros.begin(), zeros.end()));
            ptr += zeros.size();
        }
    }

    if (remainder != 0) {
        const std::string zeros(remainder, '\0');
        mem.write(ptr, std::vector<std::uint8_t>(zeros.begin(), zeros.end()));
    }
}

// the shared _HeapAlloc body
std::optional<std::uint64_t> heap_alloc_body(Qiling& ql, const ResolvedParams& params) {
    const auto dw_flags = api_get_int(get_param(params, "dwFlags"));
    const auto dw_bytes = api_get_int(get_param(params, "dwBytes"));

    const auto ptr = w(ql).heap().alloc(dw_bytes);

    if (ptr != 0 && (dw_flags & HEAP_ZERO_MEMORY)) {
        zero_mem(ql.mem(), ptr, dw_bytes);
    }

    return ptr;
}

}  // namespace

void register_heapapi_family() {
    using namespace qiling::os::api;

    // HANDLE HeapCreate(
    //   DWORD  flOptions,
    //   SIZE_T dwInitialSize,
    //   SIZE_T dwMaximumSize
    // );
    WinsdkApi("HeapCreate", WinCc::Stdcall, {
        {"flOptions", DWORD_},
        {"dwInitialSize", LPVOID_},
        {"dwMaximumSize", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_initial_size = api_get_int(get_param(params, "dwInitialSize"));

        return w(ql).heap().alloc(dw_initial_size);
    };

    // DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
    //   HANDLE hHeap,
    //   DWORD  dwFlags,
    //   SIZE_T dwBytes
    // );
    WinsdkApi("HeapAlloc", WinCc::Stdcall, {
        {"hHeap", HANDLE_},
        {"dwFlags", DWORD_},
        {"dwBytes", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return heap_alloc_body(ql, params);
    };

    // DECLSPEC_ALLOCATOR LPVOID HeapReAlloc(
    //   HANDLE                 hHeap,
    //   DWORD                  dwFlags,
    //   _Frees_ptr_opt_ LPVOID lpMem,
    //   SIZE_T                 dwBytes
    // );
    WinsdkApi("HeapReAlloc", WinCc::Stdcall, {
        {"hHeap", HANDLE_},
        {"dwFlags", DWORD_},
        {"lpMem", LPVOID_},
        {"dwBytes", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto base = api_get_int(get_param(params, "lpMem"));
        const auto new_size = api_get_int(get_param(params, "dwBytes"));

        if (base == 0) {
            return heap_alloc_body(ql, params);
        }

        if (new_size == 0) {
            w(ql).heap().free(base);
            return 0;
        }

        const auto old_size = w(ql).heap().size(base);
        auto old_data = ql.mem().read(base, old_size);

        w(ql).heap().free(base);

        if (new_size < old_size) {
            old_data.resize(static_cast<std::size_t>(new_size));
        }

        const auto new_base = w(ql).heap().alloc(new_size);
        if (new_base != 0) {
            ql.mem().write(new_base, old_data);
        }

        return new_base;
    };

    // SIZE_T HeapSize(
    //   HANDLE  hHeap,
    //   DWORD   dwFlags,
    //   LPCVOID lpMem
    // );
    WinsdkApi("HeapSize", WinCc::Stdcall, {
        {"hHeap", HANDLE_},
        {"dwFlags", DWORD_},
        {"lpMem", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "lpMem"));

        return w(ql).heap().size(pointer);
    };

    // BOOL HeapFree(
    //  HANDLE                 hHeap,
    //  DWORD                  dwFlags,
    //  _Frees_ptr_opt_ LPVOID lpMem
    // );
    WinsdkApi("HeapFree", WinCc::Stdcall, {
        {"hHeap", HANDLE_},
        {"dwFlags", DWORD_},
        {"lpMem", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_mem = api_get_int(get_param(params, "lpMem"));

        return w(ql).heap().free(lp_mem) ? 1 : 0;
    };

    // BOOL HeapSetInformation(
    //  HANDLE                 HeapHandle,
    //  HEAP_INFORMATION_CLASS HeapInformationClass,
    //  PVOID                  HeapInformation,
    //  SIZE_T                 HeapInformationLength
    // );
    WinsdkApi("HeapSetInformation", WinCc::Stdcall, {
        {"HeapHandle", HANDLE_},
        {"HeapInformationClass", DWORD_},
        {"HeapInformation", LPVOID_},
        {"HeapInformationLength", LPVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // HANDLE GetProcessHeap(
    // );
    WinsdkApi("GetProcessHeap", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).heap().start_address();
    };

    // BOOL HeapValidate(
    //   HANDLE hHeap,
    //   DWORD dwFlags,
    //   LPCVOID lpMem
    // );
    WinsdkApi("HeapValidate", WinCc::Stdcall, {
        {"hHeap", LPVOID_},
        {"dwFlags", DWORD_},
        {"lpMem", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_heap = api_get_int(get_param(params, "hHeap"));
        const auto lp_mem = api_get_int(get_param(params, "lpMem"));

        if (h_heap == 0) {
            return 0;
        }

        // TODO: Maybe _find is a heap manager implementation
        // detail, in which case we shouldn't rely on it.  (verbatim)
        const auto* chunk = w(ql).heap().find_chunk(lp_mem);

        if (chunk == nullptr) {
            return 0;
        }

        return chunk->inuse;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kHeapapiRegistered = [] {
    qiling::os::win::register_heapapi_family();
    return true;
}();
}  // namespace
