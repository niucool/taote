// Ported from qiling/os/windows/dlls/ntoskrnl.py — the 80-handler kernel
// surface. The pool/string walkers ride the QlOsWindows heap and the string
// engine; the passthru families (the _*nicmp Rtl runtime riders) return the
// None so the native bodies keep running; the info walkers answer the
// verbatim constants. The loader-side riders (the KUSER_SHARED_DATA map, the
// EPROCESS/DRIVER_OBJECT placeholders, the registry-path cursor) live in the
// loader/pe.cpp init_* walks.
#ifndef QILING_OS_WINDOWS_DLLS_NTOSKRNL_CPP
#define QILING_OS_WINDOWS_DLLS_NTOSKRNL_CPP

#include "qiling/core.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/wdk_const.hpp"
#include "qiling/os/windows/windows.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition

// the ntoskrnl.py hook_only_routine_address (the MmGetSystemRoutineAddress
// fake-stub walk)
const std::vector<const char*> kHookOnlyRoutineAddress{"IoCreateDeviceSecure"};

// utils.py read_punicode_string: the Length/MaximumLength/Buffer walk (the
// 16-byte x64 image; the 8-byte x86)
std::string read_punicode_string(Qiling& ql, std::uint64_t ptr) {
    const bool bits64 = ql.arch().bits() == 64;
    const auto length = ql.mem().read_ptr(ptr, 2);
    const auto buffer = ql.mem().read_ptr(ptr + (bits64 ? 8 : 4), bits64 ? 8 : 4);

    if (length == 0 || buffer == 0) {
        return {};
    }
    return QlOsUtils::read_wstring(ql, buffer, static_cast<int>(length) / 2);
}

// the KUSER_SHARED_DATA cell read (the ntoskrnl RtlGetVersion walk rides the
// loader's mapped shared-data page; the offsets live in pe.cpp)
std::uint64_t kusd_read32(Qiling& ql, std::size_t off) {
    const auto* pe = static_cast<const loader::QlLoaderPE*>(&ql.loader());
    return ql.mem().read_ptr(pe->kuser_shared_data_address() + off, 4);
}

// ntoskrnl.py __IoCreateDevice: the DEVICE_OBJECT image (the 64-bit layout)
std::uint64_t io_create_device_body(Qiling& ql, const ResolvedParams& params, bool secure) {
    (void)secure;
    const auto driver_object = api_get_int(get_param(params, "DriverObject"));
    const auto device_extension_size = api_get_int(get_param(params, "DeviceExtensionSize"));
    const auto device_characteristics = api_get_int(get_param(params, "DeviceCharacteristics"));
    const auto device_object = api_get_int(get_param(params, "DeviceObject"));

    // the 64-bit DEVICE_OBJECT image (the make_device_object layout; the
    // fields before the first embedded composite ride their offsets)
    constexpr std::size_t DEV_OFF_DRIVEROBJECT = 8;
    constexpr std::size_t DEV_OFF_DEVICEEXTENSION = 64;
    constexpr std::size_t DEV_OFF_FLAGS = 48;
    constexpr std::size_t DEV_OFF_CHARACTERISTICS = 52;
    constexpr std::size_t DEV_SIZE_64 = 312;

    auto& heap = w(ql).heap();
    const auto devobj_addr = heap.alloc(DEV_SIZE_64);
    std::string image(DEV_SIZE_64, '\0');
    const auto put16 = [&](std::size_t off, std::uint64_t v) {
        image[off] = static_cast<char>(v & 0xff);
        image[off + 1] = static_cast<char>((v >> 8) & 0xff);
    };
    const auto put32 = [&](std::size_t off, std::uint64_t v) {
        for (int k = 0; k < 4; ++k) {
            image[off + k] = static_cast<char>((v >> (8 * k)) & 0xff);
        }
    };
    const auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int k = 0; k < 8; ++k) {
            image[off + k] = static_cast<char>((v >> (8 * k)) & 0xff);
        }
    };

    put16(0, 3);  // FILE_DEVICE_CD_ROM_FILE_SYSTEM ?  (verbatim)
    put16(2, DEV_SIZE_64);
    put32(4, 1);  // ReferenceCount
    put64(DEV_OFF_DRIVEROBJECT, driver_object);
    put64(16, 0);  // NextDevice
    put64(24, 0);  // AttachedDevice
    put64(32, 0);  // CurrentIrp
    put64(40, 0);  // Timer
    const bool exclusive = [&] {
        const auto& p = get_param(params, "Exclusive");
        return api_get_int(p) != 0;
    }();
    put32(DEV_OFF_FLAGS, DO_DEVICE_INITIALIZING | (exclusive ? DO_EXCLUSIVE : 0));
    put32(DEV_OFF_CHARACTERISTICS, device_characteristics);
    put64(56, 0);  // Vpb
    put64(DEV_OFF_DEVICEEXTENSION, heap.alloc(device_extension_size));
    ql.mem().write(devobj_addr, std::vector<std::uint8_t>(image.begin(), image.end()));

    // update out param
    ql.mem().write_ptr(device_object, devobj_addr);

    // update DriverObject.DeviceObject (the loader image walks the
    // driver_object_address cell; the DRIVER_OBJECT.DeviceObject offset = 8)
    auto& pe = static_cast<loader::QlLoaderPE&>(ql.loader());
    ql.mem().write_ptr(pe.driver_object_address() + 8, devobj_addr);

    return STATUS_SUCCESS;
}

}  // namespace

void register_ntoskrnl_family() {
    using namespace qiling::os::api;

    // NTSYSAPI NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW);
    WinsdkApi("RtlGetVersion", WinCc::Cdecl, {
        {"lpVersionInformation", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pointer = api_get_int(get_param(params, "lpVersionInformation"));

        // read the necessary information from KUSER_SHARED_DATA  (verbatim)
        const auto put32 = [&](std::size_t off, std::uint64_t v) {
            ql.mem().write_ptr(pointer + off, v, 4);
        };
        put32(0, 276);  // the dwOSVersionInfoSize (the wide struct sizeof)
        put32(4, kusd_read32(ql, 620));
        put32(8, kusd_read32(ql, 624));

        ql.log().debug("The target is checking the windows Version!");
        return STATUS_SUCCESS;
    };

    // NTSYSAPI NTSTATUS ZwSetInformationThread(HANDLE, THREADINFOCLASS,
    //     PVOID, ULONG);
    WinsdkApi("ZwSetInformationThread", WinCc::Stdcall, {
        {"ThreadHandle", HANDLE_},
        {"ThreadInformationClass", INT_},   // the THREADINFOCLASS
        {"ThreadInformation", PVOID_},
        {"ThreadInformationLength", ULONG_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto thread = api_get_int(get_param(params, "ThreadHandle"));
        const auto information = api_get_int(get_param(params, "ThreadInformationClass"));
        const auto dst = api_get_int(get_param(params, "ThreadInformation"));
        const auto size = api_get_int(get_param(params, "ThreadInformationLength"));

        auto& os = w(ql);
        if (thread == os.thread_manager().cur_thread()->get_id()) {
            if (size >= 100) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            if (information == ThreadHideFromDebugger) {
                // The target is checking debugger via SetInformationThread
                // (verbatim)
                if (dst != 0) {
                    ql.mem().write_ptr(dst, 0, 1);
                }
            } else {
                throw QlErrorNotImplemented("API not implemented " + std::to_string(information));
            }
        } else {
            return STATUS_INVALID_HANDLE;
        }

        return STATUS_SUCCESS;
    };

    // the __Close body: the ZwClose/NtClose rides
    const auto close_body = [](Qiling& ql, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto value = api_get_int(get_param(params, "Handle"));

        const auto* handle = w(ql).handle_manager().get(value);
        if (handle == nullptr) {
            return STATUS_INVALID_HANDLE;
        }

        return STATUS_SUCCESS;
    };

    // NTSYSAPI NTSTATUS ZwClose(HANDLE Handle);
    WinsdkApi("ZwClose", WinCc::Stdcall, {
        {"Handle", HANDLE_},
    }) = [close_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return close_body(ql, params);
    };

    // NTSYSAPI NTSTATUS NtClose(HANDLE Handle);
    WinsdkApi("NtClose", WinCc::Stdcall, {
        {"Handle", HANDLE_},
    }) = [close_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return close_body(ql, params);
    };

    // the DbgPrint pair (the CDECL ellipsis + the printf engine)
    WinsdkApi("DbgPrintEx", WinCc::Cdecl, {
        {"ComponentId", ULONG_},
        {"Level", ULONG_},
        {"Format", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto format = api_get_string(ql, get_param(params, "Format"));

        const std::vector<int> slots{os::PARAM_INTN, os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        std::size_t cursor = 0;
        const auto pull = [&args, &cursor]() -> std::uint64_t {
            return cursor < args.size() ? args[cursor++] : 0;
        };

        return QlOsUtils::printf(ql, format, pull, false).count;
    };

    WinsdkApi("DbgPrint", WinCc::Cdecl, {
        {"Format", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto format = api_get_string(ql, get_param(params, "Format"));

        const std::vector<int> slots{os::PARAM_INTN};
        const auto args = ql.os().fcall().read_ellipsis(slots, QlOsUtils::count_va_pulls(format));

        std::size_t cursor = 0;
        const auto pull = [&args, &cursor]() -> std::uint64_t {
            return cursor < args.size() ? args[cursor++] : 0;
        };

        return QlOsUtils::printf(ql, format, pull, false).count;
    };

    // the IoCreateDevice pair (the shared __IoCreateDevice walk)
    WinsdkApi("IoCreateDevice", WinCc::Stdcall, {
        {"DriverObject", PVOID_},
        {"DeviceExtensionSize", ULONG_},
        {"DeviceName", PVOID_},
        {"DeviceType", DWORD_},
        {"DeviceCharacteristics", ULONG_},
        {"Exclusive", BOOL_},
        {"DeviceObject", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return io_create_device_body(ql, params, false);
    };

    WinsdkApi("IoCreateDeviceSecure", WinCc::Stdcall, {
        {"DriverObject", PVOID_},
        {"DeviceExtensionSize", ULONG_},
        {"DeviceName", PVOID_},
        {"DeviceType", DWORD_},
        {"DeviceCharacteristics", ULONG_},
        {"Exclusive", BOOL_},
        {"DefaultSDDLString", PVOID_},
        {"DeviceClassGuid", GUID_},
        {"DeviceObject", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return io_create_device_body(ql, params, true);
    };

    // NTSYSAPI NTSTATUS RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR,
    //     ULONG Revision); — the verbatim TODO
    WinsdkApi("RtlCreateSecurityDescriptor", WinCc::Stdcall, {
        {"SecurityDescriptor", PVOID_},
        {"Revision", ULONG_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // void IoDeleteDevice(PDEVICE_OBJECT DeviceObject);
    WinsdkApi("IoDeleteDevice", WinCc::Stdcall, {
        {"DeviceObject", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto addr = api_get_int(get_param(params, "DeviceObject"));
        w(ql).heap().free(addr);
        return 0;
    };

    // NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING, PUNICODE_STRING);
    WinsdkApi("IoCreateSymbolicLink", WinCc::Stdcall, {
        {"SymbolicLinkName", PVOID_},
        {"DeviceName", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName);
    WinsdkApi("IoDeleteSymbolicLink", WinCc::Stdcall, {
        {"SymbolicLinkName", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // the IRP-completion pair (the verbatim no-op bodies)
    WinsdkApi("IofCompleteRequest", WinCc::Stdcall, {
        {"Irp", PVOID_},
        {"PriorityBoost", CHAR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("IoCompleteRequest", WinCc::Stdcall, {
        {"Irp", PVOID_},
        {"PriorityBoost", CHAR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
    //
    // The upstream rides the verbatim `pass` (the kernel drivers hand in
    // pre-built structures), but the usermode samples routinely initialize
    // their OBJECT_ATTRIBUTES name this way — leaving the struct untouched
    // leaves Length/Buffer garbage and every NtCreateFile walk reads a
    // bogus UNICODE_STRING. The kernel contract: no allocation, the Buffer
    // points at the caller's string, MaximumLength = Length + sizeof(WCHAR)
    WinsdkApi("RtlInitUnicodeString", WinCc::Stdcall, {
        {"DestinationString", PVOID_},
        {"SourceString", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dest = api_get_int(get_param(params, "DestinationString"));
        const auto src = api_get_int(get_param(params, "SourceString"));
        if (dest == 0) {
            return std::nullopt;
        }
        const auto ps = ql.arch().pointersize();

        std::uint64_t len = 0;
        if (src != 0) {
            // the wide walk: the Length cell counts BYTES without the NUL
            while (len < 0x10000) {
                const auto unit = ql.mem().read_ptr(src + len, 2);
                if (unit == 0) {
                    break;
                }
                len += 2;
            }
        }
        ql.mem().write_ptr(dest, len, 2);
        ql.mem().write_ptr(dest + 2, src != 0 ? len + 2 : 0, 2);
        ql.mem().write_ptr(dest + ps, src);
        return std::nullopt;
    };

    WinsdkApi("RtlCopyUnicodeString", WinCc::Stdcall, {
        {"DestinationString", PVOID_},
        {"SourceString", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlAnsiStringToUnicodeString", WinCc::Stdcall, {
        {"DestinationString", PVOID_},
        {"SourceString", PVOID_},
        {"AllocateDestinationString", BOOL_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlInitAnsiString", WinCc::Stdcall, {
        {"DestinationString", PVOID_},
        {"SourceString", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlUnicodeStringToAnsiString", WinCc::Stdcall, {
        {"DestinationString", PVOID_},
        {"SourceString", PVOID_},
        {"AllocateDestinationString", BOOL_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // the Ex pool family: the heap-alloc riders
    const auto pool_alloc_body = [](Qiling& ql, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto size = api_get_int(get_param(params, "NumberOfBytes"));
        return w(ql).heap().alloc(size);
    };
    const auto pool_alloc_tag_body = [](Qiling& ql, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto size = api_get_int(get_param(params, "NumberOfBytes"));
        return w(ql).heap().alloc(size);
    };

    WinsdkApi("ExAllocatePool", WinCc::Stdcall, {
        {"PoolType", INT_},
        {"NumberOfBytes", ULONG_PTR_},
    }) = [pool_alloc_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return pool_alloc_body(ql, params);
    };

    WinsdkApi("ExAllocatePoolWithTag", WinCc::Stdcall, {
        {"PoolType", INT_},
        {"NumberOfBytes", ULONG_PTR_},
        {"Tag", ULONG_},
    }) = [pool_alloc_tag_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return pool_alloc_tag_body(ql, params);
    };

    WinsdkApi("ExAllocatePoolWithQuotaTag", WinCc::Stdcall, {
        {"PoolType", INT_},
        {"NumberOfBytes", ULONG_PTR_},
        {"Tag", ULONG_},
    }) = [pool_alloc_tag_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return pool_alloc_tag_body(ql, params);
    };

    WinsdkApi("ExAllocatePoolWithQuota", WinCc::Stdcall, {
        {"PoolType", INT_},
        {"NumberOfBytes", ULONG_PTR_},
    }) = [pool_alloc_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return pool_alloc_body(ql, params);
    };

    WinsdkApi("ExAllocatePoolWithTagPriority", WinCc::Stdcall, {
        {"PoolType", INT_},
        {"NumberOfBytes", ULONG_PTR_},
        {"Tag", ULONG_},
        {"Priority", INT_},   // the EX_POOL_PRIORITY
    }) = [pool_alloc_tag_body](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return pool_alloc_tag_body(ql, params);
    };

    // void ExFreePoolWithTag(PVOID P, ULONG Tag);
    WinsdkApi("ExFreePoolWithTag", WinCc::Stdcall, {
        {"P", PVOID_},
        {"Tag", ULONG_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto addr = api_get_int(get_param(params, "P"));
        w(ql).heap().free(addr);
        return 0;
    };

    // PVOID MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName);
    WinsdkApi("MmGetSystemRoutineAddress", WinCc::Stdcall, {
        {"SystemRoutineName", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto system_routine_name = api_get_int(get_param(params, "SystemRoutineName"));

        const auto routine_name = system_routine_name != 0
            ? read_punicode_string(ql, system_routine_name)
            : std::string();

        if (!routine_name.empty()) {
            // check function name in import table  (verbatim)
            auto& pe = static_cast<loader::QlLoaderPE&>(ql.loader());
            for (const char* dll_name : {"ntoskrnl.exe", "ntkrnlpa.exe", "hal.dll"}) {
                if (const auto* iat = pe.import_address_table_at(dll_name)) {
                    if (const auto ea = iat->lookup(routine_name); ea != 0) {
                        return ea;
                    }
                }
            }

            // function not found! we check function name in
            // `hook_only_routine_address`  (verbatim)
            std::size_t index = 0;
            for (const char* candidate : kHookOnlyRoutineAddress) {
                if (routine_name == candidate) {
                    break;
                }
                ++index;
            }
            if (index < kHookOnlyRoutineAddress.size()) {
                // found!  (verbatim)
                auto& pe_mut = static_cast<loader::QlLoaderPE&>(ql.loader());
                for (const char* dll_name : {"ntoskrnl.exe", "ntkrnlpa.exe", "hal.dll"}) {
                    (void)dll_name;
                    // create fake address (the image.base + index + 1 — the
                    // port parks it on the eprocess address tail since the
                    // stub images ride the loader maps)
                    const auto new_function_address = pe_mut.eprocess_address() + index + 1;
                    // the upstream writes ql.loader.import_symbols[addr] so the
                    // dispatch hook recognises the fake address; that
                    // registration is what makes the guest's call reach the
                    // handler instead of executing unmapped memory
                    pe_mut.register_import_symbol(new_function_address, "ntoskrnl.exe", routine_name);
                    // the import_symbols registration rides the ApiRegistry
                    // loader map — the port notes the deviation: the
                    // upstream writes ql.loader.import_symbols; the port's
                    // loader exposes the stubs through the load_image walk
                    return new_function_address;
                }
            }
        }

        return 0;
    };

    // the _*nicmp passthru family (the nt_rtl runtime riders — the native
    // bodies keep running)
    for (const auto& [name, with_locale] : {std::pair{"_wcsnicmp", false}, {"_strnicmp", false},
                                            {"_mbsnicmp", false}, {"_strnicmp_l", true},
                                            {"_wcsnicmp_l", true}, {"_mbsnicmp_l", true}}) {
        ApiParams ps{
            {"string1", LPCWSTR_},
            {"string2", LPCWSTR_},
            {"count", ULONG_PTR_},
        };
        if (with_locale) {
            ps.push_back({"locale", PVOID_});
        }
        WinsdkApi(name, WinCc::Stdcall, ps, true) =
            [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
            return std::nullopt;
        };
    }

    // wchar_t *wcschr(wchar_t *str, wchar_t c); — the passthru
    WinsdkApi("wcschr", WinCc::Stdcall, {
        {"str", LPCWSTR_},
        {"c", WCHAR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // BOOLEAN PsGetVersion(PULONG, PULONG, PULONG, PUNICODE_STRING);
    WinsdkApi("PsGetVersion", WinCc::Stdcall, {
        {"MajorVersion", PVOID_},
        {"MinorVersion", PVOID_},
        {"BuildNumber", PVOID_},
        {"CSDVersion", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // NTSYSAPI SIZE_T RtlCompareMemory(const VOID *, const VOID *, SIZE_T);
    WinsdkApi("RtlCompareMemory", WinCc::Stdcall, {
        {"Source1", PVOID_},
        {"Source2", PVOID_},
        {"Length", ULONG_PTR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // the critical-region pair (the verbatim None bodies)
    WinsdkApi("KeEnterCriticalRegion", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("KeLeaveCriticalRegion", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // PVOID MmMapLockedPagesSpecifyCache(PMDL, KPROCESSOR_MODE,
    //     MEMORY_CACHING_TYPE, PVOID, ULONG, ULONG);
    WinsdkApi("MmMapLockedPagesSpecifyCache", WinCc::Stdcall, {
        {"MemoryDescriptorList", PVOID_},
        {"AccessMode", INT_},
        {"CacheType", INT_},
        {"RequestedAddress", PVOID_},
        {"BugCheckOnFailure", ULONG_},
        {"Priority", ULONG_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto mdl = api_get_int(get_param(params, "MemoryDescriptorList"));

        // the MDL.MappedSystemVa offset (the make_mdl layout: the Next@0,
        // the Size@8, the MdlFlags@10, the Process@16, the MappedSystemVa@24)
        const bool bits64 = ql.arch().bits() == 64;
        const auto mapped = ql.mem().read_ptr(mdl + (bits64 ? 24 : 16), bits64 ? 8 : 4);
        return mapped;
    };

    // the Probe pair (the verbatim None bodies)
    WinsdkApi("ProbeForRead", WinCc::Stdcall, {
        {"Address", PVOID_},
        {"Length", ULONG_PTR_},
        {"Alignment", ULONG_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("ProbeForWrite", WinCc::Stdcall, {
        {"Address", PVOID_},
        {"Length", ULONG_PTR_},
        {"Alignment", ULONG_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // the string-conversion passthru family
    WinsdkApi("_vsnwprintf", WinCc::Stdcall, {
        {"buffer", LPCWSTR_},
        {"count", ULONG_PTR_},
        {"format", LPCWSTR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("mbtowc", WinCc::Stdcall, {
        {"wchar", LPCWSTR_},
        {"mbchar", LPCSTR_},
        {"count", ULONG_PTR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("_mbtowc_l", WinCc::Stdcall, {
        {"wchar", LPCWSTR_},
        {"mbchar", LPCSTR_},
        {"count", ULONG_PTR_},
        {"locale", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlAnsiCharToUnicodeChar", WinCc::Stdcall, {
        {"SourceCharacter", LPCSTR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlMultiByteToUnicodeN", WinCc::Stdcall, {
        {"UnicodeString", PVOID_},
        {"MaxBytesInUnicodeString", ULONG_},
        {"BytesInUnicodeString", PVOID_},
        {"MultiByteString", PVOID_},
        {"BytesInMultiByteString", ULONG_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // the NtQuerySystemInformation pair (the SystemModuleInformation ride)
    const auto nt_query_system_information_body =
        [](Qiling& ql, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto info_class = api_get_int(get_param(params, "SystemInformationClass"));
        const auto return_length = api_get_int(get_param(params, "ReturnLength"));
        const auto info_length = api_get_int(get_param(params, "SystemInformationLength"));
        const auto system_information = api_get_int(get_param(params, "SystemInformation"));

        // see: geoffchappell.com ... /query.htm  (verbatim note)
        if (info_class == 0xb) {  // SystemModuleInformation
            // only 1 module for ntoskrnl.exe  (verbatim)
            constexpr std::size_t kNumModules = 1;
            // the RTL_PROCESS_MODULES image (the NumberOfModules u32 + the
            // RTL_PROCESS_MODULE_INFORMATION[1]: the Section/MappedBase/
            // ImageBase ptrs, the ImageSize/Flags u32, the 4 u16s, the
            // FullPathName[256] — the 296-byte entry)
            constexpr std::size_t RPMI_SIZE = 8 + 8 + 8 + 4 + 4 + 2 + 2 + 2 + 2 + 256;
            constexpr std::size_t RPM_SIZE = 4 + kNumModules * RPMI_SIZE;

            if (return_length != 0) {
                ql.mem().write_ptr(return_length, RPM_SIZE, 4);
            }

            // if SystemInformationLength = 0, we return the total size in
            // ReturnLength  (verbatim)
            if (info_length < RPM_SIZE) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            std::string image(RPM_SIZE, '\0');
            const auto put32 = [&](std::size_t off, std::uint64_t v) {
                for (int k = 0; k < 4; ++k) {
                    image[off + k] = static_cast<char>((v >> (8 * k)) & 0xff);
                }
            };
            const auto put16 = [&](std::size_t off, std::uint64_t v) {
                image[off] = static_cast<char>(v & 0xff);
                image[off + 1] = static_cast<char>((v >> 8) & 0xff);
            };
            const auto put64 = [&](std::size_t off, std::uint64_t v) {
                for (int k = 0; k < 8; ++k) {
                    image[off + k] = static_cast<char>((v >> (8 * k)) & 0xff);
                }
            };

            put32(0, kNumModules);
            const auto& entry = image;

            auto& pe = static_cast<loader::QlLoaderPE&>(ql.loader());
            put64(4 + 0, 0);   // Section  (FIXME: load real values instead of bogus ones verbatim)
            put64(4 + 8, 0);   // MappedBase
            std::uint64_t image_base = 0;
            if (pe.is_driver()) {
                // the image walk rides the ntoskrnl.exe base — the port rides
                // the pe_image_address (the loader's main image)
                image_base = pe.pe_image_address();
            }
            put64(4 + 16, image_base);
            put32(4 + 24, 0xab000);  // ImageSize
            put32(4 + 28, 0x8804000);  // Flags
            put16(4 + 32, 0);  // LoadOrderIndex
            put16(4 + 34, 0);  // InitOrderIndex
            put16(4 + 36, 1);  // LoadCount
            put16(4 + 38, static_cast<std::uint64_t>(std::string("\\SystemRoot\\system32\\").size()));
            // the FullPathName rides the c-string bytes
            const std::string full = "\\SystemRoot\\system32\\ntoskrnl.exe";
            std::copy(full.begin(), full.end(), image.begin() + 4 + 40);
            ql.mem().write(system_information, std::vector<std::uint8_t>(entry.begin(), entry.end()));
        }

        return STATUS_SUCCESS;
    };

    WinsdkApi("NtQuerySystemInformation", WinCc::Stdcall, {
        {"SystemInformationClass", INT_},
        {"SystemInformation", PVOID_},
        {"SystemInformationLength", ULONG_},
        {"ReturnLength", PVOID_},
    }) = [nt_query_system_information_body](Qiling& ql, std::uint64_t,
                                            const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return nt_query_system_information_body(ql, params);
    };

    WinsdkApi("ZwQuerySystemInformation", WinCc::Stdcall, {
        {"SystemInformationClass", INT_},
        {"SystemInformation", PVOID_},
        {"SystemInformationLength", ULONG_},
        {"ReturnLength", PVOID_},
    }) = [nt_query_system_information_body](Qiling& ql, std::uint64_t,
                                            const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return nt_query_system_information_body(ql, params);
    };

    // the event/kernel stubs
    WinsdkApi("KeInitializeEvent", WinCc::Stdcall, {
        {"Event", PVOID_},
        {"Type", INT_},
        {"State", BOOL_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("IoCsqInitialize", WinCc::Stdcall, {
        {"Csq", PVOID_},
        {"CsqInsertIrp", PVOID_},
        {"CsqRemoveIrp", PVOID_},
        {"CsqPeekNextIrp", PVOID_},
        {"CsqAcquireLock", PVOID_},
        {"CsqReleaseLock", PVOID_},
        {"CsqCompleteCanceledIrp", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("IoStartPacket", WinCc::Stdcall, {
        {"DeviceObject", PVOID_},
        {"Irp", PVOID_},
        {"Key", PVOID_},
        {"CancelFunction", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("IoAcquireCancelSpinLock", WinCc::Stdcall, {
        {"Irql", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // PEPROCESS PsGetCurrentProcess(); — the loader eprocess
    WinsdkApi("PsGetCurrentProcess", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return static_cast<const loader::QlLoaderPE&>(ql.loader()).eprocess_address();
    };

    // HANDLE PsGetCurrentProcessId(); — the os pid
    WinsdkApi("PsGetCurrentProcessId", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).pid();
    };

    // NTSTATUS IoCreateDriver(PUNICODE_STRING, PDRIVER_INITIALIZE);
    WinsdkApi("IoCreateDriver", WinCc::Stdcall, {
        {"DriverName", PVOID_},
        {"InitializationFunction", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto init_func = api_get_int(get_param(params, "InitializationFunction"));

        auto& os = w(ql);
        auto& pe = static_cast<loader::QlLoaderPE&>(ql.loader());

        const auto ret_addr = ql.stack_read(0);

        // save SP & init_sp  (verbatim)
        const auto sp = ql.arch().regs().arch_sp();
        const auto init_sp = os.init_sp();

        os.set_fcall_ptr(os.fcall_select(WinCc::Stdcall));
        os.fcall().write_params({
            {os::PARAM_PTRX, pe.driver_object_address()},
            {os::PARAM_PTRX, pe.regitry_path_address()},
        });

        // now lest emualate InitializationFunction  (verbatim comment)
        try {
            ql.run(init_func, ret_addr);
        } catch (const QlErrorBase&) {
            // the verify_ret ride (the upstream catches the UcError and
            // verifies the RAX)
        }

        // reset SP since emulated function does not cleanup  (verbatim)
        ql.arch().regs().write("rsp", sp);
        os.set_init_sp(init_sp);

        return 0;
    };

    // the time/rte passthru family
    WinsdkApi("ExSystemTimeToLocalTime", WinCc::Stdcall, {
        {"SystemTime", PVOID_},
        {"LocalTime", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // FIXME: implement this to customize user timezone?  (verbatim)
        return std::nullopt;
    };

    WinsdkApi("RtlTimeToTimeFields", WinCc::Stdcall, {
        {"Time", PVOID_},
        {"TimeFields", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // the CRT passthru family
    WinsdkApi("vsprintf_s", WinCc::Stdcall, {
        {"buffer", PVOID_},
        {"numberOfElements", ULONG_PTR_},
        {"format", LPCSTR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("_vsprintf_s_l", WinCc::Stdcall, {
        {"buffer", PVOID_},
        {"numberOfElements", ULONG_PTR_},
        {"format", LPCSTR_},
        {"locale", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("vswprintf_s", WinCc::Stdcall, {
        {"buffer", LPCWSTR_},
        {"numberOfElements", ULONG_PTR_},
        {"format", LPCWSTR_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("_vswprintf_s_l", WinCc::Stdcall, {
        {"buffer", LPCWSTR_},
        {"numberOfElements", ULONG_PTR_},
        {"format", LPCWSTR_},
        {"locale", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // BOOLEAN MmIsAddressValid(PVOID VirtualAddress); — the verbatim 1
    WinsdkApi("MmIsAddressValid", WinCc::Stdcall, {
        {"VirtualAddress", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // the bugcheck pair (the verbatim pass bodies)
    WinsdkApi("KeBugCheckEx", WinCc::Stdcall, {
        {"BugCheckCode", ULONG_},
        {"BugCheckParameter1", ULONG_PTR_},
        {"BugCheckParameter2", ULONG_PTR_},
        {"BugCheckParameter3", ULONG_PTR_},
        {"BugCheckParameter4", ULONG_PTR_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("KeBugCheck", WinCc::Stdcall, {
        {"BugCheckCode", ULONG_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // PEPROCESS PsProcessType — the data stub (the verbatim pass)
    WinsdkApi("PsProcessType", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // NTSTATUS PsGetProcessImageFileName(PEPROCESS Process); — the hardcoded
    // path image at a fresh heap cell
    WinsdkApi("PsGetProcessImageFileName", WinCc::Stdcall, {
        {"Process", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        const auto addr = w(ql).heap().alloc(260);
        const std::string path = "C:\\test.exe";
        ql.mem().write(addr, std::vector<std::uint8_t>(path.begin(), path.end()));
        return addr;
    };

    // NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS *);
    WinsdkApi("PsLookupProcessByProcessId", WinCc::Stdcall, {
        {"ProcessId", HANDLE_},
        {"Process", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto process_id = api_get_int(get_param(params, "ProcessId"));
        const auto process = api_get_int(get_param(params, "Process"));

        // the EPROCESS placeholder (the 0x4d0 image — the
        // FIXME: define meaningful fields ride)
        const auto addr = w(ql).heap().alloc(0x4d0);
        ql.mem().write_ptr(process, addr);
        ql.log().info("PID = " + std::to_string(process_id) + ", addrof(EPROCESS) == " +
                      std::to_string(addr));

        return STATUS_SUCCESS;
    };

    // NTSTATUS ZwOpenKey/NtOpenKey(PHANDLE, ACCESS_MASK,
    //     POBJECT_ATTRIBUTES); — the verbatim STATUS_SUCCESS
    WinsdkApi("ZwOpenKey", WinCc::Stdcall, {
        {"KeyHandle", PVOID_},
        {"DesiredAccess", ULONG_},
        {"ObjectAttributes", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    WinsdkApi("NtOpenKey", WinCc::Stdcall, {
        {"KeyHandle", PVOID_},
        {"DesiredAccess", ULONG_},
        {"ObjectAttributes", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // NTSTATUS KeWaitForSingleObject(PVOID, KWAIT_REASON, KPROCESSOR_MODE,
    //     BOOLEAN, PLARGE_INTEGER);
    WinsdkApi("KeWaitForSingleObject", WinCc::Stdcall, {
        {"Object", PVOID_},
        {"WaitReason", INT_},
        {"WaitMode", INT_},
        {"Alertable", BOOL_},
        {"Timeout", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // LONG_PTR ObfReferenceObject(PVOID Object); — the passthru
    WinsdkApi("ObfReferenceObject", WinCc::Stdcall, {
        {"Object", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // NTSTATUS PsCreateSystemThread(PHANDLE, ULONG, POBJECT_ATTRIBUTES,
    //     HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID);
    WinsdkApi("PsCreateSystemThread", WinCc::Stdcall, {
        {"ThreadHandle", PVOID_},
        {"DesiredAccess", ULONG_},
        {"ObjectAttributes", PVOID_},
        {"ProcessHandle", HANDLE_},
        {"ClientId", PVOID_},
        {"StartRoutine", PVOID_},
        {"StartContext", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto thread_handle = api_get_int(get_param(params, "ThreadHandle"));
        const auto lp_thread_id = api_get_int(get_param(params, "ClientId"));

        constexpr std::uint64_t kUniqueProcess = 0x4141;
        constexpr std::uint64_t kThreadId = 0x1337;
        constexpr std::uint64_t kHandleValue = 0x31337;

        // set lpThreadId  (verbatim)
        if (lp_thread_id != 0) {
            ql.mem().write_ptr(lp_thread_id, kUniqueProcess);
            ql.mem().write_ptr(lp_thread_id + ql.arch().pointersize(), kThreadId);
        }

        // set thread handle  (verbatim)
        if (thread_handle != 0) {
            ql.mem().write_ptr(thread_handle, kHandleValue);
        }

        return STATUS_SUCCESS;
    };

    // NTSTATUS ObReferenceObjectByHandle(...); — the verbatim STATUS_SUCCESS
    WinsdkApi("ObReferenceObjectByHandle", WinCc::Stdcall, {
        {"Handle", HANDLE_},
        {"DesiredAccess", ULONG_},
        {"ObjectType", PVOID_},
        {"AccessMode", INT_},
        {"Object", PVOID_},
        {"HandleInformation", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // the Ke event family (the verbatim 0 bodies)
    WinsdkApi("KeSetEvent", WinCc::Stdcall, {
        {"Event", PVOID_},
        {"Increment", INT_},
        {"Wait", BOOL_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("KeResetEvent", WinCc::Stdcall, {
        {"Event", PVOID_},
        {"Increment", INT_},
        {"Wait", BOOL_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    WinsdkApi("KeClearEvent", WinCc::Stdcall, {
        {"Event", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // NTSTATUS PsTerminateSystemThread(NTSTATUS ExitStatus);
    WinsdkApi("PsTerminateSystemThread", WinCc::Stdcall, {
        {"ExitStatus", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // NTSTATUS ObReferenceObjectByPointer(...); — the verbatim STATUS_SUCCESS
    WinsdkApi("ObReferenceObjectByPointer", WinCc::Stdcall, {
        {"Object", PVOID_},
        {"DesiredAccess", ULONG_},
        {"ObjectType", PVOID_},
        {"AccessMode", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // NTSTATUS ObOpenObjectByPointer(...); — the named handle walk
    WinsdkApi("ObOpenObjectByPointer", WinCc::Stdcall, {
        {"Object", PVOID_},
        {"HandleAttributes", ULONG_},
        {"PassedAccessState", PVOID_},
        {"DesiredAccess", ULONG_},
        {"ObjectType", PVOID_},
        {"AccessMode", INT_},
        {"Handle", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto object = api_get_int(get_param(params, "Object"));
        const auto point_to_new_handle = api_get_int(get_param(params, "Handle"));

        const auto object_hex = [](std::uint64_t v) {
            static const char digits[] = "0123456789abcdef";
            std::string out = "0x";
            for (int k = 60; k >= 0; k -= 4) {
                out.push_back(digits[(v >> k) & 0xf]);
            }
            return out;
        };

        Handle new_handle(std::nullopt, nullptr, "p=" + object_hex(object));
        w(ql).handle_manager().append(new_handle);
        ql.mem().write_ptr(point_to_new_handle, new_handle.id);
        ql.log().info("New handle of " + object_hex(object) + " is " + object_hex(new_handle.id));

        return STATUS_SUCCESS;
    };

    // NTSYSAPI NTSTATUS ObfDereferenceObject(PVOID Object); — the CDECL stub
    WinsdkApi("ObfDereferenceObject", WinCc::Cdecl, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };

    // NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
    WinsdkApi("NtTerminateProcess", WinCc::Stdcall, {
        {"ProcessHandle", HANDLE_},
        {"ExitStatus", INT_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return STATUS_SUCCESS;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kNtoskrnlRegistered = [] {
    qiling::os::win::register_ntoskrnl_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_NTOSKRNL_CPP
