// Ported from qiling/os/windows/dlls/ntdll.py — the ntdll family. Ported in
// sub-slices: this one carries the small Zw/Rtl handlers (memcpy, the
// Query/Set information walks, the yield, the heap/string/CSRSS riders, and
// the passthru Rtl bodies). The @winsdkapi decorators map onto the
// WinsdkApi registrations; the bodies ride the verbatim upstream walks. The
// family self-registers at static-init and can be re-seeded after
// ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <spdlog/spdlog.h>

#include <filesystem>

#include "qiling/exception.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// ---- the shared info walks (ntdll.py _QueryInformationProcess /
// _QuerySystemInformation / _SetInformationProcess) ----

// loader/pe.py TEB.PebAddress placeholder — see pe.hpp
std::uint64_t peb_address(Qiling& ql) {
    return static_cast<loader::QlLoaderPE&>(ql.loader()).peb_address();
}

// ---- PROCESS_BASIC_INFORMATION (structs.py make_process_basic_info) ----
// the aligned ctypes layout: the u32 ExitStatus @0, the native fields ride
// the arch width with the natural padding. x64: 48 bytes; x86: 24.
constexpr std::size_t PBI_SIZE_64 = 48;
constexpr std::size_t PBI_SIZE_32 = 24;

void write_process_basic_info(char* dst, int bits, std::uint64_t peb_base, std::uint64_t pid,
                              std::uint64_t parent_pid) {
    const auto native = bits / 8;
    std::memset(dst, 0, bits == 64 ? PBI_SIZE_64 : PBI_SIZE_32);
    // ExitStatus @0 (u32, rides 0), the AffinityMask and the BasePriority
    // ride 0 verbatim; the PebBaseAddress/pid/parent_pid land at the native
    // slots
    const auto peb_off = bits == 64 ? 8 : 4;
    std::memcpy(dst + peb_off, &peb_base, native);
    const auto base_prio_off = bits == 64 ? 24 : 12;
    const std::uint32_t zero32 = 0;
    std::memcpy(dst + base_prio_off, &zero32, 4);
    const auto unique_off = bits == 64 ? 32 : 16;
    std::memcpy(dst + unique_off, &pid, native);
    const auto inherited_off = bits == 64 ? 40 : 20;
    std::memcpy(dst + inherited_off, &parent_pid, native);
}

// the shared _QueryInformationProcess body
std::optional<std::uint64_t> query_information_process(Qiling& ql, const ResolvedParams& params) {
    const auto handle = api_get_int(get_param(params, "ProcessHandle"));
    const auto flag = api_get_int(get_param(params, "ProcessInformationClass"));
    const auto obuf_ptr = api_get_int(get_param(params, "ProcessInformation"));
    const auto obuf_len = api_get_int(get_param(params, "ProcessInformationLength"));
    const auto res_size_ptr = api_get_int(get_param(params, "ReturnLength"));

    std::string res_data;

    if (flag == ProcessDebugFlags) {
        res_data = ql.pack32(1);

    } else if (flag == ProcessDebugPort) {
        res_data = ql.pack32(0);

    } else if (flag == ProcessDebugObjectHandle) {
        return STATUS_PORT_NOT_SET;

    } else if (flag == ProcessBasicInformation) {
        auto& loader = static_cast<loader::QlLoaderPE&>(ql.loader());
        const auto bits = static_cast<int>(ql.arch().bits());
        const auto pid = ql.profile().get_int("KERNEL", "pid");
        const auto parent_pid = ql.profile().get_int("KERNEL", "parent_pid");

        // PebBaseAddress rides the TEB.PebAddress (the TEB/PEB placeholder
        // until that slice lands)
        char buf[64];
        write_process_basic_info(buf, bits, peb_address(ql),
                                 static_cast<std::uint64_t>(pid), static_cast<std::uint64_t>(parent_pid));
        const std::size_t size = bits == 64 ? PBI_SIZE_64 : PBI_SIZE_32;
        res_data.assign(buf, size);
    } else if (flag == ProcessCookie) {
        // the verbatim (1 << bits) - 1 — the all-ones spelling for the 64-bit
        // (the C++ shift-by-64 rides UB)
        const auto h_current_process = ql.arch().bits() >= 64
            ? ~0ull
            : (1ull << ql.arch().bits()) - 1;

        if (handle != h_current_process) {
            // If a process attempts to query the cookie of another
            // process, then QueryInformationProcess returns an error.  (verbatim)
            return STATUS_INVALID_PARAMETER;
        }

        // TODO: Change this to something else,
        // maybe a static randomly generated value.  (verbatim)
        res_data = ql.pack32(0x00000001);

        if (obuf_len != static_cast<std::int64_t>(res_data.size())) {
            // If the buffer length is not ULONG size
            // then QueryInformationProcess returns an error.  (verbatim)
            return STATUS_INFO_LENGTH_MISMATCH;
        }
    } else {
        // TODO: support more info class ("flag") values  (verbatim)
        ql.log().info("QueryInformationProcess: no implementation for info class " +
                      [&] {
                          char buf[16];
                          std::snprintf(buf, sizeof(buf), "%#04x", static_cast<unsigned>(flag));
                          return std::string(buf);
                      }());

        return STATUS_UNSUCCESSFUL;
    }

    const auto res_size = res_data.size();

    if (static_cast<std::uint64_t>(obuf_len) >= res_size) {
        ql.mem().write(obuf_ptr, std::vector<std::uint8_t>(res_data.begin(), res_data.end()));
    }

    if (res_size_ptr != 0) {
        ql.mem().write_ptr(res_size_ptr, res_size, 4);
    }

    return STATUS_SUCCESS;
}

// the shared _QuerySystemInformation body
std::optional<std::uint64_t> query_system_information(Qiling& ql, const ResolvedParams& params) {
    const auto system_information_class = api_get_int(get_param(params, "SystemInformationClass"));
    const auto system_information = api_get_int(get_param(params, "SystemInformation"));
    const auto system_information_length = api_get_int(get_param(params, "SystemInformationLength"));
    const auto return_length = api_get_int(get_param(params, "ReturnLength"));

    if (system_information_class == SystemBasicInformation) {
        const std::uint64_t max_uaddr = ql.arch().type() == QL_ARCH::X86 ? 0x7FFEFFFFull : 0x7FFFFFFEFFFFull;

        // FIXME: retrieve the necessary info from KUSER_SHARED_DATA  (verbatim)
        const auto bits = ql.arch().bits();
        const auto native = bits / 8;
        std::uint8_t sbi[64];
        std::memset(sbi, 0, sizeof(sbi));

        // the 7 u32 fields @0..24
        const std::uint32_t fields[7] = {
            0,          // Reserved
            156250,     // TimerResolution
            static_cast<std::uint32_t>(ql.mem().pagesize()),  // PageSize
            0x003FC38A, // NumberOfPhysicalPages
            1,          // LowestPhysicalPageNumber
            0x0046DFFF, // HighestPhysicalPageNumber
            1,          // AllocationGranularity
        };
        for (int i = 0; i < 7; ++i) {
            std::memcpy(sbi + i * 4, &fields[i], 4);
        }

        // MinimumUserModeAddress / MaximumUserModeAddress /
        // ActiveProcessorsAffinityMask ride the native width after the
        // aligned padding (x64: @32, @40, @48; x86: @28, @32, @36)
        const auto min_addr_off = bits == 64 ? 32u : 28u;
        const std::uint64_t min_addr = 0x10000;
        const std::uint64_t mask = 0x3F;
        std::memcpy(sbi + min_addr_off, &min_addr, native);
        std::memcpy(sbi + min_addr_off + native, &max_uaddr, native);
        std::memcpy(sbi + min_addr_off + 2 * native, &mask, native);
        const std::uint8_t nproc = 6;  // NumberOfProcessors
        sbi[min_addr_off + 3 * native] = nproc;

        const std::size_t sbi_size = bits == 64 ? 64u : 44u;

        if (return_length != 0) {
            ql.mem().write_ptr(return_length, sbi_size, 4);
        }

        if (static_cast<std::uint64_t>(system_information_length) < sbi_size) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        ql.mem().write(system_information, std::vector<std::uint8_t>(sbi, sbi + sbi_size));

    } else {
        throw QlErrorNotImplemented("not implemented for SystemInformationClass=" +
                                    std::to_string(system_information_class));
    }

    return STATUS_SUCCESS;
}

// the shared _SetInformationProcess body
std::optional<std::uint64_t> set_information_process(Qiling& ql, const ResolvedParams& params) {
    const auto flag = api_get_int(get_param(params, "ProcessInformationClass"));
    const auto ibuf_ptr = api_get_int(get_param(params, "ProcessInformation"));
    const auto ibuf_len = api_get_int(get_param(params, "ProcessInformationLength"));

    std::string flag_name;
    std::string comment;
    std::uint64_t read_len = 0;

    if (flag == ProcessDebugFlags) {
        flag_name = "ProcessDebugFlags";
        comment = "";
        read_len = 4;

    } else if (flag == ProcessDebugPort) {
        flag_name = "ProcessDebugPort";
        comment = "";
        read_len = 4;

    } else if (flag == ProcessDebugObjectHandle) {
        return STATUS_PORT_NOT_SET;

    } else if (flag == ProcessBreakOnTermination) {
        flag_name = "ProcessBreakOnTermination";
        comment = "the critical flag of the process";
        read_len = 1;  // FIXME: is it really a single-byte data?  (verbatim)

    } else if (flag == ProcessExecuteFlags) {
        flag_name = "ProcessExecuteFlags";
        comment = "DEP for the process";
        read_len = 1;

    } else if (flag == ProcessBasicInformation) {
        flag_name = "ProcessBasicInformation";
        comment = "PEB debug flag for the process";

        // pbi_struct.sizeof()
        read_len = ql.arch().bits() == 64 ? PBI_SIZE_64 : PBI_SIZE_32;

    } else {
        // TODO: support more info class ("flag") values  (verbatim)
        ql.log().info("SetInformationProcess: no implementation for info class " +
                      [&] {
                          char buf[16];
                          std::snprintf(buf, sizeof(buf), "%#04x", static_cast<unsigned>(flag));
                          return std::string(buf);
                      }());

        return STATUS_UNSUCCESSFUL;
    }

    if (static_cast<std::uint64_t>(ibuf_len) >= read_len) {
        // data = (ql.mem.read_ptr if read_len in (1, 2, 4, 8) else
        //         ql.mem.read)(ibuf_ptr, read_len)  — the small lengths ride
        // the pointer read, the rest ride the byte read (verbatim)
        if (read_len == 1 || read_len == 2 || read_len == 4 || read_len == 8) {
            (void)ql.mem().read_ptr(ibuf_ptr, read_len);
        } else {
            (void)ql.mem().read(ibuf_ptr, static_cast<std::size_t>(read_len));
        }

        ql.log().debug("SetInformationProcess: " + flag_name + " was set");
        if (!comment.empty()) {
            ql.log().debug("The target may be attempting modify " + comment);
        }

        // NOTE: we don't actually change anything  (verbatim)
    }

    return STATUS_SUCCESS;
}

// ---- the OBJECT_TYPE/OBJECT_ALL_TYPES writers (structs.py
// make_unicode_string/make_object_type_info/make_object_all_types_info) ----
// the aligned ctypes layouts: the UNICODE_STRING rides the Length u16 @0,
// the MaximumLength u16 @2, the Buffer @4 (x86) / @8 (x64). The x64
// OBJECT_TYPE_INFORMATION: the TypeName @0 (16), the counts @16/@20 — 24
// bytes; the OBJECT_ALL_TYPES_INFORMATION: the count @0, the array @8 — 32
// bytes (nobjs = 1)
constexpr std::size_t UNICODE_STRING_SIZE_64 = 16;
constexpr std::size_t UNICODE_STRING_SIZE_32 = 8;
constexpr std::size_t OTI_SIZE_64 = 24;
constexpr std::size_t OTI_SIZE_32 = 16;

void write_unicode_string(char* dst, int bits, std::uint16_t length, std::uint64_t buffer) {
    std::memcpy(dst + 0, &length, 2);
    std::memcpy(dst + 2, &length, 2);
    const auto off = bits == 64 ? 8 : 4;
    std::memcpy(dst + off, &buffer, bits / 8);
}

// the ANSI_STRING read (utils.py read_pansi_string): the Length/Buffer walk
// over the aligned layout; the empty string rides {}
std::string read_pansi_string(Qiling& ql, std::uint64_t ptr) {
    const auto bits = static_cast<int>(ql.arch().bits());
    const auto raw = ql.mem().read(ptr, bits == 64 ? 16 : 8);
    std::uint16_t length = 0;
    std::memcpy(&length, raw.data(), 2);
    std::uint64_t buffer = 0;
    const auto off = bits == 64 ? 8 : 4;
    std::memcpy(&buffer, raw.data() + off, bits / 8);

    if (buffer != 0 && length != 0) {
        return QlOsUtils::read_cstring(ql, buffer, length);
    }
    return {};
}

// the shared _FindImageBaseAndFunctionTable body (ntdll.py)
std::pair<std::uint64_t, std::uint64_t> find_image_base_and_function_table(Qiling& ql,
                                                                          std::uint64_t control_pc,
                                                                          std::uint64_t image_base_ptr) {
    const auto* containing_image = ql.loader().find_containing_image(control_pc);
    const auto base_addr = containing_image != nullptr ? containing_image->base : 0;

    // Write base address to the ImageBase pointer, if provided  (verbatim)
    if (image_base_ptr != 0) {
        ql.mem().write_ptr(image_base_ptr, base_addr);
    }

    // If we don't have a valid base, abort now
    if (base_addr == 0) {
        return {0, 0};
    }

    auto& pe_loader = static_cast<loader::QlLoaderPE&>(ql.loader());
    const auto& lookup = pe_loader.function_table_lookup();
    const auto it = lookup.find(base_addr);
    const auto function_table_rva = it != lookup.end() ? it->second : 0;
    const auto function_table_addr = function_table_rva != 0 ? base_addr + function_table_rva : 0;

    return {base_addr, function_table_addr};
}

}  // namespace

void register_ntdll_family() {
    using namespace qiling::os::api;

    // ---- sub-slice 1: the small Zw/Rtl handlers + the info walks ----

    // void *memcpy(
    //    void *dest,
    //    const void *src,
    //    size_t count
    // );
    WinsdkApi("memcpy", WinCc::Cdecl, {
        {"dest", PVOID_},
        {"src", PVOID_},
        {"count", UINT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dest = api_get_int(get_param(params, "dest"));
        const auto src = api_get_int(get_param(params, "src"));
        const auto count = api_get_int(get_param(params, "count"));

        const auto data = ql.mem().read(src, count);
        ql.mem().write(dest, data);

        return dest;
    };

    // NTSTATUS WINAPI ZwQueryInformationProcess( ... );  (the pair share the
    // body; the verbatim TODO: have no idea if is cdecl or stdcall)
    WinsdkApi("ZwQueryInformationProcess", WinCc::Stdcall, {
        {"ProcessHandle", HANDLE_},
        {"ProcessInformationClass", PROCESSINFOCLASS_},
        {"ProcessInformation", PVOID_},
        {"ProcessInformationLength", DWORD_},
        {"ReturnLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return query_information_process(ql, params);
    };

    WinsdkApi("NtQueryInformationProcess", WinCc::Stdcall, {
        {"ProcessHandle", HANDLE_},
        {"ProcessInformationClass", PROCESSINFOCLASS_},
        {"ProcessInformation", PVOID_},
        {"ProcessInformationLength", DWORD_},
        {"ReturnLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return query_information_process(ql, params);
    };

    // NtQuerySystemInformation drops the body value (the verbatim missing
    // return rides None); the Zw variant returns it
    WinsdkApi("NtQuerySystemInformation", WinCc::Stdcall, {
        {"SystemInformationClass", PROCESSINFOCLASS_},
        {"SystemInformation", PVOID_},
        {"SystemInformationLength", DWORD_},
        {"ReturnLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // In minwindef.h
        // #define WINAPI      __stdcall  (verbatim comment)
        (void)query_system_information(ql, params);
        return std::nullopt;
    };

    WinsdkApi("ZwQuerySystemInformation", WinCc::Stdcall, {
        {"SystemInformationClass", PROCESSINFOCLASS_},
        {"SystemInformation", PVOID_},
        {"SystemInformationLength", DWORD_},
        {"ReturnLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return query_system_information(ql, params);
    };

    // NTSYSAPI NTSTATUS NTAPI NtSetInformatonProcess( ... )  (the pair)
    WinsdkApi("ZwSetInformationProcess", WinCc::Stdcall, {
        {"ProcessHandle", HANDLE_},
        {"ProcessInformationClass", PROCESSINFOCLASS_},
        {"ProcessInformation", PVOID_},
        {"ProcessInformationLength", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        (void)set_information_process(ql, params);  // the verbatim dropped return
        return std::nullopt;
    };

    WinsdkApi("NtSetInformationProcess", WinCc::Stdcall, {
        {"ProcessHandle", HANDLE_},
        {"ProcessInformationClass", PROCESSINFOCLASS_},
        {"ProcessInformation", PVOID_},
        {"ProcessInformationLength", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        (void)set_information_process(ql, params);
        return std::nullopt;
    };

    // pub unsafe extern "system" fn ZwCreateDebugObject(...)
    WinsdkApi("ZwCreateDebugObject", WinCc::Stdcall, {
        {"DebugObjectHandle", PVOID_},
        {"DesiredAccess", DWORD_},
        {"ObjectAttributes", PVOID_},
        {"Flags", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // FIXME: find documentation, almost none was found online, and
        // create the correct object  (verbatim: the handle id IS the
        // DebugObjectHandle cell address)
        const auto handle_addr = api_get_int(get_param(params, "DebugObjectHandle"));
        Handle handle(static_cast<std::uint64_t>(handle_addr));
        w(ql).handle_manager().append(handle);
        return STATUS_SUCCESS;
    };

    // NTSYSAPI NTSTATUS NTAPI NtYieldExecution();
    WinsdkApi("ZwYieldExecution", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // FIXME: offer timeslice of this thread  (verbatim)
        return STATUS_NO_YIELD_PERFORMED;
    };

    // NTSYSAPI PVOID RtlAllocateHeap( ... );
    WinsdkApi("RtlAllocateHeap", WinCc::Stdcall, {
        {"HeapHandle", PVOID_},
        {"Flags", DWORD_},
        {"Size", DWORD_PTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return w(ql).heap().alloc(api_get_int(get_param(params, "Size")));
    };

    // wchar_t* wcsstr( const wchar_t* dest, const wchar_t* src );
    WinsdkApi("wcsstr", WinCc::Stdcall, {
        {"dest", PVOID_},
        {"src", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dest = api_get_int(get_param(params, "dest"));
        const auto src = api_get_string(ql, get_param(params, "src"));

        const auto dest_str = QlOsUtils::read_wstring(ql, dest);

        const auto at = dest_str.find(src);
        if (at != std::string::npos) {
            return dest + at;
        }

        return 0;
    };

    // HANDLE CsrGetProcessId();
    WinsdkApi("CsrGetProcessId", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return static_cast<std::uint64_t>(ql.profile().get_int("PROCESSES", "csrss.exe"));
    };

    // the LdrControlFlowGuardEnforced stub
    WinsdkApi("LdrControlFlowGuardEnforced", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // There are some checks in ntdll for whether CFG is enabled.
        // We simply bypass these checks by returning 0.  (verbatim)
        return 0;
    };

    // NTSTATUS EtwNotificationRegister( ... );
    WinsdkApi("EtwNotificationRegister", WinCc::Stdcall, {
        {"ProviderGuid", PVOID_},
        {"Type", DWORD_},
        {"CallbackFunction", PVOID_},
        {"CallbackContext", PVOID_},
        {"RegistrationHandle", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto reg_handle_ptr = api_get_int(get_param(params, "RegistrationHandle"));

        // It is very important to have a hook for this function because it
        // is called by some Windows DLLs (sechost.dll, advapi32.dll) during
        // initialization when the global CRT lock is held.  (verbatim comment)
        // For now, just create a dummy handle, and return it.
        Handle handle;
        w(ql).handle_manager().append(handle);

        if (reg_handle_ptr != 0) {
            ql.mem().write_ptr(reg_handle_ptr, handle.id);
        }

        return STATUS_SUCCESS;
    };

    // ---- the passthru Rtl bodies (the verbatim `return` passes) ----

    // NTSYSAPI VOID RtlRaiseException( PEXCEPTION_RECORD ExceptionRecord );
    WinsdkApi("RtlRaiseException", WinCc::Stdcall, {
        {"ExceptionRecord", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // NTSYSAPI NTSTATUS ZwRaiseException( ... );  (the passthru)
    WinsdkApi("ZwRaiseException", WinCc::Stdcall, {
        {"ExceptionRecord", PVOID_},
        {"ContextRecord", PVOID_},
        {"FirstChance", BOOLEAN_},
    }, true) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto exception_ptr = api_get_int(get_param(params, "ExceptionRecord"));
        const auto context_ptr = api_get_int(get_param(params, "ContextRecord"));
        const auto first_chance = api_get_int(get_param(params, "FirstChance"));

        if (first_chance) {
            throw QlErrorNotImplemented("ZwRaiseException is not implemented for first-chance exceptions.");
        }
        // In Windows, an unhandled exception triggers the
        // top-level unhandled exception filter, after which the process
        // is terminated and error reporting services are called.  (verbatim
        // comment tail rides the walk below)
        std::uint64_t exception_code = 0;
        if (exception_ptr != 0) {
            exception_code = ql.mem().read_ptr(exception_ptr, 4);  // the code rides DWORD
            ql.log().debug("[ZwRaiseException] ExceptionCode: 0x" + [&] {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%08X", static_cast<unsigned>(exception_code));
                return std::string(buf);
            }());
        } else {
            // the verbatim shape: the upstream logs the NULL record here and
            // the later exit-code line raises the NameError (the unbound
            // exception_code); the port carries the 0 default through
            ql.log().debug("[ZwRaiseException] ExceptionRecord is NULL");
        }

        // NOTE: the port carries the 0 default through the NULL-record arm
        // (the upstream raises the NameError at the exit-code line)

        auto* handle = w(ql).handle_manager().search("TopLevelExceptionHandler");

        if (handle == nullptr) {
            ql.log().debug("[ZwRaiseException] No top-level exception filter was found.");
            ql.log().info("The process exited with code 0x" + [&] {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%08X", static_cast<unsigned>(exception_code));
                return std::string(buf);
            }() + ".");

            w(ql).set_exit_code(static_cast<int>(exception_code));

            ql.emu_stop();
            return std::nullopt;
        }

        // the verbatim order: the stack_read rides AFTER the filter check
        // (the no-filter arm never touches the stack)
        const auto ret_addr = ql.stack_read(0);

        const auto exception_filter = reinterpret_cast<std::uint64_t>(handle->obj);

        // allocate some memory for the EXCEPTION_POINTERS struct
        // (make_exception_pointers: the record + the context native pair)
        const auto epointers_size = ql.arch().bits() / 8 * 2;
        const auto exception_pointers_ptr = w(ql).heap().alloc(epointers_size);
        ql.mem().write_ptr(exception_pointers_ptr + 0, exception_ptr);
        ql.mem().write_ptr(exception_pointers_ptr + 8, context_ptr);

        ql.log().debug("[ZwRaiseException] Resuming execution at the top-level exception filter.");

        // Hack: We are going to fake that the caller of ZwRaiseException
        // actually called the unhandled exception filter instead.  (verbatim)
        //
        // We will create a hook which will be triggered when the unhandled
        // exception filter returns, so that we may terminate execution.
        // the verbatim leak: the post-filter hook outlives the handler (the
        // python object persists; the port releases the RAII handle
        // deliberately)
        const std::uint64_t code = exception_code;
        auto* leaked_hook = new HookRet(ql.hook_address([&ql, exception_pointers_ptr, code]() -> int {
            // Free the exception pointers struct we allocated earlier.
            // Might not be needed, since we are going to terminate the process
            // soon, but we might as well free it.  (verbatim)
            w(ql).heap().free(exception_pointers_ptr);

            ql.log().debug("[ZwRaiseException] Returned from the unhandled exception filter.");
            ql.log().info("The process exited with code 0x" + [&] {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%08X", static_cast<unsigned>(code));
                return std::string(buf);
            }() + ".");

            w(ql).set_exit_code(static_cast<int>(code));

            ql.emu_stop();
            return 0;
        }, ret_addr));
        (void)leaked_hook;

        // Resume execution at the registered unhandled exception filter.
        // (the verbatim passthru + the call_native staging: the pointer arg
        // and the return address ride the frame)
        std::vector<std::pair<int, std::uint64_t>> exception_filter_args;
        exception_filter_args.emplace_back(PARAM_PTRX, exception_pointers_ptr);
        w(ql).fcall().call_native(exception_filter, exception_filter_args, ret_addr);

        return std::nullopt;
    };

    WinsdkApi("RtlVirtualUnwind", WinCc::Stdcall, {
        {"HandlerType", DWORD_},
        {"ImageBase", PVOID_},
        {"ControlPc", PVOID_},
        {"FunctionEntry", PVOID_},
        {"ContextRecord", PVOID_},
        {"HandlerData", PVOID_},
        {"EstablisherFrame", PVOID_},
        {"ContextPointers", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlUnwindEx", WinCc::Stdcall, {
        {"TargetFrame", PVOID_},
        {"TargetIp", PVOID_},
        {"ExceptionRecord", PVOID_},
        {"ReturnValue", PVOID_},
        {"OriginalContext", PVOID_},
        {"HistoryTable", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlDispatchException", WinCc::Stdcall, {
        {"ExceptionRecord", PVOID_},
        {"ContextRecord", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlRestoreContext", WinCc::Cdecl, {
        {"ContextRecord", PVOID_},
        {"ExceptionRecord", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlCaptureContext", WinCc::Stdcall, {
        {"ContextRecord", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlCaptureContext2", WinCc::Stdcall, {
        {"ContextRecord", PVOID_},
        {"Flags", DWORD_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlInitializeExtendedContext2", WinCc::Stdcall, {
        {"Version", WORD_},
        {"ContextFlags", WORD_},
        {"ExtensionCount", DWORD_},
        {"ExtensionSizes", PVOID_},
        {"BufferSize", DWORD_},
        {"Buffer", PVOID_},
        {"Context", PVOID_},
        {"LengthReturned", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    WinsdkApi("RtlGetExtendedContextLength2", WinCc::Stdcall, {
        {"Version", WORD_},
        {"ContextFlags", WORD_},
        {"ExtensionCount", DWORD_},
        {"ExtensionSizes", PVOID_},
        {"Length", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return std::nullopt;
    };

    // ---- sub-slice 2: the object query, the procedure lookup, the unwind
    // table riders ----

    // NTSYSCALLAPI NTSTATUS NtQueryObject( ... );
    WinsdkApi("ZwQueryObject", WinCc::Stdcall, {
        {"Handle", HANDLE_},
        {"ObjectInformationClass", PROCESSINFOCLASS_},
        {"ObjectInformation", PVOID_},
        {"ObjectInformationLength", DWORD_},
        {"ReturnLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto handle = api_get_int(get_param(params, "Handle"));
        const auto object_information_class = api_get_int(get_param(params, "ObjectInformationClass"));
        const auto object_information = api_get_int(get_param(params, "ObjectInformation"));
        const auto object_information_length = api_get_int(get_param(params, "ObjectInformationLength"));
        const auto return_length = api_get_int(get_param(params, "ReturnLength"));

        const auto bits = static_cast<int>(ql.arch().bits());
        const bool is64 = bits == 64;
        const std::size_t oti_size = is64 ? OTI_SIZE_64 : OTI_SIZE_32;
        const std::size_t uni_size = is64 ? UNICODE_STRING_SIZE_64 : UNICODE_STRING_SIZE_32;

        // s = 'DebugObject'.encode('utf-16le'); the heap-staged name
        const std::string s = {'D', 0, 'e', 0, 'b', 0, 'u', 0, 'g', 0, 'O', 0, 'b', 0, 'j', 0,
                               'e', 0, 'c', 0, 't', 0};
        const auto addr = w(ql).heap().alloc(s.size());
        ql.mem().write(addr, std::vector<std::uint8_t>(s.begin(), s.end()));

        // TotalNumberOfObjects = 1, TotalNumberOfHandles = 1  (verbatim)
        std::uint32_t total_handles = 1;
        if (object_information_class == ObjectTypeInformation ||
            object_information_class == ObjectAllTypesInformation) {
            // the arm bodies stage below; the ObjectAllTypesInformation arm
            // zeroes the handles (the FIXME hack verbatim: al-khaser expects
            // the closed object to ride 0 handles)
            if (object_information_class == ObjectAllTypesInformation) {
                // FIXME: al-khaser refers the object named 'DebugObject' twice: the first time it creates a handle
                // for it (so number of handles is expected to be higher than 0) and then closes it. the next time
                // it accesses it (here), it expects the number of handles to be 0.
                //
                // ideally we would track the handles for each object, but since we do not - this is a hack to let
                // it pass.  (verbatim comment)
                total_handles = 0;
            }
        } else {
            throw QlErrorNotImplemented("API not implemented (ObjectInformationClass=" +
                                        std::to_string(object_information_class) + ")");
        }

        // the out size rides the class (the OTI for the ObjectType, the OATI
        // for the AllTypes)
        const std::size_t out_size = object_information_class == ObjectTypeInformation
            ? oti_size
            : (is64 ? 8u : 8u) + oti_size;  // the u32 count + the padding to the array

        if (return_length != 0) {
            ql.mem().write_ptr(return_length, out_size, 4);
        }

        if (static_cast<std::uint64_t>(object_information_length) < out_size) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (object_information != 0 && handle != 0) {
            // the save_to walk: the staged name + the counts (1, total_handles)
            char buf[64];
            std::memset(buf, 0, sizeof(buf));
            if (object_information_class == ObjectTypeInformation) {
                write_unicode_string(buf, bits, static_cast<std::uint16_t>(s.size()), addr);
                const std::uint32_t nobj = 1;
                std::memcpy(buf + uni_size, &nobj, 4);
                std::memcpy(buf + uni_size + 4, &total_handles, 4);
                ql.mem().write(object_information, std::vector<std::uint8_t>(buf, buf + oti_size));
            } else {
                // the OATI: the NumberOfObjectTypes @0, the OTI array after
                // the natural padding (the x64: @8; the x86: @4)
                const std::size_t array_off = is64 ? 8u : 4u;
                const std::uint32_t ntypes = 1;
                std::memcpy(buf, &ntypes, 4);
                write_unicode_string(buf + array_off, bits, static_cast<std::uint16_t>(s.size()), addr);
                const std::uint32_t nobj = 1;
                std::memcpy(buf + array_off + uni_size, &nobj, 4);
                std::memcpy(buf + array_off + uni_size + 4, &total_handles, 4);
                ql.mem().write(object_information, std::vector<std::uint8_t>(buf, buf + array_off + oti_size));
            }
        }

        return STATUS_SUCCESS;
    };

    // NTSTATUS LdrGetProcedureAddress( ... );
    WinsdkApi("LdrGetProcedureAddress", WinCc::Stdcall, {
        {"ModuleHandle", HMODULE_},
        {"FunctionName", PVOID_},
        {"Ordinal", WORD_},
        {"FunctionAddress", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto module_handle = api_get_int(get_param(params, "ModuleHandle"));
        const auto function_name = api_get_int(get_param(params, "FunctionName"));
        const auto ordinal = api_get_int(get_param(params, "Ordinal"));
        const auto function_address = api_get_int(get_param(params, "FunctionAddress"));

        // Check if dll is loaded  (verbatim images walk)
        std::string dll_name;
        for (const auto& image : ql.loader().images) {
            if (image.base == module_handle) {
                dll_name = std::filesystem::path(image.path).filename().string();
                for (auto& c : dll_name) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                break;
            }
        }

        if (dll_name.empty()) {
            ql.log().debug("Could not find specified handle " + std::to_string(module_handle) + " in loaded DLL");
            return STATUS_DLL_NOT_FOUND;
        }

        auto& pe_loader = static_cast<loader::QlLoaderPE&>(ql.loader());
        const auto* iat = pe_loader.import_address_table_at(dll_name);
        if (iat == nullptr) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        // identifier = read_pansi_string(...) if FunctionName else Ordinal
        if (function_name != 0) {
            const auto identifier = read_pansi_string(ql, function_name);
            if (identifier.empty()) {
                return STATUS_INVALID_PARAMETER;
            }
            if (iat->by_name.find(identifier) == iat->by_name.end()) {
                return STATUS_PROCEDURE_NOT_FOUND;
            }
            ql.mem().write_ptr(function_address, iat->by_name.at(identifier));
            return STATUS_SUCCESS;
        }

        if (ordinal == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (iat->by_ordinal.find(static_cast<std::uint64_t>(ordinal)) == iat->by_ordinal.end()) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        ql.mem().write_ptr(function_address, iat->by_ordinal.at(static_cast<std::uint64_t>(ordinal)));
        return STATUS_SUCCESS;
    };

    // NTSYSAPI PVOID RtlPcToFileHeader( ... );
    WinsdkApi("RtlPcToFileHeader", WinCc::Stdcall, {
        {"PcValue", PVOID_},
        {"BaseOfImage", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto pc = api_get_int(get_param(params, "PcValue"));
        const auto base_of_image_ptr = api_get_int(get_param(params, "BaseOfImage"));

        const auto* containing_image = ql.loader().find_containing_image(pc);
        const auto base_addr = containing_image != nullptr ? containing_image->base : 0;

        ql.mem().write_ptr(base_of_image_ptr, base_addr);
        return base_addr;
    };

    // NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry( ... );
    WinsdkApi("RtlLookupFunctionEntry", WinCc::Stdcall, {
        {"ControlPc", PVOID_},
        {"ImageBase", PVOID_},
        {"HistoryTable", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto control_pc = api_get_int(get_param(params, "ControlPc"));
        const auto image_base_ptr = api_get_int(get_param(params, "ImageBase"));

        // TODO: Make use of the history table to optimize this function.  (verbatim)
        // This function should not be getting called on x86.  (verbatim)
        if (ql.arch().type() == QL_ARCH::X86) {
            throw QlErrorNotImplemented("RtlLookupFunctionEntry is not implemented for x86");
        }

        const auto [base_addr, function_table_addr] = find_image_base_and_function_table(ql, control_pc, image_base_ptr);

        // If no function table was found, abort.
        if (function_table_addr == 0) {
            return 0;
        }

        auto& pe_loader = static_cast<loader::QlLoaderPE&>(ql.loader());
        const auto [idx, runtime_function] = pe_loader.lookup_function_entry(base_addr, control_pc);

        // If a suitable function entry was found, compute its address and return.
        if (runtime_function != nullptr) {
            return static_cast<std::uint64_t>(function_table_addr + static_cast<std::uint64_t>(idx) * 12);  // sizeof(RUNTIME_FUNCTION)
        }

        return 0;
    };

    // NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionTable( ... );
    WinsdkApi("RtlLookupFunctionTable", WinCc::Stdcall, {
        {"ControlPc", PVOID_},
        {"ImageBase", PVOID_},
        {"SizeOfTable", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto control_pc = api_get_int(get_param(params, "ControlPc"));
        const auto image_base_ptr = api_get_int(get_param(params, "ImageBase"));
        const auto size_of_table_ptr = api_get_int(get_param(params, "SizeOfTable"));

        if (ql.arch().type() == QL_ARCH::X86) {
            throw QlErrorNotImplemented("RtlLookupFunctionTable is not implemented for x86");
        }

        const auto [base_addr, function_table_addr] = find_image_base_and_function_table(ql, control_pc, image_base_ptr);

        if (function_table_addr == 0) {
            ql.mem().write_ptr(size_of_table_ptr, 0, 4);
            return 0;
        }

        if (size_of_table_ptr != 0) {
            auto& pe_loader = static_cast<loader::QlLoaderPE&>(ql.loader());
            const auto& tables = pe_loader.function_tables();
            const auto& function_table = tables.at(base_addr);

            // compute the total size of the table
            const auto size_of_table = function_table.size() * 12;  // sizeof(RUNTIME_FUNCTION)
            ql.mem().write_ptr(size_of_table_ptr, size_of_table, 4);
        }

        return function_table_addr;
    };

    // ---- the ntdll file/memory surface (the ntdll_file/virt/section test
    // shapes; the NT calls ride the same bodies the kernel32 wrappers use,
    // flattened to the NT argument lists) ----

    // NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID*
    //     BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG
    //     AllocateType, ULONG Protect); — the page-aligned heap walk
    WinsdkApi("NtAllocateVirtualMemory", WinCc::Stdcall, {
        {"ProcessHandle", PVOID_},
        {"BaseAddress", PVOID_},
        {"ZeroBits", PVOID_},
        {"RegionSize", PVOID_},
        {"AllocateType", DWORD_},
        {"Protect", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto base_ptr = api_get_int(get_param(params, "BaseAddress"));
        const auto size_ptr = api_get_int(get_param(params, "RegionSize"));
        const auto alloc_type = api_get_int(get_param(params, "AllocateType"));

        const auto ps = ql.arch().pointersize();
        auto want = size_ptr != 0 ? ql.mem().read_ptr(size_ptr, ps) : 0;
        const auto page = static_cast<std::uint64_t>(0x1000);
        want = (want + page - 1) & ~(page - 1);
        if (want == 0) {
            return static_cast<std::uint64_t>(0xc0000045u);  // STATUS_INVALID_PARAMETER_4
        }

        const auto addr = w(ql).heap().alloc(want);
        if (addr == 0) {
            return static_cast<std::uint64_t>(0xc0000017u);  // STATUS_NO_MEMORY
        }
        if (base_ptr != 0) {
            ql.mem().write_ptr(base_ptr, addr);
        }
        if (size_ptr != 0) {
            ql.mem().write_ptr(size_ptr, want);
        }
        (void)alloc_type;
        return 0;  // STATUS_SUCCESS
    };

    // NTSTATUS NtFreeVirtualMemory(...); — the heap release (the MEM_RELEASE
    // walk; the base must ride the allocation base)
    WinsdkApi("NtFreeVirtualMemory", WinCc::Stdcall, {
        {"ProcessHandle", PVOID_},
        {"BaseAddress", PVOID_},
        {"RegionSize", PVOID_},
        {"FreeType", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto base_ptr = api_get_int(get_param(params, "BaseAddress"));
        if (base_ptr != 0) {
            const auto ps = ql.arch().pointersize();
            w(ql).heap().free(ql.mem().read_ptr(base_ptr, ps));
        }
        return 0;
    };

    // NTSTATUS NtProtectVirtualMemory(...); — the no-op (the access state is
    // not observable through the single-threaded probes)
    WinsdkApi("NtProtectVirtualMemory", WinCc::Stdcall, {
        {"ProcessHandle", PVOID_},
        {"BaseAddress", PVOID_},
        {"RegionSize", PVOID_},
        {"NewProtect", DWORD_},
        {"OldProtect", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // NTSTATUS NtMapViewOfSection(...); — the zeroed view (the size cell
    // rides the view size)
    WinsdkApi("NtMapViewOfSection", WinCc::Stdcall, {
        {"SectionHandle", PVOID_},
        {"ProcessHandle", PVOID_},
        {"BaseAddress", PVOID_},
        {"ZeroBits", PVOID_},
        {"CommitSize", PVOID_},
        {"SectionOffset", PVOID_},
        {"ViewSize", PVOID_},
        {"InheritDisposition", DWORD_},
        {"AllocationType", DWORD_},
        {"Win32Protect", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto base_ptr = api_get_int(get_param(params, "BaseAddress"));
        const auto view_size_ptr = api_get_int(get_param(params, "ViewSize"));
        const auto ps = ql.arch().pointersize();

        const auto want = view_size_ptr != 0 ? ql.mem().read_ptr(view_size_ptr, ps) : 0x1000;
        const auto addr = w(ql).heap().alloc(want);
        if (addr == 0) {
            return static_cast<std::uint64_t>(0xc0000017u);
        }
        if (base_ptr != 0) {
            ql.mem().write_ptr(base_ptr, addr);
        }
        if (view_size_ptr != 0) {
            ql.mem().write_ptr(view_size_ptr, want);
        }
        return 0;
    };

    // NTSTATUS NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ...);
    // — the file rides the fs mapper (the OBJECT_ATTRIBUTES walks the name;
    // the share/access shapes map onto the open_mode walk)
    WinsdkApi("NtCreateFile", WinCc::Stdcall, {
        {"FileHandle", PVOID_},
        {"DesiredAccess", PVOID_},
        {"ObjectAttributes", PVOID_},
        {"IoStatusBlock", PVOID_},
        {"AllocationSize", PVOID_},
        {"FileAttributes", PVOID_},
        {"ShareAccess", PVOID_},
        {"CreateDisposition", PVOID_},
        {"CreateOptions", PVOID_},
        {"EaBuffer", PVOID_},
        {"EaLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto out_handle = api_get_int(get_param(params, "FileHandle"));
        const auto obj_attr = api_get_int(get_param(params, "ObjectAttributes"));
        const auto disposition_ptr = api_get_int(get_param(params, "CreateDisposition"));
        if (out_handle == 0 || obj_attr == 0) {
            return static_cast<std::uint64_t>(0xc000000du);  // STATUS_INVALID_PARAMETER
        }

        // OBJECT_ATTRIBUTES: the ObjectName field rides at the 2nd pointer
        // slot (Length, RootDirectory, ObjectName); the UNICODE_STRING body:
        // Length/MaximumLength (the two u16s), then the Buffer pointer at the
        // native alignment (the ps offset)
        const auto ps = ql.arch().pointersize();
        const auto name_struct = ql.mem().read_ptr(obj_attr + 2 * ps);
        if (name_struct == 0) {
            return static_cast<std::uint64_t>(0xc0000033u);  // STATUS_OBJECT_NAME_INVALID
        }
        const auto name_len = ql.mem().read_ptr(name_struct, 2);
        const auto name_buf = ql.mem().read_ptr(name_struct + ps);
        if (name_buf == 0 || name_len == 0) {
            return static_cast<std::uint64_t>(0xc0000033u);  // STATUS_OBJECT_NAME_INVALID
        }
        auto name_bytes = ql.mem().read(name_buf, static_cast<std::size_t>(name_len));
        // the NT object names are utf-16le verbatim (the OBJECT_ATTRIBUTES
        // contract — the Length cell counts the bytes) — decode to the narrow
        // dos-path form (the ascii subset; the non-ascii cells degrade)
        std::string name;
        for (std::size_t i = 0; i + 1 < name_bytes.size(); i += 2) {
            name.push_back(static_cast<char>(name_bytes[i]));
        }

        // the \??\ prefix rides the NT object-manager namespace marker — the
        // fs mapper wants the dos path (the C:\... body)
        if (name.rfind("\\??\\", 0) == 0) {
            name.erase(0, 4);
        }

        std::shared_ptr<QlFsMappedObject> f;
        try {
            f = w(ql).fs_mapper()->open(name, "r+");
        } catch (const std::exception&) {
            // the open miss rides the status (the FILE_OPEN on the missing
            // path; the callers probe and continue)
            if (out_handle != 0) {
                ql.mem().write_ptr(out_handle, 0);
            }
            if (const auto io = api_get_int(get_param(params, "IoStatusBlock")); io != 0) {
                ql.mem().write_ptr(io, static_cast<std::uint64_t>(0xc0000034u), 8);  // STATUS_OBJECT_NAME_NOT_FOUND
            }
            return static_cast<std::uint64_t>(0xc0000034u);
        }
        Handle new_handle(std::nullopt, f.get());
        new_handle.owned = f;
        w(ql).handle_manager().append(new_handle);

        ql.mem().write_ptr(out_handle, new_handle.id);
        if (disposition_ptr != 0) {
            ql.mem().write_ptr(disposition_ptr, 1, 4);  // FILE_OPENED
        }
        if (const auto io = api_get_int(get_param(params, "IoStatusBlock")); io != 0) {
            ql.mem().write_ptr(io, 0, 8);  // the status + the info cells
        }
        return 0;
    };

    // NTSTATUS NtWriteFile(...); — the parked-handle write
    WinsdkApi("NtWriteFile", WinCc::Stdcall, {
        {"FileHandle", PVOID_},
        {"Event", PVOID_},
        {"ApcRoutine", PVOID_},
        {"ApcContext", PVOID_},
        {"IoStatusBlock", PVOID_},
        {"Buffer", PVOID_},
        {"Length", PVOID_},
        {"ByteOffset", PVOID_},
        {"Key", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h = api_get_int(get_param(params, "FileHandle"));
        const auto buf = api_get_int(get_param(params, "Buffer"));
        const auto len = api_get_int(get_param(params, "Length"));
        const auto io = api_get_int(get_param(params, "IoStatusBlock"));

        const auto* handle = w(ql).handle_manager().get(h);
        if (handle == nullptr || handle->obj == nullptr) {
            return static_cast<std::uint64_t>(0xc0000008u);  // STATUS_INVALID_HANDLE
        }
        const auto data = ql.mem().read(buf, static_cast<std::size_t>(len));
        const auto written = static_cast<QlFsMappedObject*>(handle->obj)->write(data);
        if (io != 0) {
            ql.mem().write_ptr(io, 0, 8);           // the status
            ql.mem().write_ptr(io + 8, written);    // the info
        }
        return 0;
    };

    // NTSTATUS NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
    //     KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG); — the miss
    // answers STATUS_OBJECT_NAME_NOT_FOUND (the registry surface rides the
    // RegistryManager walk; the flat NT probe degrades)
    WinsdkApi("NtQueryValueKey", WinCc::Stdcall, {
        {"KeyHandle", PVOID_},
        {"ValueName", PVOID_},
        {"KeyValueInformationClass", DWORD_},
        {"KeyValueInformation", PVOID_},
        {"Length", PVOID_},
        {"ResultLength", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return static_cast<std::uint64_t>(0xc0000034u);  // STATUS_OBJECT_NAME_NOT_FOUND
    };

    // NTSTATUS NtCreateSection(...); — the SEC_COMMIT view stub (the pagefile
    // section shape; the file-mapped sections land with the memory-mapping
    // slice)
    WinsdkApi("NtCreateSection", WinCc::Stdcall, {
        {"SectionHandle", PVOID_},
        {"DesiredAccess", PVOID_},
        {"ObjectAttributes", PVOID_},
        {"MaximumSize", PVOID_},
        {"SectionPageProtection", PVOID_},
        {"AllocationAttributes", PVOID_},
        {"FileHandle", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto out_handle = api_get_int(get_param(params, "SectionHandle"));
        if (out_handle != 0) {
            Handle new_handle(std::nullopt, nullptr, "section");
            w(ql).handle_manager().append(new_handle);
            ql.mem().write_ptr(out_handle, new_handle.id);
        }
        return 0;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kNtdllRegistered = [] {
    register_ntdll_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
