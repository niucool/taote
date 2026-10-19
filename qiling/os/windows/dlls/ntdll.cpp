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

    WinsdkApi("RtlRaiseException", WinCc::Stdcall, {
        {"ExceptionRecord", PVOID_},
    }, true) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
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
