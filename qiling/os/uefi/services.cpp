// os/uefi/services.cpp — the service-table implementation (the slice-2
// shape: the descriptor walk + the fncc wrapper dispatch + the BS TPL pair)

#include "qiling/os/uefi/services.hpp"

#include <cstring>
#include <ctime>

#include "qiling/os/utils.hpp"
#include "qiling/os/uefi/context.hpp"
#include "qiling/os/uefi/uefi.hpp"
#include "qiling/loader/pe_uefi.hpp"

namespace qiling {
namespace os {
namespace uefi {

namespace {

// the fncc.py dxeapi wrapper shape: the address hook resolves the params
// through the os.call orchestration (the user CALL/ENTER/EXIT hooks ride
// the name-keyed table with the hook_ prefix)
int dispatch_service(Qiling* ql, std::string fname, const ServiceHook& hook,
                     std::vector<std::pair<std::string, int>> proto) {
    auto& os_uefi = static_cast<QlOsUefi&>(ql->os());
    const auto pc = ql->arch().regs().arch_pc();

    const auto api_name = std::string("hook_") + fname;
    const auto* onenter = os_uefi.find_user_api(api_name, QL_INTERCEPT::ENTER);
    const auto* onexit = os_uefi.find_user_api(api_name, QL_INTERCEPT::EXIT);
    const auto* override_hook = os_uefi.find_user_api(api_name, QL_INTERCEPT::CALL);

    // the ENTER hooks fire raw before the call (the fncc wrapper shape)
    if (onenter != nullptr) {
        (*onenter)(*ql, pc, api_name);
    }

    if (override_hook != nullptr) {
        // the CALL intercept replaces the built-in (the raw handler shape)
        auto raw = [override_hook, ql](std::uint64_t addr, const QlFunctionCall::Params& params)
            -> std::optional<std::uint64_t> {
            (void)params;
            (*override_hook)(*ql, addr, "");
            return std::nullopt;
        };
        os_uefi.call(pc, fname, raw, proto, {}, {}, false);
        return 0;
    }

    auto adapter = [hook, ql](std::uint64_t addr, const QlFunctionCall::Params& params)
        -> std::optional<std::uint64_t> {
        (void)addr;
        (void)params;
        return hook(*ql, addr, params);
    };
    os_uefi.call(pc, fname, adapter, proto, {}, {}, false);

    // the EXIT hooks fire raw after the call
    if (onexit != nullptr) {
        (*onexit)(*ql, pc, api_name);
    }
    return 0;
}

// utils.py str_to_guid: the 16-byte mixed-endian GUID at ptr to the
// canonical string (the bytes_le field order)
std::string guid_to_str(Qiling& ql, std::uint64_t ptr) {
    const auto b = ql.mem().read(ptr, 16);
    char buf[48];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[3], b[2], b[1], b[0],
                  b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return std::string(buf);
}

// bs.py hook_AllocatePages (the dxe shape verbatim)
std::optional<std::uint64_t> hook_allocate_pages(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto alloc_size = params.at(2).second * PAGE_SIZE;
    const auto type = params.at(0).second;
    const auto memory_ptr = params.at(3).second;

    if (type == 2) {  // EFI_ALLOCATE_TYPE::AllocateAddress
        const auto address = ql.mem().read_ptr(memory_ptr);
        // TODO(upstream): check the [address, address+size] availability first
        ql.mem().map(address, alloc_size, UC_PROT_ALL, "[efi-pages]");
    } else {
        const auto address = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context->heap->alloc(alloc_size);
        if (address == 0) {
            return kEfiOutOfResources;
        }
        ql.mem().write_ptr(memory_ptr, address);
    }

    return kEfiSuccess;
}

// bs.py hook_FreePages
std::optional<std::uint64_t> hook_free_pages(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto address = params.at(0).second;
    const auto ok = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context->heap->free(address);
    return ok ? kEfiSuccess : kEfiInvalidParameter;
}

// bs.py hook_AllocatePool (the pool-type TODO verbatim)
std::optional<std::uint64_t> hook_allocate_pool(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto size = params.at(1).second;
    const auto buffer = params.at(2).second;

    const auto address = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context->heap->alloc(size);
    ql.mem().write_ptr(buffer, address);
    return address != 0 ? kEfiSuccess : kEfiOutOfResources;
}

// bs.py hook_FreePool
std::optional<std::uint64_t> hook_free_pool(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto ok = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context->heap->free(params.at(0).second);
    return ok ? kEfiSuccess : kEfiInvalidParameter;
}

// protocols/common.py InstallProtocolInterface
std::optional<std::uint64_t> hook_install_protocol_interface(Qiling& ql, std::uint64_t,
                                                             const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    auto handle = ql.mem().read_ptr(params.at(0).second);
    const auto protocol_ptr = params.at(1).second;
    const auto iface = params.at(3).second;

    if (handle == 0) {
        handle = ctx.heap->alloc(1);
    }

    const auto guid = guid_to_str(ql, protocol_ptr);
    auto& per_handle = ctx.protocols[handle];
    per_handle[guid] = iface;

    ql.mem().write_ptr(params.at(0).second, handle);
    // the notify_protocol ride lands with the event slice
    return kEfiSuccess;
}

// protocols/common.py HandleProtocol
std::optional<std::uint64_t> hook_handle_protocol(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto handle = params.at(0).second;
    const auto protocol_ptr = params.at(1).second;
    const auto iface = params.at(2).second;

    const auto it = ctx.protocols.find(handle);
    if (it == ctx.protocols.end()) {
        return kEfiUnsupported;
    }

    const auto guid = guid_to_str(ql, protocol_ptr);
    const auto guid_it = it->second.find(guid);
    if (guid_it == it->second.end()) {
        return kEfiUnsupported;
    }

    ql.mem().write_ptr(iface, guid_it->second);
    return kEfiSuccess;
}

// protocols/common.py LocateProtocol
std::optional<std::uint64_t> hook_locate_protocol(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto protocol_ptr = params.at(0).second;
    const auto iface = params.at(2).second;

    const auto guid = guid_to_str(ql, protocol_ptr);
    for (const auto& [handle, guid_dic] : ctx.protocols) {
        const auto it = guid_dic.find(guid);
        if (it != guid_dic.end()) {
            ql.mem().write_ptr(iface, it->second);
            return kEfiSuccess;
        }
    }

    return kEfiNotFound;
}

// utils.py signal_event (the Set flag + the notify_list append; the
// notify-pump ride lands with the event-callback slice)
void signal_event_impl(Qiling& ql, std::uint64_t event_id) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    auto& event = loader.events[event_id];

    if (event["Set"] == 0) {
        event["Set"] = 1;
        loader.notify_list.emplace_back(event_id, event["NotifyFunction"],
                                        std::vector<std::uint64_t>{event_id, event["NotifyContext"]});
    }
}

// bs.py hook_GetMemoryMap (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_get_memory_map(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py CreateEvent (the shared CreateEvent/CreateEventEx body)
std::optional<std::uint64_t> hook_create_event(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    // the upstream ids ride len(events) — the id REUSES after a CloseEvent
    // shrinks the registry (the upstream shape verbatim)
    const auto event_id = static_cast<std::uint64_t>(loader.events.size());
    auto& event = loader.events[event_id];
    event["NotifyFunction"] = params.at(2).second;
    event["NotifyContext"] = params.at(3).second;
    event["Set"] = 0;
    ql.mem().write_ptr(params.at(4).second, event_id);
    return kEfiSuccess;
}

// bs.py hook_SetTimer (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_set_timer(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_WaitForEvent (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_wait_for_event(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_SignalEvent
std::optional<std::uint64_t> hook_signal_event(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    const auto event_id = params.at(0).second;

    if (loader.events.find(event_id) == loader.events.end()) {
        return kEfiInvalidParameter;
    }

    signal_event_impl(ql, event_id);
    return kEfiSuccess;
}

// bs.py hook_CloseEvent
std::optional<std::uint64_t> hook_close_event(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    const auto event_id = params.at(0).second;

    if (loader.events.find(event_id) == loader.events.end()) {
        return kEfiInvalidParameter;
    }

    loader.events.erase(event_id);
    loader.event_guids.erase(event_id);
    return kEfiSuccess;
}

// bs.py hook_CheckEvent — the upstream reads events[event_id]["Set"] with
// no membership check (a missing id KeyErrors upstream); the port's
// operator[] default shape answers EFI_NOT_READY for the missing id
std::optional<std::uint64_t> hook_check_event(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    const auto event_id = params.at(0).second;

    return loader.events[event_id]["Set"] != 0 ? kEfiSuccess : kEfiNotReady;
}

// protocols/common.py ReinstallProtocolInterface
std::optional<std::uint64_t> hook_reinstall_protocol_interface(Qiling& ql, std::uint64_t,
                                                               const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto handle = params.at(0).second;

    const auto handle_it = ctx.protocols.find(handle);
    if (handle_it == ctx.protocols.end()) {
        return kEfiNotFound;
    }

    const auto guid = guid_to_str(ql, params.at(1).second);
    auto& dic = handle_it->second;
    if (dic.find(guid) == dic.end()) {
        return kEfiNotFound;
    }

    dic[guid] = params.at(3).second;
    return kEfiSuccess;
}

// protocols/common.py UninstallProtocolInterface
std::optional<std::uint64_t> hook_uninstall_protocol_interface(Qiling& ql, std::uint64_t,
                                                               const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto handle = params.at(0).second;

    const auto handle_it = ctx.protocols.find(handle);
    if (handle_it == ctx.protocols.end()) {
        return kEfiNotFound;
    }

    const auto guid = guid_to_str(ql, params.at(1).second);
    auto& dic = handle_it->second;
    const auto guid_it = dic.find(guid);
    if (guid_it == dic.end()) {
        return kEfiNotFound;
    }

    dic.erase(guid_it);
    return kEfiSuccess;
}

// bs.py hook_RegisterProtocolNotify
std::optional<std::uint64_t> hook_register_protocol_notify(Qiling& ql, std::uint64_t,
                                                           const QlFunctionCall::Params& params) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    const auto event_id = params.at(1).second;

    if (loader.events.find(event_id) == loader.events.end()) {
        return kEfiInvalidParameter;
    }

    loader.event_guids[event_id] = guid_to_str(ql, params.at(0).second);
    return kEfiSuccess;
}

// protocols/common.py LocateHandles (the (buffer_size, handles) pair)
std::pair<std::uint64_t, std::vector<std::uint64_t>> locate_handles(
    os::uefi::UefiContext& ctx, int search_type, const std::string& protocol) {
    std::vector<std::uint64_t> handles;

    if (search_type == 0) {  // EFI_LOCATE_SEARCH_TYPE::AllHandles
        for (const auto& [handle, _] : ctx.protocols) {
            (void)_;
            handles.push_back(handle);
        }
    } else if (search_type == 2) {  // ByProtocol
        for (const auto& [handle, guid_dic] : ctx.protocols) {
            if (guid_dic.find(protocol) != guid_dic.end()) {
                handles.push_back(handle);
            }
        }
    }

    const auto buffer_size = handles.size() * 8;  // the pointer-size handles
    return {buffer_size, std::move(handles)};
}

// bs.py hook_LocateHandle (the LocateHandles + the buffer flow)
std::optional<std::uint64_t> hook_locate_handle(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto search_type = static_cast<int>(params.at(0).second);
    const auto protocol = guid_to_str(ql, params.at(1).second);
    const auto buffer_size_ptr = params.at(3).second;
    const auto buffer = params.at(4).second;

    const auto [buffer_size, handles] = locate_handles(ctx, search_type, protocol);
    if (handles.empty()) {
        return kEfiNotFound;
    }

    if (ql.mem().read_ptr(buffer_size_ptr) >= buffer_size) {
        auto address = buffer;
        for (const auto handle : handles) {
            ql.mem().write_ptr(address, handle);
            address += 8;
        }
        return kEfiSuccess;
    }

    ql.mem().write_ptr(buffer_size_ptr, buffer_size);
    return kEfiBufferTooSmall;
}

// bs.py hook_LocateDevicePath (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_locate_device_path(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// protocols/common.py InstallConfigurationTable (the raw GUID-bytes shape:
// the entry rides the caller's 16 mixed-endian bytes verbatim)
std::optional<std::uint64_t> hook_install_configuration_table(Qiling& ql, std::uint64_t,
                                                              const QlFunctionCall::Params& params) {
    auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    const auto guid_ptr = params.at(0).second;
    const auto table = params.at(1).second;

    if (guid_ptr == 0) {
        return kEfiInvalidParameter;
    }

    const auto st = loader.gST;
    const auto nitems_addr = st + 104;   // NumberOfTableEntries
    const auto base = ql.mem().read_ptr(st + 112);  // ConfigurationTable
    const auto nitems = ql.mem().read_ptr(nitems_addr);
    const auto guid_bytes = ql.mem().read(guid_ptr, 16);

    // find (the entry = the 16-byte GUID + the 8-byte VendorTable)
    std::uint64_t ptr = base;
    bool found = false;
    for (std::uint64_t i = 0; i < nitems; ++i, ptr += 24) {
        const auto entry_guid = ql.mem().read(ptr, 16);
        if (entry_guid == guid_bytes) {
            found = true;
            break;
        }
    }

    if (!found) {
        ptr = base + nitems * 24;
        ql.mem().write_ptr(nitems_addr, nitems + 1);
    }

    ql.mem().write(ptr, guid_bytes);
    ql.mem().write_ptr(ptr + 16, table);
    return kEfiSuccess;
}

// bs.py hook_LoadImage (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_load_image(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_StartImage (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_start_image(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_Exit (the emu_stop + SUCCESS shape)
std::optional<std::uint64_t> hook_exit(Qiling& ql, std::uint64_t, const QlFunctionCall::Params&) {
    ql.emu_stop();
    return kEfiSuccess;
}

// bs.py hook_UnloadImage (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_unload_image(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_ExitBootServices (the emu_stop + SUCCESS shape; the cleanup
// TODO note verbatim)
std::optional<std::uint64_t> hook_exit_boot_services(Qiling& ql, std::uint64_t, const QlFunctionCall::Params&) {
    ql.emu_stop();
    // TODO(upstream): cleanup BS tables and data, and notify signal list
    // gEfiEventExitBootServicesGuid
    return kEfiSuccess;
}

// bs.py hook_GetNextMonotonicCount
std::optional<std::uint64_t> hook_get_next_monotonic_count(Qiling& ql, std::uint64_t,
                                                           const QlFunctionCall::Params& params) {
    auto& os_uefi = static_cast<QlOsUefi&>(ql.os());
    os_uefi.monotonic_count += 1;
    ql.mem().write_ptr(params.at(0).second, os_uefi.monotonic_count, 8);
    return kEfiSuccess;
}

// bs.py hook_Stall (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_stall(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_SetWatchdogTimer (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_set_watchdog_timer(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_ConnectController (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_connect_controller(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_DisconnectController (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_disconnect_controller(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_OpenProtocol (the common.LocateProtocol body over the
// OpenProtocol param layout: the Protocol at 1, the Interface at 2)
std::optional<std::uint64_t> hook_open_protocol(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto protocol_ptr = params.at(1).second;
    const auto iface = params.at(2).second;

    const auto guid = guid_to_str(ql, protocol_ptr);
    for (const auto& [handle, guid_dic] : ctx.protocols) {
        (void)handle;
        const auto it = guid_dic.find(guid);
        if (it != guid_dic.end()) {
            ql.mem().write_ptr(iface, it->second);
            return kEfiSuccess;
        }
    }

    return kEfiNotFound;
}

// bs.py hook_CloseProtocol (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_close_protocol(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_OpenProtocolInformation (the verbatim EFI_NOT_FOUND stub)
std::optional<std::uint64_t> hook_open_protocol_information(Qiling&, std::uint64_t,
                                                            const QlFunctionCall::Params&) {
    return kEfiNotFound;
}

// bs.py hook_ProtocolsPerHandle (the verbatim SUCCESS stub)
std::optional<std::uint64_t> hook_protocols_per_handle(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

// bs.py hook_LocateHandleBuffer
std::optional<std::uint64_t> hook_locate_handle_buffer(Qiling& ql, std::uint64_t,
                                                       const QlFunctionCall::Params& params) {
    auto& ctx = *static_cast<loader::QlLoaderPE_UEFI&>(ql.loader()).dxe_context;
    const auto search_type = static_cast<int>(params.at(0).second);
    const auto protocol = guid_to_str(ql, params.at(1).second);
    const auto no_handles_ptr = params.at(3).second;
    const auto buffer_ptr = params.at(4).second;

    const auto [buffer_size, handles] = locate_handles(ctx, search_type, protocol);
    ql.mem().write_ptr(no_handles_ptr, handles.size());

    if (handles.empty()) {
        return kEfiNotFound;
    }

    const auto& loader = static_cast<loader::QlLoaderPE_UEFI&>(ql.loader());
    const auto address = loader.dxe_context->heap->alloc(buffer_size);
    ql.mem().write_ptr(buffer_ptr, address);

    if (address == 0) {
        return kEfiOutOfResources;
    }

    auto ptr = address;
    for (const auto handle : handles) {
        ql.mem().write_ptr(ptr, handle);
        ptr += 8;
    }

    return kEfiSuccess;
}

// bs.py hook_CalculateCrc32 (the binascii.crc32 shape: the standard CRC-32)
std::optional<std::uint64_t> hook_calculate_crc32(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto data_ptr = params.at(0).second;
    const auto data_size = params.at(1).second;
    const auto crc_ptr = params.at(2).second;

    const auto data = ql.mem().read(data_ptr, static_cast<std::size_t>(data_size));

    std::uint32_t crc = 0xFFFFFFFFu;
    for (const auto byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    crc ^= 0xFFFFFFFFu;

    ql.mem().write_ptr(crc_ptr, crc, 4);
    return kEfiSuccess;
}

// bs.py hook_CopyMem
std::optional<std::uint64_t> hook_copy_mem(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto dst = params.at(0).second;
    const auto src = params.at(1).second;
    const auto length = params.at(2).second;

    ql.mem().write(dst, ql.mem().read(src, length));
    return std::nullopt;  // the upstream body has no return (None -> the None status)
}

// bs.py hook_SetMem
std::optional<std::uint64_t> hook_set_mem(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto buffer = params.at(0).second;
    const auto value = static_cast<std::uint8_t>(params.at(2).second & 0xff);
    const auto size = params.at(1).second;

    ql.mem().write(buffer, std::vector<std::uint8_t>(size, value));
    return std::nullopt;
}

// rt.py hook_GetTime (the EFI_TIME struct write: the local wall clock with
// the unspecified timezone; the 16-byte layout Year u16/Month u8/Day u8/
// Hour u8/Minute u8/Second u8/Pad1 u8/Nanosecond u32/TimeZone u16/Daylight
// u8/Pad2 u8)
std::optional<std::uint64_t> hook_get_time(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto time_ptr = params.at(0).second;

    if (time_ptr == 0) {
        return kEfiInvalidParameter;
    }

    const auto now = std::time(nullptr);
    const auto& lt = *std::localtime(&now);

    std::vector<std::uint8_t> efi_time(16, 0);
    efi_time[0] = lt.tm_year + 1900 & 0xff;
    efi_time[1] = (lt.tm_year + 1900) >> 8;
    efi_time[2] = static_cast<std::uint8_t>(lt.tm_mon + 1);
    efi_time[3] = static_cast<std::uint8_t>(lt.tm_mday);
    efi_time[4] = static_cast<std::uint8_t>(lt.tm_hour);
    efi_time[5] = static_cast<std::uint8_t>(lt.tm_min);
    efi_time[6] = static_cast<std::uint8_t>(lt.tm_sec);
    // the Pad1 + the Nanosecond (0) + the TimeZone = 0xffff (the unspecified)
    efi_time[12] = 0xff;
    efi_time[13] = 0xff;
    // the Daylight + the Pad2 stay zero

    ql.mem().write(time_ptr, efi_time);
    return kEfiSuccess;
}

// rt.py hook_GetVariable (the variable store rides ql.env verbatim; the
// name arrives as the raw WSTRING pointer — the port reads it with the
// utils read_wstring, the upstream dxeapi resolves the accessor)
std::optional<std::uint64_t> hook_get_variable(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto var_name = os::QlOsUtils::read_wstring(ql, params.at(0).second);
    const auto vendor_guid = os::QlOsUtils::read_guid(ql, params.at(1).second);
    const auto attr_ptr = params.at(2).second;
    const auto data_size_ptr = params.at(3).second;
    const auto data_ptr = params.at(4).second;

    (void)vendor_guid;  // the namespace TODO verbatim

    if (var_name.empty() || vendor_guid.empty() || data_size_ptr == 0) {
        return kEfiInvalidParameter;
    }

    auto& env = ql.env_mut();
    const auto it = env.find(var_name);
    if (it == env.end()) {
        return kEfiNotFound;
    }

    const auto& var_data = it->second;
    const auto data_size = var_data.size();
    const auto buff_size = ql.mem().read_ptr(data_size_ptr);

    if (attr_ptr != 0) {
        // FIXME verbatim: the default attribute set until the attributed
        // variables are managed
        const auto attributes = static_cast<std::uint64_t>(kEfiVariableNonVolatile | kEfiVariableBootserviceAccess |
                                                          kEfiVariableRuntimeAccess);
        ql.mem().write_ptr(attr_ptr, attributes, 4);
    }

    ql.mem().write_ptr(data_size_ptr, data_size);

    if (buff_size < data_size) {
        return kEfiBufferTooSmall;
    }

    if (data_ptr != 0) {
        ql.mem().write(data_ptr, std::vector<std::uint8_t>(var_data.begin(), var_data.end()));
    }

    return kEfiSuccess;
}

// rt.py hook_GetNextVariableName (the nvvars ride the env["Names"] entry;
// the upstream keeps a python list object — the port serializes the names
// \0-joined; a missing Names entry returns EFI_NOT_FOUND where the
// upstream's KeyError would abort)
std::optional<std::uint64_t> hook_get_next_variable_name(Qiling& ql, std::uint64_t,
                                                         const QlFunctionCall::Params& params) {
    const auto var_name_size_ptr = params.at(0).second;
    const auto var_name_ptr = params.at(1).second;
    const auto vendor_guid = os::QlOsUtils::read_guid(ql, params.at(2).second);

    if (var_name_size_ptr == 0 || var_name_ptr == 0 || vendor_guid.empty()) {
        return kEfiInvalidParameter;
    }

    auto& env = ql.env_mut();
    const auto names_it = env.find("Names");
    if (names_it == env.end()) {
        return kEfiNotFound;
    }

    const auto name_size = ql.mem().read_ptr(var_name_size_ptr);

    // the \0-joined registry: the empty segments delimit the names
    std::vector<std::string> nvvars;
    std::string cur;
    for (const auto ch : names_it->second) {
        if (ch == '\0') {
            if (!cur.empty()) {
                nvvars.push_back(cur);
            }
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) {
        nvvars.push_back(cur);
    }

    // the last-read name rides var_name_ptr as the wide string
    std::string last;
    {
        const auto raw = ql.mem().read(var_name_ptr, static_cast<std::size_t>(name_size));
        for (std::size_t i = 0; i + 1 < raw.size(); i += 2) {
            if (raw[i] == 0) {
                break;
            }
            last.push_back(static_cast<char>(raw[i]));
        }
    }

    std::size_t idx = nvvars.size();
    for (std::size_t i = 0; i < nvvars.size(); ++i) {
        if (nvvars[i] == last) {
            idx = i;
            break;
        }
    }
    if (idx == nvvars.size()) {
        return kEfiNotFound;
    }
    if (idx == nvvars.size() - 1) {
        return kEfiNotFound;
    }

    const auto& next = nvvars[idx + 1];
    // the wide-encoded new name (the char + the \x00 terminator per char)
    std::vector<std::uint8_t> encoded;
    for (const auto ch : next) {
        encoded.push_back(static_cast<std::uint8_t>(ch));
        encoded.push_back(0);
    }
    encoded.push_back(0);
    encoded.push_back(0);

    if (encoded.size() > name_size) {
        ql.mem().write_ptr(var_name_size_ptr, encoded.size());
        return kEfiBufferTooSmall;
    }

    ql.mem().write(var_name_ptr, encoded);
    return kEfiSuccess;
}

// rt.py hook_SetVariable
std::optional<std::uint64_t> hook_set_variable(Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) {
    const auto var_name = os::QlOsUtils::read_wstring(ql, params.at(0).second);
    const auto attributes = static_cast<std::uint32_t>(params.at(2).second);
    const auto data_size = params.at(3).second;
    const auto data_ptr = params.at(4).second;

    if (var_name.empty()) {
        return kEfiInvalidParameter;
    }

    if (attributes & kEfiVariableAuthenticatedWriteAccess) {
        return kEfiUnsupported;  // the deprecated path verbatim
    }

    const bool append = (attributes & kEfiVariableAppendWrite) != 0;
    const bool auth = (attributes & (kEfiVariableTimeBasedAuthenticatedWriteAccess |
                                     kEfiVariableEnhancedAuthenticatedWriteAccess)) != 0;

    auto& env = ql.env_mut();

    // the data_size 0 deletes the var when not auth/append (the verbatim
    // TODO notes ride the upstream comments)
    if (data_size == 0 && !(auth || append)) {
        const auto it = env.find(var_name);
        if (it == env.end()) {
            return kEfiNotFound;
        }
        env.erase(it);
    }

    std::string data;
    if (data_size != 0) {
        const auto raw = ql.mem().read(data_ptr, static_cast<std::size_t>(data_size));
        data.assign(raw.begin(), raw.end());
    }

    if (append) {
        const auto it = env.find(var_name);
        if (it == env.end()) {
            return kEfiNotFound;
        }
        data = it->second + data;
    }

    env[var_name] = std::move(data);
    return kEfiSuccess;
}

// rt.py hook_GetNextHighMonotonicCount
std::optional<std::uint64_t> hook_get_next_high_monotonic_count(Qiling& ql, std::uint64_t,
                                                                const QlFunctionCall::Params& params) {
    auto& os_uefi = static_cast<QlOsUefi&>(ql.os());
    os_uefi.monotonic_count += 0x0000000100000000ull;
    const auto hmc = (os_uefi.monotonic_count >> 32) & 0xffffffff;
    ql.mem().write_ptr(params.at(0).second, hmc, 4);
    return kEfiSuccess;
}

// rt.py hook_ResetSystem (the emu_stop shape)
std::optional<std::uint64_t> hook_reset_system(Qiling& ql, std::uint64_t, const QlFunctionCall::Params&) {
    ql.emu_stop();
    return kEfiSuccess;
}

// rt.py hook_SetTime / hook_GetWakeupTime / hook_SetWakeupTime /
// hook_UpdateCapsule / hook_QueryCapsuleCapabilities / hook_QueryVariableInfo
// (the verbatim SUCCESS stubs)
std::optional<std::uint64_t> hook_rt_success_stub(Qiling&, std::uint64_t, const QlFunctionCall::Params&) {
    return kEfiSuccess;
}

}  // namespace

void install_service_table(Qiling& ql, UefiContext& context, std::uint64_t base,
                           const ServiceDescriptor* fields, std::size_t count) {
    // utils.py init_struct: the field addresses ride the descriptor order;
    // the hooked fields carry their own address as the value (written into
    // the table image)
    std::uint64_t offset = kTableHeaderSize;
    for (std::size_t i = 0; i < count; ++i) {
        const auto& field = fields[i];
        const std::uint64_t field_addr = base + offset;
        offset += 8;  // the function-pointer fields are one pointer each

        if (!field.hook) {
            continue;  // the None field stays zero
        }

        auto& os_uefi = static_cast<QlOsUefi&>(ql.os());
        (void)context;
        ql.mem().write_ptr(field_addr, field_addr, 8);

        // the captures ride the std::function (the copies owned by the hook
        // object; the ql rides by pointer)
        std::string fname(field.name);
        auto proto = field.params;
        auto hook = field.hook;
        Qiling* ql_ptr = &ql;
        const auto cb = [ql_ptr, fname, proto, hook]() -> int {
            return dispatch_service(ql_ptr, fname, hook, proto);
        };
        ql.hook_address(cb, field_addr);
        os_uefi.uefi_installed_fields_.push_back(field_addr);
    }
}

void initialize_system_table(Qiling& ql, UefiContext& context, std::uint64_t gST) {
    // st.py initialize: the layout
    const std::uint64_t sti = gST + kSystemTableSize;
    const std::uint64_t sto = sti + kSimpleTextInSize;
    const std::uint64_t gRT = sto + kSimpleTextOutSize;
    const std::uint64_t gBS = gRT + kRuntimeServicesSize;
    const std::uint64_t gDS = gBS + kBootServicesSize;
    const std::uint64_t cfg = gDS + kDsServicesSize;

    // the simple-text protocols: the descriptors ride the slice-3 hooks
    // (the Reset/ReadKeyStroke/OutputString bodies land there); the fields
    // stay zero in this slice
    (void)sti;
    (void)sto;

    // EFI_SYSTEM_TABLE: the ConIn/ConOut/RT/BS cells + the empty conftable
    auto& mem = ql.mem();
    const auto put64 = [&mem](std::uint64_t addr, std::uint64_t v) { mem.write_ptr(addr, v, 8); };
    put64(gST + 40, sti);    // ConsoleInHandle
    put64(gST + 48, sti);    // ConIn
    put64(gST + 56, 0);      // ConsoleOutHandle
    put64(gST + 64, sto);    // ConOut
    put64(gST + 72, 0);      // StandardErrorHandle
    put64(gST + 80, 0);      // StdErr
    put64(gST + 88, gRT);    // RuntimeServices
    put64(gST + 96, gBS);    // BootServices
    put64(gST + 104, 0);     // NumberOfTableEntries
    put64(gST + 112, cfg);   // ConfigurationTable

    // the boot services table: the TPL pair (the first hooks; the rest of
    // the BS fields land with the handler slices)
    static const std::vector<ServiceDescriptor> bs_fields = {
        {"RaiseTPL",
         {{"NewTpl", PARAM_INT64}},
         [](Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) -> std::optional<std::uint64_t> {
             auto& os_uefi = static_cast<QlOsUefi&>(ql.os());
             const auto prev = os_uefi.tpl;
             os_uefi.tpl = static_cast<unsigned>(params.at(0).second);
             return prev;
         }},
        {"RestoreTPL",
         {{"OldTpl", PARAM_INT64}},
         [](Qiling& ql, std::uint64_t, const QlFunctionCall::Params& params) -> std::optional<std::uint64_t> {
             auto& os_uefi = static_cast<QlOsUefi&>(ql.os());
             os_uefi.tpl = static_cast<unsigned>(params.at(0).second);
             return std::nullopt;
         }},
        {"AllocatePages",
         {{"Type", PARAM_INT32}, {"MemoryType", PARAM_INT32}, {"Pages", PARAM_INT64}, {"Memory", PARAM_INTN}},
         hook_allocate_pages},
        {"FreePages",
         {{"Memory", PARAM_INT64}, {"Pages", PARAM_INT64}},
         hook_free_pages},
        {"GetMemoryMap",
         {{"MemoryMapSize", PARAM_INTN}, {"MemoryMap", PARAM_INTN}, {"MapKey", PARAM_INTN},
          {"DescriptorSize", PARAM_INTN}, {"DescriptorVersion", PARAM_INTN}},
         hook_get_memory_map},
        {"AllocatePool",
         {{"MemoryType", PARAM_INT32}, {"Size", PARAM_INT64}, {"Buffer", PARAM_INTN}},
         hook_allocate_pool},
        {"FreePool",
         {{"Buffer", PARAM_INTN}},
         hook_free_pool},
        {"CreateEvent",
         {{"Type", PARAM_INT32}, {"NotifyTpl", PARAM_INT32}, {"NotifyFunction", PARAM_INTN},
          {"NotifyContext", PARAM_INTN}, {"Event", PARAM_INTN}},
         hook_create_event},
        {"SetTimer",
         {{"Event", PARAM_INTN}, {"Type", PARAM_INT64}, {"TriggerTime", PARAM_INT64}},
         hook_set_timer},
        {"WaitForEvent",
         {{"NumberOfEvents", PARAM_INT64}, {"Event", PARAM_INTN}, {"Index", PARAM_INTN}},
         hook_wait_for_event},
        {"SignalEvent", {{"Event", PARAM_INTN}}, hook_signal_event},
        {"CloseEvent", {{"Event", PARAM_INTN}}, hook_close_event},
        {"CheckEvent", {{"Event", PARAM_INTN}}, hook_check_event},
        {"InstallProtocolInterface",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"InterfaceType", PARAM_INT32},
          {"Interface", PARAM_INTN}},
         hook_install_protocol_interface},
        {"ReinstallProtocolInterface",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"OldInterface", PARAM_INTN},
          {"NewInterface", PARAM_INTN}},
         hook_reinstall_protocol_interface},
        {"UninstallProtocolInterface",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"Interface", PARAM_INTN}},
         hook_uninstall_protocol_interface},
        {"HandleProtocol",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"Interface", PARAM_INTN}},
         hook_handle_protocol},
        {"Reserved", {}, {}},
        {"RegisterProtocolNotify",
         {{"Protocol", PARAM_INTN}, {"Event", PARAM_INTN}, {"Registration", PARAM_INTN}},
         hook_register_protocol_notify},
        {"LocateHandle",
         {{"SearchType", PARAM_INT32}, {"Protocol", PARAM_INTN}, {"SearchKey", PARAM_INTN},
          {"BufferSize", PARAM_INTN}, {"Buffer", PARAM_INTN}},
         hook_locate_handle},
        {"LocateDevicePath",
         {{"Protocol", PARAM_INTN}, {"DevicePath", PARAM_INTN}, {"Device", PARAM_INTN}},
         hook_locate_device_path},
        {"InstallConfigurationTable",
         {{"Guid", PARAM_INTN}, {"Table", PARAM_INTN}},
         hook_install_configuration_table},
        {"LoadImage",
         {{"BootPolicy", PARAM_INT32}, {"ParentImageHandle", PARAM_INTN}, {"DevicePath", PARAM_INTN},
          {"SourceBuffer", PARAM_INTN}, {"SourceSize", PARAM_INT64}, {"ImageHandle", PARAM_INTN}},
         hook_load_image},
        {"StartImage",
         {{"ImageHandle", PARAM_INTN}, {"ExitDataSize", PARAM_INTN}, {"ExitData", PARAM_INTN}},
         hook_start_image},
        {"Exit",
         {{"ImageHandle", PARAM_INTN}, {"ExitStatus", PARAM_INT64}, {"ExitDataSize", PARAM_INT64},
          {"ExitData", PARAM_INTN}},
         hook_exit},
        {"UnloadImage", {{"ImageHandle", PARAM_INTN}}, hook_unload_image},
        {"ExitBootServices", {{"ImageHandle", PARAM_INTN}, {"MapKey", PARAM_INT64}}, hook_exit_boot_services},
        {"GetNextMonotonicCount", {{"Count", PARAM_INTN}}, hook_get_next_monotonic_count},
        {"Stall", {{"Microseconds", PARAM_INT64}}, hook_stall},
        {"SetWatchdogTimer",
         {{"Timeout", PARAM_INT64}, {"WatchdogCode", PARAM_INT64}, {"DataSize", PARAM_INT64},
          {"WatchdogData", PARAM_INTN}},
         hook_set_watchdog_timer},
        {"ConnectController",
         {{"ControllerHandle", PARAM_INTN}, {"DriverImageHandle", PARAM_INTN}, {"RemainingDevicePath", PARAM_INTN},
          {"Recursive", PARAM_INT32}},
         hook_connect_controller},
        {"DisconnectController",
         {{"ControllerHandle", PARAM_INTN}, {"DriverImageHandle", PARAM_INTN}, {"ChildHandle", PARAM_INTN}},
         hook_disconnect_controller},
        {"OpenProtocol",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"Interface", PARAM_INTN},
          {"AgentHandle", PARAM_INTN}, {"ControllerHandle", PARAM_INTN}, {"Attributes", PARAM_INT32}},
         hook_open_protocol},
        {"CloseProtocol",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"AgentHandle", PARAM_INTN},
          {"ControllerHandle", PARAM_INTN}},
         hook_close_protocol},
        {"OpenProtocolInformation",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"EntryBuffer", PARAM_INTN},
          {"EntryCount", PARAM_INTN}},
         hook_open_protocol_information},
        {"ProtocolsPerHandle",
         {{"Handle", PARAM_INTN}, {"ProtocolBuffer", PARAM_INTN}, {"ProtocolBufferCount", PARAM_INTN}},
         hook_protocols_per_handle},
        {"LocateHandleBuffer",
         {{"SearchType", PARAM_INT32}, {"Protocol", PARAM_INTN}, {"SearchKey", PARAM_INTN},
          {"NoHandles", PARAM_INTN}, {"Buffer", PARAM_INTN}},
         hook_locate_handle_buffer},
        {"LocateProtocol",
         {{"Protocol", PARAM_INTN}, {"Registration", PARAM_INTN}, {"Interface", PARAM_INTN}},
         hook_locate_protocol},
        // the varargs walk + the notify-pump ride the event-callback slice
        {"InstallMultipleProtocolInterfaces", {}, {}},
        {"UninstallMultipleProtocolInterfaces", {}, {}},
        {"CalculateCrc32",
         {{"Data", PARAM_INTN}, {"DataSize", PARAM_INT64}, {"Crc32", PARAM_INTN}},
         hook_calculate_crc32},
        {"CopyMem",
         {{"Destination", PARAM_INTN}, {"Source", PARAM_INTN}, {"Length", PARAM_INTN}},
         hook_copy_mem},
        {"SetMem",
         {{"Buffer", PARAM_INTN}, {"Size", PARAM_INTN}, {"Value", PARAM_INT8}},
         hook_set_mem},
        {"CreateEventEx",
         {{"Type", PARAM_INT32}, {"NotifyTpl", PARAM_INT64}, {"NotifyFunction", PARAM_INTN},
          {"NotifyContext", PARAM_INTN}, {"EventGroup", PARAM_INTN}, {"Event", PARAM_INTN}},
         hook_create_event},
    };
    install_service_table(ql, context, gBS, bs_fields.data(), bs_fields.size());

    // the runtime services table (rt.py initialize: the full descriptor)
    static const std::vector<ServiceDescriptor> rt_fields = {
        {"GetTime", {{"Time", PARAM_INTN}, {"Capabilities", PARAM_INTN}}, hook_get_time},
        {"SetTime", {{"Time", PARAM_INTN}}, hook_rt_success_stub},
        {"GetWakeupTime",
         {{"Enabled", PARAM_INTN}, {"Pending", PARAM_INTN}, {"Time", PARAM_INTN}},
         hook_rt_success_stub},
        {"SetWakeupTime",
         {{"Enable", PARAM_INT32}, {"Time", PARAM_INTN}},
         hook_rt_success_stub},
        {"SetVirtualAddressMap",
         {{"MemoryMapSize", PARAM_INT32}, {"DescriptorSize", PARAM_INT32}, {"DescriptorVersion", PARAM_INT32},
          {"VirtualMap", PARAM_INTN}},
         hook_rt_success_stub},
        {"ConvertPointer",
         {{"DebugDisposition", PARAM_INTN}, {"Address", PARAM_INTN}},
         hook_rt_success_stub},
        {"GetVariable",
         {{"VariableName", PARAM_PTRX + 2}, {"VendorGuid", PARAM_PTRX + 3}, {"Attributes", PARAM_INTN},
          {"DataSize", PARAM_INTN}, {"Data", PARAM_INTN}},
         hook_get_variable},
        {"GetNextVariableName",
         {{"VariableNameSize", PARAM_INTN}, {"VariableName", PARAM_INTN}, {"VendorGuid", PARAM_PTRX + 3}},
         hook_get_next_variable_name},
        {"SetVariable",
         {{"VariableName", PARAM_PTRX + 2}, {"VendorGuid", PARAM_PTRX + 3}, {"Attributes", PARAM_INT32},
          {"DataSize", PARAM_INTN}, {"Data", PARAM_INTN}},
         hook_set_variable},
        {"GetNextHighMonotonicCount", {{"HighCount", PARAM_INTN}}, hook_get_next_high_monotonic_count},
        {"ResetSystem",
         {{"ResetType", PARAM_INT32}, {"ResetStatus", PARAM_INT64}, {"DataSize", PARAM_INTN},
          {"ResetData", PARAM_INTN}},
         hook_reset_system},
        {"UpdateCapsule",
         {{"CapsuleHeaderArray", PARAM_INTN}, {"CapsuleCount", PARAM_INTN}, {"ScatterGatherList", PARAM_INT64}},
         hook_rt_success_stub},
        {"QueryCapsuleCapabilities",
         {{"CapsuleHeaderArray", PARAM_INTN}, {"CapsuleCount", PARAM_INTN}, {"MaximumCapsuleSize", PARAM_INTN},
          {"ResetType", PARAM_INTN}},
         hook_rt_success_stub},
        {"QueryVariableInfo",
         {{"Attributes", PARAM_INT32}, {"MaximumVariableStorageSize", PARAM_INTN},
          {"RemainingVariableStorageSize", PARAM_INTN}, {"MaximumVariableSize", PARAM_INTN}},
         hook_rt_success_stub},
    };
    install_service_table(ql, context, gRT, rt_fields.data(), rt_fields.size());
}

}  // namespace uefi
}  // namespace os
}  // namespace qiling
