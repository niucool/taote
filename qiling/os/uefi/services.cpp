// os/uefi/services.cpp — the service-table implementation (the slice-2
// shape: the descriptor walk + the fncc wrapper dispatch + the BS TPL pair)

#include "qiling/os/uefi/services.hpp"

#include <cstring>

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

    return kEfiUnsupported;
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
        {"GetMemoryMap", {}, {}},
        {"AllocatePool",
         {{"MemoryType", PARAM_INT32}, {"Size", PARAM_INT64}, {"Buffer", PARAM_INTN}},
         hook_allocate_pool},
        {"FreePool",
         {{"Buffer", PARAM_INTN}},
         hook_free_pool},
        {"CreateEvent", {}, {}},
        {"SetTimer", {}, {}},
        {"WaitForEvent", {}, {}},
        {"SignalEvent", {}, {}},
        {"CloseEvent", {}, {}},
        {"CheckEvent", {}, {}},
        {"InstallProtocolInterface",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"InterfaceType", PARAM_INT32},
          {"Interface", PARAM_INTN}},
         hook_install_protocol_interface},
        {"HandleProtocol",
         {{"Handle", PARAM_INTN}, {"Protocol", PARAM_INTN}, {"Interface", PARAM_INTN}},
         hook_handle_protocol},
        {"LocateProtocol",
         {{"Protocol", PARAM_INTN}, {"Registration", PARAM_INTN}, {"Interface", PARAM_INTN}},
         hook_locate_protocol},
    };
    install_service_table(ql, context, gBS, bs_fields.data(), bs_fields.size());

    // the runtime services table: the field cells stay zero until the
    // variable-services slice (the stub shape)
}

}  // namespace uefi
}  // namespace os
}  // namespace qiling
