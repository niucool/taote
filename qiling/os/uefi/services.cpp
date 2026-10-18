// os/uefi/services.cpp — the service-table implementation (the slice-2
// shape: the descriptor walk + the fncc wrapper dispatch + the BS TPL pair)

#include "qiling/os/uefi/services.hpp"

#include <cstring>

#include "qiling/os/uefi/context.hpp"
#include "qiling/os/uefi/uefi.hpp"

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
    std::fprintf(stderr, "[svc] %s at %#llx\n", fname.c_str(), static_cast<unsigned long long>(pc));

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
        const auto ret = hook(*ql, addr, params);
        return ret;
    };
    os_uefi.call(pc, fname, adapter, proto, {}, {}, false);
    std::fprintf(stderr, "[svc] %s done, pc=%#llx rsp=%#llx\n", fname.c_str(),
                 static_cast<unsigned long long>(ql->arch().regs().arch_pc()),
                 static_cast<unsigned long long>(ql->arch().regs().read("rsp")));

    // the EXIT hooks fire raw after the call
    if (onexit != nullptr) {
        (*onexit)(*ql, pc, api_name);
    }
    return 0;
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
    };
    install_service_table(ql, context, gBS, bs_fields.data(), bs_fields.size());

    // the runtime services table: the field cells stay zero until the
    // variable-services slice (the stub shape)
}

}  // namespace uefi
}  // namespace os
}  // namespace qiling
