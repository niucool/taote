// loader/pe_uefi.py — the uefi module loader (the slice-1 shape)
//
// The DXE/SMM environments initialize per the upstream shape (the heap, the
// stack, the next-image cursor, the 4KiB gST/gSmst static allocs); the
// service-table structure fills (st.initialize / bs.initialize / rt.initialize)
// land with the service-table slice. The module map+load rides the LIEF parse
// with the per-section perms when section-aligned, the map-all fallback
// otherwise (the upstream __map_sections/__map_all split verbatim).

#pragma once

#include "qiling/loader/loader.hpp"
#include "qiling/os/uefi/context.hpp"

namespace qiling {
namespace loader {

class QlLoaderPE_UEFI final : public QlLoader {
public:
    explicit QlLoaderPE_UEFI(Qiling* ql);

    void run() override;

    // loader/pe_uefi.py map_and_load: map a module at the context's
    // next_image_base (or the image's own base when non-zero) and enqueue or
    // execute it
    void map_and_load(const std::string& path, os::uefi::UefiContext& context, bool exec_now = false);

    // loader/pe_uefi.py execute_module: the entry-point call with the
    // (ImageHandle, SystemTable) args
    void execute_module(const std::string& path, std::uint64_t image_base, std::uint64_t entry_point,
                        os::uefi::UefiContext& context, std::optional<std::uint64_t> eoe_trap);

    // loader/pe_uefi.py execute_next_module: pop the queue and run the next
    // module (the notify hooks ride it)
    void execute_next_module();

    // loader/pe_uefi.py call_function
    void call_function(std::uint64_t addr, const std::vector<std::pair<int, std::uint64_t>>& args,
                       std::optional<std::uint64_t> ret);

    // the module queue (the (path, base, entry, context) tuples)
    struct ModuleInfo {
        std::string path;
        std::uint64_t image_base = 0;
        std::uint64_t entry_point = 0;
        os::uefi::UefiContext* context = nullptr;
    };
    std::vector<ModuleInfo> modules;

    // the event registry (the CreateEvent/SetTimer surface lands with the
    // services; the map rides here for the utils.signal_event shape)
    std::map<std::uint64_t, std::map<std::string, std::uint64_t>> events;
    // the RegisterProtocolNotify-set protocol GUID per event (the upstream
    // dict value rides a string; the port keys it beside the event map)
    std::map<std::uint64_t, std::string> event_guids;
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::vector<std::uint64_t>>> notify_list;

    // the TPL level (the RaiseTPL/RestoreTPL surface)
    unsigned tpl = 4;  // TPL_APPLICATION

    // the global tables (set by the service-table slice; the gST rides the
    // module args)
    std::uint64_t gST = 0;

    std::unique_ptr<os::uefi::DxeContext> dxe_context;
    std::unique_ptr<os::uefi::SmmContext> smm_context;
    os::uefi::UefiContext* context = nullptr;

private:
    void init_dxe_environment();
    void init_smm_environment();
    void register_eoe_trap(std::uint64_t address);
    void install_loaded_image_protocol(std::uint64_t image_base, std::uint64_t image_size);
    std::string running_module_path_;
};

}  // namespace loader
}  // namespace qiling
