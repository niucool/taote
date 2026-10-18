// loader/pe_uefi.py — the uefi module loader implementation (slice 1)

#include "qiling/loader/pe_uefi.hpp"

#include <algorithm>
#include <fstream>

#include <LIEF/LIEF.hpp>

#include "qiling/os/uefi/uefi.hpp"
#include "qiling/os/uefi/services.hpp"
#include "qiling/os/const.hpp"

namespace qiling {
namespace loader {

namespace {

constexpr std::uint64_t kLoadedImagePlaceholder = 0;

}  // namespace

QlLoaderPE_UEFI::QlLoaderPE_UEFI(Qiling* ql) : QlLoader(ql) {}

void QlLoaderPE_UEFI::install_loaded_image_protocol(std::uint64_t image_base, std::uint64_t image_size) {
    // loader/pe_uefi.py install_loaded_image_protocol: the descriptor rides
    // the LOADED_IMAGE_PROTOCOL profile guid; the struct write lands with
    // the protocol slice — the registry entry rides here
    auto& os_uefi = static_cast<os::uefi::QlOsUefi&>(ql_->os());
    (void)os_uefi;
    context->loaded_image_protocol_modules.push_back(image_base);
}

void QlLoaderPE_UEFI::map_and_load(const std::string& path, os::uefi::UefiContext& ctx, bool exec_now) {
    auto parsed = LIEF::PE::Parser::parse(path);
    if (parsed == nullptr) {
        throw QlErrorBase("failed to parse uefi module: " + path);
    }

    auto& mem = ql_->mem();
    const std::string image_name = std::filesystem::path(path).filename().string();

    // loader/pe_uefi.py: use the image base only if it does not point to NULL
    std::uint64_t image_base = parsed->imagebase() != 0 ? parsed->imagebase() : ctx.next_image_base;
    const std::uint64_t image_size = mem.align_up(parsed->virtual_size());

    // loader/pe_uefi.py: the base must be page-aligned
    if ((image_base % mem.pagesize()) != 0) {
        throw QlErrorBase("image base is expected to be page-aligned");
    }

    const std::uint64_t sec_alignment = parsed->optional_header().section_alignment();

    if ((sec_alignment % mem.pagesize()) == 0) {
        // __map_sections: the header + the sections, each with its perms.
        // the header blob rides the file's leading SizeOfHeaders bytes (the
        // pefile pe.header equivalent)
        std::ifstream f(path, std::ios::binary);
        const auto hdr_bytes = parsed->optional_header().sizeof_headers();
        std::vector<std::uint8_t> hdr_data(hdr_bytes);
        if (f) {
            f.read(reinterpret_cast<char*>(hdr_data.data()), static_cast<std::streamsize>(hdr_data.size()));
            hdr_data.resize(static_cast<std::size_t>(f.gcount()));
        }

        const std::uint64_t hdr_base = image_base;
        const std::uint64_t hdr_size = mem.align_up(hdr_data.size(), sec_alignment);
        mem.map(hdr_base, hdr_size, UC_PROT_READ, image_name);
        mem.write(hdr_base, hdr_data);

        for (const LIEF::PE::Section& section : parsed->sections()) {
            if (section.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_DISCARDABLE)) {
                continue;
            }
            const std::string sec_name = section.name();
            const auto sec_data = section.content();
            if (sec_data.empty()) {
                continue;
            }
            const std::uint64_t sec_base = image_base + section.virtual_address();
            const std::uint64_t sec_size = mem.align_up(sec_data.size(), sec_alignment);

            int sec_perm = 0;
            if (section.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) {
                sec_perm |= UC_PROT_READ;
            }
            if (section.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) {
                sec_perm |= UC_PROT_WRITE;
            }
            if (section.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) {
                sec_perm |= UC_PROT_EXEC;
            }
            if (sec_perm == 0) {
                sec_perm = UC_PROT_READ;
            }

            mem.map(sec_base, sec_size, static_cast<uc_prot>(sec_perm), image_name + " (" + sec_name + ")");
            mem.write(sec_base, std::vector<std::uint8_t>{sec_data.begin(), sec_data.end()});
        }
    } else {
        // __map_all: the entire file as one region
        mem.map(image_base, image_size, UC_PROT_ALL, image_name);
        // the mapped image: the sections staged at their RVAs
        for (const LIEF::PE::Section& section : parsed->sections()) {
            const auto content = section.content();
            if (content.empty()) {
                continue;
            }
            mem.write(image_base + section.virtual_address(),
                      std::vector<std::uint8_t>{content.begin(), content.end()});
        }
    }

    std::uint64_t module_entry = image_base + (parsed->entrypoint() - parsed->imagebase());

    // the debugger entry rides the first loaded module (the upstream's
    // `if self.entry_point == 0: self.entry_point = entry_point`)
    if (entry_point == 0) {
        entry_point = module_entry;
    }

    install_loaded_image_protocol(image_base, image_size);

    images.push_back(Image{image_base, image_base + image_size, std::filesystem::absolute(path).string()});

    ctx.next_image_base = image_base + image_size;

    if (exec_now) {
        execute_module(path, image_base, module_entry, ctx, std::nullopt);
    } else {
        modules.push_back(ModuleInfo{path, image_base, module_entry, &ctx});
    }
}

void QlLoaderPE_UEFI::call_function(std::uint64_t addr, const std::vector<std::pair<int, std::uint64_t>>& args,
                                    std::optional<std::uint64_t> ret) {
    auto& os_uefi = static_cast<os::uefi::QlOsUefi&>(ql_->os());
    os_uefi.fcall->call_native(addr, args, ret);
}

void QlLoaderPE_UEFI::execute_module(const std::string& path, std::uint64_t image_base, std::uint64_t entry_point,
                                     os::uefi::UefiContext& ctx, std::optional<std::uint64_t> eoe_trap) {
    // use familiar uefi names
    const std::uint64_t ImageHandle = image_base;
    const std::uint64_t SystemTable = gST;

    auto& os_uefi = static_cast<os::uefi::QlOsUefi&>(ql_->os());
    os_uefi.context = &ctx;
    context = &ctx;
    running_module_path_ = path;

    // set the stack and the frame pointers (the context's top of stack)
    const auto sp = static_cast<std::uint64_t>(ctx.top_of_stack);
    ql_->arch().regs().write("rsp", sp);
    ql_->arch().regs().write("rbp", sp);

    // the POINTER param spelling sits behind !_WIN32 in os/const.hpp; the
    // windows api slice spells it PARAM_INTN (the same value)
    call_function(entry_point,
                  {{os::PARAM_INTN, ImageHandle}, {os::PARAM_INTN, SystemTable}},
                  eoe_trap);

}

void QlLoaderPE_UEFI::execute_next_module() {
    if (modules.empty()) {
        return;
    }

    const auto mod = modules.front();
    modules.erase(modules.begin());

    auto& os_uefi = static_cast<os::uefi::QlOsUefi&>(ql_->os());
    if (os_uefi.notify_before_module_execution(mod.path)) {
        return;
    }

    execute_module(mod.path, mod.image_base, mod.entry_point, *mod.context, mod.context->end_of_execution_ptr);
}

void QlLoaderPE_UEFI::register_eoe_trap(std::uint64_t address) {
    // the eoe trap: regain control when a module entry returns; the
    // teardown (the notifications + the unloads) lands with the service
    // slices - the slice-1 trap chains the next module or stops
    auto* self = this;
    const auto cb = [self]() -> int {
        auto& os_uefi = static_cast<os::uefi::QlOsUefi&>(self->ql_->os());
        if (os_uefi.notify_after_module_execution(static_cast<int>(self->modules.size()))) {
            return 0;
        }
        if (!self->modules.empty()) {
            self->execute_next_module();
            return 0;
        }
        // no more modules: terminate gracefully
        os_uefi.set_exit_code(0);
        os_uefi.stop();
        return 0;
    };
    ql_->hook_address(cb, address);
}

void QlLoaderPE_UEFI::init_dxe_environment() {
    auto& profile = ql_->profile();
    dxe_context = std::make_unique<os::uefi::DxeContext>(ql_);
    auto& ctx = *dxe_context;

    const std::uint64_t heap_base = static_cast<std::uint64_t>(profile.get_int("DXE", "heap_address"));
    const std::uint64_t heap_size = static_cast<std::uint64_t>(profile.get_int("DXE", "heap_size"));
    ctx.init_heap(heap_base, heap_size);

    const std::uint64_t stack_base = static_cast<std::uint64_t>(profile.get_int("DXE", "stack_address"));
    const std::uint64_t stack_size = static_cast<std::uint64_t>(profile.get_int("DXE", "stack_size"));
    ctx.init_stack(stack_base, stack_size);

    ctx.next_image_base = static_cast<std::uint64_t>(profile.get_int("DXE", "image_address"));

    // the static 4KiB for the ST + the configuration tables (the service
    // slices fill it)
    gST = ctx.heap->alloc(4 * 1024);
    const auto conf_data = ctx.heap->alloc(64 * 1024);
    ctx.conf_table_data_ptr = conf_data;
    ctx.conf_table_data_next_ptr = conf_data;

    // the end-of-execution trap sits on an address that is not expected to
    // execute (the system table location)
    ctx.end_of_execution_ptr = gST;

    // st.py initialize: the ST/BS/RT/DS layout + the fills (the service
    // hooks ride the descriptor walk)
    os::uefi::initialize_system_table(*ql_, ctx, gST);
}

void QlLoaderPE_UEFI::init_smm_environment() {
    auto& profile = ql_->profile();
    smm_context = std::make_unique<os::uefi::SmmContext>(ql_);
    auto& ctx = *smm_context;

    ctx.smram_base = static_cast<std::uint64_t>(profile.get_int("SMM", "smram_base"));
    ctx.smram_size = static_cast<std::uint64_t>(profile.get_int("SMM", "smram_size"));

    const std::uint64_t heap_base = static_cast<std::uint64_t>(profile.get_int("SMM", "heap_address"));
    const std::uint64_t heap_size = static_cast<std::uint64_t>(profile.get_int("SMM", "heap_size"));
    ctx.init_heap(heap_base, heap_size);

    const std::uint64_t stack_base = static_cast<std::uint64_t>(profile.get_int("SMM", "stack_address"));
    const std::uint64_t stack_size = static_cast<std::uint64_t>(profile.get_int("SMM", "stack_size"));
    ctx.init_stack(stack_base, stack_size);

    ctx.next_image_base = static_cast<std::uint64_t>(profile.get_int("SMM", "image_address"));

    // the static 4KiB for the SMM system table (the smst.initialize fills it
    // with the service-table slice)
    const auto gSmst = ctx.heap->alloc(4 * 1024);
    const auto conf_data = ctx.heap->alloc(64 * 1024);
    ctx.conf_table_data_ptr = conf_data;
    ctx.conf_table_data_next_ptr = conf_data;

    ctx.end_of_execution_ptr = gSmst;
}

void QlLoaderPE_UEFI::run() {
    // intel 64-bit uefi modules only (the upstream checks verbatim)
    if (ql_->arch().type() != QL_ARCH::X8664) {
        throw QlErrorArch("Only 64-bit modules are supported at the moment");
    }

    init_dxe_environment();
    init_smm_environment();

    entry_point = 0;
    load_address = 0;

    // the argv modules: the SMM detection rides the 'Smm' substring (the
    // upstream TODO note verbatim — the detection is name-based)
    for (const auto& dependency : ql_->argv()) {
        const bool is_smm_module = dependency.find("Smm") != std::string::npos;
        context = is_smm_module ? static_cast<os::uefi::UefiContext*>(smm_context.get())
                                : static_cast<os::uefi::UefiContext*>(dxe_context.get());
        map_and_load(dependency, *context);
    }

    // the eoe traps (the dxe + the smm contexts) + the module chain
    register_eoe_trap(dxe_context->end_of_execution_ptr);
    register_eoe_trap(smm_context->end_of_execution_ptr);

    execute_next_module();
}

}  // namespace loader
}  // namespace qiling
