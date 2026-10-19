#include "qiling/loader/pe.hpp"

#include <LIEF/LIEF.hpp>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/windows.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/api.hpp"

#include <filesystem>
#include "qiling/os/os.hpp"

namespace qiling {
namespace loader {


QlLoaderPE::QlLoaderPE(Qiling* ql, bool libcache) : QlLoader(ql), libcache_(libcache) {}

std::uint64_t QlLoaderPE::load_image(const std::string& host_path, const std::string& label,
                                     bool set_entry_point, std::optional<std::uint64_t> base_override) {
    auto parsed = LIEF::PE::Parser::parse(host_path);
    if (parsed == nullptr) {
        throw QlErrorBase("failed to parse PE: " + host_path);
    }
    return load_parsed(std::move(parsed), host_path, label, set_entry_point, base_override);
}

std::uint64_t QlLoaderPE::load_parsed(std::unique_ptr<LIEF::PE::Binary> parsed, const std::string& host_path,
                                      const std::string& label, bool set_entry_point,
                                      std::optional<std::uint64_t> base_override) {
    // (the parse rides the caller: the dll path pre-applies the base
    // relocations to the parsed object before this walk)
    auto& mem = ql_->mem();
    const std::uint64_t image_base = parsed->imagebase();
    const std::uint64_t size_of_image = parsed->virtual_size();
    const std::uint64_t entry_rva = parsed->entrypoint() - image_base;

    // loader/pe.py load: if the default base address is taken, use the one
    // specified in profile — the dll callers pass the verbatim policy base
    // through base_override (the load_dll ImageBase/find_free_space walk)
    std::uint64_t base = base_override.value_or(image_base);
    if (!base_override.has_value() && !mem.is_available(base, mem.align_up(size_of_image))) {
        base = image_address_;
    }

    if (set_entry_point) {
        // the main image sets the entry point; the dll loads never touch it
        // (the upstream pe.py only sets self.entry_point in the main-image
        // load() branch — the dll's DllMain is never driven by load_dll)
        entry_point = base + entry_rva;
    }

    mem.map(base, mem.align_up(size_of_image), UC_PROT_ALL, label);
    images.push_back(Image{base, base + size_of_image, host_path});

    // stage the sections: each section's raw bytes land at base + RVA
    struct SectionWriter {
        Qiling* ql;
        std::uint64_t base;
    } writer{ql_, base};

    for (const LIEF::PE::Section& section : parsed->sections()) {
        if (section.size() == 0) {
            continue;
        }
        const auto content = section.content();
        if (content.empty()) {
            continue;
        }
        ql_->mem().write(writer.base + section.virtual_address(),
                         std::vector<std::uint8_t>{content.begin(), content.end()});
    }

    // loader/pe.py init_imports: the import-table walk does NOT key the
    // dispatch map — the upstream records the import_symbols by the MAPPED
    // EXPORT address (the load_dll export walk below); the IAT slots get
    // written in init_imports (the OS-layer call, after the sys dlls load)

    // loader/pe.py load_dll: the export walk fills the import_symbols map
    // keyed by the mapped export address, plus the image's own iat slice and
    // the export_symbols map (the GetProcAddress self branch walks them)
    if (parsed->has_exports()) {
        const auto* export_ = parsed->get_export();
        std::map<std::string, std::uint64_t> iat_by_name;
        std::map<std::uint64_t, std::uint64_t> iat_by_ordinal;

        // dll_name = os.path.basename(self.path).casefold() (verbatim)
        const std::filesystem::path loaded(host_path);
        std::string dll_name = loaded.filename().string();
        for (auto& c : dll_name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        for (const LIEF::PE::ExportEntry& entry : export_->entries()) {
            const std::uint64_t ea = base + entry.address();

            if (entry.is_forwarded()) {
                std::string target_dll = entry.forward_information().library;
                for (auto& c : target_dll) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                if (!target_dll.empty() && target_dll.find(".dll") == std::string::npos) {
                    target_dll += ".dll";
                }
                forwarded_exports_.push_back(ForwardedExport{dll_name, entry.name(), entry.ordinal(),
                                                             target_dll, entry.forward_information().function});
            }

            ExportSymbol symbol;
            symbol.address = ea;
            symbol.name = entry.name();
            symbol.ordinal = entry.ordinal();
            export_symbols_[ea] = std::move(symbol);

            // loader/pe.py load_dll: import_symbols[ea] = {'name', 'ordinal',
            // 'dll'} — the dispatch map is keyed by the mapped export address
            // (the hook fires at the pc inside the mapped dll body; the
            // upstream keys the same ea)
            ImportSymbol isym;
            isym.address = ea;
            isym.dll = dll_name;
            isym.name = entry.name();
            isym.ordinal = entry.ordinal();
            import_symbols_[ea] = std::move(isym);

            if (!entry.name().empty()) {
                iat_by_name[entry.name()] = ea;
            }
            iat_by_ordinal[entry.ordinal()] = ea;
        }

        import_address_table_[dll_name] = ImportTable{std::move(iat_by_name), std::move(iat_by_ordinal)};
    }

    // loader/pe.py init_function_tables — the shared call site covers both
    // the main image and the load_dll flows (the upstream calls it at both
    // ends; the port rides one place)
    init_function_tables(parsed.get(), base);

    return base;
}

void QlLoaderPE::init_function_tables(LIEF::PE::Binary* pe, std::uint64_t image_base) {
    if (ql_->arch().type() == QL_ARCH::X86) {
        return;  // the verbatim non-x86 gate
    }

    // the exception directory: the .pdata image — the port reads the mapped
    // bytes (the same Begin/End/Unwind triples the pefile objects carry)
    if (!pe->has(LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE)) {
        ql_->log().debug("Image has no exception directory; skipping exception data");
        return;
    }

    const auto& exception_dir = *pe->data_directory(LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE);
    const auto table_rva = exception_dir.RVA();
    const auto table_size = exception_dir.size();

    function_table_lookup_[image_base] = table_rva;

    auto& table = function_tables_[image_base];
    const std::size_t entries = table_size / 12;  // sizeof(RUNTIME_FUNCTION)
    table.reserve(entries);
    for (std::size_t i = 0; i < entries; ++i) {
        const auto entry_addr = image_base + table_rva + i * 12;
        RuntimeFunction rf;
        rf.begin = static_cast<std::uint32_t>(ql_->mem().read_ptr(entry_addr, 4));
        rf.end = static_cast<std::uint32_t>(ql_->mem().read_ptr(entry_addr + 4, 4));
        table.push_back(rf);
    }

    ql_->log().debug("Parsed " + std::to_string(entries) + " exception directory entries");
}

std::pair<std::int64_t, const QlLoaderPE::RuntimeFunction*> QlLoaderPE::lookup_function_entry(
    std::uint64_t base_addr, std::uint64_t control_pc) const {
    const auto it = function_tables_.find(base_addr);
    if (it == function_tables_.end()) {
        return {-1, nullptr};
    }

    // the first RUNTIME_FUNCTION whose [begin, end) range holds control_pc
    // - base_addr (the python next() walk verbatim: the None rides -1/nullptr)
    const auto rva = control_pc - base_addr;
    for (std::size_t i = 0; i < it->second.size(); ++i) {
        const auto& rf = it->second[i];
        if (rf.begin <= rva && rva < rf.end) {
            return {static_cast<std::int64_t>(i), &rf};
        }
    }
    return {-1, nullptr};
}

std::pair<std::string, std::string> QlLoaderPE::dll_path_elements(const std::string& name) const {
    // loader/pe.py __get_path_elements: translate the dll virtual path into
    // the host path
    const std::size_t sep = name.find_last_of("\\/");
    std::string dirname = sep == std::string::npos ? std::string() : name.substr(0, sep);
    std::string basename = sep == std::string::npos ? name : name.substr(sep + 1);

    // has_lib_ext: the dll/exe/sys/drv suffix check, the .dll append
    const auto dot = basename.rfind('.');
    const std::string ext = dot == std::string::npos ? std::string() : basename.substr(dot + 1);
    std::string ext_lower = ext;
    for (auto& c : ext_lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (!(ext_lower == "dll" || ext_lower == "exe" || ext_lower == "sys" || ext_lower == "drv")) {
        basename += ".dll";
    }

    // if only filename was specified assume it is located at the system32
    // folder to prevent potential dll hijacking (verbatim)
    if (dirname.empty()) {
        auto* os = static_cast<os::windows::QlOsWindows*>(&ql_->os());
        dirname = os->winsys();
    }

    // reconstruct the dll virtual path, then the host path
    const std::string vpath = dirname + "\\" + basename;
    const std::string host_path = ql_->os().path()->virtual_to_host_path(vpath);

    std::string folded = basename;
    for (auto& c : folded) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return {host_path, folded};
}

std::uint64_t QlLoaderPE::load_dll(const std::string& name) {
    auto [dll_path, dll_name] = dll_path_elements(name);

    if (dll_name.rfind("api-ms-win-", 0) == 0) {
        // Usually we should not reach this point and instead imports from
        // such DLLs should be redirected earlier (verbatim)
        return 0;
    }

        // see if this dll was already loaded
    if (const auto* image = get_image_by_name(dll_name, true)) {
        return image->base;
    }

    std::error_code ec;
    std::string dll_path_host = dll_path;
        if (!std::filesystem::exists(dll_path_host, ec)) {
        // posix hosts may not find the requested filename if it was saved
        // under a different case. (verbatim comment; the casefold walk)
        const auto folded = ql_->os().path()->host_casefold_path(dll_path_host);
        if (!folded.has_value()) {
            return 0;
        }
        dll_path_host = *folded;
    }

    // loader/pe.py load_dll: the verbatim dll base policy — the ImageBase
    // (or the dll_last_address cursor when zero), the max_mem_addr gate, the
    // find_free_space fallback and the base-relocation application (the
    // DIR64/HIGHLOW walk; the pefile relocate_image analogue)
    std::uint64_t base = 0;
    bool relocate = false;
    {
        auto parsed = LIEF::PE::Parser::parse(dll_path_host);
        if (parsed == nullptr) {
            throw QlErrorBase("failed to parse PE: " + dll_path_host);
        }
        dll_size_ += parsed->virtual_size();

        auto& mem = ql_->mem();
        const auto dll_len = mem.align_up(parsed->virtual_size());
        std::uint64_t image_base = parsed->imagebase() != 0 ? parsed->imagebase() : dll_last_address_;

        if (image_base + dll_len > mem.max_mem_addr()) {
            image_base = dll_last_address_;
            relocate = true;
        }
        if (!mem.is_available(image_base, dll_len)) {
            image_base = mem.find_free_space(dll_len, image_base, {}, 0x10000ull);
            relocate = true;
        }

        // the relocation walk rides AFTER the map (the guest-memory patching)
        const auto relocations = parsed->relocations();
        const auto original_image_base = parsed->imagebase();
        relocate = relocate && !relocations.empty();

        const std::uint64_t mapped_base = load_parsed(std::move(parsed), dll_path_host, dll_name, false, image_base);

        if (relocate) {
            const auto delta = static_cast<std::int64_t>(mapped_base) - static_cast<std::int64_t>(original_image_base);
            using RelEntry = LIEF::PE::RelocationEntry;
            for (const auto& block : relocations) {
                const auto block_va = block.virtual_address();
                for (const auto& entry : block.entries()) {
                    if (entry.type() == RelEntry::BASE_TYPES::DIR64) {
                        const auto addr = mapped_base + block_va + entry.position();
                        mem.write_ptr(addr, mem.read_ptr(addr, 8) + static_cast<std::uint64_t>(delta), 8);
                    } else if (entry.type() == RelEntry::BASE_TYPES::HIGHLOW) {
                        const auto addr = mapped_base + block_va + entry.position();
                        mem.write_ptr(addr, mem.read_ptr(addr, 4) + static_cast<std::uint64_t>(delta), 4);
                    }
                }
            }
        }
    }

    // loader/pe.py load_dll tail: the verbatim sequence — add the dll to the
    // ldr table, resolve the dll's own import table against the loaded
    // images (the api-ms ladder over the loaded export tables), then drive
    // the DllMain when the emulation has not started yet
    {
        const auto dll_base = get_image_by_name(dll_name, true) != nullptr
                                  ? get_image_by_name(dll_name, true)->base : 0;
        if (dll_base != 0 && !is_driver_) {
            add_ldr_data_table_entry(dll_name);
        }

        auto dll_parsed = LIEF::PE::Parser::parse(dll_path_host);
        if (dll_base != 0 && dll_parsed != nullptr) {
            const auto dll_len = static_cast<std::uint64_t>(dll_parsed->virtual_size());
            init_imports_for(*dll_parsed, dll_base, dll_name);

            // the DllMain ride (the verbatim blacklist + the emu-state gate)
            if (ql_->emu_state() != QL_STATE::STARTED) {
                call_dll_entrypoint(*dll_parsed, dll_base, dll_len, dll_name);
            }
        }
    }

    // loader/pe.py load_dll tail: resolve_forwarded_exports() rides after the
    // export walk (the targets loaded earlier in the sys_dlls order resolve;
    // the rest stays deferred until their dll lands)
    resolve_forwarded_exports();

    return get_image_by_name(dll_name, true) ? get_image_by_name(dll_name, true)->base : 0;
}

// loader/pe.py resolve_forwarded_exports: re-point the forwarded exports at
// the target dll's real export address (the upstream verbatim walk: the
// ordinal-only forwarders skip, the missing target tables skip, the failed
// symbol lookups warn and drop)
void QlLoaderPE::resolve_forwarded_exports() {
    while (!forwarded_exports_.empty()) {
        const auto forwarded_export = forwarded_exports_.back();
        forwarded_exports_.pop_back();

        if (forwarded_export.source_symbol.empty()) {
            // Some DLLs (shlwapi.dll) have a bunch of forwarded exports with
            // ordinals but no symbols. These are really annoying to deal
            // with, but they are used extremely rarely, so we will ignore
            // them. (verbatim comment)
            continue;
        }

        const auto target_it = import_address_table_.find(forwarded_export.target_dll);
        if (target_it == import_address_table_.end()) {
            // If IAT was not found, it is probably a virtual library. (verbatim)
            continue;
        }

        // If we have an existing entry in the process IAT for the code this
        // entry forwards to, then we will point the symbol there rather than
        // the symbol string in the exporter's data section. (verbatim)
        const std::uint64_t forward_ea = target_it->second.lookup(forwarded_export.target_symbol);
        if (forward_ea == 0) {
            ql_->log().debug("Forwarding symbol " + forwarded_export.source_dll + "." +
                             forwarded_export.source_symbol + " to " + forwarded_export.target_dll + "." +
                             forwarded_export.target_symbol + ": Failed to resolve address");
            continue;
        }

        auto& source_iat = import_address_table_[forwarded_export.source_dll];
        source_iat.by_name[forwarded_export.source_symbol] = forward_ea;
        source_iat.by_ordinal[forwarded_export.source_ordinal] = forward_ea;

        // Register the new address as having the source symbol/ordinal. This
        // way, hooks on forward source symbols will function correctly. (verbatim)
        ImportSymbol isym;
        isym.address = forward_ea;
        isym.dll = forwarded_export.source_dll;
        isym.name = forwarded_export.source_symbol;
        isym.ordinal = forwarded_export.source_ordinal;
        import_symbols_[forward_ea] = std::move(isym);

        ql_->log().debug("Forwarding symbol " + forwarded_export.source_dll + "." +
                         forwarded_export.source_symbol + " to " + forwarded_export.target_dll + "." +
                         forwarded_export.target_symbol + ": Resolved symbol");
    }
}

// loader/pe.py init_imports: the main-image import walk — the upstream
// receives the parsed pefile; the port re-parses the image (the documented
// deviation: the LIEF parse object does not survive load_image). For each
// import dll: the api-ms-win-* names ride the verbatim key_dlls scan (the
// redirect resolution over the loaded images' export tables), the dll loads
// through load_dll when unbound symbols remain, and the resolved export
// addresses write over the IAT slots (the mem.write_ptr(imp.address, addr)
// verbatim). The upstream's bound-import skip degrades to an all-unbound
// walk (LIEF's ImportEntry carries no bound flag; modern linkers never emit
// pre-bound IATs).
void QlLoaderPE::init_imports() {
    auto parsed = LIEF::PE::Parser::parse(ql_->path());
    if (parsed == nullptr || !parsed->has_imports()) {
        return;
    }

    const auto* main_image = get_image_by_name(ql_->targetname(), true);
    if (main_image == nullptr) {
        return;
    }
    init_imports_for(*parsed, main_image->base, ql_->targetname());
}

// loader/pe.py init_imports body — the walk over ONE image's import table
// (the main image and the loaded dlls share the call site, verbatim)
void QlLoaderPE::init_imports_for(LIEF::PE::Binary& parsed, std::uint64_t image_base,
                                  const std::string& image_label) {
    // the IAT slots ride the image base (LIEF's iat_address() returns the
    // RVA — the pefile imp.address equivalent carries the absolute address,
    // so the port adds the mapped base where the pefile read the final VA)

    static constexpr std::array<const char*, 4> kKeyDlls = {
        "kernel32.dll", "ntdll.dll", "kernelbase.dll", "ucrtbase.dll",
    };

    for (const LIEF::PE::Import& entry : parsed.imports()) {
        std::string dll_name = entry.name();
        for (auto& c : dll_name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        const std::string orig_dll_name = dll_name;

        bool redirected = false;
        if (dll_name.rfind("api-ms-win-", 0) == 0) {
            // the verbatim key_dlls ladder: scan the loaded images' export
            // tables for each imported symbol; exactly one candidate
            // redirects, several remember the last as the fallback and ride
            // to the next symbol, none fails the dll
            std::string fallback;
            std::string key_dll;
            const auto& imps = entry.entries();
            std::size_t idx = 0;
            while (!redirected) {
                const LIEF::PE::ImportEntry* imp = idx < imps.size() ? &imps[idx] : nullptr;
                std::vector<std::string> options;
                if (imp == nullptr) {
                    if (!fallback.empty()) {
                        options.push_back(fallback);
                    }
                } else {
                    for (const auto* kd : kKeyDlls) {
                        const auto it = import_address_table_.find(std::string(kd));
                        if (it != import_address_table_.end() &&
                            it->second.by_name.count(std::string(imp->name())) != 0) {
                            options.push_back(kd);
                        }
                    }
                }
                if (options.empty()) {
                    break;  // failed to resolve (the upstream failed flag)
                }
                if (options.size() == 1) {
                    key_dll = options.front();
                    redirected = true;
                } else {
                    fallback = options.back();
                }
                ++idx;
            }
            if (!redirected) {
                ql_->log().debug("Failed to resolve " + dll_name);
                continue;
            }
            ql_->log().debug("Redirecting " + dll_name + " to " + key_dll);
            dll_name = key_dll;
        }

        const auto unbound = [&]() {
            std::vector<const LIEF::PE::ImportEntry*> out;
            for (const LIEF::PE::ImportEntry& imp : entry.entries()) {
                out.push_back(&imp);
            }
            return out;
        }();

        if (!unbound.empty()) {
            // only load dll if encountered unbound symbol (verbatim)
            if (!redirected) {
                const auto dll_base = load_dll(entry.name());
                if (dll_base == 0) {
                    continue;
                }
            }

            const auto it = import_address_table_.find(dll_name);
            if (it == import_address_table_.end()) {
                continue;
            }
            const ImportTable& iat = it->second;

            for (const LIEF::PE::ImportEntry* imp : unbound) {
                std::uint64_t addr = 0;
                if (!imp->name().empty()) {
                    addr = iat.lookup(std::string(imp->name()));
                    if (addr == 0) {
                        ql_->log().debug("Error in loading function " + std::string(imp->name()) +
                                         " (" + orig_dll_name + ")");
                        continue;
                    }
                } else {
                    const auto oit = iat.by_ordinal.find(imp->ordinal());
                    if (oit == iat.by_ordinal.end()) {
                        continue;
                    }
                    addr = oit->second;
                }
                ql_->mem().write_ptr(image_base + imp->iat_address(), addr);
            }
        }
    }
}

void QlLoaderPE::run() {
    // loader/pe.py run(): the dll lists (the full Windows stack loads the
    // real system DLLs from the rootfs; the stubs-based fixtures run without
    // them in this slice)
    const std::uint64_t bits = ql_->arch().bits();
    const std::string ossection = bits == 64 ? "OS64" : "OS32";
    auto& profile = ql_->profile();

    stack_address_ = static_cast<std::uint64_t>(profile.get_int(ossection, "stack_address"));
    stack_size_ = static_cast<std::uint64_t>(profile.get_int(ossection, "stack_size"));
    image_address_ = static_cast<std::uint64_t>(profile.get_int(ossection, "image_address"));
    dll_address_ = static_cast<std::uint64_t>(profile.get_int(ossection, "dll_address"));
    entry_point = static_cast<std::uint64_t>(profile.get_int(ossection, "entry_point"));

    dll_last_address_ = dll_address_;

    // the command line (windows.py: cmdline + args)
    {
        std::string cmdline = ql_->targetname();
        for (std::size_t i = 1; i < ql_->argv().size(); ++i) {
            cmdline += ' ';
            cmdline += ql_->argv()[i];
        }
        cmdline += '\0';
        cmdline_.assign(cmdline.begin(), cmdline.end());
    }

    // loader/pe.py run(): the verbatim structure_last_addr seed
    // ({32: FS_SEGMENT_ADDR, 64: GS_SEGMENT_ADDR}) — the single cursor the
    // driver objects AND the TEB/PEB/LDR stack walk across BOTH paths
    structure_last_addr_ = bits == 64 ? os::windows::GS_SEGMENT_ADDR : os::windows::FS_SEGMENT_ADDR;

    // loader/pe.py load(): the stack map rides BOTH paths (the shellcode
    // + the PE) before the branch
    {
        auto& mem = ql_->mem();
        mem.map(stack_address_, stack_size_, UC_PROT_ALL, "[stack]");
    }

    if (!ql_->code().empty()) {
        // the shellcode path (loader/pe.py load(pe=None))
        is_driver_ = false;

        auto& mem = ql_->mem();
        mem.map(entry_point, static_cast<std::uint64_t>(ql_->os().code_ram_size()), UC_PROT_ALL, "[shellcode]");
        mem.write(entry_point, ql_->code());
        const auto top_of_stack = stack_address_ + stack_size_;
        const auto sp = bits == 64 ? "rsp" : "esp";
        const auto bp = bits == 64 ? "rbp" : "ebp";
        ql_->arch().regs().write(sp, top_of_stack);
        ql_->arch().regs().write(bp, top_of_stack);

        // loader/pe.py load(pe=None): the TEB/PEB/LDR stack rides the
        // shellcode path too (the upstream calls the same inits after the
        // code write; the structure cursor seeds from the GS segment base)
        init_teb();
        init_peb();
        init_ldr_data();
    } else {
        // the PE image path
        pe_image_address_ = load_image(ql_->path(), ql_->targetname());

        if (is_driver_) {
            init_driver_object();
            init_registry_path();
            init_eprocess();

            // set IRQ Level in CR8 to PASSIVE_LEVEL  (verbatim)
            ql_->arch().regs().write("CR8", 0);

            // setup CR4, enabling: DE, PSE, PAE, MCE, PGE, OSFXSR and
            // OSXMMEXCPT. some drivers may check this at initialized
            // (verbatim)
            ql_->arch().regs().write("CR4", 0b0000011011111000);
        } else {
            // loader/pe.py: initialize thread information block, then add
            // the image to the ldr table (verbatim)
            init_teb();
            init_peb();
            init_ldr_data();
            add_ldr_data_table_entry(std::filesystem::path(ql_->path()).filename().string());
        }

        // loader/pe.py run: "Stack should not init at the very bottom. Will
        // cause errors with Dlls" (verbatim comment) — the sp/bp ride the
        // stack head minus one page
        const auto top_of_stack = stack_address_ + stack_size_ - 0x1000;
        const auto sp = bits == 64 ? "rsp" : "esp";
        const auto bp = bits == 64 ? "rbp" : "ebp";
        ql_->arch().regs().write(sp, top_of_stack);
        ql_->arch().regs().write(bp, top_of_stack);
    }

    init_ki_user_shared_data();

    // loader/pe.py run(): the shellcode path loads the init_dlls tuple and
    // the PE path the sys_dlls tuple (the missing files degrade through
    // load_dll's zero return); then the import-table walk resolves the
    // main-image imports against the loaded images' export tables
    if (!ql_->code().empty()) {
        for (const char* each : {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "user32.dll"}) {
            (void)load_dll(each);
        }
    } else {
        for (const char* each : {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "mscoree.dll", "ucrtbase.dll"}) {
            (void)load_dll(each);
        }
        init_imports();
    }

    init_sp = ql_->arch().regs().arch_sp();
}

// ---- the ntoskrnl-family riders (the pe.py init_* walks) ----

// loader/pe.py init_ki_user_shared_data: the KUSER_SHARED_DATA map over the
// profile KI_USER_SHARED_DATA base + the key-field writes (the ctypes
// KUSER_SHARED_DATA offsets: the ImageNumberLow@44, the ImageNumberHigh@46,
// the NtSystemRoot@48 (the 260-char wide string), the NtProductType@612,
// the NtMajorVersion@620, the NtMinorVersion@624)
void QlLoaderPE::init_ki_user_shared_data() {
    auto& mem = ql_->mem();
    auto& profile = ql_->profile();
    const std::uint64_t bits = ql_->arch().bits();

    const std::string ossection = bits == 64 ? "OS64" : "OS32";
    const auto kusd_addr = static_cast<std::uint64_t>(profile.get_int(ossection, "KI_USER_SHARED_DATA"));

    constexpr std::size_t KUSD_SIZE = 0x1000;  // the align_up(sizeof(KUSER_SHARED_DATA))
    mem.map(kusd_addr, mem.align_up(KUSD_SIZE), UC_PROT_ALL, "[kuser shared data]");

    const auto put32 = [&](std::size_t off, std::uint64_t v) {
        mem.write_ptr(kusd_addr + off, v, 4);
    };
    const auto put16 = [&](std::size_t off, std::uint64_t v) {
        mem.write_ptr(kusd_addr + off, v, 2);
    };

    // initialize an instance with a few key fields  (verbatim)
    put16(44, 0x014c);   // IMAGE_FILE_MACHINE_I386
    put16(46, 0x8664);   // IMAGE_FILE_MACHINE_AMD64
    put32(612, profile.get_int("SYSTEM", "productType"));
    put32(620, profile.get_int("SYSTEM", "majorVersion"));
    put32(624, profile.get_int("SYSTEM", "minorVersion"));

    const auto windir = ql_->os<os::windows::QlOsWindows>().windir();
    std::vector<std::uint8_t> root;
    for (const char c : windir) {
        root.push_back(static_cast<std::uint8_t>(c));
        root.push_back(0);
    }
    root.resize(520, 0);
    mem.write(kusd_addr + 48, root);

    kuser_shared_data_address_ = kusd_addr;
}

// loader/pe.py init_eprocess: the 0x4d0 (64-bit) / 0x2c0 (32-bit) EPROCESS
// placeholder image (the FIXME: define meaningful fields verbatim ride)
void QlLoaderPE::init_eprocess() {
    const std::uint64_t bits = ql_->arch().bits();
    const std::size_t obj_size = bits == 64 ? 0x4d0 : 0x2c0;

    const auto eproc_addr = structure_last_addr_;
    const auto nobj_addr = ql_->mem().align_up(eproc_addr + obj_size, 0x10);

    // the dummy empty write (the python `eproc_obj.dummy = b''` ride)
    std::string image(obj_size, '\0');
    ql_->mem().write(eproc_addr, std::vector<std::uint8_t>(image.begin(), image.end()));

    structure_last_addr_ = nobj_addr;
    eprocess_address_ = eproc_addr;
}

// loader/pe.py init_driver_object: the DRIVER_OBJECT placeholder (the
// volatile ref — the zero image)
void QlLoaderPE::init_driver_object() {
    constexpr std::size_t DRIVER_OBJECT_SIZE_64 = 336;   // the 28 MajorFunction slots + the head
    constexpr std::size_t DRIVER_OBJECT_SIZE_32 = 208;

    const std::uint64_t bits = ql_->arch().bits();
    const std::size_t obj_size = bits == 64 ? DRIVER_OBJECT_SIZE_64 : DRIVER_OBJECT_SIZE_32;

    const auto drv_addr = structure_last_addr_;
    const auto nobj_addr = ql_->mem().align_up(drv_addr + obj_size, 0x10);

    std::string image(obj_size, '\0');
    ql_->mem().write(drv_addr, std::vector<std::uint8_t>(image.begin(), image.end()));

    // note: driver object is volatile; no need to flush its contents to mem
    // (verbatim)
    structure_last_addr_ = nobj_addr;
    driver_object_address_ = drv_addr;
}

// loader/pe.py init_registry_path: the PUNICODE_STRING RegistryPath with the
// Buffer pointing at itself (the FIXME: pointing to self? verbatim quirk)
void QlLoaderPE::init_registry_path() {
    // the UNICODE_STRING (the 16-byte x64 / the 8-byte x86 image)
    const std::uint64_t bits = ql_->arch().bits();
    const std::size_t ucstr_size = bits == 64 ? 16 : 8;

    const auto regpath_addr = structure_last_addr_;
    const auto nobj_addr = ql_->mem().align_up(regpath_addr + ucstr_size, 0x10);

    std::string image(ucstr_size, '\0');
    const auto put16 = [&](std::size_t off, std::uint64_t v) {
        image[off] = static_cast<char>(v & 0xff);
        image[off + 1] = static_cast<char>((v >> 8) & 0xff);
    };
    put16(0, 0);   // Length
    put16(2, 0);   // MaximumLength
    const auto buf_off = bits == 64 ? 8 : 4;
    const auto put_ptr = [&](std::size_t off, std::uint64_t v) {
        for (std::size_t k = 0; k < (bits == 64 ? 8 : 4); ++k) {
            image[off + k] = static_cast<char>((v >> (8 * k)) & 0xff);
        }
    };
    put_ptr(buf_off, regpath_addr);   // FIXME: pointing to self? verbatim
    ql_->mem().write(regpath_addr, std::vector<std::uint8_t>(image.begin(), image.end()));

    (void)put16;
    structure_last_addr_ = nobj_addr;
    regitry_path_address_ = regpath_addr;
}

// ---- the TEB/PEB/LDR stack (the pe.py init_teb/init_peb/init_ldr_data/
// add_ldr_data_table_entry walks; the windows.py runtime consumes the
// addresses) ----

namespace {

void put_le(std::vector<std::uint8_t>& image, std::size_t off, std::uint64_t v, std::size_t width) {
    for (std::size_t k = 0; k < width; ++k) {
        image[off + k] = static_cast<std::uint8_t>((v >> (8 * k)) & 0xff);
    }
}

}  // namespace

using namespace os::win;

// loader/pe.py init_teb: the TEB over the structure cursor (the x64 GS
// segment base / the x86 FS segment base), the StackBase/StackLimit over the
// profile stack, the self-referencing TebAddress and the PebAddress pointed
// at the PEB that init_peb lays right after (16-aligned)
void QlLoaderPE::init_teb() {
    const std::uint64_t teb_addr = structure_last_addr_;
    const std::uint64_t peb_addr = ql_->mem().align_up(teb_addr + TEB_SIZE, 0x10);

    std::vector<std::uint8_t> image(TEB_SIZE, 0);
    put_le(image, TEB_OFF_STACK_BASE, stack_address_ + stack_size_, 8);
    put_le(image, TEB_OFF_STACK_LIMIT, stack_address_, 8);
    put_le(image, TEB_OFF_TEB_ADDRESS, teb_addr, 8);
    put_le(image, TEB_OFF_PEB_ADDRESS, peb_addr, 8);
    ql_->mem().write(teb_addr, image);

    structure_last_addr_ = peb_addr;
    teb_address_ = teb_addr;
}

// loader/pe.py init_peb: the 0x7c8 PEB image with the ImageBaseAddress, the
// LdrAddress pointing at the LDR laid right after, the ProcessParameters and
// the ProcessHeap over the 0x100 heap chunks (the verbatim "Is ok to be all
// \x00" comment) and the NumberOfProcessors from the HARDWARE profile
void QlLoaderPE::init_peb() {
    auto& os_win = static_cast<os::windows::QlOsWindows&>(ql_->os());

    const std::uint64_t peb_addr = structure_last_addr_;
    const std::uint64_t ldr_addr = ql_->mem().align_up(peb_addr + PEB_SIZE, 0x10);

    std::vector<std::uint8_t> image(PEB_SIZE, 0);
    put_le(image, PEB_OFF_IMAGE_BASE_ADDRESS, pe_image_address_, 8);
    put_le(image, PEB_OFF_LDR_ADDRESS, ldr_addr, 8);
    put_le(image, PEB_OFF_PROCESS_PARAMETERS, os_win.heap().alloc(0x100), 8);
    put_le(image, PEB_OFF_PROCESS_HEAP, os_win.heap().alloc(0x100), 8);
    put_le(image, PEB_OFF_NUMBER_OF_PROCESSORS,
           static_cast<std::uint64_t>(ql_->profile().get_int("HARDWARE", "number_processors")), 4);
    ql_->mem().write(peb_addr, image);

    structure_last_addr_ = ldr_addr;
    peb_address_ = peb_addr;
}

// loader/pe.py init_ldr_data: the PEB_LDR_DATA with the three order lists
// self-linked (the Flink/Blink pointing at their own list-head cells)
void QlLoaderPE::init_ldr_data() {
    const std::uint64_t ldr_addr = structure_last_addr_;
    const std::uint64_t nobj_addr = ql_->mem().align_up(ldr_addr + LDR_DATA_SIZE, 0x10);

    std::vector<std::uint8_t> image(LDR_DATA_SIZE, 0);
    for (const auto off : {LDR_DATA_OFF_IN_LOAD_ORDER,
                           LDR_DATA_OFF_IN_MEMORY_ORDER,
                           LDR_DATA_OFF_IN_INITIALIZATION_ORDER}) {
        put_le(image, off, ldr_addr + off, 8);       // Flink
        put_le(image, off + 8, ldr_addr + off, 8);   // Blink
    }
    ql_->mem().write(ldr_addr, image);

    structure_last_addr_ = nobj_addr;
    ldr_address_ = ldr_addr;
}

// loader/pe.py add_ldr_data_table_entry: the LDR_DATA_TABLE_ENTRY over the
// heap with the DllBase, the FullDllName/BaseDllName wide strings and the
// three-order Flink/Blink chains (the ldr_list-tail walk; the first entry
// links against the LDR list heads)
void QlLoaderPE::add_ldr_data_table_entry(const std::string& dll_name) {
    auto& os_win = static_cast<os::windows::QlOsWindows&>(ql_->os());

    const Image* image_rec = get_image_by_name(dll_name, true);
    if (image_rec == nullptr) {
        // the upstream asserts; the port keeps the assert-shaped throw (the
        // image should have been added to loader.images first)
        throw QlErrorBase("image should have been added to loader.images first");
    }

    const std::uint64_t entry_addr = os_win.heap().alloc(LDR_ENTRY_SIZE);

    // populate_unistr: the utf-16le encode + the heap buffer with the NUL
    // tail and the Length/MaximumLength/Buffer cells
    const auto populate_unistr = [&](std::uint64_t entry_base, std::size_t ucs_off, const std::string& s) {
        std::u16string encoded;
        for (const char c : s) {
            encoded.push_back(static_cast<char16_t>(static_cast<unsigned char>(c)));
        }
        const std::size_t ucslen = encoded.size() * 2;
        const std::uint64_t ucsbuf = os_win.heap().alloc(ucslen + 2);

        std::vector<std::uint8_t> bytes(ucslen + 2, 0);
        for (std::size_t k = 0; k < encoded.size(); ++k) {
            bytes[k * 2] = static_cast<std::uint8_t>(encoded[k] & 0xff);
            bytes[k * 2 + 1] = static_cast<std::uint8_t>((encoded[k] >> 8) & 0xff);
        }
        ql_->mem().write(ucsbuf, bytes);

        std::vector<std::uint8_t> ucs(UNICODE_STRING_SIZE, 0);
        put_le(ucs, UNICODE_STRING_OFF_LENGTH, ucslen, 2);
        put_le(ucs, UNICODE_STRING_OFF_MAXIMUM_LENGTH, ucslen + 2, 2);
        put_le(ucs, UNICODE_STRING_OFF_BUFFER, ucsbuf, 8);
        ql_->mem().write(entry_base + ucs_off, ucs);
    };

    std::vector<std::uint8_t> entry(LDR_ENTRY_SIZE, 0);
    put_le(entry, LDR_ENTRY_OFF_DLL_BASE, image_rec->base, 8);
    ql_->mem().write(entry_addr, entry);

    const std::string full_name = os_win.winsys() + "\\" + dll_name;
    populate_unistr(entry_addr, LDR_ENTRY_OFF_FULL_DLL_NAME, full_name);
    populate_unistr(entry_addr, LDR_ENTRY_OFF_BASE_DLL_NAME, dll_name);

    // the three-order link offsets ride the LDR_DATA list offsets (the
    // InLoad/InMemory/InInitialization pairs map 1:1 over the entry)
    const auto entry_links = std::array{
        std::pair{LDR_ENTRY_OFF_IN_LOAD_ORDER_LINKS, LDR_DATA_OFF_IN_LOAD_ORDER},
        std::pair{LDR_ENTRY_OFF_IN_MEMORY_ORDER_LINKS, LDR_DATA_OFF_IN_MEMORY_ORDER},
        std::pair{LDR_ENTRY_OFF_IN_INITIALIZATION_ORDER_LINKS,
                  LDR_DATA_OFF_IN_INITIALIZATION_ORDER},
    };

    for (const auto& [entry_off, ldr_off] : entry_links) {
        std::uint64_t flink = 0;
        std::uint64_t blink = 0;
        if (!ldr_list_.empty()) {
            const std::uint64_t last = ldr_list_.back();
            // the Flink rides the last entry's current head link; the blink
            // rides the LDR list head's Blink cell
            flink = ql_->mem().read_ptr(last + entry_off, 8);
            blink = ql_->mem().read_ptr(ldr_address_ + ldr_off + 8, 8);
        } else {
            flink = ql_->mem().read_ptr(ldr_address_ + ldr_off, 8);
            blink = ql_->mem().read_ptr(ldr_address_ + ldr_off + 8, 8);
        }
        put_le(entry, entry_off, flink, 8);            // In*OrderLinks.Flink
        put_le(entry, entry_off + 8, blink, 8);        // In*OrderLinks.Blink
        ql_->mem().write(entry_addr + entry_off,
                         std::vector<std::uint8_t>(entry.begin() + entry_off,
                                                   entry.begin() + entry_off + 16));
        ql_->mem().write_ptr(ldr_address_ + ldr_off, entry_addr + entry_off);       // head Flink
        ql_->mem().write_ptr(ldr_address_ + ldr_off + 8, entry_addr + entry_off);   // head Blink
        if (!ldr_list_.empty()) {
            ql_->mem().write_ptr(ldr_list_.back() + entry_off, entry_addr + entry_off);
        }
    }

    ldr_list_.push_back(entry_addr);
}

// loader/pe.py call_dll_entrypoint: the DllMain drive — the entry section
// gate (the DllMain must live inside a mapped section), the kernelbase/
// kernel32 skip, the problematic-DllMain blacklist, then the fcall CDECL
// frame over emu_start with the bailing restore on failure (verbatim)


// loader/pe.py call_dll_entrypoint: the DllMain drive — the entry section
// gate (the DllMain must live inside a mapped section), the kernelbase/
// kernel32 skip, the problematic-DllMain blacklist, then the fcall CDECL
// frame over emu_start with the bailing restore on failure (verbatim)
void QlLoaderPE::call_dll_entrypoint(LIEF::PE::Binary& dll, std::uint64_t dll_base,
                                     std::uint64_t dll_len, const std::string& dll_name) {
    const auto entry_address = dll.entrypoint() - dll.imagebase();

    bool covered = false;
    for (const LIEF::PE::Section& section : dll.sections()) {
        if (entry_address >= section.virtual_address() &&
            entry_address < section.virtual_address() + section.size()) {
            covered = true;
            break;
        }
    }
    if (!covered) {
        return;
    }

    if (dll_name == "kernelbase.dll" || dll_name == "kernel32.dll") {
        ql_->log().debug("Ignoring " + dll_name + " entry point");
        return;
    }

    // DllMain functions often call many APIs that may crash the program if
    // they are not implemented correctly (if at all). here we blacklist the
    // problematic DLLs whose DllMain functions are known to be crashing.
    // (verbatim comment; the blacklist may be revisited)
    const auto is64 = ql_->arch().bits() == 64;
    const char* blacklist[] = {"gdi32.dll", "user32.dll"};
    for (const auto* entry : blacklist) {
        if (dll_name == entry) {
            ql_->log().debug(std::string("Ignoring ") + entry + " entry point (blacklisted)");
            return;
        }
    }
    (void)is64;

    const auto entry_point = dll_base + entry_address;
    const auto exit_point = dll_base + dll_len - 16;

    const std::vector<std::pair<int, std::uint64_t>> args = {
        {os::api::HINSTANCE_, dll_base},  // hinstDLL = base address of DLL
        {os::api::DWORD_, 1},             // fdwReason = DLL_PROCESS_ATTACH
        {os::api::LPVOID_, 0},            // lpReserved = 0
    };

    ql_->log().debug("Calling " + dll_name + " DllMain");

    const auto regs_state = ql_->arch().save();

    auto& fcall = ql_->os().fcall();
    fcall.call_native(entry_point, args, exit_point);

    // Execute the call to the entry point
    try {
        ql_->emu_start(entry_point, exit_point);
    } catch (const QlErrorBase&) {
        ql_->log().debug("Error encountered while running " + dll_name + " DllMain, bailing");

        ql_->arch().restore(*regs_state);

        // emu_start leaves the state at STARTED when it raises; reset it so a
        // single failing DllMain does not gate every subsequently loaded
        // DLL's entry point. (verbatim comment)
        ql_->state_ = QL_STATE::STOPPED;
        return;
    }
    // the successful path: fcall.cc.unwind(len(args)) (the verbatim unwind —
    // the cc pops the arg slots and the return address)
    fcall.unwind_native(3);
}
}  // namespace loader
}  // namespace qiling
