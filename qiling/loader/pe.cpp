#include "qiling/loader/pe.hpp"

#include <LIEF/LIEF.hpp>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/windows.hpp"

#include <filesystem>
#include "qiling/os/os.hpp"

namespace qiling {
namespace loader {

namespace {

// canonicalizes a dll name (pe.py __get_path_elements: append .dll, casefold)
std::string canonical_dll_name(std::string name) {
    bool has_ext = name.size() >= 4 && (name.compare(name.size() - 4, 4, ".dll", 4) == 0 ||
                                        name.compare(name.size() - 4, 4, ".DLL", 4) == 0);
    if (!has_ext) {
        name += ".dll";
    }
    for (auto& c : name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return name;
}

}  // namespace

QlLoaderPE::QlLoaderPE(Qiling* ql, bool libcache) : QlLoader(ql), libcache_(libcache) {}

std::uint64_t QlLoaderPE::load_image(const std::string& host_path, const std::string& label) {
    // LIEF 0.17 is exception-free: a failed parse surfaces as nullptr (the
    // robustness tenet: malformed binaries raise QlError*, never a host crash)
    auto parsed = LIEF::PE::Parser::parse(host_path);
    if (parsed == nullptr) {
        throw QlErrorBase("failed to parse PE: " + host_path);
    }

    auto& mem = ql_->mem();
    const bool is64 = parsed->type() == LIEF::PE::PE_TYPE::PE32_PLUS;

    const std::uint64_t image_base = parsed->imagebase();
    const std::uint64_t size_of_image = parsed->virtual_size();
    const std::uint64_t entry_rva = parsed->entrypoint() - image_base;

    // loader/pe.py load: if the default base is taken, fall back to the
    // profile image_address
    std::uint64_t base = image_base;
    if (!mem.is_available(base, mem.align_up(size_of_image))) {
        base = image_address_;
    }

    entry_point = base + entry_rva;

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

    // the imports: stub each imported function with a unique address in the
    // stub region (loader/pe.py init_imports); the api dispatcher matches
    // the pc against these stubs
    for (const LIEF::PE::Import& import : parsed->imports()) {
        const std::string dll = canonical_dll_name(import.name());
        for (const LIEF::PE::ImportEntry& entry : import.entries()) {
            ImportSymbol symbol;
            symbol.address = entry.iat_address();
            symbol.dll = dll;
            symbol.name = entry.name();
            import_symbols_[symbol.address] = std::move(symbol);
        }
    }

    // loader/pe.py init_exports: the exports ride the export_symbols map
    // (ea-keyed) plus the image's own iat slice; the GetProcAddress self
    // branch walks them verbatim
    if (parsed->has_exports()) {
        const auto* export_ = parsed->get_export();
        std::map<std::string, std::uint64_t> iat_by_name;
        std::map<std::uint64_t, std::uint64_t> iat_by_ordinal;

        for (const LIEF::PE::ExportEntry& entry : export_->entries()) {
            const std::uint64_t ea = base + entry.address();

            ExportSymbol symbol;
            symbol.address = ea;
            symbol.name = entry.name();
            symbol.ordinal = entry.ordinal();
            export_symbols_[ea] = std::move(symbol);

            if (!entry.name().empty()) {
                iat_by_name[entry.name()] = ea;
            }
            iat_by_ordinal[entry.ordinal()] = ea;
        }

        // dll_name = os.path.basename(self.path).casefold() (verbatim)
        const std::filesystem::path loaded(host_path);
        std::string dll_name = loaded.filename().string();
        for (auto& c : dll_name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
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

    // loader/pe.py: self.dll_size += dll_len (the GetSystemInfo rider; the
    // port tracks the mapped length through the load_image's parse)
    {
        auto parsed = LIEF::PE::Parser::parse(dll_path_host);
        if (parsed != nullptr) {
            dll_size_ += parsed->virtual_size();
        }
    }

    const auto base = load_image(dll_path_host, dll_name);
    (void)base;

    // the loaded image's exports ride the same maps (the load_image's
    // export-registration keyed the main image only; the dll path registers
    // under the dll basename here)
    return get_image_by_name(dll_name, true) ? get_image_by_name(dll_name, true)->base : 0;
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
    } else {
        // the PE image path
        pe_image_address_ = load_image(ql_->path(), ql_->targetname());
    }

    init_sp = ql_->arch().regs().arch_sp();
}

}  // namespace loader
}  // namespace qiling
