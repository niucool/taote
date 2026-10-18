#include "qiling/loader/pe.hpp"

#include <LIEF/LIEF.hpp>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
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

    return base;
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
        const auto base = load_image(ql_->path(), ql_->targetname());
        (void)base;
    }

    init_sp = ql_->arch().regs().arch_sp();
}

}  // namespace loader
}  // namespace qiling
