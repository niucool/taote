#include "qiling/loader/pe.hpp"

#include <pe-parse/parse.h>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace loader {

namespace {

// the iterVAStr callback adapter: (cbd, VA, module_name, symbol_name)
struct ImportCollector {
    std::string dll;  // the importing dll's canonical name
    std::vector<ImportSymbol> symbols;
};

int collect_import(void* cbd, const peparse::VA& va, const std::string& module_name, const std::string& symbol_name) {
    auto* collector = static_cast<ImportCollector*>(cbd);
    ImportSymbol symbol;
    symbol.address = va;
    symbol.dll = collector->dll;
    symbol.name = symbol_name;
    collector->symbols.push_back(std::move(symbol));
    return 0;  // continue iteration
}

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
    auto* parsed = peparse::ParsePEFromFile(host_path.c_str());
    if (parsed == nullptr) {
        // the robustness tenet: malformed binaries raise QlError*, never a
        // host crash
        throw QlErrorBase("failed to parse PE: " + host_path + " (" + peparse::GetPEErrString() + ")");
    }

    auto& mem = ql_->mem();
    const bool is64 = parsed->peHeader.nt.OptionalMagic == 0x20b;  // PE32+

    const std::uint64_t image_base = is64 ? parsed->peHeader.nt.OptionalHeader64.ImageBase
                                          : parsed->peHeader.nt.OptionalHeader.ImageBase;
    const std::uint64_t size_of_image = is64 ? parsed->peHeader.nt.OptionalHeader64.SizeOfImage
                                             : parsed->peHeader.nt.OptionalHeader.SizeOfImage;
    const std::uint64_t entry_rva = is64 ? parsed->peHeader.nt.OptionalHeader64.AddressOfEntryPoint
                                         : parsed->peHeader.nt.OptionalHeader.AddressOfEntryPoint;

    // loader/pe.py load: if the default base is taken, fall back to the
    // profile image_address
    std::uint64_t base = image_base;
    if (!mem.is_available(base, mem.align_up(size_of_image))) {
        base = image_address_;
    }

    entry_point = base + entry_rva;

    mem.map(base, mem.align_up(size_of_image), UC_PROT_ALL, label);
    images.push_back(Image{base, base + size_of_image, host_path});

    // stage the sections through the iteration API
    struct SectionWriter {
        Qiling* ql;
        std::uint64_t base;
    } writer{ql_, base};

    peparse::IterSec(parsed, [](void* cbd, const peparse::VA& va, const std::string&,
                               const peparse::image_section_header& sect, const peparse::bounded_buffer* buffer) -> int {
        (void)va;
        auto* w = static_cast<SectionWriter*>(cbd);
        if (sect.SizeOfRawData == 0 || buffer == nullptr) {
            return 0;  // continue
        }

        // the section bytes come through the bounded-buffer read API
        std::vector<std::uint8_t> data(sect.SizeOfRawData);
        for (std::uint32_t i = 0; i < sect.SizeOfRawData; ++i) {
            std::uint8_t byte = 0;
            if (peparse::readByte(const_cast<peparse::bounded_buffer*>(buffer), i, byte)) {
                data[i] = byte;
            }
        }
        w->ql->mem().write(w->base + sect.VirtualAddress, data);
        return 0;  // continue
    }, &writer);

    // the imports: stub each imported function with a unique address in the
    // stub region (loader/pe.py init_imports); the api dispatcher matches
    // the pc against these stubs
    ImportCollector collector;
    peparse::IterImpVAString(parsed, [](void* cbd, const peparse::VA& va, const std::string& module_name,
                                        const std::string& symbol_name) -> int {
        auto* c = static_cast<ImportCollector*>(cbd);
        if (c->dll.empty()) {
            c->dll = canonical_dll_name(module_name);
        } else if (canonical_dll_name(module_name) != c->dll) {
            // a new module began; keep collecting (the per-module boundary is
            // tracked by the name switch inside the loop below)
            c->dll = canonical_dll_name(module_name);
        }
        ImportSymbol symbol;
        symbol.address = va;
        symbol.dll = c->dll;
        symbol.name = symbol_name;
        c->symbols.push_back(std::move(symbol));
        return 0;  // continue
    }, &collector);

    for (const auto& symbol : collector.symbols) {
        import_symbols_[symbol.address] = symbol;
    }

    peparse::DestructParsedPE(parsed);
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
