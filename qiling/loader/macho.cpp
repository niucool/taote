// Ported from qiling/loader/macho_parser/parser.py — the MachoImage parse
// (the skeleton: the ctor runs parseFile(); parseHeader is real, the
// load-command/data stages land with their slices).
#include "qiling/core.hpp"
#include "qiling/os/os.hpp"
#include "qiling/loader/macho.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace qiling {
namespace loader {
namespace macho {

namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return {};
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>{});
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& v, std::size_t off) {
    std::uint32_t x = 0;
    std::memcpy(&x, v.data() + off, 4);
    return x;
}

std::uint64_t get_u64(const std::vector<std::uint8_t>& v, std::size_t off) {
    std::uint64_t x = 0;
    std::memcpy(&x, v.data() + off, 8);
    return x;
}

}  // namespace

MachoImage::MachoImage(const std::filesystem::path& path) {
    binary_file_ = read_file(path);
    if (binary_file_.empty() || !parse_header()) {
        return;
    }
    parse_load_command();
    // parseData lands with its slice
}

// parser.py parseHeader: the magic dispatch — MAGIC_64 -> the 64-bit
// BinaryHeader, else invalid (the fat branch lands with its slice)
bool MachoImage::parse_header() {
    const std::uint32_t magic = get_u32(binary_file_, 0);
    bool is_64 = false;
    for (std::uint32_t m : MAGIC_64) {
        if (magic == m) {
            is_64 = true;
            break;
        }
    }
    if (!is_64) {
        return false;
    }

    // the little-endian unpack of the 32-byte 64-bit header
    header_.magic = magic;
    header_.cpu_type = get_u32(binary_file_, 4);
    header_.cpu_subtype = get_u32(binary_file_, 8);
    header_.file_type = get_u32(binary_file_, 12);
    header_.lc_num = get_u32(binary_file_, 16);
    header_.lc_size = get_u32(binary_file_, 20);
    header_.flags = get_u32(binary_file_, 24);
    header_.reserved = get_u32(binary_file_, 28);

    // the CPU-type check (the upstream keys the arch via ql.arch.type; the
    // skeleton pins the x8664 container only)
    if (header_.cpu_type != CPU_TYPE_X8664) {
        header_ = Header{};
        return false;
    }
    return true;
}

// parser.py parseFile's parseLoadCommand stage: the walk reads the
// cmd_id/cmd_size pair per command, dispatches LC_SEGMENT_64 to the segment
// parse, and advances by the declared cmd_size (unknown commands skip)
bool MachoImage::parse_load_command() {
    const std::size_t header_size = 32;  // the 64-bit header with the reserved
    std::size_t cur = header_size;
    for (std::uint32_t i = 0; i < header_.lc_num; ++i) {
        if (cur + 8 > binary_file_.size()) {
            return false;
        }
        const std::uint32_t cmd = get_u32(binary_file_, cur);
        const std::uint32_t cmd_size = get_u32(binary_file_, cur + 4);
        if (cmd_size < 8 || cur + cmd_size > binary_file_.size()) {
            return false;
        }
        commands_.push_back({cmd, cmd_size, cur});

        if (cmd == LC_SYMTAB) {
            // loadcommand.py LoadSymtab: the symoff/nsyms/stroff/strsize
            // quadruple rides the cmd body
            has_symtab_ = true;
            symoff_ = get_u32(binary_file_, cur + 8);
            nsyms_ = get_u32(binary_file_, cur + 12);
            stroff_ = get_u32(binary_file_, cur + 16);
            strsize_ = get_u32(binary_file_, cur + 20);

            // the nlist_64 entries (the 16-byte records at the symoff)
            symbols_.clear();
            symbols_.reserve(nsyms_);
            for (std::uint32_t s = 0; s < nsyms_; ++s) {
                const std::size_t at = symoff_ + s * 16;
                if (at + 16 > binary_file_.size()) {
                    break;
                }
                Symbol sym;
                sym.n_strx = get_u32(binary_file_, at);
                sym.n_type = binary_file_[at + 4];
                sym.n_sect = binary_file_[at + 5];
                sym.n_desc = static_cast<std::uint16_t>(get_u32(binary_file_, at + 6) & 0xffff);
                sym.n_value = get_u64(binary_file_, at + 8);
                symbols_.push_back(sym);
            }
        }

        if (cmd == LC_DYSYMTAB) {
            // loadcommand.py LoadDysymbolTable: the 18-field command body
            // (the local/extern index pairs over the symtab + the toc/mod
            // /extref/indirect tables + the two relocation lists)
            has_dysymtab_ = true;
            dysymtab_.present = true;
            dysymtab_.ilocalsym = get_u32(binary_file_, cur + 8);
            dysymtab_.nlocalsym = get_u32(binary_file_, cur + 12);
            dysymtab_.iextdefsym = get_u32(binary_file_, cur + 16);
            dysymtab_.nextdefsym = get_u32(binary_file_, cur + 20);
            dysymtab_.iundefsym = get_u32(binary_file_, cur + 24);
            dysymtab_.nundefsym = get_u32(binary_file_, cur + 28);
            dysymtab_.tocoff = get_u32(binary_file_, cur + 32);
            dysymtab_.ntoc = get_u32(binary_file_, cur + 36);
            dysymtab_.modtaboff = get_u32(binary_file_, cur + 40);
            dysymtab_.nmodtab = get_u32(binary_file_, cur + 44);
            dysymtab_.extrefsymoff = get_u32(binary_file_, cur + 48);
            dysymtab_.nextrefsyms = get_u32(binary_file_, cur + 52);
            dysymtab_.indirectsymoff = get_u32(binary_file_, cur + 56);
            dysymtab_.nindirectsyms = get_u32(binary_file_, cur + 60);
            dysymtab_.extreloff = get_u32(binary_file_, cur + 64);
            dysymtab_.nextrel = get_u32(binary_file_, cur + 68);
            dysymtab_.locreloff = get_u32(binary_file_, cur + 72);
            dysymtab_.nlocrel = get_u32(binary_file_, cur + 76);
        }

        if (cmd == LC_SEGMENT_64) {
            // loadcommand.py LoadSegment64: the 72-byte command base (the 8
            // name + the 8/8/8/8 fields + the 4/4/4/4 prots/nsects/flags)
            // then the 0x50 section records
            constexpr std::size_t kSegBase = 72;
            if (cmd_size < kSegBase) {
                return false;
            }
            Segment seg;
            seg.name.assign(reinterpret_cast<const char*>(binary_file_.data()) + cur + 8, 16);
            const std::size_t nul = seg.name.find('\0');
            if (nul != std::string::npos) {
                seg.name.resize(nul);
            }
            seg.vm_address = get_u64(binary_file_, cur + 24);
            seg.vm_size = get_u64(binary_file_, cur + 32);
            seg.file_offset = get_u64(binary_file_, cur + 40);
            seg.file_size = get_u64(binary_file_, cur + 48);
            seg.max_vm_protection = get_u32(binary_file_, cur + 56);
            seg.init_vm_protection = get_u32(binary_file_, cur + 60);
            const std::uint32_t nsects = get_u32(binary_file_, cur + 64);
            seg.flags = get_u32(binary_file_, cur + 68);

            // data.py Segment: the content slice at the file offset
            const std::size_t fo = static_cast<std::size_t>(seg.file_offset);
            if (fo <= binary_file_.size() && fo + seg.file_size <= binary_file_.size()) {
                seg.content.assign(binary_file_.begin() + static_cast<std::ptrdiff_t>(fo),
                                   binary_file_.begin() + static_cast<std::ptrdiff_t>(fo + seg.file_size));
            }

            // loadcommand.py LoadSection64: the 0x50 stride per record
            for (std::uint32_t s = 0; s < nsects; ++s) {
                const std::size_t at = cur + kSegBase + s * 0x50;
                if (at + 0x50 > cur + cmd_size) {
                    return false;
                }
                Section sec;
                sec.name.assign(reinterpret_cast<const char*>(binary_file_.data()) + at, 16);
                sec.segment_name.assign(reinterpret_cast<const char*>(binary_file_.data()) + at + 16, 16);
                const std::size_t n1 = sec.name.find('\0');
                if (n1 != std::string::npos) {
                    sec.name.resize(n1);
                }
                const std::size_t n2 = sec.segment_name.find('\0');
                if (n2 != std::string::npos) {
                    sec.segment_name.resize(n2);
                }
                sec.address = get_u64(binary_file_, at + 32);
                sec.size = get_u64(binary_file_, at + 40);
                sec.offset = get_u32(binary_file_, at + 48);
                sec.alignment = get_u32(binary_file_, at + 52);

                // data.py Section: the content slice at the offset
                const std::size_t so = sec.offset;
                if (so <= binary_file_.size() && so + sec.size <= binary_file_.size()) {
                    sec.content.assign(binary_file_.begin() + static_cast<std::ptrdiff_t>(so),
                                       binary_file_.begin() + static_cast<std::ptrdiff_t>(so + sec.size));
                }
                seg.sections.push_back(std::move(sec));
            }
            segments_.push_back(std::move(seg));
        } else if (cmd == LC_UNIXTHREAD) {
            // loadcommand.py LoadUnixThread: the flavor + the count then the
            // state; the X86_THREAD_STATE64 state rides the rip at the state
            // index 16 (the 16 GPRs before it), the entry = the rip
            const std::size_t state_at = cur + 8;
            if (state_at + 8 > cur + cmd_size) {
                return false;
            }
            thread_flavor_ = get_u32(binary_file_, state_at);
            has_unixthread_ = true;
            if (thread_flavor_ == X86_THREAD_STATE64 && state_at + 8 + 21 * 8 <= cur + cmd_size) {
                unixthread_entry_ = get_u64(binary_file_, state_at + 8 + 16 * 8);
            }
        } else if (cmd == LC_MAIN) {
            // loadcommand.py LoadMain: the entry offset + the stack size
            if (cur + 24 > cur + cmd_size) {
                return false;
            }
            has_main_ = true;
            main_entry_offset_ = get_u64(binary_file_, cur + 8);
            main_stack_size_ = get_u64(binary_file_, cur + 16);
        }
        // the other commands skip by the declared size until their slices
        cur += cmd_size;
    }
    return true;
}

std::string MachoImage::string_at(std::uint32_t strx) const {
    if (!has_symtab_ || strx >= strsize_) {
        return {};
    }
    const std::size_t at = stroff_ + strx;
    const auto end = binary_file_.data() + at;
    const auto limit = binary_file_.data() + binary_file_.size();
    const auto nul = std::find(end, limit, static_cast<std::uint8_t>(0));
    return std::string(end, nul);
}

// ---- loader/macho.py QlLoaderMACHO ----

QlLoaderMachO::QlLoaderMachO(Qiling* ql, std::string dyld_path)
    : QlLoader(ql), dyld_path_(std::move(dyld_path)) {}

void QlLoaderMachO::run() {
    auto& profile = ql_->profile();

    // the shellcode path (loader/macho.py run: the code region maps, the
    // entry moves up into the top page, the sp rides there)
    if (!ql_->code().empty()) {
        const auto shellcode_base = ql_->os().entry_point() + 0x200000 - 0x1000;
        ql_->mem().map(ql_->os().entry_point(), ql_->os().code_ram_size(), UC_PROT_ALL, "[shellcode_stack]");
        ql_->mem().write(shellcode_base, ql_->code());
        ql_->arch().regs().set_arch_sp(shellcode_base);
        ql_->os().set_entry_point(shellcode_base);
        entry_point = shellcode_base;
        load_address = shellcode_base;
        return;
    }

    // the container path: the OS64 stack/heap + the parse + the three-pass
    // load (macho.py run verbatim shape; the commpage and the dyld branch
    // ride their slices)
    const auto stack_address = static_cast<std::uint64_t>(
        profile.get_int("OS64", "stack_address"));
    const auto stack_size = static_cast<std::uint64_t>(
        profile.get_int("OS64", "stack_size"));

    const auto image_path = ql_->path();
    MachoImage image(image_path);
    if (!image.valid()) {
        throw QlErrorBase("macho parse failed: " + image_path);
    }
    is_driver_ = image.header().file_type == 0xb;  // MH_KEXT_BUNDLE

    // the stack (macho.py loadStack: the argv/env pushes ride their slices —
    // the sp lands at the region top verbatim)
    const auto sp = stack_address + stack_size;
    ql_->mem().map(stack_address, stack_size, UC_PROT_ALL, "[stack]");
    ql_->arch().regs().set_arch_sp(sp);
    init_sp = sp;

    if (is_driver_) {
        // macho.py: `if self.is_driver: self.loadDriver(self.stack_address); self.ql.hook_code(hook_kernel_api)`
        // — the hook registration rides the os load()'s enable_kernel_api_hooks
        // (the port's deviation note there); the loadbase rides the options'
        // driver_loadbase override (0 = the verbatim 0xffffff7000000000)
        load_driver(stack_address, image,
                    ql_->driver_loadbase() != 0 ? ql_->driver_loadbase() : 0xffffff7000000000ull);
        entry_point = binary_entry_ + loadbase_;
    } else {
        // the segment pass (macho.py loadMacho pass 2): the map + the content
        const auto slide = static_cast<std::uint64_t>(profile.get_int("LOADER", "slide"));
        for (const auto& seg : image.segments()) {
            load_segment(seg, slide);
        }

        // the entry pass (macho.py pass 1): the LC_UNIXTHREAD rip or the LC_MAIN
        // offset (+ the page-zero anchor)
        if (image.has_unixthread() && image.unixthread_entry().has_value()) {
            binary_entry_ = *image.unixthread_entry();
        } else if (image.has_main()) {
            std::uint64_t page_zero = 0;
            for (const auto& seg : image.segments()) {
                if (seg.name == "__PAGEZERO") {
                    page_zero = seg.vm_size;
                }
            }
            binary_entry_ = image.main_entry_offset() + page_zero;
        }

        // the import symbols (hook.py: the stub address -> the api name; the
        // deviation note: the upstream walks the kernel.development symbol
        // tables — this port-side shortcut rides the file's own LC_SYMTAB)
        for (const auto& sym : image.symbols()) {
            if (sym.n_value == 0) {
                continue;
            }
            const auto name = image.string_at(sym.n_strx);
            if (!name.empty()) {
                import_symbols_[sym.n_value] = ImportSymbol{sym.n_value, name};
            }
        }

        entry_point = binary_entry_ + slide;
    }
    load_address = entry_point;
    ql_->os().set_entry_point(entry_point);
}

void QlLoaderMachO::load_segment(const Segment& seg, std::uint64_t slide) {
    // loadSegment64: the __PAGEZERO maps one page; the rest maps and writes
    // the content (the page-round tail on the vm end)
    constexpr std::uint64_t kPageSize = 0x1000;
    const auto vaddr_start = seg.vm_address + slide;
    auto vaddr_end = seg.vm_address + seg.vm_size + slide;

    if (seg.name.rfind("__PAGEZERO", 0) == 0) {
        ql_->mem().map(vaddr_start, kPageSize, UC_PROT_ALL, "[__PAGEZERO]");
        if (vm_end_addr_ < vaddr_end) {
            vm_end_addr_ = vaddr_end;
        }
        return;
    }

    if (vaddr_end % kPageSize != 0) {
        vaddr_end = ((vaddr_end / kPageSize) + 1) * kPageSize;
    }
    auto data = seg.content;
    if (data.size() < static_cast<std::size_t>(vaddr_end - vaddr_start)) {
        data.resize(static_cast<std::size_t>(vaddr_end - vaddr_start), 0);
    }
    ql_->mem().map(vaddr_start, vaddr_end - vaddr_start, UC_PROT_ALL, "[loadSegment64]");
    ql_->mem().write(vaddr_start, data);
    if (vm_end_addr_ < vaddr_end) {
        vm_end_addr_ = vaddr_end;
    }
}

// macho.py loadDriver: the kext segments at the 0xffffff7000000000 loadbase,
// the [STATIC] stub page, the kernel.development parse + the segment load,
// and the kernel symbol walk (the local + the extern defs over the kernel's
// LC_DYSYMTAB/LC_SYMTAB) feeding import_symbols_ (the kernel-api dispatch
// gate); the relocation passes ride the relocation slice. The upstream
// never sets the entry here (the fixtures drive via os.load_kext) — the
// port derives it from the kext's LC_UNIXTHREAD + the loadbase so the
// run()-driven fixtures can start the blob directly (the documented
// deviation)
void QlLoaderMachO::load_driver(std::uint64_t stack_addr, const MachoImage& image,
                                std::uint64_t loadbase) {
    (void)stack_addr;
    import_symbols_.clear();
    constexpr std::uint64_t kPageSize = 0x1000;
    loadbase_ = loadbase;
    load_address = loadbase_;
    for (const auto& seg : image.segments()) {
        load_segment(seg, loadbase_);
    }
    kext_size_ = vm_end_addr_ - loadbase_;

    const std::filesystem::path kernel_path =
        std::filesystem::path(ql_->rootfs()) / "System" / "Library" / "Kernels" / "kernel.development";
    MachoImage kernel(kernel_path);
    if (!kernel.valid()) {
        throw QlErrorBase("kernel parse failed: " + kernel_path.string());
    }

    // the [STATIC] page for the external static symbol jmp code
    static_addr_ = vm_end_addr_;
    ql_->mem().map(static_addr_, kPageSize, UC_PROT_ALL, "[STATIC]");
    vm_end_addr_ += kPageSize;
    static_symbols_.clear();

    // the kernel segments (the slide 0; the first segment's vm address is
    // the kernel base)
    bool first = true;
    for (const auto& seg : kernel.segments()) {
        if (first) {
            kernel_base_ = seg.vm_address;
            first = false;
        }
        load_segment(seg, 0);
    }

    // the kernel's local + extern symbol walk (the upstream walks the
    // dysymtab index ranges over the symtab and feeds import_symbols with
    // the raw n_value -> name pairs — the hook dispatch keys on these)
    const auto& dys = kernel.dysymtab();
    for (std::uint32_t i = 0; i < dys.nlocalsym; ++i) {
        const auto* sym = kernel.symbol_at(dys.ilocalsym + i);
        if (sym == nullptr) {
            break;
        }
        const auto name = kernel.string_at(sym->n_strx);
        if (!name.empty()) {
            kernel_local_symbols_[name] = sym->n_value;
            import_symbols_[sym->n_value] = ImportSymbol{sym->n_value, name};
        }
    }
    for (std::uint32_t i = 0; i < dys.nextdefsym; ++i) {
        const auto* sym = kernel.symbol_at(dys.iextdefsym + i);
        if (sym == nullptr) {
            break;
        }
        const auto name = kernel.string_at(sym->n_strx);
        if (!name.empty()) {
            kernel_extrn_symbols_[name] = sym->n_value;
            import_symbols_[sym->n_value] = ImportSymbol{sym->n_value, name};
        }
    }

    // (the local + external relocation passes ride the relocation slice)

    // the entry pass (the run()'s non-driver shape: the LC_UNIXTHREAD rip or
    // the LC_MAIN offset; the segments loaded at the loadbase — the raw rip
    // rides the loadbase at the emu-start time)
    if (image.has_unixthread() && image.unixthread_entry().has_value()) {
        binary_entry_ = *image.unixthread_entry();
    } else if (image.has_main()) {
        std::uint64_t page_zero = 0;
        for (const auto& seg : image.segments()) {
            if (seg.name == "__PAGEZERO") {
                page_zero = seg.vm_size;
            }
        }
        binary_entry_ = image.main_entry_offset() + page_zero;
    }

    // the kext's own symbol details (the upstream's kext_local_symbols /
    // kext_extern_symbols dicts, the dysymtab index ranges over the kext's
    // own symtab)
    const auto& kdys = image.dysymtab();
    for (std::uint32_t i = 0; i < kdys.nlocalsym; ++i) {
        const auto* sym = image.symbol_at(kdys.ilocalsym + i);
        if (sym == nullptr) {
            break;
        }
        const auto name = image.string_at(sym->n_strx);
        if (!name.empty()) {
            kext_local_symbols_[name] = sym->n_value;
        }
    }
    for (std::uint32_t i = 0; i < kdys.nextdefsym; ++i) {
        const auto* sym = image.symbol_at(kdys.iextdefsym + i);
        if (sym == nullptr) {
            break;
        }
        const auto name = image.string_at(sym->n_strx);
        if (!name.empty()) {
            kext_extern_symbols_[name] = sym->n_value;
        }
    }

    // the non-IOKit entry walk: __realmain points at the start function's
    // address (the kext link convention); __antimain at the stop
    const auto realmain = kext_local_symbols_.find("__realmain");
    if (realmain != kext_local_symbols_.end()) {
        const auto at = loadbase_ + realmain->second;
        kext_start_ = ql_->mem().read_ptr(at, 8);
    }
    const auto antimain = kext_local_symbols_.find("__antimain");
    if (antimain != kext_local_symbols_.end()) {
        const auto at = loadbase_ + antimain->second;
        kext_stop_ = ql_->mem().read_ptr(at, 8);
    }
}

}  // namespace macho
}  // namespace loader
}  // namespace qiling
