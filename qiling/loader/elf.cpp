#include "qiling/loader/elf.hpp"

#include <LIEF/LIEF.hpp>

#include <algorithm>
#include <fstream>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"

#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace loader {

namespace {

// the ELF container constants (e_type values; the LIEF enum matches them)
constexpr std::uint16_t ET_REL = 1;
constexpr std::uint16_t ET_EXEC = 2;
constexpr std::uint16_t ET_DYN = 3;

// the parsed container (the ELFFile analogue) — LIEF-backed (decision D17:
// one parsing dependency for PE/ELF/…; the qiling-specific consolidation and
// auxv logic stays hand-ported on top of it)
struct ElfImage {
    std::unique_ptr<LIEF::ELF::Binary> binary;

    // ET_REL/ET_EXEC/ET_DYN as the raw e_type value (the LIEF enum matches)
    std::uint16_t type() const {
        switch (binary->header().file_type()) {
            case LIEF::ELF::Header::FILE_TYPE::REL: return ET_REL;
            case LIEF::ELF::Header::FILE_TYPE::EXEC: return ET_EXEC;
            case LIEF::ELF::Header::FILE_TYPE::DYN: return ET_DYN;
            default: return 0;
        }
    }

    std::uint64_t entry() const { return binary->entrypoint(); }
    std::uint64_t phoff() const { return binary->header().program_headers_offset(); }
    std::uint16_t phentsize() const { return static_cast<std::uint16_t>(binary->header().program_header_size()); }
    std::uint16_t phnum() const { return static_cast<std::uint16_t>(binary->header().numberof_segments()); }

    const std::string& interpreter() const {
        static const std::string empty;
        return binary->has_interpreter() ? binary->interpreter() : empty;
    }

    [[nodiscard]] static ElfImage parse(const std::vector<std::uint8_t>& bytes) {
        // LIEF 0.17 is exception-free: a failed parse surfaces as nullptr
        // (the robustness tenet: a truncated or foreign container degrades
        // to QlError*, never a host crash)
        auto binary = LIEF::ELF::Parser::parse(bytes);
        if (binary == nullptr) {
            throw QlErrorBase("ELF format error: parse failed");
        }
        return ElfImage{std::move(binary)};
    }

    std::vector<const LIEF::ELF::Segment*> load_segments() const {
        std::vector<const LIEF::ELF::Segment*> out;
        for (const LIEF::ELF::Segment& seg : binary->segments()) {
            if (seg.is_load()) {
                out.push_back(&seg);
            }
        }
        // elf.py: the segments are loaded in vaddr order
        std::sort(out.begin(), out.end(), [](const LIEF::ELF::Segment* a, const LIEF::ELF::Segment* b) {
            return a->virtual_address() < b->virtual_address();
        });
        return out;
    }
};

// seg_perm_to_uc_prot (elf.py, verbatim); the LIEF FLAGS bit values match
// the ELF p_flags encodings (X=1, W=2, R=4)
int seg_perm_to_uc_prot(LIEF::ELF::Segment::FLAGS perm) {
    const auto p = static_cast<std::uint32_t>(perm);
    int prot = UC_PROT_NONE;
    if ((p & 1) != 0) prot |= UC_PROT_EXEC;
    if ((p & 2) != 0) prot |= UC_PROT_WRITE;
    if ((p & 4) != 0) prot |= UC_PROT_READ;
    return prot;
}

// the segment's file bytes (elf.py seg.data(); LIEF hands back the raw view)
std::vector<std::uint8_t> segment_data(const LIEF::ELF::Segment& seg) {
    const auto content = seg.content();
    return std::vector<std::uint8_t>{content.begin(), content.end()};
}

}  // namespace

QlLoaderELF::QlLoaderELF(Qiling* ql) : QlLoader(ql) {}

void QlLoaderELF::run() {
    // the shellcode path (elf.py: map the shellcode stack region, write the
    // code at the top, point the pc there)
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

    // the container path: parse, map, set up the stack
    std::vector<std::uint8_t> bytes;
    {
        std::ifstream in(ql_->path(), std::ios::binary);
        if (!in) {
            throw QlErrorFileNotFound("Target binary not found: \"" + ql_->path() + "\"");
        }
        in.seekg(0, std::ios::end);
        const auto size = in.tellg();
        in.seekg(0, std::ios::beg);
        bytes.resize(static_cast<std::size_t>(size));
        in.read(reinterpret_cast<char*>(bytes.data()), size);
    }

    ElfImage elf = ElfImage::parse(bytes);

    if (elf.type() == ET_REL) {
        // the LKM driver path lands with the kernel-module slice
        throw QlErrorNotImplemented("the ET_REL driver path lands with the kernel-module slice");
    }

    const bool is_dyn = elf.type() == ET_DYN;
    if (elf.type() != ET_EXEC && !is_dyn) {
        throw QlErrorBase("unexpected elf type value");
    }

    const std::string ossection = ql_->arch().bits() == 64 ? "OS64" : "OS32";
    auto& profile = ql_->profile();

    std::uint64_t stack_address = static_cast<std::uint64_t>(profile.get_int(ossection, "stack_address"));
    const std::uint64_t stack_size = static_cast<std::uint64_t>(profile.get_int(ossection, "stack_size"));
    const std::uint64_t top_of_stack = stack_address + stack_size;

    ql_->mem().map(stack_address, stack_size, UC_PROT_ALL, "[stack]");

    // ET_DYN relocates to the profile load_address; ET_EXEC stays at its base
    const std::uint64_t load_address = is_dyn
        ? static_cast<std::uint64_t>(profile.get_int(ossection, "load_address"))
        : 0;

    // ---- load_elf_segments: consolidate the PT_LOAD regions ----
    const auto load_segments = elf.load_segments();

    std::vector<LoadRegion> regions;
    std::vector<std::pair<const LIEF::ELF::Segment*, std::uint64_t>> seg_files;  // (segment, load base)

    for (const auto* seg : load_segments) {
        const auto lbound = ql_->mem().align(load_address + seg->virtual_address());
        const auto ubound = ql_->mem().align_up(load_address + seg->virtual_address() + seg->virtual_size());
        const auto perms = seg_perm_to_uc_prot(seg->flags());

        if (!regions.empty()) {
            const auto& [prev_lbound, prev_ubound, prev_perms] = regions.back();
            if (lbound == prev_ubound) {
                if (perms == prev_perms) {
                    regions.back() = LoadRegion{prev_lbound, ubound, prev_perms};
                } else {
                    regions.push_back(LoadRegion{lbound, ubound, perms});
                }
            } else if (lbound > prev_ubound) {
                regions.push_back(LoadRegion{lbound, ubound, perms});
            } else {
                // the EDL ELF 0x400-byte-page workaround (elf.py) applies to
                // ARM64; other archs treat the overlap as an error
                if (ql_->arch().type() == QL_ARCH::ARM64) {
                    regions.back() = LoadRegion{prev_lbound, ubound, prev_perms | perms};
                    continue;
                }
                throw QlErrorBase("overlapping ELF load segments");
            }
        } else {
            regions.push_back(LoadRegion{lbound, ubound, perms});
        }

        seg_files.emplace_back(seg, load_address);
    }

    for (const auto& [lbound, ubound, perms] : regions) {
        if (ubound > lbound) {
    ql_->mem().map(lbound, ubound - lbound, perms, ql_->targetname());
        }
    }

    for (const auto& [seg, base] : seg_files) {
        ql_->mem().write(base + seg->virtual_address(), segment_data(*seg));
    }

    mem_start_ = regions.front().lbound;
    mem_end_ = regions.back().ubound;
    elf_entry_ = load_address + elf.entry();

    images.push_back(Image{mem_start_, mem_end_, ql_->path()});

    // the program break sits 0x2000 past the image (elf.py, verbatim)
    brk_address_ = mem_end_ + 0x2000;

    // the interpreter (PT_INTERP): resolve through the rootfs, load its
    // segments, and let its entry take over (elf.py load_with_ld's interp
    // branch); the AT_BASE auxv entry points at the interpreter base
    std::uint64_t interp_address = 0;
    std::uint64_t entry_point_final = elf_entry_;
    if (!elf.interpreter().empty()) {
        const auto* os_posix = dynamic_cast<const os::posix::QlOsPosix*>(&ql_->os());
        const auto* os_path = (os_posix != nullptr && os_posix->path() != nullptr) ? os_posix->path() : nullptr;
        const std::string interp_vpath = elf.interpreter();
        const std::string interp_hpath = os_path != nullptr
            ? os_path->virtual_to_host_path(interp_vpath)
            // the bare-metal fallback: strip the leading slash
            : (std::filesystem::path(ql_->rootfs()) /
               (interp_vpath.front() == '/' ? interp_vpath.substr(1) : interp_vpath)).string();

        // the safety tenet (elf.py is_safe_host_path): refuse interpreter
        // paths outside the rootfs
        if (os_path == nullptr || !os_path->is_safe_host_path(interp_hpath)) {
            throw QlErrorBase("unsafe path: " + interp_hpath);
        }

        std::ifstream in(interp_hpath, std::ios::binary);
        if (!in) {
            throw QlErrorFileNotFound("interpreter not found: " + interp_hpath);
        }
        in.seekg(0, std::ios::end);
        const auto size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<std::uint8_t> interp_bytes(static_cast<std::size_t>(size));
        in.read(reinterpret_cast<char*>(interp_bytes.data()), size);

        const auto interp = ElfImage::parse(interp_bytes);

        // the interpreter vaddr base: a pre-relocated interpreter (min vaddr
        // != 0) maps at its own vaddrs, otherwise the profile's interp_address
        // slot applies (elf.py, verbatim logic)
        std::uint64_t interp_base = 0;
        std::uint64_t min_vaddr = ~std::uint64_t{0};
        for (const auto* seg : interp.load_segments()) {
            min_vaddr = std::min(min_vaddr, seg->virtual_address());
        }
        if (min_vaddr == 0) {
            interp_base = static_cast<std::uint64_t>(profile.get_int(ossection, "interp_address"));
        }

        // load the interpreter segments (the same region consolidation)
        const auto interp_segs = interp.load_segments();
        std::vector<LoadRegion> interp_regions;
        for (const auto* seg : interp_segs) {
            const auto lbound = ql_->mem().align(interp_base + seg->virtual_address());
            const auto ubound = ql_->mem().align_up(interp_base + seg->virtual_address() + seg->virtual_size());
            const auto perms = seg_perm_to_uc_prot(seg->flags());
            if (!interp_regions.empty() && lbound == interp_regions.back().ubound &&
                perms == interp_regions.back().perms) {
                interp_regions.back().ubound = ubound;
            } else {
                interp_regions.push_back(LoadRegion{lbound, ubound, perms});
            }
        }
        for (const auto& region : interp_regions) {
            if (region.ubound > region.lbound) {
                ql_->mem().map(region.lbound, region.ubound - region.lbound, region.perms, "ld");
            }
        }
        for (const auto* seg : interp_segs) {
            ql_->mem().write(interp_base + seg->virtual_address(), segment_data(*seg));
        }

        const auto interp_start = interp_regions.front().lbound;
        const auto interp_end = interp_regions.back().ubound;
        images.push_back(Image{interp_start, interp_end, interp_hpath});

        interp_address_ = interp_base;
        entry_point_final = interp_base + interp.entry();
    }

    // ---- the auxv stack (elf.py: argc/argv/envp/auxv) ----
    std::vector<std::uint8_t> elf_table;
    auto push_bytes = [&](std::uint64_t top, const std::vector<std::uint8_t>& data) {
        // write the data + the terminator, aligned to the pointer size
        std::vector<std::uint8_t> with_null(data);
        with_null.push_back(0);
        const auto ptrsize = ql_->arch().bits() / 8;
        const auto aligned = ql_->mem().align(top - with_null.size(), ptrsize);
        ql_->mem().write(aligned, with_null);
        return aligned;
    };
    auto push_str = [&](std::uint64_t top, std::string_view text) {
        return push_bytes(top, std::vector<std::uint8_t>(text.begin(), text.end()));
    };
    auto pack_ptr = [&](std::uint64_t v) {
        const auto ptrsize = ql_->arch().bits() / 8;
        std::vector<std::uint8_t> out(ptrsize, 0);
        for (std::size_t i = 0; i < ptrsize; ++i) {
            out[i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
        return out;
    };

    const auto& argv = ql_->argv();
    const auto& env = ql_->env();

    // argc
    {
        auto argc = pack_ptr(argv.size());
        elf_table.insert(elf_table.end(), argc.begin(), argc.end());
    }

    std::uint64_t new_stack = top_of_stack;
    std::uint64_t execfn = 0;
    std::uint64_t cpustraddr = 0;
    std::uint64_t randstraddr = 0;

    // argv pointers
    for (std::size_t i = 0; i < argv.size(); ++i) {
        new_stack = push_str(new_stack, argv[i]);
        auto ptr = pack_ptr(new_stack);
        elf_table.insert(elf_table.end(), ptr.begin(), ptr.end());
    }
    {
        auto null_ptr = pack_ptr(0);
        elf_table.insert(elf_table.end(), null_ptr.begin(), null_ptr.end());
    }

    // env pairs
    for (const auto& [key, value] : env) {
        std::string pair = key + "=" + value;
        new_stack = push_bytes(new_stack, std::vector<std::uint8_t>(pair.begin(), pair.end()));
        auto ptr = pack_ptr(new_stack);
        elf_table.insert(elf_table.end(), ptr.begin(), ptr.end());
    }
    {
        auto null_ptr = pack_ptr(0);
        elf_table.insert(elf_table.end(), null_ptr.begin(), null_ptr.end());
    }

    new_stack = randstraddr = push_str(new_stack, std::string(16, 'a'));
    new_stack = cpustraddr = push_str(new_stack, "i686");
    new_stack = execfn = push_str(new_stack, argv.empty() ? std::string("") : argv[0]);

    // the auxv entries (elf.py)
    const auto* os_posix = dynamic_cast<const os::posix::QlOsPosix*>(&ql_->os());
    const int uid = os_posix ? os_posix->uid() : 1000;
    const int gid = os_posix ? os_posix->gid() : 1000;

    const std::pair<AUXV, std::uint64_t> auxv_entries[] = {
        {AUXV::AT_PHDR, elf.phoff() + mem_start_},
        {AUXV::AT_PHENT, elf.phentsize()},
        {AUXV::AT_PHNUM, elf.phnum()},
        {AUXV::AT_PAGESZ, 0x1000},
        {AUXV::AT_FLAGS, 0},
        {AUXV::AT_ENTRY, elf_entry_},
        {AUXV::AT_UID, static_cast<std::uint64_t>(uid)},
        {AUXV::AT_EUID, static_cast<std::uint64_t>(uid)},
        {AUXV::AT_GID, static_cast<std::uint64_t>(gid)},
        {AUXV::AT_EGID, static_cast<std::uint64_t>(gid)},
        {AUXV::AT_CLKTCK, 100},
        {AUXV::AT_PLATFORM, cpustraddr},
        {AUXV::AT_HWCAP, 0},
        {AUXV::AT_SECURE, 0},
        {AUXV::AT_RANDOM, randstraddr},
        {AUXV::AT_HWCAP2, 0},
        {AUXV::AT_EXECFN, execfn},
        {AUXV::AT_NULL, 0},
    };

    // the AT_BASE entry lands only when an interpreter was loaded (elf.py)
    if (!elf.interpreter().empty()) {
        auto k = pack_ptr(static_cast<std::uint64_t>(AUXV::AT_BASE));
        auto v = pack_ptr(interp_address_);
        elf_table.insert(elf_table.end(), k.begin(), k.end());
        elf_table.insert(elf_table.end(), v.begin(), v.end());
    }
    const auto bytes_before_auxv = elf_table.size();
    for (const auto& [key, val] : auxv_entries) {
        auto k = pack_ptr(static_cast<std::uint64_t>(key));
        auto v = pack_ptr(val);
        elf_table.insert(elf_table.end(), k.begin(), k.end());
        elf_table.insert(elf_table.end(), v.begin(), v.end());
    }

    auto sp_align = static_cast<std::uint64_t>(ql_->arch().bits() / 8);
    // mips requires doubleword alignment (elf.py, verbatim)
    if (ql_->arch().type() == QL_ARCH::MIPS) {
        sp_align *= 2;
    }
    new_stack = ql_->mem().align(new_stack - elf_table.size(), sp_align);
    ql_->mem().write(new_stack, elf_table);

    auxv_address_ = new_stack + bytes_before_auxv;
    stack_address = new_stack;  // QlLoader::stack_address
    init_sp = ql_->arch().regs().arch_sp();

    ql_->os().set_entry_point(entry_point_final);
    entry_point = entry_point_final;

    // the interpreter + vsyscall setup land with their slices
    mmap_address_ = static_cast<std::uint64_t>(profile.get_int(ossection, "mmap_address"));

    skip_exit_check = (elf_entry_ != entry_point_final);
}

}  // namespace loader
}  // namespace qiling
