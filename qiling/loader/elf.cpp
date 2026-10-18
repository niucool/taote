#include "qiling/loader/elf.hpp"

#include <LIEF/LIEF.hpp>

#include <algorithm>
#include <cstdio>
#include <fstream>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/arch/utils.hpp"

#include "qiling/os/posix/posix.hpp"
#include "qiling/os/posix/map_syscall.hpp"

namespace qiling {
namespace loader {

namespace {

// the ELF container constants (e_type values; the LIEF enum matches them)
constexpr std::uint16_t ET_REL = 1;
constexpr std::uint16_t ET_EXEC = 2;
constexpr std::uint16_t ET_DYN = 3;

}  // namespace

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

namespace {

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

    const std::string ossection = ql_->arch().bits() == 64 ? "OS64" : "OS32";
    auto& profile = ql_->profile();

    // setup program stack (elf.py load: the map happens before the type
    // dispatch, covering the driver and the executable paths alike)
    std::uint64_t stack_address = static_cast<std::uint64_t>(profile.get_int(ossection, "stack_address"));
    const std::uint64_t stack_size = static_cast<std::uint64_t>(profile.get_int(ossection, "stack_size"));
    const std::uint64_t top_of_stack = stack_address + stack_size;

    ql_->mem().map(stack_address, stack_size, UC_PROT_ALL, "[stack]");

    if (elf.type() == ET_REL) {
        // elf.py run: the driver path + the kernel api dispatch hook
        load_driver(elf, bytes, top_of_stack, 0x8000000);

        // the shared run() tail lands the sp on the (aligned) stack top
        ql_->arch().regs().set_arch_sp(stack_address_);

        // elf.py run: self.ql.hook_code(hook_kernel_api) — the hook lives on
        // the os so the uc-after-close discipline releases it with the other
        // os-owned handles
        if (auto* os_posix = dynamic_cast<os::posix::QlOsPosix*>(&ql_->os()); os_posix != nullptr) {
            os_posix->enable_kernel_api_hooks();
        }
        return;
    }

    const bool is_dyn = elf.type() == ET_DYN;
    if (elf.type() != ET_EXEC && !is_dyn) {
        throw QlErrorBase("unexpected elf type value");
    }

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

    // elf.py run tail: sp lands on the auxv stack base (post-load_with_ld);
    // "No idea why" — the FREEBSD rdi quirk, verbatim
    ql_->arch().regs().set_arch_sp(stack_address);
    if (ql_->os().type() == QL_OS::FREEBSD) {
        ql_->arch().regs().write("rdi", stack_address + 0x40);
    }

    init_sp = ql_->arch().regs().arch_sp();

    ql_->os().set_entry_point(entry_point_final);
    entry_point = entry_point_final;

    // map the vsyscall section for some specific needs (elf.py, verbatim):
    // x86-64 LINUX only; three 1KiB-apart syscall stubs on a page that is
    // initialized with int3 padding
    if (ql_->arch().type() == QL_ARCH::X8664 && ql_->os().type() == QL_OS::LINUX) {
        const auto vsyscall_addr = profile.get_uint(ossection, "vsyscall_address");

        // SYSCALL_NR.gettimeofday, SYSCALL_NR.time, SYSCALL_NR.getcpu
        // (os/linux/syscall_nums.py, x86-64 numbers)
        constexpr std::uint64_t vsyscall_ids[] = {96, 201, 309};

        // each syscall should be 1KiB away
        constexpr std::uint64_t entry_size = 1024;
        const auto vsyscall_count = sizeof(vsyscall_ids) / sizeof(vsyscall_ids[0]);
        const auto vsyscall_size = ql_->mem().align_up(static_cast<std::uint64_t>(vsyscall_count) * entry_size);

        if (ql_->mem().is_available(vsyscall_addr, vsyscall_size)) {
            ql_->mem().map(vsyscall_addr, vsyscall_size, UC_PROT_ALL, "[vsyscall]");

            auto& assembler = ql_->arch().assembler();
            for (std::size_t i = 0; i < vsyscall_count; ++i) {
                char asm_buf[64];
                std::snprintf(asm_buf, sizeof(asm_buf), "mov rax, %#llx; syscall; ret",
                              static_cast<unsigned long long>(vsyscall_ids[i]));
                auto entry = assembler.assemble(asm_buf);
                // initialize with int3 then insert the syscall entry
                entry.resize(entry_size, 0xCC);
                ql_->mem().write(vsyscall_addr + i * entry_size, entry);
            }
        }
    }

    mmap_address_ = static_cast<std::uint64_t>(profile.get_int(ossection, "mmap_address"));

    skip_exit_check = (elf_entry_ != entry_point_final);
}

// ---- the ET_REL driver path (elf.py load_driver / lkm_get_init / lkm_dynlinker) ----

void QlLoaderELF::load_driver(const ElfImage& elf, const std::vector<std::uint8_t>& bytes,
                              std::uint64_t stack_addr, std::uint64_t loadbase) {
    // get_elfdata_mapping: the elf header followed by every SHF_ALLOC section
    // at its file offset (the relocatable object is presumed relocated to 0 —
    // the sections land at their sh_offset positions, verbatim comment)
    std::vector<std::uint8_t> elfdata_mapping;
    elfdata_mapping.assign(bytes.begin(), bytes.begin() + 64);  // the ehdr
    for (const LIEF::ELF::Section& sec : elf.binary->sections()) {
        if ((sec.flags() & 0x2u) == 0) {
            continue;  // SHF_ALLOC
        }
        if (sec.offset() > elfdata_mapping.size()) {
            elfdata_mapping.resize(static_cast<std::size_t>(sec.offset()), 0);
        }
        const auto content = sec.content();
        const auto have = std::min<std::uint64_t>(content.size(), sec.size());
        elfdata_mapping.insert(elfdata_mapping.end(), content.begin(), content.begin() + static_cast<std::ptrdiff_t>(have));
        if (have < sec.size()) {
            // SHT_NOBITS (the .bss family) contributes zeros
            elfdata_mapping.insert(elfdata_mapping.end(), static_cast<std::size_t>(sec.size() - have), 0);
        }
    }

    const std::uint64_t mem_start = ql_->mem().align(loadbase);
    const std::uint64_t mem_end = ql_->mem().align_up(loadbase + elfdata_mapping.size());

    // map some memory to intercept external functions of the Linux kernel
    ql_->mem().map(API_HOOK_MEM, API_HOOK_SIZE, UC_PROT_ALL, "[api_mem]");

    const std::string label = std::filesystem::path(ql_->path()).filename().string();
    ql_->mem().map(mem_start, mem_end - mem_start, UC_PROT_ALL, label);
    ql_->mem().write(loadbase, elfdata_mapping);

    images.push_back(Image{mem_start, mem_end, ql_->path()});

    const std::uint64_t init_module = loadbase + lkm_get_init(elf);

    brk_address_ = mem_end;

    // there is no interpreter so the emulation entry point is also the elf
    // entry (elf.py, verbatim)
    elf_entry_ = init_module;
    entry_point = init_module;
    ql_->os().set_entry_point(init_module);

    stack_address_ = ql_->mem().align(stack_addr, ql_->arch().bits() / 8);

    // set up the syscall table
    ql_->mem().map(SYSCALL_MEM, SYSCALL_SIZE, UC_PROT_ALL, "[syscall_mem]");
    ql_->mem().write(SYSCALL_MEM, std::vector<std::uint8_t>(SYSCALL_SIZE, 0));

    lkm_dynlinker(elf, loadbase);

    const auto ptrsize = ql_->arch().bits() / 8;

    // iterate over the relocatable symbols, but pick only those starting with
    // 'sys_' (elf.py, verbatim)
    for (const auto& [name, addr] : rev_reloc_symbols_) {
        if (name.rfind("sys_", 0) == 0 && name != "sys_call_table") {
            const std::string tmp_sc = name.substr(4);
            const auto syscall_id = os::posix::syscall_id_for_name(ql_->arch().type(), tmp_sc);
            if (!syscall_id) {
                continue;  // not a known syscall name (the hasattr check)
            }
            const std::uint64_t dest = SYSCALL_MEM + *syscall_id * ptrsize;
            ql_->mem().write_ptr(dest, static_cast<std::int64_t>(addr), ptrsize);
        }
    }

    // write the syscall addresses into the syscall table (the read/write/open
    // api slots, elf.py verbatim)
    for (std::size_t i = 0; i < 3; ++i) {
        const std::uint64_t dest = SYSCALL_MEM + i * ptrsize;
        ql_->mem().write_ptr(dest, static_cast<std::int64_t>(hook_addr_ + i * ptrsize), ptrsize);
    }
    // set up the hooks for the read/write/open syscalls — the port keys the
    // import table by name (the hook.py dispatch resolves hook_sys_read etc.
    // through the kernel api registry)
    import_symbols_[hook_addr_ + 0 * ptrsize] = ImportSymbol{hook_addr_ + 0 * ptrsize, "sys_read"};
    import_symbols_[hook_addr_ + 1 * ptrsize] = ImportSymbol{hook_addr_ + 1 * ptrsize, "sys_write"};
    import_symbols_[hook_addr_ + 2 * ptrsize] = ImportSymbol{hook_addr_ + 2 * ptrsize, "sys_open"};
}

std::uint64_t QlLoaderELF::lkm_get_init(const ElfImage& elf) const {
    // lkm_get_init: the file offset of the init_module function
    for (const LIEF::ELF::Symbol& sym_ref : elf.binary->symtab_symbols()) {
        const auto* sym = &sym_ref;
        if (sym == nullptr || sym->name() != "init_module") {
            continue;
        }
        // the section at st_shndx: walk the section table by index (the LIEF
        // section list preserves the raw table order)
        std::uint16_t idx = 0;
        for (const LIEF::ELF::Section& sec : elf.binary->sections()) {
            if (idx++ == sym->shndx()) {
                return sym->value() + sec.offset();
            }
        }
    }
    throw QlErrorELFFormat("invalid module: symbol init_module not found");
}

void QlLoaderELF::lkm_dynlinker(const ElfImage& elf, std::uint64_t mem_start) {
    // lkm_dynlinker: walk the object relocations, patch the mapped data, and
    // collect the api/syscall hook addresses (elf.py, verbatim)
    hook_addr_ = API_HOOK_MEM;
    import_symbols_.clear();
    rev_reloc_symbols_.clear();
    std::vector<std::string> all_symbols;

    const auto ptrsize = ql_->arch().bits() / 8;
    const auto machine = elf.binary->header().machine_type();

    for (const LIEF::ELF::Relocation& rel_ref : elf.binary->object_relocations()) {
        const auto& rel = rel_ref;
        const auto* target = rel.section();
        if (target == nullptr) {
            continue;
        }
        if ((target->flags() & 0x2u) == 0) {
            continue;  // SHF_ALLOC
        }
        if (target->name() == ".gnu.linkonce.this_module") {
            continue;  // the module's own metadata needs no relocation
        }

        const auto* sym = rel.symbol();
        if (sym == nullptr) {
            // the r_info_sym==0 relocs resolve against the section itself; the
            // upstream asserts a symbol here and would fault on the null one —
            // the port skips them (the documented deviation)
            continue;
        }

        std::string symbol_name;
        std::uint64_t sym_offset = 0;

        if (sym->name().empty()) {
            // some symbols have zero st_name; the name of the section they
            // point at is used instead (elf.py, verbatim)
            const LIEF::ELF::Section* symsec = nullptr;
            std::uint16_t idx = 0;
            for (const LIEF::ELF::Section& sec : elf.binary->sections()) {
                if (idx++ == sym->shndx()) {
                    symsec = &sec;
                    break;
                }
            }
            if (symsec == nullptr) {
                continue;
            }
            symbol_name = symsec->name();
            sym_offset = symsec->offset();
            rev_reloc_symbols_[symbol_name] = sym_offset + mem_start;
        } else {
            symbol_name = sym->name();
            sym_offset = target->offset();
            if (std::find(all_symbols.begin(), all_symbols.end(), symbol_name) != all_symbols.end()) {
                sym_offset = rev_reloc_symbols_[symbol_name] - mem_start;
            } else {
                all_symbols.push_back(symbol_name);
                if (sym->shndx() == 0) {  // SHN_UNDEF: an external symbol
                    if (symbol_name.rfind("sys_", 0) == 0) {
                        // the syscall hooks must sit pointer-aligned so the
                        // table lookups find the right callback (elf.py)
                        hook_addr_ = ql_->mem().align_up(hook_addr_, ptrsize);
                    }
                    import_symbols_[hook_addr_] = ImportSymbol{hook_addr_, symbol_name};

                    // the rootkit scan shortcut: the syscall table address in
                    // the page_offset_base slot (elf.py FIXME, verbatim)
                    if (symbol_name == "page_offset_base") {
                        ql_->mem().write_ptr(hook_addr_, static_cast<std::int64_t>(SYSCALL_MEM), ptrsize);
                    }
                    rev_reloc_symbols_[symbol_name] = hook_addr_;
                    sym_offset = hook_addr_ - mem_start;
                    hook_addr_ += ptrsize;
                } else if (sym->shndx() == 0xfff1) {  // SHN_ABS
                    rev_reloc_symbols_[symbol_name] = sym->value();
                } else {
                    // a local symbol: the defining section's offset
                    const LIEF::ELF::Section* def_sec = nullptr;
                    std::uint16_t idx2 = 0;
                    for (const LIEF::ELF::Section& sec : elf.binary->sections()) {
                        if (idx2++ == sym->shndx()) {
                            def_sec = &sec;
                            break;
                        }
                    }
                    if (def_sec == nullptr) {
                        continue;
                    }
                    rev_reloc_symbols_[symbol_name] = def_sec->offset() + sym->value() + mem_start;
                }
            }
        }

        // the patch location: the target section's file offset + the reloc
        // offset, mapped into memory (elf.py, verbatim)
        const std::uint64_t loc = target->offset() + rel.address() + mem_start;
        const auto rtype = LIEF::ELF::Relocation::to_value(rel.type());

        switch (machine) {
            case LIEF::ELF::ARCH::X86_64: {
                switch (rtype) {
                    case 11:  // R_X86_64_32S
                    case 10:  // R_X86_64_32
                    {
                        std::uint64_t val = 0;
                        if (rel.addend() != 0) {
                            val = sym_offset + static_cast<std::uint64_t>(rel.addend());
                            val += mem_start;
                        } else {
                            val = rev_reloc_symbols_[symbol_name];
                        }
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        break;
                    }
                    case 1: {  // R_X86_64_64
                        // the +0x2000000 init_module position FIXME, verbatim
                        std::uint64_t val = sym_offset + static_cast<std::uint64_t>(rel.addend());
                        val += 0x2000000;
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val), 8);
                        break;
                    }
                    case 24: {  // R_X86_64_PC64
                        std::uint64_t val = static_cast<std::uint64_t>(rel.addend()) - loc;
                        val += rev_reloc_symbols_[symbol_name];
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val), 8);
                        break;
                    }
                    case 2:    // R_X86_64_PC32
                    case 4: {  // R_X86_64_PLT32
                        std::uint64_t val = static_cast<std::uint64_t>(rel.addend()) - loc;
                        val += rev_reloc_symbols_[symbol_name];
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        break;
                    }
                    default:
                        throw QlErrorNotImplemented("Relocation type not implemented (x86-64: " +
                                                    std::to_string(rtype) + ")");
                }
                break;
            }
            case LIEF::ELF::ARCH::I386: {
                switch (rtype) {
                    case 2:    // R_386_PC32
                    case 4: {  // R_386_PLT32
                        const auto cur = static_cast<std::uint64_t>(ql_->mem().read_ptr(loc, 4));
                        std::uint64_t val = cur + rev_reloc_symbols_[symbol_name] - loc;
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        break;
                    }
                    case 1: {  // R_386_32
                        const auto cur = static_cast<std::uint64_t>(ql_->mem().read_ptr(loc, 4));
                        const std::uint64_t val = cur + rev_reloc_symbols_[symbol_name];
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        break;
                    }
                    default:
                        throw QlErrorNotImplemented("Relocation type not implemented (i386: " +
                                                    std::to_string(rtype) + ")");
                }
                break;
            }
            case LIEF::ELF::ARCH::MIPS: {
                // the mips pairs walk in relocation order (HI16 then LO16)
                switch (rtype) {
                    case 2: {  // R_MIPS_32
                        const auto cur = static_cast<std::uint64_t>(ql_->mem().read_ptr(loc, 4));
                        const std::uint64_t val = cur + rev_reloc_symbols_[symbol_name];
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        prev_mips_hi16_loc_.reset();
                        break;
                    }
                    case 5:  // R_MIPS_HI16: the actual relocation happens at LO16
                        prev_mips_hi16_loc_ = loc;
                        break;
                    case 6: {  // R_MIPS_LO16
                        if (!prev_mips_hi16_loc_) {
                            throw QlErrorNotImplemented("R_MIPS_LO16 without a preceding R_MIPS_HI16");
                        }
                        const auto hi_loc = *prev_mips_hi16_loc_;
                        std::uint64_t val = static_cast<std::uint64_t>(ql_->mem().read_ptr(hi_loc + 2, 2)) << 16 |
                                            static_cast<std::uint64_t>(ql_->mem().read_ptr(loc + 2, 2));
                        val = rev_reloc_symbols_[symbol_name] + val;
                        if ((val & 0xFFFF) >= 0x8000) {
                            val += (1ull << 16);
                        }
                        ql_->mem().write_ptr(hi_loc + 2, static_cast<std::int64_t>((val >> 16) & 0xFFFF), 2);
                        ql_->mem().write_ptr(loc + 2, static_cast<std::int64_t>(val & 0xFFFF), 2);
                        prev_mips_hi16_loc_.reset();
                        break;
                    }
                    default:
                        throw QlErrorNotImplemented("Relocation type not implemented (mips: " +
                                                    std::to_string(rtype) + ")");
                }
                break;
            }
            case LIEF::ELF::ARCH::ARM: {
                switch (rtype) {
                    case 28:   // R_ARM_CALL
                    case 29: { // R_ARM_JUMP24
                        std::uint64_t val = (rev_reloc_symbols_[symbol_name] - loc - 8) >> 2;
                        val = (val & 0xFFFFFF) | (static_cast<std::uint64_t>(ql_->mem().read_ptr(loc, 4)) & 0xFF000000u);
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        break;
                    }
                    case 2: {  // R_ARM_ABS32
                        const auto cur = static_cast<std::uint64_t>(ql_->mem().read_ptr(loc, 4));
                        const std::uint64_t val = rev_reloc_symbols_[symbol_name] + cur;
                        ql_->mem().write_ptr(loc, static_cast<std::int64_t>(val & 0xFFFFFFFFu), 4);
                        break;
                    }
                    default:
                        throw QlErrorNotImplemented("Relocation type not implemented (arm: " +
                                                    std::to_string(rtype) + ")");
                }
                break;
            }
            default:
                throw QlErrorNotImplemented("Relocation walk not implemented for this architecture");
        }
    }
}

}  // namespace loader
}  // namespace qiling
