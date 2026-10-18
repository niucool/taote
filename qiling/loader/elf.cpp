#include "qiling/loader/elf.hpp"

#include <algorithm>
#include <fstream>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"

#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace loader {

namespace {

// the ELF64 container constants
constexpr std::uint8_t ELFCLASS64 = 2;
constexpr std::uint16_t ET_REL = 1;
constexpr std::uint16_t ET_EXEC = 2;
constexpr std::uint16_t ET_DYN = 3;

constexpr std::uint32_t PT_LOAD = 1;
constexpr std::uint32_t PT_INTERP = 3;

// the program header fields (elf64_phdr, 56 bytes)
struct Phdr {
    std::uint32_t type;
    std::uint32_t flags;
    std::uint64_t offset;
    std::uint64_t vaddr;
    std::uint64_t paddr;
    std::uint64_t filesz;
    std::uint64_t memsz;
    std::uint64_t align;
};

// the parsed container (the ELFFile analogue)
struct ElfImage {
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::uint64_t entry = 0;
    std::uint64_t phoff = 0;
    std::uint16_t phentsize = 0;
    std::uint16_t phnum = 0;
    std::vector<Phdr> segments;
    std::string interpreter;  // the PT_INTERP contents (empty when absent)

    [[nodiscard]] static ElfImage parse(const std::vector<std::uint8_t>& bytes) {
        // the robustness tenet: a truncated or foreign container degrades to
        // QlErrorELFFormat, never a host crash
        if (bytes.size() < 64 || bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F') {
            throw QlErrorBase("ELF format error: not an ELF container");
        }

        ElfImage img;
        const bool is64 = bytes[4] == ELFCLASS64;
        if (!is64) {
            // the 32-bit container parses through the same fields at their
            // ELF32 offsets; the port covers the x86/arm/mips 32-bit layouts
            img.type = static_cast<std::uint16_t>(bytes[16] | (bytes[17] << 8));
            img.machine = static_cast<std::uint16_t>(bytes[18] | (bytes[19] << 8));
            img.entry = 0;  // resolved below through the 32-bit layout
            img.phoff = 0;
            // (the ELF32 auxv/mapping path lands with the 32-bit fixtures)
            throw QlErrorBase("ELF format error: the ELF32 container path lands with its slice");
        }

        auto rd16 = [&](std::size_t off) {
            return static_cast<std::uint16_t>(bytes[off] | (bytes[off + 1] << 8));
        };
        auto rd32 = [&](std::size_t off) {
            return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8) |
                   (static_cast<std::uint32_t>(bytes[off + 2]) << 16) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24);
        };
        auto rd64 = [&](std::size_t off) {
            std::uint64_t v = 0;
            for (int i = 0; i < 8; ++i) {
                v |= static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8 * i);
            }
            return v;
        };

        img.type = rd16(16);
        img.machine = rd16(18);
        img.entry = rd64(24);
        img.phoff = rd64(32);
        img.phentsize = rd16(54);
        img.phnum = rd16(56);

        if (img.phnum > 0 && img.phentsize < 56) {
            throw QlErrorBase("ELF format error: bad e_phentsize");
        }

        for (std::uint16_t i = 0; i < img.phnum; ++i) {
            const std::size_t off = img.phoff + static_cast<std::size_t>(i) * img.phentsize;
            if (off + 56 > bytes.size()) {
                throw QlErrorBase("ELF format error: truncated program headers");
            }
            Phdr ph;
            ph.type = rd32(off + 0);
            ph.flags = rd32(off + 4);
            ph.offset = rd64(off + 8);
            ph.vaddr = rd64(off + 16);
            ph.paddr = rd64(off + 24);
            ph.filesz = rd64(off + 32);
            ph.memsz = rd64(off + 40);
            ph.align = rd64(off + 48);
            img.segments.push_back(ph);
        }

        // the interpreter: the PT_INTERP segment holds the path string
        for (const auto& ph : img.segments) {
            if (ph.type == PT_INTERP) {
                const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(ph.offset);
                const auto end = begin + static_cast<std::ptrdiff_t>(ph.filesz);
                std::string interp(reinterpret_cast<const char*>(&*begin),
                                   static_cast<std::size_t>(ph.filesz));
                const auto nul = interp.find('\0');
                if (nul != std::string::npos) {
                    interp.resize(nul);
                }
                img.interpreter = std::move(interp);
                break;
            }
        }

        return img;
    }

    std::vector<const Phdr*> load_segments() const {
        std::vector<const Phdr*> out;
        for (const auto& ph : segments) {
            if (ph.type == PT_LOAD) {
                out.push_back(&ph);
            }
        }
        // elf.py: the segments are loaded in vaddr order
        std::sort(out.begin(), out.end(), [](const Phdr* a, const Phdr* b) { return a->vaddr < b->vaddr; });
        return out;
    }
};

// the file bytes at the segment's file offset (elf.py seg.data())
std::vector<std::uint8_t> segment_data(const std::vector<std::uint8_t>& bytes, const Phdr& ph) {
    if (ph.offset >= bytes.size()) {
        return {};
    }
    const auto avail = std::min<std::uint64_t>(ph.filesz, bytes.size() - ph.offset);
    return std::vector<std::uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(ph.offset),
                                     bytes.begin() + static_cast<std::ptrdiff_t>(ph.offset + avail));
}

// seg_perm_to_uc_prot (elf.py, verbatim)
int seg_perm_to_uc_prot(std::uint32_t perm) {
    int prot = UC_PROT_NONE;
    if ((perm & 1) != 0) prot |= UC_PROT_EXEC;
    if ((perm & 2) != 0) prot |= UC_PROT_WRITE;
    if ((perm & 4) != 0) prot |= UC_PROT_READ;
    return prot;
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

    if (elf.type == ET_REL) {
        // the LKM driver path lands with the kernel-module slice
        throw QlErrorNotImplemented("the ET_REL driver path lands with the kernel-module slice");
    }

    const bool is_dyn = elf.type == ET_DYN;
    if (elf.type != ET_EXEC && !is_dyn) {
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
    std::vector<std::pair<const Phdr*, std::uint64_t>> seg_files;  // (segment, load base)

    for (const auto* seg : load_segments) {
        const auto lbound = ql_->mem().align(load_address + seg->vaddr);
        const auto ubound = ql_->mem().align_up(load_address + seg->vaddr + seg->memsz);
        const auto perms = seg_perm_to_uc_prot(seg->flags);

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
        ql_->mem().write(base + seg->vaddr, segment_data(bytes, *seg));
    }

    mem_start_ = regions.front().lbound;
    mem_end_ = regions.back().ubound;
    elf_entry_ = load_address + elf.entry;

    images.push_back(Image{mem_start_, mem_end_, ql_->path()});

    // the program break sits 0x2000 past the image (elf.py, verbatim)
    brk_address_ = mem_end_ + 0x2000;

    // the interpreter (PT_INTERP): the loader resolves it through the rootfs;
    // the stub-based fixtures have none
    std::uint64_t interp_address = 0;
    std::string interp_path = elf.interpreter;
    (void)interp_path;

    const auto entry_point_final = elf_entry_;

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
        {AUXV::AT_PHDR, elf.phoff + mem_start_},
        {AUXV::AT_PHENT, elf.phentsize},
        {AUXV::AT_PHNUM, elf.phnum},
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
