// Ported from qiling/loader/elf.py — QlLoaderELF (PORT_PLAN.md §10 Phase 5).
// The pyelftools `ELFFile` surface maps onto a lean hand parser over the ELF
// container headers (the same approach utils.py's __emu_env_from_elf already
// takes; no ELFIO dependency).
//
//   ELFFile(stream)                       -> ElfImage (the parsed container)
//   elffile['e_type'/'e_entry'/...]       -> ElfImage fields
//   elffile.iter_segments(type='PT_LOAD') -> ElfImage::segments (filtered)
//   seg.data()                            -> the file bytes at p_offset
//   PT_INTERP.get_interp_name()           -> ElfImage::interpreter
//
// The LKM (ET_REL driver) path with its relocation walk, the FunctionHook
// surface and the vsyscall setup land with their slices (PORT_PLAN.md).
#ifndef QILING_LOADER_ELF_HPP
#define QILING_LOADER_ELF_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "qiling/loader/loader.hpp"

namespace qiling {
namespace loader {

// elf.py AUXV — the auxiliary vector keys (the used subset, verbatim values)
enum class AUXV : std::uint64_t {
    AT_NULL = 0,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_FLAGS = 8,
    AT_ENTRY = 9,
    AT_UID = 11,
    AT_EUID = 12,
    AT_GID = 13,
    AT_EGID = 14,
    AT_PLATFORM = 15,
    AT_HWCAP = 16,
    AT_CLKTCK = 17,
    AT_SECURE = 23,
    AT_RANDOM = 25,
    AT_HWCAP2 = 26,
    AT_EXECFN = 31,
};

class QlLoaderELF final : public QlLoader {
public:
    // the parsed PT_LOAD region (elf.py load_elf_segments' consolidated tuple)
    struct LoadRegion {
        std::uint64_t lbound;
        std::uint64_t ubound;
        int perms;
    };

    // the parsed PT_INTERP + import stub (elf.py lkm_dynlinker's surface;
    // the ET_REL driver path lands with the kernel-module slice)
    struct ImportSymbol {
        std::uint64_t address;
        std::string name;
    };

    QlLoaderELF(Qiling* ql);

    void run() override;

    // the mapped extent (load_with_ld's [mem_start, mem_end))
    std::uint64_t mem_start() const noexcept { return mem_start_; }
    std::uint64_t mem_end() const noexcept { return mem_end_; }
    std::uint64_t brk_address() const noexcept { return brk_address_; }
    std::uint64_t elf_entry() const noexcept { return elf_entry_; }
    std::uint64_t mmap_address() const noexcept { return mmap_address_; }
    std::uint64_t auxv_address() const noexcept { return auxv_address_; }
    std::uint64_t interp_address() const noexcept { return interp_address_; }

private:
    std::uint64_t mem_start_ = 0;
    std::uint64_t mem_end_ = 0;
    std::uint64_t brk_address_ = 0;
    std::uint64_t elf_entry_ = 0;
    std::uint64_t mmap_address_ = 0;
    std::uint64_t auxv_address_ = 0;
    std::uint64_t interp_address_ = 0;
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_ELF_HPP
