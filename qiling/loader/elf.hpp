// Ported from qiling/loader/elf.py — QlLoaderELF (PORT_PLAN.md §10 Phase 5).
// The pyelftools `ELFFile` surface maps onto LIEF (decision D17: one parsing
// dependency for PE/ELF/…; the qiling-specific consolidation and auxv logic
// stays hand-ported on top of it).
//
//   ELFFile(stream)                       -> ElfImage (LIEF::ELF::Binary wrapper)
//   elffile['e_type'/'e_entry'/...]       -> ElfImage accessors
//   elffile.iter_segments(type='PT_LOAD') -> ElfImage::load_segments (filtered)
//   seg.data()                            -> Segment::content()
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

struct ElfImage;  // the LIEF-backed parsed container (defined in elf.cpp)

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
    // the Python values are strings or handler objects — the port keys the
    // hook dispatch by the api name)
    struct ImportSymbol {
        std::uint64_t address;
        std::string name;
    };

    // elf.py module constants (the LKM driver path)
    static constexpr std::uint64_t API_HOOK_MEM = 0x1000000;
    static constexpr std::uint64_t API_HOOK_SIZE = 0x1000;
    static constexpr std::uint64_t SYSCALL_MEM = API_HOOK_MEM + 0x1000;
    static constexpr std::uint64_t SYSCALL_SIZE = 0x1000;

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

    // the LKM import stub table (hook.py: address -> api name)
    const ImportSymbol* import_symbols_at(std::uint64_t address) const {
        const auto it = import_symbols_.find(address);
        return it == import_symbols_.end() ? nullptr : &it->second;
    }

    // the next free api hook slot (elf.py ql.os.hook_addr; the loader owns it
    // in this port instead of stashing it on the os)
    std::uint64_t hook_addr() const noexcept { return hook_addr_; }

    // the driver stack base (elf.py self.stack_address for the ET_REL branch)
    std::uint64_t stack_address() const noexcept { return stack_address_; }

private:
    std::uint64_t mem_start_ = 0;
    std::uint64_t mem_end_ = 0;
    std::uint64_t brk_address_ = 0;
    std::uint64_t elf_entry_ = 0;
    std::uint64_t mmap_address_ = 0;
    std::uint64_t auxv_address_ = 0;
    std::uint64_t interp_address_ = 0;
    std::uint64_t hook_addr_ = 0;
    std::uint64_t stack_address_ = 0;
    std::map<std::uint64_t, ImportSymbol> import_symbols_;
    std::map<std::string, std::uint64_t> rev_reloc_symbols_;
    std::optional<std::uint64_t> prev_mips_hi16_loc_;

    // elf.py load_driver — the ET_REL kernel module mapping + the api/syscall
    // hook wiring; elf.py lkm_get_init / lkm_dynlinker
    void load_driver(const ElfImage& elf, const std::vector<std::uint8_t>& bytes,
                     std::uint64_t stack_addr, std::uint64_t loadbase);
    [[nodiscard]] std::uint64_t lkm_get_init(const ElfImage& elf) const;
    void lkm_dynlinker(const ElfImage& elf, std::uint64_t mem_start);
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_ELF_HPP
