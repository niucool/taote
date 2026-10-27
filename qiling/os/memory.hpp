// Ported from qiling/os/memory.py — the memory manager (QlMemoryManager) and
// the simple heap (QlMemoryHeap). The Python manager reaches the emulation
// services through the Qiling instance (ql.uc, ql.arch.bits, ql.pack*); the
// C++ port takes those dependencies explicitly: the unicorn engine, the
// architecture word size, and the QlCoreStructs endianness/packing surface
// (the composition root aggregates them in Phase 3).
#ifndef QILING_OS_MEMORY_HPP
#define QILING_OS_MEMORY_HPP

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <unicorn/unicorn.h>

#include "qiling/core_struct.hpp"
#include "qiling/exception.hpp"

// UC_PROT_* permission bits come from unicorn.h (included above)

#include "qiling/os/const.hpp"

namespace qiling {

// ---- MMIO handler boilerplate (memory.py QlMmioHandler Protocol) ----
//
// A simple boilerplate that can be used to implement memory mapped devices.
// The read and write methods are optional: an unimplemented method means the
// corresponding operation is silently dropped (has_read / has_write mark the
// support, like the Python hasattr checks).
class QlMmioHandler {
public:
    virtual ~QlMmioHandler() = default;

    virtual bool has_read() const noexcept { return false; }
    virtual bool has_write() const noexcept { return false; }

    virtual std::uint64_t read(std::uint64_t offset, std::uint32_t size) {
        (void)offset;
        (void)size;
        return 0;
    }

    virtual void write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        (void)offset;
        (void)size;
        (void)value;
    }
};

// tuple: range start, range end, permissions mask, range label, mmio handler
// object (if mmio range) — memory.py MapInfoEntry
struct MapInfoEntry {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    int perms = UC_PROT_ALL;
    std::string label;
    QlMmioHandler* mmio_ctx = nullptr;  // borrowed; owned by the registrant
};

// memory.py save() component state: the in-memory representation of a saved
// memory layout (the explicit binary envelope lives in qiling/snapshot.hpp)
struct SavedMemoryRange {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    int perms = UC_PROT_ALL;
    std::string label;
    std::vector<std::uint8_t> data;  // empty for mmio ranges
    QlMmioHandler* mmio_ctx = nullptr;  // raw; owned by the registrant
};

struct SavedMemory {
    std::vector<SavedMemoryRange> ram;
    std::vector<SavedMemoryRange> mmio;
};

class QlMemoryManager {
public:
    // memory.py __init__(ql, pagesize): the ql services are taken explicitly.
    // bits also fixes the pointer size (arch.pointersize == bits // 8).
    QlMemoryManager(uc_engine& uc, const QlCoreStructs& structs, int bits, std::uint64_t pagesize = 0x1000);

    // ---- map info (memory.py) ----

    void add_mapinfo(std::uint64_t mem_s, std::uint64_t mem_e, int mem_p, std::string mem_info,
                     QlMmioHandler* mmio_ctx = nullptr);
    void del_mapinfo(std::uint64_t mem_s, std::uint64_t mem_e);
    void change_mapinfo(std::uint64_t mem_s, std::uint64_t mem_e, std::optional<int> new_perms = {},
                        std::optional<std::string> new_info = {});

    // get_mapinfo: (lbound, ubound, perms, label, container). The container
    // lookup (the loader's find_containing_image) lands with the Phase 3
    // facade; until then the last column is always empty.
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::string, std::string, std::string>> get_mapinfo() const;
    std::vector<std::string> get_formatted_mapinfo() const;

    // TODO: relying on the label string is risky; find a more reliable method
    // (memory.py, verbatim note)
    std::optional<std::uint64_t> get_lib_base(std::string_view filename) const;

    const std::vector<MapInfoEntry>& map_info() const noexcept { return map_info_; }

    // ---- alignment helpers ----

    std::uint64_t align(std::uint64_t value, std::optional<std::uint64_t> alignment = {}) const;
    std::uint64_t align_up(std::uint64_t value, std::optional<std::uint64_t> alignment = {}) const;

    // ---- memory access (memory.py read/write family) ----

    std::vector<std::uint8_t> read(std::uint64_t addr, std::uint64_t size) const;
    void write(std::uint64_t addr, const std::vector<std::uint8_t>& data);
    void write(std::uint64_t addr, std::string_view data) { write(addr, std::vector<std::uint8_t>(data.begin(), data.end())); }

    // Read/write an integer value from/to a memory address; bytes are packed
    // with the emulated architecture properties (read_ptr / write_ptr).
    // size: pointer size in bytes (1/2/4/8, or 0 for the arch native size);
    // signed: interpret the value as a signed integer.
    std::int64_t read_ptr(std::uint64_t addr, std::uint64_t size = 0, bool signed_ = false) const;
    void write_ptr(std::uint64_t addr, std::int64_t value, std::uint64_t size = 0, bool signed_ = false);

    // TODO: this is an obsolete utility method that should not be used anymore
    // and here for backward compatibility. use QlOsUtils.read_cstring instead
    // (memory.py, verbatim note). reads a null-terminated string, or writes one.
    std::optional<std::string> string(std::uint64_t addr, std::optional<std::string_view> value = {},
                                      const char* encoding = "utf-8");

    // ---- mapping (memory.py) ----

    void map(std::uint64_t addr, std::uint64_t size, int perms = UC_PROT_ALL, std::optional<std::string> info = {});
    void map_mmio(std::uint64_t addr, std::uint64_t size, QlMmioHandler& handler, std::string info = "[mmio]");
    void unmap(std::uint64_t addr, std::uint64_t size);
    void unmap_between(std::uint64_t mem_s, std::uint64_t mem_e);
    void unmap_all();
    void protect(std::uint64_t addr, std::uint64_t size, int perms);

    bool is_available(std::uint64_t addr, std::uint64_t size) const;
    bool is_mapped(std::uint64_t addr, std::uint64_t size) const;

    // Locate an unallocated range of the requested size; QlOutOfMemory when
    // nothing fits (memory.py find_free_space)
    std::uint64_t find_free_space(std::uint64_t size, std::optional<std::uint64_t> minaddr = {},
                                  std::optional<std::uint64_t> maxaddr = {},
                                  std::optional<std::uint64_t> alignment = {}) const;
    std::uint64_t map_anywhere(std::uint64_t size, std::optional<std::uint64_t> minaddr = {},
                               std::optional<std::uint64_t> maxaddr = {}, std::optional<std::uint64_t> alignment = {},
                               int perms = UC_PROT_ALL, std::optional<std::string> info = {});

    // ---- search (memory.py search) ----
    // The bytes-needle path is ported; the regex Pattern[bytes] variant is not
    // (documented deviation — no in-memory regex consumer exists in the ported
    // surface).
    std::vector<std::uint64_t> search(const std::vector<std::uint8_t>& needle, std::optional<std::uint64_t> begin = {},
                                      std::optional<std::uint64_t> end = {}) const;

    // ---- snapshot (memory.py save/restore) ----
    // Save the entire memory content (ram ranges with data, mmio ranges with
    // the handler reference).
    SavedMemory save() const;
    void restore(const SavedMemory& saved_state);

    // the mapped region containing addr (the analysis surface labels its
    // per-region counters with it); nullopt when addr is unmapped
    const MapInfoEntry* region_at(std::uint64_t addr) const;

    std::uint64_t pagesize() const noexcept { return pagesize_; }

    // memory.py max_mem_addr — the arch-bounded upper address
    std::uint64_t max_mem_addr() const noexcept { return max_mem_addr_; }

private:
    // consolidated adjacent mapped regions (memory.py __mapped_regions)
    std::vector<std::pair<std::uint64_t, std::uint64_t>> mapped_regions() const;

    uc_engine* uc_;
    const QlCoreStructs* structs_;
    std::uint64_t max_mem_addr_ = 0;
    std::uint64_t pagesize_ = 0x1000;
    int pointersize_ = 8;
    std::vector<MapInfoEntry> map_info_;  // sorted by begin (bisect.insort)
    std::vector<std::unique_ptr<void, void (*)(void*)>> mmio_contexts_;
};

// ---- the simple heap (memory.py QlMemoryHeap) ----

class QlMemoryHeap {
public:
    struct Chunk {
        bool inuse = true;
        std::uint64_t address = 0;
        std::uint64_t size = 0;
    };

    QlMemoryHeap(QlMemoryManager& mem, std::uint64_t start_address, std::uint64_t end_address);

    // Allocate heap memory; returns the chunk address, or 0 on failure
    std::uint64_t alloc(std::uint64_t size);
    // Allocate a chunk whose ADDRESS is alignment-aligned (padding with a
    // filler chunk when needed, never recycling). VirtualAlloc rides this: the
    // returned base must be page-aligned, and VirtualQuery reports the chunk
    // address as BaseAddress/AllocationBase, so the chunk has to START there.
    std::uint64_t alloc_aligned(std::uint64_t size, std::uint64_t alignment);
    // Free the memory at an address; true iff freed successfully
    bool free(std::uint64_t addr);
    // The size of the used chunk starting at an address (0 when none)
    std::uint64_t size(std::uint64_t addr) const;
    // The raw chunk lookup (heapapi HeapValidate rides _find + chunk.inuse);
    // returns nullptr when no chunk starts at the address
    struct Chunk;
    const Chunk* find_chunk(std::uint64_t addr) const;
    // Clear all memory regions allocated for heap use
    void clear();

    // heap state (memory.py save/restore)
    struct SavedState {
        std::vector<Chunk> chunks;
        std::uint64_t start_address = 0;
        std::uint64_t end_address = 0;
        std::uint64_t current_alloc = 0;
        std::uint64_t current_use = 0;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> mem_alloc;
    };
    SavedState save() const;
    void restore(const SavedState& state);

    std::uint64_t start_address() const noexcept { return start_address_; }
    std::uint64_t end_address() const noexcept { return end_address_; }
    const std::vector<Chunk>& chunks() const noexcept { return chunks_; }

private:
    // append-only bump (the alloc() body without the recycle search)
    std::uint64_t alloc_append(std::uint64_t size);
    const Chunk* find(std::uint64_t addr, std::optional<bool> inuse = {}) const;
    Chunk* find(std::uint64_t addr, std::optional<bool> inuse = {});

    QlMemoryManager* mem_;
    std::vector<Chunk> chunks_;
    std::uint64_t start_address_ = 0;
    std::uint64_t end_address_ = 0;
    std::uint64_t current_alloc_ = 0;  // invariant: aligned to the page size
    std::uint64_t current_use_ = 0;    // invariant: never exceeds current_alloc_
    std::vector<std::pair<std::uint64_t, std::uint64_t>> mem_alloc_;
};

}  // namespace qiling

#endif  // QILING_OS_MEMORY_HPP
