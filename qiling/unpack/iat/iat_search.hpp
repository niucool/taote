// qiling/unpack/iat/iat_search.hpp — the IAT locator (Scylla's IATSearch).
//
// Ported shape of ../pegasus/src/scylla_wrapper (IATSearch.cpp + ApiReader.cpp):
// the reference vendors Scylla, whose model is
//
//   ApiReader      the process's resolved-symbol table: address -> (dll, name)
//   IATSearch      scan a memory range for pointer-sized values that land on a
//                  resolved symbol, then decide which of them form the IAT
//   getImports     turn the surviving slots into (dll, name) pairs
//
// Scylla is a Windows library (it opens a process handle and walks its PEB); an
// emulator has the memory and the symbol table already, so the port keeps the
// *model* and drops the process plumbing: the caller hands in the bytes and the
// base VA, and gets back the slots with their attribution.
//
// Two consumers, exactly as in the reference:
//   * the dump-side salvage (a stub rebuilt the IAT itself; the pointers are in
//     the image, but nothing told us their names),
//   * the orphan-descriptor walk (the payload's own import directory survived
//     the packer, but the header's data directory points at the stub's table).
#ifndef QILING_UNPACK_IAT_IAT_SEARCH_HPP
#define QILING_UNPACK_IAT_IAT_SEARCH_HPP

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace qiling {
namespace unpack {
namespace iat {

// One pointer-sized slot that lands on a resolved symbol.
struct ImportHit {
    std::uint64_t va = 0;    // the slot's VA (base + offset)
    std::string dll;         // lowercased, sanitized
    std::string name;        // sanitized
};

// Scylla's ApiReader: address -> (dll, name). First insert wins, so a name is
// attributed to the module that actually owns the address.
class SymbolMap {
public:
    void add(std::uint64_t address, std::string dll, std::string name);
    const std::pair<std::string, std::string>* find(std::uint64_t address) const;
    bool empty() const noexcept { return map_.empty(); }
    std::size_t size() const noexcept { return map_.size(); }

private:
    std::map<std::uint64_t, std::pair<std::string, std::string>> map_;
};

// Scylla's IATSearch + importsValid: every scanned region accumulates hits, and
// the coherent subset is what `coherent()` returns.
//
// The coherence rule is the one the reference settled on after the measured runs
// (PLAN_UNPACK §0.5.2): an IAT is a run of >= 2 pointer-spaced slots of the SAME
// dll, plus singletons anchored within two slots of such a run. When the whole
// scan holds only a handful of live pointers the stub rebuilt the table itself
// and the slots are scattered, so adjacency cannot be required and every hit is
// authoritative (its value came from the loader's own export map).
class IatScanner {
public:
    IatScanner(const SymbolMap& symbols, unsigned ptr_size) : symbols_(symbols), ptr_(ptr_size) {}

    // Scan `bytes` mapped at `va`. Offsets are recorded as slot VAs.
    void scan(const std::vector<std::uint8_t>& bytes, std::uint64_t va);

    const std::vector<ImportHit>& hits() const noexcept { return hits_; }
    // The slots that form the IAT (see the class comment).
    std::vector<ImportHit> coherent() const;

    // below this many hits the table is treated as scattered (the reference's
    // slot probe)
    std::size_t scattered_threshold = 64;

private:
    const SymbolMap& symbols_;
    unsigned ptr_;
    std::vector<ImportHit> hits_;
};

// The packed families that resolve their imports from a private table leave the
// payload's own descriptor chain in the image. Walk it (Scylla's getImports) and
// return the pairs. `image` is the dump, `base` the image base.
struct DescriptorWalk {
    std::vector<std::pair<std::string, std::string>> imports;
    std::uint32_t descriptor_rva = 0;  // the first descriptor the walk started at
    std::size_t descriptors = 0;
    // lowercased dll -> its FirstThunk (IAT) RVA. The rebuilt descriptors must
    // point their FirstThunk back at these addresses: the decompressed code
    // still calls through the original IAT slots, and the Windows loader only
    // writes resolved addresses into the FirstThunk the descriptor names.
    std::map<std::string, std::uint32_t> iat_rva_by_dll;
};
// `start_rvas` are the candidate descriptor-table RVAs to try, in order; an empty
// list lets the walker scan for a plausible table itself.
DescriptorWalk walk_import_descriptors(const std::vector<std::uint8_t>& image, std::uint64_t base,
                                       const std::vector<std::uint32_t>& start_rvas = {});

}  // namespace iat
}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_IAT_IAT_SEARCH_HPP
