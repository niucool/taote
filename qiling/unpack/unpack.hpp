// qiling/unpack/unpack.hpp — the packed-PE unpacker (PLAN_UNPACK.md).
//
// Ported from ../pegasus/src/unpacker (see the plan for the file:line map). The
// shape is the reference's:
//
//   install(ql)    before the run: classify sections, pick the watch set, arm
//                  the write-claim / section-hop hooks
//   (ql.run())     the stub executes
//   finalize(ql)   after the run: dump the image, write the meta sidecar,
//                  rebuild the PE
//
// The OEP mechanism is the reference's primary one: a section that the stub
// WROTE and then EXECUTES was decoded in place, so the first exec into a written
// section is the payload hand-off (OllyDump's section hop). Nothing here decides
// anything from the packer's name — detection only routes to family code.
#ifndef QILING_UNPACK_UNPACK_HPP
#define QILING_UNPACK_UNPACK_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "qiling/core.hpp"

namespace qiling {
namespace unpack {

// One image section, with both virtual placement and on-disk layout (the
// reference's PackSection, unpacker.h:41-49).
struct PackSection {
    std::string name;
    std::uint64_t start = 0;   // absolute VA start (base + rva)
    std::uint64_t end = 0;     // absolute VA end
    std::uint32_t vsize = 0;
    std::uint32_t raw = 0;
    bool is_exec = false;
};

struct UnpackOptions {
    std::string sample_path;  // the packed file (header snapshot, LIEF parse)
    std::string out_dir;      // artifact directory
    // the family label from the detector; "unknown" for the generic path
    std::string family = "unknown";
    bool enable_hop = true;   // the section-hop OEP detection (--no-hop turns it off)
    std::uint32_t max_stages = 16;
    bool debug = false;
    bool rebuild = true;
    // When the run uses a *synthesized* rootfs (the default), a dll the stub asks
    // LoadLibrary for can be materialized on demand as an export-less decoy
    // image. That is what makes GPA attribution possible for the stubs that open
    // a dll taote did not know about (measured: FSG resolves netapi32/rpcrt4/
    // version/wldap32... and every pair was attributed to kernel32 without it).
    // Off for a caller-provided real rootfs: never write into the user's tree.
    bool allow_decoy_dlls = false;
    std::string rootfs;  // the run rootfs (the decoy writer's target)
};

struct UnpackResult {
    std::uint64_t base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t oep = 0;          // effective OEP (VA)
    std::uint64_t oep_last_hop = 0; // the last accepted hop (VA)
    std::uint32_t stages = 0;
    bool is_64 = false;
    std::string reason;
    std::string family = "unknown";
    std::vector<std::pair<std::string, std::string>> imports;  // (dll, func), lowercased dll
    bool dump_written = false;
    bool rebuilt = false;
    std::string outfile;   // <stem>_unpacked.exe when rebuilt
    std::string dumpfile;  // <stem>_dump.bin
    std::string metafile;  // <stem>_dump.bin.meta.json
    std::string error;     // non-fatal reason text
};

class Unpacker {
public:
    explicit Unpacker(UnpackOptions opts);
    ~Unpacker();

    Unpacker(const Unpacker&) = delete;
    Unpacker& operator=(const Unpacker&) = delete;

    // Applies the section classification and arms the hooks. Must run before
    // Qiling::run() (the reference's install, unpacker.cpp:178-189).
    void install(Qiling& ql);

    // Dumps the image, writes the sidecar and rebuilds the PE. Safe to call
    // after any run outcome (the reference's finalize, unpacker.cpp:8367-8566).
    // Clears the hooks first: a HookRet's destructor calls into the engine, so
    // it must run while the Qiling that owns the engine is still alive.
    UnpackResult finalize(Qiling& ql);

    // Unregisters the armed hooks (idempotent). Must run before the Qiling that
    // install() was given is destroyed.
    void detach_hooks();

    const UnpackOptions& options() const noexcept { return opts_; }
    // the classified sections + watch set (the tests assert on these)
    const std::vector<PackSection>& sections() const noexcept { return sections_; }
    const std::vector<PackSection>& watched() const noexcept { return watched_; }

    // OEP candidate seam: a hop that the accept gate accepted (for tests).
    std::uint64_t oep() const noexcept { return meta_oep_; }

private:
    void classify_sections(Qiling& ql);
    bool inside_inplace(std::uint64_t addr) const;
    int section_index_at(std::uint64_t addr) const;

    // write-claim (the reference's on_section_write, unpacker.cpp:5197-5381)
    int on_section_write(std::uint64_t pc, std::uint64_t addr);
    // section-hop exec (on_section_exec, unpacker.cpp:5520-5810)
    int on_section_exec(std::uint64_t addr);
    // the accept gate + latch (dump_module, unpacker.cpp:6610-6834)
    void dump_module(Qiling& ql, std::uint64_t addr, const std::string& reason);
    // the loader's import set, as the rebuild's import input
    void harvest_loader_imports(Qiling& ql);
    // The GetProcAddress sentinel lane (the reference's on_gpa_api,
    // unpacker.cpp:6145-6496): a stub resolves the payload's imports through
    // GPA, and a NULL answer makes it abort (measured: UPX's restorer calls
    // ExitProcess after the first miss). Unknown names get a minted address that
    // is registered with the loader, so the value the stub stores is callable and
    // the pair is harvested for the rebuild.
    void install_gpa_sentinel(Qiling& ql);
    bool materialize_decoy_dll(const std::string& dll_name);
    void note_import(const std::string& dll, const std::string& name);
    // Scylla-style IAT salvage (the reference's salvage_iat,
    // unpacker.cpp:8584-9560): scan the dumped image for pointer-sized values
    // that land on a loaded module's export (or a minted sentinel), attribute
    // them, and keep only the coherent runs. This is what recovers the payload's
    // import set for the stubs that never call GetProcAddress (they resolve from
    // their own table / walk the EAT directly).
    void salvage_iat(Qiling& ql, const std::vector<std::uint8_t>& image);

    UnpackOptions opts_;
    std::vector<PackSection> sections_;
    std::vector<PackSection> watched_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> inplace_ranges_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> ever_written_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> written_ranges_;

    std::uint64_t base_ = 0;
    std::uint64_t image_size_ = 0;
    std::uint64_t packed_ep_va_ = 0;
    bool is_64_ = false;
    std::uint32_t stages_ = 0;
    // every accepted hop, in order: the reference's OEP candidate ledger
    // (unpacker.h:747-775). finalize picks among them instead of blindly keeping
    // the last, because late hops inside the stub's own section are junk
    // (measured: rlpack/mpress park the OEP in the stub section while the dumped
    // payload is already perfect).
    std::vector<std::uint64_t> hop_ledger_;
    // The reference's write-ordinal rule (unpacker.h:660-680, sec_last_write_insn_):
    // a hop into a section that keeps receiving writes afterwards is a mid-decode
    // excursion, not the payload hand-off. Every write bumps write_seq_; a hop
    // records the sequence it saw, and finalize compares it against the section's
    // last write.
    std::uint64_t write_seq_ = 0;
    std::map<std::uint64_t, std::uint64_t> last_write_seq_;   // section start -> seq
    std::vector<std::uint64_t> hop_write_seq_;                // parallel to hop_ledger_
    // sections already claimed: the write hook stays armed for the sequence
    // stamps but never re-claims
    std::set<std::uint64_t> claimed_;
    // addresses already offered to the accept gate (the reference's CF-hop
    // ledger dedup): the exec gate reads ever_written_ (never erased), so a
    // section that was decoded once keeps producing candidates — that is how the
    // real transfer is seen after an earlier junk hop inside the same section
    // (measured: MPRESS's decode target is entered mid-decode first, and erasing
    // the range there lost the true OEP at 0x407a98)
    std::set<std::uint64_t> dumped_addrs_;
    // the light pick (the reference's V1 prologue-shape vote, :8060-8110)
    std::uint64_t pick_oep(const std::vector<std::uint8_t>& image) const;
    std::uint64_t meta_oep_ = 0;
    std::uint64_t last_oep_ = 0;
    std::string reason_;
    std::vector<std::pair<std::string, std::string>> imports_;
    std::set<std::string> import_seen_;
    std::uint64_t gpa_sentinel_ = 0x77001000;  // the reference's fake-GPA range
    // the reference's last_ll_name_ (unpacker.cpp:269-330): the dll the stub most
    // recently opened, used to attribute a GPA whose module handle resolves to
    // nothing (the stub passes the handle of a dll taote could not materialize)
    std::string last_ll_name_;
    std::map<std::uint64_t, std::string> handle_names_;  // LoadLibrary base -> dll name
    // salvage diagnostics (the tests assert on them)
    std::size_t salvaged_slots_ = 0;
    std::size_t salvaged_pairs_ = 0;
    std::vector<std::uint8_t> header_snapshot_;  // the packed file's first 0x400

    // the per-section hook handles (RAII: HookRet unregisters)
    std::vector<std::shared_ptr<HookRet>> hooks_;
    Qiling* ql_ = nullptr;  // the run this unpacker is installed on
    // sections whose write hook has been muted (the reference disables the
    // hook; taote keeps it armed and short-circuits on the first lookup)
    std::set<std::uint64_t> muted_;
};

// The image dumper + PE rebuilder (PLAN_UNPACK §1.8). Split out so the tests can
// drive it on synthetic images without an emulator.
struct RebuildInput {
    std::vector<std::uint8_t> image;      // the dump (base-relative, image_size)
    std::uint64_t base = 0;
    std::uint64_t oep_va = 0;
    bool is_64 = false;
    std::vector<std::pair<std::string, std::string>> imports;
    std::vector<std::uint8_t> header_snapshot;  // the packed file's first 0x400
};

// Rebuilds a file-layout PE from the dump, appending a .pgimp import section.
// Returns the file bytes (empty when the dump is not a PE). Never throws into a
// caller that catches QlErrorBase: malformed input yields an empty result.
std::vector<std::uint8_t> rebuild_pe(const RebuildInput& in);

}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_UNPACK_HPP
