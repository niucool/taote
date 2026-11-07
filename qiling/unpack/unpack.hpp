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
#include "qiling/unpack/packers/aspack_host.hpp"

namespace qiling {
namespace unpack {

namespace packers {
class Packer;
}

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
    // the blob-attribution repair (see the pass in unpack.cpp): a positional
    // string-blob attribution the export database contradicts is re-owned.
    bool blob_repair = true;
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
    void detach_hooks(Qiling* ql = nullptr);

    const UnpackOptions& options() const noexcept { return opts_; }
    // the classified sections + watch set (the tests assert on these)
    const std::vector<PackSection>& sections() const noexcept { return sections_; }
    const std::vector<PackSection>& watched() const noexcept { return watched_; }

    // OEP candidate seam: a hop that the accept gate accepted (for tests).
    std::uint64_t oep() const noexcept { return meta_oep_; }
    // Loader-quirk seam: a start address the packed layout itself dictates, when
    // the header's EP cannot be executed (see detect_hollow_ep_loader_stub).
    std::uint64_t start_override() const noexcept { return start_override_va_; }

private:
    void classify_sections(Qiling& ql);
    // NSPack's hollow-EP loader stub (see unpack.cpp): the header's EP sits in a
    // section whose raw data is a fragment, so the mapped image holds zeros there
    // and the emulation executes zero bytes; the packer's real 5-byte `jmp rel32`
    // loader stub is stored at FILE offset (EP_rva - section_rva). Sets
    // start_override_va_ to that jump's in-image target.
    void detect_hollow_ep_loader_stub(Qiling& ql);
    // WinUpack's image-tail overrun: map one page past SizeOfImage at install time (see unpack.cpp;
    // a grow-on-fault memory hook crashes the host, so this is a bounded pre-map).
    void install_image_tail_slack(Qiling& ql);
    bool inside_inplace(std::uint64_t addr) const;
    int section_index_at(std::uint64_t addr) const;

    // write-claim (the reference's on_section_write, unpacker.cpp:5197-5381).
    // seq_step: the write-ordinal advance for this event - 1 per store in hook
    // mode, the store width per page-first-fault in page write-trap mode.
    int on_section_write(std::uint64_t pc, std::uint64_t addr, std::uint32_t size = 1,
                         std::uint64_t value = 0, std::uint32_t seq_step = 1);
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
    // The payload's OWN import descriptors, read out of the dumped image (RVAs +
    // dll/name strings live inside it). Packers that restore the original table
    // — EnigmaVB, Molebox, Neolite, PECompact — leave it intact, so this recovers
    // their import set without any emulation evidence.
    void harvest_image_imports(const std::vector<std::uint8_t>& image);
    // The reference's family_reconstruct_orphans (unpacker.cpp:13500-13560): the
    // stubs that rebuild the IAT themselves (FSG, BeRo, WinUpack, MEW) leave the
    // payload's import DESCRIPTORS in the image while the header's import directory
    // points at the stub's own table. Mine every orphaned descriptor chain.
    std::size_t mine_orphan_descriptors(const std::vector<std::uint8_t>& image);
    // FSG keeps the payload's import RESOLUTION list in the decoded image: after each
    // DLL name come 6-byte records, 01 <u32 nameptr> for a by-name import and
    // 02 <u16 ordinal> 00 00 for a BY-ORDINAL one. Those ordinals are the only
    // recoverable source for a payload whose descriptor/INT arrays the packer zeroed.
    std::size_t mine_ordinal_records(const std::vector<std::uint8_t>& image);

    UnpackOptions opts_;
    // the family seam (packers/packer.hpp): only the family-specific policy lives
    // there, the generic engine below is family-agnostic
    std::unique_ptr<packers::Packer> packer_;
    std::vector<PackSection> sections_;
    std::vector<PackSection> watched_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> inplace_ranges_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> ever_written_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> written_ranges_;

    // The reference's hop ACCEPT guards (unpacker.cpp:7006-7025 and 8160-8180),
    // which UPX, NSPack, Molebox and JDPack all join. A payload's own runtime
    // writes re-claim the range around the flow that is ALREADY executing there,
    // so the next instruction fires a "hop" with no control transfer - and a
    // post-OEP landing inside another section then replaces a correct incumbent
    // pick while carrying no import growth. Both are skipped here.
    std::uint64_t prev_exec_addr_ = 0;
    std::uint64_t last_hop_addr_ = 0;
    std::size_t last_hop_imp_ = 0;
    bool have_hop_ = false;

    std::uint64_t base_ = 0;
    std::uint64_t image_size_ = 0;
    std::uint64_t packed_ep_va_ = 0;
    std::uint64_t start_override_va_ = 0;
    bool is_64_ = false;

    // The junk-latch test (the reference's kJunkLatchMaxInstrs=32): a hop taken
    // almost immediately at run start is not the payload hand-off. Hook mode
    // measures it by the write ordinal (calibrated: aspack_Cacheset latch @1
    // store, real hop @35973). The write-trap cannot count stores (one fault per
    // armed span), so trap mode adds the EXECUTION count at the hop - the
    // reference's own signal - with the threshold set from measured ledgers:
    // junk latches land at 6/84/131/447 blocks (aspack_Cacheset 0x426035,
    // exe32pack_antialias 0x40d0eb, amber_chgport 0x401661, neolite_PEViewer
    // 0x59bd4d) while real hand-offs land at 667+ (aspack_Cacheset 0x4024a2) and
    // typically 10^4-10^7, so 512 sits in the measured gap (256 promoted
    // neolite's 447-block latch and lost the row). Hook mode is untouched.
    bool hop_is_strong(std::size_t i, std::uint64_t seq) const {
        if (seq >= 32) {
            return true;
        }
        return write_trap_on_ && i < hop_exec_fires_.size() && hop_exec_fires_[i] >= 512;
    }
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
    std::vector<std::uint64_t> hop_exec_fires_;               // parallel: per-block count at the hop
    // PECompact placeholder-header rows (AddressOfEntryPoint == the first
    // section's VA): the stub plants a mini-stub there and hands off tens of KB
    // later, so the first execution past this bound is the payload entry. 0 for
    // every other row, which costs one comparison per instruction.
    std::uint64_t pc_far_hop_limit_ = 0;
    std::uint64_t pc_far_hop_ = 0;
    // TAOTE_SEC_TRANS: the reference's sec_trans_hist_ (unpacker.h sec_trans_hist_,
    // consumed by the PEtite EP-exit walk). Recorded only when the env var is set,
    // because it costs a section lookup on every exec-hook fire.
    struct SecTrans { int from_sec, to_sec; std::uint64_t addr, seq; };
    std::vector<SecTrans> sec_trans_;
    std::set<int> sec_written_;                               // sections that ever saw a write
    // PEtite's EP-exit trail (the reference's sec_trans_hist_ walk): the final
    // stub->payload hand-off is the last transition into a section the run never
    // leaves again that also stops receiving stub writes. TAOTE_PET_EXIT enables it.
    int prev_sec_idx_ = -1;                                   // cached section of prev_exec_addr_
    bool pet_exit_on_ = false;
    std::uint64_t oep_from_transition_trail(const std::vector<std::uint8_t>& image) const;
    bool sec_trans_on_ = false;                               // TAOTE_SEC_TRANS
    std::vector<std::uint64_t> stack_oep_cands_;              // WinUpack parked-slot candidates (hop time)
    // sections already claimed: the write hook stays armed for the sequence
    // stamps but never re-claims
    std::set<std::uint64_t> claimed_;
    // The reference's on_dyn_code (:6096): guest-allocated regions that start
    // executing are OEP candidates (Amber/Alienyze/Neolite build or map their
    // payload in a heap buffer and run it there, so nothing lands in an image
    // section and the section-hop hook never fires).
    std::vector<std::pair<std::uint64_t, std::uint64_t>> dyn_maps_;
    std::vector<std::uint64_t> dyn_exec_;
    std::vector<std::shared_ptr<HookRet>> dyn_hooks_;
    void poll_dyn_maps();
    // regions that already existed at install (stack/GS/FS/segments): the
    // reference's dyn_code hook only fires for maps created during the run, and
    // hooking the pre-existing multi-MB regions costs a per-instruction callback
    // in every guest execution there.
    std::set<std::uint64_t> initial_maps_;
    unsigned exec_fires_ = 0;
    // addresses already offered to the accept gate (the reference's CF-hop
    // ledger dedup): the exec gate reads ever_written_ (never erased), so a
    // section that was decoded once keeps producing candidates — that is how the
    // real transfer is seen after an earlier junk hop inside the same section
    // (measured: MPRESS's decode target is entered mid-decode first, and erasing
    // the range there lost the true OEP at 0x407a98)
    std::set<std::uint64_t> dumped_addrs_;
    // ASPack single-shot host decode (PLAN_UNPACK.md 0.17nk): the stub's per-section
    // decompressor runs host-side at its own call site, then the guest resumes at the
    // post-call `pop esi`. Ported from pegasus install_aspack_hostdec_.
    void install_aspack_hostdec();
    int aspack_hostdec_fire(std::uint64_t addr);
    void mirror_host_write(std::uint64_t dst, std::uint64_t total);
    std::uint64_t aspack_call_va_ = 0;
    std::uint64_t aspack_resume_va_ = 0;
    bool aspack_guarded_ = false;
    bool aspack_only_e8_ = false;
    bool aspack_dead_ = true;
    std::uint8_t aspack_tag_ = 0;
    int aspack_bails_ = 0;
    std::uint64_t aspack_fires_ = 0;
    packers::AspackSlotTables aspack_tabs_{};

    // the FIRST write per image byte (the reference's shadow_image_/shadow_seen_,
    // unpacker.h:919-945): anti-dump stubs memset the decoded image after the
    // payload is in place (MEW) and just-in-time packers re-encrypt it (TELock), so
    // the terminal dump alone loses bytes the stub had already decoded
    std::vector<std::uint8_t> shadow_image_;
    std::vector<bool> shadow_seen_;
    // The shadow image is only consumed by the first-write families (MEW) and by
    // the TAOTE_UNPACK_SHADOW_ALL A/B switch; recording it for every store of
    // every family was hot-path cost on the decompressor loops (millions of
    // writes into the image).
    bool shadow_wanted_ = false;
    // page write-trap mode (replaces the per-store claim hook): see install
    bool write_trap_on_ = false;
    // Fast path for the per-instruction written-range test: consecutive execs hit
    // the same claim, and the linear scan over the claim set was the hottest
    // thing in the exec hook.
    mutable std::uint64_t wr_cache_lo_ = 0;
    mutable std::uint64_t wr_cache_hi_ = 0;
    // The page view at FIRST EXECUTION (the decoded state a just-in-time decrypting
    // stub needs): PEtite/JDPack decrypt a page, run it, then re-encrypt it, and
    // their first *writes* are transient ciphertext — so neither the terminal dump
    // nor the first-write shadow carries the decoded code. Snapshotting the page
    // when it is first executed captures exactly the view the reference's per-page
    // decrypt tracking needs (PETITE_INT_RUNS).
    std::vector<std::uint8_t> exec_view_;
    std::vector<bool> exec_page_seen_;
    // The WHOLE image at the first instruction fetch outside the packed-EP section
    // (TAOTE_HANDOFF_SNAP). A stub that decrypts its payload in place and then
    // RE-ENCRYPTS what it decoded (TELock, measured: 35328 single-byte stores into
    // .text, then the payload runs one page and dies) leaves nothing usable in
    // terminal memory or in the first-write shadow - the decode exists for exactly
    // the interval between the decryptor finishing and the payload's first fetch,
    // and that is the hand-off. exec_view_ captures only the pages that EXECUTE,
    // which for these stubs is one page.
    std::vector<std::uint8_t> handoff_view_;
    // the packer's install-time static OEP (the MEW header table and friends)
    std::uint64_t static_oep_ = 0;
    // the light pick (the reference's V1 prologue-shape vote, :8060-8110)
    std::uint64_t pick_oep(const std::vector<std::uint8_t>& image) const;
    // A stub that patches the in-memory PE header's AddressOfEntryPoint (the
    // EnigmaVB class, PLAN_UNPACK Phase 3 row 13) or MEW's header table records
    // the payload entry statically. Both are read here and join the pick as
    // strong candidates.
    std::uint64_t header_ep_candidate(const std::vector<std::uint8_t>& image) const;
    // the packer's decode-only ladder over the decoded body
    std::uint64_t static_oep_from_image(const std::vector<std::uint8_t>& image) const;
    std::uint64_t meta_oep_ = 0;
    std::uint64_t last_oep_ = 0;
    std::string reason_;
    std::vector<std::pair<std::string, std::string>> imports_;
    std::set<std::string> import_seen_;
    // the descriptor count harvest_image_imports recovered from the decoded
    // payload's own import directory (0 = the packer destroyed it, e.g.
    // FSG/BeRo/MEW/WinUpack). Gates the noisy bare-string heuristics in
    // mine_orphan_descriptors, which are only valid when that table is gone.
    std::uint64_t gpa_sentinel_ = 0x77001000;  // the reference's fake-GPA range
    // the reference's last_ll_name_ (unpacker.cpp:269-330): the dll the stub most
    // recently opened, used to attribute a GPA whose module handle resolves to
    // nothing (the stub passes the handle of a dll taote could not materialize)
    std::string last_ll_name_;
    std::map<std::uint64_t, std::string> handle_names_;  // LoadLibrary base -> dll name
    // salvage diagnostics (the tests assert on them)
    std::size_t salvaged_slots_ = 0;
    std::size_t salvaged_pairs_ = 0;
    std::size_t image_descriptor_count_ = 0;
    // lowercased dll -> FirstThunk (IAT) RVA from the payload's own descriptors
    std::map<std::string, std::uint32_t> image_iat_rva_by_dll_;
    // lowercased dll -> the code-referenced IAT slot RVA observed by the salvage
    // scan (these are authoritative: the code calls through them)
    std::map<std::string, std::uint32_t> salvaged_iat_rva_by_dll_;
    std::vector<std::uint8_t> header_snapshot_;  // the packed file's first 0x400

    // the per-section hook handles (RAII: HookRet unregisters)
    std::vector<std::shared_ptr<HookRet>> hooks_;
    // TAOTE_LOWPC: the rolling window of the last executed pcs, so a run that
    // dies on a fetch at a garbage address can report where control came from
    std::shared_ptr<std::vector<std::uint64_t>> pc_ring_;
    // TAOTE_LASTPC=N: a ring buffer of the last N instruction addresses, for the
    // clean stops that call no API at all (TELock/Yoda-Protector/Alienyze bail on
    // an INLINE environment check, so there is nothing to see in the api log).
    // Env-gated scaffolding: the hook is a per-instruction callback and would cost
    // the whole throughput budget if it were ever armed by default.
    std::vector<std::uint64_t> last_pcs_;
    std::size_t last_pc_pos_ = 0;
    // TAOTE_HEAPSCAN=1: record every page written OUTSIDE the dumped image and, at
    // finalize, look for a PE image there. A packer that decodes into a GlobalAlloc
    // buffer and jumps to it (Neolite: CreateFileMapping -> GlobalAlloc ->
    // FlushInstructionCache -> MessageBox -> ShellExecute) leaves nothing in the
    // dumped image, so this is the only place its payload can be. Diagnostic only:
    // a whole-address-space write hook is per-store, which is why it is env-gated.
    std::set<std::uint64_t> heap_pages_;
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
    // lowercased dll -> FirstThunk (IAT) RVA from the payload's own descriptors
    std::map<std::string, std::uint32_t> iat_rva_by_dll;
};

// Rebuilds a file-layout PE from the dump, appending a .pgimp import section.
// Returns the file bytes (empty when the dump is not a PE). Never throws into a
// caller that catches QlErrorBase: malformed input yields an empty result.
std::vector<std::uint8_t> rebuild_pe(const RebuildInput& in);
// The verbatim-dump fallback (rebuild_pe cannot lay the image out) writes the LOADED
// IMAGE, whose section table still describes the PACKED file - so PointerToRawData
// points into the compressed file and the entry maps nowhere. A memory image is flat
// by construction, so this rewrites each section's raw fields to file offset == RVA.
// Returns {} when the header is unusable or already flat.
std::vector<std::uint8_t> flatten_image_pe(const std::vector<std::uint8_t>& image);
// PEtite's stub rewrites every relative displacement in a decompressed block by
// SUBTRACTING the offset inside that block (its own pass at 0x40d38e:
// `sub dword [edx+edi+1],edx` at E8/E9 and `sub dword [edx+edi+2],edx` at 0F 8x).
// When that pass has not run, the dump holds the pre-transform stream and every
// call/jmp/jcc target is off by its own position. This undoes it, per EXECUTABLE
// section, but only when the undo genuinely restores structure: the gate is the
// share of call targets reached by more than one call site, which rises when the
// transform is removed from a pre-transform image and falls when it is removed
// from an already-correct one (measured on all 73 PEtite rows: 43 apply / 30 skip,
// 0 wrong either way). Returns the number of sections rewritten.
std::size_t undoSelfRelativeBlockTransform(std::vector<std::uint8_t>& image, std::uint64_t base);

}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_UNPACK_HPP
