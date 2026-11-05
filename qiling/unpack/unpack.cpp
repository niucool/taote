// qiling/unpack/unpack.cpp — the generic unpacker core (PLAN_UNPACK.md §1.3-§1.8).
//
// Ported from ../pegasus/src/unpacker/unpacker.cpp; the plan records the
// file:line map for every decision below. Phase 1 scope: section classification
// + watch set, write-claim tracking, section-hop OEP detection with an accept
// gate, image dump + meta sidecar, and a hand-rolled PE rebuilder that appends a
// .pgimp import section.
#include "qiling/unpack/unpack.hpp"

#if defined(__has_include)
#if __has_include(<unicorn/x86.h>)
#include <unicorn/x86.h>
#endif
#endif

#include "qiling/unpack/api_db.hpp"
#include "qiling/unpack/iat/iat_search.hpp"
#include "qiling/unpack/iat/import_rebuilder.hpp"
#include "qiling/unpack/packers/factories.hpp"
#include "qiling/unpack/packers/packer.hpp"

#include <LIEF/PE.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <numeric>

#include <nlohmann/json.hpp>

#include "qiling/exception.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace unpack {

namespace {

namespace fs = std::filesystem;

std::string lower_ascii(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string sanitize_ascii(std::string s) {
    for (auto& c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7E) {
            c = '.';
        }
    }
    return s;
}

std::string hex(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

std::uint32_t align_up(std::uint32_t v, std::uint32_t a) {
    if (a == 0) {
        return v;
    }
    return (v + a - 1) / a * a;
}

}  // namespace

Unpacker::Unpacker(UnpackOptions opts)
    : opts_(std::move(opts)), packer_(packers::make_packer(opts_.family)) {}

// hooks_ is cleared by finalize()/detach_hooks() while the engine is alive; a
// HookRet destructor after that would call uc_hook_del on a dead engine. The
// destructor therefore only detaches (release()) the handles: if the Qiling was
// destroyed first, hook_del would walk the freed hook registry (a
// heap-use-after-free the ASAN build catches). detach_hooks() is the
// live-engine path.
Unpacker::~Unpacker() {
    for (auto& h : hooks_) {
        h->release();
    }
    for (auto& h : dyn_hooks_) {
        h->release();
    }
}



int Unpacker::section_index_at(std::uint64_t addr) const {
    for (std::size_t i = 0; i < sections_.size(); ++i) {
        if (addr >= sections_[i].start && addr < sections_[i].end) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool Unpacker::inside_inplace(std::uint64_t addr) const {
    for (const auto& r : inplace_ranges_) {
        if (addr >= r.first && addr < r.second) {
            return true;
        }
    }
    return false;
}

// The reference's classify_sections (unpacker.cpp:95-171): turn the mapped
// sections into PackSection records, then choose what to watch.
void Unpacker::classify_sections(Qiling& ql) {
    sections_.clear();
    watched_.clear();
    inplace_ranges_.clear();

    const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
    base_ = pe_loader.pe_image_address();
    image_size_ = pe_loader.pe_image_size();
    is_64_ = ql.arch().bits() == 64;
    // the loader keeps the header's AddressOfEntryPoint verbatim: an RVA by
    // spec, but packers write a VA there (ASPack stores 0x42a001 = RVA|base with
    // base 0x400000), so resolve both forms instead of double-adding the base
    const auto raw_ep = pe_loader.entry_point;
    packed_ep_va_ = (raw_ep >= base_ && raw_ep < base_ + image_size_) ? raw_ep : base_ + raw_ep;

    // FSG's stub is written for a 0x400000 load: its prologue is
    // `mov ebx,0x4001d0; mov edi,0x401000; mov esi,<base+stream>` - the first two
    // operands are absolute for base 0x400000, the third is already relative to the
    // file's real base. A packed file whose ImageBase is NOT 0x400000 therefore
    // faults on its FIRST movsb, before any API call, because the destination it
    // computes is unmapped (it cannot run on Windows either). The packer's own
    // constants say what it meant, so shift the two absolute operands by
    // (base - 0x400000) when the stub carries exactly that prologue.
    if (base_ != 0x400000 &&
        packed_ep_va_ >= base_ && packed_ep_va_ < base_ + image_size_) {
        try {
            auto stub = ql.mem().read(packed_ep_va_, 15);
            if (stub.size() == 15 && stub[0] == 0xbb && stub[5] == 0xbf && stub[10] == 0xbe) {
                const auto delta = static_cast<std::uint32_t>(base_ - 0x400000);
                for (const std::size_t at : {std::size_t{1}, std::size_t{6}}) {
                    std::uint32_t v = static_cast<std::uint32_t>(stub[at]) |
                                      (static_cast<std::uint32_t>(stub[at + 1]) << 8) |
                                      (static_cast<std::uint32_t>(stub[at + 2]) << 16) |
                                      (static_cast<std::uint32_t>(stub[at + 3]) << 24);
                    if (v < 0x400000 || v >= 0x800000) {
                        continue;   // not a 0x400000-based constant: leave it alone
                    }
                    const auto moved = v + delta;
                    stub[at] = static_cast<std::uint8_t>(moved & 0xff);
                    stub[at + 1] = static_cast<std::uint8_t>((moved >> 8) & 0xff);
                    stub[at + 2] = static_cast<std::uint8_t>((moved >> 16) & 0xff);
                    stub[at + 3] = static_cast<std::uint8_t>((moved >> 24) & 0xff);
                }
                ql.mem().write(packed_ep_va_, stub);
                // The stub's multi-pass block table stores the destination VA PAGE in a
                // 16-bit word and the stub only shifts it (`movzwl (%ebx),%edi;
                // shl $0xc,%edi`), so a load base above 0xFFFF pages truncates that
                // field: fsg_cmd's block 2 wants page 0x4ad26 (= base 0x4ad00000 +
                // rva 0x26000) and the packer stored 0xad26, so the stub decodes to
                // 0xad26000 and dies before its last blocks - which is exactly where
                // the payload's import run lives (25 imports mined, recall 0.004).
                // Give it the page it asks for. The block addresses are its own
                // arithmetic on the truncated field, so the mapping restores the
                // packer's intent rather than guessing at it; the corpus has exactly
                // one such sample (fsg_cmd: FSG prologue + base page 0x4ad00), and it
                // goes from recall 0.004 to 1.0000 with the entry already exact.
                if ((base_ >> 12) > 0xffff) {
                    try {
                        const std::uint64_t truncated = ((base_ >> 12) & 0xffff) << 12;
                        // two guards keep this from being a general "map what the file
                        // says" seam: page 0 is never a block address (blocks live inside
                        // the payload), and a page that would overlap the image itself is
                        // not a truncation but a base whose low bits alias it.
                        const bool overlaps_image =
                            truncated < base_ + image_size_ && base_ < truncated + 0x400000;
                        if (truncated != 0 && !overlaps_image) {
                        ql.mem().map(truncated, 0x400000, UC_PROT_ALL, "[fsg truncated block page]");
                        if (opts_.debug) {
                            std::fprintf(stderr, "[unpack] FSG blocks map at 0x%llx\n",
                                         static_cast<unsigned long long>(truncated));
                        }
                        }
                    } catch (...) {
                    }
                }
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] FSG stub rebased by 0x%x (0x400000 -> %s)\n", delta,
                                 hex(base_).c_str());
                }
            }
        } catch (...) {
        }
    }

    // Only the first-write families read the shadow image (and the A/B switch).
    shadow_wanted_ = std::getenv("TAOTE_UNPACK_SHADOW_ALL") != nullptr ||
                     (packer_ != nullptr && packer_->shadow_policy() == packers::ShadowPolicy::first_write);
    shadow_image_.assign(static_cast<std::size_t>(image_size_), 0);
    shadow_seen_.assign(static_cast<std::size_t>(image_size_), false);
    exec_view_.assign(static_cast<std::size_t>(image_size_), 0);
    exec_page_seen_.assign(static_cast<std::size_t>(image_size_) / 0x1000 + 1, false);

    auto parsed = LIEF::PE::Parser::parse(opts_.sample_path);
    if (parsed == nullptr) {
        throw QlErrorBase("unpack: LIEF could not parse " + opts_.sample_path);
    }
    for (const auto& section : parsed->sections()) {
        PackSection ps;
        ps.name = sanitize_ascii(section.name());
        ps.start = base_ + section.virtual_address();
        ps.vsize = static_cast<std::uint32_t>(section.virtual_size());
        ps.end = ps.start + (ps.vsize ? ps.vsize : 1);
        ps.raw = static_cast<std::uint32_t>(section.sizeof_raw_data());
        ps.is_exec = section.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
        sections_.push_back(ps);
    }

    // primary watch set: exec sections + hollow (raw == 0) ones
    bool any_exec_watched = false;
    for (const auto& ps : sections_) {
        const bool hollow = ps.raw == 0 && ps.vsize > 0;
        const bool tiny_raw = ps.is_exec && ps.raw > 0 && ps.raw < ps.vsize / 4;
        if (!((ps.is_exec && ps.vsize > 0) || hollow)) {
            continue;
        }
        watched_.push_back(ps);
        if (ps.is_exec) {
            any_exec_watched = true;
            if (!hollow && !tiny_raw) {
                inplace_ranges_.insert({ps.start, ps.end});
            }
        }
    }
    // JDPack-class fallback: no exec candidate at all -> watch anything the
    // stub has to fill (unpacker.cpp:136-143)
    if (!any_exec_watched) {
        watched_.clear();
        for (const auto& ps : sections_) {
            if (ps.vsize > 0 && ps.vsize > ps.raw) {
                watched_.push_back(ps);
            }
        }
    }
    // secondary watch set: every remaining section except the packed EP's own
    // (unpacker.cpp:145-157) — Amber/MEW payloads land in sections that are not
    // marked exec in the packed layout
    for (const auto& ps : sections_) {
        bool already = false;
        for (const auto& w : watched_) {
            if (w.start == ps.start && w.end == ps.end) {
                already = true;
                break;
            }
        }
        if (already) {
            continue;
        }
        if (packed_ep_va_ >= ps.start && packed_ep_va_ < ps.end) {
            continue;
        }
        if (ps.vsize == 0) {
            continue;
        }
        watched_.push_back(ps);
    }

    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] base=%s image=%s ep=%s sections:\n", hex(base_).c_str(),
                     hex(image_size_).c_str(), hex(packed_ep_va_).c_str());
        for (const auto& ps : sections_) {
            std::fprintf(stderr, "  %-10s %s-%s vs=0x%x raw=0x%x exec=%d%s\n", ps.name.c_str(),
                         hex(ps.start).c_str(), hex(ps.end).c_str(), ps.vsize, ps.raw, ps.is_exec ? 1 : 0,
                         inside_inplace(ps.start) ? " inplace" : "");
        }
        std::fprintf(stderr, "[unpack] watched=%zu\n", watched_.size());
    }

    // the packed file's header (anti-emu stubs zero the in-memory MZ:
    // unpacker.cpp:213-221)
    try {
        std::ifstream in(opts_.sample_path, std::ios::binary);
        if (in) {
            header_snapshot_.resize(0x400);
            in.read(reinterpret_cast<char*>(header_snapshot_.data()), 0x400);
            header_snapshot_.resize(static_cast<std::size_t>(in.gcount()));
        }
    } catch (...) {
        header_snapshot_.clear();
    }
}

void Unpacker::note_import(const std::string& dll, const std::string& name) {
    if (dll.empty() || name.empty()) {
        return;
    }
    const bool fresh = import_seen_.insert(dll + "\n" + name).second;
    if (fresh) {
        imports_.emplace_back(dll, name);
    }
    if (opts_.debug) {
        static int n = 0;
        if (n++ < 6) {
            std::fprintf(stderr, "[unpack] note_import %s!%s fresh=%d imports_=%zu\n", dll.c_str(), name.c_str(),
                         fresh ? 1 : 0, imports_.size());
        }
    }
}

// One export-less decoy image for a dll the stub asked for (the reference's
// fabricated decoy module): a valid PE with a single `ret` cell, so the loader
// maps it, LoadLibrary answers its base, and GetProcAddress's module lookup names
// the dll for attribution.
bool Unpacker::materialize_decoy_dll(const std::string& dll_name) {
    if (!opts_.allow_decoy_dlls || opts_.rootfs.empty() || dll_name.empty()) {
        return false;
    }
    std::string name = fs::path(dll_name).filename().string();
    for (auto& c : name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (name.find('.') == std::string::npos) {
        name += ".dll";
    }
    const auto dir = fs::path(opts_.rootfs) / "Windows" / "System32";
    const auto path = dir / name;
    std::error_code ec;
    // A decoy cached by an older build carries the single `decoy_export` name; it
    // is stale - regenerate it with the dll's full surface.
    if (fs::exists(path, ec)) {
        try {
            std::ifstream in(path, std::ios::binary);
            std::string blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            if (blob.find("decoy_export") != std::string::npos) {
                fs::remove(path, ec);
            }
        } catch (...) {
        }
    }
    if (!fs::exists(path, ec)) {
        try {
            fs::create_directories(dir, ec);
            // A decoy that exports a SINGLE name is not enough for a stub that walks
            // the module's own export table: RLPack's resolver scans AddressOfNames
            // by name/hash, runs off the end of a one-entry table and computes a
            // garbage name pointer (measured: 0x75730000), after which the stub jumps
            // to 0 and the run dies. Seed the dll's FULL export surface from the SDK
            // database instead - every name gets its own `ret` cell.
            std::vector<std::string> surf = api_names_for(name);
            if (surf.empty()) {
                surf.emplace_back("decoy_export");
            }
            const std::size_t cell = 16;
            std::vector<std::uint8_t> code(std::max<std::size_t>(16, surf.size() * cell), 0xC3);
            auto factory = LIEF::PE::Factory::create(LIEF::PE::PE_TYPE::PE32_PLUS);
            LIEF::PE::Section text(".text", code);
            factory->add_section(text);
            auto bin = factory->get();
            std::uint32_t text_rva = 0;
            for (const auto& sec : bin->sections()) {
                if (sec.name() == ".text") {
                    text_rva = sec.virtual_address();
                }
            }
            std::vector<LIEF::PE::ExportEntry> entries;
            entries.reserve(surf.size());
            for (std::size_t i = 0; i < surf.size(); ++i) {
                entries.emplace_back(surf[i], static_cast<std::uint32_t>(text_rva + i * cell));
            }
            LIEF::PE::Export exp(name, entries);
            bin->set_export(exp);
            LIEF::PE::Builder::config_t cfg;
            cfg.exports = true;
            cfg.resources = false;
            cfg.relocations = false;
            cfg.load_configuration = false;
            cfg.tls = false;
            cfg.overlay = false;
            cfg.debug = false;
            cfg.dos_stub = false;
            LIEF::PE::Builder builder(*bin, cfg);
            builder.build();
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            const auto& bytes = builder.get_build();
            out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        } catch (...) {
            return false;
        }
    }
    return fs::exists(path, ec);
}

void Unpacker::install_gpa_sentinel(Qiling& ql) {
    auto& os = ql.os();

    // the LoadLibrary/GetModuleHandle name tracker (the reference's llname hook,
    // unpacker.cpp:269-330)
    const auto track = [this](Qiling& q, const QlOs::NamedParams& params, std::optional<std::uint64_t> retval)
        -> std::optional<std::uint64_t> {
        // the param is typed LPCSTR_/LPCWSTR_, so the resolved value arrives as a
        // std::string; a raw-pointer form (uint64) is read from guest memory
        std::string name;
        for (const auto& [key, value] : params) {
            if (key.rfind("lpLibFileName", 0) != 0 && key.rfind("lpModuleName", 0) != 0) {
                continue;
            }
            if (const auto* v = std::get_if<std::uint64_t>(&value); v != nullptr) {
                if (*v > 0x10000) {
                    try {
                        name = os::QlOsUtils::read_cstring(q, *v);
                    } catch (...) {
                        name.clear();
                    }
                }
            } else if (const auto* str = std::get_if<std::string>(&value); str != nullptr) {
                name = *str;
            }
            break;
        }
        if (name.empty()) {
            return std::nullopt;
        }
        std::string base = fs::path(name).filename().string();
        for (auto& c : base) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        last_ll_name_ = base;
        if (retval.has_value() && *retval > 0x10000) {
            handle_names_[*retval] = base;
            return std::nullopt;
        }
        // the loader could not find it: fabricate a decoy so the module handle is
        // real and the dll is identifiable
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] loadlib %s retval=%s\n", base.c_str(),
                         retval.has_value() ? hex(*retval).c_str() : "none");
        }
        if (!retval.has_value() || *retval == 0) {
            const bool ok = materialize_decoy_dll(base);
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] decoy %s -> %d\n", base.c_str(), ok ? 1 : 0);
            }
            if (ok) {
                try {
                    const auto loaded = static_cast<loader::QlLoaderPE&>(q.loader()).load_dll(base);
                    if (loaded != 0) {
                        handle_names_[loaded] = base;
                        return loaded;
                    }
                } catch (...) {
                }
            }
        }
        return std::nullopt;
    };
    for (const char* api : {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                            "GetModuleHandleA", "GetModuleHandleW"}) {
        os.set_api_exit(api, track);
    }
    os.set_api_exit("GetProcAddress",
                    [this](Qiling& q, const QlOs::NamedParams& params, std::optional<std::uint64_t> retval)
                        -> std::optional<std::uint64_t> {
        std::uint64_t hmod = 0;
        std::uint64_t name_ptr = 0;
        for (const auto& [key, value] : params) {
            const auto* v = std::get_if<std::uint64_t>(&value);
            if (v == nullptr) {
                continue;
            }
            if (key == "hModule" || key == "hLibModule") {
                hmod = *v;
            } else if (key == "lpProcName") {
                name_ptr = *v;
            }
        }
        std::string name;
        if (name_ptr > 0x10000) {
            try {
                const auto raw = q.mem().read(name_ptr, 256);
                std::size_t nul = 0;
                while (nul < raw.size() && raw[nul] != 0) {
                    ++nul;
                }
                name.assign(reinterpret_cast<const char*>(raw.data()), nul);
            } catch (...) {
                name.clear();
            }
        } else if (name_ptr != 0) {
            name = "ordinal_" + std::to_string(name_ptr);
        }
        // the dll: the module handle's image, else the image the name resolves in
        std::string dll;
        try {
            const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(q.loader());
            if (hmod != 0) {
                if (const auto* img = pe_loader.find_containing_image(hmod); img != nullptr) {
                    dll = lower_ascii(fs::path(img->path).filename().string());
                }
            }
            if (dll.empty() && retval.has_value() && *retval != 0) {
                if (const auto* img = pe_loader.find_containing_image(*retval); img != nullptr) {
                    dll = lower_ascii(fs::path(img->path).filename().string());
                }
            }
        } catch (...) {
            dll.clear();
        }
        // the LoadLibrary handle is the most authoritative owner of this
        // GetProcAddress call: a by-ordinal probe (lpProcName < 0x10000) has no
        // name to look up, and name-based attribution matches the first dll that
        // happens to import that ordinal (activeds!ordinal_9 was being stolen by
        // oleaut32!ordinal_9). Check the handle map before any name lookup.
        if (dll.empty() && hmod != 0) {
            const auto hit = handle_names_.find(hmod);
            if (hit != handle_names_.end()) {
                dll = hit->second;
            }
        }
        if (dll.empty() && !name.empty()) {
            // the handle is often a decoy: attribute by who exports the name
            // (the reference's last_ll_name_/alias evidence analogue)
            try {
                const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(q.loader());
                for (const auto& key : pe_loader.import_address_table_keys()) {
                    const auto* iat = pe_loader.import_address_table_at(key);
                    if (iat == nullptr || iat->lookup(name) == 0) {
                        continue;
                    }
                    dll = lower_ascii(key);
                    break;
                }
            } catch (...) {
                dll.clear();
            }
        }
        if (dll.empty()) {
            dll = last_ll_name_;
        }
        if (dll.empty()) {
            dll = "kernel32.dll";
        }
        dll = sanitize_ascii(dll);
        name = sanitize_ascii(name);
        if (!(retval.has_value() && *retval != 0) && std::getenv("TAOTE_GPANULL") != nullptr) {
            static std::size_t n = 0;
            if (n++ < 2) {
                auto &r = q.arch().regs();
                const auto pc = r.arch_pc();
                std::fprintf(stderr,
                             "[gpn] pc=0x%llx eax=0x%llx ebx=0x%llx ecx=0x%llx edx=0x%llx esi=0x%llx edi=0x%llx"
                             " ebp=0x%llx esp=0x%llx nameptr=0x%llx\n",
                             (unsigned long long)pc, (unsigned long long)r.read("eax"),
                             (unsigned long long)r.read("ebx"),
                             (unsigned long long)r.read("ecx"),
                             (unsigned long long)r.read("edx"),
                             (unsigned long long)r.read("esi"),
                             (unsigned long long)r.read("edi"),
                             (unsigned long long)r.read("ebp"),
                             (unsigned long long)r.read("esp"),
                             (unsigned long long)name_ptr);
                const auto sp = r.read("esp");
                try {
                    // The resolver's own state lives in the registers it was
                    // called with, so dump what they point at: a packer's
                    // import-rebuild loop keeps its descriptor/cursor there.
                    for (const char* reg : {"esi", "edi", "ebx", "ebp"}) {
                        const auto va = r.read(reg);
                        auto b = q.mem().read(va, 16);
                        std::fprintf(stderr, "[gpn] [%s]=0x%llx:", reg, (unsigned long long)va);
                        for (auto ch : b) std::fprintf(stderr, " %02x", ch);
                        std::fprintf(stderr, "\n");
                    }
                    for (int i = 0; i < 6; ++i) {
                        auto b = q.mem().read(sp + 4 * i, 4);
                        std::uint32_t v = 0;
                        std::memcpy(&v, b.data(), 4);
                        std::fprintf(stderr, "[gpn]   [esp+%2d] = 0x%08x\n", 4 * i, v);
                    }
                } catch (...) {
                }
            }
        }
        if (retval.has_value() && *retval != 0) {
            note_import(dll, name);  // the loader really resolved it
            return std::nullopt;
        }
        if (name.empty()) {
            return std::nullopt;  // nothing to mint for an unreadable name
        }
        // Mint a *callable* sentinel: the loader's synthesized stub arena gives a
        // mapped `xor eax,eax; ret` cell (a bare address would fault the moment
        // the stub calls it — measured: ASPack's stub calls VirtualAlloc through
        // the value and died with UC_ERR_FETCH_UNMAPPED), and registering the
        // name at that cell makes the dispatcher answer the call when taote has a
        // handler for it.
        std::uint64_t sentinel = 0;
        try {
            auto& pe_loader = static_cast<loader::QlLoaderPE&>(q.loader());
            sentinel = pe_loader.unbound_import_stub(name);
            if (sentinel != 0) {
                pe_loader.register_import_symbol(sentinel, dll, name);
            }
        } catch (...) {
            sentinel = 0;
        }
        if (sentinel == 0) {
            sentinel = gpa_sentinel_ += 0x10;
        }
        note_import(dll, name);
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] gpa sentinel %s!%s -> %s\n", dll.c_str(), name.c_str(),
                         hex(sentinel).c_str());
        }
        return sentinel;
    });
}

void Unpacker::install(Qiling& ql) {
    pet_exit_on_ = opts_.family == "PEtite" && std::getenv("TAOTE_NO_PET_EXIT") == nullptr;
    sec_trans_on_ = std::getenv("TAOTE_SEC_TRANS") != nullptr || pet_exit_on_;
    ql_ = &ql;
    classify_sections(ql);

    // TAOTE_SEED_STATIC / Packer::seed_image_before_run: run the family's static
    // image recovery against the guest's mapped image BEFORE the stub executes.
    // Off unless the family asks for it (or the env lever forces it for an A/B):
    // a family whose decode is not idempotent against the stub's own writeback
    // would be corrupted by pre-seeding, so this is opt-in per family.
    // The PECompact placeholder bound (see pc_far_hop_limit_): read the mapped
    // header once here. AddressOfEntryPoint == the first section's VirtualAddress
    // means the packer did not preserve the entry, which is the class where the
    // stub's hand-off is far into the payload (measured 29/29 on the family).
    if (opts_.family == "PECompact" && image_size_ >= 0x400) {
        try {
            // the section table can start past 0x200 (pecompact_Everything's does:
            // lfanew 0x100 + 24 + sopt 0xe0 = 0x1f8), so read a full header page
            const auto head = ql.mem().read(base_, std::min<std::uint64_t>(0x1000, image_size_));
            if (head.size() >= 0x60 && head[0] == 'M' && head[1] == 'Z') {
                const auto rd = [&head](std::size_t o) {
                    return o + 4 <= head.size()
                               ? static_cast<std::uint32_t>(head[o]) |
                                     (static_cast<std::uint32_t>(head[o + 1]) << 8) |
                                     (static_cast<std::uint32_t>(head[o + 2]) << 16) |
                                     (static_cast<std::uint32_t>(head[o + 3]) << 24)
                               : 0u;
                };
                const auto lfanew = rd(0x3c);
                const auto nsec = static_cast<std::size_t>(rd(lfanew + 6) & 0xffff);
                const auto sopt = static_cast<std::size_t>(rd(lfanew + 20) & 0xffff);
                const auto ep_rva = rd(lfanew + 24 + 0x10);
                const auto first_va = nsec != 0 ? rd(lfanew + 24 + sopt + 12) : 0u;
                if (ep_rva != 0 && ep_rva == first_va) {
                    pc_far_hop_limit_ = base_ + ep_rva + 0x10000;
                }
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] pecompact placeholder: ep=0x%x first_va=0x%x far bound=0x%llx\n",
                                 ep_rva, first_va, static_cast<unsigned long long>(pc_far_hop_limit_));
                }
            }
        } catch (...) {
        }
    }
    if (packer_ != nullptr && image_size_ != 0 && base_ != 0 &&
        (packer_->seed_image_before_run() || std::getenv("TAOTE_SEED_STATIC") != nullptr)) {
        try {
            std::vector<std::uint8_t> image = ql.mem().read(base_, image_size_);
            const auto before = image;
            packers::PackerContext tctx;
            tctx.ql = &ql;
            tctx.image_ptr = &image;
            tctx.image_mut = &image;
            std::vector<std::pair<std::string, std::string>> seed_imports;
            tctx.imports_out = &seed_imports;
            tctx.base = base_;
            tctx.image_size = image_size_;
            tctx.packed_ep_va = packed_ep_va_;
            tctx.is_64 = is_64_;
            tctx.debug = opts_.debug;
            tctx.family = opts_.family;
            tctx.sections = sections_;
            tctx.packed_path = &opts_.sample_path;
            tctx.seed_mode = true;
            if (packer_->transform_image(tctx)) {
                if (tctx.adopted_sections.size() > 0) {
                    sections_ = tctx.adopted_sections;
                }
                std::size_t changed = 0;
                for (std::size_t i = 0; i < image.size() && i < before.size(); ++i) {
                    changed += (image[i] != before[i]) ? 1 : 0;
                }
                if (changed != 0) {
                    ql.mem().write(base_, image);
                }
                // The seed is a WRITE by us: register the restored pages as
                // claimed so a stub that hands off into them is recognised as a
                // section hop (Alienyze's stub jumps straight to the payload
                // entry after building the IAT, and nothing else writes there).
                if (changed != 0) {
                    for (const auto& r : tctx.seeded_ranges) {
                        if (r.second <= r.first) {
                            continue;
                        }
                        const auto claim = std::make_pair(r.first, r.second);
                        ever_written_.insert(claim);
                        written_ranges_.insert(claim);
                    }
                    if (!tctx.seeded_ranges.empty()) {
                        wr_cache_lo_ = base_;
                        wr_cache_hi_ = base_ + image_size_;
                    }
                }
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] static seed: %zu bytes changed before the stub, %zu pairs\n",
                                 changed, seed_imports.size());
                }
                for (const auto& [dll, fn] : seed_imports) {
                    note_import(sanitize_ascii(dll), sanitize_ascii(fn));
                }
            }
        } catch (...) {
            // the seed is an optimisation: a family whose transform throws on the
            // live image keeps the packed one and the run proceeds as before
        }
    }

    // TAOTE_CPUIDBG=1: log every CPUID and RDTSC the guest executes. These are the
    // inline environment probes an anti-emulation stub uses, and they leave no API
    // trace at all (TELock/Yoda/Alienyze make zero API calls before bailing).
    if (std::getenv("TAOTE_CPUIDBG") != nullptr) {
        {
            auto h = std::make_shared<HookRet>(ql.hook_insn([this](const std::vector<std::uint64_t>&) -> int {
                const auto& r = ql_->arch().regs();
                const auto leaf = r.read("eax");
                const auto sub = r.read("ecx");
                std::fprintf(stderr, "[cpuid] leaf=0x%llx sub=0x%llx\n",
                             static_cast<unsigned long long>(leaf), static_cast<unsigned long long>(sub));
                return 0;
            }, UC_X86_INS_CPUID));
            std::fprintf(stderr, "[cpuidbg] cpuid hook ok=%d\n", h->obj() != nullptr ? 1 : 0);
            hooks_.push_back(std::move(h));
        }
        {
            auto h = std::make_shared<HookRet>(ql.hook_insn([this](const std::vector<std::uint64_t>&) -> int {
                const auto& r = ql_->arch().regs();
                std::fprintf(stderr, "[rdtsc] pc=0x%llx\n", static_cast<unsigned long long>(r.arch_pc()));
                return 0;
            }, UC_X86_INS_RDTSC));
            std::fprintf(stderr, "[cpuidbg] rdtsc hook ok=%d\n", h->obj() != nullptr ? 1 : 0);
            hooks_.push_back(std::move(h));
        }
    }
    // TAOTE_WATCH=lo:len[:max]: log every write inside [lo,lo+len) with the pc and the
    // value being stored. A stub's descriptor/table fields are consumed and rewritten
    // as a loop advances, so the only way to name the code that produced a bad entry is
    // to catch the store itself.
    if (const char* wt = std::getenv("TAOTE_WATCH"); wt != nullptr) {
        unsigned long long wlo = 0, wlen = 0;
        int wmax = 64;
        const int nf = std::sscanf(wt, "%llx:%llx:%d", &wlo, &wlen, &wmax);
        if (nf >= 2 && wlen != 0) {
            auto whits = std::make_shared<int>(0);
            auto h = std::make_shared<HookRet>(ql.hook_mem_write(
                [this, &ql, wlo, wlen, wmax, whits](int /*access*/, std::uint64_t addr, std::uint32_t size,
                                                    std::int64_t value) -> int {
                    if (addr < wlo || addr >= wlo + wlen) {
                        return 0;
                    }
                    if (*whits >= wmax) {
                        return 0;
                    }
                    ++*whits;
                    std::uint64_t pc = 0;
                    try {
                        pc = ql.arch().regs().arch_pc();
                    } catch (...) {
                    }
                    std::fprintf(stderr, "[watch] pc=0x%llx addr=0x%llx size=%u value=0x%llx\n",
                                 static_cast<unsigned long long>(pc), static_cast<unsigned long long>(addr),
                                 size, static_cast<unsigned long long>(value));
                    return 0;
                },
                1, 0));
            hooks_.push_back(std::move(h));
        }
    }
    if (std::getenv("TAOTE_HEAPSCAN") != nullptr) {
        auto h = std::make_shared<HookRet>(ql.hook_mem_write(
            [this](int /*access*/, std::uint64_t addr, std::uint32_t /*size*/, std::int64_t /*value*/) -> int {
                if (addr < base_ || addr >= base_ + image_size_) {
                    heap_pages_.insert(addr & ~0xfffULL);
                }
                return 0;
            },
            1, 0));
        hooks_.push_back(std::move(h));
    }
    // TAOTE_FSGTRACE: log the stub's own execution, one line per instruction, so a
    // hand-written model of FSG's decoder can be diffed against unicorn's. Used to
    // validate /tmp/fsgemu.py against fsg_cmd, whose decode taote gets right.
    if (const char* ft = std::getenv("TAOTE_FSGTRACE"); ft != nullptr) {
        // "N" traces the first N instructions in the FSG EP window; "lo:hi:N" traces
        // any range, which is how a stub decoder's own execution is read directly
        // (a range trace needs no reference run).
        std::uint64_t tr_lo = 0, tr_hi = 0;
        std::size_t n = 0;
        if (std::strchr(ft, ':') != nullptr) {
            unsigned long long a = 0, b = 0, c = 0;
            if (std::sscanf(ft, "%llx:%llx:%llu", &a, &b, &c) == 3) {
                tr_lo = a;
                tr_hi = b;
                n = (std::size_t)c;
            }
        } else {
            n = std::strtoul(ft, nullptr, 0);
        }
        if (n > 0) {
            auto h = std::make_shared<HookRet>(ql.hook_code([this, n, &ql, tr_lo, tr_hi](std::uint64_t addr, std::uint32_t) -> int {
                static std::size_t emitted = 0;
                if (emitted >= n || packed_ep_va_ == 0) {
                    return 0;
                }
                if (tr_lo != 0) {
                    if (addr < tr_lo || addr >= tr_hi) {
                        return 0;
                    }
                    auto& r2 = ql.arch().regs();
                    std::fprintf(stderr,
                                 "[tr] %llx eax=%llx ebx=%llx ecx=%llx edx=%llx esi=%llx edi=%llx ebp=%llx "
                                 "esp=%llx ef=%llx\n",
                                 (unsigned long long)addr, (unsigned long long)(r2.read("eax") & 0xffffffffull),
                                 (unsigned long long)(r2.read("ebx") & 0xffffffffull),
                                 (unsigned long long)(r2.read("ecx") & 0xffffffffull),
                                 (unsigned long long)(r2.read("edx") & 0xffffffffull),
                                 (unsigned long long)(r2.read("esi") & 0xffffffffull),
                                 (unsigned long long)(r2.read("edi") & 0xffffffffull),
                                 (unsigned long long)(r2.read("ebp") & 0xffffffffull),
                                 (unsigned long long)(r2.read("esp") & 0xffffffffull),
                                 (unsigned long long)(r2.read("eflags") & 0xffffffffull));
                    ++emitted;
                    return 0;
                }
                if (addr < packed_ep_va_ || addr >= packed_ep_va_ + 0x200) {
                    return 0;
                }
                auto& regs = ql.arch().regs();
                std::fprintf(stderr, "[fsgt] %llx eax=%llx ebx=%llx ecx=%llx edx=%llx esi=%llx edi=%llx\n",
                             static_cast<unsigned long long>(addr),
                             static_cast<unsigned long long>(regs.read("eax") & 0xffffffffull),
                             static_cast<unsigned long long>(regs.read("ebx") & 0xffffffffull),
                             static_cast<unsigned long long>(regs.read("ecx") & 0xffffffffull),
                             static_cast<unsigned long long>(regs.read("edx") & 0xffffffffull),
                             static_cast<unsigned long long>(regs.read("esi") & 0xffffffffull),
                             static_cast<unsigned long long>(regs.read("edi") & 0xffffffffull));
                ++emitted;
                return 0;
            }));
            hooks_.push_back(std::move(h));
        }
    }
    if (const char* lp = std::getenv("TAOTE_LASTPC"); lp != nullptr) {
        const std::size_t n = std::strtoul(lp, nullptr, 0);
        if (n > 0) {
            last_pcs_.assign(n, 0);
            auto h = std::make_shared<HookRet>(ql.hook_code([this, n](std::uint64_t addr, std::uint32_t) -> int {
                last_pcs_[last_pc_pos_ % n] = addr;
                ++last_pc_pos_;
                return 0;
            }));
            hooks_.push_back(std::move(h));
        }
    }

    // TAOTE_WATCH_ADDR=<hex addr>[:<n>]: print the first n writes (default 8) to that
    // guest address, with the writing pc and the value. Same debugging class as
    // TAOTE_LASTPC/TAOTE_PROBE: off by default, no behaviour change.
    if (const char* wa = std::getenv("TAOTE_WATCH_ADDR"); wa != nullptr && *wa != '\0') {
        std::string spec(wa);
        std::size_t want = 8;
        if (const auto c = spec.find(':'); c != std::string::npos) {
            want = std::strtoul(spec.c_str() + c + 1, nullptr, 0);
            spec.resize(c);
        }
        const auto watch_addr = std::strtoull(spec.c_str(), nullptr, 0);
        auto seen = std::make_shared<std::size_t>(0);
        auto h = std::make_shared<HookRet>(ql.hook_mem_write(
            [this, &ql, watch_addr, want, seen](int /*access*/, std::uint64_t addr, std::uint32_t size,
                                                std::int64_t value) -> int {
                if (addr <= watch_addr && addr + static_cast<std::uint64_t>(size) > watch_addr &&
                    *seen < want) {
                    ++*seen;
                    const auto pc = ql.arch().regs().arch_pc();
                    std::fprintf(stderr, "[watch] write to 0x%llx (len %d, covers 0x%llx) val=0x%llx pc=0x%llx\n",
                                 static_cast<unsigned long long>(addr), size,
                                 static_cast<unsigned long long>(watch_addr),
                                 static_cast<unsigned long long>(value),
                                 static_cast<unsigned long long>(pc));
                }
                return 0;
            }));
        hooks_.push_back(std::move(h));
    }

    // TAOTE_WATCH_RANGE=<hex lo>-<hex hi>[:n]: log the first n writes (default 64)
    // that land inside [lo, hi) with the writing pc, the address, the width and the
    // value - the write-only companion of TAOTE_WATCH_ADDR, for finding the first
    // store that produces a wrong byte in a decoder's scratch region.
    if (const char* wr = std::getenv("TAOTE_WATCH_RANGE"); wr != nullptr && *wr != '\0') {
        std::string spec(wr);
        std::size_t want = 64;
        if (const auto c = spec.find(':'); c != std::string::npos) {
            want = std::strtoul(spec.c_str() + c + 1, nullptr, 0);
            spec.resize(c);
        }
        const auto dash = spec.find('-');
        const auto lo = std::strtoull(spec.substr(0, dash).c_str(), nullptr, 0);
        const auto hi = dash == std::string::npos
                            ? lo + 0x1000
                            : std::strtoull(spec.substr(dash + 1).c_str(), nullptr, 0);
        auto seen = std::make_shared<std::size_t>(0);
        auto h = std::make_shared<HookRet>(ql.hook_mem_write(
            [this, &ql, lo, hi, want, seen](int /*access*/, std::uint64_t addr, std::uint32_t size,
                                            std::int64_t value) -> int {
                if (addr >= lo && addr < hi && *seen < want) {
                    ++*seen;
                    const auto pc = ql.arch().regs().arch_pc();
                    std::fprintf(stderr, "[watchr] #%zu pc=0x%llx addr=0x%llx len=%u val=0x%llx\n",
                                 *seen, static_cast<unsigned long long>(pc),
                                 static_cast<unsigned long long>(addr), size,
                                 static_cast<unsigned long long>(value));
                }
                return 0;
            }));
        hooks_.push_back(std::move(h));
    }

    // TAOTE_PROBE=<hex pc>: dump the guest registers and the return slot the first
    // time that exact pc executes. A debugging aid (like TAOTE_LASTPC/TAOTE_FSGTRACE):
    // a stub loop that runs away is only diagnosable if you can see which pointer it
    // was handed, and the operand is computed by its CALLER, so log the stack slot too.
    if (const char* probe = std::getenv("TAOTE_PROBE")) {
        const auto want = static_cast<std::uint64_t>(std::strtoull(probe, nullptr, 0));
        if (want != 0) {
            // TAOTE_PROBE_N raises the 3-hit cap; TAOTE_PROBE_FAIL logs only hits
            // where eax == 0, which is how a stub's own "corrupt input" verdict is
            // localised to the exact call that returned it.
            const char* nmax = std::getenv("TAOTE_PROBE_N");
            const int maxhits = nmax != nullptr ? std::atoi(nmax) : 3;
            const bool only_zero = std::getenv("TAOTE_PROBE_FAIL") != nullptr;
            // TAOTE_PROBE_PREV records the pc executed immediately before a probe hit:
            // a shared failure exit (PEtite's 0x4181c7 has ten edges, each a different
            // format check) is only diagnosable if the predecessor names which check it
            // was. Costs a second code hook, so it is opt-in.
            auto prev_pc = std::make_shared<std::uint64_t>(0);
            if (std::getenv("TAOTE_PROBE_PREV") != nullptr) {
                auto ph = std::make_shared<HookRet>(ql.hook_code([prev_pc, want](std::uint64_t a, std::uint32_t) -> int {
                    if (a != want) {  // keep the pc that LED here, not the probe pc itself
                        *prev_pc = a;
                    }
                    return 0;
                }));
                hooks_.push_back(std::move(ph));
            }
            auto hits = std::make_shared<int>(0);
            auto h = std::make_shared<HookRet>(ql.hook_code([this, &ql, want, hits, maxhits, only_zero, prev_pc](std::uint64_t addr,
                                                                                  std::uint32_t) -> int {
                if (addr != want || *hits >= maxhits) {
                    return 0;
                }
                if (only_zero && ql.arch().regs().read("eax") != 0) {
                    return 0;
                }
                ++*hits;
                auto& regs = ql.arch().regs();
                const auto rd = [&regs](const char* n) { return regs.read(n); };
                std::uint64_t ret = 0;
                try {
                    const auto sp = rd("esp");
                    const auto bytes = ql.mem().read(sp, 4);
                    if (bytes.size() == 4) {
                        ret = static_cast<std::uint64_t>(bytes[0]) | (static_cast<std::uint64_t>(bytes[1]) << 8) |
                              (static_cast<std::uint64_t>(bytes[2]) << 16) |
                              (static_cast<std::uint64_t>(bytes[3]) << 24);
                    }
                } catch (...) {
                }
                const auto peek = [&ql](std::uint64_t a) {
                    std::string out;
                    try {
                        for (auto b : ql.mem().read(a, 24)) {
                            out += (b >= 0x20 && b < 0x7f) ? static_cast<char>(b) : '.';
                        }
                    } catch (...) {
                        out = "?";
                    }
                    return out;
                };
                std::fprintf(stderr,
                             "[probe] pc=0x%llx eax=0x%llx ebx=0x%llx ecx=0x%llx edx=0x%llx esi=0x%llx"
                             " edi=0x%llx ebp=0x%llx esp=0x%llx eflags=0x%llx ret=0x%llx\n",
                             static_cast<unsigned long long>(addr), static_cast<unsigned long long>(rd("eax")),
                             static_cast<unsigned long long>(rd("ebx")), static_cast<unsigned long long>(rd("ecx")),
                             static_cast<unsigned long long>(rd("edx")), static_cast<unsigned long long>(rd("esi")),
                             static_cast<unsigned long long>(rd("edi")), static_cast<unsigned long long>(rd("ebp")),
                             static_cast<unsigned long long>(rd("esp")),
                             static_cast<unsigned long long>(rd("eflags")),
                             static_cast<unsigned long long>(ret));
                // an 8-dword window at esp: a stub that corrupts its own return
                // chain is only diagnosable by seeing the slots it pushes
                try {
                    const auto sp0 = rd("esp");
                    std::string win;
                    for (int k = 0; k < 8; ++k) {
                        const auto b4 = ql.mem().read(sp0 + 4 * static_cast<std::uint64_t>(k), 4);
                        if (b4.size() != 4) {
                            win += " --";
                            continue;
                        }
                        const auto v = static_cast<std::uint64_t>(b4[0]) | (static_cast<std::uint64_t>(b4[1]) << 8) |
                                       (static_cast<std::uint64_t>(b4[2]) << 16) |
                                       (static_cast<std::uint64_t>(b4[3]) << 24);
                        char buf[16];
                        std::snprintf(buf, sizeof(buf), " %llx", static_cast<unsigned long long>(v));
                        win += buf;
                    }
                    std::fprintf(stderr, "[probe]   stack[esp..+32]:%s\n", win.c_str());
                } catch (...) {
                }
                if (std::getenv("TAOTE_PROBE_PREV") != nullptr) {
                    std::fprintf(stderr, "[probe]   prev_pc=0x%llx\n",
                                 static_cast<unsigned long long>(*prev_pc));
                }
                try {
                    std::fprintf(stderr, "[probe]   fs_base=0x%llx\n",
                                 static_cast<unsigned long long>(rd("fsbase")));
                } catch (...) {
                }
                // the flags: a decrypt ladder's branch (TELock's `jns` over an
                // overlapping instruction stream) is decided by SF/OF alone, so a
                // divergence that looks like a decode difference is often a flag
                // difference. env-gated with the rest of the probe.
                try {
                    const auto fl = rd("eflags");
                    std::fprintf(stderr,
                                 "[probe]   eflags=0x%08llx [%s%s%s%s%s%s%s%s]\n",
                                 static_cast<unsigned long long>(fl),
                                 (fl & 0x1) ? "CF " : "", (fl & 0x4) ? "PF " : "",
                                 (fl & 0x10) ? "AF " : "", (fl & 0x40) ? "ZF " : "",
                                 (fl & 0x80) ? "SF " : "", (fl & 0x400) ? "OF " : "",
                                 (fl & 0x800) ? "DF " : "", (fl & 0x40000) ? "AC " : "");
                } catch (...) {
                }
                std::fprintf(stderr, "[probe]   @eax='%s' @edx='%s'\n", peek(rd("eax")).c_str(), peek(rd("edx")).c_str());
                // the LIVE bytes at pc: a self-decrypting stub's code cannot be read
                // from the terminal dump (the page is re-encrypted or the run stops
                // before the dump), and the disassembly of the instruction that is
                // about to run is often the whole question.
                try {
                    std::string hexbytes;
                    for (auto b : ql.mem().read(addr, 48)) {
                        char hb[4];
                        std::snprintf(hb, sizeof(hb), " %02x", static_cast<unsigned>(b));
                        hexbytes += hb;
                    }
                    std::fprintf(stderr, "[probe]   @pc=%s\n", hexbytes.c_str());
                } catch (...) {
                }
                // TAOTE_PROBE_EBP_DISP=<dec>: also show the dword at [ebp+disp] - the slot an
                // indirect call is about to use, which is where a pre-resolved API pointer lives
                if (const char* d = std::getenv("TAOTE_PROBE_EBP_DISP")) {
                    const auto disp = static_cast<std::int64_t>(std::strtoll(d, nullptr, 0));
                    const auto at = static_cast<std::uint64_t>(static_cast<std::int64_t>(rd("ebp")) + disp);
                    std::uint64_t v = 0;
                    std::string raw = "?";
                    try {
                        const auto b4 = ql.mem().read(at, 4);
                        if (b4.size() == 4) {
                            v = static_cast<std::uint64_t>(b4[0]) | (static_cast<std::uint64_t>(b4[1]) << 8) |
                                (static_cast<std::uint64_t>(b4[2]) << 16) | (static_cast<std::uint64_t>(b4[3]) << 24);
                        }
                        raw = peek(v);
                    } catch (...) {
                    }
                    std::fprintf(stderr, "[probe]   [ebp%+lld]=0x%llx @ptr='%s'\n", static_cast<long long>(disp),
                                 static_cast<unsigned long long>(v), raw.c_str());
                }
                return 0;
            }));
            if (h->obj() != nullptr) {
                hooks_.push_back(std::move(h));
            }
        }
    }

    // no hops at all (the Phase 0 artifact-only mode): the dump is the entry
    // state, which is what "no unpacking" means for the scoreboard
    if (!opts_.enable_hop) {
        return;
    }

    // the packer's install-time static OEP (the reference's SLOT_MEW_OEP_PARSE and
    // friends): a family that records the payload entry in its own header table
    // hands it over here, before the stub runs
    {
        packers::PackerContext ctx;
        ctx.ql = &ql;
        ctx.base = base_;
        ctx.image_size = image_size_;
        ctx.packed_ep_va = packed_ep_va_;
        ctx.is_64 = is_64_;
        ctx.debug = opts_.debug;
        ctx.family = opts_.family;
        ctx.sections = sections_;
        const auto static_ep = packer_->static_oep(ctx);
        if (static_ep != 0) {
            static_oep_ = static_ep;
        }
    }

    install_gpa_sentinel(ql);
    // let the unpacker notice guest-allocated regions at allocation time
    try {
        for (const auto& mi : ql.mem().get_mapinfo()) {
            if (std::get<1>(mi) > std::get<0>(mi)) {
                initial_maps_.insert(std::get<0>(mi));
            }
        }
        ql.os<os::windows::QlOsWindows>().set_api_observer(
            [this](const std::string& /*api*/) { poll_dyn_maps(); });
    } catch (...) {
    }

    // unpack mode: an unhandled access violation whose guest handler answered
    // EXCEPTION_CONTINUE_SEARCH resumes at the saved CONTEXT (the reference's
    // raw-chain continue) instead of ending the run. The handler has usually
    // patched the trapping instruction, so the retry progresses; the dispatch's
    // identical-fault repeat guard bounds a handler that fixes nothing.
    try {
        ql.os<os::windows::QlOsWindows>().set_seh_continue_on_exhausted(true);
        // PEtite's exception-driven decryptor walks the SEH chain it captured; the
        // loader's empty chain makes that pivot deref null (mov ebp,[ebx+8], ebx=0).
        if (opts_.family == "PEtite") {
            auto& wos = ql.os<os::windows::QlOsWindows>();
            // the stub's read-only header must fault into its handler, the TF storm
            // needs a far larger budget than 4096, and the decryptor walks the SEH chain
            // it captured - without all three the payload never runs (0.17ja).
            wos.set_prot_enforce(true);
            wos.set_tf_trap_cap(40000);
            wos.seh_seed_petite(base_);
        }
    } catch (...) {
    }

    // TELock's stub self-check (the reference's F68, telock_unpacker.cpp:169-235): a CRC32
    // over the packed .text raw span compared against constants stored in the stub section.
    // A whole generation of TELock (the NirSoft/adwcleaner class) carries constants that do
    // not match its own bytes, so the failing 6-byte `jne` at stub_start+0x104e takes the
    // abort branch (+0x127b) and the decompressor at +0x1054 never runs - measured here on
    // telock_7z.exe: crc(0x401000,0x8a00)=0x23884536 at 0x419047 mismatches, the stub shows
    // its MessageBoxA reporter (last pc 0x4192e3) and exits, so imports stays 0 on all 116
    // rows (0.17je). Redirect the PC past that jne the first time it executes. Revisions
    // whose check passes never take the branch, so this cannot change them.
    // DEFAULT ON for the family (opt-out TAOTE_NO_TLOCK_CRCBYPASS): with the stub-section-table read below this
    // moves TELock's OEP exact from 1 to 93 of 116 rows with no losses (imports stay 0 - the decode is still not
    // the payload, 0.17jn), and the gate is family-scoped so no other family's engine behaviour changes.
    if (opts_.family == "TELock" && !is_64_ && std::getenv("TAOTE_NO_TLOCK_CRCBYPASS") == nullptr) {
        // The stub records the original EP in its own section table (image base at stub+0x1cc0, ~EP at
        // stub+0x1ce0) and writes both at RUN TIME, so they have to be read from the first-write shadow -
        // the reference's TELockUnpacker::family_terminal_fill does exactly this. Collect the shadow for
        // that, but keep ShadowPolicy::none: the full OVERLAY is measured wrong for TELock on the
        // reference's own A/B ("overlay-OFF better on 5, worse on 3; telock_7z decisive at 0 vs 35191"),
        // and taote reproduced that (0.17jj: restoring it changed nothing but code_sim).
        shadow_wanted_ = true;
        std::uint64_t stub_start = 0;
        for (const auto& ps : sections_) {
            if (packed_ep_va_ >= ps.start && packed_ep_va_ < ps.end) {
                stub_start = ps.start;
                break;
            }
        }
        if (stub_start != 0) {
            const std::uint64_t site = stub_start + 0x104e;
            auto crc_hook = std::make_shared<HookRet>(
                ql.hook_code([this, site](std::uint64_t addr, std::uint32_t /*size*/) -> int {
                    try {
                        ql_->arch().regs().set_arch_pc(addr + 6);
                        if (std::getenv("TAOTE_UNPACK_DEBUG") != nullptr) {
                            std::fprintf(stderr,
                                         "[unpack] telock: self-check jne at 0x%llx skipped -> 0x%llx\n",
                                         static_cast<unsigned long long>(addr),
                                         static_cast<unsigned long long>(addr + 6));
                        }
                    } catch (...) {
                    }
                    return 0;
                }, site, site));
            if (crc_hook->obj() != nullptr) {
                hooks_.push_back(std::move(crc_hook));
            }
            // The stub then installs its own SEH frame and executes `lea eax,eax` (8d c0,
            // ModRM mod==3) at stub_start+0x16f1 as the #UD that hands control to it. Unicorn
            // raises UC_ERR_INSN_INVALID for that encoding when it starts a block on it (it is
            // the same 8d byte that fires at 0x4186a8) but NOT here, mid-block: the run returns
            // cleanly at 0x4196f1 with no emu_stop, no error, no budget hit and TF clear (7.37M
            // instructions in; measured with a marker on Qiling::emu_stop and on the rundbg path),
            // so the frame the stub just installed never runs. Deliver the #UD from the gate.
            const std::uint64_t ud_site = stub_start + 0x16f1;
            auto ud_hook = std::make_shared<HookRet>(
                ql.hook_code([this, ud_site](std::uint64_t addr, std::uint32_t /*size*/) -> int {
                    try {
                        auto& os = ql_->os<os::windows::QlOsWindows>();
                        ql_->arch().regs().set_arch_pc(addr);
                        const bool handled = os.seh_dispatch_cpu(0xC000001Du);
                        if (std::getenv("TAOTE_UNPACK_DEBUG") != nullptr) {
                            std::fprintf(stderr, "[unpack] telock: #UD at 0x%llx delivered=%d\n",
                                         static_cast<unsigned long long>(addr), handled ? 1 : 0);
                        }
                        if (!handled) {
                            ql_->emu_stop();  // same contract as the invalid-instruction hook
                        }
                    } catch (...) {
                    }
                    return 0;
                }, ud_site, ud_site));
            if (ud_hook->obj() != nullptr) {
                hooks_.push_back(std::move(ud_hook));
            }
        }
    }

    // The invalid-instruction dispatch (the reference's install_invalid_insn_,
    // unpacker.cpp:4773-4811): TELock's self-modifying ladder executes 0xf1
    // (ICEBP) and the undefined `lea reg,reg` (ModRM mod==3) form as exception
    // triggers, and unicorn reports both as UC_ERR_INSN_INVALID before any other
    // hook sees them. Deliver the matching CPU exception into the guest's fs:[0]
    // chain: 0xf1 is a trap (Eip = next instruction first), everything else is
    // STATUS_ILLEGAL_INSTRUCTION at the same Eip. An unhandled #UD stops the run
    // instead of re-faulting forever.
    if (!is_64_) {
        auto invalid_hook = std::make_shared<HookRet>(
            ql.hook_insn_invalid([this]() -> int {
                auto& regs = ql_->arch().regs();
                const auto pc = regs.arch_pc();
                std::uint8_t b = 0;
                try {
                    const auto bytes = ql_->mem().read(pc, 1);
                    if (!bytes.empty()) {
                        b = bytes[0];
                    }
                } catch (...) {
                    b = 0;
                }
                auto& os = ql_->os<os::windows::QlOsWindows>();
                if (opts_.debug) {
                    std::uint64_t fs0_early = 0;
                    try {
                        const auto f4 = ql_->mem().read(regs.read("fsbase"), 4);
                        if (f4.size() == 4) {
                            fs0_early = static_cast<std::uint64_t>(f4[0]) | (static_cast<std::uint64_t>(f4[1]) << 8) |
                                        (static_cast<std::uint64_t>(f4[2]) << 16) | (static_cast<std::uint64_t>(f4[3]) << 24);
                        }
                    } catch (...) {
                    }
                    std::fprintf(stderr, "[unpack] insn_invalid pc=%s b=0x%02x fs0=0x%llx esp=0x%llx\n", hex(pc).c_str(),
                                 static_cast<unsigned>(b), static_cast<unsigned long long>(fs0_early),
                                 static_cast<unsigned long long>(regs.arch_sp()));
                }
                if (b == 0xf1) {
                    // #DB (ICEBP) is a trap: Eip advances to the next
                    // instruction before the handler runs, exactly like real
                    // x86 (the reference's dispatch_seh(0x80000004, eip+1))
                    regs.set_arch_pc(pc + 1);
                    (void)os.seh_dispatch_cpu(0x80000004u);
                    return QL_HOOK_BLOCK;
                }
                const bool handled = os.seh_dispatch_cpu(0xC000001Du);
                if (opts_.debug) {
                    std::uint64_t fs0 = 0;
                    try {
                        const auto b4 = ql_->mem().read(regs.read("fsbase"), 4);
                        if (b4.size() == 4) {
                            fs0 = static_cast<std::uint64_t>(b4[0]) | (static_cast<std::uint64_t>(b4[1]) << 8) |
                                  (static_cast<std::uint64_t>(b4[2]) << 16) | (static_cast<std::uint64_t>(b4[3]) << 24);
                        }
                    } catch (...) {
                    }
                    std::fprintf(stderr,
                                 "[unpack] insn_invalid dispatch pc=%s handled=%d fs0=0x%llx esp=0x%llx retarget=0x%llx\n",
                                 hex(pc).c_str(), handled ? 1 : 0,
                                 static_cast<unsigned long long>(fs0),
                                 static_cast<unsigned long long>(regs.arch_sp()),
                                 static_cast<unsigned long long>(os.seh_retarget()));
                }
                if (!handled) {
                    // nothing handled the #UD: surface the original stop
                    ql_->emu_stop();
                }
                return QL_HOOK_BLOCK;
            }, 1, 0));
        if (invalid_hook->obj() != nullptr) {
            hooks_.push_back(std::move(invalid_hook));
        }

        // TAOTE_LOWPC=1: a tripwire for a stub that transfers control to a garbage pointer (the
        // measured shape is a fetch at 0x28 on winupack_PEview, i.e. a field that should have been
        // a pointer). The error line reports only the new pc, so keep a short ring of the last
        // instructions and print it when execution lands below 0x10000 - the pre-jump context.
        if (std::getenv("TAOTE_LOWPC") != nullptr) {
            auto ring = std::make_shared<std::vector<std::uint64_t>>();
            ring->reserve(16);
            pc_ring_ = ring;
            auto lh = std::make_shared<HookRet>(ql.hook_code([ring](std::uint64_t a, std::uint32_t) -> int {
                if (ring->size() == 16) {
                    ring->erase(ring->begin());
                }
                ring->push_back(a);
                return 0;
            }, 1, 0));
            if (lh->obj() != nullptr) {
                hooks_.push_back(std::move(lh));
            }
        }
        // Diagnostics that must fire on a MID-BLOCK pc. TELock's stub is an overlapping-instruction
        // stream, so its interesting addresses are never basic-block entries, and a per-BLOCK hook
        // (on_section_exec) silently misses them - that mistake produced two false negatives this
        // session before it was understood.
        //   TAOTE_TLOCK_KEY=<hex>  force edx at pc 0x41882b, the stub's decrypt-key field
        //                          (measured: forcing the reference's value decodes .text to 93%)
        //   TAOTE_PC_DUMP=<pc>     at the first execution of <pc>, dump [pc-0x60,pc+0x40), 0x40 bytes
        //                          at esp and 0x20 bytes at eax (the call the fold makes)
        if (std::getenv("TAOTE_TLOCK_KEY") != nullptr || std::getenv("TAOTE_PC_DUMP") != nullptr) {
            const char* kk = std::getenv("TAOTE_TLOCK_KEY");
            const std::uint64_t want = kk != nullptr ? std::strtoull(kk, nullptr, 0) : 0ull;
            // TAOTE_PC_DUMP=<pc>[:<n>] - <n> (1-based, default 1) selects WHICH hit dumps, so a
            // loop's per-iteration state can be captured (TELock's key fold runs 6546 times and
            // the interesting iteration is the first divergent one, not the first).
            const char* pd = std::getenv("TAOTE_PC_DUMP");
            std::uint64_t dpc = 0, dhit = 1;
            if (pd != nullptr) {
                const std::string spec = pd;
                const auto c = spec.find(':');
                dpc = std::strtoull(spec.substr(0, c).c_str(), nullptr, 0);
                if (c != std::string::npos) {
                    dhit = std::strtoull(spec.substr(c + 1).c_str(), nullptr, 0);
                    if (dhit == 0) dhit = 1;
                }
            }
            const auto hook = [this, want, dpc, dhit](std::uint64_t a, std::uint32_t) -> int {
                if (want != 0 && a == 0x41882b) {
                    ql_->arch().regs().write("edx", want);
                }
                if (dpc != 0 && a == dpc) {
                    static std::uint64_t hits = 0;
                    if (++hits == dhit) {
                        const auto hexdump = [this](std::uint64_t at, std::uint64_t n) {
                            std::string hx;
                            try {
                                const auto bytes = ql_->mem().read(at, static_cast<std::size_t>(n));
                                for (const auto b : bytes) {
                                    char t[4];
                                    std::snprintf(t, sizeof(t), "%02x", b);
                                    hx += t;
                                }
                            } catch (...) {
                                hx = "?";
                            }
                            return hx;
                        };
                        const auto& r = ql_->arch().regs();
                        // ecx/edi/ebp included: a decode loop's BOUND is almost always ecx (or a
                        // compare against edi), and a dump without them cannot answer "why did the
                        // loop stop" - the question TELock's truncated transform rows ask.
                        std::fprintf(stderr,
                                     "[pcdump] pc=0x%llx eax=0x%llx edx=0x%llx ebx=0x%llx ecx=0x%llx "
                                     "esi=0x%llx edi=0x%llx ebp=0x%llx\n",
                                     static_cast<unsigned long long>(a), static_cast<unsigned long long>(r.read("eax")),
                                     static_cast<unsigned long long>(r.read("edx")),
                                     static_cast<unsigned long long>(r.read("ebx")),
                                     static_cast<unsigned long long>(r.read("ecx")),
                                     static_cast<unsigned long long>(r.read("esi")),
                                     static_cast<unsigned long long>(r.read("edi")),
                                     static_cast<unsigned long long>(r.read("ebp")));
                        std::fprintf(stderr, "[pcdump] code( -0x40 ) %s\n", hexdump(a - 0x40, 0xC0).c_str());
                        std::fprintf(stderr, "[pcdump] stack %s\n", hexdump(r.arch_sp(), 0x40).c_str());
                        std::fprintf(stderr, "[pcdump] at_eax %s\n",
                                     hexdump(r.read("eax"), 0x20).c_str());
                        // the fold's INPUT window: its source register walks the stub's own bytes
                        std::fprintf(stderr, "[pcdump] at_esi %s\n", hexdump(r.read("esi"), 0x40).c_str());
                    }
                }
                return 0;
            };
            auto dh = std::make_shared<HookRet>(ql.hook_code(hook, base_, base_ + image_size_));
            if (dh->obj() != nullptr) {
                hooks_.push_back(std::move(dh));
            }
        }
    }

    // ONE write-claim hook and ONE section-hop hook for the whole image, not one pair
    // per watched section. Both bodies already filter by `watched_` themselves (the
    // per-section hook ranges were redundant work), and each redundant hook costs a
    // `bound_check` - plus a unicorn hook slot - on EVERY basic block and every store
    // of the run: a nine-section image installed nine of each. The guards at the top of
    // the two bodies keep the behaviour identical to the per-section ranges they
    // replaced.
    if (!watched_.empty()) {
        auto write_hook = std::make_shared<HookRet>(ql.hook_mem_write(
            [this](int /*access*/, std::uint64_t addr, std::uint32_t size, std::int64_t value) -> int {
                return on_section_write(0, addr, size, static_cast<std::uint64_t>(value));
            },
            base_, base_ + image_size_));
        if (write_hook->obj() != nullptr) {
            hooks_.push_back(std::move(write_hook));
        }

        // the section-hop hook: an exec whose range was claimed is the
        // write-then-execute hand-off. It rides UC_HOOK_BLOCK (per basic
        // block, like the reference's bundled unicorn whose CODE hook fires
        // once per block), not per instruction: the hand-off is a jump into
        // the claimed section — a block entry — and firing per instruction
        // re-runs the written-range scan on every instruction of the payload's
        // hot code.
        auto code_hook = std::make_shared<HookRet>(ql.hook_block(
            [this](std::uint64_t addr, std::uint32_t /*size*/) -> int {
                return on_section_exec(addr);
            },
            base_, base_ + image_size_));
        if (code_hook->obj() != nullptr) {
            hooks_.push_back(std::move(code_hook));
        }
    }
}

// The reference's on_section_write (unpacker.cpp:5197-5381). `pc` is unused: the
// hook fires after the store, so the pc is read from the arch state.
int Unpacker::on_section_write(std::uint64_t /*pc*/, std::uint64_t addr, std::uint32_t size,
                               std::uint64_t value) {
    // TAOTE_WRITE_FASTPATH (diagnostic, default off): skip the whole write body so a
    // run isolates its cost from the dispatch plumbing around it.
    static const bool write_fastpath = std::getenv("TAOTE_WRITE_FASTPATH") != nullptr;
    if (write_fastpath) {
        return 0;
    }
    // the single image-wide write hook: an address outside every watched section must
    // behave as if the hook never fired (no shadow bookkeeping either)
    {
        bool watched = false;
        for (const auto& ps : watched_) {
            if (addr >= ps.start && addr < ps.end) {
                watched = true;
                break;
            }
        }
        if (!watched) {
            return 0;
        }
    }
    // shadow the first write per byte: a store of `size` bytes lands little-endian
    if (shadow_wanted_ && addr >= base_ && addr - base_ < image_size_) {
        const auto off = static_cast<std::size_t>(addr - base_);
        const auto n = std::min<std::size_t>({static_cast<std::size_t>(size ? size : 1),
                                              sizeof(std::uint64_t),
                                              static_cast<std::size_t>(image_size_ - off)});
        for (std::size_t i = 0; i < n; ++i) {
            if (!shadow_seen_[off + i]) {
                shadow_seen_[off + i] = true;
                shadow_image_[off + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xff);
            }
        }
    }
    for (const auto& ps : watched_) {
        if (!(addr >= ps.start && addr < ps.end)) {
            continue;
        }
        const auto key = std::make_pair(ps.start, ps.end);
        if (muted_.count(ps.start) != 0) {
            return 0;
        }
        // keep the write ordinal current for the OEP pick (the hook stays armed
        // for this even after the claim; the reference's YODA_PLATEAU stamp)
        ++write_seq_;
        last_write_seq_[ps.start] = write_seq_;
        if (sec_trans_on_) {
            for (std::size_t k = 0; k < sections_.size(); ++k) {
                if (sections_[k].start == ps.start) { sec_written_.insert((int)k); break; }
            }
        }
        if (claimed_.count(ps.start) != 0) {
            return 0;  // already claimed: only the ordinal is interesting now
        }
        const bool is_ep_section = packed_ep_va_ >= ps.start && packed_ep_va_ < ps.end;
        // self-write suppression (unpacker.cpp:5251-5284): the stub writing its
        // own section is not a decode; claim nothing and stop listening there
        const std::uint64_t pc = ql_->arch().regs().arch_pc();
        const bool pc_in_same_section = pc >= ps.start && pc < ps.end;
        if (pc_in_same_section && !is_ep_section) {
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] mute self-write %s (pc=%s addr=%s ep=%s)\n", ps.name.c_str(),
                             hex(pc).c_str(), hex(addr).c_str(), hex(packed_ep_va_).c_str());
            }
            muted_.insert(ps.start);
            return 0;
        }
        // hollow-predecessor cap (unpacker.cpp:5324-5350): a raw==0 section
        // immediately before the stub's EP section is the decode target, but the
        // stub's own code sits at the EP — claim only below it
        std::uint64_t claim_start = ps.start;
        std::uint64_t claim_end = ps.end;
        if (is_ep_section) {
            bool hollow_pred = false;
            for (const auto& q : sections_) {
                if (q.end <= ps.start && ps.start - q.end < 0x1000 && q.raw == 0 && q.vsize > 0) {
                    hollow_pred = true;
                    break;
                }
            }
            if (hollow_pred && packed_ep_va_ > 0x100 && packed_ep_va_ - 0x100 > ps.start) {
                claim_end = packed_ep_va_ - 0x100;
            }
        }
        // a claim covers the WHOLE PAGE WINDOW it starts in (round 183): a
        // section's declared vsize understates what the stub decrypts into it -
        // amber_pipelist's .bss claim nominally ends at 0x4053e8 while the true
        // payload entry is 0x40550b, which is inside the last page the claim
        // touched. Rounding to the page boundary is the same lesson the ASPack
        // work taught about clamping a decode window to its section.
        if (claim_end == ps.end && claim_end % 0x1000 != 0) {
            const std::uint64_t aligned = (claim_end + 0xfff) & ~static_cast<std::uint64_t>(0xfff);
            claim_end = std::min<std::uint64_t>(aligned, base_ + image_size_);
        }
        const auto claim = std::make_pair(claim_start, claim_end);
        ever_written_.insert(claim);
        written_ranges_.insert(claim);
        wr_cache_lo_ = claim.first;
        wr_cache_hi_ = claim.second;
        // one claim per section per run (the reference disables the write hook on
        // first fire): the stub's own traffic in a claimed section cannot
        // re-claim it, but the write ordinals keep flowing for the OEP pick
        claimed_.insert(ps.start);
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] claim %s [%s,%s) write=%s pc=%s\n", ps.name.c_str(),
                         hex(claim_start).c_str(), hex(claim_end).c_str(), hex(addr).c_str(),
                         hex(pc).c_str());
        }
        return 0;
    }
    return 0;
}


// The reference's on_dyn_code (:6096): put a code hook on every guest-allocated
// region that appears after install and remember the first address executed in
// it. Amber/Alienyze/Neolite map or copy their payload into a heap buffer and run
// it there, so no image section is ever written and the section-hop hook cannot
// see the hand-off.
void Unpacker::poll_dyn_maps() {
    if (ql_ == nullptr) {
        return;
    }
    try {
        for (const auto& mi : ql_->mem().get_mapinfo()) {
            const auto lo = std::get<0>(mi);
            const auto hi = std::get<1>(mi);
            if (hi <= lo || lo == base_ || lo >= 0x10000000 || hi - lo < 0x1000 ||
                hi - lo > 0x4000000) {
                continue;  // image, dll tree, or an engine scratch segment
            }
            if (initial_maps_.count(lo) != 0) {
                continue;  // pre-existing region, not a guest allocation
            }
            bool known = false;
            for (const auto& m : dyn_maps_) {
                if (m.first == lo) {
                    known = true;
                    break;
                }
            }
            if (known) {
                continue;
            }
            dyn_maps_.emplace_back(lo, hi);
            auto hook = std::make_shared<HookRet>(
                ql_->hook_block([this, lo](std::uint64_t addr, std::uint32_t) -> int {
                    if (std::find(dyn_exec_.begin(), dyn_exec_.end(), addr) == dyn_exec_.end()) {
                        if (dyn_exec_.size() < 64) {
                            dyn_exec_.push_back(addr);
                        }
                        if (opts_.debug) {
                            std::fprintf(stderr, "[unpack] dyn exec 0x%llx (region 0x%llx)\n",
                                         static_cast<unsigned long long>(addr),
                                         static_cast<unsigned long long>(lo));
                        }
                    }
                    return 0;
                }, lo, hi));
            if (hook->obj() != nullptr) {
                dyn_hooks_.push_back(std::move(hook));
            }
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] dyn map 0x%llx-0x%llx %s\n",
                             static_cast<unsigned long long>(lo), static_cast<unsigned long long>(hi),
                             std::get<2>(mi).c_str());
            }
        }
    } catch (...) {
    }
}

// The reference's on_section_exec (unpacker.cpp:5520-5810): a written section
// that starts executing is the payload hand-off.
int Unpacker::on_section_exec(std::uint64_t addr) {
    // TAOTE_HOOK_FASTPATH=<level> (diagnostic, default off): return early so a run
    // isolates the cost of each stage of THIS body from unicorn's own per-block trap
    // plus the dispatch chain. level 1 = at entry, 2 = after the written-range test,
    // 3 = after the stub-region / in-place tests.
    static const int hook_fastpath = [] {
        const char* v = std::getenv("TAOTE_HOOK_FASTPATH");
        return v != nullptr ? std::atoi(v) : 0;
    }();
    if (hook_fastpath == 1) {
        return 0;
    }
    // The single image-wide hook must behave exactly like the per-watched-section
    // hooks it replaced: an address outside every watched section never fired.
    {
        bool watched = false;
        for (const auto& ps : watched_) {
            if (addr >= ps.start && addr < ps.end) {
                watched = true;
                break;
            }
        }
        if (!watched) {
            return 0;
        }
    }
    // EXPERIMENT (TAOTE_IF_USER=1): a Windows ring-3 thread runs with IF set and cannot clear it
    // (CLI faults with #GP; POPF ignores IF outside ring 0). Unicorn executes CLI silently and
    // taote's guest therefore runs with IF=0, while the reference runs at eflags=0x202. TELock
    // reads its own flags back before choosing the decryptor's key seed and takes a different
    // branch when the interrupt flag is clear (measured: the seed block 0x418fb1.. at 0x418faf).
    if (std::getenv("TAOTE_IF_USER") != nullptr) {
        auto& fl_regs = ql_->arch().regs();
        const auto fl = fl_regs.read("eflags");
        if ((fl & 0x200ull) == 0) {
            fl_regs.write("eflags", fl | 0x200ull);
        }
    }
    const std::uint64_t prev_exec = prev_exec_addr_;
    prev_exec_addr_ = addr;
    // TAOTE_SEC_TRANS: record section-to-section transitions (the reference's
    // sec_trans_hist_, which its PEtite EP-exit walk reads backward). Off unless
    // the env var is set: it is a diagnostic, not a shipped mechanism (yet).
    if (sec_trans_on_) {
        // cached lookup: this hook fires hundreds of thousands of times, so a linear
        // section scan per fire is only affordable when the section actually changes
        const auto idx_of = [&](std::uint64_t a, int hint) -> int {
            if (hint >= 0 && hint < (int)sections_.size() && a >= sections_[hint].start &&
                a < sections_[hint].end) {
                return hint;
            }
            for (std::size_t k = 0; k < sections_.size(); ++k) {
                if (a >= sections_[k].start && a < sections_[k].end) return (int)k;
            }
            return -1;
        };
        const int to = idx_of(addr, prev_sec_idx_);
        const int from = idx_of(prev_exec, prev_sec_idx_);
        if (to >= 0) {
            prev_sec_idx_ = to;
        }
        if (to >= 0 && from != to) {
            sec_trans_.push_back({from, to, addr, (std::uint64_t)exec_fires_});
        }
    }
    if (opts_.debug) {
        static int fires = 0;
        ++fires;
        if (fires % 200000 == 0) {
            std::fprintf(stderr, "[unpack] exec fires=%d at %s written=%zu\n", fires, hex(addr).c_str(),
                         written_ranges_.size());
        }
        static int in_payload = 0;
        if (addr >= 0x401000 && addr < 0x422000 && in_payload < 12) {
            std::fprintf(stderr, "[unpack] exec PAYLOAD %s (written=%zu)\n", hex(addr).c_str(),
                         written_ranges_.size());
            ++in_payload;
        }
    }
    // WinUpack parked-stack harvest: the engine keeps the payload OEP in its own
    // frame (the reference snapshots [esp+8] at the import loop's `call ecx`,
    // winupack_unpacker.cpp:651-690, because esp has drifted by finalize time).
    // Harvest once, from the first frame seen inside the stub section, and keep
    // every in-image dword: the pick validates them by prologue shape.
    // The reference's on_dyn_code (:6096): a guest-allocated region that starts
    // executing is an OEP candidate. The map list is polled from the winapi
    // observer (VirtualAlloc is when such a region appears) and occasionally from
    // here, so a region created without an API call is still seen.
    if (ql_ != nullptr && (++exec_fires_ % 65536) == 0) {
        poll_dyn_maps();
    }
    const bool in_written = [&] {
        if (wr_cache_hi_ != 0 && addr >= wr_cache_lo_ && addr <= wr_cache_hi_) {
            return true;
        }
        for (const auto& r : written_ranges_) {
            if (addr >= r.first && addr <= r.second) {
                wr_cache_lo_ = r.first;
                wr_cache_hi_ = r.second;
                return true;
            }
        }
        return false;
    }();

    if (hook_fastpath == 2) {
        return 0;
    }
    // TAOTE_HOP_TRACE=<hex addr>: one-line report the first time a given address
    // enters the hop detector, BEFORE any early return - the instrument the
    // claim-ledger questions need (which early return fires, which range matched,
    // what prev_exec was) instead of another hypothesis about the accept rules.
    {
        static const std::uint64_t hop_trace = []() -> std::uint64_t {
            const char* t = std::getenv("TAOTE_HOP_TRACE");
            return t != nullptr ? static_cast<std::uint64_t>(std::strtoull(t, nullptr, 0)) : 0;
        }();
        if (hop_trace != 0 && addr == hop_trace) {
            static bool once = false;
            if (!once) {
                once = true;
                int spans = 0;
                std::uint64_t mf = 0, mt = 0;
                for (const auto& r : written_ranges_) {
                    if (addr >= r.first && addr <= r.second) {
                        ++spans;
                        mf = r.first;
                        mt = r.second;
                    }
                }
                std::fprintf(stderr,
                             "[hoptrace] addr=0x%llx prev=0x%llx stages=%d dumped=%d ranges=%zu matched=%d "
                             "range=[0x%llx,0x%llx) in_written=%d inplace=%d ep_dist=0x%llx meta_oep=0x%llx\n",
                             static_cast<unsigned long long>(addr),
                             static_cast<unsigned long long>(prev_exec),
                             static_cast<int>(stages_), dumped_addrs_.count(addr) ? 1 : 0,
                             written_ranges_.size(), spans,
                             static_cast<unsigned long long>(mf), static_cast<unsigned long long>(mt),
                             in_written ? 1 : 0, inside_inplace(addr) ? 1 : 0,
                             static_cast<unsigned long long>(
                                 addr > packed_ep_va_ ? addr - packed_ep_va_ : packed_ep_va_ - addr),
                             static_cast<unsigned long long>(meta_oep_));
            }
        }
    }
    // PECompact placeholder rows only: remember the FIRST executed address far past
    // the planted mini-stub. The stub decompresses, jumps into the payload tens of KB
    // later, and by then the claim ledger has CONSUMED the section, so every branch
    // below sees in_written == false and returns before a hop could be recorded
    // (measured: pecompact_Everything's ledger holds one entry, 0x401016, while the
    // truth 0x545f0d executes). This must therefore run BEFORE those early returns.
    // pc_far_hop_limit_ is 0 for every other family and row.
    // The capture demands payload EVIDENCE as well as distance: the address must
    // lie inside a range the run WROTE (ever_written_, the never-erased claim set).
    // Distance alone catches the stub's own tail - pecompact_Everything executes
    // 0x5a095c, past the bound but outside its claim - which is why the bound is
    // paired with this test. Both are cheap: the loop only runs for addresses past
    // the bound, and only until the first capture.
    if (pc_far_hop_ == 0 && pc_far_hop_limit_ != 0 && addr >= pc_far_hop_limit_ &&
        addr - base_ < image_size_) {
        for (const auto& r : ever_written_) {
            if (addr >= r.first && addr <= r.second) {
                pc_far_hop_ = addr;
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] pecompact far hand-off captured at 0x%llx\n",
                                 static_cast<unsigned long long>(addr));
                }
                break;
            }
        }
    }
    if (hook_fastpath == 3) {
        return 0;
    }
    // the stub's own code near the packed EP is not the payload (unless the
    // stub decoded over itself there)
    const std::uint64_t ep_delta = addr > packed_ep_va_ ? addr - packed_ep_va_ : packed_ep_va_ - addr;
    if (ep_delta < 0x1000 && !in_written) {
        return 0;
    }
    // in-place exec sections are noise unless written
    if (inside_inplace(addr) && !in_written) {
        return 0;
    }
    if (!in_written) {
        // TAOTE_HOP_CLEAR=1: a transfer out of the packer's own section into another
        // image section is a hand-off even when the destination was NEVER written -
        // the in-clear class, where the packed file already holds the payload's bytes
        // so the stub only redirects execution (measured on jdpack_PEview: NOT ONE
        // write lands in .text, ranges=2 and matched=0 at the true entry, so the
        // written-range rule can never accept it although prev_exec=0x415402 is the
        // stub and the entry itself executes).
        // TAOTE_HOP_CLEAR: unset -> JDPack only (measured), "1" -> every family
        // (corpus r113: +jdpack_PEview but -upx_FastHash_kr, because UPX decompresses
        // INTO the destination section, so its transfers do have writes and this
        // fallback mis-fires), "0" -> off.
        static const int clear_mode = [] {
            const char* e = std::getenv("TAOTE_HOP_CLEAR");
            if (e == nullptr) return 1;                      // family-scoped default
            return std::strcmp(e, "0") == 0 ? 0 : 2;         // 2 = every family
        }();
        const bool clear_hop = clear_mode == 2 || (clear_mode == 1 && opts_.family == "JDPack");
        if (clear_hop && addr >= base_ && addr - base_ < image_size_) {
            const PackSection* stub_sec = nullptr;
            const PackSection* dst_sec = nullptr;
            for (const auto& ps : sections_) {
                if (packed_ep_va_ >= ps.start && packed_ep_va_ < ps.end) {
                    stub_sec = &ps;
                }
                if (addr >= ps.start && addr < ps.end) {
                    dst_sec = &ps;
                }
            }
            const bool from_stub = stub_sec != nullptr && prev_exec >= stub_sec->start &&
                                   prev_exec < stub_sec->end;
            // A clear transfer only FILLS A GAP: if any claim already exists it is not
            // emitted, because the in-clear class can produce a long tail of spurious
            // transfers out of the stub (measured on upx_FastHash_kr: the true
            // 0x41dffa is accepted first, then clear hops at 0x41c7ad / 0x41d6cd /
            // 0x43cc15 overwrite it), while the rows this is for have NO written-range
            // claim at all.
            // ...and it may override a claim that sits INSIDE the packed-EP section,
            // which is junk by construction (dump_module already refuses the mirror
            // case - a new candidate in the stub section never replaces an outside
            // claim). jdpack_PEview is exactly this: meta_oep_ is already 0x41502e in
            // .jdpack when the real 0x401000 executes, while on upx_FastHash_kr the
            // existing claim 0x41dffa is NOT in the stub section and must survive.
            const bool cur_is_stub_junk =
                meta_oep_ != 0 && stub_sec != nullptr && meta_oep_ >= stub_sec->start &&
                meta_oep_ < stub_sec->end;
            if (from_stub && dst_sec != nullptr && dst_sec != stub_sec &&
                (meta_oep_ == 0 || cur_is_stub_junk) &&
                dumped_addrs_.insert(addr).second && stages_ < opts_.max_stages) {
                // WEAK claim: emit the candidate but leave have_hop_/last_hop_imp_ alone,
                // so a later WRITTEN-range hop is still judged as a first hop. Not doing
                // this cost upx_FastHash_kr on corpus r113: the clear transfer set
                // last_hop_imp_, and the payload's real hop that followed was then
                // rejected as "import-quiet" (imports had not grown), pinning the claim
                // to the wrong 0x41bf46. On the in-clear rows there is no later written
                // hop at all, so the weak claim simply stands.
                dump_module(*ql_, addr, "section_clear");
            }
        }
        return 0;
    }
    // the hand-off whole-image snapshot (see Unpacker::handoff_view_)
    if (handoff_view_.empty() && std::getenv("TAOTE_HANDOFF_SNAP") != nullptr && ql_ != nullptr &&
        packed_ep_va_ != 0 && addr >= base_ && addr - base_ < image_size_) {
        std::uint64_t stub_lo = 0, stub_hi = 0;
        for (const auto& ps : sections_) {
            if (packed_ep_va_ >= ps.start && packed_ep_va_ < ps.end) {
                stub_lo = ps.start;
                stub_hi = ps.end;
                break;
            }
        }
        const bool in_stub = stub_lo != 0 && addr >= stub_lo && addr < stub_hi;
        if (stub_lo != 0 && !in_stub) {
            try {
                handoff_view_ = ql_->mem().read(base_, image_size_);
            } catch (...) {
                handoff_view_.clear();
            }
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] handoff snapshot at 0x%llx (%zu bytes)\n",
                             static_cast<unsigned long long>(addr), handoff_view_.size());
            }
        }
    }
    // the executed-page view (see Unpacker::exec_view_)
    if (addr >= base_ && addr - base_ < image_size_) {
        const auto page = static_cast<std::size_t>((addr - base_) / 0x1000);
        if (page < exec_page_seen_.size() && !exec_page_seen_[page] && ql_ != nullptr) {
            exec_page_seen_[page] = true;
            const auto off = page * 0x1000;
            const auto n = std::min<std::size_t>(0x1000, image_size_ - off);
            try {
                const auto bytes = ql_->mem().read(base_ + off, n);
                std::copy(bytes.begin(), bytes.end(),
                          exec_view_.begin() + static_cast<std::ptrdiff_t>(off));
            } catch (...) {
            }
        }
    }
    // Hop detection over the LIVE CLAIMS (the reference's written_ranges_, not
    // its never-erased ever_written_): a section that has already handed off is
    // consumed, exactly like the reference. This is what keeps the candidate
    // ledger at a handful of entries - the reference ledgers 2 candidates on
    // aspack_Cacheset where taote ledgers 2695, and its picker then keeps the
    // true OEP trivially. TAOTE_CLAIM_LEDGER=0 restores the old ever_written_
    // behaviour for A/B measurement.
    static const bool claim_ledger = std::getenv("TAOTE_CLAIM_LEDGER") == nullptr ||
                                     std::string(std::getenv("TAOTE_CLAIM_LEDGER")) != "0";
    if (claim_ledger) {
        // The two hop-accept guards (the reference's UPX/NSPack/Molebox/JDPack
        // set). Both only ever DROP a candidate, so they are measured as a gate
        // on the families that use them rather than on every family.
        // PEtite joins the payload-internal traffic guard. The 15-row
        // decoded-but-OEP-wrong pool splits cleanly on one probe - does the true EP
        // ever execute? - and 7 rows DO execute their true entry while claiming a
        // LATER address (PEtite 5, Neolite 1, JDPack 1), which is exactly this
        // guard's shape: the payload's own runtime writes reclaim a range around the
        // executing flow and the replacement hop wins. Measured on the 73-row
        // PEtite family: OEP exact 65 -> 72, all-three 61 -> 65 (+4: 7za, HDDScan,
        // Hasher, md5summer), imports unchanged 66, ZERO rows lost, and the 15-row
        // pool's petite_7za/HDDScan/Hasher/md5summer all land on their true EP.
        // Neolite was measured in the same arm and REJECTED: 92 -> 73 all-three
        // (-19), because its demand-paged .text legitimately re-hops inside the
        // range. TAOTE_HOPGUARD_EXTRA=<Family[,Family]> keeps the A/B available.
        static const std::string hop_extra = [] {
            const char* e = std::getenv("TAOTE_HOPGUARD_EXTRA");
            return std::string(e != nullptr ? e : "");
        }();
        const bool hop_guarded = opts_.family == "UPX" || opts_.family == "NSPack" ||
                                 opts_.family == "Molebox" || opts_.family == "JDPack" ||
                                 opts_.family == "PEtite" ||
                                 (!hop_extra.empty() &&
                                  hop_extra.find(opts_.family) != std::string::npos);
        for (const auto& r : written_ranges_) {
            if (addr >= r.first && addr <= r.second) {
                if (hop_guarded && have_hop_) {
                    // payload-internal traffic: the previous executed block was
                    // ALREADY inside this range, so this is the payload's own
                    // runtime writes re-claiming around the executing flow, not a
                    // transfer into it
                    if (prev_exec >= r.first && prev_exec <= r.second) {
                        if (opts_.debug) {
                            std::fprintf(stderr,
                                         "[unpack] hop skip self-traffic %s (prev %s in range)\n",
                                         hex(addr).c_str(), hex(prev_exec).c_str());
                        }
                        continue;
                    }
                    // import-quiet landing: a genuine OEP transfer carries the
                    // import jump; a post-OEP landing does not
                    if (last_hop_imp_ + 32 > imports_.size()) {
                        if (opts_.debug) {
                            std::fprintf(stderr,
                                         "[unpack] hop skip import-quiet %s (imp %zu vs still %zu)\n",
                                         hex(addr).c_str(), imports_.size(), last_hop_imp_);
                        }
                        continue;
                    }
                }
                if (dumped_addrs_.insert(addr).second && stages_ < opts_.max_stages) {
                    dump_module(*ql_, addr, "section_hop");
                    // consume the claim (the reference erases written_ranges_
                    // here) except for the lazy-decompressor families, whose
                    // payload enters the section mid-decode first and hands off
                    // again from inside it (MPRESS's trampoline back-hop)
                    if (opts_.family != "MPRESS") {
                        written_ranges_.erase(r);
                        wr_cache_lo_ = wr_cache_hi_ = 0;
                    }
                    // the guards below judge against the LAST ACCEPTED hop
                    last_hop_addr_ = addr;
                    last_hop_imp_ = imports_.size();
                    have_hop_ = true;
                }
                break;
            }
        }
        return 0;
    }
    for (const auto& r : ever_written_) {
        if (addr >= r.first && addr <= r.second) {
            // the reference's CF-hop observer: every first-exec of an address in a
            // decoded section is a candidate, and the pick decides (erasing the
            // range here lost the real transfer after an early mid-decode hop)
            if (dumped_addrs_.insert(addr).second && stages_ < opts_.max_stages) {
                dump_module(*ql_, addr, "section_hop");
            }
            break;
        }
    }
    return 0;
}

// The reference's dump_module accept gate (unpacker.cpp:6610-6834), cut down to
// the generic rules: never a zero page, never a printable data blob (unless the
// target section is exec/hollow), first hop wins, later hops must not shrink.
void Unpacker::dump_module(Qiling& ql, std::uint64_t addr, const std::string& reason) {
    // The reference ledgers candidates during the run and emits the dump once at
    // pick time from terminal memory (unpacker.cpp:6789-6830 + pick_and_emit_oep
    // :7991-8366). Emitting per candidate here burned the stage cap on junk hops
    // and made the artifact depend on which hop happened to be 16th.
    if (hop_ledger_.size() >= 65536) {
        return;
    }
    bool accept = true;
    std::vector<std::uint8_t> head;
    try {
        head = ql.mem().read(addr, 16);
    } catch (...) {
        head.clear();
    }
    bool all_zero = !head.empty();
    int printable = 0;
    for (auto c : head) {
        const auto u = static_cast<unsigned char>(c);
        if (u != 0) {
            all_zero = false;
        }
        if (u >= 0x20 && u <= 0x7E) {
            ++printable;
        }
    }
    const int sec = section_index_at(addr);
    const bool privileged = sec >= 0 && (sections_[static_cast<std::size_t>(sec)].is_exec ||
                                         sections_[static_cast<std::size_t>(sec)].raw == 0);
    if (head.empty()) {
        accept = privileged;  // unreadable: only an exec/hollow target qualifies
    } else if (all_zero) {
        accept = false;  // nothing to fetch there
    } else if (printable > 12 && !privileged) {
        accept = false;  // a data blob, not code
    }
    // TELock DEMAND-PAGES its payload: the stub jumps into .text while the page is still
    // encrypted (or zeroed and filled on the first fault), so an EXECUTED hop into a section
    // the run WROTE can read as all-zero here and still be the true entry. Measured: on the 6
    // TELock rows that still fail, the reference reports exactly this address while its own
    // dump is equally undecoded (telock_OpenedFilesView: ref dump 37227/61440 nonzero, 0xfc10
    // all zero, ref OEP = 0xfc10 = the executed address). Family-scoped and restricted: the
    // target must be an execution hit inside a WRITTEN range and outside the stub's own
    // section, and the printable-blob rejection above still stands.
    if (!accept && all_zero && opts_.family == "TELock") {
        const int dsec = section_index_at(addr);
        const int ep_sec = section_index_at(packed_ep_va_);
        bool written = false;
        for (const auto& r : written_ranges_) {
            if (addr >= r.first && addr <= r.second) {
                written = true;
                break;
            }
        }
        if (dsec >= 0 && dsec != ep_sec && written) {
            accept = true;
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] accept undecoded TELock hop %s (written section, executed)\n",
                             hex(addr).c_str());
            }
        }
    }
    if (accept && meta_oep_ != 0) {
        const int new_sec = section_index_at(addr);
        const int cur_sec = section_index_at(meta_oep_);
        const int ep_sec = section_index_at(packed_ep_va_);
        if (new_sec >= 0 && new_sec == ep_sec && cur_sec != ep_sec) {
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] reject hop %s (stub-section junk, keeping %s)\n",
                             hex(addr).c_str(), hex(meta_oep_).c_str());
            }
            return;
        }
    }
    if (!accept) {
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] reject hop %s (%s)\n", hex(addr).c_str(), reason.c_str());
        }
        return;
    }
    // The reference's WinUpack parked-stack snapshot (winupack_unpacker.cpp:651-690): the stub
    // parks the payload entry in its own frame for the hand-off. Measured at HOP TIME on six
    // OEP-wrong rows, the frame is already there and the entry sits at stack slot [6] every
    // time - winupack_Diskmon 0x40b4b8, ShareEnum 0x409013, Everything 0x545f0d,
    // FastHash_kr 0x41dffa, HashCalc 0x411e58, mtinst 0x1003866 (ALL exact truths) - while the
    // slots around it are the image base+0x1000 and a page-end scratch. So no per-instruction
    // hook is needed (that version cost a TB boundary per instruction: Bginfo 53 s -> 75-85 s
    // and it flipped at the 85 s budget): scan the window HERE, at the event that already
    // exists, and let the finalize pick validate the candidates against the decoded image.
    // TAOTE_HOPSNAP: at every accepted hop, print the in-image dwords of the stack window, so
    // whether a packer parks its payload entry in the frame can be measured per family (the
    // WinUpack win came from exactly this reading).
    if (std::getenv("TAOTE_HOPSNAP") != nullptr) {
        std::uint64_t sp0 = 0;
        try {
            sp0 = ql.arch().regs().read("esp");
        } catch (...) {
        }
        std::string win;
        for (int k = 0; k < 48; ++k) {
            std::uint64_t v = 0;
            try {
                const auto b = ql.mem().read(sp0 + 4 * static_cast<std::uint64_t>(k), 4);
                if (b.size() != 4) {
                    break;
                }
                v = static_cast<std::uint64_t>(b[0]) | (static_cast<std::uint64_t>(b[1]) << 8) |
                    (static_cast<std::uint64_t>(b[2]) << 16) | (static_cast<std::uint64_t>(b[3]) << 24);
            } catch (...) {
                break;
            }
            if (v >= base_ && v - base_ < image_size_) {
                win += " [" + std::to_string(k) + "]=" + hex(v);
            }
        }
        std::fprintf(stderr, "[hopsnap] hop=%s esp=%s inimage:%s\n", hex(addr).c_str(), hex(sp0).c_str(), win.c_str());
    }
    if (opts_.family == "WinUpack" || std::getenv("TAOTE_STACK_OEP_ALL") != nullptr) {
        std::uint64_t sp = 0;
        try {
            sp = ql.arch().regs().read("esp");
        } catch (...) {
        }
        // ONLY slot [6] = esp+0x18: measured as the WinUpack hand-off record on 6/6 rows.
        // A whole-window scan regressed 8 already-correct rows (the window also carries the
        // image base+0x1000 and a page-end scratch, which can validate as prologues).
        for (int k = 6; k <= 6; ++k) {
            std::uint64_t v = 0;
            try {
                const auto b = ql.mem().read(sp + 4 * static_cast<std::uint64_t>(k), 4);
                if (b.size() != 4) {
                    break;
                }
                v = static_cast<std::uint64_t>(b[0]) | (static_cast<std::uint64_t>(b[1]) << 8) |
                    (static_cast<std::uint64_t>(b[2]) << 16) | (static_cast<std::uint64_t>(b[3]) << 24);
            } catch (...) {
                break;
            }
            if (v >= base_ && v - base_ < image_size_) {
                stack_oep_cands_.push_back(v);
            }
        }
    }
    hop_ledger_.push_back(addr);
    hop_write_seq_.push_back(write_seq_);
    meta_oep_ = addr;
    last_oep_ = addr;
    reason_ = reason;
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] OEP candidate %s (%s)\n", hex(addr).c_str(), reason.c_str());
    }
}

// The reference harvests imports from the loader table + the GPA hook + family
// tables (unpacker.cpp:6145-6496). Phase 1 takes the packed file's own import
// descriptors (the loader loaded exactly those); the sentinel lane lands in
// Phase 1b.
void Unpacker::harvest_loader_imports(Qiling& /*ql*/) {
    // ACCUMULATES: the GPA lane recorded pairs during the run (measured: the FSG
    // stub resolves 315 names through GetProcAddress and this clear() threw them
    // away, leaving the rebuild with the packed file's own 2 imports)
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] harvest_loader_imports (have %zu)\n", imports_.size());
    }
    try {
        auto parsed = LIEF::PE::Parser::parse(opts_.sample_path);
        if (parsed == nullptr) {
            return;
        }
        for (const auto& imp : parsed->imports()) {
            const auto dll = lower_ascii(imp.name());
            for (const auto& e : imp.entries()) {
                std::string fn = e.name();
                if (fn.empty()) {
                    fn = "ordinal_" + std::to_string(e.ordinal());
                }
                note_import(sanitize_ascii(dll), sanitize_ascii(fn));
            }
        }
    } catch (...) {
    }
}

void Unpacker::detach_hooks() {
    // HookRet::~HookRet -> QlCoreHooks::hook_del -> uc_hook_del: only valid while
    // the engine lives. Clearing here is what makes the tool's scope order safe.
    hooks_.clear();
    dyn_hooks_.clear();
}

// The reference builds stub_map_ from the GPA sentinels + every emulated module's
// export address, then scans the dump (unpacker.cpp:8652-9560). Slot coherence is
// the noise filter: a same-dll run of adjacent slots, or a singleton anchored
// within two slots of a kept one.
// The FSG resolved-import list: [dll name\0][6-byte record]*  where a record is
//   01 <u32 nameptr>            an import by NAME (the +3-shifted string run)
//   02 <u16 ordinal> 00 00      an import BY ORDINAL
// and the next DLL name follows the last record. Measured on the five FSG rows that
// sit exactly at their named-import ceiling (all their missing pairs are ordinals):
// adrestore recovers activeds#9, oleaut32#8,#9, wldap32#13,#14,#73,#88,#118,#145,#155
// and ShareEnum recovers comctl32#17 and oleaut32#2,#6..#9,#12,#94,#150,#200..#202 -
// every one of them exactly. The rebuilder already turns an "ordinal_<N>" pair into a
// real ordinal thunk (iat/import_rebuilder.cpp:26), so noting the pair is enough.
std::size_t Unpacker::mine_ordinal_records(const std::vector<std::uint8_t>& image) {
    if (image.size() < 0x400) {
        return 0;
    }
    const auto at32 = [&image](std::size_t o) -> std::uint32_t {
        return static_cast<std::uint32_t>(image[o]) | (static_cast<std::uint32_t>(image[o + 1]) << 8) |
               static_cast<std::uint32_t>(image[o + 2]) << 16 | static_cast<std::uint32_t>(image[o + 3]) << 24;
    };
    const auto at16 = [&image](std::size_t o) -> std::uint32_t {
        return static_cast<std::uint32_t>(image[o]) | (static_cast<std::uint32_t>(image[o + 1]) << 8);
    };
    const auto name_byte = [](std::uint8_t c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
               c == '-' || c == '.';
    };
    std::size_t noted = 0;
    std::size_t groups = 0;
    for (std::size_t i = 4; i + 4 < image.size(); ++i) {
        if (image[i] != '.' || (image[i + 1] != 'd' && image[i + 1] != 'D') ||
            (image[i + 2] != 'l' && image[i + 2] != 'L') || (image[i + 3] != 'l' && image[i + 3] != 'L')) {
            continue;
        }
        // walk back to the start of the name and require a NUL right after ".dll"
        std::size_t b = i;
        while (b > 0 && name_byte(image[b - 1]) && i - b < 40) {
            --b;
        }
        const std::size_t end = i + 4;
        if (b == i || end >= image.size() || image[end] != 0) {
            continue;
        }
        std::string dll(reinterpret_cast<const char*>(image.data() + b), i - b + 4);
        bool has_dot = false;
        for (const auto ch : dll) {
            has_dot = has_dot || ch == '.';
        }
        if (!has_dot || dll.size() < 6) {
            continue;
        }
        // the record list, until it stops looking like one
        std::vector<std::uint32_t> ords;
        std::size_t p = end + 1;
        while (p + 6 <= image.size() && ords.size() < 512) {
            if (image[p] == 0x02) {
                ords.push_back(at16(p + 1));
                p += 6;
            } else if (image[p] == 0x01) {
                const auto ptr = at32(p + 1);
                if (ptr < 0x200 || ptr >= image.size()) {
                    break;
                }
                p += 6;
            } else {
                break;
            }
        }
        if (ords.empty()) {
            continue;
        }
        ++groups;
        for (const auto ord : ords) {
            note_import(sanitize_ascii(dll), "ordinal_" + std::to_string(ord));
            ++noted;
        }
        i = end;
    }
    if (opts_.debug && noted != 0) {
        std::fprintf(stderr, "[unpack] ordinal records: %zu groups, %zu ordinals\n", groups, noted);
    }
    return noted;
}

std::size_t Unpacker::mine_orphan_descriptors(const std::vector<std::uint8_t>& image) {
    if (image.size() < 0x400) {
        return 0;
    }
    const auto at32 = [&image](std::size_t o) -> std::uint32_t {
        if (o + 4 > image.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(image[o]) | (static_cast<std::uint32_t>(image[o + 1]) << 8) |
               (static_cast<std::uint32_t>(image[o + 2]) << 16) |
               (static_cast<std::uint32_t>(image[o + 3]) << 24);
    };
    const auto cstr = [&image](std::size_t o, std::size_t max) {
        std::string out;
        while (o < image.size() && image[o] != 0 && out.size() < max) {
            const auto c = image[o++];
            if (c < 0x20 || c > 0x7E) {
                return std::string{};  // not a printable string
            }
            out.push_back(static_cast<char>(c));
        }
        return out;
    };
    const auto dll_like = [](const std::string& s) {
        if (s.size() < 4 || s.size() > 40) {
            return false;
        }
        std::string low = s;
        for (auto& c : low) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return low.size() > 4 && (low.compare(low.size() - 4, 4, ".dll") == 0 ||
                                  low.compare(low.size() - 4, 4, ".drv") == 0 ||
                                  low.compare(low.size() - 4, 4, ".ocx") == 0 ||
                                  low.compare(low.size() - 4, 4, ".sys") == 0);
    };

    // FSG/BeRo/MEW/WinUpack shift the FIRST character of every stored import name
    // by -3, so a decoded FSG payload's string run reads `bexit`, `falloc`,
    // `wolower` for `_exit`, `malloc`, `tolower`. The INT-table path undoes that
    // under api_owner evidence (round 39); the string-group path did not, which is
    // why FSG's decoded rows recovered 128 names and still scored recall 0.03 -
    // every name was one character off and matched nothing. Same evidence rule:
    // apply the shift only when the export database knows the shifted spelling and
    // not the stored one.
    const auto shifted_form = [](const std::string& fn) -> std::string {
        if (fn.empty()) {
            return {};
        }
        const auto sh = static_cast<unsigned char>(fn[0] - 3);
        // '_' covers the CRT internals (_exit, _pctype); '?' covers C++ MANGLED
        // names, which FSG shifts like everything else ('B?1type_info@@UAE@XZ' is
        // '??1type_info@@UAE@XZ').
        if (std::isalnum(sh) == 0 && sh != '_' && sh != '?') {
            return {};
        }
        std::string alt = fn;
        alt[0] = static_cast<char>(sh);
        return alt;
    };
    const auto reshift = [&shifted_form](std::string fn) -> std::string {
        if (!fn.empty() && api_owner(fn) == nullptr) {
            const auto alt = shifted_form(fn);
            if (!alt.empty() && api_owner(alt) != nullptr) {
                return alt;
            }
        }
        return fn;
    };
    // The shift is a property of the STRING RUN, not of a name: one run belongs to
    // one packer, so if the evidence backs the shift for at least half of the names
    // that can be tested, every unknown name in that block is shifted - including
    // the CRT internals the export database does not carry (`_isctype`, `_pctype`,
    // `_mb_cur_max`, which the per-name test alone leaves spelled `bisctype`,
    // `bpctype`, `b_mb_cur_max`).
    // A stored name beginning "B?" cannot be a real import: MSVC C++ mangling always
    // begins with '?', so its shift is structural evidence rather than a database
    // lookup (the mangled names are not in the export database at all, which is why
    // the evidence vote left fsg_DarkNamer's whole MSVCP60 block spelled "B?0_Logit").
    const auto mangled_shift = [](const std::string& fn) {
        return fn.size() >= 2 && fn[0] == 'B' && fn[1] == '?';
    };
    const auto block_is_shifted = [&shifted_form, &mangled_shift](const std::vector<std::string>& names) {
        std::size_t for_shift = 0;
        std::size_t against = 0;
        for (const auto& fn : names) {
            if (fn.empty()) {
                continue;
            }
            if (mangled_shift(fn)) {
                ++for_shift;
                continue;
            }
            if (api_owner(fn) != nullptr) {
                ++against;
                continue;
            }
            const auto alt = shifted_form(fn);
            if (!alt.empty() && api_owner(alt) != nullptr) {
                ++for_shift;
            }
        }
        return for_shift > against && for_shift != 0;
    };
    const auto block_name = [&reshift, &shifted_form, &mangled_shift](const std::string& fn, bool shifted_block) -> std::string {
        if (mangled_shift(fn)) {
            const auto alt = shifted_form(fn);
            if (!alt.empty()) {
                return alt;
            }
        }
        if (api_owner(fn) != nullptr) {
            return fn;   // this spelling is a real export: leave it alone
        }
        if (shifted_block) {
            const auto alt = shifted_form(fn);
            if (!alt.empty()) {
                return alt;
            }
        }
        return reshift(fn);
    };
    const auto in_image = [&image](std::uint32_t rva) {
        return rva >= 0x200 && static_cast<std::size_t>(rva) + 2 < image.size();
    };
    const std::size_t ptr = is_64_ ? 8 : 4;
    std::size_t pairs = 0;
    for (std::size_t o = 0; o + 20 <= image.size(); o += 4) {
        const auto name_rva = at32(o + 12);
        if (!in_image(name_rva)) {
            continue;
        }
        const auto dll = cstr(name_rva, 48);
        if (!dll_like(dll)) {
            continue;
        }
        const auto oft = at32(o);
        const auto ft = at32(o + 16);
        if ((oft != 0 && !in_image(oft)) || (ft != 0 && !in_image(ft))) {
            continue;
        }
        const auto thunk_rva = oft != 0 ? oft : ft;
        if (!in_image(thunk_rva)) {
            continue;
        }
        std::size_t named = 0;
        for (std::size_t k = 0; k < 4096; ++k) {
            const auto toff = static_cast<std::size_t>(thunk_rva) + k * ptr;
            const auto thunk = ptr == 8 ? static_cast<std::uint64_t>(at32(toff)) |
                                              (static_cast<std::uint64_t>(at32(toff + 4)) << 32)
                                        : static_cast<std::uint64_t>(at32(toff));
            if (thunk == 0) {
                break;
            }
            const auto flag = ptr == 8 ? 0x8000000000000000ull : 0x80000000ull;
            if ((thunk & flag) != 0) {
                note_import(sanitize_ascii(dll), "ordinal_" + std::to_string(thunk & 0xffff));
                ++named;
                continue;
            }
            if (!in_image(static_cast<std::uint32_t>(thunk))) {
                continue;
            }
            const auto fn = cstr(static_cast<std::size_t>(thunk) + 2, 96);
            if (fn.size() < 2) {
                continue;
            }
            note_import(sanitize_ascii(dll), sanitize_ascii(fn));
            ++named;
            ++pairs;
        }
        if (opts_.debug && named != 0) {
            std::fprintf(stderr, "[unpack] orphan descriptor at 0x%zx: %s (%zu)\n", o, dll.c_str(), named);
        }
    }

    // The stubs obfuscate the descriptor fields too (FSG shifts the FIRST character
    // of every stored name by -3: 'JetModuleHandleA' -> 'GetModuleHandleA'), so the
    // descriptor walk above finds only the stub's own chain. Mine the tables
    // structurally instead: a run of pointer-spaced RVAs that all point at stored
    // name strings is an INT array, and the nearest preceding dll-name string names
    // it (the reference's family_reconstruct_orphans).
    std::vector<std::uint32_t> name_offsets;
    for (std::size_t o = 0x200; o + 5 < image.size(); ++o) {
        if (image[o] < 0x21 || image[o] > 0x7E) {
            continue;
        }
        const auto sname = cstr(o, 96);
        if (sname.size() >= 4 && (o == 0 || image[o - 1] == 0)) {
            name_offsets.push_back(static_cast<std::uint32_t>(o));
        }
    }
    const auto points_at_name = [&name_offsets](std::uint32_t v) {
        return std::binary_search(name_offsets.begin(), name_offsets.end(), v + 2) ||
               std::binary_search(name_offsets.begin(), name_offsets.end(), v);
    };
    // the DLL stems the IMAGE itself names (descriptor names and *.dll strings):
    // the export database has one default owner per name, but when the image says
    // which DLLs it uses, those win.
    std::set<std::string> present_dlls;
    for (std::size_t o = 0x200; o + 5 < image.size(); ++o) {
        if (image[o] < 0x21 || image[o] > 0x7E) {
            continue;
        }
        const auto s = cstr(o, 48);
        if (s.size() <= 4) {
            continue;
        }
        std::string low = s;
        for (auto& c : low) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        for (const char* ext : {".dll", ".drv", ".ocx"}) {
            const auto n = std::strlen(ext);
            if (low.size() > n && low.compare(low.size() - n, n, ext) == 0) {
                present_dlls.insert(low.substr(0, low.size() - n));
                break;
            }
        }
    }
    std::vector<std::pair<std::size_t, std::vector<std::string>>> tables;
    for (std::size_t o = 0; o + ptr * 2 <= image.size(); o += 4) {
        std::vector<std::string> members;
        std::size_t k = 0;
        for (; k < 512; ++k) {
            const auto off = o + k * ptr;
            const auto v = at32(off);
            if (v == 0) {
                break;
            }
            if (!points_at_name(v)) {
                members.clear();
                break;
            }
            // The thunk usually points at a 2-byte ordinal hint followed by the
            // name, but some packers (PEtite) point STRAIGHT at the name, so
            // reading v+2 chops the first two characters ('BitBlt' -> 'qBlt').
            // Taking the longer of the two parses is safe by construction: when v
            // really is a hint the parse at v starts on non-printable hint bytes
            // and fails. (Round 35 measured this change as INERT - 0 of 73 PEtite
            // samples moved - because nothing consumed the names: the table
            // attribution dropped them. With the export database in place the
            // same fix is what makes attribution possible, so it is re-applied
            // here as part of that mechanism, not as a repeat of an inert tweak.)
            auto fn = cstr(static_cast<std::size_t>(v) + 2, 96);
            if (const auto at_v = cstr(v, 96); at_v.size() > fn.size()) {
                fn = at_v;
            }
            if (fn.size() < 3) {
                members.clear();
                break;
            }
            // FSG/BeRo/MEW/WinUpack shift the FIRST character of every stored
            // name by -3. Undoing that blindly corrupts every other family's
            // names (measured on PEtite: 'EnableWindow' -> 'BnableWindow', so the
            // whole table then matches nothing), so the shift is now applied only
            // when it is EVIDENCE-BACKED: when the export database knows the
            // shifted spelling and not the stored one.
            if (api_owner(fn) == nullptr) {
                const auto shifted = static_cast<unsigned char>(fn[0] - 3);
                if (std::isalpha(shifted) != 0) {
                    std::string alt = fn;
                    alt[0] = static_cast<char>(shifted);
                    if (api_owner(alt) != nullptr) {
                        fn = alt;
                    }
                }
            }
            members.push_back(fn);
        }
        if (members.size() >= 2) {
            tables.emplace_back(o, std::move(members));
            o += k * ptr;  // skip the table body
        }
    }
    for (const auto& [off, members] : tables) {
        // the dll string nearest before the table (the descriptor name)
        std::string dll;
        for (std::size_t back = 0; back < 0x800 && back <= off; back += 4) {
            const auto cand = at32(off - back);
            if (cand < 0x200 || static_cast<std::size_t>(cand) + 4 >= image.size()) {
                continue;
            }
            auto text = cstr(cand, 48);
            if (!text.empty()) {
                std::string low = text;
                for (auto& c : low) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                if (low.size() > 4 && low.compare(low.size() - 4, 4, ".dll") == 0) {
                    dll = text;
                    break;
                }
            }
        }
        if (dll.empty()) {
            // No DLL string before this table (the stub's rebuilt tables keep the
            // names but drop the descriptor's Name field). Attribute each member
            // through the export database instead: an SDK table of what each DLL
            // exports, preferring a DLL the IMAGE itself names. Measured offline
            // on petite_PEViewer: 12 tables / 2056 members -> 953 correctly
            // attributed pairs, recall 0.940 against the original's 570, versus
            // 0.0333 for the report's current set. Without the database the same
            // scan recovers 5 pairs, i.e. nothing.
            // One INT table is ONE dll's import list, so the owners of its NAMED
            // members are positional evidence for its ordinal members: an
            // "ordinal_<n>" entry comes from the dll that owns its neighbours,
            // not from an unknown one. Skipping ordinals was measured as the
            // remaining PEtite gap (recall 0.803 with every name attributed and
            // every ordinal dropped).
            std::map<std::string, std::size_t> owner_votes;
            for (const auto& fn : members) {
                if (fn.rfind("ordinal_", 0) != 0) {
                    if (const char* o = api_owner(fn); o != nullptr) {
                        ++owner_votes[o];
                    }
                }
            }
            std::string dominant;
            for (const auto& [dll_name, votes] : owner_votes) {
                if (dominant.empty() || votes > owner_votes[dominant]) {
                    dominant = dll_name;
                }
            }
            std::size_t attributed = 0;
            std::size_t ordinals = 0;
            for (const auto& fn : members) {
                const bool is_ordinal = fn.rfind("ordinal_", 0) == 0;
                std::string stem;
                if (is_ordinal) {
                    if (dominant.empty()) {
                        continue;   // no evidence at all for the owner: don't guess
                    }
                    stem = dominant;
                    ++ordinals;
                } else {
                    const char* owner = api_owner(fn);
                    if (owner == nullptr) {
                        continue;
                    }
                    stem = owner;
                }
                note_import(sanitize_ascii(stem + ".dll"), sanitize_ascii(fn));
                ++attributed;
                ++pairs;
            }
            if (opts_.debug && attributed != 0) {
                std::fprintf(stderr,
                             "[unpack] orphan INT table at 0x%zx: db-attributed (%zu of %zu, %zu ordinals under %s, first %s)\n",
                             off, attributed, members.size(), ordinals, dominant.c_str(),
                             members.front().c_str());
            }
            continue;
        }
        for (const auto& fn : members) {
            note_import(sanitize_ascii(dll), sanitize_ascii(fn));
        }
        pairs += members.size();
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] orphan INT table at 0x%zx: %s (%zu names, first %s)\n", off,
                         dll.c_str(), members.size(), members.front().c_str());
        }
    }

    // FSG/BeRo/MEW/WinUpack store the payload's import LIST as a bare string blob —
    // `KERNEL32.dll\0JetModuleHandleA\0JetStartupInfoA\0...` with no pointer table
    // and no descriptors (measured: not one dword in the image points at the dll
    // name), and they shift the FIRST character of every stored name by +3
    // ('JetModuleHandleA' is GetModuleHandleA, 'OocalAlloc' is LocalAlloc). Walk the
    // blob in order: a dll-like string starts a group, the strings after it name that
    // dll, until the next dll-like string (the reference's orphan-name mining).
    std::size_t blob_pairs = 0;
    // Descriptor-less packers only: when the image already carries a real import
    // descriptor chain (harvest_image_imports found >= 4), the bare-string blob
    // heuristics below only fabricate phantom imports (MSPDB80.DLL, hhctrl.ocx)
    // from data strings, so skip them for those images.
    if (image_descriptor_count_ >= 4) {
        // Descriptor-ANCHORED string pass. An image carrying a real chain used to skip
        // every blob heuristic, because the unrestricted ones fabricated phantoms
        // (MSPDB80.DLL, hhctrl.ocx). But a chain can be mostly EMPTY while the names it
        // omits sit in the image as plain strings: measured on 104 RLPack rows, 4069 of
        // 19391 missing pairs (21%) have their name string in the dump, and recovering
        // them moves 7 rows over the 0.95 import criterion (accesschk 0.048 -> 1.000,
        // handle 0.692 -> 1.000, livekd 0.047 -> 0.987, procexp 0.038 -> 0.964,
        // ADInsight 0.037 -> 0.985, Coreinfo 0.052 -> 0.965, procdump 0.064 -> 0.959).
        // The restriction is what keeps it precision-safe: a name is only accepted when
        // its EXACT spelling is a known export AND its owner is one of the DLLs the
        // image's own descriptors already name - so no new DLL can be invented and a
        // data string can never claim a phantom module.
        std::set<std::string> declared;
        for (const auto& [dll, fn] : imports_) {
            std::string d = lower_ascii(dll);
            const auto slash = d.find_last_of("/\\");
            if (slash != std::string::npos) {
                d = d.substr(slash + 1);
            }
            if (d.size() > 4 && d.compare(d.size() - 4, 4, ".dll") == 0) {
                d.resize(d.size() - 4);
            }
            if (!d.empty()) {
                declared.insert(d);
            }
        }
        std::size_t anchored = 0;
        if (!declared.empty()) {
            std::string run;
            run.reserve(64);
            const auto flush = [&]() {
                if (run.size() >= 4 && run.size() <= 64) {
                    const char* owner = api_owner(run);
                    if (owner != nullptr) {
                        std::string o = lower_ascii(owner);
                        if (o.size() > 4 && o.compare(o.size() - 4, 4, ".dll") == 0) {
                            o.resize(o.size() - 4);
                        }
                        if (declared.count(o) != 0) {
                            note_import(o, run);
                            ++anchored;
                        }
                    }
                }
                run.clear();
            };
            for (const auto c : image) {
                const auto u = static_cast<unsigned char>(c);
                const bool ident = (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') ||
                                   (u >= '0' && u <= '9') || u == '_' || u == '@' || u == '?';
                if (ident) {
                    if (run.size() < 64) {
                        run.push_back(c);
                    } else {
                        run.clear();
                    }
                } else {
                    flush();
                }
            }
            flush();
        }
        if (opts_.debug) {
            std::fprintf(stderr,
                         "[unpack] descriptor-anchored strings: %zu declared dlls -> %zu pairs (total %zu)\n",
                         declared.size(), anchored, imports_.size());
        }
        return pairs + blob_pairs + anchored;
    }
    // FSG/BeRo/MEW/WinUpack store the payload's import list as a bare string run:
    // [dll][name][name]…[marker][dll][name]… with one- or two-character separator
    // pieces ('D', 'r') between the blocks and no pointer table at all. Walk the run
    // once, switching the attributed dll whenever a dll-like piece appears and
    // tolerating a few short separator pieces inside a block (measured on MEW, whose
    // groups are separated by exactly such markers).
    std::vector<std::pair<std::string, std::vector<std::string>>> groups;
    {
        std::string cur_dll;
        std::vector<std::string> names;
        auto p = std::size_t{0x200};
        int separators = 0;
        const auto flush = [&]() {
            if (!cur_dll.empty() && names.size() >= 2) {
                groups.emplace_back(cur_dll, names);
            }
            names.clear();
            separators = 0;
        };
        while (p + 6 < image.size()) {
            const auto piece = cstr(p, 96);
            if (piece.empty()) {
                // a NUL starts the next block; any other single non-printable byte is
                // the ordinal-flag marker these tables put before a name (0x80 in
                // MEW's oleaut32/shlwapi blocks), so it is skipped without ending the
                // block
                if (p < image.size() && image[p] == 0 && ++separators > 3) {
                    flush();
                }
                ++p;
                continue;
            }
            p += piece.size() + 1;
            if (dll_like(piece)) {
                flush();
                cur_dll = piece;
                continue;
            }
            bool ident = piece.size() >= 4;
            for (const auto c : piece) {
                if (!(std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '@' || c == '?')) {
                    ident = false;
                    break;
                }
            }
            if (!ident) {
                if (++separators > 3) {
                    flush();
                }
                continue;
            }
            // the stored name is reported verbatim: FSG shifts the first character
            // of its blob names (+3: 'JetModuleHandleA') while MEW stores them
            // unshifted, and no generic rule separates the two — an unconditional
            // undo corrupts the honest names and vice versa. The dll stems (which is
            // what coverage measures) are identical either way.
            auto fn = piece;
            if (!cur_dll.empty()) {
                names.push_back(std::move(fn));
                separators = 0;
            }
        }
        flush();
    }
    // Second, per-dll pass: the single walk above flushes on separators and so can
    // merge or drop the blocks that sit between two markers. Walk from EVERY dll-like
    // string instead and collect what follows it, then union the results (measured:
    // MEW realises 11 of its 14 dlls with the single walk, FSG 9 of 12).
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> per_dll;
        for (std::size_t o = 0x200; o + 6 < image.size(); ++o) {
            const auto dll = cstr(o, 48);
            if (dll.empty() || !dll_like(dll)) {
                continue;
            }
            std::vector<std::string> names;
            auto p = o + dll.size() + 1;
            int separators = 0;
            for (int guard = 0; guard < 512; ++guard) {
                const auto piece = cstr(p, 96);
                if (piece.empty()) {
                    if (p < image.size() && image[p] == 0 && ++separators > 3) {
                        break;
                    }
                    ++p;
                    continue;
                }
                p += piece.size() + 1;
                if (dll_like(piece)) {
                    break;
                }
                bool ident = piece.size() >= 4;
                for (const auto c : piece) {
                    if (!(std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '@' ||
                          c == '?')) {
                        ident = false;
                        break;
                    }
                }
                if (!ident) {
                    if (++separators > 3) {
                        break;
                    }
                    continue;
                }
                names.push_back(piece);
                separators = 0;
            }
            // a dll with a single import is legitimate (MEW's shlwapi block holds
            // exactly SHDeleteKeyW); the >= 3 blocks gate below carries the noise
            // control instead of a per-block minimum
            if (!names.empty()) {
                per_dll.emplace_back(dll, std::move(names));
                o = p;
            }
        }
        // FSG/BeRo/MEW/WinUpack shift the FIRST character of every stored import
        // name by -3, so a decoded FSG payload's string run reads `bexit`, `falloc`,
        // `wolower` instead of `_exit`, `malloc`, `tolower`. The INT-table path
        // undoes that under api_owner evidence (round 39); the string-group path did
        // not, which is why FSG's decoded rows recovered 128 names and still scored a
        // recall of 0.03 - every name was one character off and matched nothing.
        // Same evidence rule here: apply the shift only when the export database
        // knows the shifted spelling and not the stored one.
        std::set<std::string> seen_dlls;
        for (const auto& [dll, names] : per_dll) {
            seen_dlls.insert(dll);
        }
        if (per_dll.size() >= 3) {
            for (const auto& [dll, names] : per_dll) {
                const bool shifted_block = block_is_shifted(names);
                for (const auto& fn : names) {
                    note_import(sanitize_ascii(dll), sanitize_ascii(block_name(fn, shifted_block)));
                }
            }
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] per-dll blob pass: %zu blocks, %zu dlls\n", per_dll.size(),
                             seen_dlls.size());
            }
        }
    }
    std::size_t total_names = 0;
    std::set<std::string> unique_dlls;
    for (const auto& [dll, names] : groups) {
        total_names += names.size();
        unique_dlls.insert(dll);
    }
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] import-string scan: %zu groups, %zu names, %zu dlls\n",
                     groups.size(), total_names, unique_dlls.size());
    }
    if (groups.size() >= 2 && total_names >= 6) {
        for (const auto& [dll, names] : groups) {
            const bool shifted_block = block_is_shifted(names);
            for (const auto& fn : names) {
                note_import(sanitize_ascii(dll), sanitize_ascii(block_name(fn, shifted_block)));
                ++blob_pairs;
            }
        }
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] import-string groups: %zu groups, %zu dlls, %zu names (first %s!%s)\n",
                         groups.size(), unique_dlls.size(), total_names,
                         groups.front().first.c_str(), groups.front().second.front().c_str());
        }
    }
    return pairs + blob_pairs;
}

void Unpacker::harvest_image_imports(const std::vector<std::uint8_t>& image) {
    // Scylla's getImports: walk the payload's own descriptor chain in the dump.
    // The packers that restore the original table leave it intact (EnigmaVB,
    // Molebox, Neolite, PECompact), so this recovers their import set without
    // any emulation evidence.
    const auto walk = iat::walk_import_descriptors(image, base_);
    image_descriptor_count_ = walk.descriptors;
    image_iat_rva_by_dll_ = walk.iat_rva_by_dll;
    for (const auto& pr : walk.imports) {
        note_import(pr.first, pr.second);
    }
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] image import table harvest: %zu descriptors -> %zu imports (desc_rva=%s, iat_map=%zu)\n",
                     walk.descriptors, imports_.size(), hex(walk.descriptor_rva).c_str(),
                     walk.iat_rva_by_dll.size());
    }
}

void Unpacker::salvage_iat(Qiling& ql, const std::vector<std::uint8_t>& image) {
    salvaged_slots_ = 0;
    salvaged_pairs_ = 0;
    if (image.size() < 8) {
        return;
    }
    // Scylla's ApiReader: the loader's resolved-export table is the symbol map
    iat::SymbolMap symbols;
    try {
        const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
        for (const auto& [addr, entry] : pe_loader.import_symbols()) {
            if (addr == 0 || entry.name.empty()) {
                continue;
            }
            const auto dll = lower_ascii(fs::path(entry.dll).filename().string());
            if (dll.empty()) {
                continue;
            }
            symbols.add(addr, dll, entry.name);
        }
    } catch (...) {
        return;
    }
    // F52 / stub_map_: register every LOADED module's export addresses from its
    // GUEST export directory, so a slot is attributed by ADDRESS instead of by
    // whichever GPA handle happened to be current when the name was asked for
    // (the reference's stub_map_ + guest-EAT ordinal lane. As of §0.17 the stub
    // DLLs are PE32 for a 32-bit run, which is what makes their export
    // directories readable here.)
    {
        std::size_t mods = 0, named = 0, ords = 0;
        for (const auto& img : ql.loader().save()) {
            if (img.base == 0 || img.base == base_ || img.end <= img.base + 0x40) {
                continue;
            }
            const auto dll = lower_ascii(fs::path(img.path).filename().string());
            if (dll.empty()) {
                continue;
            }
            std::vector<std::uint8_t> hdr;
            try {
                hdr = ql.mem().read(img.base, 0x400);
            } catch (...) {
                continue;
            }
            if (hdr.size() < 0x40 || hdr[0] != 'M' || hdr[1] != 'Z') {
                continue;
            }
            const auto peoff = static_cast<std::size_t>(hdr[0x3c]) |
                               (static_cast<std::size_t>(hdr[0x3d]) << 8) |
                               (static_cast<std::size_t>(hdr[0x3e]) << 16) |
                               (static_cast<std::size_t>(hdr[0x3f]) << 24);
            if (peoff + 0xc8 > hdr.size() || hdr[peoff] != 'P' || hdr[peoff + 1] != 'E') {
                continue;
            }
            const auto magic = static_cast<std::uint16_t>(hdr[peoff + 24]) |
                               (static_cast<std::uint16_t>(hdr[peoff + 25]) << 8);
            if (magic != 0x10b) {
                continue;  // PE32 only (the corpus is 32-bit)
            }
            const auto rd32 = [](const std::uint8_t* p) -> std::uint32_t {
                return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
                       (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
            };
            const auto dd = peoff + 24 + 0x60;
            const auto exp_rva = rd32(hdr.data() + dd);
            const auto exp_sz = rd32(hdr.data() + dd + 4);
            if (exp_rva == 0 || exp_sz == 0 || exp_sz > (1u << 20)) {
                continue;
            }
            std::vector<std::uint8_t> exd, eat, ntab, otab;
            try {
                exd = ql.mem().read(img.base + exp_rva, 0x28);
            } catch (...) {
                continue;
            }
            if (exd.size() < 0x28) {
                continue;
            }
            const auto obase = rd32(exd.data() + 0x10);
            const auto nfuncs = rd32(exd.data() + 0x14);
            const auto nnames = rd32(exd.data() + 0x18);
            const auto eat_rva = rd32(exd.data() + 0x1c);
            const auto ntab_rva = rd32(exd.data() + 0x20);
            const auto otab_rva = rd32(exd.data() + 0x24);
            if (nfuncs == 0 || nfuncs > 0x8000 || eat_rva == 0) {
                continue;
            }
            try {
                eat = ql.mem().read(img.base + eat_rva, static_cast<std::size_t>(nfuncs) * 4);
                if (nnames != 0 && nnames <= nfuncs && ntab_rva != 0 && otab_rva != 0) {
                    ntab = ql.mem().read(img.base + ntab_rva, static_cast<std::size_t>(nnames) * 4);
                    otab = ql.mem().read(img.base + otab_rva, static_cast<std::size_t>(nnames) * 2);
                }
            } catch (...) {
                continue;
            }
            if (eat.size() < static_cast<std::size_t>(nfuncs) * 4) {
                continue;
            }
            std::map<std::uint32_t, std::string> name_by_idx;
            for (std::size_t i = 0; i < nnames && otab.size() >= (i + 1) * 2 && ntab.size() >= (i + 1) * 4; ++i) {
                const auto namerva = rd32(ntab.data() + i * 4);
                const auto idx = static_cast<std::uint32_t>(otab[i * 2]) |
                                 (static_cast<std::uint32_t>(otab[i * 2 + 1]) << 8);
                if (namerva == 0 || idx >= nfuncs) {
                    continue;
                }
                std::string nm;
                try {
                    const auto raw = ql.mem().read(img.base + namerva, 96);
                    nm.assign(reinterpret_cast<const char*>(raw.data()),
                              static_cast<std::size_t>(std::find(raw.begin(), raw.end(), 0) - raw.begin()));
                } catch (...) {
                    continue;
                }
                if (!nm.empty()) {
                    name_by_idx[idx] = sanitize_ascii(nm);
                }
            }
            const bool ord_dominant = name_by_idx.size() * 2 < nfuncs;
            for (std::uint32_t i = 0; i < nfuncs; ++i) {
                const auto rva = rd32(eat.data() + i * 4);
                if (rva == 0) {
                    continue;
                }
                if (rva >= exp_rva && rva < exp_rva + exp_sz) {
                    continue;  // forwarded slot
                }
                const auto va = img.base + rva;
                if (va >= 0x77000000ULL && va < 0x77020000ULL) {
                    continue;  // the engine's fake-GPA decoy range
                }
                const auto it = name_by_idx.find(i);
                if (it != name_by_idx.end()) {
                    symbols.add(va, dll, it->second);
                    ++named;
                } else if (ord_dominant) {
                    symbols.add(va, dll, "ordinal_" + std::to_string(obase + i));
                    ++ords;
                }
            }
            ++mods;
        }
        if (opts_.debug && std::getenv("TAOTE_SALVDBG") != nullptr) {
            std::fprintf(stderr, "[salv] module exports: %zu modules, %zu named, %zu ordinals, symbols=%zu\n",
                         mods, named, ords, symbols.size());
        }
    }
    if (symbols.empty()) {
        return;
    }

    // Collect the loaded DLL modules' address ranges so the scan below skips
    // them. A real rootfs maps genuine vendor DLLs whose own memory is dense
    // with self-pointers (their own IAT/export tables), and scanning those
    // produces thousands of false IAT hits (measured on upx_ADExplorer.exe:
    // kernel32!WerpNotifyLoadStringResource plus hundreds of WER/ntdll names).
    // The guest's IAT lives in its own image or in a private heap buffer, never
    // inside a loaded DLL, so skipping the modules loses nothing real.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> module_ranges;
    try {
        for (const auto& img : ql.loader().save()) {
            if (img.base == 0 || img.base == base_ || img.end <= img.base) {
                continue;
            }
            module_ranges.emplace_back(img.base, img.end);
        }
    } catch (...) {
    }
    const auto in_module = [&module_ranges](std::uint64_t lo, std::uint64_t hi) {
        for (const auto& [b, e] : module_ranges) {
            if (lo < e && hi > b) {
                return true;
            }
        }
        return false;
    };

    // Scylla's IATSearch: scan the image, then every other mapped region (the
    // stubs that rebuild the IAT themselves keep the table in a private buffer)
    iat::IatScanner scanner(symbols, is_64_ ? 8u : 4u);
    scanner.scan(image, base_);
    try {
        for (const auto& mi : ql.mem().get_mapinfo()) {
            const auto lo = std::get<0>(mi);
            const auto hi = std::get<1>(mi);
            if (hi <= lo || lo == base_ || hi - lo > 0x400000 || lo < 0x10000 || in_module(lo, hi)) {
                continue;  // the FS/GDT scratch, the engine's own maps, and loaded DLLs
            }
            std::vector<std::uint8_t> bytes;
            try {
                bytes = ql.mem().read(lo, hi - lo);
            } catch (...) {
                continue;
            }
            scanner.scan(bytes, lo);
        }
    } catch (...) {
    }
    const auto kept = scanner.coherent();
    if (kept.empty()) {
        return;
    }
    for (const auto& hit : kept) {
        note_import(hit.dll, hit.name);
    }
    // Reconstruct the payload's IAT layout from the in-image hits. The original
    // descriptor table is destroyed (UPX zeroes it), but the IAT slots themselves
    // still hold resolved pointers and are laid out as one contiguous run per dll,
    // separated by 4-byte zero terminators. Segment those runs and attribute each
    // to its dll by the named hits it contains — by-ordinal slots resolve to
    // shared stub cells (activeds!ordinal_2 and oleaut32!ordinal_9 both land on
    // the same synthetic address), so their dll label is noise. All-ordinal dlls
    // fall back to import-count matching against the unclaimed segments.
    struct IatSeg {
        std::uint32_t start = 0;
        std::uint32_t end = 0;
        std::size_t n = 0;
        std::map<std::string, std::size_t> named;
    };
    std::vector<IatSeg> segs;
    {
        // The descriptor walk's FirstThunk values name the *stub's* IAT for
        // UPX-style images (the header import directory still points there), and
        // the *payload's* IAT for descriptor-restoring packers. Either way those
        // slots must not pollute the payload segmentation below: in the former
        // case they are junk, in the latter the walk map already carries the
        // correct anchors (the merge below keeps them as the fallback).
        std::uint32_t stub_lo = 0xFFFFFFFFu;
        std::uint32_t stub_hi = 0;
        for (const auto& [dll, rva] : image_iat_rva_by_dll_) {
            (void)dll;
            if (rva == 0) {
                continue;
            }
            stub_lo = std::min(stub_lo, rva);
            stub_hi = std::max(stub_hi, rva);
        }
        std::vector<std::tuple<std::uint32_t, std::string, bool>> slots;  // rva, dll, is_named
        for (const auto& hit : scanner.hits()) {
            if (hit.va < base_ || hit.va >= base_ + image_size_) {
                continue;
            }
            const auto rva = static_cast<std::uint32_t>(hit.va - base_);
            if (stub_lo <= stub_hi && rva + 4 > stub_lo && rva < stub_hi + 0x10) {
                continue;  // the stub's own IAT, not the payload's
            }
            const bool named = hit.name.compare(0, 8, "ordinal_") != 0;
            slots.emplace_back(rva, hit.dll, named);
        }
        std::sort(slots.begin(), slots.end(),
                  [](const auto& a, const auto& b) { return std::get<0>(a) < std::get<0>(b); });
        for (const auto& [rva, dll, named] : slots) {
            if (segs.empty() || rva > segs.back().end + 4) {
                segs.push_back(IatSeg{rva, rva, 1, {}});
            } else if (rva == segs.back().end + 4) {
                segs.back().end = rva;
                segs.back().n += 1;
            } else {
                continue;  // duplicate slot rva
            }
            if (named) {
                segs.back().named[dll] += 1;
            }
        }
    }
    std::map<std::string, std::uint32_t> anchors;
    std::set<std::size_t> claimed;
    for (std::size_t i = 0; i < segs.size(); ++i) {
        if (segs[i].named.empty()) {
            continue;
        }
        std::string best;
        std::size_t bestn = 0;
        for (const auto& [dll, c] : segs[i].named) {
            if (c > bestn) {
                best = dll;
                bestn = c;
            }
        }
        if (!best.empty()) {
            anchors[best] = segs[i].start;
            claimed.insert(i);
        }
    }
    std::map<std::string, std::size_t> counts;
    for (const auto& [dll, name] : imports_) {
        (void)name;
        counts[dll] += 1;
    }
    for (const auto& [dll, count] : counts) {
        if (anchors.count(dll) != 0) {
            continue;
        }
        for (std::size_t i = 0; i < segs.size(); ++i) {
            if (claimed.count(i) != 0 || segs[i].n != count) {
                continue;
            }
            anchors[dll] = segs[i].start;
            claimed.insert(i);
            break;
        }
    }
    salvaged_iat_rva_by_dll_ = std::move(anchors);
    salvaged_slots_ = kept.size();
    salvaged_pairs_ = kept.size();
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] salvage: %zu hits -> %zu slots\n", scanner.hits().size(), kept.size());
        for (std::size_t i = 0; i < scanner.hits().size() && i < 4; ++i) {
            std::fprintf(stderr, "[unpack]   hit at 0x%llx dll=<%s> name=<%s>\n",
                         static_cast<unsigned long long>(scanner.hits()[i].va),
                         scanner.hits()[i].dll.c_str(), scanner.hits()[i].name.c_str());
        }
    }
}

// The reference's OEP pick, cut to the shape vote (docs/oep-pick-design.md V1):
// a real entry point starts like a function, a junk hop does not. Ties go to the
// later candidate, and a candidate inside the packed EP's own section is penalised
// (the stub keeps executing there after the payload has been decoded).
std::uint64_t Unpacker::pick_oep(const std::vector<std::uint8_t>& image) const {
    const int ep_sec = section_index_at(packed_ep_va_);
    float best_score = -1e9f;
    std::uint64_t best = meta_oep_;
    // The INCUMBENT prior (the reference's +1e6, unpacker.h:1200-1210): the first
    // accepted hop wins unless it is provably not an entry — measured, the first
    // hop is the true OEP for UPX/ASPack/FSG/Molebox/Packman/WinUpack, and a
    // scoring pass that ignored that demoted 11 verified samples.
    const auto shape_at = [&image, this](std::uint64_t va) -> int {
        if (va < base_ || va - base_ + 16 > image.size()) {
            return 0;
        }
        const auto* p = image.data() + (va - base_);
        if (p[0] == 0x55 && p[1] == 0x8b && p[2] == 0xec) {
            return 3;
        }
        if (p[0] == 0x6a && p[2] == 0x68 && p[7] == 0xe8) {
            return 3;
        }
        if (p[0] == 0xe8 && p[5] == 0xe9) {
            return 2;
        }
        // The CRT startup entry shapes WinUpack/JDPack payloads actually use:
        // `call __security_init_cookie; push 0x10; push imm32` (e8 <rel32> 6a ??
        // 68 ..) and `call ...; test eax,eax` (e8 <rel32> 85 c0 ..). Both scored 0
        // here, so the WinUpack policy gate rejected a hop that WAS the true entry
        // and the ladder then picked a `55 8b ec` look-alike: measured against the
        // reference, winupack_cmd/molebox_cmd's true entry is 0x829a (e8 ea f9 ff
        // ff 6a 10 68) and winupack_PEview's is 0x1000 (e8 d7 00 00 00 85 c0 75),
        // and the reference reports all three exactly while taote missed them.
        if (p[0] == 0xe8 && p[5] == 0x6a && p[7] == 0x68) {
            return 2;
        }
        if (p[0] == 0xe8 && p[5] == 0x85 && p[6] == 0xc0) {
            return 2;
        }
        if (p[0] == 0xe9) {
            return 1;
        }
        return 0;
    };
    // the statically known entries win outright: the packer itself recorded them
    if (const auto mew = static_oep_; mew != 0) {
        return mew;
    }
    if (const auto hdr = header_ep_candidate(image); hdr != 0) {
        return hdr;
    }
    const bool decode_only = packer_ != nullptr && packer_->decode_only();
    // PECompact mini-stub entry fix (reference unpacker.cpp:11936-11958, default
    // ON there as SE_NO_PECOMPACT_EPFIX): PECompact keeps the ORIGINAL entry in
    // the packed header and plants a ~0x16-byte mini-stub there that CALLs the
    // decompressor; when it returns, execution resumes just past the stub, so the
    // section-hop latch records header EP + 0x16 and every artifact came out with
    // EP = header EP + 0x16 while the payload was otherwise correct. When a hop
    // lands within 0x40 bytes past the packed header EP in the same section, the
    // header EP is the faithful entry. This must outrank the shared ladder, which
    // otherwise fires its Pass-C CFG-thunk scan on the decoded body and overrides
    // the correct hop (pecompact_PEViewer: hop 0x40151a = header EP + 0x16, the
    // ladder replaced it with a 0x4f99f0 look-alike).
    if (opts_.family == "PECompact") {
        // A unique CRT-init thunk (the ladder's Pass A shape) outranks the
        // mini-stub epfix: pecompact_Bginfo/cpuz_x32 have exactly one such
        // thunk as their real entry (0x5b5d42 / 0x4f7c76) AND a hop latch that
        // lands near the header mini-stub, and the epfix must not hijack them.
        // Count the Pass-A shape first (the reference's picker runs it ahead of
        // the family EP fix).
        std::uint64_t pass_a = 0;
        std::size_t pass_a_count = 0;
        for (const auto& ps : sections_) {
            const auto start = static_cast<std::size_t>(ps.start - base_);
            const auto span = std::min<std::size_t>(static_cast<std::size_t>(ps.end - ps.start), image.size() - start);
            for (std::size_t i = 1; i + 11 < span; ++i) {
                const auto* b = image.data() + start + i;
                if (b[0] != 0xe8 || b[5] != 0xe9) {
                    continue;
                }
                const auto prev = b[-1];
                if (!(prev == 0xc3 || prev == 0xcc || prev == 0x90 || prev == 0xc2)) {
                    continue;
                }
                const auto rel = static_cast<std::int32_t>(static_cast<std::uint32_t>(b[6]) |
                                                           (static_cast<std::uint32_t>(b[7]) << 8) |
                                                           (static_cast<std::uint32_t>(b[8]) << 16) |
                                                           (static_cast<std::uint32_t>(b[9]) << 24));
                const auto tgt = static_cast<std::int64_t>(ps.start + i + 10) + rel;
                if (tgt < static_cast<std::int64_t>(base_) ||
                    tgt >= static_cast<std::int64_t>(base_ + image_size_)) {
                    continue;
                }
                const auto boff = static_cast<std::size_t>(tgt - static_cast<std::int64_t>(base_));
                if (boff + 9 > image.size()) {
                    continue;
                }
                const auto* q = image.data() + boff;
                if (!((q[0] == 0x6a && q[2] == 0x68 && q[7] == 0xe8) ||
                      (q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec) ||
                      (q[0] == 0xe8 && q[5] == 0xe9))) {
                    continue;
                }
                pass_a = ps.start + i;
                ++pass_a_count;
            }
        }
        if (pass_a_count == 1) {
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] pecompact: unique CRT-init thunk %s outranks epfix\n",
                             hex(pass_a).c_str());
            }
            return pass_a;
        }
        // mini-stub entry fix (reference unpacker.cpp:11936-11958): PECompact
        // keeps the ORIGINAL entry in the packed header and plants a ~0x16-byte
        // mini-stub there that CALLs the decompressor; the section-hop latch
        // records the resume point (header EP + 0x16). When a hop lands within
        // 0x40 bytes past the packed header EP in the same section, the header
        // EP is the faithful entry.
        const auto pep = packed_ep_va_;
        // Is the header's AddressOfEntryPoint just the first section's start?
        // (see the placeholder note below)
        const bool pep_is_placeholder = [&] {
            if (image.size() < 0x40) {
                return false;
            }
            const auto rd32 = [&image](std::size_t o) -> std::uint32_t {
                if (o + 4 > image.size()) {
                    return 0;
                }
                return static_cast<std::uint32_t>(image[o]) | (static_cast<std::uint32_t>(image[o + 1]) << 8) |
                       (static_cast<std::uint32_t>(image[o + 2]) << 16) |
                       (static_cast<std::uint32_t>(image[o + 3]) << 24);
            };
            const auto lfanew = rd32(0x3c);
            if (lfanew + 0x40 > image.size()) {
                return false;
            }
            const auto ep_rva = rd32(lfanew + 24 + 0x10);
            const auto nsec = static_cast<std::uint32_t>(image[lfanew + 6]) |
                              (static_cast<std::uint32_t>(image[lfanew + 7]) << 8);
            const auto sopt = static_cast<std::uint32_t>(image[lfanew + 20]) |
                              (static_cast<std::uint32_t>(image[lfanew + 21]) << 8);
            if (nsec == 0) {
                return false;
            }
            const auto first_va = rd32(lfanew + 24 + sopt + 12);
            return ep_rva != 0 && ep_rva == first_va;
        }();
        // The entry-shaped CRT cluster inside the decoded body (the reference's
        // Borland+SEH LAST table, bounded to a real cluster the same way the
        // decode-only ladder bounds it).
        const auto borland_seh_cluster = [&](const std::vector<std::uint8_t>& img) -> std::uint64_t {
            std::size_t b_count = 0, b_last = 0, s_count = 0, s_last = 0;
            for (std::size_t i = 0; i + 8 < img.size(); ++i) {
                if (img[i] == 0x6a && img[i + 2] == 0x68 && img[i + 7] == 0xe8) {
                    const auto pv = static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(img[i + 3]) | (static_cast<std::uint32_t>(img[i + 4]) << 8) |
                        (static_cast<std::uint32_t>(img[i + 5]) << 16) |
                        (static_cast<std::uint32_t>(img[i + 6]) << 24));
                    if (pv > base_ && pv < base_ + image_size_) {
                        ++b_count;
                        b_last = i;
                    }
                }
            }
            const auto hw = std::min<std::size_t>(img.size(), 0x40000);
            for (std::size_t i = 0; i + 6 < hw; ++i) {
                if (img[i] == 0x55 && img[i + 1] == 0x8b && img[i + 2] == 0xec && img[i + 3] == 0x6a &&
                    img[i + 4] == 0xff && img[i + 5] == 0x68) {
                    ++s_count;
                    s_last = i;
                }
            }
            if (b_count > 0 && b_count <= 8 && b_count > s_count) {
                return base_ + b_last;
            }
            if (s_count > 0 && s_count <= 8 && s_count >= b_count) {
                return base_ + s_last;
            }
            return 0;
        };
        // The placeholder header EP has a second witness the ladder can lose: the
        // stub plants a mini-stub AT the placeholder, so the first hop lands there
        // and the payload is entered tens of KB later - and THAT hop is the original
        // entry. Measured on pecompact_Everything/Hasher/md5summer: ledger hop
        // 0x545f0d (or its family) against the ladder's startup frame 0x4bf150, with
        // the reference reporting the same address and oep_source=hop. Only taken
        // when the header EP is a placeholder (the 29/29 separated class above) and
        // only for a hop FAR past it. The threshold is measured, not chosen: on the
        // three rows this wins the first such hop is 0x145f0d / 0x82628 / 0x9ec68
        // past the section start, while the two rows it must not touch (Diskmon,
        // PEview - whose placeholder IS the entry) reach only 0x8a7e / 0xdc, so
        // 0x10000 sits inside a 7x gap.
        // Default ON (measured: PECompact OEP 92 -> 95, all-three 92 -> 95, exactly
        // the three rows below, ZERO losses on the 97-row family). TAOTE_NO_PC_FARHOP=1
        // keeps the A/B available.
        static const bool pc_farhop = std::getenv("TAOTE_NO_PC_FARHOP") == nullptr;
        if (pc_farhop && pep_is_placeholder && pc_far_hop_ != 0 &&
            section_index_at(pc_far_hop_) == section_index_at(pep)) {
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] pecompact epfix: far hand-off %s beats placeholder %s\n",
                             hex(pc_far_hop_).c_str(), hex(pep).c_str());
            }
            return pc_far_hop_;
        }
        for (const auto va : hop_ledger_) {
            if (va > pep && va - pep <= 0x40 && section_index_at(va) == section_index_at(pep)) {
                // The epfix must not preempt a REAL SEH-startup frame. Round
                // 17 measured this precisely: extending the whole ladder here
                // regresses pecompact_PEViewer (the ladder's Pass-C look-alike
                // 0x4f99f0 beat the correct packed EP 0x401504), and extending
                // the Borland+SEH CLUSTER rule to PECompact would regress 9 of
                // the samples that currently pass (AccessEnum, Cacheset,
                // Diskmon, adrestore, ctrl2cap, dfrgui, efsdump, ftp, pagedfrg).
                // What IS safe is the narrower fact: when the ladder's answer is
                // itself a `55 8b ec 6a ff 68` startup frame - Pass B's evidence,
                // not Pass C's - it is a genuine entry and outranks the header EP.
                // Measured: pecompact_{DarkNamer,Hash,rm} flip to exact and no
                // currently-passing sample changes.
                const auto ladder = static_oep_from_image(image);
                const bool ladder_is_startup_frame = [&] {
                    if (ladder == 0 || ladder < base_) {
                        return false;
                    }
                    const auto off = static_cast<std::size_t>(ladder - base_);
                    if (off + 6 > image.size()) {
                        return false;
                    }
                    const auto* q = image.data() + off;
                    return q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec && q[3] == 0x6a && q[4] == 0xff &&
                           q[5] == 0x68;
                }();
                if (ladder != 0 && ladder != pep && ladder_is_startup_frame) {
                    if (opts_.debug) {
                        std::fprintf(stderr, "[unpack] pecompact epfix: startup frame %s outranks header ep %s (hop %s)\n",
                                     hex(ladder).c_str(), hex(pep).c_str(), hex(va).c_str());
                    }
                    return ladder;
                }
                // The PLACEHOLDER header EP (round 18). When the header's
                // AddressOfEntryPoint equals the FIRST SECTION's VirtualAddress,
                // the packer did not preserve the original entry - the field is
                // a placeholder and the epfix is trusting the stub.
                // Measured over all 96 valid PECompact samples: header EP
                // preserved -> true EP == header EP in **67/67**; header EP ==
                // first section start -> true EP != header EP in **29/29**. A
                // perfect separation, so the epfix defers to the entry-shaped
                // cluster evidence in the second case only (the PsTools-family
                // builds: hop 0x401016, true entry tens of KB later).
                if (pep_is_placeholder) {
                    if (const auto cluster = borland_seh_cluster(image); cluster != 0) {
                        if (opts_.debug) {
                            std::fprintf(stderr, "[unpack] pecompact epfix: placeholder header ep %s -> cluster %s\n",
                                         hex(pep).c_str(), hex(cluster).c_str());
                        }
                        return cluster;
                    }
                }
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] pecompact epfix: hop %s -> header ep %s\n",
                                 hex(va).c_str(), hex(pep).c_str());
                }
                return pep;
            }
        }
    }
    // The decode-only families: their decode lands in one big section whose head is
    // also the stub, so the run's own transitions are mostly stub-internal noise.
    // The static ladder over the decoded body is the authority (the reference's
    // F41c/F47: only an ACCEPTED, replacement-gated hop outranks it — taote has no
    // such gate, so the ladder leads and the ledger is the fallback).
    // F41c/F47 precedence: for NSPack and RLPack an ACCEPTED section hop (a real
    // transfer out of the stub's own section) outranks the static ladder - the
    // reference measures exactly this (nspack_portmon: the accepted hop's true
    // OEP 0x413b0e was being replaced by a wrong passc CFG-thunk; rlpack_mtinst:
    // the accepted hop is already the true 0x1003866). taote's ladder led
    // unconditionally, which is why NSPack sits at 0% exact OEP. MPRESS keeps the
    // ladder first: its ledger holds only stub-internal entries (the trampoline),
    // and the real OEP comes from the decoded body's thunk.
    // "Accepted" means the same thing here as in the non-decode path below: the
    // hop is not a junk latch (write ordinal >= 32) and the bytes at the target
    // are entry-shaped. The old test required the hop to leave the packed EP's
    // own section, which is exactly wrong for NSPack: its payload decodes INTO
    // that section, so the true OEP shares it and the filter discarded the
    // correct ledger entry (nspack_Cacheset: the ledger holds 0x4024a2@156337 =
    // the true EP, the filter dropped it and Pass B's 3 MSVC frames then
    // overrode it with the LAST one, 0x406c29).
    if (decode_only && opts_.family != "MPRESS" && !hop_ledger_.empty()) {
        for (std::size_t i = hop_ledger_.size(); i-- > 0;) {
            const auto va = hop_ledger_[i];
            const auto seq = i < hop_write_seq_.size() ? hop_write_seq_[i] : 0;
            if (seq >= 32 && shape_at(va) >= 2) {
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] pick OEP %s (accepted hop outranks the ladder, seq=%llu)\n",
                                 hex(va).c_str(), static_cast<unsigned long long>(seq));
                }
                return va;
            }
        }
    }
    if (decode_only) {
        if (const auto ladder = static_oep_from_image(image); ladder != 0) {
            return ladder;
        }
    }
    // The INCUMBENT STRENGTH rule (the reference's pick_and_emit_oep prior,
    // unpacker.cpp:8156-8260): a candidate that the run itself accepted is
    // STRONG (+1e6, unpickable-against) unless it is a JUNK LATCH - a hop taken
    // almost immediately at run start (the reference's kJunkLatchMaxInstrs=32,
    // here the write ordinal, which counts the same thing: how much the stub had
    // written when the hop fired). The static ladder may only override a WEAK
    // incumbent. Measured on aspack_Cacheset: the ledger holds exactly the two
    // candidates the reference holds (0x42602f@1 junk latch, 0x4024a2@35973 the
    // real OEP), and letting the ladder override the strong one picked a
    // look-alike prologue at 0x406c29 instead.
    static const bool incumbent_rule =
        std::getenv("TAOTE_OEP_INCUMBENT") == nullptr ||
        std::string(std::getenv("TAOTE_OEP_INCUMBENT")) != "0";
    if (!incumbent_rule || hop_ledger_.empty()) {
        // no ledger: nothing is strong
    } else {
        // The incumbent (the reference's pick_and_emit_oep: score the candidates,
        // keep the best; V1 is the shape vote and it is what separates a payload
        // entry from a relay point). With the claim ledger on the ledger holds a
        // handful of hops, so the vote is: the LAST candidate whose bytes start
        // like a function (the payload's entry is the final hand-off), else the
        // FIRST candidate that is not a junk latch (the reference's
        // kJunkLatchMaxInstrs=32, here the write ordinal), else nothing.
        // Measured: aspack_Cacheset 0x4024a2 (55 8b ec) over the latch 0x42602f;
        // molebox_AccessEnum 0x407a98 over the container relay 0x42b5a4;
        // bero_Autologon 0x403980 over the post-payload write hop 0x439000.
        std::uint64_t lead = 0;
        std::uint64_t lead_seq = 0;
        for (std::size_t i = hop_ledger_.size(); i-- > 0;) {
            const auto seq = i < hop_write_seq_.size() ? hop_write_seq_[i] : 0;
            if (seq >= 32 && shape_at(hop_ledger_[i]) >= 2) {
                lead = hop_ledger_[i];
                lead_seq = seq;
                break;
            }
        }
        if (lead == 0) {
            for (std::size_t i = 0; i < hop_ledger_.size(); ++i) {
                const auto seq = i < hop_write_seq_.size() ? hop_write_seq_[i] : 0;
                if (seq >= 32) {
                    lead = hop_ledger_[i];
                    lead_seq = seq;
                    break;
                }
            }
        }
        if (lead == 0) {
            lead = hop_ledger_.front();
            lead_seq = hop_write_seq_.size() == hop_ledger_.size() ? hop_write_seq_.front() : 0;
        }
        const int lead_sec = section_index_at(lead);
        const bool lead_is_latch = lead_seq != 0 && lead_seq < 32;
        // A hand-off into memory that holds no recognisable code shape is not an
        // entry: WinUpack's stub hops into the buffer it is still decompressing
        // (winupack_Cacheset: 0x42e80b, 16 zero bytes), and taking that hop made
        // the pick land outside the payload the run had already decoded.
        // Narrower than "entry-shaped": only memory that holds NOTHING (all zero
        // in the first 16 bytes, or outside every section) is disqualified. A
        // shape_at() test was measured too strict - it also rejected the genuine
        // entries of calc/cmd/PEViewer (0x12d6c, 0x829a, 0x1504), costing 37
        // samples across ASPack/BeRo/EXpressor/Eronana/JDPack/Packman/UPX.
        // SCOPE: WinUpack only. Its stub hops into the buffer it is still
        // decompressing, and only there does the hop's target shape decide
        // anything: measured corpus-wide, a shape_at() gate inside this rule took
        // WinUpack 39 -> 57 all-three but cost 37 samples in ASPack/BeRo/
        // EXpressor/Eronana/JDPack/Packman/UPX/Yoda-Crypter/PEtite, whose genuine
        // entries are plain code (0x12d6c, 0x829a, 0x1504). Every other family
        // keeps the old rule byte-for-byte.
        const bool lead_winupack = opts_.family == "WinUpack";
        const bool lead_shaped = !lead_winupack || shape_at(lead) >= 1;
        const bool lead_strong = lead != 0 && !lead_is_latch && lead_shaped;
        if (lead_strong) {
            const bool ladder_says_same = [&] {
                const auto l = static_oep_from_image(image);
                return l == lead;
            }();
            (void)ladder_says_same;
            (void)lead_sec;
            return lead;
        }
    }
    if (!hop_ledger_.empty()) {
        const auto first = hop_ledger_.front();
        const int first_sec = section_index_at(first);
        const bool in_stub_section = first_sec >= 0 && first_sec == ep_sec;
        if (!in_stub_section && shape_at(first) >= 2) {
            // an ACCEPTED hop (a real transfer out of the stub's own section) is
            // the strongest signal and outranks the static ladder (the reference's
            // F41c/F47 accepted-hop suppression)
            return first;
        }
        // the decode-only ladder's static patterns correct a junk first hop
        if (const auto ladder = static_oep_from_image(image); ladder != 0) {
            return ladder;
        }
        // the incumbent is junk: prefer a real prologue outside the stub section,
        // then the ladder's landing in the decoded section
        for (const auto va : hop_ledger_) {
            const int sec = section_index_at(va);
            if (sec >= 0 && sec == ep_sec) {
                continue;
            }
            if (shape_at(va) >= 3) {
                return va;
            }
        }
    }
    // The decode-only ladder's landing (the reference's guess_oep over the decoded
    // section, unpacker.cpp:6920-6981 + ladder_fill_dump_): when every candidate so
    // far is junk, the payload entry is the first prologue in the largest section
    // the stub wrote. NSPack/RLPack/MPRESS never hand off explicitly under
    // emulation; this is the artifact their stubs leave behind.
    {
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges(ever_written_.begin(), ever_written_.end());
        std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
            return (a.second - a.first) > (b.second - b.first);
        });
        for (const auto& r : ranges) {
            if (r.first < base_ || r.second <= r.first) {
                continue;
            }
            const auto start = static_cast<std::size_t>(r.first - base_);
            const auto span = std::min<std::size_t>(static_cast<std::size_t>(r.second - r.first), 0x20000);
            if (start + span > image.size()) {
                continue;
            }
            for (std::size_t i = 0; i + 16 <= span; ++i) {
                const auto* p = image.data() + start + i;
                const bool prologue = (p[0] == 0x6a && p[2] == 0x68 && p[7] == 0xe8) ||
                                      (p[0] == 0x55 && p[1] == 0x8b && p[2] == 0xec);
                if (!prologue) {
                    continue;
                }
                int printable = 0;
                for (int k = 0; k < 16; ++k) {
                    if (p[k] >= 0x20 && p[k] <= 0x7E) {
                        ++printable;
                    }
                }
                if (printable <= 12) {
                    return r.first + i;
                }
            }
        }
    }
    for (std::size_t i = 0; i < hop_ledger_.size(); ++i) {
        const auto va = hop_ledger_[i];
        if (va < base_ || va - base_ + 16 > image.size()) {
            continue;
        }
        const auto* p = image.data() + (va - base_);
        float score = 0.f;
        int printable = 0;
        bool all_zero = true;
        for (int k = 0; k < 16; ++k) {
            const auto u = p[k];
            if (u != 0) {
                all_zero = false;
            }
            if (u >= 0x20 && u <= 0x7E) {
                ++printable;
            }
        }
        if (all_zero) {
            score -= 4.f;
        } else if (printable > 12) {
            score -= 2.f;
        }
        // classic prologues: 6a xx 68 imm32 e8 (MSVC CRT), 55 8b ec (frame), e8 .. e9
        if (p[0] == 0x6a && p[2] == 0x68 && p[7] == 0xe8) {
            score += 5.f;
        }
        if (p[0] == 0x55 && p[1] == 0x8b && p[2] == 0xec) {
            score += 4.5f;
        }
        if (p[0] == 0xe8 && p[5] == 0xe9) {
            score += 3.f;
        }
        if (p[0] == 0xe9) {
            score += 2.f;  // a tail jump (the payload's own thunk chain)
        }
        const int sec = section_index_at(va);
        if (sec >= 0 && sec == ep_sec) {
            score -= 3.f;  // still in the stub's section
        } else if (sec >= 0 && sections_[static_cast<std::size_t>(sec)].is_exec) {
            score += 1.f;
        }
        // the write-ordinal rule: a section still being written after this hop is
        // mid-decode, not the hand-off (MPRESS/RLPack park an early hop inside the
        // decode target and keep writing)
        if (sec >= 0) {
            const auto start = sections_[static_cast<std::size_t>(sec)].start;
            const auto it = last_write_seq_.find(start);
            if (it != last_write_seq_.end() && i < hop_write_seq_.size() && it->second > hop_write_seq_[i]) {
                score -= 2.f;
            } else {
                score += 1.f;
            }
        }
        score -= 0.001f * static_cast<float>(i);  // an entry precedes its callees: earlier wins a tie
        if (score > best_score) {
            best_score = score;
            best = va;
        }
    }
    return best;
}

// The in-memory header's AddressOfEntryPoint, when the stub changed it and the new
// value lands in a section the stub wrote: that is the payload entry the packer
// itself recorded (pegasus reads the same field for EnigmaVB,
// packers/enigma_vb_unpacker.h:8-24).
std::uint64_t Unpacker::header_ep_candidate(const std::vector<std::uint8_t>& image) const {
    if (image.size() < 0x200) {
        return 0;
    }
    const auto rd32 = [&image](std::size_t o) -> std::uint32_t {
        if (o + 4 > image.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(image[o]) | (static_cast<std::uint32_t>(image[o + 1]) << 8) |
               (static_cast<std::uint32_t>(image[o + 2]) << 16) | (static_cast<std::uint32_t>(image[o + 3]) << 24);
    };
    const auto lfanew = rd32(0x3c);
    if (lfanew + 0x40 > image.size() || image[lfanew] != 'P' || image[lfanew + 1] != 'E') {
        return 0;
    }
    const auto opt = lfanew + 24;
    const auto ep_rva = rd32(opt + 0x10);
    if (ep_rva == 0) {
        return 0;
    }
    const auto va = base_ + ep_rva;
    if (va >= base_ + image_size_) {
        return 0;
    }
    // an unchanged header EP is the *stub's* entry for the in-place packers, but
    // for the boxers it IS the payload's (EnigmaVB keeps the original
    // AddressOfEntryPoint in the header and jumps there from its TLS callback)
    if (va == packed_ep_va_ && opts_.family != "EnigmaVB") {
        return 0;
    }
    // a virtualizer writes the header but never the sections (EnigmaVB: the
    // loader is a TLS callback that sets up a VFS), so for that family the field
    // is trusted unconditionally (the reference's M1 path); elsewhere only when
    // the stub's decode actually covered the address
    if (opts_.family == "EnigmaVB") {
        return va;
    }
    for (const auto& r : ever_written_) {
        if (va >= r.first && va <= r.second) {
            return va;
        }
    }
    return 0;
}

// The packer's static ladder over the DECODED body (the reference's
// decode_only_ladder): only the families that hand off through the decoded
// body's own trampolines implement it.
// PEtite EP-exit walk (../pegasus/src/unpacker/packers/petite_unpacker.cpp, the
// [pet-epexit] trail): walk the section-transition history BACKWARD and take the
// first transition whose target section the run never leaves again and which saw no
// write at or after the hand-off (a 64-instruction grace, the reference's constant).
// The terminal prologue scan cannot do this job once the payload runs: it latches
// mid-decode .text entries (measured: family OEP 36 -> 26 with the payload running).
std::uint64_t Unpacker::oep_from_transition_trail(const std::vector<std::uint8_t>& image) const {
    if (sec_trans_.empty() || image.empty()) {
        return 0;
    }
    constexpr std::uint64_t kGrace = 64;
    // Excursions (A->B followed by B->A within a generous window) are calls into another
    // section that come straight back, not hand-offs. petite_ctrl2cap is the measured case:
    // t4 0->1 at seq 218552 and t5 1->0 at seq 218553 ONE instruction later, and the walk
    // without this filter picked t5 (0x403ee4) while the true entry was t3 (0x40221a).
    constexpr std::uint64_t kExcursion = 1u << 20;
    std::vector<char> drop(sec_trans_.size(), 0);
    for (std::size_t i = 0; i < sec_trans_.size(); ++i) {
        if (drop[i] != 0) {
            continue;
        }
        for (std::size_t j = i + 1; j < sec_trans_.size(); ++j) {
            if (drop[j] != 0) {
                continue;
            }
            if (sec_trans_[j].from_sec == sec_trans_[i].to_sec && sec_trans_[j].to_sec == sec_trans_[i].from_sec &&
                sec_trans_[j].seq >= sec_trans_[i].seq &&
                sec_trans_[j].seq - sec_trans_[i].seq <= kExcursion) {
                drop[i] = 1;
                drop[j] = 1;
                break;
            }
        }
    }
    for (std::size_t i = sec_trans_.size(); i-- > 0;) {
        if (drop[i] != 0) {
            continue;
        }
        const auto& t = sec_trans_[i];
        if (t.addr == 0 || t.addr < base_ || t.addr - base_ >= image.size()) {
            continue;
        }
        // (a) the run must never leave the target section again
        bool left_again = false;
        for (std::size_t j = i + 1; j < sec_trans_.size(); ++j) {
            if (drop[j] != 0) {
                continue;
            }
            if (sec_trans_[j].from_sec == t.to_sec && sec_trans_[j].to_sec != t.to_sec) {
                left_again = true;
                break;
            }
        }
        if (left_again) {
            continue;
        }
        // (b) no stub writes into that section at or after the hand-off (+ grace)
        if (t.to_sec >= 0 && t.to_sec < (int)sections_.size()) {
            const auto it = last_write_seq_.find(sections_[t.to_sec].start);
            if (it != last_write_seq_.end() && it->second + kGrace > t.seq) {
                continue;
            }
        }
        // (c) the hand-off target must look like a function entry
        const auto off = static_cast<std::size_t>(t.addr - base_);
        if (off + 8 > image.size()) {
            continue;
        }
        const auto* p = image.data() + off;
        const bool prologue =
            (p[0] == 0x55 && p[1] == 0x8b && p[2] == 0xec) ||  // push ebp; mov ebp,esp
            (p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xe5) ||  // push ebp; mov ebp,esp (gcc)
            (p[0] == 0x6a && p[2] == 0x68 && p[7] == 0xe8) ||  // push imm; push imm; call
            (p[0] == 0xe8 && p[5] == 0x6a && p[7] == 0x68);    // call; push; push
        // a hand-off to the very first byte of a section is structural: petite_PEview's
        // true entry is `e8 d7 00 00 00 85 c0` at rva 0x1000, which none of the shape
        // classes cover, and the trail's other transition (0x40a400) is a mid-decode one.
        const bool at_section_start = t.to_sec >= 0 && t.to_sec < (int)sections_.size() &&
                                      t.addr == sections_[t.to_sec].start;
        if (!prologue && !at_section_start) {
            continue;
        }
        return t.addr;
    }
    return 0;
}

std::uint64_t Unpacker::static_oep_from_image(const std::vector<std::uint8_t>& image) const {
    if (packer_ == nullptr || image.empty()) {
        return 0;
    }
    // TAOTE_WRITTEN_RANGES: print the run's ever_written_ ranges at finalize, so a
    // family seam's candidate scan can be prototyped offline against exactly the
    // regions the reference scans (PLAN_UNPACK 0.17hk).
    if (sec_trans_on_) {
        std::fprintf(stderr, "[sectrans] %zu transitions, %zu sections\n", sec_trans_.size(),
                     sections_.size());
        for (std::size_t k = 0; k < sections_.size(); ++k) {
            std::fprintf(stderr, "[sectrans] sec %zu start=0x%llx end=0x%llx written=%d seq=%llu\n", k,
                         (unsigned long long)sections_[k].start, (unsigned long long)sections_[k].end,
                         (int)(sec_written_.count((int)k) > 0),
                         (unsigned long long)(last_write_seq_.count(sections_[k].start)
                                                  ? last_write_seq_.at(sections_[k].start)
                                                  : 0));
        }
        for (const auto& t : sec_trans_) {
            std::fprintf(stderr, "[sectrans] t from=%d to=%d addr=0x%llx seq=%llu\n", t.from_sec, t.to_sec,
                         (unsigned long long)t.addr, (unsigned long long)t.seq);
        }
    }
    if (std::getenv("TAOTE_WRITTEN_RANGES") != nullptr) {
        std::fprintf(stderr, "[written] %zu ranges\n", ever_written_.size());
        for (const auto& r : ever_written_) {
            std::fprintf(stderr, "[written] 0x%llx-0x%llx\n", (unsigned long long)r.first,
                         (unsigned long long)r.second);
        }
    }
    packers::PackerContext ctx;
    ctx.image_ptr = &image;
    ctx.base = base_;
    ctx.image_size = image_size_;
    ctx.packed_ep_va = packed_ep_va_;
    ctx.is_64 = is_64_;
    ctx.debug = opts_.debug;
    ctx.family = opts_.family;
    ctx.packed_path = &opts_.sample_path;
    ctx.sections = sections_;
    // The hint is the LAST hop the run took, ordinal regardless: the ordinal
    // only says how much the stub had written (strength), while the hint is
    // pure geometry - the call's return address sits inside the payload entry
    // (measured +0x16 for both Cacheset and AccessEnum, whose first hop is a
    // junk latch at ordinal 3).
    if (!hop_ledger_.empty()) {
        ctx.hop_hint = hop_ledger_.back();
    }
    return packer_->static_oep_from_image(ctx);
}

UnpackResult Unpacker::finalize(Qiling& ql) {
    // TAOTE_LOWPC: report where control came from when the stage died on a bad fetch
    if (pc_ring_ != nullptr && !pc_ring_->empty()) {
        std::fprintf(stderr, "[lowpc] last pcs:");
        for (const auto p : *pc_ring_) {
            std::fprintf(stderr, " 0x%llx", static_cast<unsigned long long>(p));
        }
        std::fprintf(stderr, "\n");
    }
    // TAOTE_DUMP_RANGE=lo-hi[,lo-hi]: the TERMINAL bytes of any guest range, printed
    // at finalize. The write census (TAOTE_WATCH_RANGE) says where a stub wrote but
    // not what the structure looks like afterwards, and a heap-resident payload is
    // outside the image dump - this is how such a region is read out.
    if (const char* dr = std::getenv("TAOTE_DUMP_RANGE")) {
        const std::string spec = dr;
        std::size_t pos = 0;
        while (pos < spec.size()) {
            const auto comma = spec.find(',', pos);
            const auto end = comma == std::string::npos ? spec.size() : comma;
            unsigned long long lo = 0, hi = 0;
            if (std::sscanf(spec.c_str() + pos, "%llx-%llx", &lo, &hi) == 2 && hi > lo) {
                std::fprintf(stderr, "[dumprng] 0x%llx-0x%llx (%llu bytes)\n", lo, hi, hi - lo);
                try {
                    const auto bytes = ql.mem().read(lo, static_cast<std::size_t>(hi - lo));
                    for (std::size_t i = 0; i < bytes.size(); i += 16) {
                        std::fprintf(stderr, "[dumprng] %08llx:", lo + i);
                        for (std::size_t k = 0; k < 16 && i + k < bytes.size(); ++k) {
                            std::fprintf(stderr, " %02x", bytes[i + k]);
                        }
                        std::fprintf(stderr, "\n");
                    }
                } catch (...) {
                }
            }
            pos = end + 1;
        }
    }
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] finalize begin: imports=%zu\n", imports_.size());
    }
    if (!heap_pages_.empty()) {
        // Walk the recorded pages in runs and look for an MZ/PE pair. The payload a
        // stub decodes into a heap buffer is the only candidate that can never show
        // up in the dumped image itself.
        std::fprintf(stderr, "[heapscan] %zu pages written outside the image\n", heap_pages_.size());
        std::size_t found = 0;
        auto it = heap_pages_.begin();
        while (it != heap_pages_.end()) {
            const std::uint64_t start = *it;
            std::uint64_t end = start + 0x1000;
            while (heap_pages_.count(end) != 0) {
                end += 0x1000;
            }
            const std::size_t span = static_cast<std::size_t>(std::min<std::uint64_t>(end - start, 0x800000));
            std::vector<std::uint8_t> buf;
            try {
                buf = ql.mem().read(start, span);
            } catch (...) {
                buf.clear();
            }
            for (std::size_t i = 0; i + 0x40 < buf.size(); ++i) {
                if (buf[i] == 'M' && buf[i + 1] == 'Z') {
                    const auto lfanew = static_cast<std::size_t>(static_cast<std::uint32_t>(buf[i + 0x3c]) |
                                                                 (static_cast<std::uint32_t>(buf[i + 0x3d]) << 8) |
                                                                 (static_cast<std::uint32_t>(buf[i + 0x3e]) << 16) |
                                                                 (static_cast<std::uint32_t>(buf[i + 0x3f]) << 24));
                    if (i + lfanew + 0x40 < buf.size() && buf[i + lfanew] == 'P' && buf[i + lfanew + 1] == 'E' &&
                        buf[i + lfanew + 2] == 0 && buf[i + lfanew + 3] == 0) {
                        const auto nsec = static_cast<unsigned>(buf[i + lfanew + 6] |
                                                               (buf[i + lfanew + 7] << 8));
                        const auto soh = static_cast<unsigned>(buf[i + lfanew + 20] |
                                                               (buf[i + lfanew + 21] << 8));
                        const std::size_t opt = i + lfanew + 24;
                        std::uint32_t ep = 0;
                        std::uint32_t imgbase = 0;
                        if (opt + 32 < buf.size()) {
                            ep = static_cast<std::uint32_t>(buf[opt + 16]) |
                                 (static_cast<std::uint32_t>(buf[opt + 17]) << 8) |
                                 (static_cast<std::uint32_t>(buf[opt + 18]) << 16) |
                                 (static_cast<std::uint32_t>(buf[opt + 19]) << 24);
                            imgbase = static_cast<std::uint32_t>(buf[opt + 28]) |
                                      (static_cast<std::uint32_t>(buf[opt + 29]) << 8) |
                                      (static_cast<std::uint32_t>(buf[opt + 30]) << 16) |
                                      (static_cast<std::uint32_t>(buf[opt + 31]) << 24);
                        }
                        std::fprintf(stderr,
                                     "[heapscan] PE at 0x%llx (nsec=%u soh=%u ep=0x%x base=0x%x)\n",
                                     static_cast<unsigned long long>(start + i), nsec, soh, ep, imgbase);
                        ++found;
                        i += lfanew;
                    }
                }
            }
            it = heap_pages_.lower_bound(end);
        }
        std::fprintf(stderr, "[heapscan] candidates: %zu\n", found);
    }
    if (!last_pcs_.empty()) {
        const std::size_t n = last_pcs_.size();
        const std::size_t cnt = std::min(last_pc_pos_, n);
        std::fprintf(stderr, "[unpack] last %zu instructions:\n", cnt);
        for (std::size_t i = last_pc_pos_ + n - cnt; i < last_pc_pos_ + n; ++i) {
            std::fprintf(stderr, "[pc] 0x%llx\n", static_cast<unsigned long long>(last_pcs_[i % n]));
        }
    }
    detach_hooks();
    UnpackResult res;
    // an embedded-PE adoption replaces the image and moves base_ (Amber-class
    // payloads run from a heap buffer), so the adopted EP must also suppress the
    // static ladder below
    bool adopted_ep = false;
    res.base = base_;
    res.image_size = image_size_;
    res.is_64 = is_64_;
    res.family = opts_.family;
    try {
        // the terminal image. base_/image_size_ come from install(); a caller that
        // skipped install() (a Phase 0 smoke) gets them here.
        if (base_ == 0) {
            const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
            base_ = pe_loader.pe_image_address();
            image_size_ = pe_loader.pe_image_size();
            const auto raw_ep = pe_loader.entry_point;
            packed_ep_va_ = (raw_ep >= base_ && raw_ep < base_ + image_size_) ? raw_ep : base_ + raw_ep;
            is_64_ = ql.arch().bits() == 64;
        }
        harvest_loader_imports(ql);
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] final pc=%s writes=%llu\n",
                         hex(ql.arch().regs().arch_pc()).c_str(),
                         static_cast<unsigned long long>(write_seq_));
            // TELock SEH-chain probe: dump the fs:[0] chain the stub installed
            try {
                const auto chain = ql.mem().read_ptr(0x6000, 4);
                std::fprintf(stderr, "[unpack] fs:[0] chain=%s\n", hex(chain).c_str());
                if (chain != 0 && chain != 0xffffffffull && chain > 0x1000) {
                    const auto next = ql.mem().read_ptr(chain, 4);
                    const auto handler = ql.mem().read_ptr(chain + 4, 4);
                    std::fprintf(stderr, "[unpack] seh frame @%s next=%s handler=%s\n", hex(chain).c_str(),
                                 hex(next).c_str(), hex(handler).c_str());
                }
            } catch (...) {
                std::fprintf(stderr, "[unpack] fs:[0] read failed\n");
            }
        }
        if (opts_.debug) {
            for (const auto& mi : ql.mem().get_mapinfo()) {
                const auto lo = std::get<0>(mi);
                const auto hi = std::get<1>(mi);
                if (hi > lo) {
                    std::fprintf(stderr, "[unpack] map %s-%s %s %s\n", hex(lo).c_str(), hex(hi).c_str(),
                                 std::get<2>(mi).c_str(), std::get<3>(mi).c_str());
                }
            }
        }

        std::vector<std::uint8_t> image;
        if (base_ != 0 && image_size_ != 0) {
            try {
                image = ql.mem().read(base_, image_size_);
            } catch (...) {
                image.clear();
            }
        }
        if (image.empty()) {
            res.error = "image read failed";
            return res;
        }
        // A packer that wipes the payload image's section headers leaves a dump
        // that parses as a PE whose every section is size 0 at RVA 0, so the
        // claimed entry maps into no section at all. Measured corpus-wide: this
        // affects exactly 106 samples, all Exe32pack (the reference documents the
        // same defect: "Exe32pack zeroes all section headers in the dump"), and
        // the data directories are NOT wiped (import RVA and IAT survive), so the
        // image is otherwise intact. The packed file keeps the layout the stub
        // decodes into, so its own section table is the faithful source: restoring
        // it puts the claimed entry inside .text on 106 of 106 measured samples.
        // Gated twice - only when EVERY dumped section header is zero and the
        // packed table is non-degenerate - so no other image can be touched.
        const auto restore_degenerate_sections = [this](std::vector<std::uint8_t>& img) {
            auto rd16_at = [](const std::vector<std::uint8_t>& v, std::size_t o) -> std::uint16_t {
                if (o + 2 > v.size()) return 0;
                return static_cast<std::uint16_t>(v[o] | (v[o + 1] << 8));
            };
            auto rd32_at = [](const std::vector<std::uint8_t>& v, std::size_t o) -> std::uint32_t {
                if (o + 4 > v.size()) return 0;
                return static_cast<std::uint32_t>(v[o]) | (static_cast<std::uint32_t>(v[o + 1]) << 8) |
                       (static_cast<std::uint32_t>(v[o + 2]) << 16) |
                       (static_cast<std::uint32_t>(v[o + 3]) << 24);
            };
            if (img.size() < 0x40 || img[0] != 'M' || img[1] != 'Z' || opts_.sample_path.empty()) {
                return;
            }
            const auto lf = static_cast<std::size_t>(rd32_at(img, 0x3c));
            if (lf + 0x40 > img.size() || std::memcmp(img.data() + lf, "PE\0\0", 4) != 0) {
                return;
            }
            const auto nsec = static_cast<std::size_t>(rd16_at(img, lf + 6));
            const auto soi = static_cast<std::size_t>(rd16_at(img, lf + 20));
            if (nsec == 0 || nsec > 96) {
                return;
            }
            const auto tbl = lf + 24 + soi;
            if (tbl + nsec * 40 > img.size()) {
                return;
            }
            for (std::size_t i = 0; i < nsec; ++i) {
                const auto o = tbl + i * 40 + 8;
                if (rd32_at(img, o) != 0 || rd32_at(img, o + 4) != 0 || rd32_at(img, o + 8) != 0 ||
                    rd32_at(img, o + 12) != 0) {
                    return;   // not the degenerate case
                }
            }
            std::vector<std::uint8_t> packed;
            try {
                std::ifstream in(opts_.sample_path, std::ios::binary);
                packed.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            } catch (...) {
                return;
            }
            if (packed.size() < 0x40 || packed[0] != 'M' || packed[1] != 'Z') {
                return;
            }
            const auto plf = static_cast<std::size_t>(rd32_at(packed, 0x3c));
            if (plf + 0x40 > packed.size() || std::memcmp(packed.data() + plf, "PE\0\0", 4) != 0) {
                return;
            }
            const auto pnsec = static_cast<std::size_t>(rd16_at(packed, plf + 6));
            const auto psoi = static_cast<std::size_t>(rd16_at(packed, plf + 20));
            if (pnsec != nsec || psoi != soi) {
                return;   // a different layout: not the same image
            }
            const auto ptbl = plf + 24 + psoi;
            if (ptbl + pnsec * 40 > packed.size()) {
                return;
            }
            bool any = false;
            for (std::size_t i = 0; i < pnsec && !any; ++i) {
                const auto o = ptbl + i * 40 + 8;
                any = rd32_at(packed, o) != 0 || rd32_at(packed, o + 4) != 0 ||
                      rd32_at(packed, o + 8) != 0;
            }
            if (!any) {
                return;
            }
            std::memcpy(img.data() + tbl, packed.data() + ptbl, pnsec * 40);
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] restored %zu zeroed section headers from the packed file\n",
                             pnsec);
            }
        };
        restore_degenerate_sections(image);
        // Families whose payload is present but still ENCRYPTED at rest
        // transform the image in place first (the reference's
        // recover_alienyze / family_transform_dump_image): Alienyze's stub XORs
        // with a per-sample single-byte key and only decrypts on demand through
        // guard pages the emulation never trips, so the dump holds ciphertext and
        // every downstream parse (OEP pick, import harvest) would see noise.
        std::vector<std::pair<std::string, std::string>> transform_imports;
        if (packer_ != nullptr) {
            packers::PackerContext tctx;
            tctx.ql = &ql;
            tctx.image_ptr = &image;
            tctx.image_mut = &image;
            tctx.imports_out = &transform_imports;
            tctx.base = base_;
            tctx.image_size = image_size_;
            tctx.packed_ep_va = packed_ep_va_;
            tctx.is_64 = is_64_;
            tctx.debug = opts_.debug;
            tctx.family = opts_.family;
            tctx.sections = sections_;
            tctx.packed_path = &opts_.sample_path;
            if (packer_->transform_image(tctx)) {
                sections_ = tctx.adopted_sections;
            }
            // pairs the transform recovered (Alienyze's `.alien` store): only adds
            // to the recall-based import criterion, never removes
            for (const auto& [dll, fn] : transform_imports) {
                note_import(sanitize_ascii(dll), sanitize_ascii(fn));
            }
            if (opts_.debug && !transform_imports.empty()) {
                std::fprintf(stderr, "[unpack] transform imports: %zu pairs\n",
                             transform_imports.size());
            }
        }
        // Amber-class: the payload PE is assembled in a heap buffer and the
        // original sections are never written, so there is no hop to find — adopt
        // the embedded image (the reference's try_embedded_pe).
        //
        // A junk latch must not block that: Amber's stub writes a few bytes into
        // .text and jumps there BEFORE the payload exists (amber_chgport: the only
        // accepted hop is 0x401661 at write ordinal 25 and it executes a section
        // that was never filled), so "the ledger is empty" is too strong a gate.
        // The engine already defines a STRONG hop as one at write ordinal >= 32
        // (the decode_only precedence rule uses exactly that bound), so adopt over
        // weak hops only and leave every real hand-off alone.
        const bool heap_family = packer_ != nullptr && packer_->heap_payload_family();
        bool ledger_blocks_adoption = !hop_ledger_.empty();
        if (ledger_blocks_adoption && heap_family) {
            bool all_weak = true;
            for (std::size_t i = 0; i < hop_ledger_.size(); ++i) {
                const auto seq = i < hop_write_seq_.size() ? hop_write_seq_[i] : 0;
                if (seq >= 32) {
                    all_weak = false;
                    break;
                }
            }
            ledger_blocks_adoption = !all_weak;
            if (!ledger_blocks_adoption && opts_.debug) {
                std::fprintf(stderr, "[unpack] adoption over %zu weak hop(s) (all seq < 32)\n",
                             hop_ledger_.size());
            }
        }
        if (!ledger_blocks_adoption && packer_ != nullptr) {
            packers::PackerContext actx;
            actx.ql = &ql;
            actx.image_ptr = &image;
            actx.base = base_;
            actx.image_size = image_size_;
            actx.packed_ep_va = packed_ep_va_;
            actx.is_64 = is_64_;
            actx.debug = opts_.debug;
            actx.family = opts_.family;
            actx.sections = sections_;
            if (packer_->adopt_embedded_pe(actx) && !actx.adopted.empty()) {
                image = std::move(actx.adopted);
                // the payload replaced the stub: re-point the engine at it (the
                // hooks are already armed, so only the geometry changes)
                if (actx.adopted_base != 0) {
                    base_ = actx.adopted_base;
                    image_size_ = actx.adopted_size;
                    sections_ = actx.adopted_sections;
                    watched_.clear();
                }
                const auto ep_rva = [&image]() -> std::uint64_t {
                    const auto lfanew = static_cast<std::size_t>(image[0x3c]) |
                                        (static_cast<std::size_t>(image[0x3d]) << 8) |
                                        (static_cast<std::size_t>(image[0x3e]) << 16) |
                                        (static_cast<std::size_t>(image[0x3f]) << 24);
                    const auto o = lfanew + 24 + 16;
                    return static_cast<std::uint64_t>(image[o]) | (static_cast<std::uint64_t>(image[o + 1]) << 8) |
                           (static_cast<std::uint64_t>(image[o + 2]) << 16) |
                           (static_cast<std::uint64_t>(image[o + 3]) << 24);
                }();
                const auto ep_va = base_ + ep_rva;
                if (ep_rva != 0 && ep_va < base_ + image_size_) {
                    meta_oep_ = ep_va;
                    reason_ = "embedded_pe";
                    stages_ = 1;
                    // the adopted image moves the base: the report captured
                    // res.base from the stub before this block, and the static
                    // ladder below would otherwise overwrite the exact EP the
                    // adoption just proved (amber_nbtstat: payload base
                    // 0x5011dea + ep 0x2a65, which is the reference's answer).
                    res.base = base_;
                    adopted_ep = true;
                }
            }
        }
        // the OEP pick over the hop ledger (terminal image in hand)
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] hop ledger (%zu):", hop_ledger_.size());
            for (std::size_t i = 0; i < hop_ledger_.size(); ++i) {
                std::fprintf(stderr, " %s@%llu", hex(hop_ledger_[i]).c_str(),
                             static_cast<unsigned long long>(i < hop_write_seq_.size() ? hop_write_seq_[i] : 0));
            }
            std::fprintf(stderr, "\n[unpack] write ordinals:");
            for (const auto& kv : last_write_seq_) {
                std::fprintf(stderr, " sec=%s:%llu", hex(kv.first).c_str(),
                             static_cast<unsigned long long>(kv.second));
            }
            std::fprintf(stderr, "\n");
        }
        if (hop_ledger_.empty() && !adopted_ep) {
            // no hop: the static entries, then the decoded-section ladder scan
            if (const auto mew = static_oep_; mew != 0) {
                meta_oep_ = mew;
                reason_ = "mew_static_oep";
                stages_ = 1;
            } else if (const auto hdr = header_ep_candidate(image); hdr != 0) {
                meta_oep_ = hdr;
                reason_ = "header_ep";
                stages_ = 1;
            } else if (const auto ladder = static_oep_from_image(image); ladder != 0) {
                meta_oep_ = ladder;
                reason_ = (opts_.family == "NSPack" || opts_.family == "RLPack" || opts_.family == "MPRESS")
                              ? "ladder_passc"
                              : "ladder_scan";
                stages_ = 1;
            }
        }
        if (!hop_ledger_.empty()) {
            const auto picked = pick_oep(image);
            if (picked != meta_oep_) {
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] pick OEP %s (was %s)\n", hex(picked).c_str(),
                                 hex(meta_oep_).c_str());
                }
                meta_oep_ = picked;
            }
            reason_ = "section_hop";
            stages_ = 1;  // one dump, at the picked OEP (the reference's semantics)
        }
        // WinUpack's parked slot outranks both the hop and the ladder when it validates as a
        // payload entry: the stub writes it into its own frame for the hand-off. The LAST
        // validating slot wins (measured: the entry sits at slot [6], behind the image-base and
        // page-end scratch slots of the same frame).
        for (auto it = stack_oep_cands_.rbegin(); it != stack_oep_cands_.rend(); ++it) {
            const std::uint64_t cand = *it;
            const auto rva = cand - base_;
            bool ok = rva + 8 <= image.size();
            if (ok) {
                const auto* b = image.data() + rva;
                const bool c1 = b[0] == 0x55 && b[1] == 0x8b && b[2] == 0xec && b[3] == 0x6a && b[4] == 0xff;
                const bool c3 = b[0] == 0x55 && b[1] == 0x8b && b[2] == 0xec && b[3] == 0x83 &&
                                (b[4] == 0xec || b[4] == 0xc4);
                const bool c2 = b[0] == 0x55 && b[1] == 0x89 && b[2] == 0xe5 && b[3] == 0x83;
                const bool h1 = b[0] == 0x6a && b[2] == 0x68 && b[7] == 0xe8;
                const bool thunk = b[0] == 0xff && b[1] == 0x25;
                ok = c1 || c3 || c2 || h1 || thunk;
            }
            if (ok && cand != meta_oep_) {
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] pick OEP %s (parked stack slot, was %s)\n", hex(cand).c_str(),
                                 hex(meta_oep_).c_str());
                }
                meta_oep_ = cand;
                reason_ = "stack_oep";
                stages_ = 1;
            }
            if (ok) {
                break;
            }
        }
        // the executed-page view: for the JIT-decrypting stubs this is the decoded
        // code; it overlays only pages that were actually executed
        if (exec_view_.size() == image.size() && std::getenv("TAOTE_UNPACK_NO_EXECVIEW") == nullptr) {
            std::size_t restored = 0;
            for (std::size_t page = 0; page < exec_page_seen_.size(); ++page) {
                if (!exec_page_seen_[page]) {
                    continue;
                }
                const auto off = page * 0x1000;
                const auto n = std::min<std::size_t>(0x1000, image.size() - off);
                if (std::memcmp(image.data() + off, exec_view_.data() + off, n) != 0) {
                    std::memcpy(image.data() + off, exec_view_.data() + off, n);
                    ++restored;
                }
            }
            if (opts_.debug && restored != 0) {
                std::fprintf(stderr, "[unpack] exec-page overlay: %zu pages\n", restored);
            }
        }
        // The hand-off snapshot (TAOTE_HANDOFF_SNAP, see Unpacker::handoff_view_): the
        // decoder's output, captured at the moment execution first left the stub.
        if (!handoff_view_.empty() && handoff_view_.size() == image.size()) {
            std::size_t replaced = 0;
            for (std::size_t i = 0; i < image.size(); ++i) {
                if (handoff_view_[i] != image[i]) {
                    image[i] = handoff_view_[i];
                    ++replaced;
                }
            }
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] handoff overlay %zu bytes\n", replaced);
            }
        }
        // The family's terminal OEP fill (the reference's family_terminal_fill):
        // a last-resort correction applied AFTER the pick, because for some
        // families the hop machinery settles on a plausible-looking but wrong
        // entry that no earlier seam can tell from the real one. Runs on the
        // image as it will be dumped (the overlays below only add bytes).
        // TELock's stub records the original entry point as ~EP in its own section table - image base at
        // stub+0x1cc0, ~EP at stub+0x1ce0 - written at run time, so it is read from the first-write shadow
        // (the reference's TELockUnpacker::family_terminal_fill, gated there by SE_TELOCK_CRCFIX). Used only
        // when the run latched nothing usable: our TELock claims are the stub's own first stage (stub+0x37).
        if (opts_.family == "TELock" && shadow_seen_.size() == image_size_ && !sections_.empty()) {
            std::uint64_t st_start = 0;
            for (const auto& ps : sections_) {
                if (packed_ep_va_ >= ps.start && packed_ep_va_ < ps.end) {
                    st_start = ps.start;
                    break;
                }
            }
            const bool junk = meta_oep_ == 0 || (st_start != 0 && meta_oep_ >= st_start);
            if (st_start != 0 && junk && st_start >= base_) {
                const auto st_off = static_cast<std::size_t>(st_start - base_);
                if (st_off + 0x1ce4 <= shadow_seen_.size() && shadow_seen_[st_off + 0x1cc0] &&
                    shadow_seen_[st_off + 0x1ce0]) {
                    std::uint32_t imgb = 0, k3 = 0;
                    std::memcpy(&imgb, &shadow_image_[st_off + 0x1cc0], 4);
                    std::memcpy(&k3, &shadow_image_[st_off + 0x1ce0], 4);
                    std::uint64_t ep = static_cast<std::uint64_t>(static_cast<std::uint32_t>(~k3)) + imgb;
                    // TELock zeroes every section's Characteristics (0xc0000040 on all of them), so an
                    // is_exec test would reject everything here; the structural test is the reference's:
                    // inside the image and outside the stub section.
                    const bool in_image = ep >= base_ && ep - base_ < image_size_;
                    std::uint64_t st_end = st_start + image_size_;
                    for (const auto& ps : sections_) {
                        if (ps.start == st_start) {
                            st_end = ps.end;
                            break;
                        }
                    }
                    const bool in_stub = ep >= st_start && ep < st_end;
                    if (in_image && !in_stub) {
                        if (opts_.debug) {
                            std::fprintf(stderr,
                                         "[unpack] telock oep-from-table: ~K3=0x%x -> 0x%llx (was 0x%llx)\n",
                                         static_cast<unsigned>(~k3 & 0xffffffffu),
                                         static_cast<unsigned long long>(ep),
                                         static_cast<unsigned long long>(meta_oep_));
                        }
                        meta_oep_ = ep;
                        last_oep_ = ep;
                        reason_ = "telock_oep_table";
                    }
                }
            }
        }
        if (packer_ != nullptr && image.size() == image_size_) {
            packers::PackerContext fctx;
            fctx.ql = &ql;
            fctx.image_ptr = &image;
            fctx.base = base_;
            fctx.image_size = image_size_;
            fctx.packed_ep_va = packed_ep_va_;
            fctx.is_64 = is_64_;
            fctx.debug = opts_.debug;
            fctx.family = opts_.family;
            fctx.sections = sections_;
            fctx.reason = reason_;
            fctx.oep_mut = &meta_oep_;
            if (packer_->family_fill(fctx)) {
                reason_ = "family_fill";
                stages_ = 1;
            }
        }
        // MEW's stub memsets the decoded image right before handing off, so the
        // terminal dump is zeroed where the payload lives; the reference keeps the
        // full first-write overlay for this family alone (unpacker.cpp:178-200).
        // the full first-write overlay is right for the families whose decoder
        // writes each decrypted byte once and then RE-ENCRYPTS the page after
        // executing it (MEW memsets the image; PECompact re-encrypts), and wrong
        // for the JIT families that write transient ciphertext pages first
        // (JDPack .text 0.93 -> 0.47, PEtite 0.80 -> 0.69, measured §0.5.3b)
        const bool shadow_family =
            packer_ != nullptr && packer_->shadow_policy() == packers::ShadowPolicy::first_write;
        const bool shadow_all = std::getenv("TAOTE_UNPACK_SHADOW_ALL") != nullptr;
        if ((shadow_family || shadow_all) && shadow_seen_.size() == image.size()) {
            std::size_t restored = 0;
            for (std::size_t i = 0; i < image.size(); ++i) {
                if (shadow_seen_[i] && shadow_image_[i] != image[i]) {
                    image[i] = shadow_image_[i];
                    ++restored;
                }
            }
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] mew shadow overlay %zu bytes\n", restored);
            }
        }
        // Measured: a FULL first-write overlay HURTS the JIT families (JDPack .text
        // similarity 0.93 -> 0.47, PEtite 0.80 -> 0.69) because their stubs write
        // transient ciphertext/decoy pages before the real decode; only the
        // zeros-restore below is safe generically (the reference keeps the full
        // overlay for MEW alone, behind its family seam).
        // the shadow overlay: restore bytes the stub decoded and then wiped
        if (shadow_seen_.size() == image.size()) {
            std::size_t restored = 0;
            for (std::size_t i = 0; i < image.size(); ++i) {
                if (image[i] == 0 && shadow_seen_[i] && shadow_image_[i] != 0) {
                    image[i] = shadow_image_[i];
                    ++restored;
                }
            }
            if (opts_.debug && restored != 0) {
                std::fprintf(stderr, "[unpack] shadow restored %zu bytes\n", restored);
            }
        }
        // Phase 1b: the payload's own import descriptors (the header's directory,
        // then every orphaned chain the stub left behind), then the salvage scan
        harvest_image_imports(image);
        mine_orphan_descriptors(image);
        mine_ordinal_records(image);
        salvage_iat(ql, image);

        // no hop fired: park the OEP on a plausible payload prologue so the
        // artifact is still analysis-usable (the reference's guess_oep,
        // unpacker.cpp:6920-6981)
        if (meta_oep_ == 0) {
            std::uint64_t guess = 0;
            for (const auto& ps : sections_) {
                if (ps.raw == 0 || ps.vsize == 0) {
                    continue;
                }
                const auto span = std::min<std::uint64_t>(ps.end - ps.start, 0x10000);
                std::vector<std::uint8_t> body;
                // Round 177: read the artifact image, not live memory. By this
                // point the exec-page overlay has already put the FIRST-EXECUTION
                // view into `image`, while the live page can hold what the stub
                // re-encrypted (PEtite/JDPack decrypt, run, then re-encrypt). The
                // guess was scanning zeros and parking the OEP 5 bytes past the
                // truth: measured on petite_PEview.exe, where the decoded .text
                // starts `f9 01 0f 84 ...` but live memory read zeros and the
                // guess landed on 0x401005 instead of the section start 0x401000.
                const auto off0 = static_cast<std::size_t>(ps.start - base_);
                if (off0 < image.size()) {
                    const auto n = std::min<std::size_t>(static_cast<std::size_t>(span), image.size() - off0);
                    body.assign(image.begin() + static_cast<std::ptrdiff_t>(off0),
                                image.begin() + static_cast<std::ptrdiff_t>(off0 + n));
                }
                if (body.empty()) {
                    continue;
                }
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] guess scan sec=0x%llx span=0x%llx first8=",
                                 (unsigned long long)ps.start, (unsigned long long)body.size());
                    for (std::size_t k = 0; k < 8 && k < body.size(); ++k) std::fprintf(stderr, "%02x", body[k]);
                    std::fprintf(stderr, "\n");
                }
                // Round 177: the CRT entry shapes BEFORE the loose heuristics.
                // The non-zero-run fallback below skips a real entry whose rel32
                // contains a zero byte: measured on petite_PEview.exe, whose
                // decoded section starts `e8 d7 00 00 00 85 c0 75` (call; test
                // eax,eax - the shape class added in round 134) and which the
                // run heuristic parked at +5, five bytes past the truth.
                for (std::size_t i = 0; i + 8 < body.size(); ++i) {
                    if (body[i] == 0xe8 && ((body[i + 5] == 0x6a && body[i + 7] == 0x68) ||
                                            (body[i + 5] == 0x85 && body[i + 6] == 0xc0))) {
                        guess = ps.start + i;
                        break;
                    }
                }
                if (guess != 0) {
                    break;
                }
                for (std::size_t i = 0; i + 10 < body.size(); ++i) {
                    if (body[i] == 0x6a && body[i + 2] == 0x68 && body[i + 7] == 0xe8) {
                        guess = ps.start + i;
                        break;
                    }
                }
                if (guess == 0) {
                    for (std::size_t i = 0; i + 4 <= body.size();) {
                        if (body[i] != 0) {
                            std::size_t j = i;
                            while (j < body.size() && body[j] != 0) {
                                ++j;
                            }
                            if (j - i >= 4) {
                                guess = ps.start + i;
                                break;
                            }
                            i = j;
                        } else {
                            ++i;
                        }
                    }
                }
                if (guess != 0) {
                    break;
                }
            }
            if (guess != 0) {
                meta_oep_ = guess;
                last_oep_ = guess;
                reason_ = "fallback_guess";
                res.error = "no section hop; OEP guessed";
            }
        }
        if (pet_exit_on_ && !image.empty()) {
            const auto trail = oep_from_transition_trail(image);
            if (trail != 0 && trail != meta_oep_) {
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] petite ep-exit: OEP %s (was %s), %zu transitions\n",
                                 hex(trail).c_str(), hex(meta_oep_).c_str(), sec_trans_.size());
                }
                meta_oep_ = trail;
                last_oep_ = trail;
                reason_ = "petite_ep_exit";
            }
        }
        res.oep = meta_oep_;
        res.oep_last_hop = last_oep_;
        res.stages = stages_;
        res.reason = reason_;

        // ---- the artifacts (the reference's contract, unpacker.cpp:6836-7090)
        const std::string stem = fs::path(opts_.sample_path).filename().string();
        std::error_code ec;
        fs::create_directories(opts_.out_dir, ec);
        // PEtite's per-block relative-displacement pass does not always run in the
        // emulated stub; when it did not, the dump holds the pre-transform stream
        // and every call/jmp/jcc target is off by its own position. Self-gated on
        // the collision share, so an already-correct image is left alone.
        if (opts_.family == "PEtite") {
            undoSelfRelativeBlockTransform(image, res.base);
        }
        const auto dump_path = fs::path(opts_.out_dir) / (stem + "_dump.bin");
        {
            std::ofstream out(dump_path, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(image.data()),
                      static_cast<std::streamsize>(image.size()));
            res.dump_written = static_cast<bool>(out);
            res.dumpfile = dump_path.string();
        }
        // ---- blob-attribution repair -------------------------------------
        // The string-blob miner attributes positionally: every name goes to the
        // DLL marker that preceded it. That is a guess, and when the export
        // database says the assigned DLL does not export the name at all the guess
        // is provably wrong. Measured on Alienyze's near-miss rows (named-only
        // recall before -> after): procexp 0.927 -> 1.000, ADExplorer 0.818 ->
        // 1.000, ADInsight 0.860 -> 1.000, Procmon 0.909 -> 1.000, webhttrack
        // 0.886 -> 0.982.
        //
        // Gated hard, because a loose version of this lost samples (round 41):
        // the repair only fires when the name is unknown to the assigned DLL, the
        // database lists the name at all, and EXACTLY ONE of its owners is a DLL
        // the IMAGE itself names. A pair from descriptor or table evidence is
        // never reached: those attribute through structures, and this pass only
        // looks at names the blob miner filed.
        if (opts_.blob_repair) {
            std::set<std::string> image_dlls;
            for (std::size_t i = 0x200; i + 5 < image.size(); ++i) {
                if (image[i] < 0x21 || image[i] > 0x7E || (i != 0 && image[i - 1] != 0)) {
                    continue;
                }
                std::string s2;
                for (std::size_t k = i; k < image.size() && image[k] >= 0x21 && image[k] <= 0x7E;
                     ++k) {
                    s2.push_back(static_cast<char>(image[k]));
                    if (s2.size() >= 48) {
                        break;
                    }
                }
                std::string low = s2;
                for (auto& ch : low) {
                    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                }
                for (const char* ext : {".dll", ".drv", ".ocx"}) {
                    const auto n = std::strlen(ext);
                    if (low.size() > n && low.compare(low.size() - n, n, ext) == 0) {
                        image_dlls.insert(low.substr(0, low.size() - n));
                        break;
                    }
                }
            }
            std::size_t fixed = 0;
            std::vector<std::pair<std::string, std::string>> out;
            std::set<std::string> seen;
            for (const auto& [dll, name] : imports_) {
                std::string stem_low = dll;
                for (auto& ch : stem_low) {
                    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                }
                for (const char* ext : {".dll", ".drv", ".ocx"}) {
                    const auto n = std::strlen(ext);
                    if (stem_low.size() > n && stem_low.compare(stem_low.size() - n, n, ext) == 0) {
                        stem_low.resize(stem_low.size() - n);
                        break;
                    }
                }
                std::string use = dll;
                if (name.rfind("ordinal_", 0) != 0 && !image_dlls.empty()) {
                    const auto owners = api_owners(name);
                    const bool known_to_assigned =
                        std::find(owners.begin(), owners.end(), stem_low) != owners.end();
                    if (!owners.empty() && !known_to_assigned) {
                        std::string only;
                        std::size_t hits = 0;
                        for (const auto& o : owners) {
                            if (image_dlls.count(o) != 0) {
                                only = o;
                                ++hits;
                            }
                        }
                        if (hits == 1) {
                            use = only + ".dll";
                            ++fixed;
                        }
                    }
                }
                if (seen.insert(use + "\n" + name).second) {
                    out.emplace_back(use, name);
                }
            }
            if (fixed != 0) {
                if (opts_.debug) {
                    std::fprintf(stderr, "[unpack] blob repair: %zu pairs re-attributed (%zu -> %zu)\n",
                                 fixed, imports_.size(), out.size());
                }
                imports_.swap(out);
            }
        }

        const auto meta_path = fs::path(opts_.out_dir) / (stem + "_dump.bin.meta.json");
        {
            nlohmann::json meta;
            meta["base"] = hex(res.base);
            meta["oep"] = hex(res.oep);
            meta["oep_last_hop"] = hex(res.oep_last_hop);
            meta["is_64"] = res.is_64;
            meta["stages"] = res.stages;
            meta["reason"] = sanitize_ascii(res.reason);
            meta["family"] = sanitize_ascii(res.family);
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] meta imports=%zu\n", imports_.size());
            }
            nlohmann::json imps = nlohmann::json::array();
            for (const auto& pr : imports_) {
                imps.push_back({sanitize_ascii(pr.first), sanitize_ascii(pr.second)});
            }
            meta["imports"] = imps;
            std::ofstream out(meta_path, std::ios::binary | std::ios::trunc);
            out << meta.dump(1) << "\n";
            res.metafile = meta_path.string();
        }
        // The artifact contract: a written dump and meta must be NON-EMPTY. A full
        // or quota-limited filesystem otherwise produces 0-byte files with rc=0,
        // which grades as a per-row capability delta in both directions (the
        // reference's harness hit exactly this and manufactured a fake signal).
        {
            std::error_code fec;
            const auto dsz = fs::file_size(dump_path, fec);
            const auto d_ok = !fec && dsz > 0;
            fec.clear();
            const auto msz = fs::file_size(meta_path, fec);
            const auto m_ok = !fec && msz > 0;
            if (!d_ok || !m_ok) {
                throw QlErrorBase("artifact write failed: " + dump_path.string() + " (" +
                                  std::to_string(d_ok ? dsz : 0) + " bytes), " +
                                  meta_path.string() + " (" + std::to_string(m_ok ? msz : 0) +
                                  " bytes)");
            }
        }
        res.imports = imports_;

        // ---- the rebuild (§1.8)
        if (opts_.rebuild) {
            RebuildInput in;
            in.image = std::move(image);
            in.base = res.base;
            in.oep_va = res.oep;
            in.is_64 = res.is_64;
            in.imports = imports_;
            in.header_snapshot = header_snapshot_;
            // the salvage scan's code-referenced IAT slots win over the descriptor
            // walk's FirstThunk (which names the stub's table for UPX-style images);
            // fall back to the descriptor walk for any dll the salvage never saw.
            {
                auto iat_map = image_iat_rva_by_dll_;
                for (const auto& [dll, rva] : salvaged_iat_rva_by_dll_) {
                    iat_map[dll] = rva;
                }
                in.iat_rva_by_dll = std::move(iat_map);
            }
            auto rebuilt = rebuild_pe(in);
            if (!rebuilt.empty()) {
                const auto exe_path = fs::path(opts_.out_dir) / (stem + "_unpacked.exe");
                std::ofstream out(exe_path, std::ios::binary | std::ios::trunc);
                out.write(reinterpret_cast<const char*>(rebuilt.data()),
                          static_cast<std::streamsize>(rebuilt.size()));
                res.rebuilt = static_cast<bool>(out);
                res.outfile = exe_path.string();
            } else {
                // the reference's degenerate-path contract (Exe32pack): when the
                // header cannot be rebuilt, the dump IS the artifact
                const auto exe_path = fs::path(opts_.out_dir) / (stem + "_unpacked.exe");
                // A memory image is flat (file offset == RVA), but the section table it
                // carries still describes the packed file, so written verbatim the entry
                // maps nowhere (corpus r105: alienyze_tinytask.exe "entry-not-mapped").
                const auto flat = flatten_image_pe(in.image);
                const auto& bytes = flat.empty() ? in.image : flat;
                std::ofstream out(exe_path, std::ios::binary | std::ios::trunc);
                out.write(reinterpret_cast<const char*>(bytes.data()),
                          static_cast<std::streamsize>(bytes.size()));
                res.rebuilt = static_cast<bool>(out);
                res.outfile = exe_path.string();
                if (res.reason.empty()) {
                    res.reason = "dump_verbatim";
                }
                res.error += res.error.empty() ? "rebuild failed; emitted the dump" : "; rebuild failed";
            }
        }
    } catch (const QlErrorBase& e) {
        res.error = e.what();
    } catch (const std::exception& e) {
        res.error = e.what();
    } catch (...) {
        res.error = "unpack finalize failed";
    }
    return res;

    // A corrupt-header input can fail before any stage runs (the loader refuses
    // it, e.g. an absurd section count), which used to print "reason=" with
    // nothing after it. Every specific label above wins; this only names a
    // state nothing else claimed.
    if (res.reason.empty()) {
        res.reason = res.base == 0 ? "init_failed" : "no_hop";
    }
}

// ---------------------------------------------------------------------------
// the hand-rolled rebuilder (PLAN_UNPACK §1.8, the reference's reconstruct()
// unpacker.cpp:11581-13700). Every offset read is bounds-checked: the input is
// attacker-controlled memory.
// ---------------------------------------------------------------------------
namespace {

std::uint16_t rd16(const std::vector<std::uint8_t>& v, std::size_t o) {
    if (o + 2 > v.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(v[o] | (v[o + 1] << 8));
}

std::uint32_t rd32(const std::vector<std::uint8_t>& v, std::size_t o) {
    if (o + 4 > v.size()) {
        return 0;
    }
    return static_cast<std::uint32_t>(v[o]) | (static_cast<std::uint32_t>(v[o + 1]) << 8) |
           (static_cast<std::uint32_t>(v[o + 2]) << 16) | (static_cast<std::uint32_t>(v[o + 3]) << 24);
}

void wr16(std::vector<std::uint8_t>& v, std::size_t o, std::uint16_t x) {
    if (o + 2 > v.size()) {
        return;
    }
    v[o] = static_cast<std::uint8_t>(x & 0xff);
    v[o + 1] = static_cast<std::uint8_t>((x >> 8) & 0xff);
}

void wr32(std::vector<std::uint8_t>& v, std::size_t o, std::uint32_t x) {
    if (o + 4 > v.size()) {
        return;
    }
    v[o] = static_cast<std::uint8_t>(x & 0xff);
    v[o + 1] = static_cast<std::uint8_t>((x >> 8) & 0xff);
    v[o + 2] = static_cast<std::uint8_t>((x >> 16) & 0xff);
    v[o + 3] = static_cast<std::uint8_t>((x >> 24) & 0xff);
}

struct SecRec {
    std::size_t entry_off = 0;
    std::uint32_t va = 0;
    std::uint32_t vsize = 0;
    std::uint32_t chars = 0;
    std::uint32_t raw_ptr = 0;
    std::uint32_t raw_size = 0;
};

}  // namespace

namespace {

struct RelSite {
    std::uint32_t off;   // offset inside the section
    std::uint32_t disp_off;  // 1 for E8/E9, 2 for 0F 8x
    std::uint32_t next;  // instruction length: 5 or 6
};

// scan exactly like the stub does: after a relative field, skip the instruction
void scan_rel_sites(const std::uint8_t* p, std::size_t n, std::vector<RelSite>& out) {
    std::size_t i = 0;
    while (i + 6 <= n) {
        if (p[i] == 0xe8 || p[i] == 0xe9) {
            out.push_back({static_cast<std::uint32_t>(i), 1, 5});
            i += 5;
        } else if (p[i] == 0x0f && p[i + 1] >= 0x80 && p[i + 1] <= 0x8f) {
            out.push_back({static_cast<std::uint32_t>(i), 2, 6});
            i += 6;
        } else {
            ++i;
        }
    }
}

// the share of call targets that more than one call site reaches
double collide_share(const std::uint8_t* p, std::size_t n, const std::vector<RelSite>& sites,
                     std::uint64_t sec_va, std::uint64_t lo, std::uint64_t hi, bool undo) {
    std::unordered_map<std::uint64_t, int> hits;
    for (const auto& s : sites) {
        std::int32_t d = 0;
        std::memcpy(&d, p + s.off + s.disp_off, 4);
        std::int64_t disp = d;
        if (undo) {
            disp -= static_cast<std::int64_t>(s.off);
        }
        const std::int64_t t = static_cast<std::int64_t>(sec_va + s.off + s.next) + disp;
        if (t < static_cast<std::int64_t>(lo) || t >= static_cast<std::int64_t>(hi)) {
            continue;
        }
        ++hits[static_cast<std::uint64_t>(t)];
    }
    std::size_t tot = 0;
    std::size_t shared = 0;
    for (const auto& kv : hits) {
        tot += static_cast<std::size_t>(kv.second);
        if (kv.second > 1) {
            shared += static_cast<std::size_t>(kv.second);
        }
    }
    return tot == 0 ? 0.0 : static_cast<double>(shared) / static_cast<double>(tot);
}

}  // namespace

std::size_t undoSelfRelativeBlockTransform(std::vector<std::uint8_t>& image, std::uint64_t base) {
    // the MZ is deliberately NOT required: PEtite's stub zeroes the in-memory header
    // (the dump starts 00 5A) and rebuild_pe restores it from the header snapshot, so
    // the section table is still readable here even though the MZ is gone.
    if (image.size() < 0x200) {
        return 0;
    }
    const std::size_t e_lfanew = rd32(image, 0x3c);
    if (e_lfanew + 0x18 > image.size() || image[e_lfanew] != 'P' || image[e_lfanew + 1] != 'E') {
        return 0;
    }
    const std::size_t coff = e_lfanew + 4;
    const std::size_t opt_off = coff + 20;
    const std::uint16_t opt_size = rd16(image, coff + 16);
    if (opt_off + opt_size > image.size()) {
        return 0;
    }
    const std::uint16_t magic = rd16(image, opt_off);
    if (magic != 0x10b && magic != 0x20b) {
        return 0;
    }
    const std::uint32_t sizeimg = rd32(image, opt_off + 0x38);
    const std::uint32_t n_sec = rd16(image, coff + 2);
    if (n_sec == 0 || n_sec > 96) {
        return 0;
    }
    const std::size_t sec_table = opt_off + opt_size;
    const std::uint64_t lo = base;
    const std::uint64_t hi = base + (sizeimg != 0 ? sizeimg : image.size());
    std::size_t rewritten = 0;
    for (std::uint32_t i = 0; i < n_sec; ++i) {
        const std::size_t e = sec_table + static_cast<std::size_t>(i) * 40;
        if (e + 40 > image.size()) {
            break;
        }
        const std::uint32_t vsize = rd32(image, e + 8);
        const std::uint32_t va = rd32(image, e + 12);
        if (vsize == 0) {
            continue;
        }
        // PAGE granularity, not section: PEtite's dump keeps the packed section table
        // (characteristics are often zeroed, and one section covers the decoded payload
        // AND the stub), so the code region is only distinguishable by the gate. Page
        // decisions also keep the stub's own code out: on petite_rrdec the payload pages
        // measure c0~0.00 -> c1~0.55 while the stub page measures 0.154 -> 0.000.
        const std::uint64_t avail = va < image.size() ? image.size() - va : 0;
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(vsize, avail));
        std::size_t pages = 0;
        // ONE continuous scan of the section: a page-local scan desynchronises at page
        // boundaries and leaves a few dispatches uncorrected (measured: rrdec 9 instead
        // of 4, 7z 25 instead of 0). The gate is still decided per page.
        std::vector<RelSite> all_sites;
        scan_rel_sites(image.data() + va, n, all_sites);
        if (all_sites.size() < 16) {
            continue;
        }
        const auto sec_va = base + va;
        // Section-level decision first (this is the statistic validated over all 73 PEtite
        // rows: 43 sections improve, 30 are already correct, 0 wrong either way). A page
        // decision alone fires on already-correct code, where the collision share is
        // already high (measured false positives: c0 = 0.375/0.533/0.396), so pages are
        // only rewritten inside a section the gate accepts AND where c0 is near zero.
        const double s0 = collide_share(image.data() + va, n, all_sites, sec_va, lo, hi, false);
        const double s1 = collide_share(image.data() + va, n, all_sites, sec_va, lo, hi, true);
        if (s1 - s0 < 0.05) {
            continue;
        }
        for (std::size_t poff = 0; poff < n; poff += 0x1000) {
            std::vector<RelSite> sites;
            for (const auto& s : all_sites) {
                if (s.off >= poff && s.off < poff + 0x1000) {
                    sites.push_back(s);
                }
            }
            if (sites.size() < 16) {
                continue;
            }
            const double c0 = collide_share(image.data() + va, n, sites, sec_va, lo, hi, false);
            const double c1 = collide_share(image.data() + va, n, sites, sec_va, lo, hi, true);
            if (c0 >= 0.10 || c1 - c0 < 0.05) {
                continue;  // already correct here, or not a transformed code page
            }
            std::uint8_t* p = image.data() + va;
            for (const auto& s : sites) {
                std::int32_t d = 0;
                std::memcpy(&d, p + s.off + s.disp_off, 4);
                const std::int32_t nd =
                    static_cast<std::int32_t>(static_cast<std::uint32_t>(d) - s.off);
                std::memcpy(p + s.off + s.disp_off, &nd, 4);
            }
            ++pages;
            if (std::getenv("TAOTE_UNPACK_DEBUG") != nullptr) {
                std::fprintf(stderr,
                             "[unpack] petite: undo block transform in section %u page %#zx "
                             "(%zu sites, collide %.3f -> %.3f)\n",
                             i, poff, sites.size(), c0, c1);
            }
        }
        if (pages != 0) {
            ++rewritten;
        }
    }
    return rewritten;
}

std::vector<std::uint8_t> flatten_image_pe(const std::vector<std::uint8_t>& image) {
    std::vector<std::uint8_t> mem = image;
    if (mem.size() < 0x200 || mem[0] != 'M' || mem[1] != 'Z') {
        return {};
    }
    const std::size_t e_lfanew = rd32(mem, 0x3c);
    if (e_lfanew + 0x18 > mem.size() || mem[e_lfanew] != 'P' || mem[e_lfanew + 1] != 'E') {
        return {};
    }
    const std::size_t coff = e_lfanew + 4;
    const std::size_t opt_off = coff + 20;
    const std::uint16_t opt_size = rd16(mem, coff + 16);
    if (opt_off + opt_size > mem.size()) {
        return {};
    }
    const std::uint16_t magic = rd16(mem, opt_off);
    if (magic != 0x10b && magic != 0x20b) {
        return {};
    }
    const std::uint32_t file_align = rd32(mem, opt_off + 0x24) ? rd32(mem, opt_off + 0x24) : 0x200;
    const std::uint32_t n_sec = rd16(mem, coff + 2);
    if (n_sec == 0 || n_sec > 96) {
        return {};
    }
    const std::size_t sec_table = opt_off + opt_size;
    std::uint32_t first_va = 0;
    int changed = 0;
    for (std::uint32_t i = 0; i < n_sec; ++i) {
        const std::size_t e = sec_table + static_cast<std::size_t>(i) * 40;
        if (e + 40 > mem.size()) {
            return {};
        }
        const std::uint32_t vsize = rd32(mem, e + 8);
        const std::uint32_t va = rd32(mem, e + 12);
        const std::uint32_t rsz = rd32(mem, e + 16);
        const std::uint32_t rpt = rd32(mem, e + 20);
        if (i == 0) {
            first_va = va;
        }
        const std::uint32_t content = vsize != 0 ? vsize : rsz;
        const std::uint32_t flat_rsz = align_up(content, file_align);
        const std::uint64_t avail = va < mem.size() ? mem.size() - va : 0;
        // never claim bytes past EOF: the artifact must stay a well-formed PE
        if (flat_rsz == 0 || flat_rsz > avail) {
            continue;
        }
        if (rpt != va || rsz != flat_rsz) {
            wr32(mem, e + 16, flat_rsz);
            wr32(mem, e + 20, va);
            ++changed;
        }
    }
    if (changed == 0) {
        return {};
    }
    const std::uint32_t soh =
        align_up(static_cast<std::uint32_t>(std::min<std::size_t>(first_va, 0x10000)), file_align);
    if (soh != 0) {
        wr32(mem, opt_off + 0x3c, soh);  // SizeOfHeaders, same offset in PE32 and PE32+
    }
    return mem;
}

std::vector<std::uint8_t> rebuild_pe(const RebuildInput& in) {
    std::vector<std::uint8_t> mem = in.image;
    if (mem.size() <= 0x400) {
        return {};
    }
    // A degenerate section table (Exe32pack: every raw size 0 and a header that
    // cannot be laid out) leaves the dump as the only faithful artifact — the
    // reference's RECON_STAGE_EXE32_DEGENERATE path. Detected after the layout
    // below by `degenerate`, which returns the image verbatim.
    // anti-emu stubs zero the in-memory MZ: restore the packed file's header
    if (!(mem[0] == 'M' && mem[1] == 'Z')) {
        if (in.header_snapshot.size() >= 2 && in.header_snapshot[0] == 'M' && in.header_snapshot[1] == 'Z') {
            const auto n = std::min(in.header_snapshot.size(), mem.size());
            std::copy(in.header_snapshot.begin(), in.header_snapshot.begin() + static_cast<std::ptrdiff_t>(n),
                      mem.begin());
        }
    }
    if (!(mem[0] == 'M' && mem[1] == 'Z')) {
        return {};
    }
    const std::size_t e_lfanew = rd32(mem, 0x3c);
    if (e_lfanew + 0x18 > mem.size() || mem[e_lfanew] != 'P' || mem[e_lfanew + 1] != 'E') {
        return {};
    }
    const std::size_t coff = e_lfanew + 4;
    const std::size_t opt_off = coff + 20;
    const std::uint16_t opt_size = rd16(mem, coff + 16);
    if (opt_off + opt_size > mem.size()) {
        return {};
    }
    const std::uint16_t magic = rd16(mem, opt_off);
    const bool is64 = magic == 0x20b;
    if (!(magic == 0x10b || magic == 0x20b)) {
        return {};
    }
    const std::uint32_t sec_align = rd32(mem, opt_off + 0x20) ? rd32(mem, opt_off + 0x20) : 0x1000;
    const std::uint32_t file_align = rd32(mem, opt_off + 0x24) ? rd32(mem, opt_off + 0x24) : 0x200;

    // data-directory base, normalised to the 16-entry layout on a corrupt header
    // (the WinUpack case, unpacker.cpp:11720-11735)
    const std::uint32_t std_opt_size = is64 ? 0xF0 : 0xE0;
    std::size_t dd_base = 0;
    const std::uint32_t n_rva = rd32(mem, opt_off + (is64 ? 0x6c : 0x5c));
    if (n_rva != 16 && opt_size >= std_opt_size) {
        dd_base = opt_off + (is64 ? 0x70 : 0x60);
        wr32(mem, opt_off + (is64 ? 0x6c : 0x5c), 16);
    } else if (n_rva <= 16 && 8ull * n_rva <= opt_size) {
        dd_base = opt_off + opt_size - 8ull * n_rva;
    } else {
        dd_base = opt_off + (is64 ? 0x70 : 0x60);
        wr32(mem, opt_off + (is64 ? 0x6c : 0x5c), 16);
    }

    // the section table, clamped (anti-emu headers claim 0xFFCD sections,
    // unpacker.cpp:11745-11770)
    const std::size_t sec_table = opt_off + opt_size;
    std::uint32_t n_sec = rd16(mem, coff + 2);
    if (n_sec == 0 || n_sec > 96) {
        std::uint32_t alt = 0;
        if (in.header_snapshot.size() >= 0x40) {
            const std::uint32_t elf = rd32(in.header_snapshot, 0x3c);
            if (elf + 8 <= in.header_snapshot.size()) {
                alt = rd16(in.header_snapshot, elf + 6);
            }
        }
        n_sec = (alt > 0 && alt <= 96) ? alt : 16u;
        wr16(mem, coff + 2, static_cast<std::uint16_t>(n_sec));
    }
    std::vector<SecRec> secs;
    std::uint32_t max_va_end = 0;
    for (std::uint32_t i = 0; i < n_sec; ++i) {
        const std::size_t e = sec_table + static_cast<std::size_t>(i) * 40;
        if (e + 40 > mem.size()) {
            break;
        }
        SecRec s;
        s.entry_off = e;
        s.vsize = rd32(mem, e + 8);
        s.va = rd32(mem, e + 12);
        s.chars = rd32(mem, e + 36);
        // the UPX decompression stub clears MEM_WRITE on the executable sections
        // in the dump's in-memory header, leaving the payload's .data region
        // read-only. Restore the characteristics the loader actually mapped them
        // with from the packed file's header snapshot (RWX), and write them back
        // below — the section headers are otherwise copied verbatim from mem.
        if (in.header_snapshot.size() > e + 36 + 4) {
            s.chars = rd32(in.header_snapshot, e + 36);
        }
        secs.push_back(s);
        const std::uint64_t end = static_cast<std::uint64_t>(s.va) + s.vsize;
        if (end > max_va_end) {
            max_va_end = static_cast<std::uint32_t>(std::min<std::uint64_t>(end, 0xffffffffull));
        }
    }
    if (secs.empty()) {
        return {};
    }

    // the OEP as an RVA (some families store one already, unpacker.cpp:11780-11795)
    std::uint32_t oep_rva = 0;
    if (in.oep_va != 0) {
        if (in.oep_va >= in.base && in.oep_va - in.base < static_cast<std::uint64_t>(max_va_end) + 0x100000) {
            oep_rva = static_cast<std::uint32_t>(in.oep_va - in.base);
        } else if (in.oep_va < static_cast<std::uint64_t>(max_va_end) + 0x100000) {
            oep_rva = static_cast<std::uint32_t>(in.oep_va);
        }
    }

    // ---- the .pgimp blob (Scylla's ImportRebuilder: iat/import_rebuilder)
    const auto groups = iat::group_imports(in.imports);
    const std::uint32_t new_va = align_up(max_va_end, sec_align);
    const auto section = iat::build_import_section(groups, new_va, in.iat_rva_by_dll);
    if (section.blob.empty()) {
        return {};
    }
    const std::uint32_t iat_rva = section.iat_rva;
    const std::uint32_t iat_size = section.iat_size;
    const std::uint32_t new_vsize = static_cast<std::uint32_t>(section.blob.size());

    // ---- file layout (unpacker.cpp:13630-13680)
    const std::uint32_t n_sec_total = static_cast<std::uint32_t>(secs.size()) + 1;
    const std::size_t header_end = sec_table + static_cast<std::size_t>(n_sec_total) * 40;
    const std::uint32_t size_of_headers =
        align_up(static_cast<std::uint32_t>(std::min<std::size_t>(header_end, 0x10000)), file_align);

    std::uint32_t cursor = size_of_headers;
    for (auto& s : secs) {
        const std::uint64_t avail = mem.size() > s.va ? mem.size() - s.va : 0;
        std::uint64_t content = std::min<std::uint64_t>(s.vsize, avail);
        if (content == 0) {
            content = s.vsize;
        }
        s.raw_ptr = cursor;
        s.raw_size = align_up(static_cast<std::uint32_t>(std::min<std::uint64_t>(content, 0x7fffffff)), file_align);
        cursor += s.raw_size;
    }
    const std::uint32_t pgimp_raw_ptr = cursor;
    const std::uint32_t pgimp_raw_size = align_up(new_vsize, file_align);

    // headers + every section's raw + the .pgimp raw
    std::vector<std::uint8_t> out(static_cast<std::size_t>(pgimp_raw_ptr) + pgimp_raw_size, 0);

    // headers
    const std::size_t hdr_n = std::min<std::size_t>(size_of_headers, mem.size());
    std::copy(mem.begin(), mem.begin() + static_cast<std::ptrdiff_t>(hdr_n), out.begin());

    // section headers + raw content
    for (const auto& s : secs) {
        wr32(out, s.entry_off + 16, s.raw_size);
        wr32(out, s.entry_off + 20, s.raw_ptr);
        wr32(out, s.entry_off + 36, s.chars);
        const std::uint64_t avail = mem.size() > s.va ? mem.size() - s.va : 0;
        const std::uint64_t content = std::min<std::uint64_t>(s.raw_size, avail);
        if (content > 0 && static_cast<std::size_t>(s.raw_ptr) + content <= out.size()) {
            std::copy(mem.begin() + static_cast<std::ptrdiff_t>(s.va),
                      mem.begin() + static_cast<std::ptrdiff_t>(s.va + content),
                      out.begin() + static_cast<std::ptrdiff_t>(s.raw_ptr));
        }
    }
    // the .pgimp section header
    {
        const std::size_t e = sec_table + secs.size() * 40;
        if (e + 40 <= out.size()) {
            const char name[8] = {'.', 'p', 'g', 'i', 'm', 'p', 0, 0};
            std::memcpy(&out[e], name, 8);
            wr32(out, e + 8, new_vsize);                 // VirtualSize
            wr32(out, e + 12, new_va);                   // VirtualAddress
            wr32(out, e + 16, pgimp_raw_size);           // SizeOfRawData
            wr32(out, e + 20, pgimp_raw_ptr);            // PointerToRawData
            wr32(out, e + 36, 0x40000040);               // INITIALIZED_DATA | READ
        }
        std::copy(section.blob.begin(), section.blob.end(),
                  out.begin() + static_cast<std::ptrdiff_t>(pgimp_raw_ptr));
    }

    // the optional header fields the loader reads
    const std::uint32_t size_of_image = align_up(new_va + new_vsize, sec_align);
    wr32(out, opt_off + 0x10, oep_rva);              // AddressOfEntryPoint
    wr32(out, opt_off + 0x38, size_of_image);        // SizeOfImage
    wr32(out, opt_off + 0x3c, size_of_headers);      // SizeOfHeaders
    wr32(out, opt_off + 0x40, 0);                    // CheckSum
    wr16(out, coff + 2, static_cast<std::uint16_t>(secs.size() + 1));
    // data directories: import = .pgimp descriptors, IAT = the first thunk array
    wr32(out, dd_base + 1 * 8, new_va + static_cast<std::uint32_t>(section.descriptors_off));
    wr32(out, dd_base + 1 * 8 + 4, static_cast<std::uint32_t>(section.descriptors_size));
    if (iat_rva != 0) {
        wr32(out, dd_base + 12 * 8, iat_rva);
        wr32(out, dd_base + 12 * 8 + 4, iat_size);
    }
    // The degenerate-path contract (the reference's RECON_STAGE_EXE32_DEGENERATE):
    // when the section table carried no bytes (Exe32pack — every VirtualSize/raw
    // pair is inconsistent), the laid-out file holds nothing but headers and the
    // faithful artifact is the image dump itself, whose own section table still
    // points into it and parses as a file-layout PE.
    if (out.size() < in.image.size() / 4) {
        return in.image;
    }
    return out;
}

}  // namespace unpack
}  // namespace qiling
