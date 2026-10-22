// qiling/unpack/unpack.cpp — the generic unpacker core (PLAN_UNPACK.md §1.3-§1.8).
//
// Ported from ../pegasus/src/unpacker/unpacker.cpp; the plan records the
// file:line map for every decision below. Phase 1 scope: section classification
// + watch set, write-claim tracking, section-hop OEP detection with an accept
// gate, image dump + meta sidecar, and a hand-rolled PE rebuilder that appends a
// .pgimp import section.
#include "qiling/unpack/unpack.hpp"

#include <LIEF/PE.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
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

Unpacker::Unpacker(UnpackOptions opts) : opts_(std::move(opts)) {}

// hooks_ is cleared by finalize()/detach_hooks() while the engine is alive; a
// HookRet destructor after that would call uc_hook_del on a dead engine
Unpacker::~Unpacker() { hooks_.clear(); }



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
    if (!fs::exists(path, ec)) {
        try {
            fs::create_directories(dir, ec);
            auto factory = LIEF::PE::Factory::create(LIEF::PE::PE_TYPE::PE32_PLUS);
            std::vector<std::uint8_t> code(16, 0xC3);
            LIEF::PE::Section text(".text", code);
            factory->add_section(text);
            auto bin = factory->get();
            std::uint32_t text_rva = 0;
            for (const auto& sec : bin->sections()) {
                if (sec.name() == ".text") {
                    text_rva = sec.virtual_address();
                }
            }
            LIEF::PE::Export exp(name, {LIEF::PE::ExportEntry("decoy_export", text_rva)});
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
            const auto hit = handle_names_.find(hmod);
            if (hit != handle_names_.end()) {
                dll = hit->second;
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
    ql_ = &ql;
    classify_sections(ql);

    // no hops at all (the Phase 0 artifact-only mode): the dump is the entry
    // state, which is what "no unpacking" means for the scoreboard
    if (!opts_.enable_hop) {
        return;
    }

    // MEW static OEP parse: packed EP `e9 rel32` -> stub `be imm32`; the dword at
    // imm32+4 is the original OEP (mew_unpacker.cpp:28-64)
    if (opts_.family == "MEW") {
        try {
            const auto ep = ql.mem().read(packed_ep_va_, 5);
            if (ep.size() == 5 && ep[0] == 0xe9) {
                const auto rel = static_cast<std::int32_t>(
                    static_cast<std::uint32_t>(ep[1]) | (static_cast<std::uint32_t>(ep[2]) << 8) |
                    (static_cast<std::uint32_t>(ep[3]) << 16) | (static_cast<std::uint32_t>(ep[4]) << 24));
                const auto stub_va = static_cast<std::uint64_t>(static_cast<std::int64_t>(packed_ep_va_ + 5) + rel);
                const auto st = ql.mem().read(stub_va, 5);
                if (st.size() == 5 && st[0] == 0xbe) {
                    const auto table = static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(st[1]) | (static_cast<std::uint32_t>(st[2]) << 8) |
                        (static_cast<std::uint32_t>(st[3]) << 16) | (static_cast<std::uint32_t>(st[4]) << 24));
                    const auto ov = ql.mem().read(table + 4, 4);
                    if (ov.size() == 4) {
                        const auto va = static_cast<std::uint64_t>(
                            static_cast<std::uint32_t>(ov[0]) | (static_cast<std::uint32_t>(ov[1]) << 8) |
                            (static_cast<std::uint32_t>(ov[2]) << 16) | (static_cast<std::uint32_t>(ov[3]) << 24));
                        if (va >= base_ && va < base_ + image_size_) {
                            mew_oep_candidate_ = va;
                            if (opts_.debug) {
                                std::fprintf(stderr, "[unpack] mew static OEP %s\n", hex(va).c_str());
                            }
                        }
                    }
                }
            }
        } catch (...) {
            mew_oep_candidate_ = 0;
        }
    }

    install_gpa_sentinel(ql);

    // unpack mode: an unhandled access violation whose guest handler answered
    // EXCEPTION_CONTINUE_SEARCH resumes at the saved CONTEXT (the reference's
    // raw-chain continue) instead of ending the run. The handler has usually
    // patched the trapping instruction, so the retry progresses; the dispatch's
    // identical-fault repeat guard bounds a handler that fixes nothing.
    try {
        ql.os<os::windows::QlOsWindows>().set_seh_continue_on_exhausted(true);
    } catch (...) {
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
                    std::fprintf(stderr, "[unpack] insn_invalid pc=%s b=0x%02x\n", hex(pc).c_str(),
                                 static_cast<unsigned>(b));
                }
                if (b == 0xf1) {
                    // #DB (ICEBP) is a trap: Eip advances to the next
                    // instruction before the handler runs, exactly like real
                    // x86 (the reference's dispatch_seh(0x80000004, eip+1))
                    regs.set_arch_pc(pc + 1);
                    (void)os.seh_dispatch_cpu(0x80000004u);
                    return QL_HOOK_BLOCK;
                }
                if (!os.seh_dispatch_cpu(0xC000001Du)) {
                    // nothing handled the #UD: surface the original stop
                    ql_->emu_stop();
                }
                return QL_HOOK_BLOCK;
            }, 1, 0));
        if (invalid_hook->obj() != nullptr) {
            hooks_.push_back(std::move(invalid_hook));
        }
    }

    for (const auto& ps : watched_) {
        const std::uint64_t start = ps.start;
        const std::uint64_t end = ps.end;

        // the write-claim hook: first write into a watched section claims it
        auto write_hook = std::make_shared<HookRet>(
            ql.hook_mem_write([this, start](int /*access*/, std::uint64_t addr, std::uint32_t size,
                                            std::int64_t value) -> int {
                (void)start;
                return on_section_write(0, addr, size, static_cast<std::uint64_t>(value));
            }, start, end));
        if (write_hook->obj() != nullptr) {
            hooks_.push_back(std::move(write_hook));
        }

        // the section-hop hook: an exec whose range was claimed is the
        // write-then-execute hand-off
        auto code_hook = std::make_shared<HookRet>(
            ql.hook_code([this](std::uint64_t addr, std::uint32_t /*size*/) -> int {
                return on_section_exec(addr);
            }, start, end));
        if (code_hook->obj() != nullptr) {
            hooks_.push_back(std::move(code_hook));
        }
    }
}

// The reference's on_section_write (unpacker.cpp:5197-5381). `pc` is unused: the
// hook fires after the store, so the pc is read from the arch state.
int Unpacker::on_section_write(std::uint64_t /*pc*/, std::uint64_t addr, std::uint32_t size,
                               std::uint64_t value) {
    // shadow the first write per byte: a store of `size` bytes lands little-endian
    if (addr >= base_ && addr - base_ < image_size_) {
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
        const auto claim = std::make_pair(claim_start, claim_end);
        ever_written_.insert(claim);
        written_ranges_.insert(claim);
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

// The reference's on_section_exec (unpacker.cpp:5520-5810): a written section
// that starts executing is the payload hand-off.
int Unpacker::on_section_exec(std::uint64_t addr) {
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
    const bool in_written = [&] {
        for (const auto& r : written_ranges_) {
            if (addr >= r.first && addr <= r.second) {
                return true;
            }
        }
        return false;
    }();

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
        return 0;
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
}

// The reference builds stub_map_ from the GPA sentinels + every emulated module's
// export address, then scans the dump (unpacker.cpp:8652-9560). Slot coherence is
// the noise filter: a same-dll run of adjacent slots, or a singleton anchored
// within two slots of a kept one.
std::uint64_t Unpacker::ladder_oep(const std::vector<std::uint8_t>& image) const {
    if (image.size() < 0x200 || sections_.empty()) {
        return 0;
    }
    const auto body_of = [&](const PackSection& ps) {
        std::vector<std::uint8_t> b;
        if (ps.start < base_) {
            return b;
        }
        const auto off = static_cast<std::size_t>(ps.start - base_);
        if (off >= image.size()) {
            return b;
        }
        const auto span = std::min<std::size_t>(
            {static_cast<std::size_t>(ps.end - ps.start), 4u * 1024 * 1024, image.size() - off});
        b.assign(image.begin() + static_cast<std::ptrdiff_t>(off),
                 image.begin() + static_cast<std::ptrdiff_t>(off + span));
        return b;
    };
    const bool mpress = opts_.family == "MPRESS";
    // The decode target: the largest section. Its degenerate head holds the packed
    // EP too, so neither the exec flag nor the watch state is a filter.
    const PackSection* tgt = nullptr;
    for (const auto& ps : sections_) {
        if (!tgt || (ps.end - ps.start) > (tgt->end - tgt->start)) {
            tgt = &ps;
        }
    }
    // Pass B: the MSVC entry frame `55 8b ec 6a ff 68 <image-addr> 64 a1` is
    // unique per image (every other function shares the `55 8b ec` head but not
    // the SEH push). RLPack AccessEnum's payload has no Pass-C thunk at all.
    {
        std::size_t hits = 0;
        std::uint64_t hit_va = 0;
        for (const auto& ps : sections_) {
            const auto body = body_of(ps);
            for (std::size_t i = 0; i + 11 < body.size(); ++i) {
                if (body[i] == 0x55 && body[i + 1] == 0x8b && body[i + 2] == 0xec && body[i + 3] == 0x6a &&
                    body[i + 4] == 0xff && body[i + 5] == 0x68) {
                    const auto pv = static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(body[i + 6]) |
                        (static_cast<std::uint32_t>(body[i + 7]) << 8) |
                        (static_cast<std::uint32_t>(body[i + 8]) << 16) |
                        (static_cast<std::uint32_t>(body[i + 9]) << 24));
                    if (pv > base_ && pv < base_ + image_size_) {
                        ++hits;
                        hit_va = ps.start + i;
                    }
                }
            }
        }
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] ladder passB hits=%zu last=%s\n", hits, hex(hit_va).c_str());
        }
        if (!mpress && hits >= 1 && hits <= 8) {
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] ladder: unique MSVC frame entry %s\n", hex(hit_va).c_str());
            }
            return hit_va;
        }
    }
    // Borland/Delphi pre-check: a UNIQUE `6a ?? 68 <image-addr> e8` (push/push/call
    // entry) in the largest section is the entry — it also suppresses the Pass-C
    // override, which would otherwise fire on a false-positive CFG thunk. It is
    // scoped to the decode-only families like the rest of the ladder: 7z's MSVC
    // payload happens to hold exactly one such sequence and the pre-check then
    // shadowed the Pass-B entry that the four-frame cluster identifies (measured:
    // jdpack_7zFM picked 0x405723 instead of its true 0x422ce2).
    if (tgt != nullptr) {
        const auto b = body_of(*tgt);
        std::size_t count = 0;
        std::size_t off = 0;
        for (std::size_t i = 0; i + 8 < b.size(); ++i) {
            if (b[i] == 0x6a && b[i + 2] == 0x68 && b[i + 7] == 0xe8) {
                const auto pv = static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(b[i + 3]) | (static_cast<std::uint32_t>(b[i + 4]) << 8) |
                    (static_cast<std::uint32_t>(b[i + 5]) << 16) | (static_cast<std::uint32_t>(b[i + 6]) << 24));
                if (pv > base_ && pv < base_ + image_size_) {
                    ++count;
                    off = i;
                }
            }
        }
        if (count == 1) {
            if (opts_.debug) {
                std::fprintf(stderr, "[unpack] ladder: unique Borland entry in %s\n", tgt->name.c_str());
            }
            return tgt->start + off;
        }
    }
    // A function-boundary thunk: `ret|int3|nop <e8 rel32> <e9 rel32> <prologue>`.
    // The original entry of the ADInsight-class payloads is
    //   5d c3 | e8 <call __security_init_cookie> e9 <rel32> | 6a 14 68 <imm32> e8
    // i.e. a CRT-init thunk sitting on a function boundary, followed by the real
    // body. The MPRESS packer's runtime fixups rewrite the two rel32 operands, so
    // the reference's `e9 00000000` test does not survive the decode — the
    // boundary prefix does. Requiring the set to be corpus-unique (exactly one)
    // keeps it inert for the samples whose entry is a plain MSVC/Borland frame
    // (ADExplorer/AccessEnum have zero hits).
    if (tgt != nullptr) {
        const auto tb = body_of(*tgt);
        std::size_t bc_count = 0;
        std::size_t bc_off = 0;
        for (std::size_t i = 1; i + 18 < tb.size(); ++i) {
            if (tb[i] != 0xe8 || tb[i + 5] != 0xe9) {
                continue;
            }
            const auto* q = tb.data() + i + 10;
            const bool prologue = (q[0] == 0x6a && q[2] == 0x68 && q[7] == 0xe8) ||
                                  (q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec);
            if (!prologue) {
                continue;
            }
            const auto prev = tb[i - 1];
            if (prev == 0xc3 || prev == 0xcc || prev == 0x90 || prev == 0xc2) {
                ++bc_count;
                bc_off = i;
            }
        }
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] ladder boundary-thunks in %s: %zu\n", tgt->name.c_str(), bc_count);
        }
        if (bc_count == 1) {
            return tgt->start + bc_off;
        }
    }
    // Pass C: a CFG thunk `cc|c3 e8 <rel32> e9 <rel32>`. Every section is scanned
    // (NSPack decodes .text into nsp0 while the OEP lives in nsp1).
    for (const auto& ps : sections_) {
        const auto b = body_of(ps);
        if (b.size() < 12) {
            continue;
        }
        std::size_t c_count = 0;
        std::size_t c_off = 0;
        std::size_t c3_count = 0;
        std::size_t c3_off = 0;
        std::size_t c3_last_off = 0;
        std::size_t c3_valid_off = 0;
        bool c3_prologue_valid = false;
        for (std::size_t i = 0; i + 11 < b.size(); ++i) {
            if ((b[i] == 0xcc || b[i] == 0xc3) && b[i + 1] == 0xe8 && b[i + 6] == 0xe9) {
                ++c_count;
                c_off = i + 1;
                if (b[i] == 0xc3) {
                    ++c3_count;
                    c3_off = i + 1;
                    c3_last_off = i + 1;
                    const auto rel = static_cast<std::int32_t>(
                        static_cast<std::uint32_t>(b[i + 7]) | (static_cast<std::uint32_t>(b[i + 8]) << 8) |
                        (static_cast<std::uint32_t>(b[i + 9]) << 16) |
                        (static_cast<std::uint32_t>(b[i + 10]) << 24));
                    const auto jmp_tgt = static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(ps.start + i + 6 + 5) + rel);
                    if (jmp_tgt >= base_ && jmp_tgt < base_ + image_size_) {
                        c3_valid_off = i + 1;
                        // the e9 target of a real thunk is the CRT entry: it starts
                        // with a recognizable prologue (a false hit inside the
                        // decompressor jumps to arbitrary code)
                        const auto boff = static_cast<std::int64_t>(i + 11) + rel;
                        if (boff >= 0 && static_cast<std::size_t>(boff) + 8 <= b.size()) {
                            const auto* q = b.data() + boff;
                            if ((q[0] == 0x6a && q[2] == 0x68 && q[7] == 0xe8) ||
                                (q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec) ||
                                (q[0] == 0xe8 && q[5] == 0xe9)) {
                                c3_prologue_valid = true;
                            }
                        }
                    }
                }
            }
        }
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] ladder %s: C=%zu C3=%zu valid=%zu\n", ps.name.c_str(), c_count,
                         c3_count, c3_valid_off);
        }
        // MPRESS's c3 hits often land on a wrong function, so the reference skips
        // them — unless the validation passed (the e9 target is in-image AND starts
        // with a recognizable prologue), in which case it is the CFG thunk that
        // leads to the entry, exactly as for the other two families
        if (c3_count >= 1 && (!mpress || c3_prologue_valid || c3_valid_off != 0)) {
            // a validated hit wins; otherwise the LAST c3 hit (the main entry runs
            // after all CRT init — mpress_ADExplorer: the second of two)
            return ps.start + (c3_valid_off != 0 ? c3_valid_off : c3_last_off);
        }
        if (c_count == 1 && !(mpress && c3_count == c_count && !c3_prologue_valid)) {
            return ps.start + c_off;
        }
    }
    if (!mpress) {
        return 0;
    }
    // MPRESS: (a) a UNIQUE bare `e8 <rel32> e9 00000000` — the entry calls
    // __security_init_cookie then nop-jumps to the Borland entry;
    // (b) otherwise the LAST of the Borland / SEH entry patterns in the decode
    // target (the main entry runs after all CRT init), SEH winning ties.
    const auto b = tgt != nullptr ? body_of(*tgt) : std::vector<std::uint8_t>{};
    {
        std::size_t zc_count = 0;
        std::size_t zc_off = 0;
        for (std::size_t i = 0; i + 11 < b.size(); ++i) {
            if (b[i] == 0xe8 && b[i + 5] == 0xe9) {
                const auto rel = static_cast<std::uint32_t>(b[i + 6]) | (static_cast<std::uint32_t>(b[i + 7]) << 8) |
                                 (static_cast<std::uint32_t>(b[i + 8]) << 16) |
                                 (static_cast<std::uint32_t>(b[i + 9]) << 24);
                if (rel == 0) {
                    ++zc_count;
                    zc_off = i;
                }
            }
        }
        if (zc_count == 1) {
            return tgt->start + zc_off;
        }
    }
    {
        std::size_t b_count = 0;
        std::size_t b_last = 0;
        for (std::size_t i = 0; i + 8 < b.size(); ++i) {
            if (b[i] == 0x6a && b[i + 2] == 0x68 && b[i + 7] == 0xe8) {
                const auto pv = static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(b[i + 3]) | (static_cast<std::uint32_t>(b[i + 4]) << 8) |
                    (static_cast<std::uint32_t>(b[i + 5]) << 16) | (static_cast<std::uint32_t>(b[i + 6]) << 24));
                if (pv > base_ && pv < base_ + image_size_) {
                    ++b_count;
                    b_last = i;
                }
            }
        }
        std::size_t s_count = 0;
        std::size_t s_last = 0;
        const auto hw = std::min<std::size_t>(b.size(), 0x40000);
        for (std::size_t i = 0; i + 6 < hw; ++i) {
            if (b[i] == 0x55 && b[i + 1] == 0x8b && b[i + 2] == 0xec && b[i + 3] == 0x6a && b[i + 4] == 0xff &&
                b[i + 5] == 0x68) {
                ++s_count;
                s_last = i;
            }
        }
        if (b_count > 0 && b_count > s_count) {
            return tgt->start + b_last;
        }
        if (s_count > 0 && s_count >= b_count) {
            return tgt->start + s_last;
        }
    }
    return 0;
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
            auto fn = cstr(static_cast<std::size_t>(v) + 2, 96);
            if (fn.size() < 3) {
                fn = cstr(v, 96);
            }
            if (fn.size() < 3) {
                members.clear();
                break;
            }
            // undo FSG's -3 first-character shift when it lands on a letter
            const auto shifted = static_cast<unsigned char>(fn[0] - 3);
            if (std::isalpha(shifted) != 0) {
                fn[0] = static_cast<char>(shifted);
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
        std::set<std::string> seen_dlls;
        for (const auto& [dll, names] : per_dll) {
            seen_dlls.insert(dll);
        }
        if (per_dll.size() >= 3) {
            for (const auto& [dll, names] : per_dll) {
                for (const auto& fn : names) {
                    note_import(sanitize_ascii(dll), sanitize_ascii(fn));
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
    if (groups.size() >= 2 && total_names >= 6) {
        for (const auto& [dll, names] : groups) {
            for (const auto& fn : names) {
                note_import(sanitize_ascii(dll), sanitize_ascii(fn));
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

bool Unpacker::adopt_embedded_pe(Qiling& ql, std::vector<std::uint8_t>& image) {
    std::uint64_t best = 0;
    std::uint64_t best_size = 0;
    try {
        for (const auto& mi : ql.mem().get_mapinfo()) {
            const auto lo = std::get<0>(mi);
            const auto hi = std::get<1>(mi);
            if (hi <= lo || lo == base_ || hi - lo < 0x1000 || hi - lo > 0x8000000) {
                continue;
            }
            if (lo >= 0x10000000) {
                continue;  // the loaded dll tree
            }
            std::vector<std::uint8_t> head;
            try {
                head = ql.mem().read(lo, std::min<std::uint64_t>(hi - lo, 0x1000));
            } catch (...) {
                continue;
            }
            if (head.size() < 0x200 || head[0] != 'M' || head[1] != 'Z') {
                continue;
            }
            const auto lfanew = static_cast<std::size_t>(head[0x3c]) | (static_cast<std::size_t>(head[0x3d]) << 8) |
                                (static_cast<std::size_t>(head[0x3e]) << 16) |
                                (static_cast<std::size_t>(head[0x3f]) << 24);
            if (lfanew + 0x40 > head.size() || head[lfanew] != 'P' || head[lfanew + 1] != 'E') {
                continue;
            }
            const auto opt = lfanew + 24;
            const auto magic = static_cast<std::uint32_t>(head[opt]) | (static_cast<std::uint32_t>(head[opt + 1]) << 8);
            if (magic != 0x10b && magic != 0x20b) {
                continue;
            }
            const auto soi = static_cast<std::uint64_t>(head[opt + 0x38]) |
                             (static_cast<std::uint64_t>(head[opt + 0x39]) << 8) |
                             (static_cast<std::uint64_t>(head[opt + 0x3a]) << 16) |
                             (static_cast<std::uint64_t>(head[opt + 0x3b]) << 24);
            if (soi < 0x1000 || soi > hi - lo) {
                continue;
            }
            if (soi > best_size) {
                best = lo;
                best_size = soi;
            }
        }
    } catch (...) {
        return false;
    }
    if (best == 0) {
        return false;
    }
    std::vector<std::uint8_t> embedded;
    try {
        embedded = ql.mem().read(best, best_size);
    } catch (...) {
        return false;
    }
    if (embedded.size() < 0x200) {
        return false;
    }
    // adopt: the payload image replaces the stub's
    const auto old_base = base_;
    base_ = best;
    image_size_ = best_size;
    image = embedded;
    // re-point the section table at the payload's own sections
    sections_.clear();
    watched_.clear();
    const auto rd = [&embedded](std::size_t o) -> std::uint32_t {
        if (o + 4 > embedded.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(embedded[o]) | (static_cast<std::uint32_t>(embedded[o + 1]) << 8) |
               (static_cast<std::uint32_t>(embedded[o + 2]) << 16) |
               (static_cast<std::uint32_t>(embedded[o + 3]) << 24);
    };
    const auto rd16 = [&embedded](std::size_t o) -> std::uint32_t {
        if (o + 2 > embedded.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(embedded[o]) | (static_cast<std::uint32_t>(embedded[o + 1]) << 8);
    };
    const auto e_lfanew = static_cast<std::size_t>(rd(0x3c));
    const auto n_sec = rd16(e_lfanew + 6);
    const auto opt_size = rd16(e_lfanew + 20);
    const auto sec_table = e_lfanew + 24 + static_cast<std::size_t>(opt_size);
    for (std::size_t i = 0; i < n_sec && i < 96; ++i) {
        const auto o = sec_table + i * 40;
        PackSection ps;
        for (std::size_t k = 0; k < 8 && embedded[o + k] != 0; ++k) {
            ps.name.push_back(static_cast<char>(embedded[o + k]));
        }
        ps.vsize = rd(o + 8);
        ps.start = base_ + rd(o + 12);
        ps.end = ps.start + (ps.vsize ? ps.vsize : 1);
        ps.raw = rd(o + 16);
        const auto ch = rd(o + 36);
        ps.is_exec = (ch & 0x20000000u) != 0;
        sections_.push_back(ps);
    }
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] embedded PE at %s size %s (stub at %s)\n", hex(best).c_str(),
                     hex(best_size).c_str(), hex(old_base).c_str());
    }
    return true;
}

void Unpacker::harvest_image_imports(const std::vector<std::uint8_t>& image) {
    const auto at = [&image](std::size_t o, int n) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = n - 1; i >= 0; --i) {
            if (o + static_cast<std::size_t>(i) >= image.size()) {
                return 0;
            }
            v = (v << 8) | image[o + static_cast<std::size_t>(i)];
        }
        return v;
    };
    const auto cstr = [&image](std::size_t o) -> std::string {
        std::string s;
        while (o < image.size() && image[o] != 0 && s.size() < 128) {
            const auto ch = image[o++];
            s.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<char>(ch) : '.');
        }
        return s;
    };
    if (image.size() < 0x200) {
        return;
    }
    const auto lfanew = static_cast<std::size_t>(at(0x3c, 4));
    if (lfanew + 0x40 > image.size() || image[lfanew] != 'P' || image[lfanew + 1] != 'E') {
        return;
    }
    const auto opt = lfanew + 24;
    const auto magic = at(opt, 2);
    const bool is64 = magic == 0x20b;
    if (!(magic == 0x10b || magic == 0x20b)) {
        return;
    }
    const auto n_rva = at(opt + (is64 ? 0x6c : 0x5c), 4);
    std::size_t dd = 0;
    const auto opt_size = at(lfanew + 20, 2);
    if (n_rva != 16 || opt_size < (is64 ? 0xF0u : 0xE0u)) {
        dd = opt + (is64 ? 0x70 : 0x60);
    } else {
        dd = opt + static_cast<std::size_t>(opt_size) - 8 * static_cast<std::size_t>(n_rva);
    }
    const auto imp_rva = at(dd + 8, 4);
    if (imp_rva == 0) {
        return;
    }
    const auto ptr = is64 ? 8 : 4;
    for (std::size_t i = 0; i < 512; ++i) {
        const auto off = static_cast<std::size_t>(imp_rva) + i * 20;
        if (off + 20 > image.size()) {
            break;
        }
        const auto oft = at(off, 4);
        const auto name_rva = at(off + 12, 4);
        const auto ft = at(off + 16, 4);
        if (name_rva == 0 || (oft == 0 && ft == 0)) {
            break;  // the null descriptor (or a malformed one)
        }
        std::string dll = cstr(static_cast<std::size_t>(name_rva));
        if (dll.empty()) {
            continue;
        }
        const auto thunk_rva = oft != 0 ? oft : ft;
        for (std::size_t k = 0; k < 4096; ++k) {
            const auto toff = static_cast<std::size_t>(thunk_rva) + k * static_cast<std::size_t>(ptr);
            if (toff + static_cast<std::size_t>(ptr) > image.size()) {
                break;
            }
            const auto thunk = at(toff, ptr);
            if (thunk == 0) {
                break;
            }
            const auto flag = is64 ? 0x8000000000000000ull : 0x80000000ull;
            if ((thunk & flag) != 0) {
                note_import(sanitize_ascii(dll), "ordinal_" + std::to_string(thunk & 0xffff));
                continue;
            }
            const auto fn = cstr(static_cast<std::size_t>(thunk) + 2);  // skip the hint
            if (!fn.empty()) {
                note_import(sanitize_ascii(dll), fn);
            }
        }
    }
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] image import table harvest: %zu imports\n", imports_.size());
    }
}

void Unpacker::salvage_iat(Qiling& ql, const std::vector<std::uint8_t>& image) {
    salvaged_slots_ = 0;
    salvaged_pairs_ = 0;
    if (image.size() < 8) {
        return;
    }
    // addr -> (dll, name)
    std::map<std::uint64_t, std::pair<std::string, std::string>> stub_map;
    try {
        const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
        for (const auto& [addr, entry] : pe_loader.import_symbols()) {
            if (addr == 0 || entry.name.empty()) {
                continue;
            }
            std::string dll = lower_ascii(fs::path(entry.dll).filename().string());
            if (dll.empty()) {
                continue;
            }
            stub_map.emplace(addr, std::make_pair(sanitize_ascii(dll), sanitize_ascii(entry.name)));
        }
    } catch (...) {
        return;
    }
    if (stub_map.empty()) {
        return;
    }

    const std::size_t ptr = is_64_ ? 8 : 4;
    struct Hit {
        std::uint32_t off;
        std::string dll;
        std::string name;
    };
    std::vector<Hit> hits;
    const auto scan_bytes = [&](const std::vector<std::uint8_t>& bytes) {
        for (std::size_t o = 0; o + ptr <= bytes.size(); o += ptr) {
            std::uint64_t v = 0;
            for (std::size_t k = 0; k < ptr; ++k) {
                v |= static_cast<std::uint64_t>(bytes[o + k]) << (8 * k);
            }
            if (v < 0x10000) {
                continue;
            }
            const auto it = stub_map.find(v);
            if (it == stub_map.end()) {
                continue;
            }
            hits.push_back(Hit{static_cast<std::uint32_t>(o), it->second.first, it->second.second});
        }
    };
    scan_bytes(image);
    // the reference's salvage_iat_write scans EVERY mapped region, not just the
    // image: the stubs that rebuild the IAT themselves (FSG, BeRo, WinUpack, MEW)
    // keep the table in a private buffer (unpacker.cpp:9480-9620)
    try {
        for (const auto& mi : ql.mem().get_mapinfo()) {
            const auto lo = std::get<0>(mi);
            const auto hi = std::get<1>(mi);
            if (hi <= lo || lo == base_ || hi - lo > 0x400000) {
                continue;
            }
            if (lo < 0x10000) {
                continue;  // the FS/GDT scratch
            }
            std::vector<std::uint8_t> bytes;
            try {
                bytes = ql.mem().read(lo, hi - lo);
            } catch (...) {
                continue;
            }
            scan_bytes(bytes);
        }
    } catch (...) {
    }
    if (hits.empty()) {
        return;
    }
    std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.off < b.off; });

    // pass 0 (the reference's slot probe, unpacker.cpp:9480-9560): when the whole
    // image holds only a handful of live import pointers, the stub rebuilt the IAT
    // itself and the slots are scattered — adjacency cannot be required. The values
    // come from the loader's own export map, so they are authoritative.
    if (hits.size() <= 64) {
        for (const auto& h : hits) {
            note_import(h.dll, h.name);
            ++salvaged_slots_;
        }
        if (opts_.debug) {
            std::fprintf(stderr, "[unpack] salvage: %zu scattered hits -> all kept\n", hits.size());
        }
        return;
    }

    // pass 1: runs of >= 2 adjacent pointer-spaced slots of the same dll
    std::set<std::size_t> kept;
    for (std::size_t i = 0; i < hits.size();) {
        std::size_t j = i + 1;
        while (j < hits.size() && hits[j].off == hits[j - 1].off + ptr && hits[j].dll == hits[j - 1].dll) {
            ++j;
        }
        if (j - i >= 2) {
            for (std::size_t k = i; k < j; ++k) {
                kept.insert(k);
            }
        }
        i = j;
    }
    // pass 2: singletons anchored within two slots of a kept neighbour
    for (std::size_t i = 0; i < hits.size(); ++i) {
        if (kept.count(i) != 0) {
            continue;
        }
        bool anchor = false;
        for (std::size_t k = 0; k < hits.size() && !anchor; ++k) {
            if (kept.count(k) == 0) {
                continue;
            }
            const auto d = hits[i].off > hits[k].off ? hits[i].off - hits[k].off : hits[k].off - hits[i].off;
            anchor = d <= 2 * ptr && hits[i].dll == hits[k].dll;
        }
        if (anchor) {
            kept.insert(i);
        }
    }
    for (const auto idx : kept) {
        note_import(hits[idx].dll, hits[idx].name);
        ++salvaged_pairs_;
    }
    salvaged_slots_ = kept.size();
    if (opts_.debug) {
        std::fprintf(stderr, "[unpack] salvage: %zu hits -> %zu slots, %zu pairs\n", hits.size(), kept.size(),
                     salvaged_pairs_);
        for (std::size_t i = 0; i < hits.size() && i < 4; ++i) {
            std::fprintf(stderr, "[unpack]   hit off=0x%x dll=<%s> name=<%s>\n", hits[i].off,
                         hits[i].dll.c_str(), hits[i].name.c_str());
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
        if (p[0] == 0xe9) {
            return 1;
        }
        return 0;
    };
    // the statically known entries win outright: the packer itself recorded them
    if (const auto mew = mew_static_oep(); mew != 0) {
        return mew;
    }
    if (const auto hdr = header_ep_candidate(image); hdr != 0) {
        return hdr;
    }
    const bool decode_only = opts_.family == "NSPack" || opts_.family == "RLPack" || opts_.family == "MPRESS";
    // The decode-only families: their decode lands in one big section whose head is
    // also the stub, so the run's own transitions are mostly stub-internal noise.
    // The static ladder over the decoded body is the authority (the reference's
    // F41c/F47: only an ACCEPTED, replacement-gated hop outranks it — taote has no
    // such gate, so the ladder leads and the ledger is the fallback).
    if (decode_only) {
        if (const auto ladder = ladder_oep(image); ladder != 0) {
            return ladder;
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
        if (const auto ladder = ladder_oep(image); ladder != 0) {
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

// MEW's header table (the reference's SLOT_MEW_OEP_PARSE, mew_unpacker.cpp:28-64):
// the packed EP is `e9 rel32` to a stub starting `be imm32`, and the dword at
// imm32+4 is the original OEP.
std::uint64_t Unpacker::mew_static_oep() const {
    if (base_ == 0) {
        return 0;
    }
    return mew_oep_candidate_;
}

UnpackResult Unpacker::finalize(Qiling& ql) {
    detach_hooks();
    UnpackResult res;
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
        // Amber-class: the payload PE is assembled in a heap buffer and the
        // original sections are never written, so there is no hop to find — adopt
        // the embedded image (the reference's try_embedded_pe)
        if (hop_ledger_.empty() &&
            (opts_.family == "Amber" || opts_.family == "Alienyze")) {
            std::vector<std::uint8_t> adopted = image;
            if (adopt_embedded_pe(ql, adopted)) {
                image = std::move(adopted);
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
        if (hop_ledger_.empty()) {
            // no hop: the static entries, then the decoded-section ladder scan
            if (const auto mew = mew_static_oep(); mew != 0) {
                meta_oep_ = mew;
                reason_ = "mew_static_oep";
                stages_ = 1;
            } else if (const auto hdr = header_ep_candidate(image); hdr != 0) {
                meta_oep_ = hdr;
                reason_ = "header_ep";
                stages_ = 1;
            } else if (const auto ladder = ladder_oep(image); ladder != 0) {
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
        // MEW's stub memsets the decoded image right before handing off, so the
        // terminal dump is zeroed where the payload lives; the reference keeps the
        // full first-write overlay for this family alone (unpacker.cpp:178-200).
        if (opts_.family == "MEW" && shadow_seen_.size() == image.size()) {
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
                try {
                    body = ql.mem().read(ps.start, span);
                } catch (...) {
                    continue;
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
        res.oep = meta_oep_;
        res.oep_last_hop = last_oep_;
        res.stages = stages_;
        res.reason = reason_;

        // ---- the artifacts (the reference's contract, unpacker.cpp:6836-7090)
        const std::string stem = fs::path(opts_.sample_path).filename().string();
        std::error_code ec;
        fs::create_directories(opts_.out_dir, ec);
        const auto dump_path = fs::path(opts_.out_dir) / (stem + "_dump.bin");
        {
            std::ofstream out(dump_path, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(image.data()),
                      static_cast<std::streamsize>(image.size()));
            res.dump_written = static_cast<bool>(out);
            res.dumpfile = dump_path.string();
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
                std::ofstream out(exe_path, std::ios::binary | std::ios::trunc);
                out.write(reinterpret_cast<const char*>(in.image.data()),
                          static_cast<std::streamsize>(in.image.size()));
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

    // ---- the .pgimp blob (the reference's build_import_section, :10031-10420)
    struct Group {
        std::string dll;
        std::vector<std::string> names;
    };
    std::vector<Group> groups;
    for (const auto& pr : in.imports) {
        auto dll = pr.first;
        std::transform(dll.begin(), dll.end(), dll.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        auto it = std::find_if(groups.begin(), groups.end(), [&](const Group& g) { return g.dll == dll; });
        if (it == groups.end()) {
            groups.push_back(Group{dll, {}});
            it = std::prev(groups.end());
        }
        if (std::find(it->names.begin(), it->names.end(), pr.second) == it->names.end()) {
            it->names.push_back(pr.second);
        }
    }

    const std::uint32_t new_va = align_up(max_va_end, sec_align);
    std::vector<std::uint8_t> blob;
    const auto put = [&blob](const void* p, std::size_t n) {
        const auto* b = static_cast<const std::uint8_t*>(p);
        blob.insert(blob.end(), b, b + n);
    };
    // descriptor array first (dd[1]) then, per group, INT + IAT + names
    const std::size_t desc_off = blob.size();
    const std::size_t desc_size = (groups.size() + 1) * 20;
    blob.resize(desc_off + desc_size, 0);

    std::vector<std::size_t> desc_slot(groups.size());
    for (std::size_t g = 0; g < groups.size(); ++g) {
        desc_slot[g] = desc_off + g * 20;
    }

    std::uint32_t iat_rva = 0;
    std::uint32_t iat_size = 0;
    for (std::size_t g = 0; g < groups.size(); ++g) {
        const auto& grp = groups[g];
        const std::size_t n = grp.names.size();
        const std::size_t int_off = blob.size();
        blob.resize(int_off + (n + 1) * 4, 0);
        const std::size_t iat_off = blob.size();
        blob.resize(iat_off + (n + 1) * 4, 0);
        // names
        std::vector<std::uint32_t> name_rvas;
        name_rvas.reserve(n);
        for (const auto& fn : grp.names) {
            if (blob.size() % 2 != 0) {
                blob.push_back(0);
            }
            name_rvas.push_back(new_va + static_cast<std::uint32_t>(blob.size()));
            const std::uint16_t hint = 0;
            put(&hint, 2);
            put(fn.data(), fn.size());
            const char nul = '\0';
            put(&nul, 1);
        }
        const std::size_t name_off = blob.size();
        (void)name_off;
        const std::uint32_t dll_name_rva = [&] {
            if (blob.size() % 2 != 0) {
                blob.push_back(0);
            }
            const auto rva = new_va + static_cast<std::uint32_t>(blob.size());
            put(grp.dll.data(), grp.dll.size());
            const char nul = '\0';
            put(&nul, 1);
            return rva;
        }();

        // the INT + IAT thunk arrays (hint/name RVAs, both arrays identical: the
        // loader writes the resolved addresses into the IAT)
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint32_t thunk = name_rvas[i];
            std::memcpy(&blob[int_off + i * 4], &thunk, 4);
            std::memcpy(&blob[iat_off + i * 4], &thunk, 4);
        }

        const std::uint32_t int_rva = new_va + static_cast<std::uint32_t>(int_off);
        const std::uint32_t this_iat_rva = new_va + static_cast<std::uint32_t>(iat_off);
        if (iat_rva == 0) {
            iat_rva = this_iat_rva;
        }
        iat_size += static_cast<std::uint32_t>((n + 1) * 4);

        wr32(blob, desc_slot[g], int_rva);        // OriginalFirstThunk
        wr32(blob, desc_slot[g] + 4, 0);          // TimeDateStamp
        wr32(blob, desc_slot[g] + 8, 0);          // ForwarderChain
        wr32(blob, desc_slot[g] + 12, dll_name_rva);
        wr32(blob, desc_slot[g] + 16, this_iat_rva);  // FirstThunk
    }
    const std::uint32_t new_vsize = static_cast<std::uint32_t>(blob.size());
    if (new_vsize == 0) {
        return {};
    }

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
        std::copy(blob.begin(), blob.end(), out.begin() + static_cast<std::ptrdiff_t>(pgimp_raw_ptr));
    }

    // the optional header fields the loader reads
    const std::uint32_t size_of_image = align_up(new_va + new_vsize, sec_align);
    wr32(out, opt_off + 0x10, oep_rva);              // AddressOfEntryPoint
    wr32(out, opt_off + 0x38, size_of_image);        // SizeOfImage
    wr32(out, opt_off + 0x3c, size_of_headers);      // SizeOfHeaders
    wr32(out, opt_off + 0x40, 0);                    // CheckSum
    wr16(out, coff + 2, static_cast<std::uint16_t>(secs.size() + 1));
    // data directories: import = .pgimp descriptors, IAT = the first thunk array
    wr32(out, dd_base + 1 * 8, new_va + static_cast<std::uint32_t>(desc_off));
    wr32(out, dd_base + 1 * 8 + 4, static_cast<std::uint32_t>(desc_size));
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
