// tests/Pe_Sample_Runner.hpp — the fixture runner for the Windows API sample
// binaries (the ../pegasus tests/bins set, vendored under tests/data/pegasus).
//
// Each sample imports the real system dlls (kernel32.dll, ntdll.dll, the
// api-ms-win-crt-* redirects, msvcrt.dll, ...). The runner LIEF-parses the
// import table, synthesizes one stub dll per imported module (the
// tests/Pe_Stub.hpp technique, extended to any arch: a hand-rolled PE32/PE32+
// image with one 16-byte ret cell per export and image entry 0), stages them
// into a private
// rootfs together with the sample, and runs the sample through the real
// QlOsWindows path. The guest calls landing on the stub cells dispatch into
// the ApiRegistry handlers exactly like the real-dll hosts do.
//
// The runner also captures what the tests assert on:
//   * the guest stdout text (the printf/puts renders — the stdout stream is
//     pointed at a capture file before the run)
//   * the stats API log (name -> the ret values in call order)
//   * the read_string log (every guest string the handlers decoded)
//   * for dll samples: the DllMain/export return values
#ifndef QILING_TESTS_PE_SAMPLE_RUNNER_HPP
#define QILING_TESTS_PE_SAMPLE_RUNNER_HPP

#include <algorithm>
#include <deque>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <LIEF/PE.hpp>

#include "qiling/core.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/windows/dlls/dlls.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace testing {

namespace pe_sample_detail {

namespace fs = std::filesystem;

struct SamplePlan {
    bool is64 = true;
    std::vector<std::pair<std::string, std::vector<std::string>>> imports;  // dll -> export names
    std::uint32_t entry_rva = 0;
    std::uint64_t imagebase = 0;
    std::vector<std::pair<std::string, std::uint32_t>> exports_own;         // name -> rva
};

inline std::string lower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

inline fs::path bins_dir() {
    return fs::path(__FILE__).parent_path() / "data" / "pegasus";
}

inline SamplePlan plan_for(const fs::path& sample) {
    SamplePlan plan;
    auto bin = LIEF::PE::Parser::parse(sample.string());
    if (bin == nullptr) {
        throw std::runtime_error("LIEF parse failed: " + sample.string());
    }
    plan.is64 = bin->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64;

    for (const auto& imp : bin->imports()) {
        std::vector<std::string> names;
        for (const auto& e : imp.entries()) {
            if (!e.name().empty()) {
                names.push_back(e.name());
            }
        }
        // every imported dll gets a stub image, even one whose imports are
        // ordinal-only (WS2_32 in PMA 16-01): the loader's sys_dlls-independent
        // import walk loads it on both emulators, and a dll that only one side
        // can find shifts that side's heap for every later guest allocation
        plan.imports.emplace_back(lower(imp.name()), std::move(names));
    }

    // LIEF reports the entrypoint as a VA and the export addresses as RVAs in
    // this build (see the loader's own note) — normalize the entry to an RVA.
    // A DLL image carries the 0x80000000 flag bit in that VA, so the difference
    // has to be masked back to 31 bits (the 01-01.dll entry reads 0x800012fa
    // with imagebase 0x10000000: the rva is 0x12fa, not 0x700012fa)
    plan.imagebase = static_cast<std::uint64_t>(bin->imagebase());
    plan.entry_rva = static_cast<std::uint32_t>(bin->entrypoint() - plan.imagebase) & 0x7fffffffu;
    if (bin->get_export() != nullptr) {
        for (const auto& e : bin->get_export()->entries()) {
            plan.exports_own.emplace_back(e.name(), static_cast<std::uint32_t>(e.address()));
        }
    }
    return plan;
}

// the minimal stub dll: the correct PE headers/sections/export table, one
// 0xC3 cell per export, entry point 0 (so the loader's DllMain drive skips).
// Rendered by hand, mirroring tools/stub_dlls.py (which seeds the reference
// emulator's rootfs with the same shape): the vcpkg LIEF Builder cannot
// round-trip PE32 — reproduced with LIEF 0.17.6, where a PE32 build drops the
// .text section, writes SizeOfOptionalHeader = 0x60 and a section table its own
// parser cannot read, so the export table is lost on re-parse. The
// optional-header magic must match the GUEST: a 32-bit reader (the unpacker's
// F52 guest-EAT walk, PLAN_UNPACK §0.15/§0.17) sees no exports on a PE32+
// image, so x86 guests get PE32 and x64 guests get PE32+.
inline void write_stub_dll(const fs::path& rootfs, const std::string& dll_name,
                           const std::vector<std::string>& exports, bool is64 = false) {
    const std::size_t cells = std::max<std::size_t>(exports.size(), 1);
    const std::uint32_t cell_size = 16;
    const std::uint32_t section_align = 0x1000;
    const std::uint32_t file_align = 0x200;

    const auto align_up = [](std::uint64_t v, std::uint64_t a) { return (v + a - 1) / a * a; };

    // .text: one cell per export. The default fill is the plain `ret` cell the
    // API hooks never execute. _initterm_e has to answer 0 (xor eax,eax; ret):
    // with no handler registered any more (ucrt.cpp) the stub cell executes on
    // the stub path and must report the success the retired no-op hook gave.
    std::vector<std::uint8_t> text(cells * cell_size, 0xC3);
    for (std::size_t i = 0; i < exports.size(); ++i) {
        if (exports[i] == "_initterm_e") {
            text[i * cell_size + 0] = 0x31;  // xor eax, eax
            text[i * cell_size + 1] = 0xC0;
            text[i * cell_size + 2] = 0xC3;  // ret
            for (std::size_t j = 3; j < cell_size; ++j) {
                text[i * cell_size + j] = 0xCC;
            }
        }
    }

    const std::uint32_t text_rva = section_align;
    const std::uint32_t text_size = static_cast<std::uint32_t>(text.size());
    const std::uint32_t edata_rva = static_cast<std::uint32_t>(align_up(text_rva + text_size, section_align));

    // .edata: IMAGE_EXPORT_DIRECTORY, then EAT / name pointers / ordinals,
    // then the module name and the export names.
    const std::uint32_t funcs_off = 40;
    const std::uint32_t name_ptrs_off = funcs_off + static_cast<std::uint32_t>(cells) * 4;
    const std::uint32_t ordinals_off = name_ptrs_off + static_cast<std::uint32_t>(cells) * 4;
    const std::uint32_t strings_off = ordinals_off + static_cast<std::uint32_t>(cells) * 2;

    std::vector<std::uint8_t> strings;
    const auto append_cstr = [&](const std::string& s) {
        strings.insert(strings.end(), s.begin(), s.end());
        strings.push_back(0);
    };
    append_cstr(dll_name);  // the module name is the first string (offset 0)
    std::vector<std::uint32_t> name_offsets;
    name_offsets.reserve(exports.size());
    for (const auto& name : exports) {
        name_offsets.push_back(static_cast<std::uint32_t>(strings.size()));
        append_cstr(name);
    }
    while (strings.size() % 4 != 0) {
        strings.push_back(0);
    }

    std::vector<std::uint8_t> edata;
    const auto e16 = [&](std::uint16_t v) {
        edata.push_back(static_cast<std::uint8_t>(v & 0xff));
        edata.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    };
    const auto e32 = [&](std::uint32_t v) {
        e16(static_cast<std::uint16_t>(v & 0xffff));
        e16(static_cast<std::uint16_t>((v >> 16) & 0xffff));
    };
    e32(0);                                   // Characteristics
    e32(0);                                   // TimeDateStamp
    e16(0); e16(0);                           // MajorVersion, MinorVersion
    e32(0);                                   // Name RVA (patched below)
    e32(1);                                   // Base
    e32(static_cast<std::uint32_t>(exports.size()));  // NumberOfFunctions
    e32(static_cast<std::uint32_t>(exports.size()));  // NumberOfNames
    e32(edata_rva + funcs_off);               // AddressOfFunctions
    e32(edata_rva + name_ptrs_off);           // AddressOfNames
    e32(edata_rva + ordinals_off);            // AddressOfNameOrdinals
    for (std::size_t i = 0; i < cells; ++i) {
        e32(text_rva + static_cast<std::uint32_t>(i * cell_size));
    }
    for (const auto off : name_offsets) {
        e32(edata_rva + strings_off + off);
    }
    for (std::size_t i = 0; i < cells; ++i) {
        e16(static_cast<std::uint16_t>(i));
    }
    const std::uint32_t name_rva = edata_rva + strings_off;  // dll name is the first string
    edata[12] = static_cast<std::uint8_t>(name_rva & 0xff);
    edata[13] = static_cast<std::uint8_t>((name_rva >> 8) & 0xff);
    edata[14] = static_cast<std::uint8_t>((name_rva >> 16) & 0xff);
    edata[15] = static_cast<std::uint8_t>((name_rva >> 24) & 0xff);
    edata.insert(edata.end(), strings.begin(), strings.end());

    struct StubSection {
        std::string name;
        std::uint32_t rva;
        std::vector<std::uint8_t> data;
        std::uint32_t raw_size;
        std::uint32_t raw_ptr;
        std::uint32_t characteristics;
    };
    std::vector<StubSection> sections;
    sections.push_back({".text", text_rva, text,
                        static_cast<std::uint32_t>(align_up(text.size(), file_align)),
                        0, 0x60000020u});
    sections.push_back({".edata", edata_rva, edata,
                        static_cast<std::uint32_t>(align_up(edata.size(), file_align)),
                        0, 0x40000040u});
    std::uint32_t raw_cursor = file_align;
    for (auto& s : sections) {
        s.raw_ptr = raw_cursor;
        s.data.resize(s.raw_size, 0);
        raw_cursor += s.raw_size;
    }

    const std::uint32_t size_of_image =
        static_cast<std::uint32_t>(align_up(edata_rva + edata.size(), section_align));
    const std::uint64_t image_base = is64 ? 0x180000000ULL : 0x10000000ULL;
    const std::uint32_t size_of_code =
        sections[0].raw_size + sections[1].raw_size;

    std::vector<std::uint8_t> out(raw_cursor, 0);
    out[0] = 'M'; out[1] = 'Z';
    out[0x3c] = 0x40; out[0x3d] = 0; out[0x3e] = 0; out[0x3f] = 0;  // e_lfanew
    out[0x40] = 'P'; out[0x41] = 'E'; out[0x42] = 0; out[0x43] = 0;

    const auto w16 = [&](std::size_t off, std::uint16_t v) {
        out[off] = static_cast<std::uint8_t>(v & 0xff);
        out[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    };
    const auto w32 = [&](std::size_t off, std::uint32_t v) {
        w16(off, static_cast<std::uint16_t>(v & 0xffff));
        w16(off + 2, static_cast<std::uint16_t>((v >> 16) & 0xffff));
    };

    // COFF header
    w16(0x44, is64 ? 0x8664 : 0x14c);                         // Machine
    w16(0x46, static_cast<std::uint16_t>(sections.size()));    // NumberOfSections
    w32(0x48, 0);                                             // TimeDateStamp
    w32(0x4c, 0);                                             // PointerToSymbolTable
    w32(0x50, 0);                                             // NumberOfSymbols
    w16(0x54, is64 ? 0xf0 : 0xe0);                            // SizeOfOptionalHeader
    w16(0x56, is64 ? 0x2022 : 0x2102);                        // Characteristics

    // optional header
    const std::size_t opt = 0x58;
    if (!is64) {
        w16(opt + 0, 0x10b);                       // Magic (PE32)
        out[opt + 2] = 0; out[opt + 3] = 0;        // linker versions
        w32(opt + 4, size_of_code);                // SizeOfCode
        w32(opt + 8, 0);                           // SizeOfInitializedData
        w32(opt + 12, 0);                          // SizeOfUninitializedData
        w32(opt + 16, 0);                          // AddressOfEntryPoint (no DllMain)
        w32(opt + 20, text_rva);                   // BaseOfCode
        w32(opt + 24, edata_rva);                  // BaseOfData
        w32(opt + 28, static_cast<std::uint32_t>(image_base));
        w32(opt + 32, section_align);              // SectionAlignment
        w32(opt + 36, file_align);                 // FileAlignment
        w16(opt + 40, 6); w16(opt + 42, 0);        // OS version
        w16(opt + 44, 0); w16(opt + 46, 0);        // image version
        w16(opt + 48, 6); w16(opt + 50, 0);        // subsystem version
        w32(opt + 52, 0);                          // Win32VersionValue
        w32(opt + 56, size_of_image);              // SizeOfImage
        w32(opt + 60, file_align);                 // SizeOfHeaders
        w32(opt + 64, 0);                          // CheckSum
        w16(opt + 68, 3);                          // Subsystem (console)
        w16(opt + 70, 0x400);                      // DllCharacteristics
        w32(opt + 72, 0x100000);                   // SizeOfStackReserve
        w32(opt + 76, 0x1000);                     // SizeOfStackCommit
        w32(opt + 80, 0x100000);                   // SizeOfHeapReserve
        w32(opt + 84, 0x1000);                     // SizeOfHeapCommit
        w32(opt + 88, 0);                          // LoaderFlags
        w32(opt + 92, 16);                         // NumberOfRvaAndSizes
        w32(opt + 96, edata_rva);                  // data dir[0]: export
        w32(opt + 100, static_cast<std::uint32_t>(edata.size()));
    } else {
        w16(opt + 0, 0x20b);                       // Magic (PE32+)
        out[opt + 2] = 0; out[opt + 3] = 0;
        w32(opt + 4, size_of_code);
        w32(opt + 8, 0);
        w32(opt + 12, 0);
        w32(opt + 16, 0);                          // AddressOfEntryPoint
        w32(opt + 20, text_rva);                   // BaseOfCode
        w32(opt + 24, static_cast<std::uint32_t>(image_base & 0xffffffffu));
        w32(opt + 28, static_cast<std::uint32_t>((image_base >> 32) & 0xffffffffu));
        w32(opt + 32, section_align);
        w32(opt + 36, file_align);
        w16(opt + 40, 6); w16(opt + 42, 0);
        w16(opt + 44, 0); w16(opt + 46, 0);
        w16(opt + 48, 6); w16(opt + 50, 0);
        w32(opt + 52, 0);
        w32(opt + 56, size_of_image);
        w32(opt + 60, file_align);                 // SizeOfHeaders
        w32(opt + 64, 0);
        w16(opt + 68, 3);
        w16(opt + 70, 0x400);
        w32(opt + 72, 0x100000); w32(opt + 76, 0);      // SizeOfStackReserve
        w32(opt + 80, 0x1000);   w32(opt + 84, 0);      // SizeOfStackCommit
        w32(opt + 88, 0x100000); w32(opt + 92, 0);      // SizeOfHeapReserve
        w32(opt + 96, 0x1000);   w32(opt + 100, 0);     // SizeOfHeapCommit
        w32(opt + 104, 0);                             // LoaderFlags
        w32(opt + 108, 16);                            // NumberOfRvaAndSizes
        w32(opt + 112, edata_rva);                     // data dir[0]: export
        w32(opt + 116, static_cast<std::uint32_t>(edata.size()));
    }

    // section headers (sequentially after the optional header)
    std::size_t sh = opt + (is64 ? 0xf0 : 0xe0);
    for (const auto& s : sections) {
        std::string nm = s.name;
        nm.resize(8, '\0');
        std::copy(nm.begin(), nm.end(), out.begin() + sh);
        w32(sh + 8, static_cast<std::uint32_t>(s.data.size()));  // VirtualSize
        w32(sh + 12, s.rva);                                     // VirtualAddress
        w32(sh + 16, s.raw_size);                                // SizeOfRawData
        w32(sh + 20, s.raw_ptr);                                 // PointerToRawData
        w32(sh + 24, 0);                                         // PointerToRelocations
        w32(sh + 28, 0);                                         // PointerToLinenumbers
        w16(sh + 32, 0);                                         // NumberOfRelocations
        w16(sh + 34, 0);                                         // NumberOfLinenumbers
        w32(sh + 36, s.characteristics);                         // Characteristics
        sh += 40;
        std::copy(s.data.begin(), s.data.end(), out.begin() + s.raw_ptr);
    }

    const auto dir = rootfs / "Windows" / "System32";
    fs::create_directories(dir);
    std::ofstream out_file(dir / dll_name, std::ios::binary);
    out_file.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
}

// The CRT keeps the command line in *data* exports (`_acmdln` is a char*, not
// a function). A real msvcrt.dll exports the variable itself, so the loader's
// IAT write is correct; a synthesized stub can only export a code cell, and a
// guest reading it as a pointer dereferences the 0xC3 fill. For the stub
// rootfs the IAT slot is therefore pointed at a heap copy of the command line
// (the value the real variable holds).
inline void patch_data_export_slots(Qiling& ql, const fs::path& sample) {
    auto parsed = LIEF::PE::Parser::parse(sample.string());
    if (parsed == nullptr) {
        return;
    }
    const auto& loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
    const auto& cmdline = loader.cmdline();
    if (cmdline.empty()) {
        return;
    }
    const auto image_base = static_cast<std::uint64_t>(parsed->imagebase());
    const auto ptr = ql.arch().pointersize();

    // `_acmdln` is the *variable* (a char*): the import slot holds the
    // address of the variable, and the variable holds the pointer to the
    // text. The synthesized stub exports a 16-byte code cell, so the cell
    // itself becomes the variable: the text pointer is written into it.
    auto& heap = ql.os<os::windows::QlOsWindows>().heap();
    std::uint64_t narrow_text = 0;
    std::uint64_t wide_text = 0;
    const auto ensure_narrow = [&]() {
        if (narrow_text == 0) {
            std::vector<std::uint8_t> bytes(cmdline.begin(), cmdline.end());
            bytes.push_back(0);
            narrow_text = heap.alloc(bytes.size() + 8);
            ql.mem().write(narrow_text, bytes);
        }
        return narrow_text;
    };
    const auto ensure_wide = [&]() {
        if (wide_text == 0) {
            std::vector<std::uint8_t> bytes;
            for (const auto c : cmdline) {
                if (c == 0) {
                    break;
                }
                bytes.push_back(c);
                bytes.push_back(0);
            }
            bytes.push_back(0);
            bytes.push_back(0);
            wide_text = heap.alloc(bytes.size() + 8);
            ql.mem().write(wide_text, bytes);
        }
        return wide_text;
    };

    for (const auto& imported : parsed->imports()) {
        auto dll = imported.name();
        for (auto& c : dll) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        for (const auto& entry : imported.entries()) {
            const auto name = entry.name();
            std::uint64_t text = 0;
            if (name == "_acmdln") {
                text = ensure_narrow();
            } else if (name == "_wcmdln") {
                text = ensure_wide();
            } else {
                continue;
            }
            // the stub dll's export cell is the variable: the loader's IAT map
            // already points the guest's slot at it, so both the direct
            // `_acmdln` read and `__p__acmdln`'s `*p` land on the text
            const auto* iat = loader.import_address_table_at(dll);
            const auto cell = iat != nullptr ? iat->lookup(name) : 0;
            if (cell != 0) {
                ql.mem().write_ptr(cell, static_cast<std::int64_t>(text), ptr);
            } else {
                ql.mem().write_ptr(image_base + entry.iat_address(), text, ptr);
            }
        }
    }
}

// a unique, wiped rootfs per run (the temp dirs persist across processes; the
// stale dlls from an earlier run would leak into the loader's dll walks)
inline fs::path make_rootfs(const std::string& tag) {
    static int counter = 0;
    const auto base = fs::temp_directory_path() /
                      ("ql_pegasus_" + tag + "_" + std::to_string(counter++));
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base);
    return base;
}

}  // namespace pe_sample_detail

// the per-run capture the tests assert on
struct SampleOutcome {
    bool ran = false;
    int exit_code = -1;
    std::string error;                                        // the exception text
    std::string output;                                       // the guest stdout
    std::map<std::string, std::vector<std::uint64_t>> api;    // name -> ret values
    std::set<std::string> strings;                            // the decoded guest strings
    std::vector<std::pair<std::string, std::uint64_t>> entries;  // dll entry -> return
    std::uint64_t imagebase = 0;                                 // the main image base
    std::vector<std::string> modules;                            // the loaded dll names
    std::vector<std::string> error_types;                        // the entry-point error taxonomy
    std::vector<qiling::os::windows::EntryPointError> errors;    // type + message + pc
    std::vector<ApiCallRecord> calls;                            // every dispatch, in call order
    std::map<std::string, std::vector<IndicatorEvent>> indicators;  // the behavioural indicators
    std::map<std::string, RegionAccessStats> memory_access;      // per-region counters (analysis)
    std::set<std::uint64_t> coverage;                            // the retired pcs (analysis)
    std::vector<qiling::os::ArtifactRecord> artifacts;           // the artifact manifest
    std::size_t unsupported = 0;                                 // imports with no handler
    std::vector<std::string> unsupported_apis;                   // their names (the real gap signal)

    // the call records for one api name (empty when never dispatched)
    const std::vector<std::uint64_t>& retvals(const std::string& name) const {
        static const std::vector<std::uint64_t> kEmpty{};
        const auto it = api.find(name);
        return it == api.end() ? kEmpty : it->second;
    }
    bool called(const std::string& name) const { return api.find(name) != api.end(); }
    bool output_has(const std::string& needle) const {
        return output.find(needle) != std::string::npos;
    }
};

// the run configuration knobs the fixtures need
struct SampleOptions {
    std::vector<std::string> argv;                                       // the guest argv tail
    std::vector<std::pair<std::string, std::string>> files;              // rootfs path -> content
    std::map<std::string, std::vector<std::string>> stub_extras;         // dll -> extra exports
    std::function<void(Qiling&)> configure;                             // per-run tweaks
    std::function<void(Qiling&)> after_run;                             // post-run probe (a memory dump)
    std::uint64_t max_api_count = 0;                                     // the api budget guard
    std::uint64_t timeout = 0;                                           // seconds (0 = none)
    std::uint64_t count = 0;                                             // instruction budget (0 = none)
    std::optional<std::filesystem::path> sample_path;                                // run an out-of-tree sample (the PMA corpus)
    // run against a caller-seeded rootfs instead of synthesizing one (the
    // differential hands both emulators the same tree, so the stub dll export
    // sets cannot differ between them); the sample must already sit at
    // <rootfs>/Windows/<name>
    std::optional<std::filesystem::path> rootfs;
    std::string api_record;   // the deterministic-replay store (Phase 5.5)
    std::string api_replay;
    // the upstream test knobs the qiling PE suite drives
    QL_STOP stop = QL_STOP::NONE;                                       // the stop condition (return_main fixtures)
    std::optional<std::uint64_t> end;                                   // run(end=...) — a pc to stop at
    std::string stdin_text;                                             // seeded guest stdin (the crackme fixture)
    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> patches;  // ql.patch(addr, bytes)
    std::optional<std::string> profile;                                 // a user profile (the gandcrab fixtures)
    bool analysis = false;  // memory-tracing + coverage (PLAN_PARITY Phase 3 item 4)
    // PLAN_PARITY Phase 3 item 5: a non-empty dir turns on the content-addressed
    // artifact store; `artifacts` selects guest ranges to save as `BEGIN:SIZE`
    std::string artifact_dir;
    // PLAN_PARITY Phase 3 item 6: the config-parity surface
    std::vector<std::pair<std::string, std::string>> fs_mappings;  // guest, host
    std::vector<std::string> volumes;                              // "host:guest"
    std::vector<qiling::QilingOptions::RegistryPatch> registry_patches;
    std::vector<std::string> artifacts;
    bool api_replay_serve = false;
};

// ---------------------------------------------------------------------------
// The real-dll comparison mode.
//
// Every comparison against ../pegasus runs with the real System32 tree: the
// reference's own fixtures are ordinary CRT-linked binaries, and a synthesized
// stub dll cannot answer for the CRT (the initializer walk, the locale
// accessors, the unwinder). Set TAOTE_WINDOWS_ROOTFS to a tree holding
// x86_windows/ and x8664_windows/ and the comparison suites resolve the arch for
// the sample, stage it at <rootfs>/Windows/<name> (the runner does not stage into
// a caller-provided rootfs) and return the rootfs to run against. Unset, the
// suites keep the deterministic stub path.
inline std::filesystem::path real_comparison_base() {
    if (const char* env = std::getenv("TAOTE_WINDOWS_ROOTFS"); env != nullptr && *env != '\0') {
        return std::filesystem::path(env);
    }
    return {};
}

// the PE COFF machine of a sample (0x14c i386, 0x8664 amd64)
inline unsigned real_comparison_machine(const std::filesystem::path& sample) {
    std::ifstream f(sample, std::ios::binary);
    if (!f) {
        return 0;
    }
    std::vector<char> head(0x400);
    f.read(head.data(), static_cast<std::streamsize>(head.size()));
    const auto got = static_cast<std::size_t>(f.gcount());
    if (got < 0x40 || head[0] != 'M' || head[1] != 'Z') {
        return 0;
    }
    const auto read_at = [&](std::size_t off, std::size_t n) -> std::uint32_t {
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            v |= static_cast<std::uint32_t>(static_cast<unsigned char>(head[off + i])) << (8 * i);
        }
        return v;
    };
    const auto lfanew = read_at(0x3c, 4);
    if (lfanew + 6 > got) {
        return 0;
    }
    return read_at(lfanew + 4, 2);
}

// The rootfs to compare against for one sample, with the sample staged into it.
// An empty path means "no real tree configured: use the stub rootfs".
inline std::filesystem::path stage_into_real_rootfs(const std::filesystem::path& sample) {
    const auto base = real_comparison_base();
    if (base.empty()) {
        return {};
    }
    const auto arch = real_comparison_machine(sample) == 0x8664 ? "x8664_windows" : "x86_windows";
    const auto rootfs = base / arch;
    std::error_code ec;
    if (!std::filesystem::exists(rootfs / "Windows" / "System32" / "kernel32.dll", ec)) {
        return {};
    }
    std::filesystem::create_directories(rootfs / "Windows", ec);
    std::filesystem::copy_file(sample, rootfs / "Windows" / sample.filename(),
                               std::filesystem::copy_options::overwrite_existing, ec);
    return ec ? std::filesystem::path{} : rootfs;
}

inline SampleOutcome run_pe_sample(const std::string& bin_name, const SampleOptions& opts = {}) {
    using namespace pe_sample_detail;
    namespace fs = std::filesystem;

    SampleOutcome out;
    const fs::path sample = opts.sample_path ? *opts.sample_path : bins_dir() / bin_name;
    if (!fs::exists(sample)) {
        out.error = "missing fixture: " + sample.string();
        return out;
    }

    // Every comparison against ../pegasus runs in real-dll mode: when a real
    // tree is configured and the caller did not pin a rootfs, stage this sample
    // into it and run there (see stage_into_real_rootfs). The caller's explicit
    // opts.rootfs still wins, and with no tree configured the stub path runs
    // exactly as before.
    SampleOptions run_opts = opts;
    if (!run_opts.rootfs.has_value()) {
        if (const auto real = stage_into_real_rootfs(sample); !real.empty()) {
            run_opts.rootfs = real;
        }
    }

    std::unique_ptr<Qiling> ql_storage;
    fs::path capture_path;
    std::shared_ptr<QlFile> capture_file;

    // the captured guest output + the stats record — read from whatever state
    // the run reached, so a faulted sample still reports its API calls and its
    // entry-point error class
    const auto capture_stats = [&]() {
        if (capture_file) {
            capture_file->close();
        }
        if (!capture_path.empty()) {
            std::ifstream in(capture_path, std::ios::binary);
            out.output.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        if (ql_storage == nullptr) {
            return;
        }
        auto& qlr = *ql_storage;
        out.errors = qlr.os<qiling::os::windows::QlOsWindows>().entry_point_errors();
        for (const auto& err : out.errors) {
            out.error_types.push_back(err.type);
        }
        if (!out.ran) {
            // a faulted run still has a meaningful exit code (STATUS_*)
            out.exit_code = qlr.os().exit_code();
        }
        const auto& stats = qlr.os().stats();
        out.unsupported = stats.unsupported_api_count();
        out.unsupported_apis.assign(stats.unsupported_apis().begin(), stats.unsupported_apis().end());
        for (const auto& [name, records] : stats.syscalls()) {
            auto& dst = out.api[name];
            for (const auto& r : records) {
                dst.push_back(r.retval);
                out.calls.push_back(r);
            }
        }
        // the stats map is keyed by name, so restore the dispatch order the
        // position counter recorded (the parity tool diffs sequences)
        std::sort(out.calls.begin(), out.calls.end(),
                  [](const ApiCallRecord& a, const ApiCallRecord& b) { return a.position < b.position; });
        out.indicators = stats.indicators();
        out.memory_access = stats.memory_access();
        out.coverage = stats.coverage();
        out.artifacts = qlr.os().artifacts().records();
        for (const auto& [s, addrs] : stats.strings()) {
            (void)addrs;
            out.strings.insert(s);
        }
    };

    Qiling* ql_after = nullptr;  // the post-run probe's handle (set once the run owns it)
    std::shared_ptr<std::deque<std::uint64_t>> pc_ring;  // TAOTE_PE_TRACE ring
    std::shared_ptr<HookRet> trace_hook;
    try {
        const auto plan = plan_for(sample);
        const auto rootfs = run_opts.rootfs.has_value() ? *run_opts.rootfs
                                                    : make_rootfs(fs::path(bin_name).stem().string());

        // the synthesized system dlls (plus the caller-provided extra exports —
        // the real modules export far more than the import table names)
        for (const auto& [dll, exports] : plan.imports) {
            if (run_opts.rootfs.has_value()) {
                break;
            }
            auto names = exports;
            const auto extra = run_opts.stub_extras.find(dll);
            if (extra != run_opts.stub_extras.end()) {
                for (const auto& name : extra->second) {
                    if (std::find(names.begin(), names.end(), name) == names.end()) {
                        names.push_back(name);
                    }
                }
            }
            write_stub_dll(rootfs, dll, names, plan.is64);
        }
        // the same key dlls the reference's harness always seeds
        // (tools/stub_dlls.py): the loader's sys_dlls tuple asks for all of
        // them on every PE run, and a missing image means no LDR entry, no
        // heap allocation for it and therefore a shifted heap for every later
        // guest allocation - an environment difference, not a guest one
        for (const char* key_dll : {"ntdll.dll", "kernelbase.dll", "kernel32.dll",
                                    "ucrtbase.dll", "mscoree.dll"}) {
            if (run_opts.rootfs.has_value()) {
                break;
            }
            if (!fs::exists(rootfs / "Windows" / "System32" / key_dll)) {
                auto names = std::vector<std::string>{};
                for (const auto& [dll, exports] : plan.imports) {
                    if (dll == key_dll) {
                        names = exports;
                    }
                }
                write_stub_dll(rootfs, key_dll, names, plan.is64);
            }
        }
        fs::create_directories(rootfs / "Windows" / "registry");
        fs::create_directories(rootfs / "qltest");
        for (const auto& [name, content] : run_opts.files) {
            const auto path = rootfs / name;
            fs::create_directories(path.parent_path());
            std::ofstream f(path, std::ios::binary);
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

        const auto exe_in_rootfs = rootfs / "Windows" / sample.filename().string();
        if (!run_opts.rootfs.has_value()) {
            fs::copy_file(sample, exe_in_rootfs, fs::copy_options::overwrite_existing);
        }

        QilingOptions options;
        options.rootfs = rootfs.string();
        options.ostype = QL_OS::WINDOWS;
        options.archtype = plan.is64 ? QL_ARCH::X8664 : QL_ARCH::X86;
        // the loader's debug walk (the redirect ladder, the unbound imports, the
        // DllMain bail-outs) is the tool for the real-dll rootfs debugging —
        // flip it with TAOTE_VERBOSE=debug instead of an opt field
        if (const char* v = std::getenv("TAOTE_VERBOSE"); v != nullptr && std::strcmp(v, "debug") == 0) {
            options.verbose = QL_VERBOSE::DEBUG;
        }
        options.max_api_count = run_opts.max_api_count;
        options.timeout = run_opts.timeout;
        options.count = run_opts.count;
        options.api_record_path = run_opts.api_record;
        options.api_replay_path = run_opts.api_replay;
        options.analysis = run_opts.analysis;
        options.artifact_dir = run_opts.artifact_dir;
        options.fs_mappings = run_opts.fs_mappings;
        options.volumes = run_opts.volumes;
        options.registry_patches = run_opts.registry_patches;
        options.api_replay_serve = run_opts.api_replay_serve;
        options.profile = run_opts.profile;
        options.stop = run_opts.stop;
        options.argv.push_back(exe_in_rootfs.string());
        for (const auto& a : run_opts.argv) {
            options.argv.push_back(a);
        }

        ql_storage = std::make_unique<Qiling>(std::move(options));
        Qiling& ql = *ql_storage;
        ql_after = &ql;
        capture_path = rootfs / "guest_stdout.txt";

        // the guest stdout capture (the printf/puts renders land here)
        auto captured = QlFile::open_mode(capture_path.string(), "w+b");
        capture_file = captured;
        ql.os().set_stdout(captured);

        // the seeded guest stdin (core.py hooking the fd table; here the tests
        // that need a scripted input hand it in whole)
        if (!run_opts.stdin_text.empty()) {
            const auto stdin_path = rootfs / "guest_stdin.txt";
            {
                std::ofstream f(stdin_path, std::ios::binary);
                f.write(run_opts.stdin_text.data(), static_cast<std::streamsize>(run_opts.stdin_text.size()));
            }
            ql.os().set_stdin(QlFile::open_mode(stdin_path.string(), "rb"));
        }

        for (const auto& [addr, bytes] : run_opts.patches) {
            ql.patch(addr, bytes);
        }

        // the loader state the module-system checks assert on
        {
            const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
            out.imagebase = pe_loader.pe_image_address();
            for (const auto& [dll, names] : plan.imports) {
                (void)names;
                if (pe_loader.get_image_by_name(dll, true) != nullptr) {
                    out.modules.push_back(dll);
                }
            }
        }

        // a pc-ring for diagnostics: TAOTE_PE_TRACE=N keeps the last N retired
        // instructions (with their pcs) so a fault can be read back in order
        if (const char* env = std::getenv("TAOTE_PE_TRACE"); env != nullptr && *env != '\0') {
            const auto keep = static_cast<std::size_t>(std::strtoull(env, nullptr, 0));
            pc_ring = std::make_shared<std::deque<std::uint64_t>>();
            trace_hook = std::make_shared<HookRet>(ql.hook_code(
                [pc_ring, keep](std::uint64_t address, std::uint32_t) {
                    pc_ring->push_back(address);
                    while (pc_ring->size() > (keep == 0 ? 64 : keep)) {
                        pc_ring->pop_front();
                    }
                    return 0;
                }));
        }

        if (run_opts.configure) {
            run_opts.configure(ql);
        }

        if (!run_opts.rootfs.has_value()) {
            // the data-export shim only applies to the synthesized stubs
            patch_data_export_slots(ql, sample);
        }

        const auto file_name = lower(sample.filename().string());
        const bool is_dll = file_name.size() > 4 &&
                            (file_name.compare(file_name.size() - 4, 4, ".dll") == 0 ||
                             file_name.compare(file_name.size() - 5, 5, ".dll_") == 0);
        // a dll target always runs through the drive (DllMain, then every named
        // export): the corpus dlls often carry an export table LIEF cannot
        // enumerate in this build, and running one as a program executes the
        // entry point with an argument set it never expects
        if (is_dll) {
            // drive the DllMain and every export: stage a return address into
            // a mapped ret cell so each entry returns cleanly to the driver
            const auto& loader = static_cast<const loader::QlLoaderPE&>(ql.loader());
            const auto imagebase = loader.pe_image_address();
            const auto cave = ql.mem().find_free_space(0x1000, 0x20000000ull, std::nullopt, 0x1000ull);
            ql.mem().map(cave, 0x1000, UC_PROT_ALL, "[ret cave]");
            ql.mem().write(cave, std::vector<std::uint8_t>{0xC3});
            const auto sp0 = ql.arch().regs().arch_sp();
            const std::uint64_t ptr = plan.is64 ? 8 : 4;

            const auto run_entry = [&](std::uint64_t addr, const std::string& tag) {
                // the DllMain contract: (HINSTANCE, DLL_PROCESS_ATTACH, LPVOID)
                // — the CRT startup branches on the reason, so the drive has
                // to hand reason = 1 down or it takes the detach path
                std::uint64_t sp = sp0;
                if (plan.is64) {
                    ql.arch().regs().write("rcx", imagebase);  // hinst
                    ql.arch().regs().write("rdx", 1);          // DLL_PROCESS_ATTACH
                    ql.arch().regs().write("r8", 0);           // the reserved cell
                    sp -= ptr;
                    ql.mem().write_ptr(sp, cave, ptr);
                } else {
                    sp -= 4;
                    ql.mem().write_ptr(sp, 0, 4);                             // the reserved cell
                    sp -= 4;
                    ql.mem().write_ptr(sp, 1, 4);                              // DLL_PROCESS_ATTACH
                    sp -= 4;
                    ql.mem().write_ptr(sp, imagebase, 4);                      // hinst
                    sp -= 4;
                    ql.mem().write_ptr(sp, cave, 4);                           // the return address
                }
                ql.arch().regs().set_arch_sp(sp);
                ql.run(addr, cave);
                out.entries.emplace_back(tag, ql.arch().regs().read(plan.is64 ? "rax" : "eax"));
            };

            run_entry(imagebase + plan.entry_rva, "DllMain");
            for (const auto& [name, rva] : plan.exports_own) {
                if (name == "DllMain" || rva == plan.entry_rva) {
                    continue;
                }
                run_entry(imagebase + rva, name);
            }
            out.ran = true;
            out.exit_code = 0;
        } else {
            if (run_opts.end.has_value()) {
                ql.run(std::nullopt, run_opts.end);
            } else {
                ql.run();
            }
            out.ran = true;
            out.exit_code = ql.os().exit_code();
        }

        // the artifact store: save the requested guest ranges while the memory
        // is still there (the manifest is captured below)
        for (const auto& spec : run_opts.artifacts) {
            const auto colon = spec.find(':');
            const auto begin = static_cast<std::uint64_t>(std::stoull(spec.substr(0, colon), nullptr, 0));
            const auto size = static_cast<std::uint64_t>(std::stoull(spec.substr(colon + 1), nullptr, 0));
            ql.os().artifacts().save_memory(ql, begin, size);
        }

        if (run_opts.after_run) {
            run_opts.after_run(ql);
        }

        capture_stats();
    } catch (const std::exception& e) {
        out.error = e.what();
        if (pc_ring) {
            std::fprintf(stderr, "pc trace (last %zu):\n", pc_ring->size());
            for (const auto pc : *pc_ring) {
                std::fprintf(stderr, "  0x%llx\n", static_cast<unsigned long long>(pc));
            }
        }
        if (run_opts.after_run && ql_after != nullptr) {
            try {
                run_opts.after_run(*ql_after);
            } catch (...) {
            }
        }
        capture_stats();
    } catch (...) {
        out.error = "unknown exception";
        capture_stats();
    }
    return out;
}

}  // namespace testing

}  // namespace qiling

#endif  // QILING_TESTS_PE_SAMPLE_RUNNER_HPP
