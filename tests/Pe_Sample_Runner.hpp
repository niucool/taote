// tests/Pe_Sample_Runner.hpp — the fixture runner for the Windows API sample
// binaries (the ../pegasus tests/bins set, vendored under tests/data/pegasus).
//
// Each sample imports the real system dlls (kernel32.dll, ntdll.dll, the
// api-ms-win-crt-* redirects, msvcrt.dll, ...). The runner LIEF-parses the
// import table, synthesizes one stub dll per imported module (the
// tests/Pe_Stub.hpp technique, extended to any arch: a PE32+ image with one
// 16-byte ret cell per export and image entry 0), stages them into a private
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
#include <cstdint>
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
        if (!names.empty()) {
            plan.imports.emplace_back(lower(imp.name()), std::move(names));
        }
    }

    // LIEF reports the entrypoint as a VA and the export addresses as RVAs in
    // this build (see the loader's own note) — normalize the entry to an RVA
    plan.imagebase = static_cast<std::uint64_t>(bin->imagebase());
    plan.entry_rva = static_cast<std::uint32_t>(bin->entrypoint() - plan.imagebase);
    if (bin->get_export() != nullptr) {
        for (const auto& e : bin->get_export()->entries()) {
            plan.exports_own.emplace_back(e.name(), static_cast<std::uint32_t>(e.address()));
        }
    }
    return plan;
}

// the minimal stub dll: the correct PE headers/sections/export table, one
// 0xC3 cell per export, entry point 0 (so the loader's DllMain drive skips).
// Always PE32+: the vcpkg LIEF cannot round-trip its own PE32 images (the
// re-parse loses the export table), and a 0xC3 cell is valid in both ISAs.
inline void write_stub_dll(const fs::path& rootfs, const std::string& dll_name,
                           const std::vector<std::string>& exports) {
    auto factory = LIEF::PE::Factory::create(LIEF::PE::PE_TYPE::PE32_PLUS);

    std::vector<std::uint8_t> code(std::max<std::size_t>(exports.size(), 1) * 16, 0xC3);
    LIEF::PE::Section text(".text");
    text.content(code);
    text.virtual_size(static_cast<std::uint32_t>(code.size()));
    factory->add_section(text);

    auto bin = factory->get();

    std::uint32_t text_rva = 0;
    for (const auto& sec : bin->sections()) {
        if (sec.name() == ".text") {
            text_rva = sec.virtual_address();
        }
    }

    std::vector<LIEF::PE::ExportEntry> entries;
    for (std::size_t i = 0; i < exports.size(); ++i) {
        entries.emplace_back(exports[i], text_rva + static_cast<std::uint32_t>(i * 16));
    }
    if (!entries.empty()) {
        bin->set_export(LIEF::PE::Export(dll_name, entries));
    }

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

    const auto dir = rootfs / "Windows" / "System32";
    fs::create_directories(dir);
    std::ofstream out(dir / dll_name, std::ios::binary);
    const auto& bytes = builder.get_build();
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
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
};

inline SampleOutcome run_pe_sample(const std::string& bin_name, const SampleOptions& opts = {}) {
    using namespace pe_sample_detail;
    namespace fs = std::filesystem;

    SampleOutcome out;
    const fs::path sample = bins_dir() / bin_name;
    if (!fs::exists(sample)) {
        out.error = "missing fixture: " + sample.string();
        return out;
    }

    try {
        const auto plan = plan_for(sample);
        const auto rootfs = make_rootfs(fs::path(bin_name).stem().string());

        // the synthesized system dlls (plus the caller-provided extra exports —
        // the real modules export far more than the import table names)
        for (const auto& [dll, exports] : plan.imports) {
            auto names = exports;
            const auto extra = opts.stub_extras.find(dll);
            if (extra != opts.stub_extras.end()) {
                for (const auto& name : extra->second) {
                    if (std::find(names.begin(), names.end(), name) == names.end()) {
                        names.push_back(name);
                    }
                }
            }
            write_stub_dll(rootfs, dll, names);
        }
        fs::create_directories(rootfs / "Windows" / "registry");
        fs::create_directories(rootfs / "qltest");
        for (const auto& [name, content] : opts.files) {
            const auto path = rootfs / name;
            fs::create_directories(path.parent_path());
            std::ofstream f(path, std::ios::binary);
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

        const auto exe_in_rootfs = rootfs / "Windows" / sample.filename().string();
        fs::copy_file(sample, exe_in_rootfs, fs::copy_options::overwrite_existing);

        QilingOptions options;
        options.rootfs = rootfs.string();
        options.ostype = QL_OS::WINDOWS;
        options.archtype = plan.is64 ? QL_ARCH::X8664 : QL_ARCH::X86;
        options.argv.push_back(exe_in_rootfs.string());
        for (const auto& a : opts.argv) {
            options.argv.push_back(a);
        }

        Qiling ql(std::move(options));

        // the guest stdout capture (the printf/puts renders land here)
        const auto capture_path = rootfs / "guest_stdout.txt";
        auto captured = QlFile::open_mode(capture_path.string(), "w+b");
        ql.os().set_stdout(captured);

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

        if (opts.configure) {
            opts.configure(ql);
        }

        if (sample.extension() == ".dll" && !plan.exports_own.empty()) {
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
            ql.run();
            out.ran = true;
            out.exit_code = ql.os().exit_code();
        }

        // the captured guest output + the stats record
        captured->close();
        {
            std::ifstream in(capture_path, std::ios::binary);
            out.output.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        const auto& stats = ql.os().stats();
        for (const auto& [name, records] : stats.syscalls()) {
            auto& dst = out.api[name];
            for (const auto& r : records) {
                dst.push_back(r.retval);
            }
        }
        for (const auto& [s, addrs] : stats.strings()) {
            (void)addrs;
            out.strings.insert(s);
        }
    } catch (const std::exception& e) {
        out.error = e.what();
    } catch (...) {
        out.error = "unknown exception";
    }
    return out;
}

}  // namespace testing
}  // namespace qiling

#endif  // QILING_TESTS_PE_SAMPLE_RUNNER_HPP
