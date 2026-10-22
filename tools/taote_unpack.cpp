// tools/taote_unpack.cpp — the unpacker CLI (PLAN_UNPACK.md §3 Phase 0).
//
// The flag surface is pegasus's, so the reference evaluation harness
// (tools/unpack_eval/run_all.sh) drives taote unmodified:
//
//   taote_unpack -t <packed.exe> --unpack --unpack-output <dir> --unpack-timeout 85
//
// Artifacts (the reference's contract, PLAN_UNPACK §1.6):
//   <stem>_dump.bin            the image at the OEP
//   <stem>_dump.bin.meta.json  base / oep / oep_last_hop / is_64 / stages /
//                              reason / imports
//   <stem>_unpacked.exe        the rebuilt file-layout PE
//
// Rootfs: the unpacker runs against a synthesized stub-dll rootfs by default
// (deterministic, and the analogue of the reference's decoy modules). --rootfs
// points at a real Windows tree instead; the sample is staged into
// <rootfs>/Windows/ for that case.
#include <LIEF/PE.hpp>

#include <csignal>
#include <execinfo.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "../tests/Pe_Sample_Runner.hpp"
#include "qiling/const.hpp"
#include "qiling/unpack/unpack.hpp"

namespace fs = std::filesystem;
using qiling::testing::SampleOptions;
using qiling::testing::pe_sample_detail::plan_for;
using qiling::testing::pe_sample_detail::write_stub_dll;

namespace {

void usage() {
    std::cout << "usage: taote_unpack -t <sample> [--unpack] [--unpack-output DIR]\n"
                 "                    [--unpack-timeout SECONDS] [--rootfs DIR] [--json]\n"
                 "                    [--no-hop] [--argv ARGS] [--count N] [--family NAME]\n"
                 "\n"
                 "  -t, --target PATH        the packed PE to unpack\n"
                 "      --unpack             enable unpacking (default when -t is given)\n"
                 "      --unpack-output DIR  artifact directory (default: ./unpacked)\n"
                 "      --unpack-timeout S   emulation budget in seconds (default: 120)\n"
                 "      --rootfs DIR         run against a real Windows tree (x86_windows/\n"
                 "                           or x8664_windows/), else a stub rootfs is made\n"
                 "      --json               print the result as one JSON object\n"
                 "      --no-hop             disable section-hop OEP detection (the Phase 0\n"
                 "                           artifact-only mode: dump the entry state)\n"
                 "      --family NAME        family label for the metadata (default: auto)\n";
}

std::string json_escape(const std::string& in) {
    std::string out;
    for (unsigned char c : in) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

// The family label the detector would produce; the Phase 2 detector replaces
// this. Kept in the tool so --family can override it for experiments.
std::string guess_family(const fs::path& sample) {
    auto parsed = LIEF::PE::Parser::parse(sample.string());
    if (parsed == nullptr) {
        return "unknown";
    }
    std::vector<std::string> names;
    for (const auto& s : parsed->sections()) {
        std::string n = s.name();
        for (auto& c : n) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        names.push_back(n);
    }
    const auto has = [&names](const char* want) {
        for (const auto& n : names) {
            if (n.find(want) != std::string::npos) {
                return true;
            }
        }
        return false;
    };
    if (has("upx0") && has("upx1")) return "UPX";
    if (has(".aspack") || has(".adata")) return "ASPack";
    if (has(".mpress1")) return "MPRESS";
    if (has("mew")) return "MEW";
    if (has("nsp0") || has("nsp1")) return "NSPack";
    if (has("petite")) return "PEtite";
    if (has(".packed") || has(".rlpack")) return "RLPack";
    if (has(".neolit")) return "Neolite";
    if (has(".alien")) return "Alienyze";
    if (has(".yp")) return "YodaProtector";
    if (has("$win8")) return "Exe32pack";
    if (has("fsg")) return "FSG";
    if (has(".upack")) return "WinUpack";
    if (has(".enigma1") || has(".enigma2")) return "EnigmaVB";
    if (has(".themida")) return "Themida";
    if (has(".jdpack")) return "JDPack";
    if (has(".packman")) return "Packman";
    if (has(".bero")) return "BeRoEXEPacker";
    if (has(".eronana")) return "Eronana";
    if (has(".ex_cod") || has(".ex_dat")) return "EXpressor";
    return "unknown";
}

}  // namespace

namespace {
// TAOTE_UNPACK_BT: a host crash prints its stack instead of dying silently
// (the unpack path parses attacker-controlled images; Phase 6 hardens it, this
// makes the first failure diagnosable).
void crash_trace(int) {
    void* frames[64];
    const int n = ::backtrace(frames, 64);
    std::fprintf(stderr, "[taote_unpack] host fault, backtrace:\n");
    ::backtrace_symbols_fd(frames, n, 2);
    std::_Exit(139);
}
}  // namespace

int main(int argc, char** argv) {
    if (std::getenv("TAOTE_UNPACK_BT") != nullptr) {
        std::signal(SIGSEGV, crash_trace);
        std::signal(SIGABRT, crash_trace);
    }
    std::string target;
    std::string out_dir = "./unpacked";
    std::string rootfs;
    std::string family;
    std::string argv_tail;
    std::uint64_t timeout = 120;
    // The instruction budget is a safety net, not the primary limiter (the
    // simulated-time budget is). The reference has no instruction cap at all
    // (max_instructions_ = -1); 40M was cutting slow decoders short — measured:
    // aspack/upx/mpress/packman/mew/jdpack AccessEnum and the EXpressor/MEW/
    // Molebox/BeRo/WinUpack AD* samples all reach the exact OEP and a correct
    // dump only when the budget is raised (they now grade UNPACKED_VERIFIED).
    std::uint64_t count = 200000000;
    bool json = false;
    // TAOTE_UNPACK_NO_HOP: the Phase 0 artifact-only mode, settable by env so the
    // reference harness (which only passes the pegasus flags) can drive it
    bool enable_hop = std::getenv("TAOTE_UNPACK_NO_HOP") == nullptr;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if ((arg == "-t" || arg == "--target") && i + 1 < argc) {
            target = argv[++i];
        } else if (arg == "--unpack") {
            // the flag only exists for harness compatibility: -t unpacks
        } else if (arg == "--unpack-output" && i + 1 < argc) {
            out_dir = argv[++i];
        } else if (arg == "--unpack-timeout" && i + 1 < argc) {
            timeout = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--rootfs" && i + 1 < argc) {
            rootfs = argv[++i];
        } else if (arg == "--family" && i + 1 < argc) {
            family = argv[++i];
        } else if (arg == "--argv" && i + 1 < argc) {
            argv_tail = argv[++i];
        } else if (arg == "--count" && i + 1 < argc) {
            count = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--json") {
            json = true;
        } else if (arg == "--no-hop") {
            enable_hop = false;
        } else if (arg == "-h" || arg == "--help") {
            usage();
            return 0;
        } else {
            std::cerr << "taote_unpack: unknown argument " << arg << "\n";
            return 2;
        }
    }
    if (target.empty()) {
        usage();
        return 2;
    }
    const fs::path sample(target);
    if (!fs::exists(sample)) {
        std::cerr << "taote_unpack: no such file: " << target << "\n";
        return 2;
    }

    qiling::os::register_dlls();

    // ---- the rootfs: a caller-provided tree, or a synthesized stub one
    fs::path run_rootfs;
    const auto plan = plan_for(sample);
    if (!rootfs.empty()) {
        run_rootfs = fs::path(rootfs);
        // the arch subtree, when the caller pointed at a base directory
        if (!fs::exists(run_rootfs / "Windows" / "System32")) {
            const auto arch_dir = plan.is64 ? "x8664_windows" : "x86_windows";
            if (fs::exists(run_rootfs / arch_dir / "Windows" / "System32")) {
                run_rootfs = run_rootfs / arch_dir;
            }
        }
        fs::create_directories(run_rootfs / "Windows");
        fs::copy_file(sample, run_rootfs / "Windows" / sample.filename(),
                      fs::copy_options::overwrite_existing);
    } else {
        run_rootfs = fs::temp_directory_path() /
                     ("taote_unpack_" + std::to_string(::getpid()) + "_" +
                      std::to_string(std::hash<std::string>{}(sample.string()) % 100000));
        fs::create_directories(run_rootfs / "Windows" / "System32");
        fs::create_directories(run_rootfs / "Windows" / "registry");
        for (const auto& [dll, exports] : plan.imports) {
            write_stub_dll(run_rootfs, dll, exports);
        }
        for (const char* key_dll : {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll",
                                    "mscoree.dll"}) {
            if (!fs::exists(run_rootfs / "Windows" / "System32" / key_dll)) {
                std::vector<std::string> names;
                for (const auto& [dll, exports] : plan.imports) {
                    if (dll == key_dll) {
                        names = exports;
                    }
                }
                write_stub_dll(run_rootfs, key_dll, names);
            }
        }
        fs::copy_file(sample, run_rootfs / "Windows" / sample.filename(),
                      fs::copy_options::overwrite_existing);
    }

    const auto exe_in_rootfs = run_rootfs / "Windows" / sample.filename();

    qiling::QilingOptions options;
    options.rootfs = run_rootfs.string();
    options.ostype = qiling::QL_OS::WINDOWS;
    options.archtype = plan.is64 ? qiling::QL_ARCH::X8664 : qiling::QL_ARCH::X86;
    options.timeout = timeout;
    options.count = count;
    options.argv.push_back(exe_in_rootfs.string());
    if (!argv_tail.empty()) {
        options.argv.push_back(argv_tail);
    }

    qiling::unpack::UnpackOptions uopts;
    uopts.sample_path = sample.string();
    uopts.out_dir = out_dir;
    uopts.enable_hop = enable_hop;
    uopts.family = family.empty() ? guess_family(sample) : family;
    uopts.rootfs = run_rootfs.string();
    uopts.allow_decoy_dlls = rootfs.empty();  // never write into a caller's tree
    uopts.debug = std::getenv("TAOTE_UNPACK_DEBUG") != nullptr;
    qiling::unpack::Unpacker unpacker(uopts);

    qiling::unpack::UnpackResult result;
    std::string run_error;
    // the engine must outlive the armed hooks: finalize() clears them before the
    // unique_ptr releases the Qiling (a HookRet destructor calls into the engine)
    std::unique_ptr<qiling::Qiling> ql;
    std::shared_ptr<qiling::QlFile> captured;
    try {
        ql = std::make_unique<qiling::Qiling>(options);
        const auto capture_path = run_rootfs / "guest_stdout.txt";
        captured = qiling::QlFile::open_mode(capture_path.string(), "w+b");
        ql->os().set_stdout(captured);
        unpacker.install(*ql);
        try {
            // TAOTE_UNPACK_START=<hex>: start the emulation somewhere other than the
            // header EP (a dev switch for the samples whose packed EP is bogus —
            // NSPack writes 0x101b into a zero-filled section head)
            if (const char* start_env = std::getenv("TAOTE_UNPACK_START")) {
                const auto start_va = std::strtoull(start_env, nullptr, 0);
                if (start_va != 0) {
                    ql->set_entry_point(start_va);
                    std::fprintf(stderr, "[unpack] start forced to 0x%llx\n",
                                 static_cast<unsigned long long>(start_va));
                }
            }
            ql->run();
        } catch (const qiling::QlErrorBase& e) {
            // the guest faulted: the artifact is still produced from whatever
            // state the run reached (the reference does the same)
            run_error = e.what();
        }
    } catch (const qiling::QlErrorBase& e) {
        result.error = e.what();
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    if (ql != nullptr) {
        if (captured != nullptr) {
            captured->close();
        }
        const auto fin = unpacker.finalize(*ql);
        result = fin;
        ql.reset();
    } else {
        unpacker.detach_hooks();
    }

    if (!run_error.empty() && result.error.empty()) {
        result.error = run_error;
    }

    if (json) {
        std::printf(
            "{\"sample\":\"%s\",\"family\":\"%s\",\"base\":\"0x%llx\",\"oep\":\"0x%llx\","
            "\"oep_last_hop\":\"0x%llx\",\"stages\":%u,\"is_64\":%s,\"reason\":\"%s\","
            "\"imports\":%zu,\"dump\":%s,\"unpacked\":%s,\"outfile\":\"%s\",\"error\":\"%s\"}\n",
            json_escape(sample.filename().string()).c_str(), json_escape(result.family).c_str(),
            static_cast<unsigned long long>(result.base), static_cast<unsigned long long>(result.oep),
            static_cast<unsigned long long>(result.oep_last_hop), result.stages,
            result.is_64 ? "true" : "false", json_escape(result.reason).c_str(), result.imports.size(),
            result.dump_written ? "true" : "false", result.rebuilt ? "true" : "false",
            json_escape(result.outfile).c_str(), json_escape(result.error).c_str());
    } else {
        std::printf("[unpack] %s family=%s base=0x%llx oep=0x%llx stages=%u reason=%s imports=%zu%s%s\n",
                    sample.filename().string().c_str(), result.family.c_str(),
                    static_cast<unsigned long long>(result.base),
                    static_cast<unsigned long long>(result.oep), result.stages, result.reason.c_str(),
                    result.imports.size(), result.error.empty() ? "" : " error=",
                    result.error.c_str());
    }
    if (!rootfs.empty()) {
        // do not leave the staged sample behind in a caller-provided tree
        std::error_code ec;
        fs::remove(exe_in_rootfs, ec);
    }
    return 0;
}
