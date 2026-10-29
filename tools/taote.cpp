// tools/taote.cpp — the unpacker CLI (PLAN_UNPACK.md §3 Phase 0).
//
// The flag surface is pegasus's, so the reference evaluation harness
// (tools/unpack_eval/run_all.sh) drives taote unmodified:
//
//   taote -t <packed.exe> --unpack --unpack-output <dir> --unpack-timeout 85
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
//
// Profiles: the Windows PE defaults are built into the binary (the exact
// contents of qiling/profiles/windows.ql), so no .ql file is required. A
// `--profile <file>` layers a user profile on top, and repeated
// `--set SECTION.KEY=VALUE` overrides individual values (wins over --profile).
#include <LIEF/PE.hpp>

#include <csignal>
#if !defined(_WIN32)
#include <execinfo.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../tests/Pe_Sample_Runner.hpp"
#include "qiling/const.hpp"
#include "qiling/unpack/packer_detector.hpp"
#include "qiling/unpack/unpack.hpp"

namespace fs = std::filesystem;
using qiling::testing::SampleOptions;
using qiling::unpack::detect_from_file;
using qiling::testing::pe_sample_detail::plan_for;
using qiling::testing::pe_sample_detail::write_stub_dll;

namespace {

void usage() {
    std::cout << "usage: taote -t <sample> [--unpack] [--unpack-output DIR]\n"
                 "                 [--unpack-timeout SECONDS] [--rootfs DIR] [--json]\n"
                 "                 [--no-hop] [--argv ARGS] [--count N] [--family NAME]\n"
                 "                 [--profile FILE] [--set SECTION.KEY=VALUE]...\n"
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
                 "      --family NAME        family label for the metadata (default: auto)\n"
                 "      --profile FILE       load a .ql profile over the built-in defaults\n"
                 "      --set S.K=V          override one profile value (repeatable; wins\n"
                 "                           over --profile), e.g. --set KERNEL.pid=42\n";
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

// The family label routes the run to a packer seam (qiling/unpack/packers). The
// detector lives in the library so the tests can assert on it and so the tool has
// no unpacking logic of its own.
std::string guess_family(const fs::path& sample) {
    const auto det = detect_from_file(sample.string());
    if (std::getenv("TAOTE_DEBUG_DETECTOR") != nullptr) {
        std::fprintf(stderr, "[detector] %s -> %s (%s%s%s)\n", sample.filename().string().c_str(), det.name.c_str(),
                     det.sig_kind.c_str(), det.detail.empty() ? "" : ": ", det.detail.c_str());
    }
    return det.name;
}

}  // namespace

namespace {
#if !defined(_WIN32)
// TAOTE_UNPACK_BT: a host crash prints its stack instead of dying silently
// (the unpack path parses attacker-controlled images; Phase 6 hardens it, this
// makes the first failure diagnosable). backtrace() is glibc-only, so the
// handler is POSIX-only; Windows runs degrade to the plain crash.
void crash_trace(int) {
    void* frames[64];
    const int n = ::backtrace(frames, 64);
    std::fprintf(stderr, "[taote] host fault, backtrace:\n");
    ::backtrace_symbols_fd(frames, n, 2);
    std::_Exit(139);
}
#endif
}  // namespace

int main(int argc, char** argv) {
#if !defined(_WIN32)
    if (std::getenv("TAOTE_UNPACK_BT") != nullptr) {
        std::signal(SIGSEGV, crash_trace);
        std::signal(SIGABRT, crash_trace);
    }
#endif
    std::string target;
    std::string out_dir = "./unpacked";
    std::string rootfs;
    std::string family;
    std::string argv_tail;
    std::string profile_path;
    std::map<std::string, std::map<std::string, std::string>> profile_overrides;
    std::uint64_t timeout = 120;
    // The instruction budget is a safety net, not the primary limiter (the
    // simulated-time budget is). The reference has no instruction cap at all
    // (max_instructions_ = -1); 40M was cutting slow decoders short — measured:
    // aspack/upx/mpress/packman/mew/jdpack AccessEnum and the EXpressor/MEW/
    // Molebox/BeRo/WinUpack AD* samples all reach the exact OEP and a correct
    // dump only when the budget is raised (they now grade UNPACKED_VERIFIED).
    // Instruction cap. The time budget (--unpack-timeout) is the real limiter for
    // runaway stubs; this is the fallback for a stub that spins without touching
    // the clock. 200M truncated real payloads before their own import resolver ran:
    // winupack_Procmon ended at exactly 2e8 instructions with 715 mined pairs at
    // recall 0.005, and 600M lets the same run FINISH (40-46s, under the budget) at
    // recall 1.000. Measured with the 86-sample fair set at a 300s budget: taote
    // 23/86 vs the reference's 74/86, with imports 28 vs 75 - the count, not the
    // wall clock, was the binding constraint on that whole class.
    std::uint64_t count = 2000000000;
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
        } else if (arg == "--profile" && i + 1 < argc) {
            profile_path = argv[++i];
        } else if (arg == "--set" && i + 1 < argc) {
            const std::string spec = argv[++i];
            const auto eq = spec.find('=');
            const auto dot = spec.find('.');
            if (eq == std::string::npos || dot == std::string::npos || dot == 0 || eq < dot ||
                dot + 1 == eq || eq + 1 == spec.size()) {
                std::cerr << "taote: --set expects SECTION.KEY=VALUE, got: " << spec << "\n";
                return 2;
            }
            profile_overrides[spec.substr(0, dot)][spec.substr(dot + 1, eq - dot - 1)] =
                spec.substr(eq + 1);
        } else if (arg == "-h" || arg == "--help") {
            usage();
            return 0;
        } else {
            std::cerr << "taote: unknown argument " << arg << "\n";
            return 2;
        }
    }
    if (target.empty()) {
        usage();
        return 2;
    }
    const fs::path sample(target);
    if (!fs::exists(sample)) {
        std::cerr << "taote: no such file: " << target << "\n";
        return 2;
    }

    qiling::os::register_dlls();

    // ---- the rootfs: a caller-provided tree, or a synthesized stub one
    // An input LIEF cannot parse (two FSG samples in the corpus) used to
    // std::terminate here; report it as an error instead, like every other
    // per-sample failure.
    fs::path run_rootfs;
    qiling::testing::pe_sample_detail::SamplePlan plan;
    try {
        plan = plan_for(sample);
    } catch (const std::exception& e) {
        std::printf("[unpack] %s family=unknown base=0x0 oep=0x0 stages=0 reason=input_parse_failed "
                    "imports=0 error=%s\n", sample.filename().string().c_str(), e.what());
        return 1;
    }
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
        // Sweep temp trees left behind by runs that died before their cleanup
        // (a host abort or SIGKILL skips the RAII guard, and a long harness run
        // leaks one copy of the stub tree per crashed sample: 11k dirs / 5.3GB
        // measured). Only our own prefix, only trees older than an hour.
        try {
            const auto tmp = fs::temp_directory_path();
            const auto now = fs::file_time_type::clock::now();
            for (const auto& e : fs::directory_iterator(tmp)) {
                const auto name = e.path().filename().string();
                if (name.rfind("taote_", 0) != 0 || !e.is_directory()) {
                    continue;
                }
                std::error_code ec;
                const auto when = fs::last_write_time(e.path(), ec);
                if (ec || now - when < std::chrono::hours(1)) {
                    continue;
                }
                fs::remove_all(e.path(), ec);
            }
        } catch (...) {
        }
        run_rootfs = fs::temp_directory_path() /
                     ("taote_" + std::to_string(::getpid()) + "_" +
                      std::to_string(std::hash<std::string>{}(sample.string()) % 100000));
        fs::create_directories(run_rootfs / "Windows" / "System32");
        fs::create_directories(run_rootfs / "Windows" / "registry");
        for (const auto& [dll, exports] : plan.imports) {
            write_stub_dll(run_rootfs, dll, exports, plan.is64);
        }
        // The five key DLLs every guest needs. Round 22 measured a WIDER set
        // here (user32, advapi32, gdi32, shell32, ole32, oleaut32, comctl32,
        // shlwapi, version, psapi, ws2_32, wininet, crypt32, iphlpapi,
        // userenv) and it was NOT kept: corpus all-three 1588 -> 1584 (1 gain /
        // 5 losses) because a sample whose LoadLibraryA used to fail now loads
        // an export-less stub and keeps working, so borderline runs crossed the
        // 85s harness budget and their import salvage collapsed
        // (pecompact_PEViewer import recall 1.0 -> 0.035 at dur 58 -> 85,
        // pecompact_cpuz_x32 1.0 -> 0.046 at 48 -> 85, pecompact_ComIntRep
        // 1.0 -> 0.047 at 79 -> 85, mpress_ComIntRep 1.0 -> 0.905 at 79 -> 85).
        // It also did not convert Amber. A wider rootfs needs to come with a
        // budget story, not on its own.
        for (const char* key_dll : {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll",
                                    "mscoree.dll"}) {
            if (!fs::exists(run_rootfs / "Windows" / "System32" / key_dll)) {
                std::vector<std::string> names;
                for (const auto& [dll, exports] : plan.imports) {
                    if (dll == key_dll) {
                        names = exports;
                    }
                }
                write_stub_dll(run_rootfs, key_dll, names, plan.is64);
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
    if (!profile_path.empty()) {
        options.profile = std::move(profile_path);
    }
    options.profile_overrides = std::move(profile_overrides);
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
