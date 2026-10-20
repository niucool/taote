// tools/parity_trace.cpp — the taote side of the qiling-parity differential
// (PLAN_PARITY.md Phase 1.9).
//
// It runs one PE through the same in-tree sample runner the tests use
// (tests/Pe_Sample_Runner.hpp: synthesize stub dlls, real QlOsWindows path) and
// dumps what taote observed as JSON, in the shape
// tools/qiling_reference_runner.py emits for the reference:
//
//   { "emulator": "taote", "sample": ..., "image_base": ...,
//     "apis": [ { "position": 0, "name": "GetStdHandle", "retval": ...,
//                 "retaddr": ... } ],
//     "stdout": "...", "strings": [...], "exit_code": ...,
//     "error": "...", "error_types": [...] }
//
// tools/parity_vs_qiling.py runs both sides and diffs the normalized traces.
//
// usage: parity_trace <sample> [--argv A B] [--count N] [--timeout S]
//                     [--max-api-count N] [--dump-imports FILE] [--out FILE]
//                     [--code-trace FILE] [--code-trace-range BEGIN END]
//                     [--mem-watch FILE BEGIN SIZE] [--dump-heap FILE]
//                     [--dump-images FILE] [--dump-mem FILE BEGIN SIZE]
//                     [--record-api FILE] [--replay-api FILE] [--replay-serve]
#include <LIEF/PE.hpp>

#include <algorithm>
#include <iomanip>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../tests/Pe_Sample_Runner.hpp"

namespace {

std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
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

std::uint64_t parse_u64(const char* text) {
    return static_cast<std::uint64_t>(std::strtoull(text, nullptr, 0));
}

}  // namespace

// the code-trace hook outlives the configure callback (HookRet unregisters on
// destruction)
std::shared_ptr<qiling::HookRet> code_hook;
std::shared_ptr<qiling::HookRet> mem_watch_hook;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: parity_trace <sample> [--argv A B] [--count N] [--timeout S] [--max-api-count N]\n"
                 "                   [--dump-imports FILE] [--out FILE]\n";
        return 2;
    }

    const std::string sample = argv[1];
    std::string out_path;
    std::string dump_imports;
    std::string code_trace;
    std::string api_record;
    std::string api_replay;
    bool replay_serve = false;
    std::string rootfs;
    std::string dump_mem;
    std::string dump_images;
    std::string dump_heap;
    std::string mem_watch;
    std::uint64_t dump_mem_begin = 0;
    std::uint64_t dump_mem_size = 0;
    std::uint64_t mem_watch_begin = 0;
    std::uint64_t mem_watch_size = 0;
    std::uint64_t code_begin = 0;
    std::uint64_t code_end = 0;
    qiling::testing::SampleOptions opts;
    opts.count = 0;
    opts.timeout = 0;
    opts.max_api_count = 0;

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--argv") {
            while (i + 1 < argc && std::strncmp(argv[i + 1], "--", 2) != 0) {
                opts.argv.emplace_back(argv[++i]);
            }
        } else if (arg == "--count" && i + 1 < argc) {
            opts.count = parse_u64(argv[++i]);
        } else if (arg == "--timeout" && i + 1 < argc) {
            opts.timeout = parse_u64(argv[++i]);
        } else if (arg == "--max-api-count" && i + 1 < argc) {
            opts.max_api_count = parse_u64(argv[++i]);
        } else if (arg == "--dump-imports" && i + 1 < argc) {
            dump_imports = argv[++i];
        } else if (arg == "--record-api" && i + 1 < argc) {
            api_record = argv[++i];
        } else if (arg == "--replay-api" && i + 1 < argc) {
            api_replay = argv[++i];
        } else if (arg == "--replay-serve") {
            replay_serve = true;
        } else if (arg == "--rootfs" && i + 1 < argc) {
            rootfs = argv[++i];
        } else if (arg == "--dump-mem" && i + 3 < argc) {
            dump_mem = argv[++i];
            dump_mem_begin = parse_u64(argv[++i]);
            dump_mem_size = parse_u64(argv[++i]);
        } else if (arg == "--dump-images" && i + 1 < argc) {
            dump_images = argv[++i];
        } else if (arg == "--dump-heap" && i + 1 < argc) {
            dump_heap = argv[++i];
        } else if (arg == "--mem-watch" && i + 3 < argc) {
            mem_watch = argv[++i];
            mem_watch_begin = parse_u64(argv[++i]);
            mem_watch_size = parse_u64(argv[++i]);
        } else if (arg == "--code-trace" && i + 1 < argc) {
            code_trace = argv[++i];
        } else if (arg == "--code-trace-range" && i + 2 < argc) {
            code_begin = parse_u64(argv[++i]);
            code_end = parse_u64(argv[++i]);
        } else if (arg == "--out" && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            std::cerr << "parity_trace: unknown argument " << arg << "\n";
            return 2;
        }
    }

    // the dll handler surface is registered once per process (the tests do this
    // in their fixture; a standalone tool has to do it itself)
    qiling::os::register_dlls();

    // the resolved import stubs, for diagnosing "the guest called the wrong API"
    // (stub address -> export name, as the loader built them)
    if (!dump_imports.empty()) {
        opts.configure = [&dump_imports, &sample](qiling::Qiling& ql) {
            std::ofstream out(dump_imports);
            const auto& loader = static_cast<const qiling::loader::QlLoaderPE&>(ql.loader());
            for (const auto& [addr, entry] : loader.import_symbols()) {
                out << std::hex << addr << " " << entry.name << "\n";
            }

            // and the guest's own IAT: for every import entry, the slot in the
            // image and the stub address the loader wrote there. `import_symbols`
            // says what the loader *can* dispatch; this says what the guest will
            // actually call, which is what a "why did the guest call X" question
            // needs (the two disagree whenever a slot is left unwritten).
            const auto parsed = LIEF::PE::Parser::parse(sample);
            if (parsed != nullptr) {  // NOLINT(bugprone-unused-return-value)
                const auto image_base = static_cast<std::uint64_t>(parsed->imagebase());
                const auto pointer_size = ql.arch().pointersize();
                for (const auto& imported : parsed->imports()) {
                    for (const auto& entry : imported.entries()) {
                        const auto slot = image_base + entry.iat_address();
                        std::uint64_t target = 0;
                        try {
                            const auto raw = ql.mem().read(slot, pointer_size);
                            for (std::size_t i = raw.size(); i-- > 0;) {
                                target = (target << 8) | raw[i];
                            }
                        } catch (const std::exception&) {
                            target = 0;
                        }
                        const auto it = loader.import_symbols().find(target);
                        out << "iat " << std::hex << slot << " -> " << target << " "
                            << (it != loader.import_symbols().end() ? it->second.name : std::string("?"))
                            << " (" << entry.name() << ")\n";
                    }
                }
            }
        };
    }

    // an instruction-level trace over a pc window: the differ compares API
    // calls, so a control-flow divergence between two dispatches (where the two
    // guests execute *different code* with no differing API value in between)
    // is invisible to it - this is the probe for exactly that
    if (!code_trace.empty()) {
        opts.configure = [&code_trace, &code_begin, &code_end, previous = opts.configure](qiling::Qiling& ql) {
            if (previous) {
                previous(ql);
            }
            auto out = std::make_shared<std::ofstream>(code_trace);
            // HookRet is RAII: dropping it unregisters the hook, so the handle
            // outlives the configure callback
            code_hook = std::make_shared<qiling::HookRet>(ql.hook_code([out, code_begin, code_end, &ql](
                std::uint64_t address, std::uint32_t size) {
                if (address >= code_begin && (code_end == 0 || address < code_end)) {
                    // the stack pointer rides along: a stack-content divergence
                    // between two identical instruction streams shows up here
                    // first (the same `ret` popping different values)
                    *out << std::hex << address << " " << std::dec << size << " "
                         << std::hex << ql.arch().regs().arch_sp() << "\n";
                }
                return 0;
            }));
        };
    }

    // watch guest writes into one memory window, with the pc that wrote: the
    // probe for "two runs executed the same instructions but a stack slot ends
    // up holding a different value"
    if (!mem_watch.empty()) {
        opts.configure = [&mem_watch, &mem_watch_begin, &mem_watch_size, previous = opts.configure](qiling::Qiling& ql) {
            if (previous) {
                previous(ql);
            }
            auto out = std::make_shared<std::ofstream>(mem_watch);
            mem_watch_hook = std::make_shared<qiling::HookRet>(ql.hook_mem_write(
                [out, &ql, mem_watch_begin, mem_watch_size](int, std::uint64_t address, std::uint32_t size, std::int64_t value) {
                    if (address + size > mem_watch_begin && address < mem_watch_begin + mem_watch_size) {
                        *out << std::hex << ql.arch().regs().arch_pc() << " " << address << " " << std::dec << size
                             << " " << std::hex << static_cast<std::uint64_t>(value) << "\n";
                    }
                    return 0;
                }));
        };
    }

    // the loader's image table right after load: what a dll walk actually
    // resolved (a stub the reference found and taote did not shifts the heap
    // and changes which imports resolve)
    if (!dump_images.empty()) {
        auto previous = opts.configure;
        opts.configure = [&dump_images, previous](qiling::Qiling& ql) {
            if (previous) {
                previous(ql);
            }
            std::ofstream out(dump_images);
            const auto& pe_loader = static_cast<const qiling::loader::QlLoaderPE&>(ql.loader());
            for (const auto& image : pe_loader.images) {
                out << std::hex << image.base << " " << image.path << "\n";
            }
            const auto& cmdline = pe_loader.cmdline();
            out << "cmdline '" << std::string(cmdline.begin(), cmdline.end()) << "'\n";
        };
    }

    // the heap's chunk table right after load: the probe for "both runs
    // dispatch the same allocator calls but the addresses come out shifted",
    // which is the loader's own allocations, not the guest's
    if (!dump_heap.empty()) {
        auto previous = opts.configure;
        opts.configure = [&dump_heap, previous](qiling::Qiling& ql) {
            if (previous) {
                previous(ql);
            }
            auto& heap = ql.os<qiling::os::windows::QlOsWindows>().heap();
            std::ofstream out(dump_heap);
            out << "start " << std::hex << heap.start_address() << "\n";
            out << std::hex;
            for (const auto& c : heap.chunks()) {
                out << c.address << " " << std::dec << c.size << (c.inuse ? " inuse" : " free") << " ";
                std::vector<std::uint8_t> raw;
                try {
                    raw = ql.mem().read(c.address, std::min<std::uint64_t>(c.size, 64));
                } catch (...) {
                }
                for (const auto b : raw) {
                    out << (b >= 0x20 && b < 0x7f ? static_cast<char>(b) : '.');
                }
                out << "\n";
            }
        };
    }

    // the run-end memory window: "what did this cell hold when the guest
    // stopped", which is how an IAT slot / stack cell divergence is settled
    if (!dump_mem.empty()) {
        opts.after_run = [&dump_mem, &dump_mem_begin, &dump_mem_size](qiling::Qiling& ql) {
            std::ofstream out(dump_mem);
            std::vector<std::uint8_t> raw;
            try {
                raw = ql.mem().read(dump_mem_begin, dump_mem_size);
            } catch (const std::exception& e) {
                out << "unreadable: " << e.what() << "\n";
                return;
            }
            out << std::hex;
            for (std::size_t i = 0; i < raw.size(); i += 4) {
                out << (dump_mem_begin + i) << ": ";
                for (std::size_t j = i; j < std::min(i + 4, raw.size()); ++j) {
                    out << std::setw(2) << std::setfill('0') << static_cast<unsigned>(raw[j]) << " ";
                }
                out << "\n";
            }
        };
    }

    // the deterministic-replay store: record every dispatch's answer, or
    // re-check a later run against the recording (PLAN_PARITY Phase 5.5)
    opts.api_record = api_record;
    opts.api_replay = api_replay;
    opts.api_replay_serve = replay_serve;

    // the shared rootfs: the differential seeds one tree for both emulators so
    // their stub dll export sets (and the paths the guest sees) cannot differ
    if (!rootfs.empty()) {
        opts.rootfs = std::filesystem::path(rootfs);
    }

    opts.sample_path = std::filesystem::path(sample);
    const auto outcome = qiling::testing::run_pe_sample(std::filesystem::path(sample).filename().string(), opts);

    std::ostringstream js;
    js << "{";
    js << "\"emulator\":\"taote\"";
    js << ",\"sample\":\"" << json_escape(std::filesystem::path(sample).filename().string()) << "\"";
    js << ",\"ran\":" << (outcome.ran ? "true" : "false");
    js << ",\"exit_code\":" << outcome.exit_code;
    js << ",\"image_base\":" << outcome.imagebase;
    js << ",\"unsupported\":" << outcome.unsupported;
    js << ",\"error\":\"" << json_escape(outcome.error) << "\"";
    js << ",\"error_types\":[";
    for (std::size_t i = 0; i < outcome.error_types.size(); ++i) {
        js << (i ? "," : "") << "\"" << json_escape(outcome.error_types[i]) << "\"";
    }
    js << "]";
    js << ",\"apis\":[";
    for (std::size_t i = 0; i < outcome.calls.size(); ++i) {
        const auto& c = outcome.calls[i];
        if (i) {
            js << ",";
        }
        js << "{\"position\":" << c.position << ",\"name\":\"" << json_escape(c.name) << "\"";
        js << ",\"dll\":\"" << json_escape(c.dll) << "\"";
        js << ",\"params\":[";
        for (std::size_t k = 0; k < c.params.size(); ++k) {
            js << (k ? "," : "") << "\"" << json_escape(c.params[k]) << "\"";
        }
        js << "]";
        js << ",\"retval\":" << (c.retval_present ? std::to_string(c.retval) : std::string("null"));
        js << ",\"retaddr\":" << c.retaddr;
        js << ",\"address\":" << c.address << "}";
    }
    js << "]";
    js << ",\"indicators\":[";
    {
        bool first_ind = true;
        for (const auto& [kind, events] : outcome.indicators) {
            for (const auto& ev : events) {
                js << (first_ind ? "" : ",") << "{\"kind\":\"" << json_escape(ev.kind) << "\",\"target\":\""
                   << json_escape(ev.target) << "\",\"position\":" << ev.position << "}";
                first_ind = false;
            }
        }
    }
    js << "]";
    js << ",\"stdout\":\"" << json_escape(outcome.output) << "\"";
    js << ",\"strings\":[";
    std::size_t i = 0;
    for (const auto& s : outcome.strings) {
        js << (i++ ? "," : "") << "\"" << json_escape(s) << "\"";
    }
    js << "]}";

    const std::string text = js.str();
    if (out_path.empty()) {
        std::cout << text;
    } else {
        std::ofstream out(out_path, std::ios::binary);
        out << text;
    }
    return 0;
}
