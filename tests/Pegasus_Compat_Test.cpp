// tests/Pegasus_Compat_Test.cpp — the behavioural parity checks ported from
// the pegasus suite (../pegasus/tests/<name>.cpp).
//
// The pegasus tests drive the pegasus C++ API (Pegasus/PegasusConfig/report
// events); the taote equivalents assert the same observable behaviour through
// the qiling port's own surfaces: the guest stdout render, the QlOsStats API
// log (name -> the ret values in call order), the read_string log, the loader
// images and the QlOsWindows state. See tests/PEGASUS_TEST_PARITY.md for the
// per-test mapping and the tests that stay pegasus-only.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "qiling/loader/pe.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/volumes.hpp"
#include "qiling/gdbserver.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <thread>
#include "qiling/os/windows/dlls/dlls.hpp"
#include "qiling/os/windows/windows.hpp"

#include "Pe_Sample_Runner.hpp"
#include "qiling/os/windows/ntdefs.hpp"
#include "qiling/os/windows/structs.hpp"

using qiling::testing::SampleOptions;
using qiling::testing::SampleOutcome;
using qiling::testing::run_pe_sample;

namespace {

// The stats string log (stats.py log_string) records the decoded strings
// tokenized on whitespace, so a multi-word MessageBox text is asserted word
// by word: every word of the expected text has to show up.
bool has_words(const SampleOutcome& out, const std::string& text) {
    std::string word;
    for (char c : text) {
        if (c == ' ') {
            if (!word.empty() && out.strings.count(word) == 0) return false;
            word.clear();
        } else {
            word.push_back(c);
        }
    }
    return word.empty() || out.strings.count(word) == 1;
}

}  // namespace

// ---- test_argv.cpp: ArgvTest.ArgvPassedToExe ------------------------------
// The x86 CRT sample prints argc and every argv entry; taote must hand the
// tail arguments through to the guest unchanged.
TEST(PegasusParity, ArgvPassedToExe) {
    qiling::os::register_dlls();

    SampleOptions opts;
    std::vector<std::string> argv;
    for (int i = 0; i < 10; ++i) {
        argv.push_back("argument_" + std::to_string(i + 1));
    }
    opts.argv = argv;

    const auto out = run_pe_sample("argv_test_x86.exe", opts);
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);
    EXPECT_EQ(out.exit_code, 0);

    // argc counts argv[0] + the 10 tail arguments
    EXPECT_TRUE(out.output_has("argc = 11")) << out.output;
    for (int i = 0; i < 10; ++i) {
        const auto line = "argv[" + std::to_string(i + 1) + "] = argument_" + std::to_string(i + 1);
        EXPECT_TRUE(out.output_has(line)) << "missing: " << line << "\n" << out.output;
    }

    // the sample renders one printf per argument (pegasus: printf_count >= 10)
    EXPECT_GE(out.retvals("__stdio_common_vfprintf").size(), 10u);
}

// ---- test_get_proc_address.cpp: GetProcAddressTest.MissingFunctionReturnsZero
// The sample looks four exports up through GetProcAddress: the third one
// (AreFileApisANSI) is exported and must resolve, the fourth
// (ThisFunctionIsNotExportedByKernel32) must answer NULL.
TEST(PegasusParity, ApiRecordsCarryTheDllAndRenderedArguments) {
    // PLAN_PARITY Phase 3: the analysis surface. A record names its module, so
    // an expectation can be dll-qualified (KERNEL32.GetProcAddress) the way
    // pegasus's cases are, and the arguments are rendered - strings as their
    // text, everything else as a hex scalar - which is what an
    // argument-sensitive expectation needs.
    const auto out = run_pe_sample("file_access_test_x86.exe");

    const auto find = [&out](const std::string& name) -> const qiling::ApiCallRecord* {
        for (const auto& call : out.calls) {
            if (call.name == name) {
                return &call;
            }
        }
        return nullptr;
    };

    const auto* load = find("LoadLibraryW");
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->dll, "kernel32.dll");
    ASSERT_EQ(load->params.size(), 1u);
    // the wide string argument is rendered as its text, not its pointer
    EXPECT_EQ(load->params[0], "lpLibFileName='ntdll.dll'");

    // a scalar argument stays a hex scalar
    const auto* feature = find("IsProcessorFeaturePresent");
    ASSERT_NE(feature, nullptr);
    ASSERT_EQ(feature->params.size(), 1u);
    EXPECT_EQ(feature->params[0], "ProcessorFeature=0xa");
}

TEST(PegasusParity, AnalysisOptionRecordsRegionCountersAndCoverage) {
    // PLAN_PARITY Phase 3 item 4: one option folds pegasus's
    // cfg.analysis.memory_tracing + coverage into the existing stats - the
    // per-region read/write counters and the set of pcs that retired - instead
    // of a parallel profiler.
    qiling::os::register_dlls();

    SampleOptions opts;
    opts.analysis = true;
    const auto out = run_pe_sample("argv_test_x86.exe", opts);

    ASSERT_EQ(out.exit_code, 0);
    EXPECT_FALSE(out.coverage.empty()) << "the guest executed code, so coverage cannot be empty";
    // the counters are keyed by the mapped region's label, so the image, the
    // stack and the TEB's FS segment each carry their own numbers
    ASSERT_FALSE(out.memory_access.empty());
    const auto image = out.memory_access.find("argv_test_x86.exe");
    ASSERT_NE(image, out.memory_access.end());
    EXPECT_GT(image->second.reads, 0u);
    EXPECT_GT(image->second.writes, 0u);
    EXPECT_GT(image->second.bytes_read, 0u);
    const auto stack = out.memory_access.find("[stack]");
    ASSERT_NE(stack, out.memory_access.end());
    EXPECT_GT(stack->second.writes, 0u);

    // and the surface is opt-in: without the option nothing is recorded
    const auto plain = run_pe_sample("argv_test_x86.exe");
    EXPECT_TRUE(plain.coverage.empty());
    EXPECT_TRUE(plain.memory_access.empty());
}

TEST(PegasusParity, VirtualClockAdvancesOnSleepInsteadOfWallTime) {
    // PLAN_PARITY Phase 5.4: with the virtual clock on, Sleep advances the
    // guest's clock instead of spending host time, so a sample that measures
    // elapsed time is deterministic; with it off the port keeps upstream's
    // behaviour (a passthrough and a constant GetTickCount).
    namespace os = qiling::os;
    os::register_dlls();

    const auto tick = [](const std::optional<std::uint64_t>& v) { return v.value_or(0); };

    {
        qiling::QilingOptions options;
        options.ostype = qiling::QL_OS::WINDOWS;
        options.archtype = qiling::QL_ARCH::X86;
        options.rootfs = std::filesystem::temp_directory_path().string();
        options.code = std::vector<std::uint8_t>{0xC3};
        options.virtual_clock = true;
        qiling::Qiling ql{options};

        auto* tick_api = os::ApiRegistry::instance().find("GetTickCount");
        auto* sleep_api = os::ApiRegistry::instance().find("Sleep");
        ASSERT_NE(tick_api, nullptr);
        ASSERT_NE(sleep_api, nullptr);

        const auto before = tick(tick_api->handler(ql, 0, {}));
        EXPECT_EQ(before, 200000u);  // the upstream base

        (void)sleep_api->handler(ql, 0, os::ResolvedParams{{"dwMilliseconds", 1500ull}});

        EXPECT_EQ(tick(tick_api->handler(ql, 0, {})), 201500u) << "Sleep must move the virtual clock";
        EXPECT_EQ(ql.os<os::windows::QlOsWindows>().virtual_time_ms(), 201500u);
    }

    {
        // off: the upstream constant, and Sleep changes nothing
        qiling::QilingOptions options;
        options.ostype = qiling::QL_OS::WINDOWS;
        options.archtype = qiling::QL_ARCH::X86;
        options.rootfs = std::filesystem::temp_directory_path().string();
        options.code = std::vector<std::uint8_t>{0xC3};
        qiling::Qiling ql{options};

        auto* tick_api = os::ApiRegistry::instance().find("GetTickCount");
        auto* sleep_api = os::ApiRegistry::instance().find("Sleep");
        (void)sleep_api->handler(ql, 0, os::ResolvedParams{{"dwMilliseconds", 1500ull}});
        EXPECT_EQ(tick(tick_api->handler(ql, 0, {})), 200000u);
    }
}

TEST(PegasusParity, GdbServerServesRegistersMemoryAndSingleStep) {
    // PLAN_PARITY Phase 3 item 7: the gdbserver slice covers the three intents
    // the reference's test_gdb.cpp names (connect + read registers, read
    // memory, single step) over the real GDB remote protocol.
    namespace fs = std::filesystem;

    qiling::os::register_dlls();
    auto options = qiling::QilingOptions{};
    options.ostype = qiling::QL_OS::WINDOWS;
    options.archtype = qiling::QL_ARCH::X86;
    options.rootfs = fs::temp_directory_path().string();
    options.code = std::vector<std::uint8_t>{0x90, 0x90, 0x90, 0xC3};  // nop; nop; nop; ret
    qiling::Qiling ql{options};

    // shellcode staging: the loader records the entry (the pc is set by run),
    // so the server's step starts from there
    const auto pc = ql.loader().entry_point;
    ASSERT_NE(pc, 0u);
    ql.arch().regs().set_arch_pc(pc);

    qiling::QlGdb gdb(ql, "127.0.0.1", 0);
    gdb.start();
    ASSERT_NE(gdb.port(), 0);

    // the protocol surface, without a socket first
    EXPECT_EQ(gdb.handle_packet("?"), "S05");
    EXPECT_EQ(gdb.handle_packet("qSupported"), "PacketSize=1000;qXfer:features:read-");
    EXPECT_EQ(gdb.handle_packet("qAttached"), "1");
    const auto all = gdb.handle_packet("g");
    EXPECT_EQ(all.size(), ql.arch().bits() == 64 ? 24u * 16u : 16u * 8u);
    EXPECT_EQ(gdb.handle_packet("Z0,1000,1"), "OK");
    EXPECT_EQ(gdb.handle_packet("z0,1000,1"), "OK");
    // an unknown command answers an empty packet (the client's "unsupported")
    // - 'g' itself is the register read, so the probe must not start with one
    EXPECT_EQ(gdb.handle_packet("Xyz"), "");

    // the execution packets: a step retires exactly one instruction
    ql.arch().regs().set_arch_pc(pc);
    EXPECT_EQ(gdb.handle_packet("s"), "S05");
    EXPECT_EQ(ql.arch().regs().arch_pc(), pc + 1);
    char mreq[64];
    std::snprintf(mreq, sizeof(mreq), "m%lx,3", static_cast<unsigned long>(pc));
    EXPECT_EQ(gdb.handle_packet(mreq), "909090");

    // the transport, deterministically and bounded: a socketpair carries the
    // same packets, so no accept() is involved (a listener wait is bounded by
    // accept_client's poll budget, which the expiry arm below pins)
    int sv[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    std::thread server([&gdb, fd = sv[0]] { gdb.serve_fd(fd, 2000); });

    const auto rsp = [fd = sv[1]](std::string_view payload) -> std::string {
        char sum[8];
        std::uint8_t s = 0;
        for (const char c : payload) s = static_cast<std::uint8_t>(s + static_cast<std::uint8_t>(c));
        std::snprintf(sum, sizeof(sum), "#%02x", s);
        const std::string frame = "$" + std::string(payload) + sum;
        (void)::send(fd, frame.data(), frame.size(), 0);
        std::string reply;
        char ch = 0;
        while (::recv(fd, &ch, 1, 0) == 1) {
            if (ch == '$') break;
        }
        while (::recv(fd, &ch, 1, 0) == 1 && ch != '#') reply.push_back(ch);
        char ignored[2];
        (void)::recv(fd, ignored, 2, 0);
        return reply;
    };

    EXPECT_EQ(rsp("?"), "S05");
    EXPECT_EQ(rsp("qAttached"), "1");
    EXPECT_EQ(rsp("D"), "OK");
    ::close(sv[1]);
    if (server.joinable()) server.join();
    EXPECT_EQ(gdb.last_status(), qiling::QlGdbStatus::Detached);

    // the listener budget: with nobody connecting, accept_client expires rather
    // than blocking (the same discipline as the socket samples' wall clock)
    qiling::QlGdb idle(ql, "127.0.0.1", 0);
    idle.start();
    EXPECT_FALSE(idle.accept_client(50));
    EXPECT_EQ(idle.last_status(), qiling::QlGdbStatus::ListenTimeout);
    idle.stop();
    (void)ql;
}

TEST(PegasusParity, ConfigParityMountsFilesAndPatchesTheRegistry) {
    // PLAN_PARITY Phase 3 item 6: the config surface pegasus's test_volumes /
    // test_config rows set up per case - explicit guest->host mappings, the
    // "host:guest" volume specs (with their drive-letter colon quirk) and a
    // registry patch that lands in the diff store, not in a hive file.
    namespace fs = std::filesystem;
    namespace os = qiling::os;

    // the spec parser: the separator is the first ':' that is not a drive letter
    {
        const auto [host, guest] = os::parse_volume_spec("C:\\data:C:\\guest");
        EXPECT_EQ(host.string(), "C:\\data");
        EXPECT_EQ(guest, "C:\\guest");
        EXPECT_THROW(os::parse_volume_spec("no-separator"), qiling::QlErrorBase);
        EXPECT_THROW(os::parse_volume_spec(":guest"), qiling::QlErrorBase);
    }

    // a directory volume expands to one entry per file, sorted, backslashed
    {
        const auto tree = fs::temp_directory_path() / "ql_volume_tree";
        std::error_code ec;
        fs::remove_all(tree, ec);
        fs::create_directories(tree / "sub");
        std::ofstream(tree / "a.txt") << "a";
        std::ofstream(tree / "sub" / "b.txt") << "b";

        const auto entries = os::expand_volume_entries(tree, "C:\\mnt");
        ASSERT_EQ(entries.size(), 2u);
        EXPECT_EQ(entries[0].first, "C:\\mnt\\a.txt");
        EXPECT_EQ(entries[1].first, "C:\\mnt\\sub\\b.txt");
        fs::remove_all(tree, ec);
    }

    // and the run end: the mapping is visible to the guest's file APIs, the
    // volume's file is readable, and the registry patch answers a read
    qiling::os::register_dlls();
    SampleOptions opts;

    const auto host_file = fs::temp_directory_path() / "ql_volume_host.txt";
    std::ofstream(host_file) << "volume";

    opts.fs_mappings = {{"C:\\qltest\\mapped.txt", host_file.string()}};
    opts.volumes = {host_file.string() + ":C:\\qltest\\vol.txt"};
    opts.registry_patches = {{"HKEY_CURRENT_USER\\Software\\QilingTest", "Greeting", 1, "hi"}};

    opts.after_run = [](qiling::Qiling& ql) {
        auto* win = &ql.os<qiling::os::windows::QlOsWindows>();
        EXPECT_TRUE(win->fs_mapper()->file_exists("C:\\qltest\\mapped.txt"));
        EXPECT_TRUE(win->fs_mapper()->file_exists("C:\\qltest\\vol.txt"));

        // the patched value is readable and typed (REG_SZ -> text)
        const auto [type, value] = win->registry_manager().read("HKEY_CURRENT_USER\\Software\\QilingTest",
                                                               "Greeting", 1);
        ASSERT_TRUE(type.has_value());
        EXPECT_EQ(*type, 1);
        ASSERT_TRUE(value.has_value());
        const auto* text = std::get_if<std::string>(&*value);
        ASSERT_NE(text, nullptr);
        EXPECT_EQ(*text, "hi");
    };

    const auto out = run_pe_sample("argv_test_x86.exe", opts);
    ASSERT_EQ(out.exit_code, 0);
    fs::remove(host_file);
}

TEST(PegasusParity, ArtifactStoreIsContentAddressedAndManifested) {
    // PLAN_PARITY Phase 3 item 5: pegasus's test_artifact_store shape - dumps
    // are named by their content's sha256, stored once, and the manifest rides
    // the Snapshot envelope so a snapshot and its dumps travel together.
    namespace os = qiling::os;

    // the digest is the real SHA-256 (the NIST vectors)
    EXPECT_EQ(os::sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(os::sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const auto dir = std::filesystem::temp_directory_path() / "ql_artifacts_test";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);

    os::QlArtifactStore store(dir);
    const auto h1 = store.put("file", "a.bin", "hello");
    // the same bytes under a different label cost one blob, not two
    const auto h2 = store.put("file", "copy.bin", "hello");
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(h1, os::sha256_hex("hello"));
    ASSERT_EQ(store.records().size(), 1u);
    EXPECT_TRUE(store.contains(h1));
    EXPECT_TRUE(std::filesystem::exists(dir / h1));

    const auto back = store.get(h1);
    EXPECT_EQ(std::string(back.begin(), back.end()), "hello");

    // the manifest round-trips through the snapshot envelope
    qiling::SnapshotWriter writer;
    store.write_manifest(writer);
    const auto blob = std::move(writer).finish();

    os::QlArtifactStore restored(dir);
    const std::string raw(blob.begin(), blob.end());  // the reader views the buffer
    qiling::SnapshotReader reader(raw);
    restored.read_manifest(reader);
    ASSERT_EQ(restored.records().size(), 1u);
    EXPECT_EQ(restored.records()[0].kind, "file");
    EXPECT_EQ(restored.records()[0].label, "a.bin");
    EXPECT_EQ(restored.records()[0].hash, h1);
    EXPECT_EQ(restored.records()[0].size, 5u);

    // and a real run stores a guest range, labelled with its region
    qiling::os::register_dlls();
    SampleOptions opts;
    opts.artifact_dir = dir.string();
    opts.artifacts = {"0x401000:0x100"};
    const auto out = run_pe_sample("argv_test_x86.exe", opts);
    ASSERT_EQ(out.exit_code, 0);
    ASSERT_FALSE(out.artifacts.empty());
    EXPECT_EQ(out.artifacts.back().kind, "memory");
    EXPECT_EQ(out.artifacts.back().label, "argv_test_x86.exe");
    EXPECT_EQ(out.artifacts.back().size, 0x100u);
    EXPECT_TRUE(std::filesystem::exists(dir / out.artifacts.back().hash));

    std::filesystem::remove_all(dir, ec);
}

TEST(PegasusParity, GetProcAddressMissingFunctionReturnsZero) {
    qiling::os::register_dlls();

    SampleOptions opts;
    // the synthesized kernel32 stub carries only the import-table names; the
    // real kernel32 also exports the names the sample probes for
    opts.stub_extras["kernel32.dll"] = {"AreFileApisANSI", "LCMapStringEx", "LocaleNameToLCID"};

    const auto out = run_pe_sample("GetProcAddress.exe", opts);
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);
    EXPECT_EQ(out.exit_code, 0);

    // the four probe names decode through the handler (the read_string log)
    EXPECT_TRUE(out.strings.count("AreFileApisANSI") == 1) << "the AreFileApisANSI probe did not decode";
    EXPECT_TRUE(out.strings.count("ThisFunctionIsNotExportedByKernel32") == 1);

    const auto& rets = out.retvals("GetProcAddress");
    ASSERT_GE(rets.size(), 3u) << "expected the sample's GetProcAddress probes";
    // the last probe is the bogus name: it must answer NULL; the exported
    // names ahead of it resolve to mapped addresses
    EXPECT_EQ(rets.back(), 0u) << "the non-exported name must answer NULL";
    std::size_t resolved = 0;
    for (std::size_t i = 0; i + 1 < rets.size(); ++i) {
        if (rets[i] != 0) ++resolved;
    }
    EXPECT_GE(resolved, 2u) << "the exported names must resolve";
}

// ---- test_file_access.cpp: FileAccessTest.FileAccessEmulation -------------
// NtCreateFile opens C:\myfile.txt through the fs mapper, NtReadFile fills the
// sample's buffer and the sample prints the first bytes it read. pegasus
// asserts the same three observations (the create, the read, the printf).
TEST(PegasusParity, FileAccessEmulationX86) {
    qiling::os::register_dlls();

    SampleOptions opts;
    opts.files.emplace_back("myfile.txt", "hello from the emulated file\n");
    // the sample resolves the NT file surface through GetProcAddress
    opts.stub_extras["ntdll.dll"] = {"NtOpenFile", "NtCreateFile", "NtReadFile", "NtWriteFile"};

    const auto out = run_pe_sample("file_access_test_x86.exe", opts);
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);
    EXPECT_EQ(out.exit_code, 0);

    EXPECT_TRUE(out.called("NtCreateFile")) << "NtCreateFile not dispatched";
    EXPECT_TRUE(out.called("NtReadFile")) << "NtReadFile not dispatched";
    EXPECT_EQ(out.retvals("NtCreateFile").empty() ? 1u : static_cast<unsigned>(out.retvals("NtCreateFile")[0]), 0u)
        << "the create must answer STATUS_SUCCESS";

    EXPECT_TRUE(out.output_has("File successfully opened.")) << out.output;
    // the read lands in the guest buffer: the sample prints its first 4 bytes
    // as a hex value ("hell")
    EXPECT_TRUE(out.output_has("File contained: 0x")) << out.output;
    EXPECT_TRUE(out.output_has("File contained: 0x6c6c6568")) << out.output;
}

TEST(PegasusParity, FileAccessEmulationX64) {
    qiling::os::register_dlls();

    SampleOptions opts;
    opts.files.emplace_back("myfile.txt", "hello from the emulated file\n");
    opts.stub_extras["ntdll.dll"] = {"NtOpenFile", "NtCreateFile", "NtReadFile", "NtWriteFile"};

    const auto out = run_pe_sample("file_access_test_x64.exe", opts);
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);
    EXPECT_EQ(out.exit_code, 0);

    EXPECT_TRUE(out.called("NtCreateFile"));
    EXPECT_TRUE(out.called("NtReadFile"));
    EXPECT_TRUE(out.output_has("File successfully opened.")) << out.output;
    // the x64 width prints all eight bytes: "hello fr"
    EXPECT_TRUE(out.output_has("File contained: 0x7266206f6c6c6568")) << out.output;
}

// ---- test_dlls.cpp: DllEmuTest.DllEmulationRuns ---------------------------
// The dll sample's DllMain and two exports each show a message box and return
// a recognizable value: 1 (TRUE), 0x41414141 and 0x42424242.
namespace {

void check_dll_sample(const char* bin_name) {
    qiling::os::register_dlls();
    const auto out = run_pe_sample(bin_name);
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);

    ASSERT_EQ(out.entries.size(), 3u) << "expected the DllMain + two exports";
    EXPECT_EQ(out.entries[0].first, "DllMain");
    EXPECT_EQ(out.entries[0].second, 1u);          // DllMain answers TRUE

    // the MessageBox family dispatches through the static imports
    EXPECT_TRUE(out.called("MessageBoxA")) << "MessageBoxA not dispatched";
    EXPECT_TRUE(out.called("MessageBoxW")) << "MessageBoxW not dispatched";

    // the caption/text arguments decode through the handler (read_string)
    EXPECT_TRUE(has_words(out, "Inside process attach"));
    EXPECT_TRUE(has_words(out, "My caption"));
    EXPECT_TRUE(has_words(out, "Inside emu_test_one"));
    EXPECT_TRUE(has_words(out, "First export"));
    EXPECT_TRUE(has_words(out, "Inside emu_test_two"));
    EXPECT_TRUE(has_words(out, "Second export"));
}

}  // namespace

TEST(PegasusParity, DllEmulationRunsX86) { check_dll_sample("dll_test_x86.dll"); }
TEST(PegasusParity, DllEmulationRunsX64) { check_dll_sample("dll_test_x64.dll"); }

// ---- test_module_system.cpp: ModuleSystemTest.* ---------------------------
// The PEB module list has to carry the loaded images (the loader's LDR
// entries) — pegasus asserts se.get_user_modules() is non-empty.
TEST(PegasusParity, PEBModulesPopulated) {
    qiling::os::register_dlls();

    const auto out = run_pe_sample("argv_test_x86.exe");
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);

    // the main image is mapped and the imported modules ride the loader (the
    // PEB LDR table entries are built from the same image list)
    EXPECT_GT(out.imagebase, 0u);
    ASSERT_FALSE(out.modules.empty()) << "PEB modules should be populated";
    EXPECT_TRUE(std::find(out.modules.begin(), out.modules.end(), "kernel32.dll") != out.modules.end());
}

// ---- test_seh.cpp: SehTest.SehDispatchEnabled -----------------------------
// The fixture's __try/__except script: every formatted line must render (the
// pegasus DISPATCH_SCRIPT order).
TEST(PegasusParity, SehDispatchEnabled) {
    qiling::os::register_dlls();

    const auto out = run_pe_sample("seh_test_x86.exe");
    ASSERT_TRUE(out.error.empty()) << out.error;
    ASSERT_TRUE(out.ran);
    EXPECT_EQ(out.exit_code, 0);

    // the pegasus DISPATCH_SCRIPT (the sample's formatted lines)
    const std::vector<std::string> script = {
        "Hello emulator\n",
        "First access violation\r\n",
        "First nested access violation\r\n",
        "Second nested access violation\r\n",
        "After access violations\r\n",
        "In finally\r\n",
        "Returning...\n",
    };
    for (const auto& line : script) {
        EXPECT_TRUE(out.output.find(line) != std::string::npos)
            << "missing script line: " << line << "\n--- guest stdout ---\n" << out.output;
    }

    // the __except filter ran (the sample prints from inside it)
    EXPECT_TRUE(out.output_has("In filter")) << out.output;
    EXPECT_TRUE(out.output_has("Caught AV as expected")) << out.output;
}

// ---- test_seh.cpp: SehTest.SehDispatchDisabled ----------------------------
// With the dispatch switched off the first access violation must surface as
// an invalid write instead of reaching the handler.
TEST(PegasusParity, SehDispatchDisabled) {
    qiling::os::register_dlls();

    SampleOptions opts;
    opts.configure = [](qiling::Qiling& ql) { ql.os<qiling::os::windows::QlOsWindows>().set_seh_dispatch(false); };

    const auto out = run_pe_sample("seh_test_x86.exe", opts);
    EXPECT_FALSE(out.error.empty()) << "the undelivered access violation must surface as an error";
    EXPECT_TRUE(out.output.find("First access violation") == std::string::npos)
        << "no handler output may render without the dispatch\n" << out.output;
    // the fault is the sample's `mov dword ptr [0], 0x14`
    EXPECT_TRUE(out.error.find("write") != std::string::npos) << out.error;
    // ... and the entry-point error taxonomy names it the pegasus way
    ASSERT_EQ(out.error_types.size(), 1u) << "one fault, one error record";
    EXPECT_EQ(out.error_types[0], "invalid_write");
    // the record carries the guest pc it was raised at (pegasus's
    // get_error_info(addr)), so a report can say where the sample died
    ASSERT_EQ(out.errors.size(), 1u);
    EXPECT_EQ(out.errors[0].type, "invalid_write");
    EXPECT_NE(out.errors[0].address, 0u);
    EXPECT_FALSE(out.errors[0].message.empty());
    // an unhandled access violation ends the guest with the Windows exit code
    EXPECT_EQ(out.exit_code, static_cast<int>(0xC0000005u));
}

// ---- the hang guard (PLAN_PARITY.md Phase 1.4) --------------------------
// A runaway guest is stopped by the deterministic instruction budget and the
// run records the guard in the same error vocabulary as a fault.
TEST(PegasusParity, InstructionBudgetStopsRunawayGuest) {
    qiling::os::register_dlls();

    SampleOptions opts;
    opts.count = 300;  // argv_test_x86 needs far more to reach ExitProcess

    const auto out = run_pe_sample("argv_test_x86.exe", opts);
    EXPECT_TRUE(out.error.empty()) << out.error;
    ASSERT_FALSE(out.error_types.empty()) << "the guard must be recorded";
    EXPECT_EQ(out.error_types.front(), "timeout");
}

// ---- the unsupported-import discipline (PLAN_PARITY.md Phase 1.1) -------
// An import with no handler is recorded and answered through the calling
// convention (a zero return value), never left to the stub cell's garbage rax.
TEST(PegasusParity, UnsupportedImportsAreRecorded) {    qiling::os::register_dlls();

    // the file_access sample probes two names taote does not implement through
    // its own import table; with the stubs left in place they show up in the
    // unsupported set
    SampleOptions opts;
    opts.stub_extras["kernel32.dll"] = {"ThisApiIsNotImplemented"};
    opts.files.emplace_back("myfile.txt", "hello\n");
    opts.stub_extras["ntdll.dll"] = {"NtOpenFile", "NtCreateFile", "NtReadFile", "NtWriteFile"};

    const auto out = run_pe_sample("file_access_test_x86.exe", opts);
    EXPECT_TRUE(out.error.empty()) << out.error;
    // Nothing in this sample imports the extra stub names, so they stay out of
    // the set. The names that DO show up are the CRT's own initializer walk:
    // `_initterm` and `_initterm_e` deliberately have no handler here (the
    // reference hooks neither — upstream msvcrt.py never registers them), so a
    // CRT-linked guest walks its own initializer table and the recorder counts
    // the two dispatches. That is the intended shape: intercepting them would
    // stop the guest's initializers from ever running (which is what kept
    // msvcp140's std::cout unconstructed on a real-dll rootfs). The guard is
    // that nothing *else* leaks into the set — a regression that starts
    // answering unimplemented imports through a synthetic frame shows up as a
    // new name here.
    static const std::set<std::string> kDeliberatelyUnhooked = {"_initterm", "_initterm_e"};
    std::string names;
    std::size_t unexpected = 0;
    for (const auto& n : out.unsupported_apis) {
        names += (names.empty() ? "" : ", ") + n;
        if (kDeliberatelyUnhooked.count(n) == 0) {
            ++unexpected;
        }
    }
    EXPECT_EQ(unexpected, 0u) << "recorded: [" << names << "]";
}

// ---- test_porting_winemu.cpp: the string-read round trips ---------------
// The upstream read_wstring delegates to read_string, so both readers feed
// the stats string log; the C++ port's standalone wide walk has to keep that
// contract (see the read_wstring log fix).
TEST(PegasusParity, ReadMemStringRoundTripsAndLogs) {
    qiling::QilingOptions options;
    options.rootfs = qiling::testing::pe_sample_detail::make_rootfs("strings").string();
    options.code = std::vector<std::uint8_t>{0xC3};
    options.ostype = qiling::QL_OS::LINUX;
    options.archtype = qiling::QL_ARCH::X86;
    qiling::Qiling ql(std::move(options));

    constexpr std::uint64_t kAscii = 0x2000000;
    constexpr std::uint64_t kWide = 0x2001000;
    ql.mem().map(kAscii, 0x2000, UC_PROT_ALL, "[string-scratch]");

    const std::string ascii = "qiling-ascii";
    ql.mem().write(kAscii, std::vector<std::uint8_t>(ascii.begin(), ascii.end()));
    ql.mem().write(kAscii + ascii.size(), std::vector<std::uint8_t>{0});
    EXPECT_EQ(qiling::os::QlOsUtils::read_cstring(ql, kAscii), ascii);

    std::vector<std::uint8_t> wide;
    const std::string wtext = "qiling-wide";
    for (char c : wtext) {
        wide.push_back(static_cast<std::uint8_t>(c));
        wide.push_back(0);
    }
    wide.push_back(0);
    wide.push_back(0);
    ql.mem().write(kWide, wide);
    EXPECT_EQ(qiling::os::QlOsUtils::read_wstring(ql, kWide), wtext);

    // both readers feed the stats log (tokenized on whitespace)
    const auto& logged = ql.os().stats().strings();
    EXPECT_TRUE(logged.count("qiling-ascii") == 1) << "read_cstring did not log";
    EXPECT_TRUE(logged.count("qiling-wide") == 1) << "read_wstring did not log";
}

// ---- test_porting_winemu.cpp: ObjmanPortingTest.ShellcodeLoadAndRun -----
// The blob path maps the caller's code at the CODE profile address and runs
// it to the exit point: the shellcode's result lands in the return register.
TEST(PegasusParity, ShellcodeLoadAndRun) {
    qiling::QilingOptions options;
    options.rootfs = qiling::testing::pe_sample_detail::make_rootfs("shellcode").string();
    // mov eax, 0x1234 (the blob rides the CODE load address; emu_start stops
    // at entry + the blob size, so no return instruction is needed)
    options.code = std::vector<std::uint8_t>{0xB8, 0x34, 0x12, 0x00, 0x00};
    options.ostype = qiling::QL_OS::WINDOWS;
    options.archtype = qiling::QL_ARCH::X86;
    qiling::Qiling ql(std::move(options));

    ql.run();
    EXPECT_EQ(ql.arch().regs().read("eax"), 0x1234u);
}

// ---- ntdefs (PLAN_PARITY.md Phase 2: the layout table) ------------------
// The handlers write these images into guest memory; the layouts are the
// contract, so the table is asserted instead of being trusted.
namespace ntdefs = qiling::os::windows::ntdefs;

TEST(PegasusParity, NtDefsLayoutTableMatchesTheGuestAbi) {
    // the x86 / x64 pairs the reference suite's size validation walks
    // the loader structures: the layout table's columns are the loader's own
    // word set (loader_layout(32) for x86, structs.hpp for x64)
    {
        using namespace qiling::os::win;
        const auto loader32 = loader_layout(32);
        const auto loader64 = loader_layout(64);
        for (const auto& layout : qiling::os::windows::ntdefs::kLayouts) {
            const std::string name = layout.name;
            if (name == "PEB") {
                EXPECT_EQ(layout.x86.size, loader32.peb_size);
                EXPECT_EQ(layout.x64.size, loader64.peb_size);
            } else if (name == "TEB") {
                EXPECT_EQ(layout.x86.size, loader32.teb_size);
                EXPECT_EQ(layout.x64.size, loader64.teb_size);
            } else if (name == "LDR_DATA_TABLE_ENTRY") {
                EXPECT_EQ(layout.x86.size, loader32.ldr_entry_size);
                EXPECT_EQ(layout.x64.size, loader64.ldr_entry_size);
            } else if (name == "PEB_LDR_DATA") {
                EXPECT_EQ(layout.x86.size, loader32.ldr_data_size);
                EXPECT_EQ(layout.x64.size, loader64.ldr_data_size);
            }
        }
    }

    EXPECT_EQ(ntdefs::UNICODE_STRING_SIZE_X86, 8u);
    EXPECT_EQ(ntdefs::UNICODE_STRING_SIZE_X64, 16u);
    EXPECT_EQ(ntdefs::UNICODE_STRING_OFF_BUFFER_X86, 4u);
    EXPECT_EQ(ntdefs::UNICODE_STRING_OFF_BUFFER_X64, 8u);

    EXPECT_EQ(ntdefs::OBJECT_ATTRIBUTES_SIZE_X86, 24u);
    EXPECT_EQ(ntdefs::OBJECT_ATTRIBUTES_SIZE_X64, 48u);
    // the ObjectName slot sits at 2 pointers (what the NtCreateFile walk reads)
    EXPECT_EQ(ntdefs::OBJECT_ATTRIBUTES_OFF_NAME_X86, 8u);
    EXPECT_EQ(ntdefs::OBJECT_ATTRIBUTES_OFF_NAME_X64, 16u);

    EXPECT_EQ(ntdefs::IO_STATUS_BLOCK_SIZE_X86, 8u);
    EXPECT_EQ(ntdefs::IO_STATUS_BLOCK_SIZE_X64, 16u);
    EXPECT_EQ(ntdefs::EXCEPTION_RECORD_OFF_ADDRESS_X86, 12u);
    EXPECT_EQ(ntdefs::EXCEPTION_RECORD_OFF_NUMBER_PARAMS_X64, 24u);
    // the user32 message pump width (the 28-byte x86 MSG the GetMessage fix pins)
    EXPECT_EQ(ntdefs::MSG_SIZE_X86, 28u);
    EXPECT_EQ(ntdefs::MSG_SIZE_X64_W, 64u);

    // every table row is consistent and the pointer helper picks the column
    for (const auto& row : ntdefs::kLayouts) {
        EXPECT_GT(row.x86.size, 0u) << row.name;
        EXPECT_GT(row.x64.size, 0u) << row.name;
        EXPECT_GE(row.x64.size, row.x86.size) << row.name;
        EXPECT_GT(row.x86.fields_count, 0u) << row.name;
    }
    EXPECT_EQ(ntdefs::ptr_field(8, 16, 32), 8u);
    EXPECT_EQ(ntdefs::ptr_field(8, 16, 64), 16u);
}

// ---- Phase 1.3 tail: guest software interrupts --------------------------
// The UC_HOOK_INTR trampoline routes int3/int n into the same fs:[0] walk;
// with no registered frame the dispatch declines and the fault stays on the
// ordinary failure path (it must not swallow the exception).
TEST(PegasusParity, SoftwareInterruptDeclinesWithoutAHandlerChain) {
    qiling::os::register_dlls();

    qiling::QilingOptions options;
    options.ostype = qiling::QL_OS::WINDOWS;
    options.archtype = qiling::QL_ARCH::X86;
    options.code = {0xCD, 0x03};  // int 3
    qiling::Qiling ql(options);

    auto& win = ql.os<qiling::os::windows::QlOsWindows>();
    EXPECT_FALSE(win.seh_on_interrupt(3)) << "no frame in the chain: not handled";
    EXPECT_TRUE(win.entry_point_errors().empty());
}
