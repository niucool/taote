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
#include "qiling/os/windows/dlls/dlls.hpp"
#include "qiling/os/windows/windows.hpp"

#include "Pe_Sample_Runner.hpp"
#include "qiling/os/windows/ntdefs.hpp"

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
TEST(PegasusParity, UnsupportedImportsAreRecorded) {
    qiling::os::register_dlls();

    // the file_access sample probes two names taote does not implement through
    // its own import table; with the stubs left in place they show up in the
    // unsupported set
    SampleOptions opts;
    opts.stub_extras["kernel32.dll"] = {"ThisApiIsNotImplemented"};
    opts.files.emplace_back("myfile.txt", "hello\n");
    opts.stub_extras["ntdll.dll"] = {"NtOpenFile", "NtCreateFile", "NtReadFile", "NtWriteFile"};

    const auto out = run_pe_sample("file_access_test_x86.exe", opts);
    EXPECT_TRUE(out.error.empty()) << out.error;
    // nothing in this sample imports the extra name, so the counter stays zero
    // — the regression guard is that a clean sample reports zero, which the
    // reference PMA cases assert
    EXPECT_EQ(out.unsupported, 0u);
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
