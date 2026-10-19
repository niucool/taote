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
