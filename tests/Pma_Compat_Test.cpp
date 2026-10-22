// tests/Pma_Compat_Test.cpp — the PLAN_PARITY.md Phase 0 harness: the reference
// PMA cases (../pegasus/tests/test_pma_samples.cpp) re-expressed against
// taote's own surfaces.
//
// The samples are live malware and live outside the tree, so the fixture is
// gated on the corpus being present: set TAOTE_PMA_DIR, or the default
// ~/source/capa-testfiles is used. When neither exists the test skips.
//
// The reference case contract is: no top-level report errors, at least one
// entry point, zero unsupported APIs, every expected API observed, the
// indicators present, and every entry-point error class allowed. taote can
// observe the API set (QlOsStats.syscalls) today; the indicator surface
// (dll-qualified records with args, file/registry/net events) is
// PLAN_PARITY.md Phase 3, so until then a case is "green" when it runs to
// completion and every expected API name was dispatched. The green count is a
// ratchet: EXPECT_GE against kGreenBaseline, so a regression fails the suite.
#include <gtest/gtest.h>

#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "Pe_Sample_Runner.hpp"

namespace fs = std::filesystem;
using qiling::testing::SampleOptions;
using qiling::testing::run_pe_sample;
using qiling::testing::pe_sample_detail::lower;

namespace {

struct PmaCase {
    const char* name;
    const char* sample;
    std::vector<const char*> expected_apis;       // the reference list (dll-qualified)
    std::vector<const char*> allowed_errors;      // the reference tolerated entry-point errors
    std::vector<const char*> argv;                // the reference command line (empty = default)
};

// The curated 12 reference cases, in ../pegasus/tests/test_pma_samples.cpp
// order, carrying the reference API expectations verbatim.
const std::vector<PmaCase>& curated_cases() {
    static const std::vector<PmaCase> kCases = {
        {"pma-01-02-exe", "Practical Malware Analysis Lab 01-02.exe_",
         {"KERNEL32.GetProcAddress", "WININET.InternetOpenUrlA"}, {"max_api_count"}, {}},
        {"pma-03-02-dll", "Practical Malware Analysis Lab 03-02.dll_",
         {"ADVAPI32.OpenSCManagerA", "KERNEL32.GetModuleFileNameA"}, {"max_api_count"}, {}},
        {"pma-03-04-in", "Practical Malware Analysis Lab 03-04.exe_",
         {"ADVAPI32.ChangeServiceConfigA", "KERNEL32.CopyFileA", "ADVAPI32.RegSetValueExA"}, {}, {}},
        {"pma-05-01-dll", "Practical Malware Analysis Lab 05-01.dll_",
         {"KERNEL32.CreateThread", "ADVAPI32.RegSetValueExA"}, {"max_api_count", "invalid_read"}, {}},
        {"pma-06-03-exe", "Practical Malware Analysis Lab 06-03.exe_",
         {"WININET.InternetGetConnectedState", "WININET.InternetOpenUrlA", "KERNEL32.WriteFile",
          "KERNEL32.ExitProcess"}, {}, {}},
        {"pma-10-03-sys", "Practical Malware Analysis Lab 10-03.sys_",
         {"ntoskrnl.IoCreateDevice", "ntoskrnl.IoDeleteDevice"}, {}, {}},
        {"pma-11-02-dll", "Practical Malware Analysis Lab 11-02.dll_",
         {"KERNEL32.CreateToolhelp32Snapshot", "KERNEL32.VirtualProtect", "ADVAPI32.RegSetValueExA"}, {}, {}},
        {"pma-12-02-exe", "Practical Malware Analysis Lab 12-02.exe_",
         {"KERNEL32.CreateProcessA", "KERNEL32.ResumeThread", "ntdll.NtUnmapViewOfSection"}, {"invalid_fetch"}, {}},
        {"pma-12-04-exe", "Practical Malware Analysis Lab 12-04.exe_",
         {"KERNEL32.CreateRemoteThread", "KERNEL32.WinExec", "sfc_os.SfcTerminateWatcherThread"}, {}, {}},
        {"pma-14-01-exe", "Practical Malware Analysis Lab 14-01.exe_",
         {"ADVAPI32.GetCurrentHwProfileA", "urlmon.URLDownloadToCacheFileA"}, {}, {}},
        {"pma-16-03-exe", "Practical Malware Analysis Lab 16-03.exe_",
         {"KERNEL32.GetVersionExA", "KERNEL32.ExitProcess"}, {}, {}},
        {"pma-21-01-exe", "Practical Malware Analysis Lab 21-01.exe_",
         {"KERNEL32.GetTickCount", "KERNEL32.EncodePointer"}, {}, {}},
    };
    return kCases;
}

// The measured green count, per mode. Raise it whenever a case starts passing;
// never lower it (that is the ratchet). The stub number is the reference's own
// contract; the real-dll number is this project's, where the API-presence list
// is informational (see evaluate()).
constexpr std::size_t kGreenBaselineStub = 1;
constexpr std::size_t kGreenBaselineReal = 10;

fs::path pma_dir() {
    if (const char* env = std::getenv("TAOTE_PMA_DIR"); env != nullptr && *env != '\0') {
        return fs::path(env);
    }
    const auto home = std::getenv("HOME");
    if (home == nullptr) {
        return fs::path();
    }
    // Two layouts in the wild: the corpus clones directly under $HOME
    // ($HOME/source/capa-testfiles) and under the project tree
    // ($HOME/source/<project>/capa-testfiles). Whichever exists first wins.
    for (const auto& candidate : {fs::path(home) / "source" / "capa-testfiles",
                                  fs::path(home) / "source" / "jim" / "capa-testfiles"}) {
        if (fs::exists(candidate)) {
            return candidate;
        }
    }
    return fs::path(home) / "source" / "capa-testfiles";
}

// "KERNEL32.GetProcAddress" -> "getprocaddress": taote's stats key on the bare
// export name, the reference expectations carry the module qualifier.
std::string bare_api(const std::string& qualified) {
    const auto dot = qualified.rfind('.');
    return lower(dot == std::string::npos ? qualified : qualified.substr(dot + 1));
}

std::string self_exe() {
    char buf[4096] = {0};
    const auto n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    return n > 0 ? std::string(buf, static_cast<std::size_t>(n)) : std::string();
}

// Run one case in this process. Returns the failure text (empty = green).
std::string evaluate(const PmaCase& tc) {
    const fs::path sample = pma_dir() / tc.sample;
    if (!fs::exists(sample)) {
        return "missing sample " + std::string(tc.sample);
    }
    SampleOptions opts;
    opts.sample_path = sample;
    // the reference harness defaults (pma_harness.h build_case_config)
    opts.timeout = 6;
    // ... but the 600-dispatch cap is calibrated against the *stub* API surface:
    // with a real System32 tree the same program dispatches far more (the real
    // CRT alone makes hundreds of calls), so the cap stops it mid-startup and
    // the sample never reaches the APIs the case expects. The deterministic
    // instruction budget below and the per-case wall clock stay as the guards.
    if (qiling::testing::real_comparison_base().empty()) {
        opts.max_api_count = 600;
    }
    // the hang guard: a deterministic instruction budget rather than the wall
    // clock (the reference's 6 s timeout is host-speed dependent)
    opts.count = 40000000;
    for (const auto* a : tc.argv) {
        opts.argv.push_back(a);
    }
    const auto out = run_pe_sample(sample.filename().string(), opts);

    std::set<std::string> observed;
    for (const auto& [k, v] : out.api) {
        (void)v;
        observed.insert(lower(k));
    }
    // The reference's API list describes what the *emulated* API surface sees.
    // With a real System32 tree a sample reaches many of those names through the
    // real DLL's own internals instead of through a dispatched import (the same
    // reason PegasusParity.FileAccessEmulation can only assert the resolved NT
    // addresses in that mode), so the list is informational there and the
    // mode-correct contract is: it runs, with no unexpected error and no
    // stub-served unsupported API.
    const bool real_dlls = !qiling::testing::real_comparison_base().empty();
    std::string missing;
    for (const auto* api : tc.expected_apis) {
        if (observed.count(bare_api(api)) == 0) {
            missing += std::string(" ") + api;
        }
    }
    const auto missing_note = missing.empty() ? std::string() : ("; not dispatched (see the note):" + missing);
    std::string unexpected;
    for (const auto& type : out.error_types) {
        bool allowed = false;
        for (const auto* a : tc.allowed_errors) {
            if (type == a) {
                allowed = true;
            }
        }
        if (!allowed) {
            unexpected += " " + type;
        }
    }
    if (!unexpected.empty()) {
        std::string names;
        for (const auto& n : out.unsupported_apis) {
            names += " " + n;
        }
        return "unexpected entry-point errors" + unexpected + (out.error.empty() ? "" : " (" + out.error + ")") +
               (names.empty() ? "" : "; unsupported apis:" + names) + missing_note;
    }
    if (out.unsupported != 0) {
        // the names, not just the count: an unsupported import is a real gap
        // (a handler answered it with the zero policy), while a "missing" api
        // was simply never dispatched - two different facts
        std::string names;
        for (const auto& n : out.unsupported_apis) {
            names += " " + n;
        }
        return std::to_string(out.unsupported) + " unsupported apis:" + names + missing_note;
    }
    if (!missing.empty() && !real_dlls) {
        return "never reached:" + missing;
    }
    return {};
}

}  // namespace

// One case per process: the samples are live malware and an emulation that
// faults inside the interpreter can take the whole test binary down, so each
// case is driven in a child process (the parent counts exit codes).
TEST(PmaCompat, OneCase) {
    const char* name = std::getenv("TAOTE_PMA_CASE");
    if (name == nullptr || *name == '\0') {
        GTEST_SKIP() << "driver test: run through PmaCompat.CuratedCorpusApiExpectations";
    }
    const PmaCase* tc = nullptr;
    for (const auto& c : curated_cases()) {
        if (std::string(c.name) == name) {
            tc = &c;
        }
    }
    ASSERT_NE(tc, nullptr) << "unknown case " << name;
    EXPECT_EQ(evaluate(*tc), "") << "case " << name;
}

// The sweep driver: run any corpus sample by path, print the outcome as one
// line. Used by the corpus sweeps (TAOTE_PMA_SAMPLE=<path>), and by hand.
TEST(PmaCompat, ArbitrarySample) {
    const char* path = std::getenv("TAOTE_PMA_SAMPLE");
    if (path == nullptr || *path == '\0') {
        GTEST_SKIP() << "sweep driver: set TAOTE_PMA_SAMPLE to a sample path";
    }
    const fs::path sample = path;
    ASSERT_TRUE(fs::exists(sample)) << sample.string();

    // the sweep metric is the raw one (no api/instruction budget, like the
    // pre-reference-defaults measurement): a sample is "ok" when it runs to
    // its own exit without an emulation error
    SampleOptions opts;
    opts.sample_path = sample;
    // a deterministic guard instead of the wall clock: the sweep metric is the
    // raw one, but a sample may not run forever
    opts.count = 50000000;
    const auto out = run_pe_sample(sample.filename().string(), opts);

    std::string types;
    for (const auto& t : out.error_types) {
        types += types.empty() ? t : ("," + t);
    }
    std::fprintf(stderr, "SWEEP %s ok=%d exit=%d apis=%zu unsup=%zu errors=[%s] %s\n", sample.filename().c_str(),
                 static_cast<int>(out.error.empty()), out.exit_code, out.api.size(), out.unsupported, types.c_str(),
                 out.error.c_str());
}

TEST(PmaCompat, CuratedCorpusApiExpectations) {
    const auto dir = pma_dir();
    if (!fs::exists(dir / "Practical Malware Analysis Lab 01-02.exe_")) {
        GTEST_SKIP() << "capa-testfiles not found at " << dir.string() << " (set TAOTE_PMA_DIR)";
    }
    const auto self = self_exe();
    if (self.empty()) {
        GTEST_SKIP() << "cannot locate the test executable";
    }

    std::size_t green = 0;
    std::vector<std::string> red;
    for (const auto& tc : curated_cases()) {
        // the hang class (a sample blocking in a real host call) must not
        // block the suite: 45s is the reference harness's per-sample budget
        const auto cmd = "timeout 45 env TAOTE_PMA_CASE='" + std::string(tc.name) + "' '" + self +
                         "' --gtest_filter=PmaCompat.OneCase >/dev/null 2>&1";
        const int rc = std::system(cmd.c_str());
        if (rc == 0) {
            ++green;
        } else {
            red.push_back(std::string(tc.name) + (WIFSIGNALED(rc) ? " (host crash)" : ""));
        }
    }

    std::fprintf(stderr, "\nPMA curated (%s): %zu/%zu green",
                 qiling::testing::real_comparison_base().empty() ? "stub dlls" : "real dlls", green,
                 curated_cases().size());
    for (const auto& r : red) {
        std::fprintf(stderr, "\n  red: %s", r.c_str());
    }
    std::fprintf(stderr, "\n");
    const auto baseline = qiling::testing::real_comparison_base().empty() ? kGreenBaselineStub : kGreenBaselineReal;
    EXPECT_GE(green, baseline) << "the curated PMA green count regressed";
}
