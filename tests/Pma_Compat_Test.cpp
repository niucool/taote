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
    std::vector<const char*> expected_apis;  // the reference list (dll-qualified)
};

// The curated 12 reference cases, in ../pegasus/tests/test_pma_samples.cpp
// order, carrying the reference API expectations verbatim.
const std::vector<PmaCase>& curated_cases() {
    static const std::vector<PmaCase> kCases = {
        {"pma-01-02-exe", "Practical Malware Analysis Lab 01-02.exe_",
         {"KERNEL32.GetProcAddress", "WININET.InternetOpenUrlA"}},
        {"pma-03-02-dll", "Practical Malware Analysis Lab 03-02.dll_",
         {"ADVAPI32.OpenSCManagerA", "KERNEL32.GetModuleFileNameA"}},
        {"pma-03-04-in", "Practical Malware Analysis Lab 03-04.exe_",
         {"ADVAPI32.ChangeServiceConfigA", "KERNEL32.CopyFileA", "ADVAPI32.RegSetValueExA"}},
        {"pma-05-01-dll", "Practical Malware Analysis Lab 05-01.dll_",
         {"KERNEL32.CreateThread", "ADVAPI32.RegSetValueExA"}},
        {"pma-06-03-exe", "Practical Malware Analysis Lab 06-03.exe_",
         {"WININET.InternetGetConnectedState", "WININET.InternetOpenUrlA", "KERNEL32.WriteFile",
          "KERNEL32.ExitProcess"}},
        {"pma-10-03-sys", "Practical Malware Analysis Lab 10-03.sys_", {"ntoskrnl.IoCreateDevice"}},
        {"pma-11-02-dll", "Practical Malware Analysis Lab 11-02.dll_",
         {"KERNEL32.CreateToolhelp32Snapshot", "KERNEL32.VirtualProtect", "ADVAPI32.RegSetValueExA"}},
        {"pma-12-02-exe", "Practical Malware Analysis Lab 12-02.exe_",
         {"KERNEL32.CreateProcessA", "KERNEL32.ResumeThread", "ntdll.NtUnmapViewOfSection"}},
        {"pma-12-04-exe", "Practical Malware Analysis Lab 12-04.exe_",
         {"KERNEL32.CreateRemoteThread", "KERNEL32.WinExec", "sfc_os.SfcTerminateWatcherThread"}},
        {"pma-14-01-exe", "Practical Malware Analysis Lab 14-01.exe_",
         {"ADVAPI32.GetCurrentHwProfileA", "urlmon.URLDownloadToCacheFileA"}},
        {"pma-16-03-exe", "Practical Malware Analysis Lab 16-03.exe_",
         {"KERNEL32.GetVersionExA", "KERNEL32.ExitProcess"}},
        {"pma-21-01-exe", "Practical Malware Analysis Lab 21-01.exe_",
         {"KERNEL32.GetTickCount", "KERNEL32.EncodePointer"}},
    };
    return kCases;
}

// The measured green count. Raise it whenever a case starts passing; never
// lower it (that is the ratchet).
constexpr std::size_t kGreenBaseline = 0;

fs::path pma_dir() {
    if (const char* env = std::getenv("TAOTE_PMA_DIR"); env != nullptr && *env != '\0') {
        return fs::path(env);
    }
    const auto home = std::getenv("HOME");
    return home == nullptr ? fs::path() : fs::path(home) / "source" / "capa-testfiles";
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
    const auto out = run_pe_sample(sample.filename().string(), opts);

    std::set<std::string> observed;
    for (const auto& [k, v] : out.api) {
        (void)v;
        observed.insert(lower(k));
    }
    std::string missing;
    for (const auto* api : tc.expected_apis) {
        if (observed.count(bare_api(api)) == 0) {
            missing += std::string(" ") + api;
        }
    }
    if (!out.error.empty()) {
        return "error '" + out.error + "'" + (missing.empty() ? "" : "; missing apis" + missing);
    }
    if (!missing.empty()) {
        return "missing apis" + missing;
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

    std::fprintf(stderr, "\nPMA curated: %zu/%zu green", green, curated_cases().size());
    for (const auto& r : red) {
        std::fprintf(stderr, "\n  red: %s", r.c_str());
    }
    std::fprintf(stderr, "\n");
    EXPECT_GE(green, kGreenBaseline) << "the curated PMA green count regressed";
}
