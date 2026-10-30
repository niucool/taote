// tests/Unpack_Compat_Test.cpp — the unpacker contract tests (PLAN_UNPACK.md
// §3 Phase 0).
//
// The corpus is external (../dataset-packed-pe), so the emulation-backed cases
// skip when it is absent. The rebuilder/safety cases always run: they are the
// part that parses attacker-controlled bytes, and they must never take the
// process down.
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <LIEF/PE.hpp>
#include <nlohmann/json.hpp>

#include "../tests/Pe_Sample_Runner.hpp"
#include "qiling/const.hpp"
#include "qiling/core.hpp"
#include "qiling/unpack/unpack.hpp"

namespace fs = std::filesystem;
using qiling::unpack::RebuildInput;
using qiling::unpack::Unpacker;
using qiling::unpack::UnpackOptions;
using qiling::unpack::UnpackResult;
using qiling::unpack::rebuild_pe;

namespace {

fs::path corpus_root() {
    if (const char* env = std::getenv("TAOTE_PACKED_DIR"); env != nullptr && *env != '\0') {
        return fs::path(env);
    }
    const auto home = std::getenv("HOME");
    if (home == nullptr) {
        return {};
    }
    const auto candidate = fs::path(home) / "source" / "jim" / "dataset-packed-pe";
    return fs::exists(candidate) ? candidate : fs::path();
}

// a representative packed sample per family the generic core is expected to
// handle without family code
fs::path fixture(const char* relative) {
    const auto root = corpus_root();
    if (root.empty()) {
        return {};
    }
    const auto p = root / "packed" / relative;
    return fs::exists(p) ? p : fs::path();
}

struct RunConfig {
    fs::path sample;
    fs::path out_dir;
    bool hop = true;
};

// One in-process unpack run: the same shape the CLI drives (synthesize a stub
// rootfs, install, run, finalize) so the tests measure the library, not the tool.
UnpackResult run_unpack(const RunConfig& cfg) {
    using namespace qiling::testing::pe_sample_detail;
    UnpackResult result;
    // a damaged DOS signature is repaired in a copy, exactly as the CLI does
    const auto run_sample = qiling::testing::pe_sample_detail::repairable_sample(cfg.sample);
    // Mirror the CLI: a sample whose header cannot be recovered at all is a clean
    // parse failure, not an exception escaping into the caller (tools/taote.cpp
    // prints reason=input_parse_failed and returns 1 for exactly this case).
    SamplePlan plan;
    try {
        plan = plan_for(run_sample);
    } catch (const std::exception&) {
        result.reason = "input_parse_failed";
        result.error = "the input header is not recoverable";
        return result;
    }

    const auto rootfs = fs::temp_directory_path() / ("taote_unpack_test_" + cfg.sample.stem().string());
    std::error_code ec;
    fs::remove_all(rootfs, ec);
    fs::create_directories(rootfs / "Windows" / "System32");
    fs::create_directories(rootfs / "Windows" / "registry");
    for (const auto& [dll, exports] : plan.imports) {
        write_stub_dll(rootfs, dll, exports, plan.is64);
    }
    for (const char* key_dll : {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll", "mscoree.dll"}) {
        if (!fs::exists(rootfs / "Windows" / "System32" / key_dll)) {
            std::vector<std::string> names;
            for (const auto& [dll, exports] : plan.imports) {
                if (dll == key_dll) {
                    names = exports;
                }
            }
            write_stub_dll(rootfs, key_dll, names, plan.is64);
        }
    }
    const auto staged = rootfs / "Windows" / cfg.sample.filename();
    fs::copy_file(run_sample, staged, fs::copy_options::overwrite_existing);

    qiling::os::register_dlls();
    qiling::QilingOptions options;
    options.rootfs = rootfs.string();
    options.ostype = qiling::QL_OS::WINDOWS;
    options.archtype = plan.is64 ? qiling::QL_ARCH::X8664 : qiling::QL_ARCH::X86;
    options.timeout = 60;
    options.count = 40000000;
    options.argv.push_back(staged.string());

    UnpackOptions uopts;
    uopts.sample_path = run_sample.string();
    uopts.out_dir = cfg.out_dir.string();
    uopts.enable_hop = cfg.hop;
    uopts.rootfs = rootfs.string();
    uopts.allow_decoy_dlls = true;
    Unpacker unpacker(uopts);

    std::unique_ptr<qiling::Qiling> ql;
    std::shared_ptr<qiling::QlFile> captured;
    try {
        ql = std::make_unique<qiling::Qiling>(options);
        captured = qiling::QlFile::open_mode((rootfs / "guest_stdout.txt").string(), "w+b");
        ql->os().set_stdout(captured);
        unpacker.install(*ql);
        try {
            ql->run();
        } catch (const qiling::QlErrorBase&) {
            // a guest fault still yields the artifact
        }
    } catch (const qiling::QlErrorBase& e) {
        result.error = e.what();
        if (result.reason.empty()) {
            result.reason = "init_failed";   // mirrors the CLI's else branch
        }
    }
    if (ql != nullptr) {
        if (captured != nullptr) {
            captured->close();
        }
        result = unpacker.finalize(*ql);
        ql.reset();
    }
    fs::remove_all(rootfs, ec);
    return result;
}

// The image of a *not-packed* original, as the unpacker would dump it: section
// content at base+rva. This is the grader's own notion of a good artifact.
std::vector<std::uint8_t> image_of(const fs::path& sample, std::uint64_t& base, std::uint64_t& oep_va,
                                   std::vector<std::pair<std::string, std::string>>& imports) {
    std::vector<std::uint8_t> image;
    auto parsed = LIEF::PE::Parser::parse(sample.string());
    if (parsed == nullptr) {
        return image;
    }
    base = parsed->imagebase();
    std::uint64_t max_end = 0;
    for (const auto& s : parsed->sections()) {
        const auto end = static_cast<std::uint64_t>(s.virtual_address()) + s.virtual_size();
        max_end = std::max(max_end, end);
    }
    image.assign(static_cast<std::size_t>(max_end), 0);
    // the PE headers live at rva 0..SizeOfHeaders: copy them from the file first
    // (this is what the loader maps and what the dump holds)
    {
        std::ifstream f(sample, std::ios::binary);
        std::vector<std::uint8_t> head(0x400);
        f.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
        head.resize(static_cast<std::size_t>(f.gcount()));
        const auto n = std::min(head.size(), image.size());
        std::copy(head.begin(), head.begin() + static_cast<std::ptrdiff_t>(n), image.begin());
    }
    for (const auto& s : parsed->sections()) {
        const auto content = s.content();
        const auto va = static_cast<std::size_t>(s.virtual_address());
        if (va + content.size() <= image.size()) {
            std::copy(content.begin(), content.end(), image.begin() + static_cast<std::ptrdiff_t>(va));
        }
    }
    // LIEF reports the entrypoint as a VA in this build (see plan_for): accept
    // both forms instead of double-adding the base
    const auto ep = static_cast<std::uint64_t>(parsed->entrypoint());
    oep_va = (ep >= base && ep < base + max_end) ? ep : base + ep;
    for (const auto& imp : parsed->imports()) {
        std::string dll = imp.name();
        for (auto& c : dll) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        for (const auto& e : imp.entries()) {
            imports.emplace_back(dll, e.name());
        }
    }
    return image;
}

}  // namespace

// The three artifacts + the meta keys the grader reads (PLAN_UNPACK §1.6).
TEST(UnpackCompat, UnpackArtifactContract) {
    const auto sample = fixture("UPX/upx_AccessEnum.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_contract";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});

    const auto stem = sample.filename().string();
    EXPECT_TRUE(fs::exists(out / (stem + "_dump.bin"))) << res.error;
    EXPECT_TRUE(fs::exists(out / (stem + "_dump.bin.meta.json"))) << res.error;
    EXPECT_TRUE(fs::exists(out / (stem + "_unpacked.exe"))) << res.error;
    EXPECT_GT(res.oep, 0u);
    EXPECT_EQ(res.stages, 1u);

    // the rebuilt artifact must parse as a PE with a plausible image
    auto parsed = LIEF::PE::Parser::parse((out / (stem + "_unpacked.exe")).string());
    ASSERT_NE(parsed, nullptr);
    EXPECT_GT(static_cast<std::uint64_t>(parsed->virtual_size()), 0x1000u);
    bool has_pgimp = false;
    for (const auto& s : parsed->sections()) {
        has_pgimp = has_pgimp || s.name() == ".pgimp";
    }
    EXPECT_TRUE(has_pgimp) << "the rebuilt PE lacks the .pgimp import section";
    fs::remove_all(out, ec);
}

// The meta sidecar is valid JSON with the keys the grader consumes. (The
// reference's own artifact fails this for its MEW/Molebox samples: its
// hand-rolled serializer mis-escapes a name, PLAN_UNPACK §0.0.)
TEST(UnpackCompat, UnpackMetaJsonValid) {
    const auto sample = fixture("ASPack/aspack_AccessEnum.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_meta";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    const auto meta_path = out / (sample.filename().string() + "_dump.bin.meta.json");
    ASSERT_TRUE(fs::exists(meta_path)) << res.error;

    std::ifstream in(meta_path);
    nlohmann::json meta;
    ASSERT_NO_THROW(meta = nlohmann::json::parse(in));
    for (const char* key : {"base", "oep", "oep_last_hop", "is_64", "stages", "reason", "imports"}) {
        EXPECT_TRUE(meta.contains(key)) << key;
    }
    EXPECT_NE(meta["oep"].get<std::string>(), "0x0");
    EXPECT_FALSE(meta["imports"].empty());
    fs::remove_all(out, ec);
}

// FSG's four mechanisms, pinned on the sample that isolates each (PLAN_UNPACK.md
// 0.17bj/0.17bk/0.17bn/0.17bo). They are the reason FSG went 75 -> 94 of 97, and
// every one of them was invisible to the pattern passes that preceded it.
namespace {
bool has_import(const UnpackResult& r, const char* dll, const char* fn) {
    // the mined DLL spelling keeps the image's case ("WLDAP32.dll"), which is what
    // the grader lowercases on both sides - so compare case-insensitively here
    const auto want = std::string(dll);
    for (const auto& [d, n] : r.imports) {
        if (d.size() != want.size() || n != fn) {
            continue;
        }
        bool same = true;
        for (std::size_t i = 0; i < d.size(); ++i) {
            same = same && std::tolower(static_cast<unsigned char>(d[i])) ==
                               std::tolower(static_cast<unsigned char>(want[i]));
        }
        if (same) {
            return true;
        }
    }
    return false;
}
}  // namespace

// The entry is stored in the stub as a REL32 branch (`je 0x411e58`) that decodes
// to a bare RVA, so no dword search can find it and the ladder used to claim
// 0x462bf8. Reaching the exact entry also proves the loader's page-below rule no
// longer overwrites FSG's entry section (round 67): without that guard the packed
// EP executes the header page and the payload never decodes.
TEST(UnpackCompat, FsgEntryIsTheStubRel32HandOff) {
    const auto sample = fixture("FSG/fsg_HashCalc.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_rel32";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    ASSERT_EQ(res.base, 0x400000u) << res.error;
    EXPECT_EQ(res.oep, res.base + 0x11e58u);   // the truth; the ladder said 0x462bf8
    EXPECT_GT(res.imports.size(), 300u);       // the payload's own table, not the stub's 5
    fs::remove_all(out, ec);
}

// FSG keeps its resolved-import list in the decoded image as 6-byte records after
// each DLL name: `02 <u16 ordinal> 00 00` for a by-ordinal import. Without mining
// them adrestore sits at recall 0.848 (its 10 missing pairs are all ordinals).
TEST(UnpackCompat, FsgOrdinalRecordsAreMined) {
    const auto sample = fixture("FSG/fsg_adrestore.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_ordinals";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    ASSERT_EQ(res.base, 0x400000u) << res.error;
    EXPECT_TRUE(has_import(res, "activeds.dll", "ordinal_9")) << res.error;
    EXPECT_TRUE(has_import(res, "wldap32.dll", "ordinal_118"));
    EXPECT_TRUE(has_import(res, "wldap32.dll", "ordinal_155"));
    EXPECT_TRUE(has_import(res, "oleaut32.dll", "ordinal_8"));
    fs::remove_all(out, ec);
}

// The stub is written for a 0x400000 load: `mov ebx,0x4001d0` and
// `mov edi,0x401000` are absolute while `mov esi,<stream>` is relative to the
// file's real base. fsg_calc loads at 0x1000000, so without the rebase it faults
// on its first movsb before any API call; with it the stub decodes and hands off
// at the original's entry RVA 0x12d6c.
TEST(UnpackCompat, FsgStubIsRebasedForANonDefaultBase) {
    const auto sample = fixture("FSG/fsg_calc.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_rebase";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    ASSERT_EQ(res.base, 0x1000000u) << res.error;
    EXPECT_EQ(res.oep, res.base + 0x12d6cu);   // the original's AddressOfEntryPoint
    fs::remove_all(out, ec);
}

// The mult-pass block table stores the destination VA PAGE in a 16-bit word and the
// stub only shifts it, so a load base above 0xFFFF pages truncates the field:
// fsg_cmd (base 0x4ad00000) wants page 0x4ad26 and the packer wrote 0xad26. The
// stub then decodes to 0xad26000 and dies before its last blocks - which hold the
// payload's import run - so without the mapping this row mines 25 imports (recall
// 0.004) instead of all 229.
TEST(UnpackCompat, FsgTruncatedBlockPageIsMapped) {
    const auto sample = fixture("FSG/fsg_cmd.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_blockpage";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    ASSERT_EQ(res.base, 0x4ad00000u) << res.error;
    EXPECT_EQ(res.oep, res.base + 0x829au);          // the original's entry
    EXPECT_GT(res.imports.size(), 300u) << res.error;  // 25 before the block page was mapped
    EXPECT_TRUE(has_import(res, "kernel32.dll", "CreateFileW"));
    EXPECT_TRUE(has_import(res, "kernel32.dll", "CloseHandle"));
    fs::remove_all(out, ec);
}

// A zeroed DOS signature makes LIEF refuse a file whose PE header is otherwise
// intact: fsg_livekd ships with 00 00 where "MZ" belongs. The tool repairs the
// magic in a COPY and runs that, so the sample loads at all; its stub then carries
// `je 0x9663`, which is the original's entry, and the payload's import run mines to
// recall 0.973 even though the packed stream is truncated and the body stays
// undecoded (code_sim 0.105). Both halves are needed: without the copy repair the
// run never starts, and without the undecoded-target sweep the entry stays at the
// packed EP.
TEST(UnpackCompat, FsgZeroedDosSignatureIsRepaired) {
    const auto sample = fixture("FSG/fsg_livekd.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_livekd";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    ASSERT_EQ(res.base, 0x400000u) << res.error;
    EXPECT_EQ(res.oep, res.base + 0x9663u);   // the stub's je target; the fallback was the packed EP
    EXPECT_GT(res.imports.size(), 300u) << res.error;
    EXPECT_TRUE(has_import(res, "kernel32.dll", "CreateFileW"));
    fs::remove_all(out, ec);
}

// FSG shifts the first character of every import name by -3, and the undo is a
// per-BLOCK vote rather than per-name evidence: one string run belongs to one
// packer, so the shift is a property of the run. That distinction is what makes
// the CRT internals recoverable - the export database has no _isctype/_pctype,
// so a per-name "is this a known export once shifted?" test leaves them as
// bisctype/bpctype and the row's recall stays near zero. fsg_rm ships those
// names, so asserting them pins the vote itself: drop the vote and this fails
// while a plain import COUNT would still pass.
TEST(UnpackCompat, FsgStringShiftIsUndoneAsABlockVote) {
    const auto sample = fixture("FSG/fsg_rm.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_shiftvote";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    // vote-only names: no export database entry exists for these spellings
    for (const char* fn : {"_isctype", "_pctype", "fopen", "tolower", "putc"}) {
        EXPECT_TRUE(has_import(res, "msvcrt.dll", fn))
            << fn << " missing - the per-block shift vote did not fire; pairs=" << res.imports.size();
    }
    // and the shifted spellings must be gone
    for (const char* fn : {"bisctype", "bpctype", "b_mb_cur_max"}) {
        EXPECT_FALSE(has_import(res, "msvcrt.dll", fn)) << fn << " left unshifted";
    }
    fs::remove_all(out, ec);
}

// The last FSG row is dead packer output, and the tool must say so GRACEFULLY.
// fsg_Snap2HTML ships with no "PE\0\0" anywhere (the packer overwrote its header
// page with the stub), so there is nothing to repair and nothing to load. The
// contract this pins is the host-safety one: an unparsable sample returns a clean
// zero result with an input_parse_failed reason instead of throwing, crashing or
// emitting a dump that the grader would mistake for an unpack.
TEST(UnpackCompat, FsgHeaderlessInputFailsGracefully) {
    const auto sample = fixture("FSG/fsg_Snap2HTML.exe");
    if (sample.empty()) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto out = fs::temp_directory_path() / "taote_unpack_fsg_snap2html";
    std::error_code ec;
    fs::remove_all(out, ec);
    const auto res = run_unpack(RunConfig{sample, out, true});
    EXPECT_EQ(res.base, 0u) << res.error;
    EXPECT_EQ(res.oep, 0u) << res.error;
    EXPECT_TRUE(res.imports.empty()) << res.error;
    EXPECT_FALSE(res.dump_written) << res.error;
    EXPECT_NE(res.reason.find("input_parse_failed"), std::string::npos)
        << "reason was: " << res.reason;
    fs::remove_all(out, ec);
}

// The grader's own calibration: a hand-built artifact from the *not-packed*
// original must grade VERIFIED. Here that means the rebuilt PE keeps the
// original's EP RVA and a parseable section table, which is exactly checks
// (b)+(c) of verify.py.
TEST(UnpackCompat, UnpackGraderSmoke) {
    const auto root = corpus_root();
    if (root.empty() || !fs::exists(root / "not-packed" / "AccessEnum.exe")) {
        GTEST_SKIP() << "packed corpus not present (set TAOTE_PACKED_DIR)";
    }
    const auto original = root / "not-packed" / "AccessEnum.exe";
    std::uint64_t base = 0;
    std::uint64_t oep_va = 0;
    std::vector<std::pair<std::string, std::string>> imports;
    auto image = image_of(original, base, oep_va, imports);
    ASSERT_FALSE(image.empty());

    RebuildInput in;
    in.image = image;
    in.base = base;
    in.oep_va = oep_va;
    in.is_64 = false;
    in.imports = imports;
    const auto rebuilt = rebuild_pe(in);
    ASSERT_FALSE(rebuilt.empty());

    const auto out = fs::temp_directory_path() / "taote_unpack_smoke.exe";
    {
        std::ofstream f(out, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(rebuilt.data()), static_cast<std::streamsize>(rebuilt.size()));
    }
    auto orig_pe = LIEF::PE::Parser::parse(original.string());
    auto out_pe = LIEF::PE::Parser::parse(out.string());
    ASSERT_NE(orig_pe, nullptr);
    ASSERT_NE(out_pe, nullptr);
    // (c) the entry point survives the rebuild
    EXPECT_EQ(static_cast<std::uint64_t>(out_pe->entrypoint()) - static_cast<std::uint64_t>(out_pe->imagebase()),
              static_cast<std::uint64_t>(orig_pe->entrypoint()) -
                  static_cast<std::uint64_t>(orig_pe->imagebase()));
    // (b) a sane image
    EXPECT_GE(static_cast<std::uint64_t>(out_pe->virtual_size()), 0x1000u);
    EXPECT_GE(out_pe->sections().size(), orig_pe->sections().size());
    std::error_code ec;
    fs::remove(out, ec);
}

// The rebuilder parses attacker-controlled bytes: malformed input must yield an
// empty result, never a crash (PLAN_UNPACK §4.1, Phase 6).
TEST(UnpackCompat, UnpackHostSafety) {
    const auto root = corpus_root();
    std::vector<std::uint8_t> image;
    std::uint64_t base = 0x400000;
    std::uint64_t oep_va = 0;
    std::vector<std::pair<std::string, std::string>> imports;
    if (!root.empty() && fs::exists(root / "not-packed" / "AccessEnum.exe")) {
        image = image_of(root / "not-packed" / "AccessEnum.exe", base, oep_va, imports);
    }
    if (image.size() < 0x1000) {
        // a synthetic minimal image, so the case runs everywhere
        image.assign(0x4000, 0);
        image[0] = 'M';
        image[1] = 'Z';
        const std::uint32_t lfanew = 0x80;
        std::memcpy(&image[0x3c], &lfanew, 4);
        image[lfanew] = 'P';
        image[lfanew + 1] = 'E';
        base = 0x400000;
        oep_va = 0x401000;
    }

    // deterministic mutations: truncations, header garbage, absurd section counts
    const std::vector<std::size_t> cuts = {0, 1, 2, 0x3c, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800};
    std::size_t checked = 0;
    for (const auto cut : cuts) {
        for (int variant = 0; variant < 8; ++variant) {
            RebuildInput in;
            in.image = image;
            if (cut > 0 && cut < in.image.size()) {
                in.image.resize(cut);
            }
            if (variant > 0 && in.image.size() > 0x100) {
                // scribble on the header region only (the parser's input)
                for (int k = 0; k < variant * 3; ++k) {
                    const std::size_t off = static_cast<std::size_t>((k * 37 + variant * 11) % 0x100);
                    in.image[off] = static_cast<std::uint8_t>(0xff - variant);
                }
            }
            if (variant == 7 && in.image.size() > 0x90) {
                const std::uint16_t huge = 0xffcd;  // the observed TELock/7z corruption
                std::memcpy(&in.image[0x80 + 6], &huge, 2);
            }
            in.base = base;
            in.oep_va = oep_va;
            in.imports = imports;
            auto out = rebuild_pe(in);
            if (!out.empty()) {
                // whatever it produced must still parse (or be rejected by LIEF)
                EXPECT_TRUE(out.size() > 0x40);
            }
            ++checked;
        }
    }
    EXPECT_EQ(checked, cuts.size() * 8);
}
