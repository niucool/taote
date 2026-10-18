// Windows API registration suite — PORT_PLAN.md §10 Phase 4 (the winsdkapi
// decorator engine over the static ApiRegistry; the fncc calling conventions).
#include <gtest/gtest.h>

#include <string>

#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"

using namespace qiling;
using namespace qiling::os;

namespace {

// a registration guard: the registry is process-global, so the tests clear it
struct RegistryScope {
    ~RegistryScope() { ApiRegistry::instance().clear(); }
};

}  // namespace

TEST(WinApiRegistry, RegisterAndFindByName) {
    RegistryScope scope;

    // the @winsdkapi(cc=STDCALL, params={...}) analogue: a fluent builder
    WinsdkApi("GetStdHandle", WinCc::Stdcall, {{"nStdHandle", api::DWORD_}}) =
        [](Qiling&, std::uint64_t) -> std::optional<std::uint64_t> {
        return 0xfffffff5;  // STD_OUTPUT_HANDLE
    };

    const auto* entry = ApiRegistry::instance().find("GetStdHandle");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->cc, WinCc::Stdcall);
    ASSERT_EQ(entry->params.size(), 1u);
    EXPECT_EQ(entry->params[0].first, "nStdHandle");
    EXPECT_EQ(entry->params[0].second, static_cast<int>(api::DWORD_));
    EXPECT_NE(entry->handler, nullptr);
}

TEST(WinApiRegistry, FindIsCaseSensitiveLikeGetattr) {
    RegistryScope scope;

    WinsdkApi("GetCommandLineA", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t) -> std::optional<std::uint64_t> { return 0; };

    // the Python getattr is case-sensitive
    EXPECT_NE(ApiRegistry::instance().find("GetCommandLineA"), nullptr);
    EXPECT_EQ(ApiRegistry::instance().find("getcommandlinea"), nullptr);
}

TEST(WinApiRegistry, ReRegistrationReplaces) {
    RegistryScope scope;

    WinsdkApi("ExitProcess", WinCc::Stdcall, {{"uExitCode", api::UINT_}}) =
        [](Qiling&, std::uint64_t) -> std::optional<std::uint64_t> { return 0; };

    // a later registration with the same name replaces the entry (the Python
    // decorator overwrites the module attribute)
    WinsdkApi("ExitProcess", WinCc::Ms64, {}) =
        [](Qiling&, std::uint64_t) -> std::optional<std::uint64_t> { return 0; };

    const auto* entry = ApiRegistry::instance().find("ExitProcess");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->cc, WinCc::Ms64);
    EXPECT_TRUE(entry->params.empty());
}

TEST(WinApiRegistry, NamesListedForCoverage) {
    RegistryScope scope;

    WinsdkApi("GetStdHandle", WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t) -> std::optional<std::uint64_t> { return 0; };
    WinsdkApi("GetCommandLineA", WinCc::Stdcall, {}) = [](Qiling&, std::uint64_t) -> std::optional<std::uint64_t> { return 0; };

    const auto names = ApiRegistry::instance().names();
    EXPECT_EQ(names.size(), 2u);
}
