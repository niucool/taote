// HandleManager suite — PORT_PLAN.md §10 Phase 4 (os/windows/handle.py: the
// Windows handle simulation, verbatim semantics).
#include <gtest/gtest.h>

#include "qiling/os/windows/handle.hpp"

using namespace qiling;

TEST(HandleManager, PrepopulatedWithStdioAndRegistryHives) {
    os::HandleManager mgr;

    // the standard handles exist out of the box
    EXPECT_NE(mgr.get(os::QL_STD_INPUT_HANDLE), nullptr);
    EXPECT_NE(mgr.get(os::QL_STD_OUTPUT_HANDLE), nullptr);
    EXPECT_NE(mgr.get(os::QL_STD_ERROR_HANDLE), nullptr);

    // the registry hives are pre-bound by name
    EXPECT_NE(mgr.search("HKEY_LOCAL_MACHINE"), nullptr);
    EXPECT_NE(mgr.search("HKEY_CLASSES_ROOT"), nullptr);
    EXPECT_NE(mgr.search("HKEY_USERS"), nullptr);
    EXPECT_EQ(mgr.search("HKEY_NO_SUCH_HIVE"), nullptr);
}

TEST(HandleManager, AppendAndGetLifecycle) {
    os::HandleManager mgr;

    os::Handle handle;
    const auto id = handle.id;
    mgr.append(std::move(handle));

    const auto fetched = mgr.get(id);
    ASSERT_NE(fetched, nullptr);
    EXPECT_EQ(fetched->id, id);

    // a fresh handle gets a distinct id (the 0xa0000000 allocator)
    os::Handle other;
    EXPECT_NE(other.id, id);

    mgr.delete_handle(id);
    EXPECT_EQ(mgr.get(id), nullptr);
}

TEST(HandleManager, SearchByObj) {
    os::HandleManager mgr;

    const auto marker = reinterpret_cast<void*>(0x1234);
    os::Handle handle{std::nullopt, marker};
    mgr.append(std::move(handle));

    EXPECT_EQ(mgr.search_by_obj(marker) != nullptr, true);
    EXPECT_EQ(mgr.search_by_obj(reinterpret_cast<void*>(0x999)) , nullptr);
}
