// Memory suite — PORT_PLAN.md §10 Phase 2 (the qiling/os/memory.py surface:
// map/unmap/protect round-trips, read/write/ptr/string helpers, mapinfo,
// free-space search, and the QlMemoryHeap).
#include <gtest/gtest.h>

#include <string>

#include "qiling/arch/x86.hpp"
#include "qiling/os/memory.hpp"

using namespace qiling;

namespace {

struct MemHarness {
    QlArchX8664 arch;
    QlCoreStructs structs{QL_ENDIAN::EL, 64};
    QlMemoryManager mem;

    MemHarness() : arch(nullptr), mem(arch.uc(), structs, 64) {}
};

}  // namespace

TEST(MemoryManager, MapReadWriteRoundTrip) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL, "test");

    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    h.mem.write(0x1080, payload);
    EXPECT_EQ(h.mem.read(0x1080, 4), payload);
}

TEST(MemoryManager, ReadPtrWritePtr) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);

    // the native (8-byte) path
    h.mem.write_ptr(0x1000, 0x1122334455667788ull);
    EXPECT_EQ(h.mem.read_ptr(0x1000), 0x1122334455667788);

    // explicit sizes with endianness (EL: low byte first)
    h.mem.write_ptr(0x1010, 0xAABB, 2, false);
    EXPECT_EQ(h.mem.read(0x1010, 2), (std::vector<std::uint8_t>{0xBB, 0xAA}));
    EXPECT_EQ(h.mem.read_ptr(0x1010, 2), 0xAABB);

    // signed interpretation
    h.mem.write_ptr(0x1020, static_cast<std::int64_t>(-1), 2, true);
    EXPECT_EQ(h.mem.read_ptr(0x1020, 2, true), -1);

    // unsupported sizes degrade to the conversion error
    EXPECT_THROW(static_cast<void>(h.mem.read_ptr(0x1000, 3)), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(h.mem.read_ptr(0x1000, 16)), QlErrorStructConversion);
}

TEST(MemoryManager, StringReadWrite) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);

    h.mem.string(0x1000, "hello");
    EXPECT_EQ(h.mem.read(0x1000, 6), (std::vector<std::uint8_t>{'h', 'e', 'l', 'l', 'o', 0}));
    EXPECT_EQ(h.mem.string(0x1000), std::optional<std::string>("hello"));
}

TEST(MemoryManager, MapCollisionRaises) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);
    // overlapping map raises QlMemoryMappedError (memory.py verbatim)
    EXPECT_THROW(h.mem.map(0x1800, 0x1000, UC_PROT_ALL), QlMemoryMappedError);
    EXPECT_NO_THROW(h.mem.map(0x2000, 0x1000, UC_PROT_ALL));
}

TEST(MemoryManager, UnmapAndIsAvailable) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);

    EXPECT_FALSE(h.mem.is_available(0x1000, 0x100));
    EXPECT_TRUE(h.mem.is_available(0x2000, 0x100));
    EXPECT_TRUE(h.mem.is_mapped(0x1000, 0x100));

    h.mem.unmap(0x1000, 0x1000);
    EXPECT_TRUE(h.mem.is_available(0x1000, 0x100));
    EXPECT_FALSE(h.mem.is_mapped(0x1000, 0x100));
}

TEST(MemoryManager, UnmapBetween) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL, "a");
    h.mem.map(0x2000, 0x1000, UC_PROT_ALL, "b");

    // unicorn's mem_unmap requires page-aligned ranges, so the range spans
    // full pages; unmap_between splits it at the live region boundaries
    h.mem.unmap_between(0x1000, 0x3000);
    EXPECT_FALSE(h.mem.is_mapped(0x1000, 0x1000));
    EXPECT_FALSE(h.mem.is_mapped(0x2000, 0x1000));
    EXPECT_TRUE(h.mem.is_available(0x1000, 0x2000));
}

TEST(MemoryManager, ProtectChangesPerms) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);
    h.mem.protect(0x1000, 0x1000, UC_PROT_READ);

    const auto mapinfo = h.mem.get_mapinfo();
    ASSERT_EQ(mapinfo.size(), 1u);
    EXPECT_EQ(std::get<2>(mapinfo[0]), "r--");
}

TEST(MemoryManager, MapinfoAddDeleteChange) {
    MemHarness h;
    h.mem.add_mapinfo(0x1000, 0x2000, UC_PROT_ALL, "[test]");
    h.mem.add_mapinfo(0x3000, 0x4000, UC_PROT_READ, "[other]");

    EXPECT_EQ(h.mem.map_info().size(), 2u);
    // sorted by begin
    EXPECT_EQ(h.mem.map_info()[0].label, "[test]");
    EXPECT_EQ(h.mem.map_info()[1].label, "[other]");

    h.mem.change_mapinfo(0x1000, 0x2000, UC_PROT_NONE, "[renamed]");
    EXPECT_EQ(h.mem.map_info()[0].perms, UC_PROT_NONE);
    EXPECT_EQ(h.mem.map_info()[0].label, "[renamed]");

    h.mem.del_mapinfo(0x3000, 0x4000);
    EXPECT_EQ(h.mem.map_info().size(), 1u);
}

TEST(MemoryManager, GetLibBase) {
    MemHarness h;
    h.mem.add_mapinfo(0x1000, 0x2000, UC_PROT_ALL, "[windows] C:\\Windows\\system32\\kernel32.dll");
    EXPECT_EQ(h.mem.get_lib_base("kernel32.dll"), std::optional<std::uint64_t>(0x1000));
    EXPECT_EQ(h.mem.get_lib_base("nosuch.dll"), std::nullopt);
}

TEST(MemoryManager, FindFreeSpaceAndMapAnywhere) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);

    // the first gap after the mapped page
    const auto addr = h.mem.find_free_space(0x2000);
    EXPECT_EQ(addr, 0x2000);

    // bounded search
    EXPECT_EQ(h.mem.find_free_space(0x800, 0x5000, 0x8000), 0x5000);

    // exhausted domain degrades to QlOutOfMemory
    EXPECT_THROW(h.mem.find_free_space(0x2000, 0x1000, 0x2000), QlOutOfMemory);

    const auto mapped = h.mem.map_anywhere(0x800, std::nullopt, std::nullopt, std::nullopt, UC_PROT_ALL, "anywhere");
    EXPECT_TRUE(h.mem.is_mapped(mapped, 0x800));
}

TEST(MemoryManager, SearchFindsBytes) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL);
    h.mem.write(0x1080, std::string_view("\xDE\xAD\xBE\xEF", 4));
    h.mem.write(0x1100, std::string_view("\xDE\xAD\xBE\xEF", 4));

    const auto hits = h.mem.search({0xDE, 0xAD, 0xBE, 0xEF});
    ASSERT_EQ(hits.size(), 2u);
    EXPECT_EQ(hits[0], 0x1080u);
    EXPECT_EQ(hits[1], 0x1100u);
}

TEST(MemoryManager, SaveRestoreRoundTrip) {
    MemHarness h;
    h.mem.map(0x1000, 0x1000, UC_PROT_ALL, "stateful");
    h.mem.write(0x1080, std::string_view("STATE-A", 7));

    const auto saved = h.mem.save();
    ASSERT_EQ(saved.ram.size(), 1u);
    EXPECT_EQ(saved.ram[0].label, "stateful");
    ASSERT_EQ(saved.ram[0].data.size(), 0x1000u);

    // mutate the memory
    h.mem.write(0x1080, std::string_view("STATE-B", 7));
    EXPECT_EQ(h.mem.read(0x1080, 7), (std::vector<std::uint8_t>{'S', 'T', 'A', 'T', 'E', '-', 'B'}));

    // restore brings the original content back byte-identically
    h.mem.restore(saved);
    EXPECT_EQ(h.mem.read(0x1080, 7), (std::vector<std::uint8_t>{'S', 'T', 'A', 'T', 'E', '-', 'A'}));
}

TEST(MemoryHeap, AllocFreeRecycle) {
    MemHarness h;
    QlMemoryHeap heap(h.mem, 0x30000, 0x40000);

    const auto a = heap.alloc(0x100);
    ASSERT_NE(a, 0u);
    EXPECT_EQ(heap.size(a), 0x100u);

    const auto b = heap.alloc(0x80);
    EXPECT_NE(b, 0u);
    EXPECT_NE(b, a);

    EXPECT_TRUE(heap.free(a));
    EXPECT_FALSE(heap.free(a));  // double free fails

    // freed memory is recycled for a fitting allocation
    const auto c = heap.alloc(0x40);
    EXPECT_EQ(c, a);

    // free returns false for unknown addresses
    EXPECT_FALSE(heap.free(0xdead));
}

TEST(MemoryHeap, GrowAndBound) {
    MemHarness h;
    QlMemoryHeap heap(h.mem, 0x30000, 0x31000);  // a 0x1000-byte heap

    // allocate past one page: the heap grows in page-size steps
    const auto a = heap.alloc(0x800);
    ASSERT_NE(a, 0u);
    const auto b = heap.alloc(0x800);
    ASSERT_NE(b, 0u);

    // exceeding the heap end fails with 0 (memory.py verbatim behavior)
    EXPECT_EQ(heap.alloc(0x800), 0u);
}
