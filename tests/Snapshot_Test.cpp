// Snapshot suite — PORT_PLAN.md §10 Phase 2 (memory + register snapshot over
// the explicit versioned binary envelope; byte-identical resumable state).
#include <gtest/gtest.h>

#include <string>

#include "qiling/arch/x86.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/snapshot.hpp"

using namespace qiling;

// ---- the binary envelope ----

TEST(SnapshotEnvelope, RoundTripSections) {
    SnapshotWriter w;
    w.begin_section("alpha");
    w.put_u32(0xDEADBEEF);
    w.put_str("hello snapshot");
    w.end_section();
    w.begin_section("beta");
    w.put_u64(0x1122334455667788ull);
    w.end_section();

    const auto blob = std::move(w).finish();
    SnapshotReader r(std::string_view(reinterpret_cast<const char*>(blob.data()), blob.size()));

    ASSERT_TRUE(r.seek_section("alpha"));
    EXPECT_EQ(r.get_u32(), 0xDEADBEEFu);
    EXPECT_EQ(r.get_str(), "hello snapshot");

    ASSERT_TRUE(r.seek_section("beta"));
    EXPECT_EQ(r.get_u64(), 0x1122334455667788ull);
}

TEST(SnapshotEnvelope, MissingSectionIsAbsent) {
    SnapshotWriter w;
    w.begin_section("only");
    w.put_u8(1);
    w.end_section();

    const auto blob = std::move(w).finish();
    SnapshotReader r(std::string_view(reinterpret_cast<const char*>(blob.data()), blob.size()));
    EXPECT_FALSE(r.seek_section("absent"));
    EXPECT_TRUE(r.seek_section("only"));
}

TEST(SnapshotEnvelope, MalformedInputDegradesToError) {
    std::vector<std::uint8_t> garbage = {0x00, 0x01, 0x02};
    EXPECT_THROW(static_cast<void>(SnapshotReader(std::string_view(reinterpret_cast<const char*>(garbage.data()), garbage.size()))),
                 QlErrorBase);

    // a truncated section payload is rejected, never a host crash
    SnapshotWriter w;
    w.begin_section("s");
    w.put_bytes("payload");
    w.end_section();
    auto raw = std::move(w).finish();
    raw.resize(raw.size() - 3);  // corrupt the payload length accounting

    SnapshotReader r(std::string_view(reinterpret_cast<const char*>(raw.data()), raw.size()));
    EXPECT_THROW(r.seek_section("s"), QlErrorBase);
}

TEST(SnapshotEnvelope, SkipsUnknownSections) {
    SnapshotWriter w;
    w.begin_section("first");
    w.put_u8(0xAA);
    w.end_section();
    w.begin_section("second");
    w.put_u8(0xBB);
    w.end_section();

    const auto blob = std::move(w).finish();
    SnapshotReader r(std::string_view(reinterpret_cast<const char*>(blob.data()), blob.size()));
    // skipping an unknown section positions after its payload
    EXPECT_TRUE(r.seek_section("first"));
    EXPECT_TRUE(r.seek_section("second"));
    EXPECT_EQ(r.get_u8(), 0xBBu);
    EXPECT_TRUE(r.at_end());
}

// ---- memory + registers snapshot (the core.py:609 component surface) ----

TEST(Snapshot, MemoryAndRegistersRoundTrip) {
    QlArchX8664 arch(nullptr);
    QlCoreStructs structs(QL_ENDIAN::EL, 64);
    QlMemoryManager mem(arch.uc(), structs, 64);

    mem.map(0x1000, 0x1000, UC_PROT_ALL, "state");
    mem.write(0x1080, std::string_view("SNAPSHOT", 8));
    arch.regs().write("rax", 0xAAAA1111AAAA2222ull);
    arch.regs().write("rip", 0x1080);

    // save: memory content + all registers (core.py save(reg=True, mem=True))
    const auto saved_mem = mem.save();
    const auto saved_regs = arch.regs().save();

    // mutate everything
    mem.write(0x1080, std::string_view("MUTATED!", 8));
    arch.regs().write("rax", 0xBBBB2222BBBB3333ull);
    arch.regs().write("rip", 0x9999);

    // restore brings the saved state back byte-identically
    mem.restore(saved_mem);
    arch.regs().restore(saved_regs);

    EXPECT_EQ(mem.read(0x1080, 8), (std::vector<std::uint8_t>{'S', 'N', 'A', 'P', 'S', 'H', 'O', 'T'}));
    EXPECT_EQ(arch.regs().read("rax"), 0xAAAA1111AAAA2222ull);
    EXPECT_EQ(arch.regs().read("rip"), 0x1080u);
}

TEST(Snapshot, MemoryEnvelopeIsByteIdentical) {
    QlArchX8664 arch(nullptr);
    QlCoreStructs structs(QL_ENDIAN::EL, 64);
    QlMemoryManager mem(arch.uc(), structs, 64);

    mem.map(0x1000, 0x1000, UC_PROT_ALL, "page");
    mem.write(0x1000, std::string_view("\x01\x02\x03\x04", 4));

    // serialize the saved memory through the versioned envelope
    const auto saved = mem.save();
    SnapshotWriter w;
    w.begin_section("mem");
    w.put_u32(static_cast<std::uint32_t>(saved.ram.size()));
    for (const auto& range : saved.ram) {
        w.put_u64(range.begin);
        w.put_u64(range.end);
        w.put_u32(static_cast<std::uint32_t>(range.perms));
        w.put_str(range.label);
        w.put_u64(range.data.size());
        w.put_bytes(std::string_view(reinterpret_cast<const char*>(range.data.data()), range.data.size()));
    }
    w.end_section();
    auto blob = std::move(w).finish();

    // read it back and verify the content survived the round-trip
    SnapshotReader r(std::string_view(reinterpret_cast<const char*>(blob.data()), blob.size()));
    ASSERT_TRUE(r.seek_section("mem"));
    const auto range_count = r.get_u32();
    ASSERT_EQ(range_count, 1u);
    EXPECT_EQ(r.get_u64(), 0x1000u);
    EXPECT_EQ(r.get_u64(), 0x2000u);
    EXPECT_EQ(r.get_u32(), static_cast<std::uint32_t>(UC_PROT_ALL));
    EXPECT_EQ(r.get_str(), "page");
    const auto data_len = r.get_u64();
    ASSERT_EQ(data_len, 0x1000u);
    const auto data = r.get_bytes(data_len);
    EXPECT_EQ(data[0], 0x01);
    EXPECT_EQ(data[4], 0x00);
}

TEST(Snapshot, RestoreResumesExecution) {
    // the byte-identical resumable state criterion: a stopped emulation's
    // state (regs + mem) restores and execution continues from the snapshot
    QlArchX8664 arch(nullptr);
    QlCoreStructs structs(QL_ENDIAN::EL, 64);
    QlMemoryManager mem(arch.uc(), structs, 64);

    mem.map(0x1000, 0x1000, UC_PROT_ALL);
    // 0x1000: mov eax, 0x41   |   0x1005: inc eax   |   0x1007: nop
    mem.write(0x1000, std::string_view("\xB8\x41\x00\x00\x00\xFF\xC0\x90", 8));

    // run the first instruction
    uc_emu_start(&arch.uc(), 0x1000, 0x1005, 0, 0);
    EXPECT_EQ(arch.regs().read("eax"), 0x41u);

    // snapshot the running state
    const auto saved_mem = mem.save();
    const auto saved_regs = arch.regs().save();

    // mutate and stop
    arch.regs().write("rax", 0x0);
    arch.regs().write("rip", 0x1000);

    // restore and resume from the snapshot point
    mem.restore(saved_mem);
    arch.regs().restore(saved_regs);

    ASSERT_EQ(uc_emu_start(&arch.uc(), 0x1005, 0x1007, 0, 0), UC_ERR_OK);
    // inc eax ran on the restored state: 0x41 + 1
    EXPECT_EQ(arch.regs().read("eax"), 0x42u);
}
