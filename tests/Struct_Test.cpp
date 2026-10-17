// Struct suite — PORT_PLAN.md §10 Phase 2 (the qiling/core_struct.py surface:
// endian-aware pack/unpack, the bit-selected bindings, and the conversion
// error paths).
#include <gtest/gtest.h>

#include <string>

#include "qiling/core_struct.hpp"

using namespace qiling;

TEST(CoreStructs, PackUnpackRoundTrip) {
    const QlCoreStructs el(QL_ENDIAN::EL, 64);

    EXPECT_EQ(el.pack8(0xAB), std::string("\xAB", 1));
    EXPECT_EQ(el.pack8s(-1), std::string("\xFF", 1));
    EXPECT_EQ(el.pack16(0xBEEF), std::string("\xEF\xBE", 2));
    EXPECT_EQ(el.pack16s(-2), std::string("\xFE\xFF", 2));
    EXPECT_EQ(el.pack32(0xDEADBEEF), std::string("\xEF\xBE\xAD\xDE", 4));
    EXPECT_EQ(el.pack32s(-3), std::string("\xFD\xFF\xFF\xFF", 4));
    EXPECT_EQ(el.pack64(0x0123456789ABCDEFull), std::string("\xEF\xCD\xAB\x89\x67\x45\x23\x01", 8));
    EXPECT_EQ(el.pack64s(-4), std::string("\xFC\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8));

    EXPECT_EQ(el.unpack8(std::string_view("\xAB", 1)), 0xABu);
    EXPECT_EQ(el.unpack8s(std::string_view("\xFF", 1)), -1);
    EXPECT_EQ(el.unpack16(std::string_view("\xEF\xBE", 2)), 0xBEEFu);
    EXPECT_EQ(el.unpack16s(std::string_view("\xFE\xFF", 2)), -2);
    EXPECT_EQ(el.unpack32(std::string_view("\xEF\xBE\xAD\xDE", 4)), 0xDEADBEEFu);
    EXPECT_EQ(el.unpack32s(std::string_view("\xFD\xFF\xFF\xFF", 4)), -3);
    EXPECT_EQ(el.unpack64(std::string_view("\xEF\xCD\xAB\x89\x67\x45\x23\x01", 8)), 0x0123456789ABCDEFull);
    EXPECT_EQ(el.unpack64s(std::string_view("\xFC\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8)), -4);
}

TEST(CoreStructs, BigEndianPacking) {
    // big-endian struct.Struct('>H' etc.) — byte-reversed vs the little-endian form
    const QlCoreStructs eb(QL_ENDIAN::EB, 64);

    EXPECT_EQ(eb.pack16(0xBEEF), std::string("\xBE\xEF", 2));
    EXPECT_EQ(eb.pack32(0xDEADBEEF), std::string("\xDE\xAD\xBE\xEF", 4));
    EXPECT_EQ(eb.pack64(0x0123456789ABCDEFull), std::string("\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8));

    EXPECT_EQ(eb.unpack16(std::string_view("\xBE\xEF", 2)), 0xBEEFu);
    EXPECT_EQ(eb.unpack32(std::string_view("\xDE\xAD\xBE\xEF", 4)), 0xDEADBEEFu);
    EXPECT_EQ(eb.unpack64(std::string_view("\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8)), 0x0123456789ABCDEFull);
}

TEST(CoreStructs, SignedRangeChecks) {
    const QlCoreStructs el(QL_ENDIAN::EL, 64);

    // struct.pack raises struct.error on out-of-range; the port degrades to
    // the framework exception (documented deviation)
    EXPECT_THROW(static_cast<void>(el.pack16s(70000)), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(el.pack16s(-70000)), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(el.pack8(256)), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(el.pack8s(128)), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(el.pack32(0x1'0000'0000ull)), QlErrorStructConversion);
    EXPECT_NO_THROW(static_cast<void>(el.pack8s(-128)));
    EXPECT_NO_THROW(static_cast<void>(el.pack16s(32767)));
}

TEST(CoreStructs, UnpackSizeMismatch) {
    const QlCoreStructs el(QL_ENDIAN::EL, 64);
    EXPECT_THROW(static_cast<void>(el.unpack16(std::string_view("\xEF", 1))), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(el.unpack64(std::string_view("\xEF\xBE\xAD\xDE", 4))), QlErrorStructConversion);
}

TEST(CoreStructs, BitSelectedBindings) {
    // the handlers table: pack/packs/unpack/unpacks bind to the word size
    const QlCoreStructs bits64(QL_ENDIAN::EL, 64);
    EXPECT_EQ(bits64.pack(0x0123456789ABCDEFull), std::string("\xEF\xCD\xAB\x89\x67\x45\x23\x01", 8));
    EXPECT_EQ(bits64.packs(-4), std::string("\xFC\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8));
    EXPECT_EQ(bits64.unpack(std::string_view("\xEF\xCD\xAB\x89\x67\x45\x23\x01", 8)), 0x0123456789ABCDEFull);
    EXPECT_EQ(bits64.unpacks(std::string_view("\xFC\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8)), -4);

    const QlCoreStructs bits32(QL_ENDIAN::EL, 32);
    EXPECT_EQ(bits32.pack(0xDEADBEEF), std::string("\xEF\xBE\xAD\xDE", 4));
    EXPECT_EQ(bits32.unpacks(std::string_view("\xFD\xFF\xFF\xFF", 4)), -3);

    const QlCoreStructs bits16(QL_ENDIAN::EL, 16);
    EXPECT_EQ(bits16.pack(0xBEEF), std::string("\xEF\xBE", 2));

    // unsupported widths are rejected at construction (core_struct.py handlers)
    EXPECT_THROW(static_cast<void>(QlCoreStructs(QL_ENDIAN::EL, 8)), QlErrorStructConversion);
    EXPECT_THROW(static_cast<void>(QlCoreStructs(QL_ENDIAN::EL, 128)), QlErrorStructConversion);
}
