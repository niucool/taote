// Ported from qiling/core_struct.py — structure packing and unpacking for
// different architecture bits. Part of the core.py Qiling class (mixed in);
// the C++ port keeps it a standalone component the composition root aggregates
// (core.py: `class Qiling(QlCoreHooks, QlCoreStructs)`).
//
// struct.pack returns fresh bytes; the C++ port returns std::string (SSO covers
// every packed width, so no heap traffic).
#ifndef QILING_CORE_STRUCT_HPP
#define QILING_CORE_STRUCT_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "qiling/const.hpp"
#include "qiling/exception.hpp"

namespace qiling {

// Don't assume self is Qiling (core_struct.py, verbatim).
class QlCoreStructs {
public:
    // core_struct.py builds struct.Struct('{modifier}B|b|H|h|I|i|Q|q') per
    // width/sign; the C++ port packs/unpacks with explicit endianness and
    // validates ranges, degrading to QlErrorStructConversion where
    // struct.pack/unpack would raise struct.error (documented deviation).
    QlCoreStructs(QL_ENDIAN endian, int bit);

    // deferred-init for the composition root (mirrors the Python
    // QlCoreStructs.__init__(self, endian, bits) mid-construction call)
    QlCoreStructs() = default;
    void init(QL_ENDIAN endian, int bit);

    // bit-selected accessors (core_struct.py handlers table): pack / packs /
    // unpack / unpacks for the architecture word size
    std::string pack(std::uint64_t x) const { return (this->*pack_)(x); }
    std::string packs(std::int64_t x) const { return (this->*packs_)(x); }
    std::uint64_t unpack(std::string_view data) const { return (this->*unpack_)(data); }
    std::int64_t unpacks(std::string_view data) const { return (this->*unpacks_)(data); }

    // per-width pack/unpack (verbatim method set from core_struct.py; the
    // endianness is the construction value, like the bound struct.Struct)
    std::string pack64(std::uint64_t x) const;
    std::string pack64s(std::int64_t x) const;
    std::uint64_t unpack64(std::string_view x) const;
    std::int64_t unpack64s(std::string_view x) const;

    std::string pack32(std::uint64_t x) const;
    std::string pack32s(std::int64_t x) const;
    std::uint64_t unpack32(std::string_view x) const;
    std::int64_t unpack32s(std::string_view x) const;

    std::string pack16(std::uint64_t x) const;
    std::string pack16s(std::int64_t x) const;
    std::uint64_t unpack16(std::string_view x) const;
    std::int64_t unpack16s(std::string_view x) const;

    std::string pack8(std::uint64_t x) const;
    std::string pack8s(std::int64_t x) const;
    std::uint64_t unpack8(std::string_view x) const;
    std::int64_t unpack8s(std::string_view x) const;

private:
    using PackFn = std::string (QlCoreStructs::*)(std::uint64_t) const;
    using PackSFn = std::string (QlCoreStructs::*)(std::int64_t) const;
    using UnpackFn = std::uint64_t (QlCoreStructs::*)(std::string_view) const;
    using UnpackSFn = std::int64_t (QlCoreStructs::*)(std::string_view) const;

    bool big_endian_ = false;

    PackFn pack_ = nullptr;
    PackSFn packs_ = nullptr;
    UnpackFn unpack_ = nullptr;
    UnpackSFn unpacks_ = nullptr;
};

}  // namespace qiling

#endif  // QILING_CORE_STRUCT_HPP
