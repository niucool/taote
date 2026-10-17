#include "qiling/core_struct.hpp"

#include <cstring>
#include <limits>

namespace qiling {

namespace {

// endianness of the host, for the byteswap decision (C++17: no std::endian)
bool host_is_big_endian() noexcept {
#if defined(_WIN32) || (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    return false;
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return true;
#else
    const std::uint16_t probe = 1;
    return *reinterpret_cast<const std::uint8_t*>(&probe) == 0;
#endif
}

std::uint16_t bswap16(std::uint16_t v) noexcept { return static_cast<std::uint16_t>((v << 8) | (v >> 8)); }

std::uint32_t bswap32(std::uint32_t v) noexcept {
    return ((v & 0x000000ffull) << 24) | ((v & 0x0000ff00ull) << 8) | ((v & 0x00ff0000ull) >> 8) |
           ((v & 0xff000000ull) >> 24);
}

std::uint64_t bswap64(std::uint64_t v) noexcept {
    return (static_cast<std::uint64_t>(bswap32(static_cast<std::uint32_t>(v))) << 32) |
           bswap32(static_cast<std::uint32_t>(v >> 32));
}

template <typename T>
T byteswap(T v) noexcept;

template <>
std::uint16_t byteswap<std::uint16_t>(std::uint16_t v) noexcept { return bswap16(v); }
template <>
std::uint32_t byteswap<std::uint32_t>(std::uint32_t v) noexcept { return bswap32(v); }
template <>
std::uint64_t byteswap<std::uint64_t>(std::uint64_t v) noexcept { return bswap64(v); }
template <>
std::int16_t byteswap<std::int16_t>(std::int16_t v) noexcept { return bswap16(static_cast<std::uint16_t>(v)); }
template <>
std::int32_t byteswap<std::int32_t>(std::int32_t v) noexcept { return bswap32(static_cast<std::uint32_t>(v)); }
template <>
std::int64_t byteswap<std::int64_t>(std::int64_t v) noexcept { return bswap64(static_cast<std::uint64_t>(v)); }
template <>
std::uint8_t byteswap<std::uint8_t>(std::uint8_t v) noexcept { return v; }
template <>
std::int8_t byteswap<std::int8_t>(std::int8_t v) noexcept { return v; }

template <typename T>
std::string pack_width(bool big_endian, T value) {
    T out = value;
    if (big_endian != host_is_big_endian()) out = byteswap(out);
    return std::string(reinterpret_cast<const char*>(&out), sizeof(T));
}

template <typename T>
T unpack_width(bool big_endian, std::string_view data) {
    if (data.size() != sizeof(T)) {
        throw QlErrorStructConversion("unpack size mismatch");
    }
    T out = 0;
    std::memcpy(&out, data.data(), sizeof(T));
    if (big_endian != host_is_big_endian()) out = byteswap(out);
    return out;
}

template <typename T>
void check_signed_range(std::int64_t x) {
    // struct.pack raises struct.error on out-of-range values; the C++ port
    // degrades to the framework exception (documented in STATUS.md).
    if (x < static_cast<std::int64_t>(std::numeric_limits<T>::min()) ||
        x > static_cast<std::int64_t>(std::numeric_limits<T>::max())) {
        throw QlErrorStructConversion("value out of range");
    }
}

}  // namespace

QlCoreStructs::QlCoreStructs(QL_ENDIAN endian, int bit) : big_endian_(endian == QL_ENDIAN::EB) {
    // core_struct.py handlers table: the bit-width selected pack / packs /
    // unpack / unpacks bindings
    switch (bit) {
        case 64:
            pack_ = &QlCoreStructs::pack64;
            packs_ = &QlCoreStructs::pack64s;
            unpack_ = &QlCoreStructs::unpack64;
            unpacks_ = &QlCoreStructs::unpack64s;
            break;
        case 32:
            pack_ = &QlCoreStructs::pack32;
            packs_ = &QlCoreStructs::pack32s;
            unpack_ = &QlCoreStructs::unpack32;
            unpacks_ = &QlCoreStructs::unpack32s;
            break;
        case 16:
            pack_ = &QlCoreStructs::pack16;
            packs_ = &QlCoreStructs::pack16s;
            unpack_ = &QlCoreStructs::unpack16;
            unpacks_ = &QlCoreStructs::unpack16s;
            break;
        default:
            throw QlErrorStructConversion("Unsupported Qiling struct conversion");
    }
}

// ---- 64 ----

std::string QlCoreStructs::pack64(std::uint64_t x) const { return pack_width<std::uint64_t>(big_endian_, x); }

std::string QlCoreStructs::pack64s(std::int64_t x) const { return pack_width<std::int64_t>(big_endian_, x); }

std::uint64_t QlCoreStructs::unpack64(std::string_view x) const { return unpack_width<std::uint64_t>(big_endian_, x); }

std::int64_t QlCoreStructs::unpack64s(std::string_view x) const { return unpack_width<std::int64_t>(big_endian_, x); }

// ---- 32 ----

std::string QlCoreStructs::pack32(std::uint64_t x) const {
    if (x > std::numeric_limits<std::uint32_t>::max()) {
        throw QlErrorStructConversion("value out of range");
    }
    return pack_width<std::uint32_t>(big_endian_, static_cast<std::uint32_t>(x));
}

std::string QlCoreStructs::pack32s(std::int64_t x) const {
    check_signed_range<std::int32_t>(x);
    return pack_width<std::int32_t>(big_endian_, static_cast<std::int32_t>(x));
}

std::uint64_t QlCoreStructs::unpack32(std::string_view x) const { return unpack_width<std::uint32_t>(big_endian_, x); }

std::int64_t QlCoreStructs::unpack32s(std::string_view x) const { return unpack_width<std::int32_t>(big_endian_, x); }

// ---- 16 ----

std::string QlCoreStructs::pack16(std::uint64_t x) const {
    if (x > std::numeric_limits<std::uint16_t>::max()) {
        throw QlErrorStructConversion("value out of range");
    }
    return pack_width<std::uint16_t>(big_endian_, static_cast<std::uint16_t>(x));
}

std::string QlCoreStructs::pack16s(std::int64_t x) const {
    check_signed_range<std::int16_t>(x);
    return pack_width<std::int16_t>(big_endian_, static_cast<std::int16_t>(x));
}

std::uint64_t QlCoreStructs::unpack16(std::string_view x) const { return unpack_width<std::uint16_t>(big_endian_, x); }

std::int64_t QlCoreStructs::unpack16s(std::string_view x) const { return unpack_width<std::int16_t>(big_endian_, x); }

// ---- 8 ----

std::string QlCoreStructs::pack8(std::uint64_t x) const {
    if (x > std::numeric_limits<std::uint8_t>::max()) {
        throw QlErrorStructConversion("value out of range");
    }
    return pack_width<std::uint8_t>(big_endian_, static_cast<std::uint8_t>(x));
}

std::string QlCoreStructs::pack8s(std::int64_t x) const {
    check_signed_range<std::int8_t>(x);
    return pack_width<std::int8_t>(big_endian_, static_cast<std::int8_t>(x));
}

std::uint64_t QlCoreStructs::unpack8(std::string_view x) const { return unpack_width<std::uint8_t>(big_endian_, x); }

std::int64_t QlCoreStructs::unpack8s(std::string_view x) const { return unpack_width<std::int8_t>(big_endian_, x); }

}  // namespace qiling
