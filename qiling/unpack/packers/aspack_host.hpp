// ASPack (2.x) host-side codec: a pure re-implementation of the stub's
// per-section decompressor (dynamic canonical Huffman over a big-endian
// bit window, LZ77 with rep distances and length/distance slot tables)
// plus the post-decode E8/E9 call/jmp transform.  Discovered against
// aspack_WinSCP.exe / aspack_ADInsight.exe and validated byte-exact
// against the emulator's own decode (every decoded section matches the
// native run's guest dump byte-for-byte) -- see STATUS.md (449+).
//
// The codec is guest-free: no emulator types, no side effects.  The
// caller (UniversalUnpacker::install_aspack_hostdec_) feeds the packed
// section stream and publishes the result into guest memory.
#pragma once
// Ported verbatim from pegasus src/unpacker/packers/aspack_unpacker.h (see
// aspack_stub_sig.hpp for the engage). Guest-free: no emulator types.

#include <cstdint>
#include <cstddef>
#include <vector>

#include "aspack_stub_sig.hpp"

namespace qiling::unpack::packers {

// The three slot tables the embed in the stub body ([S+0x732], [S+0x74e],
// [S+0x76a] relative to the .aspack section start).  They are part of the
// engage signature, so on a verified engage they are these exact
// constants; they are carried explicitly so the codec stays honest.
struct AspackSlotTables {
    uint8_t extra_base[28];  // match-length extra: base value per symbol
    uint8_t extra_bits[28];  // match-length extra: extra-bit count
    uint8_t dist_bits[58];   // distance slot bit counts
};

struct AspackDecodeResult {
    bool ok = false;
    uint32_t total = 0;      // bytes produced (== out_size on valid packs)
    uint32_t consumed = 0;   // source bytes consumed by the bit reader
};

// Decode one packed section.  `src` holds src_avail readable bytes (the
// mapped section content); `out_cap` must be >= out_size + 0x120 (the
// stub decodes into a scratch of size + 0x10e and a match may legally
// stride a few bytes past out_size before the length check lands -- on
// valid streams total == out_size exactly).
AspackDecodeResult aspack_decode_section(const uint8_t* src, size_t src_avail,
                                         uint32_t out_size,
                                         const AspackSlotTables& tabs,
                                         uint8_t* out, size_t out_cap);

// The post-decode call/jmp transform, exactly the stub's semantics over the
// decoded buffer (the first decoded section only -- the stub arm-twists its
// own `mov bl,0` one-shot gate).  The packer patches three things into the
// stub that select the flavour, and all three are read from the stub bytes:
//   guarded/tag (S+0x137 / S+0x13A)
//     unguarded       : rel32' = stored - pos          (every e8 and e9)
//     guarded (tag t) : only sites whose stored low byte == t qualify,
//                       rel32' = ((stored & ~0xff) << 24 | >> 8) - pos
//                       (the stub's `and al,0 ; rol eax,0x18`)
//   only_e8 (S+0x12B == 0x04)
//     the filter body's `jmp rel8` skips the `cmp al,0xe9 / je` pair, so
//     only 0xE8 sites are transformed and an 0xE9 byte is an ordinary byte.
void aspack_e8e9_unfilter(uint8_t* buf, uint32_t total, bool guarded,
                          uint8_t tag, bool only_e8 = false);

} // namespace pegasus
