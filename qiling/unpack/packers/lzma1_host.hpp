#pragma once
// Shared LZMA1 host decoder (ported from pegasus src/unpacker/packers/lzma1_host).
//
// Both families this serves drive a *textbook* LZMA1 range coder with a
// runtime-derived entry point, so the transcription is one body of code with
// two frame derivations -- not two codecs:
//   * NSPack's materialised stage-2 decoder (page 0x8000, block entry 0x85a9)
//     initialises its models with `mov eax,0x4000400; rep stosd` + `rep stosw`
//     over `0x736 + (0x300 << (lc+lp))` bytes, shifts range by 11 for the
//     probability bound, adapts with `prob += (2048-prob)>>5` / `prob -= prob>>5`
//     and indexes isMatch as `(state<<4) + posState` (pb=4) -- i.e. exactly the
//     body below, with lc/lp/pb read from its own header byte;
//   * WinUpack's descriptor (+0x24 OEP, two in-image streams) uses the same
//     coder (STATUS 463/461 measured the same 11-bit bound and 5-bit adaptation).
//
// The body was extracted verbatim from the UPX LZMA (method 14) accelerator so
// that accelerator keeps its measured behaviour; callers differ only in how they
// derive (comp, destLen, lc, lp, pb) and what they do with the result.
#include <cstdint>
#include <vector>

namespace qiling::unpack::packers {

struct Lzma1Result {
    bool ok = false;
    std::vector<uint8_t> out;
    uint32_t pos = 0, len = 0, rep0 = 1, state = 0, mflag = 0, prevbyte = 0;
    uint64_t consumed = 0;
};

// Decode one LZMA1 stream.  `ok` is false when the stream ends early or the
// guard trips; the partial result is still returned (pos/consumed describe where
// it stopped), which is what a diagnostic wants.
Lzma1Result lzma1_decode(const std::vector<uint8_t>& comp, uint32_t destLen,
                         uint32_t lc, uint32_t lp, uint32_t pbv);

}  // namespace qiling::unpack::packers
