// ASPack (2.x) host-side codec -- see aspack_unpacker.h.  This is a
// semantic transcription of the stub decoder at (.aspack+0x6c8):
//
//   bit source   : 32-bit window over big-endian bytes; `c` counts the
//                  consumed bits (init 0x20 so the first 4 refills purge
//                  the uninitialized window).  The 24-bit code field is
//                  F = (buf >> (8 - c)) & 0xFFFFFF; getbits(n) takes its
//                  top n bits and adds n to c; refill shifts a byte in at
//                  the bottom while c >= 8 and subtracts 8.
//   models       : canonical Huffman rendered as cumulative base values
//                  on the 2^24 axis (base[0..15], base[0]=0) plus class
//                  counts (cbase) plus a 256-entry prefix->length fast
//                  table (lengths <= 8).  Decode: F&0xFFFE00 vs the base
//                  ladder picks the length L, then
//                  idx = ((F - base[L-1]) >> (24-L)) + cbase[L].
//                  A build FAILS unless the code is exactly complete
//                  (cumulative == 2^24, never exceeding mid-run).
//   block header : bit 0 -> drop the previous block's lengths; then 19
//                  4-bit CL lengths whose Huffman drives the 757-entry
//                  lens program: sym<0x10: delta to the previous block's
//                  length (&0xF); 0x10: repeat last length (2 bits + 3);
//                  0x11: zeros (3 bits + 3); >=0x12: zeros (7 bits + 11).
//                  Then the lit/len (0x2D1), match-extra (0x1C) and
//                  distance-top (8) models are built over the three
//                  lens spans, and the uniform-distance-top flag is
//                  latched (all-3 lengths).
//   main loop    : symbol < 0x100 -> literal; 0x100..0x2CF -> match with
//                  length ((sym&7)+2 [+ extra table lookup on 7]) and a
//                  distance from the 58-slot table (raw bits, or the
//                  distance-top model for the high bits when the flag is
//                  set and the slot has >= 3 bits); distances < 3 are
//                  rep indices (with the rep[0] swap); symbol 0x2D0
//                  refreshes the models; the loop ends when the output
//                  reaches the section's declared size.
#include "aspack_host.hpp"

#include <cstring>
#include <stdexcept>

namespace qiling::unpack::packers {

namespace {

struct DecFail {};

struct BitReader {
    const uint8_t* src;
    size_t pos = 0;
    size_t limit = 0;
    uint32_t buf = 0;
    int c = 0x20;

    void refill() {
        while (c >= 8) {
            if (pos >= limit) throw DecFail{};
            buf = (buf << 8) | src[pos++];
            c -= 8;
        }
    }
    // The 24-bit top-aligned field F.
    uint32_t peek24() {
        refill();
        return (buf >> (8 - c)) & 0xFFFFFFu;
    }
    uint32_t getbits(int n) {
        refill();
        uint32_t v = ((buf >> (8 - c)) & 0xFFFFFFu) >> (24 - n);
        c += n;
        return v;
    }
};

struct Model {
    uint32_t base[16];    // builder level ladder; decode reads base[L-1]
    uint32_t cbase[16];
    uint8_t fast[256];
    std::vector<uint32_t> symtab;
};

// Canonical-Huffman table build; returns false exactly where the stub's
// builder returns al=0 (over-subscription mid-ladder, or an incomplete
// final code).
bool build_model(const uint8_t* lens, size_t n, Model& m) {
    uint32_t cnt[16] = {};
    for (size_t k = 0; k < n; k++) {
        uint32_t L = lens[k];
        if (L > 15) throw DecFail{};  // native would index past the table
        cnt[L]++;
    }
    cnt[0] = 0;
    uint32_t edi = 0;
    int shift = 0x17;
    uint32_t prev_hi = 0;
    std::memset(m.fast, 0, sizeof(m.fast));
    m.base[0] = 0;
    m.cbase[0] = 0;
    for (int L = 1; L <= 15; L++, shift--) {
        edi += cnt[L] << shift;
        if (edi > 0x1000000u) return false;
        m.base[L] = edi;
        m.cbase[L] = m.cbase[L - 1] + cnt[L - 1];
        if (shift >= 16) {  // L <= 8: the prefix fast-table span
            uint32_t hi = edi >> 16;
            if (hi < prev_hi || hi > 256) throw DecFail{};
            if (hi > prev_hi) std::memset(m.fast + prev_hi, L, hi - prev_hi);
            prev_hi = hi;
        }
    }
    if (edi != 0x1000000u) return false;
    m.symtab.assign(n, 0);
    uint32_t cur[16];
    std::memcpy(cur, m.cbase, sizeof(cur));
    for (size_t k = 0; k < n; k++) {
        uint32_t L = lens[k];
        if (L) {
            if (cur[L] >= n) throw DecFail{};
            m.symtab[cur[L]++] = (uint32_t)k;
        }
    }
    return true;
}

uint32_t decode_sym(BitReader& bs, const Model& m) {
    uint32_t F = bs.peek24() & 0xFFFE00u;
    int L;
    if (F < m.base[8]) {
        L = m.fast[F >> 16];
        if (L <= 0 || L > 8) throw DecFail{};
    } else if (F < m.base[10]) {
        L = (F < m.base[9]) ? 9 : 10;
    } else if (F < m.base[11]) {
        L = 11;
    } else if (F < m.base[12]) {
        L = 12;
    } else if (F < m.base[13]) {
        L = 13;
    } else {
        L = (F < m.base[14]) ? 14 : 15;
    }
    bs.c += L;
    uint32_t idx = ((F - m.base[L - 1]) >> (24 - L)) + m.cbase[L];
    if (idx >= m.symtab.size()) throw DecFail{};
    return m.symtab[idx];
}

struct DecodeState {
    uint8_t prev[0x2F5];       // previous block's lengths (delta source)
    int flag264 = 0;           // distance-top model is non-uniform
    Model m_lit, m_extra, m_dist;
    bool have_lit = false, have_extra = false, have_dist = false;
};

// The block header reader; false where the stub would bail (al=0).
bool read_block_header(BitReader& bs, DecodeState& st) {
    if (bs.getbits(1) == 0) std::memset(st.prev, 0, sizeof(st.prev));
    uint8_t cl[19];
    for (int i = 0; i < 19; i++) cl[i] = (uint8_t)bs.getbits(4);
    Model clm;
    if (!build_model(cl, 19, clm)) return false;
    uint8_t lens[0x2F5];
    std::memset(lens, 0, sizeof(lens));
    uint32_t i = 0;
    while (i < 0x2F5) {
        uint32_t s = decode_sym(bs, clm);
        if (s < 0x10) {
            lens[i] = (uint8_t)((st.prev[i] + s) & 0xF);
            i++;
        } else if (s == 0x10) {
            int r = (int)bs.getbits(2) + 3;
            if (i == 0) throw DecFail{};  // native reads stale stack here
            uint8_t b = lens[i - 1];
            while (r-- > 0 && i < 0x2F5) lens[i++] = b;
        } else if (s == 0x11) {
            int r = (int)bs.getbits(3) + 3;
            while (r-- > 0 && i < 0x2F5) lens[i++] = 0;
        } else {
            int r = (int)bs.getbits(7) + 0xB;
            while (r-- > 0 && i < 0x2F5) lens[i++] = 0;
        }
    }
    if (!build_model(lens + 0x000, 0x2D1, st.m_lit)) return false;
    if (!build_model(lens + 0x2D1, 0x01C, st.m_extra)) return false;
    if (!build_model(lens + 0x2ED, 0x008, st.m_dist)) return false;
    st.have_lit = st.have_extra = st.have_dist = true;
    st.flag264 = 0;
    for (int k = 0; k < 8; k++)
        if (lens[0x2ED + k] != 3) { st.flag264 = 1; break; }
    std::memcpy(st.prev, lens, sizeof(lens));
    return true;
}

} // namespace

AspackDecodeResult aspack_decode_section(const uint8_t* src, size_t src_avail,
                                         uint32_t out_size,
                                         const AspackSlotTables& tabs,
                                         uint8_t* out, size_t out_cap) {
    AspackDecodeResult res;
    if (!src || !out) return res;
    if ((uint64_t)out_size + 0x120ull > out_cap) return res;
    try {
        BitReader bs;
        bs.src = src; bs.pos = 0; bs.limit = src_avail;
        uint32_t T58[58];
        uint32_t acc = 0;
        for (int j = 0; j < 58; j++) {
            T58[j] = acc;
            acc += 1u << tabs.dist_bits[j];
        }
        DecodeState st;
        std::memset(st.prev, 0, sizeof(st.prev));
        if (!read_block_header(bs, st)) return res;
        uint32_t rep[4] = {0, 0, 0, 0};
        uint32_t total = 0;
        uint64_t guard = 0;
        const uint64_t guard_cap =
            std::max<uint64_t>(1ull << 26, 8ull * (uint64_t)out_size + (1ull << 20));
        for (;;) {
            if (++guard > guard_cap) throw DecFail{};
            uint32_t sym = decode_sym(bs, st.m_lit);
            if (sym < 0x100) {
                if (total >= out_cap) throw DecFail{};
                out[total++] = (uint8_t)sym;
            } else if (sym < 0x2D0) {
                uint32_t ls = sym - 0x100;
                uint32_t lenclass = ls >> 3;
                if (lenclass >= 58) throw DecFail{};
                uint32_t mlen = (ls & 7) + 2;
                if ((ls & 7) == 7) {
                    uint32_t extra = decode_sym(bs, st.m_extra);
                    if (extra > 27) throw DecFail{};
                    mlen += tabs.extra_base[extra] +
                            bs.getbits(tabs.extra_bits[extra]);
                }
                uint32_t dbase = T58[lenclass];
                uint32_t dbits = tabs.dist_bits[lenclass];
                uint32_t d;
                if (st.flag264 && dbits >= 3) {
                    uint32_t low = bs.getbits((int)dbits - 3);
                    uint32_t top = decode_sym(bs, st.m_dist);
                    if (top > 7) throw DecFail{};
                    d = dbase + top + low * 8;
                } else {
                    d = dbase + bs.getbits((int)dbits);
                }
                uint32_t ecx;
                if (d < 3) {
                    ecx = rep[d];
                    if (d) {
                        rep[d] = rep[0];
                        rep[0] = ecx;
                    }
                } else {
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = d - 3;
                    ecx = d - 3;
                }
                uint32_t dist = ecx + 1;
                if (dist > total) throw DecFail{};
                if ((uint64_t)total + mlen > out_cap) throw DecFail{};
                uint32_t srcp = total - dist;
                if (dist >= mlen) {
                    std::memcpy(out + total, out + srcp, mlen);
                } else {
                    for (uint32_t k = 0; k < mlen; k++)
                        out[total + k] = out[srcp + k];
                }
                total += mlen;
            } else {
                if (!read_block_header(bs, st)) return res;
            }
            if (total >= out_size) break;
        }
        res.ok = true;
        res.total = total;
        res.consumed = (uint32_t)bs.pos;
        return res;
    } catch (...) {
        return AspackDecodeResult{};
    }
}

void aspack_e8e9_unfilter(uint8_t* buf, uint32_t total, bool guarded,
                          uint8_t tag, bool only_e8) {
    // ecx/ebx/esi arithmetic exactly as the stub loop (0x16e611f..):
    // int32 counter starting at total-5, loop exits on ==0 or sign (the
    // guest's `or ecx,ecx / je / js`).  Position accounting: a plain
    // byte advances ebx by 1, a transformed site by 5.
    int32_t ecx = (int32_t)total - 5;
    uint32_t ebx = 0;  // byte position of the candidate opcode
    uint32_t esi = 0;  // scan cursor
    for (;;) {
        if (ecx == 0 || ecx < 0) break;
        uint8_t al = buf[esi++];
        // only_e8: the `jmp rel8` at S+0x12B skips the `cmp al,0xe9 / je`
        // pair, so an 0xE9 byte falls through to the plain-byte path
        // (esi already advanced past it, ebx += 1, ecx -= 1).
        if (al == 0xE8 || (al == 0xE9 && !only_e8)) {
            uint32_t v = (uint32_t)buf[esi] | ((uint32_t)buf[esi + 1] << 8) |
                         ((uint32_t)buf[esi + 2] << 16) |
                         ((uint32_t)buf[esi + 3] << 24);
            if (guarded && buf[esi] != tag) {
                // not a marked site: the opcode counts as a plain byte
                // and the scan continues inside the stored dword
                ebx += 1;
                ecx -= 1;
                continue;
            }
            if (guarded) {
                v &= 0xFFFFFF00u;
                v = (v << 24) | (v >> 8);  // rol eax, 0x18
            }
            v -= ebx;
            buf[esi] = (uint8_t)v;
            buf[esi + 1] = (uint8_t)(v >> 8);
            buf[esi + 2] = (uint8_t)(v >> 16);
            buf[esi + 3] = (uint8_t)(v >> 24);
            ebx += 5;
            esi += 4;
            ecx -= 5;
        } else {
            ebx += 1;
            ecx -= 1;
        }
    }
}

} // namespace pegasus
