#include "lzma1_host.hpp"

#include <algorithm>
#include <cstdint>

namespace qiling::unpack::packers {

Lzma1Result lzma1_decode(const std::vector<uint8_t>& comp,
                                        uint32_t destLen, uint32_t lc,
                                        uint32_t lp, uint32_t pbv) {
    Lzma1Result R;
    const uint64_t nprobs = 0x736 + ((uint64_t)0x300 << (lc + lp));
    std::vector<uint16_t> pr(nprobs, 0x400);
    R.out.assign(destLen, 0);
    std::vector<uint8_t>& out = R.out;
    uint32_t range = 0xffffffffu, code = 0;
    uint64_t sp = 0;
    const uint64_t srcLen = comp.size();
    for (uint32_t k = 0; k < 5; ++k) {
        if (sp >= srcLen) return R;
        code = (code << 8) | comp[sp++];   // the standard rc init
    }
    auto rdbyte = [&](uint32_t& b) -> bool {
        if (sp >= srcLen) return false;
        b = comp[sp++];
        return true;
    };
    auto bitf = [&](uint32_t pi, int& bit) -> bool {
        uint32_t p = pr[pi];
        uint32_t bound = (range >> 11) * p;
        if (code < bound) {
            range = bound;
            pr[pi] = (uint16_t)(p + ((2048u - p) >> 5));
            bit = 0;
        } else {
            code -= bound;
            range -= bound;
            pr[pi] = (uint16_t)(p - (p >> 5));
            bit = 1;
        }
        if (range < (1u << 24)) {
            uint32_t nb;
            if (!rdbyte(nb)) return false;
            code = (code << 8) | nb;
            range <<= 8;
        }
        return true;
    };
    auto btf = [&](uint32_t pi, uint32_t bits, uint32_t& val) -> bool {
        uint32_t m = 1; int b;
        for (uint32_t i = 0; i < bits; ++i) {
            if (!bitf(pi + m, b)) return false;
            m = m * 2 + (uint32_t)b;
        }
        val = m - (1u << bits);
        return true;
    };
    auto btr = [&](uint32_t pi, uint32_t bits, uint32_t& val) -> bool {
        uint32_t m = 1; int b; val = 0;
        for (uint32_t i = 0; i < bits; ++i) {
            if (!bitf(pi + m, b)) return false;
            m = m * 2 + (uint32_t)b;
            val |= (uint32_t)b << i;
        }
        return true;
    };
    auto len_dec = [&](uint32_t lb, uint32_t ps, uint32_t& val) -> bool {
        int b;
        if (!bitf(lb, b)) return false;
        if (b == 0) {
            uint32_t v;
            if (!btf(lb + 2 + ps * 8, 3, v)) return false;
            val = v;
            return true;
        }
        if (!bitf(lb + 1, b)) return false;
        if (b == 0) {
            uint32_t v;
            if (!btf(lb + 0x82 + ps * 8, 3, v)) return false;
            val = v + 8;
        } else {
            uint32_t v;
            if (!btf(lb + 0x102, 8, v)) return false;
            val = v + 0x10;
        }
        return true;
    };
    bool bail = false;
    uint32_t state = 0, rep0 = 1, rep1 = 1, rep2 = 1, rep3 = 1;
    uint32_t prevbyte = 0, mflag = 0, len = 0;
    uint32_t lpMask = (1u << lp) - 1;
    const uint64_t guard_cap =
        std::max<uint64_t>(1ull << 30, 48ull * destLen);
    uint64_t guard = 0;
    uint32_t pos = 0;
    for (; pos < destLen;) {
        if (++guard > guard_cap) { bail = true; break; }
        uint32_t posState = pos & ((1u << pbv) - 1);
        int b;
        if (!bitf((state << 4) + posState, b)) { bail = true; break; }
        if (b == 0) {
            // ---- literal ----
            state = (state < 4) ? 0 :
                    (state < 10) ? (state - 3) : (state - 6);
            uint32_t litState =
                ((pos & lpMask) << lc) + (prevbyte >> (8 - lc));
            uint32_t litbase = 0x736 + litState * 0x300;
            uint32_t byte;
            if (mflag) {
                uint8_t mb = (pos >= rep0) ? out[pos - rep0] : 0;
                uint32_t mbi = mb >> 7;
                mb = (uint8_t)(mb << 1);
                if (!bitf(litbase + 0x101 + mbi * 0x100, b))
                    { bail = true; break; }
                uint32_t sym = 2u | (uint32_t)b;
                bool on = (b == (int)mbi);
                while (sym < 0x100 && on) {
                    uint32_t nb = mb >> 7;
                    mb = (uint8_t)(mb << 1);
                    if (!bitf(litbase + (nb + 1) * 0x100 + sym, b))
                        { bail = true; break; }
                    sym = sym * 2 + (uint32_t)b;
                    if (b != (int)nb) on = false;
                }
                if (bail) break;
                while (sym < 0x100) {
                    if (!bitf(litbase + sym, b))
                        { bail = true; break; }
                    sym = sym * 2 + (uint32_t)b;
                }
                if (bail) break;
                byte = sym & 0xffu;
                mflag = 0;
            } else {
                uint32_t m = 1;
                while (m < 0x100) {
                    if (!bitf(litbase + m, b))
                        { bail = true; break; }
                    m = m * 2 + (uint32_t)b;
                }
                if (bail) break;
                byte = m & 0xffu;
            }
            out[pos] = (uint8_t)byte;
            prevbyte = byte;
            ++pos;
            continue;
        }
        // ---- match ----
        mflag = 1;
        if (!bitf(state + 0xc0, b)) { bail = true; break; }
        if (b == 0) {
            rep3 = rep2; rep2 = rep1; rep1 = rep0;
            state = (state >= 7) ? 10 : 7;
            if (!len_dec(0x332, posState, len)) { bail = true; break; }
            uint32_t slot = (len < 4) ? len : 3;
            uint32_t slotv = 0;
            if (!btf(0x1b0 + slot * 0x40, 6, slotv))
                { bail = true; break; }
            uint32_t d;
            if (slotv < 4) {
                d = slotv;
            } else {
                d = (2u | (slotv & 1)) << ((slotv >> 1) - 1);
                if (slotv < 0xe) {
                    uint32_t rv;
                    if (!btr(0x2af + (d - slotv), (slotv >> 1) - 1, rv))
                        { bail = true; break; }
                    d += rv;
                } else {
                    uint32_t nb = (slotv >> 1) - 5;
                    if (nb > 32) { bail = true; break; }
                    uint32_t d4 = 0;
                    for (uint32_t k = 0; k < nb; ++k) {
                        range >>= 1;
                        if (code >= range) {
                            code -= range;
                            d4 = (d4 << 1) | 1u;
                        } else {
                            d4 <<= 1;
                        }
                        if (range < (1u << 24)) {
                            uint32_t nb2;
                            if (!rdbyte(nb2)) { bail = true; break; }
                            code = (code << 8) | nb2;
                            range <<= 8;
                        }
                    }
                    if (bail) break;
                    d += d4 << 4;
                    uint32_t av;
                    if (!btr(0x322, 4, av)) { bail = true; break; }
                    d += av;
                }
            }
            rep0 = d + 1;
        } else {
            if (!bitf(state + 0xcc, b)) { bail = true; break; }
            if (b == 0) {
                if (!bitf((state << 4) + 0xf0 + posState, b))
                    { bail = true; break; }
                if (b == 0) {
                    // shortrep: one byte (the state >= 7 path)
                    uint8_t bb = (pos >= rep0) ? out[pos - rep0] : 0;
                    state = (state >= 7) ? 11 : 9;
                    out[pos] = bb;
                    prevbyte = bb;
                    ++pos;
                    continue;
                }
                if (!len_dec(0x534, posState, len))
                    { bail = true; break; }
                state = (state >= 7) ? 11 : 8;
            } else {
                uint32_t d;
                if (!bitf(state + 0xd8, b)) { bail = true; break; }
                if (b == 0) {
                    d = rep1;
                    rep1 = rep0;
                } else {
                    if (!bitf(state + 0xe4, b)) { bail = true; break; }
                    d = (b == 0) ? rep2 : rep3;
                    if (b != 0) rep3 = rep2;
                    rep2 = rep1;
                    rep1 = rep0;
                }
                rep0 = d;
                if (!len_dec(0x534, posState, len))
                    { bail = true; break; }
                state = (state >= 7) ? 11 : 8;
            }
        }
        // ---- the byte copy (sequential; the LZMA dictionary head below
        // the current pos reads as zeros -- dist > pos is legal; for
        // k >= rep0 the source is this match's own earlier output) -----
        uint32_t n2 = len + 2;
        if (n2 > destLen - pos) n2 = destLen - pos;
        if (n2 == 0) { bail = true; break; }
        for (uint32_t k = 0; k < n2; ++k) {
            int64_t s = (int64_t)pos + k - rep0;
            out[pos + k] = (s >= 0) ? out[s] : 0;
        }
        prevbyte = out[pos + n2 - 1];
        pos += n2;
    }
    R.pos = pos; R.len = len; R.rep0 = rep0; R.state = state;
    R.mflag = mflag; R.prevbyte = prevbyte; R.consumed = sp;
    if (bail || pos < destLen) return R;
    R.ok = true;
    return R;
}

}  // namespace qiling::unpack::packers
