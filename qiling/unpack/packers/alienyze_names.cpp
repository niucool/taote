// qiling/unpack/packers/alienyze_names.cpp — see alienyze_names.hpp.
#include "qiling/unpack/packers/alienyze_names.hpp"

#include <algorithm>
#include <cstddef>
#include <set>
#include <cstdio>
#include <cstdlib>

namespace qiling {
namespace unpack {
namespace alienyze {

namespace {

// The band's key is per-sample, so detect it: the transformation that makes the
// most ".dll\0" tokens appear inside the image is the band's XOR byte. Four hits
// is pegasus's cap (b3e412a8) - enough to tell a real band from a coincidence.
std::uint8_t detect_key(const std::uint8_t* img, std::size_t n, int& hits_out) {
    // One pass instead of 255: a ".dll\0" token under key k means
    // img[i] == '.'^k, so k is DETERMINED by the first byte and the rest is a
    // 4-byte check. The histogram makes the scan O(n) instead of O(255n)
    // (measured: the naive form cost 0.34 s/row on the Alienyze corpus).
    int hist[256] = {0};
    for (std::size_t i = 0; i + 5 <= n; ++i) {
        const std::uint8_t k = static_cast<std::uint8_t>(img[i] ^ '.');
        if (k == 0) {
            continue;
        }
        if (img[i + 1] == static_cast<std::uint8_t>('d' ^ k) &&
            img[i + 2] == static_cast<std::uint8_t>('l' ^ k) &&
            img[i + 3] == static_cast<std::uint8_t>('l' ^ k) &&
            img[i + 4] == static_cast<std::uint8_t>(0 ^ k)) {
            if (hist[k] < 4) {  // pegasus's cap: four hits is a band, not luck
                ++hist[k];
            }
        }
    }
    std::uint8_t best = 0;
    int best_hits = 0;
    for (int k = 1; k < 256; ++k) {
        if (hist[k] > best_hits) {
            best_hits = hist[k];
            best = static_cast<std::uint8_t>(k);
        }
    }
    hits_out = best_hits;
    return best;
}

bool is_stem_char(std::uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

// "kernel32" owns "kernel32.dll"'s names; the api_db stems carry no extension
bool stem_matches(const std::string& token, const std::string& owner) {
    if (token == owner) {
        return true;
    }
    return token.size() < owner.size() ? owner.compare(0, token.size(), token) == 0
                                       : token.compare(0, owner.size(), owner) == 0;
}

}  // namespace

MinedNames mine_name_band(const std::uint8_t* img, std::size_t n,
                          std::vector<std::string> (*owner_lookup)(const std::string&)) {
    MinedNames out;
    if (img == nullptr || n < 0x8000 || owner_lookup == nullptr) {
        return out;
    }
    out.key = detect_key(img, n, out.key_hits);
    if (out.key == 0 || out.key_hits == 0) {
        return out;
    }
    const std::uint8_t key = out.key;
    std::vector<std::uint8_t> dx(n);
    for (std::size_t i = 0; i < n; ++i) {
        dx[i] = static_cast<std::uint8_t>(img[i] ^ key);
    }

    // ---- the DLL tokens: a "<stem>.dll" ASCII run, stored in group order ----
    struct Tok {
        std::size_t pos;
        std::string stem;
    };
    std::vector<Tok> toks;
    for (std::size_t o = 0; o + 5 < n; ++o) {
        if (!(dx[o] == '.' && (dx[o + 1] | 32) == 'd' && (dx[o + 2] | 32) == 'l' &&
              (dx[o + 3] | 32) == 'l')) {
            continue;
        }
        std::size_t s = o;
        while (s > 0 && is_stem_char(dx[s - 1])) {
            --s;
        }
        if (s == o) {
            continue;
        }
        std::string stem(reinterpret_cast<const char*>(&dx[s]), o - s);
        for (auto& c : stem) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (stem.size() >= 2 && stem.size() <= 24) {
            toks.push_back({o, stem});
        }
        o += 3;
    }
    if (toks.empty()) {
        return out;
    }

    // ---- bands: zero runs of 16+ bytes separate the store from junk zones ----
    struct Band {
        std::size_t a, b;
    };
    std::vector<Band> bands;
    {
        std::size_t s = 0;
        for (std::size_t o = 0; o < n;) {
            if (dx[o] != 0) {
                ++o;
                continue;
            }
            std::size_t z = o;
            while (z < n && dx[z] == 0) {
                ++z;
            }
            if (z - o >= 16) {
                if (s < o) {
                    bands.push_back({s, o});
                }
                s = z;
            }
            o = z;
        }
        if (s < n) {
            bands.push_back({s, n});
        }
    }

    // ---- the forward-greedy cut ----
    std::set<std::pair<std::string, std::string>> mined;
    for (const auto& bd : bands) {
        std::vector<std::string> btok;
        bool near_tok = false;
        for (const auto& t : toks) {
            if (t.pos + 64 >= bd.a && t.pos <= bd.b + 64) {
                near_tok = true;
            }
            if (t.pos >= bd.a && t.pos <= bd.b + 128) {
                btok.push_back(t.stem);
            }
        }
        if (!near_tok || btok.empty()) {
            continue;
        }
        std::size_t tok_idx = 0;
        for (std::size_t o = bd.a; o + 6 < bd.b;) {
            std::size_t e = o;
            while (e < bd.b && dx[e] >= 0x20 && dx[e] <= 0x7e) {
                ++e;
            }
            const std::size_t len = e - o;
            if (len >= 4 && len <= 64) {
                std::string fn(reinterpret_cast<const char*>(&dx[o]), len);
                // the HintName guard: the two un-XORed bytes before the run are a
                // plausible PE hint ordinal. This is what kills the stub's own
                // Fls*/CRT-math decoy stores, which have no hint field.
                const auto hint = o >= 2
                                      ? static_cast<std::uint16_t>(dx[o - 2] | (dx[o - 1] << 8))
                                      : 0;
                const bool has_hint = o >= 2 && hint >= 0x08 && hint <= 0x2fff &&
                                      fn.find('.') == std::string::npos;
                if (has_hint && fn.compare(0, 3, "Fls") != 0) {
                    std::string lower = fn;
                    for (auto& c : lower) {
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    }
                    const auto owners = owner_lookup(lower);
                    for (std::size_t j = tok_idx; j < btok.size(); ++j) {
                        bool owned = false;
                        for (const auto& ow : owners) {
                            if (stem_matches(btok[j], ow)) {
                                owned = true;
                                break;
                            }
                        }
                        if (owned) {
                            mined.insert({btok[j], fn});
                            tok_idx = j;
                            break;
                        }
                    }
                }
            }
            o = e + 1;
        }
    }
    out.pairs.assign(mined.begin(), mined.end());
    if (std::getenv("TAOTE_BANDDBG") != nullptr) {
        std::fprintf(stderr, "[band] n=%zu key=%u hits=%d toks=%zu bands=%zu mined=%zu\n", n,
                     static_cast<unsigned>(key), out.key_hits, toks.size(), bands.size(),
                     out.pairs.size());
    }
    return out;
}

}  // namespace alienyze
}  // namespace unpack
}  // namespace qiling
