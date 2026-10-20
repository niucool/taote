// PLAN_PARITY Phase 3 item 5: the content-addressed artifact store (see the
// header for the contract). The digest is a plain SHA-256 - the tree carries no
// crypto library and the store only needs a stable name, not a signature.
#include "qiling/os/artifacts.hpp"

#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"

namespace qiling::os {

namespace {

constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

std::string sha256_hex_impl(const std::uint8_t* data, std::size_t size) {
    std::uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // the padded message: the data, a 0x80 byte, zeros, then the bit length
    std::vector<std::uint8_t> msg(data, data + size);
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) {
        msg.push_back(0);
    }
    const auto bits = static_cast<std::uint64_t>(size) * 8;
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<std::uint8_t>((bits >> (i * 8)) & 0xff));
    }

    for (std::size_t off = 0; off < msg.size(); off += 64) {
        std::uint32_t w[64] = {};
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(msg[off + i * 4]) << 24) |
                   (static_cast<std::uint32_t>(msg[off + i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(msg[off + i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(msg[off + i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const auto s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const auto ch = (e & f) ^ (~e & g);
            const auto temp1 = hh + s1 + ch + kSha256K[i] + w[i];
            const auto s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::ostringstream out;
    for (const auto word : h) {
        out << std::hex << std::setw(8) << std::setfill('0') << word;
    }
    return out.str();
}

}  // namespace

std::string sha256_hex(std::string_view data) {
    return sha256_hex_impl(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

QlArtifactStore::QlArtifactStore(std::filesystem::path dir) : dir_(std::move(dir)) {}

bool QlArtifactStore::contains(std::string_view hash) const {
    if (dir_.empty() || hash.empty()) {
        return false;
    }
    std::error_code ec;
    return std::filesystem::exists(dir_ / std::string(hash), ec);
}

std::string QlArtifactStore::put(std::string_view kind, std::string_view label, std::string_view data) {
    const auto digest = sha256_hex(data);

    for (const auto& rec : records_) {
        if (rec.hash == digest) {
            return digest;  // already accounted for
        }
    }

    if (!dir_.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(dir_, ec);
        const auto path = dir_ / digest;
        // write once: an existing blob is the same bytes by construction
        if (!std::filesystem::exists(path, ec)) {
            std::ofstream out(path, std::ios::binary);
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
        }
    }

    records_.push_back(ArtifactRecord{std::string(kind), std::string(label), digest, data.size()});
    return digest;
}

std::string QlArtifactStore::save_memory(Qiling& ql, std::uint64_t begin, std::uint64_t size, std::string_view label) {
    const auto bytes = ql.mem().read(begin, static_cast<std::size_t>(size));
    std::string text;
    if (!label.empty()) {
        text = std::string(label);
    } else if (const auto* region = ql.mem().region_at(begin); region != nullptr) {
        text = region->label;
    }
    return put("memory", text, std::string(bytes.begin(), bytes.end()));
}

std::string QlArtifactStore::save_file(const std::filesystem::path& path, std::string_view label) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw QlErrorBase("cannot open artifact source: " + path.string());
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    const auto data = buf.str();
    return put("file", label.empty() ? path.filename().string() : std::string(label), data);
}

std::vector<std::uint8_t> QlArtifactStore::get(std::string_view hash) const {
    if (!dir_.empty()) {
        std::ifstream in(dir_ / std::string(hash), std::ios::binary);
        if (in) {
            std::ostringstream buf;
            buf << in.rdbuf();
            const auto data = buf.str();
            return std::vector<std::uint8_t>(data.begin(), data.end());
        }
    }
    return {};
}

void QlArtifactStore::write_manifest(SnapshotWriter& writer) const {
    writer.begin_section("artifacts");
    writer.put_u32(static_cast<std::uint32_t>(records_.size()));
    for (const auto& rec : records_) {
        writer.put_str(rec.kind);
        writer.put_str(rec.label);
        writer.put_str(rec.hash);
        writer.put_u64(rec.size);
    }
    writer.end_section();
}

void QlArtifactStore::read_manifest(SnapshotReader& reader) {
    records_.clear();
    if (!reader.seek_section("artifacts")) {
        return;
    }
    const auto count = reader.get_u32();
    for (std::uint32_t i = 0; i < count; ++i) {
        ArtifactRecord rec;
        rec.kind = reader.get_str();
        rec.label = reader.get_str();
        rec.hash = reader.get_str();
        rec.size = reader.get_u64();
        records_.push_back(std::move(rec));
    }
}

}  // namespace qiling::os
