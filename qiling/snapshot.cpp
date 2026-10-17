#include "qiling/snapshot.hpp"

#include <algorithm>
#include <cstring>

namespace qiling {

namespace {

void put_u32_at(std::vector<std::uint8_t>& buf, std::size_t pos, std::uint32_t v) {
    buf[pos + 0] = static_cast<std::uint8_t>(v);
    buf[pos + 1] = static_cast<std::uint8_t>(v >> 8);
    buf[pos + 2] = static_cast<std::uint8_t>(v >> 16);
    buf[pos + 3] = static_cast<std::uint8_t>(v >> 24);
}

void put_u64_at(std::vector<std::uint8_t>& buf, std::size_t pos, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf[pos + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
    }
}

std::uint32_t get_u32_at(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t get_u64_at(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

}  // namespace

// ---- SnapshotWriter ----

void SnapshotWriter::begin_section(std::string_view name) {
    if (in_section_) {
        end_section();
    }
    put_u32(static_cast<std::uint32_t>(name.size()));
    put_bytes(name);
    // reserve the payload-length slot, patched at end_section
    section_payload_pos_ = raw_.size();
    raw_.insert(raw_.end(), 8, 0);
    in_section_ = true;
}

void SnapshotWriter::end_section() {
    if (!in_section_) {
        return;
    }
    put_u64_at(raw_, section_payload_pos_, raw_.size() - section_payload_pos_ - 8);
    in_section_ = false;
}

void SnapshotWriter::put_u8(std::uint8_t v) { raw_.push_back(v); }

void SnapshotWriter::put_u32(std::uint32_t v) {
    raw_.resize(raw_.size() + 4);
    put_u32_at(raw_, raw_.size() - 4, v);
}

void SnapshotWriter::put_u64(std::uint64_t v) {
    raw_.resize(raw_.size() + 8);
    put_u64_at(raw_, raw_.size() - 8, v);
}

void SnapshotWriter::put_bytes(std::string_view data) {
    raw_.insert(raw_.end(), data.begin(), data.end());
}

// ---- SnapshotReader ----

SnapshotReader::SnapshotReader(std::string_view raw) : raw_(raw) {
    if (raw_.size() < 12 || raw_.substr(0, 4) != "QLSN" || get_u32_at(reinterpret_cast<const std::uint8_t*>(raw_.data()) + 4) != 1) {
        throw QlErrorBase("snapshot: malformed header");
    }
    pos_ = 12;
}

bool SnapshotReader::seek_section(std::string_view name) {
    // the previous section's unread payload is skipped: seek positions at the
    // payload start, and a following seek resumes after that payload
    pos_ = std::max(pos_, section_end_);
    const std::size_t scan_start = pos_;

    while (pos_ < raw_.size()) {
        if (raw_.size() - pos_ < 4) {
            pos_ = scan_start;
            return false;
        }
        const std::uint32_t name_len = get_u32_at(reinterpret_cast<const std::uint8_t*>(raw_.data()) + pos_);
        pos_ += 4;
        if (raw_.size() - pos_ < name_len + 8) {
            throw QlErrorBase("snapshot: truncated section header");
        }
        const std::string section_name(raw_.substr(pos_, name_len));
        pos_ += name_len;
        const std::uint64_t payload_len = get_u64_at(reinterpret_cast<const std::uint8_t*>(raw_.data()) + pos_);
        pos_ += 8;

        if (raw_.size() - pos_ < payload_len) {
            throw QlErrorBase("snapshot: truncated section payload");
        }

        if (section_name == name) {
            section_end_ = pos_ + static_cast<std::size_t>(payload_len);
            return true;
        }
        pos_ += payload_len;  // skip
    }
    // a failed seek leaves the stream where the scan began, so later seeks
    // still observe the sections that were skipped
    pos_ = scan_start;
    return false;
}

std::uint8_t SnapshotReader::get_u8() {
    if (raw_.size() - pos_ < 1) {
        throw QlErrorBase("snapshot: out of bounds read");
    }
    return raw_[pos_++];
}

std::uint32_t SnapshotReader::get_u32() {
    if (raw_.size() - pos_ < 4) {
        throw QlErrorBase("snapshot: out of bounds read");
    }
    const auto v = get_u32_at(reinterpret_cast<const std::uint8_t*>(raw_.data()) + pos_);
    pos_ += 4;
    return v;
}

std::uint64_t SnapshotReader::get_u64() {
    if (raw_.size() - pos_ < 8) {
        throw QlErrorBase("snapshot: out of bounds read");
    }
    const auto v = get_u64_at(reinterpret_cast<const std::uint8_t*>(raw_.data()) + pos_);
    pos_ += 8;
    return v;
}

std::string SnapshotReader::get_bytes(std::uint64_t size) {
    if (raw_.size() - pos_ < size) {
        throw QlErrorBase("snapshot: out of bounds read");
    }
    std::string out(raw_.substr(pos_, size));
    pos_ += size;
    return out;
}

}  // namespace qiling
