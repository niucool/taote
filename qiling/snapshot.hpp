// C++-only: the explicit versioned binary snapshot envelope (PORT_PLAN.md
// 5.12 / OQ 7 — no pickle compatibility; the Python dict-based save/restore is
// replaced by per-component serialization over this envelope).
//
// Format:
//   header : magic "QLSN" (4 bytes) + u32 version (1) + u32 section count
//   section: u32 name length + name bytes + u64 payload length + payload bytes
//
// All integers are little-endian. Readers validate bounds and degrade to
// QlErrorBase on malformed input (the robustness tenet: never a host crash).
#ifndef QILING_SNAPSHOT_HPP
#define QILING_SNAPSHOT_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {

class SnapshotWriter {
public:
    SnapshotWriter() { raw_.insert(raw_.end(), {'Q', 'L', 'S', 'N', 1, 0, 0, 0, 0, 0, 0, 0}); }

    // begins a section; payload bytes follow via put_* until end_section
    void begin_section(std::string_view name);
    void end_section();

    void put_u8(std::uint8_t v);
    void put_u32(std::uint32_t v);
    void put_u64(std::uint64_t v);
    void put_bytes(std::string_view data);
    void put_str(std::string_view s) { put_u32(static_cast<std::uint32_t>(s.size())); put_bytes(s); }

    std::vector<std::uint8_t> finish() && { return std::move(raw_); }
    const std::vector<std::uint8_t>& raw() const noexcept { return raw_; }

private:
    std::vector<std::uint8_t> raw_;
    bool in_section_ = false;
    std::size_t section_payload_pos_ = 0;
};

class SnapshotReader {
public:
    explicit SnapshotReader(std::string_view raw);

    // skips to the named section; returns false when absent
    bool seek_section(std::string_view name);

    std::uint8_t get_u8();
    std::uint32_t get_u32();
    std::uint64_t get_u64();
    std::string get_bytes(std::uint64_t size);
    std::string get_str() { return get_bytes(get_u32()); }

    // true when the whole stream was consumed
    bool at_end() const noexcept { return pos_ >= raw_.size(); }

private:
    std::string_view raw_;
    std::size_t pos_ = 0;
    // end of the previously seeked section's payload; the next seek resumes
    // from there (the consumer reads the payload between seeks)
    std::size_t section_end_ = 0;
};

}  // namespace qiling

#endif  // QILING_SNAPSHOT_HPP
