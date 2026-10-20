// PLAN_PARITY Phase 3 item 5: the content-addressed artifact store.
//
// Pegasus's test_artifact_store / test_profiler_artifacts / test_memory_capture
// rows want dumps that a report can point at by hash rather than by path: every
// blob is stored once under <dir>/<sha256>, and the manifest (kind, label, size,
// digest) rides the existing Snapshot envelope's "artifacts" section, so a
// snapshot and the dumps it refers to travel together.
#ifndef QILING_OS_ARTIFACTS_HPP
#define QILING_OS_ARTIFACTS_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "qiling/exception.hpp"
#include "qiling/snapshot.hpp"

namespace qiling {

class Qiling;

namespace os {

// the SHA-256 digest of the bytes, lowercase hex (the store's key)
std::string sha256_hex(std::string_view data);

struct ArtifactRecord {
    std::string kind;   // "memory" / "file" / "image" / ...
    std::string label;  // the human handle (a region name, a path)
    std::string hash;   // the sha256 hex digest (the on-disk name)
    std::uint64_t size = 0;
};

class QlArtifactStore {
public:
    explicit QlArtifactStore(std::filesystem::path dir = {});

    const std::filesystem::path& directory() const noexcept { return dir_; }

    // stores the bytes once (a repeated blob costs one file), returns the digest
    std::string put(std::string_view kind, std::string_view label, std::string_view data);

    // a guest memory range; the label defaults to the containing region's name
    std::string save_memory(Qiling& ql, std::uint64_t begin, std::uint64_t size, std::string_view label = {});

    // a host file (the guest's dropped file, a captured sample)
    std::string save_file(const std::filesystem::path& path, std::string_view label = {});

    bool contains(std::string_view hash) const;
    std::vector<std::uint8_t> get(std::string_view hash) const;

    const std::vector<ArtifactRecord>& records() const noexcept { return records_; }
    void clear() noexcept { records_.clear(); }

    // the manifest over the Snapshot envelope ("artifacts" section: u32 count,
    // then per record kind/label/hash/size)
    void write_manifest(SnapshotWriter& writer) const;
    void read_manifest(SnapshotReader& reader);

private:
    std::filesystem::path dir_;
    std::vector<ArtifactRecord> records_;
};

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_ARTIFACTS_HPP
