// PLAN_PARITY Phase 3 item 6: config parity for the filesystem surface.
//
// Ported from pegasus src/volumes.cpp: a "host:guest" volume spec maps a host
// file or directory tree into the emulated filesystem. pegasus expands the tree
// into config entries (one per file, mode "full_path"); taote has a real mapper
// (QlFsMapper::add_mapping), so a volume becomes one mapping per file - the same
// observable behaviour without a config intermediate.
//
// The separator is the first ':' that is not part of a drive-letter prefix, so
// "C:\\samples:C:\\guest" parses like pegasus's.
#ifndef QILING_OS_VOLUMES_HPP
#define QILING_OS_VOLUMES_HPP

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {

class QlFsMapper;

namespace os {

// parse_volume_spec: "host:guest" -> (host path, guest path); QlErrorBase on a
// malformed spec (pegasus: std::invalid_argument / runtime_error)
std::pair<std::filesystem::path, std::string> parse_volume_spec(const std::string& spec);

// expand_volume_entries: a host file maps to the guest path itself, a host
// directory maps each regular file recursively to guest\\<relative path>
// (sorted, backslash separators - pegasus's expand_volume_to_entries)
std::vector<std::pair<std::string, std::filesystem::path>> expand_volume_entries(
    const std::filesystem::path& host_path, const std::string& guest_path);

// mounts every spec through the mapper (a duplicate guest path is replaced, so
// a volume overrides an earlier mapping - pegasus prepends its entries)
void apply_volumes(QlFsMapper& mapper, const std::vector<std::string>& volume_specs);

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_VOLUMES_HPP
