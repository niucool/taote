// PLAN_PARITY Phase 3 item 6: the volume-spec port (see the header).
#include "qiling/os/volumes.hpp"

#include <algorithm>

#include "qiling/os/mapper.hpp"

namespace qiling::os {

std::pair<std::filesystem::path, std::string> parse_volume_spec(const std::string& spec) {
    if (spec.empty()) {
        throw QlErrorBase("empty volume specification");
    }

    // skip a leading drive letter (X:) when looking for the separator
    std::size_t start = 0;
    if (spec.length() >= 2 && spec[1] == ':') {
        start = 2;
    }

    const auto idx = spec.find(':', start);
    if (idx == std::string::npos) {
        throw QlErrorBase("invalid volume spec (missing ':' separator): " + spec);
    }

    const auto host = spec.substr(0, idx);
    const auto guest = spec.substr(idx + 1);
    if (host.empty()) {
        throw QlErrorBase("empty host path in volume spec: " + spec);
    }
    if (guest.empty()) {
        throw QlErrorBase("empty guest path in volume spec: " + spec);
    }

    return {std::filesystem::path(host), guest};
}

std::vector<std::pair<std::string, std::filesystem::path>> expand_volume_entries(
    const std::filesystem::path& host_path, const std::string& guest_path) {
    namespace fs = std::filesystem;

    std::vector<std::pair<std::string, std::filesystem::path>> entries;

    std::error_code ec;
    const auto resolved = fs::absolute(host_path, ec);
    if (ec || !fs::exists(resolved)) {
        throw QlErrorBase("volume host path does not exist: " + resolved.string());
    }

    if (fs::is_regular_file(resolved)) {
        entries.emplace_back(guest_path, resolved);
        return entries;
    }

    if (fs::is_directory(resolved)) {
        std::vector<fs::path> files;
        for (auto it = fs::recursive_directory_iterator(resolved, ec); !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            if (it->is_regular_file()) {
                files.push_back(it->path());
            }
        }
        std::sort(files.begin(), files.end());

        for (const auto& child : files) {
            const auto rel = fs::relative(child, resolved, ec);
            std::string emu_path = guest_path;
            for (const auto& part : rel) {
                if (!emu_path.empty() && emu_path.back() != '\\') {
                    emu_path += '\\';
                }
                emu_path += part.string();
            }
            entries.emplace_back(emu_path, child);
        }
    }

    return entries;
}

void apply_volumes(QlFsMapper& mapper, const std::vector<std::string>& volume_specs) {
    for (const auto& spec : volume_specs) {
        const auto [host, guest] = parse_volume_spec(spec);
        for (auto& [emu_path, path] : expand_volume_entries(host, guest)) {
            // a volume overrides an earlier mapping: the force flag is the
            // mapper's documented replacement path
            mapper.add_mapping(emu_path, path.string(), true);
        }
    }
}

}  // namespace qiling::os
