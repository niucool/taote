#include "qiling/os/path.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>

#include "qiling/exception.hpp"

namespace qiling {

namespace {

// splits a path into its '/'-separated components; both separators are
// normalized (NT virtual paths use '\\', and host paths on Windows do too)
std::vector<std::string> path_parts(std::string_view path, bool nt) {
    std::vector<std::string> parts;

    std::string normalized(path);
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    (void)nt;

    std::string_view rest = normalized;
    while (!rest.empty()) {
        const auto slash = rest.find('/');
        const auto part = rest.substr(0, slash);
        if (!part.empty()) {
            parts.emplace_back(part);
        }
        rest = (slash == std::string_view::npos) ? std::string_view{} : rest.substr(slash + 1);
    }

    return parts;
}

// pathlib-style prefix check: `path` begins with `prefix` at a component boundary
bool path_starts_with(std::string_view path, std::string_view prefix, bool nt) {
    const auto pp = path_parts(path, nt);
    const auto rp = path_parts(prefix, nt);

    if (rp.size() > pp.size()) {
        return false;
    }
    for (std::size_t i = 0; i < rp.size(); ++i) {
        const bool same = nt
            ? std::equal(rp[i].begin(), rp[i].end(), pp[i].begin(), pp[i].end(),
                         [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); })
            : rp[i] == pp[i];
        if (!same) {
            return false;
        }
    }
    return true;
}

// joins parts with '/'
std::string join_parts(const std::vector<std::string>& parts, std::size_t first = 0, std::size_t count = std::string::npos) {
    std::string out;
    const std::size_t last = std::min(parts.size(), (count == std::string::npos ? parts.size() : first + count));
    for (std::size_t i = first; i < last; ++i) {
        if (!out.empty()) {
            out += '/';
        }
        out += parts[i];
    }
    return out;
}

}  // namespace

QlOsPath::QlOsPath(const std::string& rootfs, const std::string& cwd, QL_OS emulos)
    : emulos_(emulos) {
    // rootfs is a local directory on the host, expected to exist (strict=True)
    std::error_code ec;
    const std::filesystem::path resolved = std::filesystem::canonical(std::filesystem::path(rootfs), ec);
    if (ec || !std::filesystem::is_directory(resolved, ec)) {
        throw QlErrorFileNotFound("rootfs not found: " + rootfs);
    }
    rootfs_ = resolved.string();

    // path.py: the cwd must be an absolute virtual path
    if (!virtual_is_absolute(cwd)) {
        throw QlErrorBase("current working directory must be an absolute path: " + cwd);
    }
    cwd_ = cwd;
}

bool QlOsPath::virtual_is_absolute(std::string_view virtpath) const {
    if (virtual_is_nt()) {
        // drive-letter (X:/ or X:\) or UNC (\\server\share) anchors
        if (virtpath.size() >= 2 && virtpath[1] == ':') {
            return true;
        }
        if (virtpath.size() >= 2 && virtpath[0] == '\\' && virtpath[1] == '\\') {
            return true;
        }
        return false;
    }
    return !virtpath.empty() && virtpath.front() == '/';
}

void QlOsPath::split_virtual(std::string_view virtpath, std::string& anchor, std::string& body) const {
    if (virtual_is_nt()) {
        if (virtpath.size() >= 2 && virtpath[1] == ':') {
            // the anchor is "X:/"
            anchor.assign(virtpath.substr(0, 2));
            anchor += '/';
            body.assign(virtpath.substr(2));
        } else if (virtpath.size() >= 2 && virtpath[0] == '\\' && virtpath[1] == '\\') {
            // UNC anchor: \\server\share
            std::string rest{virtpath.substr(2)};
            const auto slash = rest.find_first_of("\\/");
            if (slash != std::string_view::npos) {
                const auto share_end = rest.find_first_of("\\/", slash + 1);
                anchor.assign(virtpath.substr(0, share_end == std::string_view::npos ? std::string_view::npos : 2 + share_end));
                body.assign(virtpath.substr(anchor.size()));
            } else {
                anchor.assign(virtpath);
                body.clear();
            }
        } else {
            anchor.clear();
            body.assign(virtpath);
        }
        // normalize the body separators
        std::replace(body.begin(), body.end(), '\\', '/');
    } else {
        const bool absolute = !virtpath.empty() && virtpath.front() == '/';
        anchor = absolute ? "/" : "";
        body = absolute ? std::string(virtpath.substr(1)) : std::string(virtpath);
    }
}

std::string QlOsPath::virtual_abspath(std::string_view virtpath) const {
    std::string anchor;
    std::string body;
    split_virtual(virtpath, anchor, body);

    // path.py __virtual_abspath: absolute paths survive as-is; relative ones
    // rebase on the cwd
    if (!anchor.empty()) {
        if (anchor.size() == 1) {  // the POSIX root anchor "/"
            // absvpath = anchor / stripped(vpath): a leading '..' strip
            auto parts = path_parts(body, virtual_is_nt());
            while (!parts.empty() && parts.front() == "..") {
                parts.erase(parts.begin());
            }
            return anchor + join_parts(parts);
        }

        // NT anchor: body may still need the parent-ref strip
        auto parts = path_parts(body, true);
        while (!parts.empty() && parts.front() == "..") {
            parts.erase(parts.begin());
        }
        return anchor + join_parts(parts);
    }

    // relative: rebase on the cwd body, then strip leading parent refs
    std::string cwd_anchor;
    std::string cwd_body;
    split_virtual(cwd_, cwd_anchor, cwd_body);

    auto parts = path_parts(cwd_body, virtual_is_nt());
    for (const auto& part : path_parts(body, virtual_is_nt())) {
        parts.push_back(part);
    }

    // referencing root's parent directory circles back to root
    while (!parts.empty() && parts.front() == "..") {
        parts.erase(parts.begin());
    }

    return cwd_anchor + join_parts(parts);
}

std::string QlOsPath::virtual_to_host_path(std::string_view virtpath) const {
    // __virtual_resolve: expand ".." against the accumulated host path and
    // follow virtual symlinks (a symlink target that escapes rootfs is an
    // absolute host path per path.py's __resolved_vsymlink fallback)
    const std::string absvpath = virtual_abspath(virtpath);

    std::string anchor;
    std::string body;
    split_virtual(absvpath, anchor, body);

    std::filesystem::path acc_host;
    bool host_valid = true;

    for (const auto& part : path_parts(body, virtual_is_nt())) {
        if (part == "..") {
            if (host_valid) {
                acc_host = acc_host.parent_path();
            }
            continue;
        }

        // symlink probe against the accumulated host path
        const std::filesystem::path probe = (host_valid ? acc_host : std::filesystem::path(rootfs_)) / part;
        std::error_code ec;
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(probe, ec)) && !ec) {
            // __resolved_vsymlink: resolve, then try to rebase on rootfs
            const std::filesystem::path resolved = std::filesystem::canonical(probe, ec);
            if (!ec) {
                std::error_code rel_ec;
                const auto rel = std::filesystem::relative(resolved, std::filesystem::path(rootfs_), rel_ec);
                if (!rel_ec && !rel.empty() && rel.string().find("..") == std::string::npos) {
                    // virtual: continue accumulating with the rebased path
                    if (host_valid) {
                        acc_host = std::filesystem::path(rootfs_) / rel;
                    }
                    continue;
                }
                // external target: the accumulated host path becomes host-absolute
                acc_host = resolved;
                host_valid = false;
                continue;
            }
        }

        if (host_valid) {
            acc_host = acc_host / part;
        }
    }

    // __virtual_to_host_path: rebase the resolved virtual path on rootfs
    if (host_valid) {
        return (std::filesystem::path(rootfs_) / acc_host).string();
    }
    return acc_host.string();
}

bool QlOsPath::is_safe_host_path(std::string_view hostpath) const {
    // __is_safe_host_path(strict=False): canonicalize what exists, then check
    // the rootfs prefix
    std::error_code ec;
    const std::filesystem::path resolved = std::filesystem::weakly_canonical(std::filesystem::path(hostpath), ec);
    if (ec) {
        return false;
    }

    return path_starts_with(resolved.string(), rootfs_, false);
}

std::string QlOsPath::host_to_virtual_path(std::string_view hostpath) const {
    std::error_code ec;
    const std::filesystem::path resolved = std::filesystem::weakly_canonical(std::filesystem::path(hostpath), ec);
    const std::filesystem::path root(rootfs_);

    std::error_code rel_ec;
    const auto rel = std::filesystem::relative(resolved, root, rel_ec);
    if (rel_ec || rel.empty() || rel.string().find("..") != std::string::npos) {
        throw QlErrorBase("path does not map to the rootfs: " + std::string(hostpath));
    }

    // rebase on the cwd anchor
    std::string anchor;
    std::string body;
    split_virtual(cwd_, anchor, body);
    (void)body;

    return anchor + rel.generic_string();
}

bool QlOsPath::is_virtual_abspath(std::string_view virtpath) const {
    return virtual_is_absolute(virtpath);
}

std::optional<std::string> QlOsPath::host_casefold_path(std::string_view hostpath) const {
    // __host_casefold_path: on NT hosts paths match case-insensitively — the
    // Python code returns None right away (the file truly does not exist)
#ifdef _WIN32
    (void)hostpath;
    return std::nullopt;
#else
    if (!virtual_is_nt()) {
        return std::string(hostpath);
    }

    // POSIX host emulating NT: case-insensitive component walk
    std::filesystem::path norm;
    for (const auto& part : path_parts(hostpath, false)) {
        bool found = false;
        std::error_code ec;
        if (!std::filesystem::exists(norm / part, ec)) {
            for (const auto& entry : std::filesystem::directory_iterator(norm.empty() ? std::filesystem::path(".") : norm, ec)) {
                std::string name = entry.path().filename().string();
                std::string folded = name;
                std::transform(folded.begin(), folded.end(), folded.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                std::string want(part);
                std::transform(want.begin(), want.end(), want.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (folded == want) {
                    norm = norm / name;
                    found = true;
                    break;
                }
            }
            if (!found) {
                return std::nullopt;
            }
        } else {
            norm = norm / part;
        }
    }

    return norm.string();
#endif
}

}  // namespace qiling
