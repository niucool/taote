// Ported from qiling/os/path.py — QlOsPath, the virtual↔host path manipulator
// (PORT_PLAN.md §5.6 / Phase 3). Python builds on pathlib's PurePosixPath /
// PureWindowsPath; the C++ port implements the same semantics over strings:
//
//   - virtual path flavors: POSIX (LINUX/FREEBSD/MACOS) vs NT (WINDOWS/DOS)
//   - `virtual_abspath`: rebase relative paths on the virtual cwd, strip
//     leading parent refs (surviving above root circles back to root)
//   - `virtual_to_host_path`: resolve `..` components and virtual symlinks,
//     then rebase the result on the rootfs host directory
//   - `is_safe_host_path`: containment check after canonicalization
//
// Documented deviations: Windows UNC anchors collapse to the `\\server\share`
// prefix only when both components are present; PureWindowsPath's short-name
// (8.3) semantics are not modeled.
#ifndef QILING_OS_PATH_HPP
#define QILING_OS_PATH_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "qiling/const.hpp"

namespace qiling {

class QlOsPath {
public:
    // Python: Path(rootfs).resolve(strict=True) — the rootfs must exist
    QlOsPath(const std::string& rootfs, const std::string& cwd, QL_OS emulos);

    // ---- virtual-path queries ----

    // virtual_abspath — absolute virtual path (cwd-rebased, parent-ref stripped)
    std::string virtual_abspath(std::string_view virtpath) const;

    // virtual_abspath_at (unistd.py virtual_abspath_at): the same rebase off
    // an explicit base directory (the dirfd-based resolution) — absolute
    // virtual paths survive as-is
    std::string virtual_abspath_from(std::string_view base_dir, std::string_view virtpath) const;

    // path.py cwd setter (the chdir ride)
    void set_cwd(std::string cwd) { cwd_ = std::move(cwd); }

    // virtual_to_host_path — the host path (rootfs-rebased, symlinks resolved)
    std::string virtual_to_host_path(std::string_view virtpath) const;

    // is_safe_host_path — true when the canonicalized host path stays inside rootfs
    bool is_safe_host_path(std::string_view hostpath) const;

    // host_to_virtual_path — the virtual path of a rootfs-internal host path;
    // throws QlErrorBase when the host path does not map to a rootfs location
    std::string host_to_virtual_path(std::string_view hostpath) const;

    // is_virtual_abspath — whether the virtual path is absolute
    bool is_virtual_abspath(std::string_view virtpath) const;

    // file_casefold_path (path.py host_casefold_path): on NT hosts paths match
    // case-insensitively, so no folding is needed (returns nullopt); on POSIX
    // hosts the walk finds the actual on-disk casing (nullopt when absent)
    std::optional<std::string> host_casefold_path(std::string_view hostpath) const;

    // ---- cwd ----

    std::string root() const noexcept { return rootfs_; }
    std::string cwd() const noexcept { return cwd_; }

private:
    // determines the NT flavor of virtual paths (windows/dos emulations)
    bool virtual_is_nt() const noexcept { return emulos_ == QL_OS::WINDOWS || emulos_ == QL_OS::DOS; }

    // splits a virtual path into anchor ("" for relative) and body
    void split_virtual(std::string_view virtpath, std::string& anchor, std::string& body) const;

    // true when the virtual path is absolute in its flavor
    bool virtual_is_absolute(std::string_view virtpath) const;

    std::string rootfs_;
    std::string cwd_;  // virtual cwd (anchor included)
    QL_OS emulos_;
};

}  // namespace qiling

#endif  // QILING_OS_PATH_HPP
