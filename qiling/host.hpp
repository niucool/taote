// Ported from qiling/host.py — interface to the hosting platform.
#ifndef QILING_HOST_HPP
#define QILING_HOST_HPP

#include <filesystem>
#include <optional>

#include "qiling/const.hpp"

namespace qiling {

class QlHost {
public:
    QlHost() = default;

    // Hosting platform OS type (host.py os; cached_property -> lazy member).
    // The platform detection uses the compile-time platform instead of
    // platform.system(); the string passed through utils.os_convert is the
    // same value platform.system() would produce.
    std::optional<QL_OS> os() const;

    // Hosting platform architecture type (host.py arch).
    std::optional<QL_ARCH> arch() const;

private:
    mutable std::optional<QL_OS> os_;      // empty = not yet computed
    mutable std::optional<QL_ARCH> arch_;  // nullopt value = computed, no match
    mutable bool os_done_ = false;
    mutable bool arch_done_ = false;
};

// Absolute path of the running executable, or an empty path when the platform
// has no way to ask. Used to find the install tree's data directory relative to
// the binary, so a copied build/deploy keeps working (see qiling::data_dir).
std::filesystem::path host_executable_path();

}  // namespace qiling

#endif  // QILING_HOST_HPP
