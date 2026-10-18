// Ported from qiling/os/macos/kernel_func.py — the macos FileSystem helper
// (the vm-to-real path mapping over the rootfs + the isexists check + the
// getattrlist common-attr walk) + the macos/utils.py page_align_end helper.
#ifndef QILING_OS_MACOS_KERNEL_FUNC_HPP
#define QILING_OS_MACOS_KERNEL_FUNC_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/macos/const.hpp"

namespace qiling {
namespace os {
namespace macos {

// macos/utils.py page_align_end: the round-up to the page multiple (the
// verbatim arithmetic shape)
inline std::uint64_t page_align_end(std::uint64_t addr, std::uint64_t page_size) {
    if (addr % page_size == 0) {
        return addr;
    }
    return ((addr / page_size) + 1) * page_size;
}

// kernel_func.py FileSystem
class FileSystem {
public:
    explicit FileSystem(Qiling& ql) : ql_(ql) {}

    // kernel_func.py FileSystem.vm_to_real_path: the abs paths ride the
    // rootfs with the leading slash stripped; the rel paths join as-is
    std::string vm_to_real_path(const std::string& vm_path) const;

    // kernel_func.py FileSystem.isexists: os.path.exists over the real path
    bool isexists(const std::string& vm_path) const;

    // kernel_func.py FileSystem.get_common_attr: the ATTR_CMN_* walk over
    // the host stat (the name/dev/type/inode cells in the upstream order;
    // the name cell rides at the front with its offset when requested)
    std::vector<std::uint8_t> get_common_attr(const std::string& path, std::uint32_t cmn_flags) const;

private:
    Qiling& ql_;
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_KERNEL_FUNC_HPP
