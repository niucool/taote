// Ported from qiling/os/macos/kernel_func.py — the macos FileSystem helper
// (the vm-to-real mapping + the isexists + the common-attr walk).
#include "qiling/os/macos/kernel_func.hpp"

#include <sys/stat.h>

#include <filesystem>

#include "qiling/os/macos/const.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

// pack LE (the upstream's struct.pack("<L"/"<Q", ...))
template <typename T>
void put_le(std::vector<std::uint8_t>& out, T v) {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint64_t>(v) >> (8 * i)));
    }
}

}  // namespace

std::string FileSystem::vm_to_real_path(const std::string& vm_path) const {
    if (vm_path.empty()) {
        return {};
    }
    // kernel_func.py: os.path.join(self.base_path, vm_path[1:]) for the abs
    // paths (the leading slash stripped), the rel paths join as-is
    if (vm_path[0] == '/') {
        return (std::filesystem::path(ql_.rootfs()) / vm_path.substr(1)).string();
    }
    return (std::filesystem::path(ql_.rootfs()) / vm_path).string();
}

bool FileSystem::isexists(const std::string& vm_path) const {
    return std::filesystem::exists(vm_to_real_path(vm_path));
}

std::vector<std::uint8_t> FileSystem::get_common_attr(const std::string& path,
                                                      std::uint32_t cmn_flags) const {
    const auto real_path = vm_to_real_path(path);
    if (!std::filesystem::exists(real_path)) {
        return {};
    }

    // the host stat (the upstream's os.stat(real_path) — the dev/ino cells)
#if defined(_WIN32)
    struct _stat64 st {};
    ::_stat64(real_path.c_str(), &st);
#else
    struct stat st {};
    ::stat(real_path.c_str(), &st);
#endif

    // the upstream keys the type checks off the VM path (verbatim quirk:
    // os.path.isdir(path)/os.path.islink(path), not the real path)
    std::error_code ec;
    const bool vm_is_dir = std::filesystem::is_directory(std::filesystem::path(path), ec);
    const bool vm_is_link = std::filesystem::is_symlink(std::filesystem::path(path), ec);

    std::vector<std::uint8_t> attr;
    std::string filename;

    if ((cmn_flags & ATTR_CMN_NAME) != 0) {
        // the upstream splits on '/' and takes the last segment
        const auto pos = path.rfind('/');
        filename = pos == std::string::npos ? path : path.substr(pos + 1);
        put_le(attr, static_cast<std::uint32_t>(filename.size() + 1));  // add \0
    }

    if ((cmn_flags & ATTR_CMN_DEVID) != 0) {
        put_le(attr, static_cast<std::uint32_t>(st.st_dev));
    }

    if ((cmn_flags & ATTR_CMN_OBJTYPE) != 0) {
        if (vm_is_dir) {
            put_le(attr, VDIR);
        } else if (vm_is_link) {
            put_le(attr, VLNK);
        } else {
            put_le(attr, VREG);
        }
    }

    if ((cmn_flags & ATTR_CMN_OBJID) != 0) {
        put_le(attr, static_cast<std::uint64_t>(st.st_ino));
    }

    // at last, add the name (the upstream's name_offset = len(attr) + 4; the
    // offset cell rides at the front of the whole record)
    if ((cmn_flags & ATTR_CMN_NAME) != 0) {
        const auto name_offset = static_cast<std::uint32_t>(attr.size() + 4);
        std::vector<std::uint8_t> out;
        put_le(out, name_offset);
        out.insert(out.end(), attr.begin(), attr.end());
        out.insert(out.end(), filename.begin(), filename.end());
        out.push_back(0);
        return out;
    }

    return attr;
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
