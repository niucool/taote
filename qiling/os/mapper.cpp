#include "qiling/os/mapper.hpp"

#include <filesystem>

#include "qiling/exception.hpp"

namespace qiling {

QlFsMapper::QlFsMapper(const QlOsPath& path) : path_(&path) {}

bool QlFsMapper::contains(std::string_view vpath) const {
    // canonicalize the path first (mapper.py __contains__)
    return mapping_.find(path_->virtual_abspath(vpath)) != mapping_.end();
}

bool QlFsMapper::has_mapping(std::string_view vpath) const {
    return contains(vpath);
}

std::shared_ptr<QlFsMappedObject> QlFsMapper::open_mapped(std::string_view absvpath, const std::string& mode) {
    (void)mode;  // stdio layer has no distinct text mode; kept for the signature
    const auto& mapped = mapping_.at(std::string(absvpath));

    if (const auto* host_path = std::get_if<std::string>(&mapped)) {
        // mapped to a file name on the host file system
        return QlFile::open_mode(*host_path, mode);
    }

    if (const auto* factory = std::get_if<std::function<std::shared_ptr<QlFsMappedObject>()>>(&mapped)) {
        // mapped to a class or a method
        return (*factory)();
    }

    // mapped to another kind of object
    return std::get<std::shared_ptr<QlFsMappedObject>>(mapped);
}

std::shared_ptr<QlFsMappedObject> QlFsMapper::open_new(std::string_view absvpath, const std::string& mode) {
    const std::string hpath = path_->virtual_to_host_path(absvpath);

    if (!path_->is_safe_host_path(hpath)) {
        // mapper.py raises PermissionError
        throw QlErrorBase("unsafe path: " + hpath);
    }

    return QlFile::open_mode(hpath, mode);
}

std::shared_ptr<QlFsMappedObject> QlFsMapper::open_ql_file(std::string_view vpath, int flags, int mode) {
    const std::string absvpath = path_->virtual_abspath(vpath);

    if (has_mapping(absvpath)) {
        const auto& mapped = mapping_.at(absvpath);
        if (const auto* host_path = std::get_if<std::string>(&mapped)) {
            return QlFile::open(*host_path, flags, mode);
        }
        if (const auto* factory = std::get_if<std::function<std::shared_ptr<QlFsMappedObject>()>>(&mapped)) {
            return (*factory)();
        }
        return std::get<std::shared_ptr<QlFsMappedObject>>(mapped);
    }

    // fresh host file with guest access flags
    const std::string hpath = path_->virtual_to_host_path(absvpath);
    if (!path_->is_safe_host_path(hpath)) {
        throw QlErrorBase("unsafe path: " + hpath);
    }
    return QlFile::open(hpath, flags, mode);
}

std::shared_ptr<QlFsMappedObject> QlFsMapper::open(std::string_view vpath, std::string_view mode) {
    const std::string absvpath = path_->virtual_abspath(vpath);

    // map the guest mode string onto the stdio mode (mapper.py passes the
    // mode through to open())
    bool read = false, write = false, append = false;
    bool update = false;
    for (const char c : mode) {
        switch (c) {
            case 'r': read = true; break;
            case 'w': write = true; break;
            case 'a': append = true; break;
            case '+': update = true; break;
            default: break;  // 'b' and encoding suffixes are no-ops here
        }
    }

    const char* stdio_mode = "rb";
    if (update) {
        stdio_mode = append ? "ab+" : (write ? "w+b" : "r+b");
    } else if (write) {
        stdio_mode = "wb";
    } else if (append) {
        stdio_mode = "ab";
    }

    if (has_mapping(absvpath)) {
        return open_mapped(absvpath, stdio_mode);
    }
    return open_new(absvpath, stdio_mode);
}

bool QlFsMapper::file_exists(std::string_view vpath) const {
    if (has_mapping(vpath)) {
        return true;
    }

    const std::string hpath = path_->virtual_to_host_path(vpath);
    if (!path_->is_safe_host_path(hpath)) {
        throw QlErrorBase("unsafe path: " + hpath);
    }

    std::error_code ec;
    return std::filesystem::is_regular_file(hpath, ec) && !ec;
}

bool QlFsMapper::create_empty_file(std::string_view vpath) {
    if (!file_exists(vpath)) {
        try {
            const auto f = open(vpath, "w+");
            f->close();
        } catch (const std::exception&) {
            // for some reason, we could not create an empty file
            return false;
        }
    }

    return true;
}

void QlFsMapper::add_mapping(std::string_view vpath, QlFsBinding binding, bool force) {
    const std::string absvpath = path_->virtual_abspath(vpath);

    if (has_mapping(absvpath) && !force) {
        throw QlErrorBase("mapping already exists: \"" + absvpath + "\"");
    }

    mapping_[absvpath] = std::move(binding);
}

void QlFsMapper::remove_mapping(std::string_view vpath) {
    const std::string absvpath = path_->virtual_abspath(vpath);

    const auto it = mapping_.find(absvpath);
    if (it == mapping_.end()) {
        throw QlErrorBase(std::string(absvpath));  // KeyError analogue
    }

    mapping_.erase(it);
}

void QlFsMapper::rename_mapping(std::string_view old_vpath, std::string_view new_vpath) {
    const std::string old_absvpath = path_->virtual_abspath(old_vpath);

    // vpath to rename does not exist
    if (!has_mapping(old_absvpath)) {
        throw QlErrorBase(std::string(old_vpath));
    }

    const std::string new_absvpath = path_->virtual_abspath(new_vpath);

    // new vpath already exists
    if (has_mapping(new_absvpath)) {
        throw QlErrorBase(new_absvpath);
    }

    // avoid renaming to the same vpath
    if (old_absvpath == new_absvpath) {
        return;
    }

    auto it = mapping_.find(old_absvpath);
    mapping_[new_absvpath] = std::move(it->second);
    mapping_.erase(it);
}

}  // namespace qiling
