// Ported from qiling/os/mapper.py — QlFsMapper + the mapped-object dispatch.
// (The QlFsMappedObject interface itself lives in filestruct.hpp, mirroring
// the Python split where the base class guards against circular imports.)
#ifndef QILING_OS_MAPPER_HPP
#define QILING_OS_MAPPER_HPP

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <variant>

#include "qiling/os/filestruct.hpp"
#include "qiling/os/path.hpp"

namespace qiling {

// The binding flavors mapper.py accepts for add_mapping:
//   - a string: an existing host path (bound as the target of `open`)
//   - a factory callable: invoked with no arguments each open
//   - an object instance: returned as-is each open
using QlFsBinding = std::variant<
    std::string,
    std::function<std::shared_ptr<QlFsMappedObject>()>,
    std::shared_ptr<QlFsMappedObject>>;

class QlFsMapper {
public:
    explicit QlFsMapper(const QlOsPath& path);

    // `vpath in mapper` — canonicalized virtual path lookup
    bool contains(std::string_view vpath) const;

    // has_mapping — vpath in self
    bool has_mapping(std::string_view vpath) const;

    std::size_t size() const noexcept { return mapping_.size(); }
    std::size_t mapping_count() const noexcept { return size(); }

    // open_ql_file(vpath, flags, mode) — a mapped binding or a fresh host file
    std::shared_ptr<QlFsMappedObject> open_ql_file(std::string_view vpath, int flags, int mode);

    // open(vpath, mode) — the Python builtins.open analogue
    std::shared_ptr<QlFsMappedObject> open(std::string_view vpath, std::string_view mode);

    // file_exists — mapping present, or the host path exists
    bool file_exists(std::string_view vpath) const;

    // create_empty_file — returns false when the file could not be created
    bool create_empty_file(std::string_view vpath);

    // add_mapping(vpath, binding, force) — QlErrorBase on duplicate (the
    // Python KeyError analogue)
    void add_mapping(std::string_view vpath, QlFsBinding binding, bool force = false);

    // remove_mapping — QlErrorBase when the vpath has no mapping (KeyError)
    void remove_mapping(std::string_view vpath);

    // rename_mapping — QlErrorBase on a missing source or an existing target
    void rename_mapping(std::string_view old_vpath, std::string_view new_vpath);

private:
    // __open_mapped / __open_new dispatch
    std::shared_ptr<QlFsMappedObject> open_mapped(std::string_view absvpath, const std::string& mode);
    std::shared_ptr<QlFsMappedObject> open_new(std::string_view absvpath, const std::string& mode);

    std::map<std::string, QlFsBinding, std::less<>> mapping_;
    const QlOsPath* path_;
};

}  // namespace qiling

#endif  // QILING_OS_MAPPER_HPP
