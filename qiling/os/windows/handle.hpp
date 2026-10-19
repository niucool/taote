// Ported from qiling/os/windows/handle.py — the Windows handle simulation
// (PORT_PLAN.md §10 Phase 4). The pre-bound registry hive and stdio handle ids
// come from os/windows/const.py.
#ifndef QILING_OS_WINDOWS_HANDLE_HPP
#define QILING_OS_WINDOWS_HANDLE_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace qiling {
namespace os {

// os/windows/const.py: the standard handle ids
inline constexpr std::uint32_t QL_STD_INPUT_HANDLE = 0xfffffff6;   // -10
inline constexpr std::uint32_t QL_STD_OUTPUT_HANDLE = 0xfffffff5;  // -11
inline constexpr std::uint32_t QL_STD_ERROR_HANDLE = 0xfffffff4;   // -12

class Handle {
public:
    // handle.py: the id allocator base
    static constexpr std::uint32_t ID_BASE = 0xa0000000;

    std::uint64_t id = 0;
    void* obj = nullptr;
    std::string name;
    std::optional<std::uint32_t> permissions;

    // the type-erased ownership slot (filestruct.py: the python Handle keeps
    // the python object alive via the reference; the C++ port type-erases the
    // shared_ptr so the mapped file outlives the mapper call)
    std::shared_ptr<void> owned;

    // the ids widen to u64: the python Handle(id=...) rides arbitrary ints
    // (the MapViewOfFile passes the heap address; the registry hive ids stay
    // the u32 spellings)
    explicit Handle(std::optional<std::uint64_t> id_ = std::nullopt, void* obj_ = nullptr,
                    std::string name_ = {}, std::optional<std::uint32_t> perms = std::nullopt)
        : id(next_id(id_)), obj(obj_), name(std::move(name_)), permissions(std::move(perms)) {}

private:
    static std::uint64_t next_id(std::optional<std::uint64_t> requested) {
        static std::uint64_t counter = ID_BASE;
        if (requested.has_value()) {
            return *requested;
        }
        const auto id = counter;
        ++counter;
        return id;
    }
};

class HandleManager {
public:
    // handle.py: the pre-bound stdio + registry hive handles
    inline static const Handle STDIN{QL_STD_INPUT_HANDLE};
    inline static const Handle STDOUT{QL_STD_OUTPUT_HANDLE};
    inline static const Handle STDERR{QL_STD_ERROR_HANDLE};

    HandleManager();

    void append(Handle handle);
    Handle* get(std::uint64_t id);
    void delete_handle(std::uint64_t id);
    Handle* search(const std::string& name);
    Handle* search_by_obj(void* obj);

private:
    std::map<std::uint64_t, Handle> handles_;
};

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_HANDLE_HPP
