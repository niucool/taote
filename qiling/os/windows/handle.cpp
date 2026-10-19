#include "qiling/os/windows/handle.hpp"

namespace qiling {
namespace os {

HandleManager::HandleManager() {
    // handle.py __init__: the standard io streams and the registry hives
    append(Handle(QL_STD_INPUT_HANDLE));
    append(Handle(QL_STD_OUTPUT_HANDLE));
    append(Handle(QL_STD_ERROR_HANDLE));

    append(Handle(0x80000000, nullptr, "HKEY_CLASSES_ROOT"));
    append(Handle(0x80000001, nullptr, "HKEY_CURRENT_USER"));
    append(Handle(0x80000002, nullptr, "HKEY_LOCAL_MACHINE"));
    append(Handle(0x80000003, nullptr, "HKEY_USERS"));
    append(Handle(0x80000004, nullptr, "HKEY_PERFORMANCE_DATA"));
    append(Handle(0x80000005, nullptr, "HKEY_CURRENT_CONFIG"));
    append(Handle(0x80000007, nullptr, "HKEY_CURRENT_USER_LOCAL_SETTINGS"));
    append(Handle(0x80000060, nullptr, "HKEY_PERFORMANCE_NLSTEXT"));
    append(Handle(0x80000050, nullptr, "HKEY_PERFORMANCE_TEXT"));
}

void HandleManager::append(Handle handle) {
    handles_[handle.id] = std::move(handle);
}

Handle* HandleManager::get(std::uint64_t id) {
    const auto it = handles_.find(id);
    return it == handles_.end() ? nullptr : &it->second;
}

void HandleManager::delete_handle(std::uint64_t id) {
    handles_.erase(id);
}

Handle* HandleManager::search(const std::string& name) {
    for (auto& [_, handle] : handles_) {
        if (handle.name == name) {
            return &handle;
        }
    }
    return nullptr;
}

Handle* HandleManager::search_by_obj(void* obj) {
    for (auto& [_, handle] : handles_) {
        if (handle.obj == obj) {
            return &handle;
        }
    }
    return nullptr;
}

}  // namespace os
}  // namespace qiling
