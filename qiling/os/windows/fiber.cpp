#include "qiling/os/windows/fiber.hpp"

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace os {
namespace windows {

std::uint64_t FiberManager::alloc(std::optional<std::uint64_t> cb) {
    const auto idx = idx_;
    ++idx_;

    fibers_.emplace(idx, Fiber(idx, cb));
    return idx;
}

bool FiberManager::free(std::uint64_t idx) {
    const auto it = fibers_.find(idx);
    if (it == fibers_.end()) {
        last_error_ = QL_ERROR_INVALID_PARAMETER;
        if (ql_ != nullptr) {
            ql_->os().set_last_error(static_cast<int>(QL_ERROR_INVALID_PARAMETER));
        }
        return false;
    }

    // fiber.py free: the fiber callback invocation stays skipped (the <SKIP>
    // block, verbatim rationale: diverting the flow inside an api hook cannot
    // resume the surrounding hook without ending the emulation session)

    fibers_.erase(it);
    return true;
}

bool FiberManager::set(std::uint64_t idx, std::uint64_t data) {
    const auto it = fibers_.find(idx);
    if (it == fibers_.end()) {
        last_error_ = QL_ERROR_INVALID_PARAMETER;
        if (ql_ != nullptr) {
            ql_->os().set_last_error(static_cast<int>(QL_ERROR_INVALID_PARAMETER));
        }
        return false;
    }

    it->second.set_data(data);
    return true;
}

std::uint64_t FiberManager::get(std::uint64_t idx) {
    const auto it = fibers_.find(idx);
    if (it == fibers_.end()) {
        last_error_ = QL_ERROR_INVALID_PARAMETER;
        if (ql_ != nullptr) {
            ql_->os().set_last_error(static_cast<int>(QL_ERROR_INVALID_PARAMETER));
        }
        return 0;
    }

    return it->second.data();
}

std::uint64_t FiberManager::get_noerr(std::uint64_t idx) const {
    // fiber.py get_noerr: the silent variant (FlsGetValue2)
    const auto it = fibers_.find(idx);
    return it == fibers_.end() ? 0 : it->second.data();
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
