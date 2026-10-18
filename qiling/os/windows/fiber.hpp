// Ported from qiling/os/windows/fiber.py — the fiber table (Fiber/FiberManager).
// The callback-invoking branch of `free` stays skipped exactly as the Python
// source does (the <SKIP> block, verbatim rationale).
#ifndef QILING_OS_WINDOWS_FIBER_HPP
#define QILING_OS_WINDOWS_FIBER_HPP

#include <cstdint>
#include <map>
#include <optional>

#include "qiling/os/windows/clipboard.hpp"  // QL_ERROR_INVALID_PARAMETER

namespace qiling {

class Qiling;

namespace os {
namespace windows {

class Fiber {
public:
    Fiber(std::uint64_t idx, std::optional<std::uint64_t> cb = std::nullopt)
        : idx_(idx), cb_(cb) {}

    std::uint64_t idx() const noexcept { return idx_; }
    std::optional<std::uint64_t> callback() const noexcept { return cb_; }
    std::uint64_t data() const noexcept { return data_; }
    void set_data(std::uint64_t value) noexcept { data_ = value; }

private:
    std::uint64_t idx_;
    std::optional<std::uint64_t> cb_;
    std::uint64_t data_ = 0;
};

class FiberManager {
public:
    explicit FiberManager(Qiling* ql) : ql_(ql) {}

    // alloc: create a fiber (optionally with an entry callback)
    std::uint64_t alloc(std::optional<std::uint64_t> cb = std::nullopt);

    // free: remove the fiber (the callback invocation stays skipped — the
    // fiber.py <SKIP> note, verbatim)
    bool free(std::uint64_t idx);

    // set/get the fiber-local data
    bool set(std::uint64_t idx, std::uint64_t data);
    std::uint64_t get(std::uint64_t idx);
    std::uint64_t get_noerr(std::uint64_t idx) const;

    std::size_t size() const noexcept { return fibers_.size(); }

    // the last error surface (os.py last_error)
    std::uint32_t last_error() const noexcept { return last_error_; }
    void clear_last_error() noexcept { last_error_ = 0; }

private:
    std::map<std::uint64_t, Fiber> fibers_;
    std::uint64_t idx_ = 0;
    std::uint32_t last_error_ = 0;
    Qiling* ql_ = nullptr;
};

}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_FIBER_HPP
