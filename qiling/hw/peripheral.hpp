// Ported from qiling/hw/peripheral.py (QlPeripheralUtils + QlPeripheral) and
// hw/utils/access.py (Action/Access). The read/write hook walk (the
// monitor-decorator shape: the ENTER/CALL/EXIT intercepts around the body,
// the CALL replacing the body) rides the base class; the subclass bodies
// override read_body/write_body where the upstream subclasses override the
// monitor-decorated read/write.
#pragma once

#include "qiling/core.hpp"

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace qiling {
namespace hw {

// hw/utils/access.py
enum class PeripheralAction { READ = 0, WRITE = 1 };

class Access {
public:
    Access(PeripheralAction action, std::uint64_t offset, std::uint64_t value = 0)
        : action_(action), offset_(offset), value_(value) {}

    PeripheralAction action() const noexcept { return action_; }
    std::uint64_t offset() const noexcept { return offset_; }
    std::uint64_t value() const noexcept { return value_; }

    // the verbatim __eq__: the action + the offset decide; the value only
    // participates on the writes
    bool operator==(const Access& o) const noexcept {
        if (action_ != o.action_ || offset_ != o.offset_) {
            return false;
        }
        return action_ == PeripheralAction::READ || value_ == o.value_;
    }

private:
    PeripheralAction action_;
    std::uint64_t offset_;
    std::uint64_t value_;
};

// the access-sequence ring (the recorder's history)
class AccessSequence {
public:
    explicit AccessSequence(std::size_t maxlen = 2) : maxlen_(maxlen) {}

    void add(const Access& access) {
        deque_.push_back(access);
        while (deque_.size() > maxlen_) {
            deque_.pop_front();
        }
    }

    const std::deque<Access>& items() const noexcept { return deque_; }

private:
    std::deque<Access> deque_;
    std::size_t maxlen_;
};

// the hook callback: (port, action, offset, size, value) — the user_data
// rides the registration lambda capture (the upstream's hook_function pair)
using PeripheralHookCallback = std::function<std::int64_t(
    class QlPeripheral&, PeripheralAction, std::uint64_t, std::uint32_t, std::uint64_t)>;

// peripheral.py QlPeripheralUtils — the hook intercept walk
class QlPeripheralUtils {
public:
    enum class Intercept { ENTER = 0, CALL = 1, EXIT = 2 };

    struct HookHandle {
        bool is_read = false;
        Intercept intercept = Intercept::ENTER;
        PeripheralHookCallback callback;
    };

    void watch() { verbose_ = true; }
    bool verbose() const noexcept { return verbose_; }

    HookHandle hook_read(PeripheralHookCallback callback, Intercept intercept = Intercept::ENTER) {
        HookHandle handle{true, intercept, std::move(callback)};
        user_read_.at(static_cast<int>(intercept)).push_back(handle);
        return handle;
    }

    HookHandle hook_write(PeripheralHookCallback callback, Intercept intercept = Intercept::ENTER) {
        HookHandle handle{false, intercept, std::move(callback)};
        user_write_.at(static_cast<int>(intercept)).push_back(handle);
        return handle;
    }

    void hook_del(const HookHandle& handle) {
        auto& mapper = handle.is_read ? user_read_ : user_write_;
        auto& list = mapper.at(static_cast<int>(handle.intercept));
        for (auto it = list.begin(); it != list.end(); ++it) {
            if (&*it == &handle) {
                list.erase(it);
                return;
            }
        }
    }

protected:
    // the _hook_call walk: the last callback's retval rides (the verbatim
    // "retval = callback(...)" over-write). The callback receives the
    // peripheral reference — the CRTP-style down-cast from the utils base.
    template <typename Peripheral>
    std::optional<std::int64_t> hook_call(const std::vector<HookHandle>& list, PeripheralAction action,
                                          std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        std::optional<std::int64_t> retval;
        for (const auto& handle : list) {
            retval = handle.callback(*static_cast<Peripheral*>(this), action, offset, size, value);
        }
        return retval;
    }

    bool verbose_ = false;
    std::array<std::vector<HookHandle>, 3> user_read_{};
    std::array<std::vector<HookHandle>, 3> user_write_{};
};

// peripheral.py QlPeripheral — the instance bytes back the register state.
// The Type structure (the upstream ctypes struct) rides as the concrete
// subclass's struct_size + the named-field offsets.
class QlPeripheral : public QlPeripheralUtils {
public:
    QlPeripheral(Qiling& ql, std::string label, std::size_t image_size)
        : ql_(&ql), label_(std::move(label)), instance_(image_size, 0) {}

    virtual ~QlPeripheral() = default;

    friend class QlHwManager;

    const std::string& label() const noexcept { return label_; }
    Qiling& ql() noexcept { return *ql_; }

    // the register-image size (the upstream ctypes.sizeof(self.struct)) —
    // the size rides the ctor (the base-ctor virtual dispatch cannot see
    // the override yet); the virtual stays for the region/size queries
    std::size_t struct_size() const noexcept { return instance_.size(); }

    // the memory intervals the peripheral occupies relative to its base
    // (the verbatim region: [(0, sizeof(struct))])
    virtual std::vector<std::pair<std::uint64_t, std::uint64_t>> region() const {
        return {{0, struct_size()}};
    }

    std::uint64_t size() const {
        std::uint64_t total = 0;
        for (const auto& [lbound, rbound] : region()) {
            total += rbound - lbound;
        }
        return total;
    }

    // the base address (assigned by the manager at the create — the
    // upstream's region-map-backed base property rides the same value)
    std::uint64_t base() const noexcept { return base_; }

    // the per-slice state update (the upstream's hasattr(ent, 'step') walk
    // rides the virtual default no-op)
    // the raw instance access (the ctypes memmove pair)
    std::uint64_t raw_read(std::uint64_t offset, std::uint32_t size) const {
        std::uint64_t out = 0;
        std::memcpy(&out, instance_.data() + offset, std::min<std::size_t>(size, sizeof(out)));
        return out;
    }

    void raw_write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        const auto bytes = std::min<std::size_t>(size, sizeof(value));
        std::memcpy(instance_.data() + offset, &value, bytes);
    }

    // the monitor-decorated read/write: the ENTER/CALL/EXIT walks around the
    // body; the CALL intercept replaces the body (the decorator's if/else)
    std::uint64_t read(std::uint64_t offset, std::uint32_t size) {
        hook_call<QlPeripheral>(user_read_[static_cast<int>(Intercept::ENTER)], PeripheralAction::READ, offset, size, 0);

        std::uint64_t retval = 0;
        if (!user_read_[static_cast<int>(Intercept::CALL)].empty()) {
            const auto result = hook_call<QlPeripheral>(user_read_[static_cast<int>(Intercept::CALL)],
                                          PeripheralAction::READ, offset, size, 0);
            if (result.has_value()) {
                retval = static_cast<std::uint64_t>(*result);
            }
        } else {
            retval = read_body(offset, size);
        }

        hook_call<QlPeripheral>(user_read_[static_cast<int>(Intercept::EXIT)], PeripheralAction::READ, offset, size, 0);
        return retval;
    }

    void write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        hook_call<QlPeripheral>(user_write_[static_cast<int>(Intercept::ENTER)], PeripheralAction::WRITE, offset, size, value);

        if (!user_write_[static_cast<int>(Intercept::CALL)].empty()) {
            hook_call<QlPeripheral>(user_write_[static_cast<int>(Intercept::CALL)], PeripheralAction::WRITE, offset, size, value);
        } else {
            write_body(offset, size, value);
        }

        hook_call<QlPeripheral>(user_write_[static_cast<int>(Intercept::EXIT)], PeripheralAction::WRITE, offset, size, value);
    }

    // the monitor-wrapped bodies (the upstream's decorated read/write)
    virtual std::uint64_t read_body(std::uint64_t offset, std::uint32_t size) {
        return raw_read(offset, size);
    }

    virtual void write_body(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
        raw_write(offset, size, value);
    }

    // the per-slice state update (the upstream's hasattr(ent, 'step') walk
    // rides the virtual default no-op)
    virtual void step() {}

    // the snapshot pair (the verbatim save/restore over the instance bytes)
    std::vector<std::uint8_t> save() const { return instance_; }

    void restore(const std::vector<std::uint8_t>& data) {
        instance_.assign(data.begin(), data.end());
    }

protected:
    Qiling* ql_;
    std::string label_;
    std::vector<std::uint8_t> instance_;
    std::uint64_t base_ = 0;
};

}  // namespace hw
}  // namespace qiling
