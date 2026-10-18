// Ported from qiling/hw/gpio/hooks.py (GpioHooks). The per-pin set/reset
// hook table (16 pins by default); the upstream stores (func, args, kwargs)
// tuples — the port rides std::function captures (the deviation noted).
#pragma once

#ifndef QILING_HW_GPIO_HOOKS_HPP
#define QILING_HW_GPIO_HOOKS_HPP

#include <functional>
#include <vector>

namespace qiling {
namespace hw {

class GpioHooks {
public:
    using HookFunc = std::function<void()>;

    // hooks.py GpioHooks.__init__(ql, pin_num) — the ql rides the captures
    explicit GpioHooks(std::size_t pin_num = 16)
        : hook_set_func_(pin_num), hook_reset_func_(pin_num) {}

    void hook_set(std::size_t pin, HookFunc func) {
        hook_set_func_.at(pin) = std::move(func);
    }

    void hook_reset(std::size_t pin, HookFunc func) {
        hook_reset_func_.at(pin) = std::move(func);
    }

    void hook_del_set(std::size_t pin) {
        hook_set_func_.at(pin) = nullptr;
    }

    void hook_del_reset(std::size_t pin) {
        hook_reset_func_.at(pin) = nullptr;
    }

    void call_hook_set(std::size_t pin) {
        if (pin < hook_set_func_.size() && hook_set_func_[pin]) {
            hook_set_func_[pin]();
        }
    }

    void call_hook_reset(std::size_t pin) {
        if (pin < hook_reset_func_.size() && hook_reset_func_[pin]) {
            hook_reset_func_[pin]();
        }
    }

protected:
    std::vector<HookFunc> hook_set_func_;
    std::vector<HookFunc> hook_reset_func_;
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_GPIO_HOOKS_HPP
