// Ported from qiling/hw/connectivity.py (PeripheralTube +
// QlConnectivityPeripheral). The byte tube pairs (the itube feeds the
// peripheral input, the otube collects the peripheral output) ride the
// std::deque; the save/restore snapshots the tube queues verbatim.
#pragma once

#ifndef QILING_HW_CONNECTIVITY_HPP
#define QILING_HW_CONNECTIVITY_HPP

#include "qiling/hw/peripheral.hpp"

#include <cstring>
#include <deque>
#include <string>
#include <vector>

namespace qiling {
namespace hw {

// connectivity.py PeripheralTube — the byte queue (the queue.Queue over the
// single bytes; readable = the non-empty, read drains up to numb)
class PeripheralTube {
public:
    bool readable() const noexcept { return !data_.empty(); }

    std::vector<std::uint8_t> read(std::size_t numb = 4096) {
        std::vector<std::uint8_t> out;
        while (out.size() < numb && !data_.empty()) {
            out.push_back(data_.front());
            data_.pop_front();
        }
        return out;
    }

    void write(const std::vector<std::uint8_t>& bytes) {
        data_.insert(data_.end(), bytes.begin(), bytes.end());
    }

    // connectivity.py save: drain-then-refill (the queue survives the
    // snapshot round trip)
    std::vector<std::uint8_t> save() {
        const auto bytes = read(0xffffffffu);
        write(bytes);
        return bytes;
    }

    void restore(const std::vector<std::uint8_t>& bytes) {
        data_.clear();
        write(bytes);
    }

    // the single-byte walk (the put/get pair the usart bodies ride)
    void put(std::uint8_t byte) { data_.push_back(byte); }

    std::uint8_t get() {
        const auto byte = data_.front();
        data_.pop_front();
        return byte;
    }

private:
    std::deque<std::uint8_t> data_;
};

// connectivity.py QlConnectivityPeripheral — the tube-paired peripheral base
class QlConnectivityPeripheral : public QlPeripheral {
public:
    QlConnectivityPeripheral(Qiling& ql, const std::string& label, std::size_t image_size, std::size_t limit = 1)
        : QlPeripheral(ql, std::move(label), image_size), limit_(limit) {}

    // connectivity.py has_input / send / recv / send_to_user / recv_from_user
    bool has_input() const { return itube_.readable(); }

    void send(const std::vector<std::uint8_t>& data) { itube_.write(data); }

    std::vector<std::uint8_t> recv(std::size_t numb = 4096) { return otube_.read(numb); }

    void send_to_user(std::uint64_t data) { otube_.put(static_cast<std::uint8_t>(data)); }

    std::uint8_t recv_from_user() { return itube_.get(); }

    // connectivity.py connect / device_list — the connected-device walk (the
    // device_handler decorator rides the QlConnectivityPeripheral subclasses
    // that expose the step; the port keeps the device list for the chardev
    // bridge slice)
    void connect(QlPeripheral* device) {
        if (device_list_.size() < limit_) {
            device_list_.push_back(device);
        }
    }

    // connectivity.py device_handler — the decorator's pre-walk: the otube
    // byte forwards to every connected device and the devices step before
    // the subclass body runs (the C++ rides the explicit pre-walk call at
    // the top of the decorated steps)
    void device_handler_prewalk() {
        if (!device_list_.empty()) {
            if (otube_.readable()) {
                const auto data = otube_.read(1);
                for (auto* device : device_list_) {
                    if (auto* conn = dynamic_cast<QlConnectivityPeripheral*>(device)) {
                        conn->send(data);
                    }
                }
            }
            for (auto* device : device_list_) {
                device->step();
            }
        }
    }

    const std::vector<QlPeripheral*>& device_list() const noexcept { return device_list_; }

    PeripheralTube& itube() noexcept { return itube_; }
    PeripheralTube& otube() noexcept { return otube_; }

    // connectivity.py save: (itube, otube, instance bytes) — the triple rides
    // the concatenated snapshot (the tube byte counts prefixed)
    std::vector<std::uint8_t> save() const override {
        std::vector<std::uint8_t> out;
        const auto append_with_size = [&out](const std::vector<std::uint8_t>& bytes) {
            const std::uint32_t n = static_cast<std::uint32_t>(bytes.size());
            out.insert(out.end(), reinterpret_cast<const std::uint8_t*>(&n),
                       reinterpret_cast<const std::uint8_t*>(&n) + sizeof(n));
            out.insert(out.end(), bytes.begin(), bytes.end());
        };
        append_with_size(const_cast<QlConnectivityPeripheral*>(this)->itube_.save());
        append_with_size(const_cast<QlConnectivityPeripheral*>(this)->otube_.save());
        out.insert(out.end(), instance_.begin(), instance_.end());
        return out;
    }

    void restore(const std::vector<std::uint8_t>& data) override {
        std::size_t at = 0;
        const auto take_with_size = [&at, &data](PeripheralTube& tube) {
            std::uint32_t n = 0;
            if (at + sizeof(n) > data.size()) {
                throw QlErrorBase("connectivity snapshot too short");
            }
            std::memcpy(&n, data.data() + at, sizeof(n));
            at += sizeof(n);
            if (at + n > data.size()) {
                throw QlErrorBase("connectivity snapshot too short");
            }
            tube.restore(std::vector<std::uint8_t>(data.begin() + at, data.begin() + at + n));
            at += n;
        };
        take_with_size(itube_);
        take_with_size(otube_);
        instance_.assign(data.begin() + at, data.end());
    }

protected:
    PeripheralTube itube_;
    PeripheralTube otube_;
    std::size_t limit_;
    std::vector<QlPeripheral*> device_list_;
};

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_CONNECTIVITY_HPP
