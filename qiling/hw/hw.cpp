#include "qiling/hw/hw.hpp"

#include <algorithm>

namespace qiling {
namespace hw {

QlPripheralHandler::QlPripheralHandler(QlHwManager& hwman, std::uint64_t base, std::uint64_t size,
                                       std::string label)
    : hwman_(&hwman), base_(base), size_(size), label_(std::move(label)) {
    // the non-mapped backing buffer (the cached _mmio bytearray, lazily
    // grown on the first use upstream — allocated here at the region size)
    mmio_.assign(static_cast<std::size_t>(size), 0);
}

std::uint64_t QlPripheralHandler::read(std::uint64_t offset, std::uint32_t size) {
    const std::uint64_t address = base_ + offset;

    if (auto* hardware = hwman_->find(address)) {
        return hardware->read(address - hardware->base(), size);
    }

    // the non-mapped hardware read (the debug-log branch verbatim): the
    // backing buffer bytes
    std::uint64_t out = 0;
    const auto bytes = std::min<std::size_t>(size, sizeof(out));
    if (offset + bytes <= mmio_.size()) {
        std::memcpy(&out, mmio_.data() + offset, bytes);
    }
    return out;
}

void QlPripheralHandler::write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    const std::uint64_t address = base_ + offset;

    if (auto* hardware = hwman_->find(address)) {
        hardware->write(address - hardware->base(), size, value);
        return;
    }

    if (offset < mmio_.size()) {
        const auto bytes = std::min<std::size_t>(size, mmio_.size() - offset);
        std::memcpy(mmio_.data() + offset, &value, std::min<std::size_t>(bytes, sizeof(value)));
    }
}

QlPeripheral* QlHwManager::create(const std::string& label, const std::string& struct_name,
                                  std::uint64_t base) {
    const auto it = factories_.find(struct_name);
    if (it == factories_.end()) {
        // the upstream's QlErrorModuleFunctionNotFound catch: the warn +
        // the null (the FIXME verbatim — the create may return null)
        return nullptr;
    }

    auto entity = it->second(*ql_, label);
    entity->base_ = base;  // the manager-assigned base (the upstream rides
                           // the base property over the region map)

    auto* raw = entity.get();
    entity_[label] = std::move(entity);
    region_[label].reserve(raw->region().size());
    for (const auto& [lbound, rbound] : raw->region()) {
        region_[label].emplace_back(lbound + base, rbound + base);
    }
    return raw;
}

void QlHwManager::destroy(const std::string& label) {
    entity_.erase(label);
    region_.erase(label);
}

QlPeripheral* QlHwManager::find(std::uint64_t address) const {
    for (const auto& [label, regions] : region_) {
        for (const auto& [lbound, rbound] : regions) {
            if (lbound <= address && address < rbound) {
                return entity_.at(label).get();
            }
        }
    }
    return nullptr;
}

void QlHwManager::step() {
    for (auto& [label, entity] : entity_) {
        entity->step();
    }
}

void QlHwManager::setup_mmio(std::uint64_t begin, std::uint64_t size, const std::string& info) {
    mmio_handlers_.push_back(std::make_unique<QlPripheralHandler>(*this, begin, size, info));
    ql_->mem().map_mmio(begin, size, *mmio_handlers_.back(), info);
}

std::uint64_t QlHwManager::region_base(const std::string& label) const {
    const auto it = region_.find(label);
    if (it == region_.end() || it->second.empty()) {
        return 0;
    }
    return it->second.front().first;
}

}  // namespace hw
}  // namespace qiling
