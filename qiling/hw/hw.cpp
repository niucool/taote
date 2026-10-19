#include "qiling/hw/hw.hpp"
#include "qiling/hw/cm_nvic.hpp"
#include "qiling/hw/cm_scb.hpp"
#include "qiling/hw/cm_systick.hpp"
#include "qiling/hw/stm32f1xx_gpio.hpp"
#include "qiling/hw/stm32f4xx_usart.hpp"
#include "qiling/hw/stm32f4xx_tim.hpp"
#include "qiling/hw/stm32f1xx_exti.hpp"
#include "qiling/hw/stm32f1xx_simple.hpp"

#include <algorithm>
#include <map>

namespace qiling {
namespace hw {

QlHwManager::QlHwManager(Qiling& ql) : ql_(&ql) {
    // the built-in struct factories (the upstream rides the dynamic
    // ql_get_module_function('qiling.hw', struct) import over the qiling.hw
    // package; the port registers the ported peripherals at construction)
    register_struct("cm3_systick", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<CortexMSysTick>(q, label);
    });
    register_struct("cm_nvic", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<CortexMNvic>(q, label);
    });
    register_struct("cm4_scb", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<CortexM4Scb>(q, label);
    });
    register_struct("STM32F1xxGpio", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<STM32F1xxGpio>(q, label);
    });
    register_struct("STM32F1xxAfio", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<STM32F1xxAfio>(q, label);
    });
    register_struct("STM32F1xxUsart", [](Qiling& q, const std::string& label, const PeripheralKwargs& kwargs) {
        std::int64_t intn = -1;
        const auto it = kwargs.find("intn");
        if (it != kwargs.end()) {
            intn = static_cast<std::int64_t>(it->second);
        }
        return std::make_unique<STM32F1xxUsart>(q, label, intn);
    });
    register_struct("STM32F4xxTim", [](Qiling& q, const std::string& label, const PeripheralKwargs& kwargs) {
        auto intn_of = [&kwargs](const char* key) {
            const auto it = kwargs.find(key);
            return it == kwargs.end() ? -1 : static_cast<std::int64_t>(it->second);
        };
        return std::make_unique<STM32F4xxTim>(q, label, intn_of("intn"), intn_of("brk_intn"),
                                              intn_of("cc_intn"), intn_of("trg_com_intn"), intn_of("up_intn"));
    });
    register_struct("STM32F1xxTim", [](Qiling& q, const std::string& label, const PeripheralKwargs& kwargs) {
        auto intn_of = [&kwargs](const char* key) {
            const auto it = kwargs.find(key);
            return it == kwargs.end() ? -1 : static_cast<std::int64_t>(it->second);
        };
        return std::make_unique<STM32F1xxTim>(q, label, intn_of("intn"), intn_of("brk_intn"),
                                              intn_of("cc_intn"), intn_of("trg_com_intn"), intn_of("up_intn"));
    });
    register_struct("STM32F1xxRcc", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<STM32F1xxRcc>(q, label);
    });
    register_struct("STM32F1xxFlash", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<STM32F1xxFlash>(q, label);
    });
    register_struct("STM32F1xxAdc", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<STM32F1xxAdc>(q, label);
    });
    register_struct("STM32F1xxSpi", [](Qiling& q, const std::string& label, const PeripheralKwargs&) {
        return std::make_unique<STM32F1xxSpi>(q, label);
    });
    register_struct("CortexMBitband", [](Qiling& q, const std::string& label, const PeripheralKwargs& kwargs) {
        const auto base = kwargs.find("base");
        const auto size = kwargs.find("size");
        return std::make_unique<CortexMBitband>(q, label, base == kwargs.end() ? 0 : base->second,
                                                size == kwargs.end() ? 0 : size->second);
    });
    register_struct("MemoryRemap", [](Qiling& q, const std::string& label, const PeripheralKwargs& kwargs) {
        const auto base = kwargs.find("base");
        const auto size = kwargs.find("size");
        return std::make_unique<MemoryRemap>(q, label, base == kwargs.end() ? 0 : base->second,
                                             size == kwargs.end() ? 0 : size->second);
    });
    register_struct("STM32F1xxExti", [](Qiling& q, const std::string& label, const PeripheralKwargs& kwargs) {
        auto exti = std::make_unique<STM32F1xxExti>(q, label);
        const auto intn_of = [&kwargs](const char* key) {
            const auto it = kwargs.find(key);
            return it == kwargs.end() ? -1 : static_cast<std::int64_t>(it->second);
        };
        for (int line = 0; line <= 4; ++line) {
            const auto key = "exti" + std::to_string(line) + "_intn";
            exti->set_line_intn(line, intn_of(key.c_str()));
        }
        exti->set_shared_intn(intn_of("exti9_5_intn"), intn_of("exti15_10_intn"));
        return exti;
    });
}

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
                                  std::uint64_t base, const PeripheralKwargs& kwargs) {
    const auto it = factories_.find(struct_name);
    if (it == factories_.end()) {
        // the upstream's QlErrorModuleFunctionNotFound catch: the warn +
        // the null (the FIXME verbatim — the create may return null)
        return nullptr;
    }

    auto entity = it->second(*ql_, label, kwargs);
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
