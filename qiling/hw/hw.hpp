// Ported from qiling/hw/hw.py (QlPripheralHandler + QlHwManager). The
// handler rides the port's QlMmioHandler surface (the memory.mmio hook walk
// already ported in os/memory) — the find-or-buffer read/write dispatch is
// the verbatim QlPripheralHandler shape.
#pragma once

#include "qiling/hw/peripheral.hpp"

#include <memory>
#include <unordered_map>

namespace qiling {
namespace hw {

// hw.py QlPripheralHandler — the MMIO trampoline between the uc mmio access
// and the peripheral registry (the non-mapped offsets ride the handler's own
// byte buffer, the verbatim _mmio walk)
class QlPripheralHandler : public QlMmioHandler {
public:
    QlPripheralHandler(QlHwManager& hwman, std::uint64_t base, std::uint64_t size, std::string label);

    bool has_read() const noexcept override { return true; }
    bool has_write() const noexcept override { return true; }

    std::uint64_t read(std::uint64_t offset, std::uint32_t size) override;
    void write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;

private:
    QlHwManager* hwman_;
    std::uint64_t base_;
    std::uint64_t size_;
    std::string label_;
    std::vector<std::uint8_t> mmio_;  // the non-mapped backing buffer
};

// hw.py QlHwManager — the peripheral registry + the MMIO wiring
class QlHwManager {
public:
    explicit QlHwManager(Qiling& ql) : ql_(&ql) {}

    Qiling& ql() noexcept { return *ql_; }

    // the peripheral factory: the concrete struct is resolved by the
    // registered name (the upstream's ql_get_module_function('qiling.hw',
    // struct) ride)
    using PeripheralFactory = std::function<std::unique_ptr<QlPeripheral>(Qiling&, const std::string& label)>;

    void register_struct(const std::string& struct_name, PeripheralFactory factory) {
        factories_.insert_or_assign(struct_name, std::move(factory));
    }

    // create: the struct name resolves through the factory registry (the
    // upstream's dynamic import walk); the base defaults ride the
    // struct-registered defaults upstream — the port carries the explicit
    // base (the env-driven load_env defers with the env-dict machinery)
    QlPeripheral* create(const std::string& label, const std::string& struct_name, std::uint64_t base);
    void destroy(const std::string& label);

    // find: the peripheral owning the address, or nullptr
    QlPeripheral* find(std::uint64_t address) const;

    // step: the peripheral state updates (the hasattr(ent, 'step') walk)
    void step();

    // setup_mmio: the MMIO region wired to the handler (the memory.map_mmio
    // ride); the handler owns the region until the manager dies
    void setup_mmio(std::uint64_t begin, std::uint64_t size, const std::string& info);

    const std::unordered_map<std::string, std::unique_ptr<QlPeripheral>>& entities() const noexcept {
        return entity_;
    }

    // the region lookup (the peripheral.py base property rides this)
    std::uint64_t region_base(const std::string& label) const;

private:
    friend class QlPripheralHandler;

    Qiling* ql_;
    std::unordered_map<std::string, std::unique_ptr<QlPeripheral>> entity_;
    std::unordered_map<std::string, std::vector<std::pair<std::uint64_t, std::uint64_t>>> region_;
    std::unordered_map<std::string, PeripheralFactory> factories_;
    std::vector<std::unique_ptr<QlPripheralHandler>> mmio_handlers_;
};

}  // namespace hw
}  // namespace qiling
