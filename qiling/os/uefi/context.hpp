// os/uefi/context.py — the uefi execution contexts (the DXE and the SMM)
//
// The port slice 1 carries the context shell: the heap, the stack, the
// protocol installation registry and the configuration-table data cursors.
// The conftable walker (UefiConfTable) lands with the service-table slice;
// the SMM-specific pieces (the smram bounds, the swsmi handlers) land with
// the SMM slice.

#pragma once

#include <map>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"

namespace qiling {
namespace os {
namespace uefi {

// ProcessorBind.py CPU_STACK_ALIGNMENT
inline constexpr std::uint64_t CPU_STACK_ALIGNMENT = 16;
inline constexpr std::uint64_t PAGE_SIZE = 0x1000;

class UefiContext {
public:
    explicit UefiContext(Qiling* ql) : ql_(ql) {}
    virtual ~UefiContext() = default;

    // context.py init_heap / init_stack
    void init_heap(std::uint64_t base, std::uint64_t size);
    void init_stack(std::uint64_t base, std::uint64_t size);

    // context.py install_protocol: the (handle, guid) -> struct-address
    // registry; the struct instance write + the notify ride the service
    // slices
    void install_protocol(std::string_view guid, std::uint64_t handle, std::uint64_t address);
    bool has_protocol(std::string_view guid, std::uint64_t handle) const;

    // ---- the state the loader and the services share ----

    std::unique_ptr<QlMemoryHeap> heap;
    std::uint64_t top_of_stack = 0;
    std::map<std::uint64_t, std::map<std::string, std::uint64_t>> protocols;
    std::vector<std::uint64_t> loaded_image_protocol_modules;
    std::uint64_t next_image_base = 0;
    std::uint64_t conf_table_data_ptr = 0;
    std::uint64_t conf_table_data_next_ptr = 0;
    std::uint64_t end_of_execution_ptr = 0;

protected:
    Qiling* ql_;
};

class DxeContext : public UefiContext {
public:
    explicit DxeContext(Qiling* ql) : UefiContext(ql) {}
};

class SmmContext : public UefiContext {
public:
    explicit SmmContext(Qiling* ql) : UefiContext(ql) {}

    std::uint64_t smram_base = 0;
    std::uint64_t smram_size = 0;
};

}  // namespace uefi
}  // namespace os
}  // namespace qiling
