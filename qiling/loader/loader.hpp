// Ported from qiling/loader/loader.py — QlLoader base (PORT_PLAN.md §10 Phase 3).
// The per-format loaders (pe/elf/macho/dos/uefi/mcu) derive from this base; the
// BLOB loader (blob.py) lands in this phase as the shellcode test vehicle.
#ifndef QILING_LOADER_LOADER_HPP
#define QILING_LOADER_LOADER_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "qiling/exception.hpp"

namespace qiling {

class Qiling;

namespace loader {

// loader.py Image — a mapped executable image descriptor (NamedTuple in Python)
struct Image {
    std::uint64_t base;
    std::uint64_t end;
    std::string path;
};

class QlLoader {
public:
    explicit QlLoader(Qiling* ql);
    virtual ~QlLoader();

    QlLoader(const QlLoader&) = delete;
    QlLoader& operator=(const QlLoader&) = delete;

    // loader.py find_containing_image — the image whose [base, end) range holds
    // `address`, or nullptr
    const Image* find_containing_image(std::uint64_t address) const;

    // loader.py get_image_by_name — basename match; casefold when requested
    const Image* get_image_by_name(std::string_view name, bool casefold = false) const;

    // loader.py save/restore — the mapped images list
    std::vector<Image> save() const;
    void restore(const std::vector<Image>& saved_state);

    // loader main method; derivatives must implement one of their own
    virtual void run() = 0;

    // per-format loader properties (set by run())
    std::uint64_t load_address = 0;
    std::uint64_t entry_point = 0;
    std::uint64_t init_sp = 0;
    std::uint64_t init_sp_pb = 0;  // physical base for the initial stack (ARM boot)
    std::uint64_t brk_address = 0;  // unistd.py brk: the program break
    bool is_driver = false;         // elf.py: true for the ET_REL loads

    // loader.py skip_exit_check — set by loaders that place their own return
    // guard (e.g. baremetal/bootloaders)
    bool skip_exit_check = false;

    std::vector<Image> images;

protected:
    Qiling* ql_;
};

}  // namespace loader

// utils.py select_loader's C++ port (declared in utils.hpp, defined in
// utils.cpp) constructs the loaders through this alias; the concrete factory
// signatures keep the loader headers light.
using QlLoaderPtr = std::unique_ptr<loader::QlLoader>;

}  // namespace qiling

#endif  // QILING_LOADER_LOADER_HPP
