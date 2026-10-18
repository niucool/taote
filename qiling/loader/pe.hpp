// Ported from qiling/loader/pe.py — QlLoaderPE (the PE loader core over
// LIEF; PORT_PLAN.md §10 Phase 4, D17). The pefile-based inspection maps onto
// the LIEF PE API:
//
//   pefile.PE(path)                        -> LIEF::PE::Parser::parse(path)
//   OPTIONAL_HEADER.AddressOfEntryPoint    -> Binary::entrypoint()
//   OPTIONAL_HEADER.ImageBase              -> Binary::imagebase()
//   OPTIONAL_HEADER.SizeOfImage            -> Binary::virtual_size()
//   get_memory_mapped_image()              -> the manual section-wise mapping
//                                             (sections() + content())
//   DIRECTORY_ENTRY_IMPORT                 -> Binary::imports() (Import/ImportEntry)
//   get_sqlite... / libcache               -> deferred (the QlPeCache pickle layer)
//
// The TEB/PEB/LDR structures land with the full Windows stack (their layout
// tables live in os/windows/structs.py, itself a ctypes schema generator).
#ifndef QILING_LOADER_PE_HPP
#define QILING_LOADER_PE_HPP

#include <map>
#include <string>
#include <vector>

#include "qiling/loader/loader.hpp"

namespace qiling {
namespace loader {

// one resolved import stub: the address in emulated memory where the api hook
// dispatches, plus the identity of the imported function
struct ImportSymbol {
    std::uint64_t address;
    std::string dll;      // canonicalized (casefolded) dll basename
    std::string name;     // the symbol name (empty for ordinal imports)
    std::uint64_t ordinal = 0;
};

class QlLoaderPE final : public QlLoader {
public:
    QlLoaderPE(Qiling* ql, bool libcache);

    void run() override;

    // loader/pe.py init_imports: the resolved stubs, keyed by address (the
    // hook_winapi dispatcher looks up by pc)
    const std::map<std::uint64_t, ImportSymbol>& import_symbols() const noexcept { return import_symbols_; }

    // the import stub at an address (nullptr when the pc is not a stub)
    const ImportSymbol* import_symbols_at(std::uint64_t address) const {
        const auto it = import_symbols_.find(address);
        return it == import_symbols_.end() ? nullptr : &it->second;
    }

    // the stack configuration (the OS{bits} profile section)
    std::uint64_t stack_address() const noexcept { return stack_address_; }
    std::uint64_t stack_size() const noexcept { return stack_size_; }

    // loader/pe.py cmdline: `cmdline args...`
    const std::vector<std::uint8_t>& cmdline() const noexcept { return cmdline_; }

private:
    // loads one PE image (the main executable or a dll) and returns its base
    std::uint64_t load_image(const std::string& host_path, const std::string& label);

    bool libcache_ = false;
    bool is_driver_ = false;
    std::uint64_t stack_address_ = 0;
    std::uint64_t stack_size_ = 0;
    std::uint64_t image_address_ = 0;
    std::uint64_t dll_address_ = 0;
    std::uint64_t dll_size_ = 0;
    std::uint64_t dll_last_address_ = 0;
    std::map<std::uint64_t, ImportSymbol> import_symbols_;
    std::vector<std::uint8_t> cmdline_;
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_PE_HPP
