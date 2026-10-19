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

// one main-image export (loader/pe.py init_exports: the export_symbols walk)
struct ExportSymbol {
    std::uint64_t address;   // the absolute ea (the image base + the rva)
    std::string name;        // empty for the ordinal-only exports
    std::uint64_t ordinal = 0;
};

// one dll's import-address-table slice (loader/pe.py: the iat dict is keyed
// by both the symbol name and the ordinal; the port keeps the two views)
struct ImportTable {
    std::map<std::string, std::uint64_t> by_name;
    std::map<std::uint64_t, std::uint64_t> by_ordinal;

    std::uint64_t lookup(const std::string& name) const {
        const auto it = by_name.find(name);
        return it == by_name.end() ? 0 : it->second;
    }
    std::uint64_t lookup(std::uint64_t ordinal) const {
        const auto it = by_ordinal.find(ordinal);
        return it == by_ordinal.end() ? 0 : it->second;
    }
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

    // loader/pe.py: the main image base (pe_image_address)
    std::uint64_t pe_image_address() const noexcept { return pe_image_address_; }

    // loader/pe.py: the accumulated mapped dll size (the dll_size walk in
    // load_dll; the GetSystemInfo upper-bound rider)
    std::uint64_t dll_size() const noexcept { return dll_size_; }

    // loader/pe.py: the dll load base (the dll_address profile value)
    std::uint64_t dll_address() const noexcept { return dll_address_; }

    // loader/pe.py PEB.BeingDebugged (the debugapi rider): the PEB itself
    // lands with the full TEB/PEB/LDR stack; the flag rides a placeholder
    // default of 0 (the not-being-debugged state) until that slice wires
    // the real PEB byte
    std::uint8_t peb_being_debugged() const noexcept { return peb_being_debugged_; }

    // loader/pe.py TEB.PebAddress (the ntdll ProcessBasicInformation
    // rider): the same TEB/PEB placeholder — the address rides 0 until the
    // TEB/PEB/LDR stack slice wires the real layout
    std::uint64_t peb_address() const noexcept { return peb_address_; }

    // loader/pe.py init_exports: the main-image exports keyed by the ea
    const std::map<std::uint64_t, ExportSymbol>& export_symbols() const noexcept { return export_symbols_; }

    // loader/pe.py: the import-address tables keyed by the casefolded dll
    // basename (the by_name/by_ordinal views over one table)
    const ImportTable* import_address_table_at(const std::string& dll) const {
        const auto it = import_address_table_.find(dll);
        return it == import_address_table_.end() ? nullptr : &it->second;
    }

    // loader/pe.py load_dll: resolve a dll by name (the .dll append, the
    // winsys default, the loaded check), map it, and register its exports
    std::uint64_t load_dll(const std::string& name);

    // loader/pe.py cmdline: `cmdline args...`
    const std::vector<std::uint8_t>& cmdline() const noexcept { return cmdline_; }

private:
    // loads one PE image (the main executable or a dll) and returns its base
    std::uint64_t load_image(const std::string& host_path, const std::string& label);

    // loader/pe.py __get_path_elements: the dll basename (the .dll append +
    // the casefold) and the host path (the winsys default when nameless)
    std::pair<std::string, std::string> dll_path_elements(const std::string& name) const;

    bool libcache_ = false;
    bool is_driver_ = false;
    std::uint64_t stack_address_ = 0;
    std::uint64_t stack_size_ = 0;
    std::uint64_t image_address_ = 0;
    std::uint64_t dll_address_ = 0;
    std::uint64_t dll_size_ = 0;
    std::uint64_t dll_last_address_ = 0;
    std::uint8_t peb_being_debugged_ = 0;
    std::uint64_t peb_address_ = 0;
    std::uint64_t pe_image_address_ = 0;
    std::map<std::uint64_t, ImportSymbol> import_symbols_;
    std::map<std::uint64_t, ExportSymbol> export_symbols_;
    std::map<std::string, ImportTable> import_address_table_;
    std::vector<std::uint8_t> cmdline_;
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_PE_HPP
