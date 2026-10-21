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

#include <memory>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <LIEF/PE.hpp>

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

// loader/pe.py ForwardedExport — the deferred forwarder resolution record
struct ForwardedExport {
    std::string source_dll;
    std::string source_symbol;
    std::uint64_t source_ordinal = 0;
    std::string target_dll;
    std::string target_symbol;
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
    // register a runtime-resolved routine address as a dispatchable import
    // (the ntoskrnl MmGetSystemRoutineAddress path parks a fake address per
    // hook-only routine; without the registration the guest calls it and the
    // dispatcher does not recognise the address)
    void register_import_symbol(std::uint64_t address, std::string dll, std::string name) {
        import_symbols_[address] = ImportSymbol{address, std::move(dll), std::move(name), 0};
    }

    const ImportSymbol* import_symbols_at(std::uint64_t address) const {
        const auto it = import_symbols_.find(address);
        return it == import_symbols_.end() ? nullptr : &it->second;
    }

    // the stack configuration (the OS{bits} profile section)
    std::uint64_t stack_address() const noexcept { return stack_address_; }
    std::uint64_t stack_size() const noexcept { return stack_size_; }

    // loader/pe.py: the main image base (pe_image_address)
    std::uint64_t pe_image_address() const noexcept { return pe_image_address_; }

    // the main image's mapped extent (the address-space range the dispatcher
    // must not treat as an import slot: a dll target's own exports are keyed
    // into import_symbols_ by load_dll just like a real import)
    std::uint64_t pe_image_size() const noexcept { return pe_image_size_; }

    // loader/pe.py: the accumulated mapped dll size (the dll_size walk in
    // load_dll; the GetSystemInfo upper-bound rider)
    std::uint64_t dll_size() const noexcept { return dll_size_; }

    // loader/pe.py: the dll load base (the dll_address profile value)
    std::uint64_t dll_address() const noexcept { return dll_address_; }

    // loader/pe.py PEB.BeingDebugged (the debugapi rider): the byte rides
    // the real PEB image (the init_peb wiring; the not-being-debugged
    // default of 0)
    std::uint8_t peb_being_debugged() const noexcept { return peb_being_debugged_; }

    // loader/pe.py TEB.PebAddress (the ntdll ProcessBasicInformation
    // rider): the init_peb-computed address
    std::uint64_t peb_address() const noexcept { return peb_address_; }

    // loader/pe.py TEB.TebAddress (the gs_base rider) and the LDR address
    // (PEB.LdrAddress), plus the ldr_list entry addresses
    std::uint64_t teb_address() const noexcept { return teb_address_; }
    std::uint64_t ldr_address() const noexcept { return ldr_address_; }
    const std::vector<std::uint64_t>& ldr_list() const noexcept { return ldr_list_; }

    // loader/pe.py: the driver flag (the MH_KEXT... the PE 0xb ride — the
    // load_image parse sets it; the driver branch riders read it)
    bool is_driver() const noexcept { return is_driver_; }

    // loader/pe.py init_ki_user_shared_data / init_eprocess /
    // init_driver_object / init_registry_path — the ntoskrnl-family riders
    // (the KUSER_SHARED_DATA map + the EPROCESS/DRIVER_OBJECT placeholder
    // images; the ntoskrnl handlers consume the addresses)
    std::uint64_t kuser_shared_data_address() const noexcept { return kuser_shared_data_address_; }
    std::uint64_t eprocess_address() const noexcept { return eprocess_address_; }
    std::uint64_t driver_object_address() const noexcept { return driver_object_address_; }
    // the UNICODE_STRING init_registry_path built (DriverEntry's 2nd argument)
    std::uint64_t registry_path_address() const noexcept { return registry_path_address_; }
    std::uint64_t regitry_path_address() const noexcept { return regitry_path_address_; }
    void init_ki_user_shared_data();
    void init_eprocess();
    void init_security_cookie();   // the /GS cookie cell (drivers)
    void init_driver_object();
    void init_registry_path();

    // loader/pe.py init_teb / init_peb / init_ldr_data /
    // add_ldr_data_table_entry — the TEB/PEB/LDR stack (the non-driver PE
    // and the shellcode paths; the drivers skip them verbatim)
    void init_teb();
    void init_peb();
    void init_ldr_data();
    void add_ldr_data_table_entry(const std::string& dll_name);

    // loader/pe.py init_imports — the main-image import walk (the api-ms
    // redirect ladder + the load_dll rides + the IAT slot writes)
    void init_imports();
    void init_imports_for(LIEF::PE::Binary& parsed, std::uint64_t image_base, const std::string& image_label);

    // loader/pe.py call_dll_entrypoint — the DllMain drive (the verbatim
    // blacklist + the emu-state gate + the fcall CDECL frame)
    void call_dll_entrypoint(LIEF::PE::Binary& dll, std::uint64_t dll_base, std::uint64_t dll_len,
                             const std::string& dll_name);

    // loader/pe.py resolve_forwarded_exports — re-points the forwarded
    // exports' IAT cells and the dispatch keys at the target dll's real
    // export address (the KERNELBASE-style forwarder chains)
    void resolve_forwarded_exports();

    // loader/pe.py init_function_tables / lookup_function_entry — the
    // x64/.pdata RUNTIME_FUNCTION walk (the upstream parses the pefile
    // DIRECTORY_ENTRY_EXCEPTION objects; the port reads the mapped .pdata
    // bytes, the same Begin/End fields). The x86 images never populate the
    // tables (the verbatim arch gate). The Rtl* unwind riders consume these
    // maps.
    struct RuntimeFunction {
        std::uint32_t begin = 0;  // the BeginAddress RVA
        std::uint32_t end = 0;    // the EndAddress RVA
    };
    const std::map<std::uint64_t, std::vector<RuntimeFunction>>& function_tables() const noexcept { return function_tables_; }
    const std::map<std::uint64_t, std::uint64_t>& function_table_lookup() const noexcept { return function_table_lookup_; }

    // loader/pe.py lookup_function_entry: the (index, entry) whose [begin,
    // end) range holds control_pc - base_addr, or the {-1, nullptr}
    std::pair<std::int64_t, const RuntimeFunction*> lookup_function_entry(std::uint64_t base_addr,
                                                                          std::uint64_t control_pc) const;

    // loader/pe.py init_function_tables — the non-x86 parse over the mapped
    // .pdata (the exception-table data directory)
    void init_function_tables(LIEF::PE::Binary* pe, std::uint64_t image_base);

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

    // the real-system-dll fallback: an import no loaded image exports used to
    // leave the guest's IAT slot holding its raw hint/name RVA, which the
    // guest then executes as code (win7 msvcrt lacks _initialize_onexit_table,
    // so msvcp140's CRT startup fetched into 0x90fa4 and its DllMain bailed
    // before the initializer walk could construct std::cout). The slot is
    // answered by a lazily-mapped page of xor eax,eax; ret cells instead —
    // one per unresolved symbol name, matching the stub-rootfs ret-cell
    // philosophy for APIs the environment genuinely cannot provide
    std::uint64_t unbound_import_stub(const std::string& name, std::uint64_t ordinal = 0);

    // the symbol an unbound-import stub cell stands in for (nullptr when the
    // address is not one of the stub page's cells). hook_winapi consults this
    // so an import the rootfs's DLL does not export — the Win7 rootfs exports
    // none of the Universal CRT's api-ms-win-crt-* surface — is still served by
    // taote's own handler instead of by a bare answer-0 cell
    const std::string* stub_symbol_at(std::uint64_t address) const noexcept {
        const auto it = stub_addr_names_.find(address);
        return it == stub_addr_names_.end() ? nullptr : &it->second;
    }

    // loader/pe.py cmdline: `cmdline args...`
    const std::vector<std::uint8_t>& cmdline() const noexcept { return cmdline_; }

private:
    // loads one PE image (the main executable or a dll) and returns its base
    std::uint64_t load_image(const std::string& host_path, const std::string& label,
                             bool set_entry_point = true,
                             std::optional<std::uint64_t> base_override = {});

    // the post-parse load walk (the dll path pre-applies the base
    // relocations to the parsed object and passes the policy base through)
    std::uint64_t load_parsed(std::unique_ptr<LIEF::PE::Binary> parsed, const std::string& host_path,
                              const std::string& label, bool set_entry_point,
                              std::optional<std::uint64_t> base_override = {});

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
    // loader/pe.py structure_last_addr: the structure-allocation cursor (the
    // driver branch seeds it from the dll cursor; the init_* walks advance it
    // by the aligned structure sizes)
    std::uint64_t structure_last_addr_ = 0;
    std::uint8_t peb_being_debugged_ = 0;
    std::uint64_t peb_address_ = 0;

    // the TEB/PEB/LDR stack (the init_* walks seed them; the ldr_list
    // mirrors the upstream self.ldr_list entry addresses)
    std::uint64_t teb_address_ = 0;
    std::uint64_t ldr_address_ = 0;
    std::vector<std::uint64_t> ldr_list_;
    std::map<std::uint64_t, std::vector<RuntimeFunction>> function_tables_;
    std::map<std::uint64_t, std::uint64_t> function_table_lookup_;
    std::uint64_t pe_image_address_ = 0;
    std::uint64_t pe_image_size_ = 0;
    std::uint64_t last_image_size_ = 0;
    std::map<std::uint64_t, ImportSymbol> import_symbols_;
    std::map<std::uint64_t, ExportSymbol> export_symbols_;
    std::map<std::string, ImportTable> import_address_table_;
    std::vector<std::uint8_t> cmdline_;
    std::vector<ForwardedExport> forwarded_exports_;
    std::optional<std::uint64_t> stub_page_;
    std::map<std::string, std::uint64_t> stub_cells_;
    std::map<std::uint64_t, std::string> stub_addr_names_;

    // the ntoskrnl-family rider addresses (the init_* walks seed them)
    std::uint64_t kuser_shared_data_address_ = 0;
    std::uint64_t eprocess_address_ = 0;
    std::uint64_t driver_object_address_ = 0;
    std::uint64_t registry_path_address_ = 0;
    std::uint64_t regitry_path_address_ = 0;
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_PE_HPP
