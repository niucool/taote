// Ported from qiling/loader/blob.py — the minimal shellcode loader (the Phase 3
// test vehicle: no container format to parse, the code blob maps into a plain
// RAM region).
#include "qiling/loader/blob.hpp"

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace loader {

QlLoaderBLOB::QlLoaderBLOB(Qiling* ql) : QlLoader(ql) {
    // blob.py: load_address stays 0 until run() picks it up from the os layer
    load_address = 0;
}

void QlLoaderBLOB::run() {
    // blob.py run(): the os layer (QlOsBlob) resolves the CODE profile section
    load_address = ql_->os().load_address();
    entry_point = ql_->os().entry_point();

    const std::uint64_t code_begins = load_address;
    const std::uint64_t code_size = ql_->os().code_ram_size();
    const std::uint64_t code_ends = code_begins + code_size;

    ql_->mem().map(code_begins, code_size, UC_PROT_ALL, "[code]");
    ql_->mem().write(code_begins, ql_->code());

    // allow image-related functionalities
    images.push_back(Image{code_begins, code_ends, "blob_code"});

    // FIXME: stack pointer should be a configurable profile setting (blob.py)
    ql_->arch().regs().set_arch_sp(code_ends - 0x1000);
    init_sp = code_ends - 0x1000;
}

}  // namespace loader
}  // namespace qiling
