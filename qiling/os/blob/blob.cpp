// Ported from qiling/os/blob/blob.cpp — QlOsBlob.
#include "qiling/os/blob/blob.hpp"

#include "qiling/cc/intel.hpp"
#include "qiling/cc/arm.hpp"
#include "qiling/cc/mips.hpp"
#include "qiling/cc/ppc.hpp"
#include "qiling/cc/riscv.hpp"
#include "qiling/core.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/profiles/inireader.hpp"

namespace qiling {

// blob.py: the per-arch calling convention table (intel.cdecl/amd64, arm,
// mips, riscv, ppc)
namespace {

std::unique_ptr<cc::QlCC> make_cc(QL_ARCH archtype, QlArch& arch) {
    switch (archtype) {
        case QL_ARCH::X86:
            return std::make_unique<cc::QlCdecl>(arch);
        case QL_ARCH::X8664:
            return std::make_unique<cc::amd64>(arch);
        case QL_ARCH::ARM:
        case QL_ARCH::CORTEX_M:
            return std::make_unique<cc::aarch32>(arch);
        case QL_ARCH::ARM64:
            return std::make_unique<cc::aarch64>(arch);
        case QL_ARCH::MIPS:
            return std::make_unique<cc::mipso32>(arch);
        case QL_ARCH::RISCV:
        case QL_ARCH::RISCV64:
            return std::make_unique<cc::riscv>(arch);
        case QL_ARCH::PPC:
            return std::make_unique<cc::ppc>(arch);
        default:
            throw QlErrorArch("unsupported blob architecture");
    }
}

}  // namespace

QlOsBlob::QlOsBlob(Qiling* ql) : QlOs(ql) {
    set_fcall(std::make_unique<QlFunctionCall>(*make_cc(ql->arch().type(), ql->arch())));
}

void QlOsBlob::run() {
    // if the entry point was set explicitly, override the default one
    if (ql().entry_point_set()) {
        set_entry_point(ql().entry_point());
    }

    set_exit_point(load_address() + ql().code().size());

    // if the exit point was set explicitly, override the default one
    if (ql().exit_point_set()) {
        set_exit_point(ql().exit_point());
    }

    // if heap info is provided in the profile, create the heap
    const auto heap_base = profile().has_option("CODE", "heap_address")
                               ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(profile().get_int("CODE", "heap_address")))
                               : std::nullopt;
    const auto heap_size = profile().has_option("CODE", "heap_size")
                               ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(profile().get_int("CODE", "heap_size")))
                               : std::nullopt;
    if (heap_base.has_value() && heap_size.has_value()) {
        heap_ = std::make_unique<QlMemoryHeap>(ql().mem(), *heap_base, *heap_base + *heap_size);
    }

    ql().emu_start(entry_point(), exit_point(), ql().timeout(), ql().count());
}

}  // namespace qiling
