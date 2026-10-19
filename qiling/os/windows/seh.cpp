// The SEH dispatch implementation — see seh.hpp for the design overview and
// the pegasus reference (src/windows/winemu.cpp dispatch_seh /
// _dispatch_seh_x86 / _continue_seh_x86).
#include <unicorn/unicorn.h>

#include <cstring>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/seh.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace windows {

namespace {

// the x86 CONTEXT field offsets (pegasus deffs CONTEXT<4>):
//   0x000 ContextFlags, 0x004..0x018 Dr0-Dr7, 0x01c FloatSave (112),
//   0x08c SegGs, 0x090 SegFs, 0x094 SegEs, 0x098 SegDs,
//   0x09c Edi, 0x0a0 Esi, 0x0a4 Ebx, 0x0a8 Edx, 0x0ac Ecx, 0x0b0 Eax,
//   0x0b4 Ebp, 0x0b8 Eip, 0x0bc SegCs, 0x0c0 EFlags, 0x0c4 Esp, 0x0c8 SegSs,
//   0x0cc ExtendedRegisters (512) — the fixed part ends at 0xcc
constexpr std::size_t kCtxContextFlags = 0x0;
constexpr std::size_t kCtxSegGs = 0x8c;
constexpr std::size_t kCtxSegFs = 0x90;
constexpr std::size_t kCtxSegEs = 0x94;
constexpr std::size_t kCtxSegDs = 0x98;
constexpr std::size_t kCtxEdi = 0x9c;
constexpr std::size_t kCtxEsi = 0xa0;
constexpr std::size_t kCtxEbx = 0xa4;
constexpr std::size_t kCtxEdx = 0xa8;
constexpr std::size_t kCtxEcx = 0xac;
constexpr std::size_t kCtxEax = 0xb0;
constexpr std::size_t kCtxEbp = 0xb4;
constexpr std::size_t kCtxEip = 0xb8;
constexpr std::size_t kCtxSegCs = 0xbc;
constexpr std::size_t kCtxEFlags = 0xc0;
constexpr std::size_t kCtxEsp = 0xc4;
constexpr std::size_t kCtxSegSs = 0xc8;

// CONTEXT_FULL: the debug registers + the floating point + the segments +
// the integer registers (winnt.h)
constexpr std::uint32_t kContextFull = 0x10007;

void put_u32(std::vector<std::uint8_t>& image, std::size_t off, std::uint32_t v) {
    image[off + 0] = static_cast<std::uint8_t>(v);
    image[off + 1] = static_cast<std::uint8_t>(v >> 8);
    image[off + 2] = static_cast<std::uint8_t>(v >> 16);
    image[off + 3] = static_cast<std::uint8_t>(v >> 24);
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint32_t>(image[off]) |
           (static_cast<std::uint32_t>(image[off + 1]) << 8) |
           (static_cast<std::uint32_t>(image[off + 2]) << 16) |
           (static_cast<std::uint32_t>(image[off + 3]) << 24);
}

}  // namespace

// map the sentinel page: the staged return address for the guest SEH
// handlers / filters. The page is deliberately NON-executable so the
// handler's `ret` to it faults (UC_MEM_FETCH_PROT) and the dispatcher
// continues the walk — and mapped (rw) so the address never gets reused by
// the guest allocations
bool QlOsWindows::seh_map_sentinel() {
    if (seh_sentinel_ != 0) {
        return true;
    }
    try {
        const auto base = ql_->mem().find_free_space(0x1000, 0x70000000ull, 0x78000000ull, 0x1000);
        // rw without exec: the fetch at the sentinel faults PROT
        ql_->mem().map(base, 0x1000, UC_PROT_READ | UC_PROT_WRITE, "[SEH sentinel]");
        seh_sentinel_ = base;
        return true;
    } catch (...) {
        return false;
    }
}

bool QlOsWindows::seh_fault_trampoline(uc_engine*, uc_mem_type access, std::uint64_t address,
                                        std::uint32_t /*size*/, std::int64_t /*value*/, void* user_data) {
    auto* self = static_cast<QlOsWindows*>(user_data);
    return self->seh_on_fault(static_cast<int>(access), address);
}

// the raw invalid-memory hook: the first-chance SEH dispatch. Returns false
// (the fault surfaces to uc_emu_start's error) whenever the retarget is
// armed — the run loop in QlOsWindows::run then restarts the emulation at
// the staged target. Returning false also lets the later-registered hooks
// (the ql-layer mem hooks) still observe the fault (unicorn continues the
// hook list on a false return).
bool QlOsWindows::seh_on_fault(int access, std::uint64_t address) {
    if (seh_sentinel_ == 0 || bits_ != 32 || !seh_dispatch_enabled_) {
        return false;  // the dispatch is not armed (or switched off)
    }

    // the sentinel fetch: a guest SEH handler / filter returned — continue
    // the dispatch walk
    if ((access == UC_MEM_FETCH_PROT || access == UC_MEM_FETCH_UNMAPPED) && address == seh_sentinel_) {
        return seh_continue();
    }

    // only the data faults dispatch (a read/write against unmapped memory);
    // the fetch faults elsewhere stay on the existing failure path
    if (access != UC_MEM_WRITE_UNMAPPED && access != UC_MEM_READ_UNMAPPED) {
        return false;
    }

    return seh_dispatch(address, access == UC_MEM_WRITE_UNMAPPED ? 1u : 0u);
}

// pegasus _dispatch_seh_x86: stage the fs:[0] frame handler call and arm the
// retarget. Returns true when the dispatch took the fault.
bool QlOsWindows::seh_dispatch(std::uint64_t fault_addr, std::uint32_t access_type) {
    auto& regs = ql_->arch().regs();
    auto& mem = ql_->mem();

    // the exception list head (fs:[0]; the TEB rides the FS segment base)
    const auto chain = mem.read_ptr(FS_SEGMENT_ADDR, 4);
    if (chain == 0 || chain == 0xffffffffull) {
        return false;  // no registered frame: the fault propagates
    }
    const auto next = mem.read_ptr(chain, 4);
    const auto handler = mem.read_ptr(chain + 4, 4);
    if (handler == 0 || handler == 0xffffffffull) {
        return false;  // a malformed frame: rather fail than dispatch garbage
    }
    if (next != 0 && next != 0xffffffffull && (next < 0x1000 || next >= 0xfffff000)) {
        return false;
    }

    // the repeat guard: an identical (pc, address) fault storm (a handler
    // that resumes without fixing anything) must not spin forever
    const auto pc = regs.arch_pc();
    if (pc == seh_fault_pc_ && fault_addr == seh_fault_addr_) {
        if (++seh_repeat_count_ > 16) {
            return false;
        }
    } else {
        seh_fault_pc_ = pc;
        seh_fault_addr_ = fault_addr;
        seh_repeat_count_ = 1;
    }

    // the structures page: the EXCEPTION_POINTERS at +0, the
    // EXCEPTION_RECORD at +0x10, the CONTEXT at +0x100. A fresh page per
    // dispatch, deliberately: every record a live frame still points at has
    // to stay readable (a filter reads its own CONTEXT), so nothing is
    // recycled while the walk nests. The allocation is one page from the
    // 0x70000000-0x78000000 arena, i.e. a 32k-dispatch budget
    std::uint64_t page = 0;
    try {
        page = mem.find_free_space(0x1000, 0x70000000ull, 0x78000000ull, 0x1000);
        mem.map(page, 0x1000, UC_PROT_ALL, "[SEH]");
    } catch (...) {
        return false;
    }
    const auto p_ptrs = page;
    const auto p_record = page + 0x10;
    const auto p_ctx = page + 0x100;

    // EXCEPTION_POINTERS {ExceptionRecord, ContextRecord}
    mem.write_ptr(p_ptrs, p_record, 4);
    mem.write_ptr(p_ptrs + 4, p_ctx, 4);

    // EXCEPTION_RECORD: the ACCESS_VIOLATION code, the faulting pc, the
    // read/write type + the faulting address in the info params
    std::vector<std::uint8_t> rec(SEH_RECORD_SIZE, 0);
    put_u32(rec, 0, 0xC0000005);  // ExceptionCode = STATUS_ACCESS_VIOLATION
    put_u32(rec, 4, 0);           // ExceptionFlags
    put_u32(rec, 8, 0);           // ExceptionRecord (nested chains: none)
    put_u32(rec, 12, static_cast<std::uint32_t>(pc));
    put_u32(rec, 16, 2);          // NumberParameters
    put_u32(rec, 20, access_type);
    put_u32(rec, 24, static_cast<std::uint32_t>(fault_addr));
    mem.write(p_record, rec);

    // the x86 CONTEXT image
    seh_build_context(p_ctx);

    // the ms_exc convention: the EXCEPTION_POINTERS pointer just below the
    // registration record — the compiled __except filters read it through
    // the ebp-based locals ([ebp-0x14] -> the frame slot)
    mem.write_ptr(chain - 4, p_ptrs, 4);

    // stage the frame handler call:
    //   handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext)
    // with the sentinel as the return address
    auto esp = regs.arch_sp();
    esp -= 4; mem.write_ptr(esp, 0, 4);           // DispatcherContext
    esp -= 4; mem.write_ptr(esp, p_ctx, 4);       // ContextRecord
    esp -= 4; mem.write_ptr(esp, chain, 4);       // EstablisherFrame
    esp -= 4; mem.write_ptr(esp, p_record, 4);    // ExceptionRecord
    esp -= 4; mem.write_ptr(esp, seh_sentinel_, 4);  // the return address
    regs.set_arch_sp(esp);

    // reset the walk state: _except_handler4_common re-records the frames
    seh_frames_.clear();
    seh_context_addr_ = p_ctx;
    seh_retarget_ = handler;
    return true;
}

// pegasus _continue_seh_x86: the sentinel return — walk the recorded frames.
// The guest eax carries the last return value (the trampoline's
// ExceptionContinueSearch from _except_handler4_common, or the filter's
// verdict).
bool QlOsWindows::seh_continue() {
    auto& regs = ql_->arch().regs();
    const auto ret = static_cast<std::uint32_t>(regs.read("eax"));

    for (auto& frame : seh_frames_) {
        if (frame.searched) {
            continue;
        }
        auto& scope = frame.scope;

        // the filter first (the __except (expression) evaluation)
        if (!scope.filter_called && scope.filter != 0 && scope.filter != 0xffffffffu) {
            auto esp = regs.arch_sp() - 4;
            ql_->mem().write_ptr(esp, seh_sentinel_, 4);
            regs.set_arch_sp(esp);
            seh_retarget_ = scope.filter;
            scope.filter_called = true;
            return true;
        }

        if (ret == kExceptionExecuteHandler || scope.filter == 0) {
            if (!scope.handler_called && scope.handler != 0 && scope.handler != 0xffffffffu) {
                seh_retarget_ = scope.handler;
                scope.handler_called = true;
                return true;
            }
        } else if (ret == kExceptionContinueExecution) {
            // reload the saved CONTEXT (the handler may have patched Eip)
            // and resume
            seh_load_context();
            seh_retarget_ = regs.arch_pc();
            return true;
        }
        // EXCEPTION_CONTINUE_SEARCH: the next frame
        frame.searched = true;
    }

    // the walk exhausted: unhandled — the fault surfaces (the run loop sees
    // no retarget and the emu error propagates)
    return false;
}

// capture the current guest state into the x86 CONTEXT image
void QlOsWindows::seh_build_context(std::uint64_t dest) const {
    const auto& regs = ql_->arch().regs();

    std::vector<std::uint8_t> ctx(SEH_CONTEXT_SIZE, 0);
    put_u32(ctx, kCtxContextFlags, kContextFull);
    put_u32(ctx, kCtxSegGs, static_cast<std::uint32_t>(regs.read("gs")));
    put_u32(ctx, kCtxSegFs, static_cast<std::uint32_t>(regs.read("fs")));
    put_u32(ctx, kCtxSegEs, static_cast<std::uint32_t>(regs.read("es")));
    put_u32(ctx, kCtxSegDs, static_cast<std::uint32_t>(regs.read("ds")));
    put_u32(ctx, kCtxEdi, static_cast<std::uint32_t>(regs.read("edi")));
    put_u32(ctx, kCtxEsi, static_cast<std::uint32_t>(regs.read("esi")));
    put_u32(ctx, kCtxEbx, static_cast<std::uint32_t>(regs.read("ebx")));
    put_u32(ctx, kCtxEdx, static_cast<std::uint32_t>(regs.read("edx")));
    put_u32(ctx, kCtxEcx, static_cast<std::uint32_t>(regs.read("ecx")));
    put_u32(ctx, kCtxEax, static_cast<std::uint32_t>(regs.read("eax")));
    put_u32(ctx, kCtxEbp, static_cast<std::uint32_t>(regs.read("ebp")));
    put_u32(ctx, kCtxEip, static_cast<std::uint32_t>(regs.arch_pc()));
    put_u32(ctx, kCtxSegCs, static_cast<std::uint32_t>(regs.read("cs")));
    put_u32(ctx, kCtxEFlags, static_cast<std::uint32_t>(regs.read("eflags")));
    put_u32(ctx, kCtxEsp, static_cast<std::uint32_t>(regs.arch_sp()));
    put_u32(ctx, kCtxSegSs, static_cast<std::uint32_t>(regs.read("ss")));
    ql_->mem().write(dest, ctx);
}

// restore the guest state from the saved CONTEXT (the handler-patched image)
void QlOsWindows::seh_load_context() {
    if (seh_context_addr_ == 0) {
        return;
    }
    const auto image = ql_->mem().read(seh_context_addr_, SEH_CONTEXT_SIZE);
    auto& regs = ql_->arch().regs();

    regs.write("edi", get_u32(image, kCtxEdi));
    regs.write("esi", get_u32(image, kCtxEsi));
    regs.write("ebx", get_u32(image, kCtxEbx));
    regs.write("edx", get_u32(image, kCtxEdx));
    regs.write("ecx", get_u32(image, kCtxEcx));
    regs.write("eax", get_u32(image, kCtxEax));
    regs.write("ebp", get_u32(image, kCtxEbp));
    regs.write("eflags", get_u32(image, kCtxEFlags));
    regs.set_arch_sp(get_u32(image, kCtxEsp));
    regs.set_arch_pc(get_u32(image, kCtxEip));
}

void QlOsWindows::seh_record_frame(std::uint64_t frame, const SehScopeRecord& scope) {
    seh_frames_.push_back(SehFrame{frame, scope, false});
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
