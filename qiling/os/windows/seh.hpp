// Port of the pegasus SEH dispatch (src/windows/winemu.cpp dispatch_seh /
// _dispatch_seh_x86 / _continue_seh_x86) — the upstream Python qiling has no
// Windows exception dispatch (only hook_winapi), so the reference for this
// subsystem is the pegasus emulator that runs the same sample family
// (cfg.exceptions.dispatch_handlers). The design keeps the taote port's shape:
// the raw unicorn mem-invalid hook arms a retarget and declines the fault
// (returns false) so uc_emu_start surfaces the error; QlOsWindows::run then
// restarts the emulation at the staged target (the handler / the filter /
// the resume pc) — the pegasus seh_retarget_ run-loop idiom.
//
// The dispatch state machine (x86 only; the x64 VEH walk is a follow-up):
//   1. a guest AV (read/write unmapped) -> seh_dispatch: build the
//      EXCEPTION_RECORD + the x86 CONTEXT (+ EXCEPTION_POINTERS) in a mapped
//      scratch page, stage the fs:[0] frame handler call (record,
//      establisher, context, dispatcher) with the sentinel return address,
//      write the EXCEPTION_POINTERS pointer at establisher-4 (the ms_exc
//      convention the __except filters read through [ebp-0x14])
//   2. the frame handler (the CRT trampoline) calls _except_handler4_common
//      — implemented natively in dlls/msvcrt.cpp — which walks the EH4
//      registration chain ({Next, Handler, ScopeTable^cookie, TryLevel}),
//      decodes the scope table (the cookie xor) and records the frames +
//      the current TryLevel's scope record (FilterFunc / HandlerAddress)
//   3. the trampoline returns to the sentinel (a mapped non-executable page:
//      the fetch faults FETCH_PROT) -> seh_continue walks the recorded
//      frames: call the filter, and on EXCEPTION_EXECUTE_HANDLER jump to the
//      scope record's handler address (the __except block); on
//      EXCEPTION_CONTINUE_EXECUTION reload the saved CONTEXT (the handler may
//      have patched Eip) and resume
#ifndef QILING_OS_WINDOWS_SEH_HPP
#define QILING_OS_WINDOWS_SEH_HPP

#include <cstddef>
#include <cstdint>

namespace qiling {
namespace os {
namespace windows {

// the exception disposition codes (winnt.h EXCEPTION_DISPOSITION /
// EXCEPTION_ROUTINE): the frame handler / filter answers one of these
inline constexpr std::uint32_t kExceptionContinueExecution = 0xffffffffu;
inline constexpr std::uint32_t kExceptionContinueSearch = 0;
inline constexpr std::uint32_t kExceptionExecuteHandler = 1;

// the x86 CONTEXT image size (the fixed part through SegSs is 0xcc, then the
// 512-byte ExtendedRegisters block — pegasus deffs CONTEXT<4> total)
inline constexpr std::size_t SEH_CONTEXT_SIZE = 716;

// the EXCEPTION_RECORD image (x86: the 5 header fields + 15 params)
inline constexpr std::size_t SEH_RECORD_SIZE = 80;

// the scope-record shape at the end of the EH4 scope table (the 16-byte
// {GSCookieOffset, GSCookieXOROffset, EHCookieOffset, EHCookieXOROffset}
// header precedes the records)
struct SehScopeRecord {
    std::uint32_t enclosing_level = 0;
    std::uint32_t filter = 0;      // the __except filter address (0 = a __finally scope)
    std::uint32_t handler = 0;     // the __except block entry / the finally body
    bool filter_called = false;
    bool handler_called = false;
};

// one recorded EH4 registration frame from the chain walk
struct SehFrame {
    std::uint64_t frame = 0;       // the guest address of the registration record
    SehScopeRecord scope;          // the current TryLevel's record
    bool searched = false;         // the frame declined the exception (CONTINUE_SEARCH)
};

}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_SEH_HPP
