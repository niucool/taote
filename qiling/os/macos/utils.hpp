// Ported from qiling/os/macos/utils.py (gen_stub_code — the ev-callback
// trampoline builder).
#pragma once

#include <cstdint>
#include <vector>

namespace qiling {

class Qiling;

namespace os {
namespace macos {

// utils.py gen_stub_code: the callback trampoline. The shellcode loads the
// params into the ms64 arg registers (rdi/rsi/rdx/rcx/r8/r9); with more
// than 6 params the extras ride `movabs rax, param; push rax` (the last
// pushed lands at [rsp], so [rsp+8] carries the 7th param — the ms64 stack
// convention), followed by the stack cleaner (`add rsp, N*8; ret` — or the
// bare `ret`) allocated on the guest heap, then either the
// `push cleaner; movabs rax, func; jmp rax` dispatch or the func<=0 shape
// (`movabs rax, ret; ret`). The trampoline rides the guest heap and the
// returned address is what the RUN=true emit path stack-pushes.
std::uint64_t gen_stub_code(Qiling& ql, const std::vector<std::uint64_t>& params, std::uint64_t func,
                            std::uint64_t ret = 0);

}  // namespace macos
}  // namespace os
}  // namespace qiling
