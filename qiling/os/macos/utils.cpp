#include "qiling/os/macos/utils.hpp"

#include "qiling/core.hpp"
#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace os {
namespace macos {

std::uint64_t gen_stub_code(Qiling& ql, const std::vector<std::uint64_t>& params, std::uint64_t func,
                            std::uint64_t ret) {
    // utils.py reg_list: the movabs prefixes for rdi/rsi/rdx/rcx/r8/r9
    static const std::uint8_t reg_list[6][2] = {{0x48, 0xBF}, {0x48, 0xBE}, {0x48, 0xBA},
                                                {0x48, 0xB9}, {0x49, 0xB8}, {0x49, 0xB9}};
    std::size_t remains = 0;
    std::vector<std::uint8_t> shellcode;
    const auto push_q = [&shellcode](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            shellcode.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
        }
    };

    if (params.size() <= 6) {
        for (std::size_t idx = 0; idx < params.size(); ++idx) {
            shellcode.push_back(reg_list[idx][0]);
            shellcode.push_back(reg_list[idx][1]);
            push_q(params[idx]);
        }
    } else {
        for (std::size_t idx = 0; idx < 6; ++idx) {
            shellcode.push_back(reg_list[idx][0]);
            shellcode.push_back(reg_list[idx][1]);
            push_q(params[idx]);
        }
        remains = params.size() - 6;
        for (std::size_t i = 0; i < remains; ++i) {
            // movabs rax, param ; push rax
            shellcode.push_back(0x48);
            shellcode.push_back(0xB8);
            push_q(params[6 + i]);
            shellcode.push_back(0x50);
        }
    }

    // the stack cleaner: add rsp, remains*8 ; ret (or the bare ret)
    std::vector<std::uint8_t> clean_stack;
    if (remains > 0) {
        clean_stack = {0x48, 0x81, 0xC4, static_cast<std::uint8_t>((remains * 8) & 0xFF),
                       static_cast<std::uint8_t>(((remains * 8) >> 8) & 0xFF), 0x00, 0x00, 0xC3};
    } else {
        clean_stack = {0xC3};
    }
    auto& heap = ql.os<posix::QlOsPosix>().heap();
    const auto cleaner = heap.alloc(clean_stack.size());
    ql.mem().write(cleaner, clean_stack);

    if (func > 0) {
        // push cleaner ; movabs rax, func ; jmp rax
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);
        push_q(cleaner);
        shellcode.push_back(0x50);
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);
        push_q(func);
        shellcode.push_back(0xFF);
        shellcode.push_back(0xE0);
    } else {
        // movabs rax, ret ; ret
        shellcode.clear();
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);
        push_q(ret);
        shellcode.push_back(0xC3);
    }

    const auto trampoline = heap.alloc(shellcode.size());
    ql.mem().write(trampoline, shellcode);
    return trampoline;
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
