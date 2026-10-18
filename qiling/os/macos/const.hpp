// Ported from qiling/os/macos/const.py — the used subset (the CS_* flags
// and the KERN return codes; the rest lands with its slice).
#ifndef QILING_OS_MACOS_CONST_HPP
#define QILING_OS_MACOS_CONST_HPP

#include <cstdint>

namespace qiling {
namespace os {
namespace macos {

// const.py KERN_SUCCESS
constexpr std::int64_t KERN_SUCCESS = 0;

// const.py CS_GET_TASK_ALLOW / CS_ENFORCEMENT (the verbatim values)
constexpr std::uint32_t CS_GET_TASK_ALLOW = 0x00000004;
constexpr std::uint32_t CS_ENFORCEMENT = 0x00001000;

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_CONST_HPP
