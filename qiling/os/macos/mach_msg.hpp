// Ported from qiling/os/macos/mach_port.py (MachMsgHeader + MachMsg) — the
// mach message-trap family's wire format.
//
//   mach_msg_header_t: msgh_bits, msgh_size, msgh_remote_port,
//   msgh_local_port, msgh_voucher_port, msgh_id — six 4-byte cells.
//
//   The message = header + content + trailer. read_msg_from_mem pins the
//   quirk: the header's own msgh_size is OVERWRITTEN by the trap's ssize
//   argument (the upstream read_msg_header sets `header.msgh_size = size`
//   after reading), and the content rides addr+24 .. addr+ssize.
//
//   The MACH_SEND/MACH_RCV flag note: the upstream mach_msg_trap parses NO
//   option flags (the `opt` argument is only logged); a trap is a send
//   handled by the server dispatch with the reply written back over the
//   same buffer.
#ifndef QILING_OS_MACOS_MACH_MSG_HPP
#define QILING_OS_MACOS_MACH_MSG_HPP

#include <cstdint>
#include <vector>

#include "qiling/core.hpp"

namespace qiling {

class Qiling;

namespace os {
namespace macos {

// const.py host info def values
constexpr std::uint32_t kHostBasicInfo = 1;
constexpr std::uint32_t kHostPriorityInfo = 5;

// mach_port.py MachMsgHeader (the 24-byte wire header)
struct MachMsgHeader {
    std::uint32_t msgh_bits = 0;
    std::uint32_t msgh_size = 0;
    std::uint32_t msgh_remote_port = 0;
    std::uint32_t msgh_local_port = 0;
    std::uint32_t msgh_voucher_port = 0;
    std::uint32_t msgh_id = 0;

    static constexpr std::size_t kSize = 24;
};

// mach_port.py MachMsg (header + content + trailer)
class MachMsg {
public:
    MachMsgHeader header;
    std::vector<std::uint8_t> content;
    std::vector<std::uint8_t> trailer;

    // read_msg_from_mem: the header from addr (msgh_size forced to size) +
    // the content = mem[addr + 24, size - 24)
    void read_msg_from_mem(Qiling& ql, std::uint64_t addr, std::uint64_t size);

    // write_msg_to_mem: the six header cells, the content at addr+24, the
    // trailer after the content
    void write_msg_to_mem(Qiling& ql, std::uint64_t addr) const;
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_MACH_MSG_HPP
