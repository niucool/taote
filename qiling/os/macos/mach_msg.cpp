// Ported from qiling/os/macos/mach_port.py — the MachMsg mem read/write
// bodies (see mach_msg.hpp for the format notes).
#include "qiling/os/macos/mach_msg.hpp"

#include "qiling/core.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

std::uint32_t read_u32(Qiling& ql, std::uint64_t addr) {
    const auto data = ql.mem().read(addr, 4);
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

void write_u32(std::vector<std::uint8_t>& buf, std::size_t at, std::uint32_t v) {
    buf[at + 0] = static_cast<std::uint8_t>(v);
    buf[at + 1] = static_cast<std::uint8_t>(v >> 8);
    buf[at + 2] = static_cast<std::uint8_t>(v >> 16);
    buf[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

}  // namespace

void MachMsg::read_msg_from_mem(Qiling& ql, std::uint64_t addr, std::uint64_t size) {
    header.msgh_bits = read_u32(ql, addr);
    header.msgh_size = read_u32(ql, addr + 4);
    header.msgh_remote_port = read_u32(ql, addr + 8);
    header.msgh_local_port = read_u32(ql, addr + 0xc);
    header.msgh_voucher_port = read_u32(ql, addr + 0x10);
    header.msgh_id = read_u32(ql, addr + 0x14);
    // the read_msg_header quirk: the trap's ssize overrides the wire size
    header.msgh_size = static_cast<std::uint32_t>(size);
    // between header and content is 4 byte \x00 (the upstream comment — the
    // content window covers it verbatim)
    if (size > MachMsgHeader::kSize) {
        content = ql.mem().read(addr + MachMsgHeader::kSize, size - MachMsgHeader::kSize);
    }
}

void MachMsg::write_msg_to_mem(Qiling& ql, std::uint64_t addr) const {
    std::vector<std::uint8_t> hdr(MachMsgHeader::kSize, 0);
    write_u32(hdr, 0, header.msgh_bits);
    write_u32(hdr, 4, header.msgh_size);
    write_u32(hdr, 8, header.msgh_remote_port);
    write_u32(hdr, 0xc, header.msgh_local_port);
    write_u32(hdr, 0x10, header.msgh_voucher_port);
    write_u32(hdr, 0x14, header.msgh_id);
    ql.mem().write(addr, hdr);
    if (!content.empty()) {
        ql.mem().write(addr + MachMsgHeader::kSize, content);
    }
    if (!trailer.empty()) {
        ql.mem().write(addr + MachMsgHeader::kSize + content.size(), trailer);
    }
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
