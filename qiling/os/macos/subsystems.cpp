// Ported from qiling/os/macos/subsystems.py — the MachHostServer /
// MachTaskServer reply builders (the fixed-data shapes verbatim; the
// reply headers ride msgh_bits=4608 for host_info and 0x80001200 for the
// port-name replies, with the local port = the manager's 2187 port).
#include "qiling/os/macos/subsystems.hpp"

#include "qiling/core.hpp"
#include "qiling/os/macos/mach_port.hpp"
#include "qiling/os/macos/macos.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

// the reply-content trailer: the port name, pad1(4), pad2(2), the
// disposition 0x11, the type 0, pad end(4)
std::vector<std::uint8_t> port_trailer(std::uint32_t port_name) {
    std::vector<std::uint8_t> t;
    const auto u32 = [&t](std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            t.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    };
    const auto u16 = [&t](std::uint16_t v) {
        t.push_back(static_cast<std::uint8_t>(v));
        t.push_back(static_cast<std::uint8_t>(v >> 8));
    };
    u32(port_name);
    u32(0);             // pad1
    u16(0);             // pad2
    t.push_back(0x11);  // disposition
    t.push_back(0x00);  // type
    u32(0);             // pad end
    return t;
}

void pack_u32(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
}

void pack_u64(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
}

// the common reply header for the port-name replies (the id and the size
// set by the caller): msgh_bits 0x80001200, remote 0, local = the
// manager's 2187 port, voucher 0
MachMsg port_reply_header(Qiling& ql, std::uint32_t id, std::uint32_t size) {
    MachMsg out;
    out.header.msgh_bits = 0x80001200;
    out.header.msgh_size = size;
    out.header.msgh_remote_port = 0;
    out.header.msgh_local_port = ql.os<QlOsMacos>().macho_mach_port().name;
    out.header.msgh_voucher_port = 0;
    out.header.msgh_id = id;
    return out;
}

}  // namespace

MachMsg MachHostServer::host_info(const MachMsgHeader& in_header,
                                  const std::vector<std::uint8_t>& in_content) {
    // parse request
    MachMsg out_msg;
    if (in_content.size() < 16) {
        // the upstream's `raise` (the short-content guard)
        throw QlErrorBase("the host info content is short");
    }
    std::uint64_t ndr = 0;
    for (int i = 0; i < 8; ++i) {
        ndr |= static_cast<std::uint64_t>(in_content[static_cast<std::size_t>(i)]) << (8 * i);
    }
    (void)ndr;  // the NDR is parsed but unused (the upstream shape)
    const std::uint32_t flavor = in_content[8] | (static_cast<std::uint32_t>(in_content[9]) << 8) |
                                 (static_cast<std::uint32_t>(in_content[10]) << 16) |
                                 (static_cast<std::uint32_t>(in_content[11]) << 24);
    const std::uint32_t host_info_outCnt =
        in_content[12] | (static_cast<std::uint32_t>(in_content[13]) << 8) |
        (static_cast<std::uint32_t>(in_content[14]) << 16) |
        (static_cast<std::uint32_t>(in_content[15]) << 24);
    // may be we need wapper a func in kernel func ,but it is also a huge
    // projrct (the upstream comment) — gen reply

    if (flavor == kHostBasicInfo) {
        out_msg.header.msgh_bits = 4608;
        out_msg.header.msgh_size = 88;
        out_msg.header.msgh_remote_port = 0;
        out_msg.header.msgh_local_port = ql_->os<QlOsMacos>().macho_mach_port().name;
        out_msg.header.msgh_voucher_port = 0;
        out_msg.header.msgh_id = 300;

        pack_u64(out_msg.content, 0x100000000);        // NDR
        pack_u32(out_msg.content, 0x0);                // ret code / KERN SUCCESS
        pack_u32(out_msg.content, host_info_outCnt);   // host info output count

        // host info out
        pack_u32(out_msg.content, 0x2);                // max_cpus
        pack_u32(out_msg.content, 0x2);                // avail_cpus
        pack_u32(out_msg.content, 0x80000000);         // memory_size
        pack_u32(out_msg.content, 0x7);                // cpu_type
        pack_u32(out_msg.content, 0x4);                // cpu_subtype
        if (host_info_outCnt > 5) {
            pack_u32(out_msg.content, 0x1);            // cpu_threadtype
            pack_u32(out_msg.content, 0x2);            // physical_cpu
            pack_u32(out_msg.content, 0x2);            // physical_cpu_max
            pack_u32(out_msg.content, 0x4);            // logic_cpu
            pack_u32(out_msg.content, 0x4);            // logic_cpu_max
            pack_u64(out_msg.content, 0x400000000);    // max_mem
        }
    } else if (flavor == kHostPriorityInfo) {
        out_msg.header.msgh_bits = 4608;
        out_msg.header.msgh_size = 72;
        out_msg.header.msgh_remote_port = 0;
        out_msg.header.msgh_local_port = ql_->os<QlOsMacos>().macho_mach_port().name;
        out_msg.header.msgh_voucher_port = 0;
        out_msg.header.msgh_id = 300;

        pack_u64(out_msg.content, 0x100000000);        // NDR
        pack_u32(out_msg.content, 0x0);                // ret code / KERN SUCCESS
        pack_u32(out_msg.content, host_info_outCnt);   // host info output count
        // host info out
        pack_u32(out_msg.content, 0x50);               // kernel_priority = MINPRI_KERNEL
        pack_u32(out_msg.content, 0x50);               // system_priority = MINPRI_KERNEL
        pack_u32(out_msg.content, 0x40);               // server_priority = MINPRI_RESERVED
        pack_u32(out_msg.content, 0x1f);               // user_priority = BASEPRI_DEFAULT
        pack_u32(out_msg.content, 0x0);                // depress_priority = DEPRESSPRI
        pack_u32(out_msg.content, 0x0);                // idle_priority = IDLEPRI
        pack_u32(out_msg.content, 0x0);                // minimum_priority = MINPRI_USER
        pack_u32(out_msg.content, 0x4f);               // maximum_priority = MAXPRI_RESERVED
    } else {
        // "Host flavor not support"
        throw QlErrorBase("the host info flavor is not supported");
    }
    return out_msg;
}

MachMsg MachHostServer::host_get_clock_service(const MachMsgHeader& in_header,
                                               const std::vector<std::uint8_t>& in_content) {
    (void)in_header;
    (void)in_content;
    MachMsg out_msg;
    out_msg.header.msgh_bits = 0x80001200;
    out_msg.header.msgh_size = 0x00000028;
    out_msg.header.msgh_remote_port = 0x00000000;
    out_msg.header.msgh_local_port = ql_->os<QlOsMacos>().macho_mach_port().name;
    out_msg.header.msgh_voucher_port = 0;
    out_msg.header.msgh_id = 306;

    // the retcode cell (pack("<L", 0x1))
    out_msg.content = {0x01, 0x00, 0x00, 0x00};

    // the trailer carries the manager's clock port name (0x803)
    const auto& os_macos = ql_->os<QlOsMacos>();
    out_msg.trailer = port_trailer(static_cast<std::uint32_t>(
        os_macos.macho_port_manager().clock_port.name & 0xFFFFFFFFu));
    return out_msg;
}

MachMsg MachTaskServer::semaphore_create(const MachMsgHeader& in_header,
                                         const std::vector<std::uint8_t>& in_content) {
    (void)in_header;
    (void)in_content;
    MachMsg out_msg;
    out_msg.header.msgh_bits = 0x80001200;
    out_msg.header.msgh_size = 0x00000028;
    out_msg.header.msgh_remote_port = 0x00000000;
    out_msg.header.msgh_local_port = ql_->os<QlOsMacos>().macho_mach_port().name;
    out_msg.header.msgh_voucher_port = 0;
    out_msg.header.msgh_id = 3518;

    out_msg.content = {0x01, 0x00, 0x00, 0x00};

    // the trailer carries the manager's semaphore port name (0x903)
    const auto& os_macos = ql_->os<QlOsMacos>();
    out_msg.trailer = port_trailer(static_cast<std::uint32_t>(
        os_macos.macho_port_manager().semaphore_port.name & 0xFFFFFFFFu));
    return out_msg;
}

MachMsg MachTaskServer::get_special_port(const MachMsgHeader& in_header,
                                         const std::vector<std::uint8_t>& in_content) {
    (void)in_header;
    (void)in_content;
    MachMsg out_msg;
    out_msg.header.msgh_bits = 0x80001200;
    out_msg.header.msgh_size = 0x00000028;
    out_msg.header.msgh_remote_port = 0x00000000;
    out_msg.header.msgh_local_port = ql_->os<QlOsMacos>().macho_mach_port().name;
    out_msg.header.msgh_voucher_port = 0;
    out_msg.header.msgh_id = 3509;

    out_msg.content = {0x01, 0x00, 0x00, 0x00};

    // the trailer carries the manager's special port name (0x707)
    const auto& os_macos = ql_->os<QlOsMacos>();
    out_msg.trailer = port_trailer(static_cast<std::uint32_t>(
        os_macos.macho_port_manager().special_port.name & 0xFFFFFFFFu));
    return out_msg;
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
