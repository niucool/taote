// Ported from qiling/os/qnx/message.py — the QNX resource-manager message
// handlers (the io_write slice; the io_connect/io_read/io_lseek/stat and the
// sys/mem families land with their fixtures).
#include "qiling/os/qnx/message.hpp"

#include "qiling/core.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/helpers.hpp"
#include "qiling/os/qnx/qnx.hpp"

namespace qiling {
namespace os {
namespace qnx {

namespace {

// message.py _IO_COMBINE_FLAG
constexpr std::uint16_t kIoCombineFlag = 0x8000;

// map_msgtype.py msgtype_table (lib/c/public/sys/iomsg.h): the dispatch
// entries (the type → the handler)
struct MsgTypeEntry {
    std::uint16_t type;
    MsgHandler handler;
};

const MsgTypeEntry kMsgTypeTable[] = {
    {0x102, ql_qnx_msg_io_write},  // io_write
};

}  // namespace

MsgHandler find_message_handler(std::uint16_t type) {
    for (const auto& entry : kMsgTypeTable) {
        if (entry.type == type) {
            return entry.handler;
        }
    }
    return nullptr;
}

// message.py ql_qnx_msg_io_write: the write delegation — the header rides
// iov[0] and the payload rides iov[1] (the smsg+8 dword); the combine and
// the xtype paths are not implemented (the upstream raise shape)
std::optional<std::int64_t> ql_qnx_msg_io_write(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)rmsg;
    (void)rparts;

    // struct _io_write in lib/c/public/sys/iomsg.h:
    // (type, combine_len, nbytes, xtype, zero) = unpack("<HHiII", body)
    const auto body = get_message_body(ql, smsg, sparts);
    const auto type = static_cast<std::uint16_t>(body[0] | (body[1] << 8));
    const auto combine_len = static_cast<std::uint16_t>(body[2] | (body[3] << 8));
    const auto nbytes = static_cast<std::int32_t>(body[4] | (body[5] << 8) | (body[6] << 16) |
                                                  (static_cast<std::uint32_t>(body[7]) << 24));
    const auto xtype = static_cast<std::uint32_t>(body[8] | (body[9] << 8) | (body[10] << 16) |
                                                  (static_cast<std::uint32_t>(body[11]) << 24));

    if ((combine_len & kIoCombineFlag) != 0 || xtype != 0) {
        throw QlErrorNotImplemented("qnx io_write: IO combine and XTYPE support not implemented");
    }

    // the write's buffer pointer rides the second iov entry (the smsg+8
    // dword; the flat form shares the offset)
    auto& conn = static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid));
    const auto buf = static_cast<std::uint64_t>(ql.mem().read_ptr(smsg + 8, 4));

    // the posix write delegation (message.py ql_syscall_write import)
    const auto* entry = posix::SyscallRegistry::instance().find("write");
    const std::vector<std::uint64_t> write_args{static_cast<std::uint64_t>(*conn.fd), buf,
                                                static_cast<std::uint64_t>(nbytes)};
    return entry->handler(ql, write_args);
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
