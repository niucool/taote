// Ported from qiling/os/qnx/message.py — the QNX resource-manager message
// handlers. The kernel's msg_sendv resolves the message type through the
// msgtype table and dispatches here; the io_* handlers delegate to the posix
// file layer through the shared registry.
#ifndef QILING_OS_QNX_MESSAGE_HPP
#define QILING_OS_QNX_MESSAGE_HPP

#include <cstdint>
#include <optional>

#include "qiling/os/posix/syscall.hpp"

namespace qiling {
namespace os {
namespace qnx {

// message.py: the msg-send signature (the coid, the send iov, the reply iov)
using MsgHandler =
    std::optional<std::int64_t>(*)(Qiling& ql, std::uint64_t coid, std::uint64_t smsg, std::int32_t sparts,
                                   std::uint64_t rmsg, std::int32_t rparts);

// map_msgtype.py: the message-type dispatch (the ARM msgtype_table reversed
// to the handlers; the slice carries io_write — the rest land with their
// fixtures)
MsgHandler find_message_handler(std::uint16_t type);

// message.py ql_qnx_msg_io_write: the write delegation (lib/c/1/write.c)
std::optional<std::int64_t> ql_qnx_msg_io_write(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

// message.py ql_qnx_msg_sys_conf: the confstr/sysconf dispatch
// (lib/c/1a/confstr.c + lib/c/1/sysconf.c)
std::optional<std::int64_t> ql_qnx_msg_sys_conf(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_MESSAGE_HPP
