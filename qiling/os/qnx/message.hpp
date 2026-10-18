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

// message.py ql_qnx_msg_io_read (lib/c/1/read.c): the read delegation
std::optional<std::int64_t> ql_qnx_msg_io_read(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                               std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

// message.py ql_qnx_msg_io_lseek (lib/c/1/lseek.c): the lseek delegation
std::optional<std::int64_t> ql_qnx_msg_io_lseek(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

// message.py ql_qnx_msg_io_stat (lib/c/1/fstat.c): the fstat delegation
// (the QNXARMStat packing)
std::optional<std::int64_t> ql_qnx_msg_io_stat(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                               std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

// mman.py syscall_mmap_impl (the qnx shape): the enclosing-page mapping
std::optional<std::int64_t> syscall_mmap_impl(Qiling& ql, std::uint64_t addr, std::uint64_t length,
                                              std::uint64_t prot, std::uint64_t flags, std::int64_t fd,
                                              std::int64_t pgoffset);

// message.py ql_qnx_msg_mem_map (services/system/public/sys/memmsg.h): the
// mmap delegation (the prot shift + the <QQQ> reply)
std::optional<std::int64_t> ql_qnx_msg_mem_map(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                               std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

// message.py ql_qnx_msg_sys_conf: the confstr/sysconf dispatch
// (lib/c/1a/confstr.c + lib/c/1/sysconf.c)
std::optional<std::int64_t> ql_qnx_msg_sys_conf(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

// message.py ql_qnx_msg_io_connect (_connect_ctrl.c::_connect_io): the
// OPEN/MKNOD paths (the COMBINE subtypes raise not-implemented)
std::optional<std::int64_t> ql_qnx_msg_io_connect(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                  std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts);

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_MESSAGE_HPP
