// Ported from qiling/os/qnx/helpers.py — the QNX connection record (the
// coid → pid/chid/fd triple behind the kernel's connection table).
#ifndef QILING_OS_QNX_HELPERS_HPP
#define QILING_OS_QNX_HELPERS_HPP

#include <cstdint>
#include <optional>
#include <vector>

#include "qiling/core.hpp"

namespace qiling {
namespace os {
namespace qnx {

// helpers.py QnxConn: the connection record (the pid, the channel id and the
// optional backing file descriptor — the std streams occupy 0..2)
struct QnxConn {
    std::uint32_t pid;
    std::uint32_t chid;
    std::optional<int> fd;

    QnxConn(std::uint32_t pid_, std::uint32_t chid_, std::optional<int> fd_ = std::nullopt)
        : pid(pid_), chid(chid_), fd(fd_) {}
};

// helpers.py get_message_body: the positive parts count rides the iov form
// (only the first iov entry is walked, verbatim); the negative count is the
// flat byte length
std::vector<std::uint8_t> get_message_body(Qiling& ql, std::uint64_t msg, std::int32_t parts);

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_HELPERS_HPP
