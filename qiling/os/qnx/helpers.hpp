// Ported from qiling/os/qnx/helpers.py — the QNX connection record (the
// coid → pid/chid/fd triple behind the kernel's connection table).
#ifndef QILING_OS_QNX_HELPERS_HPP
#define QILING_OS_QNX_HELPERS_HPP

#include <cstdint>
#include <optional>

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

}  // namespace qnx
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_QNX_HELPERS_HPP
