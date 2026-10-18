// Ported from qiling/os/posix/filestruct.py ql_socket + the socket.py
// handlers — sub-slice 1: the socket/shutdown core (the socket creation,
// the fd-table ride, the shutdown). The connect/bind/listen/accept and the
// send/recv families land with their sub-slices; the frame-level state
// (the guest sockaddr parse) rides the same QlSocket.
#pragma once

#include "qiling/core.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace qiling {
namespace os {
namespace posix {

// the guest socket-type constants (the linux ABI values; the host
// SOCK_STREAM/DGRAM/RAW values match verbatim on the windows and the posix
// hosts — the mips table lands with its slice)
inline constexpr int kSockStream = 1;
inline constexpr int kSockDgram = 2;
inline constexpr int kSockRaw = 3;
inline constexpr int kSockSeqpacket = 5;
// the guest domain constants (the linux ABI; the host AF_INET/AF_UNIX
// values match, the AF_INET6 maps 10→23 on the windows host)
inline constexpr int kAfUnix = 1;
inline constexpr int kAfInet = 2;
inline constexpr int kAfInet6 = 10;
// the shutdown how values (the SHUT_* ABI)
inline constexpr int kShutRd = 0;
inline constexpr int kShutWr = 1;
inline constexpr int kShutRdwr = 2;

// filestruct.py ql_socket — the host socket wrapped in the fs-mapped
// object interface
class QlSocket : public QlFsMappedObject {
public:
    // ql_socket.open(domain, socktype, protocol): the host socket call;
    // the OSError shapes map onto the QlError* translations
    static std::shared_ptr<QlSocket> open(int domain, int socktype, int protocol);

    ~QlSocket() override;

    std::vector<std::uint8_t> read(std::size_t read_len) override;
    std::size_t write(const std::vector<std::uint8_t>& write_buf) override;
    int fileno() override;
    void close() override;

    // shutdown(how): the ConnectionError shapes onto -1 at the caller
    // (returns false when the host socket errors)
    bool shutdown(int how);

    // connect/bind/listen/accept (the sockaddr variants ride the guest-
    // parsed tuples — the AF_UNIX path string, the AF_INET (host, port) pair)
    bool connect_unix(const std::string& hpath);
    bool connect_inet(const std::string& host, std::uint16_t port);
    bool bind_unix(const std::string& hpath);
    bool bind_inet(const std::string& host, std::uint16_t port);
    bool listen(int backlog);
    // accept: the new connection socket + the peer (host, port) for the
    // AF_INET (the empty pair for the unix sockets); nullptr on the failure
    std::shared_ptr<QlSocket> accept(std::string& peer_path, std::string& peer_host,
                                     std::uint16_t& peer_port);

    int family() const noexcept { return family_; }
    int socktype() const noexcept { return socktype_; }
    int protocol() const noexcept { return protocol_; }

private:
    explicit QlSocket(std::uintptr_t host_handle, int domain, int socktype, int protocol);

    std::uintptr_t host_handle_ = 0;  // the host socket handle (the SOCKET
                                      // on _WIN32, the fd elsewhere)
    bool closed_ = false;
    int family_ = 0;
    int socktype_ = 0;
    int protocol_ = 0;
};

std::optional<std::int64_t> syscall_socket(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_shutdown(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_connect(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_bind(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_listen(Qiling& ql, const std::vector<std::uint64_t>& params);
std::optional<std::int64_t> syscall_accept(Qiling& ql, const std::vector<std::uint64_t>& params);

}  // namespace posix
}  // namespace os
}  // namespace qiling
