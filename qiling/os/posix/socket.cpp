// Ported from qiling/os/posix/filestruct.py ql_socket + syscall/socket.py —
// sub-slice 1: the socket/shutdown core. The host socket rides the CRT
// sockets API (winsock on _WIN32 with the one-time WSAStartup, the POSIX
// sockets elsewhere).
//
// the winsock ordering gotcha: winsock2.h MUST precede windows.h (unicorn's
// headers pull windows.h) — the lean-and-mean + the winsock-first include
// block, then the rest
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "qiling/os/posix/socket.hpp"

#include <cstring>

#include "qiling/exception.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/os/posix/syscall.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/memory.hpp"

namespace qiling {
namespace os {
namespace posix {

namespace {

#ifdef _WIN32

// the one-time winsock init (the python socket module does it internally)
bool wsa_started() {
    static const bool ok = [] {
        WSADATA data{};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return ok;
}

std::uintptr_t host_socket_open(int domain, int socktype, int protocol) {
    if (!wsa_started()) {
        throw QlErrorBase("WSAStartup failed");
    }
    const SOCKET s = ::socket(domain, socktype, protocol);
    if (s == INVALID_SOCKET) {
        // the OSError translations (the "Protocol not supported" family)
        switch (WSAGetLastError()) {
            case WSAEAFNOSUPPORT:
                throw QlErrorBase("address family not supported");
            case WSAEPROTONOSUPPORT:
            case WSAESOCKTNOSUPPORT:
                throw QlErrorBase("protocol not supported");
            default:
                throw QlErrorBase("socket open failed");
        }
    }
    return static_cast<std::uintptr_t>(s);
}

void host_socket_close(std::uintptr_t handle) {
    ::closesocket(static_cast<SOCKET>(handle));
}

int host_socket_shutdown(std::uintptr_t handle, int how) {
    return ::shutdown(static_cast<SOCKET>(handle), how);
}

#else

std::uintptr_t host_socket_open(int domain, int socktype, int protocol) {
    const int fd = ::socket(domain, socktype, protocol);
    if (fd < 0) {
        throw QlErrorBase("socket open failed");
    }
    return static_cast<std::uintptr_t>(fd);
}

void host_socket_close(std::uintptr_t handle) {
    ::close(static_cast<int>(handle));
}

int host_socket_shutdown(std::uintptr_t handle, int how) {
    return ::shutdown(static_cast<int>(handle), how);
}

#endif

// the host socket-type passthrough (the SOCK_* ABI values match on the
// supported hosts; the mips table lands with its slice)
int host_socket_type(int vsock_type) {
    switch (vsock_type) {
        case kSockStream:
        case kSockDgram:
        case kSockRaw:
        case kSockSeqpacket:
            return vsock_type;
        default:
            return vsock_type;  // the raw passthrough (the host rejects)
    }
}

}  // namespace

QlSocket::QlSocket(std::uintptr_t host_handle, int domain, int socktype, int protocol)
    : host_handle_(host_handle), family_(domain), socktype_(socktype), protocol_(protocol) {
}

QlSocket::~QlSocket() {
    if (!closed_ && host_handle_ != 0) {
        host_socket_close(host_handle_);
    }
}

std::shared_ptr<QlSocket> QlSocket::open(int domain, int socktype, int protocol) {
    return std::shared_ptr<QlSocket>(
        new QlSocket(host_socket_open(domain, host_socket_type(socktype), protocol),
                     domain, socktype, protocol));
}

std::vector<std::uint8_t> QlSocket::read(std::size_t read_len) {
    // ql_socket.read: the os.read over the socket fd (the recv without flags)
    std::vector<std::uint8_t> out(read_len, 0);
#ifdef _WIN32
    const int n = ::recv(static_cast<SOCKET>(host_handle_), reinterpret_cast<char*>(out.data()),
                         static_cast<int>(read_len), 0);
#else
    const ssize_t n = ::read(static_cast<int>(host_handle_), out.data(), read_len);
#endif
    if (n < 0) {
        out.clear();
        return out;
    }
    out.resize(static_cast<std::size_t>(n));
    return out;
}

std::size_t QlSocket::write(const std::vector<std::uint8_t>& write_buf) {
    // ql_socket.write: the os.write over the socket fd
#ifdef _WIN32
    const int n = ::send(static_cast<SOCKET>(host_handle_),
                         reinterpret_cast<const char*>(write_buf.data()),
                         static_cast<int>(write_buf.size()), 0);
#else
    const ssize_t n = ::write(static_cast<int>(host_handle_), write_buf.data(), write_buf.size());
#endif
    return n < 0 ? 0 : static_cast<std::size_t>(n);
}

int QlSocket::fileno() {
#ifdef _WIN32
    return static_cast<int>(host_handle_);
#else
    return static_cast<int>(host_handle_);
#endif
}

void QlSocket::close() {
    if (!closed_ && host_handle_ != 0) {
        host_socket_close(host_handle_);
        closed_ = true;
    }
}

bool QlSocket::shutdown(int how) {
    // ql_socket.shutdown: the ConnectionError shapes onto the caller's -1
    return host_socket_shutdown(host_handle_, how) == 0;
}

std::optional<std::int64_t> syscall_socket(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_socket(domain, socktype, protocol): the next free fd slot,
    // the open through the host sockets API, the fd-table ride
    const auto domain = static_cast<int>(params[0]);
    const auto socktype = static_cast<int>(params[1]);
    const auto protocol = static_cast<int>(params[2]);

    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    int idx = -1;
    for (int i = 0; i < QlFileDes::NR_OPEN; ++i) {
        if (fd_table.at(i) == nullptr) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        return -24;  // -EMFILE
    }

    try {
        auto sock = QlSocket::open(domain, socktype, protocol);
        fd_table.set(idx, std::move(sock));
    } catch (const QlErrorBase&) {
        // the "May raise error: Protocol not supported" branch — the open
        // failure collapses onto -1 (the upstream sets idx = -1)
        return -1;
    }

    return idx;
}

std::optional<std::int64_t> syscall_shutdown(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_shutdown(sockfd, how)
    const auto sockfd = static_cast<std::int64_t>(params[0]);
    const auto how = static_cast<int>(params[1]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        // the "not an opened socket" rides -EBADF/-ENOTSOCK — the port
        // collapses the non-socket fd onto -ENOTSOCK (the upstream's
        // isinstance check)
        return -88;  // -ENOTSOCK
    }

    try {
        if (!sock->shutdown(how)) {
            return -1;  // the ConnectionError branch
        }
    } catch (const QlErrorBase&) {
        return -1;
    }
    return 0;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
