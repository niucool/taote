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
#include <afunix.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
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


// the level/option mapping (the const_mapping.py two-stage shape: the
// guest value → the name via the linux tables, the name → the host constant
// via the winsock/POSIX constants). The SOL_SOCKET options carry the full
// tables; the IPPROTO_IP/TCP option tables land with their slices.
#ifdef _WIN32
constexpr int kHostSolSocket = 0xffff;
#else
constexpr int kHostSolSocket = SOL_SOCKET;
#endif

int host_socket_level(int vsock_level) {
    // the linux_x86_socket_level table: SOL_SOCKET 0x1, IPPROTO_IP 0x0,
    // IPPROTO_TCP 0x6, IPPROTO_UDP 0x11, IPPROTO_IPV6 0x29, IPPROTO_RAW 0xff
    switch (vsock_level) {
        case 0x0000:
        case 0x0006:
        case 0x0011:
        case 0x0029:
        case 0x00ff:
            return vsock_level;  // the non-SOL levels pass through (the
                                 // host protocol constants match)
        case 0x0001:
            return kHostSolSocket;
        default:
            throw QlErrorBase("Could not convert emulated socket level " +
                              std::to_string(vsock_level) +
                              " to a socket level name");
    }
}

int host_socket_option(int vsock_level, int vsock_opt) {
    // the linux_x86_socket_options table → the host constants (the winsock
    // values differ from the linux ones; the POSIX hosts match verbatim)
    switch (vsock_opt) {
        case 0x0001: return SO_DEBUG;
        case 0x0002: return SO_REUSEADDR;
        case 0x0003: return SO_TYPE;
        case 0x0004: return SO_ERROR;
        case 0x0005: return SO_DONTROUTE;
        case 0x0006: return SO_BROADCAST;
        case 0x0007: return SO_SNDBUF;
        case 0x0008: return SO_RCVBUF;
        case 0x0009: return SO_KEEPALIVE;
        case 0x000a: return SO_OOBINLINE;
        case 0x000d: return SO_LINGER;
        default:
            throw QlErrorBase("Could not convert emulated socket option " +
                              std::to_string(vsock_opt) +
                              " to a host socket option");
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

std::vector<std::uint8_t> QlSocket::getsockopt(int level, int optname, std::size_t buflen) {
#ifdef _WIN32
    std::vector<std::uint8_t> out(buflen, 0);
    int len = static_cast<int>(buflen);
    if (::getsockopt(static_cast<SOCKET>(host_handle_), level, optname,
                     reinterpret_cast<char*>(out.data()), &len) != 0) {
        throw QlErrorBase("getsockopt failed");
    }
    out.resize(static_cast<std::size_t>(len));
    return out;
#else
    std::vector<std::uint8_t> out(buflen, 0);
    socklen_t len = static_cast<socklen_t>(buflen);
    if (::getsockopt(static_cast<int>(host_handle_), level, optname,
                     out.data(), &len) != 0) {
        throw QlErrorBase("getsockopt failed");
    }
    out.resize(static_cast<std::size_t>(len));
    return out;
#endif
}

bool QlSocket::setsockopt(int level, int optname, const std::vector<std::uint8_t>& value) {
#ifdef _WIN32
    return ::setsockopt(static_cast<SOCKET>(host_handle_), level, optname,
                        reinterpret_cast<const char*>(value.data()),
                        static_cast<int>(value.size())) == 0;
#else
    return ::setsockopt(static_cast<int>(host_handle_), level, optname,
                        value.data(), static_cast<socklen_t>(value.size())) == 0;
#endif
}

std::pair<std::shared_ptr<QlSocket>, std::shared_ptr<QlSocket>> QlSocket::socketpair(int domain,
                                                                                     int socktype,
                                                                                     int protocol) {
#ifdef _WIN32
    // the winsock socketpair lacks — the loopback accept walk (the classic
    // emulation: the listener + the connector on 127.0.0.1:0)
    const SOCKET listener = ::socket(domain, socktype, protocol);
    if (listener == INVALID_SOCKET) {
        throw QlErrorBase("socketpair: listener failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(listener, 1) != 0) {
        ::closesocket(listener);
        throw QlErrorBase("socketpair: bind/listen failed");
    }
    sockaddr_in bound{};
    int blen = sizeof(bound);
    ::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &blen);

    const SOCKET client = ::socket(domain, socktype, protocol);
    if (client == INVALID_SOCKET) {
        ::closesocket(listener);
        throw QlErrorBase("socketpair: client failed");
    }
    // the connect rides the BOUND address verbatim (the family, the loopback
    // addr, the ephemeral port off the getsockname)
    if (::connect(client, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) != 0) {
        ::closesocket(client);
        ::closesocket(listener);
        throw QlErrorBase("socketpair: connect failed");
    }
    sockaddr_in peer{};
    int plen = sizeof(peer);
    const SOCKET server = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &plen);
    ::closesocket(listener);
    if (server == INVALID_SOCKET) {
        ::closesocket(client);
        throw QlErrorBase("socketpair: accept failed");
    }
    return {std::shared_ptr<QlSocket>(new QlSocket(static_cast<std::uintptr_t>(client), domain, socktype, protocol)),
            std::shared_ptr<QlSocket>(new QlSocket(static_cast<std::uintptr_t>(server), domain, socktype, protocol))};
#else
    int sv[2] = {-1, -1};
    if (::socketpair(domain, socktype, protocol, sv) != 0) {
        throw QlErrorBase("socketpair failed");
    }
    return {std::shared_ptr<QlSocket>(new QlSocket(static_cast<std::uintptr_t>(sv[0]), domain, socktype, protocol)),
            std::shared_ptr<QlSocket>(new QlSocket(static_cast<std::uintptr_t>(sv[1]), domain, socktype, protocol))};
#endif
}

std::vector<std::uint8_t> QlSocket::recv(std::size_t bufsize, int flags) {
    // ql_socket.recv: the socket.recv(bufsize, flags)
    std::vector<std::uint8_t> out(bufsize, 0);
#ifdef _WIN32
    const int n = ::recv(static_cast<SOCKET>(host_handle_), reinterpret_cast<char*>(out.data()),
                         static_cast<int>(bufsize), flags);
#else
    const ssize_t n = ::recv(static_cast<int>(host_handle_), out.data(), bufsize, flags);
#endif
    if (n < 0) {
        return {};  // the OSError shapes onto the empty read at the caller
    }
    out.resize(static_cast<std::size_t>(n));
    return out;
}

std::int64_t QlSocket::send(const std::vector<std::uint8_t>& data, int flags) {
    // ql_socket.send: the socket.send(data, flags)
#ifdef _WIN32
    const int n = ::send(static_cast<SOCKET>(host_handle_),
                         reinterpret_cast<const char*>(data.data()),
                         static_cast<int>(data.size()), flags);
#else
    const ssize_t n = ::send(static_cast<int>(host_handle_), data.data(), data.size(), flags);
#endif
    return n < 0 ? 0 : static_cast<std::int64_t>(n);
}

bool QlSocket::shutdown(int how) {
    // ql_socket.shutdown: the ConnectionError shapes onto the caller's -1
    return host_socket_shutdown(host_handle_, how) == 0;
}

bool QlSocket::connect_unix(const std::string& hpath) {
#ifdef _WIN32
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto len = hpath.size() < sizeof(addr.sun_path) - 1 ? hpath.size() : sizeof(addr.sun_path) - 1;
    std::memcpy(addr.sun_path, hpath.c_str(), len);
    addr.sun_path[len] = '\0';
    return ::connect(static_cast<SOCKET>(host_handle_), reinterpret_cast<sockaddr*>(&addr),
                     static_cast<int>(sizeof(addr))) == 0;
#else
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto len = hpath.size() < sizeof(addr.sun_path) - 1 ? hpath.size() : sizeof(addr.sun_path) - 1;
    std::memcpy(addr.sun_path, hpath.c_str(), len);
    addr.sun_path[len] = '\0';
    return ::connect(static_cast<int>(host_handle_), reinterpret_cast<sockaddr*>(&addr),
                     static_cast<socklen_t>(sizeof(addr))) == 0;
#endif
}

bool QlSocket::connect_inet(const std::string& host, std::uint16_t port) {
    // the getaddrinfo walk (the python socket.connect resolves the host
    // through getaddrinfo as well)
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || res == nullptr) {
        return false;
    }
#ifdef _WIN32
    const int rc = ::connect(static_cast<SOCKET>(host_handle_), res->ai_addr,
                             static_cast<int>(res->ai_addrlen));
#else
    const int rc = ::connect(static_cast<int>(host_handle_), res->ai_addr,
                             static_cast<socklen_t>(res->ai_addrlen));
#endif
    ::freeaddrinfo(res);
    return rc == 0;
}

bool QlSocket::bind_unix(const std::string& hpath) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto len = hpath.size() < sizeof(addr.sun_path) - 1 ? hpath.size() : sizeof(addr.sun_path) - 1;
    std::memcpy(addr.sun_path, hpath.c_str(), len);
    addr.sun_path[len] = '\0';
#ifdef _WIN32
    return ::bind(static_cast<SOCKET>(host_handle_), reinterpret_cast<sockaddr*>(&addr),
                  static_cast<int>(sizeof(addr))) == 0;
#else
    return ::bind(static_cast<int>(host_handle_), reinterpret_cast<sockaddr*>(&addr),
                  static_cast<socklen_t>(sizeof(addr))) == 0;
#endif
}

bool QlSocket::bind_inet(const std::string& host, std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
#ifdef _WIN32
    addr.sin_port = ::htons(port);
#else
    addr.sin_port = ::htons(port);
#endif
    addr.sin_addr.s_addr = ::inet_addr(host.c_str());
#ifdef _WIN32
    return ::bind(static_cast<SOCKET>(host_handle_), reinterpret_cast<sockaddr*>(&addr),
                  static_cast<int>(sizeof(addr))) == 0;
#else
    return ::bind(static_cast<int>(host_handle_), reinterpret_cast<sockaddr*>(&addr),
                  static_cast<socklen_t>(sizeof(addr))) == 0;
#endif
}

bool QlSocket::listen(int backlog) {
#ifdef _WIN32
    return ::listen(static_cast<SOCKET>(host_handle_), backlog) == 0;
#else
    return ::listen(static_cast<int>(host_handle_), backlog) == 0;
#endif
}

std::shared_ptr<QlSocket> QlSocket::accept(std::string& peer_path, std::string& peer_host,
                                           std::uint16_t& peer_port) {
    // the accept walk: the AF_INET peers carry (host, port); the AF_UNIX
    // peers carry the path; the AF_UNSPEC result rides the accepted socket
    sockaddr_storage peer{};
#ifdef _WIN32
    int peer_len = static_cast<int>(sizeof(peer));
    const SOCKET conn = ::accept(static_cast<SOCKET>(host_handle_),
                                 reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (conn == INVALID_SOCKET) {
        return nullptr;
    }
    const auto conn_handle = static_cast<std::uintptr_t>(conn);
#else
    socklen_t peer_len = static_cast<socklen_t>(sizeof(peer));
    const int conn = ::accept(static_cast<int>(host_handle_),
                              reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (conn < 0) {
        return nullptr;
    }
    const auto conn_handle = static_cast<std::uintptr_t>(conn);
#endif
    peer_path.clear();
    peer_host.clear();
    peer_port = 0;

    if (peer.ss_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&peer);
        char buf[INET_ADDRSTRLEN] = {0};
#ifdef _WIN32
        ::inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf));
#else
        ::inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf));
#endif
        peer_host = buf;
        peer_port = ::ntohs(in->sin_port);
    } else if (peer.ss_family == AF_UNIX) {
        const auto* un = reinterpret_cast<const sockaddr_un*>(&peer);
        peer_path = std::string(un->sun_path);
    }

    return std::shared_ptr<QlSocket>(new QlSocket(conn_handle, static_cast<int>(peer.ss_family),
                                                  socktype_, protocol_));
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

// the sockaddr parse: the family word (u16 LE) then the family-specific
// body — the AF_UNIX path rides the sun_path bytes, the AF_INET the
// (port BE u16, the 4-byte s_addr)
struct SockaddrView {
    int family = 0;
    std::string unix_path;   // the sun_path partition at the NUL
    std::string inet_host;   // the dotted-quad
    std::uint16_t inet_port = 0;
};

SockaddrView parse_sockaddr(Qiling& ql, std::uint64_t addr, std::uint64_t addrlen) {
    SockaddrView out;
    if (addrlen < 2) {
        return out;
    }
    const auto raw = ql.mem().read(addr, addrlen);
    out.family = static_cast<std::uint16_t>(raw[0] | (raw[1] << 8));

    if (out.family == kAfUnix) {
        for (std::size_t i = 2; i < raw.size(); ++i) {
            if (raw[i] == 0) {
                break;  // the sun_path partitions at the first NUL
            }
            out.unix_path.push_back(static_cast<char>(raw[i]));
        }
    } else if (out.family == kAfInet && addrlen >= 8) {
        // the local name avoids the winsock in_addr s_addr macro collision
        const std::uint32_t raw_addr = static_cast<std::uint32_t>(raw[4]) |
                                       (static_cast<std::uint32_t>(raw[5]) << 8) |
                                       (static_cast<std::uint32_t>(raw[6]) << 16) |
                                       (static_cast<std::uint32_t>(raw[7]) << 24);
        char buf[16] = {0};
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      (raw_addr >> 0) & 0xff, (raw_addr >> 8) & 0xff,
                      (raw_addr >> 16) & 0xff, (raw_addr >> 24) & 0xff);
        out.inet_host = buf;
        out.inet_port = static_cast<std::uint16_t>((raw[2] << 8) | raw[3]);  // the network order
    }
    return out;
}

std::optional<std::int64_t> syscall_connect(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_connect(sockfd, addr, addrlen)
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    const auto sa = parse_sockaddr(ql, params[1], params[2]);
    if (sa.family != sock->family()) {
        return -1;  // the family-mismatch branch (the upstream returns -1)
    }

    bool ok = false;
    if (sa.family == kAfUnix) {
        // ql_unix_socket_path: the virtual path rides the rootfs transform
        // (the abstract namespace rides the raw bytes; the TODO verbatim)
        std::string dest = sa.unix_path;
        if (!dest.empty() && dest.front() != char{0}) {
            dest = ql.os().path()->virtual_to_host_path(dest);
        }
        ok = sock->connect_unix(dest);
    } else if (sa.family == kAfInet) {
        ok = sock->connect_inet(sa.inet_host, sa.inet_port);
    } else {
        return -47;  // -EAFNOSUPPORT
    }

    if (!ok) {
        // the (ConnectionError, FileNotFoundError) branch — the errno
        // granularity rides the typed-translation slice; -1 for now
        return -1;
    }
    return 0;
}

std::optional<std::int64_t> syscall_bind(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_bind(sockfd, addr, addrlen): the bindtolocalhost and the
    // unprivileged-port shift ride the os flags (the defaults hold here —
    // bindtolocalhost=false, root=false → the 8000 shift for the <=1024
    // ports, the verbatim shape)
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    auto sa = parse_sockaddr(ql, params[1], params[2]);
    if (sa.family == kAfUnix) {
        // ql_unix_socket_path: the vpath -> the host path via the rootfs
        std::string dest = sa.unix_path;
        if (!dest.empty() && dest.front() != char{0}) {
            dest = ql.os().path()->virtual_to_host_path(dest);
        }
        if (!sock->bind_unix(dest)) {
            return -13;  // -EACCES (the errno granularity rides its slice)
        }
        return 0;
    }
    if (sa.family == kAfInet) {
        if (sa.inet_port != 0 && sa.inet_port <= 1024) {
            sa.inet_port = static_cast<std::uint16_t>(sa.inet_port + 8000);
        }
        if (!sock->bind_inet(sa.inet_host, sa.inet_port)) {
            return -13;
        }
        return 0;
    }
    return -47;  // -EAFNOSUPPORT
}

std::optional<std::int64_t> syscall_listen(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_listen(sockfd, backlog)
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }
    if (!sock->listen(static_cast<int>(params[1]))) {
        return -13;  // the ConnectionError errno shape
    }
    return 0;
}

std::optional<std::int64_t> syscall_accept(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_accept(sockfd, addr, addrlenptr): the new connection rides
    // the next free fd; the peer sockaddr writes back when the addr is set
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    std::string peer_path;
    std::string peer_host;
    std::uint16_t peer_port = 0;
    std::shared_ptr<QlSocket> conn;
    try {
        conn = sock->accept(peer_path, peer_host, peer_port);
    } catch (const QlErrorBase&) {
        return -1;  // the ConnectionError branch
    }
    if (conn == nullptr) {
        return -1;  // the BlockingIOError/ConnectionError shape
    }

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
    fd_table.set(idx, conn);

    if (params[1] != 0) {
        // the peer sockaddr write-back: the AF_INET peers carry the
        // (family, port BE, addr BE) triple
        if (conn->family() == kAfInet) {
            std::vector<std::uint8_t> sa(16, 0);
            sa[0] = 0x02;
            sa[1] = 0x00;
            sa[2] = static_cast<std::uint8_t>(peer_port >> 8);
            sa[3] = static_cast<std::uint8_t>(peer_port & 0xff);
            // the s_addr fills from the host parse (the inet_aton inverse)
            unsigned a = 0, b = 0, c = 0, d = 0;
            std::sscanf(peer_host.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
            sa[4] = static_cast<std::uint8_t>(a);
            sa[5] = static_cast<std::uint8_t>(b);
            sa[6] = static_cast<std::uint8_t>(c);
            sa[7] = static_cast<std::uint8_t>(d);
            const auto addrlen = ql.mem().read_ptr(params[2]);
            ql.mem().write(params[1], sa);
            ql.mem().write_ptr(params[2], 16);
            (void)addrlen;
        } else if (conn->family() == kAfUnix) {
            std::vector<std::uint8_t> sa(110, 0);
            sa[0] = 0x01;
            sa[1] = 0x00;
            const auto bytes = std::vector<std::uint8_t>(peer_path.begin(), peer_path.end());
            std::memcpy(sa.data() + 2, bytes.data(), std::min<std::size_t>(bytes.size(), 107));
            ql.mem().write(params[1], sa);
            ql.mem().write_ptr(params[2], 110);
        }
    }

    return idx;
}

std::optional<std::int64_t> syscall_recv(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_recv(sockfd, buf, length, flags): the recv bytes land at
    // the buf, the count rides the return (the upstream writes the content
    // verbatim — the empty read writes nothing)
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    const auto content = sock->recv(static_cast<std::size_t>(params[2]), static_cast<int>(params[3]));
    if (!content.empty()) {
        ql.mem().write(params[1], content);
    }
    return static_cast<std::int64_t>(content.size());
}

std::optional<std::int64_t> syscall_send(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_send(sockfd, buf, length, flags): the IOError branch rides
    // the 0 (the verbatim "regreturn = 0")
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    const auto content = ql.mem().read(params[1], static_cast<std::size_t>(params[2]));
    return sock->send(content, static_cast<int>(params[3]));
}

std::optional<std::int64_t> syscall_sendto(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_sendto(sockfd, buf, length, flags, addr, addrlen): the
    // connection-mode sockets and the NULL addr ride the send body (the
    // verbatim "calling sendto with NULL addr is equivalent to send")
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    if (sock->socktype() == kSockStream || sock->socktype() == kSockSeqpacket ||
        (params[4] == 0 && params[5] == 0)) {
        return syscall_send(ql, {params[0], params[1], params[2], params[3]});
    }

    // the datagram sendto rides its sub-slice (the dest parse + the
    // sendto host call)
    throw QlErrorBase("sendto: the datagram dest path lands with its slice");
}

std::optional<std::int64_t> syscall_recvfrom(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_recvfrom(sockfd, buf, length, flags, addr, addrlen): the
    // STREAM sockets and the NULL addr ride the recv body (the verbatim
    // "calling recvfrom with a NULL addr is identical to calling recv")
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    if (sock->socktype() == kSockStream || (params[4] == 0 && params[5] == 0)) {
        return syscall_recv(ql, {params[0], params[1], params[2], params[3]});
    }

    throw QlErrorBase("recvfrom: the datagram src path lands with its slice");
}


std::optional<std::int64_t> syscall_getsockopt(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_getsockopt(sockfd, level, optname, optval_addr, optlen_addr):
    // the optlen rides the in-out cell (the min-1024 clamp verbatim); the
    // level/option names ride the two-stage mapping
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    auto optlen = static_cast<std::int64_t>(ql.mem().read_ptr(params[4], 4));
    if (optlen > 1024) {
        optlen = 1024;
    }
    if (optlen < 0) {
        return -22;  // -EINVAL (the verbatim check)
    }

    try {
        const auto hlevel = host_socket_level(static_cast<int>(params[1]));
        const auto hopt = host_socket_option(hlevel, static_cast<int>(params[2]));
        const auto optval = sock->getsockopt(hlevel, hopt, static_cast<std::size_t>(optlen));
        if (!optval.empty()) {
            ql.mem().write(params[3], optval);
        }
    } catch (const QlErrorBase&) {
        return -22;  // the OSError errno shape
    }
    return 0;
}

std::optional<std::int64_t> syscall_setsockopt(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_setsockopt(sockfd, level, optname, optval_addr, optlen):
    // the NULL optval rides the empty-value host call (the verbatim
    // "value is None" branch); the level/option names ride the mapping
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    try {
        const auto hlevel = host_socket_level(static_cast<int>(params[1]));
        const auto hopt = host_socket_option(hlevel, static_cast<int>(params[2]));
        if (params[3] == 0) {
            if (!sock->setsockopt(hlevel, hopt, {})) {
                return -22;
            }
            return 0;
        }
        const auto optval = ql.mem().read(params[3], static_cast<std::size_t>(params[4]));
        if (!sock->setsockopt(hlevel, hopt, optval)) {
            std::fprintf(stderr, "[sopt] set failed\n");
            return -22;  // the OSError errno shape
        }
        return 0;
    } catch (const QlErrorBase& e) {
        std::fprintf(stderr, "[sopt] throw=%s\n", e.what());
        // the NotImplementedError shapes propagate upstream — the port
        // degrades onto -EINVAL (the errno-granularity deferral)
        return -22;
    }
}

std::optional<std::int64_t> syscall_socketpair(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_socketpair(domain, socktype, protocol, sv): the two fds
    // into the sv pair (the i32 writes at sv+0/sv+4 — the upstream's
    // write_ptr(sv+0, idx1) / (sv+4, idx2) verbatim)
    const auto domain = static_cast<int>(params[0]);
    const auto socktype = static_cast<int>(params[1]);
    const auto protocol = static_cast<int>(params[2]);
    const auto sv = params[3];

    auto& fd_table = ql.os<posix::QlOsPosix>().fd();
    int idx1 = -1;
    int idx2 = -1;
    for (int i = 0; i < QlFileDes::NR_OPEN; ++i) {
        if (fd_table.at(i) == nullptr) {
            if (idx1 == -1) {
                idx1 = i;
            } else {
                idx2 = i;
                break;
            }
        }
    }
    if (idx1 == -1 || idx2 == -1) {
        return -24;  // -EMFILE
    }

    try {
        auto pair = QlSocket::socketpair(domain, socktype, protocol);
        fd_table.set(idx1, pair.first);
        fd_table.set(idx2, pair.second);
    } catch (const QlErrorBase&) {
        return -1;  // the OSError branch
    }

    ql.mem().write_ptr(sv, static_cast<std::uint64_t>(idx1), 4);
    ql.mem().write_ptr(sv + 4, static_cast<std::uint64_t>(idx2), 4);
    return 0;
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
