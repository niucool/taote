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
#include <mswsock.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
    // the WSA_FLAG_OVERLAPPED socket — the WSARecvMsg ride (the msg-family
    // slice) requires the overlapped attribute (the msdn WSARecvMsg pin)
    const SOCKET s = ::WSASocketW(domain, socktype, protocol, nullptr, 0,
                                  WSA_FLAG_OVERLAPPED);
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
    // the linux_x86_socket_options / linux_socket_ip_options /
    // linux_socket_tcp_options tables → the host constants (the winsock
    // values differ from the linux ones; the POSIX hosts match verbatim).
    // The host-undefined options throw (the NotImplementedError shape).
    if (vsock_level == 0x0000) {  // IPPROTO_IP — the linux_socket_ip_options
        switch (vsock_opt) {
            case 0x0001: return IP_TOS;
            case 0x0002: return IP_TTL;
            case 0x0003: return IP_HDRINCL;
            case 0x0004: return IP_OPTIONS;
            case 0x0008: return IP_PKTINFO;
            case 0x0020: return IP_MULTICAST_IF;
            case 0x0021: return IP_MULTICAST_TTL;
            case 0x0022: return IP_MULTICAST_LOOP;
            case 0x0023: return IP_ADD_MEMBERSHIP;
            case 0x0024: return IP_DROP_MEMBERSHIP;
            case 0x0027: return IP_ADD_SOURCE_MEMBERSHIP;
            case 0x0028: return IP_DROP_SOURCE_MEMBERSHIP;
            default:
                break;  // the linux-only names (IP_MTU_DISCOVER, IP_RECVERR,
                        // ...) have no host constant — the throw below
        }
    } else if (vsock_level == 0x0006) {  // IPPROTO_TCP — linux_socket_tcp_options
        switch (vsock_opt) {
            case 0x01: return TCP_NODELAY;
            case 0x02: return TCP_MAXSEG;
            case 0x04: return TCP_KEEPIDLE;
            case 0x05: return TCP_KEEPINTVL;
            case 0x06: return TCP_KEEPCNT;
            default:
                break;  // the linux-only names (TCP_CORK, TCP_INFO, ...) —
                        // the throw below
        }
    } else {
        // the SOL_SOCKET table (the linux_x86_socket_options walk)
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
                break;
        }
    }
    throw QlErrorBase("Could not convert emulated socket option " +
                      std::to_string(vsock_opt) +
                      " to a host socket option");
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

std::int64_t QlSocket::sendto(const std::vector<std::uint8_t>& data, int flags, const std::string& path,
                              const std::string& host, std::uint16_t port) {
    // ql_socket.sendto: the socket.sendto(buf, flags, dest) — the AF_UNIX
    // rides the path, the AF_INET the (host, port); -1 on the error (the
    // caller maps the ConnectionError/FileNotFoundError shapes onto 0)
    sockaddr_storage ss{};
    socklen_t slen = 0;
    if (!path.empty()) {
        auto* un = reinterpret_cast<sockaddr_un*>(&ss);
        un->sun_family = static_cast<decltype(un->sun_family)>(kAfUnix);
        const auto plen = std::min(path.size(), sizeof(un->sun_path));
        std::memcpy(un->sun_path, path.data(), plen);
        slen = static_cast<socklen_t>(2 + plen);
    } else {
        auto* in = reinterpret_cast<sockaddr_in*>(&ss);
        in->sin_family = static_cast<decltype(in->sin_family)>(kAfInet);
        in->sin_port = ::htons(port);
        ::inet_pton(AF_INET, host.c_str(), &in->sin_addr);
        slen = sizeof(sockaddr_in);
    }
#ifdef _WIN32
    const int n = ::sendto(static_cast<SOCKET>(host_handle_),
                           reinterpret_cast<const char*>(data.data()),
                           static_cast<int>(data.size()), flags,
                           reinterpret_cast<const sockaddr*>(&ss), slen);
#else
    const ssize_t n = ::sendto(static_cast<int>(host_handle_), data.data(), data.size(), flags,
                               reinterpret_cast<const sockaddr*>(&ss), slen);
#endif
    return n < 0 ? -1 : static_cast<std::int64_t>(n);
}

std::vector<std::uint8_t> QlSocket::recvfrom(std::size_t bufsize, int flags, std::string& path,
                                             std::string& host, std::uint16_t& port) {
    // ql_socket.recvfrom: the socket.recvfrom(bufsize, flags) — the src
    // address rides the out params
    sockaddr_storage ss{};
    std::vector<std::uint8_t> out(bufsize, 0);
#ifdef _WIN32
    int slen = sizeof(ss);
    const int n = ::recvfrom(static_cast<SOCKET>(host_handle_),
                             reinterpret_cast<char*>(out.data()),
                             static_cast<int>(bufsize), flags,
                             reinterpret_cast<sockaddr*>(&ss), &slen);
#else
    socklen_t slen = sizeof(ss);
    const ssize_t n = ::recvfrom(static_cast<int>(host_handle_), out.data(), bufsize, flags,
                                 reinterpret_cast<sockaddr*>(&ss), &slen);
#endif
    path.clear();
    host.clear();
    port = 0;
    if (n <= 0) {
        return {};
    }
    if (ss.ss_family == static_cast<decltype(ss.ss_family)>(kAfUnix)) {
        const auto* un = reinterpret_cast<const sockaddr_un*>(&ss);
        const auto have = slen > 2 ? static_cast<std::size_t>(slen) - 2 : 0;
        path.assign(un->sun_path, std::min(have, sizeof(un->sun_path)));
    } else if (ss.ss_family == static_cast<decltype(ss.ss_family)>(kAfInet)) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&ss);
        char buf[INET_ADDRSTRLEN] = {0};
        if (::inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf)) != nullptr) {
            host = buf;
        }
        port = ntohs(in->sin_port);
    }
    out.resize(static_cast<std::size_t>(n));
    return out;
}

bool QlSocket::shutdown(int how) {
    // ql_socket.shutdown: the ConnectionError shapes onto the caller's -1
    return host_socket_shutdown(host_handle_, how) == 0;
}

namespace {

// the shared ancdata parse over the CMSG walk — the POSIX rides the
// cmsghdr (the 4-byte cmsg_len); the winsock walks the WSACMSGHDR (the
// size_t cmsg_len) inline in its branch
#ifndef _WIN32
void collect_ancdata_posix(struct msghdr& msg, QlSocket::RecvMsgResult& out) {
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        const auto* d = reinterpret_cast<const std::uint8_t*>(c) + sizeof(cmsghdr);
        const auto dlen = (c->cmsg_len > sizeof(cmsghdr)) ? static_cast<std::size_t>(c->cmsg_len - sizeof(cmsghdr)) : 0;
        out.ancdata.emplace_back(c->cmsg_level, c->cmsg_type,
                                 std::vector<std::uint8_t>(d, d + dlen));
    }
}
#endif  // !_WIN32

}  // namespace

QlSocket::RecvMsgResult QlSocket::recvmsg(std::size_t bufsize, std::size_t ancbufsize, int flags) {
    // ql_socket.recvmsg: the socket.recvmsg(bufsize, ancbufsize, flags)
    RecvMsgResult out;
#ifdef _WIN32
    // the winsock lacks recvmsg(2) — the WSARecvMsg ride via the extension
    // function pointer (the WSAID_WSARECVMSG dance)
    using LPFN_WSARECVMSG = INT(WSAAPI*)(SOCKET, LPWSAMSG, LPDWORD, LPWSAOVERLAPPED,
                                         LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    static const GUID kRecvMsgGuid = WSAID_WSARECVMSG;  // GUID
    LPFN_WSARECVMSG wsa_recvmsg = nullptr;
    DWORD nbr = 0;
    if (::WSAIoctl(static_cast<SOCKET>(host_handle_), SIO_GET_EXTENSION_FUNCTION_POINTER,
                   const_cast<GUID*>(&kRecvMsgGuid), sizeof(kRecvMsgGuid),
                   &wsa_recvmsg, sizeof(wsa_recvmsg), &nbr, nullptr, nullptr) != 0 ||
        wsa_recvmsg == nullptr) {
        throw QlErrorBase("recvmsg: the WSARecvMsg extension is unavailable");
    }

    std::vector<std::uint8_t> data(bufsize, 0);
    WSABUF wbuf{static_cast<ULONG>(bufsize), reinterpret_cast<char*>(data.data())};
    std::vector<char> ctrl(ancbufsize, 0);
    sockaddr_storage ss{};
    WSAMSG wmsg{};
    wmsg.name = reinterpret_cast<LPSOCKADDR>(&ss);
    wmsg.namelen = static_cast<INT>(sizeof(ss));
    wmsg.lpBuffers = &wbuf;
    wmsg.dwBufferCount = 1;
    wmsg.Control.len = static_cast<ULONG>(ancbufsize);
    wmsg.Control.buf = ctrl.data();
    wmsg.dwFlags = static_cast<DWORD>(flags);
    DWORD nrecvd = 0;
    INT rc = wsa_recvmsg(static_cast<SOCKET>(host_handle_), &wmsg, &nrecvd, nullptr, nullptr);
    if (rc != 0) {
        throw QlErrorBase("recvmsg: the WSARecvMsg call failed");
    }

    data.resize(static_cast<std::size_t>(nrecvd));
    out.data = std::move(data);
    out.mflags = static_cast<int>(wmsg.dwFlags);
    for (WSACMSGHDR* c = CMSG_FIRSTHDR(&wmsg); c != nullptr; c = CMSG_NXTHDR(&wmsg, c)) {
        const auto* d = reinterpret_cast<const std::uint8_t*>(c) + sizeof(WSACMSGHDR);
        const auto dlen = (c->cmsg_len > sizeof(WSACMSGHDR))
                              ? static_cast<std::size_t>(c->cmsg_len - sizeof(WSACMSGHDR))
                              : 0;
        out.ancdata.emplace_back(c->cmsg_level, c->cmsg_type,
                                 std::vector<std::uint8_t>(d, d + dlen));
    }
    (void)nbr;
#else
    std::vector<std::uint8_t> data(bufsize, 0);
    std::vector<char> ctrl(ancbufsize, 0);
    iovec iov{};
    iov.iov_base = data.data();
    iov.iov_len = bufsize;
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.data();
    msg.msg_controllen = ancbufsize;
    msg.msg_flags = flags;
    const auto n = ::recvmsg(static_cast<int>(host_handle_), &msg, flags);
    if (n < 0) {
        throw QlErrorBase("recvmsg: the host recvmsg failed");
    }

    out.data.resize(static_cast<std::size_t>(n));
    out.mflags = msg.msg_flags;
    collect_ancdata_posix(msg, out);
#endif
    return out;
}

namespace {

// the shared local/peer-name walk (the getsockname/getpeername bodies):
// the AF_UNIX path or the AF_INET (host, port) from the host name call
bool host_name_lookup(std::uintptr_t host_handle, bool peer,
                      std::string& path, std::string& host, std::uint16_t& port) {
#ifdef _WIN32
    sockaddr_storage ss{};
    int slen = sizeof(ss);
    const int rc = peer ? ::getpeername(static_cast<SOCKET>(host_handle),
                                        reinterpret_cast<sockaddr*>(&ss), &slen)
                        : ::getsockname(static_cast<SOCKET>(host_handle),
                                        reinterpret_cast<sockaddr*>(&ss), &slen);
    if (rc != 0) {
        return false;
    }
#else
    sockaddr_storage ss{};
    socklen_t slen = sizeof(ss);
    const int rc = peer ? ::getpeername(static_cast<int>(host_handle),
                                        reinterpret_cast<sockaddr*>(&ss), &slen)
                        : ::getsockname(static_cast<int>(host_handle),
                                        reinterpret_cast<sockaddr*>(&ss), &slen);
    if (rc != 0) {
        return false;
    }
#endif
    if (ss.ss_family == static_cast<decltype(ss.ss_family)>(kAfInet)) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&ss);
        char buf[INET_ADDRSTRLEN] = {0};
        if (::inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf)) == nullptr) {
            return false;
        }
        host = buf;
        port = ntohs(in->sin_port);
        return true;
    }
#ifdef _WIN32
    if (ss.ss_family == static_cast<decltype(ss.ss_family)>(kAfUnix)) {
        const auto* un = reinterpret_cast<const sockaddr_un*>(&ss);
        const auto plen = slen > 2 ? static_cast<std::size_t>(slen) - 2 : 0;
        path.assign(un->sun_path, std::min(plen, sizeof(un->sun_path)));
        return true;
    }
#else
    if (ss.ss_family == static_cast<decltype(ss.ss_family)>(kAfUnix)) {
        const auto* un = reinterpret_cast<const sockaddr_un*>(&ss);
        path.assign(un->sun_path, strnlen(un->sun_path, sizeof(un->sun_path)));
        return true;
    }
#endif
    return false;
}

}  // namespace

bool QlSocket::getsockname(std::string& path, std::string& host, std::uint16_t& port) {
    return host_name_lookup(host_handle_, false, path, host, port);
}

bool QlSocket::getpeername(std::string& path, std::string& host, std::uint16_t& port) {
    return host_name_lookup(host_handle_, true, path, host, port);
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

namespace {

// the shared sockaddr write-back (the upstream getsockname/getpeername and
// the accept addr-body shapes): the AF_UNIX path (the host→virtual transform
// + the addrlen truncation) or the AF_INET triple; the save happens when
// objsize <= addrlen while the addrlen cell ALWAYS updates when set
std::size_t write_sockaddr(Qiling& ql, int family, std::uint64_t addr,
                           std::uint64_t addrlenptr, const std::string& path,
                           const std::string& host, std::uint16_t port) {
    const auto addrlen = addrlenptr != 0 ? ql.mem().read_ptr(addrlenptr) : 0;
    std::size_t objsize = 0;
    std::vector<std::uint8_t> obj;

    if (family == kAfUnix) {
        auto vpath = ql.os().path()->host_to_virtual_path(path);
        if (addrlen != 0) {
            // the addrlen indicates the total obj size allowed to be
            // written — that already includes the family field (2) and the
            // path null terminator (1) (the comment verbatim)
            const auto keep = addrlen >= 3 ? static_cast<std::size_t>(addrlen - 3) : 0;
            if (vpath.size() > keep) {
                vpath.resize(keep);
            }
        }
        objsize = 2 + vpath.size() + 1;
        obj.assign(objsize, 0);
        obj[0] = 0x01;
        obj[1] = 0x00;
        std::memcpy(obj.data() + 2, vpath.data(), vpath.size());
    } else if (family == kAfInet) {
        objsize = 16;
        obj.assign(16, 0);
        obj[0] = 0x02;
        obj[1] = 0x00;
        obj[2] = static_cast<std::uint8_t>(port >> 8);
        obj[3] = static_cast<std::uint8_t>(port & 0xff);
        unsigned a = 0, b = 0, c = 0, d = 0;
        std::sscanf(host.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        obj[4] = static_cast<std::uint8_t>(a);
        obj[5] = static_cast<std::uint8_t>(b);
        obj[6] = static_cast<std::uint8_t>(c);
        obj[7] = static_cast<std::uint8_t>(d);
    }

    if (objsize != 0) {
        if (objsize <= addrlen) {
            ql.mem().write(addr, obj);
        }
        if (addrlenptr != 0) {
            ql.mem().write_ptr(addrlenptr, objsize);
        }
    }
    return objsize;
}

// the getsockname/getpeername common body (the peer flag picks the walk)
std::optional<std::int64_t> syscall_getsockname_impl(Qiling& ql,
                                                     const std::vector<std::uint64_t>& params,
                                                     bool peer) {
    const auto sockfd = static_cast<std::int64_t>(params[0]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    std::string path, host;
    std::uint16_t port = 0;
    const bool ok = peer ? sock->getpeername(path, host, port)
                         : sock->getsockname(path, host, port);
    if (!ok) {
        return -1;  // the OSError branch rides -1
    }

    write_sockaddr(ql, sock->family(), params[1], params[2], path, host, port);
    return 0;
}

}  // namespace

std::optional<std::int64_t> syscall_getsockname(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_getsockname(sockfd, addr, addrlenptr): the name write-back
    // over the shared helper (the AF_UNIX path with the host→virtual
    // transform + the addrlen truncation; the AF_INET triple)
    return syscall_getsockname_impl(ql, params, false);
}

std::optional<std::int64_t> syscall_getpeername(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_getpeername(sockfd, addr, addrlenptr): the peer name
    return syscall_getsockname_impl(ql, params, true);
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

    // the datagram walk: the dest parse rides the guest sockaddr (the
    // AF_UNIX ql_unix_socket_path transform, the AF_INET (host, port));
    // the (ConnectionError, FileNotFoundError) branch rides 0 (verbatim)
    const auto sa = parse_sockaddr(ql, params[4], params[5]);
    std::string dest_path, dest_host;
    std::uint16_t dest_port = 0;
    if (sa.family == kAfUnix) {
        dest_path = sa.unix_path;
        if (!dest_path.empty() && dest_path.front() != char{0}) {
            dest_path = ql.os().path()->virtual_to_host_path(dest_path);
        }
    } else if (sa.family == kAfInet) {
        dest_host = sa.inet_host;
        dest_port = sa.inet_port;
    } else {
        // dest stays None — the verbatim "if dest is not None" fall-through
        return 0;
    }

    const auto data = ql.mem().read(params[1], params[2]);
    if (sock->sendto(data, static_cast<int>(params[3]), dest_path, dest_host, dest_port) < 0) {
        return 0;  // the except branch (verbatim)
    }
    return static_cast<std::int64_t>(data.size());
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

    // the datagram walk: the src address rides the out params; the
    // write-back consults the FIXME verbatim (the addrlen is NOT read —
    // the whole obj writes at addr), the abstract-namespace path stays
    // unfilled (the upstream comment verbatim)
    std::string src_path, src_host;
    std::uint16_t src_port = 0;
    const auto data = sock->recvfrom(static_cast<std::size_t>(params[2]),
                                     static_cast<int>(params[3]), src_path, src_host, src_port);

    std::size_t objlen = 0;
    std::vector<std::uint8_t> obj;
    if (sock->family() == kAfUnix) {
        objlen = 2 + src_path.size() + 1;
        obj.assign(objlen, 0);
        obj[0] = 0x01;
        obj[1] = 0x00;
        // abstract Unix socket path is not filled in recvfrom
        if (!src_path.empty()) {
            std::memcpy(obj.data() + 2, src_path.data(), src_path.size());
        }
    } else if (sock->family() == kAfInet) {
        objlen = 16;
        obj.assign(16, 0);
        obj[0] = 0x02;
        obj[1] = 0x00;
        obj[2] = static_cast<std::uint8_t>(src_port >> 8);
        obj[3] = static_cast<std::uint8_t>(src_port & 0xff);
        unsigned a = 0, b = 0, c = 0, d = 0;
        std::sscanf(src_host.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        obj[4] = static_cast<std::uint8_t>(a);
        obj[5] = static_cast<std::uint8_t>(b);
        obj[6] = static_cast<std::uint8_t>(c);
        obj[7] = static_cast<std::uint8_t>(d);
    }
    // else objlen stays 0 — the verbatim "else objlen = 0" (no write-back)

    if (objlen != 0) {
        ql.mem().write(params[4], obj);
    }
    ql.mem().write(params[1], data);
    return static_cast<std::int64_t>(data.size());
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

std::optional<std::int64_t> syscall_socketcall(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_socketcall(call, args): the x86 multiplexer (net.py) — the
    // call picks the handler, the args array rides the guest memory at the
    // pointer-size stride, the per-call arg counts mirror the upstream's
    // inspect.signature walk. The unhandled calls (recvmsg/sendmmsg/accept4
    // land with their slices) throw the NotImplementedError shape verbatim.
    struct Entry { int call; std::size_t nargs; void (*invoke)(Qiling&, const std::vector<std::uint64_t>&); const char* name; };
    static constexpr Entry kCalls[] = {
        {1, 3, nullptr, "socket"},   {2, 3, nullptr, "bind"},
        {3, 3, nullptr, "connect"}, {4, 2, nullptr, "listen"},
        {5, 3, nullptr, "accept"},  {6, 3, nullptr, "getsockname"},
        {7, 3, nullptr, "getpeername"}, {8, 4, nullptr, "socketpair"},
        {9, 4, nullptr, "send"},    {10, 4, nullptr, "recv"},
        {11, 6, nullptr, "sendto"}, {12, 6, nullptr, "recvfrom"},
        {13, 2, nullptr, "shutdown"}, {14, 5, nullptr, "setsockopt"},
        {15, 5, nullptr, "getsockopt"},
    };

    const auto call = static_cast<int>(params[0]);
    const auto args = params[1];

    const Entry* entry = nullptr;
    for (const auto& e : kCalls) {
        if (e.call == call) {
            entry = &e;
            break;
        }
    }
    if (entry == nullptr) {
        // the verbatim raise: 'socketcall: call {name or call} not
        // implemented' (the name lookup rides the SOCKETCALL enum — the
        // unknown numeric keeps the number, matching the upstream shape)
        throw QlErrorBase(std::string("socketcall: call ") +
                          std::to_string(call) + " not implemented");
    }

    std::vector<std::uint64_t> a;
    a.reserve(entry->nargs);
    for (std::size_t i = 0; i < entry->nargs; ++i) {
        a.push_back(static_cast<std::uint64_t>(
            ql.mem().read_ptr(args + i * static_cast<std::uint64_t>(ql.arch().pointersize()))));
    }

    switch (entry->call) {
        case 1:  return syscall_socket(ql, a);
        case 2:  return syscall_bind(ql, a);
        case 3:  return syscall_connect(ql, a);
        case 4:  return syscall_listen(ql, a);
        case 5:  return syscall_accept(ql, a);
        case 6:  return syscall_getsockname(ql, a);
        case 7:  return syscall_getpeername(ql, a);
        case 8:  return syscall_socketpair(ql, a);
        case 9:  return syscall_send(ql, a);
        case 10: return syscall_recv(ql, a);
        case 11: return syscall_sendto(ql, a);
        case 12: return syscall_recvfrom(ql, a);
        case 13: return syscall_shutdown(ql, a);
        case 14: return syscall_setsockopt(ql, a);
        case 15: return syscall_getsockopt(ql, a);
        default:
            throw QlErrorBase("socketcall: unreachable dispatch");
    }
}

std::optional<std::int64_t> syscall_recvmsg(Qiling& ql, const std::vector<std::uint64_t>& params) {
    // ql_syscall_recvmsg(sockfd, msg_addr, flags): the msghdr load (the
    // upstream's fixed make_msghdr layout), the iov scatter, the cmsg
    // write-back, the msg_flags save-back, the count ride
    const auto sockfd = static_cast<std::int64_t>(params[0]);
    const auto msg_addr = params[1];
    const auto flags = static_cast<int>(params[2]);

    auto* sock = dynamic_cast<QlSocket*>(fd_get(ql, sockfd).get());
    if (sock == nullptr) {
        return -88;  // -ENOTSOCK
    }

    // the msghdr load (the fixed offsets — the upstream layout is
    // arch-independent: msg_name u64@0, msg_namelen i32@8, msg_iov@16,
    // msg_iovlen i32@24, msg_control@32, msg_controllen i32@40, the
    // msg_flags i32@48)
    const auto msg_namelen = ql.mem().read_ptr(msg_addr + 8, 4);
    const auto msg_iov = ql.mem().read_ptr(msg_addr + 16);
    const auto msg_iovlen = ql.mem().read_ptr(msg_addr + 24, 4);
    const auto msg_control = ql.mem().read_ptr(msg_addr + 32);
    const auto msg_controllen = ql.mem().read_ptr(msg_addr + 40, 4);

    QlSocket::RecvMsgResult rm;
    try {
        // TODO: handle the addr (the verbatim TODO — the name is discarded)
        rm = sock->recvmsg(static_cast<std::size_t>(msg_namelen),
                           static_cast<std::size_t>(msg_controllen), flags);
    } catch (const QlErrorBase&) {
        return -1;  // the ConnectionError branch
    }

    // the iov scatter: the size = min(iov_len, the remaining data) per the
    // verbatim min-walk (the iovec rides the arch pointer size)
    const auto psize = static_cast<std::uint64_t>(ql.arch().pointersize());
    auto iovec_addr = msg_iov;
    std::size_t written = 0;
    for (std::uint64_t i = 0; i < static_cast<std::uint64_t>(msg_iovlen); ++i) {
        const auto iov_base = ql.mem().read_ptr(iovec_addr);
        const auto iov_len = ql.mem().read_ptr(iovec_addr + psize, static_cast<std::uint64_t>(psize));
        const auto size = std::min<std::size_t>(iov_len, rm.data.size() - written);
        ql.mem().write(iov_base,
                       std::vector<std::uint8_t>(rm.data.begin() + static_cast<std::ptrdiff_t>(written),
                                                 rm.data.begin() + static_cast<std::ptrdiff_t>(written + size)));
        written += size;
        iovec_addr += 2 * psize;
    }

    // the cmsg write-back: the 12-byte cmsghdr (the 3 x i32 — the verbatim
    // make_cmsghdr), the cmsg_len carries ONLY the data length (the verbatim
    // quirk: obj.cmsg_len = len(cmsg_data))
    auto cmsg_addr = msg_control;
    for (const auto& [level, type, cdata] : rm.ancdata) {
        ql.mem().write_ptr(cmsg_addr, static_cast<std::int64_t>(cdata.size()), 4);
        ql.mem().write_ptr(cmsg_addr + 4, static_cast<std::uint64_t>(level), 4);
        ql.mem().write_ptr(cmsg_addr + 8, static_cast<std::uint64_t>(type), 4);
        cmsg_addr += 12;
        ql.mem().write(cmsg_addr, cdata);
        cmsg_addr += cdata.size();
    }

    // msg.msg_flags = mflags; the save_to rides the whole-struct write-back
    // (only the flags changed — the single-cell write is equivalent)
    ql.mem().write_ptr(msg_addr + 48, static_cast<std::uint64_t>(rm.mflags), 4);

    return static_cast<std::int64_t>(rm.data.size());
}

}  // namespace posix
}  // namespace os
}  // namespace qiling
