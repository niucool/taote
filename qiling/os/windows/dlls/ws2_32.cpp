// The ws2_32.dll family — the winsock API surface. The upstream qiling
// implements the family in os/windows/dlls/ws2_32.py; the port rides the
// shared posix::QlSocket engine (the posix/socket.cpp host walk) so the tcp/ip
// samples exercise the real loopback paths. The SOCKET value is the handle
// id; the posix::QlSocket body parks in the handle manager (the _wfopen_s shape).
#ifndef QILING_OS_WINDOWS_DLLS_WS2_32_CPP
#define QILING_OS_WINDOWS_DLLS_WS2_32_CPP

#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/posix/socket.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/handle.hpp"
#include "qiling/os/windows/windows.hpp"

#include <cstring>
#include <string>
#include <vector>

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffffu
#endif

namespace qiling {
namespace os {
namespace win {

namespace {

// the handle slot -> the posix::QlSocket body (nullptr when the id is not a socket)
posix::QlSocket* socket_of(Qiling& ql, std::uint64_t sock) {
    const auto* handle = w(ql).handle_manager().get(sock);
    if (handle == nullptr || handle->obj == nullptr) {
        return nullptr;
    }
    return dynamic_cast<posix::QlSocket*>(static_cast<QlFsMappedObject*>(handle->obj));
}

// the (host, port) pair out of the guest sockaddr_in image (the family field
// rides the same offset on both variants; the port is the network order)
bool parse_sockaddr_in(Qiling& ql, std::uint64_t addr, std::uint64_t len,
                       std::string& host, std::uint16_t& port) {
    if (len < 8) {
        return false;
    }
    const auto data = ql.mem().read(addr, static_cast<std::size_t>(len));
    const auto family = static_cast<std::uint16_t>(data[0]) | (static_cast<std::uint16_t>(data[1]) << 8);
    if (family != 2) {  // AF_INET
        return false;
    }
    port = static_cast<std::uint16_t>(((static_cast<std::uint16_t>(data[2]) << 8)) | data[3]);
    host = std::to_string(data[4]) + "." + std::to_string(data[5]) + "." +
           std::to_string(data[6]) + "." + std::to_string(data[7]);
    return true;
}

}  // namespace

void register_ws2_32_family() {
    using namespace qiling::os::api;

    // SOCKET socket(int af, int type, int protocol);
    WinsdkApi("socket", WinCc::Stdcall, {
        {"af", INT_},
        {"type", INT_},
        {"protocol", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto af = static_cast<int>(api_get_int(get_param(params, "af")));
        const auto type = static_cast<int>(api_get_int(get_param(params, "type")));
        const auto protocol = static_cast<int>(api_get_int(get_param(params, "protocol")));

        auto sock = posix::QlSocket::open(af, type, protocol);

        Handle new_handle(std::nullopt, sock.get());
        new_handle.owned = sock;
        w(ql).handle_manager().append(new_handle);
        return new_handle.id;
    };

    // int closesocket(SOCKET s);
    WinsdkApi("closesocket", WinCc::Stdcall, {
        {"s", SOCKET_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_int(get_param(params, "s"));
        auto* sock = socket_of(ql, s);
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }
        sock->close();
        w(ql).handle_manager().delete_handle(s);
        return 0;
    };

    // int shutdown(SOCKET s, int how);
    WinsdkApi("shutdown", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"how", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_int(get_param(params, "s"));
        const auto how = static_cast<int>(api_get_int(get_param(params, "how")));
        auto* sock = socket_of(ql, s);
        if (sock == nullptr || !sock->shutdown(how)) {
            return static_cast<std::uint64_t>(-1);
        }
        return 0;
    };

    // int bind(SOCKET s, const sockaddr* name, int namelen);
    WinsdkApi("bind", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"name", PVOID_},
        {"namelen", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_int(get_param(params, "s"));
        const auto name = api_get_int(get_param(params, "name"));
        const auto namelen = api_get_int(get_param(params, "namelen"));
        auto* sock = socket_of(ql, s);

        std::string host;
        std::uint16_t port = 0;
        if (sock == nullptr || !parse_sockaddr_in(ql, name, namelen, host, port)) {
            return static_cast<std::uint64_t>(-1);
        }
        return sock->bind_inet(host, port) ? 0 : static_cast<std::uint64_t>(-1);
    };

    // int listen(SOCKET s, int backlog);
    WinsdkApi("listen", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"backlog", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto backlog = static_cast<int>(api_get_int(get_param(params, "backlog")));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr || !sock->listen(backlog)) {
            return static_cast<std::uint64_t>(-1);
        }
        return 0;
    };

    // the WSAETIMEDOUT the non-blocking accept/recv path answers
    static constexpr int kWsaeTimedOut = 10060;

    // SOCKET accept(SOCKET s, sockaddr* addr, int* addrlen);
    WinsdkApi("accept", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"addr", PVOID_},
        {"addrlen", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        auto* listener = socket_of(ql, api_get_int(get_param(params, "s")));
        if (listener == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        // the host accept blocks, so a guest that waits for a peer must not
        // hold the emulator: wait within the budget and answer WSAETIMEDOUT
        // when nothing arrives (no fake connection is ever handed back)
        const int budget_ms = w(ql).socket_wait_budget_ms();
        if (!listener->wait_readable(budget_ms)) {
            w(ql).set_last_error(kWsaeTimedOut);
            return static_cast<std::uint64_t>(-1);
        }

        std::string peer_path, peer_host;
        std::uint16_t peer_port = 0;
        auto conn = listener->accept(peer_path, peer_host, peer_port);
        if (conn == nullptr) {
            w(ql).set_last_error(kWsaeTimedOut);
            return static_cast<std::uint64_t>(-1);
        }

        Handle new_handle(std::nullopt, conn.get());
        new_handle.owned = conn;
        w(ql).handle_manager().append(new_handle);
        return new_handle.id;
    };

    // int connect(SOCKET s, const sockaddr* name, int namelen);
    WinsdkApi("connect", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"name", PVOID_},
        {"namelen", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_int(get_param(params, "s"));
        const auto name = api_get_int(get_param(params, "name"));
        const auto namelen = api_get_int(get_param(params, "namelen"));
        auto* sock = socket_of(ql, s);

        std::string host;
        std::uint16_t port = 0;
        if (sock == nullptr || !parse_sockaddr_in(ql, name, namelen, host, port)) {
            return static_cast<std::uint64_t>(-1);
        }
        return sock->connect_inet(host, port) ? 0 : static_cast<std::uint64_t>(-1);
    };

    // int send(SOCKET s, const char* buf, int len, int flags);
    WinsdkApi("send", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"buf", PVOID_},
        {"len", INT_},
        {"flags", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buf = api_get_int(get_param(params, "buf"));
        const auto len = api_get_int(get_param(params, "len"));
        const auto flags = static_cast<int>(api_get_int(get_param(params, "flags")));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        const auto data = ql.mem().read(buf, static_cast<std::size_t>(len));
        const auto n = sock->send(data, flags);
        return n < 0 ? static_cast<std::uint64_t>(-1) : static_cast<std::uint64_t>(n);
    };

    // int recv(SOCKET s, char* buf, int len, int flags);
    WinsdkApi("recv", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"buf", PVOID_},
        {"len", INT_},
        {"flags", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buf = api_get_int(get_param(params, "buf"));
        const auto len = api_get_int(get_param(params, "len"));
        const auto flags = static_cast<int>(api_get_int(get_param(params, "flags")));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        const auto data = sock->recv(static_cast<std::size_t>(len), flags);
        if (!data.empty()) {
            ql.mem().write(buf, data);
        }
        return data.size();
    };

    // int sendto(SOCKET s, const char* buf, int len, int flags,
    //            const sockaddr* to, int tolen); — the addr-less shape rides
    // send (the verbatim None-addr branch)
    WinsdkApi("sendto", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"buf", PVOID_},
        {"len", INT_},
        {"flags", INT_},
        {"to", PVOID_},
        {"tolen", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buf = api_get_int(get_param(params, "buf"));
        const auto len = api_get_int(get_param(params, "len"));
        const auto flags = static_cast<int>(api_get_int(get_param(params, "flags")));
        const auto to = api_get_int(get_param(params, "to"));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        const auto data = ql.mem().read(buf, static_cast<std::size_t>(len));
        if (to == 0) {
            const auto n = sock->send(data, flags);
            return n < 0 ? static_cast<std::uint64_t>(-1) : static_cast<std::uint64_t>(n);
        }

        std::string host;
        std::uint16_t port = 0;
        if (!parse_sockaddr_in(ql, to, api_get_int(get_param(params, "tolen")), host, port)) {
            return static_cast<std::uint64_t>(-1);
        }
        const auto n = sock->sendto(data, flags, "", host, port);
        return n < 0 ? static_cast<std::uint64_t>(-1) : static_cast<std::uint64_t>(n);
    };

    // int recvfrom(SOCKET s, char* buf, int len, int flags,
    //              sockaddr* from, int* fromlen); — the source address is
    // discarded (the verbatim TODO rides)
    WinsdkApi("recvfrom", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"buf", PVOID_},
        {"len", INT_},
        {"flags", INT_},
        {"from", PVOID_},
        {"fromlen", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto buf = api_get_int(get_param(params, "buf"));
        const auto len = api_get_int(get_param(params, "len"));
        const auto flags = static_cast<int>(api_get_int(get_param(params, "flags")));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        std::string src_path, src_host;
        std::uint16_t src_port = 0;
        const auto data = sock->recvfrom(static_cast<std::size_t>(len), flags, src_path, src_host, src_port);
        if (!data.empty()) {
            ql.mem().write(buf, data);
        }
        return data.size();
    };

    // int setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen);
    WinsdkApi("setsockopt", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"level", INT_},
        {"optname", INT_},
        {"optval", PVOID_},
        {"optlen", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto optval = api_get_int(get_param(params, "optval"));
        const auto optlen = api_get_int(get_param(params, "optlen"));
        const auto level = static_cast<int>(api_get_int(get_param(params, "level")));
        const auto optname = static_cast<int>(api_get_int(get_param(params, "optname")));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        std::vector<std::uint8_t> value;
        if (optval != 0 && optlen > 0) {
            value = ql.mem().read(optval, static_cast<std::size_t>(optlen));
        }
        return sock->setsockopt(level, optname, value) ? 0 : static_cast<std::uint64_t>(-1);
    };

    // int getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen);
    WinsdkApi("getsockopt", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"level", INT_},
        {"optname", INT_},
        {"optval", PVOID_},
        {"optlen", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto optval = api_get_int(get_param(params, "optval"));
        const auto optlen_ptr = api_get_int(get_param(params, "optlen"));
        const auto level = static_cast<int>(api_get_int(get_param(params, "level")));
        const auto optname = static_cast<int>(api_get_int(get_param(params, "optname")));
        auto* sock = socket_of(ql, api_get_int(get_param(params, "s")));
        if (sock == nullptr) {
            return static_cast<std::uint64_t>(-1);
        }

        const auto inlen = ql.mem().read_ptr(optlen_ptr, 4);
        const auto value = sock->getsockopt(level, optname, static_cast<std::size_t>(inlen));
        const auto n = std::min<std::uint64_t>(value.size(), inlen);
        if (optval != 0 && n != 0) {
            ql.mem().write(optval, std::vector<std::uint8_t>(value.begin(), value.begin() + static_cast<std::ptrdiff_t>(n)));
        }
        ql.mem().write_ptr(optlen_ptr, n, 4);
        return 0;
    };

    // int ioctlsocket(SOCKET s, long cmd, u_long* argp); — the FIONBIO set
    // rides the value (the blocking state is not tracked); FIONREAD answers 0
    WinsdkApi("ioctlsocket", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"cmd", PVOID_},
        {"argp", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
    //            const timeval* timeout); — the ready-set passthrough (the
    // zero-timeout probes answer the write-side readiness)
    WinsdkApi("select", WinCc::Stdcall, {
        {"nfds", INT_},
        {"readfds", PVOID_},
        {"writefds", PVOID_},
        {"exceptfds", PVOID_},
        {"timeout", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // the byte-order / string helpers (the pure-arithmetic walk)
    WinsdkApi("htons", WinCc::Stdcall, {{"hostshort", PVOID_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto v = api_get_int(get_param(params, "hostshort"));
        return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
    };
    WinsdkApi("ntohs", WinCc::Stdcall, {{"netshort", PVOID_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto v = api_get_int(get_param(params, "netshort"));
        return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
    };
    WinsdkApi("htonl", WinCc::Stdcall, {{"hostlong", PVOID_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto v = api_get_int(get_param(params, "hostlong"));
        return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff);
    };
    WinsdkApi("ntohl", WinCc::Stdcall, {{"netlong", PVOID_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto v = api_get_int(get_param(params, "netlong"));
        return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff);
    };

    // unsigned long inet_addr(const char* cp);
    WinsdkApi("inet_addr", WinCc::Stdcall, {{"cp", LPCSTR_}}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto cp = api_get_string(ql, get_param(params, "cp"));
        std::uint32_t addr = 0;
        int shift = 0;
        std::uint32_t part = 0;
        int octets = 0;
        for (const char c : cp) {
            if (c == '.') {
                addr |= part << shift;
                shift += 8;
                part = 0;
                ++octets;
            } else if (c >= '0' && c <= '9') {
                part = part * 10 + static_cast<std::uint32_t>(c - '0');
            } else {
                return static_cast<std::uint64_t>(INADDR_NONE);
            }
        }
        addr |= part << shift;
        (void)octets;
        return addr;
    };

    // char* inet_ntoa(struct in_addr in);
    WinsdkApi("inet_ntoa", WinCc::Stdcall, {{"in", PVOID_}}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto in = api_get_int(get_param(params, "in"));
        const auto dot = [&](int shift) {
            return std::to_string((in >> shift) & 0xff);
        };
        const std::string text = dot(0) + "." + dot(8) + "." + dot(16) + "." + dot(24);
        const auto buf = w(ql).heap().alloc(text.size() + 1);
        ql.mem().write(buf, std::vector<std::uint8_t>(text.begin(), text.end()));
        ql.mem().write_ptr(buf + text.size(), 0, 1);
        return buf;
    };

    // INT WSAAPI inet_pton(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
    WinsdkApi("inet_pton", WinCc::Stdcall, {
        {"Family", INT_},
        {"pszAddrString", LPCSTR_},
        {"pAddrBuf", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto family = static_cast<int>(api_get_int(get_param(params, "Family")));
        const auto text = api_get_string(ql, get_param(params, "pszAddrString"));
        const auto out = api_get_int(get_param(params, "pAddrBuf"));

        if (family != 2) {
            return 0;  // the ipv6 parse rides unsupported (0 = parse error)
        }

        std::uint32_t addr = 0;
        int shift = 0;
        std::uint32_t part = 0;
        for (const char c : text) {
            if (c == '.') {
                addr |= part << shift;
                shift += 8;
                part = 0;
            } else if (c >= '0' && c <= '9') {
                part = part * 10 + static_cast<std::uint32_t>(c - '0');
            } else {
                return 0;
            }
        }
        addr |= part << shift;
        ql.mem().write(out, std::vector<std::uint8_t>{
            static_cast<std::uint8_t>(addr), static_cast<std::uint8_t>(addr >> 8),
            static_cast<std::uint8_t>(addr >> 16), static_cast<std::uint8_t>(addr >> 24)});
        return 1;
    };

    // PCSTR WSAAPI inet_ntop(INT Family, const VOID* pAddr, PSTR pStringBuf,
    //                         size_t StringBufSize);
    WinsdkApi("inet_ntop", WinCc::Stdcall, {
        {"Family", INT_},
        {"pAddr", PVOID_},
        {"pStringBuf", PVOID_},
        {"StringBufSize", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto family = static_cast<int>(api_get_int(get_param(params, "Family")));
        const auto p_addr = api_get_int(get_param(params, "pAddr"));
        const auto out = api_get_int(get_param(params, "pStringBuf"));
        const auto out_len = api_get_int(get_param(params, "StringBufSize"));
        if (family != 2) {
            return 0;
        }

        const auto data = ql.mem().read(p_addr, 4);
        std::string text;
        for (int i = 0; i < 4; ++i) {
            if (i != 0) {
                text += '.';
            }
            text += std::to_string(data[static_cast<std::size_t>(i)]);
        }
        if (text.size() + 1 > out_len) {
            w(ql).set_last_error(0x6eu);  // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }
        ql.mem().write(out, std::vector<std::uint8_t>(text.begin(), text.end()));
        ql.mem().write_ptr(out + text.size(), 0, 1);
        return out;
    };

    // struct hostent* getaddrinfo/gethostbyname rides gethostbyname (the
    // wsock32 body); the free walk is a no-op (the heap strings leak, the
    // emulation's lifetime covers them)
    WinsdkApi("getaddrinfo", WinCc::Stdcall, {
        {"pNodeName", LPCSTR_},
        {"pServiceName", LPCSTR_},
        {"pHints", PVOID_},
        {"ppResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto out = api_get_int(get_param(params, "ppResult"));
        const auto node = api_get_string(ql, get_param(params, "pNodeName"));

        auto& heap = w(ql).heap();
        const auto ps = ql.arch().pointersize();

        // one A record carrying 127.0.0.1 (the loopback answer; the dns
        // resolution surface lands with its slice)
        std::vector<std::uint8_t> ip{127, 0, 0, 1};
        const auto ip_addr = heap.alloc(ip.size());
        ql.mem().write(ip_addr, ip);

        const auto addr_list = heap.alloc(2 * ps);
        ql.mem().write_ptr(addr_list, ip_addr);
        ql.mem().write_ptr(addr_list + ps, 0);

        const auto info = heap.alloc(64);
        ql.mem().write_ptr(info + 0 * ps, 0);           // ai_flags
        ql.mem().write_ptr(info + 1 * ps, 2);           // ai_family = AF_INET
        ql.mem().write_ptr(info + 2 * ps, 1);           // ai_socktype = SOCK_STREAM
        ql.mem().write_ptr(info + 3 * ps, 6);           // ai_protocol = IPPROTO_TCP
        ql.mem().write_ptr(info + 4 * ps, ps);          // ai_addrlen
        ql.mem().write_ptr(info + 5 * ps, addr_list);   // ai_addr (the sockaddr reads the ip bytes)
        ql.mem().write_ptr(info + 6 * ps, 0);           // ai_canonname
        ql.mem().write_ptr(info + 7 * ps, 0);           // ai_next

        ql.mem().write_ptr(out, info);
        return 0;
    };

    WinsdkApi("freeaddrinfo", WinCc::Stdcall, {{"pAddrInfo", PVOID_}}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // the WSA error-state family (the per-thread last error is a shared
    // cell for the single-threaded surface)
    WinsdkApi("WSASetLastError", WinCc::Stdcall, {{"iError", INT_}}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        w(ql).set_last_error(static_cast<int>(api_get_int(get_param(params, "iError"))));
        return 0;
    };
    WinsdkApi("WSAGetLastError", WinCc::Stdcall, {}) =
        [](Qiling& ql, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return w(ql).last_error();
    };

    // int WSAStartup / WSACleanup — the ws2_32 spellings of the wsock32
    // registrations (the same names may ride either dll)
    WinsdkApi("WSAStartup", WinCc::Stdcall, {
        {"wVersionRequested", WORD_},
        {"lpWSAData", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // fill the WSADATA image (the version cells + the description text)
        const auto lp = api_get_int(get_param(params, "lpWSAData"));
        if (lp != 0) {
            ql.mem().write_ptr(lp + 0, 0x0202, 2);  // wVersion 2.2
            ql.mem().write_ptr(lp + 2, 0x0202, 2);  // wHighVersion 2.2
            const std::string desc = "Qiling Winsock 2.2";
            ql.mem().write(lp + 8, std::vector<std::uint8_t>(desc.begin(), desc.end()));
            ql.mem().write_ptr(lp + 8 + desc.size(), 0, 1);
        }
        return 0;
    };
    WinsdkApi("WSACleanup", WinCc::Stdcall, {}) =
        [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int __WSAFDIsSet(SOCKET s, fd_set* set); — the membership probe
    WinsdkApi("__WSAFDIsSet", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"set", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto s = api_get_int(get_param(params, "s"));
        const auto set = api_get_int(get_param(params, "set"));

        if (set == 0) {
            return 0;
        }
        const auto count = ql.mem().read_ptr(set, 4);
        for (std::uint64_t i = 0; i < count; ++i) {
            if (ql.mem().read_ptr(set + 4 + i * 4, 4) == s) {
                return 1;
            }
        }
        return 0;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kWs2_32Registered = [] {
    qiling::os::win::register_ws2_32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_WS2_32_CPP
