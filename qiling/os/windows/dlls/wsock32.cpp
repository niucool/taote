// Ported from qiling/os/windows/dlls/wsock32.py — the winsock stub family
// (the WSAAPI rides the STDCALL convention; the connect walk parses the
// sockaddr image, the gethostbyname builds the profile-seeded hostent).
#ifndef QILING_OS_WINDOWS_DLLS_WSOCK32_CPP
#define QILING_OS_WINDOWS_DLLS_WSOCK32_CPP

#include "qiling/core.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>
#include <vector>

namespace qiling {
namespace os {
namespace win {

void register_wsock32_family() {
    using namespace qiling::os::api;

    // int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
    WinsdkApi("WSAStartup", WinCc::Stdcall, {
        {"wVersionRequested", WORD_},
        {"lpWSAData", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // SOCKET WSASocketA(int af, int type, int protocol,
    //     LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags);
    WinsdkApi("WSASocketA", WinCc::Stdcall, {
        {"af", INT_},
        {"type", INT_},
        {"protocol", INT_},
        {"lpProtocolInfo", PVOID_},
        {"g", INT_},
        {"dwFlags", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 0;
    };

    // int connect(SOCKET s, const sockaddr *name, int namelen);
    WinsdkApi("connect", WinCc::Stdcall, {
        {"s", SOCKET_},
        {"name", PVOID_},
        {"namelen", INT_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto name = api_get_int(get_param(params, "name"));
        const auto namelen = api_get_int(get_param(params, "namelen"));

        // sockaddr is not based on BaseStruct, so we have to read it manually
        // (verbatim; the ipv4 assumed by default — the family field rides the
        // same offset on both variants)
        const auto data = ql.mem().read(name, static_cast<std::size_t>(namelen));
        const auto read_at = [&](std::size_t off, std::size_t n) {
            std::uint64_t v = 0;
            for (std::size_t k = 0; k < n && off + k < data.size(); ++k) {
                v |= static_cast<std::uint64_t>(data[off + k]) << (8 * k);
            }
            return v;
        };

        const auto sin_family = read_at(0, 2);
        const auto sin_port = read_at(2, 2);  // the network order (BE)

        if (sin_family == 0x17) {  // IPv6
            // the 16 address bytes ride the 8-offset body; the pairs join as
            // the colon segments (the upstream log-only ride)
            std::string addr;
            for (std::size_t k = 8; k < 24 && k < data.size(); k += 2) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "%02x%02x", data[k], data[k + 1]);
                if (!addr.empty()) {
                    addr += ':';
                }
                addr += buf;
            }
            (void)addr;
        } else if (sin_family == 0x2) {  // IPv4
            std::string addr;
            for (std::size_t k = 4; k < 8 && k < data.size(); ++k) {
                if (!addr.empty()) {
                    addr += '.';
                }
                addr += std::to_string(data[k]);
            }
            (void)addr;
        } else {
            // sockaddr sin_family unhandled variant  (verbatim)
            return 0;
        }

        // FIXME: wait.. we just printed stuff out, and did not connect
        // anywhere..  (verbatim)
        return 0;
    };

    // hostent * gethostbyname(const char *name);
    WinsdkApi("gethostbyname", WinCc::Stdcall, {
        {"name", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto name_ptr = api_get_int(get_param(params, "name"));
        auto& heap = w(ql).heap();

        // prepare the ip address data bytes (the profile NETWORK section)
        const auto ip_str = ql.profile().get("NETWORK", "dns_response_ip").value_or("");
        std::vector<std::uint8_t> ip;
        for (auto it = ip_str.rbegin(); it != ip_str.rend();) {
            auto end = it;
            while (end != ip_str.rend() && *end != '.') {
                ++end;
            }
            std::string octet(end.base(), it.base());
            ip.push_back(static_cast<std::uint8_t>(std::stoi(octet)));
            it = end != ip_str.rend() ? end + 1 : end;
        }

        // allocate room for the ip address data bytes
        const auto list_item = heap.alloc(ip.size());
        ql.mem().write(list_item, ip);

        // allocate room for a list with one item, followed by a nullptr
        // sentinel
        const auto addr_list = heap.alloc(2 * ql.arch().pointersize());
        ql.mem().write_ptr(addr_list, list_item);
        ql.mem().write_ptr(addr_list + ql.arch().pointersize(), 0);

        // we need a pointer to a nullptr; reuse the sentinel address for that
        const auto d_nullptr = addr_list + ql.arch().pointersize();

        // the hostent image rides the documented 64-bit offsets
        const auto hostnet_addr = heap.alloc(HOSTENT_SIZE);
        std::string image(HOSTENT_SIZE, '\0');
        const auto put64 = [&](std::size_t off, std::uint64_t v) {
            for (int k = 0; k < 8; ++k) {
                image[off + k] = static_cast<char>((v >> (8 * k)) & 0xff);
            }
        };
        const auto put16 = [&](std::size_t off, std::uint64_t v) {
            image[off] = static_cast<char>(v & 0xff);
            image[off + 1] = static_cast<char>((v >> 8) & 0xff);
        };
        put64(HOSTENT_OFF_HNAME, name_ptr);
        put64(HOSTENT_OFF_HALIASES, d_nullptr);
        put16(HOSTENT_OFF_HADDRTYPE, 2);  // AF_INET
        put16(HOSTENT_OFF_HLENGTH, ip.size());
        put64(HOSTENT_OFF_HADDRLIST, addr_list);
        ql.mem().write(hostnet_addr, std::vector<std::uint8_t>(image.begin(), image.end()));

        return hostnet_addr;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kWsock32Registered = [] {
    qiling::os::win::register_wsock32_family();
    return true;
}();
}  // namespace

#endif  // QILING_OS_WINDOWS_DLLS_WSOCK32_CPP
