// PLAN_PARITY Phase 3 item 7: the gdbserver slice (see the header).
#include "qiling/gdbserver.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include "qiling/core.hpp"
#include "qiling/arch/arch.hpp"
#include "qiling/os/os.hpp"

namespace qiling {

namespace {

// the GDB register order per architecture (the numbers a client asks for):
// the x86/x86_64 general set, GDB's ordering, not unicorn's enum order
const std::vector<std::string>& gdb_register_names(std::size_t bits) {
    static const std::vector<std::string> kX86 = {"eax", "ecx", "edx", "ebx", "esp",  "ebp", "esi", "edi",
                                                  "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"};
    static const std::vector<std::string> kX64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                                  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
                                                  "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"};
    return bits == 64 ? kX64 : kX86;
}

std::string to_hex_le(std::uint64_t value, std::size_t bytes) {
    std::string out;
    out.reserve(bytes * 2);
    static const char* kDigits = "0123456789abcdef";
    for (std::size_t i = 0; i < bytes; ++i) {
        const auto byte = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0xf]);
    }
    return out;
}

bool from_hex(const std::string_view text, std::uint64_t& value) {
    value = 0;
    if (text.empty()) {
        return false;
    }
    for (const char c : text) {
        int digit = -1;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return false;
        value = (value << 4) | static_cast<std::uint64_t>(digit);
    }
    return true;
}

std::uint8_t checksum(std::string_view payload) {
    std::uint8_t sum = 0;
    for (const char c : payload) {
        sum = static_cast<std::uint8_t>(sum + static_cast<std::uint8_t>(c));
    }
    return sum;
}

}  // namespace

QlGdb::QlGdb(Qiling& ql, std::string ip, int port) : ql_(ql), ip_(std::move(ip)), port_(static_cast<std::uint16_t>(port)) {}

QlGdb::~QlGdb() { stop(); }

void QlGdb::start() {
    if (listen_fd_ >= 0) {
        return;
    }

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        throw QlErrorBase("gdb: cannot create the listening socket");
    }
    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (::inet_pton(AF_INET, ip_.c_str(), &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        throw QlErrorBase("gdb: cannot bind " + ip_ + ":" + std::to_string(port_));
    }
    if (::listen(listen_fd_, 1) != 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        throw QlErrorBase("gdb: cannot listen");
    }

    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
        port_ = ntohs(local.sin_port);
    }
}

void QlGdb::stop() {
    running_ = false;
    if (client_fd_ >= 0) {
        ::close(client_fd_);
        client_fd_ = -1;
    }
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

bool QlGdb::accept_client(int timeout_ms) {
    // the listener wait is a poll, never a bare accept: a client that never
    // arrives ends the call with gdb_listen_timeout instead of holding the
    // process (the block-budget rule)
    if (listen_fd_ < 0) {
        start();
    }
    pollfd pfd{};
    pfd.fd = listen_fd_;
    pfd.events = POLLIN;
    const int rc = ::poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        status_ = QlGdbStatus::ListenTimeout;
        return false;
    }
    const int fd = ::accept(listen_fd_, nullptr, nullptr);
    if (fd < 0) {
        status_ = QlGdbStatus::ListenTimeout;
        return false;
    }
    client_fd_ = fd;
    return true;
}

void QlGdb::run() {
    start();
    running_ = true;
    while (running_) {
        if (!accept_client(timeout_ms_)) {
            // no client within the budget: report the named status and return
            running_ = false;
            break;
        }
        serve_fd(client_fd_, timeout_ms_);
        if (client_fd_ >= 0) {
            ::close(client_fd_);
            client_fd_ = -1;
        }
    }
}

QlGdbStatus QlGdb::serve_fd(int fd, int timeout_ms) {
    // the read side has the same budget: a connected client that stops talking
    // is a gdb_client_timeout, not a hang
    timeout_ms_ = timeout_ms;
    status_ = QlGdbStatus::Detached;
    while (true) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, timeout_ms_);
        if (rc == 0) {
            status_ = QlGdbStatus::ClientTimeout;
            return status_;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            status_ = QlGdbStatus::ClientTimeout;
            return status_;
        }
        const auto packet = receive_packet(fd);
        if (packet.empty()) {
            status_ = QlGdbStatus::Detached;
            return status_;
        }
        if (packet[0] == '\x03') {
            send_packet(stop_reply(2), fd);
            continue;
        }
        if (packet == "k") {
            ql_.stop();
            return status_;
        }
        const auto reply = handle_packet(packet);
        if (!send_packet(reply, fd)) {
            status_ = QlGdbStatus::Detached;
            return status_;
        }
        if (packet == "D") {
            running_ = false;
            return status_;
        }
    }
}

bool QlGdb::send_packet(std::string_view payload, int fd) {
    char sum[8];
    std::snprintf(sum, sizeof(sum), "#%02x", checksum(payload));
    const std::string frame = "$" + std::string(payload) + sum;
    std::size_t sent = 0;
    while (sent < frame.size()) {
        const auto n = ::send(fd, frame.data() + sent, frame.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    // consume the client's ack (a '+' before its next packet is tolerated on
    // receive, so a missing ack here is harmless)
    return true;
}

std::string QlGdb::receive_packet(int fd) {
    std::string buffer;
    char ch = 0;
    // wait for '$'
    while (true) {
        const auto n = ::recv(fd, &ch, 1, 0);
        if (n <= 0) {
            return {};
        }
        if (ch == '$') {
            break;
        }
        if (ch == '\x03') {
            return std::string(1, '\x03');  // the interrupt byte
        }
    }
    while (::recv(fd, &ch, 1, 0) == 1 && ch != '#') {
        buffer.push_back(ch);
    }
    char ignored[2];
    (void)::recv(fd, ignored, 2, 0);  // the checksum
    const char ack = '+';
    (void)::send(fd, &ack, 1, MSG_NOSIGNAL);
    return buffer;
}

void QlGdb::serve_client(int fd) {
    while (true) {
        const auto packet = receive_packet(fd);
        if (packet.empty()) {
            return;
        }
        if (packet[0] == '\x03') {
            // an interrupt stops the guest where it is
            send_packet(stop_reply(2), fd);  // SIGINT
            continue;
        }
        if (packet == "k") {
            ql_.stop();
            return;
        }
        const auto reply = handle_packet(packet);
        if (!send_packet(reply, fd)) {
            return;
        }
        if (packet == "D") {
            // the client detached: end the accept loop too, so run() returns
            running_ = false;
            return;
        }
    }
}

std::string QlGdb::stop_reply(int signal) const {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "S%02x", signal);
    return buf;
}

std::vector<std::string> QlGdb::register_names() const {
    return gdb_register_names(ql_.arch().bits());
}

std::string QlGdb::registers() const {
    std::string out;
    const auto bytes = ql_.arch().pointersize();
    for (const auto& name : register_names()) {
        std::uint64_t value = 0;
        try {
            value = ql_.arch().regs().read(name);
        } catch (const std::exception&) {
            value = 0;
        }
        // the segment/flag registers still ride the pointer width (a client
        // reads its own layout; the values are what matter here)
        out += to_hex_le(value, bytes);
    }
    return out;
}

bool QlGdb::set_registers(std::string_view hex) {
    const auto bytes = ql_.arch().pointersize();
    const auto names = register_names();
    if (hex.size() != names.size() * bytes * 2) {
        return false;
    }
    for (std::size_t i = 0; i < names.size(); ++i) {
        std::uint64_t value = 0;
        if (!from_hex(hex.substr(i * bytes * 2, bytes * 2), value)) {
            return false;
        }
        try {
            ql_.arch().regs().write(names[i], value);
        } catch (const std::exception&) {
            // a register the port does not map is skipped, not fatal
            continue;
        }
    }
    return true;
}

std::string QlGdb::read_register(int index) const {
    const auto names = register_names();
    if (index < 0 || static_cast<std::size_t>(index) >= names.size()) {
        return {};
    }
    std::uint64_t value = 0;
    try {
        value = ql_.arch().regs().read(names[static_cast<std::size_t>(index)]);
    } catch (const std::exception&) {
        value = 0;
    }
    return to_hex_le(value, ql_.arch().pointersize());
}

bool QlGdb::write_register(int index, std::string_view hex) {
    const auto names = register_names();
    if (index < 0 || static_cast<std::size_t>(index) >= names.size()) {
        return false;
    }
    std::uint64_t value = 0;
    if (!from_hex(hex, value)) {
        return false;
    }
    try {
        ql_.arch().regs().write(names[static_cast<std::size_t>(index)], value);
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

void QlGdb::step() {
    auto& uc = ql_.arch().uc();
    const auto pc = ql_.arch().regs().arch_pc();
    uc_err err = uc_emu_start(&uc, pc, 0, 0, 1);
    (void)err;
}

void QlGdb::cont() {
    if (breakpoint_hook_.type() == 0) {
        // one hook for the whole run: stop the engine on a breakpoint address
        breakpoint_hook_ = ql_.hook_code([this](std::uint64_t address, std::uint32_t) -> int {
            if (breakpoints_.count(address) != 0) {
                stopped_ = true;
                uc_emu_stop(&ql_.arch().uc());
                return QL_HOOK_BLOCK;
            }
            return 0;
        });
    }

    stopped_ = false;
    auto& uc = ql_.arch().uc();
    const auto pc = ql_.arch().regs().arch_pc();
    const auto end = ql_.os().exit_point() != 0 ? ql_.os().exit_point() : 0;
    while (!stopped_) {
        const auto before = ql_.arch().regs().arch_pc();
        (void)uc_emu_start(&uc, before, end, 0, 0);
        // a run that makes no progress or reached the exit ends the continue
        break;
    }
    (void)pc;
}

std::string QlGdb::handle_packet(std::string_view packet) {
    if (packet.empty()) {
        return {};
    }

    const auto cmd = packet[0];
    const auto rest = packet.substr(1);

    switch (cmd) {
    case '?':
        return stop_reply(5);  // SIGTRAP: attached and stopped
    case 'g':
        return registers();
    case 'G':
        return set_registers(rest) ? "OK" : "E01";
    case 'p': {
        std::uint64_t index = 0;
        if (!from_hex(rest, index)) {
            return "E01";
        }
        return read_register(static_cast<int>(index));
    }
    case 'P': {
        const auto eq = rest.find('=');
        if (eq == std::string_view::npos) {
            return "E01";
        }
        std::uint64_t index = 0;
        if (!from_hex(rest.substr(0, eq), index)) {
            return "E01";
        }
        return write_register(static_cast<int>(index), rest.substr(eq + 1)) ? "OK" : "E01";
    }
    case 'm': {
        const auto comma = rest.find(',');
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        if (comma == std::string_view::npos || !from_hex(rest.substr(0, comma), addr) ||
            !from_hex(rest.substr(comma + 1), size)) {
            return "E01";
        }
        try {
            const auto bytes = ql_.mem().read(addr, static_cast<std::size_t>(size));
            std::string out;
            for (const auto b : bytes) {
                out += to_hex_le(b, 1);
            }
            return out;
        } catch (const std::exception&) {
            return "E01";
        }
    }
    case 'M': {
        const auto comma = rest.find(',');
        const auto colon = rest.find(':');
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        if (comma == std::string_view::npos || colon == std::string_view::npos ||
            !from_hex(rest.substr(0, comma), addr) || !from_hex(rest.substr(comma + 1, colon - comma - 1), size)) {
            return "E01";
        }
        const auto hex = rest.substr(colon + 1);
        if (hex.size() != size * 2) {
            return "E01";
        }
        std::vector<std::uint8_t> bytes;
        for (std::size_t i = 0; i < hex.size(); i += 2) {
            std::uint64_t byte = 0;
            if (!from_hex(hex.substr(i, 2), byte)) {
                return "E01";
            }
            bytes.push_back(static_cast<std::uint8_t>(byte));
        }
        try {
            ql_.mem().write(addr, bytes);
        } catch (const std::exception&) {
            return "E01";
        }
        return "OK";
    }
    case 'c':
        cont();
        return stop_reply(5);
    case 's':
        step();
        return stop_reply(5);
    case 'Z':
    case 'z': {
        // Z0,addr,kind / z0,addr,kind
        const auto comma = rest.find(',');
        if (comma == std::string_view::npos) {
            return {};
        }
        const auto kind = rest.substr(0, comma);
        std::uint64_t addr = 0;
        if (kind != "0" || !from_hex(rest.substr(comma + 1, rest.find(',', comma + 1) - comma - 1), addr)) {
            return {};
        }
        if (cmd == 'Z') {
            breakpoints_.insert(addr);
        } else {
            breakpoints_.erase(addr);
        }
        return "OK";
    }
    case 'D':
        return "OK";
    case 'H':
        return "OK";
    case 'q': {
        if (rest.rfind("Supported", 0) == 0) {
            return "PacketSize=1000;qXfer:features:read-";
        }
        if (rest == "Attached" || rest.rfind("Attached;", 0) == 0) {
            return "1";
        }
        if (rest == "C") {
            return "QC1";
        }
        return {};
    }
    default:
        return {};
    }
}

}  // namespace qiling
