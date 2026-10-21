// PLAN_PARITY Phase 3 item 7: the gdbserver slice.
//
// Ported from upstream qiling's debugger/debugger.py + debugger/gdb/gdb.py,
// reduced to the packets the three test_gdb rows exercise (the reference's own
// test_gdb.cpp only skips: connect-and-read-registers, read memory,
// single-step). The surface is the GDB remote serial protocol over TCP:
//
//   ?  g  G  p  P  m  M  c  s  Z0  z0  D  k  qSupported  qAttached
//
// Registers are read/written through the port's QlRegisterManager, memory
// through QlMemoryManager, and step/continue drive the unicorn engine directly
// (one instruction for `s`; `c` runs to a breakpoint or the exit point).
#ifndef QILING_GDBSERVER_HPP
#define QILING_GDBSERVER_HPP

#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "qiling/core_hooks_types.hpp"

namespace qiling {

class Qiling;

// the accept/serve outcome: a listener or a client that never arrives must end
// with a named status rather than block the process (the same discipline the
// blocking-host-call budget applies to the socket samples)
enum class QlGdbStatus {
    Ok,
    ListenTimeout,  // gdb_listen_timeout: no client within the budget
    ClientTimeout,  // gdb_client_timeout: a connected client went quiet
    Detached,       // the client sent D / disconnected
};

// debugger/debugger.py QlDebugger
class QlDebugger {
public:
    virtual ~QlDebugger() = default;
    // serve until the client detaches (blocks)
    virtual void run() = 0;
};

class QlGdb final : public QlDebugger {
public:
    explicit QlGdb(Qiling& ql, std::string ip = "127.0.0.1", int port = 9999);
    ~QlGdb() override;

    // binds and listens (port 0 picks a free port, reported by port())
    void start();
    void run() override;
    void stop();

    // bounded serving: the listener waits at most timeout_ms for a client, and
    // an accepted client is served with the same read budget. serve_fd serves
    // an already-connected descriptor (a socketpair in the tests), so nothing
    // in the test path depends on a real accept().
    bool accept_client(int timeout_ms);
    QlGdbStatus serve_fd(int fd, int timeout_ms = 5000);
    QlGdbStatus last_status() const noexcept { return status_; }

    std::uint16_t port() const noexcept { return port_; }
    bool attached() const noexcept { return client_fd_ >= 0; }

    // the protocol surface: one packet in (no '$'/'#' frame), one reply out.
    // Public so the packets are testable without a socket.
    std::string handle_packet(std::string_view packet);

private:
    std::string registers() const;
    bool set_registers(std::string_view hex);
    std::string read_register(int index) const;
    bool write_register(int index, std::string_view hex);
    std::vector<std::string> register_names() const;

    void serve_client(int fd);
    int timeout_ms_ = 5000;
    bool send_packet(std::string_view payload, int fd);
    std::string receive_packet(int fd);
    std::string stop_reply(int signal) const;

    // execution: one instruction (`s`) or until a breakpoint / the exit point
    void step();
    void cont();

    Qiling& ql_;
    std::string ip_;
    std::uint16_t port_ = 0;
    int listen_fd_ = -1;
    int client_fd_ = -1;
    bool running_ = false;
    bool stopped_ = false;
    QlGdbStatus status_ = QlGdbStatus::Ok;
    std::set<std::uint64_t> breakpoints_;
    HookRet breakpoint_hook_;
};

}  // namespace qiling

#endif  // QILING_GDBSERVER_HPP
