// os/dos/dos.py — the QlOsDos declaration + the FLAGS register bits

#pragma once

#include <chrono>
#include <map>

#include "qiling/core.hpp"
#include "qiling/os/filestruct.hpp"
#include "qiling/os/os.hpp"
#include "qiling/core_hooks_types.hpp"

namespace qiling {
namespace os {
namespace dos {

// dos.py Flags (https://en.wikipedia.org/wiki/FLAGS_register)
enum class Flags : std::uint64_t {
    CF = 1ull << 0,    // carry
    PF = 1ull << 2,    // parity
    AF = 1ull << 4,    // alignment
    ZF = 1ull << 6,    // zero
    SF = 1ull << 7,    // sign
    TF = 1ull << 8,    // trap
    IF = 1ull << 9,    // interrupt
    DF = 1ull << 10,   // direction
    OF = 1ull << 11,   // overflow
};

using IntHandler = std::function<void(Qiling&)>;

// the (intno, ah) key the dos interrupt dispatch and the user api table
// ride (dos.py's (intno, ah) tuple)
using IntLeaf = std::pair<unsigned, unsigned>;

class QlOsDos : public QlOs {
public:
    explicit QlOsDos(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::DOS; }

    void run() override;

    // dos.py set_flag_value / test_flags / set_cf / clear_cf / set_zf /
    // clear_cf
    void set_flag_value(Flags fl, int val);
    bool test_flags(Flags fl) const;
    void set_cf();
    void clear_cf();
    void set_zf();
    void clear_zf();

    // dos.py hook_syscall: the interrupt dispatcher entry (exposed for the
    // tests)
    int dispatch_interrupt(std::uint32_t intno);

    // dos.py set_api over the (intno, ah) keys: CALL runs raw, ENTER fires
    // before the handler and EXIT after it
    void set_int_api(unsigned intno, unsigned ah, std::function<void(Qiling&)> handler, QL_INTERCEPT intercept = QL_INTERCEPT::CALL);

    // the user api maps (dos.py user_defined_api keyed by the (intno, ah)
    // tuple; the base's name-keyed table serves the fcall surfaces)
    std::map<QL_INTERCEPT, std::map<IntLeaf, std::function<void(Qiling&)>>> int_user_api_;

    // ---- used by int 21h ----
    int handle_next = 0;
    std::map<int, std::shared_ptr<QlFile>> handles;

    // ---- used by int 10h ----
    // the upstream rides curses; the port keeps the terminal detached (the
    // documented deviation) and retains the state shell for the handlers
    std::map<int, std::map<int, int>> color_pairs;
    std::map<int, std::map<int, int>> reverse_color_pairs;
    void* stdscr = nullptr;

    // the profile [KERNEL] version / ticks_per_second
    int dos_ver = 7;
    double ticks_per_second = 18.206;

    // dos.py start_time (the int 1Ah elapsed-ticks base)
    std::chrono::steady_clock::time_point start_time{};

private:
    // dos.py hook_syscall (the ctor invokes it)
    void hook_syscall_dispatch();

    // the registered intr hook (the HookRet RAII: destroying it unregisters)
    std::optional<HookRet> intr_hook_;
};

}  // namespace dos
}  // namespace os
}  // namespace qiling
