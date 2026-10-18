// os/dos/dos.py — the QlOsDos implementation

#include "qiling/os/dos/dos.hpp"

#include <cstdio>

#include "qiling/loader/dos.hpp"
#include "qiling/os/dos/interrupts.hpp"
#include "qiling/os/dos/utils.hpp"

namespace qiling {
namespace os {
namespace dos {

QlOsDos::QlOsDos(Qiling* ql) : QlOs(ql) {
    // dos.py: the path helpers exist for the dos family
    init_paths_if_managed();

    hook_syscall_dispatch();

    // dos.py: handle_next=0, handles={}, color_pairs={} — defaulted in the
    // header

    const auto ver = profile().get_int("KERNEL", "version");
    dos_ver = static_cast<int>(ver);
    const auto tps = profile().get("KERNEL", "ticks_per_second");
    if (tps.has_value()) {
        ticks_per_second = std::stod(*tps);
    }

    // dos.py start_time = datetime.now() (set in run(); the port stamps it
    // here so the int 1Ah leaves can read it even pre-run)
    start_time = std::chrono::steady_clock::now();
}

void QlOsDos::set_flag_value(Flags fl, int val) {
    // dos.py: eflags = eflags & (~fl) | (fl * val)
    auto& regs = ql().arch().regs();
    const auto eflags = regs.read("eflags");
    const auto f = static_cast<std::uint64_t>(fl);
    regs.write("eflags", (eflags & ~f) | (f * static_cast<std::uint64_t>(val)));
}

bool QlOsDos::test_flags(Flags fl) const {
    return (ql().arch().regs().read("eflags") & static_cast<std::uint64_t>(fl)) == static_cast<std::uint64_t>(fl);
}

void QlOsDos::set_cf() { set_flag_value(Flags::CF, 1); }

void QlOsDos::clear_cf() { set_flag_value(Flags::CF, 0); }

void QlOsDos::set_zf() { set_flag_value(Flags::ZF, 1); }

void QlOsDos::clear_zf() { set_flag_value(Flags::ZF, 0); }

void QlOsDos::set_int_api(unsigned intno, unsigned ah, std::function<void(Qiling&)> handler, QL_INTERCEPT intercept) {
    int_user_api_[intercept][{intno, ah}] = std::move(handler);
}

int QlOsDos::dispatch_interrupt(std::uint32_t intno) {
    std::fprintf(stderr, "[trace] int %02xh\n", intno);
    // dos.py hook_syscall cb: the (intno, ah) dispatch with the user
    // CALL/ENTER/EXIT hooks riding the leaf key
    const auto ah = static_cast<unsigned>(ql().arch().regs().read("ah"));
    const IntLeaf intinfo{intno, ah};

    auto& table = handlers();

    // dos.py: func = user_defined_api[CALL].get(intinfo) or handlers[intno];
    // onenter/onexit ride the ENTER/EXIT maps
    const IntHandler* func = nullptr;
    if (int_user_api_.count(QL_INTERCEPT::CALL) != 0 && int_user_api_.at(QL_INTERCEPT::CALL).count(intinfo) != 0) {
        // the CALL intercept replaces the built-in handler entirely (the
        // upstream dict-get semantics: a truthy CALL entry wins over the
        // built-in)
        const auto& h = int_user_api_.at(QL_INTERCEPT::CALL).at(intinfo);
        h(ql());
        return 0;
    }

    if (table.count(intno) != 0) {
        func = &table.at(intno);
    }

    std::function<void(Qiling&)> onenter;
    std::function<void(Qiling&)> onexit;
    if (int_user_api_.count(QL_INTERCEPT::ENTER) != 0 && int_user_api_.at(QL_INTERCEPT::ENTER).count(intinfo) != 0) {
        onenter = int_user_api_.at(QL_INTERCEPT::ENTER).at(intinfo);
    }
    if (int_user_api_.count(QL_INTERCEPT::EXIT) != 0 && int_user_api_.at(QL_INTERCEPT::EXIT).count(intinfo) != 0) {
        onexit = int_user_api_.at(QL_INTERCEPT::EXIT).at(intinfo);
    }

    if (onenter) {
        onenter(ql());
    }

    if (func == nullptr) {
        char msg[48];
        std::snprintf(msg, sizeof(msg), "DOS interrupt %02xh is not implemented", static_cast<unsigned>(intno));
        throw QlErrorNotImplemented(msg);
    }

    std::fprintf(stderr, "[trace] handler for %02xh\n", intno);
    (*func)(ql());

    std::fprintf(stderr, "[trace] after handler %02xh\n", intno);

    if (onexit) {
        onexit(ql());
    }

    return 0;
}

void QlOsDos::hook_syscall_dispatch() {
    // dos.py hook_syscall: hook_intr(cb) with the (intno, ah) dispatch
    std::fprintf(stderr, "[trace] hook_syscall_dispatch registering\n");
    const auto cb = [this](std::uint32_t intno) -> int { return dispatch_interrupt(intno); };
    intr_hook_ = ql().hook_intr(cb);
    std::fprintf(stderr, "[trace] hook registered\n");
}

void QlOsDos::run() {
    // dos.py run: the entry point rides the loader (the dos path always has
    // one); the exit point stays 0 unless the caller set one
    const auto entry = ql().entry_point_set() ? ql().entry_point() : ql().loader().entry_point;
    const auto exit = ql().exit_point_set() ? ql().exit_point() : 0;

    // dos.py: start_time = datetime.now()
    start_time = std::chrono::steady_clock::now();

    try {
        ql().emu_start(entry, exit, ql().timeout(), ql().count());
    } catch (const QlErrorBase&) {
        emu_error();
        throw;
    }
}

}  // namespace dos
}  // namespace os
}  // namespace qiling
