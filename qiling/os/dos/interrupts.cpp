// os/dos/interrupts — the handler implementations (the upstream carries one
// file per interrupt; the port keeps the leaf-table shape per file as
// namespaces within this TU)

#include "qiling/os/dos/interrupts.hpp"

#include <filesystem>
#include <thread>

#include "qiling/os/dos/dos.hpp"
#include "qiling/os/dos/utils.hpp"

namespace qiling {
namespace os {
namespace dos {

namespace {

// ---- int20.py (the terminate; ah=13h rides the no-op leaf) ----

namespace int20 {

void leaf_13(Qiling& /*ql*/) {
    // int20.py __leaf_13: pass
}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    if (ah != 0x13) {
        // int20.py: the leaf is looked up and the miss raises
        throw QlErrorNotImplemented("leaf of INT 20h is not implemented");
    }
    leaf_13(ql);
}

}  // namespace int20

// ---- int21.py (the DOS services) ----

namespace int21 {

// write a character to screen
void leaf_02(Qiling& ql) {
    const auto ch = ql.arch().regs().read("dl");
    ql.arch().regs().write("al", ch);

    // the upstream prints to the stdout via curses-less print (the leaf 02
    // shape is plain print)
    std::fputc(static_cast<int>(ch & 0xff), stdout);
}

// write a string to screen
void leaf_09(Qiling& ql) {
    const auto str = read_dos_string_from_ds_dx(ql);
    std::fputs(str.c_str(), stdout);
}

// clear input buffer
void leaf_0c(Qiling& /*ql*/) {}

// set interrupt vector
void leaf_25(Qiling& /*ql*/) {}

// create psp
void leaf_26(Qiling& /*ql*/) {}

// get dos version
void leaf_30(Qiling& ql) {
    ql.arch().regs().write("ax", static_cast<std::uint64_t>(static_cast<QlOsDos&>(ql.os()).dos_ver));
}

// get or set ctrl-break
void leaf_33(Qiling& /*ql*/) {}

// get interrupt vector
void leaf_35(Qiling& /*ql*/) {}

// open file for write
void leaf_3c(Qiling& ql) {
    // fileattr ignored
    const auto fname = read_dos_string_from_ds_dx(ql);
    const auto fpath = ql.os().path()->virtual_to_host_path(fname);

    auto& os = static_cast<QlOsDos&>(ql.os());
    os.handles[os.handle_next] = QlFile::open_mode(fpath, "wb");
    ql.arch().regs().write("ax", static_cast<std::uint64_t>(os.handle_next));
    os.handle_next += 1;
    os.clear_cf();
}

// open file for read
void leaf_3d(Qiling& ql) {
    const auto fname = read_dos_string_from_ds_dx(ql);
    const auto fpath = ql.os().path()->virtual_to_host_path(fname);

    auto& os = static_cast<QlOsDos&>(ql.os());
    os.handles[os.handle_next] = QlFile::open_mode(fpath, "rb");
    ql.arch().regs().write("ax", static_cast<std::uint64_t>(os.handle_next));
    os.handle_next += 1;
    os.clear_cf();
}

// close file
void leaf_3e(Qiling& ql) {
    const auto hd = static_cast<int>(ql.arch().regs().read("bx"));
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.handles.count(hd) != 0) {
        auto f = os.handles.at(hd);
        os.handles.erase(hd);
        f->close();

        os.clear_cf();
    } else {
        ql.arch().regs().write("ax", 0x06);
        os.set_cf();
    }
}

// read from file
void leaf_3f(Qiling& ql) {
    const auto hd = static_cast<int>(ql.arch().regs().read("bx"));
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.handles.count(hd) != 0) {
        const auto& f = os.handles.at(hd);
        const auto buffer = linaddr(ql.arch().regs().read("ds"), ql.arch().regs().read("dx"));
        const auto sz = ql.arch().regs().read("cx");
        const auto rd = f->read(static_cast<std::size_t>(sz));
        ql.mem().write(buffer, rd);
        os.clear_cf();
        ql.arch().regs().write("ax", rd.size());
    } else {
        ql.arch().regs().write("ax", 0x06);
        os.set_cf();
    }
}

// write to file
void leaf_40(Qiling& ql) {
    const auto hd = static_cast<int>(ql.arch().regs().read("bx"));
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.handles.count(hd) != 0) {
        const auto& f = os.handles.at(hd);
        const auto buffer = linaddr(ql.arch().regs().read("ds"), ql.arch().regs().read("dx"));
        const auto sz = ql.arch().regs().read("cx");
        const auto rd = ql.mem().read(buffer, static_cast<std::size_t>(sz));
        f->write(rd);
        os.clear_cf();
        ql.arch().regs().write("ax", rd.size());
    } else {
        ql.arch().regs().write("ax", 0x06);
        os.set_cf();
    }
}

// delete file
void leaf_41(Qiling& ql) {
    const auto fname = read_dos_string_from_ds_dx(ql);
    const auto fpath = ql.os().path()->virtual_to_host_path(fname);

    std::error_code ec;
    std::filesystem::remove(fpath, ec);
    if (!ec) {
        static_cast<QlOsDos&>(ql.os()).clear_cf();
    } else {
        ql.arch().regs().write("ax", 0x05);
        static_cast<QlOsDos&>(ql.os()).set_cf();
    }
}

// get drive info (the minimal shape)
void leaf_43(Qiling& ql) {
    ql.arch().regs().write("cx", 0xffff);
    static_cast<QlOsDos&>(ql.os()).clear_cf();
}

// allocate memory (announce only)
void leaf_48(Qiling& ql) {
    // dos.py: size = bx * 0x10; announce but do not do anything really
    const auto size = ql.arch().regs().read("bx") * 0x10;
    (void)size;

    // success
    static_cast<QlOsDos&>(ql.os()).clear_cf();
}

// deallocate memory (the stub)
void leaf_49(Qiling& /*ql*/) {}

// modify memory allocation (announce only)
void leaf_4a(Qiling& ql) {
    const auto addr = ql.arch().regs().read("es");
    const auto size = ql.arch().regs().read("bx") * 0x10;
    (void)addr;
    (void)size;

    // success
    static_cast<QlOsDos&>(ql.os()).clear_cf();
}

// terminate (the graceful exit)
void leaf_4c(Qiling& ql) {
    // dos.py: the "Program terminated gracefully" log then the stop
    ql.os().set_exit_code(0);
    ql.emu_stop();
}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    static const std::map<unsigned, std::function<void(Qiling&)>> leaves = {
        {0x02, leaf_02},  {0x06, leaf_02},  {0x09, leaf_09},  {0x0c, leaf_0c},  {0x25, leaf_25},
        {0x26, leaf_26},  {0x30, leaf_30},  {0x33, leaf_33},  {0x35, leaf_35},  {0x3c, leaf_3c},
        {0x3d, leaf_3d},  {0x3e, leaf_3e},  {0x3f, leaf_3f},  {0x40, leaf_40},  {0x41, leaf_41},
        {0x43, leaf_43},  {0x48, leaf_48},  {0x49, leaf_49},  {0x4a, leaf_4a},  {0x4c, leaf_4c},
    };

    const auto it = leaves.find(static_cast<unsigned>(ah));
    if (it == leaves.end()) {
        throw QlErrorNotImplemented("leaf of INT 21h is not implemented");
    }

    it->second(ql);
}

}  // namespace int21

}  // namespace

const std::map<unsigned, IntHandler>& handlers() {
    static const std::map<unsigned, IntHandler> table = {
        {0x20, int20::handler},
        {0x21, int21::handler},
    };
    return table;
}

}  // namespace dos
}  // namespace os
}  // namespace qiling
