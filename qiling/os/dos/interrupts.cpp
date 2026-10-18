// os/dos/interrupts — the handler implementations (the upstream carries one
// file per interrupt; the port keeps the leaf-table shape per file as
// namespaces within this TU)

#include "qiling/os/dos/interrupts.hpp"

#include <ctime>
#include <fstream>
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

// ---- int1a.py (the clock services) ----

namespace int1a {

// int1a.py __set_elapsed_ticks: the ticks since the run started
void set_elapsed_ticks(Qiling& ql) {
    auto& os = static_cast<QlOsDos&>(ql.os());
    const auto now = std::chrono::steady_clock::now();
    const auto secs = std::chrono::duration<double>(now - os.start_time).count();
    const auto ticks = static_cast<std::uint64_t>(secs * os.ticks_per_second);

    ql.arch().regs().write("cx", (ticks >> 16) & 0xffff);
    ql.arch().regs().write("dx", ticks & 0xffff);
}

void leaf_00(Qiling& ql) {
    set_elapsed_ticks(ql);
    ql.arch().regs().write("al", 0);
}

void leaf_01(Qiling& ql) { set_elapsed_ticks(ql); }

// int1a.py __leaf_02_03: the RTC time (the BCD hour/minute/second, dl=0)
void leaf_02_03(Qiling& ql) {
    const std::time_t t = std::time(nullptr);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif

    ql.arch().regs().write("ch", bin2bcd(tm_buf.tm_hour));
    ql.arch().regs().write("cl", bin2bcd(tm_buf.tm_min));
    ql.arch().regs().write("dh", bin2bcd(tm_buf.tm_sec));
    ql.arch().regs().write("dl", 0);
    static_cast<QlOsDos&>(ql.os()).clear_cf();
}

// int1a.py __leaf_04_05: the RTC date (the century/year/month/day in BCD)
void leaf_04_05(Qiling& ql) {
    const std::time_t t = std::time(nullptr);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    const int year = tm_buf.tm_year + 1900;

    ql.arch().regs().write("ch", bin2bcd((year - 1) / 100));
    ql.arch().regs().write("cl", bin2bcd(year % 100));
    ql.arch().regs().write("dh", bin2bcd(tm_buf.tm_mon + 1));
    ql.arch().regs().write("dl", bin2bcd(tm_buf.tm_mday));
    static_cast<QlOsDos&>(ql.os()).clear_cf();
}

// int1a.py __leaf_06_07_09: the alarm set/cancel rides unsupported (the set_cf)
void leaf_06_07_09(Qiling& ql) { static_cast<QlOsDos&>(ql.os()).set_cf(); }

void leaf_08(Qiling& /*ql*/) {}

void leaf_0a(Qiling& ql) {
    const std::time_t t = std::time(nullptr);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif

    // the days since 1980-01-01 (the upstream's datetime(1980, 1, 1) base)
    std::tm epoch{};
    epoch.tm_year = 80;
    epoch.tm_mon = 0;
    epoch.tm_mday = 1;
    epoch.tm_hour = 0;
    epoch.tm_min = 0;
    epoch.tm_sec = 0;
    epoch.tm_isdst = -1;

    const auto days = static_cast<std::int64_t>(std::mktime(&tm_buf) - std::mktime(&epoch)) / (24 * 60 * 60);
    ql.arch().regs().write("cx", static_cast<std::uint64_t>(days));
}

void leaf_0b(Qiling& /*ql*/) {}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    static const std::map<unsigned, std::function<void(Qiling&)>> leaves = {
        {0x00, leaf_00},        {0x01, leaf_01},   {0x02, leaf_02_03},        {0x03, leaf_02_03},
        {0x04, leaf_04_05},     {0x05, leaf_04_05}, {0x06, leaf_06_07_09},    {0x07, leaf_06_07_09},
        {0x08, leaf_08},        {0x09, leaf_06_07_09}, {0x0a, leaf_0a},       {0x0b, leaf_0b},
    };

    const auto it = leaves.find(static_cast<unsigned>(ah));
    if (it == leaves.end()) {
        throw QlErrorNotImplemented("leaf of INT 1Ah is not implemented");
    }

    it->second(ql);
}

}  // namespace int1a

// ---- int19.py (the MBR boot: reload the boot sector and transfer) ----

namespace int19 {

// the drive bindings key the fs mapper by the hex string of the drive
// number (the loader/dos.py add_mapping(0x80, ...) int key ported as "0x80")
std::string drive_key(std::uint64_t dl) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%x", static_cast<unsigned>(dl & 0xff));
    return std::string(buf);
}

void handler(Qiling& ql) {
    // int19.py: dl carries the drive; the mapped disk rides the fs mapper,
    // the unmapped case falls back to the program file itself
    const auto dl = ql.arch().regs().read("dl");
    std::vector<std::uint8_t> mbr;

    auto& os = static_cast<QlOsDos&>(ql.os());
    const auto key = drive_key(dl);
    if (os.fs_mapper() != nullptr && os.fs_mapper()->has_mapping(key)) {
        auto disk = os.fs_mapper()->open(key, "rb+");
        disk->lseek(0, 0);
        mbr = disk->read(512);
    } else {
        std::ifstream f(ql.path(), std::ios::binary);
        mbr.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        if (mbr.size() > 512) {
            mbr.resize(512);
        }
    }

    // int19.py: write at 0x7C00 then transfer (cs=0x07C0, ip=0); the memory
    // is not cleaned (the upstream note)
    ql.mem().write(0x7C00, mbr);
    ql.arch().regs().write("cs", 0x07C0);
    ql.arch().regs().write("ip", 0);
}

}  // namespace int19

}  // namespace

const std::map<unsigned, IntHandler>& handlers() {
    static const std::map<unsigned, IntHandler> table = {
        {0x1a, int1a::handler},
        {0x19, int19::handler},
        {0x20, int20::handler},
        {0x21, int21::handler},
    };
    return table;
}

}  // namespace dos
}  // namespace os
}  // namespace qiling
