// os/dos/interrupts — the handler implementations (the upstream carries one
// file per interrupt; the port keeps the leaf-table shape per file as
// namespaces within this TU)

#include "qiling/os/dos/interrupts.hpp"

#include <ctime>
#include <fstream>
#include <thread>
#include <filesystem>
#include <thread>

#include "qiling/os/dos/dos.hpp"
#include "qiling/os/dos/utils.hpp"
#include "qiling/os/disk.hpp"

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

// ---- int13.py (the disk services over QlDisk) ----

namespace int13 {

// int13.py DiskError (the int 13h status codes)
enum class DiskError : std::uint8_t {
    NoError = 0,
    BadCommand = 1,
};

// int13.py parse_dap: unpack("<BBHHHQ", dapbs) -> (size, reserved, cnt,
// offset, segment, lba)
struct Dap {
    unsigned size = 0;
    unsigned reserved = 0;
    unsigned cnt = 0;
    unsigned offset = 0;
    unsigned segment = 0;
    std::uint64_t lba = 0;
};

Dap parse_dap(const std::vector<std::uint8_t>& b) {
    Dap d;
    d.size = b[0];
    d.reserved = b[1];
    d.cnt = static_cast<unsigned>(b[2] | (b[3] << 8));
    d.offset = static_cast<unsigned>(b[4] | (b[5] << 8));
    d.segment = static_cast<unsigned>(b[6] | (b[7] << 8));
    for (int i = 0; i < 8; ++i) {
        d.lba |= static_cast<std::uint64_t>(b[8 + i]) << (8 * i);
    }
    return d;
}

// the mapped-disk access: the QlDisk binding rides the fs mapper (the
// object-instance bindings return as-is)
os::QlDisk& mapped_disk(Qiling& ql, std::uint64_t dl) {
    auto& os = static_cast<QlOsDos&>(ql.os());
    return *std::static_pointer_cast<os::QlDisk>(os.fs_mapper()->open(int19::drive_key(dl), "rb+"));
}

void leaf_00(Qiling& ql) { static_cast<QlOsDos&>(ql.os()).clear_cf(); }

void leaf_02(Qiling& ql) {
    const auto idx = ql.arch().regs().read("dl");
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.fs_mapper() == nullptr || !os.fs_mapper()->has_mapping(int19::drive_key(idx))) {
        ql.arch().regs().write("ah", static_cast<std::uint8_t>(DiskError::BadCommand));
        os.set_cf();
        return;
    }

    const auto cx = ql.arch().regs().read("cx");
    const auto cylinder = ((cx & 0xff00) >> 8) | ((cx & 0xC0) << 2);
    const auto head = ql.arch().regs().read("dh");
    const auto sector = cx & 63;
    const auto cnt = ql.arch().regs().read("al");

    auto& disk = mapped_disk(ql, idx);
    const auto content = disk.read_chs(static_cast<int>(cylinder), static_cast<int>(head),
                                       static_cast<int>(sector), static_cast<int>(cnt));

    ql.mem().write(linaddr(ql.arch().regs().read("es"), ql.arch().regs().read("bx")), content);
    os.clear_cf();
    ql.arch().regs().write("ah", 0);
    ql.arch().regs().write("al", sector);
}

// int13.py __leaf_08: the drive parameter table
void leaf_08(Qiling& ql) {
    const auto idx = ql.arch().regs().read("dl");
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.fs_mapper() == nullptr || !os.fs_mapper()->has_mapping(int19::drive_key(idx))) {
        ql.arch().regs().write("ah", static_cast<std::uint8_t>(DiskError::BadCommand));
        os.set_cf();
        return;
    }

    auto& disk = mapped_disk(ql, idx);
    ql.arch().regs().write("dl", os.fs_mapper()->mapping_count());
    ql.arch().regs().write("dh", static_cast<std::uint64_t>(disk.n_heads() - 1));
    ql.arch().regs().write("bl", 0x4);
    ql.arch().regs().write("di", 0);
    ql.arch().regs().write("ds", 0);

    const auto n_sectors = std::min<std::uint64_t>(disk.n_sectors(), 63);
    const auto n_cylinders = std::min<std::uint64_t>(disk.n_cylinders(), 1023);

    auto cx = (n_sectors & 0b111111);
    cx |= ((n_cylinders & 0b11) << 6);
    cx |= (((n_cylinders & 0b1111111100) >> 2) << 8);

    ql.arch().regs().write("cx", cx);
    ql.arch().regs().write("ah", 0);
    os.clear_cf();
}

// int13.py __leaf_41: the extensions installation check
void leaf_41(Qiling& ql) {
    ql.arch().regs().write("ah", 0);
    // 1 -> the packet-structure access; 2 -> the drive locking/ejecting;
    // 4 -> the enhanced disk drive support
    ql.arch().regs().write("bx", 0xaa55);
    ql.arch().regs().write("cx", 7);
}

void leaf_42(Qiling& ql) {
    const auto idx = ql.arch().regs().read("dl");
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.fs_mapper() == nullptr || !os.fs_mapper()->has_mapping(int19::drive_key(idx))) {
        ql.arch().regs().write("ah", static_cast<std::uint8_t>(DiskError::BadCommand));
        os.set_cf();
        return;
    }

    const auto dapbs = ql.mem().read(linaddr(ql.arch().regs().read("ds"), ql.arch().regs().read("si")), 16);
    const auto dap = parse_dap(dapbs);
    auto& disk = mapped_disk(ql, idx);
    const auto content = disk.read_sectors(dap.lba, static_cast<int>(dap.cnt));

    ql.mem().write(linaddr(dap.segment, dap.offset), content);
    os.clear_cf();
    ql.arch().regs().write("ah", 0);
}

void leaf_43(Qiling& ql) {
    const auto idx = ql.arch().regs().read("dl");
    auto& os = static_cast<QlOsDos&>(ql.os());

    if (os.fs_mapper() == nullptr || !os.fs_mapper()->has_mapping(int19::drive_key(idx))) {
        ql.arch().regs().write("ah", static_cast<std::uint8_t>(DiskError::BadCommand));
        os.set_cf();
        return;
    }

    const auto dapbs = ql.mem().read(linaddr(ql.arch().regs().read("ds"), ql.arch().regs().read("si")), 16);
    const auto dap = parse_dap(dapbs);
    auto& disk = mapped_disk(ql, idx);
    const auto buffer = ql.mem().read(linaddr(dap.segment, dap.offset), dap.cnt * static_cast<unsigned>(disk.sector_size()));
    disk.write_sectors(dap.lba, static_cast<int>(dap.cnt), buffer);

    os.clear_cf();
    ql.arch().regs().write("ah", 0);
}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    static const std::map<unsigned, std::function<void(Qiling&)>> leaves = {
        {0x00, leaf_00},  {0x02, leaf_02},  {0x08, leaf_08},  {0x41, leaf_41},  {0x42, leaf_42},  {0x43, leaf_43},
    };

    const auto it = leaves.find(static_cast<unsigned>(ah));
    if (it == leaves.end()) {
        throw QlErrorNotImplemented("leaf of INT 13h is not implemented");
    }

    it->second(ql);
}

}  // namespace int13

// ---- int15.py (the system services; the APM shape)
// @see: http://www.oldlinux.org/Linux.old/docs/interrupts/int-html/int-15.htm

namespace int15 {

void leaf_00(Qiling& /*ql*/) {}
void leaf_01(Qiling& /*ql*/) {}

// int15.py __leaf_53: the APM interface
void leaf_53(Qiling& ql) {
    const auto al = ql.arch().regs().read("al");

    if (al == 0x01) {
        static_cast<QlOsDos&>(ql.os()).clear_cf();
    } else if (al == 0x0e) {
        ql.arch().regs().write("ax", 0x0102);
        static_cast<QlOsDos&>(ql.os()).clear_cf();
    } else if (al == 0x07) {
        if ((ql.arch().regs().read("bx") == 1) && (ql.arch().regs().read("cx") == 3)) {
            // the "Emulation Stop" log
            ql.os().set_exit_code(0);
            ql.emu_stop();
        }
    } else {
        throw QlErrorNotImplemented("leaf of INT 15h is not implemented");
    }
}

// int15.py __leaf_86: the microsecond wait
void leaf_86(Qiling& ql) {
    const auto dx = ql.arch().regs().read("dx");
    const auto cx = ql.arch().regs().read("cx");
    const auto full_secs = ((cx << 16) + dx) / 1000000.0;

    std::this_thread::sleep_for(std::chrono::duration<double>(full_secs));

    // the single-thread assumption note (the upstream verbatim)
    static_cast<QlOsDos&>(ql.os()).clear_cf();
    ql.arch().regs().write("ah", 0x80);
}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    static const std::map<unsigned, std::function<void(Qiling&)>> leaves = {
        {0x00, leaf_00}, {0x01, leaf_01}, {0x53, leaf_53}, {0x86, leaf_86},
    };

    const auto it = leaves.find(static_cast<unsigned>(ah));
    if (it == leaves.end()) {
        throw QlErrorNotImplemented("leaf of INT 15h is not implemented");
    }

    it->second(ql);
}

}  // namespace int15

// ---- int16.py (the keyboard services)
//
// The upstream rides the curses stdscr for the input; the port keeps the
// terminal detached and reads the blocking leaf through the injected stdin
// stream. The SCANCODES table ports the ASCII-key subset (the curses KEY_*
// constants have no port counterpart).

namespace int16 {

// int16.py SCANCODES (the ascii-key subset)
const std::map<unsigned, unsigned>& scancodes() {
    static const std::map<unsigned, unsigned> table = {
        {'1', 0x02}, {'!', 0x02}, {'2', 0x03}, {'@', 0x03}, {'3', 0x04}, {'#', 0x04},
        {'4', 0x05}, {'$', 0x05}, {'5', 0x06}, {'%', 0x06}, {'6', 0x07}, {'^', 0x07},
        {'7', 0x08}, {'&', 0x07}, {'8', 0x09}, {'*', 0x09}, {'9', 0x0A}, {'(', 0x0A},
        {'0', 0x0B}, {')', 0x0B}, {'-', 0x0C}, {'_', 0x0C}, {'=', 0x0D}, {'+', 0x0D},
        {'\b', 0x0E}, {'\t', 0x0F},
        {'q', 0x10}, {'Q', 0x10}, {'w', 0x11}, {'W', 0x11}, {'e', 0x12}, {'E', 0x12},
        {'r', 0x13}, {'R', 0x13}, {'t', 0x14}, {'T', 0x14}, {'y', 0x15}, {'Y', 0x15},
        {'u', 0x16}, {'U', 0x16}, {'i', 0x17}, {'I', 0x17}, {'o', 0x18}, {'O', 0x18},
        {'p', 0x19}, {'P', 0x19}, {'[', 0x1A}, {'}', 0x1A}, {']', 0x1B}, {'{', 0x1B},
        {'\r', 0x1C}, {'\n', 0x1C},
        {'a', 0x1E}, {'A', 0x1E}, {'s', 0x1F}, {'S', 0x1F}, {'d', 0x20}, {'D', 0x20},
        {'f', 0x21}, {'F', 0x21}, {'g', 0x22}, {'G', 0x22}, {'h', 0x23}, {'H', 0x23},
        {'j', 0x24}, {'J', 0x24}, {'k', 0x25}, {'K', 0x25}, {'l', 0x26}, {'L', 0x26},
        {';', 0x27}, {':', 0x27}, {39, 0x28}, {'"', 0x28}, {'`', 0x29}, {'~', 0x29},
        {92, 0x2B}, {'|', 0x2B},
        {'z', 0x2C}, {'Z', 0x2C}, {'x', 0x2D}, {'X', 0x2D}, {'c', 0x2E}, {'C', 0x2E},
        {'v', 0x2F}, {'V', 0x2F}, {'b', 0x30}, {'B', 0x30}, {'n', 0x31}, {'N', 0x31},
        {'m', 0x32}, {'M', 0x32}, {',', 0x33}, {'<', 0x33}, {'.', 0x34}, {'>', 0x34},
        {'/', 0x35}, {'?', 0x35},
        {' ', 0x39},
    };
    return table;
}

unsigned get_scan_code(unsigned ch) {
    const auto& table = scancodes();
    const auto it = table.find(ch);
    return it != table.end() ? it->second : 0;
}

// int16.py __leaf_00: the blocking read; the ascii rides al and the scan
// code rides ah
void leaf_00(Qiling& ql) {
    auto& os = static_cast<QlOsDos&>(ql.os());
    const auto ch = os.stdin_stream().read(1);
    const auto key = ch.empty() ? 0 : ch[0];

    if (key < 0x80) {
        ql.arch().regs().write("al", key);
    } else {
        ql.arch().regs().write("al", 0);
    }
    ql.arch().regs().write("ah", get_scan_code(key));
}

// int16.py __leaf_01: the poll — the non-blocking console read has no
// portable shape in the port (the curses timeout(0) analogue); degrades to
// the documented NotImplemented
void leaf_01(Qiling& /*ql*/) {
    throw QlErrorNotImplemented("INT 16h poll: the curses-free port keeps the terminal detached");
}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    static const std::map<unsigned, std::function<void(Qiling&)>> leaves = {
        {0x00, leaf_00},
        {0x01, leaf_01},
    };

    const auto it = leaves.find(static_cast<unsigned>(ah));
    if (it == leaves.end()) {
        throw QlErrorNotImplemented("leaf of INT 16h is not implemented");
    }

    it->second(ql);
}

}  // namespace int16

// ---- int10.py (the BIOS video; the upstream rides curses)
//
// The port keeps the terminal detached (the curses setup/surface is not
// carried): the mode-set resolution map stays verbatim (the unknown mode
// throws), the cursor/scroll leaves degrade to no-ops, the char/attr read
// keeps the upstream's null-stdscr branch (ax=0x0720) and the teletype echo
// writes through the console out.

namespace int10 {

// int10.py resolution map (the BIOS video modes)
unsigned video_resolution(unsigned al) {
    switch (al) {
        case 0x00: case 0x01: return 25 << 8 | 40;
        case 0x02: case 0x03: return 25 << 8 | 80;
        case 0x04: case 0x05: return 200 << 8 | 320;
        case 0x06: return 200 << 8 | 640;
        case 0x08: return 200 << 8 | 160;
        case 0x09: return 200 << 8 | 320;
        case 0x0a: return 200 << 8 | 640;
        case 0x0d: return 200 << 8 | 320;
        case 0x0e: return 200 << 8 | 640;
        case 0x0f: case 0x10: return 350 << 8 | 640;
        case 0x11: case 0x12: return 480 << 8 | 640;
        case 0x13: return 200 << 8 | 320;
        default: return 0;
    }
}

// int10.py __leaf_00: the mode set (the curses init skipped - detached)
void leaf_00(Qiling& ql) {
    const auto al = ql.arch().regs().read("al");

    if (video_resolution(static_cast<unsigned>(al)) == 0) {
        throw QlErrorNotImplemented("the video mode resolution is not implemented");
    }
}

void leaf_01(Qiling& /*ql*/) {
    // the cursor shape: the ch&0x20 hides the cursor (the curses curs_set);
    // detached, nothing to do
}

void leaf_02(Qiling& /*ql*/) {
    // the cursor move: detached, nothing to do
}

void leaf_05(Qiling& ql) {
    // int10.py __leaf_05: al=0
    ql.arch().regs().write("al", 0);
}

void leaf_06(Qiling& /*ql*/) {
    // the scroll: detached, nothing to do
}

void leaf_08(Qiling& ql) {
    // int10.py __leaf_08: the stdscr-null branch (the port's stdscr stays
    // null) - ax=0x0720 (the space with the default attr)
    ql.arch().regs().write("ax", 0x0720);
}

// int10.py __leaf_0e: the teletype echo
void leaf_0e(Qiling& ql) {
    const auto al = ql.arch().regs().read("al");
    auto& out = ql.os().console_out();
    out.write({static_cast<std::uint8_t>(al & 0xff)});
}

void handler(Qiling& ql) {
    const auto ah = ql.arch().regs().read("ah");

    static const std::map<unsigned, std::function<void(Qiling&)>> leaves = {
        {0x00, leaf_00}, {0x01, leaf_01}, {0x02, leaf_02}, {0x05, leaf_05},
        {0x06, leaf_06}, {0x08, leaf_08}, {0x0e, leaf_0e},
    };

    const auto it = leaves.find(static_cast<unsigned>(ah));
    if (it == leaves.end()) {
        throw QlErrorNotImplemented("leaf of INT 10h is not implemented");
    }

    it->second(ql);
}

}  // namespace int10

}  // namespace

const std::map<unsigned, IntHandler>& handlers() {
    static const std::map<unsigned, IntHandler> table = {
        {0x13, int13::handler},
        {0x15, int15::handler},
        {0x16, int16::handler},
        {0x10, int10::handler},
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
