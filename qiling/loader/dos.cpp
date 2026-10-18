// loader/dos.py — the QlLoaderDOS implementation

#include "qiling/loader/dos.hpp"

#include <fstream>

#include "qiling/core.hpp"
#include "qiling/os/disk.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace loader {

namespace {

// the little-endian u16 reader (loader/dos.py ql.unpack16)
std::uint16_t unpack16(const std::vector<std::uint8_t>& data, std::size_t off) {
    return static_cast<std::uint16_t>(data[off] | (data[off + 1] << 8));
}

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw QlErrorBase("dos loader: cannot open " + path);
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

bool ends_with(const std::string& s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix.data(), suffix.size()) == 0;
}

}  // namespace

ComParser::ComParser(Qiling& ql, const std::vector<std::uint8_t>& data) {
    // loader/dos.py: assert data[0:2] == b'MZ'
    if (data.size() < 0x18 || data[0] != 'M' || data[1] != 'Z') {
        throw QlErrorBase("dos loader: not an MZ-image COM file");
    }
    (void)ql;

    const auto nbytes = unpack16(data, 2) != 0 ? unpack16(data, 2) : 0x200;  // bytes in the last block; 0 means fully populated
    const auto nblocks = unpack16(data, 4);                                  // blocks used
    const auto hdrpgs = unpack16(data, 8);                                   // header paragraphs

    size = (static_cast<std::uint64_t>(nblocks) - 1) * 0x200 + nbytes;
    header_size = static_cast<std::uint64_t>(hdrpgs) * 0x10;

    init_ss = unpack16(data, 14);
    init_sp = unpack16(data, 16);
    init_ip = unpack16(data, 20);
    init_cs = unpack16(data, 22);
}

QlLoaderDOS::QlLoaderDOS(Qiling* ql) : QlLoader(ql) {}

void QlLoaderDOS::run() {
    const auto path = ql_->path();
    auto& profile = ql_->profile();

    std::vector<std::uint8_t> content;
    std::uint16_t cs = 0;
    std::uint16_t ip = 0;
    std::uint16_t sp = 0;
    std::uint16_t ss = 0;

    if (ends_with(path, ".DOS_COM")) {
        // bare COM file: the entry rides the profile's [COM] section
        content = read_file(path);

        cs = static_cast<std::uint16_t>(profile.get_int("COM", "start_cs"));
        ip = static_cast<std::uint16_t>(profile.get_int("COM", "start_ip"));
        sp = static_cast<std::uint16_t>(profile.get_int("COM", "start_sp"));
        ss = cs;
    } else if (ends_with(path, ".DOS_EXE")) {
        // COM file with a DOS header
        content = read_file(path);

        const auto com = ComParser(*ql_, content);

        cs = com.init_cs;
        ip = com.init_ip;
        sp = com.init_sp;
        ss = com.init_ss;

        content.erase(content.begin(), content.begin() + static_cast<std::ptrdiff_t>(com.header_size));
    } else if (ends_with(path, ".DOS_MBR")) {
        content = read_file(path);

        cs = 0x0000;
        ip = 0x7c00;
        sp = 0xfff0;
        ss = cs;

        // the BIOS-to-MBR interface: the first drive rides the fs mapper and
        // dl carries the drive number
        if (!ql_->os().fs_mapper()->has_mapping("0x80")) {
            ql_->os().map_fs_path("0x80", std::make_shared<os::QlDisk>(path, "0x80"));
        }

        ql_->arch().regs().write("dx", 0x80);
    } else {
        throw QlErrorNotImplemented("dos loader: the unrecognized program type");
    }

    auto& regs = ql_->arch().regs();
    regs.write("cs", cs);
    regs.write("ds", cs);
    regs.write("es", cs);
    regs.write("ss", ss);
    regs.write("ip", ip);
    regs.write("sp", sp);

    const auto base_address = (static_cast<std::uint64_t>(cs) << 4) + ip;
    const auto stack_address = (static_cast<std::uint64_t>(ss) << 4) + sp;

    // loader/dos.py sets stack_address/start_address/stack_size instance
    // attrs; the dos run() consumes only the entry point, so the port folds
    // the stack into init_sp and keeps the rest implicit
   
    (void)stack_address;

    // map the entire system memory
    ql_->mem().map(0, 0x100000, UC_PROT_ALL, "[FULL]");
    ql_->mem().write(base_address, content);

    load_address = base_address;
    entry_point = base_address;
    init_sp = stack_address;
    ql_->os().set_entry_point(base_address);
}

}  // namespace loader
}  // namespace qiling
