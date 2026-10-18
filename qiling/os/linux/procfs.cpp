// mirrors the upstream pair-walk; the cmdline/environ join the latin-1 bytes
// (the ascii subset maps 1:1). The self_exe opens the host image through the
// std streams; the self_map renders the mapinfo table.
#include "qiling/os/linux/procfs.hpp"
#include "qiling/os/linux/linux.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

#include "qiling/core.hpp"
#include "qiling/loader/elf.hpp"
#include "qiling/os/memory.hpp"

namespace qiling {
namespace os {
namespace linux {

std::vector<std::uint8_t> FsMappedStream::read(std::size_t read_len) {
    const auto avail = content_.size() - std::min(content_.size(), cursor_);
    const auto take = std::min<std::size_t>(read_len, avail);
    std::vector<std::uint8_t> out(content_.begin() + static_cast<std::ptrdiff_t>(cursor_),
                                  content_.begin() + static_cast<std::ptrdiff_t>(cursor_ + take));
    cursor_ += take;
    return out;
}

std::size_t FsMappedStream::write(const std::vector<std::uint8_t>&) {
    // procfs is read-only
    return 0;
}

std::vector<std::uint8_t> QlProcFS::self_auxv(QlOsLinux& os) {
    auto& ql = os.ql();
    const auto nbytes = ql.arch().bits() / 8;
    const auto* loader_elf = dynamic_cast<const loader::QlLoaderELF*>(&ql.loader());
    if (loader_elf == nullptr) {
        return {};
    }
    std::uint64_t auxv_addr = loader_elf->auxv_address();

    // keep reading until the AUXV.AT_NULL pair is reached (procfs.py, verbatim)
    std::vector<std::uint8_t> auxv;
    while (true) {
        const auto key = ql.mem().read(auxv_addr, nbytes);
        auxv.insert(auxv.end(), key.begin(), key.end());
        auxv_addr += nbytes;

        const auto val = ql.mem().read(auxv_addr, nbytes);
        auxv.insert(auxv.end(), val.begin(), val.end());
        auxv_addr += nbytes;

        const bool pair_is_zero = std::all_of(key.begin(), key.end(), [](std::uint8_t b) { return b == 0; }) &&
                                  std::all_of(val.begin(), val.end(), [](std::uint8_t b) { return b == 0; });
        if (pair_is_zero) {
            break;
        }
    }
    return auxv;
}

std::vector<std::uint8_t> QlProcFS::self_cmdline(QlOsLinux& os) {
    std::vector<std::uint8_t> cmdline;
    bool first = true;
    for (const auto& arg : os.ql().argv()) {
        if (!first) {
            cmdline.push_back(0);
        }
        first = false;
        cmdline.insert(cmdline.end(), arg.begin(), arg.end());
    }
    cmdline.push_back(0);
    return cmdline;
}

std::vector<std::uint8_t> QlProcFS::self_environ(QlOsLinux& os) {
    std::vector<std::uint8_t> env_data;
    bool first = true;
    for (const auto& [key, value] : os.ql().env()) {
        if (!first) {
            env_data.push_back(0);
        }
        first = false;
        env_data.insert(env_data.end(), key.begin(), key.end());
        env_data.push_back('=');
        env_data.insert(env_data.end(), value.begin(), value.end());
    }
    env_data.push_back(0);
    return env_data;
}

std::vector<std::uint8_t> QlProcFS::self_exe(QlOsLinux& os) {
    std::ifstream in(os.ql().path(), std::ios::binary);
    if (!in) {
        return {};
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    const auto text = buffer.str();
    return std::vector<std::uint8_t>{text.begin(), text.end()};
}

std::vector<std::uint8_t> QlProcFS::self_map(QlMemoryManager& mem) {
    std::string content;
    for (const auto& [lbound, ubound, perms, label, container] : mem.get_mapinfo()) {
        std::ostringstream line;
        line << std::hex << lbound << '-' << ubound << '\t' << perms << "p\t0\t00:00\t0\t"
             << (container.empty() ? label : container) << '\n';
        content += line.str();
    }
    return std::vector<std::uint8_t>{content.begin(), content.end()};
}

}  // namespace linux
}  // namespace os
}  // namespace qiling
