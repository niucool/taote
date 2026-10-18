// os/dos/utils.py — the string-reading helpers

#include "qiling/os/dos/utils.hpp"

namespace qiling {
namespace os {
namespace dos {

std::string read_dos_string(Qiling& ql, std::uint64_t address) {
    std::string out;
    while (true) {
        const auto ch = ql.mem().read(address, 1);
        if (!ch.empty() && ch[0] == '$') {
            break;
        }
        if (!ch.empty()) {
            out.push_back(static_cast<char>(ch[0]));
        }
        address += 1;
    }
    return out;
}

std::string read_dos_string_from_ds_dx(Qiling& ql) {
    const auto address = linaddr(ql.arch().regs().read("ds"), ql.arch().regs().read("dx"));
    return read_dos_string(ql, address);
}

}  // namespace dos
}  // namespace os
}  // namespace qiling
