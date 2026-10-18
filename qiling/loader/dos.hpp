// loader/dos.py — the DOS loader (the bare COM, the MZ-headered COM and the
// MBR branches over the 8086 real-mode memory model)
//
// The upstream's curses excepthook plumbing is a TUI artifact and is not
// ported. The drive bindings key the fs mapper by the hex string of the
// drive number ("0x80") — the Python original keys the dict by the int.

#pragma once

#include "qiling/loader/loader.hpp"

namespace qiling {
namespace loader {

// loader/dos.py ComParser — the most basic COM file parser
class ComParser {
public:
    ComParser(Qiling& ql, const std::vector<std::uint8_t>& data);

    std::uint64_t size = 0;
    std::uint64_t header_size = 0;
    std::uint16_t init_ss = 0;
    std::uint16_t init_sp = 0;
    std::uint16_t init_ip = 0;
    std::uint16_t init_cs = 0;
};

class QlLoaderDOS final : public QlLoader {
public:
    explicit QlLoaderDOS(Qiling* ql);

    void run() override;
};

}  // namespace loader
}  // namespace qiling
