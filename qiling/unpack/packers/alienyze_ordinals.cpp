// qiling/unpack/packers/alienyze_ordinals.cpp — see alienyze_ordinals.hpp.
#include "qiling/unpack/packers/alienyze_ordinals.hpp"

namespace qiling {
namespace unpack {
namespace alienyze {

namespace {

constexpr std::size_t kMaxSlots = 8192;  // far past any real import table

std::uint32_t rd32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

// an INT slot: a hint/name RVA inside the image, an import ordinal, or a
// terminator/pad zero
enum class Slot { Zero, Name, Ordinal };

Slot classify(std::uint32_t v, std::size_t n) {
    if (v == 0) {
        return Slot::Zero;
    }
    if (v >= 0x1000 && v < n) {
        return Slot::Name;
    }
    if ((v & 0xffff0000u) == 0x80000000u && (v & 0xffffu) != 0 && (v & 0xffffu) < 0x4000u) {
        return Slot::Ordinal;
    }
    return Slot::Zero;  // not a table slot: the caller stops on this
}

}  // namespace

std::vector<std::pair<std::string, std::uint32_t>> store_ordinal_pairs(
    const std::uint8_t* dec, std::size_t n, std::size_t idt_end,
    const std::vector<std::string>& dll_names, const std::vector<std::size_t>& dll_name_counts) {
    std::vector<std::pair<std::string, std::uint32_t>> out;
    if (dec == nullptr || n == 0 || idt_end == 0 || idt_end >= n || dll_names.empty() ||
        dll_names.size() != dll_name_counts.size()) {
        return out;
    }

    // ---- the table: zero-separated blocks, one per DLL ----
    struct Block {
        std::size_t names = 0;
        std::vector<std::uint32_t> ordinals;
    };
    std::vector<Block> blocks;
    Block cur;
    bool any = false;
    const auto flush = [&blocks, &cur, &any] {
        if (any) {
            blocks.push_back(cur);
            cur = Block{};
            any = false;
        }
    };
    std::size_t p = idt_end;
    bool terminated = false;
    for (std::size_t i = 0; i < kMaxSlots && p + 4 <= n; ++i, p += 4) {
        const std::uint32_t v = rd32(dec + p);
        if (v == 0) {
            flush();  // the INT array's own terminator
            continue;
        }
        switch (classify(v, n)) {
            case Slot::Name:
                ++cur.names;
                any = true;
                break;
            case Slot::Ordinal:
                cur.ordinals.push_back(v & 0xffffu);
                any = true;
                break;
            default:
                terminated = true;  // the first dword that is neither: table over
                break;
        }
        if (terminated) {
            break;
        }
    }
    if (!terminated) {
        flush();
    }

    // ---- the attribution ----
    // A block whose every slot is an ordinal is a DLL the store imported
    // exclusively by ordinal: such a DLL leaves no name record, so its marker
    // group is empty too. Both lists are in the store's own DLL order, so they
    // pair up 1:1 - and only when the two counts actually agree, which is the
    // self-check (measured 2 blocks against OLEAUT32+WS2_32 on
    // alienyze_HWMonitorPro_x32, 1 against WS2_32 on alienyze_Everything).
    // The positional block->marker map is NOT usable: measured, the ordinal
    // blocks sit at table positions 5 and 12 against marker indices 11 and 12.
    std::vector<std::size_t> pure;
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        if (blocks[i].names == 0 && !blocks[i].ordinals.empty()) {
            pure.push_back(i);
        }
    }
    std::vector<std::size_t> nameless;
    for (std::size_t i = 0; i < dll_names.size(); ++i) {
        if (dll_name_counts[i] == 0) {
            nameless.push_back(i);
        }
    }
    if (pure.empty() || pure.size() != nameless.size()) {
        return out;
    }
    for (std::size_t k = 0; k < pure.size(); ++k) {
        const auto& blk = blocks[pure[k]];
        const std::string& dll = dll_names[nameless[k]];
        for (const std::uint32_t ord : blk.ordinals) {
            out.emplace_back(dll, ord);
        }
    }
    return out;
}

}  // namespace alienyze
}  // namespace unpack
}  // namespace qiling
