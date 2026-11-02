// qiling/unpack/packers/alienyze_names.hpp — the Alienyze store's name band.
//
// PLAN_UNPACK.md §11 (ported from pegasus b3e412a8). On the decoy-box class the
// stub materializes the payload's whole import-name store in the image as
// PE HintName records ([hint16][name]\0 runs) and then XORs the region in place,
// so the terminal image carries the vocabulary under a per-sample key (KillPot
// 0x0b, Cacheset 0x8d, WinList 0x5b, ...). The store's DLL tokens trail the name
// groups in group order, which is what attributes a name to its DLL without any
// descriptor (the "forward-greedy cut": each name binds the first token at or
// after a monotone cursor that actually exports it).
#ifndef QILING_UNPACK_PACKERS_ALIENYZE_NAMES_HPP
#define QILING_UNPACK_PACKERS_ALIENYZE_NAMES_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace qiling {
namespace unpack {
namespace alienyze {

struct MinedNames {
    std::uint8_t key = 0;    // the auto-detected band XOR byte (0 = none found)
    int key_hits = 0;        // how many transformed ".dll\0" tokens the key matched
    std::vector<std::pair<std::string, std::string>> pairs;  // (dll, name)
};

// Mines the (byte ^ key) name band out of `img`. `dll_is_known` decides whether a
// token stem may own a name (the api_db check in the library, injected so the
// module stays testable).
MinedNames mine_name_band(const std::uint8_t* img, std::size_t n,
                          std::vector<std::string> (*owner_lookup)(const std::string&));

}  // namespace alienyze
}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_PACKERS_ALIENYZE_NAMES_HPP
