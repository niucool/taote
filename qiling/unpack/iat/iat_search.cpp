#include "qiling/unpack/iat/iat_search.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <set>

namespace qiling {
namespace unpack {
namespace iat {

namespace {

std::string lower_ascii(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string sanitize_ascii(std::string s) {
    for (auto& c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7e) {
            c = '.';
        }
    }
    return s;
}

std::uint64_t read_le(const std::vector<std::uint8_t>& v, std::size_t o, int n) {
    std::uint64_t r = 0;
    for (int i = n - 1; i >= 0; --i) {
        if (o + static_cast<std::size_t>(i) >= v.size()) {
            return 0;
        }
        r = (r << 8) | v[o + static_cast<std::size_t>(i)];
    }
    return r;
}

std::string read_cstr(const std::vector<std::uint8_t>& v, std::size_t o, std::size_t limit = 128) {
    std::string s;
    while (o < v.size() && v[o] != 0 && s.size() < limit) {
        const auto ch = v[o++];
        s.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<char>(ch) : '.');
    }
    return s;
}

}  // namespace

void SymbolMap::add(std::uint64_t address, std::string dll, std::string name) {
    if (address == 0 || name.empty() || dll.empty()) {
        return;
    }
    map_.emplace(address, std::make_pair(lower_ascii(std::move(dll)), sanitize_ascii(std::move(name))));
}

const std::pair<std::string, std::string>* SymbolMap::find(std::uint64_t address) const {
    const auto it = map_.find(address);
    return it == map_.end() ? nullptr : &it->second;
}

void IatScanner::scan(const std::vector<std::uint8_t>& bytes, std::uint64_t va) {
    if (ptr_ == 0) {
        return;
    }
    for (std::size_t o = 0; o + ptr_ <= bytes.size(); o += ptr_) {
        std::uint64_t v = 0;
        for (unsigned k = 0; k < ptr_; ++k) {
            v |= static_cast<std::uint64_t>(bytes[o + k]) << (8 * k);
        }
        if (v < 0x10000) {
            continue;  // the null page / the FS scratch: never an import
        }
        const auto* hit = symbols_.find(v);
        if (hit == nullptr) {
            continue;
        }
        hits_.push_back(ImportHit{va + o, hit->first, hit->second});
    }
}

std::vector<ImportHit> IatScanner::coherent() const {
    if (hits_.empty()) {
        return {};
    }
    if (hits_.size() <= scattered_threshold) {
        // scattered table (the stub rebuilt it): the values are authoritative
        return hits_;
    }
    // runs of >= 2 pointer-spaced slots of the same dll, then anchored singletons
    std::set<std::size_t> kept;
    for (std::size_t i = 0; i < hits_.size();) {
        std::size_t j = i + 1;
        while (j < hits_.size() && hits_[j].va == hits_[j - 1].va + ptr_ && hits_[j].dll == hits_[j - 1].dll) {
            ++j;
        }
        if (j - i >= 2) {
            for (std::size_t k = i; k < j; ++k) {
                kept.insert(k);
            }
        }
        i = j;
    }
    for (std::size_t i = 0; i < hits_.size(); ++i) {
        if (kept.count(i) != 0) {
            continue;
        }
        for (std::size_t k = 0; k < hits_.size(); ++k) {
            if (kept.count(k) == 0) {
                continue;
            }
            const auto a = hits_[i].va;
            const auto b = hits_[k].va;
            const auto d = a > b ? a - b : b - a;
            if (d <= 2 * ptr_ && hits_[i].dll == hits_[k].dll) {
                kept.insert(i);
                break;
            }
        }
    }
    std::vector<ImportHit> out;
    out.reserve(kept.size());
    for (const auto idx : kept) {
        out.push_back(hits_[idx]);
    }
    return out;
}

DescriptorWalk walk_import_descriptors(const std::vector<std::uint8_t>& image, std::uint64_t /*base*/,
                                       const std::vector<std::uint32_t>& start_rvas) {
    DescriptorWalk out;
    if (image.size() < 0x200) {
        return out;
    }
    const auto lfanew = static_cast<std::size_t>(read_le(image, 0x3c, 4));
    if (lfanew + 0x40 > image.size() || image[lfanew] != 'P' || image[lfanew + 1] != 'E') {
        return out;
    }
    const auto opt = lfanew + 24;
    const auto magic = read_le(image, opt, 2);
    const bool is64 = magic == 0x20b;
    if (!(magic == 0x10b || magic == 0x20b)) {
        return out;
    }
    const auto opt_size = read_le(image, lfanew + 20, 2);
    const auto n_rva = read_le(image, opt + (is64 ? 0x6c : 0x5c), 4);
    std::size_t dd = 0;
    if (n_rva != 16 || opt_size < (is64 ? 0xF0u : 0xE0u)) {
        dd = opt + (is64 ? 0x70 : 0x60);
    } else {
        dd = opt + static_cast<std::size_t>(opt_size) - 8 * static_cast<std::size_t>(n_rva);
    }

    std::vector<std::uint32_t> starts = start_rvas;
    const auto header_rva = static_cast<std::uint32_t>(read_le(image, dd + 8, 4));
    if (header_rva != 0) {
        starts.push_back(header_rva);
    }
    if (starts.empty()) {
        return out;
    }

    const unsigned ptr = is64 ? 8 : 4;
    const auto flag = is64 ? 0x8000000000000000ull : 0x80000000ull;
    for (const auto imp_rva : starts) {
        if (imp_rva == 0 || static_cast<std::size_t>(imp_rva) >= image.size()) {
            continue;
        }
        std::size_t found = 0;
        for (std::size_t i = 0; i < 512; ++i) {
            const auto off = static_cast<std::size_t>(imp_rva) + i * 20;
            if (off + 20 > image.size()) {
                break;
            }
            const auto oft = read_le(image, off, 4);
            const auto name_rva = read_le(image, off + 12, 4);
            const auto ft = read_le(image, off + 16, 4);
            if (name_rva == 0 || (oft == 0 && ft == 0)) {
                break;  // the null descriptor (or a malformed one)
            }
            const auto dll = read_cstr(image, static_cast<std::size_t>(name_rva));
            if (dll.empty()) {
                continue;
            }
            ++found;
            std::string dll_key = sanitize_ascii(dll);
            std::transform(dll_key.begin(), dll_key.end(), dll_key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            out.iat_rva_by_dll[dll_key] = ft != 0 ? ft : oft;  // the IAT the code calls through
            const auto thunk_rva = oft != 0 ? oft : ft;
            for (std::size_t k = 0; k < 4096; ++k) {
                const auto toff = static_cast<std::size_t>(thunk_rva) + k * ptr;
                if (toff + ptr > image.size()) {
                    break;
                }
                const auto thunk = read_le(image, toff, ptr);
                if (thunk == 0) {
                    break;
                }
                if ((thunk & flag) != 0) {
                    out.imports.emplace_back(sanitize_ascii(dll), "ordinal_" + std::to_string(thunk & 0xffff));
                    continue;
                }
                const auto fn = read_cstr(image, static_cast<std::size_t>(thunk) + 2);  // skip the hint
                if (!fn.empty()) {
                    out.imports.emplace_back(sanitize_ascii(dll), fn);
                }
            }
        }
        if (found != 0) {
            out.descriptor_rva = imp_rva;
            out.descriptors = found;
            return out;
        }
    }
    return out;
}

}  // namespace iat
}  // namespace unpack
}  // namespace qiling
