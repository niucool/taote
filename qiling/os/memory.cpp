#include "qiling/os/memory.hpp"

#include <algorithm>
#include <cstdio>

namespace qiling {

// ---- QlMemoryManager ----

QlMemoryManager::QlMemoryManager(uc_engine& uc, const QlCoreStructs& structs, int bits, std::uint64_t pagesize)
    : uc_(&uc), structs_(&structs) {
    // memory.py bit_stuff: the addressable range per architecture word size
    const std::uint64_t bit_stuff[] = {
        0,                                       // (unused)
        (std::uint64_t{1} << 16) - 1,            // 16 bit placeholder (not used by qiling)
        (std::uint64_t{1} << 32) - 1,            // 32
        0,                                       // (unused)
        (std::uint64_t{1} << 64) - 1,            // 64
    };

    switch (bits) {
        case 64:
            max_mem_addr_ = (std::uint64_t{1} << 64) - 1;
            break;
        case 32:
            max_mem_addr_ = (std::uint64_t{1} << 32) - 1;
            break;
        case 16:
            // memory.py: 20bit address line
            max_mem_addr_ = (std::uint64_t{1} << 20) - 1;
            break;
        default:
            throw QlErrorStructConversion("Unsupported Qiling architecture for memory manager");
    }
    (void)bit_stuff;

    // make sure pagesize is a power of 2 (memory.py, verbatim assertion)
    if (pagesize == 0 || (pagesize & (pagesize - 1)) != 0) {
        throw QlErrorBase("pagesize has to be a power of 2");
    }
    pagesize_ = pagesize;
    pointersize_ = bits / 8;
}

void QlMemoryManager::add_mapinfo(std::uint64_t mem_s, std::uint64_t mem_e, int mem_p, std::string mem_info,
                                  QlMmioHandler* mmio_ctx) {
    // bisect.insort: keep map_info sorted by (begin, end, ...)
    MapInfoEntry entry{mem_s, mem_e, mem_p, std::move(mem_info), mmio_ctx};
    const auto it = std::lower_bound(map_info_.begin(), map_info_.end(), entry,
                                     [](const MapInfoEntry& a, const MapInfoEntry& b) {
                                         return a.begin < b.begin || (a.begin == b.begin && a.end < b.end);
                                     });
    map_info_.insert(it, std::move(entry));
}

void QlMemoryManager::del_mapinfo(std::uint64_t mem_s, std::uint64_t mem_e) {
    // memory.py del_mapinfo: split every overlapping range around the deleted one
    std::vector<std::size_t> overlap;
    for (std::size_t idx = 0; idx < map_info_.size(); ++idx) {
        const auto& [lbound, ubound, _, __, ___] = map_info_[idx];
        if ((mem_s < ubound) && (mem_e > lbound)) {
            overlap.push_back(idx);
        }
    }
    if (overlap.empty()) {
        return;
    }

    // create new entries by splitting the overlapping ranges; done before the
    // removal (memory.py, verbatim note)
    std::vector<MapInfoEntry> new_entries;
    for (const auto idx : overlap) {
        const auto& [lbound, ubound, perms, label, mmio_ctx] = map_info_[idx];
        if (lbound < mem_s) {
            new_entries.push_back(MapInfoEntry{lbound, mem_s, perms, label, mmio_ctx});
        }
        if (mem_e < ubound) {
            new_entries.push_back(MapInfoEntry{mem_e, ubound, perms, label, mmio_ctx});
        }
    }

    // remove the overlapping entries (they are consecutive; map_info is sorted)
    const std::size_t i0 = overlap.front();
    const std::size_t i1 = overlap.back();
    map_info_.erase(map_info_.begin() + static_cast<std::ptrdiff_t>(i0), map_info_.begin() + static_cast<std::ptrdiff_t>(i1) + 1);

    // add the new ones
    for (auto& entry : new_entries) {
        add_mapinfo(entry.begin, entry.end, entry.perms, std::move(entry.label), entry.mmio_ctx);
    }
}

void QlMemoryManager::change_mapinfo(std::uint64_t mem_s, std::uint64_t mem_e, std::optional<int> new_perms,
                                     std::optional<std::string> new_info) {
    if (!new_perms.has_value() && !new_info.has_value()) {
        // nothing to do
        return;
    }

    // locate the map info entry to change
    const auto it = std::find_if(map_info_.begin(), map_info_.end(), [mem_s, mem_e](const MapInfoEntry& entry) {
        return mem_s >= entry.begin && mem_e <= entry.end;
    });
    if (it == map_info_.end()) {
        // memory.py logs the error and returns; the C++ port degrades the same way
        return;
    }

    const auto [lbound, ubound, _, label, mmio_ctx] = *it;
    int perms = it->perms;
    std::string info = it->label;

    if (new_perms.has_value()) perms = *new_perms;
    if (new_info.has_value()) info = *new_info;

    del_mapinfo(mem_s, mem_e);
    add_mapinfo(lbound, ubound, perms, std::move(info), mmio_ctx);
}

std::vector<std::tuple<std::uint64_t, std::uint64_t, std::string, std::string, std::string>>
QlMemoryManager::get_mapinfo() const {
    // (lbound, ubound, perms, label, container) — the container lookup (the
    // loader's find_containing_image) lands with the Phase 3 facade
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::string, std::string, std::string>> out;
    out.reserve(map_info_.size());

    for (const auto& entry : map_info_) {
        // python: 'r' if perms & UC_PROT_READ else '-', likewise w/x — always
        // three characters
        std::string perms;
        perms += (entry.perms & UC_PROT_READ) ? 'r' : '-';
        perms += (entry.perms & UC_PROT_WRITE) ? 'w' : '-';
        perms += (entry.perms & UC_PROT_EXEC) ? 'x' : '-';
        out.emplace_back(entry.begin, entry.end, std::move(perms), entry.label, std::string());
    }
    return out;
}

std::vector<std::string> QlMemoryManager::get_formatted_mapinfo() const {
    const auto mapinfo = get_mapinfo();

    // determine the column widths based on the longest value per field
    std::size_t len_addr = 1;
    std::size_t len_label = 1;
    for (const auto& [lbound, ubound, _, label, _2] : mapinfo) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx", ubound);
        len_addr = std::max(len_addr, std::strlen(buf));
        len_label = std::max(len_label, label.size());
    }

    std::vector<std::string> table;
    table.reserve(mapinfo.size() + 1);

    // title row
    {
        std::string title = "Start";
        title.append(len_addr - title.size(), ' ');
        title += "   End";
        title.append(len_addr - 3, ' ');
        title += "   Perm  Label";
        title.append(len_label - 5 > 0 ? len_label - 5 : 0, ' ');
        title += "   Image";
        table.push_back(std::move(title));
    }

    for (const auto& [lbound, ubound, perms, label, container] : mapinfo) {
        char row[512];
        std::snprintf(row, sizeof(row), "%0*llx - %0*llx   %-5s   %s   %s", static_cast<int>(len_addr),
                      static_cast<unsigned long long>(lbound), static_cast<int>(len_addr),
                      static_cast<unsigned long long>(ubound), perms.c_str(), label.c_str(), container.c_str());
        table.emplace_back(row);
    }
    return table;
}

std::optional<std::uint64_t> QlMemoryManager::get_lib_base(std::string_view filename) const {
    // capture boxed label prefixes (memory.py regex ^\[.+\]\s*)
    for (const auto& [lbound, _, __, info, ___] : map_info_) {
        std::string_view stripped = info;
        if (!stripped.empty() && stripped.front() == '[') {
            const auto close = stripped.find(']');
            if (close != std::string_view::npos) {
                stripped.remove_prefix(close + 1);
                while (!stripped.empty() && (stripped.front() == ' ' || stripped.front() == '\t')) stripped.remove_prefix(1);
            }
        }
        // os.path.basename(info) == filename
        const auto base = stripped.find_last_of("/\\");
        const std::string_view basename = (base == std::string_view::npos) ? stripped : stripped.substr(base + 1);
        if (basename == filename) {
            return lbound;
        }
    }
    return std::nullopt;
}

std::uint64_t QlMemoryManager::align(std::uint64_t value, std::optional<std::uint64_t> alignment) const {
    const std::uint64_t a = alignment.value_or(pagesize_);
    // round down to the nearest alignment
    return value & ~(a - 1);
}

std::uint64_t QlMemoryManager::align_up(std::uint64_t value, std::optional<std::uint64_t> alignment) const {
    const std::uint64_t a = alignment.value_or(pagesize_);
    // round up to the nearest alignment
    return (value + a - 1) & ~(a - 1);
}

std::vector<std::uint8_t> QlMemoryManager::read(std::uint64_t addr, std::uint64_t size) const {
    std::vector<std::uint8_t> out(static_cast<std::size_t>(size));
    if (size != 0) {
        const uc_err err = uc_mem_read(uc_, addr, out.data(), size);
        if (err != UC_ERR_OK) {
            throw QlErrorBase("failed to read memory (uc_err " + std::to_string(static_cast<int>(err)) + ") at 0x" + [&] { char b[32]; std::snprintf(b, sizeof(b), "%llx", (unsigned long long)addr); return std::string(b); }());
        }
    }
    return out;
}

void QlMemoryManager::write(std::uint64_t addr, const std::vector<std::uint8_t>& data) {
    const uc_err err = uc_mem_write(uc_, addr, data.data(), data.size());
    if (err != UC_ERR_OK) {
        // the address and size belong in the message: "failed to write memory
        // (uc_err 7)" alone cannot be acted on (the read path already reports
        // its address), and a handler bug is exactly what it usually is
        char where[80];
        std::snprintf(where, sizeof(where), " at 0x%llx (%zu bytes)",
                      static_cast<unsigned long long>(addr), data.size());
        throw QlErrorBase("failed to write memory (uc_err " +
                          std::to_string(static_cast<int>(err)) + where + ")");
    }
}

std::int64_t QlMemoryManager::read_ptr(std::uint64_t addr, std::uint64_t size, bool signed_) const {
    if (size == 0) {
        // memory.py: size = self.ql.arch.pointersize (== bits // 8)
        size = static_cast<std::uint64_t>(pointersize_);
    }

    auto data = read(addr, size);
    const std::string_view view{reinterpret_cast<const char*>(data.data()), data.size()};

    if (size == 1) return signed_ ? structs_->unpack8s(view) : static_cast<std::int64_t>(structs_->unpack8(view));
    if (size == 2) return signed_ ? structs_->unpack16s(view) : static_cast<std::int64_t>(structs_->unpack16(view));
    if (size == 4) return signed_ ? structs_->unpack32s(view) : static_cast<std::int64_t>(structs_->unpack32(view));
    if (size == 8) return structs_->unpack64s(view);

    throw QlErrorStructConversion("Unsupported pointer size: " + std::to_string(size));
}

void QlMemoryManager::write_ptr(std::uint64_t addr, std::int64_t value, std::uint64_t size, bool signed_) {
    if (size == 0) {
        size = static_cast<std::uint64_t>(pointersize_);
    }

    std::string packed;
    if (size == 1) packed = signed_ ? structs_->pack8s(static_cast<std::int64_t>(value) & 0xff) : structs_->pack8(value & 0xff);
    else if (size == 2) packed = signed_ ? structs_->pack16s(static_cast<std::int64_t>(value)) : structs_->pack16(static_cast<std::uint16_t>(value));
    else if (size == 4) packed = signed_ ? structs_->pack32s(static_cast<std::int32_t>(static_cast<std::uint32_t>(value))) : structs_->pack32(static_cast<std::uint32_t>(value));
    else if (size == 8) packed = signed_ ? structs_->pack64s(static_cast<std::int64_t>(value)) : structs_->pack64(value);
    else throw QlErrorStructConversion("Unsupported pointer size: " + std::to_string(size));

    write(addr, packed);
}

std::optional<std::string> QlMemoryManager::string(std::uint64_t addr, std::optional<std::string_view> value,
                                                   const char* encoding) {
    (void)encoding;  // the guest path is byte-oriented; the encoding parameter is
                     // carried for API parity (latin1 read = raw bytes)

    if (!value.has_value()) {
        std::string ret;
        auto c = read(addr, 1);
        while (!c.empty() && c[0] != 0) {
            ret.push_back(static_cast<char>(c[0]));
            ++addr;
            c = read(addr, 1);
        }
        return ret;
    }

    std::vector<std::uint8_t> data(value->begin(), value->end());
    data.push_back(0);
    write(addr, data);
    return std::nullopt;
}

void QlMemoryManager::map(std::uint64_t addr, std::uint64_t size, int perms, std::optional<std::string> info) {
    if (!is_available(addr, size)) {
        throw QlMemoryMappedError("Requested memory is unavailable");
    }

    const uc_err err = uc_mem_map(uc_, addr, size, perms);
    if (err != UC_ERR_OK) {
        throw QlMemoryMappedError("failed to map memory (uc_err " + std::to_string(static_cast<int>(err)) + ")");
    }
    add_mapinfo(addr, addr + size, perms, info.value_or("[mapped]"), nullptr);
}

void QlMemoryManager::map_mmio(std::uint64_t addr, std::uint64_t size, QlMmioHandler& handler, std::string info) {
    int prot = UC_PROT_NONE;
    if (handler.has_read()) prot |= UC_PROT_READ;
    if (handler.has_write()) prot |= UC_PROT_WRITE;

    // the generic mmio wrappers forward to the handler through the trampoline
    // context (the handler object + the manager for the ql-facing calls)
    struct MmioCtx {
        QlMemoryManager* self;
        QlMmioHandler* handler;
    };

    std::unique_ptr<void, void (*)(void*)> ctx{new MmioCtx{this, &handler}, [](void* p) {
                                                  delete static_cast<MmioCtx*>(p);
                                              }};

    // both callbacks are always registered; the range protections (derived
    // from the handler capabilities above) keep the unsupported operations
    // from being reached (memory.py passes the bound methods the same way)
    const uc_err err = uc_mmio_map(
        uc_, addr, size,
        [](uc_engine* uc, std::uint64_t offset, unsigned size, void* user_data) -> std::uint64_t {
            (void)uc;
            auto* ctx = static_cast<MmioCtx*>(user_data);
            try {
                return ctx->handler->read(offset, size);
            } catch (...) {
                // an mmio handler exception follows the hookcallback
                // discipline: contained here, never unwinding into unicorn
                // (the wiring to the engine's internal-exception surface
                // lands with the Phase 3 facade)
                return 0;
            }
        },
        ctx.get(),
        [](uc_engine* uc, std::uint64_t offset, unsigned size, std::uint64_t value, void* user_data) {
            (void)uc;
            auto* ctx = static_cast<MmioCtx*>(user_data);
            try {
                ctx->handler->write(offset, size, value);
            } catch (...) {
                // see above
            }
        },
        ctx.get());

    if (err != UC_ERR_OK) {
        throw QlMemoryMappedError("failed to map mmio (uc_err " + std::to_string(static_cast<int>(err)) + ")");
    }

    mmio_contexts_.emplace_back(std::move(ctx));
    add_mapinfo(addr, addr + size, prot, std::move(info), &handler);
}

void QlMemoryManager::unmap(std::uint64_t addr, std::uint64_t size) {
    del_mapinfo(addr, addr + size);
    const uc_err err = uc_mem_unmap(uc_, addr, size);
    if (err != UC_ERR_OK) {
        throw QlErrorBase("failed to unmap memory (uc_err " + std::to_string(static_cast<int>(err)) + ")");
    }
}

void QlMemoryManager::unmap_between(std::uint64_t mem_s, std::uint64_t mem_e) {
    // unicorn's mem_unmap rejects ranges that span separate mappings, so the
    // requested range is split at the live region boundaries (uc_mem_regions)
    uc_mem_region* regions = nullptr;
    std::uint32_t count = 0;
    if (uc_mem_regions(uc_, &regions, &count) != UC_ERR_OK) {
        throw QlErrorBase("unmap_between: failed to query memory regions");
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint64_t begin = regions[i].begin;
        const std::uint64_t end = regions[i].end + 1;  // regions end is inclusive
        const std::uint64_t lo = std::max(begin, mem_s);
        const std::uint64_t hi = std::min(end, mem_e);
        if (lo < hi) {
            spans.emplace_back(lo, hi);
        }
    }
    uc_free(regions);

    for (const auto& [lbound, ubound] : spans) {
        unmap(lbound, ubound - lbound);
    }
}

void QlMemoryManager::unmap_all() {
    uc_mem_region* regions = nullptr;
    std::uint32_t count = 0;
    if (uc_mem_regions(uc_, &regions, &count) != UC_ERR_OK) {
        return;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        unmap(regions[i].begin, regions[i].end - regions[i].begin + 1);
    }
    uc_free(regions);
}

void QlMemoryManager::protect(std::uint64_t addr, std::uint64_t size, int perms) {
    // mask off the perms bits that are not supported by unicorn
    perms &= UC_PROT_ALL;

    const std::uint64_t aligned_address = align(addr);
    const std::uint64_t aligned_size = align_up((addr & (pagesize_ - 1)) + size);

    const uc_err err = uc_mem_protect(uc_, aligned_address, aligned_size, perms);
    if (err != UC_ERR_OK) {
        throw QlErrorBase("failed to protect memory (uc_err " + std::to_string(static_cast<int>(err)) + ")");
    }
    change_mapinfo(aligned_address, aligned_address + aligned_size, perms);
}

const MapInfoEntry* QlMemoryManager::region_at(std::uint64_t addr) const {
    for (const auto& entry : map_info_) {
        if (addr >= entry.begin && addr < entry.end) {
            return &entry;
        }
    }
    return nullptr;
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> QlMemoryManager::mapped_regions() const {
    // consolidate adjacent regions; protections and labels are ignored
    std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
    if (map_info_.empty()) {
        return out;
    }

    auto [p_lbound, p_ubound, _, __, ___] = map_info_.front();
    for (std::size_t i = 1; i < map_info_.size(); ++i) {
        const auto& [lbound, ubound, _, __, ___] = map_info_[i];
        if (lbound == p_ubound) {
            p_ubound = ubound;
        } else {
            out.emplace_back(p_lbound, p_ubound);
            p_lbound = lbound;
            p_ubound = ubound;
        }
    }
    out.emplace_back(p_lbound, p_ubound);
    return out;
}

bool QlMemoryManager::is_available(std::uint64_t addr, std::uint64_t size) const {
    const std::uint64_t begin = addr;
    const std::uint64_t end = addr + size;

    const auto regions = mapped_regions();
    return !std::any_of(regions.begin(), regions.end(), [begin, end](const auto& r) {
        const auto& [lbound, ubound] = r;
        return (lbound <= begin && begin < ubound) || (lbound < end && end <= ubound) ||
               (begin <= lbound && lbound < ubound && ubound <= end);
    });
}

bool QlMemoryManager::is_mapped(std::uint64_t addr, std::uint64_t size) const {
    const std::uint64_t begin = addr;
    const std::uint64_t end = addr + size;

    const auto regions = mapped_regions();
    return std::any_of(regions.begin(), regions.end(), [begin, end](const auto& r) {
        const auto& [lbound, ubound] = r;
        return (lbound <= begin && begin < end && end <= ubound);
    });
}

std::uint64_t QlMemoryManager::find_free_space(std::uint64_t size, std::optional<std::uint64_t> minaddr_in,
                                               std::optional<std::uint64_t> maxaddr_in,
                                               std::optional<std::uint64_t> alignment) const {
    const std::uint64_t align_value = alignment.value_or(pagesize_);

    // memory space bounds (exclusive); the 64-bit upper bound saturates
    // (2^64 is not representable, and Python bignums do not apply here)
    std::uint64_t mem_lbound = 0;
    std::uint64_t mem_ubound = (max_mem_addr_ == ~std::uint64_t{0}) ? ~std::uint64_t{0} : max_mem_addr_ + 1;

    const std::uint64_t minaddr = minaddr_in.value_or(mem_lbound);
    const std::uint64_t maxaddr = maxaddr_in.value_or(mem_ubound);

    if (minaddr >= maxaddr) {
        throw QlErrorBase("assertion: minaddr < maxaddr");
    }
    if ((maxaddr - minaddr) < size) {
        throw QlOutOfMemory("Search range is smaller than size");
    }

    // gap ranges between the mapped ones and the memory bounds
    std::vector<std::pair<std::uint64_t, std::uint64_t>> gaps;
    gaps.emplace_back(mem_lbound, map_info_.empty() ? mem_ubound : map_info_.front().begin);
    for (std::size_t i = 0; i < map_info_.size(); ++i) {
        const std::uint64_t ubound = map_info_[i].end;
        const std::uint64_t lbound = (i + 1 < map_info_.size()) ? map_info_[i + 1].begin : mem_ubound;
        gaps.emplace_back(ubound, lbound);
    }

    for (const auto& [lbound, ubound] : gaps) {
        if (!(lbound < maxaddr && minaddr < ubound)) {
            continue;
        }
        const std::uint64_t addr = align_up(std::max(minaddr, lbound), align_value);
        const std::uint64_t end = addr + size;

        if ((lbound <= addr && addr < end && end <= ubound) && (minaddr <= addr && addr < end && end <= maxaddr)) {
            return addr;
        }
    }

    throw QlOutOfMemory("Out Of Memory");
}

std::uint64_t QlMemoryManager::map_anywhere(std::uint64_t size, std::optional<std::uint64_t> minaddr,
                                            std::optional<std::uint64_t> maxaddr, std::optional<std::uint64_t> alignment,
                                            int perms, std::optional<std::string> info) {
    const std::uint64_t aligned = align_up(size, alignment);
    const std::uint64_t addr = find_free_space(aligned, minaddr, maxaddr, alignment);
    map(addr, aligned, perms, std::move(info));
    return addr;
}

std::vector<std::uint64_t> QlMemoryManager::search(const std::vector<std::uint8_t>& needle,
                                                   std::optional<std::uint64_t> begin_in,
                                                   std::optional<std::uint64_t> end_in) const {
    if (map_info_.empty()) {
        return {};
    }

    const std::uint64_t begin = begin_in.value_or(map_info_.front().begin);
    const std::uint64_t end = end_in.value_or(map_info_.back().end);

    std::vector<std::uint64_t> results;
    for (const auto& [lbound, ubound, _, __, mmio_ctx] : map_info_) {
        if (end < lbound || ubound < begin || mmio_ctx != nullptr) {
            continue;  // outside the search range, or an mmio range (side effects)
        }
        const std::uint64_t lo = std::max(begin, lbound);
        const std::uint64_t hi = std::min(end, ubound);

        const auto haystack = read(lo, hi - lo);
        for (auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
             it != haystack.end();
             it = std::search(it + 1, haystack.end(), needle.begin(), needle.end())) {
            results.push_back(static_cast<std::uint64_t>(it - haystack.begin()) + lo);
        }
    }
    return results;
}

SavedMemory QlMemoryManager::save() const {
    SavedMemory out;
    for (const auto& entry : map_info_) {
        SavedMemoryRange range;
        range.begin = entry.begin;
        range.end = entry.end;
        range.perms = entry.perms;
        range.label = entry.label;

        if (entry.mmio_ctx == nullptr) {
            range.data = read(entry.begin, entry.end - entry.begin);
            out.ram.push_back(std::move(range));
        } else {
            range.mmio_ctx = entry.mmio_ctx;
            out.mmio.push_back(std::move(range));
        }
    }
    return out;
}

void QlMemoryManager::restore(const SavedMemory& saved_state) {
    for (const auto& range : saved_state.ram) {
        const std::uint64_t size = range.end - range.begin;
        if (is_available(range.begin, size)) {
            map(range.begin, size, range.perms, range.label);
        }
        write(range.begin, range.data);
    }

    for (const auto& range : saved_state.mmio) {
        const std::uint64_t size = range.end - range.begin;
        if (!is_mapped(range.begin, size) && range.mmio_ctx != nullptr) {
            // memory.py re-uses the stored handler object to re-map the range
            map_mmio(range.begin, size, *range.mmio_ctx, range.label);
        }
    }
}

// ---- QlMemoryHeap (memory.py) ----

QlMemoryHeap::QlMemoryHeap(QlMemoryManager& mem, std::uint64_t start_address, std::uint64_t end_address)
    : mem_(&mem), start_address_(start_address), end_address_(end_address) {}

std::uint64_t QlMemoryHeap::alloc(std::uint64_t size) {
    // attempt to recycle an existing unused chunk first: locate the smallest
    // available chunk that has enough room
    const Chunk* found = nullptr;
    for (const auto& chunk : chunks_) {
        if (!chunk.inuse && chunk.size >= size && (found == nullptr || chunk.size < found->size)) {
            found = &chunk;
        }
    }

    if (found == nullptr) {
        // is a new chunk going to exceed the currently allocated heap space?
        // in that case, allocate additional heap space
        if (current_use_ + size > current_alloc_) {
            const std::uint64_t real_size = mem_->align_up(size);

            // if that additional allocation is going to exceed the heap upper
            // bound, fail
            if (start_address_ + current_use_ + real_size > end_address_) {
                return 0;
            }

            mem_->map(start_address_ + current_alloc_, real_size, UC_PROT_ALL, "[heap]");
            mem_alloc_.emplace_back(start_address_ + current_alloc_, real_size);
            current_alloc_ += real_size;
        }

        Chunk chunk;
        chunk.address = start_address_ + current_use_;
        chunk.size = size;
        chunks_.push_back(chunk);
        current_use_ += size;
        return chunk.address;
    }

    // recycle: mark the located chunk in use
    for (auto& chunk : chunks_) {
        if (&chunk == found) {
            chunk.inuse = true;
            return chunk.address;
        }
    }
    return 0;
}

bool QlMemoryHeap::free(std::uint64_t addr) {
    Chunk* chunk = find(addr, true);
    if (chunk == nullptr) {
        return false;
    }
    chunk->inuse = false;
    return true;
}

const QlMemoryHeap::Chunk* QlMemoryHeap::find_chunk(std::uint64_t addr) const {
    // heapapi hook_HeapValidate rides the raw _find (the inuse flag is read
    // by the caller)
    return find(addr);
}

std::uint64_t QlMemoryHeap::size(std::uint64_t addr) const {
    const Chunk* chunk = find(addr, true);
    return chunk != nullptr ? chunk->size : 0;
}

void QlMemoryHeap::clear() {
    chunks_.clear();

    for (const auto& [addr, size] : mem_alloc_) {
        mem_->unmap(addr, size);
    }
    mem_alloc_.clear();

    current_alloc_ = 0;
    current_use_ = 0;
}

const QlMemoryHeap::Chunk* QlMemoryHeap::find(std::uint64_t addr, std::optional<bool> inuse) const {
    for (const auto& chunk : chunks_) {
        if (addr == chunk.address && (!inuse.has_value() || chunk.inuse == *inuse)) {
            return &chunk;
        }
    }
    return nullptr;
}

QlMemoryHeap::Chunk* QlMemoryHeap::find(std::uint64_t addr, std::optional<bool> inuse) {
    for (auto& chunk : chunks_) {
        if (addr == chunk.address && (!inuse.has_value() || chunk.inuse == *inuse)) {
            return &chunk;
        }
    }
    return nullptr;
}

QlMemoryHeap::SavedState QlMemoryHeap::save() const {
    SavedState state;
    state.chunks = chunks_;
    state.start_address = start_address_;
    state.end_address = end_address_;
    state.current_alloc = current_alloc_;
    state.current_use = current_use_;
    state.mem_alloc = mem_alloc_;
    return state;
}

void QlMemoryHeap::restore(const SavedState& state) {
    chunks_ = state.chunks;
    start_address_ = state.start_address;
    end_address_ = state.end_address;
    current_alloc_ = state.current_alloc;
    current_use_ = state.current_use;
    mem_alloc_ = state.mem_alloc;
}

}  // namespace qiling
