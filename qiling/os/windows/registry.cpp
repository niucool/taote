// Ported from qiling/os/windows/registry.py — see the header note. The nlohmann
// json backing replaces the stdlib json module; the RegConf accessors keep the
// upstream semantics (the conf-first read precedence lives in RegistryManager).
#include "qiling/os/windows/registry.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace os {

// const.py REG_TYPES (the value side: the numeric id -> the canonical name)
const char* reg_type_name(int reg_type) {
    switch (static_cast<RegType>(reg_type)) {
        case RegType::RegNone: return "REG_NONE";
        case RegType::RegSZ: return "REG_SZ";
        case RegType::RegExpandSZ: return "REG_EXPAND_SZ";
        case RegType::RegBin: return "REG_BINARY";
        case RegType::RegDWord: return "REG_DWORD";
        case RegType::RegBigEndian: return "REG_DWORD_BIG_ENDIAN";
        case RegType::RegLink: return "REG_LINK";
        case RegType::RegMultiSZ: return "REG_MULTI_SZ";
        case RegType::RegResourceList: return "REG_RESOURCE_LIST";
        case RegType::RegFullResourceDescriptor: return "REG_FULL_RESOURCE_DESCRIPTOR";
        case RegType::RegResourceRequirementsList: return "REG_RESOURCE_REQUIREMENTS_LIST";
        case RegType::RegQWord: return "REG_QWORD";
    }
    return "REG_UNKNOWN";
}

namespace registry {

namespace {

nlohmann::json reg_value_to_json(const RegValue& value) {
    if (const auto* s = std::get_if<std::string>(&value)) {
        return *s;
    }
    if (const auto* n = std::get_if<std::int64_t>(&value)) {
        return *n;
    }
    if (const auto* b = std::get_if<std::vector<std::uint8_t>>(&value)) {
        // the bytes values encode as a hex string (json has no bytes type)
        std::ostringstream out;
        out << std::hex;
        for (const auto byte : *b) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02x", byte);
            out << buf;
        }
        return out.str();
    }
    return nullptr;
}

RegValue reg_value_from_json(const nlohmann::json& node) {
    if (node.is_number_integer()) {
        return static_cast<std::int64_t>(node.get<long long>());
    }
    if (node.is_string()) {
        return node.get<std::string>();
    }
    return std::monostate{};
}

}  // namespace

// ---- RegConf ----

RegConf::RegConf(std::string fname) : fname_(std::move(fname)) {
    std::ifstream in(fname_);
    if (!in) {
        return;  // registry.py: IOError -> an empty conf
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    const auto text = buffer.str();
    if (text.empty()) {
        return;  // registry.py: json.loads(data or '{}')
    }

    try {
        const auto root = nlohmann::json::parse(text);
        for (auto it = root.begin(); it != root.end(); ++it) {
            const auto& subkeys = it.value();
            for (auto sub = subkeys.begin(); sub != subkeys.end(); ++sub) {
                const auto& item = sub.value();
                const auto type = item.at("type").get<int>();
                const auto value = reg_value_from_json(item.at("value"));
                conf_[it.key()][sub.key()] = {type, value};
            }
        }
    } catch (const nlohmann::json::parse_error&) {
        throw QlErrorJsonDecode("Windows registry JSON decode error");
    }
}

bool RegConf::exists(std::string_view key) const {
    return conf_.find(std::string(key)) != conf_.end();
}

void RegConf::create(std::string_view key) {
    if (!exists(key)) {
        conf_[std::string(key)] = {};
    }
}

void RegConf::delete_entry(std::string_view key, std::string_view subkey) {
    if (exists(key)) {
        conf_[std::string(key)].erase(std::string(subkey));
    }
}

std::pair<std::optional<int>, std::optional<RegValue>> RegConf::read(std::string_view key, std::string_view subkey,
                                                                     int reg_type) const {
    const auto kit = conf_.find(std::string(key));
    if (kit == conf_.end()) {
        return {std::nullopt, std::nullopt};
    }
    const auto sit = kit->second.find(std::string(subkey));
    if (sit == kit->second.end()) {
        return {std::nullopt, std::nullopt};
    }
    const auto& [item_type, item_value] = sit->second;
    if (reg_type < 0 || static_cast<RegType>(reg_type) != static_cast<RegType>(item_type)) {
        // registry.py: any recorded type is returned as-is (the caller filters);
        // the unknown names raise
        (void)reg_type;
    }
    return {item_type, item_value};
}

void RegConf::write(std::string_view key, std::string_view subkey, int reg_type, RegValue data) {
    if (!exists(key)) {
        create(key);
    }
    conf_[std::string(key)][std::string(subkey)] = {reg_type, std::move(data)};
}

void RegConf::save(std::string_view fname) const {
    if (conf_.empty()) {
        return;  // registry.py: only write when there is a diff
    }
    nlohmann::json root = nlohmann::json::object();
    for (const auto& [key, subkeys] : conf_) {
        for (const auto& [subkey, entry] : subkeys) {
            root[key][subkey] = {
                {"type", entry.first},
                {"value", reg_value_to_json(entry.second)},
            };
        }
    }
    std::ofstream out(std::string(fname), std::ios::binary);
    out << root.dump(4);
}

// ---- RegHive (the hive parsing defers; the no-op mutations are verbatim) ----

// ---- RegHive: the regf reader ----
//
// The on-disk registry hive (the python-registry surface upstream rides):
//   * a 0x1000 base block, "regf" at 0, the root key cell offset at 0x24
//     (relative to the hbins area that starts at 0x1000);
//   * hbins of page-multiple size, "hbin" at 0, cells inside them;
//   * a cell is a signed size followed by its payload - negative means
//     allocated, and "nk"/"vk"/"lf"/"lh"/"li" name the payload kinds;
//   * "nk" holds the key's name, its subkey count + list offset and its value
//     count + list offset; a subkey/value offset is *cell-relative* to the
//     hbins start;
//   * "vk" holds a value's name, its data size (the high bit means the data
//     rides inline in the offset field), its data offset and its type.
// Everything here is read-only: a write goes to the RegConf diff first, so the
// hive file is never mutated (registry.py's RegHive.create is a no-op too).

namespace {

std::uint32_t rd32(const std::vector<std::uint8_t>& data, std::size_t off) {
    if (off + 4 > data.size()) {
        return 0;
    }
    return static_cast<std::uint32_t>(data[off]) | (static_cast<std::uint32_t>(data[off + 1]) << 8) |
           (static_cast<std::uint32_t>(data[off + 2]) << 16) | (static_cast<std::uint32_t>(data[off + 3]) << 24);
}

}  // namespace

bool RegHive::load_hive(std::string_view hive_name) const {
    std::filesystem::path path = hname_;
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        path /= std::filesystem::path(hive_name);
    }
    if (!std::filesystem::exists(path, ec) || ec) {
        data_.clear();
        loaded_hive_.assign(hive_name);
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    data_.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    loaded_hive_.assign(hive_name);

    // the base block has to say "regf" and carry a root cell inside the hbins
    if (data_.size() < 0x1000 || std::memcmp(data_.data(), "regf", 4) != 0) {
        data_.clear();
        return false;
    }
    root_off_ = rd32(data_, 0x24);
    if (root_off_ == 0 || 0x1000 + root_off_ >= data_.size()) {
        data_.clear();
        return false;
    }
    return true;
}

RegHive::RegHive(std::string_view hname) : hname_(std::string(hname)) {
    // a direct file loads now; the hive-directory shape loads lazily, per key
    std::error_code ec;
    if (std::filesystem::is_regular_file(hname_, ec) && !ec) {
        (void)load_hive("");
    }
}

std::size_t RegHive::cell_at(std::size_t rel_off) const {
    // the cell's payload starts 4 bytes into the cell (past the signed size)
    const auto abs = 0x1000 + rel_off;
    if (abs + 4 > data_.size()) {
        return std::string::npos;
    }
    return abs + 4;
}

std::string RegHive::key_name(std::size_t nk) const {
    if (nk == std::string::npos || nk + 0x4c > data_.size() || std::memcmp(data_.data() + nk, "nk", 2) != 0) {
        return {};
    }
    const auto name_len = static_cast<std::size_t>(rd32(data_, nk + 0x48));
    if (nk + 0x4c + name_len > data_.size()) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(data_.data() + nk + 0x4c), name_len);
}

std::vector<std::size_t> RegHive::subkeys(std::size_t nk) const {
    std::vector<std::size_t> out;
    if (nk == std::string::npos || nk + 0x2c > data_.size()) {
        return out;
    }
    const auto count = static_cast<std::size_t>(rd32(data_, nk + 0x14));
    const auto list_off = static_cast<std::size_t>(rd32(data_, nk + 0x1c));
    const auto list = cell_at(list_off);
    if (list == std::string::npos || list + 4 > data_.size()) {
        return out;
    }
    const auto sig = std::memcmp(data_.data() + list, "li", 2) == 0 ? "li" : "lf";
    const bool direct = std::memcmp(data_.data() + list, "li", 2) == 0;
    (void)sig;
    // lf/lh carry (offset, hash) pairs of 8 bytes; li carries bare offsets
    const std::size_t stride = direct ? 4 : 8;
    for (std::size_t i = 0; i < count; ++i) {
        const auto at = list + 4 + i * stride;
        if (at + 4 > data_.size()) {
            break;
        }
        out.push_back(static_cast<std::size_t>(rd32(data_, at)));
    }
    return out;
}

std::size_t RegHive::find_key(std::string_view key) const {
    // the guest key is the full path ("HKEY_LOCAL_MACHINE\SOFTWARE\...")
    std::string path(key);
    std::vector<std::string> parts;
    std::size_t start_at = 0;
    while (start_at <= path.size()) {
        const auto end = path.find('\\', start_at);
        parts.push_back(path.substr(start_at, end == std::string::npos ? std::string::npos : end - start_at));
        if (end == std::string::npos) {
            break;
        }
        start_at = end + 1;
    }

    // HKEY_LOCAL_MACHINE\SOFTWARE\... rides the SOFTWARE hive and
    // HKEY_CURRENT_USER rides NTUSER.DAT; anything else names its own hive
    std::string hive_name;
    std::size_t first_key_part = 1;
    const auto head = parts.empty() ? std::string() : parts[0];
    if ((head == "HKEY_LOCAL_MACHINE" || head == "HKEY_USERS") && parts.size() > 1) {
        hive_name = parts[1];
        first_key_part = 2;
    } else if (head == "HKEY_CURRENT_USER") {
        hive_name = "NTUSER.DAT";
        first_key_part = 1;
    } else {
        hive_name = head;
        first_key_part = 1;
    }

    if (hive_name != loaded_hive_ || data_.empty()) {
        if (!load_hive(hive_name) && data_.empty()) {
            return std::string::npos;
        }
    }

    std::string rest;
    for (std::size_t i = first_key_part; i < parts.size(); ++i) {
        if (!rest.empty()) {
            rest.push_back('\\');
        }
        rest += parts[i];
    }

    auto current = cell_at(root_off_);
    if (current == std::string::npos) {
        return std::string::npos;
    }

    std::size_t start = 0;
    while (start <= rest.size()) {
        const auto end = rest.find('\\', start);
        const auto component = rest.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!component.empty()) {
            std::size_t found = std::string::npos;
            for (const auto child : subkeys(current)) {
                const auto child_cell = cell_at(child);
                if (key_name(child_cell) == component) {
                    found = child_cell;
                    break;
                }
            }
            if (found == std::string::npos) {
                return std::string::npos;
            }
            current = found;
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return current;
}

std::size_t RegHive::find_value(std::size_t nk, std::string_view name) const {
    if (nk == std::string::npos || nk + 0x2c > data_.size()) {
        return std::string::npos;
    }
    const auto count = static_cast<std::size_t>(rd32(data_, nk + 0x24));
    const auto list_off = static_cast<std::size_t>(rd32(data_, nk + 0x28));
    const auto list = cell_at(list_off);
    if (list == std::string::npos) {
        return std::string::npos;
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto at = list + i * 4;
        if (at + 4 > data_.size()) {
            break;
        }
        const auto vk = cell_at(static_cast<std::size_t>(rd32(data_, at)));
        if (vk == std::string::npos || vk + 0x14 > data_.size() || std::memcmp(data_.data() + vk, "vk", 2) != 0) {
            continue;
        }
        const auto name_len = static_cast<std::size_t>(rd32(data_, vk + 2) & 0xffffu);
        if (vk + 0x14 + name_len > data_.size()) {
            continue;
        }
        const std::string value_name(reinterpret_cast<const char*>(data_.data() + vk + 0x14), name_len);
        if (value_name == name) {
            return vk;
        }
    }
    return std::string::npos;
}

bool RegHive::exists(std::string_view key) const {
    return find_key(key) != std::string::npos;
}

void RegHive::create(std::string_view) {}

void RegHive::delete_entry(std::string_view, std::string_view) {}

std::pair<std::optional<int>, std::optional<RegValue>> RegHive::read(std::string_view key, std::string_view subkey,
                                                                    int reg_type) const {
    (void)reg_type;
    const auto nk = find_key(key);
    const auto vk = find_value(nk, subkey);
    if (vk == std::string::npos) {
        return {std::nullopt, std::nullopt};
    }

    const auto type = static_cast<int>(rd32(data_, vk + 0x0c));
    const auto raw_size = rd32(data_, vk + 0x04);
    const bool inline_data = (raw_size & 0x80000000u) != 0;
    const auto size = static_cast<std::size_t>(raw_size & 0x7fffffffu);
    const auto data_field = vk + 0x08;

    std::vector<std::uint8_t> bytes;
    if (inline_data) {
        const auto base = vk + 0x08;
        for (std::size_t i = 0; i < size && base + i < data_.size(); ++i) {
            bytes.push_back(data_[base + i]);
        }
    } else {
        const auto payload = cell_at(static_cast<std::size_t>(rd32(data_, data_field)));
        if (payload == std::string::npos) {
            return {std::nullopt, std::nullopt};
        }
        for (std::size_t i = 0; i < size && payload + i < data_.size(); ++i) {
            bytes.push_back(data_[payload + i]);
        }
    }

    // the typed value domain: REG_SZ/EXPAND_SZ decode as microsoft utf-16le,
    // REG_DWORD/QWORD as an integer, everything else as raw bytes
    if (type == 1 || type == 2) {
        std::string text;
        for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
            const auto unit = static_cast<std::uint16_t>(bytes[i] | (bytes[i + 1] << 8));
            if (unit == 0) {
                break;
            }
            text.push_back(unit < 0x80 ? static_cast<char>(unit) : '?');
        }
        return {type, RegValue{text}};
    }
    if (type == 4 && bytes.size() >= 4) {
        return {type, RegValue{static_cast<std::int64_t>(rd32(bytes, 0))}};
    }
    if (type == 11 && bytes.size() >= 8) {
        std::uint64_t value = 0;
        for (int i = 7; i >= 0; --i) {
            value = (value << 8) | bytes[static_cast<std::size_t>(i)];
        }
        return {type, RegValue{static_cast<std::int64_t>(value)}};
    }
    return {type, RegValue{bytes}};
}

void RegHive::write(std::string_view, std::string_view, int, RegValue) {}

// ---- RegistryManager ----

RegistryManager::RegistryManager(Qiling& ql, std::string hivedir) : ql_(&ql) {
    regdiff_ = (std::filesystem::path(ql.rootfs()) / "registry" / (ql.targetname() + "_diff.json")).string();

    // if the conf file does not exist, create its directory to enable the
    // later save (registry.py, verbatim)
    std::error_code ec;
    const std::filesystem::path diff_dir = std::filesystem::path(regdiff_).parent_path();
    if (!std::filesystem::exists(diff_dir)) {
        std::filesystem::create_directories(diff_dir, ec);
        ec.clear();
    }

    if (ql.code().empty()) {
        if (!std::filesystem::exists(hivedir)) {
            throw QlErrorFileNotFound("Windows registry directory not found: \"" + hivedir + "\"!");
        }
    }

    reghive_ = std::make_unique<RegHive>(hivedir);
    regconf_ = std::make_unique<RegConf>(regdiff_);
}

bool RegistryManager::exists(std::string_view key) {
    access(key);
    return regconf_->exists(key) || reghive_->exists(key);
}

std::pair<std::optional<int>, std::optional<RegValue>> RegistryManager::read(std::string_view key,
                                                                             std::string_view subkey, int reg_type) {
    auto result = regconf_->read(key, subkey, reg_type);

    if (!result.first.has_value() && !result.second.has_value()) {
        result = reghive_->read(key, subkey, reg_type);
    }

    access(key, std::string(subkey), result.first, result.second);

    return result;
}

void RegistryManager::create(std::string_view key) {
    regconf_->create(key);
    reghive_->create(key);
}

void RegistryManager::delete_entry(std::string_view key, std::string_view subkey) {
    regconf_->delete_entry(key, subkey);
    reghive_->delete_entry(key, subkey);
}

std::string RegistryManager::read_string_at(Qiling& ql, std::uint64_t addr, bool wide) {
    // os/utils.py read_string: the char-stepped scan to the terminator
    const auto charlen = wide ? 2 : 1;
    std::string out;
    std::uint64_t cur = addr;
    while (true) {
        const auto ch = ql.mem().read(cur, charlen);
        const bool terminator = wide ? (ch.size() < 2 || (ch[0] == 0 && ch[1] == 0)) : (!ch.empty() && ch[0] == 0);
        if (terminator || ch.empty()) {
            break;
        }
        if (wide) {
            out.push_back(static_cast<char>(ch[0]));
        } else {
            out.push_back(static_cast<char>(ch[0]));
        }
        cur += charlen;
        }
    return out;
}

RegValue RegistryManager::reg_mem_read(int data_type, std::uint64_t data_addr, std::uint64_t data_size, bool wide,
                                       Qiling& ql) {
    if (data_type == static_cast<int>(RegType::RegSZ) || data_type == static_cast<int>(RegType::RegExpandSZ)) {
        return read_string_at(ql, data_addr, wide);
    }
    if (data_type == static_cast<int>(RegType::RegDWord)) {
        return static_cast<std::int64_t>(ql.mem().read_ptr(data_addr, 4));
    }
    if (data_type == static_cast<int>(RegType::RegQWord)) {
        return static_cast<std::int64_t>(ql.mem().read_ptr(data_addr, 8));
    }
    if (data_type == static_cast<int>(RegType::RegBin)) {
        return ql.mem().read(data_addr, data_size);
    }
    if (data_type == static_cast<int>(RegType::RegMultiSZ)) {
        // the multi-string: the NUL-separated strings ending on a double NUL
        // (the char width follows the A/W call shape); the textual form joins
        // the entries with '\n' — the store holds one string either way
        const auto charlen = wide ? std::uint64_t{2} : std::uint64_t{1};
        std::uint64_t cur = data_addr;
        const auto end = data_addr + (data_size == 0 ? std::uint64_t{0x10000} : data_size);
        std::string joined;
        bool first = true;
        while (cur < end) {
            const auto ch = ql.mem().read(cur, static_cast<std::size_t>(charlen));
            const bool terminator = wide ? (ch.size() < 2 || (ch[0] == 0 && ch[1] == 0))
                                         : (!ch.empty() && ch[0] == 0);
            if (terminator) {
                // the double NUL ends the multi-string; a single one ends an entry
                const auto next = cur + charlen;
                bool second = false;
                if (next < end) {
                    const auto nch = ql.mem().read(next, static_cast<std::size_t>(charlen));
                    second = wide ? (nch.size() < 2 || (nch[0] == 0 && nch[1] == 0))
                                  : (!nch.empty() && nch[0] == 0);
                }
                if (second) {
                    break;
                }
                if (!first) {
                    joined.push_back('\n');
                }
                first = false;
                cur = next;
                continue;
            }
            if (ch.empty()) {
                break;
            }
            joined.push_back(static_cast<char>(ch[0]));
            if (!first) {
                // (the entry remains open — the newline lands on the next entry)
            }
            cur += charlen;
        }
        return joined;
    }
    throw QlErrorNotImplemented(std::string("registry type ") + reg_type_name(data_type) + " not implemented");
}

std::uint64_t RegistryManager::reg_mem_write(int data_type, std::uint64_t data_addr, const RegValue& data_val,
                                             std::uint64_t max_size, bool wide, Qiling& ql) {
    std::vector<std::uint8_t> data;

    if (data_type == static_cast<int>(RegType::RegSZ) || data_type == static_cast<int>(RegType::RegExpandSZ)) {
        const auto& s = std::get<std::string>(data_val);
        // the narrow form is the utf-8 bytes; the wide form is utf-16le (the
        // ascii subset encodes as the doubled bytes)
        if (wide) {
            data.reserve(s.size() * 2 + 2);
            for (const char c : s) {
                data.push_back(static_cast<std::uint8_t>(c));
                data.push_back(0);
            }
            data.push_back(0);
            data.push_back(0);
        } else {
            data.assign(s.begin(), s.end());
            data.push_back(0);
        }
    } else if (data_type == static_cast<int>(RegType::RegDWord)) {
        const auto v = static_cast<std::uint32_t>(std::get<std::int64_t>(data_val));
        for (int i = 0; i < 4; ++i) {
            data.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    } else if (data_type == static_cast<int>(RegType::RegQWord)) {
        const auto v = static_cast<std::uint64_t>(std::get<std::int64_t>(data_val));
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    } else if (data_type == static_cast<int>(RegType::RegBin)) {
        data = std::get<std::vector<std::uint8_t>>(data_val);
    } else if (data_type == static_cast<int>(RegType::RegMultiSZ)) {
        // the '\n'-joined entries render as the NUL-separated multi-string
        // (the trailing double NUL rides the char width)
        std::string joined;
        if (std::holds_alternative<std::string>(data_val)) {
            joined = std::get<std::string>(data_val);
        } else if (std::holds_alternative<std::vector<std::uint8_t>>(data_val)) {
            const auto& raw = std::get<std::vector<std::uint8_t>>(data_val);
            joined.assign(raw.begin(), raw.end());
        }
        for (const char c : joined) {
            if (c == '\n') {
                data.push_back(0);
                if (wide) {
                    data.push_back(0);
                }
            } else {
                data.push_back(static_cast<std::uint8_t>(c));
                if (wide) {
                    data.push_back(0);
                }
            }
        }
        data.push_back(0);
        if (wide) {
            data.push_back(0);
        }
        data.push_back(0);
        if (wide) {
            data.push_back(0);
        }
    } else {
        throw QlErrorNotImplemented(std::string("registry type ") + reg_type_name(data_type) + " not implemented");
    }

    // in case the out buffer is set to null or it is too small, skip the data
    // writing (registry.py, verbatim)
    if (data_addr != 0 && max_size >= data.size()) {
        ql.mem().write(data_addr, data);
    }

    return data.size();
}

// registry.py write_reg_value_into_mem: the static wrapper over the
// __reg_mem_write walk (the Marshal the typed value into the guest memory)
std::uint64_t RegistryManager::write_reg_value_into_mem(int data_type, std::uint64_t data_addr, const RegValue& data_val,
                                                        std::uint64_t max_size, bool wide, Qiling& ql) {
    return reg_mem_write(data_type, data_addr, data_val, max_size, wide, ql);
}

void RegistryManager::write_value(std::string_view key, std::string_view subkey, int reg_type, RegValue data) {
    regconf_->write(key, subkey, reg_type, std::move(data));
}

void RegistryManager::write(std::string_view key, std::string_view subkey, int reg_type, std::uint64_t data_addr,
                            std::uint64_t data_size, bool wide) {
    const auto data = reg_mem_read(reg_type, data_addr, data_size, wide, *ql_);

    regconf_->write(key, subkey, reg_type, data);
    reghive_->write(key, subkey, reg_type, data);
}

void RegistryManager::access(std::string_view key, std::optional<std::string> item, std::optional<int> type,
                             std::optional<RegValue> value) {
    // registry.py access: the value repr lands in the stats record; the
    // windows os always carries the QlWinStats flavour (set in the ctor)
    std::optional<std::string> value_repr;
    if (value.has_value()) {
        if (const auto* s = std::get_if<std::string>(&*value)) {
            value_repr = *s;
        } else if (const auto* n = std::get_if<std::int64_t>(&*value)) {
            value_repr = std::to_string(*n);
        } else if (const auto* b = std::get_if<std::vector<std::uint8_t>>(&*value)) {
            value_repr = "<bytes:" + std::to_string(b->size()) + ">";
        }
    }
    auto* win_stats = dynamic_cast<QlWinStats*>(&ql_->os().stats());
    if (win_stats != nullptr) {
        win_stats->log_reg_access(key, std::move(item), std::move(type), std::move(value_repr));
    }
}

void RegistryManager::save() {
    regconf_->save(regdiff_);
}

}  // namespace registry
}  // namespace os
}  // namespace qiling
