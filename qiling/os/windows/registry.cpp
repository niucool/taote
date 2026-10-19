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

RegHive::RegHive(std::string_view hname) : hname_(std::string(hname)) {}

bool RegHive::exists(std::string_view) const {
    return false;  // the pre-existing hive reads land with the hive slice
}

void RegHive::create(std::string_view) {}

void RegHive::delete_entry(std::string_view, std::string_view) {}

std::pair<std::optional<int>, std::optional<RegValue>> RegHive::read(std::string_view, std::string_view, int) const {
    return {std::nullopt, std::nullopt};
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
