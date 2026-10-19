// Ported from qiling/os/windows/registry.py — the registry manager (RegConf +
// RegHive + RegistryManager). The python-registry hive parsing has no C++
// counterpart in this tree: RegHive's read path defers (the existing-hive
// reads land with the real-hive fixture slice) while its create/delete/write
// no-ops port verbatim. The RegConf diff store is fully functional: the
// manager reads the diff first (registry.py's precedence), writes land in the
// diff only, and save() serialises the json.
#ifndef QILING_OS_WINDOWS_REGISTRY_HPP
#define QILING_OS_WINDOWS_REGISTRY_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "qiling/os/stats.hpp"

namespace qiling {

class Qiling;

namespace os {

// const.py REG_TYPES — the win32 registry value types (the numeric ids match
// the Registry package constants)
enum class RegType : int {
    RegNone = 0,
    RegSZ = 1,
    RegExpandSZ = 2,
    RegBin = 3,
    RegDWord = 4,
    RegBigEndian = 5,
    RegLink = 6,
    RegMultiSZ = 7,
    RegResourceList = 8,
    RegFullResourceDescriptor = 9,
    RegResourceRequirementsList = 10,
    RegQWord = 11,
};

// the REG_TYPES[reg_type] name table (const.py, verbatim strings)
const char* reg_type_name(int reg_type);

// the read/write value domain (the str/bytes/int triple)
using RegValue = std::variant<std::monostate, std::int64_t, std::string, std::vector<std::uint8_t>>;

namespace registry {

// registry.py RegConf — the json-backed diff store
class RegConf {
public:
    explicit RegConf(std::string fname);

    bool exists(std::string_view key) const;
    void create(std::string_view key);
    void delete_entry(std::string_view key, std::string_view subkey);
    std::pair<std::optional<int>, std::optional<RegValue>> read(std::string_view key, std::string_view subkey,
                                                                int reg_type) const;
    void write(std::string_view key, std::string_view subkey, int reg_type, RegValue data);
    void save(std::string_view fname) const;

private:
    std::string fname_;
    std::map<std::string, std::map<std::string, std::pair<int, RegValue>>, std::less<>> conf_;
};

// registry.py RegHive — the pre-existing hive files. The binary hive parsing
// defers (the python-registry package analogue); the mutation methods keep
// the upstream no-op semantics verbatim.
class RegHive {
public:
    explicit RegHive(std::string_view hname);

    bool exists(std::string_view key) const;
    void create(std::string_view key);
    void delete_entry(std::string_view key, std::string_view subkey);
    std::pair<std::optional<int>, std::optional<RegValue>> read(std::string_view key, std::string_view subkey,
                                                                int reg_type) const;
    void write(std::string_view key, std::string_view subkey, int reg_type, RegValue data);

private:
    std::string hname_;
};

// registry.py RegistryManager — the diff-first read precedence, the
// guest-memory marshalling for the api calls, and the access logging.
class RegistryManager {
public:
    RegistryManager(Qiling& ql, std::string hivedir);

    bool exists(std::string_view key);
    std::pair<std::optional<int>, std::optional<RegValue>> read(std::string_view key, std::string_view subkey,
                                                                int reg_type);
    void create(std::string_view key);
    void delete_entry(std::string_view key, std::string_view subkey);

    // registry.py write: read the typed value from the guest memory at
    // data_addr, then record it in the diff (and the hive, a no-op)
    void write(std::string_view key, std::string_view subkey, int reg_type, std::uint64_t data_addr,
               std::uint64_t data_size, bool wide);

    // registry.py write_reg_value_into_mem: marshal the typed value into the
    // guest memory; returns the byte count (skipped when the buffer is null
    // or too small)
    static std::uint64_t write_reg_value_into_mem(int data_type, std::uint64_t data_addr, const RegValue& data_val,
                                                  std::uint64_t max_size, bool wide, class Qiling& ql);

    void save();

private:
    // registry.py __reg_mem_read / __reg_mem_write
    static RegValue reg_mem_read(int data_type, std::uint64_t data_addr, std::uint64_t data_size, bool wide,
                                 class Qiling& ql);
    static std::uint64_t reg_mem_write(int data_type, std::uint64_t data_addr, const RegValue& data_val,
                                       std::uint64_t max_size, bool wide, class Qiling& ql);
    static std::string read_string_at(class Qiling& ql, std::uint64_t addr, bool wide);

public:
    // registry.py access: record the key/item touch in the diff store (the
    // python surface is public; the RegOpenKey profile-hit arm rides it)
    void access(std::string_view key, std::optional<std::string> item = std::nullopt,
                std::optional<int> type = std::nullopt, std::optional<RegValue> value = std::nullopt);

private:

    Qiling* ql_ = nullptr;
    std::string regdiff_;
    std::unique_ptr<RegConf> regconf_;
    std::unique_ptr<RegHive> reghive_;
};

}  // namespace registry
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_REGISTRY_HPP
