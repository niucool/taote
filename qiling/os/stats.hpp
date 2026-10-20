// Ported from qiling/os/stats.py — QlOsStats (API-call and string recording).
// JSON serialization (the summary's json.dumps) is replaced with std::ostream
// formatting; the recorded fields are identical.
#ifndef QILING_OS_STATS_HPP
#define QILING_OS_STATS_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace qiling {

// os/os.py — the summary lines carry host-side JSON-ish structures; the C++ port
// renders them as compact field lists (a documented deviation: Python's summary
// embeds json.dumps output for the params/retval values).
struct ApiCallRecord {
    std::uint64_t address;
    std::string name;         // api function name
    // the owning module, so an expectation can be dll-qualified
    // (`KERNEL32.GetProcAddress`) the way pegasus's cases are
    std::string dll;
    // the rendered arguments (`name=0x...`, or `name='text'` for the string
    // families): the analysis surface an argument-sensitive expectation needs
    // (PMA 06-03 asserts InternetOpenUrlA's URL)
    std::vector<std::string> params;
    std::uint64_t retval;
    bool retval_present;
    std::uint64_t retaddr;
    std::uint64_t position;
};

// the behavioural indicator surface (PLAN_PARITY Phase 3 item 2): pegasus
// answers "did the sample touch this file/registry key/domain" from typed
// events, so the same facts are recorded as (kind, target) pairs -
// file_open/file_create/file_read/file_write, reg_open_key/reg_create_key/
// reg_read_value/reg_write_value/reg_list_subkeys, net_dns/net_http
struct IndicatorEvent {
    std::string kind;
    std::string target;
    std::uint64_t position = 0;
};

class QlOsStats {
public:
    QlOsStats() = default;
    virtual ~QlOsStats() = default;

    virtual void clear();

    virtual std::vector<std::string> summary() const;

    // log_api_call — record an emulated API invocation
    void log_api_call(std::uint64_t address, std::string_view name,
                      std::uint64_t retval, bool retval_present,
                      std::uint64_t retaddr);
    // the dll-qualified, argument-carrying form (the record fields above)
    void log_api_call(std::uint64_t address, std::string_view name, std::string_view dll,
                      std::vector<std::string> params, std::uint64_t retval, bool retval_present,
                      std::uint64_t retaddr);

    // log_unsupported_api — record an import that no handler serves (pegasus
    // counts these and the reference PMA cases assert the count is zero)
    void log_unsupported_api(std::string_view name);

    std::size_t unsupported_api_count() const noexcept { return unsupported_apis_.size(); }
    const std::set<std::string>& unsupported_apis() const noexcept { return unsupported_apis_; }

    // the api dispatch count (the max_api_count guard reads it)
    std::size_t api_count() const noexcept { return api_count_; }

    // log_indicator — record a behavioural indicator (file/registry/network)
    void log_indicator(std::string_view kind, std::string_view target);

    const std::map<std::string, std::vector<IndicatorEvent>>& indicators() const noexcept { return indicators_; }

    // log_string — record string appearance (tokenized by spaces)
    void log_string(std::string_view s);

    std::uint64_t position() const noexcept { return position_; }
    void advance_position() noexcept { ++position_; }

    const std::map<std::string, std::vector<ApiCallRecord>>& syscalls() const noexcept { return syscalls_; }
    const std::map<std::string, std::set<std::uint64_t>>& strings() const noexcept { return strings_; }

private:
    std::map<std::string, std::vector<ApiCallRecord>> syscalls_;
    std::map<std::string, std::set<std::uint64_t>> strings_;
    std::map<std::string, std::vector<IndicatorEvent>> indicators_;
    std::set<std::string> unsupported_apis_;
    std::size_t api_count_ = 0;
    std::uint64_t position_ = 0;
};

// os/stats.py QlWinStats — the Windows stats flavour: the registry access
// records join the syscall/string surfaces (windows.py: self.stats = QlWinStats())
struct RegAccessRecord {
    std::string item;                    // the sub item name (empty for the bare key access)
    std::optional<int> type;             // the value type when known
    std::optional<std::string> value;    // the recorded value repr (str/bytes/int)
    std::uint64_t position = 0;
};

class QlWinStats : public QlOsStats {
public:
    void clear() override;
    std::vector<std::string> summary() const override;

    // stats.py log_reg_access: record a registry access (key, item, type, value)
    void log_reg_access(std::string_view key, std::optional<std::string> item,
                        std::optional<int> type, std::optional<std::string> value);

    const std::map<std::string, std::vector<RegAccessRecord>>& registry() const noexcept { return registry_; }

private:
    std::map<std::string, std::vector<RegAccessRecord>> registry_;
};

}  // namespace qiling

#endif  // QILING_OS_STATS_HPP
