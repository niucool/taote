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
    std::uint64_t retval;
    bool retval_present;
    std::uint64_t retaddr;
    std::uint64_t position;
};

class QlOsStats {
public:
    QlOsStats() = default;

    void clear();

    std::vector<std::string> summary() const;

    // log_api_call — record an emulated API invocation
    void log_api_call(std::uint64_t address, std::string_view name,
                      std::uint64_t retval, bool retval_present,
                      std::uint64_t retaddr);

    // log_string — record string appearance (tokenized by spaces)
    void log_string(std::string_view s);

    std::uint64_t position() const noexcept { return position_; }

    const std::map<std::string, std::vector<ApiCallRecord>>& syscalls() const noexcept { return syscalls_; }
    const std::map<std::string, std::set<std::uint64_t>>& strings() const noexcept { return strings_; }

private:
    std::map<std::string, std::vector<ApiCallRecord>> syscalls_;
    std::map<std::string, std::set<std::uint64_t>> strings_;
    std::uint64_t position_ = 0;
};

}  // namespace qiling

#endif  // QILING_OS_STATS_HPP
