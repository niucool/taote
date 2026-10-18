// Ported from qiling/os/qnx/helpers.py — the QNX message-body helper (the
// header-declared pieces; the QnxConn record above).
#include "qiling/os/qnx/helpers.hpp"

#include "qiling/core.hpp"

namespace qiling {
namespace os {
namespace qnx {

std::vector<std::uint8_t> get_message_body(Qiling& ql, std::uint64_t msg, std::int32_t parts) {
    // helpers.py get_message_body: the iov form rides the first iov entry
    // (the base at msg+0, the length at msg+4 — the later entries are read
    // by the individual handlers, verbatim); the negative form is the flat
    // byte length
    if (parts >= 0) {
        const auto base = ql.mem().read_ptr(msg, 4);
        const auto len = ql.mem().read_ptr(msg + 4, 4);
        return ql.mem().read(base, len);
    }
    return ql.mem().read(msg, static_cast<std::uint64_t>(-parts));
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
