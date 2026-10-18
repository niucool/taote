// Ported from qiling/os/macos/subsystems.py — MachHostServer + MachTaskServer,
// the MIG-generated message servers (the fixed-data replies verbatim; the
// upstream TODO "we havent finish the server it self, only return the fixed
// data" carries over).
#ifndef QILING_OS_MACOS_SUBSYSTEMS_HPP
#define QILING_OS_MACOS_SUBSYSTEMS_HPP

#include <cstdint>
#include <vector>

#include "qiling/os/macos/mach_msg.hpp"

namespace qiling {

class Qiling;

namespace os {
namespace macos {

// subsystems.py MachHostServer: the host-surface message ids
class MachHostServer {
public:
    explicit MachHostServer(Qiling& ql) : ql_(&ql) {}

    // msgh_id 200: the HOST_BASIC_INFO / HOST_PRIORITY_INFO fixed replies
    // (the content: NDR(8) + retcode + outCnt + the per-flavor cells; the
    // content shorter than 16 bytes and the unknown flavors raise)
    MachMsg host_info(const MachMsgHeader& in_header, const std::vector<std::uint8_t>& in_content);

    // msgh_id 206: the clock-service reply (the retcode content + the
    // trailer carrying the manager's clock port 0x803)
    MachMsg host_get_clock_service(const MachMsgHeader& in_header,
                                   const std::vector<std::uint8_t>& in_content);

private:
    Qiling* ql_;
};

// subsystems.py MachTaskServer: the task-surface message ids
class MachTaskServer {
public:
    explicit MachTaskServer(Qiling& ql) : ql_(&ql) {}

    // msgh_id 3418: the semaphore_create reply (id 3518, the semaphore port
    // 0x903 in the trailer)
    MachMsg semaphore_create(const MachMsgHeader& in_header,
                             const std::vector<std::uint8_t>& in_content);

    // msgh_id 3409: the get_special_port reply (id 3509, the special port
    // 0x707 in the trailer)
    MachMsg get_special_port(const MachMsgHeader& in_header,
                             const std::vector<std::uint8_t>& in_content);

private:
    Qiling* ql_;
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_SUBSYSTEMS_HPP
