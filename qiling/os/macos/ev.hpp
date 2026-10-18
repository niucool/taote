// Ported from qiling/os/macos/events/macos.py (QlMacOSEv / QlMacOSEvManager)
// and events/macos_policy.py (QlMacOSPolicy). The manager carries the proc
// list (the 1144-byte proc_t images seeded through add_process), the lazy
// ev-ctx state (the label/ucred/vnode cells init_ev_ctx builds), the
// event-emit jobs and the emit/trigger surface. The socket-networking half
// of the upstream manager (the sflt/ipf emitters, the scapy packet build,
// the socket ctls) rides a later slice with the kext message machinery.
#ifndef QILING_OS_MACOS_EV_HPP
#define QILING_OS_MACOS_EV_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <map>

#include "qiling/core.hpp"

namespace qiling {

class Qiling;

namespace os {
namespace macos {

// events/macos.py MacOSEventType + events/macos_policy.py MACPolicy_EventType
// (both AutoNumber enums over the shared counter — the MAC table starts at
// base_event_MAC = 0x2000 and the upstream declares the 335 mac-policy ids
// contiguous)
enum class MacOSEventType : unsigned {
    EV_CTL_CONNECT,
    EV_CTL_DISCONNECT,
    EV_CTL_SEND,
    EV_CTL_SETOPT,
    EV_CTL_GETOPT,
    EV_SFLT_ATTACH,
    EV_SFLT_BIND,
    EV_SFLT_LISTEN,
    EV_SFLT_CONNECT_IN,
    EV_SFLT_CONNECT_OUT,
    EV_SFLT_NOTIFY_BOUND,
    EV_SFLT_NOTIFY_CONNECTING,
    EV_SFLT_NOTIFY_CONNECTED,
    EV_SFLT_NOTIFY_CLOSING,
    EV_SFLT_NOTIFY_DISCONNECTING,
    EV_SFLT_NOTIFY_DISCONNECTED,
    EV_SFLT_DATA_IN,
    EV_SFLT_DATA_OUT,
    EV_SFLT_SETOPTION,
    EV_SFLT_GETOPTION,
    EV_SFLT_DETACH,
    EV_IPF_INPUT,
    EV_IPF_OUTPUT,
    EV_IPF_DETACH,
    EV_KAUTH_GENERIC,
    EV_KAUTH_PROCESS,
    EV_KAUTH_VNODE,
    EV_KAUTH_FILEOP,
    // the MAC-policy event ids share the AutoNumber counter (base_event_MAC)
    EV_MAC_mpo_file_check_mmap,
};

// events/macos_policy.py base_event_MAC — the MAC-policy id base
constexpr unsigned kBaseEventMAC = 0x2000;

// macos_structs.py base_event_socket + SocketEvent (the sflt notify event
// ids; the emitters pass `value - base_event_socket` as the notify offset)
constexpr unsigned kBaseEventSocket = 0x1000;

enum class SocketEvent : unsigned {
    CONNECTING = 0x1001,
    CONNECTED = 0x1002,
    DISCONNECTING = 0x1003,
    DISCONNECTED = 0x1004,
    FLUSH_READ = 0x1005,
    SHUTDOWN = 0x1006,
    CANTRECVMORE = 0x1007,
    CANTSENDMORE = 0x1008,
    CLOSING = 0x1009,
    BOUND = 0x100a,
};

// macos_structs.py NetworkProtocol (the verbatim 105-entry IPPROTO table;
// the sflt emitters pass protocol.value as the emit filter)
// the winsock IPPROTO_* macros collide with the verbatim enumerator names —
// suspend them around the enum (the types.hpp S_IF* pattern, with restore)
#pragma push_macro("IPPROTO_IP")
#undef IPPROTO_IP
#pragma push_macro("IPPROTO_ICMP")
#undef IPPROTO_ICMP
#pragma push_macro("IPPROTO_IGMP")
#undef IPPROTO_IGMP
#pragma push_macro("IPPROTO_GGP")
#undef IPPROTO_GGP
#pragma push_macro("IPPROTO_IPV4")
#undef IPPROTO_IPV4
#pragma push_macro("IPPROTO_TCP")
#undef IPPROTO_TCP
#pragma push_macro("IPPROTO_ST")
#undef IPPROTO_ST
#pragma push_macro("IPPROTO_EGP")
#undef IPPROTO_EGP
#pragma push_macro("IPPROTO_PIGP")
#undef IPPROTO_PIGP
#pragma push_macro("IPPROTO_RCCMON")
#undef IPPROTO_RCCMON
#pragma push_macro("IPPROTO_NVPII")
#undef IPPROTO_NVPII
#pragma push_macro("IPPROTO_PUP")
#undef IPPROTO_PUP
#pragma push_macro("IPPROTO_ARGUS")
#undef IPPROTO_ARGUS
#pragma push_macro("IPPROTO_EMCON")
#undef IPPROTO_EMCON
#pragma push_macro("IPPROTO_XNET")
#undef IPPROTO_XNET
#pragma push_macro("IPPROTO_CHAOS")
#undef IPPROTO_CHAOS
#pragma push_macro("IPPROTO_UDP")
#undef IPPROTO_UDP
#pragma push_macro("IPPROTO_MUX")
#undef IPPROTO_MUX
#pragma push_macro("IPPROTO_MEAS")
#undef IPPROTO_MEAS
#pragma push_macro("IPPROTO_HMP")
#undef IPPROTO_HMP
#pragma push_macro("IPPROTO_PRM")
#undef IPPROTO_PRM
#pragma push_macro("IPPROTO_IDP")
#undef IPPROTO_IDP
#pragma push_macro("IPPROTO_TRUNK1")
#undef IPPROTO_TRUNK1
#pragma push_macro("IPPROTO_TRUNK2")
#undef IPPROTO_TRUNK2
#pragma push_macro("IPPROTO_LEAF1")
#undef IPPROTO_LEAF1
#pragma push_macro("IPPROTO_LEAF2")
#undef IPPROTO_LEAF2
#pragma push_macro("IPPROTO_RDP")
#undef IPPROTO_RDP
#pragma push_macro("IPPROTO_IRTP")
#undef IPPROTO_IRTP
#pragma push_macro("IPPROTO_TP")
#undef IPPROTO_TP
#pragma push_macro("IPPROTO_BLT")
#undef IPPROTO_BLT
#pragma push_macro("IPPROTO_NSP")
#undef IPPROTO_NSP
#pragma push_macro("IPPROTO_INP")
#undef IPPROTO_INP
#pragma push_macro("IPPROTO_SEP")
#undef IPPROTO_SEP
#pragma push_macro("IPPROTO_3PC")
#undef IPPROTO_3PC
#pragma push_macro("IPPROTO_IDPR")
#undef IPPROTO_IDPR
#pragma push_macro("IPPROTO_XTP")
#undef IPPROTO_XTP
#pragma push_macro("IPPROTO_DDP")
#undef IPPROTO_DDP
#pragma push_macro("IPPROTO_CMTP")
#undef IPPROTO_CMTP
#pragma push_macro("IPPROTO_TPXX")
#undef IPPROTO_TPXX
#pragma push_macro("IPPROTO_IL")
#undef IPPROTO_IL
#pragma push_macro("IPPROTO_IPV6")
#undef IPPROTO_IPV6
#pragma push_macro("IPPROTO_SDRP")
#undef IPPROTO_SDRP
#pragma push_macro("IPPROTO_ROUTING")
#undef IPPROTO_ROUTING
#pragma push_macro("IPPROTO_FRAGMENT")
#undef IPPROTO_FRAGMENT
#pragma push_macro("IPPROTO_IDRP")
#undef IPPROTO_IDRP
#pragma push_macro("IPPROTO_RSVP")
#undef IPPROTO_RSVP
#pragma push_macro("IPPROTO_GRE")
#undef IPPROTO_GRE
#pragma push_macro("IPPROTO_MHRP")
#undef IPPROTO_MHRP
#pragma push_macro("IPPROTO_BHA")
#undef IPPROTO_BHA
#pragma push_macro("IPPROTO_ESP")
#undef IPPROTO_ESP
#pragma push_macro("IPPROTO_AH")
#undef IPPROTO_AH
#pragma push_macro("IPPROTO_INLSP")
#undef IPPROTO_INLSP
#pragma push_macro("IPPROTO_SWIPE")
#undef IPPROTO_SWIPE
#pragma push_macro("IPPROTO_NHRP")
#undef IPPROTO_NHRP
#pragma push_macro("IPPROTO_ICMPV6")
#undef IPPROTO_ICMPV6
#pragma push_macro("IPPROTO_NONE")
#undef IPPROTO_NONE
#pragma push_macro("IPPROTO_DSTOPTS")
#undef IPPROTO_DSTOPTS
#pragma push_macro("IPPROTO_AHIP")
#undef IPPROTO_AHIP
#pragma push_macro("IPPROTO_CFTP")
#undef IPPROTO_CFTP
#pragma push_macro("IPPROTO_HELLO")
#undef IPPROTO_HELLO
#pragma push_macro("IPPROTO_SATEXPAK")
#undef IPPROTO_SATEXPAK
#pragma push_macro("IPPROTO_KRYPTOLAN")
#undef IPPROTO_KRYPTOLAN
#pragma push_macro("IPPROTO_RVD")
#undef IPPROTO_RVD
#pragma push_macro("IPPROTO_IPPC")
#undef IPPROTO_IPPC
#pragma push_macro("IPPROTO_ADFS")
#undef IPPROTO_ADFS
#pragma push_macro("IPPROTO_SATMON")
#undef IPPROTO_SATMON
#pragma push_macro("IPPROTO_VISA")
#undef IPPROTO_VISA
#pragma push_macro("IPPROTO_IPCV")
#undef IPPROTO_IPCV
#pragma push_macro("IPPROTO_CPNX")
#undef IPPROTO_CPNX
#pragma push_macro("IPPROTO_CPHB")
#undef IPPROTO_CPHB
#pragma push_macro("IPPROTO_WSN")
#undef IPPROTO_WSN
#pragma push_macro("IPPROTO_PVP")
#undef IPPROTO_PVP
#pragma push_macro("IPPROTO_BRSATMON")
#undef IPPROTO_BRSATMON
#pragma push_macro("IPPROTO_ND")
#undef IPPROTO_ND
#pragma push_macro("IPPROTO_WBMON")
#undef IPPROTO_WBMON
#pragma push_macro("IPPROTO_WBEXPAK")
#undef IPPROTO_WBEXPAK
#pragma push_macro("IPPROTO_EON")
#undef IPPROTO_EON
#pragma push_macro("IPPROTO_VMTP")
#undef IPPROTO_VMTP
#pragma push_macro("IPPROTO_SVMTP")
#undef IPPROTO_SVMTP
#pragma push_macro("IPPROTO_VINES")
#undef IPPROTO_VINES
#pragma push_macro("IPPROTO_TTP")
#undef IPPROTO_TTP
#pragma push_macro("IPPROTO_IGP")
#undef IPPROTO_IGP
#pragma push_macro("IPPROTO_DGP")
#undef IPPROTO_DGP
#pragma push_macro("IPPROTO_TCF")
#undef IPPROTO_TCF
#pragma push_macro("IPPROTO_IGRP")
#undef IPPROTO_IGRP
#pragma push_macro("IPPROTO_OSPFIGP")
#undef IPPROTO_OSPFIGP
#pragma push_macro("IPPROTO_SRPC")
#undef IPPROTO_SRPC
#pragma push_macro("IPPROTO_LARP")
#undef IPPROTO_LARP
#pragma push_macro("IPPROTO_MTP")
#undef IPPROTO_MTP
#pragma push_macro("IPPROTO_AX25")
#undef IPPROTO_AX25
#pragma push_macro("IPPROTO_IPEIP")
#undef IPPROTO_IPEIP
#pragma push_macro("IPPROTO_MICP")
#undef IPPROTO_MICP
#pragma push_macro("IPPROTO_SCCSP")
#undef IPPROTO_SCCSP
#pragma push_macro("IPPROTO_ETHERIP")
#undef IPPROTO_ETHERIP
#pragma push_macro("IPPROTO_ENCAP")
#undef IPPROTO_ENCAP
#pragma push_macro("IPPROTO_APES")
#undef IPPROTO_APES
#pragma push_macro("IPPROTO_GMTP")
#undef IPPROTO_GMTP
#pragma push_macro("IPPROTO_PIM")
#undef IPPROTO_PIM
#pragma push_macro("IPPROTO_IPCOMP")
#undef IPPROTO_IPCOMP
#pragma push_macro("IPPROTO_PGM")
#undef IPPROTO_PGM
#pragma push_macro("IPPROTO_SCTP")
#undef IPPROTO_SCTP
#pragma push_macro("IPPROTO_DIVERT")
#undef IPPROTO_DIVERT
#pragma push_macro("IPPROTO_RAW")
#undef IPPROTO_RAW
#pragma push_macro("IPPROTO_MAX")
#undef IPPROTO_MAX
#pragma push_macro("IPPROTO_DONE")
#undef IPPROTO_DONE

enum class NetworkProtocol : unsigned {
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_GGP = 3,
    IPPROTO_IPV4 = 4,
    IPPROTO_TCP = 6,
    IPPROTO_ST = 7,
    IPPROTO_EGP = 8,
    IPPROTO_PIGP = 9,
    IPPROTO_RCCMON = 10,
    IPPROTO_NVPII = 11,
    IPPROTO_PUP = 12,
    IPPROTO_ARGUS = 13,
    IPPROTO_EMCON = 14,
    IPPROTO_XNET = 15,
    IPPROTO_CHAOS = 16,
    IPPROTO_UDP = 17,
    IPPROTO_MUX = 18,
    IPPROTO_MEAS = 19,
    IPPROTO_HMP = 20,
    IPPROTO_PRM = 21,
    IPPROTO_IDP = 22,
    IPPROTO_TRUNK1 = 23,
    IPPROTO_TRUNK2 = 24,
    IPPROTO_LEAF1 = 25,
    IPPROTO_LEAF2 = 26,
    IPPROTO_RDP = 27,
    IPPROTO_IRTP = 28,
    IPPROTO_TP = 29,
    IPPROTO_BLT = 30,
    IPPROTO_NSP = 31,
    IPPROTO_INP = 32,
    IPPROTO_SEP = 33,
    IPPROTO_3PC = 34,
    IPPROTO_IDPR = 35,
    IPPROTO_XTP = 36,
    IPPROTO_DDP = 37,
    IPPROTO_CMTP = 38,
    IPPROTO_TPXX = 39,
    IPPROTO_IL = 40,
    IPPROTO_IPV6 = 41,
    IPPROTO_SDRP = 42,
    IPPROTO_ROUTING = 43,
    IPPROTO_FRAGMENT = 44,
    IPPROTO_IDRP = 45,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_MHRP = 48,
    IPPROTO_BHA = 49,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_INLSP = 52,
    IPPROTO_SWIPE = 53,
    IPPROTO_NHRP = 54,
    IPPROTO_ICMPV6 = 58,
    IPPROTO_NONE = 59,
    IPPROTO_DSTOPTS = 60,
    IPPROTO_AHIP = 61,
    IPPROTO_CFTP = 62,
    IPPROTO_HELLO = 63,
    IPPROTO_SATEXPAK = 64,
    IPPROTO_KRYPTOLAN = 65,
    IPPROTO_RVD = 66,
    IPPROTO_IPPC = 67,
    IPPROTO_ADFS = 68,
    IPPROTO_SATMON = 69,
    IPPROTO_VISA = 70,
    IPPROTO_IPCV = 71,
    IPPROTO_CPNX = 72,
    IPPROTO_CPHB = 73,
    IPPROTO_WSN = 74,
    IPPROTO_PVP = 75,
    IPPROTO_BRSATMON = 76,
    IPPROTO_ND = 77,
    IPPROTO_WBMON = 78,
    IPPROTO_WBEXPAK = 79,
    IPPROTO_EON = 80,
    IPPROTO_VMTP = 81,
    IPPROTO_SVMTP = 82,
    IPPROTO_VINES = 83,
    IPPROTO_TTP = 84,
    IPPROTO_IGP = 85,
    IPPROTO_DGP = 86,
    IPPROTO_TCF = 87,
    IPPROTO_IGRP = 88,
    IPPROTO_OSPFIGP = 89,
    IPPROTO_SRPC = 90,
    IPPROTO_LARP = 91,
    IPPROTO_MTP = 92,
    IPPROTO_AX25 = 93,
    IPPROTO_IPEIP = 94,
    IPPROTO_MICP = 95,
    IPPROTO_SCCSP = 96,
    IPPROTO_ETHERIP = 97,
    IPPROTO_ENCAP = 98,
    IPPROTO_APES = 99,
    IPPROTO_GMTP = 100,
    IPPROTO_PIM = 103,
    IPPROTO_IPCOMP = 108,
    IPPROTO_PGM = 113,
    IPPROTO_SCTP = 132,
    IPPROTO_DIVERT = 254,
    IPPROTO_RAW = 255,
    IPPROTO_MAX = 256,
    IPPROTO_DONE = 257,
};

#pragma pop_macro("IPPROTO_IP")
#pragma pop_macro("IPPROTO_ICMP")
#pragma pop_macro("IPPROTO_IGMP")
#pragma pop_macro("IPPROTO_GGP")
#pragma pop_macro("IPPROTO_IPV4")
#pragma pop_macro("IPPROTO_TCP")
#pragma pop_macro("IPPROTO_ST")
#pragma pop_macro("IPPROTO_EGP")
#pragma pop_macro("IPPROTO_PIGP")
#pragma pop_macro("IPPROTO_RCCMON")
#pragma pop_macro("IPPROTO_NVPII")
#pragma pop_macro("IPPROTO_PUP")
#pragma pop_macro("IPPROTO_ARGUS")
#pragma pop_macro("IPPROTO_EMCON")
#pragma pop_macro("IPPROTO_XNET")
#pragma pop_macro("IPPROTO_CHAOS")
#pragma pop_macro("IPPROTO_UDP")
#pragma pop_macro("IPPROTO_MUX")
#pragma pop_macro("IPPROTO_MEAS")
#pragma pop_macro("IPPROTO_HMP")
#pragma pop_macro("IPPROTO_PRM")
#pragma pop_macro("IPPROTO_IDP")
#pragma pop_macro("IPPROTO_TRUNK1")
#pragma pop_macro("IPPROTO_TRUNK2")
#pragma pop_macro("IPPROTO_LEAF1")
#pragma pop_macro("IPPROTO_LEAF2")
#pragma pop_macro("IPPROTO_RDP")
#pragma pop_macro("IPPROTO_IRTP")
#pragma pop_macro("IPPROTO_TP")
#pragma pop_macro("IPPROTO_BLT")
#pragma pop_macro("IPPROTO_NSP")
#pragma pop_macro("IPPROTO_INP")
#pragma pop_macro("IPPROTO_SEP")
#pragma pop_macro("IPPROTO_3PC")
#pragma pop_macro("IPPROTO_IDPR")
#pragma pop_macro("IPPROTO_XTP")
#pragma pop_macro("IPPROTO_DDP")
#pragma pop_macro("IPPROTO_CMTP")
#pragma pop_macro("IPPROTO_TPXX")
#pragma pop_macro("IPPROTO_IL")
#pragma pop_macro("IPPROTO_IPV6")
#pragma pop_macro("IPPROTO_SDRP")
#pragma pop_macro("IPPROTO_ROUTING")
#pragma pop_macro("IPPROTO_FRAGMENT")
#pragma pop_macro("IPPROTO_IDRP")
#pragma pop_macro("IPPROTO_RSVP")
#pragma pop_macro("IPPROTO_GRE")
#pragma pop_macro("IPPROTO_MHRP")
#pragma pop_macro("IPPROTO_BHA")
#pragma pop_macro("IPPROTO_ESP")
#pragma pop_macro("IPPROTO_AH")
#pragma pop_macro("IPPROTO_INLSP")
#pragma pop_macro("IPPROTO_SWIPE")
#pragma pop_macro("IPPROTO_NHRP")
#pragma pop_macro("IPPROTO_ICMPV6")
#pragma pop_macro("IPPROTO_NONE")
#pragma pop_macro("IPPROTO_DSTOPTS")
#pragma pop_macro("IPPROTO_AHIP")
#pragma pop_macro("IPPROTO_CFTP")
#pragma pop_macro("IPPROTO_HELLO")
#pragma pop_macro("IPPROTO_SATEXPAK")
#pragma pop_macro("IPPROTO_KRYPTOLAN")
#pragma pop_macro("IPPROTO_RVD")
#pragma pop_macro("IPPROTO_IPPC")
#pragma pop_macro("IPPROTO_ADFS")
#pragma pop_macro("IPPROTO_SATMON")
#pragma pop_macro("IPPROTO_VISA")
#pragma pop_macro("IPPROTO_IPCV")
#pragma pop_macro("IPPROTO_CPNX")
#pragma pop_macro("IPPROTO_CPHB")
#pragma pop_macro("IPPROTO_WSN")
#pragma pop_macro("IPPROTO_PVP")
#pragma pop_macro("IPPROTO_BRSATMON")
#pragma pop_macro("IPPROTO_ND")
#pragma pop_macro("IPPROTO_WBMON")
#pragma pop_macro("IPPROTO_WBEXPAK")
#pragma pop_macro("IPPROTO_EON")
#pragma pop_macro("IPPROTO_VMTP")
#pragma pop_macro("IPPROTO_SVMTP")
#pragma pop_macro("IPPROTO_VINES")
#pragma pop_macro("IPPROTO_TTP")
#pragma pop_macro("IPPROTO_IGP")
#pragma pop_macro("IPPROTO_DGP")
#pragma pop_macro("IPPROTO_TCF")
#pragma pop_macro("IPPROTO_IGRP")
#pragma pop_macro("IPPROTO_OSPFIGP")
#pragma pop_macro("IPPROTO_SRPC")
#pragma pop_macro("IPPROTO_LARP")
#pragma pop_macro("IPPROTO_MTP")
#pragma pop_macro("IPPROTO_AX25")
#pragma pop_macro("IPPROTO_IPEIP")
#pragma pop_macro("IPPROTO_MICP")
#pragma pop_macro("IPPROTO_SCCSP")
#pragma pop_macro("IPPROTO_ETHERIP")
#pragma pop_macro("IPPROTO_ENCAP")
#pragma pop_macro("IPPROTO_APES")
#pragma pop_macro("IPPROTO_GMTP")
#pragma pop_macro("IPPROTO_PIM")
#pragma pop_macro("IPPROTO_IPCOMP")
#pragma pop_macro("IPPROTO_PGM")
#pragma pop_macro("IPPROTO_SCTP")
#pragma pop_macro("IPPROTO_DIVERT")
#pragma pop_macro("IPPROTO_RAW")
#pragma pop_macro("IPPROTO_MAX")
#pragma pop_macro("IPPROTO_DONE")

// one registered callback: the (name, type) pair keys it; the upstream keys
// the map by the QlMacOSEv object (the identity compare) — the port keys by
// the pair plus an insertion sequence so equal names still coexist
struct EvEntry {
    std::string name;
    MacOSEventType type;
    std::uint64_t func_addr = 0;
    std::uint64_t ev_obj = 0;  // the event-object address (set_params inserts
                               // it at the ev_index slot when set)
    int ev_index = -1;         // set_params inserts the event object at this slot
    std::optional<std::uint64_t> protocol;  // the sflt/socket protocol filter
};

// a pending emit job: the callback + the resolved params + the event type
// (the upstream's job tuple carries the QlMacOSEv object)
struct EvJob {
    std::uint64_t func_addr = 0;
    std::vector<std::uint64_t> params;
    MacOSEventType type = MacOSEventType::EV_CTL_CONNECT;
};

// the proc-table record: the guest proc_t image address plus the fields the
// manager itself owns (the image carries the rest)
struct ProcRecord {
    std::int32_t pid = 0;
    std::uint64_t base = 0;  // the guest proc_t image
};

// events/macos.py QlMacOSEvManager. The RUN=True emit path stack-pushes the
// gen_stub_code trampoline (the guest's next ret lands in it); the RUN=false
// path queues a job for the trigger() drain. The port carries the proc
// table, the lazy ev-ctx cells, the emit/trigger surface and the policy
// hooks the kernel_api handlers read. The socket-networking emitters (the
// net_*/ctl_* methods) ride the following slice.
class QlEvManager {
public:
    explicit QlEvManager(Qiling& ql);

    // the Qiling facade takes the os pointer as QlOs* — no accessor for the
    // derived os exists on the core, so the heap rides through the caller;
    // the manager stores the posix heap directly instead

    // __init__ seeds: current_proc = ql.argv[0]; the port takes it explicitly
    void set_proc(const std::string& name) { current_proc_ = name; }
    const std::string& current_proc() const { return current_proc_; }

    // the allproc list-head cell (set_allproc: the lazy load rides the cell)
    void set_allproc(std::uint64_t allprocs_addr);
    std::uint64_t allproc_addr() const { return allproc_addr_; }

    // add_process: the 1144-byte proc_t image on the heap (the p_list head
    // wiring rides the my_procs vector; the upstream also writes the
    // le_next/le_prev cells — the head/tail list update), the duplicate pid
    // logs and returns
    void add_process(std::int32_t pid, const std::string& name);

    // proc_find: the first my_procs entry with p_pid == pid
    const ProcRecord* proc_find(std::int32_t pid) const;

    // init_ev_ctx: the lazy label/ucred/vnode cells (the 501/501/501/15
    // posix cred verbatim); each returns the guest image address
    std::uint64_t ensure_label();
    std::uint64_t ensure_cred();
    std::uint64_t ensure_vnode();

    // the cred accessors the kauth handlers read (the cr_posix cells)
    std::uint32_t cred_uid() const;    // cr_posix.cr_uid
    std::uint32_t cred_rgid() const;   // cr_posix.cr_rgid

    // register/deregister: the (name, type) keyed callback list; ev_obj/idx
    // carry the set_params insert and protocol the socket-emitter filter
    void register_cb(std::uint64_t func_addr, const std::string& ev_name, MacOSEventType ev_type,
                     std::uint64_t ev_obj = 0, int ev_index = -1,
                     std::optional<std::uint64_t> protocol = std::nullopt);
    std::vector<const EvEntry*> get_events_by_name(const std::string& ev_name) const;
    std::vector<const EvEntry*> get_events_by_type(MacOSEventType ev_type) const;
    std::vector<const EvEntry*> get_events_by_type_and_proto(MacOSEventType ev_type,
                                                             std::uint64_t protocol) const;

    // emit: the params resolve through set_params (the ev_obj inserts at the
    // ev_index slot when one was registered). The RUN flag splits the path —
    // the live emulation stack-pushes the gen_stub_code trampoline (the
    // guest's next ret lands in it); the post-run queues a job for the
    // trigger() drain (macos.py: `if self.ql.os.RUN is True`)
    void emit(const std::string& ev_name, MacOSEventType ev_type, std::vector<std::uint64_t> params);
    // emit_by_type: the ins_cookie form replaces params[0] with the ipf
    // cookie registered for the event's name (the ipf_input/output cookie
    // swap); set_ipf_cookie feeds the table (the kext driver side)
    void emit_by_type(MacOSEventType ev_type, std::vector<std::uint64_t> params, bool ins_cookie = false);
    void emit_by_type_and_proto(MacOSEventType ev_type, std::uint64_t protocol,
                                std::vector<std::uint64_t> params);
    void set_ipf_cookie(const std::string& ev_name, std::uint64_t cookie);

    // the pending jobs (the RUN=false path — the driver queues instead of
    // stack-pushing) and the trigger that drains them: the params (<=6) land
    // in the ms64 arg registers, the extras stack-push (the upstream leaves
    // the stack unbalanced — verbatim), each job runs through
    // ql.run(begin=cb); the savedrip=deadcode ride is the kext-only branch
    // and defers with the kext slices (the default non-kext shape skips it
    // upstream too)
    void trigger();
    const std::vector<EvJob>& jobs() const { return jobs_; }
    void clear_jobs() { jobs_.clear(); }

    // ---- the socket-networking emitters (the macos.py half deferred from
    // the emit/trigger slice) ----

    // __init__ seeds: src 192.168.13.37:1337 / dst 10.2.13.38:1338 with the
    // babe c0de be57 / babe feed face macs (the ports stored in host order;
    // gen_sock writes the sin_port in network order)
    void set_src_host(const std::string& host) { src_host_ = host; }
    void set_src_port(std::uint16_t port) { src_port_ = port; }
    void set_src_mac(const std::string& mac) { src_mac_ = mac; }
    void set_dst_host(const std::string& host) { dst_host_ = host; }
    void set_dst_port(std::uint16_t port) { dst_port_ = port; }
    void set_dst_mac(const std::string& mac) { dst_mac_ = mac; }

    // the per-socket guest sockaddr_in_t images (gen_sock appends; the
    // emitters address them by index — the upstream's self.sockets list)
    void clear_socks() { sockets_.clear(); }
    std::size_t sockets_count() const { return sockets_.size(); }
    std::uint64_t socket_base(std::size_t idx) const { return sockets_.at(idx); }

    // gen_sock: the 16-byte sockaddr_in_t on the heap (sin_len=16,
    // sin_family=2, the network-order port, the dotted-quad address);
    // appends to the sockets list and returns the guest image address
    std::uint64_t gen_sock(const std::string& host, std::uint16_t port);

    // net_new_socket: the sflt_attach ride — emit EV_SFLT_ATTACH
    // [cookie_holder, 0] (the guest callback writes the cookie through the
    // holder pointer), trigger(), then read the cookie back (the upstream
    // allocates the holder on the heap when the caller passes 0)
    std::uint64_t net_new_socket(NetworkProtocol protocol, std::uint64_t cookie_holder = 0);

    // the kext control emitters: the sockaddr_ctl_t/mbuf_t/sockopt_t images
    // on the heap + the emit (RUN splits push/queue as usual)
    void ctl_connect(const std::string& nke_name, std::uint64_t unitinfo = 0);
    void ctl_disconnect(const std::string& nke_name, std::uint64_t unitinfo = 0);
    void ctl_send(const std::string& nke_name, const std::string& data);
    void ctl_setopt(const std::string& nke_name, std::uint64_t opt, const std::string& data,
                    std::uint64_t unitinfo = 0);
    void ctl_getopt(const std::string& nke_name, std::uint64_t opt, const std::string& data,
                    std::uint64_t unitinfo = 0);

    // the sflt connection emitters: the socket pair from the src/dst
    // endpoints + the notify cascade. The upstream net_connect_out reads an
    // unbound local `cookie` (a latent NameError — never exercised upstream);
    // the port takes it as the parameter (the documented deviation)
    void net_connect_out(NetworkProtocol protocol, std::uint64_t cookie);
    void net_connect_in(std::uint64_t cookie, NetworkProtocol protocol);
    void net_disconnect(std::uint64_t cookie, std::uint64_t so, NetworkProtocol protocol);
    void net_set_option(std::uint64_t cookie, std::uint64_t so, const std::string& data,
                        NetworkProtocol protocol);
    void net_get_option(std::uint64_t cookie, std::uint64_t so, const std::string& data,
                        NetworkProtocol protocol);

private:
    Qiling* ql_;
    std::vector<EvEntry> callbacks_;
    std::vector<ProcRecord> my_procs_;
    // the socket-emitter state (the __init__ seeds: the endpoints, the
    // sockets list; the ipf_cookie_ table above feeds emit_by_type's
    // ins_cookie swap)
    std::string src_host_ = "192.168.13.37";
    std::uint16_t src_port_ = 1337;
    std::string src_mac_ = "babec0debe57";
    std::string dst_host_ = "10.2.13.38";
    std::uint16_t dst_port_ = 1338;
    std::string dst_mac_ = "babefeedface";
    std::vector<std::uint64_t> sockets_;  // the guest sockaddr_in_t image addresses
    std::vector<EvJob> jobs_;
    std::map<std::string, std::uint64_t> ipf_cookie_;  // the ipf cookie per event name
    std::uint64_t allproc_addr_ = 0;
    bool allproc_set_ = false;
    std::string current_proc_;
    // the lazy ev-ctx cells (None until init_ev_ctx seeds them)
    std::uint64_t label_addr_ = 0;
    std::uint64_t cred_addr_ = 0;
    std::uint64_t vnode_addr_ = 0;
};

// events/macos_policy.py QlMacOSPolicy — the mpo_* fixture surface; the bank
// stays (the upstream dict is written by the kext fixtures, never read)
class QlOsPolicy {
public:
    QlOsPolicy(Qiling& ql, QlEvManager& manager) : ql_(&ql), manager_(manager) {}

    // mpo_file_check_mmap: the fileglob_t image + the emit
    void mpo_file_check_mmap(unsigned prot, unsigned flags, unsigned file_pos);

    std::uint64_t bank_get(const std::string& key, std::uint64_t fallback) const {
        const auto it = bank_.find(key);
        return it == bank_.end() ? fallback : it->second;
    }
    void bank_set(const std::string& key, std::uint64_t value) { bank_[key] = value; }

private:
    Qiling* ql_;
    QlEvManager& manager_;
    std::map<std::string, std::uint64_t> bank_;
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_EV_HPP
