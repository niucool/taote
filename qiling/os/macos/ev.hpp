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

// a pending emit job: the callback + the resolved params
struct EvJob {
    std::uint64_t func_addr = 0;
    std::vector<std::uint64_t> params;
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

private:
    Qiling* ql_;
    std::vector<EvEntry> callbacks_;
    std::vector<ProcRecord> my_procs_;
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
