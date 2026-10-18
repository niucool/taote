// Ported from qiling/os/macos/events/macos.py and events/macos_policy.py.
// The proc_t/ucred_t/label_t/vnode_t/fileglob_t guest images are built from
// the upstream ctypes field offsets (the port pins them with static_asserts
// in macos_structs.hpp); the port's cr_ref cell uses the 4-byte shape (the
// upstream's c_ulong splits 4/8 by host platform — the port pins the 4-byte
// shape consistently for writer and reader).
#include "qiling/os/macos/ev.hpp"

#include <algorithm>

#include "qiling/core.hpp"
#include "qiling/os/macos/macos.hpp"
#include "qiling/os/macos/utils.hpp"
#include "qiling/os/posix/posix.hpp"

namespace qiling {
namespace os {
namespace macos {

namespace {

// the struct field offsets (the ctypes census; pinned against the
// static_asserts in macos_structs.hpp)
constexpr std::size_t kProcSize = 1144;
constexpr std::size_t kProcPid = 16;
constexpr std::size_t kProcPpid = 40;
constexpr std::size_t kProcPgrpid = 44;
constexpr std::size_t kProcFlag = 400;
constexpr std::size_t kProcUcred = 304;
constexpr std::size_t kProcComm = 728;   // c_char * 17
constexpr std::size_t kProcName = 745;   // c_char * 33
constexpr std::size_t kUcredSize = 144;
constexpr std::size_t kUcredRef = 16;    // cr_ref (the pinned 4-byte shape)
constexpr std::size_t kUcredPosix = 20;  // cr_posix
constexpr std::size_t kPcredUid = 0;
constexpr std::size_t kPcredRgid = 80;
constexpr std::size_t kLabelSize = 64;
constexpr std::size_t kVnodeSize = 400;

void write_u32(std::vector<std::uint8_t>& buf, std::size_t at, std::uint32_t v) {
    buf[at + 0] = static_cast<std::uint8_t>(v);
    buf[at + 1] = static_cast<std::uint8_t>(v >> 8);
    buf[at + 2] = static_cast<std::uint8_t>(v >> 16);
    buf[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

void write_u64(std::vector<std::uint8_t>& buf, std::size_t at, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
    }
}

}  // namespace

QlEvManager::QlEvManager(Qiling& ql) : ql_(&ql) {}

void QlEvManager::set_allproc(std::uint64_t allprocs_addr) {
    // set_allproc clears my_procs and re-reads the head cell lazily; the
    // port keeps the cell address (the loadFromMem walk lands with the
    // kernel-syscall slice that reads the chain back)
    allproc_addr_ = allprocs_addr;
    allproc_set_ = true;
    my_procs_.clear();
}

void QlEvManager::add_process(std::int32_t pid, const std::string& name) {
    for (const auto& p : my_procs_) {
        if (p.pid == pid) {
            // "Duplicated process"
            return;
        }
    }

    auto& heap = ql_->os<posix::QlOsPosix>().heap();
    const auto base = heap.alloc(kProcSize);
    std::vector<std::uint8_t> image(kProcSize, 0);

    write_u32(image, kProcPid, static_cast<std::uint32_t>(pid));
    write_u32(image, kProcPpid, 1);
    write_u32(image, kProcPgrpid, static_cast<std::uint32_t>(pid));
    write_u32(image, kProcFlag, 0x00000004);  // 64 bit process
    write_u64(image, kProcUcred, heap.alloc(kUcredSize));  // p_ucred

    // p_comm = name + NUL pad to 17; p_name = p_comm + NUL pad to 33
    const auto comm = name.substr(0, 16);
    for (std::size_t i = 0; i < comm.size(); ++i) {
        image[kProcComm + i] = static_cast<std::uint8_t>(comm[i]);
    }
    image[kProcComm + comm.size()] = 0;
    for (std::size_t i = 0; i < 17; ++i) {
        image[kProcName + i] = image[kProcComm + i];
    }

    ql_->mem().write(base, image);

    if (my_procs_.empty()) {
        // allproc.lh_first = the new proc; the upstream writes the head cell
        // through the set_allproc-loaded list_head — the port writes the
        // cell directly when the address is known (set_allproc precedes)
        if (allproc_set_) {
            std::vector<std::uint8_t> head(8, 0);
            write_u64(head, 0, base);
            ql_->mem().write(allproc_addr_, head);
        }
        my_procs_.push_back(ProcRecord{pid, base});
        return;
    }

    // the tail chain: prev.p_list.le_next = the new base; new.p_list.le_prev
    // = the prev base (both 8-byte cells through the 16-byte list_entry at 0)
    const auto prev_base = my_procs_.back().base;
    {
        std::vector<std::uint8_t> cell(8, 0);
        write_u64(cell, 0, base);
        ql_->mem().write(prev_base + 0, cell);  // le_next
    }
    {
        std::vector<std::uint8_t> cell(8, 0);
        write_u64(cell, 0, prev_base);
        ql_->mem().write(base + 8, cell);  // le_prev
    }
    my_procs_.push_back(ProcRecord{pid, base});
}

const ProcRecord* QlEvManager::proc_find(std::int32_t pid) const {
    for (const auto& p : my_procs_) {
        if (p.pid == pid) {
            return &p;
        }
    }
    return nullptr;
}

std::uint64_t QlEvManager::ensure_label() {
    if (label_addr_ == 0) {
        auto& heap = ql_->os<posix::QlOsPosix>().heap();
        label_addr_ = heap.alloc(kLabelSize);
        std::vector<std::uint8_t> image(kLabelSize, 0);
        write_u32(image, 0, 1);  // l_flags = 1
        ql_->mem().write(label_addr_, image);
    }
    return label_addr_;
}

std::uint64_t QlEvManager::ensure_cred() {
    if (cred_addr_ == 0) {
        ensure_label();
        auto& heap = ql_->os<posix::QlOsPosix>().heap();
        cred_addr_ = heap.alloc(kUcredSize);
        std::vector<std::uint8_t> image(kUcredSize, 0);
        // cr_ref = 2; the posix cred (501/501/501/15/groups/20/20/501/2)
        write_u32(image, kUcredRef, 2);
        write_u32(image, kUcredPosix + 0, 501);   // cr_uid
        write_u32(image, kUcredPosix + 4, 501);   // cr_ruid
        write_u32(image, kUcredPosix + 8, 501);   // cr_svuid
        image[kUcredPosix + 12] = 15;             // cr_ngroups (short)
        image[kUcredPosix + 13] = 0;
        // cr_groups[0..15] = the pyarr — index 0..5 ride 20/12/61/79/80/81,
        // the rest zero (the upstream array is 16 wide, the tail zeros)
        const std::uint32_t groups[] = {20, 12, 61, 79, 80, 81};
        for (int i = 0; i < 6; ++i) {
            write_u32(image, kUcredPosix + 16 + 4 * i, groups[i]);
        }
        write_u32(image, kUcredPosix + 80, 20);   // cr_rgid
        write_u32(image, kUcredPosix + 84, 20);   // cr_svgid
        write_u32(image, kUcredPosix + 88, 501);  // cr_gmuid
        write_u32(image, kUcredPosix + 92, 2);    // cr_flags
        write_u64(image, 120, label_addr_);  // cr_label = POINTER64(label)
        ql_->mem().write(cred_addr_, image);
    }
    return cred_addr_;
}

std::uint64_t QlEvManager::ensure_vnode() {
    if (vnode_addr_ == 0) {
        auto& heap = ql_->os<posix::QlOsPosix>().heap();
        vnode_addr_ = heap.alloc(kVnodeSize);
        // v_name rides a separate buffer carrying current_proc
        const auto name_addr = heap.alloc(current_proc_.size());
        ql_->mem().write(name_addr,
                         std::vector<std::uint8_t>(current_proc_.begin(), current_proc_.end()));
        std::vector<std::uint8_t> image(kVnodeSize, 0);
        // v_name at 344 (the census) — write_u64 over the pointer cell
        write_u64(image, 344, name_addr);
        ql_->mem().write(vnode_addr_, image);
    }
    return vnode_addr_;
}

std::uint32_t QlEvManager::cred_uid() const {
    if (cred_addr_ == 0) {
        return 0;
    }
    const auto data = ql_->mem().read(cred_addr_ + kUcredPosix + kPcredUid, 4);
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint32_t QlEvManager::cred_rgid() const {
    if (cred_addr_ == 0) {
        return 0;
    }
    const auto data = ql_->mem().read(cred_addr_ + kUcredPosix + kPcredRgid, 4);
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

void QlEvManager::register_cb(std::uint64_t func_addr, const std::string& ev_name, MacOSEventType ev_type,
                              std::uint64_t ev_obj, int ev_index, std::optional<std::uint64_t> protocol) {
    callbacks_.push_back(EvEntry{ev_name, ev_type, func_addr, ev_obj, ev_index, protocol});
}

std::vector<const EvEntry*> QlEvManager::get_events_by_name(const std::string& ev_name) const {
    std::vector<const EvEntry*> found;
    for (const auto& cb : callbacks_) {
        if (cb.name == ev_name) {
            found.push_back(&cb);
        }
    }
    return found;
}

std::vector<const EvEntry*> QlEvManager::get_events_by_type(MacOSEventType ev_type) const {
    std::vector<const EvEntry*> found;
    for (const auto& cb : callbacks_) {
        if (cb.type == ev_type) {
            found.push_back(&cb);
        }
    }
    return found;
}

std::vector<const EvEntry*> QlEvManager::get_events_by_type_and_proto(MacOSEventType ev_type,
                                                                      std::uint64_t protocol) const {
    std::vector<const EvEntry*> found;
    for (const auto& cb : callbacks_) {
        if (cb.type == ev_type && cb.protocol.has_value() && *cb.protocol == protocol) {
            found.push_back(&cb);
        }
    }
    return found;
}

// utils.py set_params: the event object inserts at the ev_index slot when
// one was registered (the QlMacOSEv.event.base goes into the params list)
static std::vector<std::uint64_t> set_params(const EvEntry& ev, std::vector<std::uint64_t> params) {
    if (ev.ev_index != -1 && ev.ev_obj != 0) {
        params.insert(params.begin() + static_cast<std::ptrdiff_t>(ev.ev_index), ev.ev_obj);
    }
    return params;
}

void QlEvManager::emit(const std::string& ev_name, MacOSEventType ev_type, std::vector<std::uint64_t> params) {
    // get_event_by_name_and_type: the first (name, type) match
    const EvEntry* found = nullptr;
    for (const auto& cb : callbacks_) {
        if (cb.name == ev_name && cb.type == ev_type) {
            found = &cb;
            break;
        }
    }
    if (found == nullptr) {
        // "No callbacks found for (%s, %s)"
        return;
    }
    const auto resolved = set_params(*found, std::move(params));
    // macos.py: `if self.ql.os.RUN is True: stack_push(gen_stub_code(...))`
    // else the job queues for the trigger drain
    if (ql_->os<QlOsMacos>().RUN) {
        const auto stub = gen_stub_code(*ql_, resolved, found->func_addr);
        ql_->stack_push(stub);
    } else {
        jobs_.push_back(EvJob{found->func_addr, std::move(resolved)});
    }
}

void QlEvManager::emit_by_type(MacOSEventType ev_type, std::vector<std::uint64_t> params, bool ins_cookie) {
    for (const auto& cb : callbacks_) {
        if (cb.type == ev_type) {
            auto resolved = set_params(cb, params);
            // macos.py: `if ins_cookie is True and ev.name in self.ipf_cookie:
            //            params[0] = self.ipf_cookie[ev.name]`
            if (ins_cookie) {
                const auto it = ipf_cookie_.find(cb.name);
                if (it != ipf_cookie_.end()) {
                    resolved[0] = it->second;
                }
            }
            if (ql_->os<QlOsMacos>().RUN) {
                const auto stub = gen_stub_code(*ql_, resolved, cb.func_addr);
                ql_->stack_push(stub);
            } else {
                jobs_.push_back(EvJob{cb.func_addr, std::move(resolved)});
            }
        }
    }
}

void QlEvManager::emit_by_type_and_proto(MacOSEventType ev_type, std::uint64_t protocol,
                                         std::vector<std::uint64_t> params) {
    for (const auto* cb : get_events_by_type_and_proto(ev_type, protocol)) {
        const auto resolved = set_params(*cb, params);
        if (ql_->os<QlOsMacos>().RUN) {
            const auto stub = gen_stub_code(*ql_, resolved, cb->func_addr);
            ql_->stack_push(stub);
        } else {
            jobs_.push_back(EvJob{cb->func_addr, std::move(resolved)});
        }
    }
}

void QlEvManager::set_ipf_cookie(const std::string& ev_name, std::uint64_t cookie) {
    ipf_cookie_[ev_name] = cookie;
}

// events/macos.py trigger: the params (<=6) land in the ms64 arg registers,
// the extras stack-push (the upstream leaves the stack unbalanced —
// verbatim), and each job runs through ql.run(begin=cb). The
// savedrip=deadcode line is the kext-only branch (the default non-kext
// shape skips it upstream too); it defers with the kext slices.
void QlEvManager::trigger() {
    static const std::uint64_t reg_list[6] = {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                                              UC_X86_REG_RCX, UC_X86_REG_R8,  UC_X86_REG_R9};
    for (const auto& job : jobs_) {
        const auto& params = job.params;
        if (params.size() <= 6) {
            for (std::size_t idx = 0; idx < params.size(); ++idx) {
                ql_->arch().regs().write(reg_list[idx], params[idx]);
            }
        } else {
            for (std::size_t idx = 0; idx < 6; ++idx) {
                ql_->arch().regs().write(reg_list[idx], params[idx]);
            }
            const auto remains = params.size() - 6;
            for (std::size_t i = 0; i < remains; ++i) {
                ql_->stack_push(params[6 + i]);
            }
        }
        ql_->run(job.func_addr);
    }
    jobs_.clear();
}

void QlOsPolicy::mpo_file_check_mmap(unsigned prot, unsigned flags, unsigned file_pos) {
    const auto cred = manager_.ensure_cred();
    const auto vnode = manager_.ensure_vnode();
    auto& heap = ql_->os<posix::QlOsPosix>().heap();
    // fileglob_t: fg_flag/fg_count/fg_msgcount/fg_lflags (16) + fg_cred/fg_data
    const auto fg = heap.alloc(32);
    std::vector<std::uint8_t> image(32, 0);
    write_u32(image, 0, 1);  // fg_flag
    write_u32(image, 4, 1);  // fg_count
    write_u64(image, 16, cred);
    write_u64(image, 24, vnode);
    ql_->mem().write(fg, image);

    manager_.emit_by_type(MacOSEventType::EV_MAC_mpo_file_check_mmap,
                          {cred, fg, manager_.ensure_label(), prot, flags, file_pos, 0});
}

}  // namespace macos
}  // namespace os
}  // namespace qiling
