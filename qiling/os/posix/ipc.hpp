// Ported from qiling/os/posix/msq.py (QlMsgBuf/QlMsqId/QlMsq), shm.py
// (QlShmId/QlShm) and syscall/{msg,shm}.py (the msgget/msgsnd/msgrcv and
// the shmget/shmat/shmdt bodies). The message queues and the shm segments
// ride the port's in-memory emulation (the upstream rides the host
// select.epoll-free structures too — the msq queue is the deque with the
// maxlen MSGMNB, the shm rides the guest mem maps).
#pragma once

#ifndef QILING_OS_POSIX_IPC_HPP
#define QILING_OS_POSIX_IPC_HPP

#include <deque>
#include <map>
#include <vector>

namespace qiling {
namespace os {
namespace posix {

// const.py IPC_*/MSG_*/SHM_* (the bit tables the bodies walk)
namespace ipc {
inline constexpr std::uint64_t kPrivate = 0;
inline constexpr std::uint64_t kCreat = 0x200;
inline constexpr std::uint64_t kExcl = 0x400;
inline constexpr std::uint64_t kNowait = 0x800;

inline constexpr std::uint64_t kMsgNoError = 0x1000;
inline constexpr std::uint64_t kMsgExcept = 0x2000;
inline constexpr std::uint64_t kMsgCopy = 0x4000;

inline constexpr std::uint64_t kShmW = 0x80;
inline constexpr std::uint64_t kShmR = 0x100;
inline constexpr std::uint64_t kShmRdonly = 0x1000;
inline constexpr std::uint64_t kShmRnd = 0x2000;
inline constexpr std::uint64_t kShmExec = 0x10000;

inline constexpr std::size_t kMsgMni = 32000;
inline constexpr std::size_t kMsgMnb = 16384;
inline constexpr std::size_t kShmMni = 4096;
}  // namespace ipc

// msq.py QlMsgBuf — the (mtype, mtext) pair
struct MsqBuf {
    std::uint64_t mtype = 0;
    std::vector<std::uint8_t> mtext;
};

// msq.py QlMsqId — the ipc64_perm reflection + the maxlen'd queue
class MsqId {
public:
    MsqId() = default;
    MsqId(std::int64_t key, int uid, int gid, std::uint64_t mode)
        : key_(key), uid_(uid), gid_(gid), mode_(mode) {}

    std::int64_t key() const noexcept { return key_; }
    int uid() const noexcept { return uid_; }
    int gid() const noexcept { return gid_; }
    std::uint64_t mode() const noexcept { return mode_; }

    std::deque<MsqBuf>& queue() noexcept { return queue_; }
    const std::deque<MsqBuf>& queue() const noexcept { return queue_; }

private:
    std::int64_t key_;
    int uid_;
    int gid_;
    std::uint64_t mode_;
    std::deque<MsqBuf> queue_;
};

// msq.py QlMsq — the id-keyed map (the ids ride 0x0F000000 + 0x1000 steps)
class Msq {
public:
    std::int64_t add(MsqId&& msq) {
        const auto id = next_id_;
        msqs_[id] = std::move(msq);
        next_id_ += 0x1000;
        return id;
    }

    void remove(std::int64_t msqid) { msqs_.erase(msqid); }

    std::pair<std::int64_t, MsqId*> get_by_key(std::int64_t key) {
        for (auto& [id, msq] : msqs_) {
            if (msq.key() == key) {
                return {id, &msq};
            }
        }
        return {-1, nullptr};
    }

    MsqId* get_by_id(std::int64_t msqid) {
        const auto it = msqs_.find(msqid);
        return it == msqs_.end() ? nullptr : &it->second;
    }

    std::size_t size() const noexcept { return msqs_.size(); }

private:
    std::map<std::int64_t, MsqId> msqs_;
    std::int64_t next_id_ = 0x0F000000;
};

// shm.py QlShmId — the ipc64_perm reflection + the segment size + the
// attachment tracking
class ShmId {
public:
    ShmId() = default;
    ShmId(std::int64_t key, int uid, int gid, std::uint64_t mode, std::uint64_t segsz)
        : key_(key), uid_(uid), gid_(gid), mode_(mode), segsz_(segsz) {}

    std::int64_t key() const noexcept { return key_; }
    int uid() const noexcept { return uid_; }
    int gid() const noexcept { return gid_; }
    std::uint64_t mode() const noexcept { return mode_; }
    std::uint64_t segsz() const noexcept { return segsz_; }

    std::vector<std::uint64_t>& attach() noexcept { return attach_; }
    const std::vector<std::uint64_t>& attach() const noexcept { return attach_; }

private:
    std::int64_t key_;
    int uid_;
    int gid_;
    std::uint64_t mode_;
    std::uint64_t segsz_;
    std::vector<std::uint64_t> attach_;
};

// shm.py QlShm — the id-keyed map
class Shm {
public:
    std::int64_t add(ShmId&& shm) {
        const auto id = next_id_;
        shms_[id] = std::move(shm);
        next_id_ += 0x1000;
        return id;
    }

    void remove(std::int64_t shmid) { shms_.erase(shmid); }

    std::pair<std::int64_t, ShmId*> get_by_key(std::int64_t key) {
        for (auto& [id, shm] : shms_) {
            if (shm.key() == key) {
                return {id, &shm};
            }
        }
        return {-1, nullptr};
    }

    ShmId* get_by_id(std::int64_t shmid) {
        const auto it = shms_.find(shmid);
        return it == shms_.end() ? nullptr : &it->second;
    }

    ShmId* get_by_attaddr(std::uint64_t shmaddr) {
        for (auto& [id, shm] : shms_) {
            for (const auto addr : shm.attach()) {
                if (addr == shmaddr) {
                    return &shm;
                }
            }
        }
        return nullptr;
    }

    std::size_t size() const noexcept { return shms_.size(); }

private:
    std::map<std::int64_t, ShmId> shms_;
    std::int64_t next_id_ = 0x0F000000;
};

}  // namespace posix
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_POSIX_IPC_HPP
