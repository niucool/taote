// Ported from qiling/os/linux/thread.py QlLinuxThread — see the header note.
// The thread ids start at 2000 (the LINUX_THREAD_ID global) and increment;
// the set_child_tid write (the CLONE_CHILD_SETTID semantics) happens here.
#include "qiling/os/linux/thread.hpp"

#include "qiling/core.hpp"

namespace qiling {
namespace os {
namespace linux {

namespace {

// thread.py LINUX_THREAD_ID global
std::uint64_t linux_thread_id = 2000;

}  // namespace

QlLinuxThread::QlLinuxThread(Qiling* ql, std::uint64_t start_address, std::uint64_t exit_point,
                             void* context, std::uint64_t set_child_tid_addr, std::int64_t thread_id)
    : QlThread(ql),
      start_address_(start_address),
      exit_point_(exit_point),
      saved_context_(context) {
    if (thread_id < 0) {
        // thread.py new_thread_id
        thread_id_ = linux_thread_id++;
    } else {
        thread_id_ = static_cast<std::uint64_t>(thread_id);
    }

    // thread.py: set_child_tid writes the thread id at the address (the very
    // first thing a CLONE_CHILD_SETTID thread does)
    if (set_child_tid_addr != 0) {
        set_child_tid_address_ = set_child_tid_addr;
        ql->mem().write_ptr(set_child_tid_addr, static_cast<std::int64_t>(thread_id_), 4);
    }
}

}  // namespace linux
}  // namespace os
}  // namespace qiling
