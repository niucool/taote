// Ported from qiling/os/macos/mach_port.py + task.py + thread.py — the
// minimal mach-port/task/thread surfaces the syscall self-trap handlers
// ride (the loader's kext/msg machinery stays deferred; these are the plain
// value shapes).
//
//   mach_port.py MachPort            -> MachPort (a named port: the name)
//   mach_port.py MachPortManager     -> MachPortManager (the fixed-name
//                                       host/clock/semaphore/special ports)
//   task.py MachoTask                -> MachoTask (the id + the vm offsets)
//   thread.py QlMachoThread          -> MachoThread (the id + the port)
//
// The port's deviation note: the upstream's loader/macho.py run() creates
// these on the QlOs (macho_mach_port/macho_port_manager/macho_task/
// macho_thread); the port seeds them in the QlOsMacos ctor until the
// Mach-O loader slice lands (the shellcode fixtures need them).
#ifndef QILING_OS_MACOS_MACH_PORT_HPP
#define QILING_OS_MACOS_MACH_PORT_HPP

#include <cstdint>

namespace qiling {
namespace os {
namespace macos {

// mach_port.py MachPort (a named port)
struct MachPort {
    std::uint64_t name = 0;
};

// mach_port.py MachPortManager: the fixed-name ports (the upstream's ctor
// values verbatim) + the my_port handed in
struct MachPortManager {
    MachPort host_port{0x303};
    MachPort clock_port{0x803};
    MachPort semaphore_port{0x903};
    MachPort special_port{0x707};
    MachPort my_port{};
};

// task.py MachoTask (the id + the vm range bookkeeping)
struct MachoTask {
    std::uint64_t id = 9876;  // the upstream's "random id"
    std::uint64_t min_offset = 0x00000000;
    std::uint64_t max_offset = 0xFFE00000;
};

// thread.py QlMachoThread (the id + the port)
struct MachoThread {
    std::uint64_t id = 123;
    MachPort port{0x307};
};

// mach_port.py MachPortManager.get_thread_port (the thread's port name)
inline std::uint64_t get_thread_port(const MachoThread& thread) {
    return thread.port.name;
}

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_MACH_PORT_HPP
