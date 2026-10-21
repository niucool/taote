#include "qiling/os/windows/wdk_ioctl.hpp"

#include "qiling/loader/pe.hpp"

#include <algorithm>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/wdk_const.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

namespace {

constexpr std::uint32_t kIrpMjDeviceControl = IRP_MJ_DEVICE_CONTROL;
constexpr std::uint32_t kIrpMjWrite = IRP_MJ_WRITE;

void write_at(Qiling& ql, std::uint64_t addr, std::uint64_t value, std::size_t size) {
    ql.mem().write_ptr(addr, value, size);
}

}  // namespace

DriverObjectLayout driver_object_layout(int bits) {
    // DRIVER_OBJECT (winnt.h): Type@0, Size@2, DeviceObject@8, Flags@0x10,
    // DriverStart/Size/Section/Extension, DriverName (UNICODE_STRING),
    // HardwareDatabase, FastIoDispatch, DriverInit, DriverStartIo,
    // DriverUnload, then MajorFunction[28]
    if (bits == 64) {
        return {0x08, 0x68, 0x70};
    }
    return {0x04, 0x34, 0x38};
}

std::uint64_t driver_major_function(Qiling& ql, std::uint32_t major) {
    const auto* pe = static_cast<const loader::QlLoaderPE*>(&ql.loader());
    const auto base = pe->driver_object_address();
    if (base == 0) {
        return 0;
    }
    const auto layout = driver_object_layout(static_cast<int>(ql.arch().bits()));
    const auto ps = static_cast<std::size_t>(ql.arch().pointersize());
    return static_cast<std::uint64_t>(
        ql.mem().read_ptr(base + layout.major_function + static_cast<std::uint64_t>(major) * ps, ps));
}

std::uint64_t driver_device_object(Qiling& ql) {
    const auto* pe = static_cast<const loader::QlLoaderPE*>(&ql.loader());
    const auto base = pe->driver_object_address();
    if (base == 0) {
        return 0;
    }
    const auto layout = driver_object_layout(static_cast<int>(ql.arch().bits()));
    const auto ps = static_cast<std::size_t>(ql.arch().pointersize());
    return static_cast<std::uint64_t>(ql.mem().read_ptr(base + layout.device_object, ps));
}

std::uint32_t ioctl_code(std::uint32_t device_type, std::uint32_t function, std::uint32_t method,
                         std::uint32_t access) {
    return (device_type << 16) | (access << 14) | (function << 2) | method;
}

// The common body: build the IRP triple, hand it to the driver's dispatch, then
// read the results back out of the IRP. `major` picks which dispatch slot runs
// and `stack` writes the IO_STACK_LOCATION's Parameters union for that major
// function.
namespace {

struct IrpFrame {
    std::uint64_t irp = 0;
    std::uint64_t stack = 0;
    std::uint64_t system_buffer = 0;
    std::uint64_t output_buffer = 0;
    std::uint64_t mdl = 0;
    std::uint64_t mapped = 0;
};

// Stage the driver's dispatch call the way the loader drives a DllMain: a native
// frame with (DeviceObject, Irp) and a sentinel return address, then run until
// the sentinel. utils.py does the equivalent by setting the fcall params and
// calling ql.run(major_func); the until-address is what tells unicorn to stop at
// the return, so the run does not walk off into the sentinel cell.
void call_dispatch(Qiling& ql, std::uint64_t major_function, std::uint64_t device_object,
                   std::uint64_t irp) {
    auto& os = ql.os<os::windows::QlOsWindows>();
    auto sentinel = os.thread_manager_ret_addr();
    if (sentinel == 0) {
        // no thread manager cell yet (a bare test Qiling): place one, filled with
        // int3 so an unexpected jump there stops instead of executing garbage
        sentinel = os.heap().alloc(8);
        ql.mem().write(sentinel, std::vector<std::uint8_t>(8, 0xcc));
        os.set_thread_ret_addr(sentinel);
    }
    os.set_fcall_ptr(os.fcall_select(WinCc::Stdcall));
    os.fcall().call_native(major_function,
                           {{static_cast<int>(os::api::LPVOID_), device_object},
                            {static_cast<int>(os::api::LPVOID_), irp}},
                           sentinel);
    ql.emu_start(major_function, sentinel);
}

}  // namespace

IoctlResult ioctl(Qiling& ql, std::uint32_t ctl_code, std::uint32_t output_buffer_size,
                  const std::string& input_buffer) {
    const auto major = driver_major_function(ql, kIrpMjDeviceControl);
    if (major == 0) {
        throw QlErrorSyscallError("null MajorFunction field");
    }

    const auto bits = static_cast<int>(ql.arch().bits());
    const auto ps = static_cast<std::size_t>(ql.arch().pointersize());
    auto& heap = ql.os<os::windows::QlOsWindows>().heap();
    auto& mem = ql.mem();

    std::vector<std::uint64_t> allocations;
    const auto alloc = [&](std::size_t size) {
        const auto a = heap.alloc(std::max<std::size_t>(size, 1));
        allocations.push_back(a);
        return a;
    };

    const auto input_buffer_size = static_cast<std::uint32_t>(input_buffer.size());
    const auto input_buffer_addr = alloc(input_buffer_size);
    mem.write(input_buffer_addr,
              std::vector<std::uint8_t>(input_buffer.begin(), input_buffer.end()));

    const auto output_buffer_addr = alloc(output_buffer_size);

    const auto system_buffer_size = std::max(input_buffer_size, output_buffer_size);
    const auto system_buffer_addr = alloc(system_buffer_size);
    mem.write(system_buffer_addr,
              std::vector<std::uint8_t>(input_buffer.begin(), input_buffer.end()));

    // IRP + IO_STACK_LOCATION + (for the direct methods) an MDL
    IrpFrame f;
    const auto irp_size = bits == 64 ? 0xd0u : 0x74u;
    const auto stack_size = bits == 64 ? 0x48u : 0x24u;
    const auto mdl_size = bits == 64 ? 0x30u : 0x1cu;

    f.irp = alloc(irp_size);
    f.stack = alloc(stack_size);
    f.system_buffer = system_buffer_addr;
    f.output_buffer = output_buffer_addr;

    const auto method = static_cast<std::uint32_t>(ctl_code & 0x3u);

    if (method == METHOD_IN_DIRECT || method == METHOD_OUT_DIRECT) {
        f.mdl = alloc(mdl_size);
        f.mapped = alloc(output_buffer_size);
        // MDL: MappedSystemVa/StartVa point at the same block, ByteCount is the
        // output size, ByteOffset 0
        const auto mapped_off = bits == 64 ? 0x18u : 0x0cu;
        const auto start_off = bits == 64 ? 0x20u : 0x10u;
        const auto count_off = bits == 64 ? 0x28u : 0x14u;
        write_at(ql, f.mdl + mapped_off, f.mapped, ps);
        write_at(ql, f.mdl + start_off, f.mapped, ps);
        write_at(ql, f.mdl + count_off, output_buffer_size, 4);
    } else if (method == METHOD_NEITHER) {
        // UserBuffer carries the output block for METHOD_NEITHER
    }

    // IO_STACK_LOCATION.Parameters.DeviceIoControl
    const auto out_len_off = bits == 64 ? 0x08u : 0x04u;
    const auto in_len_off = bits == 64 ? 0x10u : 0x08u;
    const auto code_off = bits == 64 ? 0x18u : 0x0cu;
    const auto type3_off = bits == 64 ? 0x20u : 0x10u;
    write_at(ql, f.stack + out_len_off, output_buffer_size, ps);
    write_at(ql, f.stack + in_len_off, input_buffer_size, ps);
    write_at(ql, f.stack + code_off, ctl_code, 4);
    write_at(ql, f.stack + type3_off, input_buffer_addr, ps);

    // IRP fields
    const auto mdl_off = bits == 64 ? 0x08u : 0x04u;
    const auto assoc_off = bits == 64 ? 0x18u : 0x0cu;
    const auto user_buffer_off = bits == 64 ? 0x70u : 0x3cu;
    const auto irpstack_off = bits == 64 ? 0xb8u : 0x64u;
    if (f.mdl != 0) {
        write_at(ql, f.irp + mdl_off, f.mdl, ps);
    }
    if (method == METHOD_NEITHER) {
        write_at(ql, f.irp + user_buffer_off, f.output_buffer, ps);
    }
    write_at(ql, f.irp + assoc_off, f.system_buffer, ps);
    write_at(ql, f.irp + irpstack_off, f.stack, ps);

    call_dispatch(ql, major, driver_device_object(ql), f.irp);

    // read the outcome back
    const auto status_off = bits == 64 ? 0x30u : 0x18u;
    const auto info_off = bits == 64 ? 0x38u : 0x1cu;
    IoctlResult out;
    out.status = static_cast<std::int32_t>(mem.read_ptr(f.irp + status_off, 4));
    out.information = static_cast<std::uint64_t>(mem.read_ptr(f.irp + info_off, ps));

    if (out.status >= 0 && out.information != 0) {
        std::uint64_t from = 0;
        if (method == METHOD_BUFFERED) {
            from = f.system_buffer;
        } else if (method == METHOD_IN_DIRECT || method == METHOD_OUT_DIRECT) {
            const auto mapped = static_cast<std::uint64_t>(mem.read_ptr(
                f.mdl + (bits == 64 ? 0x18u : 0x0cu), ps));
            from = mapped;
        } else {
            from = f.output_buffer;
        }
        const auto n = static_cast<std::size_t>(out.information);
        const auto bytes = mem.read(from, n);
        out.output.assign(bytes.begin(), bytes.end());
    }

    for (const auto a : allocations) {
        try {
            heap.free(a);
        } catch (...) {
        }
    }

    return out;
}

std::uint64_t io_write(Qiling& ql, const std::string& buffer) {
    const auto major = driver_major_function(ql, kIrpMjWrite);
    if (major == 0) {
        throw QlErrorSyscallError("null MajorFunction field");
    }

    const auto bits = static_cast<int>(ql.arch().bits());
    const auto ps = static_cast<std::size_t>(ql.arch().pointersize());
    auto& heap = ql.os<os::windows::QlOsWindows>().heap();
    auto& mem = ql.mem();

    const auto data = heap.alloc(std::max<std::size_t>(buffer.size(), 1));
    mem.write(data, std::vector<std::uint8_t>(buffer.begin(), buffer.end()));
    const auto irp_size = bits == 64 ? 0xd0u : 0x74u;
    const auto stack_size = bits == 64 ? 0x48u : 0x24u;
    const auto irp = heap.alloc(irp_size);
    const auto stack = heap.alloc(stack_size);

    // IO_STACK_LOCATION.Parameters.Write.Length
    write_at(ql, stack + (bits == 64 ? 0x08u : 0x04u), buffer.size(), ps);
    write_at(ql, irp + (bits == 64 ? 0x18u : 0x0cu), data, ps);
    write_at(ql, irp + (bits == 64 ? 0xb8u : 0x64u), stack, ps);

    call_dispatch(ql, major, driver_device_object(ql), irp);

    const auto info = static_cast<std::uint64_t>(
        mem.read_ptr(irp + (bits == 64 ? 0x38u : 0x1cu), ps));
    try {
        heap.free(stack);
        heap.free(irp);
        heap.free(data);
    } catch (...) {
    }
    return info;
}

}  // namespace win
}  // namespace os
}  // namespace qiling
