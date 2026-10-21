// Ported from qiling/os/windows/utils.py: io_Write / io_Read / ioctl — the
// IRP plumbing a driver case rides (test_pe_sys.py's sioctl.sys asserts on it).
//
// The layout constants are the winnt.h structures at the two guest widths, which
// is what upstream's make_irp / make_io_stack_location / make_mdl build through
// ctypes:
//
//   IRP (x64)          MdlAddress@0x08  AssociatedIrp.SystemBuffer@0x18
//                      IoStatus.Status@0x30  IoStatus.Information@0x38
//                      UserBuffer@0x70  irpstack@0xb8   (size 0xd0)
//   IRP (x86)          MdlAddress@0x04  AssociatedIrp.SystemBuffer@0x0c
//                      IoStatus.Status@0x18  IoStatus.Information@0x1c
//                      UserBuffer@0x3c  irpstack@0x64   (size 0x74)
//   IO_STACK_LOCATION  Parameters.DeviceIoControl: OutputBufferLength at
//                      +0x08, InputBufferLength at +0x10, IoControlCode at
//                      +0x18, Type3InputBuffer at +0x20; DeviceObject, then
//                      FileObject/CompletionRoutine/Context follow
//   MDL                MappedSystemVa@0x18 (x64) / 0x0c (x86)
//
// The driver object itself is DRIVER_OBJECT: DeviceObject@0x08 and the
// MajorFunction table at 0x70 (x64) / 0x38 (x86), DriverUnload just before it.
#ifndef QILING_OS_WINDOWS_WDK_IOCTL_HPP
#define QILING_OS_WINDOWS_WDK_IOCTL_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>

namespace qiling {

class Qiling;

namespace os {
namespace win {

// DRIVER_OBJECT field offsets
struct DriverObjectLayout {
    std::uint64_t device_object;
    std::uint64_t driver_unload;
    std::uint64_t major_function;  // the table base (28 pointer slots)
};
DriverObjectLayout driver_object_layout(int bits);

// the MajorFunction slot for one IRP major function, read from the guest
std::uint64_t driver_major_function(Qiling& ql, std::uint32_t major);
// DRIVER_OBJECT.DeviceObject
std::uint64_t driver_device_object(Qiling& ql);

// the IOCTL result shape upstream's ioctl returns: (status, information,
// output data)
struct IoctlResult {
    std::int32_t status = 0;
    std::uint64_t information = 0;
    std::string output;
};

// utils.py ioctl: build an IRP for the given (IoControlCode, output buffer size,
// input buffer) triple, call the driver's IRP_MJ_DEVICE_CONTROL handler, and read
// back the status/information/output the handler left in it. Throws
// QlErrorSyscallError when the driver registered no handler (the upstream shape).
IoctlResult ioctl(Qiling& ql, std::uint32_t ioctl_code, std::uint32_t output_buffer_size,
                  const std::string& input_buffer);

// utils.py io_Write: an IRP_MJ_WRITE to the driver; answers the number of bytes
// the handler reported.
std::uint64_t io_write(Qiling& ql, const std::string& buffer);

// the IOCTL code macro (winioctl.h CTL_CODE)
std::uint32_t ioctl_code(std::uint32_t device_type, std::uint32_t function, std::uint32_t method,
                         std::uint32_t access);

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_WDK_IOCTL_HPP
