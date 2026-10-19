// Ported from qiling/os/windows/wdk_const.py - the WDK/NT constant tables
// (the IRP major functions, the device types, the IOCTL bases). Scalar
// entries verbatim; each definition #ifndef-guarded for the windows.h
// macro collisions (the const.hpp precedent).
#ifndef QILING_OS_WINDOWS_WDK_CONST_HPP
#define QILING_OS_WINDOWS_WDK_CONST_HPP

#include <cstdint>

namespace qiling {
namespace os {
namespace win {

#ifndef PROCESSOR_FEATURE_MAX
inline constexpr std::uint32_t PROCESSOR_FEATURE_MAX = 64u;
#endif
#ifndef MAX_WOW64_SHARED_ENTRIES
inline constexpr std::uint32_t MAX_WOW64_SHARED_ENTRIES = 16u;
#endif
#ifndef IRP_MJ_CREATE
inline constexpr std::uint32_t IRP_MJ_CREATE = 0x00;
#endif
#ifndef IRP_MJ_CREATE_NAMED_PIPE
inline constexpr std::uint32_t IRP_MJ_CREATE_NAMED_PIPE = 0x01;
#endif
#ifndef IRP_MJ_CLOSE
inline constexpr std::uint32_t IRP_MJ_CLOSE = 0x02;
#endif
#ifndef IRP_MJ_READ
inline constexpr std::uint32_t IRP_MJ_READ = 0x03;
#endif
#ifndef IRP_MJ_WRITE
inline constexpr std::uint32_t IRP_MJ_WRITE = 0x04;
#endif
#ifndef IRP_MJ_QUERY_INFORMATION
inline constexpr std::uint32_t IRP_MJ_QUERY_INFORMATION = 0x05;
#endif
#ifndef IRP_MJ_SET_INFORMATION
inline constexpr std::uint32_t IRP_MJ_SET_INFORMATION = 0x06;
#endif
#ifndef IRP_MJ_QUERY_EA
inline constexpr std::uint32_t IRP_MJ_QUERY_EA = 0x07;
#endif
#ifndef IRP_MJ_SET_EA
inline constexpr std::uint32_t IRP_MJ_SET_EA = 0x08;
#endif
#ifndef IRP_MJ_FLUSH_BUFFERS
inline constexpr std::uint32_t IRP_MJ_FLUSH_BUFFERS = 0x09;
#endif
#ifndef IRP_MJ_QUERY_VOLUME_INFORMATION
inline constexpr std::uint32_t IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0a;
#endif
#ifndef IRP_MJ_SET_VOLUME_INFORMATION
inline constexpr std::uint32_t IRP_MJ_SET_VOLUME_INFORMATION = 0x0b;
#endif
#ifndef IRP_MJ_DIRECTORY_CONTROL
inline constexpr std::uint32_t IRP_MJ_DIRECTORY_CONTROL = 0x0c;
#endif
#ifndef IRP_MJ_FILE_SYSTEM_CONTROL
inline constexpr std::uint32_t IRP_MJ_FILE_SYSTEM_CONTROL = 0x0d;
#endif
#ifndef IRP_MJ_DEVICE_CONTROL
inline constexpr std::uint32_t IRP_MJ_DEVICE_CONTROL = 0x0e;
#endif
#ifndef IRP_MJ_INTERNAL_DEVICE_CONTROL
inline constexpr std::uint32_t IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0f;
#endif
#ifndef IRP_MJ_SHUTDOWN
inline constexpr std::uint32_t IRP_MJ_SHUTDOWN = 0x10;
#endif
#ifndef IRP_MJ_LOCK_CONTROL
inline constexpr std::uint32_t IRP_MJ_LOCK_CONTROL = 0x11;
#endif
#ifndef IRP_MJ_CLEANUP
inline constexpr std::uint32_t IRP_MJ_CLEANUP = 0x12;
#endif
#ifndef IRP_MJ_CREATE_MAILSLOT
inline constexpr std::uint32_t IRP_MJ_CREATE_MAILSLOT = 0x13;
#endif
#ifndef IRP_MJ_QUERY_SECURITY
inline constexpr std::uint32_t IRP_MJ_QUERY_SECURITY = 0x14;
#endif
#ifndef IRP_MJ_SET_SECURITY
inline constexpr std::uint32_t IRP_MJ_SET_SECURITY = 0x15;
#endif
#ifndef IRP_MJ_POWER
inline constexpr std::uint32_t IRP_MJ_POWER = 0x16;
#endif
#ifndef IRP_MJ_SYSTEM_CONTROL
inline constexpr std::uint32_t IRP_MJ_SYSTEM_CONTROL = 0x17;
#endif
#ifndef IRP_MJ_DEVICE_CHANGE
inline constexpr std::uint32_t IRP_MJ_DEVICE_CHANGE = 0x18;
#endif
#ifndef IRP_MJ_QUERY_QUOTA
inline constexpr std::uint32_t IRP_MJ_QUERY_QUOTA = 0x19;
#endif
#ifndef IRP_MJ_SET_QUOTA
inline constexpr std::uint32_t IRP_MJ_SET_QUOTA = 0x1a;
#endif
#ifndef IRP_MJ_PNP
inline constexpr std::uint32_t IRP_MJ_PNP = 0x1b;
#endif
#ifndef IRP_MJ_MAXIMUM_FUNCTION
inline constexpr std::uint32_t IRP_MJ_MAXIMUM_FUNCTION = 0x1b;
#endif
#ifndef device_name_unknown
inline constexpr std::uint32_t device_name_unknown = 0x00000000;
#endif
#ifndef FILE_DEVICE_BEEP
inline constexpr std::uint32_t FILE_DEVICE_BEEP = 0x00000001;
#endif
#ifndef FILE_DEVICE_CD_ROM
inline constexpr std::uint32_t FILE_DEVICE_CD_ROM = 0x00000002;
#endif
#ifndef FILE_DEVICE_CD_ROM_FILE_SYSTEM
inline constexpr std::uint32_t FILE_DEVICE_CD_ROM_FILE_SYSTEM = 0x00000003;
#endif
#ifndef FILE_DEVICE_CONTROLLER
inline constexpr std::uint32_t FILE_DEVICE_CONTROLLER = 0x00000004;
#endif
#ifndef FILE_DEVICE_DATALINK
inline constexpr std::uint32_t FILE_DEVICE_DATALINK = 0x00000005;
#endif
#ifndef FILE_DEVICE_DFS
inline constexpr std::uint32_t FILE_DEVICE_DFS = 0x00000006;
#endif
#ifndef FILE_DEVICE_DISK
inline constexpr std::uint32_t FILE_DEVICE_DISK = 0x00000007;
#endif
#ifndef FILE_DEVICE_DISK_FILE_SYSTEM
inline constexpr std::uint32_t FILE_DEVICE_DISK_FILE_SYSTEM = 0x00000008;
#endif
#ifndef FILE_DEVICE_FILE_SYSTEM
inline constexpr std::uint32_t FILE_DEVICE_FILE_SYSTEM = 0x00000009;
#endif
#ifndef FILE_DEVICE_INPORT_PORT
inline constexpr std::uint32_t FILE_DEVICE_INPORT_PORT = 0x0000000a;
#endif
#ifndef FILE_DEVICE_KEYBOARD
inline constexpr std::uint32_t FILE_DEVICE_KEYBOARD = 0x0000000b;
#endif
#ifndef FILE_DEVICE_MAILSLOT
inline constexpr std::uint32_t FILE_DEVICE_MAILSLOT = 0x0000000c;
#endif
#ifndef FILE_DEVICE_MIDI_IN
inline constexpr std::uint32_t FILE_DEVICE_MIDI_IN = 0x0000000d;
#endif
#ifndef FILE_DEVICE_MIDI_OUT
inline constexpr std::uint32_t FILE_DEVICE_MIDI_OUT = 0x0000000e;
#endif
#ifndef FILE_DEVICE_MOUSE
inline constexpr std::uint32_t FILE_DEVICE_MOUSE = 0x0000000f;
#endif
#ifndef FILE_DEVICE_MULTI_UNC_PROVIDER
inline constexpr std::uint32_t FILE_DEVICE_MULTI_UNC_PROVIDER = 0x00000010;
#endif
#ifndef FILE_DEVICE_NAMED_PIPE
inline constexpr std::uint32_t FILE_DEVICE_NAMED_PIPE = 0x00000011;
#endif
#ifndef FILE_DEVICE_NETWORK
inline constexpr std::uint32_t FILE_DEVICE_NETWORK = 0x00000012;
#endif
#ifndef FILE_DEVICE_NETWORK_BROWSER
inline constexpr std::uint32_t FILE_DEVICE_NETWORK_BROWSER = 0x00000013;
#endif
#ifndef FILE_DEVICE_NETWORK_FILE_SYSTEM
inline constexpr std::uint32_t FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014;
#endif
#ifndef FILE_DEVICE_NULL
inline constexpr std::uint32_t FILE_DEVICE_NULL = 0x00000015;
#endif
#ifndef FILE_DEVICE_PARALLEL_PORT
inline constexpr std::uint32_t FILE_DEVICE_PARALLEL_PORT = 0x00000016;
#endif
#ifndef FILE_DEVICE_PHYSICAL_NETCARD
inline constexpr std::uint32_t FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017;
#endif
#ifndef FILE_DEVICE_PRINTER
inline constexpr std::uint32_t FILE_DEVICE_PRINTER = 0x00000018;
#endif
#ifndef FILE_DEVICE_SCANNER
inline constexpr std::uint32_t FILE_DEVICE_SCANNER = 0x00000019;
#endif
#ifndef FILE_DEVICE_SERIAL_MOUSE_PORT
inline constexpr std::uint32_t FILE_DEVICE_SERIAL_MOUSE_PORT = 0x0000001a;
#endif
#ifndef FILE_DEVICE_SERIAL_PORT
inline constexpr std::uint32_t FILE_DEVICE_SERIAL_PORT = 0x0000001b;
#endif
#ifndef FILE_DEVICE_SCREEN
inline constexpr std::uint32_t FILE_DEVICE_SCREEN = 0x0000001c;
#endif
#ifndef FILE_DEVICE_SOUND
inline constexpr std::uint32_t FILE_DEVICE_SOUND = 0x0000001d;
#endif
#ifndef FILE_DEVICE_STREAMS
inline constexpr std::uint32_t FILE_DEVICE_STREAMS = 0x0000001e;
#endif
#ifndef FILE_DEVICE_TAPE
inline constexpr std::uint32_t FILE_DEVICE_TAPE = 0x0000001f;
#endif
#ifndef FILE_DEVICE_TAPE_FILE_SYSTEM
inline constexpr std::uint32_t FILE_DEVICE_TAPE_FILE_SYSTEM = 0x00000020;
#endif
#ifndef FILE_DEVICE_TRANSPORT
inline constexpr std::uint32_t FILE_DEVICE_TRANSPORT = 0x00000021;
#endif
#ifndef FILE_DEVICE_UNKNOWN
inline constexpr std::uint32_t FILE_DEVICE_UNKNOWN = 0x00000022;
#endif
#ifndef FILE_DEVICE_VIDEO
inline constexpr std::uint32_t FILE_DEVICE_VIDEO = 0x00000023;
#endif
#ifndef FILE_DEVICE_VIRTUAL_DISK
inline constexpr std::uint32_t FILE_DEVICE_VIRTUAL_DISK = 0x00000024;
#endif
#ifndef FILE_DEVICE_WAVE_IN
inline constexpr std::uint32_t FILE_DEVICE_WAVE_IN = 0x00000025;
#endif
#ifndef FILE_DEVICE_WAVE_OUT
inline constexpr std::uint32_t FILE_DEVICE_WAVE_OUT = 0x00000026;
#endif
#ifndef FILE_DEVICE_8042_PORT
inline constexpr std::uint32_t FILE_DEVICE_8042_PORT = 0x00000027;
#endif
#ifndef FILE_DEVICE_NETWORK_REDIRECTOR
inline constexpr std::uint32_t FILE_DEVICE_NETWORK_REDIRECTOR = 0x00000028;
#endif
#ifndef FILE_DEVICE_BATTERY
inline constexpr std::uint32_t FILE_DEVICE_BATTERY = 0x00000029;
#endif
#ifndef FILE_DEVICE_BUS_EXTENDER
inline constexpr std::uint32_t FILE_DEVICE_BUS_EXTENDER = 0x0000002a;
#endif
#ifndef FILE_DEVICE_MODEM
inline constexpr std::uint32_t FILE_DEVICE_MODEM = 0x0000002b;
#endif
#ifndef FILE_DEVICE_VDM
inline constexpr std::uint32_t FILE_DEVICE_VDM = 0x0000002c;
#endif
#ifndef FILE_DEVICE_MASS_STORAGE
inline constexpr std::uint32_t FILE_DEVICE_MASS_STORAGE = 0x0000002d;
#endif
#ifndef FILE_DEVICE_SMB
inline constexpr std::uint32_t FILE_DEVICE_SMB = 0x0000002e;
#endif
#ifndef FILE_DEVICE_KS
inline constexpr std::uint32_t FILE_DEVICE_KS = 0x0000002f;
#endif
#ifndef FILE_DEVICE_CHANGER
inline constexpr std::uint32_t FILE_DEVICE_CHANGER = 0x00000030;
#endif
#ifndef FILE_DEVICE_SMARTCARD
inline constexpr std::uint32_t FILE_DEVICE_SMARTCARD = 0x00000031;
#endif
#ifndef FILE_DEVICE_ACPI
inline constexpr std::uint32_t FILE_DEVICE_ACPI = 0x00000032;
#endif
#ifndef FILE_DEVICE_DVD
inline constexpr std::uint32_t FILE_DEVICE_DVD = 0x00000033;
#endif
#ifndef FILE_DEVICE_FULLSCREEN_VIDEO
inline constexpr std::uint32_t FILE_DEVICE_FULLSCREEN_VIDEO = 0x00000034;
#endif
#ifndef FILE_DEVICE_DFS_FILE_SYSTEM
inline constexpr std::uint32_t FILE_DEVICE_DFS_FILE_SYSTEM = 0x00000035;
#endif
#ifndef FILE_DEVICE_DFS_VOLUME
inline constexpr std::uint32_t FILE_DEVICE_DFS_VOLUME = 0x00000036;
#endif
#ifndef FILE_DEVICE_SERENUM
inline constexpr std::uint32_t FILE_DEVICE_SERENUM = 0x00000037;
#endif
#ifndef FILE_DEVICE_TERMSRV
inline constexpr std::uint32_t FILE_DEVICE_TERMSRV = 0x00000038;
#endif
#ifndef FILE_DEVICE_KSEC
inline constexpr std::uint32_t FILE_DEVICE_KSEC = 0x00000039;
#endif
#ifndef FILE_DEVICE_FIPS
inline constexpr std::uint32_t FILE_DEVICE_FIPS = 0x0000003A;
#endif
#ifndef FILE_DEVICE_INFINIBAND
inline constexpr std::uint32_t FILE_DEVICE_INFINIBAND = 0x0000003B;
#endif
#ifndef FILE_DEVICE_VMBUS
inline constexpr std::uint32_t FILE_DEVICE_VMBUS = 0x0000003E;
#endif
#ifndef FILE_DEVICE_CRYPT_PROVIDER
inline constexpr std::uint32_t FILE_DEVICE_CRYPT_PROVIDER = 0x0000003F;
#endif
#ifndef FILE_DEVICE_WPD
inline constexpr std::uint32_t FILE_DEVICE_WPD = 0x00000040;
#endif
#ifndef FILE_DEVICE_BLUETOOTH
inline constexpr std::uint32_t FILE_DEVICE_BLUETOOTH = 0x00000041;
#endif
#ifndef FILE_DEVICE_MT_COMPOSITE
inline constexpr std::uint32_t FILE_DEVICE_MT_COMPOSITE = 0x00000042;
#endif
#ifndef FILE_DEVICE_MT_TRANSPORT
inline constexpr std::uint32_t FILE_DEVICE_MT_TRANSPORT = 0x00000043;
#endif
#ifndef FILE_DEVICE_BIOMETRIC
inline constexpr std::uint32_t FILE_DEVICE_BIOMETRIC = 0x00000044;
#endif
#ifndef FILE_DEVICE_PMI
inline constexpr std::uint32_t FILE_DEVICE_PMI = 0x00000045;
#endif
#ifndef FILE_ANY_ACCESS
inline constexpr std::uint32_t FILE_ANY_ACCESS = 0u;
#endif
#ifndef FILE_READ_DATA
inline constexpr std::uint32_t FILE_READ_DATA = 1u;
#endif
#ifndef FILE_WRITE_DATA
inline constexpr std::uint32_t FILE_WRITE_DATA = 2u;
#endif
#ifndef METHOD_BUFFERED
inline constexpr std::uint32_t METHOD_BUFFERED = 0u;
#endif
#ifndef METHOD_IN_DIRECT
inline constexpr std::uint32_t METHOD_IN_DIRECT = 1u;
#endif
#ifndef METHOD_OUT_DIRECT
inline constexpr std::uint32_t METHOD_OUT_DIRECT = 2u;
#endif
#ifndef METHOD_NEITHER
inline constexpr std::uint32_t METHOD_NEITHER = 3u;
#endif
#ifndef DO_BUFFERED_IO
inline constexpr std::uint32_t DO_BUFFERED_IO = 0x00000004;
#endif
#ifndef DO_EXCLUSIVE
inline constexpr std::uint32_t DO_EXCLUSIVE = 0x00000008;
#endif
#ifndef DO_DIRECT_IO
inline constexpr std::uint32_t DO_DIRECT_IO = 0x00000010;
#endif
#ifndef DO_MAP_IO_BUFFER
inline constexpr std::uint32_t DO_MAP_IO_BUFFER = 0x00000020;
#endif
#ifndef DO_DEVICE_INITIALIZING
inline constexpr std::uint32_t DO_DEVICE_INITIALIZING = 0x00000080;
#endif
#ifndef DO_SHUTDOWN_REGISTERED
inline constexpr std::uint32_t DO_SHUTDOWN_REGISTERED = 0x00000800;
#endif
#ifndef DO_BUS_ENUMERATED_DEVICE
inline constexpr std::uint32_t DO_BUS_ENUMERATED_DEVICE = 0x00001000;
#endif
#ifndef DO_POWER_PAGABLE
inline constexpr std::uint32_t DO_POWER_PAGABLE = 0x00002000;
#endif
#ifndef DO_POWER_INRUSH
inline constexpr std::uint32_t DO_POWER_INRUSH = 0x00004000;
#endif

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_WDK_CONST_HPP
