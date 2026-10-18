// os/uefi — the service-table layer (st.py / bs.py / rt.py / fncc.py)
//
// The EFI structure layouts are the hand-written constant tables (the
// upstream drives the ctypes STRUCT machinery; the port spellings pin the
// same field offsets for the 64-bit natural alignment). The descriptor
// install rides the init_struct shape: the callable fields get hooked at
// their offsets, the None fields stay zero.
//
// Layout reference (the x64):
//   EFI_TABLE_HEADER  = 24 bytes (Signature u64, Revision u32, HeaderSize
//                       u32, CRC32 u32, Reserved u32)
//   EFI_SYSTEM_TABLE  = 120 (Hdr + FirmwareVendor + FirmwareRevision(pad)
//                       + 10 pointers + NumberOfTableEntries + Conftable)
//   EFI_BOOT_SERVICES = 376 (Hdr + 44 function pointers)
//   EFI_RUNTIME_SERVICES = 136 (Hdr + 14 function pointers)
//   EFI_SIMPLE_TEXT_INPUT_PROTOCOL  = 40 (Hdr + Reset + ReadKeyStroke +
//                       WaitForKey)
//   EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = 96 (Hdr + 8 pointers + Mode)

#pragma once

#ifndef QILING_OS_UEFI_SERVICES_HPP
#define QILING_OS_UEFI_SERVICES_HPP

#include <functional>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/os/os.hpp"

namespace qiling {
namespace os {
namespace uefi {

class UefiContext;
class QlOsUefi;

// ---- the layout constants ----

constexpr std::uint64_t kTableHeaderSize = 24;
constexpr std::uint64_t kSystemTableSize = 120;
constexpr std::uint64_t kSystemTableConIn = 48;
constexpr std::uint64_t kSystemTableConOut = 64;
constexpr std::uint64_t kSystemTableRuntimeServices = 88;
constexpr std::uint64_t kSystemTableBootServices = 96;
constexpr std::uint64_t kSystemTableNumberOfTableEntries = 104;
constexpr std::uint64_t kSystemTableConfigurationTable = 112;
constexpr std::uint64_t kBootServicesSize = 376;
constexpr std::uint64_t kRuntimeServicesSize = 136;
constexpr std::uint64_t kSimpleTextInSize = 40;
constexpr std::uint64_t kSimpleTextOutSize = 96;
constexpr std::uint64_t kDsServicesSize = 120;  // ds.py EFI_DXE_SERVICES (the Hdr + 11 pointers)
// ProcessorBind.py: the TPL_APPLICATION level
constexpr unsigned kTplApplication = 4;

// ---- the descriptor install machinery (utils.py init_struct + fncc.py
// dxeapi) ----

// the boot/runtime-services api hook (the fncc wrapper shape)
using ServiceHook = std::function<std::optional<std::uint64_t>(Qiling& ql, std::uint64_t address,
                                                     const QlFunctionCall::Params& params)>;

struct ServiceDescriptor {
    std::string_view name;
    // the fcall proto (the (name, type) pairs; the int types stay raw)
    std::vector<std::pair<std::string, int>> params;
    ServiceHook hook;
};

// utils.py init_struct: walk the descriptor fields from the table header;
// the hooked fields carry their own address as the value and register the
// address hook (the None fields stay zero)
void install_service_table(Qiling& ql, UefiContext& context, std::uint64_t base,
                           const ServiceDescriptor* fields, std::size_t count);

// st.py initialize: lay out gST/sti/sto/gRT/gBS/gDS/cfg from the 4KiB chunk
// and fill them (the bs/rt descriptors ride their own slices)
void initialize_system_table(Qiling& ql, UefiContext& context, std::uint64_t gST);

// the const.py EFI_STATUS codes (the error bit set)
constexpr std::uint64_t kEfiErrorBit = 1ull << 63;
constexpr std::uint64_t kEfiSuccess = 0;
constexpr std::uint64_t kEfiInvalidParameter = kEfiErrorBit | 2;
constexpr std::uint64_t kEfiUnsupported = kEfiErrorBit | 3;
constexpr std::uint64_t kEfiBufferTooSmall = kEfiErrorBit | 5;
constexpr std::uint64_t kEfiNotReady = kEfiErrorBit | 6;
constexpr std::uint64_t kEfiOutOfResources = kEfiErrorBit | 9;
constexpr std::uint64_t kEfiNotFound = kEfiErrorBit | 14;

}  // namespace uefi
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_UEFI_SERVICES_HPP
