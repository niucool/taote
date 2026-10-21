// Ported from qiling/os/windows/ntdefs.py — the Windows structure layout table
// (PLAN_PARITY.md Phase 2). The handlers write these images field by field, so
// the offsets are the contract between the guest and the emulator; keeping them
// in one table (with a test) replaces the ad-hoc arithmetic the handlers used to
// carry and unblocks the reference suite's size-validation rows.
//
// The upstream table is Python dictionaries of (name, type) pairs; the C++ port
// keeps the *derived* sizes/offsets (what the guest actually observes) and the
// field order that produced them.
#ifndef QILING_OS_WINDOWS_NTDEFS_HPP
#define QILING_OS_WINDOWS_NTDEFS_HPP

#include <cstdint>

namespace qiling {
namespace os {
namespace windows {
namespace ntdefs {

// one structure layout: the total size and the field offsets, for one bitness
struct StructLayout {
    std::uint32_t size;
    std::uint32_t fields_count;
};

// the layouts the handlers depend on. pegasus validates these through
// test_win_size_validation_all; the two columns are x86 and x64.
struct Layout {
    const char* name;
    StructLayout x86;
    StructLayout x64;
};

// UNICODE_STRING { USHORT Length, USHORT MaximumLength, PWSTR Buffer }
inline constexpr std::uint32_t UNICODE_STRING_SIZE_X86 = 8;
inline constexpr std::uint32_t UNICODE_STRING_SIZE_X64 = 16;
inline constexpr std::uint32_t UNICODE_STRING_OFF_LENGTH = 0;
inline constexpr std::uint32_t UNICODE_STRING_OFF_MAXIMUM_LENGTH = 2;
inline constexpr std::uint32_t UNICODE_STRING_OFF_BUFFER_X86 = 4;
inline constexpr std::uint32_t UNICODE_STRING_OFF_BUFFER_X64 = 8;

// OBJECT_ATTRIBUTES { HANDLE RootDirectory, PUNICODE_STRING ObjectName,
//                     ULONG Attributes, PVOID SecurityDescriptor,
//                     PVOID SecurityQualityOfService }
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_SIZE_X86 = 24;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_SIZE_X64 = 48;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_LENGTH = 0;        // ULONG Length
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_ROOT_X86 = 4;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_ROOT_X64 = 8;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_NAME_X86 = 8;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_NAME_X64 = 16;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_ATTRIBUTES_X86 = 12;
inline constexpr std::uint32_t OBJECT_ATTRIBUTES_OFF_ATTRIBUTES_X64 = 24;

// IO_STATUS_BLOCK { NTSTATUS Status (or PVOID Pointer), ULONG_PTR Information }
inline constexpr std::uint32_t IO_STATUS_BLOCK_SIZE_X86 = 8;
inline constexpr std::uint32_t IO_STATUS_BLOCK_SIZE_X64 = 16;
inline constexpr std::uint32_t IO_STATUS_BLOCK_OFF_INFORMATION_X86 = 4;
inline constexpr std::uint32_t IO_STATUS_BLOCK_OFF_INFORMATION_X64 = 8;

// EXCEPTION_RECORD { NTSTATUS ExceptionCode, DWORD ExceptionFlags,
//                    ptr ExceptionRecord, ptr ExceptionAddress,
//                    DWORD NumberParameters, DWORD _pad, ULONG_PTR[15] }
inline constexpr std::uint32_t EXCEPTION_RECORD_SIZE_X86 = 80;
inline constexpr std::uint32_t EXCEPTION_RECORD_SIZE_X64 = 152;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_CODE = 0;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_FLAGS = 4;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_ADDRESS_X86 = 12;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_ADDRESS_X64 = 16;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_NUMBER_PARAMS_X86 = 16;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_NUMBER_PARAMS_X64 = 24;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_INFORMATION_X86 = 24;
inline constexpr std::uint32_t EXCEPTION_RECORD_OFF_INFORMATION_X64 = 32;

// EXCEPTION_POINTERS { ptr ExceptionRecord, ptr ContextRecord }
inline constexpr std::uint32_t EXCEPTION_POINTERS_SIZE_X86 = 8;
inline constexpr std::uint32_t EXCEPTION_POINTERS_SIZE_X64 = 16;

// CONTEXT (x86, CONTEXT_FULL shape the SEH dispatch stages)
inline constexpr std::uint32_t CONTEXT_SIZE_X86 = 716;
inline constexpr std::uint32_t CONTEXT_SIZE_X64 = 1232;

// the registry value/key images
inline constexpr std::uint32_t KEY_VALUE_FULL_INFORMATION_HEADER_X86 = 20;
inline constexpr std::uint32_t KEY_VALUE_FULL_INFORMATION_HEADER_X64 = 32;

// MSG (the user32 message pump) — 28 bytes on x86, the A/W variants 48/64 on
// x64 (the message id rides offsets 4 / 8)
inline constexpr std::uint32_t MSG_SIZE_X86 = 28;
inline constexpr std::uint32_t MSG_SIZE_X64_A = 48;
inline constexpr std::uint32_t MSG_SIZE_X64_W = 64;

// the table the tests walk (the pegasus test_win_size_validation_all shape)
inline constexpr Layout kLayouts[] = {
    {"UNICODE_STRING", {UNICODE_STRING_SIZE_X86, 3}, {UNICODE_STRING_SIZE_X64, 3}},
    {"OBJECT_ATTRIBUTES", {OBJECT_ATTRIBUTES_SIZE_X86, 6}, {OBJECT_ATTRIBUTES_SIZE_X64, 6}},
    {"IO_STATUS_BLOCK", {IO_STATUS_BLOCK_SIZE_X86, 2}, {IO_STATUS_BLOCK_SIZE_X64, 2}},
    {"EXCEPTION_RECORD", {EXCEPTION_RECORD_SIZE_X86, 6}, {EXCEPTION_RECORD_SIZE_X64, 6}},
    {"EXCEPTION_POINTERS", {EXCEPTION_POINTERS_SIZE_X86, 2}, {EXCEPTION_POINTERS_SIZE_X64, 2}},
    {"CONTEXT", {CONTEXT_SIZE_X86, 36}, {CONTEXT_SIZE_X64, 62}},
    {"MSG", {MSG_SIZE_X86, 7}, {MSG_SIZE_X64_W, 7}},
    // the loader structures: the x86 column is loader_layout(32)'s word set,
    // the x64 column the structs.hpp one (PEB/TEB/LDR entry/UNICODE_STRING)
    {"PEB", {1148, 6}, {0x7c8, 6}},
    {"TEB", {420, 5}, {488, 5}},
    {"LDR_DATA_TABLE_ENTRY", {156, 6}, {304, 6}},
    {"PEB_LDR_DATA", {48, 4}, {88, 4}},
};

// the pointer-sized field offset helper the handlers use instead of computing
// `2 * pointersize` inline
constexpr std::uint32_t ptr_field(std::uint32_t off_x86, std::uint32_t off_x64, std::size_t bits) {
    return bits == 64 ? off_x64 : off_x86;
}

}  // namespace ntdefs
}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_NTDEFS_HPP
