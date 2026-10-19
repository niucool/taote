// Ported from qiling/os/windows/const.py - the Win32 value constants used by
// the dll API handlers. Scalar entries are verbatim; the table-valued entries
// (REG_TYPES, LOCALE/LOCALE_EN_US, MAP_VK, SYSTEMS_VERSION, Mapper) port with
// their consumer modules (registry.cpp already carries REG_TYPES).
//
// windows.h (pulled in transitively via unicorn on _WIN32) defines many of
// these names as macros with identical values; each definition is therefore
// #ifndef-guarded so either include order compiles.
#ifndef QILING_OS_WINDOWS_CONST_HPP
#define QILING_OS_WINDOWS_CONST_HPP

#include <cstdint>
#include <map>
#include <string>

namespace qiling {
namespace os {
namespace win {

#ifndef ERROR_SUCCESS
inline constexpr std::uint32_t ERROR_SUCCESS = 0x0;
#endif
#ifndef ERROR_INVALID_FUNCTION
inline constexpr std::uint32_t ERROR_INVALID_FUNCTION = 0x1;
#endif
#ifndef ERROR_FILE_NOT_FOUND
inline constexpr std::uint32_t ERROR_FILE_NOT_FOUND = 0x2;
#endif
#ifndef ERROR_PATH_NOT_FOUND
inline constexpr std::uint32_t ERROR_PATH_NOT_FOUND = 0x3;
#endif
#ifndef ERROR_ACCESS_DENIED
inline constexpr std::uint32_t ERROR_ACCESS_DENIED = 0x5;
#endif
#ifndef ERROR_INVALID_HANDLE
inline constexpr std::uint32_t ERROR_INVALID_HANDLE = 0x6;
#endif
#ifndef ERROR_GEN_FAILURE
inline constexpr std::uint32_t ERROR_GEN_FAILURE = 0x1f;
#endif
#ifndef ERROR_FILE_EXISTS
inline constexpr std::uint32_t ERROR_FILE_EXISTS = 0x50;
#endif
#ifndef ERROR_INVALID_PARAMETER
inline constexpr std::uint32_t ERROR_INVALID_PARAMETER = 0x57;
#endif
#ifndef ERROR_BUFFER_OVERFLOW
inline constexpr std::uint32_t ERROR_BUFFER_OVERFLOW = 0x6F;
#endif
#ifndef ERROR_INSUFFICIENT_BUFFER
inline constexpr std::uint32_t ERROR_INSUFFICIENT_BUFFER = 0x7A;
#endif
#ifndef ERROR_BAD_PATHNAME
inline constexpr std::uint32_t ERROR_BAD_PATHNAME = 0xa1;
#endif
#ifndef ERROR_ALREADY_EXISTS
inline constexpr std::uint32_t ERROR_ALREADY_EXISTS = 0xB7;
#endif
#ifndef ERROR_MORE_DATA
inline constexpr std::uint32_t ERROR_MORE_DATA = 0xEA;
#endif
#ifndef ERROR_NO_MORE_ITEMS
inline constexpr std::uint32_t ERROR_NO_MORE_ITEMS = 0x103;
#endif
#ifndef ERROR_DIRECTORY
inline constexpr std::uint32_t ERROR_DIRECTORY = 0x10b;
#endif
#ifndef ERROR_NOT_OWNER
inline constexpr std::uint32_t ERROR_NOT_OWNER = 0x120;
#endif
#ifndef ERROR_NO_UNICODE_TRANSLATION
inline constexpr std::uint32_t ERROR_NO_UNICODE_TRANSLATION = 0x459;
#endif
#ifndef ERROR_OLD_WIN_VERSION
inline constexpr std::uint32_t ERROR_OLD_WIN_VERSION = 0x47E;
#endif
#ifndef ERROR_CLIPBOARD_NOT_OPEN
inline constexpr std::uint32_t ERROR_CLIPBOARD_NOT_OPEN = 0x58a;
#endif
#ifndef STATUS_SUCCESS
inline constexpr std::uint32_t STATUS_SUCCESS = 0u;
#endif
#ifndef STATUS_UNSUCCESSFUL
inline constexpr std::uint32_t STATUS_UNSUCCESSFUL = 0xC0000001;
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
inline constexpr std::uint32_t STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
#endif
#ifndef STATUS_INVALID_PARAMETER
inline constexpr std::uint32_t STATUS_INVALID_PARAMETER = 0xC000000D;
#endif
#ifndef STATUS_INVALID_HANDLE
inline constexpr std::uint32_t STATUS_INVALID_HANDLE = 0xC0000008;
#endif
#ifndef STATUS_PROCEDURE_NOT_FOUND
inline constexpr std::uint32_t STATUS_PROCEDURE_NOT_FOUND = 0xC000007A;
#endif
#ifndef STATUS_DLL_NOT_FOUND
inline constexpr std::uint32_t STATUS_DLL_NOT_FOUND = 0xC0000135;
#endif
#ifndef STATUS_PORT_NOT_SET
inline constexpr std::uint32_t STATUS_PORT_NOT_SET = 0xC0000353;
#endif
#ifndef STATUS_STACK_BUFFER_OVERRUN
inline constexpr std::uint32_t STATUS_STACK_BUFFER_OVERRUN = 0xC0000409;
#endif
#ifndef STATUS_NO_YIELD_PERFORMED
inline constexpr std::uint32_t STATUS_NO_YIELD_PERFORMED = 0x40000024;
#endif
#ifndef INVALID_HANDLE_VALUE
inline constexpr std::uint64_t INVALID_HANDLE_VALUE = 0xffffffffffffffffull;
#endif
#ifndef STD_INPUT_HANDLE
inline constexpr std::uint32_t STD_INPUT_HANDLE = 0xfffffff6;
#endif
#ifndef STD_OUTPUT_HANDLE
inline constexpr std::uint32_t STD_OUTPUT_HANDLE = 0xfffffff5;
#endif
#ifndef STD_ERROR_HANDLE
inline constexpr std::uint32_t STD_ERROR_HANDLE = 0xfffffff4;
#endif
#ifndef RTL_MAXIMUM_ATOM_LENGTH
inline constexpr std::uint32_t RTL_MAXIMUM_ATOM_LENGTH = 255u;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_NORMALIZED
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_NORMALIZED = 0x01;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_PROFILE_USER
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_PROFILE_USER = 0x02;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL = 0x04;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER = 0x08;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_UNKNOWN
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_UNKNOWN = 0x10;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB = 0x20;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB = 0x40;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE = 0x80;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS = 0x100;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1 = 0x200;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2 = 0x400;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH = 0x1000;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH = 0x2000;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING = 0x4000;
#endif
#ifndef RTL_USER_PROCESS_PARAMETERS_NX
inline constexpr std::uint32_t RTL_USER_PROCESS_PARAMETERS_NX = 0x20000;
#endif
#ifndef RTL_MAX_DRIVE_LETTERS
inline constexpr std::uint32_t RTL_MAX_DRIVE_LETTERS = 32u;
#endif
#ifndef RTL_DRIVE_LETTER_VALID
inline constexpr std::uint32_t RTL_DRIVE_LETTER_VALID = 0x0001;
#endif
#ifndef SEM_FAILCRITICALERRORS
inline constexpr std::uint32_t SEM_FAILCRITICALERRORS = 0x0001;
#endif
#ifndef SEM_NOGPFAULTERRORBOX
inline constexpr std::uint32_t SEM_NOGPFAULTERRORBOX = 0x0002;
#endif
#ifndef SEM_NOALIGNMENTFAULTEXCEPT
inline constexpr std::uint32_t SEM_NOALIGNMENTFAULTEXCEPT = 0x0004;
#endif
#ifndef SEM_NOOPENFILEERRORBOX
inline constexpr std::uint32_t SEM_NOOPENFILEERRORBOX = 0x8000;
#endif
#ifndef RTL_RANGE_LIST_ADD_IF_CONFLICT
inline constexpr std::uint32_t RTL_RANGE_LIST_ADD_IF_CONFLICT = 0x00000001;
#endif
#ifndef RTL_RANGE_LIST_ADD_SHARED
inline constexpr std::uint32_t RTL_RANGE_LIST_ADD_SHARED = 0x00000002;
#endif
#ifndef RTL_RANGE_SHARED
inline constexpr std::uint32_t RTL_RANGE_SHARED = 0x01;
#endif
#ifndef RTL_RANGE_CONFLICT
inline constexpr std::uint32_t RTL_RANGE_CONFLICT = 0x02;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_RELEASE_ON_DEACTIVATION
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_RELEASE_ON_DEACTIVATION = 0x01;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NO_DEACTIVATE
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NO_DEACTIVATE = 0x02;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ON_FREE_LIST
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ON_FREE_LIST = 0x04;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_HEAP_ALLOCATED
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_HEAP_ALLOCATED = 0x08;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NOT_REALLY_ACTIVATED
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NOT_REALLY_ACTIVATED = 0x10;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED = 0x20;
#endif
#ifndef RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED
inline constexpr std::uint32_t RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED = 0x40;
#endif
#ifndef RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER
inline constexpr std::uint32_t RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER = 0x01;
#endif
#ifndef RTL_ACTIVATE_ACTIVATION_CONTEXT_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION
inline constexpr std::uint32_t RTL_ACTIVATE_ACTIVATION_CONTEXT_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION = 0x01;
#endif
#ifndef RTL_DEACTIVATE_ACTIVATION_CONTEXT_FLAG_FORCE_EARLY_DEACTIVATION
inline constexpr std::uint32_t RTL_DEACTIVATE_ACTIVATION_CONTEXT_FLAG_FORCE_EARLY_DEACTIVATION = 0x01;
#endif
#ifndef RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT
inline constexpr std::uint32_t RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT = 0x01;
#endif
#ifndef RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_HMODULE
inline constexpr std::uint32_t RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_HMODULE = 0x02;
#endif
#ifndef RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_ADDRESS
inline constexpr std::uint32_t RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_ADDRESS = 0x04;
#endif
#ifndef RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF
inline constexpr std::uint32_t RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF = 0x80000000;
#endif
#ifndef HEAP_SETTABLE_USER_VALUE
inline constexpr std::uint32_t HEAP_SETTABLE_USER_VALUE = 0x00000100;
#endif
#ifndef HEAP_SETTABLE_USER_FLAG1
inline constexpr std::uint32_t HEAP_SETTABLE_USER_FLAG1 = 0x00000200;
#endif
#ifndef HEAP_SETTABLE_USER_FLAG2
inline constexpr std::uint32_t HEAP_SETTABLE_USER_FLAG2 = 0x00000400;
#endif
#ifndef HEAP_SETTABLE_USER_FLAG3
inline constexpr std::uint32_t HEAP_SETTABLE_USER_FLAG3 = 0x00000800;
#endif
#ifndef HEAP_SETTABLE_USER_FLAGS
inline constexpr std::uint32_t HEAP_SETTABLE_USER_FLAGS = 0x00000E00;
#endif
#ifndef HEAP_CLASS_0
inline constexpr std::uint32_t HEAP_CLASS_0 = 0x00000000;
#endif
#ifndef HEAP_CLASS_1
inline constexpr std::uint32_t HEAP_CLASS_1 = 0x00001000;
#endif
#ifndef HEAP_CLASS_2
inline constexpr std::uint32_t HEAP_CLASS_2 = 0x00002000;
#endif
#ifndef HEAP_CLASS_3
inline constexpr std::uint32_t HEAP_CLASS_3 = 0x00003000;
#endif
#ifndef HEAP_CLASS_4
inline constexpr std::uint32_t HEAP_CLASS_4 = 0x00004000;
#endif
#ifndef HEAP_CLASS_5
inline constexpr std::uint32_t HEAP_CLASS_5 = 0x00005000;
#endif
#ifndef HEAP_CLASS_6
inline constexpr std::uint32_t HEAP_CLASS_6 = 0x00006000;
#endif
#ifndef HEAP_CLASS_7
inline constexpr std::uint32_t HEAP_CLASS_7 = 0x00007000;
#endif
#ifndef HEAP_CLASS_8
inline constexpr std::uint32_t HEAP_CLASS_8 = 0x00008000;
#endif
#ifndef HEAP_CLASS_MASK
inline constexpr std::uint32_t HEAP_CLASS_MASK = 0x0000F000;
#endif
#ifndef HEAP_FLAG_ALLOCS
inline constexpr std::uint32_t HEAP_FLAG_ALLOCS = 0x01000000;
#endif
#ifndef HEAP_PROTECTION_ENABLED
inline constexpr std::uint32_t HEAP_PROTECTION_ENABLED = 0x02000000;
#endif
#ifndef HEAP_BREAK_WHEN_OUT_OF_VM
inline constexpr std::uint32_t HEAP_BREAK_WHEN_OUT_OF_VM = 0x04000000;
#endif
#ifndef HEAP_NO_ALIGNMENT
inline constexpr std::uint32_t HEAP_NO_ALIGNMENT = 0x08000000;
#endif
#ifndef HEAP_CAPTURE_STACK_BACKTRACES
inline constexpr std::uint32_t HEAP_CAPTURE_STACK_BACKTRACES = 0x08000000;
#endif
#ifndef HEAP_SKIP_VALIDATION_CHECKS
inline constexpr std::uint32_t HEAP_SKIP_VALIDATION_CHECKS = 0x10000000;
#endif
#ifndef HEAP_VALIDATE_ALL_ENABLED
inline constexpr std::uint32_t HEAP_VALIDATE_ALL_ENABLED = 0x20000000;
#endif
#ifndef HEAP_VALIDATE_PARAMETERS_ENABLED
inline constexpr std::uint32_t HEAP_VALIDATE_PARAMETERS_ENABLED = 0x40000000;
#endif
#ifndef HEAP_LOCK_USER_ALLOCATED
inline constexpr std::uint32_t HEAP_LOCK_USER_ALLOCATED = 0x80000000;
#endif
#ifndef RTL_REGISTRY_ABSOLUTE
inline constexpr std::uint32_t RTL_REGISTRY_ABSOLUTE = 0u;
#endif
#ifndef RTL_REGISTRY_SERVICES
inline constexpr std::uint32_t RTL_REGISTRY_SERVICES = 1u;
#endif
#ifndef RTL_REGISTRY_CONTROL
inline constexpr std::uint32_t RTL_REGISTRY_CONTROL = 2u;
#endif
#ifndef RTL_REGISTRY_WINDOWS_NT
inline constexpr std::uint32_t RTL_REGISTRY_WINDOWS_NT = 3u;
#endif
#ifndef RTL_REGISTRY_DEVICEMAP
inline constexpr std::uint32_t RTL_REGISTRY_DEVICEMAP = 4u;
#endif
#ifndef RTL_REGISTRY_USER
inline constexpr std::uint32_t RTL_REGISTRY_USER = 5u;
#endif
#ifndef RTL_REGISTRY_MAXIMUM
inline constexpr std::uint32_t RTL_REGISTRY_MAXIMUM = 6u;
#endif
#ifndef RTL_REGISTRY_HANDLE
inline constexpr std::uint32_t RTL_REGISTRY_HANDLE = 0x40000000;
#endif
#ifndef RTL_REGISTRY_OPTIONAL
inline constexpr std::uint32_t RTL_REGISTRY_OPTIONAL = 0x80000000;
#endif
#ifndef RTL_QUERY_REGISTRY_SUBKEY
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_SUBKEY = 0x00000001;
#endif
#ifndef RTL_QUERY_REGISTRY_TOPKEY
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_TOPKEY = 0x00000002;
#endif
#ifndef RTL_QUERY_REGISTRY_REQUIRED
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_REQUIRED = 0x00000004;
#endif
#ifndef RTL_QUERY_REGISTRY_NOVALUE
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_NOVALUE = 0x00000008;
#endif
#ifndef RTL_QUERY_REGISTRY_NOEXPAND
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_NOEXPAND = 0x00000010;
#endif
#ifndef RTL_QUERY_REGISTRY_DIRECT
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_DIRECT = 0x00000020;
#endif
#ifndef RTL_QUERY_REGISTRY_DELETE
inline constexpr std::uint32_t RTL_QUERY_REGISTRY_DELETE = 0x00000040;
#endif
#ifndef VER_MINORVERSION
inline constexpr std::uint32_t VER_MINORVERSION = 0x0000001;
#endif
#ifndef VER_MAJORVERSION
inline constexpr std::uint32_t VER_MAJORVERSION = 0x0000002;
#endif
#ifndef VER_BUILDNUMBER
inline constexpr std::uint32_t VER_BUILDNUMBER = 0x0000004;
#endif
#ifndef VER_PLATFORMID
inline constexpr std::uint32_t VER_PLATFORMID = 0x0000008;
#endif
#ifndef VER_SERVICEPACKMINOR
inline constexpr std::uint32_t VER_SERVICEPACKMINOR = 0x0000010;
#endif
#ifndef VER_SERVICEPACKMAJOR
inline constexpr std::uint32_t VER_SERVICEPACKMAJOR = 0x0000020;
#endif
#ifndef VER_SUITENAME
inline constexpr std::uint32_t VER_SUITENAME = 0x0000040;
#endif
#ifndef VER_PRODUCT_TYPE
inline constexpr std::uint32_t VER_PRODUCT_TYPE = 0x0000080;
#endif
#ifndef VER_PLATFORM_WIN32s
inline constexpr std::uint32_t VER_PLATFORM_WIN32s = 0u;
#endif
#ifndef VER_PLATFORM_WIN32_WINDOWS
inline constexpr std::uint32_t VER_PLATFORM_WIN32_WINDOWS = 1u;
#endif
#ifndef VER_PLATFORM_WIN32_NT
inline constexpr std::uint32_t VER_PLATFORM_WIN32_NT = 2u;
#endif
#ifndef VER_EQUAL
inline constexpr std::uint32_t VER_EQUAL = 1u;
#endif
#ifndef VER_GREATER
inline constexpr std::uint32_t VER_GREATER = 2u;
#endif
#ifndef VER_GREATER_EQUAL
inline constexpr std::uint32_t VER_GREATER_EQUAL = 3u;
#endif
#ifndef VER_LESS
inline constexpr std::uint32_t VER_LESS = 4u;
#endif
#ifndef VER_LESS_EQUAL
inline constexpr std::uint32_t VER_LESS_EQUAL = 5u;
#endif
#ifndef VER_AND
inline constexpr std::uint32_t VER_AND = 6u;
#endif
#ifndef VER_OR
inline constexpr std::uint32_t VER_OR = 7u;
#endif
#ifndef VER_CONDITION_MASK
inline constexpr std::uint32_t VER_CONDITION_MASK = 7u;
#endif
#ifndef VER_NUM_BITS_PER_CONDITION_MASK
inline constexpr std::uint32_t VER_NUM_BITS_PER_CONDITION_MASK = 3u;
#endif
#ifndef TIME_ZONE_ID_UNKNOWN
inline constexpr std::uint32_t TIME_ZONE_ID_UNKNOWN = 0u;
#endif
#ifndef TIME_ZONE_ID_STANDARD
inline constexpr std::uint32_t TIME_ZONE_ID_STANDARD = 1u;
#endif
#ifndef TIME_ZONE_ID_DAYLIGHT
inline constexpr std::uint32_t TIME_ZONE_ID_DAYLIGHT = 2u;
#endif
#ifndef MAX_PATH
inline constexpr std::uint32_t MAX_PATH = 260u;
#endif
#ifndef RTL_CRITSECT_TYPE
inline constexpr std::uint32_t RTL_CRITSECT_TYPE = 0u;
#endif
#ifndef RTL_RESOURCE_TYPE
inline constexpr std::uint32_t RTL_RESOURCE_TYPE = 1u;
#endif
#ifndef RTL_ACQUIRE_PRIVILEGE_IMPERSONATE
inline constexpr std::uint32_t RTL_ACQUIRE_PRIVILEGE_IMPERSONATE = 1u;
#endif
#ifndef RTL_ACQUIRE_PRIVILEGE_PROCESS
inline constexpr std::uint32_t RTL_ACQUIRE_PRIVILEGE_PROCESS = 2u;
#endif
#ifndef MESSAGE_RESOURCE_UNICODE
inline constexpr std::uint32_t MESSAGE_RESOURCE_UNICODE = 0x0001;
#endif
#ifndef MAXIMUM_LEADBYTES
inline constexpr std::uint32_t MAXIMUM_LEADBYTES = 12u;
#endif
#ifndef RTL_DEBUG_QUERY_MODULES
inline constexpr std::uint32_t RTL_DEBUG_QUERY_MODULES = 0x01;
#endif
#ifndef RTL_DEBUG_QUERY_BACKTRACES
inline constexpr std::uint32_t RTL_DEBUG_QUERY_BACKTRACES = 0x02;
#endif
#ifndef RTL_DEBUG_QUERY_HEAPS
inline constexpr std::uint32_t RTL_DEBUG_QUERY_HEAPS = 0x04;
#endif
#ifndef RTL_DEBUG_QUERY_HEAP_TAGS
inline constexpr std::uint32_t RTL_DEBUG_QUERY_HEAP_TAGS = 0x08;
#endif
#ifndef RTL_DEBUG_QUERY_HEAP_BLOCKS
inline constexpr std::uint32_t RTL_DEBUG_QUERY_HEAP_BLOCKS = 0x10;
#endif
#ifndef RTL_DEBUG_QUERY_LOCKS
inline constexpr std::uint32_t RTL_DEBUG_QUERY_LOCKS = 0x20;
#endif
#ifndef RTL_HANDLE_VALID
inline constexpr std::uint32_t RTL_HANDLE_VALID = 0x1;
#endif
#ifndef RTL_ATOM_IS_PINNED
inline constexpr std::uint32_t RTL_ATOM_IS_PINNED = 0x1;
#endif
#ifndef CS_LOCK_BIT
inline constexpr std::uint32_t CS_LOCK_BIT = 0x1;
#endif
#ifndef CS_LOCK_BIT_V
inline constexpr std::uint32_t CS_LOCK_BIT_V = 0x0;
#endif
#ifndef CS_LOCK_WAITER_WOKEN
inline constexpr std::uint32_t CS_LOCK_WAITER_WOKEN = 0x2;
#endif
#ifndef CS_LOCK_WAITER_INC
inline constexpr std::uint32_t CS_LOCK_WAITER_INC = 0x4;
#endif
#ifndef RTL_FLS_MAXIMUM_AVAILABLE
inline constexpr std::uint32_t RTL_FLS_MAXIMUM_AVAILABLE = 128u;
#endif
#ifndef RTL_RESOURCE_FLAG_LONG_TERM
inline constexpr std::uint32_t RTL_RESOURCE_FLAG_LONG_TERM = 0x00000001;
#endif
#ifndef GENERIC_ALL
inline constexpr std::uint32_t GENERIC_ALL = 0x10000000;
#endif
#ifndef GENERIC_WRITE
inline constexpr std::uint32_t GENERIC_WRITE = 0x40000000;
#endif
#ifndef GENERIC_READ
inline constexpr std::uint32_t GENERIC_READ = 0x80000000;
#endif
#ifndef GENERIC_EXECUTE
inline constexpr std::uint32_t GENERIC_EXECUTE = 0x20000000;
#endif
#ifndef CREATE_NEW
inline constexpr std::uint32_t CREATE_NEW = 1u;
#endif
#ifndef CREATE_ALWAYS
inline constexpr std::uint32_t CREATE_ALWAYS = 2u;
#endif
#ifndef OPEN_EXISTING
inline constexpr std::uint32_t OPEN_EXISTING = 3u;
#endif
#ifndef OPEN_ALWAYS
inline constexpr std::uint32_t OPEN_ALWAYS = 4u;
#endif
#ifndef TRUNCATE_EXISTING
inline constexpr std::uint32_t TRUNCATE_EXISTING = 5u;
#endif
#ifndef S_OK
inline constexpr std::uint32_t S_OK = 0x00;
#endif
#ifndef S_FALSE
inline constexpr std::uint32_t S_FALSE = 0x01;
#endif
#ifndef E_ABORT
inline constexpr std::uint32_t E_ABORT = 0x80004004;
#endif
#ifndef E_ACCESSDENIED
inline constexpr std::uint32_t E_ACCESSDENIED = 0x80070005;
#endif
#ifndef E_FAIL
inline constexpr std::uint32_t E_FAIL = 0x80004005;
#endif
#ifndef E_HANDLE
inline constexpr std::uint32_t E_HANDLE = 0x80070006;
#endif
#ifndef E_INVALIDARG
inline constexpr std::uint32_t E_INVALIDARG = 0x80070057;
#endif
#ifndef E_NOINTERFACE
inline constexpr std::uint32_t E_NOINTERFACE = 0x80004002;
#endif
#ifndef E_NOTIMPL
inline constexpr std::uint32_t E_NOTIMPL = 0x80004001;
#endif
#ifndef E_OUTOFMEMORY
inline constexpr std::uint32_t E_OUTOFMEMORY = 0x8007000E;
#endif
#ifndef E_POINTER
inline constexpr std::uint32_t E_POINTER = 0x80004003;
#endif
#ifndef E_UNEXPECTED
inline constexpr std::uint32_t E_UNEXPECTED = 0x8000FFFF;
#endif
#ifndef LOCALE_USER_DEFAULT
inline constexpr std::uint32_t LOCALE_USER_DEFAULT = 0x0400;
#endif
#ifndef LOCALE_CUSTOM_DEFAULT
inline constexpr std::uint32_t LOCALE_CUSTOM_DEFAULT = 0x0C00;
#endif
#ifndef LOCALE_CUSTOM_UI_DEFAULT
inline constexpr std::uint32_t LOCALE_CUSTOM_UI_DEFAULT = 0x1400;
#endif
#ifndef LOCALE_CUSTOM_UNSPECIFIED
inline constexpr std::uint32_t LOCALE_CUSTOM_UNSPECIFIED = 0x1000;
#endif
#ifndef SystemBasicInformation
inline constexpr std::uint32_t SystemBasicInformation = 0u;
#endif
#ifndef SystemPerformanceInformation
inline constexpr std::uint32_t SystemPerformanceInformation = 2u;
#endif
#ifndef SystemTimeOfDayInformation
inline constexpr std::uint32_t SystemTimeOfDayInformation = 3u;
#endif
#ifndef SystemProcessInformation
inline constexpr std::uint32_t SystemProcessInformation = 5u;
#endif
#ifndef SystemProcessorPerformanceInformation
inline constexpr std::uint32_t SystemProcessorPerformanceInformation = 8u;
#endif
#ifndef SystemInterruptInformation
inline constexpr std::uint32_t SystemInterruptInformation = 23u;
#endif
#ifndef SystemExceptionInformation
inline constexpr std::uint32_t SystemExceptionInformation = 33u;
#endif
#ifndef SystemRegistryQuotaInformation
inline constexpr std::uint32_t SystemRegistryQuotaInformation = 37u;
#endif
#ifndef SystemLookasideInformation
inline constexpr std::uint32_t SystemLookasideInformation = 45u;
#endif
#ifndef OEM_US
inline constexpr std::uint32_t OEM_US = 437u;
#endif

// const.py LOCALE_EN_US — the int-keyed entries only (the python dict also
// carries the string-keyed locale metadata entries — sName, xLocaleToken,
// the format patterns — but the GetLocaleInfoA lookup indexes by the INT
// LCType, so those keys are unreachable from the handler path; they carry
// no handler-visible surface and ride as the dead data in the python
// source). The 0x1005 value is the single-NUL string (the std::string(1,
// char(0)) spelling).
inline const std::map<std::uint32_t, std::string> LOCALE_EN_US = {
    {0x1004, "utf-8"},
    {0x1005, std::string(1, char(0))},
    {0x1009, "1"},
};

// const.py LOCALE — the int-keyed view (the upstream also carries a
// "default" STRING key which no int LCID lookup can ever reach)
inline const std::map<std::uint32_t, const std::map<std::uint32_t, std::string>*> LOCALE = {
    {0x409, &LOCALE_EN_US},
};
#ifndef SM_ARRANGE
inline constexpr std::uint32_t SM_ARRANGE = 56u;
#endif
#ifndef SM_CLEANBOOT
inline constexpr std::uint32_t SM_CLEANBOOT = 67u;
#endif
#ifndef SM_CMONITORS
inline constexpr std::uint32_t SM_CMONITORS = 80u;
#endif
#ifndef SM_CMOUSEBUTTONS
inline constexpr std::uint32_t SM_CMOUSEBUTTONS = 43u;
#endif
#ifndef SM_CONVERTIBLESLATEMODE
inline constexpr std::uint32_t SM_CONVERTIBLESLATEMODE = 0x2003;
#endif
#ifndef SM_CXBORDER
inline constexpr std::uint32_t SM_CXBORDER = 5u;
#endif
#ifndef SM_CXCURSOR
inline constexpr std::uint32_t SM_CXCURSOR = 13u;
#endif
#ifndef SM_CXDLGFRAME
inline constexpr std::uint32_t SM_CXDLGFRAME = 7u;
#endif
#ifndef SM_CXDOUBLECLK
inline constexpr std::uint32_t SM_CXDOUBLECLK = 36u;
#endif
#ifndef SM_CXDRAG
inline constexpr std::uint32_t SM_CXDRAG = 68u;
#endif
#ifndef SM_CXEDGE
inline constexpr std::uint32_t SM_CXEDGE = 45u;
#endif
#ifndef SM_CXFIXEDFRAME
inline constexpr std::uint32_t SM_CXFIXEDFRAME = 7u;
#endif
#ifndef SM_CXFOCUSBORDER
inline constexpr std::uint32_t SM_CXFOCUSBORDER = 83u;
#endif
#ifndef SM_CXFRAME
inline constexpr std::uint32_t SM_CXFRAME = 32u;
#endif
#ifndef SM_CXFULLSCREEN
inline constexpr std::uint32_t SM_CXFULLSCREEN = 16u;
#endif
#ifndef SM_CXHSCROLL
inline constexpr std::uint32_t SM_CXHSCROLL = 21u;
#endif
#ifndef SM_CXHTHUMB
inline constexpr std::uint32_t SM_CXHTHUMB = 10u;
#endif
#ifndef SM_CXICON
inline constexpr std::uint32_t SM_CXICON = 11u;
#endif
#ifndef SM_CXICONSPACING
inline constexpr std::uint32_t SM_CXICONSPACING = 38u;
#endif
#ifndef SM_CXMAXIMIZED
inline constexpr std::uint32_t SM_CXMAXIMIZED = 61u;
#endif
#ifndef SM_CXMAXTRACK
inline constexpr std::uint32_t SM_CXMAXTRACK = 59u;
#endif
#ifndef SM_CXMENUCHECK
inline constexpr std::uint32_t SM_CXMENUCHECK = 71u;
#endif
#ifndef SM_CXMENUSIZE
inline constexpr std::uint32_t SM_CXMENUSIZE = 54u;
#endif
#ifndef SM_CXMIN
inline constexpr std::uint32_t SM_CXMIN = 28u;
#endif
#ifndef SM_CXMINIMIZED
inline constexpr std::uint32_t SM_CXMINIMIZED = 57u;
#endif
#ifndef SM_CXMINSPACING
inline constexpr std::uint32_t SM_CXMINSPACING = 47u;
#endif
#ifndef SM_CXMINTRACK
inline constexpr std::uint32_t SM_CXMINTRACK = 34u;
#endif
#ifndef SM_CXPADDEDBORDER
inline constexpr std::uint32_t SM_CXPADDEDBORDER = 92u;
#endif
#ifndef SM_CXSCREEN
inline constexpr std::uint32_t SM_CXSCREEN = 0u;
#endif
#ifndef SM_CXSIZE
inline constexpr std::uint32_t SM_CXSIZE = 30u;
#endif
#ifndef SM_CXSIZEFRAME
inline constexpr std::uint32_t SM_CXSIZEFRAME = 32u;
#endif
#ifndef SM_CXSMICON
inline constexpr std::uint32_t SM_CXSMICON = 49u;
#endif
#ifndef SM_CXSMSIZE
inline constexpr std::uint32_t SM_CXSMSIZE = 52u;
#endif
#ifndef SM_CXVIRTUALSCREEN
inline constexpr std::uint32_t SM_CXVIRTUALSCREEN = 78u;
#endif
#ifndef SM_CXVSCROLL
inline constexpr std::uint32_t SM_CXVSCROLL = 2u;
#endif
#ifndef SM_CYBORDER
inline constexpr std::uint32_t SM_CYBORDER = 6u;
#endif
#ifndef SM_CYCAPTION
inline constexpr std::uint32_t SM_CYCAPTION = 4u;
#endif
#ifndef SM_CYCURSOR
inline constexpr std::uint32_t SM_CYCURSOR = 14u;
#endif
#ifndef SM_CYDLGFRAME
inline constexpr std::uint32_t SM_CYDLGFRAME = 8u;
#endif
#ifndef SM_CYDOUBLECLK
inline constexpr std::uint32_t SM_CYDOUBLECLK = 37u;
#endif
#ifndef SM_CYDRAG
inline constexpr std::uint32_t SM_CYDRAG = 69u;
#endif
#ifndef SM_CYEDGE
inline constexpr std::uint32_t SM_CYEDGE = 46u;
#endif
#ifndef SM_CYFIXEDFRAME
inline constexpr std::uint32_t SM_CYFIXEDFRAME = 8u;
#endif
#ifndef SM_CYFOCUSBORDER
inline constexpr std::uint32_t SM_CYFOCUSBORDER = 84u;
#endif
#ifndef SM_CYFRAME
inline constexpr std::uint32_t SM_CYFRAME = 33u;
#endif
#ifndef SM_CYFULLSCREEN
inline constexpr std::uint32_t SM_CYFULLSCREEN = 17u;
#endif
#ifndef SM_CYHSCROLL
inline constexpr std::uint32_t SM_CYHSCROLL = 3u;
#endif
#ifndef SM_CYICON
inline constexpr std::uint32_t SM_CYICON = 12u;
#endif
#ifndef CRYPT_STRING_BASE64HEADER
inline constexpr std::uint32_t CRYPT_STRING_BASE64HEADER = 0u;
#endif
#ifndef CRYPT_STRING_BASE64
inline constexpr std::uint32_t CRYPT_STRING_BASE64 = 1u;
#endif
#ifndef CRYPT_STRING_BINARY
inline constexpr std::uint32_t CRYPT_STRING_BINARY = 2u;
#endif
#ifndef CRYPT_STRING_BASE64REQUESTHEADER
inline constexpr std::uint32_t CRYPT_STRING_BASE64REQUESTHEADER = 3u;
#endif
#ifndef FILE_ADD_FILE
inline constexpr std::uint32_t FILE_ADD_FILE = 0x0002;
#endif
#ifndef FILE_ADD_SUBDIRECTORY
inline constexpr std::uint32_t FILE_ADD_SUBDIRECTORY = 0x0004;
#endif
#ifndef FILE_APPEND_DATA
inline constexpr std::uint32_t FILE_APPEND_DATA = 0x0004;
#endif
#ifndef FILE_CREATE_PIPE_INSTANCE
inline constexpr std::uint32_t FILE_CREATE_PIPE_INSTANCE = 0x0004;
#endif
#ifndef FILE_DELETE_CHILD
inline constexpr std::uint32_t FILE_DELETE_CHILD = 0x0040;
#endif
#ifndef FILE_EXECUTE
inline constexpr std::uint32_t FILE_EXECUTE = 0x0020;
#endif
#ifndef FILE_LIST_DIRECTORY
inline constexpr std::uint32_t FILE_LIST_DIRECTORY = 0x0001;
#endif
#ifndef FILE_READ_ATTRIBUTES
inline constexpr std::uint32_t FILE_READ_ATTRIBUTES = 0x0080;
#endif
#ifndef FILE_READ_DATA
inline constexpr std::uint32_t FILE_READ_DATA = 0x0001;
#endif
#ifndef FILE_READ_EA
inline constexpr std::uint32_t FILE_READ_EA = 0x0008;
#endif
#ifndef FILE_TRAVERSE
inline constexpr std::uint32_t FILE_TRAVERSE = 0x0020;
#endif
#ifndef FILE_WRITE_ATTRIBUTES
inline constexpr std::uint32_t FILE_WRITE_ATTRIBUTES = 0x0100;
#endif
#ifndef FILE_WRITE_DATA
inline constexpr std::uint32_t FILE_WRITE_DATA = 0x0002;
#endif
#ifndef FILE_WRITE_EA
inline constexpr std::uint32_t FILE_WRITE_EA = 0x0010;
#endif
#ifndef FILE_ATTRIBUTE_ARCHIVE
inline constexpr std::uint32_t FILE_ATTRIBUTE_ARCHIVE = 0x0020;
#endif
#ifndef FILE_ATTRIBUTE_COMPRESSED
inline constexpr std::uint32_t FILE_ATTRIBUTE_COMPRESSED = 0x0800;
#endif
#ifndef FILE_ATTRIBUTE_DEVICE
inline constexpr std::uint32_t FILE_ATTRIBUTE_DEVICE = 0x0040;
#endif
#ifndef FILE_ATTRIBUTE_DIRECTORY
inline constexpr std::uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x0010;
#endif
#ifndef FILE_ATTRIBUTE_ENCRYPTED
inline constexpr std::uint32_t FILE_ATTRIBUTE_ENCRYPTED = 0x4000;
#endif
#ifndef FILE_ATTRIBUTE_HIDDEN
inline constexpr std::uint32_t FILE_ATTRIBUTE_HIDDEN = 0x0002;
#endif
#ifndef FILE_ATTRIBUTE_INTEGRITY_STREAM
inline constexpr std::uint32_t FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000;
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
inline constexpr std::uint32_t FILE_ATTRIBUTE_NORMAL = 0x0080;
#endif
#ifndef FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
inline constexpr std::uint32_t FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000;
#endif
#ifndef FILE_ATTRIBUTE_NO_SCRUB_DATA
inline constexpr std::uint32_t FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x20000;
#endif
#ifndef FILE_ATTRIBUTE_OFFLINE
inline constexpr std::uint32_t FILE_ATTRIBUTE_OFFLINE = 0x1000;
#endif
#ifndef FILE_ATTRIBUTE_READONLY
inline constexpr std::uint32_t FILE_ATTRIBUTE_READONLY = 0x0001;
#endif
#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
inline constexpr std::uint32_t FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000;
#endif
#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
inline constexpr std::uint32_t FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000;
#endif
#ifndef FILE_ATTRIBUTE_REPARSE_POINT
inline constexpr std::uint32_t FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
#endif
#ifndef FILE_ATTRIBUTE_SPARSE_FILE
inline constexpr std::uint32_t FILE_ATTRIBUTE_SPARSE_FILE = 0x0004;
#endif
#ifndef FILE_ATTRIBUTE_TEMPORARY
inline constexpr std::uint32_t FILE_ATTRIBUTE_TEMPORARY = 0x0100;
#endif
#ifndef FILE_ATTRIBUTE_VIRTUAL
inline constexpr std::uint32_t FILE_ATTRIBUTE_VIRTUAL = 0x10000;
#endif
#ifndef HFILE_ERROR
inline constexpr std::int32_t HFILE_ERROR = -1;
#endif
#ifndef SHGFI_ADDOVERLAYS
inline constexpr std::uint32_t SHGFI_ADDOVERLAYS = 0x000000020;
#endif
#ifndef SHGFI_ATTR_SPECIFIED
inline constexpr std::uint32_t SHGFI_ATTR_SPECIFIED = 0x000020000;
#endif
#ifndef SHGFI_ATTRIBUTES
inline constexpr std::uint32_t SHGFI_ATTRIBUTES = 0x000000800;
#endif
#ifndef SHGFI_DISPLAYNAME
inline constexpr std::uint32_t SHGFI_DISPLAYNAME = 0x000000200;
#endif
#ifndef SHGFI_EXETYPE
inline constexpr std::uint32_t SHGFI_EXETYPE = 0x000002000;
#endif
#ifndef SHGFI_ICON
inline constexpr std::uint32_t SHGFI_ICON = 0x000000100;
#endif
#ifndef SHGFI_ICONLOCATION
inline constexpr std::uint32_t SHGFI_ICONLOCATION = 0x000001000;
#endif
#ifndef SHGFI_LARGEICON
inline constexpr std::uint32_t SHGFI_LARGEICON = 0x000000000;
#endif
#ifndef TH32CS_INHERIT
inline constexpr std::uint32_t TH32CS_INHERIT = 0x80000000;
#endif
#ifndef TH32CS_SNAPHEAPLIST
inline constexpr std::uint32_t TH32CS_SNAPHEAPLIST = 0x00000001;
#endif
#ifndef TH32CS_SNAPMODULE
inline constexpr std::uint32_t TH32CS_SNAPMODULE = 0x00000008;
#endif
#ifndef TH32CS_SNAPMODULE32
inline constexpr std::uint32_t TH32CS_SNAPMODULE32 = 0x00000010;
#endif
#ifndef TH32CS_SNAPPROCESS
inline constexpr std::uint32_t TH32CS_SNAPPROCESS = 0x00000002;
#endif
#ifndef TH32CS_SNAPTHREAD
inline constexpr std::uint32_t TH32CS_SNAPTHREAD = 0x00000004;
#endif
#ifndef CSIDL_ADMINTOOLS
inline constexpr std::uint32_t CSIDL_ADMINTOOLS = 0x30;
#endif
#ifndef CSIDL_ALTSTARTUP
inline constexpr std::uint32_t CSIDL_ALTSTARTUP = 0x1D;
#endif
#ifndef CSIDL_APPDATA
inline constexpr std::uint32_t CSIDL_APPDATA = 0x1A;
#endif
#ifndef CSIDL_BITBUCKET
inline constexpr std::uint32_t CSIDL_BITBUCKET = 0x0A;
#endif
#ifndef CSIDL_CDBURN_AREA
inline constexpr std::uint32_t CSIDL_CDBURN_AREA = 0x3B;
#endif
#ifndef CSIDL_COMMON_ADMINTOOLS
inline constexpr std::uint32_t CSIDL_COMMON_ADMINTOOLS = 0x2F;
#endif
#ifndef CSIDL_COMMON_ALTSTARTUP
inline constexpr std::uint32_t CSIDL_COMMON_ALTSTARTUP = 0x1E;
#endif
#ifndef CSIDL_COMMON_APPDATA
inline constexpr std::uint32_t CSIDL_COMMON_APPDATA = 0x23;
#endif
#ifndef CSIDL_FLAG_CREATE
inline constexpr std::uint32_t CSIDL_FLAG_CREATE = 0x8000;
#endif
#ifndef SW_HIDE
inline constexpr std::uint32_t SW_HIDE = 0u;
#endif
#ifndef SW_MAXIMIZE
inline constexpr std::uint32_t SW_MAXIMIZE = 3u;
#endif
#ifndef SW_MINIMIZE
inline constexpr std::uint32_t SW_MINIMIZE = 6u;
#endif
#ifndef SW_RESTORE
inline constexpr std::uint32_t SW_RESTORE = 9u;
#endif
#ifndef SW_SHOW
inline constexpr std::uint32_t SW_SHOW = 5u;
#endif
#ifndef SW_SHOWDEFAULT
inline constexpr std::uint32_t SW_SHOWDEFAULT = 10u;
#endif
#ifndef SW_SHOWMAXIMIZED
inline constexpr std::uint32_t SW_SHOWMAXIMIZED = 3u;
#endif
#ifndef SW_SHOWMINIMIZED
inline constexpr std::uint32_t SW_SHOWMINIMIZED = 2u;
#endif
#ifndef SW_SHOWMINNOACTIVE
inline constexpr std::uint32_t SW_SHOWMINNOACTIVE = 7u;
#endif
#ifndef SW_SHOWNA
inline constexpr std::uint32_t SW_SHOWNA = 8u;
#endif
#ifndef SW_SHOWNOACTIVATE
inline constexpr std::uint32_t SW_SHOWNOACTIVATE = 4u;
#endif
#ifndef SW_SHOWNORMAL
inline constexpr std::uint32_t SW_SHOWNORMAL = 1u;
#endif
#ifndef VER_NT_DOMAIN_CONTROLLER
inline constexpr std::uint32_t VER_NT_DOMAIN_CONTROLLER = 0x0000002;
#endif
#ifndef VER_NT_SERVER
inline constexpr std::uint32_t VER_NT_SERVER = 0x0000003;
#endif
#ifndef VER_NT_WORKSTATION
inline constexpr std::uint32_t VER_NT_WORKSTATION = 0x0000001;
#endif
#ifndef MAXUSHORT
inline constexpr std::uint32_t MAXUSHORT = 0xffff;
#endif
#ifndef DRIVE_UNKNOWN
inline constexpr std::uint32_t DRIVE_UNKNOWN = 0u;
#endif
#ifndef DRIVE_NO_ROOT_DIR
inline constexpr std::uint32_t DRIVE_NO_ROOT_DIR = 1u;
#endif
#ifndef DRIVE_REMOVABLE
inline constexpr std::uint32_t DRIVE_REMOVABLE = 2u;
#endif
#ifndef DRIVE_FIXED
inline constexpr std::uint32_t DRIVE_FIXED = 3u;
#endif
#ifndef DRIVE_REMOTE
inline constexpr std::uint32_t DRIVE_REMOTE = 4u;
#endif
#ifndef DRIVE_CDROM
inline constexpr std::uint32_t DRIVE_CDROM = 5u;
#endif
#ifndef DRIVE_RAMDISK
inline constexpr std::uint32_t DRIVE_RAMDISK = 6u;
#endif
#ifndef FILE_TYPE_CHAR
inline constexpr std::uint32_t FILE_TYPE_CHAR = 0x2;
#endif
#ifndef FILE_TYPE_DISK
inline constexpr std::uint32_t FILE_TYPE_DISK = 0x1;
#endif
#ifndef FILE_TYPE_PIPE
inline constexpr std::uint32_t FILE_TYPE_PIPE = 0x3;
#endif
#ifndef FILE_TYPE_REMOTE
inline constexpr std::uint32_t FILE_TYPE_REMOTE = 0x800;
#endif
#ifndef FILE_TYPE_UNKNOWN
inline constexpr std::uint32_t FILE_TYPE_UNKNOWN = 0x0;
#endif
#ifndef PF_XSAVE_ENABLED
inline constexpr std::uint32_t PF_XSAVE_ENABLED = 0x17;
#endif
// the upstream const.py pins PF_XSAVE_ENABLED = 0x17 (23); the winnt.h macro
// preempts the name with the decimal 17 on _WIN32, so the IsProcessorFeature
//Present handler pins the upstream value explicitly under a different name
inline constexpr std::uint32_t KAPI_PF_XSAVE_ENABLED_UPSTREAM = 0x17;
#ifndef ProcessBasicInformation
inline constexpr std::uint32_t ProcessBasicInformation = 0u;
#endif
#ifndef ProcessDebugPort
inline constexpr std::uint32_t ProcessDebugPort = 7u;
#endif
#ifndef ProcessWow64Information
inline constexpr std::uint32_t ProcessWow64Information = 26u;
#endif
#ifndef ProcessImageFileName
inline constexpr std::uint32_t ProcessImageFileName = 27u;
#endif
#ifndef ProcessBreakOnTermination
inline constexpr std::uint32_t ProcessBreakOnTermination = 29u;
#endif
#ifndef ProcessProtectionInformation
inline constexpr std::uint32_t ProcessProtectionInformation = 61u;
#endif
#ifndef ProcessDebugObjectHandle
inline constexpr std::uint32_t ProcessDebugObjectHandle = 30u;
#endif
#ifndef ProcessDebugFlags
inline constexpr std::uint32_t ProcessDebugFlags = 31u;
#endif
#ifndef ProcessExecuteFlags
inline constexpr std::uint32_t ProcessExecuteFlags = 34u;
#endif
#ifndef ProcessCookie
inline constexpr std::uint32_t ProcessCookie = 36u;
#endif
#ifndef ProcessImageInformation
inline constexpr std::uint32_t ProcessImageInformation = 37u;
#endif
#ifndef ProcessMitigationPolicy
inline constexpr std::uint32_t ProcessMitigationPolicy = 52u;
#endif
#ifndef ProcessFaultInformation
inline constexpr std::uint32_t ProcessFaultInformation = 63u;
#endif
#ifndef ThreadBasicInformation
inline constexpr std::uint32_t ThreadBasicInformation = 0x0;
#endif
#ifndef ThreadTimes
inline constexpr std::uint32_t ThreadTimes = 0x1;
#endif
#ifndef ThreadPriority
inline constexpr std::uint32_t ThreadPriority = 0x2;
#endif
#ifndef ThreadHideFromDebugger
inline constexpr std::uint32_t ThreadHideFromDebugger = 0x11;
#endif
#ifndef MB_OK
inline constexpr std::uint32_t MB_OK = 0x00000000;
#endif
#ifndef MB_OKCANCEL
inline constexpr std::uint32_t MB_OKCANCEL = 0x00000001;
#endif
#ifndef MB_ABORTRETRYIGNORE
inline constexpr std::uint32_t MB_ABORTRETRYIGNORE = 0x00000002;
#endif
#ifndef MB_YESNOCANCEL
inline constexpr std::uint32_t MB_YESNOCANCEL = 0x00000003;
#endif
#ifndef MB_YESNO
inline constexpr std::uint32_t MB_YESNO = 0x00000004;
#endif
#ifndef MB_RETRYCANCEL
inline constexpr std::uint32_t MB_RETRYCANCEL = 0x00000005;
#endif
#ifndef MB_CANCELTRYCONTINUE
inline constexpr std::uint32_t MB_CANCELTRYCONTINUE = 0x00000006;
#endif
#ifndef MB_ICONERROR
inline constexpr std::uint32_t MB_ICONERROR = 0x00000010;
#endif
#ifndef MB_ICONQUESTION
inline constexpr std::uint32_t MB_ICONQUESTION = 0x00000020;
#endif
#ifndef MB_ICONWARNING
inline constexpr std::uint32_t MB_ICONWARNING = 0x00000030;
#endif
#ifndef MB_ICONINFORMATION
inline constexpr std::uint32_t MB_ICONINFORMATION = 0x00000040;
#endif
#ifndef MB_DEFBUTTON1
inline constexpr std::uint32_t MB_DEFBUTTON1 = 0x00000000;
#endif
#ifndef MB_DEFBUTTON2
inline constexpr std::uint32_t MB_DEFBUTTON2 = 0x00000100;
#endif
#ifndef MB_DEFBUTTON3
inline constexpr std::uint32_t MB_DEFBUTTON3 = 0x00000200;
#endif
#ifndef MB_DEFBUTTON4
inline constexpr std::uint32_t MB_DEFBUTTON4 = 0x00000300;
#endif
#ifndef MB_APPLMODAL
inline constexpr std::uint32_t MB_APPLMODAL = 0x00000000;
#endif
#ifndef MB_SYSTEMMODAL
inline constexpr std::uint32_t MB_SYSTEMMODAL = 0x00001000;
#endif
#ifndef MB_TASKMODAL
inline constexpr std::uint32_t MB_TASKMODAL = 0x00002000;
#endif
#ifndef MB_HELP
inline constexpr std::uint32_t MB_HELP = 0x00004000;
#endif
#ifndef MB_SETFOREGROUND
inline constexpr std::uint32_t MB_SETFOREGROUND = 0x00010000;
#endif
#ifndef MB_DEFAULT_DESKTOP_ONLY
inline constexpr std::uint32_t MB_DEFAULT_DESKTOP_ONLY = 0x00020000;
#endif
#ifndef MB_TOPMOST
inline constexpr std::uint32_t MB_TOPMOST = 0x00040000;
#endif
#ifndef MB_RIGHT
inline constexpr std::uint32_t MB_RIGHT = 0x00080000;
#endif
#ifndef MB_RTLREADING
inline constexpr std::uint32_t MB_RTLREADING = 0x00100000;
#endif
#ifndef MB_SERVICE_NOTIFICATION
inline constexpr std::uint32_t MB_SERVICE_NOTIFICATION = 0x00200000;
#endif
#ifndef IDOK
inline constexpr std::uint32_t IDOK = 1u;
#endif
#ifndef IDCANCEL
inline constexpr std::uint32_t IDCANCEL = 2u;
#endif
#ifndef IDABORT
inline constexpr std::uint32_t IDABORT = 3u;
#endif
#ifndef IDRETRY
inline constexpr std::uint32_t IDRETRY = 4u;
#endif
#ifndef IDIGNORE
inline constexpr std::uint32_t IDIGNORE = 5u;
#endif
#ifndef IDYES
inline constexpr std::uint32_t IDYES = 6u;
#endif
#ifndef IDNO
inline constexpr std::uint32_t IDNO = 7u;
#endif
#ifndef IDTRYAGAIN
inline constexpr std::uint32_t IDTRYAGAIN = 10u;
#endif
#ifndef IDCONTINUE
inline constexpr std::uint32_t IDCONTINUE = 11u;
#endif
#ifndef CF_TEXT
inline constexpr std::uint32_t CF_TEXT = 1u;
#endif
#ifndef CF_BITMAP
inline constexpr std::uint32_t CF_BITMAP = 2u;
#endif
#ifndef CF_METAFILEPICT
inline constexpr std::uint32_t CF_METAFILEPICT = 3u;
#endif
#ifndef CF_SYLK
inline constexpr std::uint32_t CF_SYLK = 4u;
#endif
#ifndef CF_DIF
inline constexpr std::uint32_t CF_DIF = 5u;
#endif
#ifndef CF_TIFF
inline constexpr std::uint32_t CF_TIFF = 6u;
#endif
#ifndef CF_OEMTEXT
inline constexpr std::uint32_t CF_OEMTEXT = 7u;
#endif
#ifndef CF_DIB
inline constexpr std::uint32_t CF_DIB = 8u;
#endif
#ifndef CF_PALETTE
inline constexpr std::uint32_t CF_PALETTE = 9u;
#endif
#ifndef CF_PENDATA
inline constexpr std::uint32_t CF_PENDATA = 10u;
#endif
#ifndef CF_RIFF
inline constexpr std::uint32_t CF_RIFF = 11u;
#endif
#ifndef CF_WAVE
inline constexpr std::uint32_t CF_WAVE = 12u;
#endif
#ifndef CF_UNICODETEXT
inline constexpr std::uint32_t CF_UNICODETEXT = 13u;
#endif
#ifndef CF_ENHMETAFILE
inline constexpr std::uint32_t CF_ENHMETAFILE = 14u;
#endif
#ifndef CF_HDROP
inline constexpr std::uint32_t CF_HDROP = 15u;
#endif
#ifndef CF_LOCALE
inline constexpr std::uint32_t CF_LOCALE = 16u;
#endif
#ifndef CF_MAX
inline constexpr std::uint32_t CF_MAX = 17u;
#endif
#ifndef CF_OWNERDISPLAY
inline constexpr std::uint32_t CF_OWNERDISPLAY = 128u;
#endif
#ifndef CF_DSPTEXT
inline constexpr std::uint32_t CF_DSPTEXT = 129u;
#endif
#ifndef CF_DSPBITMAP
inline constexpr std::uint32_t CF_DSPBITMAP = 130u;
#endif
#ifndef CF_DSPMETAFILEPICT
inline constexpr std::uint32_t CF_DSPMETAFILEPICT = 131u;
#endif
#ifndef CF_DSPENHMETAFILE
inline constexpr std::uint32_t CF_DSPENHMETAFILE = 142u;
#endif
#ifndef CF_PRIVATEFIRST
inline constexpr std::uint32_t CF_PRIVATEFIRST = 512u;
#endif
#ifndef CF_PRIVATELAST
inline constexpr std::uint32_t CF_PRIVATELAST = 767u;
#endif
#ifndef CF_GDIOBJFIRST
inline constexpr std::uint32_t CF_GDIOBJFIRST = 768u;
#endif
#ifndef CF_GDIOBJLAST
inline constexpr std::uint32_t CF_GDIOBJLAST = 1023u;
#endif
#ifndef LOAD_LIBRARY_SEARCH_APPLICATION_DIR
inline constexpr std::uint32_t LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;
#endif
#ifndef LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
inline constexpr std::uint32_t LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;
#endif
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
inline constexpr std::uint32_t LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
#endif
#ifndef LOAD_LIBRARY_SEARCH_USER_DIRS
inline constexpr std::uint32_t LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400;
#endif
#ifndef CSTR_LESS_THAN
inline constexpr std::uint32_t CSTR_LESS_THAN = 1u;
#endif
#ifndef CSTR_EQUAL
inline constexpr std::uint32_t CSTR_EQUAL = 2u;
#endif
#ifndef CSTR_GREATER_THAN
inline constexpr std::uint32_t CSTR_GREATER_THAN = 3u;
#endif
#ifndef PAGE_EXECUTE
inline constexpr std::uint32_t PAGE_EXECUTE = 0x10;
#endif
#ifndef PAGE_EXECUTE_READ
inline constexpr std::uint32_t PAGE_EXECUTE_READ = 0x20;
#endif
#ifndef PAGE_EXECUTE_READWRITE
inline constexpr std::uint32_t PAGE_EXECUTE_READWRITE = 0x40;
#endif
#ifndef PAGE_EXECUTE_WRITECOPY
inline constexpr std::uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
#endif
#ifndef PAGE_NOACCESS
inline constexpr std::uint32_t PAGE_NOACCESS = 0x1;
#endif
#ifndef PAGE_READONLY
inline constexpr std::uint32_t PAGE_READONLY = 0x2;
#endif
#ifndef PAGE_READWRITE
inline constexpr std::uint32_t PAGE_READWRITE = 0x4;
#endif
#ifndef PAGE_WRITECOPY
inline constexpr std::uint32_t PAGE_WRITECOPY = 0x8;
#endif
#ifndef PAGE_TARGETS_INVALID
inline constexpr std::uint32_t PAGE_TARGETS_INVALID = 0x40000000;
#endif
#ifndef PAGE_TARGETS_NO_UPDATE
inline constexpr std::uint32_t PAGE_TARGETS_NO_UPDATE = 0x40000000;
#endif
#ifndef PAGE_GUARD
inline constexpr std::uint32_t PAGE_GUARD = 0x100;
#endif
#ifndef PAGE_NOCACHE
inline constexpr std::uint32_t PAGE_NOCACHE = 0x200;
#endif
#ifndef PAGE_WRITECOMBINE
inline constexpr std::uint32_t PAGE_WRITECOMBINE = 0x400;
#endif
#ifndef ObjectTypeInformation
inline constexpr std::uint32_t ObjectTypeInformation = 0x2;
#endif
#ifndef ObjectBasicInformation
inline constexpr std::uint32_t ObjectBasicInformation = 0x1;
#endif
#ifndef ObjectAllTypesInformation
inline constexpr std::uint32_t ObjectAllTypesInformation = 0x3;
#endif
#ifndef HANDLE_FLAG_INHERIT
inline constexpr std::uint32_t HANDLE_FLAG_INHERIT = 0x1;
#endif
#ifndef HANDLE_FLAG_PROTECT_FROM_CLOSE
inline constexpr std::uint32_t HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2;
#endif
#ifndef OF_READ
inline constexpr std::uint32_t OF_READ = 0x00000000;
#endif
#ifndef OF_WRITE
inline constexpr std::uint32_t OF_WRITE = 0x00000001;
#endif
#ifndef OF_READWRITE
inline constexpr std::uint32_t OF_READWRITE = 0x00000002;
#endif
#ifndef OF_PARSE
inline constexpr std::uint32_t OF_PARSE = 0x00000100;
#endif
#ifndef OF_DELETE
inline constexpr std::uint32_t OF_DELETE = 0x00000200;
#endif
#ifndef OF_VERIFY
inline constexpr std::uint32_t OF_VERIFY = 0x00000400;
#endif
#ifndef OF_CANCEL
inline constexpr std::uint32_t OF_CANCEL = 0x00000800;
#endif
#ifndef OF_CREATE
inline constexpr std::uint32_t OF_CREATE = 0x00001000;
#endif
#ifndef OF_PROMPT
inline constexpr std::uint32_t OF_PROMPT = 0x00002000;
#endif
#ifndef OF_EXIST
inline constexpr std::uint32_t OF_EXIST = 0x00004000;
#endif
#ifndef OF_REOPEN
inline constexpr std::uint32_t OF_REOPEN = 0x00008000;
#endif
#ifndef OF_SHARE_COMPAT
inline constexpr std::uint32_t OF_SHARE_COMPAT = 0x00000000;
#endif
#ifndef OF_SHARE_EXCLUSIVE
inline constexpr std::uint32_t OF_SHARE_EXCLUSIVE = 0x00000010;
#endif
#ifndef OF_SHARE_DENY_WRITE
inline constexpr std::uint32_t OF_SHARE_DENY_WRITE = 0x00000020;
#endif
#ifndef OF_SHARE_DENY_READ
inline constexpr std::uint32_t OF_SHARE_DENY_READ = 0x00000030;
#endif
#ifndef OF_SHARE_DENY_NONE
inline constexpr std::uint32_t OF_SHARE_DENY_NONE = 0x00000040;
#endif
#ifndef CP_ACP
inline constexpr std::uint32_t CP_ACP = 0u;
#endif
#ifndef CP_OEMCP
inline constexpr std::uint32_t CP_OEMCP = 1u;
#endif
#ifndef CP_THREAD_ACP
inline constexpr std::uint32_t CP_THREAD_ACP = 3u;
#endif
#ifndef CP_UTF16
inline constexpr std::uint32_t CP_UTF16 = 1200u;
#endif
#ifndef CP_UTF16BE
inline constexpr std::uint32_t CP_UTF16BE = 1201u;
#endif
#ifndef CP_ASCII
inline constexpr std::uint32_t CP_ASCII = 20127u;
#endif
#ifndef CP_UTF7
inline constexpr std::uint32_t CP_UTF7 = 65000u;
#endif
#ifndef CP_UTF8
inline constexpr std::uint32_t CP_UTF8 = 65001u;
#endif
#ifndef WC_DISCARDNS
inline constexpr std::uint32_t WC_DISCARDNS = 0x0010;
#endif
#ifndef WC_SEPCHARS
inline constexpr std::uint32_t WC_SEPCHARS = 0x0020;
#endif
#ifndef WC_DEFAULTCHAR
inline constexpr std::uint32_t WC_DEFAULTCHAR = 0x0040;
#endif
#ifndef WC_ERR_INVALID_CHARS
inline constexpr std::uint32_t WC_ERR_INVALID_CHARS = 0x0080;
#endif
#ifndef WC_COMPOSITECHECK
inline constexpr std::uint32_t WC_COMPOSITECHECK = 0x0200;
#endif
#ifndef WC_NO_BEST_FIT_CHARS
inline constexpr std::uint32_t WC_NO_BEST_FIT_CHARS = 0x0400;
#endif
#ifndef TIME_ZONE_ID_INVALID
inline constexpr std::int32_t TIME_ZONE_ID_INVALID = -1;
#endif
#ifndef MAPVK_VK_TO_VSC
inline constexpr std::uint32_t MAPVK_VK_TO_VSC = 0u;
#endif

// const.py MAP_VK: the MapVirtualKeyW table keyed by the map type (the
// upstream carries the single MAPVK_VK_TO_VSC dict: the shift/ctrl/alt/win
// vk codes -> the scan codes, inserted for one sample)
inline const std::map<std::uint32_t, std::map<std::uint32_t, std::uint32_t>> MAP_VK = {
    {0, {
        {0x5b, 0x5b},
        {0x10, 0x2a},
        {0xa0, 0x2a},
        {0xa1, 0x36},
        {0x11, 0x1d},
        {0x12, 0x38},
    }},
};

#ifndef HEAP_NO_SERIALIZE
inline constexpr std::uint32_t HEAP_NO_SERIALIZE = 0x00000001;
#endif
#ifndef HEAP_GENERATE_EXCEPTIONS
inline constexpr std::uint32_t HEAP_GENERATE_EXCEPTIONS = 0x00000004;
#endif
#ifndef HEAP_ZERO_MEMORY
inline constexpr std::uint32_t HEAP_ZERO_MEMORY = 0x00000008;
#endif
#ifndef HEAP_REALLOC_IN_PLACE_ONLY
inline constexpr std::uint32_t HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
#endif
#ifndef HEAP_CREATE_ENABLE_EXECUTE
inline constexpr std::uint32_t HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;
#endif

}  // namespace win
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_CONST_HPP
