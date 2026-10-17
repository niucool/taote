// Ported from qiling/os/const.py — global primitive types used in fcalls and
// api hooks. Operating systems may map their own types to these, or create
// additional ones with custom resolvers (see: QlOs).
//
// Header-only: pure constants (mirror-layout rule 1).
#ifndef QILING_OS_CONST_HPP
#define QILING_OS_CONST_HPP

namespace qiling {
namespace os {

// global primitive types used in fcalls and api hooks
inline constexpr int PARAM_INT8 = 1;
inline constexpr int PARAM_INT16 = 2;
inline constexpr int PARAM_INT32 = 3;
inline constexpr int PARAM_INT64 = 4;
inline constexpr int PARAM_INTN = 5;

// a generic pointer type that may be used to index pointed types
inline constexpr int PARAM_PTRX = 128;

// common aliases to primitive types.
// TODO: let each OS define its own aliases and types (upstream note, verbatim)
//
// windows.h (pulled in by unicorn on WIN32) defines BYTE/DWORD/INT/UINT/BOOL
// as macros — the errno_value()/stdcall() precedent: the colliding aliases are
// omitted on Windows and the PARAM_* spellings are used instead.
#if !defined(_WIN32)
inline constexpr int BYTE = PARAM_INT8;
inline constexpr int DWORD = PARAM_INT32;
inline constexpr int INT = PARAM_INT32;
inline constexpr int UINT = PARAM_INT32;
inline constexpr int BOOL = PARAM_INT32;
inline constexpr long long LONGLONG = PARAM_INT64;
inline constexpr unsigned long long ULONGLONG = PARAM_INT64;
inline constexpr int SIZE_T = PARAM_INTN;
inline constexpr int POINTER = PARAM_INTN;
inline constexpr int HANDLE = PARAM_INTN;
inline constexpr int STRING = PARAM_PTRX + 1;
inline constexpr int WSTRING = PARAM_PTRX + 2;
inline constexpr int GUID = PARAM_PTRX + 3;
#endif  // !defined(_WIN32)

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_CONST_HPP
