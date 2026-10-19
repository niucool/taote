// Ported from qiling/os/windows/api.py — the Windows SDK type aliases used in
// API signatures. Everything maps onto the os/const.hpp PARAM_* primitives;
// the names mirror the Python aliases verbatim. Alias groups collapse onto
// their primitive (api.py: e.g. LONG/ULONG → INTN; the P*/LP*/hook pointer
// families → POINTER; the A/W string families → STRING/WSTRING).
//
// windows.h macro collisions (BYTE/DWORD/...) follow the os/const.hpp
// precedent: the colliding spellings are omitted here; the PARAM_* names are
// used at call sites instead.
#ifndef QILING_OS_WINDOWS_API_HPP
#define QILING_OS_WINDOWS_API_HPP

#include "qiling/os/const.hpp"

namespace qiling {
namespace os {
namespace api {

// api.py: the primitive groups
inline constexpr int LONG_ = PARAM_INTN;
inline constexpr int ULONG_ = PARAM_INTN;
inline constexpr int CHAR_ = PARAM_INT8;
inline constexpr int UCHAR_ = PARAM_INT16;
inline constexpr int SHORT_ = PARAM_INT16;
inline constexpr int USHORT_ = PARAM_INT16;

inline constexpr int CCHAR_ = PARAM_INT8;
inline constexpr int WCHAR_ = PARAM_INT16;

inline constexpr int ACCESS_MASK_ = PARAM_INT32;
inline constexpr int BOOLEAN_ = PARAM_INT32;
inline constexpr int BOOL_ = PARAM_INT32;   // api.py: BOOL (the win32 BOOL is the 32-bit int)
inline constexpr int NTSTATUS_ = PARAM_INT32;
inline constexpr int WORD_ = PARAM_INT32;
inline constexpr int EVENT_TYPE_ = PARAM_INT32;
inline constexpr int KPROCESSOR_MODE_ = PARAM_INT32;
inline constexpr int PROCESSINFOCLASS_ = PARAM_INT32;
inline constexpr int THREADINFOCLASS_ = PARAM_INT32;
inline constexpr int SOCKET_ = PARAM_INT32;
inline constexpr int LCID_ = PARAM_PTRX;   // api.py: POINTER
inline constexpr int DWORD_ = PARAM_INT32;
inline constexpr int DWORD_PTR_ALIAS_ = PARAM_PTRX;
inline constexpr int UINT_ = PARAM_INT32;
inline constexpr int HANDLE_ = PARAM_PTRX;
inline constexpr int WORD_ALIAS_ = PARAM_INT32;
inline constexpr int DWORDLONG_ = PARAM_INT64;

// the HANDLE family (api.py: HINSTANCE/HKEY/HMODULE/HWND/PSID/SC_HANDLE → HANDLE)
inline constexpr int HINSTANCE_ = PARAM_PTRX;
inline constexpr int HKEY_ = PARAM_PTRX;
inline constexpr int HMODULE_ = PARAM_PTRX;
inline constexpr int HWND_ = PARAM_PTRX;

// the pointer families collapse to POINTER (P*/LP*/LPC*/REGSAM/UINT_PTR/...)
inline constexpr int LPVOID_ = PARAM_PTRX;
inline constexpr int LPDWORD_ = PARAM_PTRX;
inline constexpr int LPSTR_ = PARAM_PTRX;
inline constexpr int LPWSTR_ = PARAM_PTRX;
inline constexpr int LPHANDLE_ = PARAM_PTRX;
inline constexpr int PVOID_ = PARAM_PTRX;
inline constexpr int DWORD_PTR_ = PARAM_PTRX;
inline constexpr int ULONG_PTR_ = PARAM_PTRX;
inline constexpr int UINT_PTR_ = PARAM_PTRX;

// the string families
inline constexpr int LPCSTR_ = PARAM_PTRX + 1;    // STRING
inline constexpr int PCSTR_ = PARAM_PTRX + 1;
inline constexpr int LPCWSTR_ = PARAM_PTRX + 2;   // WSTRING
inline constexpr int LPWSTR_W_ = PARAM_PTRX + 2;

// the GUID resolver placeholder
inline constexpr int GUID_ = PARAM_PTRX + 3;

}  // namespace api
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_API_HPP
