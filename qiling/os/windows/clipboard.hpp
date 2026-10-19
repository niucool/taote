// Ported from qiling/os/windows/clipboard.py — the clipboard simulation (the
// CF_* formats and the ERROR_* id come from os/windows/const.py). The locker
// identity resolves through the os thread manager when a null hWnd is given;
// the thread-manager wiring lands with the thread slice.
#ifndef QILING_OS_WINDOWS_CLIPBOARD_HPP
#define QILING_OS_WINDOWS_CLIPBOARD_HPP

#include <cstdint>
#include <string>
#include <vector>

// the QlOsWindows forward (the clipboard holds the os pointer; the full
// definition lands with the .cpp — the windows.hpp ↔ clipboard.hpp include
// cycle stays broken here)

namespace qiling {
namespace os {
namespace windows {

class QlOsWindows;

// os/windows/const.py: the standard clipboard formats. The CF_*/ERROR_* names
// collide with windows.h macros, so the QL_-prefixed spellings are used (the
// QlStdcall precedent).
inline constexpr std::uint32_t QL_CF_TEXT = 1;
inline constexpr std::uint32_t QL_CF_BITMAP = 2;
inline constexpr std::uint32_t QL_CF_METAFILEPICT = 3;
inline constexpr std::uint32_t QL_CF_SYLK = 4;
inline constexpr std::uint32_t QL_CF_DIF = 5;
inline constexpr std::uint32_t QL_CF_TIFF = 6;
inline constexpr std::uint32_t QL_CF_OEMTEXT = 7;
inline constexpr std::uint32_t QL_CF_DIB = 8;
inline constexpr std::uint32_t QL_CF_PALETTE = 9;
inline constexpr std::uint32_t QL_CF_PENDATA = 10;
inline constexpr std::uint32_t QL_CF_RIFF = 11;
inline constexpr std::uint32_t QL_CF_WAVE = 12;
inline constexpr std::uint32_t QL_CF_UNICODETEXT = 13;
inline constexpr std::uint32_t QL_CF_ENHMETAFILE = 14;
inline constexpr std::uint32_t QL_CF_HDROP = 15;
inline constexpr std::uint32_t QL_CF_LOCALE = 16;
inline constexpr std::uint32_t QL_CF_MAX = 17;
inline constexpr std::uint32_t QL_CF_OWNERDISPLAY = 0x0080;
inline constexpr std::uint32_t QL_CF_DSPTEXT = 0x0081;
inline constexpr std::uint32_t QL_CF_DSPBITMAP = 0x0082;
inline constexpr std::uint32_t QL_CF_DSPMETAFILEPICT = 0x0083;
inline constexpr std::uint32_t QL_CF_DSPENHMETAFILE = 0x0084;
inline constexpr std::uint32_t QL_CF_PRIVATEFIRST = 0x0200;
inline constexpr std::uint32_t QL_CF_PRIVATELAST = 0x02FF;
inline constexpr std::uint32_t QL_CF_GDIOBJFIRST = 0x0300;
inline constexpr std::uint32_t QL_CF_GDIOBJLAST = 0x03FF;

// const.py: the clipboard error
inline constexpr std::uint32_t QL_ERROR_CLIPBOARD_NOT_OPEN = 1418;

// const.py: the fiber-side invalid parameter
inline constexpr std::uint32_t QL_ERROR_INVALID_PARAMETER = 87;

inline constexpr std::int32_t NOT_LOCKED = -1;

class Clipboard {
public:
    explicit Clipboard(QlOsWindows* os);

    // open: lock the clipboard to the window handle (0 -> the current thread)
    bool open(std::uint32_t h_wnd);
    bool close();
    bool format_available(std::uint32_t fmt) const;

    // set_data: the text formats resolve through the emulated memory reader
    // (the QL_CF_TEXT handler reads a cstring, QL_CF_UNICODETEXT a wide string);
    // the address form takes the raw reader result
    void set_data_raw(std::uint32_t fmt, const std::string& data);
    std::string data() const { return data_; }

    // the locker check (set_data/get_data's guard)
    bool is_locked_by(std::uint32_t h_wnd) const noexcept { return locked_by_ == static_cast<std::int32_t>(h_wnd); }
    bool is_locked() const noexcept { return locked_by_ != NOT_LOCKED; }
    void force_lock(std::uint32_t h_wnd) noexcept { locked_by_ = static_cast<std::int32_t>(h_wnd); }

    std::uint32_t last_error() const noexcept { return last_error_; }

private:
    std::int32_t locked_by_ = NOT_LOCKED;
    std::string data_ = "Default Clipboard Data";
    QlOsWindows* os_ = nullptr;
    std::uint32_t last_error_ = 0;
};

}  // namespace windows
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_CLIPBOARD_HPP
