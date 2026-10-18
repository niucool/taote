#include "qiling/os/windows/clipboard.hpp"

#include "qiling/os/windows/windows.hpp"

#include <algorithm>

namespace qiling {
namespace os {
namespace windows {

Clipboard::Clipboard(QlOsWindows* os) : os_(os) {
    // clipboard.py __init__: the supported format list
}

bool Clipboard::open(std::uint32_t h_wnd) {
    // clipboard.py open: lock to the window if not already locked elsewhere
    if (locked_by_ != NOT_LOCKED && locked_by_ != static_cast<std::int32_t>(h_wnd)) {
        return false;
    }

    locked_by_ = static_cast<std::int32_t>(h_wnd);
    return true;
}

bool Clipboard::close() {
    if (locked_by_ == NOT_LOCKED) {
        if (os_ != nullptr) {
            os_->set_last_error(QL_ERROR_CLIPBOARD_NOT_OPEN);
        }
        last_error_ = QL_ERROR_CLIPBOARD_NOT_OPEN;
        return false;
    }

    locked_by_ = NOT_LOCKED;
    return true;
}

bool Clipboard::format_available(std::uint32_t fmt) const {
    // clipboard.py formats: the standard set
    switch (fmt) {
        case QL_CF_TEXT:
        case QL_CF_BITMAP:
        case QL_CF_METAFILEPICT:
        case QL_CF_SYLK:
        case QL_CF_DIF:
        case QL_CF_TIFF:
        case QL_CF_OEMTEXT:
        case QL_CF_DIB:
        case QL_CF_PALETTE:
        case QL_CF_PENDATA:
        case QL_CF_RIFF:
        case QL_CF_WAVE:
        case QL_CF_UNICODETEXT:
        case QL_CF_ENHMETAFILE:
        case QL_CF_HDROP:
        case QL_CF_LOCALE:
        case QL_CF_MAX:
        case QL_CF_OWNERDISPLAY:
        case QL_CF_DSPTEXT:
        case QL_CF_DSPBITMAP:
        case QL_CF_DSPMETAFILEPICT:
        case QL_CF_DSPENHMETAFILE:
        case QL_CF_PRIVATEFIRST:
        case QL_CF_PRIVATELAST:
        case QL_CF_GDIOBJFIRST:
        case QL_CF_GDIOBJLAST:
            return true;
        default:
            return false;
    }
}

void Clipboard::set_data_raw(std::uint32_t fmt, const std::string& data) {
    // clipboard.py set_data: only the text formats carry content (the guard
    // runs in the api hook, which resolves the string through the memory)
    (void)fmt;
    data_ = data;
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
