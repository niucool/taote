// os/dos/interrupts/__init__.py — the handler table
//
// http://spike.scu.edu.au/~barry/interrupts.html
// http://www2.ift.ulaval.ca/~marchand/ift17583/dosints.pdf

#pragma once

#include <cstdint>

#include "qiling/core.hpp"

namespace qiling {
namespace os {
namespace dos {

using IntHandler = std::function<void(Qiling&)>;

// the intno -> handler map (the __init__.py handlers dict)
const std::map<unsigned, IntHandler>& handlers();

}  // namespace dos
}  // namespace os
}  // namespace qiling
