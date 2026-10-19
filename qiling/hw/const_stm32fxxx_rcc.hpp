// Ported from qiling/hw/const/stm32fxxx_rcc.py (the RCC bit tables the F1
// and the F4 rcc peripherals share verbatim — the used subset: the CR, the
// CFGR and the CSR fields the rdyon step walk references).
#pragma once

#ifndef QILING_HW_CONST_STM32FXXX_RCC_HPP
#define QILING_HW_CONST_STM32FXXX_RCC_HPP

#include <cstdint>

namespace qiling {
namespace hw {
namespace rcc {

// hw/const/stm32fxxx_rcc.py RCC_CR
namespace cr {
inline constexpr std::uint32_t HSION = 1u << 0;
inline constexpr std::uint32_t HSIRDY = 1u << 1;
inline constexpr std::uint32_t HSITRIM = 0x1Fu << 3;
inline constexpr std::uint32_t HSICAL = 0xFFu << 8;
inline constexpr std::uint32_t HSEON = 1u << 16;
inline constexpr std::uint32_t HSERDY = 1u << 17;
inline constexpr std::uint32_t HSEBYP = 1u << 18;
inline constexpr std::uint32_t CSSON = 1u << 19;
inline constexpr std::uint32_t PLLI2SRDY = 1u << 27;
inline constexpr std::uint32_t PLLI2SON = 1u << 26;
inline constexpr std::uint32_t PLLRDY = 1u << 25;
inline constexpr std::uint32_t PLLON = 1u << 24;
}  // namespace cr

// hw/const/stm32fxxx_rcc.py RCC_CFGR
namespace cfgr {
inline constexpr std::uint32_t SW = 0x3u << 0;
inline constexpr std::uint32_t SW_0 = 1u << 0;
inline constexpr std::uint32_t SW_1 = 1u << 1;
inline constexpr std::uint32_t SWS = 0x3u << 2;
inline constexpr std::uint32_t SWS_0 = 1u << 2;
inline constexpr std::uint32_t SWS_1 = 1u << 3;
}  // namespace cfgr

// hw/const/stm32fxxx_rcc.py RCC_CSR
namespace csr {
inline constexpr std::uint32_t LSION = 1u << 0;
inline constexpr std::uint32_t LSIRDY = 1u << 1;
}  // namespace csr

}  // namespace rcc
}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_CONST_STM32FXXX_RCC_HPP
