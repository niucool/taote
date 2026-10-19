// Ported from qiling/hw/const/stm32f4xx_tim.py (the TIM register bit tables
// — the F1/F4 timer peripherals share them verbatim).
#pragma once

#ifndef QILING_HW_CONST_STM32F4XX_TIM_HPP
#define QILING_HW_CONST_STM32F4XX_TIM_HPP

#include <cstdint>

namespace qiling {
namespace hw {
namespace tim {

// hw/const/stm32f4xx_tim.py TIM_CR1
namespace cr1 {
inline constexpr std::uint32_t CEN = 1u << 0;
inline constexpr std::uint32_t UDIS = 1u << 1;
inline constexpr std::uint32_t URS = 1u << 2;
inline constexpr std::uint32_t OPM = 1u << 3;
inline constexpr std::uint32_t DIR = 1u << 4;
inline constexpr std::uint32_t CMS = 0x3u << 5;
inline constexpr std::uint32_t ARPE = 1u << 7;
inline constexpr std::uint32_t CKD = 0x3u << 8;
}  // namespace cr1

// hw/const/stm32f4xx_tim.py TIM_CR2
namespace cr2 {
inline constexpr std::uint32_t CCPC = 1u << 0;
inline constexpr std::uint32_t CCS = 1u << 2;
inline constexpr std::uint32_t CCDS = 1u << 3;
inline constexpr std::uint32_t MMS = 0x7u << 4;
inline constexpr std::uint32_t TI1S = 1u << 7;
inline constexpr std::uint32_t OIS1 = 1u << 8;
inline constexpr std::uint32_t OIS1N = 1u << 9;
inline constexpr std::uint32_t OIS2 = 1u << 10;
inline constexpr std::uint32_t OIS2N = 1u << 11;
inline constexpr std::uint32_t OIS3 = 1u << 12;
inline constexpr std::uint32_t OIS3N = 1u << 13;
inline constexpr std::uint32_t OIS4 = 1u << 14;
}  // namespace cr2

// hw/const/stm32f4xx_tim.py TIM_SMCR
namespace smcr {
inline constexpr std::uint32_t SMS = 0x7u << 0;
inline constexpr std::uint32_t TS = 0x7u << 4;
inline constexpr std::uint32_t MSM = 1u << 7;
inline constexpr std::uint32_t ETF = 0xfu << 8;
inline constexpr std::uint32_t ETPS = 0x3u << 12;
inline constexpr std::uint32_t ECE = 1u << 14;
inline constexpr std::uint32_t ETP = 1u << 15;
}  // namespace smcr

// hw/const/stm32f4xx_tim.py TIM_DIER
namespace dier {
inline constexpr std::uint32_t UIE = 1u << 0;
inline constexpr std::uint32_t CC1IE = 1u << 1;
inline constexpr std::uint32_t CC2IE = 1u << 2;
inline constexpr std::uint32_t CC3IE = 1u << 3;
inline constexpr std::uint32_t CC4IE = 1u << 4;
inline constexpr std::uint32_t COMIE = 1u << 5;
inline constexpr std::uint32_t TIE = 1u << 6;
inline constexpr std::uint32_t BIE = 1u << 7;
inline constexpr std::uint32_t UDE = 1u << 8;
inline constexpr std::uint32_t CC1DE = 1u << 9;
inline constexpr std::uint32_t CC2DE = 1u << 10;
inline constexpr std::uint32_t CC3DE = 1u << 11;
inline constexpr std::uint32_t CC4DE = 1u << 12;
inline constexpr std::uint32_t COMDE = 1u << 13;
inline constexpr std::uint32_t TDE = 1u << 14;
}  // namespace dier

// hw/const/stm32f4xx_tim.py TIM_SR
namespace sr {
inline constexpr std::uint32_t UIF = 1u << 0;
inline constexpr std::uint32_t CC1IF = 1u << 1;
inline constexpr std::uint32_t CC2IF = 1u << 2;
inline constexpr std::uint32_t CC3IF = 1u << 3;
inline constexpr std::uint32_t CC4IF = 1u << 4;
inline constexpr std::uint32_t COMIF = 1u << 5;
inline constexpr std::uint32_t TIF = 1u << 6;
inline constexpr std::uint32_t BIF = 1u << 7;
inline constexpr std::uint32_t CC1OF = 1u << 9;
inline constexpr std::uint32_t CC2OF = 1u << 10;
inline constexpr std::uint32_t CC3OF = 1u << 11;
inline constexpr std::uint32_t CC4OF = 1u << 12;
}  // namespace sr

// hw/const/stm32f4xx_tim.py TIM_EGR
namespace egr {
inline constexpr std::uint32_t UG = 1u << 0;
inline constexpr std::uint32_t CC1G = 1u << 1;
inline constexpr std::uint32_t CC2G = 1u << 2;
inline constexpr std::uint32_t CC3G = 1u << 3;
inline constexpr std::uint32_t CC4G = 1u << 4;
inline constexpr std::uint32_t COMG = 1u << 5;
inline constexpr std::uint32_t TG = 1u << 6;
inline constexpr std::uint32_t BG = 1u << 7;
}  // namespace egr

}  // namespace tim
}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_CONST_STM32F4XX_TIM_HPP
