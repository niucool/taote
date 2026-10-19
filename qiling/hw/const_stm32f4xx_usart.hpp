// Ported from qiling/hw/const/stm32f4xx_usart.py (the USART register bit
// tables — the F1 and the F4 usart peripherals share them verbatim).
#pragma once

#ifndef QILING_HW_CONST_STM32F4XX_USART_HPP
#define QILING_HW_CONST_STM32F4XX_USART_HPP

#include <cstdint>

namespace qiling {
namespace hw {
namespace usart {

// hw/const/stm32f4xx_usart.py USART_SR
namespace sr {
inline constexpr std::uint32_t CTS = 1u << 9;
inline constexpr std::uint32_t LBD = 1u << 8;
inline constexpr std::uint32_t TXE = 1u << 7;
inline constexpr std::uint32_t TC = 1u << 6;
inline constexpr std::uint32_t RXNE = 1u << 5;
inline constexpr std::uint32_t IDLE = 1u << 4;
inline constexpr std::uint32_t ORE = 1u << 3;
inline constexpr std::uint32_t NF = 1u << 2;
inline constexpr std::uint32_t FE = 1u << 1;
inline constexpr std::uint32_t PE = 1u << 0;
inline constexpr std::uint32_t RESET = TXE | TC;
}  // namespace sr

// hw/const/stm32f4xx_usart.py USART_DR
namespace dr {
inline constexpr std::uint32_t DR = 0x1ffu << 0;
}  // namespace dr

// hw/const/stm32f4xx_usart.py USART_BRR
namespace brr {
inline constexpr std::uint32_t DIV_FRACTION = 0xfu << 0;
inline constexpr std::uint32_t DIV_MANTISSA = 0xfffu << 4;
}  // namespace brr

// hw/const/stm32f4xx_usart.py USART_CR1
namespace cr1 {
inline constexpr std::uint32_t OVER8 = 1u << 15;
inline constexpr std::uint32_t UE = 1u << 13;
inline constexpr std::uint32_t M = 1u << 12;
inline constexpr std::uint32_t WAKE = 1u << 11;
inline constexpr std::uint32_t PCE = 1u << 10;
inline constexpr std::uint32_t PS = 1u << 9;
inline constexpr std::uint32_t PEIE = 1u << 8;
inline constexpr std::uint32_t TXEIE = 1u << 7;
inline constexpr std::uint32_t TCIE = 1u << 6;
inline constexpr std::uint32_t RXNEIE = 1u << 5;
inline constexpr std::uint32_t IDLEIE = 1u << 4;
inline constexpr std::uint32_t TE = 1u << 3;
inline constexpr std::uint32_t RE = 1u << 2;
inline constexpr std::uint32_t RWU = 1u << 1;
inline constexpr std::uint32_t SBK = 1u << 0;
}  // namespace cr1

// hw/const/stm32f4xx_usart.py USART_CR2
namespace cr2 {
inline constexpr std::uint32_t ADD = 0xfu << 0;
inline constexpr std::uint32_t LBDL = 1u << 5;
inline constexpr std::uint32_t LBDIE = 1u << 6;
inline constexpr std::uint32_t LBCL = 1u << 8;
inline constexpr std::uint32_t CPHA = 1u << 9;
inline constexpr std::uint32_t CPOL = 1u << 10;
inline constexpr std::uint32_t CLKEN = 1u << 11;
inline constexpr std::uint32_t STOP = 0x3u << 12;
inline constexpr std::uint32_t LINEN = 1u << 14;
}  // namespace cr2

// hw/const/stm32f4xx_usart.py USART_CR3
namespace cr3 {
inline constexpr std::uint32_t EIE = 1u << 0;
inline constexpr std::uint32_t IREN = 1u << 1;
inline constexpr std::uint32_t IRLP = 1u << 2;
inline constexpr std::uint32_t HDSEL = 1u << 3;
inline constexpr std::uint32_t NACK = 1u << 4;
inline constexpr std::uint32_t SCEN = 1u << 5;
inline constexpr std::uint32_t DMAR = 1u << 6;
inline constexpr std::uint32_t DMAT = 1u << 7;
inline constexpr std::uint32_t RTSE = 1u << 8;
inline constexpr std::uint32_t CTSE = 1u << 9;
inline constexpr std::uint32_t CTSIE = 1u << 10;
inline constexpr std::uint32_t ONEBIT = 1u << 11;
}  // namespace cr3

// hw/const/stm32f4xx_usart.py USART_GTPR
namespace gtpr {
inline constexpr std::uint32_t PSC = 0xffu << 0;
inline constexpr std::uint32_t GT = 0xffu << 8;
}  // namespace gtpr

}  // namespace usart
}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_CONST_STM32F4XX_USART_HPP
