// The stm32f103 board table (ported from qiling/extensions/mcu/stm32f1/
// stm32f103.py). The port's env carries the ';' encoded records
// "type;arg1;arg2;k=v..." (the deviation from the upstream dict-of-dicts
// documented in loader/mcu.hpp); the peripheral items ride the load_env
// create walk (the upstream's load_all shape folded into the load_env —
// the upstream load_env ignores the peripheral type with a debug log and
// the harnesses create them explicitly).
//
// The upstream board references the peripheral classes that were never
// implemented (the Wwdg/Iwdg/Bkp/Pwr/Usb/Can/Crc/Rtc/Dbgmcu): the upstream
// create's module lookup raises the QlErrorModuleFunctionNotFound and the
// peripheral is skipped with the warning. The port keeps the entries and
// mirrors the degradation (the create returns null, the entity is absent).
#pragma once

#ifndef QILING_HW_STM32F103_BOARD_HPP
#define QILING_HW_STM32F103_BOARD_HPP

#include <map>
#include <string>

namespace qiling {
namespace hw {

// extensions/mcu/stm32f1/stm32f103.py stm32f103 — the board env table
inline std::map<std::string, std::string> stm32f103_board_env() {
    return {
        // the memory regions (the flash + the system ROM + the SRAM)
        {"FLASH", "memory;0x8000000;0x20000"},
        {"SYSTEM", "memory;0x1ffff000;0x1000"},
        {"SRAM", "memory;0x20000000;0x5000"},
        // the mmio regions
        {"PERIP", "mmio;0x40000000;0x100000"},
        {"PPB", "mmio;0xE0000000;0x100000"},
        {"SRAM BBR", "mmio;0x22000000;0x2000000"},
        {"PERIP BBR", "mmio;0x42000000;0x2000000"},
        {"REMAP REGION", "mmio;0x0;0x80000"},
        // the core peripherals (the port struct names)
        {"SYSTICK", "core;cm3_systick;0xE000E010"},
        {"NVIC", "core;cm_nvic;0xE000E100"},
        {"SCB", "core;cm4_scb;0xE000ED00"},
        {"SRAM BB", "core;CortexMBitband;0x22000000;base=0x20000000;size=0x100000"},
        {"PERIP BB", "core;CortexMBitband;0x42000000;base=0x40000000;size=0x100000"},
        {"REMAP", "core;MemoryRemap;0x0;base=0x8000000;size=0x80000"},
        // the peripherals (the port struct names; the missing-upstream classes
        // degrade to null)
        {"TIM2", "peripheral;STM32F1xxTim;0x40000000;intn=0x1c"},
        {"TIM3", "peripheral;STM32F1xxTim;0x40000400;intn=0x1d"},
        {"TIM4", "peripheral;STM32F1xxTim;0x40000800;intn=0x1e"},
        {"RTC", "peripheral;STM32F1xxRtc;0x40002800;intn=0x3;alarm_intn=0x29"},
        {"WWDG", "peripheral;STM32F1xxWwdg;0x40002c00;intn=0x0"},
        {"IWDG", "peripheral;STM32F1xxIwdg;0x40003000"},
        {"BKP", "peripheral;STM32F1xxBkp;0x40006c00"},
        {"PWR", "peripheral;STM32F1xxPwr;0x40007000"},
        {"SPI2", "peripheral;STM32F1xxSpi;0x40003800;intn=0x24"},
        {"USART2", "peripheral;STM32F1xxUsart;0x40004400;intn=0x26"},
        {"USART3", "peripheral;STM32F1xxUsart;0x40004800;intn=0x27"},
        {"I2C1", "peripheral;STM32F1xxI2c;0x40005400;ev_intn=0x1f;er_intn=0x20"},
        {"I2C2", "peripheral;STM32F1xxI2c;0x40005800;ev_intn=0x21;er_intn=0x22"},
        {"USB", "peripheral;STM32F1xxUsb;0x40005c00;hp_can1_tx_intn=0x13;lp_can1_rx0_intn=0x14;hp_intn=0x13;lp_intn=0x14"},
        {"CAN1", "peripheral;STM32F1xxCan;0x40006400;rx1_intn=0x15;sce_intn=0x16;tx_intn=0x13;rx0_intn=0x14"},
        {"AFIO", "peripheral;STM32F1xxAfio;0x40010000"},
        {"EXTI", "peripheral;STM32F1xxExti;0x40010400;exti0_intn=6;exti1_intn=7;exti2_intn=8;exti3_intn=9;exti4_intn=10;exti9_5_intn=23;exti15_10_intn=40"},
        {"GPIOA", "peripheral;STM32F1xxGpio;0x40010800"},
        {"GPIOB", "peripheral;STM32F1xxGpio;0x40010c00"},
        {"GPIOC", "peripheral;STM32F1xxGpio;0x40011000"},
        {"GPIOD", "peripheral;STM32F1xxGpio;0x40011400"},
        {"GPIOE", "peripheral;STM32F1xxGpio;0x40011800"},
        {"ADC1", "peripheral;STM32F1xxAdc;0x40012400;intn=0x12"},
        {"ADC2", "peripheral;STM32F1xxAdc;0x40012800"},
        {"TIM1", "peripheral;STM32F1xxTim;0x40012c00;brk_intn=0x18;cc_intn=0x1b;trg_com_intn=0x1a;up_intn=0x19"},
        {"SPI1", "peripheral;STM32F1xxSpi;0x40013000;intn=0x23"},
        {"USART1", "peripheral;STM32F1xxUsart;0x40013800;intn=0x25"},
        {"DMA1", "peripheral;STM32F1xxDma;0x40020000;stream0_intn=0xb;stream1_intn=0xc;stream2_intn=0xd;stream3_intn=0xe;stream4_intn=0xf;stream5_intn=0x10;stream6_intn=0x11;stream7_intn=0x2f"},
        {"RCC", "peripheral;STM32F1xxRcc;0x40021000;intn=0x5"},
        {"FLASH INTERFACE", "peripheral;STM32F1xxFlash;0x40022000;intn=0x4"},
        {"CRC", "peripheral;STM32F1xxCrc;0x40023000"},
        {"DBGMCU", "peripheral;STM32F1xxDbgmcu;0xe0042000"},
    };
}

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_STM32F103_BOARD_HPP
