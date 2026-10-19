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

#ifndef QILING_HW_BOARD_ENV_HPP
#define QILING_HW_BOARD_ENV_HPP

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

// extensions/mcu/atmel/sam3x8e.py sam3x8e - the board env table. The
// peripheral items reference the SAM3xa* structs; the upstream implements
// 12 of them (the uart/pdc/wdt/adc/dac/pwm/efc/pio/pmc/spi/tc/uotghs) and
// the rest degrade with the module-not-found warn (the port mirrors the
// degradation: the create returns null, the entity stays absent).
inline std::map<std::string, std::string> sam3x8e_board_env() {
    return {
        {"SRAM BB", "core;CortexMBitband;0x22000000;base=0x20000000;size=0x100000"},
        {"PERIP BB", "core;CortexMBitband;0x42000000;base=0x40000000;size=0x100000"},
        {"REMAP", "core;MemoryRemap;0x0;base=0x80000;size=0x80000"},
        {"SYSTICK", "core;cm3_systick;0xE000E010"},
        {"NVIC", "core;cm_nvic;0xE000E100"},
        {"SCB", "core;cm4_scb;0xE000ED00"},
        {"FLASH", "memory;0x80000;0x80000"},
        {"SRAM", "memory;0x20000000;0x10000"},
        {"RAM", "memory;0x20070000;0x18000"},
        {"PERIP", "mmio;0x40000000;0x100000"},
        {"PPB", "mmio;0xE0000000;0x100000"},
        {"SRAM BBR", "mmio;0x22000000;0x4000000"},
        {"PERIP BBR", "mmio;0x42000000;0x2000000"},
        {"REMAP REGION", "mmio;0x0;0x80000"},
        {"HSMCI", "peripheral;SAM3xaHsmci;0x40000000;intn=0x15"},
        {"SSC", "peripheral;SAM3xaSsc;0x40004000;intn=0x1a"},
        {"SPI0", "peripheral;SAM3xaSpi;0x40008000;intn=0x18"},
        {"TC0", "peripheral;SAM3xaTc;0x40080000;intn=0x1b"},
        {"TC1", "peripheral;SAM3xaTc;0x40084000;intn=0x1c"},
        {"TC2", "peripheral;SAM3xaTc;0x40088000;intn=0x1d"},
        {"TWI0", "peripheral;SAM3xaTwi;0x4008c000;intn=0x16"},
        {"PDC_TWI0", "peripheral;SAM3xaPdc;0x4008c100"},
        {"TWI1", "peripheral;SAM3xaTwi;0x40090000;intn=0x17"},
        {"PDC_TWI1", "peripheral;SAM3xaPdc;0x40090100"},
        {"PWM", "peripheral;SAM3xaPwm;0x40094000;intn=0x24"},
        {"PDC_PWM", "peripheral;SAM3xaPdc;0x40094100"},
        {"USART0", "peripheral;SAM3xaUart;0x40098000;intn=0x11"},
        {"PDC_USART0", "peripheral;SAM3xaPdc;0x40098100"},
        {"USART1", "peripheral;SAM3xaUart;0x4009c000;intn=0x12"},
        {"PDC_USART1", "peripheral;SAM3xaPdc;0x4009c100"},
        {"USART2", "peripheral;SAM3xaUart;0x400a0000;intn=0x13"},
        {"PDC_USART2", "peripheral;SAM3xaPdc;0x400a0100"},
        {"USART3", "peripheral;SAM3xaUart;0x400a4000;intn=0x14"},
        {"PDC_USART3", "peripheral;SAM3xaPdc;0x400a4100"},
        {"UOTGHS", "peripheral;SAM3xaUotghs;0x400ac000;intn=0x28"},
        {"EMAC", "peripheral;SAM3xaEmac;0x400b0000;intn=0x2a"},
        {"CAN0", "peripheral;SAM3xaCan;0x400b4000;intn=0x2b"},
        {"CAN1", "peripheral;SAM3xaCan;0x400b8000;intn=0x2c"},
        {"TRNG", "peripheral;SAM3xaTrng;0x400bc000;intn=0x29"},
        {"ADC", "peripheral;SAM3xaAdc;0x400c0000;intn=0x25"},
        {"PDC_ADC", "peripheral;SAM3xaPdc;0x400c0100"},
        {"DMAC", "peripheral;SAM3xaDmac;0x400c4000;intn=0x27"},
        {"DAC", "peripheral;SAM3xaDac;0x400c8000;intn=0x26"},
        {"PDC_DAC", "peripheral;SAM3xaPdc;0x400c8100"},
        {"SMC", "peripheral;SAM3xaSmc;0x400e0000;intn=0x9"},
        {"MATRIX", "peripheral;SAM3xaMatrix;0x400e0400"},
        {"PMC", "peripheral;SAM3xaPmc;0x400e0600;intn=0x5"},
        {"UART", "peripheral;SAM3xaUart;0x400e0800;intn=0x8"},
        {"PDC_UART", "peripheral;SAM3xaPdc;0x400e0900"},
        {"CHIPID", "peripheral;SAM3xaChipid;0x400e0940"},
        {"EFC0", "peripheral;SAM3xaEfc;0x400e0a00;intn=0x6"},
        {"EFC1", "peripheral;SAM3xaEfc;0x400e0c00;intn=0x7"},
        {"PIOA", "peripheral;SAM3xaPio;0x400e0e00;intn=0xb"},
        {"PIOB", "peripheral;SAM3xaPio;0x400e1000;intn=0xc"},
        {"PIOC", "peripheral;SAM3xaPio;0x400e1200;intn=0xd"},
        {"PIOD", "peripheral;SAM3xaPio;0x400e1400;intn=0xe"},
        {"RSTC", "peripheral;SAM3xaRstc;0x400e1a00;intn=0x1"},
        {"SUPC", "peripheral;SAM3xaSupc;0x400e1a10;intn=0x0"},
        {"RTT", "peripheral;SAM3xaRtt;0x400e1a30;intn=0x3"},
        {"WDT", "peripheral;SAM3xaWdt;0x400e1a50;intn=0x4"},
        {"RTC", "peripheral;SAM3xaRtc;0x400e1a60;intn=0x2"},
        {"GPBR", "peripheral;SAM3xaGpbr;0x400e1a90"},
    };
}

// extensions/mcu/gd32vf1/gd32vf103.py gd32vf103 - the board env table (the
// RISC-V N200 core riding the eclic; the upstream-implemented structs are
// the usart/spi/i2c/gpio/dma/crc/rcu/rtc/timer/eclic and the rest degrade).
inline std::map<std::string, std::string> gd32vf103_board_env() {
    return {
        {"ECLIC", "core;GD32VF1xxEclic;0xD2000000"},
        {"FLASH", "memory;0x8000000;0x20000"},
        {"BOOT", "memory;0x1fffb000;0x5000"},
        {"SRAM", "memory;0x20000000;0x18000"},
        {"PERIP", "mmio;0x40000000;0x40000"},
        {"USBFS", "mmio;0x50000000;0x40000"},
        {"FWDGT", "peripheral;GD32VF1xxFwdgt;0x40003000"},
        {"BKP", "peripheral;GD32VF1xxBkp;0x40006c00"},
        {"PMU", "peripheral;GD32VF1xxPmu;0x40007000"},
        {"DAC", "peripheral;GD32VF1xxDac;0x40007400"},
        {"AFIO", "peripheral;GD32VF1xxAfio;0x40010000"},
        {"GPIOA", "peripheral;GD32VF1xxGpio;0x40010800"},
        {"GPIOB", "peripheral;GD32VF1xxGpio;0x40010c00"},
        {"GPIOC", "peripheral;GD32VF1xxGpio;0x40011000"},
        {"GPIOD", "peripheral;GD32VF1xxGpio;0x40011400"},
        {"GPIOE", "peripheral;GD32VF1xxGpio;0x40011800"},
        {"CRC", "peripheral;GD32VF1xxCrc;0x40023000"},
        {"USBFS_GLOBAL", "peripheral;GD32VF1xxUsbfs;0x50000000"},
        {"USBFS_HOST", "peripheral;GD32VF1xxUsbfs;0x50000400"},
        {"USBFS_DEVICE", "peripheral;GD32VF1xxUsbfs;0x50000800"},
        {"USBFS_PWRCLK", "peripheral;GD32VF1xxUsbfs;0x50000e00"},
        {"EXMC", "peripheral;GD32VF1xxExmc;0xa0000000"},
        {"DBG", "peripheral;GD32VF1xxDbg;0xe0042000"},
        {"TIMER1", "peripheral;GD32VF1xxTimer;0x40000000"},
        {"TIMER2", "peripheral;GD32VF1xxTimer;0x40000400"},
        {"TIMER3", "peripheral;GD32VF1xxTimer;0x40000800"},
        {"TIMER4", "peripheral;GD32VF1xxTimer;0x40000c00"},
        {"TIMER5", "peripheral;GD32VF1xxTimer;0x40001000"},
        {"TIMER6", "peripheral;GD32VF1xxTimer;0x40001400"},
        {"RTC", "peripheral;GD32VF1xxRtc;0x40002800"},
        {"SPI1", "peripheral;GD32VF1xxSpi;0x40003800"},
        {"SPI2", "peripheral;GD32VF1xxSpi;0x40003c00"},
        {"USART1", "peripheral;GD32VF1xxUsart;0x40004400"},
        {"USART2", "peripheral;GD32VF1xxUsart;0x40004800"},
        {"I2C0", "peripheral;GD32VF1xxI2c;0x40005400"},
        {"I2C1", "peripheral;GD32VF1xxI2c;0x40005800"},
        {"TIMER0", "peripheral;GD32VF1xxTimer;0x40012c00"},
        {"SPI0", "peripheral;GD32VF1xxSpi;0x40013000"},
        {"USART0", "peripheral;GD32VF1xxUsart;0x40013800"},
        {"DMA0", "peripheral;GD32VF1xxDma;0x40020000"},
        {"DMA1", "peripheral;GD32VF1xxDma;0x40020400"},
        {"RCU", "peripheral;GD32VF1xxRcu;0x40021000"},
    };
}

}  // namespace hw
}  // namespace qiling

#endif  // QILING_HW_BOARD_ENV_HPP
