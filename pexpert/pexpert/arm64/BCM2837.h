/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_BCM2837_H
#define _PEXPERT_ARM_BCM2837_H

#ifdef BCM2837
#include "arm64_common.h"
#endif

#define NO_MONITOR 1
#define NO_ECORE 1

#ifndef ASSEMBLER

#define PI3_UART

#define PI3_BREAK                               asm volatile("brk #0");

#define BCM2837_GPFSEL0_V               (pi3_gpio_base_vaddr + 0x0)
#define BCM2837_GPSET0_V                (pi3_gpio_base_vaddr + 0x1C)
#define BCM2837_GPCLR0_V                (pi3_gpio_base_vaddr + 0x28)
#define BCM2837_GPPUD_V                 (pi3_gpio_base_vaddr + 0x94)
#define BCM2837_GPPUDCLK0_V             (pi3_gpio_base_vaddr + 0x98)

#define BCM2837_FSEL_INPUT              0x0
#define BCM2837_FSEL_OUTPUT             0x1
#define BCM2837_FSEL_ALT0               0x4
#define BCM2837_FSEL_ALT1               0x5
#define BCM2837_FSEL_ALT2               0x6
#define BCM2837_FSEL_ALT3               0x7
#define BCM2837_FSEL_ALT4               0x3
#define BCM2837_FSEL_ALT5               0x2

#define BCM2837_FSEL_NFUNCS             54
#define BCM2837_FSEL_REG(func)          (BCM2837_GPFSEL0_V + (4 * ((func) / 10)))
#define BCM2837_FSEL_OFFS(func)         (((func) % 10) * 3)
#define BCM2837_FSEL_MASK(func)         (0x7 << BCM2837_FSEL_OFFS(func))

#define BCM2837_AUX_ENABLES_V           (pi3_aux_base_vaddr + 0x4)
#define BCM2837_AUX_MU_IO_REG_V         (pi3_aux_base_vaddr + 0x40)
#define BCM2837_AUX_MU_IER_REG_V        (pi3_aux_base_vaddr + 0x44)
#define BCM2837_AUX_MU_IIR_REG_V        (pi3_aux_base_vaddr + 0x48)
#define BCM2837_AUX_MU_LCR_REG_V        (pi3_aux_base_vaddr + 0x4C)
#define BCM2837_AUX_MU_MCR_REG_V        (pi3_aux_base_vaddr + 0x50)
#define BCM2837_AUX_MU_LSR_REG_V        (pi3_aux_base_vaddr + 0x54)
#define BCM2837_AUX_MU_MSR_REG_V        (pi3_aux_base_vaddr + 0x58)
#define BCM2837_AUX_MU_SCRATCH_V        (pi3_aux_base_vaddr + 0x5C)
#define BCM2837_AUX_MU_CNTL_REG_V       (pi3_aux_base_vaddr + 0x60)
#define BCM2837_AUX_MU_STAT_REG_V       (pi3_aux_base_vaddr + 0x64)
#define BCM2837_AUX_MU_BAUD_REG_V       (pi3_aux_base_vaddr + 0x68)
#define BCM2837_PUT32(addr, value) do { *((volatile uint32_t *) addr) = value; } while(0)
#define BCM2837_GET32(addr) *((volatile uint32_t *) addr)

#define PLATFORM_PANIC_LOG_PADDR        0x3c0fc000
#define PLATFORM_PANIC_LOG_SIZE         16384        // 16kb
#endif /* ! ASSEMBLER */

#endif /* ! _PEXPERT_ARM_BCM2837_H */
