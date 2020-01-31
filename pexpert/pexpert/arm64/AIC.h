/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_AIC_H
#define _PEXPERT_ARM_AIC_H

#ifndef ASSEMBLER

#include <stdint.h>

static inline uint32_t
_aic_read32(uintptr_t addr)
{
	return *(volatile uint32_t *)addr;
}

static inline void
_aic_write32(uintptr_t addr, uint32_t data)
{
	*(volatile uint32_t *)(addr) = data;
}

#define aic_read32(offset, data) (_aic_read32(pic_base + (offset)))
#define aic_write32(offset, data) (_aic_write32(pic_base + (offset), (data)))

#endif

// AIC timebase registers (timer base address in DT node is setup as AIC_BASE + 0x1000)
#define kAICMainTimLo                           (0x20)
#define kAICMainTimHi                           (0x28)

#endif /* ! _PEXPERT_ARM_AIC_H */
