/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_AMCC_H
#define _PEXPERT_ARM_AMCC_H

#include <pexpert/arm64/board_config.h>

/*
 * AMCC registers for KTRR/RoRegion related lockdown in early kernel bootstrap.
 * amcc_base must be retrieved from device tree before using.
 */

#if defined(KERNEL_INTEGRITY_KTRR)
#define AMCC_PGSHIFT 14
#define AMCC_PGSIZE (1 << AMCC_PGSHIFT)
#define AMCC_PGMASK (AMCC_PGSIZE - 1)

#define rMCCGEN        (*(volatile uint32_t *) (amcc_base + 0x780))
#define rRORGNBASEADDR (*(volatile uint32_t *) (amcc_base + 0x7e4))
#define rRORGNENDADDR  (*(volatile uint32_t *) (amcc_base + 0x7e8))
#define rRORGNLOCK     (*(volatile uint32_t *) (amcc_base + 0x7ec))
#endif


#endif /* _PEXPERT_ARM_AMCC_H */
