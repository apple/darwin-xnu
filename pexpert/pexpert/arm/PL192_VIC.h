/*
 * Copyright (c) 2005-2007 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_PL192_VIC_H
#define _PEXPERT_ARM_PL192_VIC_H

#define ARM_CELL_PL192_VIC

// VIC
#define rVICIRQSTATUS		(*(volatile unsigned *)(pic_base + 0x000)) // VIC IRQ Status Register
#define rVICFIQSTATUS		(*(volatile unsigned *)(pic_base + 0x004)) // VIC FIQ Status Register
#define rVICRAWINTR		(*(volatile unsigned *)(pic_base + 0x008)) // VIC Raw Interrupt Status Register
#define rVICINTSELECT		(*(volatile unsigned *)(pic_base + 0x00C)) // VIC Interrupt Select Register
#define rVICINTENABLE		(*(volatile unsigned *)(pic_base + 0x010)) // VIC Interrupt Enable Register
#define rVICINTENCLEAR		(*(volatile unsigned *)(pic_base + 0x014)) // VIC Interrupt Enable Clear  Register
#define rVICSOFTINT		(*(volatile unsigned *)(pic_base + 0x018)) // VIC Soft Interrupt Register
#define rVICSOFTINTCLEAR	(*(volatile unsigned *)(pic_base + 0x01C)) // VIC Soft Interrupt Clear Register
#define rVICPROTECTION		(*(volatile unsigned *)(pic_base + 0x020)) // VIC Protection Register
#define rVICSWPRIORITYMASK	(*(volatile unsigned *)(pic_base + 0x024)) // VIC Software Priority Mask Register
#define rVICPRIORITYDAISY	(*(volatile unsigned *)(pic_base + 0x028)) // VIC Priority Daisy Chain Register
#define rVICVECTOR(x)		(*(volatile unsigned *)(pic_base + 0x100 + 4 * (x))) // VIC Vector Registers
#define rVICVECTPRIORITY(x)	(*(volatile unsigned *)(pic_base + 0x200 + 4 * (x))) // VIC Vector Priority Registers
#define rVICPERIPHID0		(*(volatile unsigned *)(pic_base + 0xFE0)) // VIC Peripheral ID 0 Register
#define rVICPERIPHID1		(*(volatile unsigned *)(pic_base + 0xFE4)) // VIC Peripheral ID 1 Register
#define rVICPERIPHID2		(*(volatile unsigned *)(pic_base + 0xFE8)) // VIC Peripheral ID 2 Register
#define rVICPERIPHID3		(*(volatile unsigned *)(pic_base + 0xFEC)) // VIC Peripheral ID 3 Register
#define rVICPCELLID0		(*(volatile unsigned *)(pic_base + 0xFF0)) // VIC PrimeCell ID 0 Register
#define rVICPCELLID1		(*(volatile unsigned *)(pic_base + 0xFF4)) // VIC PrimeCell ID 1 Register
#define rVICPCELLID2		(*(volatile unsigned *)(pic_base + 0xFF8)) // VIC PrimeCell ID 2 Register
#define rVICPCELLID3		(*(volatile unsigned *)(pic_base + 0xFFC)) // VIC PrimeCell ID 3 Register

#endif /* ! _PEXPERT_ARM_PL192_VIC_H */
