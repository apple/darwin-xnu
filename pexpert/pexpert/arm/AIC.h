/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_AIC_H
#define _PEXPERT_ARM_AIC_H

#ifndef	ASSEMBLER

static inline unsigned long _aic_read32(unsigned long addr)
{
	unsigned long data;
	data = *(volatile unsigned *)addr;
	return data;
}

static inline void _aic_write32(unsigned long addr, unsigned long data)
{
	*(volatile unsigned *)(addr) = data;
}

#define aic_read32(offset, data) (_aic_read32(pic_base + (offset)))
#define aic_write32(offset, data) (_aic_write32(pic_base + (offset), (data)))

#endif

// AIC
#define kAICAicRev			(0x0000)
#define kAICAicCap0			(0x0004)
#define kAICAicCap0Int(n)		((n) & 0x3FF)
#define kAICAicCap0Proc(n)		((((n) >> 16) & 0x1F) + 1)
#define kAICAicCap1			(0x0008)
#define kAICAicRst			(0x000C)
#define kAICGlbCfg			(0x0010)
#define kAICMainTimLo			(0x0020)
#define kAICMainTimHi			(0x0028)
#define kAICIPINormalDbg		(0x0030)
#define kAICIPISelfDbg			(0x0034)

#define kAICWhoAmI			(0x2000)
#define kAICIack			(0x2004)
#define kAICIackVecType(n)		(((n) >> 16) & 0x7)
#define kAICIackVecTypeSpurious		(0)
#define kAICIackVecTypeExtInt		(1)
#define kAICIackVecTypeIPI		(4)
#define kAICIackVecTypeTimer		(7)
#define kAICIackVecExtInt(n)		((n) & 0x3FF)
#define kAICIackVecIPIType(n)		((n) & 0x003)
#define kAICIackVecIPITypeNormal	(1)
#define kAICIackVecIPITypeSelf		(2)
#define kAICIPISet			(0x2008)
#define kAICIPIClr			(0x200C)
#define kAICIPIClrSelf			(0x80000000)
#define kAICTmrCfg			(0x2010)
#define kAICTmrCfgEn			(1)
#define kAICTmrCfgFslPTI		(0 << 4)
#define kAICTmrCfgFslSGTI		(1 << 4)
#define kAICTmrCfgFslETI		(2 << 4)
#define kAICTmrCnt			(0x2014)
#define kAICTmrIntStat			(0x2018)
#define kAICTmrIntStatPct		(1)
#define kAICTmrStateSet			(0x201C)
#define kAICTmrStateClr			(0x2020)
#define kAICBankedCoreRegs		(0x2000)
#define kAICBankedCoreTmrCnt		(0x14)
#define kAICBankedCoreTmrIntStat	(0x18)

#define kAICTgtDst(n)			(0x3000 + (n) * 4)
#define kAICSwGenSet(n)			(0x4000 + (n) * 4)
#define kAICSwGenClr(n)			(0x4080 + (n) * 4)
#define kAICIntMaskSet(n)		(0x4100 + (n) * 4)
#define kAICIntMaskClr(n)		(0x4180 + (n) * 4)
#define kAICHwIntMon(n)			(0x4200 + (n) * 4)

#define kAICAliasWhoAmI(n)		(0x5000 + (n) * 0x80 + 0x00)
#define kAICAliasIack(n)		(0x5000 + (n) * 0x80 + 0x04)
#define kAICAliasIPISet(n)		(0x5000 + (n) * 0x80 + 0x08)
#define kAICAliasIPIClr(n)		(0x5000 + (n) * 0x80 + 0x0C)
#define kAICAliasTmrCfg(n)		(0x5000 + (n) * 0x80 + 0x10)
#define kAICAliasTmrCnt(n)		(0x5000 + (n) * 0x80 + 0x14)
#define kAICAliasTmrIntStat(n)		(0x5000 + (n) * 0x80 + 0x18)
#define kAICAliasTmrStateSet(n)		(0x5000 + (n) * 0x80 + 0x1C)
#define kAICAliasTmrStateClr(n)		(0x5000 + (n) * 0x80 + 0x20)

#define kAICExtIntShift			(5)
#define kAICExtIntMask			(0x1F)

#endif /* ! _PEXPERT_ARM_AIC_H */
