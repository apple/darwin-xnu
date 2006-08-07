/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		tsc.h
 *	Purpose:	Contains the TSC initialization and conversion
 *			factors.
 */
#ifdef KERNEL_PRIVATE
#ifndef _I386_TSC_H_
#define _I386_TSC_H_

#define BusRatioShift 40
#define BusRatioMask 0x1F
#define IA32_PERF_STS 0x198

extern uint64_t	busFCvtt2n;
extern uint64_t	busFCvtn2t;
extern uint64_t tscFreq;
extern uint64_t tscFCvtt2n;
extern uint64_t tscFCvtn2t;
extern uint64_t tscGranularity;
extern uint64_t bus2tsc;

struct tscInfo
{
uint64_t	busFCvtt2n;
uint64_t	busFCvtn2t;
uint64_t	tscFreq;
uint64_t	tscFCvtt2n;
uint64_t	tscFCvtn2t;
uint64_t	tscGranularity;
uint64_t	bus2tsc;
};
typedef struct tscInfo tscInfo_t;

extern void tsc_get_info(tscInfo_t *info);

extern void tsc_init(void);

#endif /* _I386_TSC_H_ */
#endif /* KERNEL_PRIVATE */
