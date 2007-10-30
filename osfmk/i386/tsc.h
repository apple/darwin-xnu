/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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
