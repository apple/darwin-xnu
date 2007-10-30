/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *
 *	These are the structures and constants used for the low-level trace
 */






#ifndef _LOW_TRACE_H_
#define _LOW_TRACE_H_

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct LowTraceRecord {

	unsigned short	LTR_cpu;			/* 0000 - CPU address */
	unsigned short	LTR_excpt;			/* 0002 - Exception code */
	unsigned int	LTR_timeHi;			/* 0004 - High order time */
	unsigned int	LTR_timeLo;			/* 0008 - Low order time */
	unsigned int	LTR_cr;				/* 000C - CR */
	unsigned int	LTR_dsisr;			/* 0010 - DSISR */
	unsigned int	LTR_rsvd0;			/* 0014 - reserved */
	uint64_t		LTR_srr0;			/* 0018 - SRR0 */

	uint64_t		LTR_srr1;			/* 0020 - SRR1 */
	uint64_t		LTR_dar;			/* 0028 - DAR */
	uint64_t		LTR_save;			/* 0030 - savearea */
	uint64_t		LTR_lr;				/* 0038 - LR */

	uint64_t		LTR_ctr;			/* 0040 - CTR */
	uint64_t		LTR_r0;				/* 0048 - R0 */
	uint64_t		LTR_r1;				/* 0050 - R1 */
	uint64_t		LTR_r2;				/* 0058 - R2 */

	uint64_t		LTR_r3;				/* 0060 - R3 */
	uint64_t		LTR_r4;				/* 0068 - R4 */
	uint64_t		LTR_r5;				/* 0070 - R5 */
	uint64_t		LTR_r6;				/* 0078 - R6 */

} LowTraceRecord;		
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct traceWork {

	unsigned int traceCurr;				/* Address of next slot */
	unsigned int traceMask;				/* Types to be traced */
	unsigned int traceStart;			/* Start of trace table */
	unsigned int traceEnd;				/* End of trace table */
	unsigned int traceMsnd;				/* Saved trace mask */
	unsigned int traceSize;				/* Size of trace table. Min 1 page */
	unsigned int traceGas[2];
} traceWork;
#pragma pack()

extern traceWork trcWork;
extern unsigned int lastTrace;			/* Value of low-level exception trace controls */


#endif /* ifndef _LOW_TRACE_H_ */
