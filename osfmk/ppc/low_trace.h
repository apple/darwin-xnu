/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

typedef struct LowTraceRecord {

	unsigned short	LTR_cpu;			/* 0000 - CPU address */
	unsigned short	LTR_excpt;			/* 0002 - Exception code */
	unsigned int	LTR_timeHi;			/* 0004 - High order time */
	unsigned int	LTR_timeLo;			/* 0008 - Low order time */
	unsigned int	LTR_cr;				/* 000C - CR */
	unsigned int	LTR_srr0;			/* 0010 - SRR0 */
	unsigned int	LTR_srr1;			/* 0014 - SRR1 */
	unsigned int	LTR_dar;			/* 0018 - DAR */
	unsigned int	LTR_save;			/* 001C - savearea */
	
	unsigned int	LTR_lr;				/* 0020 - LR */
	unsigned int	LTR_ctr;			/* 0024 - CTR */
	unsigned int	LTR_r0;				/* 0028 - R0 */
	unsigned int	LTR_r1;				/* 002C - R1 */
	unsigned int	LTR_r2;				/* 0030 - R2 */
	unsigned int	LTR_r3;				/* 0034 - R3 */
	unsigned int	LTR_r4;				/* 0038 - R4 */
	unsigned int	LTR_r5;				/* 003C - R5 */

} LowTraceRecord;		

typedef struct traceWork {

	unsigned int traceCurr;				/* Address of next slot */
	unsigned int traceMask;				/* Types to be traced */
	unsigned int traceStart;			/* Start of trace table */
	unsigned int traceEnd;				/* End of trace table */
	unsigned int traceMsnd;				/* Saved trace mask */
	unsigned int traceGas[3];
} traceWork;

extern traceWork trcWork;
extern unsigned int lastTrace;			/* Value of low-level exception trace controls */


#endif /* ifndef _LOW_TRACE_H_ */
