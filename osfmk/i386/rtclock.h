/*
 * Copyright (c) 2004-2007 Apple Inc. All rights reserved.
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
 *	File:		rtclock.h
 *	Purpose:	Routines for handling the machine dependent
 *				real-time clock.
 */

#ifndef _I386_RTCLOCK_H_
#define _I386_RTCLOCK_H_

#ifndef ASSEMBLER
typedef struct rtc_nanotime {
	uint64_t	tsc_base;		/* timestamp */
	uint64_t	ns_base;		/* nanoseconds */
	uint32_t	scale;			/* tsc -> nanosec multiplier */
	uint32_t	shift;			/* tsc -> nanosec shift/div */
						/* shift is overloaded with
						 * lower 32bits of tsc_freq
						 * on slower machines (SLOW_TSC_THRESHOLD) */
	uint32_t	generation;		/* 0 == being updated */
	uint32_t	spare1;
} rtc_nanotime_t;

#include <kern/etimer.h>

struct cpu_data;

extern void	_rtc_nanotime_store(
			uint64_t	tsc,
			uint64_t	nsec,
			uint32_t	scale,
			uint32_t	shift,
			rtc_nanotime_t	*dst);

extern uint64_t	_rtc_nanotime_read(
			rtc_nanotime_t	*rntp,
			int		slow);

extern rtc_nanotime_t	rtc_nanotime_info;
#endif

#define	SLOW_TSC_THRESHOLD	1000067800	/* TSC is too slow for regular nanotime() algorithm */

#if defined(__i386__)
/*
 * Assembly snippet included in exception handlers and rtc_nanotime_read()
 * %edi points to nanotime info struct
 * %edx:%eax returns nanotime
 */
#define RTC_NANOTIME_READ_FAST()					  \
0:	movl	RNT_GENERATION(%edi),%esi	/* being updated? */	; \
	testl	%esi,%esi						; \
	jz	0b				/* wait until done */	; \
	lfence								; \
	rdtsc								; \
	lfence								; \
	subl	RNT_TSC_BASE(%edi),%eax					; \
	sbbl	RNT_TSC_BASE+4(%edi),%edx	/* tsc - tsc_base */	; \
	movl	RNT_SCALE(%edi),%ecx		/* * scale factor */	; \
	movl	%edx,%ebx						; \
	mull	%ecx							; \
	movl	%ebx,%eax						; \
	movl	%edx,%ebx						; \
	mull	%ecx							; \
	addl	%ebx,%eax						; \
	adcl	$0,%edx							; \
	addl	RNT_NS_BASE(%edi),%eax		/* + ns_base */		; \
	adcl	RNT_NS_BASE+4(%edi),%edx				; \
	cmpl	RNT_GENERATION(%edi),%esi	/* check for update */	; \
	jne	0b				/* do it all again */

#elif defined(__x86_64__)

/*
 * Assembly snippet included in exception handlers and rtc_nanotime_read()
 * %rdi points to nanotime info struct.
 * %rax returns nanotime
 */
#define RTC_NANOTIME_READ_FAST()					  \
0:	movl	RNT_GENERATION(%rdi),%esi				; \
	test	%esi,%esi			/* info updating? */	; \
	jz	0b				/* - wait if so */	; \
	lfence								; \
	rdtsc								; \
	lfence								; \
	shlq	$32,%rdx						; \
	orq	%rdx,%rax			/* %rax := tsc */	; \
	subq	RNT_TSC_BASE(%rdi),%rax		/* tsc - tsc_base */	; \
	xorq	%rcx,%rcx						; \
	movl	RNT_SCALE(%rdi),%ecx					; \
	mulq	%rcx				/* delta * scale */	; \
	shrdq	$32,%rdx,%rax			/* %rdx:%rax >>= 32 */	; \
	addq	RNT_NS_BASE(%rdi),%rax		/* add ns_base */	; \
	cmpl	RNT_GENERATION(%rdi),%esi	/* repeat if changed */ ; \
	jne	0b

#endif

#endif /* _I386_RTCLOCK_H_ */
