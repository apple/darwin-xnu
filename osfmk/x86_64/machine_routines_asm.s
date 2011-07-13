/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 
#include <i386/asm.h>
#include <i386/rtclock_asm.h>
#include <i386/proc_reg.h>
#include <i386/eflags.h>
       
#include <i386/postcode.h>
#include <i386/apic.h>
#include <assym.s>

/*
**      ml_get_timebase()
**
**      Entry   - %rdi contains pointer to 64 bit structure.
**
**      Exit    - 64 bit structure filled in.
**
*/
ENTRY(ml_get_timebase)

	lfence
	rdtsc
	lfence
        shlq	$32,%rdx 
        orq	%rdx,%rax
	movq    %rax, (%rdi)
			
	ret

/*
 *  	Convert between various timer units 
 *
 *	This code converts 64-bit time units to other units.
 *	For example, the TSC is converted to HPET units.
 *
 *	Time is a 64-bit integer that is some number of ticks.
 *	Conversion is 64-bit fixed point number which is composed
 *	of a 32 bit integer and a 32 bit fraction. 
 *
 *	The time ticks are multiplied by the conversion factor.  The
 *	calculations are done as a 128-bit value but both the high
 *	and low words are dropped.  The high word is overflow and the
 *	low word is the fraction part of the result.
 *
 *	We return a 64-bit value.
 *
 *	Note that we can use this function to multiply 2 conversion factors.
 *	We do this in order to calculate the multiplier used to convert
 *	directly between any two units.
 *
 *	uint64_t tmrCvt(uint64_t time,		// %rdi
 *			uint64_t conversion)	// %rsi
 *
 */
ENTRY(tmrCvt)
	movq	%rdi,%rax
	mulq	%rsi				/* result is %rdx:%rax */
	shrdq   $32,%rdx,%rax			/* %rdx:%rax >>= 32 */
	ret

 /*
 * void _rtc_nanotime_adjust(
 *		uint64_t        tsc_base_delta,	// %rdi
 *		rtc_nanotime_t  *dst);		// %rsi
 */
ENTRY(_rtc_nanotime_adjust)
	movl	RNT_GENERATION(%rsi),%eax	/* get current generation */
	movl	$0,RNT_GENERATION(%rsi)		/* flag data as being updated */
	addq	%rdi,RNT_TSC_BASE(%rsi)

	incl	%eax				/* next generation */
	jnz	1f
	incl	%eax				/* skip 0, which is a flag */
1:	movl	%eax,RNT_GENERATION(%rsi)	/* update generation */

	ret

/*
 * unint64_t _rtc_nanotime_read(rtc_nanotime_t *rntp, int slow);
 *
 * This is the same as the commpage nanotime routine, except that it uses the
 * kernel internal "rtc_nanotime_info" data instead of the commpage data.
 * These two copies of data are kept in sync by rtc_clock_napped().
 *
 * Warning!  There is another copy of this code in osfmk/x86_64/idt64.s.
 * These are kept in sync by both using the RTC_NANOTIME_READ() macro.
 *
 * There are two versions of this algorithm, for "slow" and "fast" processors.
 * The more common "fast" algorithm is:
 *
 *	ns = (((rdtsc - rnt_tsc_base)*rnt_tsc_scale) / 2**32) + rnt_ns_base;
 *
 * Of course, the divide by 2**32 is a nop.  rnt_tsc_scale is a constant
 * computed during initialization:
 *
 *	rnt_tsc_scale = (10e9 * 2**32) / tscFreq;
 *
 * The "slow" algorithm uses long division:
 *
 *	ns = (((rdtsc - rnt_tsc_base) * 10e9) / tscFreq) + rnt_ns_base;
 *
 * Since this routine is not synchronized and can be called in any context, 
 * we use a generation count to guard against seeing partially updated data.
 * In addition, the _rtc_nanotime_store() routine zeroes the generation before
 * updating the data, and stores the nonzero generation only after all fields
 * have been stored.  Because IA32 guarantees that stores by one processor
 * must be seen in order by another, we can avoid using a lock.  We spin while
 * the generation is zero.
 *
 * unint64_t _rtc_nanotime_read(
 *			rtc_nanotime_t *rntp,		// %rdi
 *			int            slow);		// %rsi
 *
 */
ENTRY(_rtc_nanotime_read)
	test		%rsi,%rsi
	jnz		Lslow
		
	/*
	 * Processor whose TSC frequency is faster than SLOW_TSC_THRESHOLD
	 */
	PAL_RTC_NANOTIME_READ_FAST()

	ret

	/*
	 * Processor whose TSC frequency is not faster than SLOW_TSC_THRESHOLD
	 * But K64 doesn't support this...
	 */
Lslow:
	lea	1f(%rip),%rdi
	xorb	%al,%al
	call	EXT(panic)
	hlt
	.data
1: 	String	"_rtc_nanotime_read() - slow algorithm not supported"


Entry(call_continuation)
	movq	%rdi,%rcx			/* get continuation */
	movq	%rsi,%rdi			/* continuation param */
	movq	%rdx,%rsi			/* wait result */
	movq	%gs:CPU_KERNEL_STACK,%rsp	/* set the stack */
	xorq	%rbp,%rbp			/* zero frame pointer */
	call	*%rcx				/* call continuation */
	movq	%gs:CPU_ACTIVE_THREAD,%rdi
	call	EXT(thread_terminate)

