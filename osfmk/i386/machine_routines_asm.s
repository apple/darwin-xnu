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
#include <i386/apic.h>
#include <i386/eflags.h>
#include <i386/rtclock_asm.h>
#include <i386/postcode.h>
#include <i386/proc_reg.h>
#include <assym.s>

/*
**      ml_get_timebase()
**
**      Entry   - %esp contains pointer to 64 bit structure.
**
**      Exit    - 64 bit structure filled in.
**
*/
ENTRY(ml_get_timebase)

			movl    S_ARG0, %ecx
			
			lfence
			rdtsc
			lfence
			
			movl    %edx, 0(%ecx)
			movl    %eax, 4(%ecx)
			
			ret

/*
 *  	Convert between various timer units 
 *
 *		uint64_t tmrCvt(uint64_t time, uint64_t *conversion)
 *
 *		This code converts 64-bit time units to other units.
 *		For example, the TSC is converted to HPET units.
 *
 *		Time is a 64-bit integer that is some number of ticks.
 *		Conversion is 64-bit fixed point number which is composed
 *		of a 32 bit integer and a 32 bit fraction. 
 *
 *		The time ticks are multiplied by the conversion factor.  The
 *		calculations are done as a 128-bit value but both the high
 *		and low words are dropped.  The high word is overflow and the
 *		low word is the fraction part of the result.
 *
 *		We return a 64-bit value.
 *
 *		Note that we can use this function to multiply 2 conversion factors.
 *		We do this in order to calculate the multiplier used to convert
 *		directly between any two units.
 *
 */

			.globl	EXT(tmrCvt)
			.align FALIGN

LEXT(tmrCvt)

			pushl	%ebp					// Save a volatile
			movl	%esp,%ebp				// Get the parameters - 8
			pushl	%ebx					// Save a volatile
			pushl	%esi					// Save a volatile
			pushl	%edi					// Save a volatile

//			%ebp + 8	- low-order ts
//			%ebp + 12	- high-order ts
//			%ebp + 16	- low-order cvt
//			%ebp + 20	- high-order cvt

			movl	8(%ebp),%eax			// Get low-order ts
			mull	16(%ebp)				// Multiply by low-order conversion
			movl	%edx,%edi				// Need to save only the high order part
			
			movl	12(%ebp),%eax			// Get the high-order ts
			mull	16(%ebp)				// Multiply by low-order conversion
			addl	%eax,%edi				// Add in the overflow from the low x low calculation
			adcl	$0,%edx					// Add in any overflow to high high part
			movl	%edx,%esi				// Save high high part
			
//			We now have the upper 64 bits of the 96 bit multiply of ts and the low half of cvt
//			in %esi:%edi

			movl	8(%ebp),%eax			// Get low-order ts
			mull	20(%ebp)				// Multiply by high-order conversion
			movl	%eax,%ebx				// Need to save the low order part
			movl	%edx,%ecx				// Need to save the high order part
			
			movl	12(%ebp),%eax			// Get the high-order ts
			mull	20(%ebp)				// Multiply by high-order conversion
			
//			Now have %ecx:%ebx as low part of high low and %edx:%eax as high part of high high
//			We don't care about the highest word since it is overflow
			
			addl	%edi,%ebx				// Add the low words
			adcl	%ecx,%esi				// Add in the high plus carry from low
			addl	%eax,%esi				// Add in the rest of the high
			
			movl	%ebx,%eax				// Pass back low word
			movl	%esi,%edx				// and the high word
			
			popl	%edi					// Restore a volatile
			popl	%esi					// Restore a volatile
			popl	%ebx					// Restore a volatile
			popl	%ebp					// Restore a volatile

			ret						// Leave...


/* void  _rtc_nanotime_adjust(	
		uint64_t         tsc_base_delta,
	        rtc_nanotime_t  *dst);
*/
	.globl	EXT(_rtc_nanotime_adjust)
	.align	FALIGN

LEXT(_rtc_nanotime_adjust)
	mov	12(%esp),%edx			/* ptr to rtc_nanotime_info */
	
	movl	RNT_GENERATION(%edx),%ecx	/* get current generation */
	movl	$0,RNT_GENERATION(%edx)		/* flag data as being updated */

	movl	4(%esp),%eax			/* get lower 32-bits of delta */
	addl	%eax,RNT_TSC_BASE(%edx)
	adcl	$0,RNT_TSC_BASE+4(%edx)		/* propagate carry */

	incl	%ecx				/* next generation */
	jnz	1f
	incl	%ecx				/* skip 0, which is a flag */
1:	movl	%ecx,RNT_GENERATION(%edx)	/* update generation and make usable */

	ret


/* unint64_t _rtc_nanotime_read( rtc_nanotime_t *rntp, int slow );
 *
 * This is the same as the commpage nanotime routine, except that it uses the
 * kernel internal "rtc_nanotime_info" data instead of the commpage data.  The two copies
 * of data (one in the kernel and one in user space) are kept in sync by rtc_clock_napped().
 *
 * Warning!  There is another copy of this code in osfmk/i386/locore.s.  The
 * two versions must be kept in sync with each other!
 *
 * There are actually two versions of the algorithm, one each for "slow" and "fast"
 * processors.  The more common "fast" algorithm is:
 *
 *	nanoseconds = (((rdtsc - rnt_tsc_base) * rnt_tsc_scale) / 2**32) - rnt_ns_base;
 *
 * Of course, the divide by 2**32 is a nop.  rnt_tsc_scale is a constant computed during initialization:
 *
 *	rnt_tsc_scale = (10e9 * 2**32) / tscFreq;
 *
 * The "slow" algorithm uses long division:
 *
 *	nanoseconds = (((rdtsc - rnt_tsc_base) * 10e9) / tscFreq) - rnt_ns_base;
 *
 * Since this routine is not synchronized and can be called in any context, 
 * we use a generation count to guard against seeing partially updated data.  In addition,
 * the _rtc_nanotime_store() routine -- just above -- zeroes the generation before
 * updating the data, and stores the nonzero generation only after all other data has been
 * stored.  Because IA32 guarantees that stores by one processor must be seen in order
 * by another, we can avoid using a lock.  We spin while the generation is zero.
 *
 * In accordance with the ABI, we return the 64-bit nanotime in %edx:%eax.
 */
 
		.globl	EXT(_rtc_nanotime_read)
		.align	FALIGN
LEXT(_rtc_nanotime_read)
		pushl		%ebp
		movl		%esp,%ebp
		pushl		%esi
		pushl		%edi
		pushl		%ebx
		movl		8(%ebp),%edi				/* get ptr to rtc_nanotime_info */
		movl		12(%ebp),%eax				/* get "slow" flag */
		testl		%eax,%eax
		jnz		Lslow
		
		/* Processor whose TSC frequency is faster than SLOW_TSC_THRESHOLD */
		PAL_RTC_NANOTIME_READ_FAST()

		popl		%ebx
		popl		%edi
		popl		%esi
		popl		%ebp
		ret

		/* Processor whose TSC frequency is slower than or equal to SLOW_TSC_THRESHOLD */
Lslow:
		movl		RNT_GENERATION(%edi),%esi		/* get generation (0 if being changed) */
		testl		%esi,%esi				/* if being changed, loop until stable */
		jz		Lslow
		pushl		%esi					/* save generation */
		pushl		RNT_SHIFT(%edi)				/* save low 32 bits of tscFreq */

		lfence
		rdtsc	  						/* get TSC in %edx:%eax */
		lfence
		subl		RNT_TSC_BASE(%edi),%eax
		sbbl		RNT_TSC_BASE+4(%edi),%edx

		/*
		* Do the math to convert tsc ticks to nanoseconds.  We first
		* do long multiply of 1 billion times the tsc.  Then we do
		* long division by the tsc frequency
		*/
		mov		$1000000000, %ecx			/* number of nanoseconds in a second */
		mov		%edx, %ebx
		mul		%ecx
		mov		%edx, %edi
		mov		%eax, %esi
		mov		%ebx, %eax
		mul		%ecx
		add		%edi, %eax
		adc		$0, %edx				/* result in edx:eax:esi */
		mov		%eax, %edi
		popl		%ecx					/* get low 32 tscFreq */
		xor		%eax, %eax
		xchg		%edx, %eax
		div		%ecx
		xor		%eax, %eax
		mov		%edi, %eax
		div		%ecx
		mov		%eax, %ebx
		mov		%esi, %eax
		div		%ecx
		mov		%ebx, %edx				/* result in edx:eax */
		
		movl		8(%ebp),%edi				/* recover ptr to rtc_nanotime_info */
		popl		%esi					/* recover generation */

		addl		RNT_NS_BASE(%edi),%eax
		adcl		RNT_NS_BASE+4(%edi),%edx

		cmpl		RNT_GENERATION(%edi),%esi		/* have the parameters changed? */
		jne		Lslow					/* yes, loop until stable */

		pop		%ebx
		pop		%edi
		pop		%esi
		pop		%ebp
		ret							/* result in edx:eax */



/*
 * Timing routines.
 */
Entry(timer_update)
	movl	4(%esp),%ecx
	movl	8(%esp),%eax
	movl	12(%esp),%edx
	movl	%eax,TIMER_HIGHCHK(%ecx)
	movl	%edx,TIMER_LOW(%ecx)
	movl	%eax,TIMER_HIGH(%ecx)
	ret

Entry(timer_grab)
	movl	4(%esp),%ecx
0:	movl	TIMER_HIGH(%ecx),%edx
	movl	TIMER_LOW(%ecx),%eax
	cmpl	TIMER_HIGHCHK(%ecx),%edx
	jne	0b
	ret


Entry(call_continuation)
	movl	S_ARG0,%eax			/* get continuation */
	movl	S_ARG1,%edx			/* continuation param */
	movl	S_ARG2,%ecx			/* wait result */
	movl	%gs:CPU_KERNEL_STACK,%esp	/* pop the stack */
	xorl	%ebp,%ebp			/* zero frame pointer */
	subl	$8,%esp				/* align the stack */
	pushl	%ecx
	pushl	%edx
	call	*%eax				/* call continuation */
	addl	$16,%esp
	movl	%gs:CPU_ACTIVE_THREAD,%eax
	pushl	%eax
	call	EXT(thread_terminate)


