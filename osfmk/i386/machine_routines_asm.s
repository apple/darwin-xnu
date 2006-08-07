/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 
#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <i386/eflags.h>
       
#include <i386/postcode.h>
#include <i386/apic.h>
#include <assym.s>

#define	PA(addr)	(addr)
#define	VA(addr)	(addr)
	
/*
 * GAS won't handle an intersegment jump with a relocatable offset.
 */
#define	LJMP(segment,address)	\
	.byte	0xea		;\
	.long	address		;\
	.word	segment

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
			
			rdtsc
			
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

			ret								// Leave...

			.globl	EXT(rtc_nanotime_store)
			.align	FALIGN

LEXT(rtc_nanotime_store)
		push	%ebp
		mov		%esp,%ebp

		mov		32(%ebp),%edx

		mov		8(%ebp),%eax
		mov		%eax,RNT_TSC_BASE(%edx)
		mov		12(%ebp),%eax
		mov		%eax,RNT_TSC_BASE+4(%edx)

		mov		24(%ebp),%eax
		mov		%eax,RNT_SCALE(%edx)

		mov		28(%ebp),%eax
		mov		%eax,RNT_SHIFT(%edx)

		mov		16(%ebp),%eax
		mov		%eax,RNT_NS_BASE(%edx)
		mov		20(%ebp),%eax
		mov		%eax,RNT_NS_BASE+4(%edx)

		pop		%ebp
		ret

			.globl	EXT(rtc_nanotime_load)
			.align	FALIGN

LEXT(rtc_nanotime_load)
		push	%ebp
		mov		%esp,%ebp

		mov		8(%ebp),%ecx
		mov		12(%ebp),%edx

		mov		RNT_TSC_BASE(%ecx),%eax
		mov		%eax,RNT_TSC_BASE(%edx)
		mov		RNT_TSC_BASE+4(%ecx),%eax
		mov		%eax,RNT_TSC_BASE+4(%edx)

		mov		RNT_SCALE(%ecx),%eax
		mov		%eax,RNT_SCALE(%edx)

		mov		RNT_SHIFT(%ecx),%eax
		mov		%eax,RNT_SHIFT(%edx)

		mov		RNT_NS_BASE(%ecx),%eax
		mov		%eax,RNT_NS_BASE(%edx)
		mov		RNT_NS_BASE+4(%ecx),%eax
		mov		%eax,RNT_NS_BASE+4(%edx)

		pop		%ebp
		ret
