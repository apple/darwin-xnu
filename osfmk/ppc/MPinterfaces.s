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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/* 																							
 	MPinterfaces.s 

	General interface to the MP hardware handlers anonymous

	Lovingly crafted by Bill Angell using traditional methods and only natural or recycled materials.
	No animal products are used other than rendered otter bile.

*/

#include <cpus.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/POWERMAC/mp/MPPlugIn.h>
#include <mach/machine/vm_param.h>
#include <assym.s>

/*
 *			This first section is the glue for the high level C code.
 *			Anything that needs any kind of system services (e.g., VM) has to be done here.  The firmware
 *			code that implements the SC runs in real mode.
 */



/* #define	MPI_DEBUGGING	0 */
#define		MPI_DEBUGGING	0

/*
 *			The routine that implements cpu_number.
 */

ENTRY(cpu_number, TAG_NO_FRAME_USED)
 
			mfmsr	r9					/* Save the old MSR */
			rlwinm	r8,r9,0,17,15		/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
			mfsprg	r7,0				/* Get per-proc block */
			lhz		r3,PP_CPU_NUMBER(r7)	/* Get CPU number */
			mtmsr	r9					/* Restore interruptions to entry */
			blr							/* Return... */


/*
 *			The routine glues to the count CPU firmware call
 */

ENTRY(MPgetProcCount, TAG_NO_FRAME_USED)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(MPgetProcCountCall)		/* Top half of MPgetProcCount firmware call number */
			ori		r0,r0,LOW_ADDR(MPgetProcCountCall)		/* Bottom half */
			sc												/* Go see how many processors we have */
			
#if			MPI_DEBUGGING
			lis		r0,HIGH_ADDR(CutTrace)					/* Top half of trace entry maker call */
			ori		r0,r0,LOW_ADDR(CutTrace)				/* Bottom half of trace entry maker call */
			sc												/* Cut a backend trace entry */
#endif

			mr		r0,r12									/* Restore R0 */

			blr												/* Return, pass back R3... */

/*
 *			The routine glues to the start CPU firmware call - actually it's really a boot
 *			The first parameter is the CPU number to start
 *			The second parameter is the real address of the code used to boot the processor
 *			The third parameter is the real addess of the CSA for the subject processor
 */

ENTRY(MPstart, TAG_NO_FRAME_USED)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(MPstartCall)				/* Top half of MPstartCall firmware call number */
			ori		r0,r0,LOW_ADDR(MPstartCall)				/* Bottom half */
			sc												/* Go see how many processors we have */
			
#if			MPI_DEBUGGING
			lis		r0,HIGH_ADDR(CutTrace)					/* Top half of trace entry maker call */
			ori		r0,r0,LOW_ADDR(CutTrace)				/* Bottom half of trace entry maker call */
			sc												/* Cut a backend trace entry */
#endif

			mr		r0,r12									/* Restore R0 */
			blr												/* Return... */

/*
 *			This routine glues to the get external interrupt handler physical address
 */

ENTRY(MPexternalHook, TAG_NO_FRAME_USED)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(MPexternalHookCall)		/* Top half of MPexternalHookCall firmware call number */
			ori		r0,r0,LOW_ADDR(MPexternalHookCall)		/* Bottom half */
			sc												/* Go see how many processors we have */
			
#if			MPI_DEBUGGING
			lis		r0,HIGH_ADDR(CutTrace)					/* Top half of trace entry maker call */
			ori		r0,r0,LOW_ADDR(CutTrace)				/* Bottom half of trace entry maker call */
			sc												/* Cut a backend trace entry */
#endif

			mr		r0,r12									/* Restore R0 */
			blr												/* Return... */


/*
 *			This routine glues to the signal processor routine
 */

ENTRY(MPsignal, TAG_NO_FRAME_USED)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(MPsignalCall)				/* Top half of MPsignalCall firmware call number */
			ori		r0,r0,LOW_ADDR(MPsignalCall)			/* Bottom half */
			sc												/* Go kick the other guy */
			
#if			MPI_DEBUGGING
			lis		r0,HIGH_ADDR(CutTrace)					/* Top half of trace entry maker call */
			ori		r0,r0,LOW_ADDR(CutTrace)				/* Bottom half of trace entry maker call */
			sc												/* Cut a backend trace entry */
#endif

			mr		r0,r12									/* Restore R0 */
			blr												/* Return... */


/*
 *			This routine glues to the stop processor routine
 */

ENTRY(MPstop, TAG_NO_FRAME_USED)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(MPstopCall)				/* Top half of MPsignalCall firmware call number */
			ori		r0,r0,LOW_ADDR(MPstopCall)				/* Bottom half */
			sc												/* Stop the other guy cold */
			
#if			MPI_DEBUGGING
			lis		r0,HIGH_ADDR(CutTrace)					/* Top half of trace entry maker call */
			ori		r0,r0,LOW_ADDR(CutTrace)				/* Bottom half of trace entry maker call */
			sc												/* Cut a backend trace entry */
#endif

			mr		r0,r12									/* Restore R0 */
			blr												/* Return... */


/* *************************************************************************************************************
 *
 *			This second section is the glue for the low level stuff directly into the MP plugin.
 *			At this point every register in existence should be saved.  Well, they're saved,
 *			but R13 points to the savearea, and R20 to the trace entry. Please be careful
 *			with these. You won't like what happens if they're different when you exit.
 *
 ***************************************************************************************************************/


/*
 *			See how many physical processors we have
 */
 
ENTRY(MPgetProcCountLL, TAG_NO_FRAME_USED)

			lis		r11,HIGH_ADDR(EXT(MPEntries))			/* Get the address of the MP entry block  (in the V=R area) */
			ori		r11,r11,LOW_ADDR(EXT(MPEntries))		/* Get the bottom of the MP spec area */
			lwz		r10,kCountProcessors*4(r11)				/* Get the routine entry point */
			mflr	r14										/* Save the return in an unused register */
			mtlr	r10										/* Set it */
			blrl											/* Call the routine */
			mtlr	r14										/* Restore firmware caller address */
			blr												/* Leave... */

/*
 *			Start up a processor
 */

ENTRY(MPstartLL, TAG_NO_FRAME_USED)

			lis		r11,HIGH_ADDR(EXT(MPEntries))			/* Get the address of the MP entry block  (in the V=R area) */
			ori		r11,r11,LOW_ADDR(EXT(MPEntries))		/* Get the bottom of the MP spec area */
			lwz		r10,kStartProcessor*4(r11)				/* Get the routine entry point */
			mflr	r14										/* Save the return in an unused register */
			mtlr	r10										/* Set it */
			blrl											/* Call the routine */
			mtlr	r14										/* Restore firmware caller address */
			blr												/* Leave... */

/*
 *			Get physical address of SIGP external handler
 */

ENTRY(MPexternalHookLL, TAG_NO_FRAME_USED)

			lis		r11,HIGH_ADDR(EXT(MPEntries))			/* Get the address of the MP entry block  (in the V=R area) */
			ori		r11,r11,LOW_ADDR(EXT(MPEntries))		/* Get the bottom of the MP spec area */
			lwz		r10,kExternalHook*4(r11)				/* Get the routine entry point */
			mflr	r14										/* Save the return in an unused register */
			mtlr	r10										/* Set it */
			blrl											/* Call the routine */
			mtlr	r14										/* Restore firmware caller address */
			blr												/* Leave... */



/*
 *			Send a signal to another processor
 */

ENTRY(MPsignalLL, TAG_NO_FRAME_USED)

			lis		r11,HIGH_ADDR(EXT(MPEntries))			/* Get the address of the MP entry block  (in the V=R area) */
			ori		r11,r11,LOW_ADDR(EXT(MPEntries))		/* Get the bottom of the MP spec area */
			lwz		r10,kSignalProcessor*4(r11)				/* Get the routine entry point */
			mflr	r14										/* Save the return in an unused register */
			mtlr	r10										/* Set it */
			blrl											/* Call the routine */
			mtlr	r14										/* Restore firmware caller address */
			blr												/* Leave... */



/*
 *			Stop another processor
 */

ENTRY(MPstopLL, TAG_NO_FRAME_USED)

			lis		r11,HIGH_ADDR(EXT(MPEntries))			/* Get the address of the MP entry block  (in the V=R area) */
			ori		r11,r11,LOW_ADDR(EXT(MPEntries))		/* Get the bottom of the MP spec area */
			lwz		r10,kStopProcessor*4(r11)				/* Get the routine entry point */
			mflr	r14										/* Save the return in an unused register */
			mtlr	r10										/* Set it */
			blrl											/* Call the routine */
			mtlr	r14										/* Restore firmware caller address */
			blr												/* Leave... */


/*
 *			Third section: Miscellaneous MP related routines
 */



/*
 *			All non-primary CPUs start here.
 *			We are dispatched by the SMP driver. Addressing is real (no DR or IR), 
 *			interruptions disabled, etc.  R3 points to the CPUStatusArea (CSA) which contains
 *			most of the state for the processor.  This is set up by the primary.  Note that we 
 *			do not use everything in the CSA.  Caches should be clear and coherent with 
 *			no paradoxies (well, maybe one doxie, a pair would be pushing it).
 */
	
ENTRY(start_secondary,TAG_NO_FRAME_USED)

			mr		r31,r3							/* Get the pointer to the CSA */
			
			lis		r21,HIGH_ADDR(SpinTimeOut)		/* Get the top part of the spin timeout */
			ori		r21,r21,LOW_ADDR(SpinTimeOut)	/* Slam in the bottom part */
			
GetValid:	lbz		r10,CSAregsAreValid(r31)		/* Get the CSA validity value */

			
			mr.		r10,r10							/* Is the area valid yet? */
			bne		GotValid						/* Yeah... */
			addic.	r21,r21,-1						/* Count the try */
			isync									/* Make sure we don't prefetch the valid flag */
			bge+	GetValid						/* Still more tries left... */
			blr										/* Return and cancel startup request... */
				
GotValid:	li		r21,0							/* Set the valid flag off (the won't be after the RFI) */
			lwz		r10,CSAdec(r31)					/* Get the decrimenter */
			stb		r21,CSAregsAreValid(r31)		/* Clear that validity flag */
			
			lwz		r11,CSAdbat+(0*8)+0(r31)		/* Get the first DBAT */
			lwz		r12,CSAdbat+(0*8)+4(r31)		/* Get the first DBAT */
			lwz		r13,CSAdbat+(1*8)+0(r31)		/* Get the second DBAT */
			mtdec	r10								/* Set the decrimenter */
			lwz		r14,CSAdbat+(1*8)+4(r31)		/* Get the second DBAT */
			mtdbatu	0,r11							/* Set top part of DBAT 0 */
			lwz		r15,CSAdbat+(2*8)+0(r31)		/* Get the third DBAT */
			mtdbatl	0,r12							/* Set lower part of DBAT 0 */
			lwz		r16,CSAdbat+(2*8)+4(r31)		/* Get the third DBAT */
			mtdbatu	1,r13							/* Set top part of DBAT 1 */
			lwz		r17,CSAdbat+(3*8)+0(r31)		/* Get the fourth DBAT */
			mtdbatl	1,r14							/* Set lower part of DBAT 1 */
			lwz		r18,CSAdbat+(3*8)+4(r31)		/* Get the fourth DBAT */
			mtdbatu	2,r15							/* Set top part of DBAT 2 */			
			lwz		r11,CSAibat+(0*8)+0(r31)		/* Get the first IBAT */
			mtdbatl	2,r16							/* Set lower part of DBAT 2 */
			lwz		r12,CSAibat+(0*8)+4(r31)		/* Get the first IBAT */
			mtdbatu	3,r17							/* Set top part of DBAT 3 */
			lwz		r13,CSAibat+(1*8)+0(r31)		/* Get the second IBAT */
			mtdbatl	3,r18							/* Set lower part of DBAT 3 */
			lwz		r14,CSAibat+(1*8)+4(r31)		/* Get the second IBAT */
			mtibatu	0,r11							/* Set top part of IBAT 0 */
			lwz		r15,CSAibat+(2*8)+0(r31)		/* Get the third IBAT */
			mtibatl	0,r12							/* Set lower part of IBAT 0 */
			lwz		r16,CSAibat+(2*8)+4(r31)		/* Get the third IBAT */
			mtibatu	1,r13							/* Set top part of IBAT 1 */
			lwz		r17,CSAibat+(3*8)+0(r31)		/* Get the fourth IBAT */
			mtibatl	1,r14							/* Set lower part of IBAT 1 */
			lwz		r18,CSAibat+(3*8)+4(r31)		/* Get the fourth IBAT */
			mtibatu	2,r15							/* Set top part of IBAT 2 */
			lwz		r11,CSAsdr1(r31)				/* Get the SDR1 value */
			mtibatl	2,r16							/* Set lower part of IBAT 2 */
			lwz		r12,CSAsprg(r31)				/* Get SPRG0 (the per_proc_info address) */
			mtibatu	3,r17							/* Set top part of IBAT 3 */
			lwz		r13,CSAmsr(r31)					/* Get the MSR */
			mtibatl	3,r18							/* Set lower part of IBAT 3 */
			lwz		r14,CSApc(r31)					/* Get the PC */
			sync									/* Sync up */
			mtsdr1	r11								/* Set the SDR1 value */
			sync									/* Sync up */
			
			la		r10,CSAsr-4(r31)				/* Point to SR 0  - 4 */
			li		r9,0							/* Start at SR 0 */

LoadSRs:	lwz		r8,4(r10)						/* Get the next SR in line */
			addi	r10,r10,4
			mtsrin	r8,r9							/* Load up the SR */
			addis	r9,r9,0x1000					/* Bump to the next SR */
			mr.		r9,r9							/* See if we wrapped back to 0 */
			bne+	LoadSRs							/* Not yet... */
						
			lwz		r0,CSAgpr+(0*4)(r31)			/* Get a GPR */
			lwz		r9,CSAsprg+(1*4)(r31)			/* Get SPRG1 (the initial active savearea) */
			mtsrr1	r13								/* Set the MSR to dispatch */
			lwz		r1,CSAgpr+(1*4)(r31)			/* Get a GPR */
			mtsprg	0,r12							/* Set the SPRG0 (per_proc_into) value */
			lwz		r2,CSAgpr+(2*4)(r31)			/* Get a GPR */
			mtsrr0	r14								/* Set the PC to dispatch */
			lwz		r3,CSAgpr+(3*4)(r31)			/* Get a GPR */
			mtsprg	1,r9							/* Set the SPRG1 (the initial active savearea) value */
			lwz		r4,CSAgpr+(4*4)(r31)			/* Get a GPR */
			lwz		r5,CSAgpr+(5*4)(r31)			/* Get a GPR */
			lwz		r6,CSAgpr+(6*4)(r31)			/* Get a GPR */
			lwz		r7,CSAgpr+(7*4)(r31)			/* Get a GPR */
			lwz		r8,CSAgpr+(8*4)(r31)			/* Get a GPR */
			lwz		r9,CSAgpr+(9*4)(r31)			/* Get a GPR */
			lwz		r10,CSAgpr+(10*4)(r31)			/* Get a GPR */
			lwz		r11,CSAgpr+(11*4)(r31)			/* Get a GPR */
			lwz		r12,CSAgpr+(12*4)(r31)			/* Get a GPR */
			lwz		r13,CSAgpr+(13*4)(r31)			/* Get a GPR */
			lwz		r14,CSAgpr+(14*4)(r31)			/* Get a GPR */
			lwz		r15,CSAgpr+(15*4)(r31)			/* Get a GPR */
			lwz		r16,CSAgpr+(16*4)(r31)			/* Get a GPR */
			lwz		r17,CSAgpr+(17*4)(r31)			/* Get a GPR */
			lwz		r18,CSAgpr+(18*4)(r31)			/* Get a GPR */
			lwz		r19,CSAgpr+(19*4)(r31)			/* Get a GPR */
			lwz		r20,CSAgpr+(20*4)(r31)			/* Get a GPR */
			lwz		r21,CSAgpr+(21*4)(r31)			/* Get a GPR */
			lwz		r22,CSAgpr+(22*4)(r31)			/* Get a GPR */
			lwz		r23,CSAgpr+(23*4)(r31)			/* Get a GPR */
			lwz		r24,CSAgpr+(24*4)(r31)			/* Get a GPR */
			lwz		r25,CSAgpr+(25*4)(r31)			/* Get a GPR */
			lwz		r26,CSAgpr+(26*4)(r31)			/* Get a GPR */
			lwz		r27,CSAgpr+(27*4)(r31)			/* Get a GPR */
			lwz		r28,CSAgpr+(28*4)(r31)			/* Get a GPR */
			lwz		r29,CSAgpr+(29*4)(r31)			/* Get a GPR */
			lwz		r30,CSAgpr+(30*4)(r31)			/* Get a GPR */
			lwz		r31,CSAgpr+(31*4)(r31)			/* Get a GPR */
			
			sync									/* Make sure we're sunk */

			rfi										/* Get the whole shebang going... */

			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0




/*
 *			This routine handles requests to firmware from another processor.  It is actually the second level
 *			of a three level signaling protocol.  The first level is handled in the physical MP driver. It is the 
 *			basic physical control for the processor, e.g., physical stop, reset, start.  The second level (this
 *			one) handles cross-processor firmware requests, e.g., complete TLB purges.  The last are AST requests
 *			which are handled directly by mach.
 *
 *			If this code handles the request (based upon MPPICParm0BU which is valid until the next SIGP happens -
 *			actually, don't count on it once you enable) it will RFI back to the 
 *			interrupted code.  If not, it will return and let the higher level interrupt handler be called.
 *
 *			We need to worry about registers we use here, check in lowmem_vectors to see what is boten and verboten.
 *
 *			Note that there are no functions implemented yet.
 */


ENTRY(MPsignalFW, TAG_NO_FRAME_USED)


			mfspr	r7,pir							/* Get the processor address */
			lis		r6,HIGH_ADDR(EXT(MPPICPUs))		/* Get high part of CPU control block array */
			rlwinm	r7,r7,5,23,26					/* Get index into CPU array */
			ori		r6,r6,HIGH_ADDR(EXT(MPPICPUs))	/* Get low part of CPU control block array */
			add		r7,r7,r6						/* Point to the control block for this processor */
			lwz		r6,MPPICParm0BU(r7)				/* Just pick this up for now */
			blr										/* Leave... */


/*
 *			Make space for the maximum supported CPUs in the data section
 */
	
#ifdef	__ELF__
			.section ".data"
#else
			.data
#endif
			.align	5
EXT(CSA):
			.set	., .+(CSAsize*NCPUS)
#ifndef __MACHO__
			.type	EXT(CSA), @object
			.size	EXT(CSA), CSAsize*NCPUS
#endif
			.globl	EXT(CSA)
