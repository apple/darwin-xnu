/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
	
/* 																							
 	Firmware.s 

	Handle things that should be treated as an extension of the hardware

	Lovingly crafted by Bill Angell using traditional methods and only natural or recycled materials.
	No animal products are used other than rendered otter bile and deep fried pork lard.

*/

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/spec_reg.h>
#include <ppc/exception.h>
#include <mach/machine/vm_param.h>
#include <assym.s>


/*
 *			Here we generate the table of supported firmware calls 
 */
 

	
			.data
			.align	5								/* Line up on cache line */
			
			.globl	EXT(FWtable)

EXT(FWtable):

			.globl	CutTrace						/* Let everyone know 'bout it */
			.set	CutTrace,(.-EXT(FWtable))/4|0x80000000	/* Call number for CutTrace */
			.long	callUnimp						/* This was already handled in lowmem_vectors */

#include	<ppc/FirmwareCalls.h>
 
			.set	EXT(FirmwareCnt), (.-EXT(FWtable))/4	/* Get the top number */

			.text
			
#define SIMPLESCC 1
#define NOTQUITEASSIMPLE 1
/*
 *			This routine handles the firmware call routine. It must be entered with IR and DR off,
 *			interruptions disabled, and in supervisor state. 
 *
 *			When we enter, we expect R0 to have call number, and LR
 *			to point to the return.  Also, all registers saved in savearea in R13.
 *			R3 is as passed in by the user.  All others must be gotten from the save area
 */


			.align	5
			.globl	EXT(FirmwareCall)

LEXT(FirmwareCall)
		
			rlwinm	r1,r0,2,1,29					/* Clear out bit 0 and multiply by 4 */
			lis		r12,HIGH_ADDR(EXT(FWtable))		/* Get the high part of the firmware call table */
			cmplwi	r1,EXT(FirmwareCnt)*4			/* Is it a valid firmware call number */
			ori		r12,r12,LOW_ADDR(EXT(FWtable))	/* Now the low part */
			ble+	goodCall						/* Yeah, it is... */
			
			li		r3,T_SYSTEM_CALL				/* Tell the vector handler that we know nothing */
			b		EXT(FCReturn)					; Bye dudes...
			
goodCall:	mfsprg	r10,0							/* Make sure about the per_proc block */
			lwzx	r1,r1,r12						/* Pick up the address of the routine */
			lwz		r4,saver4+4(r13)				/* Pass in caller's R4 */
			lwz		r5,saver5+4(r13)				/* Pass in caller's R5 */
			rlwinm.	r1,r1,0,0,29					/* Make sure the flag bits are clear */

			mtlr	r1								/* Put it in the LR */
			beq-	callUnimp						/* This one was unimplimented... */

			blrl									/* Call the routine... */

			stw		r3,saver3+4(r13)				/* Pass back the return code to caller */
			li		r3,T_IN_VAIN					/* Tell the vector handler that we took care of it */
			b		EXT(FCReturn)					; Bye dudes...
	
callUnimp:	li		r3,T_SYSTEM_CALL				/* Tell the vector handler that we know nothing */
			b		EXT(FCReturn)					; Bye dudes...

/*
 *			This routine is used to store using a real address. It stores parmeter1 at parameter2.
 */

			.align	5
			.globl	EXT(StoreReal)

LEXT(StoreReal)

			lis		r0,HIGH_ADDR(StoreRealCall)		/* Get the top part of the SC number */
			ori		r0,r0,LOW_ADDR(StoreRealCall)	/* and the bottom part */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */
			
			.align	5
			.globl	EXT(StoreRealLL)

LEXT(StoreRealLL)

			stw		r3,0(r4)						/* Store the word */
			blr										/* Leave... */

/*
 *			This routine is used to clear a range of physical pages.
 */
			
			.align	5
			.globl	EXT(ClearReal)

LEXT(ClearReal)

			lis		r0,HIGH_ADDR(ClearRealCall)		/* Get the top part of the SC number */
			ori		r0,r0,LOW_ADDR(ClearRealCall)	/* and the bottom part */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */
			
			
			.align	5
			.globl	EXT(ClearRealLL)

LEXT(ClearRealLL)

/*
 *			We take the first parameter as a physical address.  The second is the length in bytes.
 *			Being crazy, I'll round the address down, and the length up.  We could end up clearing
 *			an extra page at the start and one at the end, but we don't really care.  If someone
 *			is stupid enough to give me unaligned addresses and lengths, I am just arrogant enough
 *			to take them at their word and to hell with them.
 */

			neg		r5,r3							/* Negate the address */ 
			addi	r4,r4,4095						/* Round length up */
			rlwinm	r5,r5,0,20,31					/* Save extra length */
			rlwinm	r3,r3,0,0,19					/* Round the page on down */
			add		r4,r4,r5						/* Add up all extra lengths */
			li		r6,32							/* Get a displacement */
			rlwinm	r4,r4,0,0,19					/* Round the length back down */
			
clrloop:	subi	r4,r4,32						/* Back off a cache line */
			dcbz	0,r3							/* Do the even line */
			sub.	r4,r4,r6						/* Back off a second time (we only do this to generate a CR */
			dcbz	r6,r3							/* Clear the even line */
			addi	r3,r3,64						/* Move up to every other line */
			bgt+	clrloop							/* Go until we've done it all... */

			blr										/* Leave... */
/*
 *			This routine will read in 32 byte of real storage.
 */
 			
			.align	5
			.globl	EXT(ReadReal)

LEXT(ReadReal)

			mfsprg	r9,2							; Get the features
			mfmsr	r0								; Get the MSR 
			li		r8,lo16(MASK(MSR_DR))			; Get the DR bit
			rlwinm.	r9,r9,0,pf64Bitb,pf64Bitb		; Are we 64-bit?
			ori		r8,r8,lo16(MASK(MSR_EE))		; Add in the EE bit
			li		r7,1							; Get set for it
			andc	r8,r0,r8						; Turn off EE and DR
			bt--	cr0_eq,rr32a					; Yes, we are...
			
			rldimi	r8,r7,63,MSR_SF_BIT				; Set SF bit (bit 0)
			sldi	r3,r3,32						; Slide on over for true 64-bit address
			mtmsrd	r8
			isync
			or		r3,r3,r4						; Join top and bottom of address
			mr		r4,r5							; Set destination address
			b		rrJoina							; Join on up...
			
rr32a:		mr		r3,r4							; Position bottom of long long
			mr		r4,r5							; Set destination address
			mtmsr	r8								/* Disable EE and DR */
			isync									/* Just make sure about it */
			
rrJoina:	lwz		r5,0(r3)						/* Get word 0 */
			lwz		r6,4(r3)						/* Get word 1 */
			lwz		r7,8(r3)						/* Get word 2 */
			lwz		r8,12(r3)						/* Get word 3 */
			lis		r2,hi16(MASK(MSR_VEC))			; Get the vector enable 
			lwz		r9,16(r3)						/* Get word 4 */
			ori		r2,r2,lo16(MASK(MSR_FP))		; Get the FP enable 
			lwz		r10,20(r3)						/* Get word 5 */
			andc	r0,r0,r2						; Clear VEC and FP enables
			lwz		r11,24(r3)						/* Get word 6 */
			lwz		r12,28(r3)						/* Get word 7 */
			
			bt--	cr0_eq,rr32b					; We are not 64-bit...

			mtmsrd	r0
			isync
			b		rrJoinb							; Join on up...

rr32b:		mtmsr	r0								/* Restore original machine state */
			isync									/* Insure goodness */
			
rrJoinb:	stw		r5,0(r4)						/* Set word 0 */
			stw		r6,4(r4)						/* Set word 1 */
			stw		r7,8(r4)						/* Set word 2 */
			stw		r8,12(r4)						/* Set word 3 */
			stw		r9,16(r4)						/* Set word 4 */
			stw		r10,20(r4)						/* Set word 5 */
			stw		r11,24(r4)						/* Set word 6 */
			stw		r12,28(r4)						/* Set word 7 */
			
			blr
			

/*
 *			This routine is used to load all 4 DBATs.
 */
 			
			.align	5
			.globl	EXT(LoadDBATs)

LEXT(LoadDBATs)


			lis		r0,HIGH_ADDR(LoadDBATsCall)		/* Top half of LoadDBATsCall firmware call number */
			ori		r0,r0,LOW_ADDR(LoadDBATsCall)	/* Bottom half */
			sc										/* Do it to it */

			blr										/* Bye bye, Birdie... */
			
 			
			.align	5
			.globl	EXT(xLoadDBATsLL)

LEXT(xLoadDBATsLL)

			lwz		r4,0(r3)						/* Get DBAT 0 high */
			lwz		r5,4(r3)						/* Get DBAT 0 low */
			lwz		r6,8(r3)						/* Get DBAT 1 high */
			lwz		r7,12(r3)						/* Get DBAT 1 low */
			lwz		r8,16(r3)						/* Get DBAT 2 high */
			lwz		r9,20(r3)						/* Get DBAT 2 low */
			lwz		r10,24(r3)						/* Get DBAT 3 high */
			lwz		r11,28(r3)						/* Get DBAT 3 low */
			
			sync									/* Common decency and the state law require that you wash your hands */
			mtdbatu	0,r4							/* Load DBAT 0 high */
			mtdbatl	0,r5							/* Load DBAT 0 low */
			mtdbatu	1,r6							/* Load DBAT 1 high */
			mtdbatl	1,r7							/* Load DBAT 1 low */
			mtdbatu	2,r8							/* Load DBAT 2 high */
			mtdbatl	2,r9							/* Load DBAT 2 low */
			mtdbatu	3,r10							/* Load DBAT 3 high */
			mtdbatl	3,r11							/* Load DBAT 3 low */
			sync									/* Make sure it's done */
			isync									/* Toss out anything new */

			blr										/* Leave... */

/*
 *			This routine is used to load all 4 IBATs.
 */

			.align	5
			.globl	EXT(LoadIBATs)

LEXT(LoadIBATs)


			lis		r0,HIGH_ADDR(LoadIBATsCall)		/* Top half of LoadIBATsCall firmware call number */
			ori		r0,r0,LOW_ADDR(LoadIBATsCall)	/* Bottom half */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */
			
			.align	5
			.globl	EXT(xLoadIBATsLL)

LEXT(xLoadIBATsLL)

			lwz		r4,0(r3)						/* Get IBAT 0 high */
			lwz		r5,4(r3)						/* Get IBAT 0 low */
			lwz		r6,8(r3)						/* Get IBAT 1 high */
			lwz		r7,12(r3)						/* Get IBAT 1 low */
			lwz		r8,16(r3)						/* Get IBAT 2 high */
			lwz		r9,20(r3)						/* Get IBAT 2 low */
			lwz		r10,24(r3)						/* Get IBAT 3 high */
			lwz		r11,28(r3)						/* Get IBAT 3 low */
			
			sync									/* Common decency and the state law require that you wash your hands */
			mtibatu	0,r4							/* Load IBAT 0 high */
			mtibatl	0,r5							/* Load IBAT 0 low */
			mtibatu	1,r6							/* Load IBAT 1 high */
			mtibatl	1,r7							/* Load IBAT 1 low */
			mtibatu	2,r8							/* Load IBAT 2 high */
			mtibatl	2,r9							/* Load IBAT 2 low */
			mtibatu	3,r10							/* Load IBAT 3 high */
			mtibatl	3,r11							/* Load IBAT 3 low */
			sync									/* Make sure it's done */
			isync									/* Toss out anything new */
			
			blr										/* Leave... */


/*
 *			This is the glue to call the CutTrace firmware call
 *			dbgTrace(id, p1, p2, p3, p4)
 */
 			
			.align	5
			.globl	EXT(dbgTrace)

LEXT(dbgTrace)
			
			mr		r2,r3
			mr		r3,r4
			lis		r0,HIGH_ADDR(CutTrace)			/* Top half of CreateFakeIO firmware call number */
			mr		r4,r5
			mr		r5,r6
			ori		r0,r0,LOW_ADDR(CutTrace)		/* Bottom half */
			mr		r6,r7
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */

/*
 *			This is the glue to create a fake I/O interruption
 */
  			
			.align	5
			.globl	EXT(CreateFakeIO)

LEXT(CreateFakeIO)
			
			lis		r0,HIGH_ADDR(CreateFakeIOCall)	/* Top half of CreateFakeIO firmware call number */
			ori		r0,r0,LOW_ADDR(CreateFakeIOCall)	/* Bottom half */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */

/*
 *			This is the glue to create a fake Dec interruption
 */
   			
			.align	5
			.globl	EXT(CreateFakeDEC)

LEXT(CreateFakeDEC)
			
#if 0
			mflr	r4								; (TEST/DEBUG)
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r4								; (TEST/DEBUG)
#endif			
			
			lis		r0,HIGH_ADDR(CreateFakeDECCall)	/* Top half of CreateFakeDEC firmware call number */
			ori		r0,r0,LOW_ADDR(CreateFakeDECCall)	/* Bottom half */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */


/*
 *			This is the glue to create a shutdown context
 */
 
			.align	5
			.globl	EXT(CreateShutdownCTX)

LEXT(CreateShutdownCTX)
			
			lis		r0,HIGH_ADDR(CreateShutdownCTXCall)	/* Top half of CreateFakeIO firmware call number */
			ori		r0,r0,LOW_ADDR(CreateShutdownCTXCall)	/* Bottom half */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */

/*
 *			This is the glue to choke system
 */
  
			.align	5
			.globl	EXT(ChokeSys)

LEXT(ChokeSys)
			
			lis		r0,HIGH_ADDR(Choke)				/* Top half of Choke firmware call number */
			ori		r0,r0,LOW_ADDR(Choke)			/* Bottom half */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */

/* 
 *			Used to initialize the SCC for debugging output
 */

  
			.align	5
			.globl	EXT(fwSCCinit)

LEXT(fwSCCinit)
		
			mfmsr	r8										/* Save the MSR */
			mr.		r3,r3									/* See if printer or modem */
			rlwinm	r12,r8,0,28,25							/* Turn off translation */
			lis		r10,0xF301								/* Set the top part */
			rlwinm	r12,r12,0,17,15							/* Turn off interruptions */
#if 0
			mtmsr	r12										/* Smash the MSR */
			isync											/* Make it clean */
#endif

			ori		r10,r10,0x2000							/* Assume the printer (this is the normal one) */
			beq+	fwSCCprnt								/* It sure are... */
			ori		r10,r10,0x0002							/* Move it over to the modem port */

fwSCCprnt:	dcbf	0,r10									/* Insure it is out */
			sync
			eieio
			dcbi	0,r10									/* Toss it */
			sync


			li		r7,0x09									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x80									/* Reset channel A */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x04									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x44									/* x16 clock, 1 stop bit */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x03									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0xC0									/* 8 bits per char */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x05									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0xE2									/* DTR mode, 8bit/char */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x02									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x00									/* Vector 0 */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0A									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x00									/* Clear misc controls */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0B									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x50									/* B/R gen T/R */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0C									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0A									/* 9600 baud low */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0D									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x00									/* 9600 baud high */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x03									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0xC1									/* 8 bits/char, Rx enable */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x05									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0xEA									/* 8 bits/char, Tx enable */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0E									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x01									/* BR rate gen enable */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0F									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x00									/* ints off */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x10									/* Reset ext/stat ints */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x10									/* Reset ext/stat ints */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x01									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x10									/* int on Rx, no Tx int enable */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x09									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x0A									/* int on Rx, Tx int enable */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Master enable, no vector */
			dcbi	0,r10
			eieio

			li		r7,0x09									/* Set the register */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			li		r7,0x02									/* No vector */
			stb		r7,0(r10)								/* Set the register */
			dcbf	0,r10									/* Force it out */
			sync 											/* Master enable, no vector */
			dcbi	0,r10
			eieio
			
			lbz		r7,0(r10)								/* Clear interrupts */
			sync 											/* Master enable, no vector */
			dcbi	0,r10
			eieio

wSCCrdy:	eieio											/* Barricade it */
			lbz		r7,0(r10)								/* Get current status */
			dcbi	0,r10
			sync
			andi.	r7,r7,0x04								/* Is transmitter empty? */
			beq		wSCCrdy									/* Nope... */

			eieio

#if 0
			mtmsr	r8										/* Restore 'rupts and TR */
			isync
#endif
			blr												/* Leave... */

/*
 *			This routine is used to write debug output to either the modem or printer port.
 *			parm 1 is printer (0) or modem (1); parm 2 is ID (printed directly); parm 3 converted to hex
 */
  
			.align	5
			.globl	EXT(dbgDisp)

LEXT(dbgDisp)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(dbgDispCall)				/* Top half of dbgDispCall firmware call number */
			ori		r0,r0,LOW_ADDR(dbgDispCall)				/* Bottom half */

			sc												/* Go display the stuff */

			mr		r0,r12									/* Restore R0 */
			blr												/* Return... */
			
/*			Here's the low-level part of dbgDisp			*/

			.align	5
			.globl	EXT(dbgDispLL)

LEXT(dbgDispLL)

dbgDispInt:	mfmsr	r8										/* Save the MSR */

#if 0
			lis		r10,0xF301			/* (TEST/DEBUG) */
			ori		r10,r10,0x2002		/* (TEST/DEBUG) */
			dcbf	0,r10				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r10				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
			li		r7,0x35				/* (TEST/DEBUG) */
			stb		r7,4(r10)			/* (TEST/DEBUG) */
			
			lis		r7,10				/* (TEST/DEBUG) */
spw6:		addi	r7,r7,-1			/* (TEST/DEBUG) */
			mr.		r7,r7				/* (TEST/DEBUG) */
			bne-	spw6				/* (TEST/DEBUG) */
			dcbf	0,r10				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r10				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
#endif

			rlwinm	r12,r8,0,28,25							/* Turn off translation */
			rlwinm	r12,r12,0,17,15							/* Turn off interruptions */

			mflr	r11										/* Save the link register */

#if 0
			mr		r7,r12				/* (TEST/DEBUG) */
			bl		dumpr7				/* (TEST/DEBUG) */
#endif

			mr.		r3,r3									/* See if printer or modem */
			lis		r10,0xF301								/* Set the top part */
			mr		r3,r4									/* Copy the ID parameter */
			
#if 0
			mr		r9,r12				/* (TEST/DEBUG) */
			
			mtmsr	r12					/* (TEST/DEBUG) */
			isync						/* (TEST/DEBUG) */

#if 0
			mtmsr	r8					/* (TEST/DEBUG) */
			isync						/* (TEST/DEBUG) */
#endif

			lis		r12,0xF301			/* (TEST/DEBUG) */
			ori		r12,r12,0x2002		/* (TEST/DEBUG) */
#if 1
			dcbf	0,r12				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r12				/* (TEST/DEBUG) */
#endif

xqrw1:		eieio						/* (TEST/DEBUG) */
			lbz		r7,0(r12)			/* (TEST/DEBUG) */
			dcbi	0,r12				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			andi.	r7,r7,0x04			/* (TEST/DEBUG) */
			beq		xqrw1				/* (TEST/DEBUG) */
			
			eieio						/* (TEST/DEBUG) */
			li		r7,0x36				/* (TEST/DEBUG) */
			stb		r7,4(r12)			/* (TEST/DEBUG) */
			eieio
			dcbf	0,r12				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r12				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
			
			
			lis		r7,10				/* (TEST/DEBUG) */
spw7:		addi	r7,r7,-1			/* (TEST/DEBUG) */
			mr.		r7,r7				/* (TEST/DEBUG) */
			bne-	spw7				/* (TEST/DEBUG) */
			dcbf	0,r12				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r12				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
			mr		r12,r9				/* (TEST/DEBUG) */
#endif

			mtmsr	r12										/* Smash the MSR */
			isync											/* Make it clean */

			
#if SIMPLESCC && !NOTQUITEASSIMPLE
			ori		r10,r10,0x3010							/* Assume the printer (this is the normal one) */
#else
			ori		r10,r10,0x2000							/* Assume the printer (this is the normal one) */
#endif
			beq+	dbgDprintr								/* It sure are... */
#if SIMPLESCC && !NOTQUITEASSIMPLE
			ori		r10,r10,0x0020							/* Move it over to the modem port */
#else
			ori		r10,r10,0x0002							/* Move it over to the modem port */

#if !NOTQUITEASSIMPLE
			lis		r7,0xF300								/* Address of SCC rounded to 128k */
			ori		r7,r7,0x0032							/* Make it cache inhibited */
			mtdbatl	3,r7									/* Load DBAT 3 low */
			lis		r7,0xF300								/* Address of SCC rounded to 128k */
			ori		r7,r7,0x0002							/* Make it supervisor only */
			mtdbatu	3,r7									/* Load DBAT 3 high */
			ori		r12,r12,0x0010							/* Turn on DR */
			mtmsr	r12										/* Smash the MSR */
			isync											/* Make it clean */

#endif
#endif
			
dbgDprintr:	sync
#if 0
			mr		r7,r10									/* (TEST/DEBUG) */
			bl		dumpr7									/* (TEST/DEBUG) */
#endif
			
			dcbi	0,r10									/* Toss it */
			eieio
			
#if 0
			lis		r12,0xF301			/* (TEST/DEBUG) */
			ori		r12,r12,0x2002		/* (TEST/DEBUG) */
			dcbf	0,r12				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r12				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
			li		r7,0x37				/* (TEST/DEBUG) */
			stb		r7,4(r12)			/* (TEST/DEBUG) */
			
			lis		r7,12				/* (TEST/DEBUG) */
spw8:		addi	r7,r7,-1			/* (TEST/DEBUG) */
			mr.		r7,r7				/* (TEST/DEBUG) */
			bne-	spw8				/* (TEST/DEBUG) */
			dcbf	0,r12				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r12				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
#endif


/*			Print the ID parameter							*/
			
			lis		r12,HIGH_ADDR(fwdisplock)				/* Get the display locker outer */
			ori		r12,r12,LOW_ADDR(fwdisplock)			/* Last part */
			
			lwarx	r7,0,r12								; ?

ddwait0:	lwarx	r7,0,r12								/* Get the lock */
			mr.		r7,r7									/* Is it locked? */
			bne-	ddwait0									/* Yup... */
			stwcx.	r12,0,r12								/* Try to get it */
			bne-	ddwait0									/* Nope, start all over... */

#if 0
			dcbf	0,r10				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r10				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
			li		r7,0x38				/* (TEST/DEBUG) */
			stb		r7,6(r10)			/* (TEST/DEBUG) */
			
			lis		r7,10				/* (TEST/DEBUG) */
spwa:		addi	r7,r7,-1			/* (TEST/DEBUG) */
			mr.		r7,r7				/* (TEST/DEBUG) */
			bne-	spwa				/* (TEST/DEBUG) */
			dcbf	0,r10				/* (TEST/DEBUG) */
			sync						/* (TEST/DEBUG) */
			dcbi	0,r10				/* (TEST/DEBUG) */
			eieio						/* (TEST/DEBUG) */
#endif
			
			rlwinm	r3,r3,8,0,31							/* Get the first character */
			bl		dbgDchar								/* Print it */
			rlwinm	r3,r3,8,0,31							/* Get the second character */
			bl		dbgDchar								/* Print it */
			rlwinm	r3,r3,8,0,31							/* Get the third character */
			bl		dbgDchar								/* Print it */
			rlwinm	r3,r3,8,0,31							/* Get the fourth character */
			bl		dbgDchar								/* Print it */
			
			li		r3,0x20									/* Get a space for a separator */
			bl		dbgDchar								/* Print it */
			bl		dbg4byte								/* Print register 5 in hex */			

			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */
			
			mtlr	r11										/* Get back the return */
#if !SIMPLESCC && !NOTQUITEASSIMPLE
			li		r7,0									/* Get a zero */
			mtdbatu	3,r7									/* Invalidate DBAT 3 upper */
			mtdbatl	3,r7									/* Invalidate DBAT 3 lower */
#endif
			lis		r12,HIGH_ADDR(fwdisplock)				/* Get the display locker outer */
			li		r7,0									/* Get a zero */
			ori		r12,r12,LOW_ADDR(fwdisplock)			/* Last part */
			dcbi	0,r10									/* ? */
			stw		r7,0(r12)								/* Release the display lock */
			mtmsr	r8										/* Restore the MSR */
			isync											/* Wait for it */
			blr												/* Leave... */
			

dbg4byte:	mflr	r12										/* Save the return */

			lis		r4,HIGH_ADDR(hexTab)					/* Point to the top of table */
			li		r6,8									/* Set number of hex digits to dump */
			ori		r4,r4,LOW_ADDR(hexTab)					/* Point to the bottom of table */
						
dbgDnext:	rlwinm	r5,r5,4,0,31							/* Rotate a nybble */
			subi	r6,r6,1									/* Back down the count */
			rlwinm	r3,r5,0,28,31							/* Isolate the last nybble */
			lbzx	r3,r4,r3								/* Convert to ascii */
			bl		dbgDchar								/* Print it */
			mr.		r6,r6									/* Any more? */
			bne+	dbgDnext								/* Convert 'em all... */

			li		r3,0x20									/* Space */
			bl		dbgDchar								/* Send it */
			mtlr	r12										/* Restore LR */
			blr												/* Return... */
			
/*			Write to whichever serial port.  Try to leave it clean, but not too hard (this is a hack) */
			
dbgDchar:	
#if SIMPLESCC && !NOTQUITEASSIMPLE		
			stb		r3,0(r10)								/* ? */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */

			lis		r7,3									/* Get enough for about 1ms */

dbgDchar0:	addi	r7,r7,-1								/* Count down */
			mr.		r7,r7									/* Waited long enough? */
			bgt+	dbgDchar0								/* Nope... */
#endif
#if NOTQUITEASSIMPLE
#if 0
			li		r7,0x01									/* ? */
			stb		r7,0(r10)								/* ? */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			lbz		r7,0(r10)								/* ? */
			dcbi	0,r10									/* Force it out */
			sync 											/* kill it off */
			eieio

			li		r7,0x00									/* ? */
			stb		r7,0(r10)								/* ? */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			lbz		r7,0(r10)								/* ? */
			dcbi	0,r10									/* Force it out */
			sync 											/* kill it off */
			eieio
#endif
		
qrw1:		eieio											/* Barricade it */
			lbz		r7,0(r10)								/* ? */
			dcbi	0,r10
			sync
			andi.	r7,r7,0x04								/* ? */
			beq		qrw1									/* Nope... */

			eieio

			stb		r3,4(r10)								/* ? */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

qrw2:		eieio											/* Barricade it */
			lbz		r7,0(r10)								/* ? */
			dcbi	0,r10
			sync
			andi.	r7,r7,0x04								/* ? */
			beq		qrw2									/* Nope... */

#if 0
			eieio
			li		r7,0x10									/* ? */
			stb		r7,0(r10)								/* ? */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio

			lbz		r7,0(r10)								/* ? */
			dcbi	0,r10									/* Force it out */
			sync 											/* kill it off */
			eieio
#endif		
			
			lis		r7,0x0080								/* ? */
			lis		r9,0xF300								/* ? */
			ori		r7,r7,0x010F							/* ? */
			stw		r7,0x28(r9)								/* ? */
			dcbf	0,r10									/* Force it out */
			sync 											/* Make sure it's out there */
			dcbi	0,r10
			eieio
			
#endif
#if !SIMPLESCC && !NOTQUITEASSIMPLE
			rlwinm	r9,r10,0,0,29							/* Get channel a */
			eieio											/* Barricade it */
		
			li		r7,0x03									/* ? */
			stb		r7,0(r9)								/* ? */
			eieio											/* Barricade it */

			lbz		r7,0(r9)								/* ? */
		
			eieio											/* Barricade it */
			lbz		r7,0(r9)								/* ? */
			
dchrw1:		eieio											/* Barricade it */
			lbz		r7,0(r10)								/* ? */
			andi.	r7,r7,0x04								/* ? */
			beq		dchrw1									/* Nope... */
			
			stb		r3,4(r10)								/* ? */
			sync											/* Make sure it's there */
			eieio											/* Don't get confused */

dchrw2:		eieio											/* Barricade it */
			lbz		r7,0(r10)								/* ? */
			andi.	r7,r7,0x04								/* ? */
			beq		dchrw2									/* Nope... */
	
			eieio											/* Avoid confusion */
			lbz		r7,0(r10)								/* ? */
			andi.	r7,r7,0x40								/* ? */
			beq+	nounder									/* Nope... */

			eieio											/* Avoid confusion */
			li		r7,0xC0									/* ? */
			stb		r7,0(r10)								/* ? */

nounder:	eieio											/* Avoid confusion */
			li		r7,0x10									/* ? */
			stb		r7,0(r10)								/* ? */

			eieio											/* Avoid confusion */
			li		r7,0x38									/* ? */
			stb		r7,0(r9)								/* ? */
		
			eieio											/* Avoid confusion */
			li		r7,0x30									/* ? */
			stb		r7,0(r10)								/* ? */

			eieio											/* Avoid confusion */
			li		r7,0x20									/* ? */
			stb		r7,0(r10)								/* ? */
			eieio											/* Avoid confusion */
			sync

#endif
			blr												/* Return */

			.globl hexTab

hexTab:		STRINGD	"0123456789ABCDEF"						/* Convert hex numbers to printable hex */ 			
			

/*
 *			Dumps all the registers in the savearea in R13
 */
 

			.align	5
			.globl	EXT(dbgRegsLL)

LEXT(dbgRegsLL)

			b		EXT(FCReturn)					; Bye dudes...
#if 0
			li		r3,0									/* ? */
			bl		dbgRegsCm								/* Join on up... */
			b		EXT(FCReturn)					; Bye dudes...
			
			
			.align	5
			.globl	EXT(dbgRegs)

LEXT(dbgRegs)

dbgRegsCm:	mfmsr	r8										/* Save the MSR */
			mr.		r3,r3									/* ? */
			rlwinm	r12,r8,0,28,25							/* Turn off translation */
			lis		r10,0xF301								/* Set the top part */
			rlwinm	r12,r12,0,17,15							/* Turn off interruptions */
			mtmsr	r12										/* Smash the MSR */
			isync											/* Make it clean */
#if SIMPLESCC && !NOTQUITEASSIMPLE
			ori		r10,r10,0x3010							/* ? */
#else
			ori		r10,r10,0x2000							/* ? */
#endif
			mflr	r11										/* Save the link register */
			beq+	dbgDprints								/* It sure are... */
#if SIMPLESCC && !NOTQUITEASSIMPLE
			ori		r10,r10,0x0020							/* ? */
#else
			ori		r10,r10,0x0002							/* ? */

			dcbf	0,r10									/* Insure it is out */
			sync
			dcbi	0,r10									/* Toss it */
#if !NOTQUITEASSIMPLE
			lis		r7,0xF300								/* ? */
			ori		r7,r7,0x0032							/* ? */
			mtdbatl	3,r7									/* ? */
			lis		r7,0xF300								/* ? */
			ori		r7,r7,0x0002							/* ? */
			mtdbatu	3,r7									/* ? */
			ori		r12,r12,0x0010							/* ? */
			mtmsr	r12										/* ? */
			isync											/* ? */
#endif
#endif

dbgDprints:	
			lis		r3,HIGH_ADDR(fwdisplock)				/* Get the display locker outer */
			ori		r3,r3,LOW_ADDR(fwdisplock)				/* Last part */
			
			lwarx	r5,0,r3									; ?
ddwait1:	lwarx	r5,0,r3									/* Get the lock */
			mr.		r5,r5									/* Is it locked? */
			bne-	ddwait1									/* Yup... */
			stwcx.	r3,0,r3									/* Try to get it */
			bne-	ddwait1									/* Nope, start all over... */
			
			li		r3,0x52									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x65									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x67									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x73									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */

			lwz		r5,saver0(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver1(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver2(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver3(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver4(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver5(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver6(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver7(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver8(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver9(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver10(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver11(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver12(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver13(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver14(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver15(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver16(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver17(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver18(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver19(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver20(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver21(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver22(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver23(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver24(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver25(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver26(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver27(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,saver28(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver29(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver30(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,saver31(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

/*			Segment registers */

			li		r3,0x53									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x65									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x67									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x73									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */

			lwz		r5,savesr0(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr1(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr2(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr3(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,savesr4(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr5(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr6(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr7(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,savesr8(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr9(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr10(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr11(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */

			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,savesr12(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr13(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr14(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesr15(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */
			
			li		r3,0x30									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x31									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x64									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x64									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,savesrr0(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savesrr1(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savedar(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savedsisr(r13)						/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */
			
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x6C									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x63									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x63									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			li		r3,0x20									/* Print eyecatcher */
			bl		dbgDchar								/* Send it */
			lwz		r5,savelr(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savecr(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			lwz		r5,savectr(r13)							/* Do register */
			bl		dbg4byte								/* Print */			
			li		r3,0x0A									/* Linefeed */
			bl		dbgDchar								/* Send it */
			li		r3,0x0D									/* Carriage return */
			bl		dbgDchar								/* Send it */
			mtlr	r11										/* Get back the return */
			dcbi	0,r10									/* ? */
#if !SIMPLESCC && !NOTQUITEASSIMPLE
			li		r7,0									/* Get a zero */
			mtdbatu	3,r7									/* Invalidate DBAT 3 upper */
			mtdbatl	3,r7									/* Invalidate DBAT 3 lower */
#endif
			lis		r3,HIGH_ADDR(fwdisplock)				/* Get the display locker outer */
			li		r7,0									/* Get a zero */
			ori		r3,r3,LOW_ADDR(fwdisplock)				/* Last part */
			stw		r7,0(r3)								/* Clear display lock */
			mtmsr	r8										/* Restore the MSR */
			isync											/* Wait for it */
			blr												/* Leave... */
#endif			
			
/*
 *			Used for debugging to leave stuff in 0x380-0x3FF (128 bytes).
 *			Mapping is V=R.  Stores and loads are real.
 */
			
			.align	5
			.globl	EXT(dbgCkpt)

LEXT(dbgCkpt)

			mr		r12,r0									/* Keep R0 pristene */
			lis		r0,HIGH_ADDR(dbgCkptCall)				/* Top half of dbgCkptCall firmware call number */
			ori		r0,r0,LOW_ADDR(dbgCkptCall)				/* Bottom half */

			sc												/* Go stash the stuff */

			mr		r0,r12									/* Restore R0 */
			blr												/* Return... */
			
/*			Here's the low-level part of dbgCkpt			*/

			.align	5
			.globl	EXT(dbgCkptLL)

LEXT(dbgCkptLL)


			li		r12,0x380								/* Point to output area */
			li		r1,32									/* Get line size */
			dcbz	0,r12									/* Make sure we don't fetch a cache line */

			lwz		r4,0x00(r3)								/* Load up storage to checkpoint */
			
			dcbt	r1,r3									/* Start in the next line */
			
			lwz		r5,0x04(r3)								/* Load up storage to checkpoint */
			lwz		r6,0x08(r3)								/* Load up storage to checkpoint */
			lwz		r7,0x0C(r3)								/* Load up storage to checkpoint */
			lwz		r8,0x10(r3)								/* Load up storage to checkpoint */
			lwz		r9,0x14(r3)								/* Load up storage to checkpoint */
			lwz		r10,0x18(r3)							/* Load up storage to checkpoint */
			lwz		r11,0x1C(r3)							/* Load up storage to checkpoint */
			
			add		r3,r3,r1								/* Bump input */
			
			stw		r4,0x00(r12)							/* Store it */
			stw		r5,0x04(r12)							/* Store it */
			stw		r6,0x08(r12)							/* Store it */
			stw		r7,0x0C(r12)							/* Store it */
			stw		r8,0x10(r12)							/* Store it */
			stw		r9,0x14(r12)							/* Store it */
			stw		r10,0x18(r12)							/* Store it */
			stw		r11,0x1C(r12)							/* Store it */
			
			dcbz	r1,r12									/* Clear the next line */
			add		r12,r12,r1								/* Point to next output line */

			lwz		r4,0x00(r3)								/* Load up storage to checkpoint */
			lwz		r5,0x04(r3)								/* Load up storage to checkpoint */
			lwz		r6,0x08(r3)								/* Load up storage to checkpoint */
			lwz		r7,0x0C(r3)								/* Load up storage to checkpoint */
			lwz		r8,0x10(r3)								/* Load up storage to checkpoint */
			lwz		r9,0x14(r3)								/* Load up storage to checkpoint */
			lwz		r10,0x18(r3)							/* Load up storage to checkpoint */
			lwz		r11,0x1C(r3)							/* Load up storage to checkpoint */
			
			dcbt	r1,r3									/* Touch the next line */
			add		r3,r3,r1								/* Point to next input line */
				
			stw		r4,0x00(r12)							/* Store it */
			stw		r5,0x04(r12)							/* Store it */
			stw		r6,0x08(r12)							/* Store it */
			stw		r7,0x0C(r12)							/* Store it */
			stw		r8,0x10(r12)							/* Store it */
			stw		r9,0x14(r12)							/* Store it */
			stw		r10,0x18(r12)							/* Store it */
			stw		r11,0x1C(r12)							/* Store it */

			dcbz	r1,r12									/* Clear the next line */
			add		r12,r12,r1								/* Point to next output line */

			lwz		r4,0x00(r3)								/* Load up storage to checkpoint */
			lwz		r5,0x04(r3)								/* Load up storage to checkpoint */
			lwz		r6,0x08(r3)								/* Load up storage to checkpoint */
			lwz		r7,0x0C(r3)								/* Load up storage to checkpoint */
			lwz		r8,0x10(r3)								/* Load up storage to checkpoint */
			lwz		r9,0x14(r3)								/* Load up storage to checkpoint */
			lwz		r10,0x18(r3)							/* Load up storage to checkpoint */
			lwz		r11,0x1C(r3)							/* Load up storage to checkpoint */
			
			dcbt	r1,r3									/* Touch the next line */
			add		r3,r3,r1								/* Point to next input line */
				
			stw		r4,0x00(r12)							/* Store it */
			stw		r5,0x04(r12)							/* Store it */
			stw		r6,0x08(r12)							/* Store it */
			stw		r7,0x0C(r12)							/* Store it */
			stw		r8,0x10(r12)							/* Store it */
			stw		r9,0x14(r12)							/* Store it */
			stw		r10,0x18(r12)							/* Store it */
			stw		r11,0x1C(r12)							/* Store it */

			dcbz	r1,r12									/* Clear the next line */
			add		r12,r12,r1								/* Point to next output line */

			lwz		r4,0x00(r3)								/* Load up storage to checkpoint */
			lwz		r5,0x04(r3)								/* Load up storage to checkpoint */
			lwz		r6,0x08(r3)								/* Load up storage to checkpoint */
			lwz		r7,0x0C(r3)								/* Load up storage to checkpoint */
			lwz		r8,0x10(r3)								/* Load up storage to checkpoint */
			lwz		r9,0x14(r3)								/* Load up storage to checkpoint */
			lwz		r10,0x18(r3)							/* Load up storage to checkpoint */
			lwz		r11,0x1C(r3)							/* Load up storage to checkpoint */
			
			stw		r4,0x00(r12)							/* Store it */
			stw		r5,0x04(r12)							/* Store it */
			stw		r6,0x08(r12)							/* Store it */
			stw		r7,0x0C(r12)							/* Store it */
			stw		r8,0x10(r12)							/* Store it */
			stw		r9,0x14(r12)							/* Store it */
			stw		r10,0x18(r12)							/* Store it */
			stw		r11,0x1C(r12)							/* Store it */
			
			blr

			
/*
 *			Do Preemption.  Forces a T_PREEMPT trap to allow a preemption to occur.
 */

			.align	5
			.globl	EXT(DoPreemptLL)

LEXT(DoPreemptLL)

			li		r3,T_PREEMPT					/* Set preemption interrupt value */
			stw		r3,saveexception(r13)			/* Modify the exception type to preemption */
			b		EXT(FCReturn)					; Bye dudes...

			
/*
 *			Force 'rupt handler to dispatch with new context
 *			R3 at the call contains the new savearea.
 *			R4 at the call contains a return code to pass back in R3.
 *			Forces a T_CSWITCH
 */

			.align	5
			.globl	EXT(SwitchContextLL)

LEXT(SwitchContextLL)

			li		r3,T_CSWITCH					/* Set context switch value */
			stw		r3,saveexception(r13)			/* Modify the exception type to switch context */
			b		EXT(FCReturn)					; Bye dudes...

			
/*
 *			Create a fake I/O 'rupt.  
 *			Forces a T_INTERRUPT trap to pretend that an actual I/O interrupt occurred.
 */

			.align	5
			.globl	EXT(CreateFakeIOLL)

LEXT(CreateFakeIOLL)

			li		r3,T_INTERRUPT					/* Set external interrupt value */
			stw		r3,saveexception(r13)			/* Modify the exception type to external */
			b		EXT(FCReturn)					; Bye dudes...
			
/*
 *			Create a shutdown context
 *			Forces a T_SHUTDOWN trap.
 */

			.align	5
			.globl	EXT(CreateShutdownCTXLL)

LEXT(CreateShutdownCTXLL)

			li		r3,T_SHUTDOWN					/* Set external interrupt value */
			stw		r3,saveexception(r13)			/* Modify the exception type to external */
			b		EXT(FCReturn)					; Bye dudes...
			
/*
 *			Create a fake decrementer 'rupt.  
 *			Forces a T_DECREMENTER trap to pretend that an actual decrementer interrupt occurred.
 */

			.align	5
			.globl	EXT(CreateFakeDECLL)

LEXT(CreateFakeDECLL)

			li		r3,T_DECREMENTER				/* Set decrementer interrupt value */
			stw		r3,saveexception(r13)			/* Modify the exception type to external */
			b		EXT(FCReturn)					; Bye dudes...

/*
 *			Choke the system.  
 */

			.align	5
			.globl	EXT(DoChokeLL)

LEXT(DoChokeLL)

			li		r3,T_CHOKE						; Set external interrupt value
			stw		r3,saveexception(r13)			; Modify the exception type to external
			b		EXT(FCReturn)					; Bye dudes...

/*
 *			Null firmware call 
 */

			.align	5
			.globl	EXT(NullLL)

LEXT(NullLL)

			li		r3,T_IN_VAIN					; Set to just ignore this one
			b		EXT(FCReturn)					; Bye dudes...

;
;			Null firmware call 
;

			.align	5
			.globl	EXT(iNullLL)

LEXT(iNullLL)

			mfspr	r4,pmc1							; Get stamp
			stw		r4,0x6100+(9*16)+0x0(0)			; Save it
#if 1
			mfspr	r4,pmc2							; Get stamp
			stw		r4,0x6100+(9*16)+0x4(0)			; Save it
			mfspr	r4,pmc3							; Get stamp
			stw		r4,0x6100+(9*16)+0x8(0)			; Save it
			mfspr	r4,pmc4							; Get stamp
			stw		r4,0x6100+(9*16)+0xC(0)			; Save it
#endif
			li		r3,T_IN_VAIN					; Set to just ignore this one
			b		EXT(FCReturn)					; Bye dudes...
			
;
;			Set the low level trace flags 
;
 
			.align	5
			.globl	EXT(LLTraceSet)

LEXT(LLTraceSet)

			mr		r4,r3							; Save the new value 
			
			lwz		r3,traceMask(0)					; Get the old trace flags to pass back 
			stw		r4,traceMask(0)					; Replace with the new ones
			blr										; Leave... 

#if 0
	
/*
; ***************************************************************************
;
;			----------------- Grateful Deb ----------------
;
;			Debugging: direct draw into main screen menu bar
;
;			Takes R4 value, converts it to hex characters and displays it.
;
;			Gotta make sure the DCBST is done to force the pixels from the cache.
;
;			Position is taken as column, row (0 based) from R3.
;			Characters are from hexfont, and are 16x16 pixels. 
;
;			Only works with two processors so far
;
;
; ***************************************************************************
*/

#define GDfromright 20
#define GDfontsize 16

			.align	5
			.globl	EXT(GratefulDeb)

LEXT(GratefulDeb)

			mfspr	r6,pir							/* Get the PIR */
			lis		r5,HIGH_ADDR(EXT(GratefulDebWork))	/* Point to our work area */
			rlwinm	r6,r6,8,23,23					/* Get part of the offset to our processors area */
			ori		r5,r5,LOW_ADDR(EXT(GratefulDebWork))	/* Start building the address */
			rlwimi	r6,r6,2,21,21					/* Get the rest of the offset to our processors area */
			add		r6,r6,r5						/* Point at our CPU's work area */
			mfmsr	r5								/* Get that MSR */
			stmw	r0,GDsave(r6)					/* Save all registers */
			lwz		r10,GDready(r6)					/* See if we're all ready to go */
			ori		r0,r5,0x2000					/* Turn on the floating point */
			mr		r31,r6							/* Get a more sane base register */
			mr.		r10,r10							/* Are we all set? */
			mtmsr	r0								/* Enable floating point */
			isync
			
			stfd	f0,GDfp0(r31)					/* Save FP */
			stfd	f1,GDfp1(r31)					/* Save FP */
			stfd	f2,GDfp2(r31)					/* Save FP */
			stfd	f3,GDfp3(r31)					/* Save FP */
		
			beq-	GDbailout						/* Go and bail... */
			
			rlwinm	r25,r3,0,16,31					/* Isolate just the row number */
			lwz		r28,GDtopleft(r31)				/* Get the physical address of our line 0 */
			rlwinm	r3,r3,16,16,31					/* Isolate the column number */
			lwz		r27,GDrowbytes(r31)				/* Get the number of bytes per row */
			lwz		r9,GDrowchar(r31)				/* Get the number of bytes per row of full leaded charactrers */
			lwz		r26,GDdepth(r31)				/* Get the bit depth */
			mullw	r25,r25,r9						/* get offset to the row to write in bytes */
			lwz		r24,GDcollgn(r31)				/* Get the size of columns in bytes */
			add		r25,r28,r25						/* Physical address of row */
			mullw	r3,r3,r24						/* Get byte offset to first output column */
			
			li		r9,32							/* Get the initial shift calc */
			
			lis		r20,HIGH_ADDR(hexfont)			/* Point to the font */
			
			li		r18,GDfontsize					/* Get the number of rows in the font */
			ori		r20,r20,LOW_ADDR(hexfont)		/* Point to the low part */
			add		r21,r25,r3						/* Physical address of top left output pixel */
			sub		r9,r9,r26						/* Get right shift justifier for pixel size */
			li		r7,32							/* Number of bits per word */

startNybble:
			la		r6,GDrowbuf1(r31)				/* Point to the row buffer */
			li		r19,8							/* Get the number of characters in a row */
			
getNybble:	rlwinm	r10,r4,9,23,26					/* Get the top nybble * 32 */
			rlwinm	r4,r4,4,0,31					/* Rotate a nybble */
			add		r10,r20,r10						/* Point to the character in the font */
			
			rlwinm	r16,r26,4,0,27					/* Width of row in actual bits */
			lhz		r15,0(r10)						/* Get the next row of the font */
			
rendrow:	rlwinm	r17,r15,16,0,0					/* Get the next font pixel in the row */
			rlwinm	r15,r15,1,16,31					/* Move in the next font pixel */
			srawi	r17,r17,31						/* Fill with 1s if black and 0s if white (reversed) */
			
			slw		r14,r14,r26						/* Make room for our pixel in a register */
			srw		r17,r17,r9						/* Isolate one pixels worth of black or white */
			sub.	r7,r7,r26						/* See how may bits are left */
			sub		r16,r16,r26						/* Count how many bits are left to store for this row */
			or		r14,r14,r17						/* Put in the pixel */
			bne+	notfull							/* Finish rendering this word */
			
			not		r14,r14							/* Invert to black on white */
			stw		r14,0(r6)						/* Write out the word */
			li		r7,32							/* Bit per word count */
			addi	r6,r6,4							/* Point to the next word */
			
notfull:	mr.		r16,r16							/* Have we finished the whole character row? */			
			bne+	rendrow							/* Finish rendering the row */
		
			addic.	r19,r19,-1						/* Are we finished with a whole display row yet? */
			bne+	getNybble						/* Not yet... */
			
			la		r6,GDrowbuf1(r31)				/* Point to the row buffer */
			rlwinm	r19,r26,31,0,29					/* Number of cache lines (depth/2) */
			mr		r14,r21							/* Get the frame buffer address */
			
//			BREAKPOINT_TRAP

blitrow:	lfd		f0,0(r6)						/* Load a line */
			lfd		f1,8(r6)					
			lfd		f2,16(r6)					
			lfd		f3,24(r6)					
			
			stfd	f0,0(r14)						/* Blit a line */
			stfd	f1,8(r14)					
			stfd	f2,16(r14)					
			stfd	f3,24(r14)	
			
			addi	r6,r6,32						/* Next buffered line */
			
			dcbst	0,r14							/* Force the line to the screen */
			sync									/* Make sure the line is on it's way */
			eieio									/* Make sure we beat the invalidate */
			dcbi	0,r14							/* Make sure we leave no paradox */
			
			addic.	r19,r19,-1						/* Done all lines yet? */
			addi	r14,r14,32						/* Point to the next output */
			bne+	blitrow							/* Nope, do it some more... */
			
			addic.	r18,r18,-1						/* Have we done all the rows in character yet? */
			addi	r20,r20,2						/* Offset the font to the next row */
			add		r21,r21,r27						/* Point to start of next row */
			bne+	startNybble						/* Nope, go through the word one more time... */
					
GDbailout:	mr		r1,r31							/* Move the workarea base */
	
			lfd		f0,GDfp0(r31)					/* Restore FP */
			lfd		f1,GDfp1(r31)					/* Restore FP */
			lfd		f2,GDfp2(r31)					/* Restore FP */
			lfd		f3,GDfp3(r31)					/* Restore FP */
			
			mtmsr	r5								/* Disable floating point */
			isync
			
			lmw		r3,GDsave+12(r1)				/* Restore most registers */
			lwz		r0,GDsave(r1)					/* Restore R0 */
			lwz		r1,GDsave+4(r1)					/* Finally, R1 */
			blr										/* Leave... */
			

/*
 *			void GratefulDebDisp(unsigned int coord, unsigned int data);
 */


			.align	5
			.globl	EXT(GratefulDebDisp)

LEXT(GratefulDebDisp)

			mfmsr	r9								/* Save the current MSR */
			mflr	r7								/* Save the return */
			andi.	r8,r9,0x7FCF					/* Clear interrupt and translation */
			mtmsr	r8								/* Turn 'em really off */
			isync									/* Make sure about the translation part */
			bl		EXT(GratefulDeb)				/* Display it */
			mtmsr	r9								/* Restore interrupt and translation */
			mtlr	r7								/* Restore return */
			isync									/* Make sure */
			blr

			
#endif

/*
 *			void checkNMI(void);
 */


			.align	5
			.globl	EXT(checkNMI)

LEXT(checkNMI)
		
			mfmsr	r9								/* Save it */
			andi.	r8,r9,0x7FCF					/* Clear it */
			mtmsr	r8								/* Disable it */
			isync									/* Fence it */
			lis		r7,0xF300						/* Find it */
			lis		r2,hi16(MASK(MSR_VEC))			; Get the vector enable 
			ori		r7,r7,0x0020					/* Find it */
			ori		r2,r2,lo16(MASK(MSR_FP))		; Get the FP enable 
			dcbi	0,r7							/* Toss it */
			sync									/* Sync it */
			andc	r9,r9,r2						; Clear VEC and FP enables
			eieio									/* Get it */
			lwz		r6,0x000C(r7)					/* Check it */
			eieio									/* Fence it */
			dcbi	0,r7							/* Toss it */
			rlwinm.	r4,r6,0,19,19					/* Check it */
			rlwinm	r6,r6,0,20,18					/* Clear it */
			sync									/* Sync it */
			eieio									/* Fence it */
			beq+	xnonmi							/* Branch on it */

			stw		r6,0x0008(r7)					/* Reset it */
			sync									/* Sync it */
			dcbi	0,r6							/* Toss it */
			eieio									/* Fence it */

			mtmsr	r9								/* Restore it */
			isync									/* Hold it */

			BREAKPOINT_TRAP							/* Kill it */
			blr										/* Return from it */

xnonmi:												/* Label it */
			mtmsr	r9								/* Restore it */
			isync									/* Hold it */
			blr										/* Return from it */

;
;			Saves floating point registers
;

			.align	5
			.globl	EXT(stFloat)

LEXT(stFloat)

			lis		r2,hi16(MASK(MSR_VEC))			; Get the vector enable 
			li		r4,0
			ori		r2,r2,lo16(MASK(MSR_FP))		; Get the FP enable 
			ori		r4,r4,lo16(MASK(MSR_EE))		; Get the EE bit

			mfmsr	r0								; Save the MSR

			andc	r4,r0,r4						; Clear EE
			ori		r4,r4,lo16(MASK(MSR_FP))		; Enable floating point
			mtmsr	r4
			isync

			andc	r0,r0,r2						; Clear VEC and FP enables
			
			stfd	f0,0x00(r3)
			stfd	f1,0x08(r3)
			stfd	f2,0x10(r3)
			stfd	f3,0x18(r3)
			stfd	f4,0x20(r3)
			stfd	f5,0x28(r3)
			stfd	f6,0x30(r3)
			stfd	f7,0x38(r3)
			stfd	f8,0x40(r3)
			stfd	f9,0x48(r3)
			stfd	f10,0x50(r3)
			stfd	f11,0x58(r3)
			stfd	f12,0x60(r3)
			stfd	f13,0x68(r3)
			stfd	f14,0x70(r3)
			stfd	f15,0x78(r3)
			stfd	f16,0x80(r3)
			stfd	f17,0x88(r3)
			stfd	f18,0x90(r3)
			stfd	f19,0x98(r3)
			stfd	f20,0xA0(r3)
			stfd	f21,0xA8(r3)
			stfd	f22,0xB0(r3)
			stfd	f23,0xB8(r3)
			stfd	f24,0xC0(r3)
			stfd	f25,0xC8(r3)
			stfd	f26,0xD0(r3)
			stfd	f27,0xD8(r3)
			stfd	f28,0xE0(r3)
			stfd	f29,0xE8(r3)
			stfd	f30,0xF0(r3)
			stfd	f31,0xF8(r3)
			mffs	f0
			stfd	f0,0x100(r3)
			lfd		f0,0x00(r3)
			mtmsr	r0
			isync
			blr
			

;
;			Saves vector registers.  Returns 0 if non-Altivec machine.
;

			.align	5
			.globl	EXT(stVectors)

LEXT(stVectors)

			lis		r2,hi16(MASK(MSR_VEC))			; Get the vector enable 
			li		r4,0
			ori		r2,r2,lo16(MASK(MSR_FP))		; Get the FP enable 
			ori		r4,r4,lo16(MASK(MSR_EE))		; Get the EE bit
			
			mfsprg	r6,2				; Get features
			mr		r5,r3				; Save area address
			rlwinm.	r6,r6,0,pfAltivecb,pfAltivecb		;  Do we have Altivec?
			li		r3,0				; Assume failure
			beqlr-						; No...
			
			mfmsr	r0					; Save the MSR
	
			andc	r4,r0,r4			; Clear EE

			oris	r4,r4,hi16(MASK(MSR_VEC))	; Enable vectors
			mtmsr	r4
			isync
			
			andc	r0,r0,r2			; Clear FP and VEC
			
			stvxl	v0,0,r5
			addi	r5,r5,16
			stvxl	v1,0,r5
			addi	r5,r5,16
			stvxl	v2,0,r5
			addi	r5,r5,16
			stvxl	v3,0,r5
			addi	r5,r5,16
			stvxl	v4,0,r5
			addi	r5,r5,16
			stvxl	v5,0,r5
			addi	r5,r5,16
			stvxl	v6,0,r5
			addi	r5,r5,16
			stvxl	v7,0,r5
			addi	r5,r5,16
			stvxl	v8,0,r5
			addi	r5,r5,16
			stvxl	v9,0,r5
			addi	r5,r5,16
			stvxl	v10,0,r5
			addi	r5,r5,16
			stvxl	v11,0,r5
			addi	r5,r5,16
			stvxl	v12,0,r5
			addi	r5,r5,16
			stvxl	v13,0,r5
			addi	r5,r5,16
			stvxl	v14,0,r5
			addi	r5,r5,16
			stvxl	v15,0,r5
			addi	r5,r5,16
			stvxl	v16,0,r5
			addi	r5,r5,16
			stvxl	v17,0,r5
			addi	r5,r5,16
			stvxl	v18,0,r5
			addi	r5,r5,16
			stvxl	v19,0,r5
			addi	r5,r5,16
			stvxl	v20,0,r5
			addi	r5,r5,16
			stvxl	v21,0,r5
			addi	r5,r5,16
			stvxl	v22,0,r5
			addi	r5,r5,16
			stvxl	v23,0,r5
			addi	r5,r5,16
			stvxl	v24,0,r5
			addi	r5,r5,16
			stvxl	v25,0,r5
			addi	r5,r5,16
			stvxl	v26,0,r5
			addi	r5,r5,16
			stvxl	v27,0,r5
			addi	r5,r5,16
			stvxl	v28,0,r5
			addi	r5,r5,16
			stvxl	v29,0,r5
			addi	r5,r5,16
			stvxl	v30,0,r5
			addi	r5,r5,16
			stvxl	v31,0,r5
			mfvscr	v31
			addi	r6,r5,16
			stvxl	v31,0,r6
			li		r3,1
			lvxl	v31,0,r5
			mtmsr	r0
			isync

			blr


;
;			Saves yet more registers
;

			.align	5
			.globl	EXT(stSpecrs)

LEXT(stSpecrs)


			lis		r2,hi16(MASK(MSR_VEC))			; Get the vector enable 
			li		r4,0
			ori		r2,r2,lo16(MASK(MSR_FP))		; Get the FP enable 
			ori		r4,r4,lo16(MASK(MSR_EE))		; Get the EE bit

 			mfsprg	r9,2							; Get feature flags 
			mtcrf	0x02,r9							; move pf64Bit cr6

			mfmsr	r0								; Save the MSR
			andc	r0,r0,r2						; Turn off VEC and FP
			andc	r4,r0,r4			; And EE
			mtmsr	r4
			isync
			
			mfpvr	r12
			stw		r12,4(r3)
			rlwinm	r12,r12,16,16,31

			bt++	pf64Bitb,stsSF1					; skip if 64-bit (only they take the hint)

			mfdbatu	r4,0
			mfdbatl	r5,0
			mfdbatu	r6,1
			mfdbatl	r7,1
			mfdbatu	r8,2
			mfdbatl	r9,2
			mfdbatu	r10,3
			mfdbatl	r11,3
			stw		r4,8(r3)
			stw		r5,12(r3)
			stw		r6,16(r3)
			stw		r7,20(r3)
			stw		r8,24(r3)
			stw		r9,28(r3)
			stw		r10,32(r3)
			stw		r11,36(r3)

			mfibatu	r4,0
			mfibatl	r5,0
			mfibatu	r6,1
			mfibatl	r7,1
			mfibatu	r8,2
			mfibatl	r9,2
			mfibatu	r10,3
			mfibatl	r11,3
			stw		r4,40(r3)
			stw		r5,44(r3)
			stw		r6,48(r3)
			stw		r7,52(r3)
			stw		r8,56(r3)
			stw		r9,60(r3)
			stw		r10,64(r3)
			stw		r11,68(r3)
			
			mfsprg	r4,0
			mfsprg	r5,1
			mfsprg	r6,2
			mfsprg	r7,3
			stw		r4,72(r3)
			stw		r5,76(r3)
			stw		r6,80(r3)
			stw		r7,84(r3)
			
			mfsdr1	r4
			stw		r4,88(r3)
			
			la		r4,92(r3)
			li		r5,0
			
stSnsr:		mfsrin	r6,r5
			addis	r5,r5,0x1000
			stw		r6,0(r4)
			mr.		r5,r5
			addi	r4,r4,4
			bne+	stSnsr

			cmplwi	r12,PROCESSOR_VERSION_750
			mfspr	r4,hid0
			stw		r4,(39*4)(r3)

			li		r4,0
			li		r5,0
			li		r6,0
			li		r7,0
			
			mfspr	r4,hid1
			mfspr	r5,l2cr
			mfspr	r6,msscr0
			mfspr	r7,msscr1

			stw		r4,(40*4)(r3)
			stw		r6,(42*4)(r3)
			stw		r5,(41*4)(r3)
			stw		r7,(43*4)(r3)

			li		r4,0
			beq		isis750
			
			mfspr	r4,pir
isis750:	stw		r4,0(r3)

			li		r4,0
			li		r5,0
			li		r6,0
			li		r7,0
			blt-	b4750
			
			mfspr	r4,thrm1
			mfspr	r5,thrm2
			mfspr	r6,thrm3
			mfspr	r7,ictc

b4750:		stw		r4,(44*4)(r3)
			stw		r5,(45*4)(r3)
			stw		r6,(46*4)(r3)
			stw		r7,(47*4)(r3)
			
			li		r4,0
			li		r6,0
			cmplwi	r12,PROCESSOR_VERSION_7400
			bne		nnmax
			
			mfspr	r6,dabr
			mfpvr	r5
			rlwinm	r5,r5,0,16,31
			cmplwi	r5,0x1101
			beq		gnmax
			cmplwi	r5,0x1102
			bne		nnmax

gnmax:		mfspr	r4,1016

nnmax:		stw		r4,(48*4)(r3)
			stw		r6,(49*4)(r3)
			
			mtmsr	r0
			isync

			blr

stsSF1:		mfsprg	r4,0
			mfsprg	r5,1
			mfsprg	r6,2
			mfsprg	r7,3
			std		r4,(18*4)(r3)
			std		r5,(20*4)(r3)
			std		r6,(22*4)(r3)
			std		r7,(24*4)(r3)
			
			mfsdr1	r4
			std		r4,(26*4)(r3)

			mfspr	r4,hid0
			std		r4,(28*4)(r3)
			mfspr	r4,hid1
			std		r4,(30*4)(r3)
			mfspr	r4,hid4
			std		r4,(32*4)(r3)
			mfspr	r4,hid5
			std		r4,(34*4)(r3)


stsSF2:		li		r5,0
			la		r4,(80*4)(r3)
			
stsslbm:	slbmfee	r6,r5
			slbmfev	r7,r5
			std		r6,0(r4)
			std		r7,8(r4)
			addi	r5,r5,1
			cmplwi	r5,64
			addi	r4,r4,16
			blt		stsslbm

			
			mtmsr	r0
			isync

			blr

;
;			fwEmMck - this forces the hardware to emulate machine checks
;			Only valid on 64-bit machines
;			Note: we want interruptions disabled here
;

			.globl	EXT(fwEmMck)
			
			.align	5

LEXT(fwEmMck)


			rlwinm	r3,r3,0,1,0						; Copy low of high high - scomd
			rlwinm	r5,r5,0,1,0						; Copy low of high high - hid1
			rlwinm	r7,r7,0,1,0						; Copy low of high high - hid4
			rlwimi	r3,r4,0,0,31					; Copy low of low low
			rlwimi	r5,r6,0,0,31					; Copy low of low low
			rlwimi	r7,r8,0,0,31					; Copy low of low low

			lis		r9,3							; Start forming hid1 error inject mask
			lis		r10,hi16(0x01084083)			; Start formaing hid4 error inject mask
			ori		r9,r9,0xC000					; Next bit
			ori		r10,r10,lo16(0x01084083)		; Next part
			sldi	r9,r9,32						; Shift up high
			sldi	r10,r10,8						; Shift into position
			
			mfspr	r0,hid1							; Get hid1
			mfspr	r2,hid4							; and hid4
			
			and		r5,r5,r9						; Keep only error inject controls - hid1
			and		r7,r7,r10						; Keep only error inject controls - hid4
			
			andc	r0,r0,r9						; Clear error inject controls hid1
			andc	r2,r2,r10						; Clear error inject controls hid4
			
			or		r0,r0,r5						; Add in the new controls hid1
			or		r2,r2,r7						; Add in the new controls hid4
			
/* ? */
#if 0
			lis		r12,CoreErrI					; Get the error inject controls
			sync

			mtspr	scomd,r3						; Set the error inject controls
			mtspr	scomc,r12						; Request error inject
			mfspr	r11,scomc						; Get back the status (we just ignore it)
#endif
			sync
			isync							
			
			mtspr	hid1,r0							; Move in hid1 controls
			mtspr	hid1,r0							; We need to do it twice
			isync
			
			sync
			mtspr	hid4,r2							; Move in hid4 controls
			isync
			
			blr										; Leave...

;
;			fwSCOMrd - read/write SCOM
;
			.align	5
			.globl	EXT(fwSCOM)

LEXT(fwSCOM)

			lhz		r12,scomfunc(r3)				; Get the function
			lwz		r4,scomreg(r3)					; Get the register
			rldicr	r4,r4,8,47						; Position for SCOM

			mr.		r12,r12							; See if read or write
			bne		fwSCwrite						; Go do a write

			mfsprg	r0,2							; Get the feature flags
			ori		r4,r4,0x8000					; Set to read data
			rlwinm.	r0,r0,pfSCOMFixUpb+1,31,31		; Set shift if we need a fix me up
			sync

			mtspr	scomc,r4						; Request the register
			mfspr	r11,scomd						; Get the register contents
			mfspr	r10,scomc						; Get back the status
			sync
			isync							

			sld		r11,r11,r0						; Fix up if needed
			
			std		r11,scomdata(r3)				; Save result
			eieio
			std		r10,scomstat(r3)				; Save status

			blr

fwSCwrite:	ld		r5,scomdata(r3)					; Get the data
			
			sync

			mtspr	scomd,r5						; Set the data
			mtspr	scomc,r4						; Set it
			mfspr	r10,scomc						; Get back the status
			sync
			isync							

			std		r10,scomstat(r3)				; Save status
			
			blr

;
;			diagTrap - this is used to trigger checks from user space
;			any "twi 31,r31,0xFFFx" will come here (x = 0 to F).
;			On entry R3 points to savearea.
;			R4 is the "x" from instruction;
;			Pass back 1 to no-op twi and return to user
;			Pass back 0 to treat as normal twi.
;

			.globl	EXT(diagTrap)
			
			.align	5

LEXT(diagTrap)

			li		r3,1							; Ignore TWI
			blr										; Leave...




;
;			setPmon - this is used to manipulate MMCR0 and MMCR1

			.globl	EXT(setPmon)
			
			.align	5

LEXT(setPmon)

			li		r0,0
			isync
			mtspr	mmcr0,r0						; Clear MMCR0
			mtspr	mmcr1,r0						; Clear MMCR1
			mtspr	pmc1,r0
			mtspr	pmc2,r0
			mtspr	pmc3,r0
			mtspr	pmc4,r0

			isync

			mtspr	mmcr0,r3						; Set MMCR0
			mtspr	mmcr1,r4						; Set MMCR1
			isync
			blr										; Leave...


