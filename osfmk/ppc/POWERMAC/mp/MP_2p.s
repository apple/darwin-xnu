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
 * @OSF_COPYRIGHT_INTERNAL_USE_ONLY@
 */

/* 																							
 	MP_2p.s 

	MP low-level signaling, configuration, et all.  This is for a and Apple/Daystar 2p board

	Lovingly crafted by Bill Angell using traditional methods

*/

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/POWERMAC/mp/MPPlugIn.h>
#include <assym.s>
#include <mach/machine/vm_param.h>



			.set	MPPlugInVersion,0						/* Current version code */

/* */
/*			Interfaces to hardware */
/* */

			.set	PCI1ARdisp,		0x00800000				/* Displacement from Bandit to PCI1 address configuiration register */
			.set	GrandCdisp,		0x01000000				/* Displacement from Bandit to Grand Central */
			.set	EventsReg,		0x20					/* Interruption events register (latched) */
			.set	LevelsReg,		0x2C					/* Interruption levels register (unlatched) */
			.set	MaskReg,		0x24					/* Interruption mask register */
			.set	ClearReg,		0x28					/* Interruption clear register */
			.set	TicksPerMic,	11						/* We'll use 11 ticks per µS - 120MHz is really 10, 180MHz is 11.24 */
			.set	EtherNRdisp,	0x01019000				/* Displacement into bandit of EtherNet ROM */

#ifdef	__ELF__
			.section ".data"
#else
			.data
#endif

			.align	5									/* Get us out to the end */

			.globl MPPIwork
#ifdef __ELF__
			.type  MPPIwork,@function
#endif

MPPIwork:
MPPIstatus:	.byte	0									/* Global MP board status */
			.set	MPPIinit,	0x80					/* Global initialization complete */
			.set	MPPI2Pv2,	0x40					/* Second rev of 2P board (no watchdog and different state machine) */
			.byte	0									/* Reserved */
MPPIinst:	.byte	0									/* Mask of CPUs installed */
MPPIonline:	.byte	0									/* Mask of CPUs online (i.e., initialized) */
MPPIlogCPU:	.long	0									/* Used to configure CPU addresses */
MPPITBsync:	.long	0									/* Used to sync time bases */
			.long	0
MPPIHammer:	.long	0									/* Address of HammerHead */
MPPIGrandC:	.long	0									/* Address of GrandCentral */
MPPIPCI1Adr: .long	0									/* Address of PCI1's config reg addr */
MPPIEther:	.long	0									/* Address of EtherNet ROM */
			
			.align	5
MPPISncFght: .fill	4,4,0								/* Space for 9 passes of a TB sync fight + 1 guard pass */
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
			.fill	4,4,0
 			.align	7									/* Point to the start of the CPU status */

			.globl EXT(MPPICPUs)
#ifdef __ELF__
			.type  EXT(MPPICPUs),@function
#endif
EXT(MPPICPUs):												/* Start of Processor specific areas */
/*			There are 8 of these indexed by processor number */


MPPICPU0:	.fill	8,4,0									/* First processor */
MPPICPU1:	.fill	8,4,0									/* Second processor */
MPPICPU2:	.fill	8,4,0									/* Third processor */
MPPICPU3:	.fill	8,4,0									/* Fourth processor */
			.set	MPPIMaxCPU, (.-EXT(MPPICPUs)-32)/32			/* Get the maximum CPU address */


			.text

/******************************************************************************************************** */
/******************************************************************************************************** */
/* */
/*			Here starteth ye stuff */
/* */
/******************************************************************************************************** */
/******************************************************************************************************** */

/******************************************************************************************************** */
/* */
/*			Validate that the hardware matches with our code.  At this point, we cannot check */
/*			for anything other than the possibility of this working.  There's no version code */
/*			or nothin'.  So, if we have a second processor and are a 604 or 604e, we'll say */
/*			we're capable.  Also we'll check version codes for our code. */
/* */
/*			When we get here, DDAT and IDAT are both on, 'rupts are disabled. */
/*  */
/*			We're called like this:  */
/*				OSStatus MP_probe(MPPlugInSpecPtr spec, UInt32 HammerheadAddr); */
/* */
/******************************************************************************************************** */

ENTRY(MPprobe, TAG_NO_FRAME_USED)

			
MPPIbase:	mfpvr	r7									/* Get the processor version */
			rlwinm	r7,r7,16,16,31						/* Isolate the processor type */

			lbz		r5,ArbConfig(r4)					/* See if there is another processor */
			
			andi.	r5,r5,TwoCPU						/* Are we a real live two processor? */
			beq		OneWay								/* Nope, we be gone... */
			
			cmplwi	cr0,r7,4							/* Are we a 604? */
			beq		SeemsOK								/* Yeah, we're cool... */
			cmplwi	cr0,r7,9							/* Are we a 604E? */
			beq		SeemsOK								/* Yeah, go finish up... */
			
OneWay:		li		r3,0								/* Say we can't find the proper CPU */
			blr											/* Leave... */
			
SeemsOK:	mr		r10,r3								/* Save the parameter list */
			
			lwz		r4,MPSversionID(r10)				/* Get the version ID */
			cmplwi	cr0,r4,kMPPlugInVersionID			/* Correct version? */
			beq		IsOK								/* Yeah, we think we're ok... */
			
			li		r3,0								/* Set bad version' */
			blr											/* Leave... */
			
IsOK:		mflr	r11									/* Save the LR */
			lis		r9,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			bl		SetBase1							/* Jump to the next instruction */
SetBase1:	mflr	r12									/* Get the base register */
			ori		r9,r9,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			addi	r12,r12,LOW_ADDR(MPPIbase-SetBase1)	/* Adjust to the start of all our code */
			
			stw		r12,MPSbaseAddr(r10)				/* Save off the common base for all functions */
			
			la		r5,LOW_ADDR(MPPIFunctions-MPPIbase)(r12)	/* Point to the base of all functions */
			stw		r5,MPSareaAddr(r10)					/* Pass back the code address */
			
			la		r5,LOW_ADDR(MPPIFuncOffs-MPPIbase)(r12)	/* Point to the function offset table */
			stw		r5,MPSoffsetTableAddr(r10)			/* Pass back the pointer to the offset table */
			
			li		r5,LOW_ADDR(MPPISize-MPPIFunctions)	/* Get our size without data area */
			stw		r5,MPSareaSize(r10)					/* Save it */
			
			stw		r9,MPSdataArea(r10)					/* Save it */
			
			la		r5,LOW_ADDR(EXT(MPPICPUs)-MPPIwork)(r9)	/* Point to the CPU area base */
			stw		r5,MPSCPUArea(r10)					/* Save it */
			
			mtlr	r11									/* Restore that return address */
			li		r3,1								/* Set no error */
			blr											/* Leave, we're all done... */

/******************************************************************************************************** */
/******************************************************************************************************** */
/* */
/*			Here starteth ye code that starteth up ye second prothether. */
/*			Yea, though ye prothether executeth asynchronously, it appears unto men */
/*			in ye shape of a synchronous process.  By ye instruction of He who gave it */
/*			form and being, it stopeth to worship and praise its Lord, to joyously  */
/*			receive His blessings and teachings, to guide its way along the path to */
/*			righteous execution. */
/* */
/******************************************************************************************************** */
/******************************************************************************************************** */


/******************************************************************************************************** */
/* */
/*			Initialize the MP hardware.  This will bring the other processor online. */
/* */
/*			First we will tick the board to its 5th state the "TBEN off" state. */
/* */
/*			Just for giggles, here's the states: */
/* */
/*			1) 1st ROM			- This state exists after motherboard reset */
/*			2) Open Firmware	- Transitions here when the SecInt line is first asserted */
/*								  Open Firmware attempts to execute some code on the secondary */
/*								  processor to obtain the PVR register.  It's got some problems */
/*								  and hangs the secondary disabled. */
/*			3) Reset (my name)	- Entered when the SecInt line is deasserted. A timer starts and */
/*								  468µS later the reset line is pulled.  I may have this wrong here, */
/*								  it may be that the reset line is held for 468µS.  Either way, */
/*								  this state is invisible to us. */
/*			4) 2nd ROM			- This state exists when the secondary processor begins executing */
/*								  after the reset. */
/*			5) TBEN off			- We transition here when SecInt is asserted in the 2nd ROM state. */
/*								  In this state, the TBEN pin is set to disable the timebase from  */
/*								  running on all processors, thus freezing time. (Performace analysis */
/*								  note: here would be the best time to run stats, all tests would */
/*								  run in 0 time giving us infinite speed.) Also the "primary arbitration" */
/*								  mode is set.  This mode causes the CPU board to arbitrate both processors */
/*								  using a single bus master.  This gets us around the L2 cache dumbness. */
/*								  We should also note that because of this, there is now no way to  */
/*								  tell if we are on the secondary processor, the WhoAmI register will */
/*								  always indicate the primary processor.  We need to have sewn */
/*								  name tags into our underwear before now. */
/*								  Finally, this state is the only way we can tell if we are executing */
/*								  on the older version of the 2-way board.  When it is in this state */
/*								  "primary arbitration" has not been enabled yet.  The WhoAmI register */
/*								  will indicate if we are on the secondary processor on not.  We should */
/*								  check this because we need to do signals differently. */
/*			6) TBEN on			- The next assertion of SecInt brings us to our final destination.  For */
/*								  those of you who will be deplaning, please remember that timebases */
/*								  are running and primary arbitration is enabled.  Always remember: */
/*								  buckle up for safety and if you're tired pull over for a rest. */
/* */
/******************************************************************************************************** */

ENTRY(MPinstall, TAG_NO_FRAME_USED)

/*			int MP_install(unsigned int *physAddr, unsigned int band1, unsigned int hammerh, unsigned int grandc,
 *			unsigned int pci1ar, unsigned int enetr);
 */
	
			lis		r11,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			mflr	r0									/* Save the LR */
			ori		r11,r11,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			
			stw		r5,MPPIHammer-MPPIwork(r11)			/* Save the HammerHead address for later */
			stw		r6,MPPIGrandC-MPPIwork(r11)			/* Save address of Grand Central */
			stw		r7,MPPIPCI1Adr-MPPIwork(r11)		/* Save the PCI1 address register address */
			stw		r8,MPPIEther-MPPIwork(r11)			/* Save Ethernet ROM address */

			li		r4,LOW_ADDR(0xC080)					/* Set CPU 0&1 installed, CPU 0 online */
			lis		r10,(MPPICOnline+MPPICReady)>>16	/* Set CPU 0 online and ready */
			
			mfspr	r6,pir								/* Get the PIR contents */
			
			sth		r4,MPPIinst-MPPIwork(r11)			/* Set 'em for later */
			rlwinm	r6,r6,0,0,27						/* Clear to use processor 0 */
			stw		r10,EXT(MPPICPUs)-MPPIwork(r11)		/* Preset CPU 0 online and ready */

			mtspr	pir,r6								/* Set our PIR */

/* */
/*			Ok, ok, enough of this.  Let's really start 'em up. */
/* */

			lis		r9,HIGH_ADDR(CPUInit)				/* Top of init code */
			li		r6,1								/* Get the other guy's CPU address		 */
			ori		r9,r9,LOW_ADDR(CPUInit)				/* Get physical address of init code */
		
			mfmsr	r8									/* Get the MSR */

			stw		r6,MPPIlogCPU-MPPIwork(r11)			/* Set the logical CPU address to assign */
						
			rlwinm	r6,r8,0,17,15						/* Turn off interruptions */
			sync										/* Make sure the work area is updated */
			mtmsr	r6									/* Flip the EE bit off */
			isync										/* Chill a bit */
			
			stw		r9,0(r7)							/* Pass the initialization code address to our friend */
			sync										/* Fence off the pig */
			
			li		r6,0								/* Clear this out */
			stb		r6,IntReg(r5)						/* Kick the other processor */
			eieio										/* Pig in the sty */

/*			At this point we should be in the "TBEN off" state.  The second processor should be starting */
/*			to come up. */

/*			Note that we are assuming that the secondary processor will reset the interrupt request. */
/*			If we are on one of the old boards, we will die in about 256µS if it is not reset, 'cause */
/*			of that silly watchchihuahua timer.  We can't use the TB or decrimenter here to set a  */
/*			timeout because when we are in "TBEN off" state these guys don't run. */

			lis		r4,HIGH_ADDR(SpinTimeOut)			/* Get about 1 second at 200MHz */
														/* At 120 MHz this is 1.66 seconds, at 400MHz it is .5 */
														/* All these are more than enough time for this handshake */
			ori		r4,r4,LOW_ADDR(SpinTimeOut)			/* Get the bottom part */

WaitReady:	lwz		r9,0(r7)							/* Get this back */
			mr.		r9,r9								/* The other processor will set to 0 */
														/*    when it is ready for the work area address */
			beq		CodeUp								/* The code is up on the other side */
			subi	r4,r4,1								/* Count the try */
			mr.		r4,r4								/* Did we timeout? */
			bne+	WaitReady							/* Nope... */
			
			li		r3,kMPPInitTO1						/* Set that we timed out with initial code bringup */
			mtmsr	r8									/* Restore the interrupt state */
			mtlr	r0									/* Restore the return addess */
			blr											/* Return a failure... */

CodeUp:		isync										/* Make sure we don't prefetch past here */
			
/*			Timebase is stopped here, no need for the funky "get time base right" loop */

			mftbu	r4									/* Get upper timebase half */
			mftb	r9									/* Get bottom  */
			stw		r4,MPPITBsync-MPPIwork(r11)			/* Save the top */
			stw		r9,MPPITBsync+4-MPPIwork(r11)		/* Save the second half */
			sync										/* Be very sure it's there */
			
			stw		r11,0(r7)							/* Set the PCI1 adr reg non-zero - this releases the spin */
														/*	loop and allows the timebase to be set. */
			eieio

			lis		r9,HIGH_ADDR(SpinTimeOut)			/* Get the spin time */
			ori		r9,r9,LOW_ADDR(SpinTimeOut)			/* Get the bottom part */
			
WaitTBset:	lwz		r4,0(r7)							/* Get this back */
			mr.		r4,r4								/* When zero, the other guy's TB is set up */
			beq-	TBSetUp								/* She's'a all done... */
			subi	r9,r9,1								/* Count the try */
			mr.		r9,r9								/* Did we timeout? */
			bne+	WaitTBset							/* Nope... */
			
			li		r3,kMPPInitTO3						/* Set that we timed out setting clock */
			mtmsr	r8									/* Restore the interrupt state */
			isync
			mtlr	r0									/* Restore the return addess */
			blr											/* Return a failure... */

TBSetUp:	stb		r6,IntReg(r5)						/* Kick the other processor again */
														/* This will tick us to the next state */
			eieio
						
SpinDelay:	addi	r6,r6,1								/* Bump spin count (we finally are trashing R6) */
			cmplwi	cr0,r6,4096							/* Spun enough? */
			ble+	SpinDelay							/* Nope... */
			
			li		r6,SecInt							/* Set the interrupt bit */
			stb		r6,IntReg(r5)						/* Deassert the external signal */
/* */
/*			Ok, the other processor should be online in a spin waiting for a start signal from */
/*			us.  It should be in the reset state with no external interruptions pending.  There may */
/*			be a decrimenter pop waiting in the wings though. */
/* */
			
			lwz		r7,MPPIGrandC-MPPIwork(r11)			/* Point to GrandCentral */
			lwz		r4,MaskReg(r7)						/* Get the grand central mask register (note that this */
														/* is a little-endian area, but I'm too lazy to access it that way */
														/* so I'll document what it really should be, but, probably, it would */
														/* have been much, much easier just to code up the lwbrx and be done */
														/* with it rather than producing this monograph describing my alternate */
														/* access method that I really don't explain anyway. */
			ori		r4,r4,0x0040						/* Flip on bit 30 (hah, figure that one out).  This enables the */
														/* Ext10 interrupt which is connected to the MACE ethernet chip's */
														/* chip-select pin. */
			stw		r4,MaskReg(r7)						/* Stick it on back */
			eieio
			
			mtlr	r0									/* Get back the original LR */
			sync										/* Make sure all storage ops are done */
			mtmsr	r8									/* Restore the MSR */
			isync
			li		r3,kSIGPnoErr						/* Set that we worked jest fine and dandy */
			blr											/* Bye now... */

			.align	5
/******************************************************************************************************** */
/******************************************************************************************************** */
/* */
/*			This is where the individual SIGP function calls reside.  */
/*			Also, it is where we cram the second processor's initialization code wo'w we */
/*			can use physical addressing. */
/* */
/******************************************************************************************************** */
/******************************************************************************************************** */

MPPIFunctions:											/* Start of all externally called functions and interrupt handling code */


/******************************************************************************************************** */
/* */
/*			Count the number of processors.  This hardwires to 2 (or 1 if no secondary) */
/* */
/******************************************************************************************************** */

CountProcessors:
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			mfmsr	r9									/* Get the MSR */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			
			ori		r10,r9,0x0010						/* Turn on DDAT */
			
			lwz		r8,MPPIHammer-MPPIwork(r12)			/* Point to the HammerHead controller */
			
			mtmsr	r10									/* Turn on DDAT */
			isync										/* Kill speculation */

			li		r3,2								/* Assume we have them all */
			lbz		r5,ArbConfig(r8)					/* Check if we've seen a second processor */
			andi.	r5,r5,TwoCPU						/* Are we a real live two processor? */
			mtmsr	r9									/* Put back the DDAT */
			isync
			
			bnelr+										/* Yeah... */
			li		r3,1								/* Nope, set a count of 1 */
			blr											/* Leave, we're inadequate... */

/******************************************************************************************************** */
/* */
/*			Start up the selected processor (R3=processor; R4=physical start address; R5=pass-thru parm) */
/* */
/******************************************************************************************************** */
			
StartProcessor:

			mr		r7,r5								/* Copy pass-thru parameter */
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			cmplw	cr0,r3,r10							/* Trying to start ourselves? */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kMPPHairyPalms					/* Set trying to do it to ourselves */
			beqlr-										/* Self abuse... */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			mflr	r11									/* Save the return address */
			add		r9,r9,r12							/* Point right at the entry */
			
SPretry:	lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			li		r3,kSIGPInterfaceBusyErr			/* Fill dead space and get busy return code */
			rlwinm.	r0,r5,0,0,0							/* Are we marked as busy? */
			lis		r6,MPPICOnline>>16					/* Get the online flag */
			bne-	ErrorReturn							/* Yeah, go leave, don't bother me now... */
			and.	r0,r5,r6							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			beq-	ErrorReturn							/* Ain't online, ain't ready, buzz off... */
			li		r3,kMPPBadState						/* Set bad state */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Turn on the busy bit */
			
			stwcx.	r5,0,r9								/* Try to set busy */
			bne-	SPretry								
			
			ori		r6,r10,MPPICfStrt<<8				/* Put the Start function in front of the processor ID */
			rlwimi	r5,r6,0,16,31						/* Put these behind the status flags */
			stw		r4,MPPICParm0(r9)					/* Set the starting physical address parameter */
			stw		r7,MPPICParm2(r9)					/* Set pass-thru parameter */
			
			sync										/* Make sure it's all out there */
			b		KickAndGo							/* We're done now... */

/******************************************************************************************************** */
/* */
/*			Reset the selected processor (R3=processor).  You can't reset yourself or the primary. */
/*			We're gonna try, try real hard...  This is not for the faint-of-heart. */
/*			If there's ever any way to yank a reset line, we'll do it here. */
/* */
/******************************************************************************************************** */
			
ResetProcessor:
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			rlwinm	r10,r10,0,28,31						/* Clean up the PIR */
			cmplw	cr0,r3,r10							/* Trying to start ourselves? */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kMPPHairyPalms					/* Set trying to do it to ourselves */
			beqlr-										/* Self abuse... */
			mr.		r9,r9								/* Trying to reset the primary?!?  Dude, that's insubordination!!!! */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			li		r3,kMPPInvalCPU						/* Say that that's a major offense */
			beqlr-										/* Bye now... */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)		/* Point into the proccessor control area		 */
			mflr	r11									/* Save the return address */
			add		r9,r9,r12							/* Point right at the entry */
			
			li		r4,16								/* Try for 16 times to get the busy lock */

RSlockS:	mftb	r6									/* Time stamp start */

RSlock:		lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			rlwinm.	r0,r5,0,2,2							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			cmplwi	cr1,r5,0							/* Check for busy */
			beq-	ErrorReturn							/* Ain't online, ain't ready, buzz off... */
			bge+	cr1,RSnotBusy						/* Not busy, make it so... */
			
			mftb	r7									/* Stamp the time */
			sub		r7,r7,r6							/* Get elapsed time */
			rlwinm.	r7,r7,16,16,31						/* Divide ticks by microseconds (this is pretty darn "kinda-in-the-ballpark") */
			cmplwi	cr0,r7,TicksPerMic					/* See if we hit 65536µS yet */
			blt+	RSlock								/* Not yet... */
			
RSatmtCnt:	subi	r4,r4,1								/* Count the retries */
			mr.		r4,r4								/* Are we done yet? */
			bgt+	RSlockS								/* Start the lock attempt again... */
			
			li		r3,kMPPCantLock						/* Say we can't get the lock */
			b		ErrorReturn							/* Bye, dude... */
			
RSnotBusy:	rlwinm	r5,r5,0,0,15						/* Clear out the function and requestor */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Set busy */
			or		r5,r10,r5							/* Add in our processor */
			ori		r5,r5,MPPICfReset<<8				/* Set the reset function */
			stwcx.	r5,0,r9								/* Cram it back */
			bne-	RSatmtCnt							/* We lost the reservation... */
			b		KickAndGo							/* Try to send it across... */
			

/******************************************************************************************************** */
/* */
/*			Here we will try to resume execution of a stopped processor (R3=processor). */
/* */
/******************************************************************************************************** */
			
ResumeProcessor:
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			cmplw	cr0,r3,r10							/* Trying to resume ourselves? */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kMPPHairyPalms					/* Set trying to do it to ourselves */
			beqlr-										/* Self abuse... */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			mflr	r11									/* Save the link register */
			add		r9,r9,r12							/* Point right at the entry */
			
RPretry:	lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			li		r3,kSIGPInterfaceBusyErr			/* Fill dead space and get busy return code */
			rlwinm.	r0,r5,0,0,0							/* Are we marked as busy? */
			lis		r6,MPPICOnline>>16					/* Get the online flag */
			bne-	ErrorReturn							/* Yeah, go leave, don't bother me now... */
			and.	r0,r5,r6							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			lis		r6,MPPICReady>>16					/* Get the ready bit */
			beq-	ErrorReturn							/* Ain't online, ain't ready, buzz off... */
			and.	r0,r5,r6							/* Are we ready? */
			li		r3,kMPPNotReady						/* Set not ready */
			lis		r6,MPPICStop>>16					/* Get the stopped bit */
			beq-	ErrorReturn							/* Ain't ready, buzz off... */
			and.	r0,r5,r6							/* Are we stopped? */
			li		r3,kMPPNotStopped					/* Set not stopped */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Turn on the busy bit */
			beq-	ErrorReturn							/* Nope, not stopped, so how do we resume? */
			
			stwcx.	r5,0,r9								/* Try to set busy */
			bne-	RPretry
			
			ori		r6,r10,MPPICfResm<<8				/* Put the resume function in front of the processor ID */
			rlwimi	r5,r6,0,16,31						/* Put these behind the status flags */
			b		KickAndGo							/* We're done now... */



/******************************************************************************************************** */
/* */
/*			Here we will try to stop execution of a running processor (R3=processor). */
/* */
/******************************************************************************************************** */
			
StopProcessor:
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			cmplw	cr0,r3,r10							/* Are we doing ourselves? */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kMPPHairyPalms					/* Set trying to do it to ourselves */
			beqlr-										/* Self abuse... */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			mflr	r11									/* Save the link register */
			add		r9,r9,r12							/* Point right at the entry */
			
PPretry:	lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			li		r3,kSIGPInterfaceBusyErr			/* Fill dead space and get busy return code */
			rlwinm.	r0,r5,0,0,0							/* Are we marked as busy? */
			lis		r6,MPPICOnline>>16					/* Get the online flag */
			bne-	ErrorReturn							/* Yeah, go leave, don't bother me now... */
			and.	r0,r5,r6							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			lis		r6,MPPICReady>>16					/* Get the ready bit */
			beq-	ErrorReturn							/* Ain't online, ain't ready, buzz off... */
			and.	r0,r5,r6							/* Are we ready? */
			li		r3,kMPPNotReady						/* Set not ready */
			lis		r6,MPPICStop>>16					/* Get the stopped bit */
			beq-	ErrorReturn							/* Ain't ready, buzz off... */
			and.	r0,r5,r6							/* Are we stopped? */
			li		r3,kMPPNotRunning					/* Set not running */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Turn on the busy bit */
			bne-	ErrorReturn							/* Nope, already stopped, so how do we stop? */
			
			stwcx.	r5,0,r9								/* Try to set busy */
			ori		r10,r10,MPPICfStop<<8				/* Put the stop function in front of the processor ID */
			bne-	PPretry
			
			rlwimi	r5,r10,0,16,31						/* Put these behind the status flags */
			b		KickAndGo							/* We're done now... */


/******************************************************************************************************** */
/* */
/*			Here we will try to signal a running processor (R3=processor). */
/*			Note that this should have good performace.  Well, actually, seeing as how slow we really are, it */
/*			probably is moot anyhow. */
/*			Another note: this function (and all most others as well) will return a timeout when the  */
/*			second processor tries to do itself on the old version of the board.  This happens because */
/*			In order to keep the watchchihuahua from popping (just imagine the scene: that little runt-dog just so */
/*			excited that its veins and eyes bulge and then explode) signaling to the secondary  */
/*			is done syncronously and disabled.  If the secondary signals the secondary, it will never enable so */
/*			it will never see the 'rupt, so it will never clear it, so it will time out, so there... */
/* */
/******************************************************************************************************** */
			
SignalProcessor:
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			mflr	r11									/* Save the link register */
			add		r9,r9,r12							/* Point right at the entry */
			
SiPretry:	lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			li		r3,kSIGPInterfaceBusyErr			/* Fill dead space and get busy return code */
			rlwinm.	r0,r5,0,0,0							/* Are we marked as busy? */
			lis		r6,MPPICOnline>>16					/* Get the online flag */
			bne-	ErrorReturn							/* Yeah, go leave, don't bother me now... */
			and.	r0,r5,r6							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			lis		r6,MPPICReady>>16					/* Get the ready bit */
			beq-	ErrorReturn							/* Ain't online, ain't ready, buzz off... */
			and.	r0,r5,r6							/* Are we ready? */
			li		r3,kMPPNotReady						/* Set not ready */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Turn on the busy bit */
			beq-	ErrorReturn							/* Ain't ready, buzz off... */
			
			stwcx.	r5,0,r9								/* Try to set busy */
			ori		r10,r10,MPPICfSigp<<8				/* Put the SIGP function in front of the processor ID */
			bne-	SiPretry
			
			stw		r4,MPPICParm0(r9)					/* Pass along the SIGP parameter */
			
			rlwimi	r5,r10,0,16,31						/* Put these behind the status flags */
			b		KickAndGo							/* We're done now... */


/******************************************************************************************************** */
/* */
/*			Here we will store the state of a processor (R3=processor; R4=status area). */
/*			Self abuse will store the state as is, is not asynchronous, and grows hair on your palms. */
/* */
/******************************************************************************************************** */
			
StoreProcessorStatus:
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			cmplw	cr0,r3,r10							/* Saving our own state???  Abusing oneself??? */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			mflr	r11									/* Save the link register */
			beq		Flagellant							/* Oh baby, oh baby... */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			add		r9,r9,r12							/* Point right at the entry */
			
SSretry:	lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			li		r3,kSIGPInterfaceBusyErr			/* Fill dead space and get busy return code */
			rlwinm.	r0,r5,0,0,0							/* Are we marked as busy? */
			lis		r6,MPPICOnline>>16					/* Get the online flag */
			bne-	ErrorReturn							/* Yeah, go leave, don't bother me now... */
			and.	r0,r5,r6							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			beq-	ErrorReturn							/* Ain't online, buzz off... */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Turn on the busy bit */
			
			stwcx.	r5,0,r9								/* Try to set busy */
			ori		r10,r10,MPPICfStat<<8				/* Put the store status function in front of the processor ID */
			bne-	SSretry								/* Lost reservation, return busy... */
			
			li		r0,0								/* Get false */
			stb		r0,CSAregsAreValid(r4)				/* Set that the registers ain't valid */
			stw		r4,MPPICParm0(r9)					/* Set the status area physical address parameter */
			
			rlwimi	r5,r10,0,16,31						/* Put these behind the status flags */
			b		KickAndGo							/* We're done now... */
			
/*			Spill one's seed upon the soil */

Flagellant:	bl		StoreStatus							/* Go store off all the registers 'n' stuff */
			mtlr	r11									/* Restore the return address */
			li		r3,kSIGPnoErr						/* Return no error */
			blr											/* Leave... */


/******************************************************************************************************** */
/* */
/*			Here we will attempt to syncronize clocks (R3=processor). */
/*			Self abuse will just return with an all-ok code. */
/* */
/******************************************************************************************************** */
			
SynchClock:
			mfspr	r10,pir								/* Get our processor number */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			cmplw	cr0,r3,r10							/* Cleaning our own clock?? */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			li		r3,kSIGPnoErr						/* Assume self-cleaning clock */
			beqlr										/* Oh baby, oh baby... */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			mflr	r11									/* Save the link register */
			add		r9,r9,r12							/* Point right at the entry */
			
SyCretry:	lwarx	r5,0,r9								/* Pick up the status flags (MPPICStat) and reserve it */
			li		r3,kSIGPInterfaceBusyErr			/* Fill dead space and get busy return code */
			rlwinm.	r0,r5,0,0,0							/* Are we marked as busy? */
			lis		r6,MPPICOnline>>16					/* Get the online flag */
			bne-	ErrorReturn							/* Yeah, go leave, don't bother me now... */
			and.	r0,r5,r6							/* Are we online */
			li		r3,kMPPOffline						/* Set offline */
			beq-	ErrorReturn							/* Ain't online, ain't ready, buzz off... */
			oris	r5,r5,(MPPICBusy>>16)&0x0000FFFF	/* Turn on the busy bit */
			li		r0,0								/* Clear this */
			
			stwcx.	r5,0,r9								/* Try to set busy */
			ori		r10,r10,MPPICfTBsy<<8				/* Put the timebase sync function in front of the processor ID */
			bne-	SyCretry							/* Lost reservation, return busy... */

			stw		r0,MPPITBsync+4-MPPIwork(r12)		/* Make sure the parm area is 0 */
			mr		r0,r11								/* Save the LR */
			bl		SyCbase								/* Get a base register */
SyCbase:	rlwimi	r5,r10,0,16,31						/* Put these behind the status flags */
			mflr	r11									/* Get the base */
			la		r11,(4*4)(r11)						/* DON'T MESS WITH THESE INSTRUCTIONS Make up the return point */
			b		KickAndGo							/* Go signal the other side */

SyCKrtrn:	mr		r11,r0								/* Restore the return */

/* */
/*			Start sync'ing 'er up */
/* */
		
			mftb	r4									/* Take a timeout stamp (don't need top half, we have at least 13 hours) */

SyCInP0:	lwz		r5,0(r9)							/* Get the CPU status word */
			rlwinm	r5,r5,24,24,31						/* Isolate the command byte */
			cmplwi	cr0,r5,MPPICfTBsy1					/* Have we reached time base sync phase 1 yet? */
			beq		SyCInP1								/* Yeah, we're in phase 1... */
			mftb	r5									/* Get the bottom half of the timer again */
			sub		r5,r5,r4							/* How long we been messin' around? */
			cmplwi	cr0,r5,1000*TicksPerMic				/* Don't try more'n' a 1000µS */
			blt+	SyCInP0								/* We haven't, so wait some more... */
			li		r3,kMPPTimeOut						/* Signal timeout */
			b		ErrorReturn							/* By dude... */
			
/* */
/*			Here we make sure there is enough time to sync the clocks before the lower part of the TB ticks */
/*			up into the high part.  This eliminates the need for any funky  */
/*			"get-the-top-then-get-the-bottom-then-get-the-top-again-to-see-if-it-changed" stuff.  That would */
/*			only make the sync harder to do. */
/*			 */
/*			Also, because we use the lower TB value for the signal, we also need to make sure we do not have */
/*			a value of 0, we would be ever-so-sorry if it was. */
/* */

SyCInP1:	li		r4,lo16(0xC000)						/* Get the minimum time left on clock before tick ('bout 1 1/4 ms) */
			li		r8,0								/* Get a 0 constant */
			
SyCdelay:	mftb	r5									/* Get the time left */
			cmplw	cr0,r5,r4							/* See if there is sufficient time before carry into high clock */
			bgt-	SyCdelay							/* Nope, hang until it is... */
			mr.		r5,r5								/* Did we just tick, however? */
			beq-	SyCdelay							/* Yeah, wait until it is at least 1... */
			
			mftbu	r4									/* Get the upper */
			stw		r4,MPPITBsync-MPPIwork(r12)			/* Make sure the top half is set */
			sync										/* Wait until it is done */
			
			mftb	r5									/* Get the lower timebase now */
			stw		r5,MPPITBsync+4-MPPIwork(r12)		/* Shove it out for the other processor */

			la		r6,MPPISncFght-MPPIwork(r12)		/* Point to the courtroom area */
			li		r5,0								/* Point to the first line */

SyCclear:	dcbz	r5,r6								/* Clear the court */
			addi	r5,r5,32							/* Point to the next line */
			cmplwi	cr0,r5,10*2*32						/* Enough for 9 iterations, 2 chunks at a time */
			blt+	SyCclear							/* Clear the whole smear... */
			sync										/* Make sure everyone's out */

			mftb	r5									/* Get the lower timebase now */
		
SyCWait:	lwz		r7,MPPITBsync+4-MPPIwork(r12)		/* Get it back */
			mftb	r6									/* Get the bottom half again */
			mr.		r7,r7								/* Have they set their clock yet? */
			sub		r0,r6,r5							/* See if we're hung up */
			beq-	SyCdonesync							/* Clock is set */
			cmplwi	cr0,r0,1000*TicksPerMic				/* Timeout if we spend more than 1000µS doing this */
			blt+	SyCWait								/* No timeout, wait some more... */
			li		r3,kMPPTimeOut						/* Set timeout */
			b		ErrorReturn							/* Leave... */
			
/* */
/*			Ok, so now we have set a preliminary TB value on the second processor.  It's close, but only */
/*			within handgranade range.   */
/* */
/*			What we will do now is to let the processors (starting with the other guy) argue about the time for */
/*			a while (10 passes-we use the middle 8).  We'll look at the results and try to adjust the other processor's */
/*			time such that the timing windows are overlapping evenly. This should put the TBs close enough together */
/*			(0-2 ticks) that the difference is undetectable. */
/* */


			
SyCdonesync:
			li		r4,0								/* Clear this */
			la		r5,MPPISncFght-MPPIwork(r12)		/* Point to the squared circle */

SyCWtArg:	
			dcbf	0,r5								/* Make sure of it */
			sync										/* Doubly shure */
			lwz		r6,0(r5)							/* Listen for the defence argument */

			mr.		r6,r6								/* See if they are done */
			beq+	SyCWtArg							/* Nope, still going... */

			mftb	r7									/* They're done, time for rebuttal */
			stw		r7,32(r5)							/* Make rebuttle */
	
			addi	r4,r4,1								/* Count rounds */

			cmplwi	cr0,r4,10							/* See if we've gone 8 rounds plus an extra one */
			addi	r5,r5,64							/* Point to the next round areas */

			blt+	SyCWtArg							/* Not yet, come out of your corners fighting... */
			
			mftb	r5									/* Stamp the wait */
			
SyCWadj:	lwz		r7,MPPITBsync+4-MPPIwork(r12)		/* Get adjustment flag */
			mftb	r6									/* Get timebase again */
			
			mr.		r7,r7								/* Have they set their timebase with adjusted time yet? */
			sub		r6,r6,r5							/* Get elapsed time */
			bne+	SyCdone								/* They say it, sync done... */
			cmplwi	cr0,r6,1000*TicksPerMic				/* Timeout if we spend more than 1000µS doing this */
			blt+	SyCWadj								/* Still time, wait until adjustment is done... */
			
			li		r3,kMPPTimeOut						/* Set timeout */
			b		ErrorReturn							/* Pass it back... */
			
SyCdone:	li		r3,kSIGPnoErr						/* No errors */
			mtlr	r11									/* Restore LR */
			blr											/* Leave... */


/******************************************************************************************************** */
/* */
/*			Here we will get the physical address of the interrupt handler. */
/* */
/******************************************************************************************************** */
			
GetExtHandlerAddress:
			mflr	r11									/* Save our return */
			bl		GEXbase								/* Make a base address */
GEXbase:	mflr	r3									/* Get address into our base */
			addi	r3,r3,LOW_ADDR(GotSignal-GEXbase)	/* Get the logical address of the 'rupt handler */

			mtlr	r11									/* Restore LR */
			blr


/******************************************************************************************************** */
/* */
/*			Here we will get a snapshot of the processor's current signaling state (R3=processor). */
/* */
/******************************************************************************************************** */
			
ProcessorState:
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			cmplwi	cr1,r3,MPPIMaxCPU					/* See if we are bigger than max */
			li		r3,kSIGPTargetAddrErr				/* CPU number is too big */
			bgtlr-	cr1									/* Sure are... (Get our address also) */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			add		r9,r9,r12							/* Point right at the entry */
			lwz		r4,MPPICStat(r9)					/* Get the status word */
			li		r3,kSIGPnoErr						/* Set no errors */
			rlwinm.	r4,r4,0,0,0							/* Test for busy status */
			beqlr										/* Return kSIGPnoErr if not busy */
			li		r3,kSIGPInterfaceBusyErr			/* Otherwise, return busy */
			blr											/* Return it */

/******************************************************************************************************** */
/* */
/*			Here we will try to handle any pending messages (just as if an interruption occurred). */
/*			The purpose of this function is to assure the message passing system runs even */
/*			though external interrupts are disabled. Lacking a separate physical signalling */
/*			class, we have to share the external interrupt signal. Unfortunately, there are */
/*			times when disabled loops occur (in spin locks, in the debugger, etc.), and when they */
/*			happen, a low level message sent to a processor will not get processed, hence this */
/*			function exists to be called from those disabled loops. Since the calls are often */
/*			from disabled code, all that can be done is to process any pending *message*. Any */
/*			pending notification interruption (referred to throughtout this code as a SIGP */
/*			interruption) must remain pending. */
/* */
/******************************************************************************************************** */
			
RunSIGPRun:
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			mfspr	r3,pir								/* Get our CPU address */
			rlwinm	r9,r3,5,23,26						/* Get index into CPU array */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			mflr	r11									/* Save the link register */
			add		r9,r9,r12							/* Point right at our entry */
			lwz		r3,MPPICPriv(r9)					/* Get our privates */
			cmplw	cr1,r11,r11							/* Make sure IdleWait doesn't try to clear 'rupt request */
			oris	r3,r3,MPPICXRun>>16					/* Diddle with them and show we entered here */
			stw		r3,MPPICPriv(r9)					/* Put away our privates */
			b		IdleWait							/* Go pretend there was an interrupt... */

/******************************************************************************************************** */
/* */
/*			Error return.  We only need this when we leave with a reservation.  We really SHOULD clear it... */
/* */
/******************************************************************************************************** */

ErrorReturn:
			mtlr	r11									/* Restore LR */
			blr											

/******************************************************************************************************** */
/* */
/*			Kick the target processor.  Note that we won't set the passing bit until we are ready to exit. */
/*			The reason for this is that we have the silly, old watchchihuahua board to deal with.  Because  */
/*			we can't just set the interrupt and leave, we gotta wait for it to be seen on the other side. */
/*			This means that there could be a timeout and if so, we need to back off the function request else */
/*			we'd see busy when they tried to redrive it.  We'll have to deal with a tad of spin on the secondary side. */
/*			note that this just applies to a primary to secondary function on the old board. */
/* */
/******************************************************************************************************** */
	
KickAndGo:
			la		r8,MPPICPU0-MPPIwork(r12)			/* Get the primary work area address */
			mtlr	r11									/* Restore the link register */
			cmplw	cr0,r8,r9							/* Which is target?  primary or secondary? */
			mfmsr	r11									/* Save off the MSR */
			oris	r5,r5,MPPICPass>>16					/* Set the passing bit on */
			stw		r5,MPPICStat(r9)					/* Store the pass and let the other processor go on */
			
			beq		KickPrimary							/* The target is the primary... */
			
			ori		r3,r11,0x0010						/* Turn on DDAT bit */
			lbz		r4,MPPIstatus-MPPIwork(r12)			/* Load up the global status byte */
			lwz		r8,MPPIHammer-MPPIwork(r12)			/* Point to the Hammerhead area */
	
			mtmsr	r3									/* Turn on DDAT */
			isync
			
			andi.	r4,r4,MPPI2Pv2						/* Are we on the new or old board? */
			li		r3,0								/* Set the bit for an interrupt request */
			beq		KickOld								/* Ok, it's the old board... */
			
			sync										/* Make sure this is out there */
			stb		r3,IntReg(r8)						/* Set the interruption signal */
			eieio
	
			mtmsr	r11									/* Set DDAT back to what it was */
			isync
			li		r3,kSIGPnoErr						/* Set no errors */
			blr											/* Leave... */
			
KickOld:	li		r4,8								/* Set the number of tries */

KickAgain:	mftb	r6									/* Stamp the bottom half of time base */
			stb		r3,IntReg(r8)						/* Stick the interrupt */
			eieio										/* Fence me in */
			
CheckKick:	lbz		r10,IntReg(r8)						/* Get the interrupt request back again */
			mr.		r10,r10								/* Yes? Got it? */
			bne		FinalDelay							/* Yeah, do the final delay and then go away... */
			
			mftb	r7									/* Get the time again */
			sub		r7,r7,r6							/* Get time-so-far */
			cmplwi	cr0,r7,75*TicksPerMic				/* Hold it for 75µS (average disable is supposed to be 100µS or so) */
			blt+	CheckKick							/* Keep waiting the whole time... */
			
			li		r10,SecInt							/* Set the deassert bit */
			mftb	r6									/* Stamp start of deassert time */
			stb		r10,IntReg(r8)						/* Deassert the interrupt request */
			eieio
			
DeassertWT:	mftb	r7									/* Stamp out the time */
			sub		r7,r7,r6							/* Get elapsed */
			cmplwi	cr0,r7,16*TicksPerMic				/* Hold off 16µS (minimum is 12µS) */
			blt+	DeassertWT							/* Keep spinning... */
			
			subi	r4,r4,1								/* See if we have another retry we can do */
			mr.		r4,r4								/* Are we there yet? */
			blt+	KickAgain							/* Retry one more time... */
			
			rlwinm	r5,r5,0,2,31						/* Clear busy and passing bits */
			rlwinm	r5,r5,0,24,15						/* Clear the function request to idle */
			
			mtmsr	r11									/* Restore DDAT stuff */
			isync

			stw		r5,MPPICStat(r9)					/* Rescind the request */
			li		r3,kMPPTimeOut						/* Set timeout */
			blr											/* Leave... */
			
FinalDelay:	mftb	r6									/* Stamp the start of the final delay */

FinalDelayW:
			mftb	r7									/* Stamp out the time */
			sub		r7,r7,r6							/* Get elapsed */
			cmplwi	cr0,r7,16*TicksPerMic				/* Hold off 16µS (minimum is 12µS) */
			blt+	FinalDelayW							/* Keep spinning... */

			mtmsr	r11									/* Restore DDAT stuff */
			isync
			li		r3,kSIGPnoErr						/* Set no errors */
			blr											/* Leave... */
			
KickPrimary:
			ori		r3,r11,0x0010						/* Turn on the DDAT bit */
			lwz		r8,MPPIEther-MPPIwork(r12)			/* Get the address of the ethernet ROM */
			
			mtmsr	r3									/* Turn on DDAT */
			isync

			li		r4,4								/* Get flip count */
			
			sync										/* Make sure the status word is out there */

FlipOff:	lbz		r3,0(r8)							/* Reference ethernet ROM to get chip select twiddled */
			eieio										/* Make sure of this (Hmm, this is chip select, not memory-mapped */
														/* storage.  Do we even need the eieio?) */
														
			addic.	r4,r4,-1							/* Have we flipped them off enough? */
			bgt+	FlipOff								/* Not yet, they deserve more... */
			
			mtmsr	r11									/* Restore DDAT stuff */
			isync
			li		r3,kSIGPnoErr						/* Set no errors */
			blr											/* Return... */

/******************************************************************************************************** */
/* */
/*			This is the code for the secondary processor */
/* */
/******************************************************************************************************** */

/*			Note that none of this code needs locks because there's kind of a synchronization */
/*			shuffle going on. */

/* */
/*			First, we need to do a bit of initialization of the processor. */
/* */


CPUInit:	
			li		r27,0x3040							/* Set floating point and machine checks on, IP to 0xFFF0xxxx */
			mtmsr	r27									/* Load 'em on in */
			isync
			
			lis		r28,-32768							/* Turn on machine checks */
														/* should be 0x8000 */
			ori		r28,r28,0xCC84						/* Enable caches, clear them,  */
														/* disable serial execution and turn BHT on */
			sync
			mtspr	HID0,r28							/* Start the cache clear */
			sync

/* */
/*			Clear out the TLB.  They be garbage after hard reset. */
/* */

			li		r0,512								/* Get number of TLB entries (FIX THIS) */
			li		r3,0								/* Start at 0 */
			mtctr	r0									/* Set the CTR */
			
purgeTLB:	tlbie	r3									/* Purge this entry */
			addi	r3,r3,4096							/* Next page */
			bdnz	purgeTLB							/* Do 'em all... */
					
			sync										/* Make sure all TLB purges are done */
			tlbsync										/* Make sure on other processors also */
			sync										/* Make sure the TLBSYNC is done */

/* */
/*			Clear out the BATs.  They are garbage after hard reset. */
/* */

			li		r3,0								/* Clear a register */
			
			mtspr	DBAT0L,r3							/* Clear BAT */
			mtspr	DBAT0U,r3							/* Clear BAT */
			mtspr	DBAT1L,r3							/* Clear BAT */
			mtspr	DBAT1U,r3							/* Clear BAT */
			mtspr	DBAT2L,r3							/* Clear BAT */
			mtspr	DBAT2U,r3							/* Clear BAT */
			mtspr	DBAT3L,r3							/* Clear BAT */
			mtspr	DBAT3U,r3							/* Clear BAT */
			
			mtspr	IBAT0L,r3							/* Clear BAT */
			mtspr	IBAT0U,r3							/* Clear BAT */
			mtspr	IBAT1L,r3							/* Clear BAT */
			mtspr	IBAT1U,r3							/* Clear BAT */
			mtspr	IBAT2L,r3							/* Clear BAT */
			mtspr	IBAT2U,r3							/* Clear BAT */
			mtspr	IBAT3L,r3							/* Clear BAT */
			mtspr	IBAT3U,r3							/* Clear BAT */

/* */
/*			Map 0xF0000000 to 0xFFFFFFFF for I/O; make it R/W non-cacheable */
/*			Map	0x00000000 to 0x0FFFFFFF for mainstore; make it R/W cachable */
/* */

			lis		r6,0xF000							/* Set RPN to last segment */
			ori		r6,r6,0x1FFF						/* Set up upper BAT for 256M, access both */
			
			lis		r7,0xF000							/* Set RPN to last segment */
			ori		r7,r7,0x0032						/* Set up lower BAT for 256M, access both, non-cachable */
		
			mtspr	DBAT0L,r7							/* Setup ROM and I/O mapped areas */
			mtspr	DBAT0U,r6							/* Now do the upper DBAT */
			sync
	
			li		r6,0x1FFF							/* Set up upper BAT for 256M, access both */
			li		r7,0x0012							/* Set up lower BAT for r/w access */
			
			mtspr	DBAT1L,r7							/* Set up an initial view of mainstore */
			mtspr	DBAT1U,r6							/* Now do the upper DBAT */
			sync

/* */
/*			Clean up SDR and segment registers */
/* */

			li		r3,0								/* Clear a register */
			mtspr	SDR1,r3								/* Clear SDR1 */
			
			li		r4,0								/* Clear index for segment registers */
			lis		r5,0x1000							/* Set the segment indexer */
			
clearSR:	mtsrin	r3,r4								/* Zero out the SR */
			add.	r4,r4,r5							/* Point to the next segment */
			bne-	clearSR								/* Keep going until we wrap back to 0 */
			
			lis		r5,HIGH_ADDR(EXT(FloatInit))		/* Get top of floating point init value */
			ori		r5,r5,LOW_ADDR(EXT(FloatInit))		/* Slam bottom */
			lfd		f0,0(r5)							/* Initialize FP0 */
			fmr		f1,f0								/* Ours in not */					
			fmr		f2,f0								/* to wonder why, */
			fmr		f3,f0								/* ours is but to */
			fmr		f4,f0								/* do or die! */
			fmr		f5,f0						
			fmr		f6,f0						
			fmr		f7,f0						
			fmr		f8,f0						
			fmr		f9,f0						
			fmr		f10,f0						
			fmr		f11,f0						
			fmr		f12,f0						
			fmr		f13,f0						
			fmr		f14,f0						
			fmr		f15,f0						
			fmr		f16,f0						
			fmr		f17,f0						
			fmr		f18,f0						
			fmr		f19,f0						
			fmr		f20,f0						
			fmr		f21,f0						
			fmr		f22,f0						
			fmr		f23,f0						
			fmr		f24,f0						
			fmr		f25,f0						
			fmr		f26,f0						
			fmr		f27,f0						
			fmr		f28,f0						
			fmr		f29,f0						
			fmr		f30,f0						
			fmr		f31,f0						
			
/* */
/*			Whew, that was like, work, man!  What a cleaning job, I should be neater */
/*			when I reset. */
/* */
/*			Finally we can get some data DAT turned on and we can reset the interrupt */
/*			(which may have been done before we get here) and get into the bring up */
/*			handshakes. */
/*		 */
/*			Note that here we need to use the actual V=R addresses for HammerHead */
/*			and PCI1 adr.  There are no virtual mappings set up on this processor. */
/*			We need to switch once the firmware is initialized.  Also, we don't know */
/*			where our control block is yet. */
/* */
		
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */

			mfmsr	r3									/* Get the MSR */
			ori		r3,r3,0x0010						/* Turn data DAT on */
			mtmsr	r3									/* DAT is on (well, almost) */
			isync										/* Now it is for sure */
		
			lis		r8,HammerHead>>16					/* Point to the HammerHead controller */
			li		r7,SecInt							/* Get value to reset */
			stb		r7,IntReg(r8)						/* Reset the interrupt */
			eieio										/* Fence it off */
		
/* */
/*			Now we can plant and harvest some bits. */
/* */
		
			lwz		r6,MPPIlogCPU-MPPIwork(r12)			/* Get the logical CPU address to assign */
			mfspr	r7,pir								/* Get the old PIR */
			rlwimi	r7,r6,0,27,31						/* Copy all of the reserved parts */
			mtspr	pir,r7								/* Set it */
			
/* */
/*			This little piece of code here determines if we are on the first or second version */
/*			of the two processor board.  The old one shouldn't ever be shipped (well, maybe by  */
/*			DayStar) but there are some around here. */
/* */
/*			The newer version of the 2P board has a different state machine than the older one. */
/*			When we are in the board state we're in now, primary arbitration is turned on while */
/*			it is not until the next state in the old board.  By checking the our bus address */
/*			(WhoAmI) we can tell. */
/* */

			lbz		r7,WhoAmI(r8)						/* Get the current bus master ID */
			andi.	r7,r7,PriCPU						/* Do we think we're the primary? */
			beq		On2Pv1								/* No, that means we're on the old 2P board */
			
			lbz		r7,MPPIstatus-MPPIwork(r12)			/* Get the status byte */
			ori		r7,r7,MPPI2Pv2						/* Show we're on the new board */
			stb		r7,MPPIstatus-MPPIwork(r12)			/* Set the board version */
			
On2Pv1:		rlwinm	r9,r6,5,23,26						/* Get index into the CPU specific area */
				
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Index to processor */
			add		r9,r9,r12							/* Get a base for our CPU specific area */
			
			oris	r6,r6,((MPPICBusy+MPPICOnline+MPPICStop)>>16)&0x0000FFFF	/* Set CPU busy, online, stopped,  */
																				/*   and busy set by himself */
			stw		r6,MPPICStat(r9)					/* Save the whole status word */
			
			li		r4,0x80								/* Get beginnings of a CPU address mask */
			lhz		r11,MPPIinst-MPPIwork(r12)			/* Get the installed and online status flags */
			srw		r4,r4,r6							/* Make a mask */
			rlwimi	r4,r4,8,16,23						/* Double up the mask for both flags */
			or		r11,r11,r4							/* Set that we are installed and online */
			sync										/* Make sure the main processor sees the rest of the stuff */
			
			sth		r11,MPPIinst-MPPIwork(r12)			/* We're almost done, just need to set the TB */
			
			lis		r5,PCI1AdrReg>>16					/* Point to the PCI1 address register		 */
			li		r4,0								/* Clear this out */
			stw		r4,0(r5)							/* Set PCI register to 0 to show we're ready for TB sync */
			eieio										/* Fence it off */

Wait4TB:	lwz		r7,0(r5)							/* Get the PCI1 reg to see if time to set time */
			mr.		r7,r7								/* Is it ready yet? */
			beq		Wait4TB								/* Nope, wait for it... */
			isync										/* No peeking... */
			
			lwz		r3,MPPITBsync-MPPIwork(r12)			/* Get the high word of TB */
			lwz		r4,MPPITBsync+4-MPPIwork(r12)		/* Get the low word */
			
/*			Note that we need no TB magic here 'cause they ain't running */

			mttbu	r3									/* Set the high part */
			mttbl	r4									/* Set the low part */
			
			rlwinm	r6,r6,0,2,31						/* Clear the busy bit and passed */
			stw		r6,MPPICStat(r9)					/* Store the status word */
			
			sync										/* Make sure all is right with the world */
			
			li		r3,0								/* Set the init done signal */
			stw		r3,0(r5)							/* Feed the dog and let him out */
			sync										/* Make sure this is pushed on out */

			li		r27,0x3040							/* Make MSR the way we likes it */
			mtmsr	r27									/* Load 'em on in */
			isync

/* */
/*			Jump on to the idle wait loop.  We're online and ready, but we're */
/*			still in the reset state.  We need to wait until we see a start signal. */
/* */
/*			Note that the idle loop expects R9 to be our CPU-specific work area; */
/*			R12 is the base of the code and global work area  */
/* */

			cmplw	cr1,r11,r12							/* Make sure IdleWait knows to clear 'rupt request */
			b		IdleWait


/******************************************************************************************************** */
/******************************************************************************************************** */
/* */
/*			Here is the interruption handler. */
/* */
/*			What we'll do here is to get our registers into a standard state and figure out which */
/*			which processor we are on.  The processors have pretty much the same code.  The primary */
/*			will reset the the secondary to primary interruption bit and the secondary will reset the SecInt */
/*			flags. */
/* */
/*			The primary to secondary interrupt is an exception interruption contolled by a bit in the  */
/*			Hammerhead IntReg.  The only bit in here is SecInt which is active low.  Writing a 0 into the */
/*			bit (bit 0) yanks on the external pin on the secondary.  Note that it is the only external */
/*			connected on the secondary.  SecInt must be set to 1 to clear the interruption.  On the old */
/*			2P board, asserting the external interrupt causes a watchdog timer to start which expires unless */
/*			the interrupt request is withdrawn. On a 180Mhz system the time to expire is about 256µS,  */
/*			not very long.  So, what we need to do is to time the assertion and if it has not been reset */
/*			reset, do it ourself.  Unfortunatelty we need to keep it deasserted for at least 12µS or the  */
/*			watchdog will not stop.  This leads to another problem: even if the secondary processor sees */
/*			the interrupt and deasserts the request itself,  we cannot reassert before the 12µS limit, */
/*			else havoc will be wrought.  We just gotta make sure. */
/* */
/*			So, the secondary to primary interrupt is megafunky.  The mother board is wired with the  */
/*			MACE ethernet chip's chip-select pin wired to Grand Centeral's external interrrupt #10 pin. */
/*			This causes a transient interrupt whenever MACE is diddled. GC latches the interrupt into the */
/*			events register where we can see it and clear it. */
/* */
/******************************************************************************************************** */
/******************************************************************************************************** */

GotSignal:	mfspr	r9,pir								/* Get our processor ID */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top half of the data area */
			rlwinm	r9,r9,5,23,26						/* Clean this up */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get the bottom half of the data area */
			la		r9,EXT(MPPICPUs)-MPPIwork(r9)			/* Point into the proccessor control area */
			mflr	r11									/* Save our return */
			add		r9,r9,r12							/* Point right at the entry */

/*			We'll come in here if we're stopped and found the 'rupt via polling */
/*			or we were kicked off by the PollSIGP call.  We  need */
/*			to wipe out the interrupt request no matter how we got here. */

SimRupt:	mfmsr	r4									/* Get the MSR */

			la		r8,MPPICPU0-MPPIwork(r12)			/* Get address of main processor's work area */
			ori		r5,r4,0x0010						/* Turn on the DDAT bit */
			cmplw	cr0,r8,r9							/* Are we on the main? */
			cmplw	cr1,r4,r4							/* Set CR1 to indicate we've cleared any 'rupts */
			bne		SecondarySig						/* Go if we are not on main processor... */

/* */
/*			Handle the secondary to primary signal */
/* */

PrimarySig:

			lwz		r8,MPPIGrandC-MPPIwork(r12)			/* Get the address of the Grand Central area base */
			mtmsr	r5									/* Turn on DDAT */
			isync										/* Now don't be usin' dem speculative executions */
			li		r7,EventsReg						/* Get address of the interrupt events register */
			lwbrx	r6,r7,r8							/* Grab the interruption events */

			lis		r5,0x4000							/* Get the mask for the Ext10 pin */
			and.	r0,r6,r5							/* See if our bit is on */
			li		r7,ClearReg							/* Point to the interruption clear register */
		
			beq+	SkpClr								/* Skip the clear 'cause it's supposed to be soooo slow... */
			
			stwbrx	r5,r7,r8							/* Reset the interrupt latch */
			eieio										/* Fence off the last 'rupt */

SkpClr:		mtmsr	r4									/* Set MSR to entry state */
			isync										/* Make sure we ain't gunked up no future storage references */
		
			bne+	IdleWait							/* Go join up and decode the function... */
			
			mtlr	r11									/* Restore return address */
			andc.	r0,r6,r5							/* Any other bits on? */
			li		r3,kMPVainInterrupt					/* Assume we got nothing */
			beqlr										/* We got nothing, tell 'em to eat 'rupt... */
			li		r3,kMPIOInterruptPending			/* Tell them to process an I/O 'rupt */
			blr											/* Ignore the interrupt... */

/* */
/*			Handle the primary to secondary signal */
/* */

SecondarySig:
			lwz		r3,MPPICStat(r9)					/* Pick up our status word */
			lis		r8,HammerHead>>16					/* Get the address of the hammerhead (used during INIT on non-main processor) */
			rlwinm.	r3,r3,0,3,3							/* Check if we are already "in-the-know" (all started up) */
			beq-	UseAltAddr							/* Nope, use hardcoded Hammerhead address */
			lwz		r8,MPPIHammer-MPPIwork(r12)			/* Get the kernel's HammerHead area */

UseAltAddr:	mtmsr	r5									/* Turn on DDAT */
			isync										/* Now don't be usin' dem speculative executions */
			li		r0,SecInt							/* Get the Secondary interrupt bit */
			stb		r0,IntReg(r8)						/* Reset the interrupt request */
			mtmsr	r4									/* Set MSR to entry state */
			eieio										/* Fence me in */
			isync										/* Make sure we ain't gunked up no future storage references */
			
			b		IdleWait							/* Go decode this request... */
			
/******************************************************************************************************** */
/******************************************************************************************************** */
/* */
/*			This is the idle wait.   */
/* */
/*			We're stuck in here so long as we are stopped or reset. */
/*			All functions except for "start" pass back through here.  Start is weird because */
/*			it is an initial thing, i.e., we can't have gotten here via any kind of exception, */
/*			so there is no state to restore.  The "started" code is expected to require no know */
/*			state and will take care of all initialization/fixup required. */
/* */
/******************************************************************************************************** */
/******************************************************************************************************** */

BadRuptState:											/* We don't do anything special yet for a bad state, just eat request */
KillBusy:	rlwinm	r3, r3, 0, 2, 31					/* Remove the message pending flags. */
			rlwinm	r3, r3, 0, 24, 16					/* Set the function to idle. */
			stw		r3,MPPICStat(r9)					/* Update/unlock the status word. */

ReenterWait: cmplwi	cr1,r9,0							/* Turn off the 'rupt cleared flag */

IdleWait:	lis		r4,MPPICBusy>>16					/* Get busy status */

SpinIdle:				
			lwz		r3,MPPICStat(r9)					/* Pick up our status word */
		
			and.	r5,r3,r4							/* Isolate the busy bit */
			lis		r6,MPPICPass>>16					/* Get the passed busy flag */
			bne		TooBusy								/* Work, work, work, that's all we do is work... */
			
			rlwinm.	r5,r3,0,4,4							/* See if we are stopped */
			lwz		r8,MPPICPriv(r9)					/* Pick up our private flags */
			bne-	SpinIdle							/* Yeah, keep spinning... */
			
			
/* */
/*			Restore the state and get outta here.  Now, we shouldn't be in a reset state and not be stopped, */
/*			so we can go ahead and safely return up a level because it exists.  If we are reset, no state exists */
/*			and we should always be stopped. */
/* */
			
			rlwinm	r4, r8, 1, 0, 0 					/* Get the explicit run bit, shifted left one. */
			rlwinm.	r5, r8, 0, 0, 0						/* See if there is a SIGP signal pending */
			and		r4, r8, r4							/* Turn off the SIGP pending bit if this was not an explicit run */
														/* Also the explicit run bit is cleared */
			mtlr	r11									/* Restore the return point */
			li		r3,kMPVainInterrupt					/* Tell the interrupt handler to ignore the interrupt */
			stw		r4,MPPICPriv(r9)					/* Set that flag back for later */
			beqlr										/* Time to leave if we ate the 'rupt... */

			li		r3,kMPSignalPending					/* Set that there is a SIGP interruption pending */
			
			blr											/* Go away, let our caller handle this thing... QED!!!!!!!!! */

/* */
/*           QQQQQ       EEEEEEEEEE    DDDDDDDDD */
/*         QQQQQQQQQ     EEEEEEEEEE    DDDDDDDDDDD */
/*        QQQQ   QQQQ    EEEE          DDD     DDD */
/*       QQQQ     QQQQ   EEEEEEEEEE    DDD     DDD */
/*       QQQQ   Q QQQQ   EEEEEEEEEE    DDD     DDD */
/*        QQQQ  QQQQQ    EEEE          DDD     DDD */
/*         QQQQQQQQQQQ   EEEEEEEEEE    DDDDDDDDDDD */
/*           QQQQQ QQQ   EEEEEEEEEE    DDDDDDDDD */
/* */
/*			(I finished here) */
/* */

			
/* */
/*			This is where we decode the function and do what's right. */
/*			First we need to check if it's really time to do something. */
/* */

TooBusy:	and.	r5,r3,r6							/* See if the passed flag is on */
			beq		SpinIdle							/* No, not yet, try the whole smear again... */
			
			beq+	cr1,KeepRupt						/* Don't clear 'rupt if we already did (or entered via RunSIGRun) */

			lwz		r5,MPPICPriv(r9)					/* Get the private flags */
			rlwinm.	r5, r5, 0, 1, 1						/* Did we enter via RunSIGPRun? */
			beq		SimRupt								/* Nope, 's'ok, go clear physical 'rupt... */
			
KeepRupt:
			bl		GetOurBase							/* Get our address */
GetOurBase:	rlwinm	r4,r3,26,22,29						/* Get the opcode index * 4 */
			mflr	r12									/* Get the base address */
			la		r7,LOW_ADDR(IFuncTable-GetOurBase)(r12)		/* Point to the function table */
			
			cmplwi	cr0,r4,7*4							/* See if they sent us some bogus junk */
														/* Change 7 if we add more functions */
			add		r7,r7,r4							/* Point right at the entry */
			bgt-	KillBusy							/* Bad request code, reset busy and eat it... */
			
			mtlr	r7									/* Set up the LR */
			
			blr											/* Go execute the function... */
	
IFuncTable:
			b		KillBusy							/* This handles the signal in vain... */
			b		IStart								/* This handles the start function */
			b		IResume								/* This handles the resume function */
			b		IStop								/* This handles the stop function */
			b		ISIGP								/* This handles the SIGP function */
			b		IStatus								/* This handles the store status function */
			b		ITBsync								/* This handles the synchronize timer base function */
			b		IReset								/* This handles the reset function */

/******************************************************************************************************** */
/******************************************************************************************************** */
/* */
/*			Here are the functions handled at interrupt time */
/* */
/******************************************************************************************************** */
/******************************************************************************************************** */

/******************************************************************************************************** */
/* */
/*			The Start function.  This guy requires that the processor be in the reset and online state. */
/* */
/******************************************************************************************************** */

IStart:		lis		r4,MPPICOnline>>16					/* Get bits required to be on */
			isync										/* Make sure we haven't gone past here */
			and		r6,r3,r4							/* See if they are on */
			cmplw	cr1,r6,r4							/* Are they all on? */
			lwz		r4,MPPICParm0(r9)					/* Get the physical address of the code to go to */
			bne-	cr1,BadRuptState					/* Some required state bits are off */
			rlwinm	r3,r3,0,2,31						/* Kill the busy bits */
			rlwinm	r3,r3,0,24,15						/* Set the function to idle */
			oris	r3,r3,MPPICReady>>16				/* Set ready state */
			rlwinm	r3,r3,0,5,3							/* Clear out the stop bit */
			mtlr	r4									/* Set the LR */
			stw		r3,MPPICStat(r9)					/* Clear out the status flags */
			lwz		r3,MPPICParm2(r9)					/* Get pass-thru parameter */
			blrl										/* Start up the code... */
/* */
/*			The rules for coming back here via BLR are just opposite the normal way:  you can trash R0-R3 and */
/*			R13-R31, all the CRs; don't touch SPRG1 or SPRG3, the MSR, the SRs or BATs 0 and 1. */
/*			Follow these simple rules and you allowed back; don't follow them and die. */
/*			We only come back here if there is some kind of startup failure so's we can try again later */
/* */

			lwz		r3,MPPICStat(r9)					/* Get back the status word */
			cmplw	cr1,r4,r4							/* Show that we have already taken care of the 'rupt */
			rlwinm	r3,r3,0,4,2							/* Reset the ready bit */
			b		KillBusy							/* Back into the fold... */

/******************************************************************************************************** */
/* */
/*			The Resume function.  This guy requires that the processor be online and ready. */
/* */
/******************************************************************************************************** */

IResume:	lis		r4,(MPPICOnline+MPPICReady)>>16		/* Get states required to be set */
			and		r6,r3,r4							/* See if they are on */
			cmplw	cr0,r6,r4							/* Are they all on? */
			bne-	BadRuptState						/* Some required off state bits are on */
			rlwinm	r3,r3,0,5,3							/* Clear out the stop bit */
			b		KillBusy							/* Get going... */

/******************************************************************************************************** */
/* */
/*			The Stop function.  All we care about here is that the guy is online. */
/* */
/******************************************************************************************************** */

IStop:		lis		r4,MPPICOnline>>16					/* All we care about is if we are online or not */
			and.	r6,r3,r4							/* See if we are online */
			beq-	BadRuptState						/* Some required off state bits are on */
			oris	r3,r3,MPPICStop>>16					/* Set the stop bit */
			b		KillBusy							/* Get stopped... */


/******************************************************************************************************** */
/* */
/*			The SIGP function.  All we care about here is that the guy is online. */
/* */
/******************************************************************************************************** */

ISIGP:		lis		r4,(MPPICOnline+MPPICReady)>>16		/* Get states required to be set */
			and		r6,r3,r4							/* See if they are on */
			lwz		r7,MPPICPriv(r9)					/* Get the private flags */
			cmplw	cr0,r6,r4							/* Are they all on? */
			oris	r6,r7,(MPPICSigp>>16)&0x0000FFFF	/* Set the SIGP pending bit */
			bne-	BadRuptState						/* Some required off state bits are on */
			lwz		r4,MPPICParm0(r9)					/* Get the SIGP parameter */
			stw		r6,MPPICPriv(r9)					/* Stick the pending bit back */
			stw		r4,MPPICParm0BU(r9)					/* Back up parm 0 so it is safe once we unlock */
			b		KillBusy							/* Get stopped... */

/******************************************************************************************************** */
/* */
/*			The store status function.  This guy requires that the processor be in the stopped state. */
/* */
/******************************************************************************************************** */

IStatus:	lis		r4,MPPICOnline>>16					/* All we care about is if we are online or not */
			and.	r6,r3,r4							/* See if we are online */
			isync										/* Make sure we havn't gone past here */
			beq-	BadRuptState						/* Some required off state bits are on */
			lwz		r4,MPPICParm0(r9)					/* Get the status area physical address */
			rlwinm.	r6,r3,0,3,3							/* Test processor ready */
			
			beq		INotReady							/* Not ready, don't assume valid exception save area */
			bl		StoreStatus							/* Go store off all the registers 'n' stuff */
			b		KillBusy							/* All done... */
			
INotReady:
			lis		r7,0xDEAD							/* Get 0xDEAD + 1 */
			ori		r7,r7,0xF1D0						/* Get 0xDEADF1D0 */
			stw		r7,CSAgpr+(0*4)(r4)					/* Store invalid R0 */
			stw		r7,CSAgpr+(1*4)(r4)					/* Store invalid R1 */
			stw		r7,CSAgpr+(2*4)(r4)					/* Store invalid R2 */
			stw		r7,CSAgpr+(3*4)(r4)					/* Store invalid R3 */
			stw		r7,CSAgpr+(4*4)(r4)					/* Store invalid R4 */
			stw		r7,CSAgpr+(5*4)(r4)					/* Store invalid R5 */
			stw		r7,CSAgpr+(6*4)(r4)					/* Store invalid R6 */
			stw		r7,CSAgpr+(7*4)(r4)					/* Store invalid R7 */
			stw		r7,CSAgpr+(8*4)(r4)					/* Store invalid R8 */
			stw		r7,CSAgpr+(9*4)(r4)					/* Store invalid R9 */
			stw		r7,CSAgpr+(10*4)(r4)				/* Store invalid R10 */
			stw		r7,CSAgpr+(11*4)(r4)				/* Store invalid R11 */
			stw		r7,CSAgpr+(12*4)(r4)				/* Store invalid R12 */
			stw		r13,CSAgpr+(13*4)(r4)				/* Save general registers */
			stw		r14,CSAgpr+(14*4)(r4)				/* Save general registers */
			stw		r15,CSAgpr+(15*4)(r4)				/* Save general registers */
			stw		r16,CSAgpr+(16*4)(r4)				/* Save general registers */
			stw		r17,CSAgpr+(17*4)(r4)				/* Save general registers */
			stw		r18,CSAgpr+(18*4)(r4)				/* Save general registers */
			stw		r19,CSAgpr+(19*4)(r4)				/* Save general registers */
			stw		r20,CSAgpr+(20*4)(r4)				/* Save general registers */
			stw		r21,CSAgpr+(21*4)(r4)				/* Save general registers */
			stw		r22,CSAgpr+(22*4)(r4)				/* Save general registers */
			stw		r23,CSAgpr+(23*4)(r4)				/* Save general registers */
			stw		r24,CSAgpr+(24*4)(r4)				/* Save general registers */
			stw		r25,CSAgpr+(25*4)(r4)				/* Save general registers */
			stw		r26,CSAgpr+(26*4)(r4)				/* Save general registers */
			stw		r27,CSAgpr+(27*4)(r4)				/* Save general registers */
			stw		r28,CSAgpr+(28*4)(r4)				/* Save general registers */
			stw		r29,CSAgpr+(29*4)(r4)				/* Save general registers */
			stw		r30,CSAgpr+(30*4)(r4)				/* Save general registers */
			stw		r31,CSAgpr+(31*4)(r4)				/* Save general registers */
			bl		StoreLiveStatus
			b		KillBusy

/* */
/*			Save the whole status.  Lot's of busy work. */
/*			Anything marked unclean is of the devil and should be shunned.  Actually, it depends upon  */
/*			knowledge of firmware control areas and is no good for a plug in.  But, we've sacrificed the */
/*			white ram and are standing within a circle made of his skin, so we can dance with the devil */
/*			safely. */
/* */

StoreStatus:
			mfspr	r10,sprg0							/* Get the pointer to the exception save area (unclean) */
			
			lwz		r5,saver0(r13)						/* Get R0 (unclean) */
			lwz		r6,saver1(r13)						/* Get R1 (unclean) */
			lwz		r7,saver2(r13)						/* Get R2 (unclean) */
			stw		r5,CSAgpr+(0*4)(r4)					/* Save R0 */
			stw		r6,CSAgpr+(1*4)(r4)					/* Save R1 */
			stw		r7,CSAgpr+(2*4)(r4)					/* Save R2 */
			lwz		r5,saver3(r13)						/* Get R3 (unclean) */
			lwz		r6,saver4(r13)						/* Get R4 (unclean) */
			lwz		r7,saver5(r13)						/* Get R5 (unclean) */
			stw		r5,CSAgpr+(3*4)(r4)					/* Save R3 */
			stw		r6,CSAgpr+(4*4)(r4)					/* Save R4 */
			stw		r7,CSAgpr+(5*4)(r4)					/* Save R5 */
			lwz		r5,saver6(r13)						/* Get R6 (unclean) */
			lwz		r6,saver7(r13)						/* Get R7 (unclean) */
			lwz		r7,saver8(r13)						/* Get R8 (unclean) */
			stw		r5,CSAgpr+(6*4)(r4)					/* Save R6 */
			stw		r6,CSAgpr+(7*4)(r4)					/* Save R7 */
			stw		r7,CSAgpr+(8*4)(r4)					/* Save R8 */
			lwz		r5,saver9(r13)						/* Get R9 (unclean) */
			lwz		r6,saver10(r13)						/* Get R10 (unclean) */
			lwz		r7,saver11(r13)						/* Get R11 (unclean) */
			stw		r5,CSAgpr+(9*4)(r4)					/* Save R9 */
			stw		r6,CSAgpr+(10*4)(r4)				/* Save R10 */
			lwz		r5,saver12(r13)						/* Get R12 (unclean) */
			stw		r7,CSAgpr+(11*4)(r4)				/* Save R11 */
			stw		r5,CSAgpr+(12*4)(r4)				/* Save R12 */
			
			lwz		r5,saver13(r13)						/* Get R13 (unclean) */
			lwz		r6,saver14(r13)						/* Get R14 (unclean) */
			lwz		r7,saver15(r13)						/* Get R15 (unclean) */
			stw		r5,CSAgpr+(13*4)(r4)				/* Save R13 */
			stw		r6,CSAgpr+(14*4)(r4)				/* Save R14 */
			stw		r7,CSAgpr+(15*4)(r4)				/* Save R15 */
			lwz		r5,saver16(r13)						/* Get R16 (unclean) */
			lwz		r6,saver17(r13)						/* Get R17 (unclean) */
			lwz		r7,saver18(r13)						/* Get R18 (unclean) */
			stw		r5,CSAgpr+(16*4)(r4)				/* Save R16 */
			stw		r6,CSAgpr+(17*4)(r4)				/* Save R17 */
			stw		r7,CSAgpr+(18*4)(r4)				/* Save R18 */
			lwz		r5,saver19(r13)						/* Get R19 (unclean) */
			lwz		r6,saver20(r13)						/* Get R20 (unclean) */
			lwz		r7,saver21(r13)						/* Get R21 (unclean) */
			stw		r5,CSAgpr+(19*4)(r4)				/* Save R19 */
			stw		r6,CSAgpr+(20*4)(r4)				/* Save R20 */
			stw		r7,CSAgpr+(21*4)(r4)				/* Save R21 */
			lwz		r5,saver22(r13)						/* Get R22 (unclean) */
			lwz		r6,saver23(r13)						/* Get R23 (unclean) */
			lwz		r7,saver24(r13)						/* Get R24 (unclean) */
			stw		r5,CSAgpr+(22*4)(r4)				/* Save R22 */
			stw		r6,CSAgpr+(23*4)(r4)				/* Save R23*/
			stw		r7,CSAgpr+(24*4)(r4)				/* Save R24 */
			lwz		r5,saver25(r13)						/* Get R25 (unclean) */
			lwz		r6,saver26(r13)						/* Get R26 (unclean) */
			lwz		r7,saver27(r13)						/* Get R27 (unclean) */
			stw		r5,CSAgpr+(25*4)(r4)				/* Save R25 */
			stw		r6,CSAgpr+(26*4)(r4)				/* Save R26 */
			stw		r7,CSAgpr+(27*4)(r4)				/* Save R27 */

			lwz		r5,saver28(r13)						/* Get R28 (unclean) */
			lwz		r6,saver29(r13)						/* Get R29 (unclean) */
			lwz		r7,saver30(r13)						/* Get R30 (unclean) */
			stw		r5,CSAgpr+(28*4)(r4)				/* Save R28 */
			lwz		r5,saver31(r13)						/* Get R31(unclean) */
			stw		r6,CSAgpr+(29*4)(r4)				/* Save R29 */
			stw		r7,CSAgpr+(30*4)(r4)				/* Save R30 */
			stw		r5,CSAgpr+(31*4)(r4)				/* Save R31 */

StoreLiveStatus:
			mfmsr	r5									/* Get the current MSR */
			ori		r6,r5,0x2000						/* Turn on floating point instructions */
			mtmsr	r6									/* Turn them on */
			isync										/* Make sure they're on */
			
			stfd 	f0,CSAfpr+(0*8)(r4)					/* Save floating point registers */
			stfd	f1,CSAfpr+(1*8)(r4)					/* Save floating point registers */
			stfd	f2,CSAfpr+(2*8)(r4)					/* Save floating point registers */
			stfd	f3,CSAfpr+(3*8)(r4)					/* Save floating point registers */
			stfd	f4,CSAfpr+(4*8)(r4)					/* Save floating point registers */
			stfd	f5,CSAfpr+(5*8)(r4)					/* Save floating point registers */
			stfd	f6,CSAfpr+(6*8)(r4)					/* Save floating point registers */
			stfd	f7,CSAfpr+(7*8)(r4)					/* Save floating point registers */
			stfd	f8,CSAfpr+(8*8)(r4)					/* Save floating point registers */
			stfd	f9,CSAfpr+(9*8)(r4)					/* Save floating point registers */
			stfd	f10,CSAfpr+(10*8)(r4)				/* Save floating point registers */
			stfd	f11,CSAfpr+(11*8)(r4)				/* Save floating point registers */
			stfd	f12,CSAfpr+(12*8)(r4)				/* Save floating point registers */
			stfd	f13,CSAfpr+(13*8)(r4)				/* Save floating point registers */
			stfd	f14,CSAfpr+(14*8)(r4)				/* Save floating point registers */
			stfd	f15,CSAfpr+(15*8)(r4)				/* Save floating point registers */
			stfd	f16,CSAfpr+(16*8)(r4)				/* Save floating point registers */
			stfd	f17,CSAfpr+(17*8)(r4)				/* Save floating point registers */
			stfd	f18,CSAfpr+(18*8)(r4)				/* Save floating point registers */
			stfd	f19,CSAfpr+(19*8)(r4)				/* Save floating point registers */
			stfd	f20,CSAfpr+(20*8)(r4)				/* Save floating point registers */
			stfd	f21,CSAfpr+(21*8)(r4)				/* Save floating point registers */
			stfd	f22,CSAfpr+(22*8)(r4)				/* Save floating point registers */
			stfd	f23,CSAfpr+(23*8)(r4)				/* Save floating point registers */
			stfd	f24,CSAfpr+(24*8)(r4)				/* Save floating point registers */
			stfd	f25,CSAfpr+(25*8)(r4)				/* Save floating point registers */
			stfd	f26,CSAfpr+(26*8)(r4)				/* Save floating point registers */
			stfd	f27,CSAfpr+(27*8)(r4)				/* Save floating point registers */
			stfd	f28,CSAfpr+(28*8)(r4)				/* Save floating point registers */
			stfd	f29,CSAfpr+(29*8)(r4)				/* Save floating point registers */
			stfd	f30,CSAfpr+(30*8)(r4)				/* Save floating point registers */
			stfd	f31,CSAfpr+(31*8)(r4)				/* Save floating point registers */
			
			mffs	f1									/* Get the FPSCR */
			stfd	f1,CSAfpscr-4(r4)					/* Save the whole thing (we'll overlay the first half with CR later) */
			
			lfd		f1,CSAfpr+(1*4)(r4)					/* Restore F1 */
			
			mtmsr	r5									/* Put the floating point back to what it was before */
			isync										/* Wait for it */
			
			lwz		r6,savecr(r13)						/* Get the old CR (unclean) */
			stw		r6,CSAcr(r4)						/* Save the CR */
			
			mfxer	r6									/* Get the XER */
			stw		r6,CSAxer(r4)						/* Save the XER */
			
			lwz		r6,savelr(r13)						/* Get the old LR (unclean) */
			stw		r6,CSAlr(r4)						/* Save the LR */
			
			mfctr	r6									/* Get the CTR */
			stw		r6,CSActr(r4)						/* Save the CTR */
			
STtbase:	mftbu	r5									/* Get the upper timebase */
			mftb	r6									/* Get the lower */
			mftbu	r7									/* Get the top again */
			cmplw	cr0,r5,r7							/* Did it tick? */
			bne-	STtbase								/* Yeah, do it again... */
			
			mfdec	r7									/* Get the decrimenter (make it at about the same time as the TB) */
			stw		r7,CSAdec(r4)						/* Save the decrimenter */
			
			
			stw		r5,CSAtbu(r4)						/* Stash the top part */
			stw		r6,CSAtbl(r4)						/* Stash the lower part */
			
			lwz		r5,savesrr1(r13)					/* SRR1 at exception is as close as we get to the MSR (unclean) */
			lwz		r6,savesrr0(r13)					/* Get SRR0 also */
			stw		r5,CSAmsr(r4)						/* Save the MSR */
			stw		r6,CSApc(r4)						/* Save the PC */
			stw		r5,CSAsrr1(r4)						/* Set SRR1 also */
			stw		r6,CSAsrr0(r4)						/* Save SRR0 */
			
			mfpvr	r5									/* Get the PVR */
			stw		r5,CSApvr(r4)						/* Save the PVR */
			
			mfspr	r5,pir								/* Get the PIR */
			stw		r5,CSApir(r4)						/* Save the PIR */
			
			mfspr	r5,ibat0u							/* Get the upper IBAT0 */
			mfspr	r6,ibat0l							/* Get the lower IBAT0 */
			stw		r5,CSAibat+(0*8+0)(r4)				/* Save the upper IBAT0 */
			stw		r6,CSAibat+(0*8+4)(r4)				/* Save the upper IBAT0 */

			mfspr	r5,ibat1u							/* Get the upper IBAT1 */
			mfspr	r6,ibat1l							/* Get the lower IBAT1 */
			stw		r5,CSAibat+(1*8+0)(r4)				/* Save the upper IBAT1 */
			stw		r6,CSAibat+(1*8+4)(r4)				/* Save the upper IBAT1 */

			mfspr	r5,ibat2u							/* Get the upper IBAT2 */
			mfspr	r6,ibat2l							/* Get the lower IBAT2 */
			stw		r5,CSAibat+(2*8+0)(r4)				/* Save the upper IBAT2 */
			stw		r6,CSAibat+(2*8+4)(r4)				/* Save the upper IBAT2 */

			mfspr	r5,ibat3u							/* Get the upper IBAT3 */
			mfspr	r6,ibat3l							/* Get the lower IBAT3 */
			stw		r5,CSAibat+(3*8+0)(r4)				/* Save the upper IBAT3 */
			stw		r6,CSAibat+(3*8+4)(r4)				/* Save the upper IBAT3 */

			mfspr	r5,dbat0u							/* Get the upper DBAT0 */
			mfspr	r6,dbat0l							/* Get the lower DBAT0 */
			stw		r5,CSAdbat+(0*8+0)(r4)				/* Save the upper DBAT0 */
			stw		r6,CSAdbat+(0*8+4)(r4)				/* Save the upper DBAT0 */

			mfspr	r5,dbat1u							/* Get the upper DBAT1 */
			mfspr	r6,dbat1l							/* Get the lower DBAT1 */
			stw		r5,CSAdbat+(1*8+0)(r4)				/* Save the upper DBAT1 */
			stw		r6,CSAdbat+(1*8+4)(r4)				/* Save the upper DBAT1 */

			mfspr	r5,dbat2u							/* Get the upper DBAT2 */
			mfspr	r6,dbat2l							/* Get the lower DBAT2 */
			stw		r5,CSAdbat+(2*8+0)(r4)				/* Save the upper DBAT2 */
			stw		r6,CSAdbat+(2*8+4)(r4)				/* Save the upper DBAT2 */

			mfspr	r5,dbat3u							/* Get the upper DBAT3 */
			mfspr	r6,dbat3l							/* Get the lower DBAT3 */
			stw		r5,CSAdbat+(3*8+0)(r4)				/* Save the upper DBAT3 */
			stw		r6,CSAdbat+(3*8+4)(r4)				/* Save the upper DBAT3 */
			
			mfsdr1	r5									/* Get the SDR1 */
			stw		r5,CSAsdr1(r4)						/* Save the SDR1 */
			
			mfsr	r5,sr0								/* Get SR 0 */
			mfsr	r6,sr1								/* Get SR 1 */
			mfsr	r7,sr2								/* Get SR 2 */
			stw		r5,CSAsr+(0*4)(r4)					/* Save SR 0 */
			stw		r6,CSAsr+(1*4)(r4)					/* Save SR 1 */
			mfsr	r5,sr3								/* Get SR 3 */
			mfsr	r6,sr4								/* Get SR 4 */
			stw		r7,CSAsr+(2*4)(r4)					/* Save SR 2 */
			mfsr	r7,sr5								/* Get SR 5 */
			stw		r5,CSAsr+(3*4)(r4)					/* Save SR 3 */
			stw		r6,CSAsr+(4*4)(r4)					/* Save SR 4 */
			mfsr	r5,sr6								/* Get SR 6 */
			mfsr	r6,sr7								/* Get SR 7 */
			stw		r7,CSAsr+(5*4)(r4)					/* Save SR 5 */
			mfsr	r7,sr8								/* Get SR 8 */
			stw		r5,CSAsr+(6*4)(r4)					/* Save SR 6 */
			stw		r6,CSAsr+(7*4)(r4)					/* Save SR 7 */
			mfsr	r5,sr9								/* Get SR 9 */
			mfsr	r6,sr10								/* Get SR 11 */
			stw		r7,CSAsr+(8*4)(r4)					/* Save SR 8 */
			mfsr	r7,sr11								/* Get SR 11 */
			stw		r5,CSAsr+(9*4)(r4)					/* Save SR 9 */
			stw		r6,CSAsr+(10*4)(r4)					/* Save SR 10 */
			mfsr	r5,sr12								/* Get SR 12 */
			mfsr	r6,sr13								/* Get SR 13 */
			stw		r7,CSAsr+(11*4)(r4)					/* Save SR 11 */
			mfsr	r7,sr14								/* Get SR 14 */
			stw		r5,CSAsr+(12*4)(r4)					/* Save SR 12 */
			stw		r6,CSAsr+(13*4)(r4)					/* Save SR 13 */
			mfsr	r5,sr15								/* Get SR 15 */
			stw		r7,CSAsr+(14*4)(r4)					/* Save SR 14 */
			stw		r5,CSAsr+(15*4)(r4)					/* Save SR 15 */
			
			mfdar	r6									/* Get the DAR */
			stw		r6,CSAdar(r4)						/* Save it */
			
			mfdsisr	r5									/* Get the DSISR */
			stw		r5,CSAdsisr(r4)						/* Save it */
			
			stw		r10,CSAsprg+(1*4)(r4)				/* Save SPRG1 */
			mfspr	r7,sprg0							/* Get SPRG0 */
			mfspr	r6,sprg2							/* Get SPRG2 */
			stw		r7,CSAsprg+(0*4)(r4)				/* Save SPRG0 */
			mfspr	r5,sprg3							/* Get SPRG3 */
			stw		r6,CSAsprg+(2*4)(r4)				/* Save SPRG2 */
			stw		r5,CSAsprg+(3*4)(r4)				/* Save SPRG4 */
			
			mfspr	r6,1013								/* Get the DABR */
			mfspr	r7,1010								/* Get the IABR */
			stw		r6,CSAdabr(r4)						/* Save the DABR */
			stw		r7,CSAiabr(r4)						/* Save the IABR */
			
			mfspr	r5,282								/* Get the EAR */
			stw		r5,CSAear(r4)						/* Save the EAR */
			
			lis		r7,0xDEAD							/* Get 0xDEAD */
			ori		r7,r7,0xF1D0						/* Get 0xDEADF1D0 */
			
			mfpvr	r5									/* Get the processor type */
			rlwinm	r5,r5,16,16,31						/* Isolate the processor */
			cmplwi	cr1,r5,4							/* Set CR1_EQ if this is a plain 604, something else if it's a 604E */
			
			mfspr	r6,hid0								/* Get HID0 */
			mr		r5,r7								/* Assume 604 */
			beq		cr1,NoHID1							/* It is... */
			mfspr	r5,hid1								/* Get the HID1 */

NoHID1:		stw		r6,CSAhid+(0*4)(r4)					/* Save HID0 */
			stw		r5,CSAhid+(1*4)(r4)					/* Save HID1 */
			stw		r7,CSAhid+(2*4)(r4)					/* Save HID2 */
			stw		r7,CSAhid+(3*4)(r4)					/* Save HID3 */
			stw		r7,CSAhid+(4*4)(r4)					/* Save HID4 */
			stw		r7,CSAhid+(5*4)(r4)					/* Save HID5 */
			stw		r7,CSAhid+(6*4)(r4)					/* Save HID6 */
			stw		r7,CSAhid+(7*4)(r4)					/* Save HID7 */
			stw		r7,CSAhid+(8*4)(r4)					/* Save HID8 */
			stw		r7,CSAhid+(9*4)(r4)					/* Save HID9 */
			stw		r7,CSAhid+(10*4)(r4)				/* Save HID10 */
			stw		r7,CSAhid+(11*4)(r4)				/* Save HID11 */
			stw		r7,CSAhid+(12*4)(r4)				/* Save HID12 */
			stw		r7,CSAhid+(13*4)(r4)				/* Save HID13 */
			stw		r7,CSAhid+(14*4)(r4)				/* Save HID14 */
			stw		r7,CSAhid+(15*4)(r4)				/* Save HID15 */
			
			mfspr	r6,952								/* Get MMCR0 */
			mr		r5,r7								/* Assume 604 */
			beq		NoMMCR1								/* It is... */
			mfspr	r5,956								/* Get the MMCR1 */

NoMMCR1:	stw		r6,CSAmmcr+(0*4)(r4)				/* Save MMCR0 */
			stw		r5,CSAmmcr+(1*4)(r4)				/* Save MMCR1 */
			
			mfspr	r6,953								/* Get PMC1 */
			mfspr	r5,954								/* Get PMC2 */
			stw		r6,CSApmc+(0*4)(r4)					/* Save PMC1 */
			stw		r5,CSApmc+(1*4)(r4)					/* Save PMC2 */
			
			mr		r6,r7								/* Assume 604 */
			mr		r5,r7								/* Assume 604 */
			beq		NoPMC3								/* Yeah... */
			mfspr	r6,957								/* Get the PMC3 for a 604E */
			mfspr	r5,958								/* Get the PMC4 for a 604E */
			
NoPMC3:		stw		r6,CSApmc+(2*4)(r4)					/* Save PMC3 */
			stw		r5,CSApmc+(3*4)(r4)					/* Save PMC4 */

			mfspr	r6,955								/* Get SIA */
			mfspr	r5,959								/* Get SDA */
			stw		r6,CSAsia(r4)						/* Save the SIA */
			stw		r5,CSAsda(r4)						/* Save the SDA */
			
			stw		r7,CSAmq(r4)						/* There is no MQ on either the 604 or 604E */
			
			
			lwz		r6,MPPICStat(r9)					/* Get the status of this processor */
			lis		r10,MPPICReady>>16					/* Get the flag for reset or not */
			li		r5,kSIGPResetState					/* Assume we're operating */
			and.	r0,r6,r10							/* See if the ready bit is set */
			lis		r10,MPPICStop>>16					/* Get the flag for stopped or not */
			beq		SetStateInf							/* Go set that we are reset... */
			and.	r0,r6,r10							/* Are we stopped? */
			li		r5,kSIGPStoppedState				/* Assume we area */
			bne		SetStateInf							/* We are, go set it... */
			li		r5,kSIGPOperatingState				/* Not stopped, so we're going */
			
SetStateInf: stb		r5,CSAstate(r4)					/* Set the state byte */
			
			li		r0,1								/* Set the truth */
			sync										/* Make sure it's stored */
			
			stb		r0,CSAregsAreValid(r4)				/* Set that the status is valid */

			blr											/* We're done here... */
			

/******************************************************************************************************** */
/* */
/*			The synchronize time base function.  No state requirements for this one. */
/* */
/******************************************************************************************************** */

ITBsync:												/* This handles the synchronize time base function */
			lis		r12,HIGH_ADDR(MPPIwork)				/* Get the top of work area */
			li		r0,MPPICfTBsy1						/* Get the flag for TB sync state 1 */
			li		r7,0								/* Get a 0 */
			ori		r12,r12,LOW_ADDR(MPPIwork)			/* Get low part of work area */
			mttbl	r7									/* Clear the bottom of the TB so's there's noupper ticks */
			mttbu	r7									/* Clear the top part, just 'cause I wanna */
			
			sync										/* Make sure all is saved */
			stb		r0,MPPICStat+2(r9)					/* Tell the main dude to tell us the time */
			isync										/* Make sure we don't go nowhere's */

/* */
/*			Remember that the sync'ing processor insures that the TB won't tick the high part for at least */
/*			16k ticks.  That should be way longer than we need for the whole process here */
/* */

WaitTBLower: lwz	r5,MPPITBsync+4-MPPIwork(r12)		/* Get the lower part of the TB */
			mttbl	r5									/* Put it in just in case it's set now */
			mr.		r5,r5								/* Was it actually? */
			beq+	WaitTBLower							/* Nope, go check again... */
			lwz		r4,MPPITBsync-MPPIwork(r12)			/* Get the high order part */
			mttbu	r4									/* Set the top half also */

			stw		r7,MPPITBsync+4-MPPIwork(r12)		/* Tell 'em we've got it */
			
			sync
			
			li		r4,0								/* Clear this */
			la		r5,MPPISncFght-32-MPPIwork(r12)		/* Point to the squared circle (our corner) */

			b		TB1stPnch							/* Go take the first punch... */

TBSargue:	
			dcbf	0,r5								/* *** Fix cache coherency (data integrity) HW bug *** */
			sync										/* *** Fix cache coherency (data integrity) HW bug *** */
			lwz		r6,0(r5)							/* Listen for the procecution's argument */
			mr.		r6,r6								/* See if they are done */
			beq+	TBSargue							/* Nope, still going... */
			
TB1stPnch:	mftb	r7									/* They're done, time for rebuttal */
			stw		r7,32(r5)							/* Make rebuttle */
	
			addi	r4,r4,1								/* Count rounds */

			cmplwi	cr0,r4,10							/* See if we've gone 9 more rounds */
			addi	r5,r5,64							/* Point to the next round areas */
		
			blt+	TBSargue							/* Not yet, come out of your corners fighting... */
			
/* */
/*			We'll set the latest-up-to-datest from the other processor now */
/* */
TBSetTB:		
			dcbf	0,r5								/* *** Fix cache coherency (data integrity) HW bug *** */
			sync										/* *** Fix cache coherency (data integrity) HW bug *** */
			lwz		r6,0(r5)							/* Listen for the procecution's argument */
			mttbl	r6									/* Set it just in case it's ok */
			mr.		r6,r6								/* See if they are done */
			beq+	TBSetTB								/* Nope, still going... */

/* */
/*			Get average duration for each processor.  We skip the first pass on the asumption */
/*			that the caches were not warmed up and it would take longer.  In proctice this */
/*			is what was seen. */
/* */

			mr		r0,r11								/* Move return address to a safe register */

			li		r4,0								/* Clear a counter */
			li		r3,0								/* Clear accumulator for duration */
			li		r10,0								/* Clear start time accumulator top half */
			li		r11,0								/* Clear start time accumulator bottom half */
			li		r1,0								/* Clear start time accumulator top half */
			li		r2,0								/* Clear start time accumulator bottom half */
			li		r10,0								/* Clear accumulator for durations */
			la		r5,MPPISncFght+64-MPPIwork(r12)		/* Get second round start time address */
		
TBSaccumU:	lwz		r6,0(r5)							/* Get start time */
			lwz		r11,32(r5)							/* Get the other processor's start time */
			lwz		r7,64(r5)							/* Get end time */
			lwz		r8,96(r5)							/* Other proc's end time */
			sub		r7,r7,r6							/* Get duration */
			sub		r8,r8,r11							/* Get other side's duration */
			addi	r4,r4,1								/* Count arguments */
			add		r3,r3,r7							/* Accumulate durations */
			add		r2,r2,r7							/* Accumulate other side's durations */
			cmplwi	cr0,r4,8							/* Have we gotten them all yet? */
			addi	r5,r5,64							/* Step to the next argument */
			blt+	TBSaccumU							/* We're not done yet... */

			add		r7,r2,r3							/* Sum the two differences */
			addi	r7,r7,0x10							/* Round up */
			rlwinm	r7,r7,27,5,31						/* Get the average difference divided in half */

			mftb	r8									/* Get the time now */
			add		r8,r8,r7							/* Slide the window */
			mttbl	r8									/* Set the time */
			
			stw		r12,MPPITBsync+4-MPPIwork(r12)		/* Show that we are done */
			
			lwz		r3,MPPICStat(r9)					/* Get back our status */
			mr		r11,r0								/* Restore the return register */
			b		KillBusy							/* We're all done now, done for it, c'est la vie... */
			

/******************************************************************************************************** */
/* */
/*			The reset function.  No state requirements for this one. */
/*			This suicides the processor. Our caller is never returned to (good english).  The only way out of  */
/*			this is a start function subsequently.  So, we give a flying f**k about the registers 'n' sutff. */
/* */
/******************************************************************************************************** */

IReset:		lis		r28,0x8000							/* Turn on machine checks */
			
			ori		r28,r28,0xCC84						/* Enable caches, clear them,  */
														/* disable serial execution and turn BHT on */
			sync
			mtspr	HID0,r28							/* Start the cache clear */
			sync

/* */
/*			Clear out the TLB.  They be garbage after hard reset. */
/* */

			li		r0,512								/* Get number of TLB entries (FIX THIS) */
			li		r3,0								/* Start at 0 */
			mtctr	r0									/* Set the CTR */
			
IRpurgeTLB:	tlbie	r3									/* Purge this entry */
			addi	r3,r3,4096							/* Next page */
			bdnz	IRpurgeTLB							/* Do 'em all... */
			
			sync										/* Make sure all TLB purges are done */
			tlbsync										/* Make sure on other processors also */
			sync										/* Make sure the TLBSYNC is done */

/* */
/*			Clear out the BATs. */
/* */

			li		r3,0								/* Clear a register */
			
			mtspr	DBAT0L,r3							/* Clear BAT */
			mtspr	DBAT0U,r3							/* Clear BAT */
			mtspr	DBAT1L,r3							/* Clear BAT */
			mtspr	DBAT1U,r3							/* Clear BAT */
			mtspr	DBAT2L,r3							/* Clear BAT */
			mtspr	DBAT2U,r3							/* Clear BAT */
			mtspr	DBAT3L,r3							/* Clear BAT */
			mtspr	DBAT3U,r3							/* Clear BAT */
			
			mtspr	IBAT0L,r3							/* Clear BAT */
			mtspr	IBAT0U,r3							/* Clear BAT */
			mtspr	IBAT1L,r3							/* Clear BAT */
			mtspr	IBAT1U,r3							/* Clear BAT */
			mtspr	IBAT2L,r3							/* Clear BAT */
			mtspr	IBAT2U,r3							/* Clear BAT */
			mtspr	IBAT3L,r3							/* Clear BAT */
			mtspr	IBAT3U,r3							/* Clear BAT */

/* */
/*			Map 0xF0000000 to 0xFFFFFFFF for I/O; make it R/W non-cacheable */
/*			Map	0x00000000 to 0x0FFFFFFF for mainstore; make it R/W cachable */
/* */

			lis		r6,0xF000							/* Set RPN to last segment */
			ori		r6,r6,0x1FFF						/* Set up upper BAT for 256M, access both */
			
			lis		r7,0xF000							/* Set RPN to last segment */
			ori		r7,r7,0x0032						/* Set up lower BAT for 256M, access both, non-cachable */
		
			mtspr	DBAT0L,r7							/* Setup ROM and I/O mapped areas */
			mtspr	DBAT0U,r6							/* Now do the upper DBAT */
			sync
	
			li		r6,0x1FFF							/* Set up upper BAT for 256M, access both */
			li		r7,0x0012							/* Set up lower BAT for r/w access */
			
			mtspr	DBAT1L,r7							/* Set up an initial view of mainstore */
			mtspr	DBAT1U,r6							/* Now do the upper DBAT */
			sync

/* */
/*			Clean up SDR and segment registers */
/* */

			li		r3,0								/* Clear a register */
			mtspr	SDR1,r3								/* Clear SDR1 */
			
			li		r4,0								/* Clear index for segment registers */
			lis		r5,0x1000							/* Set the segment indexer */
			
IRclearSR:	mtsrin	r3,r4								/* Zero out the SR */
			add.	r4,r4,r5							/* Point to the next segment */
			bne-	IRclearSR							/* Keep going until we wrap back to 0 */
			
			lis		r3,(MPPICOnline+MPPICStop)>>16		/* Set the reset/online state flags */
			b		KillBusy							/* Go wipe out the busy flags... */

/*	(TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG)  */
/* */
/*			Here lies the Phoney Firmware used to test SIGPs.  Take this out later. */
/* */
/*	(TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG)  */

mp_PhoneyFirmware:

			li		r27,0x3040							/* Set floating point and machine checks on, IP to 0xFFF0xxxx */
			mtmsr	r27									/* Load 'em on in */
			isync
			
			bl		PhoneyBase							/* Make a base register */
PhoneyBase:	mflr	r26									/* Get it */
			addi	r26,r26,LOW_ADDR(MPPIbase-PhoneyBase)	/* Adjust it back */

			la		r20,LOW_ADDR(rupttab-MPPIbase)(r26)		/* Get the address of the interrupt table */
			la		r21,LOW_ADDR(rupttabend-MPPIbase)(r26)	/* Get the end of the table */
			
relocate:	lwz		r22,0(r20)							/* Get the displacement to routine */
			add		r22,r22,r12							/* Relocate to the physical address */
			stw		r22,0(r20)							/* Stick it back */
			addi	r20,r20,4							/* Point to the next one */
			cmplw	cr0,r20,r21							/* Still in table? */
			ble+	cr0,relocate						/* Yeah... */
			
			la		r20,LOW_ADDR(rupttab-MPPIbase)(r26)	/* Get the interrupt table back again */
			mtsprg	3,r20								/* Activate the phoney Rupt table */
			
			lis		r24,hi16(HammerHead)				/* Get the actual hammerhead address */
			ori		r24,r24,0x0032						/* Make R/W non-cachable */
			lwz		r23,MPPIHammer-MPPIwork(r12)		/* Get the address mapped on the main processor */
			ori		r23,r23,0x0003						/* Set both super and user valid for 128KB */
			
			mtspr	DBAT0L,r24							/* Setup hammerhead's real address */
			mtspr	DBAT0U,r23							/* Map hammerhead to the same virtual address as on the main processor */
			sync										/* Make sure it is done */

			la		r25,MPPICPU2-MPPIwork(r12)			/* Point to a phoney register save area */
			mtsprg	1,r25								/* Phoney up initialized processor state */

			lis		r24,0xFEED							/* Get 0xFEED */
			ori		r24,r24,0xF1D0						/* Get 0xFEEDF1D0 */
			
			stw		r24,CSAgpr+(0*4)(r25)				/* Store invalid R0 */
			stw		r24,CSAgpr+(1*4)(r25)				/* Store invalid R1 */
			stw		r24,CSAgpr+(2*4)(r25)				/* Store invalid R2 */
			stw		r24,CSAgpr+(3*4)(r25)				/* Store invalid R3 */
			stw		r24,CSAgpr+(4*4)(r25)				/* Store invalid r4 */
			stw		r24,CSAgpr+(5*4)(r25)				/* Store invalid R5 */
			stw		r24,CSAgpr+(6*4)(r25)				/* Store invalid R6 */
			stw		r24,CSAgpr+(7*4)(r25)				/* Store invalid r7 */
			stw		r24,CSAgpr+(8*4)(r25)				/* Store invalid R8 */
			stw		r24,CSAgpr+(9*4)(r25)				/* Store invalid R9 */
			stw		r24,CSAgpr+(10*4)(r25)				/* Store invalid R10 */
			stw		r24,CSAgpr+(11*4)(r25)				/* Store invalid R11 */
			stw		r24,CSAgpr+(12*4)(r25)				/* Store invalid R12 */
			
waititout:	lwz		r25,0x30(br0)						/* Get wait count */
			mfmsr	r24									/* Get the MSR */
			addi	r25,r25,1							/* Bounce it up */
			ori		r24,r24,0x8000						/* Turn on external interruptions */
			stw		r25,0x30(br0)						/* Save back the count */
			mtmsr	r24									/* Set it */
			isync										/* Stop until we're here */
			b		waititout							/* Loop forever... */
			
/* */
/*			Phoney interrupt handlers */
/* */

pexternal:	mflr	r29									/* Get the LR value */
			lwz		r29,0(r29)							/* Get the rupt code */
			stw		r29,0x0B0(br0)						/* Save the code */
			bl		GotSignal							/* Call the signal handler */
			oris	r3,r3,0x8000						/* Turn on high bit so we see a code 0 */
			stw		r3,0xA8(br0)						/* Save return code in debug area */
			
ignorerupt:	mflr	r29									/* Get the LR value */
			lwz		r29,0(r29)							/* Get the rupt code */
			stw		r29,0x0B0(br0)						/* Save the code */
			rfi											/* Bail to from whence we commest... */
			.long	0			
			.long	0			
			.long	0			
			.long	0			
			.long	0			
			.long	0			
			.long	0			

rupttab:	.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	pexternal							/* Phoney external handler */
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
			.long	ignorerupt
rupttabend:	.long	ignorerupt

/*	(TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG)  */
/* */
/*			Here lies the end of the Phoney Firmware used to test SIGPs.  Take this out later. */
/* */
/*	(TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG) (TEST/DEBUG)  */


/* */
/*			Table of function offsets */
/* */

MPPIFuncOffs:

			.long	CountProcessors-MPPIFunctions					/* Offset to routine */
			.long	StartProcessor-MPPIFunctions					/* Offset to routine */
			.long	ResumeProcessor-MPPIFunctions					/* Offset to routine */
			.long	StopProcessor-MPPIFunctions						/* Offset to routine */
			.long	ResetProcessor-MPPIFunctions					/* Offset to routine */
			.long	SignalProcessor-MPPIFunctions					/* Offset to routine */
			.long	StoreProcessorStatus-MPPIFunctions				/* Offset to routine */
			.long	SynchClock-MPPIFunctions						/* Offset to routine */
			.long	GetExtHandlerAddress-MPPIFunctions				/* Offset to routine */
			.long	GotSignal-MPPIFunctions							/* Offset to routine */
			.long	ProcessorState-MPPIFunctions					/* Offset to routine */
			.long	RunSIGPRun-MPPIFunctions						/* Offset to routine */
			.long	mp_PhoneyFirmware-MPPIFunctions					/* (TEST/DEBUG) */

MPPISize:
	
