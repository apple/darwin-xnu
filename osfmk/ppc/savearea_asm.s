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
#include <assym.s>
#include <debug.h>
#include <cpus.h>
#include <db_machine_commands.h>
#include <mach_rt.h>
	
#include <mach_debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/Performance.h>
#include <ppc/exception.h>
#include <ppc/pmap_internals.h>
#include <mach/ppc/vm_param.h>
	
			.text

/*
 *			This routine will add a savearea block to the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			Note that the savearea list should NEVER be empty
 */

ENTRY(save_queue,TAG_NO_FRAME_USED)


			mfsprg	r9,2						; Get the feature flags
			mr		r11,r3						; Save the block
			mtcrf	0x04,r9						; Set the features			
			mfmsr	r12							; Get the MSR
			lis		r10,HIGH_ADDR(EXT(saveanchor))	; Get the high part of the anchor
			andi.	r3,r12,0x7FCF				; Turn off all translation and rupts
			ori		r10,r10,LOW_ADDR(EXT(saveanchor))	; Bottom half of the anchor 

			bt		pfNoMSRirb,sqNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		sqNoMSRx
			
sqNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
sqNoMSRx:
			
#if 0
			rlwinm.	r3,r11,0,0,19				/* (TEST/DEBUG) */
			bne+	notraceit					/* (TEST/DEBUG) */
			BREAKPOINT_TRAP						/* (TEST/DEBUG) */
notraceit:										/* (TEST/DEBUG) */
#else
			rlwinm	r3,r11,0,0,19				/* Make sure it's clean and tidy */
#endif

sqlck:		lwarx	r9,0,r10					/* Grab the lock value */
			li		r8,1						/* Use part of the delay time */
			mr.		r9,r9						/* Is it locked? */
			bne-	sqlcks						/* Yeah, wait for it to clear... */
			stwcx.	r8,0,r10					/* Try to seize that there durn lock */
			beq+	sqlckd						/* Got it... */
			b		sqlck						/* Collision, try again... */
			
sqlcks:		lwz		r9,SVlock(r10)				/* Get that lock in here */
			mr.		r9,r9						/* Is it free yet? */
			beq+	sqlck						/* Yeah, try for it again... */
			b		sqlcks						/* Sniff away... */
			
sqlckd:		isync								/* Make sure translation is off */
			lwz		r7,SVfree(r10)				/* Get the free save area list anchor */
			lwz		r6,SVcount(r10)				/* Get the total count of saveareas */
			stw		r3,SVfree(r10)				/* Queue in the new one */
			addi	r6,r6,sac_cnt				/* Count the ones we are linking in */
			stw		r7,SACnext(r3)				/* Queue the old first one off of us */
			li		r8,0						/* Get a free lock value */
			stw		r6,SVcount(r10)				/* Save the new count */
			
			sync								/* Make sure everything is done */
			stw		r8,SVlock(r10)				/* Unlock the savearea chain */
			
			mtmsr	r12							/* Restore interrupts and translation */
			isync								/* Dump any speculations */

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			li		r2,0x2201					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif

			blr									/* Leave... */


/*
 *			This routine will find and remove an empty savearea block from the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			We pass back the virtual address of the one we just released
 *			or a zero if none to free.
 *
 *			Note that the savearea list should NEVER be empty
 */

ENTRY(save_dequeue,TAG_NO_FRAME_USED)


			mfsprg	r9,2						; Get the feature flags
			mfmsr	r12							/* Get the MSR */
			mtcrf	0x04,r9						; Set the features			
			lis		r10,HIGH_ADDR(EXT(saveanchor))	/* Get the high part of the anchor */
			andi.	r3,r12,0x7FCF				/* Turn off all translation and 'rupts */
			ori		r10,r10,LOW_ADDR(EXT(saveanchor))	/* Bottom half of the anchor */

			bt		pfNoMSRirb,sdNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		sdNoMSRx
			
sdNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
sdNoMSRx:

sdqlck:		lwarx	r9,0,r10					/* Grab the lock value */
			li		r8,1						/* Use part of the delay time */
			mr.		r9,r9						/* Is it locked? */
			bne-	sdqlcks						/* Yeah, wait for it to clear... */
			stwcx.	r8,0,r10					/* Try to seize that there durn lock */
			beq+	sdqlckd						/* Got it... */
			b		sdqlck						/* Collision, try again... */
			
sdqlcks:	lwz		r9,SVlock(r10)				/* Get that lock in here */
			mr.		r9,r9						/* Is it free yet? */
			beq+	sdqlck						/* Yeah, try for it again... */
			b		sdqlcks						/* Sniff away... */
			

sdqlckd:	isync								; Clean out the prefetches
			lwz		r3,SVfree(r10)				/* Get the free save area list anchor */
			la		r5,SVfree(r10)				/* Remember that the we're just starting out */
			lwz		r6,SVcount(r10)				/* Get the total count of saveareas for later */
			lis		r8,sac_empty>>16			/* Get the empty block indication */
			
sdqchk:		lwz		r4,SACalloc(r3)				/* Get the allocation flags */
			lwz		r9,SACflags(r3)				/* Get the flags */
			lwz		r7,SACnext(r3)				/* Point on to the next one */
			andis.	r9,r9,hi16(sac_perm)		/* Is this permanently allocated? */
			cmplw	cr1,r4,r8					/* Does this look empty? */
			bne-	sdqperm						/* It's permanent, can't release... */
			beq-	cr1,sdqfnd					/* Yeah, empty... */

sdqperm:	la		r5,SACnext(r3)				/* Remember the last guy */
			mr.		r3,r7						/* Any more left? */
			bne+	sdqchk						/* Yeah... */
			b		sdqunlk						/* Nope, just go unlock and leave... */
			
sdqfnd:		subi	r6,r6,sac_cnt				/* Back off the number of saveareas in here */
			stw		r7,0(r5)					/* Dequeue our guy */
			lwz		r9,SACvrswap(r3)			/* Get addressing conversion */
			stw		r6,SVcount(r10)				/* Back off the count for this block */
			xor		r3,r3,r9					/* Flip to virtual addressing */

sdqunlk:	li		r8,0						/* Get a free lock value */			
			sync								/* Make sure everything is done */
			stw		r8,SVlock(r10)				/* Unlock the savearea chain */
			
			mtmsr	r12							/* Restore interrupts and translation */
			isync								/* Dump any speculations */

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			li		r2,0x2202					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif

			blr									/* Leave... */



/*
 *			This routine will obtain a savearea from the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			We pass back the virtual address of the one we just obtained
 *			or a zero if none to allocate.
 *
 *			Note that the savearea list should NEVER be empty
 *			NOTE!!! NEVER USE R0, R2, or R12 IN HERE THAT WAY WE DON'T NEED A
 *			STACK FRAME IN FPU_SAVE, FPU_SWITCH, VEC_SAVE, OR VEC_SWITCH.
 */

ENTRY(save_get_phys,TAG_NO_FRAME_USED)
			
			cmplw	cr1,r1,r1					; Set CR1_eq to indicate we want physical address
			b		csaveget					; Join the common...

ENTRY(save_get,TAG_NO_FRAME_USED)
			
			cmplwi	cr1,r1,0					; Set CR1_ne to indicate we want virtual address

csaveget:	mfsprg	r9,2						; Get the feature flags
			mfmsr	r11							; Get the MSR 
			mtcrf	0x04,r9						; Set the features			
			lis		r10,HIGH_ADDR(EXT(saveanchor))	/* Get the high part of the anchor */
			andi.	r3,r11,0x7FCF				/* Turn off all translation and 'rupts */
			ori		r10,r10,LOW_ADDR(EXT(saveanchor))	/* Bottom half of the anchor */

			bt		pfNoMSRirb,sgNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		sgNoMSRx
			
sgNoMSR:	mr		r9,r0						; Save this
			li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
			mr		r0,r9						; Restore it

sgNoMSRx:

sglck:		lwarx	r9,0,r10					/* Grab the lock value */
			li		r7,1						/* Use part of the delay time */
			mr.		r9,r9						/* Is it locked? */
			bne-	sglcks						/* Yeah, wait for it to clear... */
			stwcx.	r7,0,r10					/* Try to seize that there durn lock */
			beq+	sglckd						/* Got it... */
			b		sglck						/* Collision, try again... */
			
sglcks:		lwz		r9,SVlock(r10)				/* Get that lock in here */
			mr.		r9,r9						/* Is it free yet? */
			beq+	sglck						/* Yeah, try for it again... */
			b		sglcks						/* Sniff away... */
			
sglckd:		isync								/* Make sure translation is off */
			lwz		r8,SVfree(r10)				/* Get the head of the save area list */
			lwz		r9,SVinuse(r10)				/* Get the inuse field */

			lwz		r7,SACalloc(r8)				/* Pick up the allocation bits */
			lwz		r5,SACvrswap(r8)			/* Get real to virtual translation */
			mr.		r7,r7						/* Can we use the first one? */
			blt		use1st						/* Yeah... */
			
			andis.	r7,r7,0x8000				/* Show we used the second and remember if it was the last */
			addi	r3,r8,0x0800				/* Point to the first one */
			b		gotsave						/* We have the area now... */

use1st:		andis.	r7,r7,0x4000				/* Mark first gone and remember if empty */
			mr		r3,r8						/* Set the save area */
			
gotsave:	stw		r7,SACalloc(r8)				/* Put back the allocation bits */
			bne		nodqsave					/* There's still an empty slot, don't dequeue... */

			lwz		r4,SACnext(r8)				/* Get the next in line */
			stw		r4,SVfree(r10)				/* Dequeue our now empty save area block */
			
nodqsave:	lis		r6,HIGH_ADDR(SAVattach)		/* Show that it is attached for now */
			li		r4,0						/* Clear this for the lock */
			stw		r6,SAVflags(r3)				/* Set the flags to attached */
			addi	r9,r9,1						/* Bump up the inuse count */
			stw		r4,SAVprev(r3)				/* Make sure that backchain is clear */
			stw		r9,SVinuse(r10)				/* Set the inuse field */
			sync								/* Make sure all stores are done */
			stw		r4,SVlock(r10)				/* Unlock both save and trace areas */
			mtmsr	r11							/* Restore translation and exceptions */
			isync								/* Make sure about it */
	
#if 0
			mr		r11,r0						/* (TEST/DEBUG) */
			mr		r7,r2						/* (TEST/DEBUG) */
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			li		r2,0x2203					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
			mr		r0,r11						/* (TEST/DEBUG) */
			mr		r2,r7						/* (TEST/DEBUG) */
#endif			
			
			li		r7,0						; NOTE WELL: we set R7 to zero for vector and float saving code in cswtch.s
			beqlr-	cr1							; Return now if we want the physical address
			xor		r3,r3,r5					/* Get the virtual address */
			blr									/* Leave... */
		

/*
 *			This routine will return a savearea to the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			We take a virtual address.
 *
 */

ENTRY(save_ret,TAG_NO_FRAME_USED)

#if 0
			cmplwi	r3,0x1000					; (TEST/DEBUG)
			bgt+	notpage0					; (TEST/DEBUG)
			BREAKPOINT_TRAP						/* (TEST/DEBUG) */

notpage0:	rlwinm	r6,r3,0,0,19				/* (TEST/DEBUG) */
			rlwinm	r7,r3,21,31,31				/* (TEST/DEBUG) */
			lis		r8,0x8000					/* (TEST/DEBUG) */
			lwz		r6,SACalloc(r6)				/* (TEST/DEBUG) */
			srw		r8,r8,r7					/* (TEST/DEBUG) */
			and.	r8,r8,r6					/* (TEST/DEBUG) */
			beq+	nodoublefret				/* (TEST/DEBUG) */
			BREAKPOINT_TRAP						/* (TEST/DEBUG) */
			
nodoublefret:									/* (TEST/DEBUG) */		
#endif

			mfsprg	r9,2						; Get the feature flags
			lwz		r7,SAVflags(r3)				/* Get the flags */
			rlwinm	r6,r3,0,0,19				/* Round back down to the savearea page block */
			andis.	r7,r7,HIGH_ADDR(SAVinuse)	/* Still in use? */
			mfmsr	r12							/* Get the MSR */
			bnelr-								/* Still in use, just leave... */
			lwz		r5,SACvrswap(r6)			/* Get the conversion to real */
			mr		r8,r3						; Save the savearea address
			mtcrf	0x04,r9						; Set the features			
			lis		r10,HIGH_ADDR(EXT(saveanchor))	/* Get the high part of the anchor */
			andi.	r3,r12,0x7FCF				/* Turn off all translation and 'rupts */
			ori		r10,r10,LOW_ADDR(EXT(saveanchor))	/* Bottom half of the anchor */

			bt		pfNoMSRirb,srNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		srNoMSRx
			
srNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
srNoMSRx:

			mfsprg	r11,1						/* Get the active save area */
			xor		r3,r8,r5					/* Get the real address of the savearea */
			cmplw	r11,r3						/* Are we trying to toss the active one? */
			xor		r6,r6,r5					/* Make the savearea block real also */
			beq-	srbigtimepanic				/* This is a no-no... */

			rlwinm	r7,r3,21,31,31				/* Get position of savearea in block */
			lis		r8,0x8000					/* Build a bit mask and assume first savearea */
			srw		r8,r8,r7					/* Get bit position of do deallocate */
			
srlck:		lwarx	r11,0,r10					/* Grab the lock value */
			li		r7,1						/* Use part of the delay time */
			mr.		r11,r11						/* Is it locked? */
			bne-	srlcks						/* Yeah, wait for it to clear... */
			stwcx.	r7,0,r10					/* Try to seize that there durn lock */
			beq+	srlckd						/* Got it... */
			b		srlck						/* Collision, try again... */
			
srlcks:		lwz		r11,SVlock(r10)				/* Get that lock in here */
			mr.		r11,r11						/* Is it free yet? */
			beq+	srlck						/* Yeah, try for it again... */
			b		srlcks						/* Sniff away... */
					
srlckd:		isync								/* Toss preexecutions */
			lwz		r11,SACalloc(r6)			/* Get the allocation for this block */
			lwz		r7,SVinuse(r10)				/* Get the in use count */
			or		r11,r11,r8					/* Turn on our bit */
			subi	r7,r7,1						/* We released one, adjust count */
			cmplw	r11,r8						/* Is our's the only one free? */
			stw		r7,SVinuse(r10)				/* Save out count */
			stw		r11,SACalloc(r6)			/* Save it out */
			bne+	srtrest						/* Nope, then the block is already on the free list */

			lwz		r11,SVfree(r10)				/* Get the old head of the free list */
			stw		r6,SVfree(r10)				/* Point the head at us now */
			stw		r11,SACnext(r6)				/* Point us at the old last */
		
srtrest:	li		r8,0						/* Get set to clear the savearea lock */
			sync								/* Make sure it's all out there */
			stw		r8,SVlock(r10)				/* Unlock it */
			mtmsr	r12							/* Restore interruptions and translation */
			isync

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			li		r2,0x2204					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif

			blr									/* Go away... */

srbigtimepanic:
			lis		r6,HIGH_ADDR(EXT(panic))	/* First half of panic call */
			lis		r3,HIGH_ADDR(EXT(srfreeactive))	/* First half of panic string */
			ori		r6,r6,LOW_ADDR(EXT(panic))	/* Second half of panic call */
			ori		r3,r3,LOW_ADDR(EXT(srfreeactive))	/* Second half of panic string */
			mtlr	r6							/* Get the address of the panic routine */
			mtmsr	r12							/* Restore interruptions and translation */
			isync
			blrl								/* Panic... */

			.data
EXT(srfreeactive):
			STRINGD	"save_ret: Attempting to release the active savearea!!!!\000"
			.text


/*
 *			struct savearea	*save_cpv(struct savearea *);	 Converts a physical savearea address to virtual
 */

			.align	5
			.globl	EXT(save_cpv)

LEXT(save_cpv)
			
			mfmsr	r10							; Get the current MSR
			rlwinm	r4,r3,0,0,19				; Round back to the start of the physical savearea block
			andi.	r9,r10,0x7FEF				; Turn off interrupts and data translation
			mtmsr	r9							; Disable DR and EE
			isync
			
			lwz		r4,SACvrswap(r4)			; Get the conversion to virtual
			mtmsr	r10							; Interrupts and DR back on
			isync
			xor		r3,r3,r4					; Convert to physical
			blr


/*
 *			This routine will return the virtual address of the first free savearea
 *			block and disable for interruptions.
 *			Note really well: this is only for debugging, don't expect it to always work!
 *
 *			We take a virtual address in R3 to save the original MSR, and 
 *			return the virtual address.
 *
 */

ENTRY(save_deb,TAG_NO_FRAME_USED)

			mfsprg	r9,2						; Get the feature flags
			mfmsr	r12							/* Get the MSR */
			lis		r10,HIGH_ADDR(EXT(saveanchor))	/* Get the high part of the anchor */
			mtcrf	0x04,r9						; Set the features			
			stw		r12,0(r3)					/* Save it */
			andi.	r3,r12,0x7FCF				/* Turn off all translation and 'rupts */
			ori		r10,r10,LOW_ADDR(EXT(saveanchor))	/* Bottom half of the anchor */

			bt		pfNoMSRirb,sdbNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		sdbNoMSRx
			
sdbNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
sdbNoMSRx:

			lwz		r3,SVfree(r10)				/* Get the physical first in list */
			andi.	r11,r12,0x7FFF				/* Clear only interruption */
			lwz		r5,SACvrswap(r3)			/* Get the conversion to virtual */
			mtmsr	r11							/* Restore DAT but not INT */
			xor		r3,r3,r5					/* Make it virtual */
			isync
			blr
			
			
			


