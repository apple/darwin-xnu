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
#define PERFTIMES 0
	
			.text

/*
 *
 *			Random notes and musings...
 *
 *			Access to mappings via the PTEG hash must be done with the list locked.
 *			Access via the physical entries is controlled by the physent lock.
 *			Access to mappings is controlled by the PTEG lock once they are queued.
 *			If they are not on the list, they don't really exist, so
 *			only one processor at a time can find them, so no access control is needed. 
 *
 *			The second half of the PTE is kept in the physical entry.  It is done this
 *			way, because there may be multiple mappings that refer to the same physical
 *			page (i.e., address aliases or synonymns).  We must do it this way, because
 *			maintenance of the reference and change bits becomes nightmarish if each mapping
 *			has its own. One side effect of this, and not necessarily a bad one, is that
 *			all mappings for a single page can have a single WIMG, protection state, and RC bits.
 *			The only "bad" thing, is the reference bit.  With a single copy, we can not get
 *			a completely accurate working set calculation, i.e., we can't tell which mapping was
 *			used to reference the page, all we can tell is that the physical page was 
 *			referenced.
 *
 *			The master copys of the reference and change bits are kept in the phys_entry.
 *			Other than the reference and change bits, changes to the phys_entry are not
 *			allowed if it has any mappings.  The master reference and change bits must be
 *			changed via atomic update.
 *
 *			Invalidating a PTE merges the RC bits into the phys_entry.
 *
 *			Before checking the reference and/or bits, ALL mappings to the physical page are
 *			invalidated.
 *			
 *			PTEs are never explicitly validated, they are always faulted in.  They are also
 *			not visible outside of the hw_vm modules.  Complete seperation of church and state.
 *
 *			Removal of a mapping is invalidates its PTE.
 *
 *			So, how do we deal with mappings to I/O space? We don't have a physent for it.
 *			Within the mapping is a copy of the second half of the PTE.  This is used
 *			ONLY when there is no physical entry.  It is swapped into the PTE whenever
 *			it is built.  There is no need to swap it back out, because RC is not
 *			maintained for these mappings.
 *
 *			So, I'm starting to get concerned about the number of lwarx/stcwx loops in
 *			this.  Satisfying a mapped address with no stealing requires one lock.  If we 
 *			steal an entry, there's two locks and an atomic update.  Invalidation of an entry
 *			takes one lock and, if there is a PTE, another lock and an atomic update.  Other 
 *			operations are multiples (per mapping) of the above.  Maybe we should look for
 *			an alternative.  So far, I haven't found one, but I haven't looked hard.
 */


/*			hw_add_map(struct mapping *mp, space_t space, vm_offset_t va) - Adds a mapping
 *
 *			Adds a mapping to the PTEG hash list.
 *
 *			Interrupts must be disabled before calling.
 *
 *			Using the space and the virtual address, we hash into the hash table
 *			and get a lock on the PTEG hash chain.  Then we chain the 
 *			mapping to the front of the list.
 *
 */

			.align	5
			.globl	EXT(hw_add_map)

LEXT(hw_add_map)

#if PERFTIMES && DEBUG
			mr		r7,r3
			mflr	r11
			li		r3,20
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r7
			mtlr	r11
#endif

			mfmsr	r0							/* Get the MSR */
			eqv		r6,r6,r6					/* Fill the bottom with foxes */
			rlwinm	r11,r4,6,6,25				/* Position the space for the VSID */
			mfspr	r10,sdr1					/* Get hash table base and size */
			rlwimi	r11,r5,30,2,5				/* Insert the segment no. to make a VSID */
			mfsprg	r12,2						; Get feature flags
			rlwimi	r6,r10,16,0,15				/* Make table size -1 out of mask */
			rlwinm	r7,r5,26,10,25				/* Isolate the page index */
			or		r8,r10,r6					/* Point to the last byte in table */
			rlwinm	r9,r5,4,0,3					; Move nybble 1 up to 0
			xor		r7,r7,r11					/* Get primary hash */
			mtcrf	0x04,r12					; Set the features			
			andi.	r12,r0,0x7FCF				/* Disable translation and interruptions */
			rlwinm	r11,r11,1,1,24				/* Position VSID for pte ID */
			addi	r8,r8,1						/* Point to the PTEG Control Area */
			xor		r9,r9,r5					; Splooch vaddr nybble 0 and 1 together
			and		r7,r7,r6					/* Wrap the hash */
			rlwimi	r11,r5,10,26,31				/* Move API into pte ID */
			rlwinm	r9,r9,6,27,29				; Get splooched bits in place
			add		r8,r8,r7					/* Point to our PCA entry */
			rlwinm	r10,r4,2,27,29				; Get low 3 bits of the VSID for look-aside hash
			
			bt		pfNoMSRirb,hamNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hamNoMSRx
			
hamNoMSR:	mr		r4,r0						; Save R0
			mr		r2,r3						; Save
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r0,r4						; Restore
			mr		r3,r2						; Restore
hamNoMSRx:

			la		r4,PCAhash(r8)				/* Point to the mapping hash area */
			xor		r9,r9,r10					; Finish splooching nybble 0, 1, and the low bits of the VSID
			isync								/* Get rid of anything prefetched before we ref storage */
/*
 *			We've now got the address of our PCA, the hash chain anchor, our API subhash,
 *			and word 0 of the PTE (the virtual part). 
 *
 *			Now, we just lock the PCA.		
 */
			
			li		r12,1						/* Get the locked value */
			dcbt	0,r4						/* We'll need the hash area in a sec, so get it */
			add		r4,r4,r9					/* Point to the right mapping hash slot */
			
			lwarx	r10,0,r8					; ?

ptegLckx:	lwarx	r10,0,r8					/* Get the PTEG lock */
			mr.		r10,r10						/* Is it locked? */
			bne-	ptegLckwx					/* Yeah... */
			stwcx.	r12,0,r8					/* Take take it */
			bne-	ptegLckx					/* Someone else was trying, try again... */
			b		ptegSXgx					/* All done... */

			.align	4
			
ptegLckwx:	mr.		r10,r10						/* Check if it's already held */
			beq+	ptegLckx					/* It's clear... */
			lwz		r10,0(r8)					/* Get lock word again... */
			b		ptegLckwx					/* Wait... */
			
			.align	4
			
ptegSXgx:	isync								/* Make sure we haven't used anything yet */

			lwz		r7,0(r4)					/* Pick up the anchor of hash list */
			stw		r3,0(r4)					/* Save the new head */
			stw		r7,mmhashnext(r3)			/* Chain in the old head */
			
			stw		r4,mmPTEhash(r3)			/* Point to the head of the hash list */
			
			sync								/* Make sure the chain is updated */
			stw		r10,0(r8)					/* Unlock the hash list */
			mtmsr	r0							/* Restore translation and interruptions */
			isync								/* Toss anything done with DAT off */
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,21
			bl		EXT(dbgLog2)				; end of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									/* Leave... */


/*			mp=hw_lock_phys_vir(space, va) - Finds and locks a physical entry by vaddr.
 *
 *			Returns the mapping with the associated physent locked if found, or a
 *			zero and no lock if not.  It we timed out trying to get a the lock on
 *			the physical entry, we retun a 1.  A physical entry can never be on an
 *			odd boundary, so we can distinguish between a mapping and a timeout code.
 *
 *			Interrupts must be disabled before calling.
 *
 *			Using the space and the virtual address, we hash into the hash table
 *			and get a lock on the PTEG hash chain.  Then we search the chain for the
 *			mapping for our virtual address.  From there, we extract the pointer to
 *			the physical entry.
 *
 *			Next comes a bit of monkey business.  we need to get a lock on the physical
 *			entry.  But, according to our rules, we can't get it after we've gotten the
 *			PTEG hash lock, we could deadlock if we do.  So, we need to release the
 *			hash lock.  The problem is, though, that as soon as we release it, some 
 *			other yahoo may remove our mapping between the time that we release the
 *			hash lock and obtain the phys entry lock.  So, we can't count on the 
 *			mapping once we release the lock.  Instead, after we lock the phys entry,
 *			we search the mapping list (phys_link) for our translation.  If we don't find it,
 *			we unlock the phys entry, bail out, and return a 0 for the mapping address.  If we 
 *			did find it, we keep the lock and return the address of the mapping block.
 *
 *			What happens when a mapping is found, but there is no physical entry?
 *			This is what happens when there is I/O area mapped.  It one of these mappings
 *			is found, the mapping is returned, as is usual for this call, but we don't
 *			try to lock anything.  There could possibly be some problems here if another
 *			processor releases the mapping while we still alre using it.  Hope this 
 *			ain't gonna happen.
 *
 *			Taaa-dahhh!  Easy as pie, huh?
 *
 *			So, we have a few hacks hacks for running translate off in here. 
 *			First, when we call the lock routine, we have carnel knowlege of the registers is uses. 
 *			That way, we don't need a stack frame, which we can't have 'cause the stack is in
 *			virtual storage.  But wait, as if that's not enough...  We need one more register.  So, 
 *			we cram the LR into the CTR and return from there.
 *
 */
			.align	5
			.globl	EXT(hw_lock_phys_vir)

LEXT(hw_lock_phys_vir)

#if PERFTIMES && DEBUG
			mflr	r11
			mr		r5,r3
			li		r3,22
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r5
			mtlr	r11
#endif
			mfmsr	r12							/* Get the MSR */
			eqv		r6,r6,r6					/* Fill the bottom with foxes */
			mfsprg	r9,2						; Get feature flags 
			rlwinm	r11,r3,6,6,25				/* Position the space for the VSID */
			mfspr	r5,sdr1						/* Get hash table base and size */
			rlwimi	r11,r4,30,2,5				/* Insert the segment no. to make a VSID */
			mtcrf	0x04,r9						; Set the features			
			rlwimi	r6,r5,16,0,15				/* Make table size -1 out of mask */
			andi.	r0,r12,0x7FCF				/* Disable translation and interruptions */
			rlwinm	r9,r4,4,0,3					; Move nybble 1 up to 0
			rlwinm	r7,r4,26,10,25				/* Isolate the page index */
			or		r8,r5,r6					/* Point to the last byte in table */
			xor		r7,r7,r11					/* Get primary hash */
			rlwinm	r11,r11,1,1,24				/* Position VSID for pte ID */
			addi	r8,r8,1						/* Point to the PTEG Control Area */
			xor		r9,r9,r4					; Splooch vaddr nybble 0 and 1 together
			and		r7,r7,r6					/* Wrap the hash */
			rlwimi	r11,r4,10,26,31				/* Move API into pte ID */
			rlwinm	r9,r9,6,27,29				; Get splooched bits in place
			add		r8,r8,r7					/* Point to our PCA entry */
			rlwinm	r10,r3,2,27,29				; Get low 3 bits of the VSID for look-aside hash

			bt		pfNoMSRirb,hlpNoMSR			; No MSR...

			mtmsr	r0							; Translation and all off
			isync								; Toss prefetch
			b		hlpNoMSRx
			
hlpNoMSR:	mr		r3,r0						; Get the new MSR
			li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
hlpNoMSRx:

			la		r3,PCAhash(r8)				/* Point to the mapping hash area */
			xor		r9,r9,r10					; Finish splooching nybble 0, 1, and the low bits of the VSID
			isync								/* Make sure translation is off before we ref storage */

/*
 *			We've now got the address of our PCA, the hash chain anchor, our API subhash,
 *			and word 0 of the PTE (the virtual part). 
 *
 *			Now, we just lock the PCA and find our mapping, if it exists.				
 */
			
			dcbt	0,r3						/* We'll need the hash area in a sec, so get it */
			add		r3,r3,r9					/* Point to the right mapping hash slot */
			
			lwarx	r10,0,r8					; ?

ptegLcka:	lwarx	r10,0,r8					/* Get the PTEG lock */
			li		r5,1						/* Get the locked value */
			mr.		r10,r10						/* Is it locked? */
			bne-	ptegLckwa					/* Yeah... */
			stwcx.	r5,0,r8						/* Take take it */
			bne-	ptegLcka					/* Someone else was trying, try again... */
			b		ptegSXga					/* All done... */
			
			.align	4

ptegLckwa:	mr.		r10,r10						/* Check if it's already held */
			beq+	ptegLcka					/* It's clear... */
			lwz		r10,0(r8)					/* Get lock word again... */
			b		ptegLckwa					/* Wait... */
			
			.align	4

ptegSXga:	isync								/* Make sure we haven't used anything yet */

			mflr	r0							/* Get the LR */
			lwz		r9,0(r3)					/* Pick up the first mapping block */
			mtctr	r0							/* Stuff it into the CTR */
			
findmapa:	

			mr.		r3,r9						/* Did we hit the end? */
			bne+	chkmapa						/* Nope... */
			
			stw		r3,0(r8)					/* Unlock the PTEG lock
												   Note: we never saved anything while we 
												   had the lock, so we don't need a sync 
												   before we unlock it */

vbail:		mtmsr	r12							/* Restore translation and interruptions */
			isync								/* Make sure translation is cool */
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,23
			bl		EXT(dbgLog2)				; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			bctr								/* Return in abject failure... */
			
			.align	4

chkmapa:	lwz		r10,mmPTEv(r3)				/* Pick up our virtual ID */
			lwz		r9,mmhashnext(r3)			/* Pick up next mapping block */
			cmplw	r10,r11						/* Have we found ourself? */
			bne-	findmapa					/* Nope, still wandering... */
			
			lwz		r9,mmphysent(r3)			/* Get our physical entry pointer */
			li		r5,0						/* Clear this out */
			mr.		r9,r9						/* Is there, like, a physical entry? */
			stw		r5,0(r8)					/* Unlock the PTEG lock
												   Note: we never saved anything while we 
												   had the lock, so we don't need a sync 
												   before we unlock it */
												   
			beq-	vbail						/* If there is no physical entry, it's time
												   to leave... */
												   
/*			Here we want to call hw_lock_bit.  We don't want to use the stack, 'cause it's
 *			in virtual storage, and we're in real.  So, we've carefully looked at the code
 *			in hw_lock_bit (and unlock) and cleverly don't use any of the registers that it uses.
 *			Be very, very aware of how you change this code.  By the way, it uses:
 *			R0, R6, R7, R8, and R9.  R3, R4, and R5 contain parameters
 *			Unfortunatly, we need to stash R9 still. So... Since we know we will not be interrupted
 *			('cause we turned off interruptions and translation is off) we will use SPRG3...
 */
 
			lwz		r10,mmPTEhash(r3)			/* Save the head of the hash-alike chain.  We need it to find ourselves later */
			lis		r5,HIGH_ADDR(EXT(LockTimeOut))	/* Get address of timeout value */
			la		r3,pephyslink(r9)			/* Point to the lock word */
			ori		r5,r5,LOW_ADDR(EXT(LockTimeOut))	/* Get second half of address */
			li		r4,PHYS_LOCK				/* Get the lock bit value */
			lwz		r5,0(r5)					/* Pick up the timeout value */
			mtsprg	3,r9						/* Save R9 in SPRG3 */
			
			bl		EXT(hw_lock_bit)			/* Go do the lock */
			
			mfsprg	r9,3						/* Restore pointer to the phys_entry */		
			mr.		r3,r3						/* Did we timeout? */
			lwz		r4,pephyslink(r9)			/* Pick up first mapping block */		
			beq-	penterr						/* Bad deal, we timed out... */

			rlwinm	r4,r4,0,0,26				; Clear out the flags from first link
			
findmapb:	mr.		r3,r4						/* Did we hit the end? */
			bne+	chkmapb						/* Nope... */
			
			la		r3,pephyslink(r9)			/* Point to where the lock is */						
			li		r4,PHYS_LOCK				/* Get the lock bit value */
			bl		EXT(hw_unlock_bit)			/* Go unlock the physentry */

			li		r3,0						/* Say we failed */			
			b		vbail						/* Return in abject failure... */
			
penterr:	li		r3,1						/* Set timeout */
			b		vbail						/* Return in abject failure... */
					
			.align	5

chkmapb:	lwz		r6,mmPTEv(r3)				/* Pick up our virtual ID */
			lwz		r4,mmnext(r3)				/* Pick up next mapping block */
			cmplw	r6,r11						/* Have we found ourself? */
			lwz		r5,mmPTEhash(r3)			/* Get the start of our hash chain */
			bne-	findmapb					/* Nope, still wandering... */
			cmplw	r5,r10						/* On the same hash chain? */
			bne-	findmapb					/* Nope, keep looking... */

			b		vbail						/* Return in glorious triumph... */


/*
 *			hw_rem_map(mapping) - remove a mapping from the system.
 *
 *			Upon entry, R3 contains a pointer to a mapping block and the associated
 *			physical entry is locked if there is one.
 *
 *			If the mapping entry indicates that there is a PTE entry, we invalidate
 *			if and merge the reference and change information into the phys_entry.
 *
 *			Next, we remove the mapping from the phys_ent and the PTEG hash list.
 *
 *			Unlock any locks that are left, and exit.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 *			Note that this code depends upon the VSID being of the format 00SXXXXX
 *			where S is the segment number.
 *
 *			  
 */

			.align	5
			.globl	EXT(hw_rem_map)

LEXT(hw_rem_map)
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,24
			bl		EXT(dbgLog2)				; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
 			mfsprg	r9,2						; Get feature flags 
			mfmsr	r0							/* Save the MSR  */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r9						; Set the features			
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */

			bt		pfNoMSRirb,lmvNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		lmvNoMSRx
			
lmvNoMSR:	
			mr		r6,r0
			mr		r4,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r4
			mr		r0,r6

lmvNoMSRx:

		
			lwz		r6,mmPTEhash(r3)			/* Get pointer to hash list anchor */
			lwz		r5,mmPTEv(r3)				/* Get the VSID */
			dcbt	0,r6						/* We'll need that chain in a bit */

			rlwinm	r7,r6,0,0,25				/* Round hash list down to PCA boundary */
			li		r12,1						/* Get the locked value */
			subi	r6,r6,mmhashnext			/* Make the anchor look like an entry */

			lwarx	r10,0,r7					; ?

ptegLck1:	lwarx	r10,0,r7					/* Get the PTEG lock */
			mr.		r10,r10						/* Is it locked? */
			bne-	ptegLckw1					/* Yeah... */
			stwcx.	r12,0,r7					/* Try to take it */
			bne-	ptegLck1					/* Someone else was trying, try again... */
			b		ptegSXg1					/* All done... */
			
			.align	4

ptegLckw1:	mr.		r10,r10						/* Check if it's already held */
			beq+	ptegLck1					/* It's clear... */
			lwz		r10,0(r7)					/* Get lock word again... */
			b		ptegLckw1					/* Wait... */
			
			.align	4

ptegSXg1:	isync								/* Make sure we haven't used anything yet */

			lwz		r12,mmhashnext(r3)			/* Prime with our forward pointer */
 			lwz		r4,mmPTEent(r3)				/* Get the pointer to the PTE now that the lock's set */

srchmaps:	mr.		r10,r6						/* Save the previous entry */
			bne+	mapok						/* No error... */
			
			lis		r0,HIGH_ADDR(Choke)			/* We have a kernel choke!!! */
			ori		r0,r0,LOW_ADDR(Choke)		
			sc									/* Firmware Heimlich manuever */

			.align	4			

mapok:		lwz		r6,mmhashnext(r6)			/* Look at the next one */
			cmplwi	cr5,r4,0					/* Is there a PTE? */
			cmplw	r6,r3						/* Have we found ourselves? */
			bne+	srchmaps					/* Nope, get your head together... */
			
			stw		r12,mmhashnext(r10)			/* Remove us from the queue */
			rlwinm	r9,r5,1,0,3					/* Move in the segment */
			rlwinm	r8,r4,6,4,19				/* Line PTEG disp up to a page */
			rlwinm	r11,r5,5,4,19				/* Line up the VSID */
			lwz		r10,mmphysent(r3)			/* Point to the physical entry */
		
			beq+	cr5,nopte					/* There's no PTE to invalidate... */
			
			xor		r8,r8,r11					/* Back hash to virt index */
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))	/* Get the TLBIE lock */
			rlwimi	r9,r5,22,4,9				/* Move in the API */
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	/* Grab up the bottom part */
			mfspr	r11,pvr						/* Find out what kind of machine we are */
			rlwimi	r9,r8,0,10,19				/* Create the virtual address */
			rlwinm	r11,r11,16,16,31			/* Isolate CPU type */

			stw		r5,0(r4)					/* Make the PTE invalid */		

			cmplwi	cr1,r11,3					/* Is this a 603? */
			sync								/* Make sure the invalid is stored */
						
			lwarx	r5,0,r12					; ?

tlbhang1:	lwarx	r5,0,r12					/* Get the TLBIE lock */
			rlwinm	r11,r4,29,29,31				/* Get the bit position of entry */
			mr.		r5,r5						/* Is it locked? */
			lis		r6,0x8000					/* Start up a bit mask */
			li		r5,1						/* Get our lock word */
			bne-	tlbhang1					/* It's locked, go wait... */
			stwcx.	r5,0,r12					/* Try to get it */
			bne-	tlbhang1					/* We was beat... */
			
			srw		r6,r6,r11					/* Make a "free slot" mask */
			lwz		r5,PCAallo(r7)				/* Get the allocation control bits */
			rlwinm	r11,r6,24,8,15				/* Make the autogen bit to turn off */
			or		r5,r5,r6					/* turn on the free bit */
			rlwimi	r11,r11,24,16,23			/* Get lock bit mask to turn it off */
			
			andc	r5,r5,r11					/* Turn off the lock and autogen bits in allocation flags */
			li		r11,0						/* Lock clear value */

			tlbie	r9							/* Invalidate it everywhere */

			
			beq-	cr1,its603a					/* It's a 603, skip the tlbsync... */
			
			eieio								/* Make sure that the tlbie happens first */
			tlbsync								/* wait for everyone to catch up */
			isync								
			
its603a:	sync								/* Make sure of it all */
			stw		r11,0(r12)					/* Clear the tlbie lock */
			eieio								/* Make sure those RC bit are loaded */
			stw		r5,PCAallo(r7)				/* Show that the slot is free */
			stw		r11,mmPTEent(r3)			/* Clear the pointer to the PTE */

nopte:		mr.		r10,r10						/* See if there is a physical entry */
			la		r9,pephyslink(r10)			/* Point to the physical mapping chain */
			beq-	nophys						/* No physical entry, we're done... */
			beq-	cr5,nadamrg					/* No PTE to merge... */

			lwz		r6,4(r4)					/* Get the latest reference and change bits */
			la		r12,pepte1(r10)				/* Point right at the master copy */
			rlwinm	r6,r6,0,23,24				/* Extract just the RC bits */
			
			lwarx	r8,0,r12					; ?

mrgrc:		lwarx	r8,0,r12					/* Get the master copy */
			or		r8,r8,r6					/* Merge in latest RC */
			stwcx.	r8,0,r12					/* Save it back */
			bne-	mrgrc						/* If it changed, try again... */
			
nadamrg:	li		r11,0						/* Clear this out */
			lwz		r12,mmnext(r3)				/* Prime with our next */
			stw		r11,0(r7)					/* Unlock the hash chain now so we don't
												   lock out another processor during the 
												   our next little search */
			
			
srchpmap:	mr.		r10,r9						/* Save the previous entry */
			bne+	mapok1						/* No error... */
			
			lis		r0,HIGH_ADDR(Choke)			/* We have a kernel choke!!! */
			ori		r0,r0,LOW_ADDR(Choke)			
			sc									/* Firmware Heimlich maneuver */
			
			.align	4

mapok1:		lwz		r9,mmnext(r9)				/* Look at the next one */
			rlwinm	r8,r9,0,27,31				; Save the flags (including the lock)
			rlwinm	r9,r9,0,0,26				; Clear out the flags from first link
			cmplw	r9,r3						/* Have we found ourselves? */
			bne+	srchpmap					/* Nope, get your head together... */
			
			rlwimi	r12,r8,0,27,31				; Insert the lock and flags */
			stw		r12,mmnext(r10)				/* Remove us from the queue */
			
			mtmsr	r0							/* Interrupts and translation back on */
			isync
#if PERFTIMES && DEBUG
			mflr	r11
			li		r3,25
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mtlr	r11
#endif
			blr									/* Return... */

			.align	4

nophys:		li		r4,0						/* Make sure this is 0 */
			sync								/* Make sure that chain is updated */
			stw		r4,0(r7)					/* Unlock the hash chain */
			mtmsr	r0							/* Interrupts and translation back on */
			isync
#if PERFTIMES && DEBUG
			mflr	r11
			li		r3,25
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mtlr	r11
#endif
			blr									/* Return... */


/*
 *			hw_prot(physent, prot) - Change the protection of a physical page
 *
 *			Upon entry, R3 contains a pointer to a physical entry which is locked.
 *			R4 contains the PPC protection bits.
 *
 *			The first thing we do is to slam the new protection into the phys entry.
 *			Then we scan the mappings and process each one.
 *
 *			Acquire the lock on the PTEG hash list for the mapping being processed.
 *
 *			If the current mapping has a PTE entry, we invalidate
 *			it and merge the reference and change information into the phys_entry.
 *
 *			Next, slam the protection bits into the entry and unlock the hash list.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 *			  
 */

			.align	5
			.globl	EXT(hw_prot)

LEXT(hw_prot)
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r7,r3
//			lwz		r5,4(r3)
			li		r5,0x1111
			li		r3,26
			bl		EXT(dbgLog2)				; Start of hw_add_map
			mr		r3,r7
			mtlr	r11
#endif
 			mfsprg	r9,2						; Get feature flags 
			mfmsr	r0							/* Save the MSR  */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			li		r5,pepte1					/* Get displacement to the second word of master pte */
			mtcrf	0x04,r9						; Set the features			
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */

			bt		pfNoMSRirb,hpNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hpNoMSRx
			
hpNoMSR:	
			mr		r10,r0
			mr		r7,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r0,r10
			mr		r3,r7
hpNoMSRx:


			
			lwz		r10,pephyslink(r3)			/* Get the first mapping block */
			rlwinm	r10,r10,0,0,26				; Clear out the flags from first link

/*
 *			Note that we need to to do the interlocked update here because another processor
 *			can be updating the reference and change bits even though the physical entry
 *			is locked.  All modifications to the PTE portion of the physical entry must be
 *			done via interlocked update.
 */

			lwarx	r8,r5,r3					; ?

protcng:	lwarx	r8,r5,r3					/* Get the master copy */
			rlwimi	r8,r4,0,30,31				/* Move in the protection bits */
			stwcx.	r8,r5,r3					/* Save it back */
			bne-	protcng						/* If it changed, try again... */



protnext:	mr.		r10,r10						/* Are there any more mappings? */
			beq-	protdone					/* Naw... */
			
			lwz		r7,mmPTEhash(r10)			/* Get pointer to hash list anchor */
			lwz		r5,mmPTEv(r10)				/* Get the virtual address */
			rlwinm	r7,r7,0,0,25				/* Round hash list down to PCA boundary */

			li		r12,1						/* Get the locked value */

			lwarx	r11,0,r7					; ?

protLck1:	lwarx	r11,0,r7					/* Get the PTEG lock */
			mr.		r11,r11						/* Is it locked? */
			bne-	protLckw1					/* Yeah... */
			stwcx.	r12,0,r7					/* Try to take it */
			bne-	protLck1					/* Someone else was trying, try again... */
			b		protSXg1					/* All done... */
			
			.align	4

protLckw1:	mr.		r11,r11						/* Check if it's already held */
			beq+	protLck1					/* It's clear... */
			lwz		r11,0(r7)					/* Get lock word again... */
			b		protLckw1					/* Wait... */
			
			.align	4

protSXg1:	isync								/* Make sure we haven't used anything yet */

 			lwz		r6,mmPTEent(r10)			/* Get the pointer to the PTE now that the lock's set */

			rlwinm	r9,r5,1,0,3					/* Move in the segment */
			lwz		r2,mmPTEr(r10)				; Get the mapping copy of the PTE
			mr.		r6,r6						/* See if there is a PTE here */
			rlwinm	r8,r5,31,2,25				/* Line it up */
			rlwimi	r2,r4,0,30,31				; Move protection bits into the mapping copy
		
			beq+	protul						/* There's no PTE to invalidate... */
			
			xor		r8,r8,r6					/* Back hash to virt index */
			rlwimi	r9,r5,22,4,9				/* Move in the API */
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))	/* Get the TLBIE lock */
			rlwinm	r5,r5,0,1,31				/* Clear the valid bit */
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	/* Grab up the bottom part */
			mfspr	r11,pvr						/* Find out what kind of machine we are */
			rlwimi	r9,r8,6,10,19				/* Create the virtual address */
			rlwinm	r11,r11,16,16,31			/* Isolate CPU type */

			stw		r5,0(r6)					/* Make the PTE invalid */		
			cmplwi	cr1,r11,3					/* Is this a 603? */
			sync								/* Make sure the invalid is stored */
						
			lwarx	r11,0,r12					; ?

tlbhangp:	lwarx	r11,0,r12					/* Get the TLBIE lock */
			rlwinm	r8,r6,29,29,31				/* Get the bit position of entry */
			mr.		r11,r11						/* Is it locked? */
			lis		r5,0x8000					/* Start up a bit mask */
			li		r11,1						/* Get our lock word */
			bne-	tlbhangp					/* It's locked, go wait... */
			stwcx.	r11,0,r12					/* Try to get it */
			bne-	tlbhangp					/* We was beat... */
			
			li		r11,0						/* Lock clear value */

			tlbie	r9							/* Invalidate it everywhere */

			beq-	cr1,its603p					/* It's a 603, skip the tlbsync... */
			
			eieio								/* Make sure that the tlbie happens first */
			tlbsync								/* wait for everyone to catch up */
			isync								
			
its603p:	stw		r11,0(r12)					/* Clear the lock */
			srw		r5,r5,r8					/* Make a "free slot" mask */
			sync								/* Make sure of it all */

			lwz		r6,4(r6)					/* Get the latest reference and change bits */
			stw		r11,mmPTEent(r10)			/* Clear the pointer to the PTE */
			rlwinm	r6,r6,0,23,24				/* Extract the RC bits */
			lwz		r9,PCAallo(r7)				/* Get the allocation control bits */
			rlwinm	r8,r5,24,8,15				/* Make the autogen bit to turn off */
			rlwimi	r2,r6,0,23,24				; Put the latest RC bit in mapping copy
			or		r9,r9,r5					/* Set the slot free */
			rlwimi	r8,r8,24,16,23				/* Get lock bit mask to turn it off */
			andc	r9,r9,r8					/* Clear the auto and lock bits */
			li		r5,pepte1					/* Get displacement to the second word of master pte */
			stw		r9,PCAallo(r7)				/* Store the allocation controls */
			
			lwarx	r11,r5,r3					; ?
protmod:	lwarx	r11,r5,r3					/* Get the master copy */
			or		r11,r11,r6					/* Merge in latest RC */
			stwcx.	r11,r5,r3					/* Save it back */
			bne-	protmod						/* If it changed, try again... */
			
			sync								/* Make sure that chain is updated */

protul:		li		r4,0						/* Get a 0 */
			stw		r2,mmPTEr(r10)				; Save the updated mapping PTE
			lwz		r10,mmnext(r10)				/* Get the next */
			stw		r4,0(r7)					/* Unlock the hash chain */
			b		protnext					/* Go get the next one */
			
			.align	4

protdone:	mtmsr	r0							/* Interrupts and translation back on */
			isync
#if PERFTIMES && DEBUG
			mflr	r11
			li		r3,27
			bl		EXT(dbgLog2)				; Start of hw_add_map
			mtlr	r11
#endif
			blr									/* Return... */


/*
 *			hw_prot_virt(mapping, prot) - Change the protection of single page
 *
 *			Upon entry, R3 contains a pointer (real) to a mapping.
 *			R4 contains the PPC protection bits.
 *
 *			Acquire the lock on the PTEG hash list for the mapping being processed.
 *
 *			If the current mapping has a PTE entry, we invalidate
 *			it and merge the reference and change information into the phys_entry.
 *
 *			Next, slam the protection bits into the entry, merge the RC bits, 
 *			and unlock the hash list.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 *			  
 */

			.align	5
			.globl	EXT(hw_prot_virt)

LEXT(hw_prot_virt)
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r7,r3
//			lwz		r5,4(r3)
			li		r5,0x1111
			li		r3,40
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r7
			mtlr	r11
#endif
 			mfsprg	r9,2						; Get feature flags 
			mfmsr	r0							/* Save the MSR  */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r9						; Set the features			
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */
			
			bt		pfNoMSRirb,hpvNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hpvNoMSRx
			
hpvNoMSR:	
			mr		r5,r0
			mr		r7,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r7
			mr		r0,r5
hpvNoMSRx:


			
/*
 *			Note that we need to to do the interlocked update here because another processor
 *			can be updating the reference and change bits even though the physical entry
 *			is locked.  All modifications to the PTE portion of the physical entry must be
 *			done via interlocked update.
 */
			
			lwz		r7,mmPTEhash(r3)			/* Get pointer to hash list anchor */
			lwz		r5,mmPTEv(r3)				/* Get the virtual address */
			rlwinm	r7,r7,0,0,25				/* Round hash list down to PCA boundary */

			li		r12,1						/* Get the locked value */

			lwarx	r11,0,r7					; ?

protvLck1:	lwarx	r11,0,r7					/* Get the PTEG lock */
			mr.		r11,r11						/* Is it locked? */
			bne-	protvLckw1					/* Yeah... */
			stwcx.	r12,0,r7					/* Try to take it */
			bne-	protvLck1					/* Someone else was trying, try again... */
			b		protvSXg1					/* All done... */
			
			.align	4

protvLckw1:	mr.		r11,r11						/* Check if it's already held */
			beq+	protvLck1					/* It's clear... */
			lwz		r11,0(r7)					/* Get lock word again... */
			b		protvLckw1					/* Wait... */
			
			.align	4

protvSXg1:	isync								/* Make sure we haven't used anything yet */

 			lwz		r6,mmPTEent(r3)				/* Get the pointer to the PTE now that the lock's set */
 			lwz		r2,mmPTEr(r3)				; Get the mapping copy if the real part

			rlwinm	r9,r5,1,0,3					/* Move in the segment */
			cmplwi	cr7,r6,0					; Any PTE to invalidate?
			rlwimi	r2,r4,0,30,31				; Move in the new protection bits
			rlwinm	r8,r5,31,2,25				/* Line it up */
		
			beq+	cr7,pvnophys				/* There's no PTE to invalidate... */
			
			xor		r8,r8,r6					/* Back hash to virt index */
			rlwimi	r9,r5,22,4,9				/* Move in the API */
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))	/* Get the TLBIE lock */
			rlwinm	r5,r5,0,1,31				/* Clear the valid bit */
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	/* Grab up the bottom part */
			mfspr	r11,pvr						/* Find out what kind of machine we are */
			rlwimi	r9,r8,6,10,19				/* Create the virtual address */
			rlwinm	r11,r11,16,16,31			/* Isolate CPU type */

			stw		r5,0(r6)					/* Make the PTE invalid */		
			cmplwi	cr1,r11,3					/* Is this a 603? */
			sync								/* Make sure the invalid is stored */
						
			lwarx	r11,0,r12					; ?

tlbhangpv:	lwarx	r11,0,r12					/* Get the TLBIE lock */
			rlwinm	r8,r6,29,29,31				/* Get the bit position of entry */
			mr.		r11,r11						/* Is it locked? */
			lis		r5,0x8000					/* Start up a bit mask */
			li		r11,1						/* Get our lock word */
			bne-	tlbhangpv					/* It's locked, go wait... */
			stwcx.	r11,0,r12					/* Try to get it */
			bne-	tlbhangpv					/* We was beat... */
			
			li		r11,0						/* Lock clear value */

			tlbie	r9							/* Invalidate it everywhere */

			beq-	cr1,its603pv				/* It's a 603, skip the tlbsync... */
			
			eieio								/* Make sure that the tlbie happens first */
			tlbsync								/* wait for everyone to catch up */
			isync								
			
its603pv:	stw		r11,0(r12)					/* Clear the lock */
			srw		r5,r5,r8					/* Make a "free slot" mask */
			sync								/* Make sure of it all */

			lwz		r6,4(r6)					/* Get the latest reference and change bits */
			stw		r11,mmPTEent(r3)			/* Clear the pointer to the PTE */
			rlwinm	r6,r6,0,23,24				/* Extract the RC bits */
			lwz		r9,PCAallo(r7)				/* Get the allocation control bits */
			rlwinm	r8,r5,24,8,15				/* Make the autogen bit to turn off */
			lwz		r10,mmphysent(r3)			; Get any physical entry
			or		r9,r9,r5					/* Set the slot free */
			rlwimi	r8,r8,24,16,23				/* Get lock bit mask to turn it off */
			andc	r9,r9,r8					/* Clear the auto and lock bits */
			mr.		r10,r10						; Is there a physical entry?
			li		r5,pepte1					/* Get displacement to the second word of master pte */
			stw		r9,PCAallo(r7)				/* Store the allocation controls */
			rlwimi	r2,r6,0,23,24				; Stick in RC bits
			beq-	pvnophys					; No physical entry...
			
			
			lwarx	r11,r5,r10					; ?

protvmod:	lwarx	r11,r5,r10					/* Get the master copy */
			or		r11,r11,r6					/* Merge in latest RC */
			stwcx.	r11,r5,r10					/* Save it back */
			bne-	protvmod					/* If it changed, try again... */
			
			sync								/* Make sure that chain is updated */

pvnophys:	li		r4,0						/* Get a 0 */
			stw		r2,mmPTEr(r3)				; Set the real part of the PTE
			stw		r4,0(r7)					/* Unlock the hash chain */
			mtmsr	r0							; Restore interrupts and translation
			isync

#if PERFTIMES && DEBUG
			mflr	r11
			li		r3,41
			bl		EXT(dbgLog2)				
			mtlr	r11
#endif
			blr									/* Return... */


/*
 *			hw_attr_virt(mapping, attr) - Change the attributes of single page
 *
 *			Upon entry, R3 contains a pointer (real) to a mapping.
 *			R4 contains the WIMG bits.
 *
 *			Acquire the lock on the PTEG hash list for the mapping being processed.
 *
 *			If the current mapping has a PTE entry, we invalidate
 *			it and merge the reference and change information into the phys_entry.
 *
 *			Next, slam the WIMG bits into the entry, merge the RC bits, 
 *			and unlock the hash list.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 *			  
 */

			.align	5
			.globl	EXT(hw_attr_virt)

LEXT(hw_attr_virt)
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r7,r3
//			lwz		r5,4(r3)
			li		r5,0x1111
			li		r3,40
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r7
			mtlr	r11
#endif
			mfsprg	r9,2						; Get feature flags 
 			mfmsr	r0							/* Save the MSR  */
			mtcrf	0x04,r9						; Set the features			
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */

			bt		pfNoMSRirb,havNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		havNoMSRx
			
havNoMSR:	
			mr		r5,r0
			mr		r7,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r7
			mr		r0,r5
havNoMSRx:

/*
 *			Note that we need to to do the interlocked update here because another processor
 *			can be updating the reference and change bits even though the physical entry
 *			is locked.  All modifications to the PTE portion of the physical entry must be
 *			done via interlocked update.
 */
			
			lwz		r7,mmPTEhash(r3)			/* Get pointer to hash list anchor */
			lwz		r5,mmPTEv(r3)				/* Get the virtual address */
			rlwinm	r7,r7,0,0,25				/* Round hash list down to PCA boundary */

			li		r12,1						/* Get the locked value */

			lwarx	r11,0,r7					; ?

attrvLck1:	lwarx	r11,0,r7					/* Get the PTEG lock */
			mr.		r11,r11						/* Is it locked? */
			bne-	attrvLckw1					/* Yeah... */
			stwcx.	r12,0,r7					/* Try to take it */
			bne-	attrvLck1					/* Someone else was trying, try again... */
			b		attrvSXg1					/* All done... */
			
			.align	4

attrvLckw1:	mr.		r11,r11						/* Check if it's already held */
			beq+	attrvLck1					/* It's clear... */
			lwz		r11,0(r7)					/* Get lock word again... */
			b		attrvLckw1					/* Wait... */
			
			.align	4

attrvSXg1:	isync								/* Make sure we haven't used anything yet */

 			lwz		r6,mmPTEent(r3)				/* Get the pointer to the PTE now that the lock's set */
 			lwz		r2,mmPTEr(r3)				; Get the mapping copy if the real part

			rlwinm	r9,r5,1,0,3					/* Move in the segment */
			mr.		r6,r6						/* See if there is a PTE here */
			rlwimi	r2,r4,0,25,28				; Move in the new attribute bits
			rlwinm	r8,r5,31,2,25				/* Line it up and check if empty */
		
			beq+	avnophys					/* There's no PTE to invalidate... */
			
			xor		r8,r8,r6					/* Back hash to virt index */
			rlwimi	r9,r5,22,4,9				/* Move in the API */
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))	/* Get the TLBIE lock */
			rlwinm	r5,r5,0,1,31				/* Clear the valid bit */
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	/* Grab up the bottom part */
			mfspr	r11,pvr						/* Find out what kind of machine we are */
			rlwimi	r9,r8,6,10,19				/* Create the virtual address */
			rlwinm	r11,r11,16,16,31			/* Isolate CPU type */
			stw		r5,0(r6)					/* Make the PTE invalid */		
			cmplwi	cr1,r11,3					/* Is this a 603? */
			sync								/* Make sure the invalid is stored */
						
			lwarx	r11,0,r12					; ?

tlbhangav:	lwarx	r11,0,r12					/* Get the TLBIE lock */
			rlwinm	r8,r6,29,29,31				/* Get the bit position of entry */
			mr.		r11,r11						/* Is it locked? */
			lis		r5,0x8000					/* Start up a bit mask */
			li		r11,1						/* Get our lock word */
			bne-	tlbhangav					/* It's locked, go wait... */
			stwcx.	r11,0,r12					/* Try to get it */
			bne-	tlbhangav					/* We was beat... */
			
			li		r11,0						/* Lock clear value */

			tlbie	r9							/* Invalidate it everywhere */

			beq-	cr1,its603av				/* It's a 603, skip the tlbsync... */
			
			eieio								/* Make sure that the tlbie happens first */
			tlbsync								/* wait for everyone to catch up */
			isync								
			
its603av:	stw		r11,0(r12)					/* Clear the lock */
			srw		r5,r5,r8					/* Make a "free slot" mask */
			sync								/* Make sure of it all */

			lwz		r6,4(r6)					/* Get the latest reference and change bits */
			stw		r11,mmPTEent(r3)			/* Clear the pointer to the PTE */
			rlwinm	r6,r6,0,23,24				/* Extract the RC bits */
			lwz		r9,PCAallo(r7)				/* Get the allocation control bits */
			rlwinm	r8,r5,24,8,15				/* Make the autogen bit to turn off */
			lwz		r10,mmphysent(r3)			; Get any physical entry
			or		r9,r9,r5					/* Set the slot free */
			rlwimi	r8,r8,24,16,23				/* Get lock bit mask to turn it off */
			andc	r9,r9,r8					/* Clear the auto and lock bits */
			mr.		r10,r10						; Is there a physical entry?
			li		r5,pepte1					/* Get displacement to the second word of master pte */
			stw		r9,PCAallo(r7)				/* Store the allocation controls */
			rlwimi	r2,r6,0,23,24				; Stick in RC bits
			beq-	avnophys					; No physical entry...			
			
			lwarx	r11,r5,r10					; ?

attrvmod:	lwarx	r11,r5,r10					/* Get the master copy */
			or		r11,r11,r6					/* Merge in latest RC */
			stwcx.	r11,r5,r10					/* Save it back */
			bne-	attrvmod					/* If it changed, try again... */
			
			sync								/* Make sure that chain is updated */

avnophys:	li		r4,0						/* Get a 0 */
			stw		r2,mmPTEr(r3)				; Set the real part of the PTE
			stw		r4,0(r7)					/* Unlock the hash chain */
			
			rlwinm	r2,r2,0,0,19				; Clear back to page boundary
			
attrflsh:	cmplwi	r4,(4096-32)				; Are we about to do the last line on page?
			dcbst	r2,r4						; Flush cache because we changed attributes
			addi	r4,r4,32					; Bump up cache
			blt+	attrflsh					; Do the whole page...
			sync

			li		r4,0
attrimvl:	cmplwi	r4,(4096-32)				; Are we about to do the last line on page?
			dcbi	r2,r4						; Invalidate dcache because we changed attributes
			icbi	r2,r4						; Invalidate icache because we changed attributes
			icbi	r2,r4						; Invalidate icache because we changed attributes
			addi	r4,r4,32					; Bump up cache
			blt+	attrimvl					; Do the whole page...
			sync

			mtmsr	r0							; Restore interrupts and translation
			isync

#if PERFTIMES && DEBUG
			mflr	r11
			li		r3,41
			bl		EXT(dbgLog2)				
			mtlr	r11
#endif
			blr									/* Return... */


/*
 *			hw_pte_comm(physent) - Do something to the PTE pointing to a physical page
 *
 *			Upon entry, R3 contains a pointer to a physical entry which is locked.
 *			Note that this must be done with both interruptions off and VM off
 *
 *			First, we set up CRs 5 and 7 to indicate which of the 7 calls this is.
 *
 *			Now we scan the mappings to invalidate any with an active PTE.
 *
 *				Acquire the lock on the PTEG hash list for the mapping being processed.
 *
 *				If the current mapping has a PTE entry, we invalidate
 *				it and merge the reference and change information into the phys_entry.
 *
 *				Next, unlock the hash list and go on to the next mapping.
 *
 *	
 *			  
 */

			.align	5
			.globl	EXT(hw_inv_all)

LEXT(hw_inv_all)
	
			li		r9,0x800					/* Indicate invalidate all */
			li		r2,0						; No inadvertant modifications please
			b		hw_pte_comm					/* Join in the fun... */


			.align	5
			.globl	EXT(hw_tst_mod)

LEXT(hw_tst_mod)

			lwz		r8,pepte1(r3)				; Get the saved PTE image
			li		r9,0x400					/* Indicate test modify */
			li		r2,0						; No inadvertant modifications please
			rlwinm.	r8,r8,25,31,31				; Make change bit into return code
			beq+	hw_pte_comm					; Assume we do not know if it is set...
			mr		r3,r8						; Set the return code
			blr									; Return quickly...

 			.align	5
			.globl	EXT(hw_tst_ref)

LEXT(hw_tst_ref)
			lwz		r8,pepte1(r3)				; Get the saved PTE image
			li		r9,0x200					/* Indicate test reference bit */
			li		r2,0						; No inadvertant modifications please
			rlwinm.	r8,r8,24,31,31				; Make reference bit into return code
			beq+	hw_pte_comm					; Assume we do not know if it is set...
			mr		r3,r8						; Set the return code
			blr									; Return quickly...

/*
 *			Note that the following are all in one CR for ease of use later
 */
			.align	4
			.globl	EXT(hw_set_mod)

LEXT(hw_set_mod)
			
			li		r9,0x008					/* Indicate set modify bit */
			li		r2,0x4						; Set set C, clear none
			b		hw_pte_comm					/* Join in the fun... */


			.align	4
			.globl	EXT(hw_clr_mod)

LEXT(hw_clr_mod)
			
			li		r9,0x004					/* Indicate clear modify bit */
			li		r2,0x1						; Set set none, clear C
			b		hw_pte_comm					/* Join in the fun... */


			.align	4
			.globl	EXT(hw_set_ref)

LEXT(hw_set_ref)
			
			li		r9,0x002					/* Indicate set reference */
			li		r2,0x8						; Set set R, clear none
			b		hw_pte_comm					/* Join in the fun... */

			.align	5
			.globl	EXT(hw_clr_ref)

LEXT(hw_clr_ref)
			
			li		r9,0x001					/* Indicate clear reference bit */
			li		r2,0x2						; Set set none, clear R
			b		hw_pte_comm					/* Join in the fun... */


/*
 *			This is the common stuff.
 */

			.align	5

hw_pte_comm:									/* Common routine for pte tests and manips */
 
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r7,r3
			lwz		r4,4(r3)
			mr		r5,r9			
			li		r3,28
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r7
			mtlr	r11
#endif
 			mfsprg	r8,2						; Get feature flags 
			lwz		r10,pephyslink(r3)			/* Get the first mapping block */
			mfmsr	r0							/* Save the MSR  */
			rlwinm.	r10,r10,0,0,26				; Clear out the flags from first link and see if we are mapped
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r8						; Set the features			
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */
			beq-	comnmap						; No mapping
			dcbt	br0,r10						; Touch the first mapping in before the isync
			
comnmap:

			bt		pfNoMSRirb,hpcNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hpcNoMSRx
			
hpcNoMSR:	
			mr		r5,r0
			mr		r7,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r7
			mr		r0,r5
hpcNoMSRx:

			mtcrf	0x05,r9						/* Set the call type flags into cr5 and 7 */

			beq-	commdone					; Nothing us mapped to this page...
			b		commnext					; Jump to first pass (jump here so we can align loop)
		
			.align	5	

commnext:	lwz		r11,mmnext(r10)				; Get the pointer to the next mapping (if any)
			lwz		r7,mmPTEhash(r10)			/* Get pointer to hash list anchor */
			lwz		r5,mmPTEv(r10)				/* Get the virtual address */
			mr.		r11,r11						; More mappings to go?
			rlwinm	r7,r7,0,0,25				/* Round hash list down to PCA boundary */
			beq-	commnxtch					; No more mappings...
			dcbt	br0,r11						; Touch the next mapping

commnxtch:	li		r12,1						/* Get the locked value */

			lwarx	r11,0,r7					; ?

commLck1:	lwarx	r11,0,r7					/* Get the PTEG lock */
			mr.		r11,r11						/* Is it locked? */
			bne-	commLckw1					/* Yeah... */
			stwcx.	r12,0,r7					/* Try to take it */
			bne-	commLck1					/* Someone else was trying, try again... */
			b		commSXg1					/* All done... */
			
			.align	4

commLckw1:	mr.		r11,r11						/* Check if it's already held */
			beq+	commLck1					/* It's clear... */
			lwz		r11,0(r7)					/* Get lock word again... */
			b		commLckw1					/* Wait... */
			
			.align	4

commSXg1:	isync								/* Make sure we haven't used anything yet */

 			lwz		r6,mmPTEent(r10)			/* Get the pointer to the PTE now that the lock's set */

			rlwinm	r9,r5,1,0,3					/* Move in the segment */
			mr.		r6,r6						/* See if there is a PTE entry here */
			rlwinm	r8,r5,31,2,25				/* Line it up and check if empty */
		
			beq+	commul						/* There's no PTE to invalidate... */
			
			xor		r8,r8,r6					/* Back hash to virt index */
			rlwimi	r9,r5,22,4,9				/* Move in the API */
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))		/* Get the TLBIE lock */
			rlwinm	r5,r5,0,1,31				/* Clear the valid bit */
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	/* Grab up the bottom part */
			rlwimi	r9,r8,6,10,19				/* Create the virtual address */

			stw		r5,0(r6)					/* Make the PTE invalid */		
			mfspr	r4,pvr						/* Find out what kind of machine we are */
			sync								/* Make sure the invalid is stored */
						
			lwarx	r11,0,r12					; ?

tlbhangco:	lwarx	r11,0,r12					/* Get the TLBIE lock */
			rlwinm	r8,r6,29,29,31				/* Get the bit position of entry */
			mr.		r11,r11						/* Is it locked? */
			lis		r5,0x8000					/* Start up a bit mask */
			li		r11,1						/* Get our lock word */
			bne-	tlbhangco					/* It's locked, go wait... */
			stwcx.	r11,0,r12					/* Try to get it */
			bne-	tlbhangco					/* We was beat... */
			
			rlwinm	r4,r4,16,16,31				/* Isolate CPU type */
			li		r11,0						/* Lock clear value */
			cmplwi	r4,3						/* Is this a 603? */

			tlbie	r9							/* Invalidate it everywhere */

			beq-	its603co					/* It's a 603, skip the tlbsync... */
			
			eieio								/* Make sure that the tlbie happens first */
			tlbsync								/* wait for everyone to catch up */
			isync								
			
its603co:	stw		r11,0(r12)					/* Clear the lock */
			srw		r5,r5,r8					/* Make a "free slot" mask */
			sync								/* Make sure of it all */

			lwz		r6,4(r6)					/* Get the latest reference and change bits */
			lwz		r9,PCAallo(r7)				/* Get the allocation control bits */
			stw		r11,mmPTEent(r10)			/* Clear the pointer to the PTE */
			rlwinm	r8,r5,24,8,15				/* Make the autogen bit to turn off */
			or		r9,r9,r5					/* Set the slot free */
			rlwimi	r8,r8,24,16,23				/* Get lock bit mask to turn it off */
			rlwinm	r4,r6,0,23,24				/* Extract the RC bits */
			andc	r9,r9,r8					/* Clear the auto and lock bits */
			li		r5,pepte1					/* Get displacement to the second word of master pte */
			stw		r9,PCAallo(r7)				/* Store the allocation controls */
			
			lwarx	r11,r5,r3					; ?
commmod:	lwarx	r11,r5,r3					/* Get the master copy */
			or		r11,r11,r4					/* Merge in latest RC */
			stwcx.	r11,r5,r3					/* Save it back */
			bne-	commmod						/* If it changed, try again... */

			sync								/* Make sure that chain is updated */
			b		commulnl					; Skip loading the old real part...

commul:		lwz		r6,mmPTEr(r10)				; Get the real part

commulnl:	rlwinm	r12,r2,5,23,24				; Get the "set" bits
			rlwinm	r11,r2,7,23,24				; Get the "clear" bits
			
			or		r6,r6,r12					; Set the bits to come on
			andc	r6,r6,r11					; Clear those to come off

			stw		r6,mmPTEr(r10)				; Set the new RC

			lwz		r10,mmnext(r10)				/* Get the next */
			li		r4,0						/* Make sure this is 0 */
			mr.		r10,r10						; Is there another mapping?
			stw		r4,0(r7)					/* Unlock the hash chain */
			bne+	commnext					; Go get the next if there is one...
			
/*
 *			Now that all PTEs have been invalidated and the master RC bits are updated,
 *			we go ahead and figure out what the original call was and do that.  Note that
 *			another processor could be messing around and may have entered one of the 
 *			PTEs we just removed into the hash table.  Too bad...  You takes yer chances.
 *			If there's a problem with that, it's because some higher level was trying to
 *			do something with a mapping that it shouldn't.  So, the problem's really
 *			there, nyaaa, nyaaa, nyaaa... nyaaa, nyaaa... nyaaa! So there!
 */

commdone:	li		r5,pepte1					/* Get displacement to the second word of master pte */
			blt		cr5,commfini				/* We're finished, it was invalidate all... */
			bgt		cr5,commtst					/* It was a test modified... */
			beq		cr5,commtst					/* It was a test reference... */

/*
 *			Note that we need to to do the interlocked update here because another processor
 *			can be updating the reference and change bits even though the physical entry
 *			is locked.  All modifications to the PTE portion of the physical entry must be
 *			done via interlocked update.
 */

			rlwinm	r12,r2,5,23,24				; Get the "set" bits
			rlwinm	r11,r2,7,23,24				; Get the "clear" bits

			lwarx	r8,r5,r3					; ?

commcng:	lwarx	r8,r5,r3					/* Get the master copy */
			or		r8,r8,r12					; Set the bits to come on
			andc	r8,r8,r11					; Clear those to come off
			stwcx.	r8,r5,r3					/* Save it back */
			bne-	commcng						/* If it changed, try again... */

			mtmsr	r0							/* Interrupts and translation back on */
			isync
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,29
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									/* Return... */

			.align	4

commtst:	lwz		r8,pepte1(r3)				/* Get the PTE */
			bne-	cr5,commtcb					; This is for the change bit...
			mtmsr	r0							; Interrupts and translation back on
			rlwinm	r3,r8,24,31,31				; Copy reference bit to bit 31
			isync								; Toss prefetching
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,29
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									; Return...

			.align	4

commtcb:	rlwinm	r3,r8,25,31,31				; Copy change bit to bit 31

commfini:	mtmsr	r0							; Interrupts and translation back on
			isync								; Toss prefetching

#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,29
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									; Return...

/*
 *			unsigned int hw_test_rc(mapping *mp, boolean_t reset);
 *
 *			Test the RC bits for a specific mapping.  If reset is non-zero, clear them.
 *			We return the RC value in the mapping if there is no PTE or if C is set.
 *			(Note: R is always set with C.) Otherwise we invalidate the PTE and
 *			collect the RC bits from there, also merging them into the global copy.
 *			
 *			For now, we release the PTE slot and leave it invalid.  In the future, we
 *			may consider re-validating and not releasing the slot.  It would be faster,
 *			but our current implementation says that we will have not PTEs valid
 *			without the reference bit set.
 *
 *			We will special case C==1 && not reset to just return the RC.
 *
 *			Probable state is worst performance state: C bit is off and there is a PTE.
 */

#define		htrReset 31

			.align	5
			.globl	EXT(hw_test_rc)

LEXT(hw_test_rc)

 			mfsprg	r9,2						; Get feature flags 
			mfmsr	r0							; Save the MSR 
 			mr.		r4,r4						; See if we have a reset to do later
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interruption mask
			crnot	htrReset,cr0_eq				; Remember reset
			mtcrf	0x04,r9						; Set the features			
			rlwinm	r12,r12,0,28,25				; Clear IR and DR
			
			bt		pfNoMSRirb,htrNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		htrNoMSRx
			
htrNoMSR:	
			mr		r2,r0
			mr		r7,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r7
			mr		r0,r2
htrNoMSRx:
			
			lwz		r2,mmPTEr(r3)				; Get the real part
			lwz		r7,mmPTEhash(r3)			; Get pointer to hash list anchor
			rlwinm.	r12,r2,0,24,24				; Is the change bit on?
			lwz		r5,mmPTEv(r3)				; Get the virtual address
			crnor	cr0_eq,cr0_eq,htrReset		; Set if C=1 && not reset
			rlwinm	r7,r7,0,0,25				; Round hash list down to PCA boundary 
			bt		cr0_eq,htrcset				; Special case changed but no reset case...

			li		r12,1						; Get the locked value

htrLck1:	lwarx	r11,0,r7					; Get the PTEG lock
			mr.		r11,r11						; Is it locked?
			bne-	htrLckw1					; Yeah...
			stwcx.	r12,0,r7					; Try to take it
			bne-	htrLck1						; Someone else was trying, try again...
			b		htrSXg1						; All done...
			
			.align	4

htrLckw1:	mr.		r11,r11						; Check if it is already held 
			beq+	htrLck1						; It is clear... 
			lwz		r11,0(r7)					; Get lock word again... 
			b		htrLckw1					; Wait... 
			
			.align	4

htrSXg1:	isync								; Make sure we have not used anything yet

 			lwz		r6,mmPTEent(r3)				; Get the pointer to the PTE now that the lock is set
 			lwz		r2,mmPTEr(r3)				; Get the mapping copy of the real part

			rlwinm	r9,r5,1,0,3					; Move in the segment
			mr.		r6,r6						; Any PTE to invalidate?
			rlwinm	r8,r5,31,2,25				; Line it up 
		
			beq+	htrnopte					; There is no PTE to invalidate...
			
			xor		r8,r8,r6					; Back hash to virt index
			rlwimi	r9,r5,22,4,9				; Move in the API
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))	; Get the TLBIE lock
			rlwinm	r5,r5,0,1,31				; Clear the valid bit
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	; Grab up the bottom part
			mfspr	r11,pvr						; Find out what kind of machine we are
			rlwimi	r9,r8,6,10,19				; Create the virtual address
			rlwinm	r11,r11,16,16,31			; Isolate CPU type 

			stw		r5,0(r6)					; Make the PTE invalid	
			cmplwi	cr1,r11,3					; Is this a 603?
			sync								; Make sure the invalid is stored
						
htrtlbhang:	lwarx	r11,0,r12					; Get the TLBIE lock
			rlwinm	r8,r6,29,29,31				; Get the bit position of entry 
			mr.		r11,r11						; Is it locked?
			lis		r5,0x8000					; Start up a bit mask
			li		r11,1						; Get our lock word 
			bne-	htrtlbhang					; It is locked, go wait...
			stwcx.	r11,0,r12					; Try to get it
			bne-	htrtlbhang					; We was beat...
			
			li		r11,0						; Lock clear value 

			tlbie	r9							;Invalidate it everywhere

			beq-	cr1,htr603					; It is a 603, skip the tlbsync... 
			
			eieio								; Make sure that the tlbie happens first
			tlbsync								; wait for everyone to catch up
			isync								
			
htr603:		stw		r11,0(r12)					; Clear the lock
			srw		r5,r5,r8					; Make a "free slot" mask 
			sync								; Make sure of it all 

			lwz		r6,4(r6)					; Get the latest reference and change bits
			stw		r11,mmPTEent(r3)			; Clear the pointer to the PTE 
			rlwinm	r6,r6,0,23,24				; Extract the RC bits 
			lwz		r9,PCAallo(r7)				; Get the allocation control bits 
			rlwinm	r8,r5,24,8,15				; Make the autogen bit to turn off
			lwz		r10,mmphysent(r3)			; Get any physical entry
			or		r9,r9,r5					; Set the slot free 
			rlwimi	r8,r8,24,16,23				; Get lock bit mask to turn it off
			andc	r9,r9,r8					; Clear the auto and lock bits 
			mr.		r10,r10						; Is there a physical entry?
			li		r5,pepte1					; Get displacement to the second word of master pte
			stw		r9,PCAallo(r7)				; Store the allocation controls
			rlwimi	r2,r6,0,23,24				; Stick in RC bits
			beq-	htrnopte					; No physical entry...
			
htrmrc:		lwarx	r11,r5,r10					; Get the master copy
			or		r11,r11,r6					; Merge in latest RC
			stwcx.	r11,r5,r10					; Save it back
			bne-	htrmrc						; If it changed, try again... 
			
			sync								; Make sure that chain update is stored

htrnopte:	rlwinm	r3,r2,25,30,31				; Position RC and mask off
			bf		htrReset,htrnorst			; No reset to do...
			rlwinm	r2,r2,0,25,22				; Clear the RC if requested
			
htrnorst:	li		r4,0						; Get a 0 
			stw		r2,mmPTEr(r3)				; Set the real part of the PTE
			stw		r4,0(r7)					; Unlock the hash chain
	
			mtmsr	r0							; Restore interrupts and translation
			isync
			blr									; Return...

			.align	4

htrcset:	rlwinm	r3,r2,25,30,31				; Position RC and mask off
			mtmsr	r0							; Restore interrupts and translation
			isync
			blr									; Return...


/*
 *			hw_phys_attr(struct phys_entry *pp, vm_prot_t prot, unsigned int wimg) - Sets the default physical page attributes
 *
 *			Note that this must be done with both interruptions off and VM off
 *			Move the passed in attributes into the pte image in the phys entry
 *	
 *			  
 */

			.align	5
			.globl	EXT(hw_phys_attr)

LEXT(hw_phys_attr)

#if PERFTIMES && DEBUG
			mflr	r11
			mr		r8,r3
			mr		r7,r5
			mr		r5,r4
//			lwz		r4,4(r3)
			li		r4,0x1111
			li		r3,30
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r8
			mr		r4,r5
			mr		r5,r7
			mtlr	r11
#endif
			mfsprg	r9,2						; Get feature flags 
			mfmsr	r0							/* Save the MSR  */
			andi.	r5,r5,0x0078				/* Clean up the WIMG */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r9						; Set the features			
			rlwimi	r5,r4,0,30,31				/* Move the protection into the wimg register */
			la		r6,pepte1(r3)				/* Point to the default pte */
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */

			bt		pfNoMSRirb,hpaNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hpaNoMSRx
			
hpaNoMSR:	
			mr		r10,r0
			mr		r4,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r4
			mr		r0,r10
hpaNoMSRx:

atmattr:	lwarx	r10,0,r6					/* Get the pte */
			rlwimi	r10,r5,0,25,31				/* Move in the new attributes */
			stwcx.	r10,0,r6					/* Try it on for size */
			bne-	atmattr						/* Someone else was trying, try again... */
		
			mtmsr	r0							/* Interrupts and translation back on */
			isync
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r10
			li		r3,31
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mtlr	r11
#endif
			blr									/* All done... */



/*
 *			handlePF - handle a page fault interruption
 *
 *			If the fault can be handled, this routine will RFI directly,
 *			otherwise it will return with all registers as in entry.
 *
 *			Upon entry, state and all registers have been saved in savearea.
 *			This is pointed to by R13.
 *			IR and DR are off, interrupts are masked,
 *			Floating point be disabled.
 *			R3 is the interrupt code.
 *
 *			If we bail, we must restore cr5, and all registers except 6 and
 *			3.
 *
 */
	
			.align	5
			.globl	EXT(handlePF)

LEXT(handlePF)

/*
 *			This first part does a quick check to see if we can handle the fault.
 *			We can't handle any kind of protection exceptions here, so we pass
 *			them up to the next level.
 *
 *			The mapping lists are kept in MRS (most recently stolen)
 *			order on queues anchored within from the
 *			PTEG to which the virtual address hashes.  This is further segregated by
 *			the low-order 3 bits of the VSID XORed with the segment number and XORed
 *			with bits 4-7 of the vaddr in an attempt to keep the searches
 *			short.
 *			
 *			MRS is handled by moving the entry to the head of its list when stolen in the
 *			assumption that it will be revalidated soon.  Entries are created on the head 
 *			of the list because they will be used again almost immediately.
 *
 *			We need R13 set to the savearea, R3 set to the interrupt code, and R2
 *			set to the per_proc.
 *
 *			NOTE: In order for a page-fault redrive to work, the translation miss
 *			bit must be set in the DSISR (or SRR1 for IFETCH).  That must occur
 *			before we come here.
 */

			cmplwi	r3,T_INSTRUCTION_ACCESS		/* See if this is for the instruction */
			lwz		r8,savesrr1(r13)			; Get the MSR to determine mode
			beq-	gotIfetch					; We have an IFETCH here...
			
			lwz		r7,savedsisr(r13)			/* Get the DSISR */
			lwz		r6,savedar(r13)				/* Get the fault address */
			b		ckIfProt					; Go check if this is a protection fault...

gotIfetch:	mr		r7,r8						; IFETCH info is in SRR1
			lwz		r6,savesrr0(r13)			/* Get the instruction address */

ckIfProt:	rlwinm.	r7,r7,0,1,1					; Is this a protection exception?
			beqlr-								; Yes... (probably not though)

/*
 *			We will need to restore registers if we bail after this point.
 *			Note that at this point several SRs have been changed to the kernel versions.
 *			Therefore, for these we must build these values.
 */

#if PERFTIMES && DEBUG
			mflr	r11
			mr		r5,r6
			mr		r4,r3
			li		r3,32
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
			mfsprg	r2,0
#endif
			lwz		r3,PP_USERPMAP(r2)			; Get the user pmap (not needed if kernel access, but optimize for user??)
			rlwinm.	r8,r8,0,MSR_PR_BIT,MSR_PR_BIT	; Supervisor state access?
			rlwinm	r5,r6,6,26,29				; Get index to the segment slot
			eqv		r1,r1,r1					; Fill the bottom with foxes
			bne+	notsuper					; Go do the user mode interrupt stuff...
			
			cmplwi	cr1,r5,SR_COPYIN_NUM*4		; See if this is the copyin/copyout segment
			rlwinm	r3,r6,24,8,11				; Make the kernel VSID
			bne+	cr1,havevsid				; We are done if we do not want the copyin/out guy...
			
			mfsr	r3,SR_COPYIN				; Get the copy vsid
			b		havevsid					; Join up...

			.align	5

notsuper:	addi	r5,r5,PMAP_SEGS				; Get offset to table
			lwzx	r3,r3,r5					; Get the VSID

havevsid:	mfspr	r5,sdr1						/* Get hash table base and size */
			cror	cr1_eq,cr0_eq,cr0_eq		; Remember if kernel fault for later
			rlwinm	r9,r6,2,2,5					; Move nybble 1 up to 0 (keep aligned with VSID)
			rlwimi	r1,r5,16,0,15				/* Make table size -1 out of mask */
			rlwinm	r3,r3,6,2,25				/* Position the space for the VSID */
			rlwinm	r7,r6,26,10,25				/* Isolate the page index */
			xor		r9,r9,r3					; Splooch vaddr nybble 0 (from VSID) and 1 together
			or		r8,r5,r1					/* Point to the last byte in table */
			xor		r7,r7,r3					/* Get primary hash */
			rlwinm	r3,r3,1,1,24				/* Position VSID for pte ID */
			addi	r8,r8,1						/* Point to the PTEG Control Area */
			rlwinm	r9,r9,8,27,29				; Get splooched bits in place
			and		r7,r7,r1					/* Wrap the hash */
			rlwimi	r3,r6,10,26,31				/* Move API into pte ID */
			add		r8,r8,r7					/* Point to our PCA entry */
			rlwinm	r12,r3,27,27,29				; Get low 3 bits of the VSID for look-aside hash
			la		r11,PCAhash(r8)				/* Point to the mapping hash area */
			xor		r9,r9,r12					; Finish splooching nybble 0, 1, and the low bits of the VSID


/*
 *			We have about as much as we need to start searching the autogen (aka block maps)
 *			and mappings.  From here on, any kind of failure will bail, and
 *			contention will either bail or restart from here.
 *
 *			
 */
			
			li		r12,1						/* Get the locked value */
			dcbt	0,r11						/* We'll need the hash area in a sec, so get it */
			add		r11,r11,r9					/* Point to the right mapping hash slot */
			
			lwarx	r10,0,r8					; ?
ptegLck:	lwarx	r10,0,r8					/* Get the PTEG lock */
			mr.		r10,r10						/* Is it locked? */
			bne-	ptegLckw					/* Yeah... */
			stwcx.	r12,0,r8					/* Take take it */
			bne-	ptegLck						/* Someone else was trying, try again... */
			b		ptegSXg						/* All done... */
			
			.align	4

ptegLckw:	mr.		r10,r10						/* Check if it's already held */
			beq+	ptegLck						/* It's clear... */
			lwz		r10,0(r8)					/* Get lock word again... */
			b		ptegLckw					/* Wait... */
			
			.align	5
			
			nop									; Force ISYNC to last instruction in IFETCH
			nop									
			nop

ptegSXg:	isync								/* Make sure we haven't used anything yet */

			lwz		r9,0(r11)					/* Pick up first mapping block */
			mr		r5,r11						/* Get the address of the anchor */
			mr		r7,r9						/* Save the first in line */
			b		findmap						; Take space and force loop to cache line
		
findmap:	mr.		r12,r9						/* Are there more? */
			beq-	tryAuto						/* Nope, nothing in mapping list for us... */
			
			lwz		r10,mmPTEv(r12)				/* Get unique PTE identification */
			lwz		r9,mmhashnext(r12)			/* Get the chain, just in case */
			cmplw	r10,r3						/* Did we hit our PTE? */
 			lwz		r0,mmPTEent(r12)			/* Get the pointer to the hash table entry */
			mr		r5,r12						/* Save the current as previous */
			bne-	findmap						; Nothing here, try the next...

;			Cache line boundary here

			cmplwi	cr1,r0,0					/* Is there actually a PTE entry in the hash? */
			lwz		r2,mmphysent(r12)			/* Get the physical entry */
			bne-	cr1,MustBeOK				/* There's an entry in the hash table, so, this must 
												   have been taken care of already... */
			lis		r4,0x8000					; Tell PTE inserter that this was not an auto
			cmplwi	cr2,r2,0					/* Is there a physical entry? */
			li		r0,0x0100					/* Force on the reference bit whenever we make a PTE valid */
			bne+	cr2,gotphys					/* Skip down if we have a physical entry */
			li		r0,0x0180					/* When there is no physical entry, force on
												   both R and C bits to keep hardware from
												   updating the PTE to set them.  We don't
												   keep track of RC for I/O areas, so this is ok */
			
gotphys:	lwz		r2,mmPTEr(r12)				; Get the second part of the PTE
			b		insert						/* Go insert into the PTEG... */

MustBeOK:	li		r10,0						/* Get lock clear value */
			li		r3,T_IN_VAIN				/* Say that we handled it */
			stw		r10,PCAlock(r8)				/* Clear the PTEG lock */
			sync
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,33
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									/* Blow back and handle exception */


			
/*
 *			We couldn't find it in the mapping list.  As a last try, we will
 *			see if we can autogen it from the block mapped list.
 *	
 *			A block mapped area is defined as a contiguous virtual area that is mapped to 
 *			a contiguous physical area.  The olde-tyme IBM VM/XA Interpretive Execution
 *			architecture referred to this as a V=F, or Virtual = Fixed area. 
 *
 *			We consider a V=F area to be a single entity, adjacent areas can not be merged
 *			or overlapped.  The protection and memory attributes are the same and reference
 *			and change indications are not kept. The areas are not considered part of the
 *			physical RAM of the machine and do not have any associated physical table
 *			entries. Their primary use is intended for mapped I/O areas (e.g., framebuffers)
 *			although certain areas of RAM, such as the kernel V=R memory, can be mapped.
 *
 *			We also have a problem in the case of copyin/out: that access is done
 *			within the kernel for a user address. Unfortunately, the user isn't
 *			necessarily the current guy.  That means that we don't have access to the
 *			right autogen list. We can't support this kind of access. So, we need to do
 *			a quick check here and cause a fault if an attempt to copyin or out to
 *			any autogenned area.
 *
 *			The lists must be kept short.
 *
 *			NOTE:  kernel_pmap_store must be in V=R storage!!!!!!!!!!!!!!
 */
 
			.align	5

tryAuto:	rlwinm.	r11,r3,0,5,24				; Check if this is a kernel VSID
			lis		r10,HIGH_ADDR(EXT(kernel_pmap_store)+PMAP_BMAPS)	; Get the top part of kernel block map anchor
			crandc	cr0_eq,cr1_eq,cr0_eq		; Set if kernel access and non-zero VSID (copyin or copyout)
			mfsprg	r11,0						; Get the per_proc area
			beq-	cr0,realFault					; Can not autogen for copyin/copyout...
			ori		r10,r10,LOW_ADDR(EXT(kernel_pmap_store)+PMAP_BMAPS)	; Get the bottom part
			beq-	cr1,bmInKernel				; We are in kernel... (cr1 set way back at entry)
			
			lwz		r10,PP_USERPMAP(r11)		; Get the user pmap
			la		r10,PMAP_BMAPS(r10)			; Point to the chain anchor
			b		bmInKernel					; Jump over alignment gap...
			nop
			nop
			nop
			nop
			nop
			nop						
bmInKernel:
#ifndef CHIP_ERRATA_MAX_V1
			lwarx	r9,0,r10	
#endif /* CHIP_ERRATA_MAX_V1 */

bmapLck:	lwarx	r9,0,r10					; Get the block map anchor and lock
			rlwinm.	r5,r9,0,31,31				; Is it locked?
			ori		r5,r5,1						; Set the lock
			bne-	bmapLckw					; Yeah...
			stwcx.	r5,0,r10					; Lock the bmap list
			bne-	bmapLck						; Someone else was trying, try again...
			b		bmapSXg						; All done...
			
			.align	4

bmapLckw:	rlwinm.	r5,r9,0,31,31				; Check if it is still held
			beq+	bmapLck						; Not no more...
			lwz		r9,0(r10)					; Get lock word again...
			b		bmapLckw					; Check it out...
			
			.align	5
			
			nop									; Force ISYNC to last instruction in IFETCH
			nop									
			nop

bmapSXg:	rlwinm.	r4,r9,0,0,26				; Clear out flags and lock
			isync								; Make sure we have not used anything yet
			bne+	findAuto					; We have something, let us go...
			
bmapNone:	stw		r9,0(r10)					; Unlock it, we have nothing here
												; No sync here because we have not changed anything
			
/*
 *			When we come here, we know that we can't handle this.  Restore whatever
 *			state that we trashed and go back to continue handling the interrupt.
 */

realFault:	li		r10,0						/* Get lock clear value */
			lwz		r3,saveexception(r13)		/* Figure out the exception code again */
			stw		r10,PCAlock(r8)				/* Clear the PTEG lock */
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,33
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									/* Blow back and handle exception */
			
			.align	5
			
findAuto:	mr.		r4,r4						; Is there more?
			beq-	bmapNone					; No more...
			lwz		r5,bmstart(r4)				; Get the bottom of range
			lwz		r11,bmend(r4)				; Get the top of range
			cmplw	cr0,r6,r5					; Are we before the entry?
			cmplw	cr1,r6,r11					; Are we after the entry?
			cror	cr1_eq,cr0_lt,cr1_gt		; Set cr1_eq if new not in range
			bne+	cr1,faGot					; Found it...
			
			lwz		r4,bmnext(r4)				; Get the next one
			b		findAuto					; Check it out...
			
faGot:		rlwinm	r6,r6,0,0,19				; Round to page
			lwz		r2,bmPTEr(r4)				; Get the real part of the PTE
			sub		r5,r6,r5					; Get offset into area
			stw		r9,0(r10)					; Unlock it, we are done with it (no sync needed)
			add		r2,r2,r5					; Adjust the real address
			
			lis		r4,0x8080					/* Indicate that this was autogened */
			li		r0,0x0180					/* Autogenned areas always set RC bits.
												   This keeps the hardware from having
												   to do two storage writes */
			
/*
 *			Here where we insert the PTE into the hash.  The PTE image is in R3, R2. 
 *			The PTEG allocation controls are a bit map of the state of the PTEG. The
 *			PCAlock bits are a temporary lock for the specified PTE.  PCAfree indicates that
 *			the PTE slot is empty. PCAauto means that it comes from an autogen area.  These
 *			guys do not keep track of reference and change and are actually "wired".
 *			They're easy to maintain. PCAsteal
 *			is a sliding position mask used to "randomize" PTE slot stealing.  All 4 of these
 *			fields fit in a single word and are loaded and stored under control of the
 *			PTEG control area lock (PCAlock).
 *
 *			Note that PCAauto does not contribute to the steal calculations at all.  Originally
 *			it did, autogens were second in priority.  This can result in a pathalogical
 *			case where an instruction can not make forward progress, or one PTE slot
 *			thrashes.
 *
 *			Physically, the fields are arranged:
 *				0: PCAfree
 *				1: PCAauto
 *				2: PCAlock
 *				3: PCAsteal
 */
			
insert:		lwz		r10,PCAallo(r8)				/* Get the PTEG controls */
			eqv		r6,r6,r6					/* Get all ones */		
			mr		r11,r10						/* Make a copy */
			rlwimi	r6,r10,8,16,23				/* Insert sliding steal position */
			rlwimi	r11,r11,24,24,31			/* Duplicate the locked field */
			addi	r6,r6,-256					/* Form mask */
			rlwimi	r11,r11,16,0,15				/* This gives us a quadrupled lock mask */
			rlwinm	r5,r10,31,24,0				/* Slide over the mask for next time */
			mr		r9,r10						/* Make a copy to test */
			not		r11,r11						/* Invert the quadrupled lock */
			or		r2,r2,r0					/* Force on R, and maybe C bit */
			and		r9,r9,r11					/* Remove the locked guys */
			rlwimi	r5,r5,8,24,24				/* Wrap bottom bit to top in mask */
			rlwimi	r9,r11,0,16,31				/* Put two copies of the unlocked entries at the end */
			rlwinm	r6,r6,0,16,7				; Remove the autogens from the priority calculations
			rlwimi	r10,r5,0,24,31				/* Move steal map back in */
			and		r9,r9,r6					/* Set the starting point for stealing */

/*			So, now we have in R9:
				byte 0 = ~locked & free 
				byte 1 = 0 
				byte 2 = ~locked & (PCAsteal - 1)
				byte 3 = ~locked

				Each bit position represents (modulo 8) a PTE. If it is 1, it is available for 
				allocation at its priority level, left to right.  
				
			Additionally, the PCA steal field in R10 has been rotated right one bit.
*/
			

			rlwinm	r21,r10,8,0,7				; Isolate just the old autogen bits
			cntlzw	r6,r9						/* Allocate a slot */
			mr		r14,r12						/* Save our mapping for later */
			cmplwi	r6,32						; Was there anything available?
			rlwinm	r7,r6,29,30,31				/* Get the priority slot we got this from */
			rlwinm	r6,r6,0,29,31				; Isolate bit position
			srw		r11,r4,r6					/* Position the PTEG control bits */
			slw		r21,r21,r6					; Move corresponding old autogen flag to bit 0
			mr		r22,r11						; Get another copy of the selected slot
			
			beq-	realFault					/* Arghh, no slots! Take the long way 'round... */
			
												/* Remember, we've already set up the mask pattern
												   depending upon how we got here:
												     if got here from simple mapping, R4=0x80000000,
												     if we got here from autogen it is 0x80800000. */
			
			rlwinm	r6,r6,3,26,28				/* Start calculating actual PTE address */
			rlwimi	r22,r22,24,8,15				; Duplicate selected slot in second byte
			rlwinm.	r11,r11,0,8,15				/* Isolate just the auto bit (remember about it too) */
			andc	r10,r10,r22					/* Turn off the free and auto bits */
			add		r6,r8,r6					/* Get position into PTEG control area */
 			cmplwi	cr1,r7,1					/* Set the condition based upon the old PTE type */
			sub		r6,r6,r1					/* Switch it to the hash table */
			or		r10,r10,r11					/* Turn auto on if it is (PTEG control all set up now) */			
			subi	r6,r6,1						/* Point right */
			stw		r10,PCAallo(r8)				/* Allocate our slot */
			dcbt	br0,r6						; Touch in the PTE
			bne		wasauto						/* This was autogenned... */
			
			stw		r6,mmPTEent(r14)			/* Link the mapping to the PTE slot */
			
/*
 *			So, now we're here and what exactly do we have?  We've got: 
 *				1)	a full PTE entry, both top and bottom words in R3 and R2
 *				2)	an allocated slot in the PTEG.
 *				3)	R8 still points to the PTEG Control Area (PCA)
 *				4)	R6 points to the PTE entry.
 *				5)	R1 contains length of the hash table-1. We use this to back-translate
 *					a PTE to a virtual address so we can invalidate TLBs.
 *				6)	R11 has a copy of the PCA controls we set.
 *				7a)	R7 indicates what the PTE slot was before we got to it. 0 shows
 *					that it was empty and 2 or 3, that it was
 *					a we've stolen a live one. CR1 is set to LT for empty and GT
 *					otherwise.
 *				7b)	Bit 0 of R21 is 1 if the stolen PTE was autogenned
 *				8)	So far as our selected PTE, it should be valid if it was stolen
 *					and invalid if not.  We could put some kind of assert here to
 *					check, but I think that I'd rather leave it in as a mysterious,
 *					non-reproducable bug.
 *				9)	The new PTE's mapping has been moved to the front of its PTEG hash list
 *					so that it's kept in some semblance of a MRU list.
 *			   10)	R14 points to the mapping we're adding.
 *
 *			So, what do we have to do yet?
 *				1)	If we stole a slot, we need to invalidate the PTE completely.
 *				2)	If we stole one AND it was not an autogen, 
 *					copy the entire old PTE (including R and C bits) to its mapping.
 *				3)	Set the new PTE in the PTEG and make sure it is valid.
 *				4)	Unlock the PTEG control area.
 *				5)	Go back to the interrupt handler, changing the interrupt
 *					code to "in vain" which will restore the registers and bail out.
 *
 */
wasauto:	oris	r3,r3,0x8000				/* Turn on the valid bit */
			blt+	cr1,slamit					/* It was empty, go slam it on in... */
			
			lwz		r10,0(r6)					/* Grab the top part of the PTE */
			rlwinm	r12,r6,6,4,19				/* Match up the hash to a page boundary */
			rlwinm	r5,r10,5,4,19				/* Extract the VSID to a page boundary */
			rlwinm	r10,r10,0,1,31				/* Make it invalid */
			xor		r12,r5,r12					/* Calculate vaddr */
			stw		r10,0(r6)					/* Invalidate the PTE */
			rlwinm	r5,r10,7,27,29				; Move nybble 0 up to subhash position
			rlwimi	r12,r10,1,0,3				/* Move in the segment portion */
			lis		r9,HIGH_ADDR(EXT(tlb_system_lock))	/* Get the TLBIE lock */
			xor		r5,r5,r10					; Splooch nybble 0 and 1
			rlwimi	r12,r10,22,4,9				/* Move in the API */
			ori		r9,r9,LOW_ADDR(EXT(tlb_system_lock))	/* Grab up the bottom part */
			rlwinm	r4,r10,27,27,29				; Get low 3 bits of the VSID for look-aside hash
			
			sync								/* Make sure the invalid is stored */

			xor		r4,r4,r5					; Finish splooching nybble 0, 1, and the low bits of the VSID
						
			lwarx	r5,0,r9						; ?

tlbhang:	lwarx	r5,0,r9						/* Get the TLBIE lock */
		
			rlwinm	r4,r4,0,27,29				; Clean up splooched hash value

			mr.		r5,r5						/* Is it locked? */
			add		r4,r4,r8					/* Point to the offset into the PCA area */
			li		r5,1						/* Get our lock word */
			bne-	tlbhang						/* It's locked, go wait... */
			
			la		r4,PCAhash(r4)				/* Point to the start of the hash chain for the PTE we're replacing */
			
			stwcx.	r5,0,r9						/* Try to get it */
			bne-	tlbhang						/* We was beat... */
			
			mfspr	r7,pvr						/* Find out what kind of machine we are */
			li		r5,0						/* Lock clear value */
			rlwinm	r7,r7,16,16,31				/* Isolate CPU type */

			tlbie	r12							/* Invalidate it everywhere */

			cmplwi	r7,3						/* Is this a 603? */
			stw		r5,0(r9)					/* Clear the lock */
			
			beq-	its603						/* It's a 603, skip the tlbsync... */
			
			eieio								/* Make sure that the tlbie happens first */
			tlbsync								/* wait for everyone to catch up */
			isync								
			
its603:		rlwinm.	r21,r21,0,0,0				; See if we just stole an autogenned entry
			sync								/* Make sure of it all */

			bne		slamit						; The old was an autogen, time to slam the new in...
			
			lwz		r9,4(r6)					/* Get the real portion of old PTE */
			lwz		r7,0(r4)					/* Get the first element.  We can't get to here
												   if we aren't working with a mapping... */
			mr		r0,r7						; Save pointer to first element
												   
findold:	mr		r1,r11						; Save the previous guy
			mr.		r11,r7						/* Copy and test the chain */
			beq-	bebad						/* Assume it's not zero... */
			
			lwz		r5,mmPTEv(r11)				/* See if this is the old active one */
			cmplw	cr2,r11,r14					/* Check if this is actually the new one */
			cmplw	r5,r10						/* Is this us?  (Note: valid bit kept off in mappings) */
			lwz		r7,mmhashnext(r11)			/* Get the next one in line */
			beq-	cr2,findold					/* Don't count the new one... */
			cmplw	cr2,r11,r0					; Check if we are first on the list
			bne+	findold						/* Not it (and assume the worst)... */
			
			lwz		r12,mmphysent(r11)			/* Get the pointer to the physical entry */
			beq-	cr2,nomove					; We are first, no need to requeue...

			stw		r11,0(r4)					; Chain us to the head
			stw		r0,mmhashnext(r11)			; Chain the old head to us
			stw		r7,mmhashnext(r1)			; Unlink us

nomove:		li		r5,0						/* Clear this on out */
			
			mr.		r12,r12						/* Is there a physical entry? */
			stw		r5,mmPTEent(r11)			; Clear the PTE entry pointer
			li		r5,pepte1					/* Point to the PTE last half */
			stw		r9,mmPTEr(r11)				; Squirrel away the whole thing (RC bits are in here)
			
			beq-	mrgmrcx						; No physical entry for this one...
			
			rlwinm	r11,r9,0,23,24				/* Keep only the RC bits */

			lwarx	r9,r5,r12					; ?

mrgmrcx:	lwarx	r9,r5,r12					/* Get the master copy */
			or		r9,r9,r11					/* Merge in latest RC */
			stwcx.	r9,r5,r12					/* Save it back */
			bne-	mrgmrcx						/* If it changed, try again... */

/*
 *			Here's where we finish up.  We save the real part of the PTE, eieio it, to make sure it's
 *			out there before the top half (with the valid bit set).
 */

slamit:		stw		r2,4(r6)					/* Stash the real part */
			li		r4,0						/* Get a lock clear value */
			eieio								/* Erect a barricade */
			stw		r3,0(r6)					/* Stash the virtual part and set valid on */

			stw		r4,PCAlock(r8)				/* Clear the PCA lock */

			li		r3,T_IN_VAIN				/* Say that we handled it */
			sync								/* Go no further until the stores complete */
#if PERFTIMES && DEBUG
			mflr	r11
			mr		r4,r3
			li		r3,33
			bl		EXT(dbgLog2)						; Start of hw_add_map
			mr		r3,r4
			mtlr	r11
#endif
			blr									/* Back to the fold... */
					
bebad:		lis		r0,HIGH_ADDR(Choke)			/* We have a kernel choke!!! */
			ori		r0,r0,LOW_ADDR(Choke)				
			sc									/* Firmware Heimlich maneuver */
			
/*
 *			This walks the hash table or DBATs to locate the physical address of a virtual one.
 *			The space is provided.  If it is the kernel space, the DBATs are searched first.  Failing
 *			that, the hash table is accessed. Zero is returned for failure, so it must be special cased.
 *			This is usually used for debugging, so we try not to rely
 *			on anything that we don't have to.
 */

ENTRY(LRA, TAG_NO_FRAME_USED)

			mfsprg	r8,2						; Get feature flags 
			mfmsr	r10							/* Save the current MSR */
			mtcrf	0x04,r8						; Set the features			
			xoris	r5,r3,HIGH_ADDR(PPC_SID_KERNEL)		/* Clear the top half if equal */
			andi.	r9,r10,0x7FCF				/* Turn off interrupts and translation */
			eqv		r12,r12,r12					/* Fill the bottom with foxes */

			bt		pfNoMSRirb,lraNoMSR			; No MSR...

			mtmsr	r9							; Translation and all off
			isync								; Toss prefetch
			b		lraNoMSRx
			
lraNoMSR:	
			mr		r7,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r9						; Get new MSR
			sc									; Set it
			mr		r3,r7
lraNoMSRx:

			cmplwi	r5,LOW_ADDR(PPC_SID_KERNEL)	/* See if this is kernel space */
			rlwinm	r11,r3,6,6,25				/* Position the space for the VSID */
			isync								/* Purge pipe */
			bne-	notkernsp					/* This is not for the kernel... */		
			
			mfspr	r5,dbat0u					/* Get the virtual address and length */
			eqv		r8,r8,r8					/* Get all foxes */
			rlwinm.	r0,r5,0,30,30				/* Check if valid for supervisor state */
			rlwinm	r7,r5,0,0,14				/* Clean up the base virtual address */
			beq-	ckbat1						/* not valid, skip this one... */
			sub		r7,r4,r7					/* Subtract out the base */
			rlwimi	r8,r5,15,0,14				/* Get area length - 1 */
			mfspr	r6,dbat0l					/* Get the real part */
			cmplw	r7,r8						/* Check if it is in the range */
			bng+	fndbat						/* Yup, she's a good un... */

ckbat1:		mfspr	r5,dbat1u					/* Get the virtual address and length */			
			eqv		r8,r8,r8					/* Get all foxes */
			rlwinm.	r0,r5,0,30,30				/* Check if valid for supervisor state */
			rlwinm	r7,r5,0,0,14				/* Clean up the base virtual address */
			beq-	ckbat2						/* not valid, skip this one... */
			sub		r7,r4,r7					/* Subtract out the base */
			rlwimi	r8,r5,15,0,14				/* Get area length - 1 */
			mfspr	r6,dbat1l					/* Get the real part */
			cmplw	r7,r8						/* Check if it is in the range */
			bng+	fndbat						/* Yup, she's a good un... */
			
ckbat2:		mfspr	r5,dbat2u					/* Get the virtual address and length */
			eqv		r8,r8,r8					/* Get all foxes */
			rlwinm.	r0,r5,0,30,30				/* Check if valid for supervisor state */
			rlwinm	r7,r5,0,0,14				/* Clean up the base virtual address */
			beq-	ckbat3						/* not valid, skip this one... */
			sub		r7,r4,r7					/* Subtract out the base */
			rlwimi	r8,r5,15,0,14				/* Get area length - 1 */
			mfspr	r6,dbat2l					/* Get the real part */
			cmplw	r7,r8						/* Check if it is in the range */
			bng-	fndbat						/* Yup, she's a good un... */
			
ckbat3:		mfspr	r5,dbat3u					/* Get the virtual address and length */
			eqv		r8,r8,r8					/* Get all foxes */
			rlwinm.	r0,r5,0,30,30				/* Check if valid for supervisor state */
			rlwinm	r7,r5,0,0,14				/* Clean up the base virtual address */
			beq-	notkernsp					/* not valid, skip this one... */
			sub		r7,r4,r7					/* Subtract out the base */
			rlwimi	r8,r5,15,0,14				/* Get area length - 1 */
			mfspr	r6,dbat3l					/* Get the real part */
			cmplw	r7,r8						/* Check if it is in the range */
			bgt+	notkernsp					/* No good... */
			
fndbat:		rlwinm	r6,r6,0,0,14				/* Clean up the real address */
			mtmsr	r10							/* Restore state */
			add		r3,r7,r6					/* Relocate the offset to real */
			isync								/* Purge pipe */
			blr									/* Bye, bye... */
notkernsp:	mfspr	r5,sdr1						/* Get hash table base and size */
			rlwimi	r11,r4,30,2,5				/* Insert the segment no. to make a VSID */
			rlwimi	r12,r5,16,0,15				/* Make table size -1 out of mask */
			rlwinm	r7,r4,26,10,25				/* Isolate the page index */
			andc	r5,r5,r12					/* Clean up the hash table */
			xor		r7,r7,r11					/* Get primary hash */
			rlwinm	r11,r11,1,1,24				/* Position VSID for pte ID */
			and		r7,r7,r12					/* Wrap the hash */
			rlwimi	r11,r4,10,26,31				/* Move API into pte ID */
			add		r5,r7,r5					/* Point to the PTEG */
			oris	r11,r11,0x8000				/* Slam on valid bit so's we don't match an invalid one */

			li		r9,8						/* Get the number of PTEs to check */
			lwz		r6,0(r5)					/* Preload the virtual half */
			
fndpte:		subi	r9,r9,1						/* Count the pte */
			lwz		r3,4(r5)					/* Get the real half */
			cmplw	cr1,r6,r11					/* Is this what we want? */
			lwz		r6,8(r5)					/* Start to get the next virtual half */
			mr.		r9,r9						/* Any more to try? */
			addi	r5,r5,8						/* Bump to next slot */
			beq		cr1,gotxlate				/* We found what we were looking for... */
			bne+	fndpte						/* Go try the next PTE... */
			
			mtmsr	r10							/* Restore state */
			li		r3,0						/* Show failure */
			isync								/* Purge pipe */
			blr									/* Leave... */

gotxlate:	mtmsr	r10							/* Restore state */
			rlwimi	r3,r4,0,20,31				/* Cram in the page displacement */
			isync								/* Purge pipe */
			blr									/* Return... */



/*
 *			struct blokmap *hw_add_blk(pmap_t pmap, struct blokmap *bmr)
 *	
 *			This is used to add a block mapping entry to the MRU list whose top
 *			node is anchored at bmaps.  This is a real address and is also used as
 *			the lock.
 *
 *			Overlapping areas are not allowed.  If we find one, we return it's address and
 *			expect the upper layers to panic.  We only check this for a debug build...
 *
 */

			.align	5
			.globl	EXT(hw_add_blk)

LEXT(hw_add_blk)

 			mfsprg	r9,2						; Get feature flags 
			lwz		r6,PMAP_PMAPVR(r3)			; Get the v to r translation
			mfmsr	r0							/* Save the MSR  */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r9						; Set the features			
			xor		r3,r3,r6					; Get real address of bmap anchor
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */
			la		r3,PMAP_BMAPS(r3)			; Point to bmap header
			
			bt		pfNoMSRirb,habNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		habNoMSRx
			
habNoMSR:	
			mr		r9,r0
			mr		r8,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r8
			mr		r0,r9
habNoMSRx:
			
abLck:		lwarx	r9,0,r3						; Get the block map anchor and lock
			rlwinm.	r8,r9,0,31,31				; Is it locked?
			ori		r8,r9,1						; Set the lock
			bne-	abLckw						; Yeah...
			stwcx.	r8,0,r3						; Lock the bmap list
			bne-	abLck						; Someone else was trying, try again...
			b		abSXg						; All done...
			
			.align	4

abLckw:		rlwinm.	r5,r9,0,31,31				; Check if it is still held
			beq+	abLck						; Not no more...
			lwz		r9,0(r3)					; Get lock word again...
			b		abLckw						; Check it out...
			
			.align	5
			
			nop									; Force ISYNC to last instruction in IFETCH
			nop									

abSXg:		rlwinm	r11,r9,0,0,26				; Clear out flags and lock
			isync								; Make sure we have not used anything yet

;
;
;

			lwz		r7,bmstart(r4)				; Get start
			lwz		r8,bmend(r4)				; Get end		
			mr		r2,r11						; Get chain
	
abChk:		mr.		r10,r2						; End of chain?
			beq		abChkD						; Yes, chain is ok...
			lwz		r5,bmstart(r10)				; Get start of current area
			lwz		r6,bmend(r10)				; Get end of current area
			
			cmplw	cr0,r8,r5					; Is the end of the new before the old?
			cmplw	cr1,r8,r6					; Is the end of the new after the old?
			cmplw	cr6,r6,r7					; Is the end of the old before the new?
			cror	cr1_eq,cr0_lt,cr1_gt		; Set cr1_eq if new not in old
			cmplw	cr7,r6,r8					; Is the end of the old after the new?
			lwz		r2,bmnext(r10)				; Get pointer to the next
			cror	cr6_eq,cr6_lt,cr7_gt		; Set cr2_eq if old not in new
			crand	cr1_eq,cr1_eq,cr6_eq		; Set cr1_eq if no overlap
			beq+	cr1,abChk					; Ok check the next...
			
			stw		r9,0(r3)					; Unlock
			mtmsr	r0							; Restore xlation and rupts
			mr		r3,r10						; Pass back the overlap
			isync								;  
			blr									; Return...

abChkD:		stw		r11,bmnext(r4)				; Chain this on in
			rlwimi	r4,r9,0,27,31				; Copy in locks and flags
			sync								; Make sure that is done
			
			stw		r4,0(r3)					; Unlock and chain the new first one
			mtmsr	r0							; Restore xlation and rupts
			li		r3,0						; Pass back a no failure return code
			isync
			blr									; Return...


/*
 *			struct blokmap *hw_rem_blk(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
 *	
 *			This is used to remove a block mapping entry from the list that
 *			is anchored at bmaps.  bmaps is a virtual address and is also used as
 *			the lock.
 *
 *			Note that this function clears a single block that contains
 *			any address within the range sva to eva (inclusive).  To entirely
 *			clear any range, hw_rem_blk must be called repeatedly until it
 *			returns a 0.
 *
 *			The block is removed from the list and all hash table entries
 *			corresponding to the mapped block are invalidated and the TLB
 *			entries are purged.  If the block is large, this could take
 *			quite a while. We need to hash every possible address in the
 *			range and lock down the PCA.
 *
 *			If we attempt to remove a permanent entry, we will not do it.
 *			The block address will be ored with 1 and returned.
 *
 *
 */

			.align	5
			.globl	EXT(hw_rem_blk)

LEXT(hw_rem_blk)

  			mfsprg	r9,2						; Get feature flags
			lwz		r6,PMAP_PMAPVR(r3)			; Get the v to r translation
			mfmsr	r0							/* Save the MSR  */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r9						; Set the features			
			xor		r3,r3,r6					; Get real address of bmap anchor
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */
			la		r3,PMAP_BMAPS(r3)			; Point to the bmap chain head

			bt		pfNoMSRirb,hrbNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hrbNoMSRx
			
hrbNoMSR:	
			mr		r9,r0
			mr		r8,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r8
			mr		r0,r9
hrbNoMSRx:

rbLck:		lwarx	r9,0,r3						; Get the block map anchor and lock
			rlwinm.	r8,r9,0,31,31				; Is it locked?
			ori		r8,r9,1						; Set the lock
			bne-	rbLckw						; Yeah...
			stwcx.	r8,0,r3						; Lock the bmap list
			bne-	rbLck						; Someone else was trying, try again...
			b		rbSXg						; All done...
			
			.align	4

rbLckw:		rlwinm.	r11,r9,0,31,31				; Check if it is still held
			beq+	rbLck						; Not no more...
			lwz		r9,0(r3)					; Get lock word again...
			b		rbLckw						; Check it out...
			
			.align	5
			
			nop									; Force ISYNC to last instruction in IFETCH
			nop									

rbSXg:		rlwinm.	r2,r9,0,0,26				; Clear out flags and lock
			mr		r10,r3						; Keep anchor as previous pointer
			isync								; Make sure we have not used anything yet
			
			beq-	rbMT						; There is nothing in the list
			
rbChk:		mr		r12,r10						; Save the previous
			mr.		r10,r2						; End of chain?
			beq		rbMT						; Yes, nothing to do...
			lwz		r11,bmstart(r10)			; Get start of current area
			lwz		r6,bmend(r10)				; Get end of current area
			
			cmplw	cr0,r5,r11					; Is the end of range before the start of the area?
			cmplw	cr1,r4,r6					; Is the start of range after the end of the area?
			cror	cr1_eq,cr0_lt,cr1_gt		; Set cr1_eq if new not in range
			lwz		r2,bmnext(r10)				; Get the next one
			beq+	cr1,rbChk					; Not this one, check the next...
		
			lwz		r8,blkFlags(r10)			; Get the flags
			
			cmplw	cr1,r12,r3					; Did we delete the first one?
			rlwinm.	r8,r8,0,blkPermbit,blkPermbit	; is this a permanent block?
			bne		cr1,rbnFirst				; Nope...
			rlwimi	r9,r2,0,0,26				; Change the lock value
			ori		r2,r9,1						; Turn on the lock bit
			
rbnFirst:	bne-	rbPerm						; This is permanent, do not remove...
			lwz		r8,bmspace(r10)				; Get the VSID
			stw		r2,bmnext(r12)				; Unchain us
			
			eqv		r4,r4,r4					; Fill the bottom with foxes
			mfspr	r12,sdr1					; Get hash table base and size
			rlwinm	r8,r8,6,0,25				; Align VSID to PTEG
			rlwimi	r4,r12,16,0,15				; Make table size - 1 out of mask
			andc	r12,r12,r4					; Clean up address of hash table
			rlwinm	r5,r11,26,6,25				; Rotate virtual start address into PTEG units
			add		r12,r12,r4					; Point to PCA - 1
			rlwinm	r6,r6,26,6,25				; Rotate virtual end address into PTEG units
			addi	r12,r12,1					; Point to PCA base
			sub		r6,r6,r5					; Get the total number of PTEGs to clear
			cmplw	r6,r4						; See if this wraps all the way around
			blt		rbHash						; Nope, length is right
			subi	r6,r4,32+31					; Back down to correct length
			
rbHash:		rlwinm	r5,r5,0,10,25				; Keep only the page index
			xor		r2,r8,r5					; Hash into table
			and		r2,r2,r4					; Wrap into the table
			add		r2,r2,r12					; Point right at the PCA

rbLcka:		lwarx	r7,0,r2						; Get the PTEG lock
			mr.		r7,r7						; Is it locked?
			bne-	rbLckwa						; Yeah...
			li		r7,1						; Get the locked value
			stwcx.	r7,0,r2						; Take it
			bne-	rbLcka						; Someone else was trying, try again...
			b		rbSXga						; All done... 

rbLckwa:	mr.		r7,r7						; Check if it is already held
			beq+	rbLcka						; It is clear...
			lwz		r7,0(r2)					; Get lock word again...
			b		rbLckwa						; Wait...
			
rbSXga:		isync								; Make sure nothing used yet
			lwz		r7,PCAallo(r2)				; Get the allocation word
			rlwinm.	r11,r7,8,0,7				; Isolate the autogenerated PTEs
			or		r7,r7,r11					; Release the autogen slots
			beq+	rbAintNone					; There are not any here
			mtcrf	0xC0,r11					; Set the branch masks for autogens
			sub		r11,r2,r4					; Move back to the hash table + 1
			rlwinm	r7,r7,0,16,7				; Clear the autogen field
			subi	r11,r11,1					; Point to the PTEG
			stw		r7,PCAallo(r2)				; Update the flags
			li		r7,0						; Get an invalid PTE value

			bf		0,rbSlot1					; No autogen here
			stw		r7,0x00(r11)				; Invalidate PTE
rbSlot1:	bf		1,rbSlot2					; No autogen here
			stw		r7,0x08(r11)				; Invalidate PTE
rbSlot2:	bf		2,rbSlot3					; No autogen here
			stw		r7,0x10(r11)				; Invalidate PTE
rbSlot3:	bf		3,rbSlot4					; No autogen here
			stw		r7,0x18(r11)				; Invalidate PTE
rbSlot4:	bf		4,rbSlot5					; No autogen here
			stw		r7,0x20(r11)				; Invalidate PTE
rbSlot5:	bf		5,rbSlot6					; No autogen here
			stw		r7,0x28(r11)				; Invalidate PTE
rbSlot6:	bf		6,rbSlot7					; No autogen here
			stw		r7,0x30(r11)				; Invalidate PTE
rbSlot7:	bf		7,rbSlotx					; No autogen here
			stw		r7,0x38(r11)				; Invalidate PTE
rbSlotx:

rbAintNone:	li		r7,0						; Clear this out
			sync								; To make SMP happy
			addic.	r6,r6,-64					; Decrement the count
			stw		r7,PCAlock(r2)				; Release the PTEG lock
			addi	r5,r5,64					; Move up by adjusted page number
			bge+	rbHash						; Not done...
	
			sync								; Make sure the memory is quiet
			
;
;			Here we take the easy way out and just purge the entire TLB. This is 
;			certainly faster and definitly easier than blasting just the correct ones
;			in the range, we only need one lock and one TLBSYNC. We would hope
;			that most blocks are more than 64 pages (256K) and on every machine
;			up to Book E, 64 TLBIEs will invalidate the entire table.
;

			li		r5,64						; Get number of TLB entries to purge
			lis		r12,HIGH_ADDR(EXT(tlb_system_lock))	; Get the TLBIE lock
			li		r6,0						; Start at 0
			ori		r12,r12,LOW_ADDR(EXT(tlb_system_lock))	; Grab up the bottom part
						
rbTlbL:		lwarx	r2,0,r12					; Get the TLBIE lock
			mr.		r2,r2						; Is it locked?
			li		r2,1						; Get our lock value
			bne-	rbTlbL						; It is locked, go wait...
			stwcx.	r2,0,r12					; Try to get it
			bne-	rbTlbL						; We was beat...
	
rbTlbN:		addic.	r5,r5,-1					; See if we did them all
			tlbie	r6							; Invalidate it everywhere
			addi	r6,r6,0x1000				; Up to the next page
			bgt+	rbTlbN						; Make sure we have done it all...
			
			mfspr	r5,pvr						; Find out what kind of machine we are
			li		r2,0						; Lock clear value
			
			rlwinm	r5,r5,16,16,31				; Isolate CPU type
			cmplwi	r5,3						; Is this a 603?
			sync								; Make sure all is quiet
			beq-	rbits603a					; It is a 603, skip the tlbsync...
			
			eieio								; Make sure that the tlbie happens first
			tlbsync								; wait for everyone to catch up
			isync								

rbits603a:	sync								; Wait for quiet again
			stw		r2,0(r12)					; Unlock invalidates
			
			sync								; Make sure that is done
			
			stw		r9,0(r3)					; Unlock and chain the new first one
			mtmsr	r0							; Restore xlation and rupts
			mr		r3,r10						; Pass back the removed block
			isync
			blr									; Return...
			
rbMT:		stw		r9,0(r3)					; Unlock
			mtmsr	r0							; Restore xlation and rupts
			li		r3,0						; Say we did not find one
			isync
			blr									; Return...
			
rbPerm:		stw		r9,0(r3)					; Unlock
			mtmsr	r0							; Restore xlation and rupts
			ori		r3,r10,1					; Say we did not remove it
			isync
			blr									; Return...


/*
 *			vm_offset_t hw_cvp_blk(pmap_t pmap, vm_offset_t va)
 *	
 *			This is used to translate a virtual address within a block mapping entry
 *			to a physical address.  If not found, 0 is returned.
 *
 */

			.align	5
			.globl	EXT(hw_cvp_blk)

LEXT(hw_cvp_blk)

 			mfsprg	r9,2						; Get feature flags
 			lwz		r6,PMAP_PMAPVR(r3)			; Get the v to r translation
			mfmsr	r0							/* Save the MSR  */
			rlwinm	r12,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
			mtcrf	0x04,r9						; Set the features			
			xor		r3,r3,r6					; Get real address of bmap anchor
			rlwinm	r12,r12,0,28,25				/* Clear IR and DR */
			la		r3,PMAP_BMAPS(r3)			; Point to chain header

			bt		pfNoMSRirb,hcbNoMSR			; No MSR...

			mtmsr	r12							; Translation and all off
			isync								; Toss prefetch
			b		hcbNoMSRx
			
hcbNoMSR:	
			mr		r9,r0
			mr		r8,r3
			li		r0,loadMSR					; Get the MSR setter SC
			mr		r3,r12						; Get new MSR
			sc									; Set it
			mr		r3,r8
			mr		r0,r9
hcbNoMSRx:

cbLck:		lwarx	r9,0,r3						; Get the block map anchor and lock
			rlwinm.	r8,r9,0,31,31				; Is it locked?
			ori		r8,r9,1						; Set the lock
			bne-	cbLckw						; Yeah...
			stwcx.	r8,0,r3						; Lock the bmap list
			bne-	cbLck						; Someone else was trying, try again...
			b		cbSXg						; All done...
			
			.align	4

cbLckw:		rlwinm.	r5,r9,0,31,31				; Check if it is still held
			beq+	cbLck						; Not no more...
			lwz		r9,0(r3)					; Get lock word again...
			b		cbLckw						; Check it out...
			
			.align	5
			
			nop									; Force ISYNC to last instruction in IFETCH
			nop
			nop
			nop
			nop

cbSXg:		rlwinm.	r11,r9,0,0,26				; Clear out flags and lock
			li		r2,0						; Assume we do not find anything			
			isync								; Make sure we have not used anything yet

cbChk:		mr.		r11,r11						; Is there more?
			beq-	cbDone						; No more...
			lwz		r5,bmstart(r11)				; Get the bottom of range
			lwz		r12,bmend(r11)				; Get the top of range
			cmplw	cr0,r4,r5					; Are we before the entry?
			cmplw	cr1,r4,r12					; Are we after of the entry?
			cror	cr1_eq,cr0_lt,cr1_gt		; Set cr1_eq if new not in range
			beq-	cr1,cbNo					; We are not in the range...

			lwz		r2,bmPTEr(r11)				; Get the real part of the PTE
			sub		r5,r4,r5					; Get offset into area
			rlwinm	r2,r2,0,0,19				; Clean out everything but the page
			add		r2,r2,r5					; Adjust the real address

cbDone:		stw		r9,0(r3)					; Unlock it, we are done with it (no sync needed)
			mtmsr	r0							; Restore translation and interrupts...
			isync								; Make sure it is on
			mr		r3,r2						; Set return physical address
			blr									; Leave...
			
			.align	5
			
cbNo:		lwz		r11,bmnext(r11)				; Link next
			b		cbChk						; Check it out...
			
			
/*
 *			hw_set_user_space(pmap) 
 *			hw_set_user_space_dis(pmap) 
 *
 * 			Indicate whether memory space needs to be switched.
 *			We really need to turn off interrupts here, because we need to be non-preemptable
 *
 *			hw_set_user_space_dis is used when interruptions are already disabled. Mind the
 *			register usage here.   The VMM switch code in vmachmon.s that calls this
 *			know what registers are in use.  Check that if these change.
 */


	
			.align	5
			.globl	EXT(hw_set_user_space)

LEXT(hw_set_user_space)

			mfmsr	r10							/* Get the current MSR */
			rlwinm	r9,r10,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Turn off 'rupts */
			mtmsr	r9							/* Disable 'em */
 			lwz		r7,PMAP_PMAPVR(r3)			; Get the v to r translation
			lwz		r4,PMAP_SPACE(r3)			; Get the space
			mfsprg	r6,0						/* Get the per_proc_info address */
			xor		r3,r3,r7					; Get real address of bmap anchor
			stw		r4,PP_USERSPACE(r6)			/* Show our new address space */
			stw		r3,PP_USERPMAP(r6)			; Show our real pmap address
			mtmsr	r10							/* Restore interruptions */
			blr									/* Return... */
	
			.align	5
			.globl	EXT(hw_set_user_space_dis)

LEXT(hw_set_user_space_dis)

 			lwz		r7,PMAP_PMAPVR(r3)			; Get the v to r translation
			lwz		r4,PMAP_SPACE(r3)			; Get the space
			mfsprg	r6,0						; Get the per_proc_info address
			xor		r3,r3,r7					; Get real address of bmap anchor
			stw		r4,PP_USERSPACE(r6)			; Show our new address space
			stw		r3,PP_USERPMAP(r6)			; Show our real pmap address
			blr									; Return...
	

/*			struct mapping *hw_cpv(struct mapping *mp) - Converts a physcial mapping CB address to virtual
 *
 */

			.align	5
			.globl	EXT(hw_cpv)

LEXT(hw_cpv)
			
			rlwinm.	r4,r3,0,0,19				; Round back to the mapping block allocation control block
			mfmsr	r10							; Get the current MSR
			beq-	hcpvret						; Skip if we are passed a 0...
			andi.	r9,r10,0x7FEF				; Turn off interrupts and data translation
			mtmsr	r9							; Disable DR and EE
			isync
			
			lwz		r4,mbvrswap(r4)				; Get the conversion value
			mtmsr	r10							; Interrupts and DR back on
			isync
			xor		r3,r3,r4					; Convert to physical

hcpvret:	rlwinm	r3,r3,0,0,26				; Clean out any flags
			blr


/*			struct mapping *hw_cvp(struct mapping *mp) - Converts a virtual mapping CB address to physcial
 *
 *			Translation must be on for this
 *
 */

			.align	5
			.globl	EXT(hw_cvp)

LEXT(hw_cvp)
			
			rlwinm	r4,r3,0,0,19				; Round back to the mapping block allocation control block			
			rlwinm	r3,r3,0,0,26				; Clean out any flags
			lwz		r4,mbvrswap(r4)				; Get the conversion value
			xor		r3,r3,r4					; Convert to virtual
			blr


/*			int mapalc(struct mappingblok *mb) - Finds, allocates, and checks a free mapping entry in a block
 *
 *			Lock must already be held on mapping block list
 *			returns 0 if all slots filled.
 *			returns n if a slot is found and it is not the last
 *			returns -n if a slot os found and it is the last
 *			when n and -n are returned, the corresponding bit is cleared
 *
 */

			.align	5
			.globl	EXT(mapalc)

LEXT(mapalc)
			
			lwz		r4,mbfree(r3)				; Get the first mask 
			lis		r0,0x8000					; Get the mask to clear the first free bit
			lwz		r5,mbfree+4(r3)				; Get the second mask 
			mr		r12,r3						; Save the return
			cntlzw	r8,r4						; Get first free field
			lwz		r6,mbfree+8(r3)				; Get the third mask 
			srw.	r9,r0,r8					; Get bit corresponding to first free one
			lwz		r7,mbfree+12(r3)			; Get the fourth mask 
			cntlzw	r10,r5						; Get first free field in second word
			andc	r4,r4,r9					; Turn it off
			bne		malcfnd0					; Found one...
			
			srw.	r9,r0,r10					; Get bit corresponding to first free one in second word
			cntlzw	r11,r6						; Get first free field in third word
			andc	r5,r5,r9					; Turn it off
			bne		malcfnd1					; Found one...
			
			srw.	r9,r0,r11					; Get bit corresponding to first free one in third word
			cntlzw	r10,r7						; Get first free field in fourth word
			andc	r6,r6,r9					; Turn it off
			bne		malcfnd2					; Found one...
			
			srw.	r9,r0,r10					; Get bit corresponding to first free one in second word
			li		r3,0						; Assume abject failure
			andc	r7,r7,r9					; Turn it off
			beqlr								; There are none any left...
			
			addi	r3,r10,96					; Set the correct bit number
			stw		r7,mbfree+12(r12)			; Actually allocate the slot
			
mapafin:	or		r4,r4,r5					; Merge the first two allocation maps
			or		r6,r6,r7					; Then the last two
			or.		r4,r4,r6					; Merge both halves
			bnelr+								; Return if some left for next time...
			
			neg		r3,r3						; Indicate we just allocated the last one
			blr									; Leave...
			
malcfnd0:	stw		r4,mbfree(r12)				; Actually allocate the slot
			mr		r3,r8						; Set the correct bit number
			b		mapafin						; Exit now...
			
malcfnd1:	stw		r5,mbfree+4(r12)			; Actually allocate the slot
			addi	r3,r10,32					; Set the correct bit number
			b		mapafin						; Exit now...
			
malcfnd2:	stw		r6,mbfree+8(r12)			; Actually allocate the slot
			addi	r3,r11,64					; Set the correct bit number
			b		mapafin						; Exit now...
			

/*
 * Log out all memory usage
 */

			.align	5
			.globl	EXT(logmem)

LEXT(logmem)

			mfmsr	r2							; Get the MSR	
			lis		r10,hi16(EXT(DebugWork))		; High part of area
			lis		r12,hi16(EXT(mem_actual))	; High part of actual
			andi.	r0,r10,0x7FCF				; Interrupts and translation off
			ori		r10,r10,lo16(EXT(DebugWork))	; Get the entry
			mtmsr	r0							; Turn stuff off
			ori		r12,r12,lo16(EXT(mem_actual))	; Get the actual
			li		r0,1						; Get a one
	
			isync

			stw		r0,4(r10)					; Force logging off
			lwz		r0,0(r12)					; Get the end of memory
			
			lis		r12,hi16(EXT(mem_size))		; High part of defined memory
			ori		r12,r12,lo16(EXT(mem_size))	; Low part of defined memory
			lwz		r12,0(r12)					; Make it end of defined
			
			cmplw	r0,r12						; Is there room for the data?
			ble-	logmemexit					; No, do not even try...

			stw		r12,0(r12)					; Set defined memory size
			stw		r0,4(r12)					; Set the actual amount of memory
			
			lis		r3,hi16(EXT(hash_table_base))	; Hash table address
			lis		r4,hi16(EXT(hash_table_size))	; Hash table size
			lis		r5,hi16(EXT(pmap_mem_regions))	; Memory regions
			lis		r6,hi16(EXT(mapCtl))		; Mappings
			ori		r3,r3,lo16(EXT(hash_table_base))	
			ori		r4,r4,lo16(EXT(hash_table_size))	
			ori		r5,r5,lo16(EXT(pmap_mem_regions))	
			ori		r6,r6,lo16(EXT(mapCtl))	
			lwz		r3,0(r3)
			lwz		r4,0(r4)
			lwz		r5,4(r5)					; Get the pointer to the phys_ent table
			lwz		r6,0(r6)					; Get the pointer to the current mapping block
			stw		r3,8(r12)					; Save the hash table address
			stw		r4,12(r12)					; Save the hash table size
			stw		r5,16(r12)					; Save the physent pointer
			stw		r6,20(r12)					; Save the mappings
			
			addi	r11,r12,0x1000				; Point to area to move hash table and PCA
			
			add		r4,r4,r4					; Double size for both
			
copyhash:	lwz		r7,0(r3)					; Copy both of them
			lwz		r8,4(r3)
			lwz		r9,8(r3)
			lwz		r10,12(r3)
			subic.	r4,r4,0x10
			addi	r3,r3,0x10
			stw		r7,0(r11)
			stw		r8,4(r11)
			stw		r9,8(r11)
			stw		r10,12(r11)
			addi	r11,r11,0x10
			bgt+	copyhash
			
			rlwinm	r4,r12,20,12,31				; Get number of phys_ents

copyphys:	lwz		r7,0(r5)					; Copy physents
			lwz		r8,4(r5)
			subic.	r4,r4,1
			addi	r5,r5,8
			stw		r7,0(r11)
			stw		r8,4(r11)
			addi	r11,r11,8
			bgt+	copyphys
			
			addi	r11,r11,4095				; Round up to next page
			rlwinm	r11,r11,0,0,19

			lwz		r4,4(r6)					; Get the size of the mapping area
			
copymaps:	lwz		r7,0(r6)					; Copy the mappings
			lwz		r8,4(r6)
			lwz		r9,8(r6)
			lwz		r10,12(r6)
			subic.	r4,r4,0x10
			addi	r6,r6,0x10
			stw		r7,0(r11)
			stw		r8,4(r11)
			stw		r9,8(r11)
			stw		r10,12(r11)
			addi	r11,r11,0x10
			bgt+	copymaps

			sub		r11,r11,r12					; Get the total length we saved
			stw		r11,24(r12)					; Save the size
			
logmemexit:	mtmsr	r2							; Back to normal
			li		r3,0
			isync
			blr


