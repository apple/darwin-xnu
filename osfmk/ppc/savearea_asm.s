/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#define FPVECDBG 0

#include <assym.s>
#include <debug.h>
#include <db_machine_commands.h>
#include <mach_rt.h>
	
#include <mach_debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/Performance.h>
#include <ppc/exception.h>
#include <ppc/savearea.h>
#include <mach/ppc/vm_param.h>
	
			.text

/* Register usage conventions in this code:
 *	r9 = return address
 * r10 = per-proc ptr
 * r11 = MSR at entry
 * cr6 = feature flags (ie, pf64Bit)
 *
 * Because much of this code deals with physical addresses,
 * there are parallel paths for 32- and 64-bit machines.
 */
 

/*
 * *****************************
 * * s a v e _ s n a p s h o t *
 * *****************************
 *
 *	void save_snapshot();
 *
 *			Link the current free list & processor local list on an independent list.
 */
			.align	5
			.globl	EXT(save_snapshot)

LEXT(save_snapshot)
            mflr	r9							; get return address
            bl		saveSetup					; turn translation off, 64-bit on, load many regs
            bf--	pf64Bitb,save_snapshot32 	; skip if 32-bit processor

            ; Handle 64-bit processor.

save_snapshot64:

			ld		r8,next_savearea(r10)		; Start with the current savearea
			std		r8,SVsavefreesnapshot(0)	; Make it the restore list anchor
			ld		r5,SVfree(0)				; Get free save area list anchor 

save_snapshot64nextfree:
            mr		r7,r5
			std		r7,savemisc1(r8)  			; Link this one
			ld		r5,SAVprev(r7)				; Get the next 
            mr		r8,r7
            mr.		r0,r5
            bne		save_snapshot64nextfree

			lwz		r6,SVinuse(0)				; Get inuse count
			ld		r5,lclfree(r10)				; Get the local savearea list
            subi	r6,r6,1						; Count the first as free

save_snapshot64nextlocalfree:
            subi	r6,r6,1						; Count as free
            mr		r7,r5
			std		r7,savemisc1(r8)	 		; Link this one
			ld		r5,SAVprev(r7)				; Get the next 
            mr		r8,r7
            mr.		r0,r5
            bne		save_snapshot64nextlocalfree

			std		r5,savemisc1(r8)	   		; End the list
			stw		r6,SVsaveinusesnapshot(0)	; Save the new number of inuse saveareas

			mtlr	r9							; Restore the return
            b		saveRestore64				; Restore interrupts and translation

            ; Handle 32-bit processor.

save_snapshot32:
			lwz		r8,next_savearea+4(r10)		; Start with the current savearea
			stw		r8,SVsavefreesnapshot+4(0)	; Make it the restore list anchor
			lwz		r5,SVfree+4(0)				; Get free save area list anchor 

save_snapshot32nextfree:
            mr		r7,r5
			stw		r7,savemisc1+4(r8)  		; Link this one
			lwz		r5,SAVprev+4(r7)			; Get the next 
            mr		r8,r7
            mr.		r0,r5
            bne		save_snapshot32nextfree

			lwz		r6,SVinuse(0)				; Get inuse count
			lwz		r5,lclfree+4(r10)			; Get the local savearea list
            subi	r6,r6,1						; Count the first as free

save_snapshot32nextlocalfree:
            subi	r6,r6,1						; Count as free
            mr		r7,r5
			stw		r7,savemisc1+4(r8)	 		; Link this one
			lwz		r5,SAVprev+4(r7)			; Get the next 
            mr		r8,r7
            mr.		r0,r5
            bne		save_snapshot32nextlocalfree

			stw		r5,savemisc1+4(r8)	   		; End the list
			stw		r6,SVsaveinusesnapshot(0)	; Save the new number of inuse saveareas

			mtlr	r9							; Restore the return
            b		saveRestore32				; Restore interrupts and translation

/*
 * *********************************************
 * * s a v e _ s n a p s h o t _ r e s t o r e *
 * *********************************************
 *
 *	void save_snapshot_restore();
 *
 *			Restore the free list from the snapshot list, and reset the processors next savearea.
 */
			.align	5
			.globl	EXT(save_snapshot_restore)

LEXT(save_snapshot_restore)
            mflr	r9							; get return address
            bl		saveSetup					; turn translation off, 64-bit on, load many regs
            bf--	pf64Bitb,save_snapshot_restore32 	; skip if 32-bit processor

            ; Handle 64-bit processor.

save_snapshot_restore64:
  			lwz		r7,SVsaveinusesnapshot(0)
			stw		r7,SVinuse(0)				; Set the new inuse count

            li		r6,0
            stw		r6,lclfreecnt(r10)			; None local now
			std		r6,lclfree(r10)				; None local now

			ld		r8,SVsavefreesnapshot(0)	; Get the restore list anchor 
			std		r8,SVfree(0)				; Make it the free list anchor
			li		r5,SAVempty					; Get marker for free savearea

save_snapshot_restore64nextfree:
            addi	r6,r6,1						; Count as free
			stb		r5,SAVflags+2(r8)			; Mark savearea free
			ld		r7,savemisc1(r8)			; Get the next 
			std		r7,SAVprev(r8)		   		; Set the next in free list
            mr.		r8,r7
            bne		save_snapshot_restore64nextfree

            stw		r6,SVfreecnt(0)				; Set the new free count

            bl		saveGet64
            std		r3,next_savearea(r10)		; Get the next savearea 

			mtlr	r9							; Restore the return
            b		saveRestore64				; Restore interrupts and translation

            ; Handle 32-bit processor.

save_snapshot_restore32:
  			lwz		r7,SVsaveinusesnapshot(0)
			stw		r7,SVinuse(0)				; Set the new inuse count

            li		r6,0
            stw		r6,lclfreecnt(r10)			; None local now
			stw		r6,lclfree+4(r10)			; None local now

			lwz		r8,SVsavefreesnapshot+4(0)	; Get the restore list anchor 
			stw		r8,SVfree+4(0)				; Make it the free list anchor
			li		r5,SAVempty					; Get marker for free savearea

save_snapshot_restore32nextfree:
            addi	r6,r6,1						; Count as free
			stb		r5,SAVflags+2(r8)			; Mark savearea free
			lwz		r7,savemisc1+4(r8)			; Get the next 
			stw		r7,SAVprev+4(r8)	   		; Set the next in free list
            mr.		r8,r7
            bne		save_snapshot_restore32nextfree

            stw		r6,SVfreecnt(0)				; Set the new free count

            bl		saveGet32
            stw		r3,next_savearea+4(r10)		; Get the next savearea 

			mtlr	r9							; Restore the return
            b		saveRestore32				; Restore interrupts and translation

/*
 * ***********************
 * * s a v e _ q u e u e *
 * ***********************
 *
 *	void save_queue(ppnum_t pagenum);
 *
 *			This routine will add a savearea block to the free list.
 *			We also queue the block to the free pool list.  This is a
 *			circular double linked list. Because this block has no free entries,
 *			it gets queued to the end of the list
 */
			.align	5
			.globl	EXT(save_queue)

LEXT(save_queue)
            mflr	r9							; get return address
            mr		r8,r3						; move pagenum out of the way
            bl		saveSetup					; turn translation off, 64-bit on, load many regs
            bf--	pf64Bitb,saveQueue32		; skip if 32-bit processor
            
            sldi	r2,r8,12					; r2 <-- phys address of page
			li		r8,sac_cnt					; Get the number of saveareas per page
			mr		r4,r2						; Point to start of chain
			li		r0,SAVempty					; Get empty marker

saveQueue64a:	
            addic.	r8,r8,-1					; Keep track of how many we did
			stb		r0,SAVflags+2(r4)			; Set empty
			addi	r7,r4,SAVsize				; Point to the next slot
			ble-	saveQueue64b				; We are done with the chain
			std		r7,SAVprev(r4)				; Set this chain
			mr		r4,r7						; Step to the next
			b		saveQueue64a				; Fill the whole block...

saveQueue64b:
			bl		savelock					; Go lock the save anchor 

			ld		r7,SVfree(0)				; Get the free save area list anchor 
			lwz		r6,SVfreecnt(0)				; Get the number of free saveareas

			std		r2,SVfree(0)				; Queue in the new one 
			addi	r6,r6,sac_cnt				; Count the ones we are linking in 
			std		r7,SAVprev(r4)				; Queue the old first one off of us
			stw		r6,SVfreecnt(0)				; Save the new count
			b		saveQueueExit

            ; Handle 32-bit processor.
            
saveQueue32:            
            slwi	r2,r8,12					; r2 <-- phys address of page
			li		r8,sac_cnt					; Get the number of saveareas per page
			mr		r4,r2						; Point to start of chain
			li		r0,SAVempty					; Get empty marker

saveQueue32a:	
            addic.	r8,r8,-1					; Keep track of how many we did
			stb		r0,SAVflags+2(r4)			; Set empty
			addi	r7,r4,SAVsize				; Point to the next slot
			ble-	saveQueue32b				; We are done with the chain
			stw		r7,SAVprev+4(r4)			; Set this chain
			mr		r4,r7						; Step to the next
			b		saveQueue32a				; Fill the whole block...

saveQueue32b:
			bl		savelock					; Go lock the save anchor 

			lwz		r7,SVfree+4(0)				; Get the free save area list anchor 
			lwz		r6,SVfreecnt(0)				; Get the number of free saveareas

			stw		r2,SVfree+4(0)				; Queue in the new one 
			addi	r6,r6,sac_cnt				; Count the ones we are linking in 
			stw		r7,SAVprev+4(r4)			; Queue the old first one off of us
			stw		r6,SVfreecnt(0)				; Save the new count

saveQueueExit:									; join here from 64-bit path		
			bl		saveunlock					; Unlock the list and set the adjust count
			mtlr	r9							; Restore the return

#if FPVECDBG
			mfsprg	r2,1						; (TEST/DEBUG)
			mr.		r2,r2						; (TEST/DEBUG)
			beq--	saveRestore					; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)			; (TEST/DEBUG)
			li		r2,0x2201					; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)		; (TEST/DEBUG)
			sc									; (TEST/DEBUG)
#endif
            b		saveRestore					; Restore interrupts and translation

/*
 * *****************************
 * * s a v e _ g e t _ i n i t *
 * *****************************
 *
 *	addr64_t  save_get_init(void);
 *
 *			Note that save_get_init is used in initial processor startup only.  It
 *			is used because translation is on, but no tables exist yet and we have
 *			no V=R BAT registers that cover the entire physical memory.
 */
			.align	5
			.globl	EXT(save_get_init)

LEXT(save_get_init)
            mflr	r9							; get return address
            bl		saveSetup					; turn translation off, 64-bit on, load many regs
            bfl--	pf64Bitb,saveGet32			; Get r3 <- savearea, r5 <- page address (with SAC)
            btl++	pf64Bitb,saveGet64			; get one on a 64-bit machine
            bl		saveRestore					; restore translation etc
            mtlr	r9
            
            ; unpack the physaddr in r3 into a long long in (r3,r4)
            
            mr		r4,r3						; copy low word of phys address to r4
            li		r3,0						; assume upper word was 0
            bflr--	pf64Bitb					; if 32-bit processor, return
            srdi	r3,r4,32					; unpack reg64_t to addr64_t on 64-bit machine
            rlwinm	r4,r4,0,0,31
            blr
            

/*
 * *******************
 * * s a v e _ g e t *
 * *******************
 *
 *	savearea *save_get(void);
 *
 *			Allocate a savearea, returning a virtual address.  NOTE: we must preserve
 *			r0, r2, and r12.  Our callers in cswtch.s depend on this.
 */
			.align	5
			.globl	EXT(save_get)

LEXT(save_get)
            mflr	r9							; get return address
            mr		r5,r0						; copy regs before saveSetup nails them
            bl		saveSetup					; turn translation off, 64-bit on, load many regs
            bf--	pf64Bitb,svgt1				; skip if 32-bit processor
            
            std		r5,tempr0(r10)				; save r0 in per-proc across call to saveGet64
            std		r2,tempr2(r10)				; and r2
            std		r12,tempr4(r10)				; and r12
            bl		saveGet64					; get r3 <- savearea, r5 <- page address (with SAC)
            ld		r0,tempr0(r10)				; restore callers regs
            ld		r2,tempr2(r10)
            ld		r12,tempr4(r10)
            b		svgt2
            
svgt1:											; handle 32-bit processor
            stw		r5,tempr0+4(r10)			; save r0 in per-proc across call to saveGet32
            stw		r2,tempr2+4(r10)			; and r2
            stw		r12,tempr4+4(r10)			; and r12
            bl		saveGet32					; get r3 <- savearea, r5 <- page address (with SAC)
            lwz		r0,tempr0+4(r10)			; restore callers regs
            lwz		r2,tempr2+4(r10)
            lwz		r12,tempr4+4(r10)
            
svgt2:
			lwz		r5,SACvrswap+4(r5)			; Get the virtual to real translation (only need low word)
            mtlr	r9							; restore return address
            xor		r3,r3,r5					; convert physaddr to virtual
            rlwinm	r3,r3,0,0,31				; 0 upper word if a 64-bit machine

#if FPVECDBG
            mr		r6,r0						; (TEST/DEBUG)
            mr		r7,r2						; (TEST/DEBUG)
			mfsprg	r2,1						; (TEST/DEBUG)
			mr.		r2,r2						; (TEST/DEBUG)
			beq--	svgDBBypass					; (TEST/DEBUG)
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2203					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc									; (TEST/DEBUG) 
svgDBBypass:									; (TEST/DEBUG)
            mr		r0,r6						; (TEST/DEBUG)
            mr		r2,r7						; (TEST/DEBUG) 
#endif			
            b		saveRestore					; restore MSR and return to our caller
            
            
/*
 * ***********************************
 * * s a v e _ g e t _ p h y s _ 3 2 *
 * ***********************************
 *
 *	reg64_t	save_get_phys(void);
 *
 * 			This is the entry normally called from lowmem_vectors.s with
 *			translation and interrupts already off.
 *			MUST NOT TOUCH CR7
 */
			.align	5
			.globl	EXT(save_get_phys_32)

LEXT(save_get_phys_32)
            mfsprg	r10,0						; get the per-proc ptr
			b		saveGet32					; Get r3 <- savearea, r5 <- page address (with SAC)


/*
 * ***********************************
 * * s a v e _ g e t _ p h y s _ 6 4 *
 * ***********************************
 *
 *	reg64_t	save_get_phys_64(void);
 *
 * 			This is the entry normally called from lowmem_vectors.s with
 *			translation and interrupts already off, and in 64-bit mode.
 *			MUST NOT TOUCH CR7
 */
			.align	5
			.globl	EXT(save_get_phys_64)

LEXT(save_get_phys_64)
            mfsprg	r10,0						; get the per-proc ptr
 			b		saveGet64					; Get r3 <- savearea, r5 <- page address (with SAC)
            

/*
 * *********************
 * * s a v e G e t 6 4 *
 * *********************
 *
 *			This is the internal routine to allocate a savearea on a 64-bit processor.  
 *			Note that we must not take any exceptions of any kind, including PTE misses, as that
 *			would deadlock trying to reenter this routine.  We pass back the 64-bit physical address.
 *			First we try the local list.  If that is below a threshold, we try the global free list,
 *			which requires taking a lock, and replenish.  If there are no saveareas in either list,
 *			we will install the  backpocket and choke.  This routine assumes that the caller has
 *			turned translation off, masked interrupts,  turned on 64-bit mode, and set up:
 *				r10 = per-proc ptr
 *
 *			We return:
 *				r3 = 64-bit physical address of the savearea
 *				r5 = 64-bit physical address of the page the savearea is in, with SAC
 *
 *			We destroy:
 *				r2-r8.
 *		
 * 			MUST NOT TOUCH CR7
 */

saveGet64:            
			lwz		r8,lclfreecnt(r10)			; Get the count
			ld		r3,lclfree(r10)				; Get the start of local savearea list
			cmplwi	r8,LocalSaveMin				; Are we too low?
			ble--	saveGet64GetGlobal			; We are too low and need to grow list...

            ; Get it from the per-processor local list.
            
saveGet64GetLocal:
            li		r2,0x5555					; get r2 <-- 0x55555555 55555555, our bugbug constant
			ld		r4,SAVprev(r3)				; Chain to the next one
			oris	r2,r2,0x5555
			subi	r8,r8,1						; Back down count
            rldimi	r2,r2,32,0

			std		r2,SAVprev(r3)				; bug next ptr
			stw		r2,SAVlevel(r3)				; bug context ID
            li		r6,0
			std		r4,lclfree(r10)				; Unchain first savearea
			stw		r2,SAVact(r3)				; bug activation ptr
			rldicr	r5,r3,0,51					; r5 <-- page ptr, where SAC is kept
			stw		r8,lclfreecnt(r10)			; Set new count
			stw		r6,SAVflags(r3)				; clear the flags

            blr

            ; Local list was low so replenish from global list.
            ;	 r7 = return address to caller of saveGet64
            ;	 r8 = lclfreecnt
            ;	r10 = per-proc ptr
            
saveGet64GetGlobal:
            mflr	r7							; save return adress
			subfic	r5,r8,LocalSaveTarget		; Get the number of saveareas we need to grab to get to target
			bl		savelock					; Go lock up the anchor
			
			lwz		r2,SVfreecnt(0)				; Get the number on this list
			ld		r8,SVfree(0)				; Get the head of the save area list 
			
			sub		r3,r2,r5					; Get number left after we swipe enough for local list
			sradi	r3,r3,63					; Get 0 if enough or -1 if not
			andc	r4,r5,r3					; Get number to get if there are enough, 0 otherwise
			and		r5,r2,r3					; Get 0 if there are enough, number on list otherwise
			or.		r5,r4,r5					; r5 <- number we will move from global to local list
			beq--	saveGet64NoFree				; There are none to get...
			
			mtctr	r5							; Get loop count
			mr		r6,r8						; Remember the first in the list

saveGet64c:
            bdz		saveGet64d					; Count down and branch when we hit 0...
			ld		r8,SAVprev(r8)				; Get the next
			b		saveGet64c					; Keep going...

saveGet64d:			
            ld		r3,SAVprev(r8)				; Get the next one
			lwz		r4,SVinuse(0)				; Get the in use count
			sub		r2,r2,r5					; Count down what we stole
			std		r3,SVfree(0)				; Set the new first in list
			add		r4,r4,r5					; Count the ones we just put in the local list as "in use"
			stw		r2,SVfreecnt(0)				; Set the new count
			stw		r4,SVinuse(0)				; Set the new in use count
			
			ld		r4,lclfree(r10)				; Get the old head of list
			lwz		r3,lclfreecnt(r10)			; Get the old count
			std		r6,lclfree(r10)				; Set the new head of the list
			add		r3,r3,r5					; Get the new count
			std		r4,SAVprev(r8)				; Point to the old head
			stw		r3,lclfreecnt(r10)			; Set the new count

			bl		saveunlock					; Update the adjust field and unlock
            mtlr	r7							; restore return address
			b		saveGet64					; Start over and finally allocate the savearea...
			
            ; The local list is below the repopulate threshold and the global list is empty.
            ; First we check if there are any left in the local list and if so, we allow
            ; them to be allocated.  If not, we release the backpocket list and choke.  
            ; There is nothing more that we can do at this point.  Hopefully we stay alive
            ; long enough to grab some much-needed panic information.
            ;	 r7 = return address to caller of saveGet64 
            ;	r10 = per-proc ptr

saveGet64NoFree:			
			lwz		r8,lclfreecnt(r10)			; Get the count
			mr.		r8,r8						; Are there any reserve to get?
			beq--	saveGet64Choke				; No, go choke and die...
			bl		saveunlock					; Update the adjust field and unlock
			ld		r3,lclfree(r10)				; Get the start of local savearea list
			lwz		r8,lclfreecnt(r10)			; Get the count
            mtlr	r7							; restore return address
			b		saveGet64GetLocal			; We have some left, dip on in...
			
;			We who are about to die salute you.  The savearea chain is messed up or
;			empty.  Add in a few so we have enough to take down the system.

saveGet64Choke:
            lis		r9,hi16(EXT(backpocket))	; Get high order of back pocket
			ori		r9,r9,lo16(EXT(backpocket))	; and low part
			
			lwz		r8,SVfreecnt-saveanchor(r9)	; Get the new number of free elements
			ld		r7,SVfree-saveanchor(r9)	; Get the head of the chain
			lwz		r6,SVinuse(0)				; Get total in the old list

			stw		r8,SVfreecnt(0)				; Set the new number of free elements
			add		r6,r6,r8					; Add in the new ones
			std		r7,SVfree(0)				; Set the new head of the chain
			stw		r6,SVinuse(0)				; Set total in the new list

saveGetChokeJoin:								; join in the fun from 32-bit mode
			lis		r0,hi16(Choke)				; Set choke firmware call
			li		r7,0						; Get a clear register to unlock
			ori		r0,r0,lo16(Choke)			; Set the rest of the choke call
			li		r3,failNoSavearea			; Set failure code

			eieio								; Make sure all is committed
			stw		r7,SVlock(0)				; Unlock the free list
			sc									; System ABEND


/*
 * *********************
 * * s a v e G e t 3 2 *
 * *********************
 *
 *			This is the internal routine to allocate a savearea on a 32-bit processor.  
 *			Note that we must not take any exceptions of any kind, including PTE misses, as that
 *			would deadlock trying to reenter this routine.  We pass back the 32-bit physical address.
 *			First we try the local list.  If that is below a threshold, we try the global free list,
 *			which requires taking a lock, and replenish.  If there are no saveareas in either list,
 *			we will install the  backpocket and choke.  This routine assumes that the caller has
 *			turned translation off, masked interrupts, and set up:
 *				r10 = per-proc ptr
 *
 *			We return:
 *				r3 = 32-bit physical address of the savearea
 *				r5 = 32-bit physical address of the page the savearea is in, with SAC
 *
 *			We destroy:
 *				r2-r8.
 */

saveGet32:            
			lwz		r8,lclfreecnt(r10)			; Get the count
			lwz		r3,lclfree+4(r10)			; Get the start of local savearea list
			cmplwi	r8,LocalSaveMin				; Are we too low?
			ble-	saveGet32GetGlobal			; We are too low and need to grow list...

            ; Get savearea from per-processor local list.
            
saveGet32GetLocal:
            li		r2,0x5555					; get r2 <-- 0x55555555, our bugbug constant
			lwz		r4,SAVprev+4(r3)			; Chain to the next one
			oris	r2,r2,0x5555
			subi	r8,r8,1						; Back down count

			stw		r2,SAVprev+4(r3)			; bug next ptr
			stw		r2,SAVlevel(r3)				; bug context ID
            li		r6,0
			stw		r4,lclfree+4(r10)			; Unchain first savearea
			stw		r2,SAVact(r3)				; bug activation ptr
			rlwinm	r5,r3,0,0,19				; r5 <-- page ptr, where SAC is kept
			stw		r8,lclfreecnt(r10)			; Set new count
			stw		r6,SAVflags(r3)				; clear the flags

            blr

            ; Local list was low so replenish from global list.
            ;	 r7 = return address to caller of saveGet32
            ;	 r8 = lclfreecnt
            ;	r10 = per-proc ptr
            
saveGet32GetGlobal:
            mflr	r7							; save return adress
			subfic	r5,r8,LocalSaveTarget		; Get the number of saveareas we need to grab to get to target
			bl		savelock					; Go lock up the anchor
			
			lwz		r2,SVfreecnt(0)				; Get the number on this list
			lwz		r8,SVfree+4(0)				; Get the head of the save area list 
			
			sub		r3,r2,r5					; Get number left after we swipe enough for local list
			srawi	r3,r3,31					; Get 0 if enough or -1 if not
			andc	r4,r5,r3					; Get number to get if there are enough, 0 otherwise
			and		r5,r2,r3					; Get 0 if there are enough, number on list otherwise
			or.		r5,r4,r5					; r5 <- number we will move from global to local list
			beq-	saveGet32NoFree				; There are none to get...
			
			mtctr	r5							; Get loop count
			mr		r6,r8						; Remember the first in the list

saveGet32c:
            bdz		saveGet32d					; Count down and branch when we hit 0...
			lwz		r8,SAVprev+4(r8)			; Get the next
			b		saveGet32c					; Keep going...

saveGet32d:			
            lwz		r3,SAVprev+4(r8)			; Get the next one
			lwz		r4,SVinuse(0)				; Get the in use count
			sub		r2,r2,r5					; Count down what we stole
			stw		r3,SVfree+4(0)				; Set the new first in list
			add		r4,r4,r5					; Count the ones we just put in the local list as "in use"
			stw		r2,SVfreecnt(0)				; Set the new count
			stw		r4,SVinuse(0)				; Set the new in use count
			
			lwz		r4,lclfree+4(r10)			; Get the old head of list
			lwz		r3,lclfreecnt(r10)			; Get the old count
			stw		r6,lclfree+4(r10)			; Set the new head of the list
			add		r3,r3,r5					; Get the new count
			stw		r4,SAVprev+4(r8)			; Point to the old head
			stw		r3,lclfreecnt(r10)			; Set the new count

			bl		saveunlock					; Update the adjust field and unlock
            mtlr	r7							; restore return address
			b		saveGet32					; Start over and finally allocate the savearea...
			
            ; The local list is below the repopulate threshold and the global list is empty.
            ; First we check if there are any left in the local list and if so, we allow
            ; them to be allocated.  If not, we release the backpocket list and choke.  
            ; There is nothing more that we can do at this point.  Hopefully we stay alive
            ; long enough to grab some much-needed panic information.
            ;	 r7 = return address to caller of saveGet32
            ;	r10 = per-proc ptr

saveGet32NoFree:			
			lwz		r8,lclfreecnt(r10)			; Get the count
			mr.		r8,r8						; Are there any reserve to get?
			beq-	saveGet32Choke				; No, go choke and die...
			bl		saveunlock					; Update the adjust field and unlock
			lwz		r3,lclfree+4(r10)			; Get the start of local savearea list
			lwz		r8,lclfreecnt(r10)			; Get the count
            mtlr	r7							; restore return address
			b		saveGet32GetLocal			; We have some left, dip on in...
			
;			We who are about to die salute you.  The savearea chain is messed up or
;			empty.  Add in a few so we have enough to take down the system.

saveGet32Choke:
            lis		r9,hi16(EXT(backpocket))	; Get high order of back pocket
			ori		r9,r9,lo16(EXT(backpocket))	; and low part
			
			lwz		r8,SVfreecnt-saveanchor(r9)	; Get the new number of free elements
			lwz		r7,SVfree+4-saveanchor(r9)	; Get the head of the chain
			lwz		r6,SVinuse(0)				; Get total in the old list

			stw		r8,SVfreecnt(0)				; Set the new number of free elements
			add		r6,r6,r8					; Add in the new ones (why?)
			stw		r7,SVfree+4(0)				; Set the new head of the chain
			stw		r6,SVinuse(0)				; Set total in the new list
            
            b		saveGetChokeJoin


/*
 * *******************
 * * s a v e _ r e t *
 * *******************
 *
 *	void	save_ret(struct savearea *);				// normal call
 *	void	save_ret_wMSR(struct savearea *,reg64_t); 	// passes MSR to restore as 2nd arg
 *
 *			Return a savearea passed by virtual address to the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 */
            .globl	EXT(save_ret_wMSR)			; alternate entry pt w MSR to restore in r4
            
LEXT(save_ret_wMSR)
            crset	31							; set flag for save_ret_wMSR
            b		svrt1						; join common code
            
            .align	5
            .globl	EXT(save_ret)
            
LEXT(save_ret)
            crclr	31							; clear flag for save_ret_wMSR
svrt1:											; join from save_ret_wMSR
            mflr	r9							; get return address
            rlwinm	r7,r3,0,0,19				; get virtual address of SAC area at start of page
            mr		r8,r3						; save virtual address
            lwz		r5,SACvrswap+0(r7)			; get 64-bit converter from V to R
            lwz		r6,SACvrswap+4(r7)			; both halves, though only bottom used on 32-bit machine
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2204					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
            bl		saveSetup					; turn translation off, 64-bit on, load many regs
            bf++	31,svrt3					; skip if not save_ret_wMSR
            mr		r11,r4						; was save_ret_wMSR, so overwrite saved MSR
svrt3:
            bf--	pf64Bitb,svrt4				; skip if a 32-bit processor
            
            ; Handle 64-bit processor.
            
            rldimi	r6,r5,32,0					; merge upper and lower halves of SACvrswap together
            xor		r3,r8,r6					; get r3 <- 64-bit physical address of this savearea
            bl		saveRet64					; return it
            mtlr	r9							; restore return address
            b		saveRestore64				; restore MSR
            
            ; Handle 32-bit processor.
            
svrt4:
            xor		r3,r8,r6					; get r3 <- 32-bit physical address of this savearea
            bl		saveRet32					; return it
            mtlr	r9							; restore return address
            b		saveRestore32				; restore MSR
 

/*
 * *****************************
 * * s a v e _ r e t _ p h y s *
 * *****************************
 *
 *	void	save_ret_phys(reg64_t);
 *
 *			Called from lowmem vectors to return (ie, free) a savearea by physical address.
 *			Translation and interrupts are already off, and 64-bit mode is set if defined.
 *			We can take _no_ exceptions of any kind in this code, including PTE miss, since
 *			that would result in a deadlock.  We expect:
 *				r3 = phys addr of savearea
 *			   msr = IR, DR, and EE off, SF on
 *             cr6 = pf64Bit flag
 *			We destroy:
 *				r0,r2-r10.
 */
			.align	5
			.globl	EXT(save_ret_phys)

LEXT(save_ret_phys)
            mfsprg	r10,0						; get the per-proc ptr
            bf--	pf64Bitb,saveRet32			; handle 32-bit machine
            b		saveRet64					; handle 64-bit machine
            

/*
 * *********************
 * * s a v e R e t 6 4 *
 * *********************
 *
 *			This is the internal routine to free a savearea, passed by 64-bit physical
 *			address.  We assume that IR, DR, and EE are all off, that SF is on, and:
 *				r3 = phys address of the savearea
 *			   r10 = per-proc ptr
 *			We destroy:
 *				r0,r2-r8.
 */
            .align	5
 saveRet64:
			li		r0,SAVempty					; Get marker for free savearea
			lwz		r7,lclfreecnt(r10)			; Get the local count
			ld		r6,lclfree(r10)				; Get the old local header
			addi	r7,r7,1						; Pop up the free count
			std		r6,SAVprev(r3)				; Plant free chain pointer
			cmplwi	r7,LocalSaveMax				; Has the list gotten too long?
			stb		r0,SAVflags+2(r3)			; Mark savearea free
			std		r3,lclfree(r10)				; Chain us on in
			stw		r7,lclfreecnt(r10)			; Bump up the count
			bltlr++								; List not too long, so done
			
/*			The local savearea chain has gotten too long.  Trim it down to the target.
 *			Here's a tricky bit, and important:
 *
 *			When we trim the list, we NEVER trim the very first one.  This is because that is
 *			the very last one released and the exception exit code will release the savearea
 *			BEFORE it is done using it. Wouldn't be too good if another processor started
 *			using it, eh?  So for this case, we are safe so long as the savearea stays on
 *			the local list.  (Note: the exit routine needs to do this because it is in the 
 *			process of restoring all context and it needs to keep it until the last second.)
 */

            mflr	r0							; save return to caller of saveRet64
			mr		r2,r3						; r2 <- 1st one on local list, which must not be trimmed
			ld		r3,SAVprev(r3)				; Skip over the first
			subi	r7,r7,LocalSaveTarget		; Figure out how much to trim	
			mr		r6,r3						; r6 <- first one to trim
			mr		r5,r7						; Save the number we are trimming
			
saveRet64a:
            addic.	r7,r7,-1					; Any left to do?
			ble--	saveRet64b					; Nope...
			ld		r3,SAVprev(r3)				; Skip to the next one
			b		saveRet64a					; Keep going...
			
saveRet64b:										; r3 <- last one to trim
			ld		r7,SAVprev(r3)				; Point to the first one not to trim
			li		r4,LocalSaveTarget			; Set the target count
			std		r7,SAVprev(r2)				; Trim stuff leaving the one just released as first
			stw		r4,lclfreecnt(r10)			; Set the current count
			
			bl		savelock					; Lock up the anchor
			
			ld		r8,SVfree(0)				; Get the old head of the free list
			lwz		r4,SVfreecnt(0)				; Get the number of free ones
			lwz		r7,SVinuse(0)				; Get the number that are in use
			std		r6,SVfree(0)				; Point to the first trimmed savearea
			add		r4,r4,r5					; Add number trimmed to free count
			std		r8,SAVprev(r3)				; Chain the old head to the tail of the trimmed guys
			sub		r7,r7,r5					; Remove the trims from the in use count
			stw		r4,SVfreecnt(0)				; Set new free count
			stw		r7,SVinuse(0)				; Set new in use count

			mtlr	r0							; Restore the return to our caller
			b		saveunlock					; Set adjust count, unlock the saveanchor, and return
            

/*
 * *********************
 * * s a v e R e t 3 2 *
 * *********************
 *
 *			This is the internal routine to free a savearea, passed by 32-bit physical
 *			address.  We assume that IR, DR, and EE are all off, and:
 *				r3 = phys address of the savearea
 *			   r10 = per-proc ptr
 *			We destroy:
 *				r0,r2-r8.
 */
            .align	5
 saveRet32:
			li		r0,SAVempty					; Get marker for free savearea
			lwz		r7,lclfreecnt(r10)			; Get the local count
			lwz		r6,lclfree+4(r10)			; Get the old local header
			addi	r7,r7,1						; Pop up the free count
			stw		r6,SAVprev+4(r3)			; Plant free chain pointer
			cmplwi	r7,LocalSaveMax				; Has the list gotten too long?
			stb		r0,SAVflags+2(r3)			; Mark savearea free
			stw		r3,lclfree+4(r10)			; Chain us on in
			stw		r7,lclfreecnt(r10)			; Bump up the count
			bltlr+								; List not too long, so done
			
/*			The local savearea chain has gotten too long.  Trim it down to the target.
 *			Here's a tricky bit, and important:
 *
 *			When we trim the list, we NEVER trim the very first one.  This is because that is
 *			the very last one released and the exception exit code will release the savearea
 *			BEFORE it is done using it. Wouldn't be too good if another processor started
 *			using it, eh?  So for this case, we are safe so long as the savearea stays on
 *			the local list.  (Note: the exit routine needs to do this because it is in the 
 *			process of restoring all context and it needs to keep it until the last second.)
 */

            mflr	r0							; save return to caller of saveRet32
			mr		r2,r3						; r2 <- 1st one on local list, which must not be trimmed
			lwz		r3,SAVprev+4(r3)			; Skip over the first
			subi	r7,r7,LocalSaveTarget		; Figure out how much to trim	
			mr		r6,r3						; r6 <- first one to trim
			mr		r5,r7						; Save the number we are trimming
			
saveRet32a:
            addic.	r7,r7,-1					; Any left to do?
			ble-	saveRet32b					; Nope...
			lwz		r3,SAVprev+4(r3)			; Skip to the next one
			b		saveRet32a					; Keep going...
			
saveRet32b:										; r3 <- last one to trim
			lwz		r7,SAVprev+4(r3)			; Point to the first one not to trim
			li		r4,LocalSaveTarget			; Set the target count
			stw		r7,SAVprev+4(r2)			; Trim stuff leaving the one just released as first
			stw		r4,lclfreecnt(r10)			; Set the current count
			
			bl		savelock					; Lock up the anchor
			
			lwz		r8,SVfree+4(0)				; Get the old head of the free list
			lwz		r4,SVfreecnt(0)				; Get the number of free ones
			lwz		r7,SVinuse(0)				; Get the number that are in use
			stw		r6,SVfree+4(0)				; Point to the first trimmed savearea
			add		r4,r4,r5					; Add number trimmed to free count
			stw		r8,SAVprev+4(r3)			; Chain the old head to the tail of the trimmed guys
			sub		r7,r7,r5					; Remove the trims from the in use count
			stw		r4,SVfreecnt(0)				; Set new free count
			stw		r7,SVinuse(0)				; Set new in use count

			mtlr	r0							; Restore the return to our caller
			b		saveunlock					; Set adjust count, unlock the saveanchor, and return


/*
 * *******************************
 * * s a v e _ t r i m _ f r e e *
 * *******************************
 *
 *	struct savearea_comm	*save_trim_free(void);
 *
 *			Trim the free list down to the target count, ie by -(SVadjust) save areas.
 *			It trims the list and, if a pool page was fully allocated, puts that page on 
 *			the start of the pool list.
 *
 *			If the savearea being released is the last on a pool page (i.e., all entries
 *			are released), the page is dequeued from the pool and queued to any other 
 *			found during this scan.  Note that this queue is maintained virtually.
 *
 *			When the scan is done, the saveanchor lock is released and the list of
 *			freed pool pages is returned to our caller.
 *
 *			For latency sake we may want to revisit this code. If we are trimming a
 *			large number of saveareas, we could be disabled and holding the savearea lock
 *			for quite a while.  It may be that we want to break the trim down into parts.
 *			Possibly trimming the free list, then individually pushing them into the free pool.
 *
 *			This function expects to be called with translation on and a valid stack.
 *			It uses the standard ABI, ie we destroy r2 and r3-r11, and return the ptr in r3.
 */
			.align	5
			.globl	EXT(save_trim_free)

LEXT(save_trim_free)

			subi	r1,r1,(FM_ALIGN(16)+FM_SIZE)	; Make space for 4 registers on stack
            mflr	r9							; save our return address
			stw		r28,FM_SIZE+0(r1)			; Save R28
			stw		r29,FM_SIZE+4(r1)			; Save R29
			stw		r30,FM_SIZE+8(r1)			; Save R30
			stw		r31,FM_SIZE+12(r1)			; Save R31

            bl		saveSetup					; turn off translation and interrupts, load many regs
            bl		savelock					; Go lock up the anchor

			lwz		r8,SVadjust(0)				; How many do we need to clear out?
			li		r3,0						; Get a 0
			neg.	r8,r8						; Get the actual we need to toss (adjust is neg if too many)
            ble-	save_trim_free1				; skip if no trimming needed anymore
            bf--	pf64Bitb,saveTrim32			; handle 32-bit processors
            b		saveTrim64					; handle 64-bit processors

save_trim_free1:								; by the time we were called, no need to trim anymore			
			stw		r3,SVlock(0)				; Quick unlock (no need for sync or to set adjust, nothing changed)
			mtlr	r9							; Restore return
	
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2206					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			addi	r1,r1,(FM_ALIGN(16)+FM_SIZE); Pop stack - have not trashed register so no need to reload
			b		saveRestore					; restore translation and EE, turn SF off, return to our caller


/*
 * ***********************
 * * s a v e T r i m 3 2 *
 * ***********************
 *
 *	Handle "save_trim_free" on 32-bit processors.  At this point, translation and interrupts
 *  are off, the savearea anchor is locked, and:
 *		 r8 = #pages to trim (>0)
 *	     r9 = return address
 *	 	r10 = per-proc ptr
 *		r11 = MSR at entry
 */

saveTrim32:	
			lwz		r7,SVfree+4(0)				; Get the first on the free list
            mr		r6,r7						; Save the first one 
			mr		r5,r8						; Save the number we are trimming
			
sttrimming:	addic.	r5,r5,-1					; Any left to do?
			ble-	sttrimmed					; Nope...
			lwz		r7,SAVprev+4(r7)			; Skip to the next one
			b		sttrimming					; Keep going...

sttrimmed:	lwz		r5,SAVprev+4(r7)			; Get the next one (for new head of free list)
			lwz		r4,SVfreecnt(0)				; Get the free count
			stw		r5,SVfree+4(0)				; Set new head
			sub		r4,r4,r8					; Calculate the new free count
			li		r31,0						; Show we have no free pool blocks yet
			crclr	cr1_eq						; dont exit loop before 1st iteration
			stw		r4,SVfreecnt(0)				; Set new free count
			lis		r30,hi16(sac_empty)			; Get what empty looks like
			
;			NOTE: The savearea size must be 640 (0x280).  We are doing a divide by shifts and stuff
;			here.
;
#if SAVsize != 640
#error Savearea size is not 640!!!!!!!!!!!!
#endif

            ; Loop over each savearea we are trimming.
            ;	 r6 = next savearea to trim
            ;	 r7 = last savearea to trim
            ;	 r8 = #pages to trim (>0)
            ;    r9 = return address
            ;	r10 = per-proc ptr
            ;	r11 = MSR at entry
            ;	r30 = what SACalloc looks like when all saveareas are free
            ;	r31 = free pool block list
            ;	cr1 = beq set if we just trimmed the last, ie if we are done

sttoss:		beq+	cr1,stdone					; All done now...

			cmplw	cr1,r6,r7					; Have we finished the loop?

			lis		r0,0x0044					; Get top of table	
			rlwinm	r2,r6,0,0,19				; Back down to the savearea control stuff
			ori		r0,r0,0x2200				; Finish shift table
			rlwinm	r4,r6,25,27,30				; Get (addr >> 7) & 0x1E (same as twice high nybble)
			lwz		r5,SACalloc(r2)				; Get the allocation bits
			addi	r4,r4,1						; Shift 1 extra
			rlwinm	r3,r6,25,31,31				; Get (addr >> 7) & 1
			rlwnm	r0,r0,r4,29,31				; Get partial index
			lis		r4,lo16(0x8000)				; Get the bit mask
			add		r0,r0,r3					; Make the real index
			srw		r4,r4,r0					; Get the allocation mask
			or		r5,r5,r4					; Free this entry
			cmplw	r5,r4						; Is this the only free entry?
			lwz		r6,SAVprev+4(r6)			; Chain to the next trimmed savearea
			cmplw	cr7,r30,r5					; Does this look empty?
			stw		r5,SACalloc(r2)				; Save back the allocation bits
			beq-	stputpool					; First free entry, go put it into the pool...
			bne+	cr7,sttoss					; Not an empty block
			
;
;			We have an empty block.  Remove it from the pool list.
;
			
			lwz		r29,SACflags(r2)			; Get the flags
			cmplwi	cr5,r31,0					; Is this guy on the release list?
			lwz		r28,SACnext+4(r2)			; Get the forward chain

			rlwinm.	r0,r29,0,sac_permb,sac_permb	; Is this a permanently allocated area? (also sets 0 needed below)
			bne-	sttoss						; This is permanent entry, do not try to release...

			lwz		r29,SACprev+4(r2)			; and the previous
			beq-	cr5,stnot1st				; Not first
			lwz		r0,SACvrswap+4(r31)			; Load the previous pool page vr conversion
			
stnot1st:	stw		r28,SACnext+4(r29)			; Previous guy points to my next
			xor		r0,r0,r31					; Make the last guy virtual
			stw		r29,SACprev+4(r28)			; Next guy points back to my previous 			
			stw		r0,SAVprev+4(r2)			; Store the old top virtual as my back chain
			mr		r31,r2						; My physical is now the head of the chain
			b		sttoss						; Get the next one...
			
;
;			A pool block that had no free entries now has one.  Stick it on the pool list.
;
			
stputpool:	lwz		r28,SVpoolfwd+4(0)			; Get the first guy on the list
			li		r0,saveanchor				; Point to the saveanchor
			stw		r2,SVpoolfwd+4(0)			; Put us on the top of the list
			stw		r28,SACnext+4(r2)			; We point to the old top
			stw		r2,SACprev+4(r28)			; Old top guy points back to us
			stw		r0,SACprev+4(r2)			; Our back points to the anchor
			b		sttoss						; Go on to the next one...


/*
 * ***********************
 * * s a v e T r i m 6 4 *
 * ***********************
 *
 *	Handle "save_trim_free" on 64-bit processors.  At this point, translation and interrupts
 *  are off, SF is on, the savearea anchor is locked, and:
 *		 r8 = #pages to trim (>0)
 *	     r9 = return address
 *	 	r10 = per-proc ptr
 *		r11 = MSR at entry
 */

saveTrim64:	
			ld		r7,SVfree(0)				; Get the first on the free list
            mr		r6,r7						; Save the first one 
			mr		r5,r8						; Save the number we are trimming
			
sttrimming64:	
            addic.	r5,r5,-1					; Any left to do?
			ble--	sttrimmed64					; Nope...
			ld		r7,SAVprev(r7)				; Skip to the next one
			b		sttrimming64				; Keep going...

sttrimmed64:
            ld		r5,SAVprev(r7)				; Get the next one (for new head of free list)
			lwz		r4,SVfreecnt(0)				; Get the free count
			std		r5,SVfree(0)				; Set new head
			sub		r4,r4,r8					; Calculate the new free count
			li		r31,0						; Show we have no free pool blocks yet
			crclr	cr1_eq						; dont exit loop before 1st iteration
			stw		r4,SVfreecnt(0)				; Set new free count
			lis		r30,hi16(sac_empty)			; Get what empty looks like
			

            ; Loop over each savearea we are trimming.
            ;	 r6 = next savearea to trim
            ;	 r7 = last savearea to trim
            ;	 r8 = #pages to trim (>0)
            ;    r9 = return address
            ;	r10 = per-proc ptr
            ;	r11 = MSR at entry
            ;	r30 = what SACalloc looks like when all saveareas are free
            ;	r31 = free pool block list
            ;	cr1 = beq set if we just trimmed the last, ie if we are done
            ;
            ; WARNING: as in the 32-bit path, this code is doing a divide by 640 (SAVsize).

sttoss64:
            beq++	cr1,stdone					; All done now...

			cmpld	cr1,r6,r7					; Have we finished the loop?

			lis		r0,0x0044					; Get top of table	
			rldicr	r2,r6,0,51					; r2 <- phys addr of savearea block (with control area)
			ori		r0,r0,0x2200				; Finish shift table
			rlwinm	r4,r6,25,27,30				; Get (addr >> 7) & 0x1E (same as twice high nybble)
			lwz		r5,SACalloc(r2)				; Get the allocation bits
			addi	r4,r4,1						; Shift 1 extra
			rlwinm	r3,r6,25,31,31				; Get (addr >> 7) & 1
			rlwnm	r0,r0,r4,29,31				; Get partial index
			lis		r4,lo16(0x8000)				; Get the bit mask
			add		r0,r0,r3					; Make the real index
			srw		r4,r4,r0					; Get the allocation mask
			or		r5,r5,r4					; Free this entry
			cmplw	r5,r4						; Is this the only free entry?
			ld		r6,SAVprev(r6)				; Chain to the next trimmed savearea
			cmplw	cr7,r30,r5					; Does this look empty?
			stw		r5,SACalloc(r2)				; Save back the allocation bits
			beq--	stputpool64					; First free entry, go put it into the pool...
			bne++	cr7,sttoss64				; Not an empty block
			
;			We have an empty block.  Remove it from the pool list.
			
			lwz		r29,SACflags(r2)			; Get the flags
			cmpldi	cr5,r31,0					; Is this guy on the release list?
			ld		r28,SACnext(r2)				; Get the forward chain

			rlwinm.	r0,r29,0,sac_permb,sac_permb	; Is this a permanently allocated area? (also sets 0 needed below)
			bne--	sttoss64					; This is permanent entry, do not try to release...

			ld		r29,SACprev(r2)				; and the previous
			beq--	cr5,stnot1st64				; Not first
			ld		r0,SACvrswap(r31)			; Load the previous pool page vr conversion
			
stnot1st64:	
            std		r28,SACnext(r29)			; Previous guy points to my next
			xor		r0,r0,r31					; Make the last guy virtual
			std		r29,SACprev(r28)			; Next guy points back to my previous 			
			std		r0,SAVprev(r2)				; Store the old top virtual as my back chain
			mr		r31,r2						; My physical is now the head of the chain
			b		sttoss64					; Get the next one...
			
;			A pool block that had no free entries now has one.  Stick it on the pool list.
			
stputpool64:
            ld		r28,SVpoolfwd(0)			; Get the first guy on the list
			li		r0,saveanchor				; Point to the saveanchor
			std		r2,SVpoolfwd(0)				; Put us on the top of the list
			std		r28,SACnext(r2)				; We point to the old top
			std		r2,SACprev(r28)				; Old top guy points back to us
			std		r0,SACprev(r2)				; Our back points to the anchor
			b		sttoss64					; Go on to the next one...
			

;			We are all done.  Relocate pool release head, restore all, and go.  This code
;			is used both by the 32 and 64-bit paths.
;  				 r9 = return address
;				r10 = per-proc ptr
;				r11 = MSR at entry
;				r31 = free pool block list

stdone:		bl		saveunlock					; Unlock the saveanchor and set adjust field

			mr.		r3,r31						; Move release chain and see if there are any
			li		r5,0						; Assume either V=R or no release chain
			beq-	stnorel						; Nothing to release...
			lwz		r5,SACvrswap+4(r31)			; Get the vr conversion (only need low half if 64-bit)

stnorel:	
            bl		saveRestore					; restore translation and exceptions, turn off SF
			mtlr	r9							; Restore the return
			
			lwz		r28,FM_SIZE+0(r1)			; Restore R28
			lwz		r29,FM_SIZE+4(r1)			; Restore R29
			lwz		r30,FM_SIZE+8(r1)			; Restore R30
			lwz		r31,FM_SIZE+12(r1)			; Restore R31
			addi	r1,r1,(FM_ALIGN(16)+FM_SIZE)	; Pop the stack
			xor		r3,r3,r5					; Convert release chain address to virtual
            rlwinm	r3,r3,0,0,31				; if 64-bit, clear upper half of virtual address
							
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2207					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			blr									; Return...
            
            
/*
 * ***************************
 * * s a v e _ r e c o v e r *
 * ***************************
 *
 *	int save_recover(void);
 *
 *	Returns nonzero if we can get enough saveareas to hit the target.  We scan the free
 * 	pool.  If we empty a pool block, we remove it from the pool list.
 */			
			
			.align	5
			.globl	EXT(save_recover)

LEXT(save_recover)
            mflr	r9							; save return address
            bl		saveSetup					; turn translation and interrupts off, SF on, load many regs
            bl		savelock					; lock the savearea anchor

			lwz		r8,SVadjust(0)				; How many do we need to clear get?
			li		r3,0						; Get a 0
			mr.		r8,r8						; Do we need any?
            ble--	save_recover1				; not any more
            bf--	pf64Bitb,saveRecover32		; handle 32-bit processor
            b		saveRecover64				; handle 64-bit processor
            
save_recover1:									; by the time we locked the anchor, no longer short
			mtlr	r9							; Restore return
			stw		r3,SVlock(0)				; Quick unlock (no need for sync or to set adjust, nothing changed)
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2208					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			b		saveRestore					; turn translation etc back on, return to our caller


/*
 * *****************************
 * * s a v e R e c o v e r 3 2 *
 * *****************************
 *
 *	Handle "save_recover" on 32-bit processors.  At this point, translation and interrupts
 *  are off, the savearea anchor is locked, and:
 *		 r8 = #pages to recover
 *	     r9 = return address
 *	 	r10 = per-proc ptr
 *		r11 = MSR at entry
 */

saveRecover32:
			li		r6,saveanchor				; Start at pool anchor
			crclr	cr1_eq						; initialize the loop test					
			lwz		r7,SVfreecnt(0)				; Get the current free count


; Loop over next block in free pool.  r6 is the ptr to the last block we looked at.

srcnpool:	lwz		r6,SACnext+4(r6)			; Point to the next one
			cmplwi	r6,saveanchor				; Have we wrapped?
			beq-	srcdone						; Yes, did not have enough...
			
			lwz		r5,SACalloc(r6)				; Pick up the allocation for this pool block
			
;
;			NOTE: The savearea size must be 640 (0x280).  We are doing a multiply by shifts and add.
;			offset = (index << 9) + (index << 7)
;
#if SAVsize != 640
#error Savearea size is not 640!!!!!!!!!!!!
#endif

; Loop over free savearea in current block.
;		 r5 = bitmap of free saveareas in block at r6 (ie, SACalloc)
;		 r6 = ptr to current free pool block
;		 r7 = free count
;		 r8 = #pages more we still need to recover
;	     r9 = return address
;	 	r10 = per-proc ptr
;		r11 = MSR at entry
;		cr1 = beq if (r8==0)

srcnext:	beq-	cr1,srcdone					; We have no more to get...

			lis		r3,0x8000					; Get the top bit on
			cntlzw	r4,r5						; Find a free slot
			addi	r7,r7,1						; Bump up the free count
			srw		r3,r3,r4					; Make a mask
			slwi	r0,r4,7						; First multiply by 128
			subi	r8,r8,1						; Decrement the need count
			slwi	r2,r4,9						; Then multiply by 512
			andc.	r5,r5,r3					; Clear out the "free" bit
			add		r2,r2,r0					; Sum to multiply by 640	
			
			stw		r5,SACalloc(r6)				; Set new allocation bits
			
			add		r2,r2,r6					; Get the actual address of the savearea
			lwz		r3,SVfree+4(0)				; Get the head of the chain
			cmplwi	cr1,r8,0					; Do we actually need any more?
			stw		r2,SVfree+4(0)				; Push ourselves in the front
			stw		r3,SAVprev+4(r2)			; Chain the rest of the list behind 
			
			bne+	srcnext						; The pool block is not empty yet, try for another...
			
			lwz		r2,SACnext+4(r6)			; Get the next pointer
			lwz		r3,SACprev+4(r6)			; Get the previous pointer
			stw		r3,SACprev+4(r2)			; The previous of my next points to my previous
			stw		r2,SACnext+4(r3)			; The next of my previous points to my next
			bne+	cr1,srcnpool				; We still have more to do...


; Join here from 64-bit path when we have recovered all the saveareas we need to.

srcdone:	stw		r7,SVfreecnt(0)				; Set the new free count
			bl		saveunlock					; Unlock the save and set adjust field

			mtlr	r9							; Restore the return
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2209					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			b		saveRestore					; turn xlate and EE back on, SF off, and return to our caller


/*
 * *****************************
 * * s a v e R e c o v e r 6 4 *
 * *****************************
 *
 *	Handle "save_recover" on 64-bit processors.  At this point, translation and interrupts
 *  are off, the savearea anchor is locked, and:
 *		 r8 = #pages to recover
 *	     r9 = return address
 *	 	r10 = per-proc ptr
 *		r11 = MSR at entry
 */

saveRecover64:
			li		r6,saveanchor				; Start at pool anchor
			crclr	cr1_eq						; initialize the loop test					
			lwz		r7,SVfreecnt(0)				; Get the current free count


; Loop over next block in free pool.  r6 is the ptr to the last block we looked at.

srcnpool64:	
            ld		r6,SACnext(r6)				; Point to the next one
			cmpldi	r6,saveanchor				; Have we wrapped?
			beq--	srcdone						; Yes, did not have enough...
			
			lwz		r5,SACalloc(r6)				; Pick up the allocation for this pool block
			

; Loop over free savearea in current block.
;		 r5 = bitmap of free saveareas in block at r6 (ie, SACalloc)
;		 r6 = ptr to current free pool block
;		 r7 = free count
;		 r8 = #pages more we still need to recover
;	     r9 = return address
;	 	r10 = per-proc ptr
;		r11 = MSR at entry
;		cr1 = beq if (r8==0)
;
; WARNING: as in the 32-bit path, we depend on (SAVsize==640)

srcnext64:	
            beq--	cr1,srcdone					; We have no more to get...

			lis		r3,0x8000					; Get the top bit on
			cntlzw	r4,r5						; Find a free slot
			addi	r7,r7,1						; Bump up the free count
			srw		r3,r3,r4					; Make a mask
			slwi	r0,r4,7						; First multiply by 128
			subi	r8,r8,1						; Decrement the need count
			slwi	r2,r4,9						; Then multiply by 512
			andc.	r5,r5,r3					; Clear out the "free" bit
			add		r2,r2,r0					; Sum to multiply by 640	
			
			stw		r5,SACalloc(r6)				; Set new allocation bits
			
			add		r2,r2,r6					; Get the actual address of the savearea
			ld		r3,SVfree(0)				; Get the head of the chain
			cmplwi	cr1,r8,0					; Do we actually need any more?
			std		r2,SVfree(0)				; Push ourselves in the front
			std		r3,SAVprev(r2)				; Chain the rest of the list behind 
			
			bne++	srcnext64					; The pool block is not empty yet, try for another...
			
			ld		r2,SACnext(r6)				; Get the next pointer
			ld		r3,SACprev(r6)				; Get the previous pointer
			std		r3,SACprev(r2)				; The previous of my next points to my previous
			std		r2,SACnext(r3)				; The next of my previous points to my next
			bne++	cr1,srcnpool64				; We still have more to do...
            
            b		srcdone


/* 
 * *******************
 * * s a v e l o c k *
 * *******************
 *
 *			Lock the savearea anchor, so we can manipulate the free list.
 *              msr = interrupts and translation off
 *			We destroy:
 *				r8, r3, r12
 */			
			.align	5

savelock:	lwz		r8,SVlock(0)				; See if lock is held
            cmpwi	r8,0
			li		r12,saveanchor				; Point to the saveanchor
			bne--	savelock					; loop until lock released...
		
savelock0:	lwarx	r8,0,r12					; Grab the lock value 
			cmpwi	r8,0						; taken?
            li		r8,1						; get nonzero to lock it with
			bne--	savelock1					; already locked, wait for it to clear...
			stwcx.	r8,0,r12					; Try to seize that there durn lock
            isync								; assume we got it
            beqlr++								; reservation not lost, so we have the lock
			b		savelock0					; Try again...
			
savelock1:	li		r8,lgKillResv				; Point to killing field
			stwcx.	r8,0,r8						; Kill reservation
			b		savelock					; Start over....
		

/*
 * ***********************
 * * s a v e u n l o c k *
 * ***********************
 *
 *
 *			This is the common routine that sets the saveadjust field and unlocks the savearea 
 *			anchor.
 *				msr = interrupts and translation off
 *			We destroy:
 *				r2, r5, r6, r8.
 */
			.align	5
saveunlock:
			lwz		r6,SVfreecnt(0)				; and the number on the free list
			lwz		r5,SVinuse(0)				; Pick up the in use count
            subic.	r8,r6,FreeListMin			; do we have at least the minimum?
			lwz		r2,SVtarget(0)				; Get the target
            neg		r8,r8						; assuming we are short, get r8 <- shortfall
            blt--	saveunlock1					; skip if fewer than minimum on free list
			
			add		r6,r6,r5					; Get the total number of saveareas
			addi	r5,r2,-SaveLowHysteresis	; Find low end of acceptible range
			sub		r5,r6,r5					; Make everything below hysteresis negative
			sub		r2,r2,r6					; Get the distance from the target
			addi	r5,r5,-(SaveLowHysteresis + SaveHighHysteresis + 1)	; Subtract full hysteresis range
			srawi	r5,r5,31					; Get 0xFFFFFFFF if outside range or 0 if inside
			and		r8,r2,r5					; r8 <- 0 if in range or distance to target if not

saveunlock1:
			li		r5,0						; Set a clear value
			stw		r8,SVadjust(0)				; Set the adjustment value			
			eieio								; Make sure everything is done
			stw		r5,SVlock(0)				; Unlock the savearea chain 
			blr


/*
 * *******************
 * * s a v e _ c p v *
 * *******************
 *
 *	struct savearea	*save_cpv(addr64_t saveAreaPhysAddr);
 *
 *          Converts a physical savearea address to virtual.  Called with translation on
 *			and in 32-bit mode.  Note that the argument is passed as a long long in (r3,r4).
 */

			.align	5
			.globl	EXT(save_cpv)

LEXT(save_cpv)
            mflr	r9							; save return address
            mr		r8,r3						; save upper half of phys address here
            bl		saveSetup					; turn off translation and interrupts, turn SF on
			rlwinm	r5,r4,0,0,19				; Round back to the start of the physical savearea block
            bf--	pf64Bitb,save_cpv1			; skip if 32-bit processor
            rldimi	r5,r8,32,0					; r5 <- 64-bit phys address of block
save_cpv1:
			lwz		r6,SACvrswap+4(r5)			; Get the conversion to virtual (only need low half if 64-bit)
            mtlr	r9							; restore return address
            xor		r3,r4,r6					; convert phys to virtual
            rlwinm	r3,r3,0,0,31				; if 64-bit, zero upper half of virtual address
            b		saveRestore					; turn translation etc back on, SF off, and return r3
				
			
/*
 * *********************
 * * s a v e S e t u p *
 * *********************
 *
 * This routine is called at the start of all the save-area subroutines.
 * It turns off translation, disabled interrupts, turns on 64-bit mode,
 * and sets up cr6 with the feature flags (especially pf64Bit).
 * 
 * Note that most save-area routines cannot take _any_ interrupt (such as a
 * PTE miss) once the savearea anchor is locked, since that would result in
 * instant deadlock as we need a save-area to process any exception.
 * We set up:
 *		r10 = per-proc ptr
 *		r11 = old MSR
 *		cr5 = pfNoMSRir feature flag
 *		cr6 = pf64Bit   feature flag
 *
 * We use r0, r3, r10, and r11.
 */
 
saveSetup:
            mfmsr	r11							; get msr
			mfsprg	r3,2						; get feature flags
			li		r0,0
            mtcrf	0x2,r3						; copy pf64Bit to cr6
            ori		r0,r0,lo16(MASK(MSR_IR)+MASK(MSR_DR)+MASK(MSR_EE))
            mtcrf	0x4,r3						; copy pfNoMSRir to cr5
            andc	r3,r11,r0					; turn off IR, DR, and EE
            li		r0,1						; get a 1 in case its a 64-bit machine
            bf--	pf64Bitb,saveSetup1			; skip if not a 64-bit machine
			rldimi	r3,r0,63,MSR_SF_BIT			; turn SF (bit 0) on
            mtmsrd	r3							; turn translation and interrupts off, 64-bit mode on
            isync								; wait for it to happen
            mfsprg	r10,0						; get per-proc ptr
            blr
saveSetup1:										; here on 32-bit machines
            bt-		pfNoMSRirb,saveSetup2		; skip if cannot turn off IR with a mtmsr
            mtmsr	r3							; turn translation and interrupts off
            isync								; wait for it to happen
            mfsprg	r10,0						; get per-proc ptr
            blr
saveSetup2:										; here if pfNoMSRir set for this machine
            li		r0,loadMSR					; we will "mtmsr r3" via system call
            sc
            mfsprg	r10,0						; get per-proc ptr
            blr
        
			
/*
 * *************************
 * * s a v e R e s t o r e *
 * *************************
 *
 * Undoes the effect of calling "saveSetup", ie it turns relocation and interrupts back on,
 * and turns 64-bit mode back off.
 *		r11 = old MSR
 *		cr6 = pf64Bit   feature flag
 */
 
saveRestore:
            bt++	pf64Bitb,saveRestore64		; handle a 64-bit processor
saveRestore32:
            mtmsr	r11							; restore MSR
            isync								; wait for translation to start up
            blr
saveRestore64:									; 64-bit processor
            mtmsrd	r11							; restore MSR
            isync								; wait for changes to happen
            blr

