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

#define FPVECDBG 0

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
#include <ppc/savearea.h>
#include <mach/ppc/vm_param.h>
	
			.text

/*
 *			This routine will add a savearea block to the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			We also queue the block to the free pool list.  This is a
 *			circular double linked list. Because this block has no free entries,
 *			it gets queued to the end of the list
 *
 */

			.align	5
			.globl	EXT(save_queue)

LEXT(save_queue)

			mfsprg	r9,2						; Get the feature flags
			mr		r11,r3						; Save the block
			mtcrf	0x04,r9						; Set the features			
			mfmsr	r12							; Get the MSR
			rlwinm	r12,r12,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r12,r12,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			lis		r10,hi16(EXT(saveanchor))	; Get the high part of the anchor
			andi.	r3,r12,0x7FCF				; Turn off all translation and rupts
			ori		r10,r10,lo16(EXT(saveanchor))	; Bottom half of the anchor 

			bt		pfNoMSRirb,sqNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		sqNoMSRx
			
sqNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
sqNoMSRx:
			
			rlwinm.	r3,r11,0,0,19				; (TEST/DEBUG)
#if 0
			bne+	notrapit					; (TEST/DEBUG)
			BREAKPOINT_TRAP						; (TEST/DEBUG) 
notrapit:										; (TEST/DEBUG)
#endif


			li		r8,sac_cnt					; Get the number of saveareas per page
			mr		r4,r11						; Point to start of chain
			li		r0,SAVempty					; Get empty marker

sqchain:	addic.	r8,r8,-1					; Keep track of how many we did
			stb		r0,SAVflags+2(r4)			; Set empty
			addi	r9,r4,SAVsize				; Point to the next slot
			ble-	sqchaindn					; We are done with the chain
			stw		r9,SAVprev(r4)				; Set this chain
			mr		r4,r9						; Step to the next
			b		sqchain						; Fill the whole block...

			.align	5

sqchaindn:	mflr	r9							; Save the return address
			bl		savelock					; Go lock the save anchor 

			lwz		r7,SVfree(r10)				; Get the free save area list anchor 
			lwz		r6,SVfreecnt(r10)			; Get the number of free saveareas

			stw		r11,SVfree(r10)				; Queue in the new one 
			addi	r6,r6,sac_cnt				; Count the ones we are linking in 
			stw		r7,SAVprev(r4)				; Queue the old first one off of us
			stw		r6,SVfreecnt(r10)			; Save the new count
			
			bl		saveunlock					; Unlock the list and set the adjust count
			
			mtlr	r9							; Restore the return
			mtmsr	r12							; Restore interrupts and translation 
			isync								; Dump any speculations 

#if FPVECDBG
			mfsprg	r2,0						; (TEST/DEBUG)
			lwz		r2,next_savearea(r2)		; (TEST/DEBUG)
			mr.		r2,r2						; (TEST/DEBUG)
			beqlr-								; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)			; (TEST/DEBUG)
			li		r2,0x2201					; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)		; (TEST/DEBUG)
			sc									; (TEST/DEBUG)
#endif

			blr									; Leave... 

/*
 *			This routine will obtain a savearea.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss during this process. That's
 *			a guaranteed deadlock or screwup.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			We pass back the virtual address of the one we just obtained
 *			or a zero if none to allocate.
 *
 *			First we try the local list.  If that is below a threshold, we will
 *			lock the free list and replenish.
 *
 *			If there are no saveareas in either list, we will install the 
 *			backpocket and choke.
 *
 *			The save_get_phys call assumes that translation and interruptions are
 *			already off and that the returned address is physical.
 *
 *			Note that save_get_init is used in initial processor startup only.  It
 *			is used because translation is on, but no tables exist yet and we have
 *			no V=R BAT registers that cover the entire physical memory.
 *
 *
 *			NOTE!!! NEVER USE R0, R2, or R12 IN HERE THAT WAY WE DON'T NEED A
 *			STACK FRAME IN FPU_SAVE, FPU_SWITCH, VEC_SAVE, OR VEC_SWITCH.
 */
 
			.align	5
			.globl	EXT(save_get_init)

LEXT(save_get_init)

			mfsprg	r9,2						; Get the feature flags
			mfmsr	r12							; Get the MSR 
			rlwinm	r12,r12,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r12,r12,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			mtcrf	0x04,r9						; Set the features			
			andi.	r3,r12,0x7FCF				; Turn off all translation and interrupts

			bt		pfNoMSRirb,sgiNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		sgiGetPhys					; Go get the savearea...
			
sgiNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it

sgiGetPhys:	mflr	r11							; Save R11 (save_get_phys does not use this one)
			bl		EXT(save_get_phys)			; Get a savearea
			mtlr	r11							; Restore return
			
			mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it
			blr									; Return...
 
			.align	5
			.globl	EXT(save_get)

LEXT(save_get)
			
			crclr	cr1_eq						; Clear CR1_eq to indicate we want virtual address
			mfsprg	r9,2						; Get the feature flags
			mfmsr	r11							; Get the MSR 
			rlwinm.	r3,r11,0,MSR_EE_BIT,MSR_EE_BIT	;	Are interrupts enabled here?
			beq+	sgnomess					; Nope, do not mess with fp or vec...
			rlwinm	r11,r11,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r11,r11,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off

sgnomess:	mtcrf	0x04,r9						; Set the features			
			andi.	r3,r11,0x7FCF				; Turn off all translation and interrupts

			bt		pfNoMSRirb,sgNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		csaveget
			
sgNoMSR:	mr		r9,r0						; Save this
			li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
			mr		r0,r9						; Restore it

			b		csaveget					; Join the common...

			.align	5
			.globl	EXT(save_get_phys)

LEXT(save_get_phys)
			
			crset	cr1_eq						; Clear CR1_ne to indicate we want physical address

csaveget:	mfsprg	r9,0						; Get the per proc
			lis		r10,hi16(EXT(saveanchor))	; Get the high part of the anchor
			lwz		r8,lclfreecnt(r9)			; Get the count
			lwz		r3,lclfree(r9)				; Get the start of local savearea list
			cmplwi	r8,LocalSaveMin				; Are we too low?
			ori		r10,r10,lo16(EXT(saveanchor))	; Bottom half of the anchor 
			ble-	sglow						; We are too low and need to grow list...
			
sgreserve:	lis		r10,0x5555					; Get top of empty indication
			li		r6,0						; zero value
			lwz		r4,SAVprev(r3)				; Chain to the next one
			stw		r6,SAVflags(r3)				; Clear flags
			ori		r10,r10,0x5555				; And the bottom
			subi	r8,r8,1						; Back down count
			stw		r10,SAVprev(r3)				; Trash this
			stw		r10,SAVlevel(r3)			; Trash this
			stw		r4,lclfree(r9)				; Unchain first savearea
			rlwinm	r5,r3,0,0,19				; Back up to first page where SAC is
			stw		r10,SAVact(r3)				; Trash this
			stw		r8,lclfreecnt(r9)			; Set new count
			
			btlr+	cr1_eq						; Return now if physical request
			
			lwz		r5,SACvrswap(r5)			; Get the virtual to real translation
			
			mtmsr	r11							; Restore translation and exceptions
			isync								; Make sure about it
	
#if FPVECDBG
;			Note: we do not trace the physical request because this ususally comes from the
;			exception vector code

			mr		r6,r0						; (TEST/DEBUG)
			mr		r7,r2						; (TEST/DEBUG) 
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2203					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc									; (TEST/DEBUG) 
			mr		r0,r6						; (TEST/DEBUG)
			mr		r2,r7						; (TEST/DEBUG)
#endif			
			
			xor		r3,r3,r5					; Get the virtual address 
			blr									; Leave...

;
;			Here is the slow path which is executed when there are not enough in the local list
;
					
			.align	5
						
sglow:		mflr	r9							; Save the return
			bl		savelock					; Go lock up the anchor
			mtlr	r9							; Restore the return
			
			subfic	r5,r8,LocalSaveTarget		; Get the number of saveareas we need to grab to get to target
			lwz		r9,SVfreecnt(r10)			; Get the number on this list
			lwz		r8,SVfree(r10)				; Get the head of the save area list 
			
			sub		r3,r9,r5					; Get number left after we swipe enough for local list
			srawi	r3,r3,31					; Get 0 if enough or 0xFFFFFFFF if not
			andc	r4,r5,r3					; Get number to get if there are enough, 0 otherwise
			and		r5,r9,r3					; Get 0 if there are enough, number on list otherwise
			or.		r5,r4,r5					; Get the number we will move
			beq-	sgnofree					; There are none to get...
			
			mtctr	r5							; Get loop count
			mr		r6,r8						; Remember the first in the list
			
sgtrimf:	bdz		sgtfdone					; Count down and branch when we hit 0...
			lwz		r8,SAVprev(r8)				; Get the next
			b		sgtrimf						; Keep going...

			.align	5
			
sgtfdone:	lwz		r7,SAVprev(r8)				; Get the next one
			lwz		r4,SVinuse(r10)				; Get the in use count
			sub		r9,r9,r5					; Count down what we stole
			stw		r7,SVfree(r10)				; Set the new first in list
			add		r4,r4,r5					; Count the ones we just put in the local list as "in use"
			stw		r9,SVfreecnt(r10)			; Set the new count
			mfsprg	r9,0						; Get the per proc
			stw		r4,SVinuse(r10)				; Set the new in use count
			
			lwz		r4,lclfree(r9)				; Get the old head of list
			lwz		r3,lclfreecnt(r9)			; Get the old count
			stw		r6,lclfree(r9)				; Set the new head of the list
			add		r3,r3,r5					; Get the new count
			stw		r4,SAVprev(r8)				; Point to the old head
			stw		r3,lclfreecnt(r9)			; Set the new count

			mflr	r9							; Save the return
			bl		saveunlock					; Update the adjust field and unlock
			mtlr	r9							; Restore return
			b		csaveget					; Start over and finally allocate the savearea...
			
;
;			The local list is below the repopulate threshold and the free list is empty.
;			First we check if there are any left in the local list and if so, we allow
;			them to be allocated.  If not, we release the backpocket list and choke.  
;			There is nothing more that we can do at this point.  Hopefully we stay alive
;			long enough to grab some much-needed panic information.
;
			
sgnofree:	mfsprg	r9,0						; Get the per proc
			lwz		r8,lclfreecnt(r9)			; Get the count
			lwz		r3,lclfree(r9)				; Get the start of local savearea list
			mr.		r8,r8						; Are there any reserve to get?

			mflr	r9							; Save the return
			beq-	sgchoke						; No, go choke and die...
			bl		saveunlock					; Update the adjust field and unlock
			mtlr	r9							; Restore return

			mfsprg	r9,0						; Get the per proc again
			lwz		r3,lclfree(r9)				; Get the start of local savearea list
			lwz		r8,lclfreecnt(r9)			; Get the count
			b		sgreserve					; We have some left, dip on in...
			
;
;			We who are about to die salute you.  The savearea chain is messed up or
;			empty.  Add in a few so we have enough to take down the system.
;

sgchoke:	lis		r9,hi16(EXT(backpocket))	; Get high order of back pocket
			ori		r9,r9,lo16(EXT(backpocket))	; and low part
			
			lwz		r8,SVfreecnt(r9)			; Get the new number of free elements
			lwz		r7,SVfree(r9)				; Get the head of the chain
			lwz		r6,SVinuse(r10)				; Get total in the old list

			stw		r8,SVfreecnt(r10)			; Set the new number of free elements
			add		r6,r6,r8					; Add in the new ones
			stw		r7,SVfree(r10)				; Set the new head of the chain
			stw		r6,SVinuse(r10)				; Set total in the new list

			lis		r0,hi16(Choke)				; Set choke firmware call
			li		r7,0						; Get a clear register to unlock
			ori		r0,r0,lo16(Choke)			; Set the rest of the choke call
			li		r3,failNoSavearea			; Set failure code

			sync								; Make sure all is committed
			stw		r7,SVlock(r10)				; Unlock the free list
			sc									; System ABEND



/*
 *			This routine will return a savearea to the free list.
 *			Note really well: we can take NO exceptions of any kind,
 *			including a PTE miss once the savearea lock is held. That's
 *			a guaranteed deadlock.  That means we must disable for interrutions
 *			and turn all translation off.
 *
 *			We take a virtual address for save_ret.  For save_ret_phys we
 *			assume we are already physical/interrupts off and the address is physical.
 *
 *			Here's a tricky bit, and important:
 *
 *			When we trim the list, we NEVER trim the very first one.  This is because that is
 *			the very last one released and the exception exit code will release the savearea
 *			BEFORE it is done using it. Wouldn't be too good if another processor started
 *			using it, eh?  So for this case, we are safe so long as the savearea stays on
 *			the local list.  (Note: the exit routine needs to do this because it is in the 
 *			process of restoring all context and it needs to keep it until the last second.)
 *
 */

;
;			Note: when called from interrupt enabled code, we want to turn off vector and
;			floating point because we can not guarantee that the enablement will not change
;			while we hold a copy of the MSR.  We force it off so that the lazy switcher will
;			turn it back on if used.  However, we need to NOT change it save_ret or save_get
;			is called with interrupts disabled.  This is because both of these routine are
;			called from within the context switcher and changing the enablement would be
;			very, very bad..... (especially from within the lazt switcher)
;

			.align	5
			.globl	EXT(save_ret)

LEXT(save_ret)

			mfmsr	r12							; Get the MSR 
			rlwinm.	r9,r12,0,MSR_EE_BIT,MSR_EE_BIT	;	Are interrupts enabled here?
			beq+	EXT(save_ret_join)			; Nope, do not mess with fp or vec...
			rlwinm	r12,r12,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r12,r12,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off

			.globl	EXT(save_ret_join)

LEXT(save_ret_join)
			crclr	cr1_eq						; Clear CR1_ne to indicate we have virtual address
			mfsprg	r9,2						; Get the feature flags
			rlwinm	r6,r3,0,0,19				; Round back down to the savearea page block
			lwz		r5,SACvrswap(r6)			; Get the conversion to real
			mtcrf	0x04,r9						; Set the features			
			mfsprg	r9,0						; Get the per proc
			xor		r8,r3,r5					; Get the real address of the savearea
			andi.	r3,r12,0x7FCF				; Turn off all translation and rupts

			bt		pfNoMSRirb,srNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		srcommon
			
			.align	5
			
srNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
srNoMSRx:	b		srcommon					; Join up below...


			.align	5
			.globl	EXT(save_ret_phys)

LEXT(save_ret_phys)

			mfsprg	r9,0						; Get the per proc
			crset	cr1_eq						; Clear CR1_ne to indicate we have physical address
			mr		r8,r3						; Save the savearea address

			nop

srcommon:	
			li		r0,SAVempty					; Get marker for free savearea
			lwz		r7,lclfreecnt(r9)			; Get the local count
			lwz		r6,lclfree(r9)				; Get the old local header
			addi	r7,r7,1						; Pop up the free count
			stw		r6,SAVprev(r8)				; Plant free chain pointer
			cmplwi	r7,LocalSaveMax				; Has the list gotten too long?
			stb		r0,SAVflags+2(r8)			; Mark savearea free
			stw		r8,lclfree(r9)				; Chain us on in
			stw		r7,lclfreecnt(r9)			; Bump up the count
			bgt-	srtrim						; List is too long, go trim it...
			
			btlr	cr1_eq						; Leave if we were a physical request...
			
			mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it
	
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2204					; (TEST/DEBUG)
			mr		r3,r8						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			blr									; Leave...

;
;			The local savearea chain has gotten too long.  Trim it down to the target.
;			Note: never trim the first one, just skip over it.
;

			.align	5

srtrim:		
			mr		r2,r8						; Save the guy we are releasing
			lwz		r8,SAVprev(r8)				; Skip over the first
			subi	r7,r7,LocalSaveTarget		; Figure out how much to trim	
			mr		r6,r8						; Save the first one to trim
			mr		r5,r7						; Save the number we are trimming
			
srtrimming:	addic.	r7,r7,-1					; Any left to do?
			ble-	srtrimmed					; Nope...
			lwz		r8,SAVprev(r8)				; Skip to the next one
			b		srtrimming					; Keep going...
			
			.align	5

srtrimmed:	lis		r10,hi16(EXT(saveanchor))	; Get the high part of the anchor	
			lwz		r7,SAVprev(r8)				; Point to the next one
			ori		r10,r10,lo16(EXT(saveanchor))	; Bottom half of the anchor 
			li		r4,LocalSaveTarget			; Set the target count
			stw		r7,SAVprev(r2)				; Trim stuff leaving the one just released as first
			stw		r4,lclfreecnt(r9)			; Set the current count
			
			mflr	r9							; Save the return
			bl		savelock					; Lock up the anchor
			
			lwz		r3,SVfree(r10)				; Get the old head of the free list
			lwz		r4,SVfreecnt(r10)			; Get the number of free ones
			lwz		r7,SVinuse(r10)				; Get the number that are in use
			stw		r6,SVfree(r10)				; Point to the first trimmed savearea
			add		r4,r4,r5					; Add number trimmed to free count
			stw		r3,SAVprev(r8)				; Chain the old head to the tail of the trimmed guys
			sub		r7,r7,r5					; Remove the trims from the in use count
			stw		r4,SVfreecnt(r10)			; Set new free count
			stw		r7,SVinuse(r10)				; Set new in use count

			bl		saveunlock					; Set adjust count and unlock the saveanchor

			mtlr	r9							; Restore the return

			btlr+	cr1_eq						; Leave if we were a physical request...
			
			mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it
	
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			mr		r3,r2						; (TEST/DEBUG)
			li		r2,0x2205					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			blr									; Leave...


;
;			NOTE: This is the most complicated part of savearea maintainence. 
;			      Expect errors here.......
;
;			save_trim_free - this routine will trim the free list down to the target count.
;			It trims the list and, if the pool page was fully allocated, puts that page on 
;			the start of the pool list.
;
;			If the savearea being released is the last on a pool page (i.e., all entries
;			are released), the page is dequeued from the pool and queued to any other 
;			found during this scan.  Note that this queue is maintained virtually.
;
;			When the scan is done, the saveanchor lock is released and the list of
;			freed pool pages is returned.


;			For latency sake we may want to revisit this code. If we are trimming a
;			large number of saveareas, we could be disabled and holding the savearea lock
;			for quite a while.  It may be that we want to break the trim down into parts.
;			Possibly trimming the free list, then individually pushing them into the free pool.
;
;			This function expects to be called with translation on and a valid stack.
;

			.align	5
			.globl	EXT(save_trim_free)

LEXT(save_trim_free)

			subi	r1,r1,(FM_ALIGN(16)+FM_SIZE)	; Make space for 4 registers on stack
			mfsprg	r9,2						; Get the feature flags
			stw		r28,FM_SIZE+0(r1)			; Save R28
			mfmsr	r12							; Get the MSR 
			rlwinm	r12,r12,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r12,r12,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			stw		r29,FM_SIZE+4(r1)			; Save R28
			mtcrf	0x04,r9						; Set the features			
			stw		r30,FM_SIZE+8(r1)			; Save R28
			lis		r10,hi16(EXT(saveanchor))	; Get the high part of the anchor	
			stw		r31,FM_SIZE+12(r1)			; Save R28
			andi.	r3,r12,0x7FCF				; Turn off all translation and rupts
			ori		r10,r10,lo16(EXT(saveanchor))	; Bottom half of the anchor 
			mflr	r9							; Save the return

			bt		pfNoMSRirb,stNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		stNoMSRx
			
			.align	5
			
stNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
			
stNoMSRx:	bl		savelock					; Go lock up the anchor

			lwz		r8,SVadjust(r10)			; How many do we need to clear out?
			li		r3,0						; Get a 0
			neg.	r8,r8						; Get the actual we need to toss (adjust is neg if too many)
			lwz		r7,SVfree(r10)				; Get the first on the free list
			bgt+	stneedtrim					; Yeah, we still need it...
			
			mtlr	r9							; Restore return
			stw		r3,SVlock(r10)				; Quick unlock (no need for sync or to set adjust, nothing changed)

			mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it
	
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2206					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			addi	r1,r1,(FM_ALIGN(16)+FM_SIZE)	; Pop stack - have not trashed register so no need to reload
			blr									; Leave...

			.align	5
			
stneedtrim:	mr		r6,r7						; Save the first one 
			mr		r5,r8						; Save the number we are trimming
			
			nop
			nop
			
sttrimming:	addic.	r5,r5,-1					; Any left to do?
			ble-	sttrimmed					; Nope...
			lwz		r7,SAVprev(r7)				; Skip to the next one
			b		sttrimming					; Keep going...
			
			.align	5

sttrimmed:	lwz		r5,SAVprev(r7)				; Get the next one (for new head of free list)
			lwz		r4,SVfreecnt(r10)			; Get the free count
			stw		r5,SVfree(r10)				; Set new head
			sub		r4,r4,r8					; Calculate the new free count
			li		r31,0						; Show we have no free pool blocks yet
			cmplwi	cr1,r5,0					; Make sure this is not equal
			stw		r4,SVfreecnt(r10)			; Set new free count
			lis		r30,hi16(sac_empty)			; Get what empty looks like
			
;
;			NOTE: The savearea size must be 640 (0x280).  We are doing a divide by shifts and stuff
;			here.
;
#if SAVsize != 640
#error Savearea size is not 640!!!!!!!!!!!!
#endif

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
			lwz		r6,SAVprev(r6)				; Chain to the next trimmed savearea
			cmplw	cr7,r30,r5					; Does this look empty?
			stw		r5,SACalloc(r2)				; Save back the allocation bits
			beq-	stputpool					; First free entry, go put it into the pool...
			bne+	cr7,sttoss					; Not an empty block
			
;
;			We have an empty block.  Remove it from the pool list.
;
			
			lwz		r29,SACflags(r2)			; Get the flags
			cmplwi	cr5,r31,0					; Is this guy on the release list?
			lwz		r28,SACnext(r2)				; Get the forward chain

			rlwinm.	r0,r29,0,sac_permb,sac_permb	; Is this a permanently allocated area? (also sets 0 needed below)
			bne-	sttoss						; This is permanent entry, do not try to release...

			lwz		r29,SACprev(r2)				; and the previous
			beq-	cr5,stnot1st				; Not first
			lwz		r0,SACvrswap(r31)			; Load the previous pool page vr conversion
			
stnot1st:	stw		r28,SACnext(r29)			; Previous guy points to my next
			xor		r0,r0,r31					; Make the last guy virtual
			stw		r29,SACprev(r28)			; Next guy points back to my previous 			
			stw		r0,SAVprev(r2)				; Store the old top virtual as my back chain
			mr		r31,r2						; My physical is now the head of the chain
			b		sttoss						; Get the next one...
			
;
;			A pool block that had no free entries now has one.  Stick it on the pool list.
;
			
			.align	5
			
stputpool:	lwz		r28,SVpoolfwd(r10)			; Get the first guy on the list
			stw		r2,SVpoolfwd(r10)			; Put us on the top of the list
			stw		r28,SACnext(r2)				; We point to the old top
			stw		r2,SACprev(r28)				; Old top guy points back to us
			stw		r10,SACprev(r2)				; Our back points to the anchor
			b		sttoss						; Go on to the next one...
			
;
;			We are all done.  Relocate pool release head, restore all, and go.
;			

			.align	5
			
stdone:		bl		saveunlock					; Unlock the saveanchor and set adjust field

			mr.		r3,r31						; Move release chain and see if there are any
			li		r5,0						; Assume either V=R or no release chain
			beq-	stnorel						; Nothing to release...
			lwz		r5,SACvrswap(r31)			; Get the vr conversion

stnorel:	mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it

			mtlr	r9							; Restore the return
			
			lwz		r28,FM_SIZE+0(r1)			; Restore R28
			lwz		r29,FM_SIZE+4(r1)			; Restore R29
			lwz		r30,FM_SIZE+8(r1)			; Restore R30
			lwz		r31,FM_SIZE+12(r1)			; Restore R31
			addi	r1,r1,(FM_ALIGN(16)+FM_SIZE)	; Pop the stack
			xor		r3,r3,r5					; Convert release chain address to virtual
							
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2207					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			blr									; Return...
			
;
;			save_recover - here we scan the free pool and see if we can get
;			enough free saveareas to hit target.
;
;			If we empty a pool block, remove it from the pool list
;
;
			
			.align	5
			.globl	EXT(save_recover)

LEXT(save_recover)
			mfsprg	r9,2						; Get the feature flags
			mfmsr	r12							; Get the MSR 
			rlwinm	r12,r12,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r12,r12,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			mtcrf	0x04,r9						; Set the features			
			lis		r10,hi16(EXT(saveanchor))	; Get the high part of the anchor	
			andi.	r3,r12,0x7FCF				; Turn off all translation and rupts
			ori		r10,r10,lo16(EXT(saveanchor))	; Bottom half of the anchor 
			mflr	r9							; Save the return

			bt		pfNoMSRirb,srcNoMSR			; No MSR...

			mtmsr	r3							; Translation and all off
			isync								; Toss prefetch
			b		srcNoMSRx
			
			.align	5
			
srcNoMSR:	li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
			
srcNoMSRx:	bl		savelock					; Go lock up the anchor

			lwz		r8,SVadjust(r10)			; How many do we need to clear get?
			li		r3,0						; Get a 0
			mr.		r8,r8						; Do we need any?
			bgt+	srcneedmore					; Yeah, we still need it...
			
			mtlr	r9							; Restore return
			stw		r3,SVlock(r10)				; Quick unlock (no need for sync or to set adjust, nothing changed)

			mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it
	
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2208					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			blr									; Leave...

			.align	5
	
srcneedmore:
			mr		r6,r10						; Start at pool anchor
			cmplwi	cr1,r10,0					; Make sure we start as not equal					
			lwz		r7,SVfreecnt(r10)			; Get the current free count
			
srcnpool:	lwz		r6,SACnext(r6)				; Point to the next one
			cmplw	r6,r10						; Have we wrapped?
			beq-	srcdone						; Yes, did not have enough...
			
			lwz		r5,SACalloc(r6)				; Pick up the allocation for this pool block
			
;
;			NOTE: The savearea size must be 640 (0x280).  We are doing a multiply by shifts and add.
;			offset = (index << 9) + (index << 7)
;
#if SAVsize != 640
#error Savearea size is not 640!!!!!!!!!!!!
#endif

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
			lwz		r3,SVfree(r10)				; Get the head of the chain
			cmplwi	cr1,r8,0					; Do we actually need any more?
			stw		r2,SVfree(r10)				; Push ourselves in the front
			stw		r3,SAVprev(r2)				; Chain the rest of the list behind 
			
			bne+	srcnext						; The pool block is not empty yet, try for another...
			
			lwz		r2,SACnext(r6)				; Get the next pointer
			lwz		r3,SACprev(r6)				; Get the previous pointer
			stw		r3,SACprev(r2)				; The previous of my next points to my previous
			stw		r2,SACnext(r3)				; The next of my previous points to my next
			bne+	cr1,srcnpool				; We still have more to do...
			
srcdone:	stw		r7,SVfreecnt(r10)			; Set the new free count
			bl		saveunlock					; Unlock the save and set adjust field

			mtlr	r9							; Restore the return
			mtmsr	r12							; Restore translation and exceptions
			isync								; Make sure about it
	
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)		; (TEST/DEBUG)
			li		r2,0x2209					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG) 
			sc									; (TEST/DEBUG) 
#endif
			blr									; Leave...
			
;
;			Here is where we lock the saveanchor lock
;			We assume R10 points to the saveanchor
;			We trash R7 and R3
;

			.align	5
	
savelock:	lwarx	r7,0,r10					; Grab the lock value 
			li		r3,1						; Use part of the delay time 
			mr.		r7,r7						; Is it locked? */
			bne-	sllcks						; Yeah, wait for it to clear...
			stwcx.	r3,0,r10					; Try to seize that there durn lock
			beq+	sllckd						; Got it...
			b		savelock					; Collision, try again...

			.align	5
			
sllcks:		lwz		r7,SVlock(r10)				; Get that lock in here
			mr.		r7,r7						; Is it free yet?
			beq+	savelock					; Yeah, try for it again...
			b		sllcks						; Sniff away...
			
			nop									; Force isync to last in ifetch buffer
			nop
			nop
			
sllckd:		isync								; Make sure translation is off
			blr									; Return....


;
;			This is the common routine that sets the saveadjust field and unlocks the savearea 
;			anchor.
;			
;			Note that we can not use R9 here because we use it to save the LR across the call.
;			Also, R10 is assumed to point to the saveanchor. R3 is also reserved.
;

			.align	5

saveunlock:
			lwz		r6,SVfreecnt(r10)			; and the number on the free list
			lwz		r5,SVinuse(r10)				; Pick up the in use count
			cmplwi	r6,FreeListMin				; Do we have at least the minimum?
			blt-	sutooshort					; Do not have minumum....
			lwz		r7,SVtarget(r10)			; Get the target
			
			add		r6,r6,r5					; Get the total number of saveareas
			addi	r5,r7,-SaveLowHysteresis	; Find bottom
			sub		r5,r6,r5					; Make everything below hysteresis negative
			sub		r7,r7,r6					; Get the distance from the target
			rlwinm	r5,r5,0,0,31				; Clear negative bit
			addi	r5,r5,-(SaveLowHysteresis + SaveHighHysteresis + 1)	; Subtract full hysteresis range
			srawi	r5,r5,31					; Get 0xFFFFFFFF if outside range or 0 if inside
			and		r7,r7,r5					; Get 0 if in range or distance to target if not

			li		r8,0						; Set a clear value
			stw		r7,SVadjust(r10)			; Set the adjustment value			

			sync								; Make sure everything is done
			stw		r8,SVlock(r10)				; Unlock the savearea chain 
			blr
			
			.align	5
			
sutooshort:	subfic	r6,r6,FreeListMin			; Get the number needed to hit minimum
			li		r8,0						; Set a clear value
			stw		r6,SVadjust(r10)			; Set the adjustment value			

			sync								; Make sure everything is done
			stw		r8,SVlock(r10)				; Unlock the savearea chain 
			blr




/*
 *			struct savearea	*save_cpv(struct savearea *);	 Converts a physical savearea address to virtual
 */

			.align	5
			.globl	EXT(save_cpv)

LEXT(save_cpv)
			
			mfmsr	r10							; Get the current MSR
			rlwinm	r10,r10,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r10,r10,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r4,r3,0,0,19				; Round back to the start of the physical savearea block
			andi.	r9,r10,0x7FEF				; Turn off interrupts and data translation
			mtmsr	r9							; Disable DR and EE
			isync
			
			lwz		r4,SACvrswap(r4)			; Get the conversion to virtual
			mtmsr	r10							; Interrupts and DR back on
			isync
			xor		r3,r3,r4					; Convert to physical
			blr
