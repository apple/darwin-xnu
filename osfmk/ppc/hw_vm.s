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
#include <mach/ppc/vm_param.h>
	
			.text

;
;                                     0        0        1        2        3        4        4        5      6
;                                     0        8        6        4        2        0        8        6      3 
;                                    +--------+--------+--------+--------+--------+--------+--------+--------+
;                                    |00000000|00000SSS|SSSSSSSS|SSSSSSSS|SSSSPPPP|PPPPPPPP|PPPPxxxx|xxxxxxxx|          - EA
;                                    +--------+--------+--------+--------+--------+--------+--------+--------+
;
;                                                       0        0        1
;                                                       0        8        6      
;                                                      +--------+--------+--------+
;                                                      |//////BB|BBBBBBBB|BBBB////|                                     - SID - base
;                                                      +--------+--------+--------+
;
;                                     0        0        1
;                                     0        8        6      
;                                    +--------+--------+--------+
;                                    |////////|11111111|111111//|                                                       - SID - copy 1
;                                    +--------+--------+--------+
;
;                   0        0        1
;                   0        8        6      
;                  +--------+--------+--------+
;                  |////////|//222222|22222222|                                                                         - SID - copy 2
;                  +--------+--------+--------+
;
;          0        0        1
;          0        8        6      
;         +--------+--------+--------+
;         |//////33|33333333|33//////|                                                                                  - SID - copy 3 - not needed
;         +--------+--------+--------+                                                                                         for 65 bit VPN
;
;                   0        0        1        2        3        4        4  5   5  
;                   0        8        6        4        2        0        8  1   5  
;                  +--------+--------+--------+--------+--------+--------+--------+
;                  |00000000|00000002|22222222|11111111|111111BB|BBBBBBBB|BBBB////|                                     - SID Hash - this is all
;                  +--------+--------+--------+--------+--------+--------+--------+                                           SID copies ORed
;                   0        0        1        2        3        4        4  5   5  
;                   0        8        6        4        2        0        8  1   5  
;                  +--------+--------+--------+--------+--------+--------+--------+
;                  |00000000|0000000S|SSSSSSSS|SSSSSSSS|SSSSSS00|00000000|0000////|                                      - Shifted high order EA
;                  +--------+--------+--------+--------+--------+--------+--------+                                           left shifted "segment"
;                                                                                                                             part of EA to make
;                                                                                                                             room for SID base
;
;
;                   0        0        1        2        3        4        4  5   5  
;                   0        8        6        4        2        0        8  1   5  
;                  +--------+--------+--------+--------+--------+--------+--------+
;                  |00000000|0000000V|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVV////|                                     - VSID - SID Hash XORed
;                  +--------+--------+--------+--------+--------+--------+--------+                                            with shifted EA
;
;                   0        0        1        2        3        4        4        5        6        7      7
;                   0        8        6        4        2        0        8        6        4        2      9
;                  +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
;                  |00000000|0000000V|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVVPPPP|PPPPPPPP|PPPPxxxx|xxxxxxxx|          - VPN
;                  +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
;


/*			addr64_t hw_add_map(struct pmap *pmap, struct mapping *mp) - Adds a mapping
 *
 *			Maps a page or block into a pmap
 *
 *			Returns 0 if add worked or the vaddr of the first overlap if not
 *
 * Make mapping - not block or I/O - note: this is low-level, upper should remove duplicates
 *  
 *  1) bump mapping busy count
 *  2) lock pmap share
 *  3) find mapping full path - finds all possible list previous elements
 *  4) upgrade pmap to exclusive
 *  5) add mapping to search list
 *  6) find physent
 *  7) lock physent
 *  8) add to physent
 *  9) unlock physent
 * 10) unlock pmap
 * 11) drop mapping busy count
 * 
 * 
 * Make mapping - block or I/O - note: this is low-level, upper should remove duplicates
 *  
 *  1) bump mapping busy count
 *  2) lock pmap share
 *  3) find mapping full path - finds all possible list previous elements
 *  4) upgrade pmap to exclusive
 *  5) add mapping to search list
 *  6) unlock pmap
 *  7) drop mapping busy count
 * 
 */

			.align	5
			.globl	EXT(hw_add_map)

LEXT(hw_add_map)
 			
 			stwu	r1,-(FM_ALIGN((31-17+1)*4)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r17,FM_ARG0+0x00(r1)		; Save a register
			stw		r18,FM_ARG0+0x04(r1)		; Save a register
			stw		r19,FM_ARG0+0x08(r1)		; Save a register
 			mfsprg	r19,2						; Get feature flags 
			stw		r20,FM_ARG0+0x0C(r1)		; Save a register
			stw		r21,FM_ARG0+0x10(r1)		; Save a register
			mtcrf	0x02,r19					; move pf64Bit cr6
			stw		r22,FM_ARG0+0x14(r1)		; Save a register
			stw		r23,FM_ARG0+0x18(r1)		; Save a register
			stw		r24,FM_ARG0+0x1C(r1)		; Save a register
			stw		r25,FM_ARG0+0x20(r1)		; Save a register
			stw		r26,FM_ARG0+0x24(r1)		; Save a register
			stw		r27,FM_ARG0+0x28(r1)		; Save a register
			stw		r28,FM_ARG0+0x2C(r1)		; Save a register
			stw		r29,FM_ARG0+0x30(r1)		; Save a register
			stw		r30,FM_ARG0+0x34(r1)		; Save a register
			stw		r31,FM_ARG0+0x38(r1)		; Save a register
			stw		r0,(FM_ALIGN((31-17+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r3)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active?
			bne		hamPanic					; Call not valid for guest shadow assist pmap
#endif
			
			rlwinm	r11,r4,0,0,19				; Round down to get mapping block address
  			mr		r28,r3						; Save the pmap
  			mr		r31,r4						; Save the mapping
			bt++	pf64Bitb,hamSF1				; skip if 64-bit (only they take the hint)
			lwz		r20,pmapvr+4(r3)			; Get conversion mask for pmap
			lwz		r21,mbvrswap+4(r11)			; Get conversion mask for mapping

			b		hamSF1x						; Done...
			
hamSF1:		ld		r20,pmapvr(r3)				; Get conversion mask for pmap
			ld		r21,mbvrswap(r11)			; Get conversion mask for mapping

hamSF1x:	bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit
			
			mr		r17,r11						; Save the MSR
			xor		r28,r28,r20					; Convert the pmap to physical addressing
			xor		r31,r31,r21					; Convert the mapping to physical addressing
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			lwz		r24,mpFlags(r31)			; Pick up the flags
			bne--	hamBadLock					; Nope...

			li		r21,0						; Remember that we have the shared lock
			
;
;			Note that we do a full search (i.e., no shortcut level skips, etc.)
;			here so that we will know the previous elements so we can dequeue them
;			later.
;

hamRescan:	lwz		r4,mpVAddr(r31)				; Get the new vaddr top half
			lwz		r5,mpVAddr+4(r31)			; Get the new vaddr bottom half
			mr		r3,r28						; Pass in pmap to search
			lhz		r23,mpBSize(r31)			; Get the block size for later
			mr		r29,r4						; Save top half of vaddr for later
			mr		r30,r5						; Save bottom half of vaddr for later
			
			bl		EXT(mapSearchFull)			; Go see if we can find it
			
			li		r22,lo16(0x800C)			; Get 0xFFFF800C
			rlwinm	r0,r24,mpBSub+1,31,31		; Rotate to get 0 if 4K bsu or 1 if 32MB bsu
			addi	r23,r23,1					; Get actual length
			rlwnm	r22,r22,r0,27,31			; Rotate to get 12 or 25
			lis		r0,0x8000					; Get 0xFFFFFFFF80000000
			slw		r9,r23,r22					; Isolate the low part
			rlwnm	r22,r23,r22,22,31			; Extract the high order
			addic	r23,r9,-4096				; Get the length to the last page
			add		r0,r0,r0					; Get 0xFFFFFFFF00000000 for 64-bit or 0 for 32-bit
			addme	r22,r22						; Do high order as well...
			mr.		r3,r3						; Did we find a mapping here?
			or		r0,r30,r0					; Fill high word of 64-bit with 1s so we will properly carry
			bne--	hamOverlay					; We found a mapping, this is no good, can not double map...

			addc	r9,r0,r23					; Add size to get last page in new range
			or.		r0,r4,r5					; Are we beyond the end?
			adde	r8,r29,r22					; Add the rest of the length on
			rlwinm	r9,r9,0,0,31				; Clean top half of sum
			beq++	hamFits						; We are at the end...

			cmplw	cr1,r9,r5					; Is the bottom part of our end less?
			cmplw	r8,r4						; Is our end before the next (top part)
			crand	cr0_eq,cr0_eq,cr1_lt		; Is the second half less and the first half equal?
			cror	cr0_eq,cr0_eq,cr0_lt		; Or is the top half less
			
			bf--	cr0_eq,hamOverlay			; No, we do fit, there is an overlay...
			
;
;			Here we try to convert to an exclusive lock.  This will fail if someone else
;			has it shared.
;
hamFits:	mr.		r21,r21						; Do we already have the exclusive lock?			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			
			bne--	hamGotX						; We already have the exclusive...
			
			bl		sxlkPromote					; Try to promote shared to exclusive
			mr.		r3,r3						; Could we?
			beq++	hamGotX						; Yeah...
			
;
;			Since we could not promote our lock, we need to convert to it.
;			That means that we drop the shared lock and wait to get it
;			exclusive.  Since we release the lock, we need to do the look up
;			again.
;			
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkConvert					; Convert shared to exclusive
			mr.		r3,r3						; Could we?
			bne--	hamBadLock					; Nope, we must have timed out...
			
			li		r21,1						; Remember that we have the exclusive lock
			b		hamRescan					; Go look again...
			
			.align	5

hamGotX:	mr		r3,r28						; Get the pmap to insert into
			mr		r4,r31						; Point to the mapping
			bl		EXT(mapInsert)				; Insert the mapping into the list

			rlwinm	r11,r24,mpPcfgb+2,mpPcfg>>6	; Get the index into the page config table
			lhz		r8,mpSpace(r31)				; Get the address space
			lwz		r11,lgpPcfg(r11)			; Get the page config
			mfsdr1	r7							; Get the hash table base/bounds
			lwz		r4,pmapResidentCnt(r28)		; Get the mapped page count 
			
			andi.	r0,r24,mpType				; Is this a normal mapping?

			rlwimi	r8,r8,14,4,17				; Double address space
			rlwinm	r9,r30,0,4,31				; Clear segment
			rlwinm	r10,r30,18,14,17			; Shift EA[32:35] down to correct spot in VSID (actually shift up 14)
			rlwimi	r8,r8,28,0,3				; Get the last nybble of the hash
			rlwimi	r10,r29,18,0,13				; Shift EA[18:31] down to VSID (31-bit math works because of max hash table size)			
			rlwinm	r7,r7,0,16,31				; Isolate length mask (or count)
			addi	r4,r4,1						; Bump up the mapped page count
			srw		r9,r9,r11					; Isolate just the page index
			xor		r10,r10,r8					; Calculate the low 32 bits of the VSID
			stw		r4,pmapResidentCnt(r28)		; Set the mapped page count 
			xor		r9,r9,r10					; Get the hash to the PTEG
			
			bne--	hamDoneNP					; Not a normal mapping, therefore, no physent...
			
			bl		mapPhysFindLock				; Go find and lock the physent
			
			bt++	pf64Bitb,ham64				; This is 64-bit...
			
			lwz		r11,ppLink+4(r3)			; Get the alias chain pointer
			rlwinm	r7,r7,16,0,15				; Get the PTEG wrap size
			slwi	r9,r9,6						; Make PTEG offset
			ori		r7,r7,0xFFC0				; Stick in the bottom part
			rlwinm	r12,r11,0,~ppFlags			; Clean it up
			and		r9,r9,r7					; Wrap offset into table
			mr		r4,r31						; Set the link to install
			stw		r9,mpPte(r31)				; Point the mapping at the PTEG (exact offset is invalid)
			stw		r12,mpAlias+4(r31)			; Move to the mapping
			bl		mapPhyCSet32				; Install the link
			b		hamDone						; Go finish up...
			
			.align	5
			
ham64:		li		r0,ppLFAmask				; Get mask to clean up alias pointer
			subfic	r7,r7,46					; Get number of leading zeros
			eqv		r4,r4,r4					; Get all ones
			ld		r11,ppLink(r3)				; Get the alias chain pointer
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			srd		r4,r4,r7					; Get the wrap mask
			sldi	r9,r9,7						; Change hash to PTEG offset
			andc	r11,r11,r0					; Clean out the lock and flags
			and		r9,r9,r4					; Wrap to PTEG
			mr		r4,r31
			stw		r9,mpPte(r31)				; Point the mapping at the PTEG (exact offset is invalid)
			std		r11,mpAlias(r31)			; Set the alias pointer in the mapping

			bl		mapPhyCSet64				; Install the link
						
hamDone:	bl		mapPhysUnlock				; Unlock the physent chain

hamDoneNP:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			mr		r3,r31						; Get the mapping pointer
			bl		mapDropBusy					; Drop the busy count
			
			li		r3,0						; Set successful return
			li		r4,0						; Set successful return

hamReturn:	bt++	pf64Bitb,hamR64				; Yes...

			mtmsr	r17							; Restore enables/translation/etc.
			isync
			b		hamReturnC					; Join common...

hamR64:		mtmsrd	r17							; Restore enables/translation/etc.
			isync								
			
hamReturnC:	lwz		r0,(FM_ALIGN((31-17+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Get the return
			lwz		r17,FM_ARG0+0x00(r1)		; Save a register
			lwz		r18,FM_ARG0+0x04(r1)		; Save a register
			lwz		r19,FM_ARG0+0x08(r1)		; Save a register
			lwz		r20,FM_ARG0+0x0C(r1)		; Save a register
			mtlr	r0							; Restore the return
			lwz		r21,FM_ARG0+0x10(r1)		; Save a register
			lwz		r22,FM_ARG0+0x14(r1)		; Save a register
			lwz		r23,FM_ARG0+0x18(r1)		; Save a register
			lwz		r24,FM_ARG0+0x1C(r1)		; Save a register
			lwz		r25,FM_ARG0+0x20(r1)		; Save a register
			lwz		r26,FM_ARG0+0x24(r1)		; Save a register
			lwz		r27,FM_ARG0+0x28(r1)		; Save a register
			lwz		r28,FM_ARG0+0x2C(r1)		; Save a register
			lwz		r29,FM_ARG0+0x30(r1)		; Save a register
			lwz		r30,FM_ARG0+0x34(r1)		; Save a register
			lwz		r31,FM_ARG0+0x38(r1)		; Save a register
			lwz		r1,0(r1)					; Pop the stack
			
			blr									; Leave...

			
			.align	5

hamOverlay:	lwz		r22,mpFlags(r3)				; Get the overlay flags
			li		r0,mpC|mpR					; Get a mask to turn off RC bits
			lwz		r23,mpFlags(r31)			; Get the requested flags
			lwz		r20,mpVAddr(r3)				; Get the overlay address
			lwz		r8,mpVAddr(r31)				; Get the requested address
			lwz		r21,mpVAddr+4(r3)			; Get the overlay address
			lwz		r9,mpVAddr+4(r31)			; Get the requested address
			lhz		r10,mpBSize(r3)				; Get the overlay length
			lhz		r11,mpBSize(r31)			; Get the requested length
			lwz		r24,mpPAddr(r3)				; Get the overlay physical address
			lwz		r25,mpPAddr(r31)			; Get the requested physical address
			andc	r21,r21,r0					; Clear RC bits
			andc	r9,r9,r0					; Clear RC bits

			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			rlwinm.	r0,r22,0,mpRIPb,mpRIPb		; Are we in the process of removing this one?
			mr		r3,r20						; Save the top of the colliding address
			rlwinm	r4,r21,0,0,19				; Save the bottom of the colliding address

			bne++	hamRemv						; Removing, go say so so we help...
			
			cmplw	r20,r8						; High part of vaddr the same?
			cmplw	cr1,r21,r9					; Low part?
			crand	cr5_eq,cr0_eq,cr1_eq		; Remember if same
			
			cmplw	r10,r11						; Size the same?
			cmplw	cr1,r24,r25					; Physical address?
			crand	cr5_eq,cr5_eq,cr0_eq		; Remember
			crand	cr5_eq,cr5_eq,cr1_eq		; Remember if same
			
			xor		r23,r23,r22					; Compare mapping flag words
			andi.	r23,r23,mpType|mpPerm		; Are mapping types and attributes the same?
			crand	cr5_eq,cr5_eq,cr0_eq		; Merge in final check
			bf--	cr5_eq,hamSmash				; This is not the same, so we return a smash...
			
			ori		r4,r4,mapRtMapDup			; Set duplicate
			b		hamReturn					; And leave...
			
hamRemv:	ori		r4,r4,mapRtRemove			; We are in the process of removing the collision
			b		hamReturn					; Come back yall...
			
hamSmash:	ori		r4,r4,mapRtSmash			; Tell caller that it has some clean up to do
			b		hamReturn					; Join common epilog code

			.align	5
			
hamBadLock:	li		r3,0						; Set lock time out error code
			li		r4,mapRtBadLk				; Set lock time out error code
			b		hamReturn					; Leave....

hamPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc




/*
 *			mapping *hw_rem_map(pmap, vaddr, addr64_t *next) - remove a mapping from the system.
 *
 *			Upon entry, R3 contains a pointer to a pmap.  Since vaddr is
 *			a 64-bit quantity, it is a long long so it is in R4 and R5.
 *			
 *			We return the virtual address of the removed mapping as a 
 *			R3.
 *
 *			Note that this is designed to be called from 32-bit mode with a stack.
 *
 *			We disable translation and all interruptions here.  This keeps is
 *			from having to worry about a deadlock due to having anything locked
 *			and needing it to process a fault.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 *  Remove mapping via pmap, regular page, no pte
 * 
 *  1) lock pmap share
 *  2) find mapping full path - finds all possible list previous elements
 *  4) upgrade pmap to exclusive
 *  3) bump mapping busy count
 *  5) remove mapping from search list
 *  6) unlock pmap
 *  7) lock physent
 *  8) remove from physent
 *  9) unlock physent
 * 10) drop mapping busy count
 * 11) drain mapping busy count
 * 
 * 
 * Remove mapping via pmap, regular page, with pte
 * 
 *  1) lock pmap share
 *  2) find mapping full path - finds all possible list previous elements
 *  3) upgrade lock to exclusive
 *  4) bump mapping busy count
 *  5) lock PTEG
 *  6) invalidate pte and tlbie
 *  7) atomic merge rc into physent
 *  8) unlock PTEG
 *  9) remove mapping from search list
 * 10) unlock pmap
 * 11) lock physent
 * 12) remove from physent
 * 13) unlock physent
 * 14) drop mapping busy count
 * 15) drain mapping busy count
 * 
 * 
 * Remove mapping via pmap, I/O or block
 * 
 *  1) lock pmap share
 *  2) find mapping full path - finds all possible list previous elements
 *  3) upgrade lock to exclusive
 *  4) bump mapping busy count
 *	5) mark remove-in-progress
 *	6) check and bump remove chunk cursor if needed
 *	7) unlock pmap
 *	8) if something to invalidate, go to step 11

 *	9) drop busy
 * 10) return with mapRtRemove to force higher level to call again
 
 * 11) Lock PTEG
 * 12) invalidate ptes, no tlbie
 * 13) unlock PTEG
 * 14) repeat 11 - 13 for all pages in chunk
 * 15) if not final chunk, go to step 9
 * 16) invalidate tlb entries for the whole block map but no more than the full tlb
 * 17) lock pmap share
 * 18) find mapping full path - finds all possible list previous elements
 * 19) upgrade lock to exclusive
 * 20) remove mapping from search list
 * 21) drop mapping busy count
 * 22) drain mapping busy count
 *	
 */

			.align	5
			.globl	EXT(hw_rem_map)

LEXT(hw_rem_map)

;
;			NOTE NOTE NOTE - IF WE CHANGE THIS STACK FRAME STUFF WE NEED TO CHANGE
;			THE HW_PURGE_* ROUTINES ALSO
;

#define hrmStackSize ((31-15+1)*4)+4
			stwu	r1,-(FM_ALIGN(hrmStackSize)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r15,FM_ARG0+0x00(r1)		; Save a register
			stw		r16,FM_ARG0+0x04(r1)		; Save a register
			stw		r17,FM_ARG0+0x08(r1)		; Save a register
			stw		r18,FM_ARG0+0x0C(r1)		; Save a register
			stw		r19,FM_ARG0+0x10(r1)		; Save a register
 			mfsprg	r19,2						; Get feature flags 
			stw		r20,FM_ARG0+0x14(r1)		; Save a register
			stw		r21,FM_ARG0+0x18(r1)		; Save a register
			mtcrf	0x02,r19					; move pf64Bit cr6
			stw		r22,FM_ARG0+0x1C(r1)		; Save a register
			stw		r23,FM_ARG0+0x20(r1)		; Save a register
			stw		r24,FM_ARG0+0x24(r1)		; Save a register
			stw		r25,FM_ARG0+0x28(r1)		; Save a register
			stw		r26,FM_ARG0+0x2C(r1)		; Save a register
			stw		r27,FM_ARG0+0x30(r1)		; Save a register
			stw		r28,FM_ARG0+0x34(r1)		; Save a register
			stw		r29,FM_ARG0+0x38(r1)		; Save a register
			stw		r30,FM_ARG0+0x3C(r1)		; Save a register
			stw		r31,FM_ARG0+0x40(r1)		; Save a register
			stw		r6,FM_ARG0+0x44(r1)			; Save address to save next mapped vaddr
			stw		r0,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r3)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active? 
			bne		hrmPanic					; Call not valid for guest shadow assist pmap
#endif
			
 			bt++	pf64Bitb,hrmSF1				; skip if 64-bit (only they take the hint)
			lwz		r9,pmapvr+4(r3)				; Get conversion mask
			b		hrmSF1x						; Done...
			
hrmSF1:		ld		r9,pmapvr(r3)				; Get conversion mask

hrmSF1x:	
			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit
			
			xor		r28,r3,r9					; Convert the pmap to physical addressing

;
;			Here is where we join in from the hw_purge_* routines
;

hrmJoin:	lwz		r3,pmapFlags(r28)			; Get pmap's flags
			mfsprg	r19,2						; Get feature flags again (for alternate entries)

			mr		r17,r11						; Save the MSR
			mr		r29,r4						; Top half of vaddr
			mr		r30,r5						; Bottom half of vaddr
			
			rlwinm.	r3,r3,0,pmapVMgsaa			; Is guest shadow assist active? 
			bne--	hrmGuest					; Yes, handle specially
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne--	hrmBadLock					; Nope...
			
;
;			Note that we do a full search (i.e., no shortcut level skips, etc.)
;			here so that we will know the previous elements so we can dequeue them
;			later. Note: we get back mpFlags in R7.
;

			mr		r3,r28						; Pass in pmap to search
			mr		r4,r29						; High order of address
			mr		r5,r30						; Low order of address
			bl		EXT(mapSearchFull)			; Go see if we can find it

			andi.	r0,r7,mpPerm				; Mapping marked permanent?
			crmove	cr5_eq,cr0_eq				; Remember permanent marking
			mr		r20,r7						; Remember mpFlags
			mr.		r31,r3						; Did we? (And remember mapping address for later)
			mr		r15,r4						; Save top of next vaddr
			mr		r16,r5						; Save bottom of next vaddr
			beq--	hrmNotFound					; Nope, not found...
 			
			bf--	cr5_eq,hrmPerm				; This one can't be removed...
;
;			Here we try to promote to an exclusive lock.  This will fail if someone else
;			has it shared.
;
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkPromote					; Try to promote shared to exclusive
			mr.		r3,r3						; Could we?
			beq++	hrmGotX						; Yeah...
			
;
;			Since we could not promote our lock, we need to convert to it.
;			That means that we drop the shared lock and wait to get it
;			exclusive.  Since we release the lock, we need to do the look up
;			again.
;			
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkConvert					; Convert shared to exclusive
			mr.		r3,r3						; Could we?
			bne--	hrmBadLock					; Nope, we must have timed out...
			
			mr		r3,r28						; Pass in pmap to search
			mr		r4,r29						; High order of address
			mr		r5,r30						; Low order of address
			bl		EXT(mapSearchFull)			; Rescan the list
			
			andi.	r0,r7,mpPerm				; Mapping marked permanent?
			crmove	cr5_eq,cr0_eq				; Remember permanent marking
			mr.		r31,r3						; Did we lose it when we converted?
			mr		r20,r7						; Remember mpFlags
			mr		r15,r4						; Save top of next vaddr
			mr		r16,r5						; Save bottom of next vaddr
			beq--	hrmNotFound					; Yeah, we did, someone tossed it for us...
		
			bf--	cr5_eq,hrmPerm				; This one can't be removed...

;
;			We have an exclusive lock on the mapping chain. And we
;			also have the busy count bumped in the mapping so it can
;			not vanish on us.
;

hrmGotX:	mr		r3,r31						; Get the mapping
			bl		mapBumpBusy					; Bump up the busy count
			
;
;			Invalidate any PTEs associated with this
;			mapping (more than one if a block) and accumulate the reference
;			and change bits.
;
;			Here is also where we need to split 32- and 64-bit processing
;

			lwz		r21,mpPte(r31)				; Grab the offset to the PTE
			rlwinm	r23,r29,0,1,0				; Copy high order vaddr to high if 64-bit machine
			mfsdr1	r29							; Get the hash table base and size

			rlwinm	r0,r20,0,mpType				; Isolate mapping type
			cmplwi	cr5,r0,mpBlock				; Remember whether this is a block mapping
			cmplwi	r0,mpMinSpecial				; cr0_lt <- not a special mapping type
			
			rlwinm	r0,r21,0,mpHValidb,mpHValidb	; See if we actually have a PTE
			ori		r2,r2,0xFFFF				; Get mask to clean out hash table base (works for both 32- and 64-bit)
			cmpwi	cr1,r0,0					; Have we made a PTE for this yet? 
			rlwinm	r21,r21,0,~mpHValid			; Clear out valid bit
			crorc	cr0_eq,cr1_eq,cr0_lt		; No need to look at PTE if none or a special mapping
			rlwimi	r23,r30,0,0,31				; Insert low under high part of address
			andc	r29,r29,r2					; Clean up hash table base
			li		r22,0						; Clear this on out (also sets RC to 0 if we bail)
			mr		r30,r23						; Move the now merged vaddr to the correct register
			add		r26,r29,r21					; Point to the PTEG slot
			
			bt++	pf64Bitb,hrmSplit64			; Go do 64-bit version...
			
			rlwinm	r9,r21,28,4,29				; Convert PTEG to PCA entry
			beq-	cr5,hrmBlock32				; Go treat block specially...
			subfic	r9,r9,-4					; Get the PCA entry offset
			bt-		cr0_eq,hrmPysDQ32			; Skip next if no possible PTE...
			add		r7,r9,r29					; Point to the PCA slot
	
			bl		mapLockPteg					; Go lock up the PTEG (Note: we need to save R6 to set PCA)
	
			lwz		r21,mpPte(r31)				; Get the quick pointer again
			lwz		r5,0(r26)					; Get the top of PTE
			
			rlwinm.	r0,r21,0,mpHValidb,mpHValidb	; See if we actually have a PTE
			rlwinm	r21,r21,0,~mpHValid			; Clear out valid bit
			rlwinm	r5,r5,0,1,31				; Turn off valid bit in PTE
			stw		r21,mpPte(r31)				; Make sure we invalidate mpPte, still pointing to PTEG (keep walk_page from making a mistake)
			beq-	hrmUlckPCA32				; Pte is gone, no need to invalidate...
			
			stw		r5,0(r26)					; Invalidate the PTE

			li		r9,tlbieLock				; Get the TLBIE lock

			sync								; Make sure the invalid PTE is actually in memory
	
hrmPtlb32:	lwarx	r5,0,r9						; Get the TLBIE lock 
			mr.		r5,r5						; Is it locked?
			li		r5,1						; Get locked indicator
			bne-	hrmPtlb32					; It is locked, go spin...
			stwcx.	r5,0,r9						; Try to get it
			bne-	hrmPtlb32					; We was beat... 
			
			rlwinm.	r0,r19,0,pfSMPcapb,pfSMPcapb	; Can this processor do SMP?	
					
			tlbie	r30							; Invalidate it all corresponding TLB entries
			
			beq-	hrmNTlbs					; Jump if we can not do a TLBSYNC....
			
			eieio								; Make sure that the tlbie happens first
			tlbsync								; Wait for everyone to catch up
			sync								; Make sure of it all
			
hrmNTlbs:	li		r0,0						; Clear this 
			rlwinm	r2,r21,29,29,31				; Get slot number (8 byte entries)
			stw		r0,tlbieLock(0)				; Clear the tlbie lock
			lis		r0,0x8000					; Get bit for slot 0
			eieio								; Make sure those RC bit have been stashed in PTE
			
			srw		r0,r0,r2					; Get the allocation hash mask
			lwz		r22,4(r26)					; Get the latest reference and change bits
			or		r6,r6,r0					; Show that this slot is free

hrmUlckPCA32:			
			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock the PTEG
		
;
;			Now, it is time to remove the mapping and unlock the chain.
;			But first, we need to make sure no one else is using this 
;			mapping so we drain the busy now
;			

hrmPysDQ32:	mr		r3,r31						; Point to the mapping
			bl		mapDrainBusy				; Go wait until mapping is unused

			mr		r3,r28						; Get the pmap to remove from
			mr		r4,r31						; Point to the mapping
			bl		EXT(mapRemove)				; Remove the mapping from the list			

			lwz		r4,pmapResidentCnt(r28)		; Get the mapped page count 
			rlwinm	r0,r20,0,mpType				; Isolate mapping type
			cmplwi	cr1,r0,mpMinSpecial			; cr1_lt <- not a special mapping type
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			subi	r4,r4,1						; Drop down the mapped page count
			stw		r4,pmapResidentCnt(r28)		; Set the mapped page count 
			bl		sxlkUnlock					; Unlock the search list

			bf--	cr1_lt,hrmRetn32			; This one has no real memory associated with it so we are done...

			bl		mapPhysFindLock				; Go find and lock the physent

			lwz		r9,ppLink+4(r3)				; Get first mapping

			mr		r4,r22						; Get the RC bits we just got
			bl		mapPhysMerge				; Go merge the RC bits
			
			rlwinm	r9,r9,0,~ppFlags			; Clear the flags from the mapping pointer
			
			cmplw	r9,r31						; Are we the first on the list?
			bne-	hrmNot1st					; Nope...
			
			li		r9,0						; Get a 0
			lwz		r4,mpAlias+4(r31)			; Get our new forward pointer
			stw		r9,mpAlias+4(r31)			; Make sure we are off the chain
			bl		mapPhyCSet32				; Go set the physent link and preserve flags								
			
			b		hrmPhyDQd					; Join up and unlock it all...

			.align	5
			
hrmPerm:	li		r8,-4096					; Get the value we need to round down to a page
			and		r8,r8,r31					; Get back to a page
			lwz		r8,mbvrswap+4(r8)			; Get last half of virtual to real swap
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			
			xor		r3,r31,r8					; Flip mapping address to virtual
			ori		r3,r3,mapRtPerm				; Set permanent mapping error
			b		hrmErRtn
			
hrmBadLock:	li		r3,mapRtBadLk				; Set bad lock
			b		hrmErRtn
			
hrmEndInSight:
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			
hrmDoneChunk:
			mr		r3,r31						; Point to the mapping
			bl		mapDropBusy					; Drop the busy here since we need to come back
			li		r3,mapRtRemove				; Say we are still removing this
			b		hrmErRtn

			.align	5
			
hrmNotFound:
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			li		r3,mapRtNotFnd				; No mapping found

hrmErRtn:	bt++	pf64Bitb,hrmSF1z			; skip if 64-bit (only they take the hint)

			mtmsr	r17							; Restore enables/translation/etc.
			isync
			b		hrmRetnCmn					; Join the common return code...

hrmSF1z:	mtmsrd	r17							; Restore enables/translation/etc.
			isync
			b		hrmRetnCmn					; Join the common return code...

			.align	5

hrmNot1st:	mr.		r8,r9						; Remember and test current node
			beq-	hrmPhyDQd					; Could not find our node, someone must have unmapped us...
			lwz		r9,mpAlias+4(r9)			; Chain to the next
			cmplw	r9,r31						; Is this us?
			bne-	hrmNot1st					; Not us...
		
			lwz		r9,mpAlias+4(r9)			; Get our forward pointer
			stw		r9,mpAlias+4(r8)			; Unchain us
			
			nop									; For alignment
			
hrmPhyDQd:	bl		mapPhysUnlock				; Unlock the physent chain

hrmRetn32:	rlwinm	r8,r31,0,0,19				; Find start of page
			mr		r3,r31						; Copy the pointer to the mapping
			lwz		r8,mbvrswap+4(r8)			; Get last half of virtual to real swap
			bl		mapDrainBusy				; Go wait until mapping is unused

			xor		r3,r31,r8					; Flip mapping address to virtual
			
			mtmsr	r17							; Restore enables/translation/etc.
			isync

hrmRetnCmn:	lwz		r6,FM_ARG0+0x44(r1)			; Get address to save next mapped vaddr
			lwz		r0,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Restore the return
			lwz		r17,FM_ARG0+0x08(r1)		; Restore a register
			lwz		r18,FM_ARG0+0x0C(r1)		; Restore a register
			mr.		r6,r6						; Should we pass back the "next" vaddr?
			lwz		r19,FM_ARG0+0x10(r1)		; Restore a register
			lwz		r20,FM_ARG0+0x14(r1)		; Restore a register
			mtlr	r0							; Restore the return
			
			rlwinm	r16,r16,0,0,19				; Clean to a page boundary
			beq		hrmNoNextAdr				; Do not pass back the next vaddr...
			stw		r15,0(r6)					; Pass back the top of the next vaddr
			stw		r16,4(r6)					; Pass back the bottom of the next vaddr

hrmNoNextAdr:
			lwz		r15,FM_ARG0+0x00(r1)		; Restore a register
			lwz		r16,FM_ARG0+0x04(r1)		; Restore a register
			lwz		r21,FM_ARG0+0x18(r1)		; Restore a register
			rlwinm	r3,r3,0,0,31				; Clear top of register if 64-bit
			lwz		r22,FM_ARG0+0x1C(r1)		; Restore a register
			lwz		r23,FM_ARG0+0x20(r1)		; Restore a register
			lwz		r24,FM_ARG0+0x24(r1)		; Restore a register
			lwz		r25,FM_ARG0+0x28(r1)		; Restore a register
			lwz		r26,FM_ARG0+0x2C(r1)		; Restore a register
			lwz		r27,FM_ARG0+0x30(r1)		; Restore a register
			lwz		r28,FM_ARG0+0x34(r1)		; Restore a register
			lwz		r29,FM_ARG0+0x38(r1)		; Restore a register
			lwz		r30,FM_ARG0+0x3C(r1)		; Restore a register
			lwz		r31,FM_ARG0+0x40(r1)		; Restore a register
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...

;
;			Here is where we come when all is lost.  Somehow, we failed a mapping function
;			that must work... All hope is gone.  Alas, we die.......
;

hrmPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc


;
;			Invalidate block mappings by invalidating a chunk of autogen PTEs in PTEGs hashed
;			in the range. Then, if we did not finish, return a code indicating that we need to 
;			be called again.  Eventually, we will finish and then, we will do a TLBIE for each 
;			PTEG up to the point where we have cleared it all (64 for 32-bit architecture)
;
;			A potential speed up is that we stop the invalidate loop once we have walked through
;			the hash table once. This really is not worth the trouble because we need to have
;			mapped 1/2 of physical RAM in an individual block.  Way unlikely.
;
;			We should rethink this and see if we think it will be faster to check PTE and
;			only invalidate the specific PTE rather than all block map PTEs in the PTEG.
;

			.align	5
			
hrmBlock32:	lis		r29,0xD000					; Get shift to 32MB bsu
			rlwinm	r24,r20,mpBSub+1+2,29,29	; Rotate to get 0 if 4K bsu or 13 if 32MB bsu
			lhz		r25,mpBSize(r31)			; Get the number of pages in block
			lhz		r23,mpSpace(r31)			; Get the address space hash
			lwz		r9,mpBlkRemCur(r31)			; Get our current remove position
			rlwnm	r29,r29,r24,28,31			; Rotate to get 0 or 13
			addi	r25,r25,1					; Account for zero-based counting
			ori		r0,r20,mpRIP				; Turn on the remove in progress flag
			slw		r25,r25,r29					; Adjust for 32MB if needed
			mfsdr1	r29							; Get the hash table base and size
			rlwinm	r24,r23,maxAdrSpb,32-maxAdrSpb-maxAdrSpb,31-maxAdrSpb	; Get high order of hash
			subi	r25,r25,1					; Convert back to zero-based counting
			lwz		r27,mpVAddr+4(r31)			; Get the base vaddr
			sub		r4,r25,r9					; Get number of pages left
			cmplw	cr1,r9,r25					; Have we already hit the end?
			addi	r10,r9,mapRemChunk			; Point to the start of the next chunk
			addi	r2,r4,-mapRemChunk			; See if mapRemChunk or more
			rlwinm	r26,r29,16,7,15				; Get the hash table size
			srawi	r2,r2,31					; We have -1 if less than mapRemChunk or 0 if equal or more
			stb		r0,mpFlags+3(r31)			; Save the flags with the mpRIP bit on
			subi	r4,r4,mapRemChunk-1			; Back off for a running start (will be negative for more than mapRemChunk)
			cmpwi	cr7,r2,0					; Remember if we have finished
			slwi	r0,r9,12					; Make cursor into page offset
			or		r24,r24,r23					; Get full hash
			and		r4,r4,r2					; If more than a chunk, bring this back to 0
			rlwinm	r29,r29,0,0,15				; Isolate the hash table base
			add		r27,r27,r0					; Adjust vaddr to start of current chunk
			addi	r4,r4,mapRemChunk-1			; Add mapRemChunk-1 to get max(num left,  chunksize)
			
			bgt-	cr1,hrmEndInSight			; Someone is already doing the last hunk...
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			stw		r10,mpBlkRemCur(r31)		; Set next chunk to do (note: this may indicate after end)
			bl		sxlkUnlock					; Unlock the search list while we are invalidating
			
			rlwinm	r8,r27,4+maxAdrSpb,31-maxAdrSpb-3,31-maxAdrSpb	; Isolate the segment
			rlwinm	r30,r27,26,6,25				; Shift vaddr to PTEG offset (and remember VADDR in R27)
			xor		r24,r24,r8					; Get the proper VSID
			rlwinm	r21,r27,26,10,25			; Shift page index to PTEG offset (and remember VADDR in R27)
			ori		r26,r26,lo16(0xFFC0)		; Stick in the rest of the length
			rlwinm	r22,r4,6,10,25				; Shift size to PTEG offset
			rlwinm	r24,r24,6,0,25				; Shift hash to PTEG units
			add		r22,r22,r30					; Get end address (in PTEG units)
			
hrmBInv32:	rlwinm	r23,r30,0,10,25				; Isolate just the page index 
			xor		r23,r23,r24					; Hash it
			and		r23,r23,r26					; Wrap it into the table
			rlwinm	r3,r23,28,4,29				; Change to PCA offset
			subfic	r3,r3,-4					; Get the PCA entry offset
			add		r7,r3,r29					; Point to the PCA slot
			cmplw	cr5,r30,r22					; Check if we reached the end of the range
			addi	r30,r30,64					; bump to the next vaddr
								
			bl		mapLockPteg					; Lock the PTEG
					
			rlwinm.	r4,r6,16,0,7				; Position, save, and test block mappings in PCA
			add		r5,r23,r29					; Point to the PTEG
			li		r0,0						; Set an invalid PTE value
			beq+	hrmBNone32					; No block map PTEs in this PTEG...
			mtcrf	0x80,r4						; Set CRs to select PTE slots
			mtcrf	0x40,r4						; Set CRs to select PTE slots

			bf		0,hrmSlot0					; No autogen here
			stw		r0,0x00(r5)					; Invalidate PTE

hrmSlot0:	bf		1,hrmSlot1					; No autogen here
			stw		r0,0x08(r5)					; Invalidate PTE

hrmSlot1:	bf		2,hrmSlot2					; No autogen here
			stw		r0,0x10(r5)					; Invalidate PTE

hrmSlot2:	bf		3,hrmSlot3					; No autogen here
			stw		r0,0x18(r5)					; Invalidate PTE

hrmSlot3:	bf		4,hrmSlot4					; No autogen here
			stw		r0,0x20(r5)					; Invalidate PTE

hrmSlot4:	bf		5,hrmSlot5					; No autogen here
			stw		r0,0x28(r5)					; Invalidate PTE

hrmSlot5:	bf		6,hrmSlot6					; No autogen here
			stw		r0,0x30(r5)					; Invalidate PTE

hrmSlot6:	bf		7,hrmSlot7					; No autogen here
			stw		r0,0x38(r5)					; Invalidate PTE

hrmSlot7:	rlwinm	r0,r4,16,16,23				; Move in use to autogen
			or		r6,r6,r4					; Flip on the free bits that corrospond to the autogens we cleared
			andc	r6,r6,r0					; Turn off all the old autogen bits

hrmBNone32:	eieio								; Make sure all updates come first

			stw		r6,0(r7)					; Unlock and set the PCA
			
			bne+	cr5,hrmBInv32				; Go invalidate the next...

			bge+	cr7,hrmDoneChunk			; We have not as yet done the last chunk, go tell our caller to call again...

			mr		r3,r31						; Copy the pointer to the mapping
			bl		mapDrainBusy				; Go wait until we are sure all other removers are done with this one

			sync								; Make sure memory is consistent
			
			subi	r5,r25,63					; Subtract TLB size from page count (note we are 0 based here)
			li		r6,63						; Assume full invalidate for now
			srawi	r5,r5,31					; Make 0 if we need a full purge, -1 otherwise
			andc	r6,r6,r5					; Clear max if we have less to do
			and		r5,r25,r5					; Clear count if we have more than max
			lwz		r27,mpVAddr+4(r31)			; Get the base vaddr again
			li		r7,tlbieLock				; Get the TLBIE lock
			or		r5,r5,r6					; Get number of TLBIEs needed		
					
hrmBTLBlck:	lwarx	r2,0,r7						; Get the TLBIE lock
			mr.		r2,r2						; Is it locked?
			li		r2,1						; Get our lock value
			bne-	hrmBTLBlck					; It is locked, go wait...
			stwcx.	r2,0,r7						; Try to get it
			bne-	hrmBTLBlck					; We was beat...
	
hrmBTLBi:	addic.	r5,r5,-1					; See if we did them all
			tlbie	r27							; Invalidate it everywhere
			addi	r27,r27,0x1000				; Up to the next page
			bge+	hrmBTLBi					; Make sure we have done it all...
			
			rlwinm.	r0,r19,0,pfSMPcapb,pfSMPcapb	; Can this processor do SMP?	
			li		r2,0						; Lock clear value
			
			sync								; Make sure all is quiet
			beq-	hrmBNTlbs					; Jump if we can not do a TLBSYNC....
			
			eieio								; Make sure that the tlbie happens first
			tlbsync								; Wait for everyone to catch up
			sync								; Wait for quiet again

hrmBNTlbs:	stw		r2,tlbieLock(0)				; Clear the tlbie lock
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne-	hrmPanic					; Nope...
			
			lwz		r4,mpVAddr(r31)				; High order of address
			lwz		r5,mpVAddr+4(r31)			; Low order of address
			mr		r3,r28						; Pass in pmap to search
			mr		r29,r4						; Save this in case we need it (only promote fails)
			mr		r30,r5						; Save this in case we need it (only promote fails)
			bl		EXT(mapSearchFull)			; Go see if we can find it
			
			mr.		r3,r3						; Did we? (And remember mapping address for later)
			mr		r15,r4						; Save top of next vaddr
			mr		r16,r5						; Save bottom of next vaddr
			beq-	hrmPanic					; Nope, not found...
			
			cmplw	r3,r31						; Same mapping?
			bne-	hrmPanic					; Not good...
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkPromote					; Try to promote shared to exclusive
			mr.		r3,r3						; Could we?
			mr		r3,r31						; Restore the mapping pointer
			beq+	hrmBDone1					; Yeah...
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkConvert					; Convert shared to exclusive
			mr.		r3,r3						; Could we?
			bne--	hrmPanic					; Nope, we must have timed out...
			
			mr		r3,r28						; Pass in pmap to search
			mr		r4,r29						; High order of address
			mr		r5,r30						; Low order of address
			bl		EXT(mapSearchFull)			; Rescan the list
			
			mr.		r3,r3						; Did we lose it when we converted?
			mr		r15,r4						; Save top of next vaddr
			mr		r16,r5						; Save bottom of next vaddr
			beq--	hrmPanic					; Yeah, we did, someone tossed it for us...

hrmBDone1:	bl		mapDrainBusy				; Go wait until mapping is unused

			mr		r3,r28						; Get the pmap to remove from
			mr		r4,r31						; Point to the mapping
			bl		EXT(mapRemove)				; Remove the mapping from the list	
					
			lwz		r4,pmapResidentCnt(r28)		; Get the mapped page count 
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			subi	r4,r4,1						; Drop down the mapped page count
			stw		r4,pmapResidentCnt(r28)		; Set the mapped page count 
			bl		sxlkUnlock					; Unlock the search list
		
			b		hrmRetn32					; We are all done, get out...

;
;			Here we handle the 64-bit version of hw_rem_map
;
		
			.align	5
		
hrmSplit64:	rlwinm	r9,r21,27,5,29				; Convert PTEG to PCA entry
			beq--	cr5,hrmBlock64				; Go treat block specially...
			subfic	r9,r9,-4					; Get the PCA entry offset
			bt--	cr0_eq,hrmPysDQ64			; Skip next if no possible PTE...
			add		r7,r9,r29					; Point to the PCA slot
			
			bl		mapLockPteg					; Go lock up the PTEG
	
			lwz		r21,mpPte(r31)				; Get the quick pointer again
			ld		r5,0(r26)					; Get the top of PTE
			
			rlwinm.	r0,r21,0,mpHValidb,mpHValidb	; See if we actually have a PTE
			rlwinm	r21,r21,0,~mpHValid			; Clear out valid bit
			sldi	r23,r5,16					; Shift AVPN up to EA format
//			****	Need to adjust above shift based on the page size - large pages need to shift a bit more
			rldicr	r5,r5,0,62					; Clear the valid bit
			rldimi	r23,r30,0,36				; Insert the page portion of the VPN
			stw		r21,mpPte(r31)				; Make sure we invalidate mpPte but keep pointing to PTEG (keep walk_page from making a mistake)
			beq--	hrmUlckPCA64				; Pte is gone, no need to invalidate...
			
			std		r5,0(r26)					; Invalidate the PTE

			li		r9,tlbieLock				; Get the TLBIE lock

			sync								; Make sure the invalid PTE is actually in memory

hrmPtlb64:	lwarx	r5,0,r9						; Get the TLBIE lock 
			rldicl	r23,r23,0,16				; Clear bits 0:15 cause they say to
			mr.		r5,r5						; Is it locked?
			li		r5,1						; Get locked indicator
			bne--	hrmPtlb64w					; It is locked, go spin...
			stwcx.	r5,0,r9						; Try to get it
			bne--	hrmPtlb64					; We was beat... 
					
			tlbie	r23							; Invalidate all corresponding TLB entries
			
			eieio								; Make sure that the tlbie happens first
			tlbsync								; Wait for everyone to catch up
			
			ptesync								; Make sure of it all
			li		r0,0						; Clear this 
			rlwinm	r2,r21,28,29,31				; Get slot number (16 byte entries)
			stw		r0,tlbieLock(0)				; Clear the tlbie lock
			oris	r0,r0,0x8000				; Assume slot 0

			srw		r0,r0,r2					; Get slot mask to deallocate

			lwz		r22,12(r26)					; Get the latest reference and change bits
			or		r6,r6,r0					; Make the guy we killed free
			
hrmUlckPCA64:
			eieio								; Make sure all updates come first

			stw		r6,0(r7)					; Unlock and change the PCA
		
hrmPysDQ64:	mr		r3,r31						; Point to the mapping
			bl		mapDrainBusy				; Go wait until mapping is unused

			mr		r3,r28						; Get the pmap to remove from
			mr		r4,r31						; Point to the mapping
			bl		EXT(mapRemove)				; Remove the mapping from the list			

			rlwinm	r0,r20,0,mpType				; Isolate mapping type
			cmplwi	cr1,r0,mpMinSpecial			; cr1_lt <- not a special mapping type
			lwz		r4,pmapResidentCnt(r28)		; Get the mapped page count 
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			subi	r4,r4,1						; Drop down the mapped page count
			stw		r4,pmapResidentCnt(r28)		; Set the mapped page count 
			bl		sxlkUnlock					; Unlock the search list
		
			bf--	cr1_lt,hrmRetn64			; This one has no real memory associated with it so we are done...

			bl		mapPhysFindLock				; Go find and lock the physent

			li		r0,ppLFAmask				; Get mask to clean up mapping pointer
			ld		r9,ppLink(r3)				; Get first mapping
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			mr		r4,r22						; Get the RC bits we just got
			
			bl		mapPhysMerge				; Go merge the RC bits
			
			andc	r9,r9,r0					; Clean up the mapping pointer
			
			cmpld	r9,r31						; Are we the first on the list?
			bne--	hrmNot1st64					; Nope...
			
			li		r9,0						; Get a 0
			ld		r4,mpAlias(r31)				; Get our forward pointer
			
			std		r9,mpAlias(r31)				; Make sure we are off the chain
			bl		mapPhyCSet64				; Go set the physent link and preserve flags								

			b		hrmPhyDQd64					; Join up and unlock it all...
			
hrmPtlb64w:	li		r5,lgKillResv				; Point to some spare memory
			stwcx.	r5,0,r5						; Clear the pending reservation			
						
			
hrmPtlb64x:	lwz		r5,0(r9)					; Do a regular load to avoid taking reservation
			mr.		r5,r5						; is it locked?
			beq++	hrmPtlb64					; Nope...
			b		hrmPtlb64x					; Sniff some more...
		
			.align	5							
			
hrmNot1st64:
			mr.		r8,r9						; Remember and test current node
			beq--	hrmPhyDQd64					; Could not find our node...
			ld		r9,mpAlias(r9)				; Chain to the next
			cmpld	r9,r31						; Is this us?
			bne--	hrmNot1st64					; Not us...
		
			ld		r9,mpAlias(r9)				; Get our forward pointer
			std		r9,mpAlias(r8)				; Unchain us
			
			nop									; For alignment
			
hrmPhyDQd64:	
			bl		mapPhysUnlock				; Unlock the physent chain

hrmRetn64:	rldicr	r8,r31,0,51					; Find start of page
			mr		r3,r31						; Copy the pointer to the mapping
			lwz		r8,mbvrswap+4(r8)			; Get last half of virtual to real swap
			bl		mapDrainBusy				; Go wait until mapping is unused

			xor		r3,r31,r8					; Flip mapping address to virtual
			
			mtmsrd	r17							; Restore enables/translation/etc.
			isync
			
			b		hrmRetnCmn					; Join the common return path...


;
;			Check hrmBlock32 for comments.
;

			.align	5
			
hrmBlock64:	lis		r29,0xD000					; Get shift to 32MB bsu			
			rlwinm	r10,r20,mpBSub+1+2,29,29	; Rotate to get 0 if 4K bsu or 13 if 32MB bsu
			lhz		r24,mpSpace(r31)			; Get the address space hash
			lhz		r25,mpBSize(r31)			; Get the number of pages in block
			lwz		r9,mpBlkRemCur(r31)			; Get our current remove position
			rlwnm	r29,r29,r10,28,31			; Rotate to get 0 or 13
			addi	r25,r25,1					; Account for zero-based counting
			ori		r0,r20,mpRIP				; Turn on the remove in progress flag
			slw		r25,r25,r29					; Adjust for 32MB if needed
			mfsdr1	r29							; Get the hash table base and size
			ld		r27,mpVAddr(r31)			; Get the base vaddr
			subi	r25,r25,1					; Convert back to zero-based counting
			rlwinm	r5,r29,0,27,31				; Isolate the size
			sub		r4,r25,r9					; Get number of pages left
			cmplw	cr1,r9,r25					; Have we already hit the end?
			addi	r10,r9,mapRemChunk			; Point to the start of the next chunk
			addi	r2,r4,-mapRemChunk			; See if mapRemChunk or more
			stb		r0,mpFlags+3(r31)			; Save the flags with the mpRIP bit on
			srawi	r2,r2,31					; We have -1 if less than mapRemChunk or 0 if equal or more
			subi	r4,r4,mapRemChunk-1			; Back off for a running start (will be negative for more than mapRemChunk)
			cmpwi	cr7,r2,0					; Remember if we are doing the last chunk
			and		r4,r4,r2					; If more than a chunk, bring this back to 0
			srdi	r27,r27,12					; Change address into page index
			addi	r4,r4,mapRemChunk-1			; Add mapRemChunk-1 to get max(num left,  chunksize)
			add		r27,r27,r9					; Adjust vaddr to start of current chunk
			
			bgt--	cr1,hrmEndInSight			; Someone is already doing the last hunk...
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			stw		r10,mpBlkRemCur(r31)		; Set next chunk to do (note: this may indicate after end)
			bl		sxlkUnlock					; Unlock the search list while we are invalidating
			
			rlwimi	r24,r24,14,4,17				; Insert a copy of space hash
			eqv		r26,r26,r26					; Get all foxes here
			rldimi	r24,r24,28,8				; Make a couple copies up higher
			rldicr	r29,r29,0,47				; Isolate just the hash table base
			subfic	r5,r5,46					; Get number of leading zeros
			srd		r26,r26,r5					; Shift the size bits over		
			mr		r30,r27						; Get start of chunk to invalidate
			rldicr	r26,r26,0,56				; Make length in PTEG units
			add		r22,r4,r30					; Get end page number
									
hrmBInv64:	srdi	r0,r30,2					; Shift page index over to form ESID
			rldicr	r0,r0,0,49					; Clean all but segment portion
			rlwinm	r2,r30,0,16,31				; Get the current page index
			xor		r0,r0,r24					; Form VSID
			xor		r8,r2,r0					; Hash the vaddr
			sldi	r8,r8,7						; Make into PTEG offset
			and		r23,r8,r26					; Wrap into the hash table
			rlwinm	r3,r23,27,5,29				; Change to PCA offset (table is always 2GB or less so 32-bit instructions work here)
			subfic	r3,r3,-4					; Get the PCA entry offset
			add		r7,r3,r29					; Point to the PCA slot
			
			cmplw	cr5,r30,r22					; Have we reached the end of the range?
								
			bl		mapLockPteg					; Lock the PTEG
						
			rlwinm.	r4,r6,16,0,7				; Extract the block mappings in this here PTEG and see if there are any
			add		r5,r23,r29					; Point to the PTEG
			li		r0,0						; Set an invalid PTE value
			beq++	hrmBNone64					; No block map PTEs in this PTEG...
			mtcrf	0x80,r4						; Set CRs to select PTE slots
			mtcrf	0x40,r4						; Set CRs to select PTE slots


			bf		0,hrmSlot0s					; No autogen here
			std		r0,0x00(r5)					; Invalidate PTE

hrmSlot0s:	bf		1,hrmSlot1s					; No autogen here
			std		r0,0x10(r5)					; Invalidate PTE

hrmSlot1s:	bf		2,hrmSlot2s					; No autogen here
			std		r0,0x20(r5)					; Invalidate PTE

hrmSlot2s:	bf		3,hrmSlot3s					; No autogen here
			std		r0,0x30(r5)					; Invalidate PTE

hrmSlot3s:	bf		4,hrmSlot4s					; No autogen here
			std		r0,0x40(r5)					; Invalidate PTE

hrmSlot4s:	bf		5,hrmSlot5s					; No autogen here
			std		r0,0x50(r5)					; Invalidate PTE

hrmSlot5s:	bf		6,hrmSlot6s					; No autogen here
			std		r0,0x60(r5)					; Invalidate PTE

hrmSlot6s:	bf		7,hrmSlot7s					; No autogen here
			std		r0,0x70(r5)					; Invalidate PTE

hrmSlot7s:	rlwinm	r0,r4,16,16,23				; Move in use to autogen
			or		r6,r6,r4					; Flip on the free bits that corrospond to the autogens we cleared
			andc	r6,r6,r0					; Turn off all the old autogen bits

hrmBNone64:	eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock and set the PCA

			addi	r30,r30,1					; bump to the next PTEG
			bne++	cr5,hrmBInv64				; Go invalidate the next...

			bge+	cr7,hrmDoneChunk			; We have not as yet done the last chunk, go tell our caller to call again...

			mr		r3,r31						; Copy the pointer to the mapping
			bl		mapDrainBusy				; Go wait until we are sure all other removers are done with this one

			sync								; Make sure memory is consistent

			subi	r5,r25,255					; Subtract TLB size from page count (note we are 0 based here)
			li		r6,255						; Assume full invalidate for now
			srawi	r5,r5,31					; Make 0 if we need a full purge, -1 otherwise
			andc	r6,r6,r5					; Clear max if we have less to do
			and		r5,r25,r5					; Clear count if we have more than max
			sldi	r24,r24,28					; Get the full XOR value over to segment position
			ld		r27,mpVAddr(r31)			; Get the base vaddr
			li		r7,tlbieLock				; Get the TLBIE lock
			or		r5,r5,r6					; Get number of TLBIEs needed		
			
hrmBTLBlcl:	lwarx	r2,0,r7						; Get the TLBIE lock
			mr.		r2,r2						; Is it locked?
			li		r2,1						; Get our lock value
			bne--	hrmBTLBlcm					; It is locked, go wait...
			stwcx.	r2,0,r7						; Try to get it
			bne--	hrmBTLBlcl					; We was beat...
	
hrmBTLBj:	sldi	r2,r27,maxAdrSpb			; Move to make room for address space ID
			rldicr	r2,r2,0,35-maxAdrSpb		; Clear out the extra
			addic.	r5,r5,-1					; See if we did them all
			xor		r2,r2,r24					; Make the VSID
			rldimi	r2,r27,0,36					; Insert the page portion of the VPN
			rldicl	r2,r2,0,16					; Clear bits 0:15 cause they say we gotta

			tlbie	r2							; Invalidate it everywhere
			addi	r27,r27,0x1000				; Up to the next page
			bge++	hrmBTLBj					; Make sure we have done it all...
			
			eieio								; Make sure that the tlbie happens first
			tlbsync								; wait for everyone to catch up

			li		r2,0						; Lock clear value

			ptesync								; Wait for quiet again

			stw		r2,tlbieLock(0)				; Clear the tlbie lock
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne-	hrmPanic					; Nope...
			
			lwz		r4,mpVAddr(r31)				; High order of address
			lwz		r5,mpVAddr+4(r31)			; Low order of address
			mr		r3,r28						; Pass in pmap to search
			mr		r29,r4						; Save this in case we need it (only promote fails)
			mr		r30,r5						; Save this in case we need it (only promote fails)
			bl		EXT(mapSearchFull)			; Go see if we can find it
			
			mr.		r3,r3						; Did we? (And remember mapping address for later)
			mr		r15,r4						; Save top of next vaddr
			mr		r16,r5						; Save bottom of next vaddr
			beq-	hrmPanic					; Nope, not found...
			
			cmpld	r3,r31						; Same mapping?
			bne-	hrmPanic					; Not good...
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkPromote					; Try to promote shared to exclusive
			mr.		r3,r3						; Could we?
			mr		r3,r31						; Restore the mapping pointer
			beq+	hrmBDone2					; Yeah...
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkConvert					; Convert shared to exclusive
			mr.		r3,r3						; Could we?
			bne--	hrmPanic					; Nope, we must have timed out...
			
			mr		r3,r28						; Pass in pmap to search
			mr		r4,r29						; High order of address
			mr		r5,r30						; Low order of address
			bl		EXT(mapSearchFull)			; Rescan the list
			
			mr.		r3,r3						; Did we lose it when we converted?
			mr		r15,r4						; Save top of next vaddr
			mr		r16,r5						; Save bottom of next vaddr
			beq--	hrmPanic					; Yeah, we did, someone tossed it for us...

hrmBDone2:	bl		mapDrainBusy				; Go wait until mapping is unused

			mr		r3,r28						; Get the pmap to remove from
			mr		r4,r31						; Point to the mapping
			bl		EXT(mapRemove)				; Remove the mapping from the list	
					
			lwz		r4,pmapResidentCnt(r28)		; Get the mapped page count 
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			subi	r4,r4,1						; Drop down the mapped page count
			stw		r4,pmapResidentCnt(r28)		; Set the mapped page count 
			bl		sxlkUnlock					; Unlock the search list
		
			b		hrmRetn64					; We are all done, get out...
			
hrmBTLBlcm:	li		r2,lgKillResv				; Get space unreserve line
			stwcx.	r2,0,r2						; Unreserve it
						
hrmBTLBlcn:	lwz		r2,0(r7)					; Get the TLBIE lock
			mr.		r2,r2						; Is it held?
			beq++	hrmBTLBlcl					; Nope...
			b		hrmBTLBlcn					; Yeah...

;
;			Guest shadow assist -- mapping remove
;
;			Method of operation:
;				o Locate the VMM extension block and the host pmap
;				o Obtain the host pmap's search lock exclusively
;				o Locate the requested mapping in the shadow hash table,
;				  exit if not found
;				o If connected, disconnect the PTE and gather R&C to physent
;				o Locate and lock the physent
;				o Remove mapping from physent's chain
;				o Unlock physent
;				o Unlock pmap's search lock
;
;			Non-volatile registers on entry:
;				r17: caller's msr image
;				r19: sprg2 (feature flags)
;				r28: guest pmap's physical address
;				r29: high-order 32 bits of guest virtual address
;				r30: low-order 32 bits of guest virtual address
;
;			Non-volatile register usage:
;				r26: VMM extension block's physical address
;				r27: host pmap's physical address
;				r28: guest pmap's physical address
;				r29: physent's physical address
;				r30: guest virtual address
;				r31: guest mapping's physical address
;
			.align	5			
hrmGuest:
			rlwinm	r30,r30,0,0xFFFFF000		; Clean up low-order bits of 32-bit guest vaddr
			bt++	pf64Bitb,hrmG64				; Test for 64-bit machine
			lwz		r26,pmapVmmExtPhys+4(r28)	; r26 <- VMM pmap extension block paddr
			lwz		r27,vmxHostPmapPhys+4(r26)	; r27 <- host pmap's paddr
			b		hrmGStart					; Join common code

hrmG64:		ld		r26,pmapVmmExtPhys(r28)		; r26 <- VMM pmap extension block paddr
			ld		r27,vmxHostPmapPhys(r26)	; r27 <- host pmap's paddr
			rldimi	r30,r29,32,0				; Insert high-order 32 bits of 64-bit guest vaddr			

hrmGStart:	la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive
			
			lwz		r3,vxsGrm(r26)				; Get mapping remove request count

			lwz		r9,pmapSpace(r28)			; r9 <- guest space ID number
			la		r31,VMX_HPIDX_OFFSET(r26)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r9,r11					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r12,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r12					; r31 <- hash page index entry
			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,hrmG64Search		; Separate handling for 64-bit search
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
												
			addi	r3,r3,1						; Increment remove request count
			stw		r3,vxsGrm(r26)				; Update remove request count

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		hrmG32SrchLp				; Let the search begin!
			
			.align	5
hrmG32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free mapping flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(free && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && space match && virtual addr match
			beq		hrmGSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	hrmG32SrchLp				; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free mapping flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(free && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && space match && virtual addr match
			beq		hrmGSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		hrmGSrchMiss				; No joy in our hash group
			
hrmG64Search:			
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		hrmG64SrchLp				; Let the search begin!
			
			.align	5
hrmG64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free mapping flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(free && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && space match && virtual addr match
			beq		hrmGSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	hrmG64SrchLp				; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free mapping flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(free && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && space match && virtual addr match
			beq		hrmGSrchHit					; Join common path on hit (r31 points to guest mapping)
hrmGSrchMiss:
			lwz		r3,vxsGrmMiss(r26)			; Get remove miss count
			li		r25,mapRtNotFnd				; Return not found
			addi	r3,r3,1						; Increment miss count
			stw		r3,vxsGrmMiss(r26)			; Update miss count
			b		hrmGReturn					; Join guest return

			.align	5			
hrmGSrchHit:
			rlwinm.	r0,r6,0,mpgDormant			; Is this entry dormant?
			bne		hrmGDormant					; Yes, nothing to disconnect
			
			lwz		r3,vxsGrmActive(r26)		; Get active hit count
			addi	r3,r3,1						; Increment active hit count
			stw		r3,vxsGrmActive(r26)		; Update hit count
			
			bt++	pf64Bitb,hrmGDscon64		; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		hrmGFreePTE					; Join 64-bit path to release the PTE			
hrmGDscon64:
			bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
hrmGFreePTE:
			mr.		r3,r3						; Was there a valid PTE?
			beq		hrmGDormant					; No valid PTE, we're almost done
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE offset
			rlwinm	r8,r8,0,~mpHValid			; Make the offset invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE offset
			eieio								; Synchronize all previous updates (mapInvPtexx didn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG

hrmGDormant:
			lwz		r3,mpPAddr(r31)				; r3 <- physical 4K-page number
			bl		mapFindLockPN				; Find 'n' lock this page's physent
			mr.		r29,r3						; Got lock on our physent?
			beq--	hrmGBadPLock				; No, time to bail out

			crset	cr1_eq						; cr1_eq <- previous link is the anchor
			bt++	pf64Bitb,hrmGRemove64		; Use 64-bit version on 64-bit machine
			la		r11,ppLink+4(r29)			; Point to chain anchor
			lwz		r9,ppLink+4(r29)			; Get chain anchor
			rlwinm.	r9,r9,0,~ppFlags			; Remove flags, yielding 32-bit physical chain pointer
hrmGRemLoop:
			beq-	hrmGPEMissMiss				; End of chain, this is not good
			cmplw	r9,r31						; Is this the mapping to remove?
			lwz		r8,mpAlias+4(r9)			; Get forward chain pointer
			bne		hrmGRemNext					; No, chain onward
			bt		cr1_eq,hrmGRemRetry			; Mapping to remove is chained from anchor
			stw		r8,0(r11)					; Unchain gpv->phys mapping
			b		hrmGDelete					; Finish deleting mapping
hrmGRemRetry:
			lwarx	r0,0,r11					; Get previous link
			rlwimi	r0,r8,0,~ppFlags			; Insert new forward pointer whilst preserving flags
			stwcx.	r0,0,r11					; Update previous link
			bne-	hrmGRemRetry				; Lost reservation, retry
			b		hrmGDelete					; Finish deleting mapping
			
hrmGRemNext:
			la		r11,mpAlias+4(r9)			; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		hrmGRemLoop					; Carry on

hrmGRemove64:
			li		r7,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r7,r7,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			la		r11,ppLink(r29)				; Point to chain anchor
			ld		r9,ppLink(r29)				; Get chain anchor
			andc.	r9,r9,r7					; Remove flags, yielding 64-bit physical chain pointer
hrmGRem64Lp:
			beq--	hrmGPEMissMiss				; End of chain, this is not good
			cmpld	r9,r31						; Is this the mapping to remove?
			ld		r8,mpAlias(r9)				; Get forward chain pinter
			bne		hrmGRem64Nxt				; No mapping to remove, chain on, dude
			bt		cr1_eq,hrmGRem64Rt			; Mapping to remove is chained from anchor
			std		r8,0(r11)					; Unchain gpv->phys mapping
			b		hrmGDelete					; Finish deleting mapping
hrmGRem64Rt:
			ldarx	r0,0,r11					; Get previous link
			and		r0,r0,r7					; Get flags
			or		r0,r0,r8					; Insert new forward pointer
			stdcx.	r0,0,r11					; Slam it back in
			bne--	hrmGRem64Rt					; Lost reservation, retry
			b		hrmGDelete					; Finish deleting mapping

			.align	5		
hrmGRem64Nxt:
			la		r11,mpAlias(r9)				; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		hrmGRem64Lp					; Carry on
			
hrmGDelete:
			mr		r3,r29						; r3 <- physent addr
			bl		mapPhysUnlock				; Unlock physent chain
			lwz		r3,mpFlags(r31)				; Get mapping's flags
			rlwinm	r3,r3,0,~mpgFlags			; Clear all guest flags
			ori		r3,r3,mpgFree				; Mark mapping free
			stw		r3,mpFlags(r31)				; Update flags
			li		r25,mapRtGuest				; Set return code to 'found guest mapping'

hrmGReturn:
			la		r3,pmapSXlk(r27)			; r3 <- host pmap search lock phys addr
			bl		sxlkUnlock					; Release host pmap search lock
			
			mr		r3,r25						; r3 <- return code
			bt++	pf64Bitb,hrmGRtn64			; Handle 64-bit separately
			mtmsr	r17							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		hrmRetnCmn					; Nothing to do now but pop a frame and return
hrmGRtn64:	mtmsrd	r17							; Restore 'rupts, translation, 32-bit mode
			b		hrmRetnCmn					; Join common return

hrmGBadPLock:
hrmGPEMissMiss:
			lis		r0,hi16(Choke)				; Seen the arrow on the doorpost
			ori		r0,r0,lo16(Choke)			; Sayin' "THIS LAND IS CONDEMNED"
			li		r3,failMapping				; All the way from New Orleans
			sc									; To Jeruselem


/*
 *			mapping *hw_purge_phys(physent) - remove a mapping from the system
 *
 *			Upon entry, R3 contains a pointer to a physent.  
 *
 *			This function removes the first mapping from a physical entry
 *			alias list.  It locks the list, extracts the vaddr and pmap from
 *			the first entry.  It then jumps into the hw_rem_map function.
 *			NOTE: since we jump into rem_map, we need to set up the stack
 *			identically.  Also, we set the next parm to 0 so we do not
 *			try to save a next vaddr.
 *			
 *			We return the virtual address of the removed mapping as a 
 *			R3.
 *
 *			Note that this is designed to be called from 32-bit mode with a stack.
 *
 *			We disable translation and all interruptions here.  This keeps is
 *			from having to worry about a deadlock due to having anything locked
 *			and needing it to process a fault.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 * 
 * Remove mapping via physical page (mapping_purge)
 * 
 *  1) lock physent
 *  2) extract vaddr and pmap
 *  3) unlock physent
 *  4) do "remove mapping via pmap"
 *  
 *	
 */

			.align	5
			.globl	EXT(hw_purge_phys)

LEXT(hw_purge_phys)
			stwu	r1,-(FM_ALIGN(hrmStackSize)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r15,FM_ARG0+0x00(r1)		; Save a register
			stw		r16,FM_ARG0+0x04(r1)		; Save a register
			stw		r17,FM_ARG0+0x08(r1)		; Save a register
			stw		r18,FM_ARG0+0x0C(r1)		; Save a register
			stw		r19,FM_ARG0+0x10(r1)		; Save a register
			stw		r20,FM_ARG0+0x14(r1)		; Save a register
			stw		r21,FM_ARG0+0x18(r1)		; Save a register
			stw		r22,FM_ARG0+0x1C(r1)		; Save a register
			stw		r23,FM_ARG0+0x20(r1)		; Save a register
			stw		r24,FM_ARG0+0x24(r1)		; Save a register
			stw		r25,FM_ARG0+0x28(r1)		; Save a register
			li		r6,0						; Set no next address return
			stw		r26,FM_ARG0+0x2C(r1)		; Save a register
			stw		r27,FM_ARG0+0x30(r1)		; Save a register
			stw		r28,FM_ARG0+0x34(r1)		; Save a register
			stw		r29,FM_ARG0+0x38(r1)		; Save a register
			stw		r30,FM_ARG0+0x3C(r1)		; Save a register
			stw		r31,FM_ARG0+0x40(r1)		; Save a register
			stw		r6,FM_ARG0+0x44(r1)			; Save address to save next mapped vaddr
			stw		r0,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			bl		mapPhysLock					; Lock the physent
			
 			bt++	pf64Bitb,hppSF				; skip if 64-bit (only they take the hint)
		
			lwz		r12,ppLink+4(r3)			; Grab the pointer to the first mapping
 			li		r0,ppFlags					; Set the bottom stuff to clear
			b		hppJoin						; Join the common...
			
hppSF:		li		r0,ppLFAmask
			ld		r12,ppLink(r3)				; Get the pointer to the first mapping
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F

hppJoin:	andc.	r12,r12,r0					; Clean and test link
			beq--	hppNone						; There are no more mappings on physical page
			
			lis		r28,hi16(EXT(pmapTrans))	; Get the top of the start of the pmap hash to pmap translate table
			lhz		r7,mpSpace(r12)			; Get the address space hash
			ori		r28,r28,lo16(EXT(pmapTrans))	; Get the top of the start of the pmap hash to pmap translate table
			slwi	r0,r7,2						; Multiply space by 4
			lwz		r4,mpVAddr(r12)				; Get the top of the vaddr
			slwi	r7,r7,3						; Multiply space by 8
			lwz		r5,mpVAddr+4(r12)			; and the bottom
			add		r7,r7,r0					; Get correct displacement into translate table
			lwz		r28,0(r28)					; Get the actual translation map
	
			add		r28,r28,r7					; Point to the pmap translation
					
			bl		mapPhysUnlock				; Time to unlock the physical entry
			
 			bt++	pf64Bitb,hppSF2				; skip if 64-bit (only they take the hint)
			
			lwz		r28,pmapPAddr+4(r28)		; Get the physical address of the pmap
			b		hrmJoin						; Go remove the mapping...
			
hppSF2:		ld		r28,pmapPAddr(r28)			; Get the physical address of the pmap
			b		hrmJoin						; Go remove the mapping...

			.align	5
			
hppNone:	bl		mapPhysUnlock				; Time to unlock the physical entry

			bt++	pf64Bitb,hppSF3				; skip if 64-bit (only they take the hint)...

			mtmsr	r11							; Restore enables/translation/etc.
			isync
			b		hppRetnCmn					; Join the common return code...

hppSF3:		mtmsrd	r11							; Restore enables/translation/etc.
			isync

;
;			NOTE: we have not used any registers other than the volatiles to this point
;

hppRetnCmn:	lwz		r12,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Restore the return

			li		r3,mapRtEmpty				; Physent chain is empty
			mtlr	r12							; Restore the return
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...

/*
 *			mapping *hw_purge_map(pmap, vaddr, addr64_t *next) - remove a mapping from the system.
 *
 *			Upon entry, R3 contains a pointer to a pmap.  Since vaddr is
 *			a 64-bit quantity, it is a long long so it is in R4 and R5.
 *			
 *			We return the virtual address of the removed mapping as a 
 *			R3.
 *
 *			Note that this is designed to be called from 32-bit mode with a stack.
 *
 *			We disable translation and all interruptions here.  This keeps is
 *			from having to worry about a deadlock due to having anything locked
 *			and needing it to process a fault.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 *  Remove a mapping which can be reestablished by VM
 *
 */

			.align	5
			.globl	EXT(hw_purge_map)

LEXT(hw_purge_map)
			stwu	r1,-(FM_ALIGN(hrmStackSize)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r15,FM_ARG0+0x00(r1)		; Save a register
			stw		r16,FM_ARG0+0x04(r1)		; Save a register
			stw		r17,FM_ARG0+0x08(r1)		; Save a register
			stw		r18,FM_ARG0+0x0C(r1)		; Save a register
			stw		r19,FM_ARG0+0x10(r1)		; Save a register
 			mfsprg	r19,2						; Get feature flags 
			stw		r20,FM_ARG0+0x14(r1)		; Save a register
			stw		r21,FM_ARG0+0x18(r1)		; Save a register
			mtcrf	0x02,r19					; move pf64Bit cr6
			stw		r22,FM_ARG0+0x1C(r1)		; Save a register
			stw		r23,FM_ARG0+0x20(r1)		; Save a register
			stw		r24,FM_ARG0+0x24(r1)		; Save a register
			stw		r25,FM_ARG0+0x28(r1)		; Save a register
			stw		r26,FM_ARG0+0x2C(r1)		; Save a register
			stw		r27,FM_ARG0+0x30(r1)		; Save a register
			stw		r28,FM_ARG0+0x34(r1)		; Save a register
			stw		r29,FM_ARG0+0x38(r1)		; Save a register
			stw		r30,FM_ARG0+0x3C(r1)		; Save a register
			stw		r31,FM_ARG0+0x40(r1)		; Save a register
			stw		r6,FM_ARG0+0x44(r1)			; Save address to save next mapped vaddr
			stw		r0,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r3)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active? 
			bne		hpmPanic					; Call not valid for guest shadow assist pmap
#endif
			
 			bt++	pf64Bitb,hpmSF1				; skip if 64-bit (only they take the hint)
			lwz		r9,pmapvr+4(r3)				; Get conversion mask
			b		hpmSF1x						; Done...
			
hpmSF1:		ld		r9,pmapvr(r3)				; Get conversion mask

hpmSF1x:	
			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			xor		r28,r3,r9					; Convert the pmap to physical addressing

			mr		r17,r11						; Save the MSR

			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkExclusive				; Go get an exclusive lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne--	hrmBadLock					; Nope...
;
;			Note that we do a full search (i.e., no shortcut level skips, etc.)
;			here so that we will know the previous elements so we can dequeue them
;			later.
;
hpmSearch:
			mr		r3,r28						; Pass in pmap to search
			mr		r29,r4						; Top half of vaddr
			mr		r30,r5						; Bottom half of vaddr
			bl		EXT(mapSearchFull)			; Rescan the list
			mr.		r31,r3						; Did we? (And remember mapping address for later)
			or		r0,r4,r5					; Are we beyond the end?
			mr		r15,r4						; Save top of next vaddr
			cmplwi	cr1,r0,0					; See if there is another
			mr		r16,r5						; Save bottom of next vaddr
			bne--	hpmGotOne					; We found one, go check it out...

hpmCNext:	bne++	cr1,hpmSearch				; There is another to check...
			b		hrmNotFound					; No more in pmap to check...

hpmGotOne:	lwz		r20,mpFlags(r3)				; Get the flags
			andi.	r0,r20,lo16(mpType|mpPerm)	; cr0_eq <- normal mapping && !permanent
			rlwinm	r21,r20,8,24,31				; Extract the busy count
			cmplwi	cr2,r21,0					; Is it busy?
			crand	cr0_eq,cr2_eq,cr0_eq		; not busy and can be removed?
			beq++	hrmGotX						; Found, branch to remove the mapping...
			b		hpmCNext					; Nope...

hpmPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc

/*
 *			mapping *hw_purge_space(physent, pmap) - remove a mapping from the system based upon address space
 *
 *			Upon entry, R3 contains a pointer to a pmap.  
 *			pa is a pointer to the physent
 *
 *			This function removes the first mapping for a specific pmap from a physical entry
 *			alias list.  It locks the list, extracts the vaddr and pmap from
 *			the first apporpriate entry.  It then jumps into the hw_rem_map function.
 *			NOTE: since we jump into rem_map, we need to set up the stack
 *			identically.  Also, we set the next parm to 0 so we do not
 *			try to save a next vaddr.
 *			
 *			We return the virtual address of the removed mapping as a 
 *			R3.
 *
 *			Note that this is designed to be called from 32-bit mode with a stack.
 *
 *			We disable translation and all interruptions here.  This keeps is
 *			from having to worry about a deadlock due to having anything locked
 *			and needing it to process a fault.
 *
 *			Note that this must be done with both interruptions off and VM off
 *	
 * 
 * Remove mapping via physical page (mapping_purge)
 * 
 *  1) lock physent
 *  2) extract vaddr and pmap
 *  3) unlock physent
 *  4) do "remove mapping via pmap"
 *  
 *	
 */

			.align	5
			.globl	EXT(hw_purge_space)

LEXT(hw_purge_space)
			stwu	r1,-(FM_ALIGN(hrmStackSize)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r15,FM_ARG0+0x00(r1)		; Save a register
			stw		r16,FM_ARG0+0x04(r1)		; Save a register
			stw		r17,FM_ARG0+0x08(r1)		; Save a register
 			mfsprg	r2,2						; Get feature flags 
			stw		r18,FM_ARG0+0x0C(r1)		; Save a register
			stw		r19,FM_ARG0+0x10(r1)		; Save a register
			stw		r20,FM_ARG0+0x14(r1)		; Save a register
			stw		r21,FM_ARG0+0x18(r1)		; Save a register
			stw		r22,FM_ARG0+0x1C(r1)		; Save a register
			mtcrf	0x02,r2						; move pf64Bit cr6
			stw		r23,FM_ARG0+0x20(r1)		; Save a register
			stw		r24,FM_ARG0+0x24(r1)		; Save a register
			stw		r25,FM_ARG0+0x28(r1)		; Save a register
			stw		r26,FM_ARG0+0x2C(r1)		; Save a register
			stw		r27,FM_ARG0+0x30(r1)		; Save a register
			li		r6,0						; Set no next address return
			stw		r28,FM_ARG0+0x34(r1)		; Save a register
			stw		r29,FM_ARG0+0x38(r1)		; Save a register
			stw		r30,FM_ARG0+0x3C(r1)		; Save a register
			stw		r31,FM_ARG0+0x40(r1)		; Save a register
			stw		r6,FM_ARG0+0x44(r1)			; Save address to save next mapped vaddr
			stw		r0,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r4)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active? 
			bne		hpsPanic					; Call not valid for guest shadow assist pmap
#endif
			
			bt++	pf64Bitb,hpsSF1				; skip if 64-bit (only they take the hint)

			lwz		r9,pmapvr+4(r4)				; Get conversion mask for pmap

			b		hpsSF1x						; Done...
			
hpsSF1:		ld		r9,pmapvr(r4)				; Get conversion mask for pmap

hpsSF1x:	bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit
			
			xor		r4,r4,r9					; Convert the pmap to physical addressing

			bl		mapPhysLock					; Lock the physent
			 
 			lwz		r8,pmapSpace(r4)			; Get the space hash
 
 			bt++	pf64Bitb,hpsSF				; skip if 64-bit (only they take the hint)
		
			lwz		r12,ppLink+4(r3)			; Grab the pointer to the first mapping
			
hpsSrc32:	rlwinm.	r12,r12,0,~ppFlags			; Clean and test mapping address
			beq		hpsNone						; Did not find one...
			
			lhz		r10,mpSpace(r12)			; Get the space
			
			cmplw	r10,r8						; Is this one of ours?
			beq		hpsFnd						; Yes...
			
			lwz		r12,mpAlias+4(r12)			; Chain on to the next
			b		hpsSrc32					; Check it out...

			.align	5
		
hpsSF:		li		r0,ppLFAmask
			ld		r12,ppLink(r3)				; Get the pointer to the first mapping
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			
hpsSrc64:	andc.	r12,r12,r0					; Clean and test mapping address
			beq		hpsNone						; Did not find one...
			
			lhz		r10,mpSpace(r12)			; Get the space
			
			cmplw	r10,r8						; Is this one of ours?
			beq		hpsFnd						; Yes...
			
			ld		r12,mpAlias(r12)			; Chain on to the next
			b		hpsSrc64					; Check it out...
			
			.align	5
			
hpsFnd:		mr		r28,r4						; Set the pmap physical address
			lwz		r4,mpVAddr(r12)				; Get the top of the vaddr
			lwz		r5,mpVAddr+4(r12)			; and the bottom
			
			bl		mapPhysUnlock				; Time to unlock the physical entry
			b		hrmJoin						; Go remove the mapping...
			
			.align	5
			
hpsNone:	bl		mapPhysUnlock				; Time to unlock the physical entry

			bt++	pf64Bitb,hpsSF3				; skip if 64-bit (only they take the hint)...

			mtmsr	r11							; Restore enables/translation/etc.
			isync
			b		hpsRetnCmn					; Join the common return code...

hpsSF3:		mtmsrd	r11							; Restore enables/translation/etc.
			isync

;
;			NOTE: we have not used any registers other than the volatiles to this point
;

hpsRetnCmn:	lwz		r12,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Restore the return

			li		r3,mapRtEmpty				; No mappings for specified pmap on physent chain
			mtlr	r12							; Restore the return
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...

hpsPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc
			
/*
 *			mapping *hw_scrub_guest(physent, pmap) - remove first guest mapping associated with host
 *                                                    on this physent chain
 *
 *			Locates the first guest mapping on the physent chain that is associated with the
 *			specified host pmap. If this succeeds, the mapping is removed by joining the general
 *			remove path; otherwise, we return NULL. The caller is expected to invoke this entry
 *			repeatedly until no additional guest mappings that match our criteria are removed.
 *
 *			Because this entry point exits through hw_rem_map, our prolog pushes its frame.
 *
 *			Parameters:
 *				r3 : physent, 32-bit kernel virtual address
 *				r4 : host pmap, 32-bit kernel virtual address
 *
 *			Volatile register usage (for linkage through hrmJoin):
 *				r4 : high-order 32 bits of guest virtual address
 *				r5 : low-order 32 bits of guest virtual address
 *				r11: saved MSR image
 *
 *			Non-volatile register usage:
 *				r26: VMM extension block's physical address
 *				r27: host pmap's physical address
 *				r28: guest pmap's physical address
 *	
 */

			.align	5
			.globl	EXT(hw_scrub_guest)

LEXT(hw_scrub_guest)
			stwu	r1,-(FM_ALIGN(hrmStackSize)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r15,FM_ARG0+0x00(r1)		; Save a register
			stw		r16,FM_ARG0+0x04(r1)		; Save a register
			stw		r17,FM_ARG0+0x08(r1)		; Save a register
 			mfsprg	r2,2						; Get feature flags 
			stw		r18,FM_ARG0+0x0C(r1)		; Save a register
			stw		r19,FM_ARG0+0x10(r1)		; Save a register
			stw		r20,FM_ARG0+0x14(r1)		; Save a register
			stw		r21,FM_ARG0+0x18(r1)		; Save a register
			stw		r22,FM_ARG0+0x1C(r1)		; Save a register
			mtcrf	0x02,r2						; move pf64Bit cr6
			stw		r23,FM_ARG0+0x20(r1)		; Save a register
			stw		r24,FM_ARG0+0x24(r1)		; Save a register
			stw		r25,FM_ARG0+0x28(r1)		; Save a register
			stw		r26,FM_ARG0+0x2C(r1)		; Save a register
			stw		r27,FM_ARG0+0x30(r1)		; Save a register
			li		r6,0						; Set no next address return
			stw		r28,FM_ARG0+0x34(r1)		; Save a register
			stw		r29,FM_ARG0+0x38(r1)		; Save a register
			stw		r30,FM_ARG0+0x3C(r1)		; Save a register
			stw		r31,FM_ARG0+0x40(r1)		; Save a register
			stw		r6,FM_ARG0+0x44(r1)			; Save address to save next mapped vaddr
			stw		r0,(FM_ALIGN(hrmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

			lwz		r11,pmapVmmExt(r4)			; get VMM pmap extension block vaddr

			bt++	pf64Bitb,hsg64Salt			; Test for 64-bit machine
			lwz		r26,pmapVmmExtPhys+4(r4)	; Get VMM pmap extension block paddr
			lwz		r9,pmapvr+4(r4)				; Get 32-bit virt<->real conversion salt
			b		hsgStart					; Get to work

hsg64Salt:	ld		r26,pmapVmmExtPhys(r4)		; Get VMM pmap extension block paddr
			ld		r9,pmapvr+4(r4)				; Get 64-bit virt<->real conversion salt
			
hsgStart:	bl		EXT(mapSetUp)				; Disable 'rupts, translation, enter 64-bit mode
			xor		r27,r4,r9					; Convert host pmap_t virt->real
			bl		mapPhysLock					; Lock the physent

			bt++	pf64Bitb,hsg64Scan			; Test for 64-bit machine

			lwz		r12,ppLink+4(r3)			; Grab the pointer to the first mapping
hsg32Loop:	rlwinm.	r12,r12,0,~ppFlags			; Clean and test mapping address
			beq		hsg32Miss					; Did not find one...
			lwz		r8,mpFlags(r12)				; Get mapping's flags
			lhz		r7,mpSpace(r12)				; Get mapping's space id
			rlwinm	r8,r8,0,mpType				; Extract mapping's type code
			lis		r28,hi16(EXT(pmapTrans))	; Get the top of the start of the pmap hash to pmap translate table
			xori	r8,r8,mpGuest				; Is it a guest mapping?
			ori		r28,r28,lo16(EXT(pmapTrans))	; Get the top of the start of the pmap hash to pmap translate table
			slwi	r9,r7,2						; Multiply space by 4
			lwz		r28,0(r28)					; Get the actual translation map
			lwz		r4,mpVAddr(r12)				; Get the top of the vaddr
			slwi	r7,r7,3						; Multiply space by 8
			lwz		r5,mpVAddr+4(r12)			; Get the bottom of the vaddr
			add		r7,r7,r9					; Get correct displacement into translate table
			add		r28,r28,r7					; Point to the pmap translation
			lwz		r28,pmapPAddr+4(r28)		; Get guest pmap paddr
			lwz		r7,pmapVmmExtPhys+4(r28)	; Get VMM extension block paddr
			xor		r7,r7,r26					; Is guest associated with specified host?
			or.		r7,r7,r8					; Guest mapping && associated with host?
			lwz		r12,mpAlias+4(r12)			; Chain on to the next
			bne		hsg32Loop					; Try next mapping on alias chain			

hsg32Hit:	bl		mapPhysUnlock				; Unlock physent chain
			b		hrmJoin						; Join common path for mapping removal
			
			.align	5
hsg32Miss:	bl		mapPhysUnlock				; Unlock physent chain
			mtmsr	r11							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			li		r3,mapRtEmpty				; No mappings found matching specified criteria
			b		hrmRetnCmn					; Exit through common epilog
			
			.align	5			
hsg64Scan:	li		r6,ppLFAmask				; Get lock, flag, attribute mask seed
			ld		r12,ppLink(r3)				; Grab the pointer to the first mapping
			rotrdi	r6,r6,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
hsg64Loop:	andc.	r12,r12,r6					; Clean and test mapping address
			beq		hsg64Miss					; Did not find one...
			lwz		r8,mpFlags(r12)				; Get mapping's flags
			lhz		r7,mpSpace(r12)				; Get mapping's space id
			rlwinm	r8,r8,0,mpType				; Extract mapping's type code
			lis		r28,hi16(EXT(pmapTrans))	; Get the top of the start of the pmap hash to pmap translate table
			xori	r8,r8,mpGuest				; Is it a guest mapping?
			ori		r28,r28,lo16(EXT(pmapTrans))	; Get the top of the start of the pmap hash to pmap translate table
			slwi	r9,r7,2						; Multiply space by 4
			lwz		r28,0(r28)					; Get the actual translation map
			lwz		r4,mpVAddr(r12)				; Get the top of the vaddr
			slwi	r7,r7,3						; Multiply space by 8
			lwz		r5,mpVAddr+4(r12)			; Get the bottom of the vaddr
			add		r7,r7,r9					; Get correct displacement into translate table
			add		r28,r28,r7					; Point to the pmap translation
			ld		r28,pmapPAddr(r28)			; Get guest pmap paddr
			ld		r7,pmapVmmExtPhys(r28)		; Get VMM extension block paddr
			xor		r7,r7,r26					; Is guest associated with specified host?
			or.		r7,r7,r8					; Guest mapping && associated with host?
			ld		r12,mpAlias(r12)			; Chain on to the next
			bne		hsg64Loop					; Try next mapping on alias chain			

hsg64Hit:	bl		mapPhysUnlock				; Unlock physent chain
			b		hrmJoin						; Join common path for mapping removal
			
			.align	5
hsg64Miss:	bl		mapPhysUnlock				; Unlock physent chain
			mtmsrd	r11							; Restore 'rupts, translation
			li		r3,mapRtEmpty				; No mappings found matching specified criteria
			b		hrmRetnCmn					; Exit through common epilog


/*
 *			mapping *hw_find_space(physent, space) - finds the first mapping on physent for specified space
 *
 *			Upon entry, R3 contains a pointer to a physent.  
 *			space is the space ID from the pmap in question
 *
 *			We return the virtual address of the found mapping in 
 *			R3. Note that the mapping busy is bumped.
 *
 *			Note that this is designed to be called from 32-bit mode with a stack.
 *
 *			We disable translation and all interruptions here.  This keeps is
 *			from having to worry about a deadlock due to having anything locked
 *			and needing it to process a fault.
 *	
 */

			.align	5
			.globl	EXT(hw_find_space)

LEXT(hw_find_space)
			stwu	r1,-(FM_SIZE)(r1)			; Make some space on the stack
			mflr	r0							; Save the link register
			mr		r8,r4						; Remember the space
			stw		r0,(FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			bl		mapPhysLock					; Lock the physent
 
 			bt++	pf64Bitb,hfsSF				; skip if 64-bit (only they take the hint)
		
			lwz		r12,ppLink+4(r3)			; Grab the pointer to the first mapping
			
hfsSrc32:	rlwinm.	r12,r12,0,~ppFlags			; Clean and test mapping address
			beq		hfsNone						; Did not find one...
			
			lhz		r10,mpSpace(r12)			; Get the space
			
			cmplw	r10,r8						; Is this one of ours?
			beq		hfsFnd						; Yes...
			
			lwz		r12,mpAlias+4(r12)			; Chain on to the next
			b		hfsSrc32					; Check it out...

			.align	5
		
hfsSF:		li		r0,ppLFAmask
			ld		r12,ppLink(r3)				; Get the pointer to the first mapping
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			
hfsSrc64:	andc.	r12,r12,r0					; Clean and test mapping address
			beq		hfsNone						; Did not find one...
			
			lhz		r10,mpSpace(r12)			; Get the space
			
			cmplw	r10,r8						; Is this one of ours?
			beq		hfsFnd						; Yes...
			
			ld		r12,mpAlias(r12)			; Chain on to the next
			b		hfsSrc64					; Check it out...
			
			.align	5
			
hfsFnd:		mr		r8,r3						; Save the physent
			mr		r3,r12						; Point to the mapping
			bl		mapBumpBusy					; If we found it, bump up the busy count so the mapping does not disapear

			mr		r3,r8						; Get back the physical entry
			li		r7,0xFFF					; Get a page size mask
			bl		mapPhysUnlock				; Time to unlock the physical entry
		
			andc	r3,r12,r7					; Move the mapping back down to a page	
			lwz		r3,mbvrswap+4(r3)			; Get last half of virtual to real swap
			xor		r12,r3,r12					; Convert to virtual
			b		hfsRet						; Time to return
			
			.align	5
			
hfsNone:	bl		mapPhysUnlock				; Time to unlock the physical entry
			
hfsRet:		bt++	pf64Bitb,hfsSF3				; skip if 64-bit (only they take the hint)...

			mtmsr	r11							; Restore enables/translation/etc.
			isync
			b		hfsRetnCmn					; Join the common return code...

hfsSF3:		mtmsrd	r11							; Restore enables/translation/etc.
			isync

;
;			NOTE: we have not used any registers other than the volatiles to this point
;

hfsRetnCmn:	mr		r3,r12						; Get the mapping or a 0 if we failed

#if DEBUG
			mr.		r3,r3						; Anything to return?
			beq		hfsRetnNull					; Nope
			lwz		r11,mpFlags(r3)				; Get mapping flags
			rlwinm	r0,r11,0,mpType				; Isolate the mapping type
			cmplwi	r0,mpGuest					; Shadow guest mapping?
			beq		hfsPanic					; Yup, kick the bucket
hfsRetnNull:
#endif

			lwz		r12,(FM_SIZE+FM_LR_SAVE)(r1)	; Restore the return

			mtlr	r12							; Restore the return
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...

hfsPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc

;
;			mapping *hw_find_map(pmap, va, *nextva) - Looks up a vaddr in a pmap
;			Returns 0 if not found or the virtual address of the mapping if
;			if is.  Also, the mapping has the busy count bumped.
;
			.align	5
			.globl	EXT(hw_find_map)

LEXT(hw_find_map)
 			stwu	r1,-(FM_ALIGN((31-25+1)*4)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r25,FM_ARG0+0x00(r1)		; Save a register
			stw		r26,FM_ARG0+0x04(r1)		; Save a register
			mr		r25,r6						; Remember address of next va
			stw		r27,FM_ARG0+0x08(r1)		; Save a register
			stw		r28,FM_ARG0+0x0C(r1)		; Save a register
			stw		r29,FM_ARG0+0x10(r1)		; Save a register
			stw		r30,FM_ARG0+0x14(r1)		; Save a register
			stw		r31,FM_ARG0+0x18(r1)		; Save a register
			stw		r0,(FM_ALIGN((31-26+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r3)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active? 
			bne		hfmPanic					; Call not valid for guest shadow assist pmap
#endif
			
			lwz		r6,pmapvr(r3)				; Get the first part of the VR translation for pmap
			lwz		r7,pmapvr+4(r3)				; Get the second part


			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			mr		r27,r11						; Remember the old MSR
			mr		r26,r12						; Remember the feature bits

			xor		r28,r3,r7					; Change the common 32- and 64-bit half

			bf--	pf64Bitb,hfmSF1				; skip if 32-bit...
			
			rldimi	r28,r6,32,0					; Shift the fixed upper part of the physical over and cram in top

hfmSF1:		mr		r29,r4						; Save top half of vaddr
			mr		r30,r5						; Save the bottom half
						
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne--	hfmBadLock					; Nope...

			mr		r3,r28						; get the pmap address
			mr		r4,r29						; Get bits 0:31 to look for
			mr		r5,r30						; Get bits 32:64
			
			bl		EXT(mapSearch)				; Go see if we can find it (note: R7 comes back with mpFlags)

			rlwinm	r0,r7,0,mpRIPb,mpRIPb		; Find remove in progress bit
			mr.		r31,r3						; Save the mapping if we found it
			cmplwi	cr1,r0,0					; Are we removing?
			mr		r29,r4						; Save next va high half
			crorc	cr0_eq,cr0_eq,cr1_eq		; Not found or removing
			mr		r30,r5						; Save next va low half
			li		r6,0						; Assume we did not find it
			li		r26,0xFFF					; Get a mask to relocate to start of mapping page

			bt--	cr0_eq,hfmNotFnd			; We did not find it...

			bl		mapBumpBusy					; If we found it, bump up the busy count so the mapping does not disapear

			andc	r4,r31,r26					; Get back to the mapping page start

;			Note: we can treat 32- and 64-bit the same here. Because we are going from
;			physical to virtual and we only do 32-bit virtual, we only need the low order
;			word of the xor.

			lwz		r4,mbvrswap+4(r4)			; Get last half of virtual to real swap
			li		r6,-1						; Indicate we found it and it is not being removed
			xor		r31,r31,r4					; Flip to virtual

hfmNotFnd:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			rlwinm	r3,r31,0,0,31				; Move mapping to return register and clear top of register if 64-bit
			and		r3,r3,r6					; Clear if not found or removing

hfmReturn:	bt++	pf64Bitb,hfmR64				; Yes...

			mtmsr	r27							; Restore enables/translation/etc.
			isync
			b		hfmReturnC					; Join common...

hfmR64:		mtmsrd	r27							; Restore enables/translation/etc.
			isync								
			
hfmReturnC:	stw		r29,0(r25)					; Save the top of the next va
			stw		r30,4(r25)					; Save the bottom of the next va
			lwz		r0,(FM_ALIGN((31-25+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return
			lwz		r25,FM_ARG0+0x00(r1)		; Restore a register
			lwz		r26,FM_ARG0+0x04(r1)		; Restore a register
			and		r3,r3,r6					; Clear return if the mapping is being removed
			lwz		r27,FM_ARG0+0x08(r1)		; Restore a register
			mtlr	r0							; Restore the return
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore a register
			lwz		r29,FM_ARG0+0x10(r1)		; Restore a register
			lwz		r30,FM_ARG0+0x14(r1)		; Restore a register
			lwz		r31,FM_ARG0+0x18(r1)		; Restore a register
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...
			
			.align	5
			
hfmBadLock:	li		r3,1						; Set lock time out error code
			b		hfmReturn					; Leave....

hfmPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc


/*
 *			void hw_clear_maps(void) 
 *
 *			Remove all mappings for all phys entries.
 *	
 * 
 */

			.align	5
			.globl	EXT(hw_clear_maps)

LEXT(hw_clear_maps)
			mflr	r10							; Save the link register
            mfcr	r9							; Save the condition register
			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			lis		r5,hi16(EXT(pmap_mem_regions))		; Point to the start of the region table
			ori		r5,r5,lo16(EXT(pmap_mem_regions))	; Point to the start of the region table			

hcmNextRegion:
			lwz		r3,mrPhysTab(r5)			; Get the actual table address
			lwz		r0,mrStart(r5)				; Get start of table entry
			lwz		r4,mrEnd(r5)				; Get end of table entry
			addi	r5,r5,mrSize				; Point to the next regions

			cmplwi	r3,0						; No more regions?
			beq--	hcmDone						; Leave...

			sub		r4,r4,r0					; Calculate physical entry count
            addi	r4,r4,1
            mtctr	r4

			bt++	pf64Bitb,hcmNextPhys64		; 64-bit version


hcmNextPhys32:
			lwz		r4,ppLink+4(r3)				; Grab the pointer to the first mapping
            addi	r3,r3,physEntrySize			; Next phys_entry
			
hcmNextMap32:
			rlwinm.	r4,r4,0,~ppFlags			; Clean and test mapping address
			beq		hcmNoMap32					; Did not find one...

			lwz		r0,mpPte(r4)				; Grab the offset to the PTE
			rlwinm	r0,r0,0,~mpHValid			; Clear out valid bit
			stw		r0,mpPte(r4)				; Get the quick pointer again

			lwz		r4,mpAlias+4(r4)			; Chain on to the next
			b		hcmNextMap32				; Check it out...
hcmNoMap32:
            bdnz	hcmNextPhys32
            b		hcmNextRegion


			.align	5
hcmNextPhys64:
			li		r0,ppLFAmask				; Get mask to clean up mapping pointer
			ld		r4,ppLink(r3)				; Get the pointer to the first mapping
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
            addi	r3,r3,physEntrySize			; Next phys_entry
			
hcmNextMap64:
			andc.	r4,r4,r0					; Clean and test mapping address
			beq		hcmNoMap64					; Did not find one...

			lwz		r0,mpPte(r4)				; Grab the offset to the PTE
			rlwinm	r0,r0,0,~mpHValid			; Clear out valid bit
			stw		r0,mpPte(r4)				; Get the quick pointer again

			ld		r4,mpAlias(r4)				; Chain on to the next
			li		r0,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			b		hcmNextMap64				; Check it out...
hcmNoMap64:
            bdnz	hcmNextPhys64
            b		hcmNextRegion


			.align	5
hcmDone:
			mtlr	r10							; Restore the return
			mtcr	r9							; Restore the condition register
			bt++	pf64Bitb,hcmDone64			; 64-bit version
hcmDone32:
			mtmsr	r11							; Restore translation/mode/etc.
			isync
			blr									; Leave...

hcmDone64:
			mtmsrd	r11							; Restore translation/mode/etc.
			isync
			blr									; Leave...



/*
 *			unsigned int hw_walk_phys(pp, preop, op, postop, parm, opmod) 
 *				walks all mapping for a physical page and performs
 *				specified operations on each.
 *
 *			pp is unlocked physent
 *			preop is operation to perform on physent before walk.  This would be
 *				used to set cache attribute or protection
 *			op is the operation to perform on each mapping during walk
 *			postop is operation to perform in the phsyent after walk.  this would be
 *				used to set or reset the RC bits.
 *			opmod modifies the action taken on any connected PTEs visited during
 *				the mapping walk.
 *
 *			We return the RC bits from before postop is run.
 *
 *			Note that this is designed to be called from 32-bit mode with a stack.
 *
 *			We disable translation and all interruptions here.  This keeps is
 *			from having to worry about a deadlock due to having anything locked
 *			and needing it to process a fault.
 *
 *			We lock the physent, execute preop, and then walk each mapping in turn. 
 *			If there is a PTE, it is invalidated and the RC merged into the physent.
 *			Then we call the op function.
 *			Then we revalidate the PTE.
 *			Once all all mappings are finished, we save the physent RC and call the 
 *			postop routine.  Then we unlock the physent and return the RC.
 *	
 * 
 */

			.align	5
			.globl	EXT(hw_walk_phys)

LEXT(hw_walk_phys)
			stwu	r1,-(FM_ALIGN((31-24+1)*4)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r24,FM_ARG0+0x00(r1)		; Save a register
			stw		r25,FM_ARG0+0x04(r1)		; Save a register
			stw		r26,FM_ARG0+0x08(r1)		; Save a register
			stw		r27,FM_ARG0+0x0C(r1)		; Save a register
			mr		r24,r8						; Save the parm
			mr		r25,r7						; Save the parm
			stw		r28,FM_ARG0+0x10(r1)		; Save a register
			stw		r29,FM_ARG0+0x14(r1)		; Save a register
			stw		r30,FM_ARG0+0x18(r1)		; Save a register
			stw		r31,FM_ARG0+0x1C(r1)		; Save a register
			stw		r0,(FM_ALIGN((31-24+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit
			
			mfsprg	r26,0						; (INSTRUMENTATION)
			lwz		r27,hwWalkPhys(r26)			; (INSTRUMENTATION)
			addi	r27,r27,1					; (INSTRUMENTATION)
			stw		r27,hwWalkPhys(r26)			; (INSTRUMENTATION)
			la		r26,hwWalkFull(r26)			; (INSTRUMENTATION)
			slwi	r12,r24,2					; (INSTRUMENTATION)
			lwzx	r27,r26,r12					; (INSTRUMENTATION)
			addi	r27,r27,1					; (INSTRUMENTATION)
			stwx	r27,r26,r12					; (INSTRUMENTATION)
		
			mr		r26,r11						; Save the old MSR
			lis		r27,hi16(hwpOpBase)			; Get high order of op base
			slwi	r4,r4,7						; Convert preop to displacement
			ori		r27,r27,lo16(hwpOpBase)		; Get low order of op base
			slwi	r5,r5,7						; Convert op to displacement
			add		r12,r4,r27					; Point to the preop routine
			slwi	r28,r6,7					; Convert postop to displacement
			mtctr	r12							; Set preop routine	
			add		r28,r28,r27					; Get the address of the postop routine
			add		r27,r5,r27					; Get the address of the op routine			

			bl		mapPhysLock					; Lock the physent

			mr		r29,r3						; Save the physent address
			
			bt++	pf64Bitb,hwp64				; skip if 64-bit (only they take the hint)
			
			bctrl								; Call preop routine
			bne-	hwpEarly32					; preop says to bail now...

			cmplwi	r24,hwpMergePTE				; Classify operation modifier			
 			mtctr	r27							; Set up the op function address
			lwz		r31,ppLink+4(r3)			; Grab the pointer to the first mapping
			blt		hwpSrc32					; Do TLB invalidate/purge/merge/reload for each mapping
			beq		hwpMSrc32					; Do TLB merge for each mapping
			
hwpQSrc32:	rlwinm.	r31,r31,0,~ppFlags			; Clean and test mapping address
			beq		hwpNone32					; Did not find one...
			
			bctrl								; Call the op function
			
			bne-	hwpEarly32					; op says to bail now...
			lwz		r31,mpAlias+4(r31)			; Chain on to the next
			b		hwpQSrc32					; Check it out...

			.align	5			
hwpMSrc32:	rlwinm.	r31,r31,0,~ppFlags			; Clean and test mapping address
			beq		hwpNone32					; Did not find one...
			
			bl		mapMergeRC32				; Merge reference and change into mapping and physent
			bctrl								; Call the op function
			
			bne-	hwpEarly32					; op says to bail now...
			lwz		r31,mpAlias+4(r31)			; Chain on to the next
			b		hwpMSrc32					; Check it out...

			.align	5			
hwpSrc32:	rlwinm.	r31,r31,0,~ppFlags			; Clean and test mapping address
			beq		hwpNone32					; Did not find one...
						
;
;			Note: mapInvPte32 returns the PTE in R3 (or 0 if none), PTE high in R4, 
;			PTE low in R5.  The PCA address is in R7.  The PTEG come back locked.
;			If there is no PTE, PTE low is obtained from mapping
;
			bl		mapInvPte32					; Invalidate and lock PTE, also merge into physent
		
			bctrl								; Call the op function

			crmove	cr1_eq,cr0_eq				; Save the return code
						
			mr.		r3,r3						; Was there a previously valid PTE?
			beq-	hwpNxt32					; Nope...
			
			stw		r5,4(r3)					; Store second half of PTE
			eieio								; Make sure we do not reorder
			stw		r4,0(r3)					; Revalidate the PTE
			
			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock the PCA
			
hwpNxt32:	bne-	cr1,hwpEarly32				; op says to bail now...
			lwz		r31,mpAlias+4(r31)			; Chain on to the next
			b		hwpSrc32					; Check it out...

			.align	5

hwpNone32:	mtctr	r28							; Get the post routine address
			
			lwz		r30,ppLink+4(r29)			; Save the old RC
			mr		r3,r29						; Get the physent address
			bctrl								; Call post routine

			bl		mapPhysUnlock				; Unlock the physent
			
			mtmsr	r26							; Restore translation/mode/etc.
			isync
			
			b		hwpReturn					; Go restore registers and return...

			.align	5

hwpEarly32:	lwz		r30,ppLink+4(r29)			; Save the old RC
			mr		r3,r29						; Get the physent address
			bl		mapPhysUnlock				; Unlock the physent
			
			mtmsr	r26							; Restore translation/mode/etc.
			isync
			
			b		hwpReturn					; Go restore registers and return...

			.align	5
		
hwp64:		bctrl								; Call preop routine
			bne--	hwpEarly64					; preop says to bail now...
			
			cmplwi	r24,hwpMergePTE				; Classify operation modifier			
 			mtctr	r27							; Set up the op function address
			
			li		r24,ppLFAmask
			ld		r31,ppLink(r3)				; Get the pointer to the first mapping
			rotrdi	r24,r24,ppLFArrot			; Rotate clean up mask to get 0xF0000000000000000F
			blt		hwpSrc64					; Do TLB invalidate/purge/merge/reload for each mapping
			beq		hwpMSrc64					; Do TLB merge for each mapping
			
hwpQSrc64:	andc.	r31,r31,r24					; Clean and test mapping address
			beq		hwpNone64					; Did not find one...

			bctrl								; Call the op function

			bne--	hwpEarly64					; op says to bail now...
			ld		r31,mpAlias(r31)			; Chain on to the next
			b		hwpQSrc64					; Check it out...

			.align	5			
hwpMSrc64:	andc.	r31,r31,r24					; Clean and test mapping address
			beq		hwpNone64					; Did not find one...

			bl		mapMergeRC64				; Merge reference and change into mapping and physent
			bctrl								; Call the op function

			bne--	hwpEarly64					; op says to bail now...
			ld		r31,mpAlias(r31)			; Chain on to the next
			b		hwpMSrc64					; Check it out...

			.align	5			
hwpSrc64:	andc.	r31,r31,r24					; Clean and test mapping address
			beq		hwpNone64					; Did not find one...
;
;			Note: mapInvPte64 returns the PTE in R3 (or 0 if none), PTE high in R4, 
;			PTE low in R5. PTEG comes back locked if there is one
;
			bl		mapInvPte64					; Invalidate and lock PTEG, also merge into physent

			bctrl								; Call the op function

			crmove	cr1_eq,cr0_eq				; Save the return code
			
			mr.		r3,r3						; Was there a previously valid PTE?
			beq--	hwpNxt64					; Nope...
			
			std		r5,8(r3)					; Save bottom of PTE
			eieio								; Make sure we do not reorder 
			std		r4,0(r3)					; Revalidate the PTE
			
			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock the PCA

hwpNxt64:	bne--	cr1,hwpEarly64				; op says to bail now...
			ld		r31,mpAlias(r31)			; Chain on to the next
			b		hwpSrc64					; Check it out...
	
			.align	5
			
hwpNone64:	mtctr	r28							; Get the post routine address
			
			lwz		r30,ppLink+4(r29)			; Save the old RC
			mr		r3,r29						; Get the physent address
			bctrl								; Call post routine

			bl		mapPhysUnlock				; Unlock the physent
			
			mtmsrd	r26							; Restore translation/mode/etc.
			isync
			b		hwpReturn					; Go restore registers and return...

			.align	5

hwpEarly64:	lwz		r30,ppLink+4(r29)			; Save the old RC
			mr		r3,r29						; Get the physent address
			bl		mapPhysUnlock				; Unlock the physent
			
			mtmsrd	r26							; Restore translation/mode/etc.
			isync			

hwpReturn:	lwz		r0,(FM_ALIGN((31-24+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Restore the return
			lwz		r24,FM_ARG0+0x00(r1)		; Restore a register
			lwz		r25,FM_ARG0+0x04(r1)		; Restore a register
			lwz		r26,FM_ARG0+0x08(r1)		; Restore a register
			mr		r3,r30						; Pass back the RC
			lwz		r27,FM_ARG0+0x0C(r1)		; Restore a register
			lwz		r28,FM_ARG0+0x10(r1)		; Restore a register
			mtlr	r0							; Restore the return
			lwz		r29,FM_ARG0+0x14(r1)		; Restore a register
			lwz		r30,FM_ARG0+0x18(r1)		; Restore a register
			lwz		r31,FM_ARG0+0x1C(r1)		; Restore a register
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...


;
;			The preop/op/postop function table.
;			Each function must be 64-byte aligned and be no more than
;			16 instructions.  If more than 16, we must fix address calculations
;			at the start of hwpOpBase
;
;			The routine must set CR0_EQ in order to continue scan.
;			If CR0_EQ is not set, an early return from the function is made.
;

			.align	7
			
hwpOpBase:

;			Function 0 - No operation

hwpNoop:	cmplw	r0,r0						; Make sure CR0_EQ is set
			blr									; Just return...

			.align	5

;			This is the continuation of function 4 - Set attributes in mapping

;			We changed the attributes of a mapped page.  Make sure there are no cache paradoxes.
;			NOTE: Do we have to deal with i-cache here?

hwpSAM:		li		r11,4096					; Get page size
			
hwpSAMinvd:	sub.	r11,r11,r9					; Back off a line
			dcbf	r11,r5						; Flush the line in the data cache
			bgt++	hwpSAMinvd					; Go do the rest of it...
			
			sync								; Make sure it is done

			li		r11,4096					; Get page size
			
hwpSAMinvi:	sub.	r11,r11,r9					; Back off a line
			icbi	r11,r5						; Flush the line in the icache
			bgt++	hwpSAMinvi					; Go do the rest of it...
			
			sync								; Make sure it is done

			cmpw	r0,r0						; Make sure we return CR0_EQ
			blr									; Return...


;			Function 1 - Set protection in physent (obsolete)

			.set	.,hwpOpBase+(1*128)			; Generate error if previous function too long

hwpSPrtPhy: cmplw	r0,r0						; Make sure we return CR0_EQ
			blr									; Return...
			

;			Function 2 - Set protection in mapping

			.set	.,hwpOpBase+(2*128)			; Generate error if previous function too long

hwpSPrtMap:	lwz		r9,mpFlags(r31)				; Get the mapping flags
			lwz		r8,mpVAddr+4(r31)			; Get the protection part of mapping
			rlwinm.	r9,r9,0,mpPermb,mpPermb		; Is the mapping permanent?
			li		r0,lo16(mpN|mpPP)			; Get no-execute and protection bits
			crnot	cr0_eq,cr0_eq				; Change CR0_EQ to true if mapping is permanent
			rlwinm	r2,r25,0,mpNb-32,mpPPe-32	; Isolate new no-execute and protection bits 
			beqlr--								; Leave if permanent mapping (before we trash R5)...
			andc	r5,r5,r0					; Clear the old no-execute and prot bits
			or		r5,r5,r2					; Move in the new no-execute and prot bits
			rlwimi	r8,r5,0,20,31				; Copy into the mapping copy
			cmpw	r0,r0						; Make sure we return CR0_EQ
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			blr									; Leave...
			
;			Function 3 - Set attributes in physent

			.set	.,hwpOpBase+(3*128)			; Generate error if previous function too long

hwpSAtrPhy:	li		r5,ppLink					; Get offset for flag part of physent

hwpSAtrPhX:	lwarx	r4,r5,r29					; Get the old flags
			rlwimi	r4,r25,0,ppIb,ppGb			; Stick in the new attributes
			stwcx.	r4,r5,r29					; Try to stuff it
			bne--	hwpSAtrPhX					; Try again...
;			Note: CR0_EQ is set because of stwcx.
			blr									; Return...
			
;			Function 4 - Set attributes in mapping

			.set	.,hwpOpBase+(4*128)			; Generate error if previous function too long

hwpSAtrMap:	lwz		r9,mpFlags(r31)				; Get the mapping flags
			lwz		r8,mpVAddr+4(r31)			; Get the attribute part of mapping
			li		r2,mpM						; Force on coherent
			rlwinm.	r9,r9,0,mpPermb,mpPermb		; Is the mapping permanent?
			li		r0,lo16(mpWIMG)				; Get wimg mask		
			crnot	cr0_eq,cr0_eq				; Change CR0_EQ to true if mapping is permanent
			rlwimi	r2,r25,32-(mpIb-32-ppIb),mpIb-32,mpIb-32
												; Copy in the cache inhibited bit
			beqlr--								; Leave if permanent mapping (before we trash R5)...
			andc	r5,r5,r0					; Clear the old wimg
			rlwimi	r2,r25,32-(mpGb-32-ppGb),mpGb-32,mpGb-32
												; Copy in the guarded bit
			mfsprg	r9,2						; Feature flags
			or		r5,r5,r2					; Move in the new wimg
			rlwimi	r8,r5,0,20,31				; Copy into the mapping copy
			lwz		r2,mpPAddr(r31)				; Get the physical address
			li		r0,0xFFF					; Start a mask
			andi.	r9,r9,pf32Byte+pf128Byte	; Get cache line size
			rlwinm	r5,r0,0,1,0					; Copy to top half
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			rlwinm	r2,r2,12,1,0				; Copy to top and rotate to make physical address with junk left
			and		r5,r5,r2					; Clean stuff in top 32 bits
			andc	r2,r2,r0					; Clean bottom too
			rlwimi	r5,r2,0,0,31				; Insert low 23 to make full physical address
			b		hwpSAM						; Join common
			
;			NOTE: we moved the remainder of the code out of here because it
;			did not fit in the 128 bytes allotted.  It got stuck into the free space
;			at the end of the no-op function.



			
;			Function 5 - Clear reference in physent

			.set	.,hwpOpBase+(5*128)			; Generate error if previous function too long

hwpCRefPhy:	li		r5,ppLink+4					; Get offset for flag part of physent

hwpCRefPhX:	lwarx	r4,r5,r29					; Get the old flags
			rlwinm	r4,r4,0,ppRb+1-32,ppRb-1-32	; Clear R
			stwcx.	r4,r5,r29					; Try to stuff it
			bne--	hwpCRefPhX					; Try again...
;			Note: CR0_EQ is set because of stwcx.
			blr									; Return...

			
;			Function 6 - Clear reference in mapping 

			.set	.,hwpOpBase+(6*128)			; Generate error if previous function too long

hwpCRefMap:	li		r0,lo16(mpR)				; Get reference bit
			lwz		r8,mpVAddr+4(r31)			; Get the flag part of mapping
			andc	r5,r5,r0					; Clear in PTE copy
			andc	r8,r8,r0					; and in the mapping
			cmpw	r0,r0						; Make sure we return CR0_EQ
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			blr									; Return...

			
;			Function 7 - Clear change in physent

			.set	.,hwpOpBase+(7*128)			; Generate error if previous function too long

hwpCCngPhy:	li		r5,ppLink+4					; Get offset for flag part of physent

hwpCCngPhX:	lwarx	r4,r5,r29					; Get the old flags
			rlwinm	r4,r4,0,ppCb+1-32,ppCb-1-32	; Clear C
			stwcx.	r4,r5,r29					; Try to stuff it
			bne--	hwpCCngPhX					; Try again...
;			Note: CR0_EQ is set because of stwcx.
			blr									; Return...
			
			
;			Function 8 - Clear change in mapping

			.set	.,hwpOpBase+(8*128)			; Generate error if previous function too long

hwpCCngMap:	li		r0,lo16(mpC)				; Get change bit
			lwz		r8,mpVAddr+4(r31)			; Get the flag part of mapping
			andc	r5,r5,r0					; Clear in PTE copy
			andc	r8,r8,r0					; and in the mapping
			cmpw	r0,r0						; Make sure we return CR0_EQ
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			blr									; Return...

			
;			Function 9 - Set reference in physent

			.set	.,hwpOpBase+(9*128)			; Generate error if previous function too long

hwpSRefPhy:	li		r5,ppLink+4					; Get offset for flag part of physent

hwpSRefPhX:	lwarx	r4,r5,r29					; Get the old flags
			ori		r4,r4,lo16(ppR)				; Set the reference
			stwcx.	r4,r5,r29					; Try to stuff it
			bne--	hwpSRefPhX					; Try again...
;			Note: CR0_EQ is set because of stwcx.
			blr									; Return...

			
;			Function 10 - Set reference in mapping

			.set	.,hwpOpBase+(10*128)		; Generate error if previous function too long

hwpSRefMap:	lwz		r8,mpVAddr+4(r31)			; Get the flag part of mapping
			ori		r8,r8,lo16(mpR)				; Set reference in mapping
			cmpw	r0,r0						; Make sure we return CR0_EQ
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			blr									; Return...
			
;			Function 11 - Set change in physent

			.set	.,hwpOpBase+(11*128)		; Generate error if previous function too long

hwpSCngPhy:	li		r5,ppLink+4					; Get offset for flag part of physent

hwpSCngPhX:	lwarx	r4,r5,r29					; Get the old flags
			ori		r4,r4,lo16(ppC)				; Set the change bit
			stwcx.	r4,r5,r29					; Try to stuff it
			bne--	hwpSCngPhX					; Try again...
;			Note: CR0_EQ is set because of stwcx.
			blr									; Return...
			
;			Function 12 - Set change in mapping

			.set	.,hwpOpBase+(12*128)		; Generate error if previous function too long

hwpSCngMap:	lwz		r8,mpVAddr+4(r31)			; Get the flag part of mapping
			ori		r8,r8,lo16(mpC)				; Set chage in mapping
			cmpw	r0,r0						; Make sure we return CR0_EQ
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			blr									; Return...

;			Function 13 - Test reference in physent

			.set	.,hwpOpBase+(13*128)		; Generate error if previous function too long
			
hwpTRefPhy:	lwz		r0,ppLink+4(r29)			; Get the flags from physent	
			rlwinm.	r0,r0,0,ppRb-32,ppRb-32		; Isolate reference bit and see if 0
			blr									; Return (CR0_EQ set to continue if reference is off)...


;			Function 14 - Test reference in mapping

			.set	.,hwpOpBase+(14*128)		; Generate error if previous function too long
			
hwpTRefMap:	rlwinm.	r0,r5,0,mpRb-32,mpRb-32		; Isolate reference bit and see if 0
			blr									; Return (CR0_EQ set to continue if reference is off)...


;			Function 15 - Test change in physent

			.set	.,hwpOpBase+(15*128)		; Generate error if previous function too long
			
hwpTCngPhy:	lwz		r0,ppLink+4(r29)			; Get the flags from physent	
			rlwinm.	r0,r0,0,ppCb-32,ppCb-32		; Isolate change bit and see if 0
			blr									; Return (CR0_EQ set to continue if change is off)...


;			Function 16 - Test change in mapping

			.set	.,hwpOpBase+(16*128)		; Generate error if previous function too long
			
hwpTCngMap:	rlwinm.	r0,r5,0,mpCb-32,mpCb-32		; Isolate change bit and see if 0
			blr									; Return (CR0_EQ set to continue if change is off)...


;			Function 17 - Test reference and change in physent

			.set	.,hwpOpBase+(17*128)		; Generate error if previous function too long

hwpTRefCngPhy:			
			lwz		r0,ppLink+4(r29)			; Get the flags from physent	
			rlwinm	r0,r0,0,ppRb-32,ppCb-32		; Isolate reference and change bits
			cmplwi	r0,lo16(ppR|ppC)			; cr0_eq <- ((R == 1) && (C == 1))
			crnot	cr0_eq,cr0_eq				; cr0_eq <- ((R == 0) || (C == 0))
			blr									; Return (CR0_EQ set to continue if either R or C is off)...


;			Function 18 - Test reference and change in mapping

			.set	.,hwpOpBase+(18*128)		; Generate error if previous function too long
hwpTRefCngMap:
			rlwinm	r0,r5,0,mpRb-32,mpCb-32		; Isolate reference and change bits from mapping
			cmplwi	r0,lo16(mpR|mpC)			; cr0_eq <- ((R == 1) && (C == 1))
			crnot	cr0_eq,cr0_eq				; cr0_eq <- ((R == 0) || (C == 0))
			blr									; Return (CR0_EQ set to continue if either R or C is off)...


;			Function 19 - Clear reference and change in physent

			.set	.,hwpOpBase+(19*128)		; Generate error if previous function too long
hwpCRefCngPhy:
			li		r5,ppLink+4					; Get offset for flag part of physent

hwpCRefCngPhX:
			lwarx	r4,r5,r29					; Get the old flags
			andc	r4,r4,r25					; Clear R and C as specified by mask
			stwcx.	r4,r5,r29					; Try to stuff it
			bne--	hwpCRefCngPhX				; Try again...
;			Note: CR0_EQ is set because of stwcx.
			blr									; Return...


;			Function 20 - Clear reference and change in mapping

			.set	.,hwpOpBase+(20*128)		; Generate error if previous function too long
hwpCRefCngMap:
			srwi	r0,r25,(ppRb - mpRb)		; Align reference/change clear mask (phys->map)
			lwz		r8,mpVAddr+4(r31)			; Get the flag part of mapping
			andc	r5,r5,r0					; Clear in PTE copy
			andc	r8,r8,r0					; and in the mapping
			cmpw	r0,r0						; Make sure we return CR0_EQ
			stw		r8,mpVAddr+4(r31)			; Set the flag part of mapping
			blr									; Return...


			.set	.,hwpOpBase+(21*128)		; Generate error if previous function too long

;
;			unsigned int hw_protect(pmap, va, prot, *nextva) - Changes protection on a specific mapping.
;			
;			Returns:
;				mapRtOK     - if all is ok
;				mapRtBadLk  - if mapping lock fails
;				mapRtPerm   - if mapping is permanent
;				mapRtNotFnd - if mapping is not found
;				mapRtBlock  - if mapping is a block
;
			.align	5
			.globl	EXT(hw_protect)

LEXT(hw_protect)
 			stwu	r1,-(FM_ALIGN((31-24+1)*4)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r24,FM_ARG0+0x00(r1)		; Save a register
			stw		r25,FM_ARG0+0x04(r1)		; Save a register
			mr		r25,r7						; Remember address of next va
			stw		r26,FM_ARG0+0x08(r1)		; Save a register
			stw		r27,FM_ARG0+0x0C(r1)		; Save a register
			stw		r28,FM_ARG0+0x10(r1)		; Save a register
			mr		r24,r6						; Save the new protection flags
			stw		r29,FM_ARG0+0x14(r1)		; Save a register
			stw		r30,FM_ARG0+0x18(r1)		; Save a register
			stw		r31,FM_ARG0+0x1C(r1)		; Save a register
			stw		r0,(FM_ALIGN((31-24+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r3)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active? 
			bne		hpPanic						; Call not valid for guest shadow assist pmap
#endif
			
			lwz		r6,pmapvr(r3)				; Get the first part of the VR translation for pmap
			lwz		r7,pmapvr+4(r3)				; Get the second part


			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			mr		r27,r11						; Remember the old MSR
			mr		r26,r12						; Remember the feature bits

			xor		r28,r3,r7					; Change the common 32- and 64-bit half

			bf--	pf64Bitb,hpSF1				; skip if 32-bit...
			
			rldimi	r28,r6,32,0					; Shift the fixed upper part of the physical over and cram in top

hpSF1:		mr		r29,r4						; Save top half of vaddr
			mr		r30,r5						; Save the bottom half
						
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne--	hpBadLock					; Nope...

			mr		r3,r28						; get the pmap address
			mr		r4,r29						; Get bits 0:31 to look for
			mr		r5,r30						; Get bits 32:64
			
			bl		EXT(mapSearch)				; Go see if we can find it (note: R7 comes back with mpFlags)

			rlwinm.	r0,r7,0,mpType				; Is this a normal mapping?
			crmove	cr1_eq,cr0_eq				; cr1_eq <- this is a normal mapping
			andi.	r0,r7,mpPerm|mpRIP			; Is it permanent or being removed?
			cror	cr1_eq,cr0_eq,cr1_eq        ; cr1_eq <- normal mapping and not permanent and not being removed
			mr.		r31,r3						; Save the mapping if we found it
			mr		r29,r4						; Save next va high half
			mr		r30,r5						; Save next va low half
			
			beq--	hpNotFound					; Not found...

			bf--	cr1_eq,hpNotAllowed			; Something special is happening...
			
			bt++	pf64Bitb,hpDo64				; Split for 64 bit
			
			bl		mapInvPte32					; Invalidate and lock PTEG, also merge into physent
						
			rlwimi	r5,r24,0,mpPPb-32,mpPPe-32	; Stick in the new pp (note that we ignore no-execute for 32-bit)
			mr.		r3,r3						; Was there a previously valid PTE?

			stb		r5,mpVAddr+7(r31)			; Set the new pp field (do not muck with the rest)			

			beq--	hpNoOld32					; Nope...
			
			stw		r5,4(r3)					; Store second half of PTE
			eieio								; Make sure we do not reorder
			stw		r4,0(r3)					; Revalidate the PTE

			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock PCA
		
hpNoOld32:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			li		r3,mapRtOK					; Set normal return		
			b		hpR32						; Join common...

			.align	5			
			
			
hpDo64:		bl		mapInvPte64					; Invalidate and lock PTEG, also merge into physent
						
			rldimi	r5,r24,0,mpNb				; Stick in the new no-exectue and pp bits
			mr.		r3,r3						; Was there a previously valid PTE?

			stb		r5,mpVAddr+7(r31)			; Set the new pp field (do not muck with the rest)			

			beq--	hpNoOld64					; Nope...
			
			std		r5,8(r3)					; Store second half of PTE
			eieio								; Make sure we do not reorder
			std		r4,0(r3)					; Revalidate the PTE

			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock PCA

hpNoOld64:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			li		r3,mapRtOK					; Set normal return		
			b		hpR64						; Join common...

			.align	5							
						
hpReturn:	bt++	pf64Bitb,hpR64				; Yes...

hpR32:		mtmsr	r27							; Restore enables/translation/etc.
			isync
			b		hpReturnC					; Join common...

hpR64:		mtmsrd	r27							; Restore enables/translation/etc.
			isync								
			
hpReturnC:	stw		r29,0(r25)					; Save the top of the next va
			stw		r30,4(r25)					; Save the bottom of the next va
			lwz		r0,(FM_ALIGN((31-24+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return
			lwz		r24,FM_ARG0+0x00(r1)		; Save a register
			lwz		r25,FM_ARG0+0x04(r1)		; Save a register
			lwz		r26,FM_ARG0+0x08(r1)		; Save a register
			mtlr	r0							; Restore the return
			lwz		r27,FM_ARG0+0x0C(r1)		; Save a register
			lwz		r28,FM_ARG0+0x10(r1)		; Save a register
			lwz		r29,FM_ARG0+0x14(r1)		; Save a register
			lwz		r30,FM_ARG0+0x18(r1)		; Save a register
			lwz		r31,FM_ARG0+0x1C(r1)		; Save a register
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...
			
			.align	5
			
hpBadLock:	li		r3,mapRtBadLk				; Set lock time out error code
			b		hpReturn					; Leave....
			
hpNotFound:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			
			li		r3,mapRtNotFnd				; Set that we did not find the requested page
			b		hpReturn					; Leave....
			
hpNotAllowed:	
			rlwinm.	r0,r7,0,mpRIPb,mpRIPb		; Is it actually being removed?
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bne--	hpNotFound					; Yeah...
			bl		sxlkUnlock					; Unlock the search list
			
			li		r3,mapRtBlock				; Assume it was a block
			rlwinm	r0,r7,0,mpType				; Isolate mapping type
			cmplwi	r0,mpBlock					; Is this a block mapping?
			beq++	hpReturn					; Yes, leave...
			
			li		r3,mapRtPerm				; Set that we hit a permanent page
			b		hpReturn					; Leave....

hpPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc
			

;
;			int hw_test_rc(pmap, va, reset) - tests RC on a specific va
;			
;			Returns following code ORed with RC from mapping
;				mapRtOK     - if all is ok
;				mapRtBadLk  - if mapping lock fails
;				mapRtNotFnd - if mapping is not found
;
			.align	5
			.globl	EXT(hw_test_rc)

LEXT(hw_test_rc)
 			stwu	r1,-(FM_ALIGN((31-24+1)*4)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stw		r24,FM_ARG0+0x00(r1)		; Save a register
			stw		r25,FM_ARG0+0x04(r1)		; Save a register
			stw		r26,FM_ARG0+0x08(r1)		; Save a register
			stw		r27,FM_ARG0+0x0C(r1)		; Save a register
			stw		r28,FM_ARG0+0x10(r1)		; Save a register
			mr		r24,r6						; Save the reset request
			stw		r29,FM_ARG0+0x14(r1)		; Save a register
			stw		r30,FM_ARG0+0x18(r1)		; Save a register
			stw		r31,FM_ARG0+0x1C(r1)		; Save a register
			stw		r0,(FM_ALIGN((31-24+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

#if DEBUG
			lwz		r11,pmapFlags(r3)			; Get pmaps flags
			rlwinm.	r11,r11,0,pmapVMgsaa		; Is guest shadow assist active? 
			bne		htrPanic					; Call not valid for guest shadow assist pmap
#endif
			
			lwz		r6,pmapvr(r3)				; Get the first part of the VR translation for pmap
			lwz		r7,pmapvr+4(r3)				; Get the second part


			bl		EXT(mapSetUp)				; Turn off interrupts, translation, and possibly enter 64-bit

			mr		r27,r11						; Remember the old MSR
			mr		r26,r12						; Remember the feature bits

			xor		r28,r3,r7					; Change the common 32- and 64-bit half

			bf--	pf64Bitb,htrSF1				; skip if 32-bit...
			
			rldimi	r28,r6,32,0					; Shift the fixed upper part of the physical over and cram in top

htrSF1:		mr		r29,r4						; Save top half of vaddr
			mr		r30,r5						; Save the bottom half
						
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			li		r25,0						; Clear RC
			bne--	htrBadLock					; Nope...

			mr		r3,r28						; get the pmap address
			mr		r4,r29						; Get bits 0:31 to look for
			mr		r5,r30						; Get bits 32:64
			
			bl		EXT(mapSearch)				; Go see if we can find it (R7 comes back with mpFlags)

			rlwinm.	r0,r7,0,mpType				; Is this a normal mapping?
			crmove	cr1_eq,cr0_eq				; cr1_eq <- this is a normal mapping
			andi.	r0,r7,mpPerm|mpRIP			; Is it permanent or being removed?
			crand	cr1_eq,cr0_eq,cr1_eq        ; cr1_eq <- normal mapping and not permanent and not being removed
			mr.		r31,r3						; Save the mapping if we found it
			crandc	cr1_eq,cr1_eq,cr0_eq		; cr1_eq <- found & normal & not permanent & not being removed
			
			bf--	cr1_eq,htrNotFound			; Not found, something special, or being removed...
			
			bt++	pf64Bitb,htrDo64			; Split for 64 bit
			
			bl		mapInvPte32					; Invalidate and lock PTEG, also merge into physent
						
			cmplwi	cr1,r24,0					; Do we want to clear RC?
			lwz		r12,mpVAddr+4(r31)			; Get the bottom of the mapping vaddr field
			mr.		r3,r3						; Was there a previously valid PTE?
			li		r0,lo16(mpR|mpC)			; Get bits to clear

			and		r25,r5,r0					; Save the RC bits
			beq++	cr1,htrNoClr32				; Nope...
			
			andc	r12,r12,r0					; Clear mapping copy of RC
			andc	r5,r5,r0					; Clear PTE copy of RC
			sth		r12,mpVAddr+6(r31)			; Set the new RC			

htrNoClr32:	beq--	htrNoOld32					; No previously valid PTE...
			
			sth		r5,6(r3)					; Store updated RC
			eieio								; Make sure we do not reorder
			stw		r4,0(r3)					; Revalidate the PTE

			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock PCA

htrNoOld32:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			li		r3,mapRtOK					; Set normal return		
			b		htrR32						; Join common...

			.align	5			
			
			
htrDo64:	bl		mapInvPte64					; Invalidate and lock PTEG, also merge into physent
						
			cmplwi	cr1,r24,0					; Do we want to clear RC?
			lwz		r12,mpVAddr+4(r31)			; Get the bottom of the mapping vaddr field
			mr.		r3,r3						; Was there a previously valid PTE?
			li		r0,lo16(mpR|mpC)			; Get bits to clear

			and		r25,r5,r0					; Save the RC bits
			beq++	cr1,htrNoClr64				; Nope...
			
			andc	r12,r12,r0					; Clear mapping copy of RC
			andc	r5,r5,r0					; Clear PTE copy of RC
			sth		r12,mpVAddr+6(r31)			; Set the new RC			

htrNoClr64:	beq--	htrNoOld64					; Nope, no pevious pte...
			
			sth		r5,14(r3)					; Store updated RC
			eieio								; Make sure we do not reorder
			std		r4,0(r3)					; Revalidate the PTE

			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock PCA

htrNoOld64:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			li		r3,mapRtOK					; Set normal return		
			b		htrR64						; Join common...

			.align	5							
						
htrReturn:	bt++	pf64Bitb,htrR64				; Yes...

htrR32:		mtmsr	r27							; Restore enables/translation/etc.
			isync
			b		htrReturnC					; Join common...

htrR64:		mtmsrd	r27							; Restore enables/translation/etc.
			isync								
			
htrReturnC:	lwz		r0,(FM_ALIGN((31-24+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return
			or		r3,r3,r25					; Send the RC bits back
			lwz		r24,FM_ARG0+0x00(r1)		; Save a register
			lwz		r25,FM_ARG0+0x04(r1)		; Save a register
			lwz		r26,FM_ARG0+0x08(r1)		; Save a register
			mtlr	r0							; Restore the return
			lwz		r27,FM_ARG0+0x0C(r1)		; Save a register
			lwz		r28,FM_ARG0+0x10(r1)		; Save a register
			lwz		r29,FM_ARG0+0x14(r1)		; Save a register
			lwz		r30,FM_ARG0+0x18(r1)		; Save a register
			lwz		r31,FM_ARG0+0x1C(r1)		; Save a register
			lwz		r1,0(r1)					; Pop the stack
			blr									; Leave...
			
			.align	5
			
htrBadLock:	li		r3,mapRtBadLk				; Set lock time out error code
			b		htrReturn					; Leave....
			
htrNotFound:	
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			
			li		r3,mapRtNotFnd				; Set that we did not find the requested page
			b		htrReturn					; Leave....

htrPanic:	lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show that we failed some kind of mapping thing
			sc
			

;
;
;			mapFindLockPN - find and lock physent for a given page number
;
;
			.align	5
mapFindLockPN:
			lis		r9,hi16(EXT(pmap_mem_regions))		; Point to the start of the region table
			mr		r2,r3						; Save our target
			ori		r9,r9,lo16(EXT(pmap_mem_regions))	; Point to the start of the region table			

mapFLPNitr:	lwz		r3,mrPhysTab(r9)			; Get the actual table address
			lwz		r5,mrStart(r9)				; Get start of table entry
			lwz		r0,mrEnd(r9)				; Get end of table entry
			addi	r9,r9,mrSize				; Point to the next slot
			cmplwi	cr7,r3,0					; Are we at the end of the table?
			cmplw	r2,r5						; See if we are in this table
			cmplw	cr1,r2,r0					; Check end also
			sub		r4,r2,r5					; Calculate index to physical entry
			beq--	cr7,mapFLPNmiss				; Leave if we did not find an entry...
			cror	cr0_lt,cr0_lt,cr1_gt		; Set CR0_LT if it is NOT this entry
			slwi	r4,r4,3						; Get offset to physical entry

			blt--	mapFLPNitr					; Did not find it...
			
			add		r3,r3,r4					; Point right to the slot
			b		mapPhysLock					; Join common lock code

mapFLPNmiss:
			li		r3,0						; Show that we did not find it
			blr									; Leave...			
			

;
;			mapPhysFindLock - find physent list and lock it
;			R31 points to mapping
;
			.align	5
			
mapPhysFindLock:	
			lbz		r4,mpFlags+1(r31)			; Get the index into the physent bank table
			lis		r3,ha16(EXT(pmap_mem_regions))	; Get high order of physent table (note use of ha16 to get value appropriate for an addi of low part)
			rlwinm	r4,r4,2,24,29				; Mask index bits and convert to byte offset
			addi	r4,r4,lo16(EXT(pmap_mem_regions))	; Get low part of address of entry
			add		r3,r3,r4					; Point to table entry
			lwz		r5,mpPAddr(r31)				; Get physical page number
			lwz		r7,mrStart(r3)				; Get the start of range
			lwz		r3,mrPhysTab(r3)			; Get the start of the entries for this bank
			sub		r6,r5,r7					; Get index to physent
			rlwinm	r6,r6,3,0,28				; Get offset to physent
			add		r3,r3,r6					; Point right to the physent
			b		mapPhysLock					; Join in the lock...

;
;			mapPhysLock - lock a physent list
;			R3 contains list header
;
			.align	5

mapPhysLockS:
			li		r2,lgKillResv				; Get a spot to kill reservation
			stwcx.	r2,0,r2						; Kill it...
			
mapPhysLockT:
			lwz		r2,ppLink(r3)				; Get physent chain header
			rlwinm.	r2,r2,0,0,0					; Is lock clear?
			bne--	mapPhysLockT				; Nope, still locked...
			
mapPhysLock:	
			lwarx	r2,0,r3						; Get the lock
			rlwinm.	r0,r2,0,0,0					; Is it locked?
			oris	r0,r2,0x8000				; Set the lock bit
			bne--	mapPhysLockS				; It is locked, spin on it...
			stwcx.	r0,0,r3						; Try to stuff it back...
			bne--	mapPhysLock					; Collision, try again...
			isync								; Clear any speculations
			blr									; Leave...
			

;
;			mapPhysUnlock - unlock a physent list
;			R3 contains list header
;
			.align	5
			
mapPhysUnlock:	
			lwz		r0,ppLink(r3)				; Get physent chain header
			rlwinm	r0,r0,0,1,31				; Clear the lock bit
			eieio								; Make sure unlock comes last
			stw		r0,ppLink(r3)				; Unlock the list
			blr

;
;			mapPhysMerge - merge the RC bits into the master copy
;			R3 points to the physent 
;			R4 contains the RC bits
;
;			Note: we just return if RC is 0
;
			.align	5
			
mapPhysMerge:	
			rlwinm.	r4,r4,PTE1_REFERENCED_BIT+(64-ppRb),ppRb-32,ppCb-32	; Isolate RC bits
			la		r5,ppLink+4(r3)				; Point to the RC field
			beqlr--								; Leave if RC is 0...
			
mapPhysMergeT:
			lwarx	r6,0,r5						; Get the RC part
			or		r6,r6,r4					; Merge in the RC
			stwcx.	r6,0,r5						; Try to stuff it back...
			bne--	mapPhysMergeT				; Collision, try again...
			blr									; Leave...

;
;			Sets the physent link pointer and preserves all flags
;			The list is locked
;			R3 points to physent
;			R4 has link to set
;

			.align	5

mapPhyCSet32:
			la		r5,ppLink+4(r3)				; Point to the link word

mapPhyCSetR:
			lwarx	r2,0,r5						; Get the link and flags
			rlwimi	r4,r2,0,ppFlags				; Insert the flags
			stwcx.	r4,0,r5						; Stick them back
			bne--	mapPhyCSetR					; Someone else did something, try again...
			blr									; Return...

			.align	5

mapPhyCSet64:
			li		r0,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
		
mapPhyCSet64x:
			ldarx	r2,0,r3						; Get the link and flags
			and		r5,r2,r0					; Isolate the flags
			or		r6,r4,r5					; Add them to the link
			stdcx.	r6,0,r3						; Stick them back
			bne--	mapPhyCSet64x				; Someone else did something, try again...
			blr									; Return...						

;
;			mapBumpBusy - increment the busy count on a mapping
;			R3 points to mapping
;

			.align	5

mapBumpBusy:
			lwarx	r4,0,r3						; Get mpBusy
			addis	r4,r4,0x0100				; Bump the busy count
			stwcx.	r4,0,r3						; Save it back
			bne--	mapBumpBusy					; This did not work, try again...
			blr									; Leave...

;
;			mapDropBusy - increment the busy count on a mapping
;			R3 points to mapping
;

			.globl	EXT(mapping_drop_busy)
			.align	5

LEXT(mapping_drop_busy)
mapDropBusy:
			lwarx	r4,0,r3						; Get mpBusy
			addis	r4,r4,0xFF00				; Drop the busy count
			stwcx.	r4,0,r3						; Save it back
			bne--	mapDropBusy					; This did not work, try again...
			blr									; Leave...

;
;			mapDrainBusy - drain the busy count on a mapping
;			R3 points to mapping
;			Note: we already have a busy for ourselves. Only one
;			busy per processor is allowed, so we just spin here
;			waiting for the count to drop to 1.
;			Also, the mapping can not be on any lists when we do this
;			so all we are doing is waiting until it can be released.
;

			.align	5

mapDrainBusy:
			lwz		r4,mpFlags(r3)				; Get mpBusy
			rlwinm	r4,r4,8,24,31				; Clean it up
			cmplwi	r4,1						; Is is just our busy?
			beqlr++								; Yeah, it is clear...
			b		mapDrainBusy				; Try again...


	
;
;			handleDSeg - handle a data segment fault
;			handleISeg - handle an instruction segment fault
;
;			All that we do here is to map these to DSI or ISI and insure
;			that the hash bit is not set.  This forces the fault code
;			to also handle the missing segment.
;
;			At entry R2 contains per_proc, R13 contains savarea pointer,
;			and R11 is the exception code.
;

			.align	5
			.globl	EXT(handleDSeg)

LEXT(handleDSeg)

			li		r11,T_DATA_ACCESS			; Change fault to DSI
			stw		r11,saveexception(r13)		; Change the exception code from seg fault to PTE miss
			b		EXT(handlePF)				; Join common...

			.align	5
			.globl	EXT(handleISeg)

LEXT(handleISeg)

			li		r11,T_INSTRUCTION_ACCESS	; Change fault to ISI
			stw		r11,saveexception(r13)		; Change the exception code from seg fault to PTE miss
			b		EXT(handlePF)				; Join common...


/*
 *			handlePF - handle a page fault interruption
 *
 *			At entry R2 contains per_proc, R13 contains savarea pointer,
 *			and R11 is the exception code.
 *
 *			This first part does a quick check to see if we can handle the fault.
 *			We canot handle any kind of protection exceptions here, so we pass
 *			them up to the next level.
 *
 *			NOTE: In order for a page-fault redrive to work, the translation miss
 *			bit must be set in the DSISR (or SRR1 for IFETCH).  That must occur
 *			before we come here.
 */

			.align	5
			.globl	EXT(handlePF)

LEXT(handlePF)

 			mfsprg	r12,2						; Get feature flags 
			cmplwi	r11,T_INSTRUCTION_ACCESS		; See if this is for the instruction 
			lwz		r8,savesrr1+4(r13)			; Get the MSR to determine mode
			mtcrf	0x02,r12					; move pf64Bit to cr6
			lis		r0,hi16(dsiNoEx|dsiProt|dsiInvMode|dsiAC)	; Get the types that we cannot handle here
			lwz		r18,SAVflags(r13)			; Get the flags
			
			beq--	gotIfetch					; We have an IFETCH here...
			
			lwz		r27,savedsisr(r13)			; Get the DSISR
			lwz		r29,savedar(r13)			; Get the first half of the DAR
			lwz		r30,savedar+4(r13)			; And second half

			b		ckIfProt					; Go check if this is a protection fault...

gotIfetch:	andis.	r27,r8,hi16(dsiValid)		; Clean this up to construct a DSISR value
			lwz		r29,savesrr0(r13)			; Get the first half of the instruction address
			lwz		r30,savesrr0+4(r13)			; And second half
			stw		r27,savedsisr(r13)			; Save the "constructed" DSISR

ckIfProt:	and.	r4,r27,r0					; Is this a non-handlable exception?
			li		r20,64						; Set a limit of 64 nests for sanity check
			bne--	hpfExit						; Yes... (probably not though)
			
;
;			Note: if the RI is on, we are accessing user space from the kernel, therefore we
;			should be loading the user pmap here.
;

			andi.	r0,r8,lo16(MASK(MSR_PR)|MASK(MSR_RI))	; Are we addressing user or kernel space?
			lis		r8,hi16(EXT(kernel_pmap_phys))	; Assume kernel
			mr		r19,r2						; Remember the per_proc
			ori		r8,r8,lo16(EXT(kernel_pmap_phys))	; Assume kernel (bottom of address)
			mr		r23,r30						; Save the low part of faulting address
			beq--	hpfInKern					; Skip if we are in the kernel
			la		r8,ppUserPmap(r19)			; Point to the current user pmap
			
hpfInKern:	mr		r22,r29						; Save the high part of faulting address
			
			bt--	pf64Bitb,hpf64a				; If 64-bit, skip the next bit...

;
;			On 32-bit machines we emulate a segment exception by loading unused SRs with a
;			predefined value that corresponds to no address space.  When we see that value
;			we turn off the PTE miss bit in the DSISR to drive the code later on that will
;			cause the proper SR to be loaded.
;

			lwz		r28,4(r8)					; Pick up the pmap
			rlwinm.	r18,r18,0,SAVredriveb,SAVredriveb	; Was this a redrive?
			mr		r25,r28						; Save the original pmap (in case we nest)
			lwz		r0,pmapFlags(r28)			; Get pmap's flags
			bne		hpfGVtest					; Segs are not ours if so...
			mfsrin	r4,r30						; Get the SR that was used for translation
			cmplwi	r4,invalSpace				; Is this a simulated segment fault?
			bne++	hpfGVtest					; No...
			
			rlwinm	r27,r27,0,dsiMissb+1,dsiMissb-1	; Clear the PTE miss bit in DSISR
			b		hpfGVtest					; Join on up...
			
			.align	5

			nop									; Push hpfNest to a 32-byte boundary
			nop									; Push hpfNest to a 32-byte boundary
			nop									; Push hpfNest to a 32-byte boundary

hpf64a:		ld		r28,0(r8)					; Get the pmap pointer (64-bit)
			mr		r25,r28						; Save the original pmap (in case we nest)
			lwz		r0,pmapFlags(r28)			; Get pmap's flags
			
hpfGVtest:	rlwinm.	r0,r0,0,pmapVMgsaa			; Using guest shadow mapping assist?
			bne		hpfGVxlate					; Yup, do accelerated shadow stuff

;
;			This is where we loop descending nested pmaps
;

hpfNest:	la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			addi	r20,r20,-1					; Count nest try
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne--	hpfBadLock					; Nope...

			mr		r3,r28						; Get the pmap pointer
			mr		r4,r22						; Get top of faulting vaddr
			mr		r5,r23						; Get bottom of faulting vaddr
			bl		EXT(mapSearch)				; Go see if we can find it (R7 gets mpFlags)

			rlwinm	r0,r7,0,mpRIPb,mpRIPb		; Are we removing this one?
			mr.		r31,r3						; Save the mapping if we found it
			cmplwi	cr1,r0,0					; Check for removal
			crorc	cr0_eq,cr0_eq,cr1_eq		; Merge not found and removing
			
			bt--	cr0_eq,hpfNotFound			; Not found or removing...

			rlwinm	r0,r7,0,mpType				; Isolate mapping type
			cmplwi	r0,mpNest					; Are we again nested?
			cmplwi	cr1,r0,mpLinkage			; Are we a linkage type?
			cror	cr0_eq,cr1_eq,cr0_eq		; cr0_eq <- nested or linkage type?
			mr		r26,r7						; Get the flags for this mapping (passed back from search call)
			
			lhz		r21,mpSpace(r31)			; Get the space

			bne++	hpfFoundIt					; No, we found our guy...
			

#if pmapTransSize != 12
#error pmapTrans entry size is not 12 bytes!!!!!!!!!!!! It is pmapTransSize
#endif
			cmplwi	r0,mpLinkage				; Linkage mapping?
			cmplwi	cr1,r20,0					; Too many nestings?
			beq--	hpfSpclNest					; Do we need to do special handling?

hpfCSrch:	lhz		r21,mpSpace(r31)			; Get the space
			lwz		r8,mpNestReloc(r31)			; Get the vaddr relocation
			lwz		r9,mpNestReloc+4(r31)		; Get the vaddr relocation bottom half
			la		r3,pmapSXlk(r28)			; Point to the old pmap search lock
			lis		r0,0x8000					; Get 0xFFFFFFFF80000000
			lis		r10,hi16(EXT(pmapTrans))	; Get the translate table
			add		r0,r0,r0					; Get 0xFFFFFFFF00000000 for 64-bit or 0 for 32-bit
			blt--	cr1,hpfNestTooMuch			; Too many nestings, must be a loop...
			or		r23,r23,r0					; Make sure a carry will propagate all the way in 64-bit
			slwi	r11,r21,3					; Multiply space by 8
			ori		r10,r10,lo16(EXT(pmapTrans))	; Get the translate table low part
			addc	r23,r23,r9					; Relocate bottom half of vaddr
			lwz		r10,0(r10)					; Get the actual translation map
			slwi	r12,r21,2					; Multiply space by 4
			add		r10,r10,r11					; Add in the higher part of the index
			rlwinm	r23,r23,0,0,31				; Clean up the relocated address (does nothing in 32-bit)
			adde	r22,r22,r8					; Relocate the top half of the vaddr
			add		r12,r12,r10					; Now we are pointing at the space to pmap translation entry
			bl		sxlkUnlock					; Unlock the search list
			
			bt++	pf64Bitb,hpfGetPmap64		; Separate handling for 64-bit machines
			lwz		r28,pmapPAddr+4(r12)		; Get the physical address of the new pmap
			cmplwi	r28,0						; Is the pmap paddr valid?
			bne+	hpfNest						; Nest into new pmap...
			b		hpfBadPmap					; Handle bad pmap
			
hpfGetPmap64:
			ld		r28,pmapPAddr(r12)			; Get the physical address of the new pmap
			cmpldi	r28,0						; Is the pmap paddr valid?
			bne++	hpfNest						; Nest into new pmap...
			b		hpfBadPmap					; Handle bad pmap			


;
;			Error condition.  We only allow 64 nestings.  This keeps us from having to 
;			check for recusive nests when we install them.
;
		
			.align	5

hpfNestTooMuch:
			lwz		r20,savedsisr(r13)			; Get the DSISR
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list (R3 good from above)
			ori		r20,r20,1					; Indicate that there was a nesting problem 
			stw		r20,savedsisr(r13)			; Stash it
			lwz		r11,saveexception(r13)		; Restore the exception code
			b		EXT(PFSExit)				; Yes... (probably not though)

;
;			Error condition - lock failed - this is fatal
;
		
			.align	5

hpfBadLock:
			lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failMapping				; Show mapping failure
			sc
			
;
;			Error condition - space id selected an invalid pmap - fatal
;

			.align	5
			
hpfBadPmap:
			lis		r0,hi16(Choke)				; System abend
			ori		r0,r0,lo16(Choke)			; System abend
			li		r3,failPmap					; Show invalid pmap
			sc
			
;
;			Did not find any kind of mapping
;

			.align	5
			
hpfNotFound:
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock it
			lwz		r11,saveexception(r13)		; Restore the exception code
			
hpfExit:										; We need this because we can not do a relative branch
			b		EXT(PFSExit)				; Yes... (probably not though)


;
;			Here is where we handle special mappings.  So far, the only use is to load a 
;			processor specific segment register for copy in/out handling.
;
;			The only (so far implemented) special map is used for copyin/copyout.
;			We keep a mapping of a "linkage" mapping in the per_proc.
;			The linkage mapping is basically a nested pmap that is switched in
;			as part of context switch.  It relocates the appropriate user address
;			space slice into the right place in the kernel.
;

			.align	5

hpfSpclNest:	
			la		r31,ppUMWmp(r19)			; Just point to the mapping
			oris	r27,r27,hi16(dsiLinkage)	; Show that we had a linkage mapping here
			b		hpfCSrch					; Go continue search...


;
;			We have now found a mapping for the address we faulted on. 
;			

;
;			Here we go about calculating what the VSID should be. We concatanate
;			the space ID (14 bits wide) 3 times.  We then slide the vaddr over
;			so that bits 0:35 are in 14:49 (leaves a hole for one copy of the space ID).
;			Then we XOR and expanded space ID and the shifted vaddr.  This gives us
;			the VSID.  
;
;			This is used both for segment handling and PTE handling
;


#if maxAdrSpb != 14
#error maxAdrSpb (address space id size) is not 14 bits!!!!!!!!!!!!
#endif

;			Important non-volatile registers at this point ('home' means the final pmap/mapping found
;   		when a multi-level mapping has been successfully searched):
;				r21: home space id number
;				r22: relocated high-order 32 bits of vaddr
;				r23: relocated low-order 32 bits of vaddr 	
;				r25: pmap physical address
;				r27: dsisr
;				r28: home pmap physical address
;				r29: high-order 32 bits of faulting vaddr
;				r30: low-order 32 bits of faulting vaddr
;				r31: mapping's physical address

			.align	5
			
hpfFoundIt:	lwz		r12,pmapFlags(r28)			; Get the pmap flags so we can find the keys for this segment
hpfGVfound:	rlwinm.	r0,r27,0,dsiMissb,dsiMissb	; Did we actually miss the segment?
			rlwinm	r15,r23,18,14,17			; Shift 32:35 (0:3) of vaddr just above space ID
			rlwinm	r20,r21,28,22,31			; Shift upper 10 bits of space into high order
			rlwinm	r14,r22,18,14,31			; Shift 0:17 of vaddr over
			rlwinm	r0,r27,0,dsiLinkageb,dsiLinkageb	; Isolate linkage mapping flag
			rlwimi	r21,r21,14,4,17				; Make a second copy of space above first
			cmplwi	cr5,r0,0					; Did we just do a special nesting?
			rlwimi	r15,r22,18,0,13				; Shift 18:31 of vaddr just above shifted 32:35	
			crorc	cr0_eq,cr0_eq,cr5_eq		; Force outselves through the seg load code if special nest
			rlwimi	r21,r21,28,0,3				; Get low order of 3rd copy of space at top of register
			xor		r14,r14,r20					; Calculate the top half of VSID
			xor		r15,r15,r21					; Calculate the bottom half of the VSID
			rlwinm	r14,r14,12,15,19			; Slide the top of the VSID over to correct position (trim for 65 bit addressing)
			rlwinm	r12,r12,9,20,22				; Isolate and position key for cache entry
			rlwimi	r14,r15,12,20,31			; Slide top of bottom of VSID over into the top
			rlwinm	r15,r15,12,0,19				; Slide the last nybble into the low order segment position
			or		r12,r12,r15					; Add key into the bottom of VSID
;
;			Note: ESID is in R22:R23 pair; VSID is in R14:R15; cache form VSID is R14:R12
			
			bne++	hpfPteMiss					; Nope, normal PTE miss...

;
;			Here is the only place that we make an entry in the pmap segment cache.
;
;			Note that we do not make an entry in the segment cache for special
;			nested mappings.  This makes the copy in/out segment get refreshed
;			when switching threads.
;
;			The first thing that we do is to look up the ESID we are going to load
;			into a segment in the pmap cache.  If it is already there, this is
;			a segment that appeared since the last time we switched address spaces.
;			If all is correct, then it was another processors that made the cache
;			entry.  If not, well, it is an error that we should die on, but I have
;			not figured a good way to trap it yet.
;
;			If we get a hit, we just bail, otherwise, lock the pmap cache, select
;			an entry based on the generation number, update the cache entry, and 
;			also update the pmap sub-tag as well.  The sub-tag is a table of 4 bit
;			entries that correspond to the last 4 bits (32:35 for 64-bit and 
;			0:3 for 32-bit) of the ESID.
;
;			Then we unlock and bail.
;
;			First lock it.  Then select a free slot or steal one based on the generation
;			number. Then store it, update the allocation flags, and unlock.
;
;			The cache entry contains an image of the ESID/VSID pair we would load for
;			64-bit architecture.  For 32-bit, it is a simple transform to an SR image.
;
;			Remember, this cache entry goes in the ORIGINAL pmap (saved in R25), not
;			the current one, which may have changed because we nested.
;
;			Also remember that we do not store the valid bit in the ESID.  If we 
;			od, this will break some other stuff.
;

			bne--	cr5,hpfNoCacheEnt2			; Skip the cache entry if this is a "special nest" fault....
			
			mr		r3,r25						; Point to the pmap
			mr		r4,r22						; ESID high half
			mr		r5,r23						; ESID low half
			bl		pmapCacheLookup				; Go see if this is in the cache already
			
			mr.		r3,r3						; Did we find it?
			mr		r4,r11						; Copy this to a different register

			bne--	hpfNoCacheEnt				; Yes, we found it, no need to make another entry...
			
			lwz		r10,pmapSCSubTag(r25)		; Get the first part of the sub-tag lookup table
			lwz		r11,pmapSCSubTag+4(r25)		; Get the second part of the sub-tag lookup table
			
			cntlzw	r7,r4						; Find a free slot

			subi	r6,r7,pmapSegCacheUse		; We end up with a negative if we find one
			rlwinm	r30,r30,0,0,3				; Clean up the ESID
			srawi	r6,r6,31					; Get 0xFFFFFFFF if we have one, 0 if not
			addi	r5,r4,1						; Bump the generation number
			and		r7,r7,r6					; Clear bit number if none empty
			andc	r8,r4,r6					; Clear generation count if we found an empty
			rlwimi	r4,r5,0,17,31				; Insert the new generation number into the control word			
			or		r7,r7,r8					; Select a slot number
			li		r8,0						; Clear
			andi.	r7,r7,pmapSegCacheUse-1		; Wrap into the number we are using
			oris	r8,r8,0x8000				; Get the high bit on
			la		r9,pmapSegCache(r25)		; Point to the segment cache
			slwi	r6,r7,4						; Get index into the segment cache
			slwi	r2,r7,2						; Get index into the segment cache sub-tag index
			srw		r8,r8,r7					; Get the mask
			cmplwi	r2,32						; See if we are in the first or second half of sub-tag
			li		r0,0						; Clear
			rlwinm	r2,r2,0,27,31				; Wrap shift so we do not shift cache entries 8-F out
			oris	r0,r0,0xF000				; Get the sub-tag mask
			add		r9,r9,r6					; Point to the cache slot
			srw		r0,r0,r2					; Slide sub-tag mask to right slot (shift work for either half)
			srw		r5,r30,r2					; Slide sub-tag to right slot (shift work for either half)
			
			stw		r29,sgcESID(r9)				; Save the top of the ESID
			andc	r10,r10,r0					; Clear sub-tag slot in case we are in top
			andc	r11,r11,r0					; Clear sub-tag slot in case we are in bottom
			stw		r30,sgcESID+4(r9)			; Save the bottom of the ESID
			or		r10,r10,r5					; Stick in subtag in case top half
			or		r11,r11,r5					; Stick in subtag in case bottom half
			stw		r14,sgcVSID(r9)				; Save the top of the VSID
			andc	r4,r4,r8					; Clear the invalid bit for the slot we just allocated
			stw		r12,sgcVSID+4(r9)			; Save the bottom of the VSID and the key
			bge		hpfSCSTbottom				; Go save the bottom part of sub-tag
			
			stw		r10,pmapSCSubTag(r25)		; Save the top of the sub-tag
			b		hpfNoCacheEnt				; Go finish up...
			
hpfSCSTbottom:
			stw		r11,pmapSCSubTag+4(r25)		; Save the bottom of the sub-tag


hpfNoCacheEnt:	
			eieio								; Make sure cache is updated before lock
			stw		r4,pmapCCtl(r25)			; Unlock, allocate, and bump generation number


hpfNoCacheEnt2:
			lwz		r4,ppMapFlags(r19)			; Get the protection key modifier
			bt++	pf64Bitb,hpfLoadSeg64		; If 64-bit, go load the segment...
						
;
;			Make and enter 32-bit segment register
;

			lwz		r16,validSegs(r19)			; Get the valid SR flags
			xor		r12,r12,r4					; Alter the storage key before loading segment register
			rlwinm	r2,r30,4,28,31				; Isolate the segment we are setting
			rlwinm	r6,r12,19,1,3				; Insert the keys and N bit			
			lis		r0,0x8000					; Set bit 0
			rlwimi	r6,r12,20,12,31				; Insert 4:23 the VSID
			srw		r0,r0,r2					; Get bit corresponding to SR
			rlwimi	r6,r14,20,8,11				; Get the last nybble of the SR contents			
			or		r16,r16,r0					; Show that SR is valid
		
			mtsrin	r6,r30						; Set the actual SR
			
			stw		r16,validSegs(r19)			; Set the valid SR flags
		
			b		hpfPteMiss					; SR loaded, go do a PTE...
			
;
;			Make and enter 64-bit segment look-aside buffer entry.
;			Note that the cache entry is the right format except for valid bit.
;			We also need to convert from long long to 64-bit register values.
;


			.align	5
			
hpfLoadSeg64:
			ld		r16,validSegs(r19)			; Get the valid SLB entry flags
			sldi	r8,r29,32					; Move high order address over
			sldi	r10,r14,32					; Move high part of VSID over
			
			not		r3,r16						; Make valids be 0s
			li		r0,1						; Prepare to set bit 0
			
			cntlzd	r17,r3						; Find a free SLB	
			xor		r12,r12,r4					; Alter the storage key before loading segment table entry
			or		r9,r8,r30					; Form full 64-bit address
			cmplwi	r17,63						; Did we find a free SLB entry?		
			sldi	r0,r0,63					; Get bit 0 set
			or		r10,r10,r12					; Move in low part and keys
			addi	r17,r17,1					; Skip SLB 0 always
			blt++	hpfFreeSeg					; Yes, go load it...

;
;			No free SLB entries, select one that is in use and invalidate it
;
			lwz		r4,ppSegSteal(r19)			; Get the next slot to steal
			addi	r17,r4,pmapSegCacheUse+1	; Select stealee from non-cached slots only
			addi	r4,r4,1						; Set next slot to steal
			slbmfee	r7,r17						; Get the entry that is in the selected spot
			subi	r2,r4,63-pmapSegCacheUse	; Force steal to wrap
			rldicr	r7,r7,0,35					; Clear the valid bit and the rest
			srawi	r2,r2,31					; Get -1 if steal index still in range
			slbie	r7							; Invalidate the in-use SLB entry
			and		r4,r4,r2					; Reset steal index when it should wrap
			isync								; 
			
			stw		r4,ppSegSteal(r19)			; Set the next slot to steal
;
;			We are now ready to stick the SLB entry in the SLB and mark it in use
;

hpfFreeSeg:	
			subi	r4,r17,1					; Adjust shift to account for skipping slb 0
			mr		r7,r9						; Get a copy of the ESID with bits 36:63 clear
			srd		r0,r0,r4					; Set bit mask for allocation
			oris	r9,r9,0x0800				; Turn on the valid bit
			or		r16,r16,r0					; Turn on the allocation flag
			rldimi	r9,r17,0,58					; Copy in the SLB entry selector
			
			beq++	cr5,hpfNoBlow				; Skip blowing away the SLBE if this is not a special nest...
			slbie	r7							; Blow away a potential duplicate
			
hpfNoBlow:	slbmte	r10,r9						; Make that SLB entry

			std		r16,validSegs(r19)			; Mark as valid
			b		hpfPteMiss					; STE loaded, go do a PTE...
			
;
;			The segment has been set up and loaded if need be.  Now we are ready to build the
;			PTE and get it into the hash table.
;
;			Note that there is actually a race here.  If we start fault processing on
;			a different pmap, i.e., we have descended into a nested pmap, it is possible
;			that the nest could have been removed from the original pmap.  We would
;			succeed with this translation anyway.  I do not think we need to worry
;			about this (famous last words) because nobody should be unnesting anything 
;			if there are still people activily using them.  It should be up to the
;			higher level VM system to put the kibosh on this.
;
;			There is also another race here: if we fault on the same mapping on more than
;			one processor at the same time, we could end up with multiple PTEs for the same
;			mapping.  This is not a good thing....   We really only need one of the
;			fault handlers to finish, so what we do is to set a "fault in progress" flag in
;			the mapping.  If we see that set, we just abandon the handler and hope that by
;			the time we restore context and restart the interrupted code, the fault has
;			been resolved by the other guy.  If not, we will take another fault.
;
		
;
;			NOTE: IMPORTANT - CR7 contains a flag indicating if we have a block mapping or not.
;			It is required to stay there until after we call mapSelSlot!!!!
;

			.align	5
			
hpfPteMiss:	lwarx	r0,0,r31					; Load the mapping flag field
			lwz		r12,mpPte(r31)				; Get the quick pointer to PTE
			li		r3,mpHValid					; Get the PTE valid bit
			andi.	r2,r0,lo16(mpFIP)			; Are we handling a fault on the other side?
			ori		r2,r0,lo16(mpFIP)			; Set the fault in progress flag
			crnot	cr1_eq,cr0_eq				; Remember if FIP was on
			and.	r12,r12,r3					; Isolate the valid bit
			crorc	cr0_eq,cr1_eq,cr0_eq		; Bail if FIP is on.  Then, if already have PTE, bail...
			beq--	hpfAbandon					; Yes, other processor is or already has handled this...
			rlwinm	r0,r2,0,mpType				; Isolate mapping type
			cmplwi	r0,mpBlock					; Is this a block mapping?
			crnot	cr7_eq,cr0_eq				; Remember if we have a block mapping
			stwcx.	r2,0,r31					; Store the flags
			bne--	hpfPteMiss					; Collision, try again...

			bt++	pf64Bitb,hpfBldPTE64		; Skip down to the 64 bit stuff...

;
;			At this point we are about to do the 32-bit PTE generation.
;
;			The following is the R14:R15 pair that contains the "shifted" VSID:
;
;                             1        2        3        4        4        5      6 
;           0        8        6        4        2        0        8        6      3
;          +--------+--------+--------+--------+--------+--------+--------+--------+
;          |00000000|0000000V|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVV////|////////|    
;          +--------+--------+--------+--------+--------+--------+--------+--------+                   
;
;			The 24 bits of the 32-bit architecture VSID is in the following:
;
;                             1        2        3        4        4        5      6 
;           0        8        6        4        2        0        8        6      3
;          +--------+--------+--------+--------+--------+--------+--------+--------+
;          |////////|////////|////////|////VVVV|VVVVVVVV|VVVVVVVV|VVVV////|////////|    
;          +--------+--------+--------+--------+--------+--------+--------+--------+                   
;


hpfBldPTE32:
			lwz		r25,mpVAddr+4(r31)			; Grab the base virtual address for the mapping (32-bit portion)	
			lwz		r24,mpPAddr(r31)			; Grab the base physical page number for the mapping	

			mfsdr1	r27							; Get the hash table base address

			rlwinm	r0,r23,0,4,19				; Isolate just the page index
			rlwinm	r18,r23,10,26,31			; Extract the API
			xor		r19,r15,r0					; Calculate hash << 12
			mr		r2,r25						; Save the flag part of the mapping
			rlwimi	r18,r14,27,1,4				; Move bits 28:31 of the "shifted" VSID into the PTE image
			rlwinm	r16,r27,16,7,15				; Extract the hash table size
			rlwinm	r25,r25,0,0,19				; Clear out the flags
			slwi	r24,r24,12					; Change ppnum to physical address (note: 36-bit addressing no supported)
			sub		r25,r23,r25					; Get offset in mapping to page (0 unless block map)
			ori		r16,r16,lo16(0xFFC0)		; Slap in the bottom of the mask
			rlwinm	r27,r27,0,0,15				; Extract the hash table base
			rlwinm	r19,r19,26,6,25				; Shift hash over to make offset into hash table
			add		r24,r24,r25					; Adjust to true physical address
			rlwimi	r18,r15,27,5,24				; Move bits 32:31 of the "shifted" VSID into the PTE image
			rlwimi	r24,r2,0,20,31				; Slap in the WIMG and prot
			and		r19,r19,r16					; Wrap hash table offset into the hash table
			ori		r24,r24,lo16(mpR)			; Turn on the reference bit right now
			rlwinm	r20,r19,28,10,29			; Shift hash over to make offset into PCA
			add		r19,r19,r27					; Point to the PTEG
			subfic	r20,r20,-4					; Get negative offset to PCA
			oris	r18,r18,lo16(0x8000)		; Make sure the valid bit is on
			add		r20,r20,r27					; Point to the PCA slot
		
;
;			We now have a valid PTE pair in R18/R24.  R18 is PTE upper and R24 is PTE lower.
;			R19 contains the offset of the PTEG in the hash table. R20 has offset into the PCA.
;		
;			We need to check PTE pointer (mpPte) again after we lock the PTEG.  It is possible 
;			that some other processor beat us and stuck in a PTE or that 
;			all we had was a simple segment exception and the PTE was there the whole time.
;			If we find one a pointer, we are done.
;

			mr		r7,r20						; Copy the PCA pointer
			bl		mapLockPteg					; Lock the PTEG
	
			lwz		r12,mpPte(r31)				; Get the offset to the PTE
			mr		r17,r6						; Remember the PCA image
			mr		r16,r6						; Prime the post-select PCA image
			andi.	r0,r12,mpHValid				; Is there a PTE here already?
			li		r21,8						; Get the number of slots

			bne-	cr7,hpfNoPte32				; Skip this for a block mapping...

			bne-	hpfBailOut					; Someone already did this for us...

;
;			The mapSelSlot function selects a PTEG slot to use. As input, it uses R6 as a 
;			pointer to the PCA.  When it returns, R3 contains 0 if an unoccupied slot was
;			selected, 1 if it stole a non-block PTE, or 2 if it stole a block mapped PTE.
;			R4 returns the slot index.
;
;			REMEMBER: CR7 indicates that we are building a block mapping.
;

hpfNoPte32:	subic.	r21,r21,1					; See if we have tried all slots
			mr		r6,r17						; Get back the original PCA
			rlwimi	r6,r16,0,8,15				; Insert the updated steal slot
			blt-	hpfBailOut					; Holy Cow, all slots are locked...
			
			bl		mapSelSlot					; Go select a slot (note that the PCA image is already set up)

			cmplwi	cr5,r3,1					; Did we steal a slot?
			rlwimi	r19,r4,3,26,28				; Insert PTE index into PTEG address yielding PTE address
			mr		r16,r6						; Remember the PCA image after selection
			blt+	cr5,hpfInser32				; Nope, no steal...
			
			lwz		r6,0(r19)					; Get the old PTE
			lwz		r7,4(r19)					; Get the real part of the stealee
			rlwinm	r6,r6,0,1,31				; Clear the valid bit
			bgt		cr5,hpfNipBM				; Do not try to lock a non-existant physent for a block mapping...
			srwi	r3,r7,12					; Change phys address to a ppnum
			bl		mapFindPhyTry				; Go find and try to lock physent (note: if R3 is 0, there is no physent for this page)
			cmplwi	cr1,r3,0					; Check if this is in RAM
			bne-	hpfNoPte32					; Could not get it, try for another...
			
			crmove	cr5_gt,cr1_eq				; If we did not find a physent, pretend that this is a block map
			
hpfNipBM:	stw		r6,0(r19)					; Set the invalid PTE

			sync								; Make sure the invalid is stored
			li		r9,tlbieLock				; Get the TLBIE lock
			rlwinm	r10,r6,21,0,3				; Shift last 4 bits of space to segment part
			
hpfTLBIE32:	lwarx	r0,0,r9						; Get the TLBIE lock 
			mfsprg	r4,0						; Get the per_proc
			rlwinm	r8,r6,25,18,31				; Extract the space ID
			rlwinm	r11,r6,25,18,31				; Extract the space ID
			lwz		r7,hwSteals(r4)				; Get the steal count
			srwi	r2,r6,7						; Align segment number with hash
			rlwimi	r11,r11,14,4,17				; Get copy above ourselves
			mr.		r0,r0						; Is it locked? 
			srwi	r0,r19,6					; Align PTEG offset for back hash
			xor		r2,r2,r11					; Get the segment number (plus a whole bunch of extra bits)
 			xor		r11,r11,r0					; Hash backwards to partial vaddr
			rlwinm	r12,r2,14,0,3				; Shift segment up
			mfsprg	r2,2						; Get feature flags 
			li		r0,1						; Get our lock word 
			rlwimi	r12,r6,22,4,9				; Move up the API
			bne-	hpfTLBIE32					; It is locked, go wait...
			rlwimi	r12,r11,12,10,19			; Move in the rest of the vaddr
			
			stwcx.	r0,0,r9						; Try to get it
			bne-	hpfTLBIE32					; We was beat...
			addi	r7,r7,1						; Bump the steal count
			
			rlwinm.	r0,r2,0,pfSMPcapb,pfSMPcapb	; Can this be an MP box?
			li		r0,0						; Lock clear value 

			tlbie	r12							; Invalidate it everywhere 

			
			beq-	hpfNoTS32					; Can not have MP on this machine...
			
			eieio								; Make sure that the tlbie happens first 
			tlbsync								; Wait for everyone to catch up 
			sync								; Make sure of it all

hpfNoTS32:	stw		r0,tlbieLock(0)				; Clear the tlbie lock
			
			stw		r7,hwSteals(r4)				; Save the steal count
			bgt		cr5,hpfInser32				; We just stole a block mapping...
			
			lwz		r4,4(r19)					; Get the RC of the just invalidated PTE
			
			la		r11,ppLink+4(r3)			; Point to the master RC copy
			lwz		r7,ppLink+4(r3)				; Grab the pointer to the first mapping
			rlwinm	r2,r4,27,ppRb-32,ppCb-32	; Position the new RC

hpfMrgRC32:	lwarx	r0,0,r11					; Get the master RC
			or		r0,r0,r2					; Merge in the new RC
			stwcx.	r0,0,r11					; Try to stick it back
			bne-	hpfMrgRC32					; Try again if we collided...
			
			
hpfFPnch:	rlwinm.	r7,r7,0,~ppFlags			; Clean and test mapping address
			beq-	hpfLostPhys					; We could not find our mapping.  Kick the bucket...
			
			lhz		r10,mpSpace(r7)				; Get the space
			lwz		r9,mpVAddr+4(r7)			; And the vaddr
			cmplw	cr1,r10,r8					; Is this one of ours?
			xor		r9,r12,r9					; Compare virtual address
			cmplwi	r9,0x1000					; See if we really match
			crand	cr0_eq,cr1_eq,cr0_lt		; See if both space and vaddr match
			beq+	hpfFPnch2					; Yes, found ours...
			
			lwz		r7,mpAlias+4(r7)			; Chain on to the next
			b		hpfFPnch					; Check it out...

hpfFPnch2:	sub		r0,r19,r27					; Get offset to the PTEG
			stw		r0,mpPte(r7)				; Invalidate the quick pointer (keep quick pointer pointing to PTEG)
			bl		mapPhysUnlock				; Unlock the physent now
			
hpfInser32:	oris	r18,r18,lo16(0x8000)		; Make sure the valid bit is on

			stw		r24,4(r19)					; Stuff in the real part of the PTE
			eieio								; Make sure this gets there first

			stw		r18,0(r19)					; Stuff the virtual part of the PTE and make it valid
			mr		r17,r16						; Get the PCA image to save
			b		hpfFinish					; Go join the common exit code...
			
			
;
;			At this point we are about to do the 64-bit PTE generation.
;
;			The following is the R14:R15 pair that contains the "shifted" VSID:
;
;                             1        2        3        4        4        5      6 
;           0        8        6        4        2        0        8        6      3
;          +--------+--------+--------+--------+--------+--------+--------+--------+
;          |00000000|0000000V|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVVVVVV|VVVV////|////////|    
;          +--------+--------+--------+--------+--------+--------+--------+--------+                   
;
;

			.align	5

hpfBldPTE64:
			ld		r10,mpVAddr(r31)			; Grab the base virtual address for the mapping 
			lwz		r24,mpPAddr(r31)			; Grab the base physical page number for the mapping	

			mfsdr1	r27							; Get the hash table base address

			sldi	r11,r22,32					; Slide top of adjusted EA over
			sldi	r14,r14,32					; Slide top of VSID over
			rlwinm	r5,r27,0,27,31				; Isolate the size
			eqv		r16,r16,r16					; Get all foxes here
			rlwimi	r15,r23,16,20,24			; Stick in EA[36:40] to make AVPN	
			mr		r2,r10						; Save the flag part of the mapping
			or		r11,r11,r23					; Stick in bottom of adjusted EA for full 64-bit value	
			rldicr	r27,r27,0,45				; Clean up the hash table base
			or		r15,r15,r14					; Stick in bottom of AVPN for full 64-bit value	
			rlwinm	r0,r11,0,4,19				; Clear out everything but the page
			subfic	r5,r5,46					; Get number of leading zeros
			xor		r19,r0,r15					; Calculate hash
			ori		r15,r15,1					; Turn on valid bit in AVPN to make top of PTE
			srd		r16,r16,r5					; Shift over to get length of table
			srdi	r19,r19,5					; Convert page offset to hash table offset
			rldicr	r16,r16,0,56				; Clean up lower bits in hash table size			
			rldicr	r10,r10,0,51				; Clear out flags
			sldi	r24,r24,12					; Change ppnum to physical address
			sub		r11,r11,r10					; Get the offset from the base mapping
			and		r19,r19,r16					; Wrap into hash table
			add		r24,r24,r11					; Get actual physical address of this page
			srdi	r20,r19,5					; Convert PTEG offset to PCA offset
			rldimi	r24,r2,0,52					; Insert the keys, WIMG, RC, etc.
			subfic	r20,r20,-4					; Get negative offset to PCA
			ori		r24,r24,lo16(mpR)			; Force on the reference bit
			add		r20,r20,r27					; Point to the PCA slot		
			add		r19,r19,r27					; Point to the PTEG
			
;
;			We now have a valid PTE pair in R15/R24.  R15 is PTE upper and R24 is PTE lower.
;			R19 contains the offset of the PTEG in the hash table. R20 has offset into the PCA.
;		
;			We need to check PTE pointer (mpPte) again after we lock the PTEG.  It is possible 
;			that some other processor beat us and stuck in a PTE or that 
;			all we had was a simple segment exception and the PTE was there the whole time.
;			If we find one a pointer, we are done.
;
			
			mr		r7,r20						; Copy the PCA pointer
			bl		mapLockPteg					; Lock the PTEG
	
			lwz		r12,mpPte(r31)				; Get the offset to the PTE
			mr		r17,r6						; Remember the PCA image
			mr		r18,r6						; Prime post-selection PCA image
			andi.	r0,r12,mpHValid				; See if we have a PTE now
			li		r21,8						; Get the number of slots
		
			bne--	cr7,hpfNoPte64				; Skip this for a block mapping...

			bne--	hpfBailOut					; Someone already did this for us...

;
;			The mapSelSlot function selects a PTEG slot to use. As input, it uses R3 as a 
;			pointer to the PCA.  When it returns, R3 contains 0 if an unoccupied slot was
;			selected, 1 if it stole a non-block PTE, or 2 if it stole a block mapped PTE.
;			R4 returns the slot index.
;
;			REMEMBER: CR7 indicates that we are building a block mapping.
;

hpfNoPte64:	subic.	r21,r21,1					; See if we have tried all slots
			mr		r6,r17						; Restore original state of PCA
			rlwimi	r6,r18,0,8,15				; Insert the updated steal slot
			blt-	hpfBailOut					; Holy Cow, all slots are locked...
			
			bl		mapSelSlot					; Go select a slot

			cmplwi	cr5,r3,1					; Did we steal a slot?			
			mr		r18,r6						; Remember the PCA image after selection
			insrdi	r19,r4,3,57					; Insert slot index into PTEG address bits 57:59, forming the PTE address
			lwz		r10,hwSteals(r2)			; Get the steal count
			blt++	cr5,hpfInser64				; Nope, no steal...

			ld		r6,0(r19)					; Get the old PTE
			ld		r7,8(r19)					; Get the real part of the stealee
			rldicr	r6,r6,0,62					; Clear the valid bit
			bgt		cr5,hpfNipBMx				; Do not try to lock a non-existant physent for a block mapping...
			srdi	r3,r7,12					; Change page address to a page address
			bl		mapFindPhyTry				; Go find and try to lock physent (note: if R3 is 0, there is no physent for this page)
			cmplwi	cr1,r3,0					; Check if this is in RAM
			bne--	hpfNoPte64					; Could not get it, try for another...
			
			crmove	cr5_gt,cr1_eq				; If we did not find a physent, pretend that this is a block map
			
hpfNipBMx:	std		r6,0(r19)					; Set the invalid PTE
			li		r9,tlbieLock				; Get the TLBIE lock

			srdi	r11,r6,5					; Shift VSID over for back hash
			mfsprg	r4,0						; Get the per_proc
			xor		r11,r11,r19					; Hash backwards to get low bits of VPN
			sync								; Make sure the invalid is stored
			
			sldi	r12,r6,16					; Move AVPN to EA position
			sldi	r11,r11,5					; Move this to the page position
			
hpfTLBIE64:	lwarx	r0,0,r9						; Get the TLBIE lock 
			mr.		r0,r0						; Is it locked? 
			li		r0,1						; Get our lock word
			bne--	hpfTLBIE65					; It is locked, go wait...
			
			stwcx.	r0,0,r9						; Try to get it
			rldimi	r12,r11,0,41				; Stick the low part of the page number into the AVPN
			rldicl	r8,r6,52,50					; Isolate the address space ID
			bne--	hpfTLBIE64					; We was beat...
			addi	r10,r10,1					; Bump the steal count
			
			rldicl	r11,r12,0,16				; Clear cause the book says so
			li		r0,0						; Lock clear value 

			tlbie	r11							; Invalidate it everywhere 

			mr		r7,r8						; Get a copy of the space ID
			eieio								; Make sure that the tlbie happens first
			rldimi	r7,r7,14,36					; Copy address space to make hash value
			tlbsync								; Wait for everyone to catch up
			rldimi	r7,r7,28,22					; Add in a 3rd copy of the hash up top
			srdi	r2,r6,26					; Shift original segment down to bottom
			
			ptesync								; Make sure of it all
			xor		r7,r7,r2					; Compute original segment
			stw		r0,tlbieLock(0)				; Clear the tlbie lock

			stw		r10,hwSteals(r4)			; Save the steal count
			bgt		cr5,hpfInser64				; We just stole a block mapping...
			
			rldimi	r12,r7,28,0					; Insert decoded segment
			rldicl	r4,r12,0,13					; Trim to max supported address
			
			ld		r12,8(r19)					; Get the RC of the just invalidated PTE			

			la		r11,ppLink+4(r3)			; Point to the master RC copy
			ld		r7,ppLink(r3)				; Grab the pointer to the first mapping
			rlwinm	r2,r12,27,ppRb-32,ppCb-32	; Position the new RC

hpfMrgRC64:	lwarx	r0,0,r11					; Get the master RC
			li		r12,ppLFAmask				; Get mask to clean up alias pointer
			or		r0,r0,r2					; Merge in the new RC
			rotrdi	r12,r12,ppLFArrot			; Rotate clean up mask to get 0xF0000000000000000F
			stwcx.	r0,0,r11					; Try to stick it back
			bne--	hpfMrgRC64					; Try again if we collided...
	
hpfFPnchx:	andc.	r7,r7,r12					; Clean and test mapping address
			beq--	hpfLostPhys					; We could not find our mapping.  Kick the bucket...
			
			lhz		r10,mpSpace(r7)				; Get the space
			ld		r9,mpVAddr(r7)				; And the vaddr
			cmplw	cr1,r10,r8					; Is this one of ours?
			xor		r9,r4,r9					; Compare virtual address
			cmpldi	r9,0x1000					; See if we really match
			crand	cr0_eq,cr1_eq,cr0_lt		; See if both space and vaddr match
			beq++	hpfFPnch2x					; Yes, found ours...
			
			ld		r7,mpAlias(r7)				; Chain on to the next
			b		hpfFPnchx					; Check it out...

			.align	5

hpfTLBIE65:	li		r7,lgKillResv				; Point to the reservatio kill area
			stwcx.	r7,0,r7						; Kill reservation		
			
hpfTLBIE63: lwz		r0,0(r9)					; Get the TLBIE lock
			mr.		r0,r0						; Is it locked?
			beq++	hpfTLBIE64					; Yup, wait for it...
			b		hpfTLBIE63					; Nope, try again..



hpfFPnch2x:	sub		r0,r19,r27					; Get offset to PTEG
			stw		r0,mpPte(r7)				; Invalidate the quick pointer (keep pointing at PTEG though)
			bl		mapPhysUnlock				; Unlock the physent now
			

hpfInser64:	std		r24,8(r19)					; Stuff in the real part of the PTE
			eieio								; Make sure this gets there first
			std		r15,0(r19)					; Stuff the virtual part of the PTE and make it valid
			mr		r17,r18						; Get the PCA image to set
			b		hpfFinish					; Go join the common exit code...

hpfLostPhys:
			lis		r0,hi16(Choke)				; System abend - we must find the stolen mapping or we are dead
			ori		r0,r0,lo16(Choke)			; System abend
			sc
			
;
;			This is the common code we execute when we are finished setting up the PTE.
;
	
			.align	5
			
hpfFinish:	sub		r4,r19,r27					; Get offset of PTE
			ori		r4,r4,lo16(mpHValid)		; Add valid bit to PTE offset
			bne		cr7,hpfBailOut				; Do not set the PTE pointer for a block map
			stw		r4,mpPte(r31)				; Remember our PTE
			
hpfBailOut:	eieio								; Make sure all updates come first
			stw		r17,0(r20)					; Unlock and set the final PCA
			
;
;			This is where we go if we have started processing the fault, but find that someone
;			else has taken care of it.
;

hpfIgnore:	lwz		r2,mpFlags(r31)				; Get the mapping flags
			rlwinm	r2,r2,0,mpFIPb+1,mpFIPb-1	; Clear the "fault in progress" flag
			sth		r2,mpFlags+2(r31)			; Set it
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			li		r11,T_IN_VAIN				; Say that it was handled
			b		EXT(PFSExit)				; Leave...

;
;			This is where we go when we  find that someone else
;			is in the process of handling the fault.
;

hpfAbandon:	li		r3,lgKillResv				; Kill off any reservation
			stwcx.	r3,0,r3						; Do it
			
			la		r3,pmapSXlk(r28)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list

			li		r11,T_IN_VAIN				; Say that it was handled
			b		EXT(PFSExit)				; Leave...
			
;
;			Guest shadow assist -- page fault handler
;
;			Here we handle a fault in a guest pmap that has the guest shadow mapping
;			assist active. We locate the VMM pmap extension block, which contains an
;			index over the discontiguous multi-page shadow hash table. The index
;			corresponding to our vaddr is selected, and the selected group within
;			that page is searched for a valid and active entry that contains
;			our vaddr and space id. The search is pipelined, so that we may fetch
;			the next slot while examining the current slot for a hit. The final
;			search iteration is unrolled so that we don't fetch beyond the end of
;			our group, which could have dire consequences depending upon where the
;			physical hash page is located.
;
;			The VMM pmap extension block occupies a page. Begining at offset 0, we
;			have the pmap_vmm_ext proper. Aligned at the first 128-byte boundary
;			after the pmap_vmm_ext is the hash table physical address index, a 
;			linear list of 64-bit physical addresses of the pages that comprise
;			the hash table.
;
;			In the event that we succesfully locate a guest mapping, we re-join
;			the page fault path at hpfGVfound with the mapping's address in r31;
;			otherwise, we re-join at hpfNotFound. In either case, we re-join holding
;			a share of the pmap search lock for the host pmap with the host pmap's
;			address in r28, the guest pmap's space id in r21, and the guest pmap's
;			flags in r12.
;

			.align	5
hpfGVxlate:
			bt		pf64Bitb,hpfGV64			; Take 64-bit path for 64-bit machine
			
			lwz		r11,pmapVmmExtPhys+4(r28)	; r11 <- VMM pmap extension block paddr
			lwz		r12,pmapFlags(r28)			; r12 <- guest pmap's flags
			lwz		r21,pmapSpace(r28)			; r21 <- guest space ID number
			lwz		r28,vmxHostPmapPhys+4(r11)	; r28 <- host pmap's paddr
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			rlwinm	r10,r30,0,0xFFFFF000		; r10 <- page-aligned guest vaddr
			lwz		r6,vxsGpf(r11)				; Get guest fault count
			
			srwi	r3,r10,12					; Form shadow hash:
			xor		r3,r3,r21					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r4,r3,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r4					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r3,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr

			la		r3,pmapSXlk(r28)			; Point to the host pmap's search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne-	hpfBadLock					; Nope...

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			addi	r6,r6,1						; Increment guest fault count
			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			stw		r6,vxsGpf(r11)				; Update guest fault count
			b		hpfGVlp32

			.align	5
hpfGVlp32:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			andi.	r6,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r21					; Compare space ID
			or		r0,r6,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r10					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		hpfGVfound					; Join common patch on hit (r31 points to mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	hpfGVlp32					; Iterate

			clrrwi	r5,r5,12					; Remove flags from virtual address			
			andi.	r3,r3,mpgFree+mpgDormant	; Isolate guest free and dormant flag
			xor		r4,r4,r21					; Compare space ID
			or		r0,r3,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r10					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		hpfGVfound					; Join common patch on hit (r31 points to mapping)
			
			b		hpfGVmiss

			.align	5
hpfGV64:
			ld		r11,pmapVmmExtPhys(r28)		; r11 <- VMM pmap extension block paddr
			lwz		r12,pmapFlags(r28)			; r12 <- guest pmap's flags
			lwz		r21,pmapSpace(r28)			; r21 <- guest space ID number
			ld		r28,vmxHostPmapPhys(r11)	; r28 <- host pmap's paddr
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			rlwinm	r10,r30,0,0xFFFFF000		; Form 64-bit guest vaddr
			rldimi	r10,r29,32,0				;  cleaning up low-order 12 bits			
			lwz		r6,vxsGpf(r11)				; Get guest fault count

			srwi	r3,r10,12					; Form shadow hash:
			xor		r3,r3,r21					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r4,r3,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r4					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r3,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr
												
			la		r3,pmapSXlk(r28)			; Point to the host pmap's search lock
			bl		sxlkShared					; Go get a shared lock on the mapping lists
			mr.		r3,r3						; Did we get the lock?
			bne--	hpfBadLock					; Nope...

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			addi	r6,r6,1						; Increment guest fault count
			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			stw		r6,vxsGpf(r11)				; Update guest fault count
			b		hpfGVlp64
			
			.align	5
hpfGVlp64:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			andi.	r6,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flag
			xor		r7,r7,r21					; Compare space ID
			or		r0,r6,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r10					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		hpfGVfound					; Join common path on hit (r31 points to mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	hpfGVlp64					; Iterate

			clrrdi	r5,r5,12					; Remove flags from virtual address			
			andi.	r3,r3,mpgFree+mpgDormant	; Isolate guest free and dormant flag
			xor		r4,r4,r21					; Compare space ID
			or		r0,r3,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r10					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		hpfGVfound					; Join common path on hit (r31 points to mapping)

hpfGVmiss:
			lwz		r6,vxsGpfMiss(r11)			; Guest guest fault miss count
			addi	r6,r6,1						; Increment miss count
			stw		r6,vxsGpfMiss(r11)			; Update guest fault miss count
			b		hpfNotFound
			
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

			lis		r8,hi16(MASK(MSR_VEC))		; Get the vector enable
			mfmsr	r10							; Get the current MSR 
			ori		r8,r8,lo16(MASK(MSR_FP))	; Add in FP
			ori		r9,r8,lo16(MASK(MSR_EE))	; Add in the EE
			andc	r10,r10,r8					; Turn off VEC, FP for good
			andc	r9,r10,r9					; Turn off EE also
			mtmsr	r9							; Disable them 
 			isync								; Make sure FP and vec are off
			mfsprg	r6,1						; Get the current activation
			lwz		r6,ACT_PER_PROC(r6)			; Get the per_proc block
			lwz		r2,ppUserPmapVirt(r6)		; Get our virtual pmap address
			mfsprg	r4,2						; The the feature flags
			lwz		r7,pmapvr(r3)				; Get the v to r translation
 			lwz		r8,pmapvr+4(r3)				; Get the v to r translation
 			mtcrf	0x80,r4						; Get the Altivec flag
			xor		r4,r3,r8					; Get bottom of the real address of bmap anchor
			cmplw	cr1,r3,r2					; Same address space as before?
			stw		r7,ppUserPmap(r6)			; Show our real pmap address
			crorc	cr1_eq,cr1_eq,pfAltivecb	; See if same address space or not altivec machine
			stw		r4,ppUserPmap+4(r6)			; Show our real pmap address
			stw		r3,ppUserPmapVirt(r6)		; Show our virtual pmap address
			mtmsr	r10							; Restore interruptions 
			beqlr--	cr1							; Leave if the same address space or not Altivec

			dssall								; Need to kill all data streams if adrsp changed
			sync
			blr									; Return... 
	
			.align	5
			.globl	EXT(hw_set_user_space_dis)

LEXT(hw_set_user_space_dis)

 			lwz		r7,pmapvr(r3)				; Get the v to r translation
 			mfsprg	r4,2						; The the feature flags
			lwz		r8,pmapvr+4(r3)				; Get the v to r translation
			mfsprg	r6,1						; Get the current activation
			lwz		r6,ACT_PER_PROC(r6)			; Get the per_proc block
			lwz		r2,ppUserPmapVirt(r6)		; Get our virtual pmap address
 			mtcrf	0x80,r4						; Get the Altivec flag
			xor		r4,r3,r8					; Get bottom of the real address of bmap anchor
			cmplw	cr1,r3,r2					; Same address space as before?
			stw		r7,ppUserPmap(r6)			; Show our real pmap address
			crorc	cr1_eq,cr1_eq,pfAltivecb	; See if same address space or not altivec machine
			stw		r4,ppUserPmap+4(r6)			; Show our real pmap address
			stw		r3,ppUserPmapVirt(r6)		; Show our virtual pmap address
			beqlr--	cr1							; Leave if the same

			dssall								; Need to kill all data streams if adrsp changed
			sync
			blr									; Return...
	
/*			int mapalc1(struct mappingblok *mb) - Finds, allocates, and zeros a free 1-bit mapping entry
 *
 *			Lock must already be held on mapping block list
 *			returns 0 if all slots filled.
 *			returns n if a slot is found and it is not the last
 *			returns -n if a slot is found and it is the last
 *			when n and -n are returned, the corresponding bit is cleared
 *			the mapping is zeroed out before return
 *
 */

			.align	5
			.globl	EXT(mapalc1)

LEXT(mapalc1)
			lwz		r4,mbfree(r3)				; Get the 1st mask 
			lis		r0,0x8000					; Get the mask to clear the first free bit
			lwz		r5,mbfree+4(r3)				; Get the 2nd mask 
			mr		r12,r3						; Save the block ptr
			cntlzw	r3,r4						; Get first 1-bit in 1st word
			srw.	r9,r0,r3					; Get bit corresponding to first free one
			cntlzw	r10,r5						; Get first free field in second word
			andc	r4,r4,r9					; Turn 1-bit off in 1st word
			bne		mapalc1f					; Found one in 1st word
			
			srw.	r9,r0,r10					; Get bit corresponding to first free one in 2nd word
            li		r3,0						; assume failure return
			andc	r5,r5,r9					; Turn it off
			beqlr--								; There are no 1 bits left...
            addi	r3,r10,32					; set the correct number
            
mapalc1f:
            or.		r0,r4,r5					; any more bits set?
            stw		r4,mbfree(r12)				; update bitmasks
            stw		r5,mbfree+4(r12)
            
            slwi	r6,r3,6						; get (n * mpBasicSize), ie offset of mapping in block
            addi	r7,r6,32
            dcbz	r6,r12						; clear the 64-byte mapping
            dcbz	r7,r12
            
            bnelr++								; return if another bit remains set
            
            neg		r3,r3						; indicate we just returned the last bit
            blr


/*			int mapalc2(struct mappingblok *mb) - Finds, allocates, and zero's a free 2-bit mapping entry
 *
 *			Lock must already be held on mapping block list
 *			returns 0 if all slots filled.
 *			returns n if a slot is found and it is not the last
 *			returns -n if a slot is found and it is the last
 *			when n and -n are returned, the corresponding bits are cleared
 * 			We find runs of 2 consecutive 1 bits by cntlzw(n & (n<<1)).
 *			the mapping is zero'd out before return
 */

			.align	5
			.globl	EXT(mapalc2)
LEXT(mapalc2)
			lwz		r4,mbfree(r3)				; Get the first mask 
			lis		r0,0x8000					; Get the mask to clear the first free bit
			lwz		r5,mbfree+4(r3)				; Get the second mask 
			mr		r12,r3						; Save the block ptr
            slwi	r6,r4,1						; shift first word over
            and		r6,r4,r6					; lite start of double bit runs in 1st word
            slwi	r7,r5,1						; shift 2nd word over
			cntlzw	r3,r6						; Get first free 2-bit run in 1st word
            and		r7,r5,r7					; lite start of double bit runs in 2nd word
			srw.	r9,r0,r3					; Get bit corresponding to first run in 1st word
			cntlzw	r10,r7						; Get first free field in second word
            srwi	r11,r9,1					; shift over for 2nd bit in 1st word
			andc	r4,r4,r9					; Turn off 1st bit in 1st word
            andc	r4,r4,r11					; turn off 2nd bit in 1st word
			bne		mapalc2a					; Found two consecutive free bits in 1st word
			
			srw.	r9,r0,r10					; Get bit corresponding to first free one in second word
            li		r3,0						; assume failure
            srwi	r11,r9,1					; get mask for 2nd bit
			andc	r5,r5,r9					; Turn off 1st bit in 2nd word
            andc	r5,r5,r11					; turn off 2nd bit in 2nd word
			beq--	mapalc2c					; There are no runs of 2 bits in 2nd word either
            addi	r3,r10,32					; set the correct number
            
mapalc2a:
            or.		r0,r4,r5					; any more bits set?
            stw		r4,mbfree(r12)				; update bitmasks
            stw		r5,mbfree+4(r12)
            slwi	r6,r3,6						; get (n * mpBasicSize), ie offset of mapping in block
            addi	r7,r6,32
            addi	r8,r6,64
            addi	r9,r6,96
            dcbz	r6,r12						; zero out the 128-byte mapping
            dcbz	r7,r12						; we use the slow 32-byte dcbz even on 64-bit machines
            dcbz	r8,r12						; because the mapping may not be 128-byte aligned
            dcbz	r9,r12
            
            bnelr++								; return if another bit remains set
            
            neg		r3,r3						; indicate we just returned the last bit
            blr
            
mapalc2c:
            rlwinm	r7,r5,1,31,31				; move bit 0 of 2nd word to bit 31
            and.	r0,r4,r7					; is the 2-bit field that spans the 2 words free?
            beqlr								; no, we failed
            rlwinm	r4,r4,0,0,30				; yes, turn off bit 31 of 1st word
            rlwinm	r5,r5,0,1,31				; turn off bit 0 of 2nd word
            li		r3,31						; get index of this field
            b		mapalc2a
			

;
;			This routine initialzes the hash table and PCA.
;			It is done here because we may need to be 64-bit to do it.
;

			.align	5
			.globl	EXT(hw_hash_init)

LEXT(hw_hash_init)

 			mfsprg	r10,2						; Get feature flags 
			lis		r12,hi16(EXT(hash_table_size))		; Get hash table size address
			mtcrf	0x02,r10					; move pf64Bit to cr6
			lis		r11,hi16(EXT(hash_table_base))		; Get hash table base address
			lis		r4,0xFF01					; Set all slots free and start steal at end
			ori		r12,r12,lo16(EXT(hash_table_size))	; Get hash table size address
			ori		r11,r11,lo16(EXT(hash_table_base))	; Get hash table base address

			lwz		r12,0(r12)					; Get hash table size
			li		r3,0						; Get start
			bt++	pf64Bitb,hhiSF				; skip if 64-bit (only they take the hint)

			lwz		r11,4(r11)					; Get hash table base
			
hhiNext32:	cmplw	r3,r12						; Have we reached the end?
			bge-	hhiCPCA32					; Yes...			
			dcbz	r3,r11						; Clear the line
			addi	r3,r3,32					; Next one...
			b		hhiNext32					; Go on...

hhiCPCA32:	rlwinm	r12,r12,28,4,29				; Get number of slots * 4
			li		r3,-4						; Displacement to first PCA entry
			neg		r12,r12						; Get negative end of PCA	
			
hhiNPCA32:	stwx	r4,r3,r11					; Initialize the PCA entry
			subi	r3,r3,4						; Next slot
			cmpw	r3,r12						; Have we finished?
			bge+	hhiNPCA32					; Not yet...
			blr									; Leave...

hhiSF:		mfmsr	r9							; Save the MSR
			li		r8,1						; Get a 1
			mr		r0,r9						; Get a copy of the MSR
			ld		r11,0(r11)					; Get hash table base
			rldimi	r0,r8,63,MSR_SF_BIT			; Set SF bit (bit 0)
			mtmsrd	r0							; Turn on SF
			isync
			
			
hhiNext64:	cmpld	r3,r12						; Have we reached the end?
			bge--	hhiCPCA64					; Yes...			
			dcbz128	r3,r11						; Clear the line
			addi	r3,r3,128					; Next one...
			b		hhiNext64					; Go on...

hhiCPCA64:	rlwinm	r12,r12,27,5,29				; Get number of slots * 4
			li		r3,-4						; Displacement to first PCA entry
			neg		r12,r12						; Get negative end of PCA	
		
hhiNPCA64:	stwx	r4,r3,r11					; Initialize the PCA entry
			subi	r3,r3,4						; Next slot
			cmpd	r3,r12						; Have we finished?
			bge++	hhiNPCA64					; Not yet...

			mtmsrd	r9							; Turn off SF if it was off
			isync
			blr									; Leave...
			
			
;
;			This routine sets up the hardware to start translation.
;			Note that we do NOT start translation.
;

			.align	5
			.globl	EXT(hw_setup_trans)

LEXT(hw_setup_trans)

 			mfsprg	r11,0						; Get the per_proc block
 			mfsprg	r12,2						; Get feature flags 
 			li		r0,0						; Get a 0
 			li		r2,1						; And a 1
			mtcrf	0x02,r12					; Move pf64Bit to cr6
			stw		r0,validSegs(r11)			; Make sure we think all SR/STEs are invalid
			stw		r0,validSegs+4(r11)			; Make sure we think all SR/STEs are invalid, part deux
			sth		r2,ppInvSeg(r11)			; Force a reload of the SRs
			sth		r0,ppCurSeg(r11)			; Set that we are starting out in kernel
			
			bt++	pf64Bitb,hstSF				; skip if 64-bit (only they take the hint)

			li		r9,0						; Clear out a register
			sync
			isync
			mtdbatu 0,r9						; Invalidate maps
			mtdbatl 0,r9						; Invalidate maps
			mtdbatu 1,r9						; Invalidate maps
			mtdbatl 1,r9						; Invalidate maps
			mtdbatu 2,r9						; Invalidate maps
			mtdbatl 2,r9						; Invalidate maps
			mtdbatu 3,r9						; Invalidate maps
			mtdbatl 3,r9						; Invalidate maps

			mtibatu 0,r9						; Invalidate maps
			mtibatl 0,r9						; Invalidate maps
			mtibatu 1,r9						; Invalidate maps
			mtibatl 1,r9						; Invalidate maps
			mtibatu 2,r9						; Invalidate maps
			mtibatl 2,r9						; Invalidate maps
			mtibatu 3,r9						; Invalidate maps
			mtibatl 3,r9						; Invalidate maps

			lis		r11,hi16(EXT(hash_table_base))		; Get hash table base address
			lis		r12,hi16(EXT(hash_table_size))		; Get hash table size address
			ori		r11,r11,lo16(EXT(hash_table_base))	; Get hash table base address
			ori		r12,r12,lo16(EXT(hash_table_size))	; Get hash table size address
			lwz		r11,4(r11)					; Get hash table base
			lwz		r12,0(r12)					; Get hash table size
			subi	r12,r12,1					; Back off by 1
			rlwimi	r11,r12,16,23,31			; Stick the size into the sdr1 image
			
			mtsdr1	r11							; Ok, we now have the hash table set up
			sync
			
			li		r12,invalSpace				; Get the invalid segment value
			li		r10,0						; Start low
			
hstsetsr:	mtsrin	r12,r10						; Set the SR
			addis	r10,r10,0x1000				; Bump the segment
			mr.		r10,r10						; Are we finished?
			bne+	hstsetsr					; Nope...	
			sync
			blr									; Return...

;
;			64-bit version
;

hstSF:		lis		r11,hi16(EXT(hash_table_base))		; Get hash table base address
			lis		r12,hi16(EXT(hash_table_size))		; Get hash table size address
			ori		r11,r11,lo16(EXT(hash_table_base))	; Get hash table base address
			ori		r12,r12,lo16(EXT(hash_table_size))	; Get hash table size address
			ld		r11,0(r11)					; Get hash table base
			lwz		r12,0(r12)					; Get hash table size
			cntlzw	r10,r12						; Get the number of bits
			subfic	r10,r10,13					; Get the extra bits we need
			or		r11,r11,r10					; Add the size field to SDR1
			
			mtsdr1	r11							; Ok, we now have the hash table set up
			sync

			li		r0,0						; Set an SLB slot index of 0
			slbia								; Trash all SLB entries (except for entry 0 that is)
			slbmfee	r7,r0						; Get the entry that is in SLB index 0
			rldicr	r7,r7,0,35					; Clear the valid bit and the rest
			slbie	r7							; Invalidate it

			blr									; Return...


;
;			This routine turns on translation for the first time on a processor
;

			.align	5
			.globl	EXT(hw_start_trans)

LEXT(hw_start_trans)

			
			mfmsr	r10							; Get the msr
			ori		r10,r10,lo16(MASK(MSR_IR) | MASK(MSR_DR))	; Turn on translation

			mtmsr	r10							; Everything falls apart here
			isync
			
			blr									; Back to it.



;
;			This routine validates a segment register.
;				hw_map_seg(pmap_t pmap, addr64_t seg, addr64_t va)
;
;				r3 = virtual pmap
;				r4 = segment[0:31]
;				r5 = segment[32:63]
;				r6 = va[0:31]
;				r7 = va[32:63]
;
;			Note that we transform the addr64_t (long long) parameters into single 64-bit values.
;			Note that there is no reason to apply the key modifier here because this is only
;			used for kernel accesses.
;

			.align	5
			.globl	EXT(hw_map_seg)

LEXT(hw_map_seg)

			lwz		r0,pmapSpace(r3)			; Get the space, we will need it soon
			lwz		r9,pmapFlags(r3)			; Get the flags for the keys now
 			mfsprg	r10,2						; Get feature flags 

;
;			Note: the following code would problably be easier to follow if I split it,
;			but I just wanted to see if I could write this to work on both 32- and 64-bit
;			machines combined.
;
			
;
;			Here we enter with va[0:31] in r6[0:31] (or r6[32:63] on 64-bit machines)
;			and va[32:63] in r7[0:31] (or r7[32:63] on 64-bit machines)

			rlwinm	r4,r4,0,1,0					; Copy seg[0:31] into r4[0;31] - no-op for 32-bit
			rlwinm	r7,r7,18,14,17				; Slide va[32:35] east to just west of space ID
			mtcrf	0x02,r10					; Move pf64Bit and pfNoMSRirb to cr5 and 6
			srwi	r8,r6,14					; Slide va[0:17] east to just west of the rest
			rlwimi	r7,r6,18,0,13				; Slide va[18:31] east to just west of slid va[32:25]
			rlwimi	r0,r0,14,4,17				; Dup address space ID above itself
			rlwinm	r8,r8,0,1,0					; Dup low part into high (does nothing on 32-bit machines)
			rlwinm	r2,r0,28,0,31				; Rotate rotate low nybble to top of low half
			rlwimi	r2,r2,0,1,0					; Replicate bottom 32 into top 32
			rlwimi	r8,r7,0,0,31				; Join va[0:17] with va[18:35] (just like mr on 32-bit machines)			

			rlwimi	r2,r0,0,4,31				; We should now have 4 copies of the space
												; concatenated together.   There is garbage
												; at the top for 64-bit but we will clean
												; that out later.
			rlwimi	r4,r5,0,0,31				; Copy seg[32:63] into r4[32:63] - just like mr for 32-bit

			
;
;			Here we exit with va[0:35] shifted into r8[14:51], zeros elsewhere, or
;			va[18:35] shifted into r8[0:17], zeros elsewhere on 32-bit machines
;			
												
;
;			What we have now is:
;
;					 0        0        1        2        3        4        4        5      6
;					 0        8        6        4        2        0        8        6      3	- for 64-bit machines
;					+--------+--------+--------+--------+--------+--------+--------+--------+
;			r2 =	|xxxx0000|AAAAAAAA|AAAAAABB|BBBBBBBB|BBBBCCCC|CCCCCCCC|CCDDDDDD|DDDDDDDD|	- hash value
;					+--------+--------+--------+--------+--------+--------+--------+--------+
;														 0        0        1        2      3	- for 32-bit machines
;														 0        8        6        4      1
;
;					 0        0        1        2        3        4        4        5      6
;					 0        8        6        4        2        0        8        6      3	- for 64-bit machines
;					+--------+--------+--------+--------+--------+--------+--------+--------+
;			r8 =	|00000000|000000SS|SSSSSSSS|SSSSSSSS|SSSSSSSS|SSSSSSSS|SS000000|00000000|	- shifted and cleaned EA
;					+--------+--------+--------+--------+--------+--------+--------+--------+
;														 0        0        1        2      3	- for 32-bit machines
;														 0        8        6        4      1
;
;					 0        0        1        2        3        4        4        5      6
;					 0        8        6        4        2        0        8        6      3	- for 64-bit machines
;					+--------+--------+--------+--------+--------+--------+--------+--------+
;			r4 =	|SSSSSSSS|SSSSSSSS|SSSSSSSS|SSSSSSSS|SSSS0000|00000000|00000000|00000000|	- Segment
;					+--------+--------+--------+--------+--------+--------+--------+--------+
;														 0        0        1        2      3	- for 32-bit machines
;														 0        8        6        4      1


			xor		r8,r8,r2					; Calculate VSID
			
			bf--	pf64Bitb,hms32bit			; Skip out if 32-bit...
			mfsprg	r12,0						; Get the per_proc
			li		r0,1						; Prepare to set bit 0 (also to clear EE)
			mfmsr	r6							; Get current MSR
			li		r2,MASK(MSR_IR)|MASK(MSR_DR)	; Get the translation bits
			mtmsrd	r0,1						; Set only the EE bit to 0
			rlwinm	r6,r6,0,MSR_EE_BIT,MSR_EE_BIT	; See if EE bit is on
			mfmsr	r11							; Get the MSR right now, after disabling EE
			andc	r2,r11,r2					; Turn off translation now
			rldimi	r2,r0,63,0					; Get bit 64-bit turned on
			or		r11,r11,r6					; Turn on the EE bit if it was on
			mtmsrd	r2							; Make sure translation and EE are off and 64-bit is on
			isync								; Hang out a bit
						
			ld		r6,validSegs(r12)			; Get the valid SLB entry flags
			sldi	r9,r9,9						; Position the key and noex bit
			
			rldimi	r5,r8,12,0					; Form the VSID/key
			
			not		r3,r6						; Make valids be 0s
			
			cntlzd	r7,r3						; Find a free SLB	
			cmplwi	r7,63						; Did we find a free SLB entry?		
			
			slbie	r4							; Since this ESID may still be in an SLBE, kill it

			oris	r4,r4,0x0800				; Turn on the valid bit in ESID
			addi	r7,r7,1						; Make sure we skip slb 0
			blt++	hmsFreeSeg					; Yes, go load it...

;
;			No free SLB entries, select one that is in use and invalidate it
;
			lwz		r2,ppSegSteal(r12)			; Get the next slot to steal
			addi	r7,r2,pmapSegCacheUse+1		; Select stealee from non-cached slots only
			addi	r2,r2,1						; Set next slot to steal
			slbmfee	r3,r7						; Get the entry that is in the selected spot
			subi	r8,r2,64-(pmapSegCacheUse+1)	; Force steal to wrap
			rldicr	r3,r3,0,35					; Clear the valid bit and the rest
			srawi	r8,r8,31					; Get -1 if steal index still in range
			slbie	r3							; Invalidate the in-use SLB entry
			and		r2,r2,r8					; Reset steal index when it should wrap
			isync								; 
			
			stw		r2,ppSegSteal(r12)			; Set the next slot to steal
;
;			We are now ready to stick the SLB entry in the SLB and mark it in use
;

hmsFreeSeg:	subi	r2,r7,1						; Adjust for skipped slb 0
			rldimi	r4,r7,0,58					; Copy in the SLB entry selector
			srd		r0,r0,r2					; Set bit mask for allocation
			rldicl	r5,r5,0,15					; Clean out the unsupported bits
			or		r6,r6,r0					; Turn on the allocation flag
			
			slbmte	r5,r4						; Make that SLB entry

			std		r6,validSegs(r12)			; Mark as valid
			mtmsrd	r11							; Restore the MSR
			isync
			blr									; Back to it...

			.align	5

hms32bit:
			mfsprg	r12,1						; Get the current activation
			lwz		r12,ACT_PER_PROC(r12)		; Get the per_proc block
			rlwinm	r8,r8,0,8,31				; Clean up the VSID
			rlwinm	r2,r4,4,28,31				; Isolate the segment we are setting
			lis		r0,0x8000					; Set bit 0
			rlwimi	r8,r9,28,1,3				; Insert the keys and N bit			
			srw		r0,r0,r2					; Get bit corresponding to SR
			addi	r7,r12,validSegs			; Point to the valid segment flags directly
		
			mtsrin	r8,r4						; Set the actual SR	
			isync								; Need to make sure this is done
		
hmsrupt:	lwarx	r6,0,r7						; Get and reserve the valid segment flags
			or		r6,r6,r0					; Show that SR is valid
			stwcx.	r6,0,r7						; Set the valid SR flags
			bne--	hmsrupt						; Had an interrupt, need to get flags again...

			blr									; Back to it...


;
;			This routine invalidates a segment register.
;

			.align	5
			.globl	EXT(hw_blow_seg)

LEXT(hw_blow_seg)

 			mfsprg	r10,2						; Get feature flags 
			mtcrf	0x02,r10					; move pf64Bit and pfNoMSRirb to cr5 and 6
		
			rlwinm	r9,r4,0,0,3					; Save low segment address and make sure it is clean
			
			bf--	pf64Bitb,hbs32bit			; Skip out if 32-bit...
			
			li		r0,1						; Prepare to set bit 0 (also to clear EE)
			mfmsr	r6							; Get current MSR
			li		r2,MASK(MSR_IR)|MASK(MSR_DR)	; Get the translation bits
			mtmsrd	r0,1						; Set only the EE bit to 0
			rlwinm	r6,r6,0,MSR_EE_BIT,MSR_EE_BIT	; See if EE bit is on
			mfmsr	r11							; Get the MSR right now, after disabling EE
			andc	r2,r11,r2					; Turn off translation now
			rldimi	r2,r0,63,0					; Get bit 64-bit turned on
			or		r11,r11,r6					; Turn on the EE bit if it was on
			mtmsrd	r2							; Make sure translation and EE are off and 64-bit is on
			isync								; Hang out a bit

			rldimi	r9,r3,32,0					; Insert the top part of the ESID
			
			slbie	r9							; Invalidate the associated SLB entry
			
			mtmsrd	r11							; Restore the MSR
			isync
			blr									; Back to it.

			.align	5

hbs32bit:
			mfsprg	r12,1						; Get the current activation
			lwz		r12,ACT_PER_PROC(r12)		; Get the per_proc block
			addi	r7,r12,validSegs			; Point to the valid segment flags directly
			lwarx	r4,0,r7						; Get and reserve the valid segment flags
			rlwinm	r6,r9,4,28,31				; Convert segment to number
			lis		r2,0x8000					; Set up a mask
			srw		r2,r2,r6					; Make a mask
			and.	r0,r4,r2					; See if this is even valid
			li		r5,invalSpace				; Set the invalid address space VSID
			beqlr								; Leave if already invalid...
			
			mtsrin	r5,r9						; Slam the segment register
			isync								; Need to make sure this is done
		
hbsrupt:	andc	r4,r4,r2					; Clear the valid bit for this segment
			stwcx.	r4,0,r7						; Set the valid SR flags
			beqlr++								; Stored ok, no interrupt, time to leave...
			
			lwarx	r4,0,r7						; Get and reserve the valid segment flags again
			b		hbsrupt						; Try again...

;
;			This routine invadates the entire pmap segment cache
;
;			Translation is on, interrupts may or may not be enabled.
;

			.align	5
			.globl	EXT(invalidateSegs)

LEXT(invalidateSegs)

			la		r10,pmapCCtl(r3)			; Point to the segment cache control
			eqv		r2,r2,r2					; Get all foxes
			
isInv:		lwarx	r4,0,r10					; Get the segment cache control value
			rlwimi	r4,r2,0,0,15				; Slam in all invalid bits
			rlwinm.	r0,r4,0,pmapCCtlLckb,pmapCCtlLckb	; Is it already locked?
			bne--	isInv0						; Yes, try again...
			
			stwcx.	r4,0,r10					; Try to invalidate it
			bne--	isInv						; Someone else just stuffed it...
			blr									; Leave...
			

isInv0:		li		r4,lgKillResv				; Get reservation kill zone
			stwcx.	r4,0,r4						; Kill reservation

isInv1:		lwz		r4,pmapCCtl(r3)				; Get the segment cache control
			rlwinm.	r0,r4,0,pmapCCtlLckb,pmapCCtlLckb	; Is it already locked?
			bne--	isInv						; Nope...
			b		isInv1						; Still locked do it again...
			
;
;			This routine switches segment registers between kernel and user.
;			We have some assumptions and rules:
;				We are in the exception vectors
;				pf64Bitb is set up
;				R3 contains the MSR we going to
;				We can not use R4, R13, R20, R21, R29
;				R13 is the savearea
;				R29 has the per_proc
;
;			We return R3 as 0 if we did not switch between kernel and user
;			We also maintain and apply the user state key modifier used by VMM support;	
;			If we go to the kernel it is set to 0, otherwise it follows the bit 
;			in spcFlags.
;

			.align	5
			.globl	EXT(switchSegs)

LEXT(switchSegs)

			lwz		r22,ppInvSeg(r29)			; Get the ppInvSeg (force invalidate) and ppCurSeg (user or kernel segments indicator)
			lwz		r9,spcFlags(r29)			; Pick up the special user state flags
			rlwinm	r2,r3,MSR_PR_BIT+1,31,31	; Isolate the problem mode bit
			rlwinm	r3,r3,MSR_RI_BIT+1,31,31	; Isolate the recoverable interrupt bit
			lis		r8,hi16(EXT(kernel_pmap_phys))	; Assume kernel
			or		r2,r2,r3					; This will 1 if we will be using user segments
			li		r3,0						; Get a selection mask
			cmplw	r2,r22						; This will be EQ if same state and not ppInvSeg
			ori		r8,r8,lo16(EXT(kernel_pmap_phys))	; Assume kernel (bottom of address)
			sub		r3,r3,r2					; Form select mask - 0 if kernel, -1 if user
			la		r19,ppUserPmap(r29)			; Point to the current user pmap

;			The following line is an exercise of a generally unreadable but recompile-friendly programing practice
			rlwinm	r30,r9,userProtKeybit+1+(63-sgcVSKeyUsr),sgcVSKeyUsr-32,sgcVSKeyUsr-32	; Isolate the user state protection key 

			andc	r8,r8,r3					; Zero kernel pmap ptr if user, untouched otherwise
			and		r19,r19,r3					; Zero user pmap ptr if kernel, untouched otherwise
			and		r30,r30,r3					; Clear key modifier if kernel, leave otherwise
			or		r8,r8,r19					; Get the pointer to the pmap we are using

			beqlr								; We are staying in the same mode, do not touch segs...

			lwz		r28,0(r8)					; Get top half of pmap address
			lwz		r10,4(r8)					; Get bottom half

			stw		r2,ppInvSeg(r29)			; Clear request for invalidate and save ppCurSeg
			rlwinm	r28,r28,0,1,0				; Copy top to top
			stw		r30,ppMapFlags(r29)			; Set the key modifier
			rlwimi	r28,r10,0,0,31				; Insert bottom
			
			la		r10,pmapCCtl(r28)			; Point to the segment cache control
			la		r9,pmapSegCache(r28)		; Point to the segment cache

ssgLock:	lwarx	r15,0,r10					; Get and reserve the segment cache control
			rlwinm.	r0,r15,0,pmapCCtlLckb,pmapCCtlLckb	; Someone have the lock?
			ori		r16,r15,lo16(pmapCCtlLck)	; Set lock bit
			bne--	ssgLock0					; Yup, this is in use...

			stwcx.	r16,0,r10					; Try to set the lock
			bne--	ssgLock						; Did we get contention?
			
			not		r11,r15						; Invert the invalids to valids
			li		r17,0						; Set a mask for the SRs we are loading
			isync								; Make sure we are all caught up

			bf--	pf64Bitb,ssg32Enter			; If 32-bit, jump into it...
		
			li		r0,0						; Clear
			slbia								; Trash all SLB entries (except for entry 0 that is)
			li		r17,1						; Get SLB index to load (skip slb 0)
			oris	r0,r0,0x8000				; Get set for a mask
			b		ssg64Enter					; Start on a cache line...

			.align	5

ssgLock0:	li		r15,lgKillResv				; Killing field
			stwcx.	r15,0,r15					; Kill reservation

ssgLock1:	lwz		r15,pmapCCtl(r28)			; Get the segment cache controls
			rlwinm.	r15,r15,0,pmapCCtlLckb,pmapCCtlLckb	; Someone have the lock?
			beq++	ssgLock						; Yup, this is in use...
			b		ssgLock1					; Nope, try again...
;
;			This is the 32-bit address space switch code.
;			We take a reservation on the segment cache and walk through.
;			For each entry, we load the specified entries and remember which
;			we did with a mask.  Then, we figure out which segments should be
;			invalid and then see which actually are.  Then we load those with the
;			defined invalid VSID. 
;			Afterwards, we unlock the segment cache.
;

			.align	5

ssg32Enter:	cntlzw	r12,r11						; Find the next slot in use
			cmplwi	r12,pmapSegCacheUse			; See if we are done
			slwi	r14,r12,4					; Index to the cache slot
			lis		r0,0x8000					; Get set for a mask
			add		r14,r14,r9					; Point to the entry
		
			bge-	ssg32Done					; All done...
		
			lwz		r5,sgcESID+4(r14)			; Get the ESID part
			srw		r2,r0,r12					; Form a mask for the one we are loading
			lwz		r7,sgcVSID+4(r14)			; And get the VSID bottom

			andc	r11,r11,r2					; Clear the bit
			lwz		r6,sgcVSID(r14)				; And get the VSID top

			rlwinm	r2,r5,4,28,31				; Change the segment number to a number

			xor		r7,r7,r30					; Modify the key before we actually set it
			srw		r0,r0,r2					; Get a mask for the SR we are loading
			rlwinm	r8,r7,19,1,3				; Insert the keys and N bit			
			or		r17,r17,r0					; Remember the segment
			rlwimi	r8,r7,20,12,31				; Insert 4:23 the VSID
			rlwimi	r8,r6,20,8,11				; Get the last nybble of the SR contents			

			mtsrin	r8,r5						; Load the segment
			b		ssg32Enter					; Go enter the next...
			
			.align	5
			
ssg32Done:	lwz		r16,validSegs(r29)			; Get the valid SRs flags
			stw		r15,pmapCCtl(r28)			; Unlock the segment cache controls

			lis		r0,0x8000					; Get set for a mask
			li		r2,invalSpace				; Set the invalid address space VSID

			nop									; Align loop
			nop									; Align loop
			andc	r16,r16,r17					; Get list of SRs that were valid before but not now
			nop									; Align loop

ssg32Inval:	cntlzw	r18,r16						; Get the first one to invalidate
			cmplwi	r18,16						; Have we finished?
			srw		r22,r0,r18					; Get the mask bit
			rlwinm	r23,r18,28,0,3				; Get the segment register we need
			andc	r16,r16,r22					; Get rid of the guy we just did
			bge		ssg32Really					; Yes, we are really done now...

			mtsrin	r2,r23						; Invalidate the SR
			b		ssg32Inval					; Do the next...
			
			.align	5

ssg32Really:
			stw		r17,validSegs(r29)			; Set the valid SR flags
			li		r3,1						; Set kernel/user transition
			blr

;
;			This is the 64-bit address space switch code.
;			First we blow away all of the SLB entries.
;			Walk through,
;			loading the SLB.  Afterwards, we release the cache lock
;
;			Note that because we have to treat SLBE 0 specially, we do not ever use it...
;			Its a performance thing...
;

			.align	5

ssg64Enter:	cntlzw	r12,r11						; Find the next slot in use
			cmplwi	r12,pmapSegCacheUse			; See if we are done
			slwi	r14,r12,4					; Index to the cache slot
			srw		r16,r0,r12					; Form a mask for the one we are loading
			add		r14,r14,r9					; Point to the entry
			andc	r11,r11,r16					; Clear the bit
			bge--	ssg64Done					; All done...

			ld		r5,sgcESID(r14)				; Get the ESID part
			ld		r6,sgcVSID(r14)				; And get the VSID part
			oris	r5,r5,0x0800				; Turn on the valid bit
			or		r5,r5,r17					; Insert the SLB slot
			xor		r6,r6,r30					; Modify the key before we actually set it
			addi	r17,r17,1					; Bump to the next slot
			slbmte	r6,r5						; Make that SLB entry
			b		ssg64Enter					; Go enter the next...
			
			.align	5
			
ssg64Done:	stw		r15,pmapCCtl(r28)			; Unlock the segment cache controls

			eqv		r16,r16,r16					; Load up with all foxes
			subfic	r17,r17,64					; Get the number of 1 bits we need

			sld		r16,r16,r17					; Get a mask for the used SLB entries
			li		r3,1						; Set kernel/user transition
			std		r16,validSegs(r29)			; Set the valid SR flags
			blr

;
;			mapSetUp - this function sets initial state for all mapping functions.
;			We turn off all translations (physical), disable interruptions, and 
;			enter 64-bit mode if applicable.
;
;			We also return the original MSR in r11, the feature flags in R12,
;			and CR6 set up so we can do easy branches for 64-bit
;			hw_clear_maps assumes r10, r9 will not be trashed.
;

			.align	5
			.globl	EXT(mapSetUp)

LEXT(mapSetUp)

			lis		r0,hi16(MASK(MSR_VEC))		; Get the vector mask
 			mfsprg	r12,2						; Get feature flags 
 			ori		r0,r0,lo16(MASK(MSR_FP))	; Get the FP as well
			mtcrf	0x04,r12					; move pf64Bit and pfNoMSRirb to cr5 and 6
			mfmsr	r11							; Save the MSR 
			mtcrf	0x02,r12					; move pf64Bit and pfNoMSRirb to cr5 and 6
			andc	r11,r11,r0					; Clear VEC and FP for good
			ori		r0,r0,lo16(MASK(MSR_EE)|MASK(MSR_DR)|MASK(MSR_IR))	; Get rid of EE, IR, and DR
			li		r2,1						; Prepare for 64 bit
			andc	r0,r11,r0					; Clear the rest
			bt		pfNoMSRirb,msuNoMSR			; No MSR...
			bt++	pf64Bitb,msuSF				; skip if 64-bit (only they take the hint)

			mtmsr	r0							; Translation and all off
			isync								; Toss prefetch
			blr									; Return...

			.align	5

msuSF:		rldimi	r0,r2,63,MSR_SF_BIT			; set SF bit (bit 0)
			mtmsrd	r0							; set 64-bit mode, turn off EE, DR, and IR
			isync								; synchronize
			blr									; Return...

			.align	5

msuNoMSR:	mr		r2,r3						; Save R3 across call
			mr		r3,r0						; Get the new MSR value
			li		r0,loadMSR					; Get the MSR setter SC
			sc									; Set it
			mr		r3,r2						; Restore R3
			blr									; Go back all set up...
			

;
;			Guest shadow assist -- remove all guest mappings
;
;			Remove all mappings for a guest pmap from the shadow hash table.
;
;			Parameters:
;				r3 : address of pmap, 32-bit kernel virtual address
;
;			Non-volatile register usage:
;				r24 : host pmap's physical address
;				r25 : VMM extension block's physical address
;				r26 : physent address
;				r27 : guest pmap's space ID number
;				r28 : current hash table page index
;				r29 : guest pmap's physical address
;				r30 : saved msr image
;				r31 : current mapping
;
			.align	5
			.globl	EXT(hw_rem_all_gv)
			
LEXT(hw_rem_all_gv)

#define graStackSize ((31-24+1)*4)+4
			stwu	r1,-(FM_ALIGN(graStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(graStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25
			stw		r24,FM_ARG0+0x1C(r1)		; Save non-volatile r24
												
			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr

			bt++	pf64Bitb,gra64Salt			; Test for 64-bit machine
			lwz		r25,pmapVmmExtPhys+4(r3)	; r25 <- VMM pmap extension block paddr
			lwz		r9,pmapvr+4(r3)				; Get 32-bit virt<->real conversion salt
			lwz		r24,vmxHostPmapPhys+4(r11)	; r24 <- host pmap's paddr
			b		graStart					; Get to it			
gra64Salt:	ld		r25,pmapVmmExtPhys(r3)		; r25 <- VMM pmap extension block paddr
			ld		r9,pmapvr(r3)				; Get 64-bit virt<->real conversion salt
			ld		r24,vmxHostPmapPhys(r11)	; r24 <- host pmap's paddr
graStart:	bl		EXT(mapSetUp)				; Disable 'rupts, translation, enter 64-bit mode
			xor		r29,r3,r9					; Convert pmap_t virt->real
			mr		r30,r11						; Save caller's msr image

			la		r3,pmapSXlk(r24)			; r3 <- host pmap's search lock
			bl		sxlkExclusive				; Get lock exclusive
			
			lwz		r3,vxsGra(r25)				; Get remove all count
			addi	r3,r3,1						; Increment remove all count
			stw		r3,vxsGra(r25)				; Update remove all count

			li		r28,0						; r28 <- first hash page table index to search
			lwz		r27,pmapSpace(r29)			; r27 <- guest pmap's space ID number
graPgLoop:	
			la		r31,VMX_HPIDX_OFFSET(r25)	; Get base of hash page physical index
			rlwinm	r11,r28,GV_PGIDX_SZ_LG2,GV_HPAGE_MASK
												; Convert page index into page physical index offset
			add		r31,r31,r11					; Calculate page physical index entry address
			bt++	pf64Bitb,gra64Page			; Separate handling for 64-bit
			lwz		r31,4(r31)					; r31 <- first slot in hash table page to examine
			b		graLoop						; Examine all slots in this page
gra64Page:	ld		r31,0(r31)					; r31 <- first slot in hash table page to examine
			b		graLoop						; Examine all slots in this page

			.align	5
graLoop:	lwz		r3,mpFlags(r31)				; Get mapping's flags
			lhz		r4,mpSpace(r31)				; Get mapping's space ID number
			rlwinm	r6,r3,0,mpgFree				; Isolate guest free mapping flag
			xor		r4,r4,r27					; Compare space ID number
			or.		r0,r6,r4					; cr0_eq <- !free && space id match
			bne		graMiss						; Not one of ours, skip it
			
			lwz		r11,vxsGraHits(r25)			; Get remove hit count
			addi	r11,r11,1					; Increment remove hit count
			stw		r11,vxsGraHits(r25)			; Update remove hit count

			rlwinm.	r0,r3,0,mpgDormant			; Is this entry dormant?
			bne		graRemPhys					; Yes, nothing to disconnect
			
			lwz		r11,vxsGraActive(r25)		; Get remove active count
			addi	r11,r11,1					; Increment remove hit count
			stw		r11,vxsGraActive(r25)		; Update remove hit count

			bt++	pf64Bitb,graDscon64			; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		graFreePTE					; Join 64-bit path to release the PTE			
graDscon64:	bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
graFreePTE: mr.		r3,r3						; Was there a valid PTE?
			beq-	graRemPhys					; No valid PTE, we're almost done
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE pointer
			rlwinm	r8,r8,0,~mpHValid			; Make the pointer invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE pointer
			eieio								; Synchronize all previous updates (mapInvPtexx doesn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG
			
graRemPhys:
			lwz		r3,mpPAddr(r31)				; r3 <- physical 4K-page number
			bl		mapFindLockPN				; Find 'n' lock this page's physent
			mr.		r26,r3						; Got lock on our physent?
			beq--	graBadPLock					; No, time to bail out

			crset	cr1_eq						; cr1_eq <- previous link is the anchor
			bt++	pf64Bitb,graRemove64		; Use 64-bit version on 64-bit machine
			la		r11,ppLink+4(r26)			; Point to chain anchor
			lwz		r9,ppLink+4(r26)			; Get chain anchor
			rlwinm.	r9,r9,0,~ppFlags			; Remove flags, yielding 32-bit physical chain pointer

graRemLoop:	beq-	graRemoveMiss				; End of chain, this is not good
			cmplw	r9,r31						; Is this the mapping to remove?
			lwz		r8,mpAlias+4(r9)			; Get forward chain pointer
			bne		graRemNext					; No, chain onward
			bt		cr1_eq,graRemRetry			; Mapping to remove is chained from anchor
			stw		r8,0(r11)					; Unchain gpv->phys mapping
			b		graRemoved					; Exit loop
graRemRetry:
			lwarx	r0,0,r11					; Get previous link
			rlwimi	r0,r8,0,~ppFlags			; Insert new forward pointer whilst preserving flags
			stwcx.	r0,0,r11					; Update previous link
			bne-	graRemRetry					; Lost reservation, retry
			b		graRemoved					; Good work, let's get outta here
			
graRemNext:	la		r11,mpAlias+4(r9)			; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		graRemLoop					; Carry on

graRemove64:
			li		r7,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r7,r7,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			la		r11,ppLink(r26)				; Point to chain anchor
			ld		r9,ppLink(r26)				; Get chain anchor
			andc.	r9,r9,r7					; Remove flags, yielding 64-bit physical chain pointer
graRem64Lp:	beq--	graRemoveMiss				; End of chain, this is not good
			cmpld	r9,r31						; Is this the mapping to remove?
			ld		r8,mpAlias(r9)				; Get forward chain pinter
			bne		graRem64Nxt					; Not mapping to remove, chain on, dude
			bt		cr1_eq,graRem64Rt			; Mapping to remove is chained from anchor
			std		r8,0(r11)					; Unchain gpv->phys mapping
			b		graRemoved					; Exit loop
graRem64Rt:	ldarx	r0,0,r11					; Get previous link
			and		r0,r0,r7					; Get flags
			or		r0,r0,r8					; Insert new forward pointer
			stdcx.	r0,0,r11					; Slam it back in
			bne--	graRem64Rt					; Lost reservation, retry
			b		graRemoved					; Good work, let's go home
		
graRem64Nxt:
			la		r11,mpAlias(r9)				; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		graRem64Lp					; Carry on

graRemoved:
			mr		r3,r26						; r3 <- physent's address
			bl		mapPhysUnlock				; Unlock the physent (and its chain of mappings)
			
			lwz		r3,mpFlags(r31)				; Get mapping's flags
			rlwinm	r3,r3,0,~mpgFlags			; Clear all guest flags
			ori		r3,r3,mpgFree				; Mark mapping free
			stw		r3,mpFlags(r31)				; Update flags
			
graMiss:	addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping
			rlwinm.	r0,r31,0,GV_PAGE_MASK		; End of hash table page?
			bne		graLoop						; No, examine next slot
			addi	r28,r28,1					; Increment hash table page index
			cmplwi	r28,GV_HPAGES				; End of hash table?
			bne		graPgLoop					; Examine next hash table page
			
			la		r3,pmapSXlk(r24)			; r3 <- host pmap's search lock
			bl		sxlkUnlock					; Release host pmap's search lock
			
			bt++	pf64Bitb,graRtn64			; Handle 64-bit separately
			mtmsr	r30							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		graPopFrame					; Nothing to do now but pop a frame and return
graRtn64:	mtmsrd	r30							; Restore 'rupts, translation, 32-bit mode
graPopFrame:		
			lwz		r0,(FM_ALIGN(graStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r24,FM_ARG0+0x1C(r1)		; Restore non-volatile r24
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

graBadPLock:
graRemoveMiss:
			lis		r0,hi16(Choke)				; Dmitri, you know how we've always talked about the
			ori		r0,r0,lo16(Choke)			;  possibility of something going wrong with the bomb?
			li		r3,failMapping				; The BOMB, Dmitri.
			sc									; The hydrogen bomb.


;
;			Guest shadow assist -- remove local guest mappings
;
;			Remove local mappings for a guest pmap from the shadow hash table.
;
;			Parameters:
;				r3 : address of guest pmap, 32-bit kernel virtual address
;
;			Non-volatile register usage:
;				r20 : current active map word's physical address
;				r21 : current hash table page address
;				r22 : updated active map word in process
;				r23 : active map word in process
;				r24 : host pmap's physical address
;				r25 : VMM extension block's physical address
;				r26 : physent address
;				r27 : guest pmap's space ID number
;				r28 : current active map index
;				r29 : guest pmap's physical address
;				r30 : saved msr image
;				r31 : current mapping
;
			.align	5
			.globl	EXT(hw_rem_local_gv)
			
LEXT(hw_rem_local_gv)

#define grlStackSize ((31-20+1)*4)+4
			stwu	r1,-(FM_ALIGN(grlStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(grlStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25
			stw		r24,FM_ARG0+0x1C(r1)		; Save non-volatile r24
			stw		r23,FM_ARG0+0x20(r1)		; Save non-volatile r23
			stw		r22,FM_ARG0+0x24(r1)		; Save non-volatile r22
			stw		r21,FM_ARG0+0x28(r1)		; Save non-volatile r21
			stw		r20,FM_ARG0+0x2C(r1)		; Save non-volatile r20
												
			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr

			bt++	pf64Bitb,grl64Salt			; Test for 64-bit machine
			lwz		r25,pmapVmmExtPhys+4(r3)	; r25 <- VMM pmap extension block paddr
			lwz		r9,pmapvr+4(r3)				; Get 32-bit virt<->real conversion salt
			lwz		r24,vmxHostPmapPhys+4(r11)	; r24 <- host pmap's paddr
			b		grlStart					; Get to it			
grl64Salt:	ld		r25,pmapVmmExtPhys(r3)		; r25 <- VMM pmap extension block paddr
			ld		r9,pmapvr(r3)				; Get 64-bit virt<->real conversion salt
			ld		r24,vmxHostPmapPhys(r11)	; r24 <- host pmap's paddr

grlStart:	bl		EXT(mapSetUp)				; Disable 'rupts, translation, enter 64-bit mode
			xor		r29,r3,r9					; Convert pmap_t virt->real
			mr		r30,r11						; Save caller's msr image

			la		r3,pmapSXlk(r24)			; r3 <- host pmap's search lock
			bl		sxlkExclusive				; Get lock exclusive

			li		r28,0						; r28 <- index of first active map word to search
			lwz		r27,pmapSpace(r29)			; r27 <- guest pmap's space ID number
			b		grlMap1st					; Examine first map word

			.align	5
grlNextMap:	stw		r22,0(r21)					; Save updated map word
			addi	r28,r28,1					; Increment map word index
			cmplwi	r28,GV_MAP_WORDS			; See if we're done
			beq		grlDone						; Yup, let's get outta here

grlMap1st:	la		r20,VMX_ACTMAP_OFFSET(r25)	; Get base of active map word array
			rlwinm	r11,r28,GV_MAPWD_SZ_LG2,GV_MAP_MASK
												; Convert map index into map index offset
			add		r20,r20,r11					; Calculate map array element address
			lwz		r22,0(r20)					; Get active map word at index
			mr.		r23,r22						; Any active mappings indicated?
			beq		grlNextMap					; Nope, check next word
			
			la		r21,VMX_HPIDX_OFFSET(r25)	; Get base of hash page physical index
			rlwinm	r11,r28,GV_MAP_SHIFT,GV_HPAGE_MASK
												; Extract page index from map word index and convert
												;  into page physical index offset
			add		r21,r21,r11					; Calculate page physical index entry address
			bt++	pf64Bitb,grl64Page			; Separate handling for 64-bit
			lwz		r21,4(r21)					; Get selected hash table page's address
			b		grlLoop						; Examine all slots in this page
grl64Page:	ld		r21,0(r21)					; Get selected hash table page's address
			b		grlLoop						; Examine all slots in this page
			
			.align	5
grlLoop:	cntlzw	r11,r23						; Get next active bit lit in map word
			cmplwi	r11,32						; Any active mappings left in this word?
			lis		r12,0x8000					; Prepare mask to reset bit
			srw		r12,r12,r11					; Position mask bit
			andc	r23,r23,r12					; Reset lit bit
			beq		grlNextMap					; No bits lit, examine next map word						

			slwi	r31,r11,GV_SLOT_SZ_LG2		; Get slot offset in slot band from lit bit number
			rlwinm	r31,r28,GV_BAND_SHIFT,GV_BAND_MASK
												; Extract slot band number from index and insert
			add		r31,r31,r21					; Add hash page address yielding mapping slot address

			lwz		r3,mpFlags(r31)				; Get mapping's flags
			lhz		r4,mpSpace(r31)				; Get mapping's space ID number
			rlwinm	r5,r3,0,mpgGlobal			; Extract global bit
			xor		r4,r4,r27					; Compare space ID number
			or.		r4,r4,r5					; (space id miss || global)
			bne		grlLoop						; Not one of ours, skip it
			andc	r22,r22,r12					; Reset active bit corresponding to this mapping
			ori		r3,r3,mpgDormant			; Mark entry dormant
			stw		r3,mpFlags(r31)				; Update mapping's flags

			bt++	pf64Bitb,grlDscon64			; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		grlFreePTE					; Join 64-bit path to release the PTE			
grlDscon64:	bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
grlFreePTE: mr.		r3,r3						; Was there a valid PTE?
			beq-	grlLoop						; No valid PTE, we're done with this mapping
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE pointer
			rlwinm	r8,r8,0,~mpHValid			; Make the pointer invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE pointer
			eieio								; Synchronize all previous updates (mapInvPtexx doesn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG
			b		grlLoop						; On to next active mapping in this map word
						
grlDone:	la		r3,pmapSXlk(r24)			; r3 <- host pmap's search lock
			bl		sxlkUnlock					; Release host pmap's search lock
			
			bt++	pf64Bitb,grlRtn64			; Handle 64-bit separately
			mtmsr	r30							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		grlPopFrame					; Nothing to do now but pop a frame and return
grlRtn64:	mtmsrd	r30							; Restore 'rupts, translation, 32-bit mode
grlPopFrame:		
			lwz		r0,(FM_ALIGN(grlStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r24,FM_ARG0+0x1C(r1)		; Restore non-volatile r24
			lwz		r23,FM_ARG0+0x20(r1)		; Restore non-volatile r23
			lwz		r22,FM_ARG0+0x24(r1)		; Restore non-volatile r22
			lwz		r21,FM_ARG0+0x28(r1)		; Restore non-volatile r21
			lwz		r20,FM_ARG0+0x2C(r1)		; Restore non-volatile r20
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller


;
;			Guest shadow assist -- resume a guest mapping
;
;			Locates the specified dormant mapping, and if it exists validates it and makes it
;			active.
;
;			Parameters:
;				r3 : address of host pmap, 32-bit kernel virtual address
;				r4 : address of guest pmap, 32-bit kernel virtual address
;				r5 : host virtual address, high-order 32 bits
;				r6 : host virtual address,  low-order 32 bits
;				r7 : guest virtual address, high-order 32 bits
;				r8 : guest virtual address,  low-order 32 bits
;				r9 : guest mapping protection code
;
;			Non-volatile register usage:
;				r23 : VMM extension block's physical address
;				r24 : physent physical address
;				r25 : caller's msr image from mapSetUp
;				r26 : guest mapping protection code
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : host virtual address
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;
			.align	5
			.globl	EXT(hw_res_map_gv)
			
LEXT(hw_res_map_gv)

#define grsStackSize ((31-23+1)*4)+4

			stwu	r1,-(FM_ALIGN(grsStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(grsStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25
			stw		r24,FM_ARG0+0x1C(r1)		; Save non-volatile r24
			stw		r23,FM_ARG0+0x20(r1)		; Save non-volatile r23

			rlwinm	r29,r6,0,0xFFFFF000			; Clean up low-order 32 bits of host vaddr
			rlwinm	r30,r8,0,0xFFFFF000			; Clean up low-order 32 bits of guest vaddr
			mr		r26,r9						; Copy guest mapping protection code

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r4)			; r9 <- guest space ID number
			bt++	pf64Bitb,grs64Salt			; Handle 64-bit machine separately
			lwz		r23,pmapVmmExtPhys+4(r3)	; r23 <- VMM pmap extension block paddr
			lwz		r27,pmapvr+4(r3)			; Get 32-bit virt<->real host pmap conversion salt
			lwz		r28,pmapvr+4(r4)			; Get 32-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
			b		grsStart					; Get to it			

grs64Salt:	rldimi	r29,r5,32,0					; Insert high-order 32 bits of 64-bit host vaddr			
			rldimi	r30,r7,32,0					; Insert high-order 32 bits of 64-bit guest vaddr			
			ld		r23,pmapVmmExtPhys(r3)		; r23 <- VMM pmap extension block paddr
			ld		r27,pmapvr(r3)				; Get 64-bit virt<->real host pmap conversion salt
			ld		r28,pmapvr(r4)				; Get 64-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr

grsStart:	xor		r27,r3,r27					; Convert host pmap_t virt->real
			xor		r28,r4,r28					; Convert guest pmap_t virt->real
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r25,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive

			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,grs64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		grs32SrchLp					; Let the search begin!
			
			.align	5
grs32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && space match && virtual addr match
			beq		grsSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	grs32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && space match && virtual addr match
			beq		grsSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		grsSrchMiss					; No joy in our hash group
			
grs64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		grs64SrchLp					; Let the search begin!
			
			.align	5
grs64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && space match && virtual addr match
			beq		grsSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	grs64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && space match && virtual addr match
			bne		grsSrchMiss					; No joy in our hash group
			
grsSrchHit:
			rlwinm.	r0,r6,0,mpgDormant			; Is the mapping dormant?
			bne		grsFindHost					; Yes, nothing to disconnect

			bt++	pf64Bitb,grsDscon64			; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		grsFreePTE					; Join 64-bit path to release the PTE			
grsDscon64:	bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
grsFreePTE: mr.		r3,r3						; Was there a valid PTE?
			beq-	grsFindHost					; No valid PTE, we're almost done
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE pointer
			rlwinm	r8,r8,0,~mpHValid			; Make the pointer invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE pointer
			eieio								; Synchronize all previous updates (mapInvPtexx didn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG

grsFindHost:

// We now have a dormant guest mapping that matches our space id and virtual address. Our next
// step is to locate the host mapping that completes the guest mapping's connection to a physical
// frame. The guest and host mappings must connect to the same physical frame, so they must both
// be chained on the same physent. We search the physent chain for a host mapping matching our
// host's space id and the host virtual address. If we succeed, we know that the entire chain
// of mappings (guest virtual->host virtual->physical) is valid, so the dormant mapping can be
// resumed. If we fail to find the specified host virtual->physical mapping, it is because the
// host virtual or physical address has changed since the guest mapping was suspended, so it
// is no longer valid and cannot be resumed -- we therefore delete the guest mappping and tell
// our caller that it will have to take its long path, translating the host virtual address
// through the host's skiplist and installing a new guest mapping.

			lwz		r3,mpPAddr(r31)				; r3 <- physical 4K-page number
			bl		mapFindLockPN				; Find 'n' lock this page's physent
			mr.		r24,r3						; Got lock on our physent?
			beq--	grsBadPLock					; No, time to bail out
			
			bt++	pf64Bitb,grsPFnd64			; 64-bit version of physent chain search
			
			lwz		r9,ppLink+4(r24)			; Get first mapping on physent
			lwz		r6,pmapSpace(r27)			; Get host pmap's space id number
			rlwinm	r9,r9,0,~ppFlags			; Be-gone, unsightly flags
grsPELoop:	mr.		r12,r9						; Got a mapping to look at?
			beq-	grsPEMiss					; Nope, we've missed hva->phys mapping
			lwz		r7,mpFlags(r12)				; Get mapping's flags
			lhz		r4,mpSpace(r12)				; Get mapping's space id number
			lwz		r5,mpVAddr+4(r12)			; Get mapping's virtual address
			lwz		r9,mpAlias+4(r12)			; Next mapping in physent alias chain
			
			rlwinm	r0,r7,0,mpType				; Isolate mapping's type
			rlwinm	r5,r5,0,~mpHWFlags			; Bye-bye unsightly flags
			xori	r0,r0,mpNormal				; Normal mapping?
			xor		r4,r4,r6					; Compare w/ host space id number
			xor		r5,r5,r29					; Compare w/ host virtual address
			or		r0,r0,r4					; r0 <- (wrong type || !space id)
			or.		r0,r0,r5					; cr0_eq <- (right type && space id hit && hva hit)
			beq		grsPEHit					; Hit
			b		grsPELoop					; Iterate
			
grsPFnd64:	li		r0,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			ld		r9,ppLink(r24)				; Get first mapping on physent
			lwz		r6,pmapSpace(r27)			; Get pmap's space id number
			andc	r9,r9,r0					; Cleanup mapping pointer
grsPELp64:	mr.		r12,r9						; Got a mapping to look at?
			beq--	grsPEMiss					; Nope, we've missed hva->phys mapping
			lwz		r7,mpFlags(r12)				; Get mapping's flags
			lhz		r4,mpSpace(r12)				; Get mapping's space id number
			ld		r5,mpVAddr(r12)				; Get mapping's virtual address
			ld		r9,mpAlias(r12)				; Next mapping physent alias chain
			rlwinm	r0,r7,0,mpType				; Isolate mapping's type
			rldicr	r5,r5,0,mpHWFlagsb-1		; Bye-bye unsightly flags
			xori	r0,r0,mpNormal				; Normal mapping?
			xor		r4,r4,r6					; Compare w/ host space id number
			xor		r5,r5,r29					; Compare w/ host virtual address
			or		r0,r0,r4					; r0 <- (wrong type || !space id)
			or.		r0,r0,r5					; cr0_eq <- (right type && space id hit && hva hit)
			beq		grsPEHit					; Hit
			b		grsPELp64					; Iterate
			
grsPEHit:	lwz		r0,mpVAddr+4(r31)			; Get va byte containing protection bits
			rlwimi	r0,r26,0,mpPP				; Insert new protection bits
			stw		r0,mpVAddr+4(r31)			; Write 'em back

			eieio								; Ensure previous mapping updates are visible
			lwz		r0,mpFlags(r31)				; Get flags
			rlwinm	r0,r0,0,~mpgDormant			; Turn off dormant flag
			stw		r0,mpFlags(r31)				; Set updated flags, entry is now valid
			
			li		r31,mapRtOK					; Indicate success
			b		grsRelPhy					; Exit through physent lock release

grsPEMiss:	crset	cr1_eq						; cr1_eq <- previous link is the anchor
			bt++	pf64Bitb,grsRemove64		; Use 64-bit version on 64-bit machine
			la		r11,ppLink+4(r24)			; Point to chain anchor
			lwz		r9,ppLink+4(r24)			; Get chain anchor
			rlwinm.	r9,r9,0,~ppFlags			; Remove flags, yielding 32-bit physical chain pointer
grsRemLoop:	beq-	grsPEMissMiss				; End of chain, this is not good
			cmplw	r9,r31						; Is this the mapping to remove?
			lwz		r8,mpAlias+4(r9)			; Get forward chain pointer
			bne		grsRemNext					; No, chain onward
			bt		cr1_eq,grsRemRetry			; Mapping to remove is chained from anchor
			stw		r8,0(r11)					; Unchain gpv->phys mapping
			b		grsDelete					; Finish deleting mapping
grsRemRetry:
			lwarx	r0,0,r11					; Get previous link
			rlwimi	r0,r8,0,~ppFlags			; Insert new forward pointer whilst preserving flags
			stwcx.	r0,0,r11					; Update previous link
			bne-	grsRemRetry					; Lost reservation, retry
			b		grsDelete					; Finish deleting mapping
			
			.align	5
grsRemNext:	la		r11,mpAlias+4(r9)			; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		grsRemLoop					; Carry on

grsRemove64:
			li		r7,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r7,r7,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			la		r11,ppLink(r24)				; Point to chain anchor
			ld		r9,ppLink(r24)				; Get chain anchor
			andc.	r9,r9,r7					; Remove flags, yielding 64-bit physical chain pointer
grsRem64Lp:	beq--	grsPEMissMiss				; End of chain, this is not good
			cmpld	r9,r31						; Is this the mapping to remove?
			ld		r8,mpAlias(r9)				; Get forward chain pinter
			bne		grsRem64Nxt					; Not mapping to remove, chain on, dude
			bt		cr1_eq,grsRem64Rt			; Mapping to remove is chained from anchor
			std		r8,0(r11)					; Unchain gpv->phys mapping
			b		grsDelete					; Finish deleting mapping
grsRem64Rt:	ldarx	r0,0,r11					; Get previous link
			and		r0,r0,r7					; Get flags
			or		r0,r0,r8					; Insert new forward pointer
			stdcx.	r0,0,r11					; Slam it back in
			bne--	grsRem64Rt					; Lost reservation, retry
			b		grsDelete					; Finish deleting mapping

			.align	5		
grsRem64Nxt:
			la		r11,mpAlias(r9)				; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		grsRem64Lp					; Carry on
			
grsDelete:
			lwz		r3,mpFlags(r31)				; Get mapping's flags
			rlwinm	r3,r3,0,~mpgFlags			; Clear all guest flags
			ori		r3,r3,mpgFree				; Mark mapping free
			stw		r3,mpFlags(r31)				; Update flags

			li		r31,mapRtNotFnd				; Didn't succeed

grsRelPhy:	mr		r3,r24						; r3 <- physent addr
			bl		mapPhysUnlock				; Unlock physent chain
			
grsRelPmap:	la		r3,pmapSXlk(r27)			; r3 <- host pmap search lock phys addr
			bl		sxlkUnlock					; Release host pmap search lock
			
grsRtn:		mr		r3,r31						; r3 <- result code
			bt++	pf64Bitb,grsRtn64			; Handle 64-bit separately
			mtmsr	r25							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		grsPopFrame					; Nothing to do now but pop a frame and return
grsRtn64:	mtmsrd	r25							; Restore 'rupts, translation, 32-bit mode
grsPopFrame:		
			lwz		r0,(FM_ALIGN(grsStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r24,FM_ARG0+0x1C(r1)		; Restore non-volatile r24
			lwz		r23,FM_ARG0+0x20(r1)		; Restore non-volatile r23
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

			.align	5
grsSrchMiss:
			li		r31,mapRtNotFnd				; Could not locate requested mapping
			b		grsRelPmap					; Exit through host pmap search lock release

grsBadPLock:
grsPEMissMiss:
			lis		r0,hi16(Choke)				; Dmitri, you know how we've always talked about the
			ori		r0,r0,lo16(Choke)			;  possibility of something going wrong with the bomb?
			li		r3,failMapping				; The BOMB, Dmitri.
			sc									; The hydrogen bomb.


;
;			Guest shadow assist -- add a guest mapping
;
;			Adds a guest mapping.
;
;			Parameters:
;				r3 : address of host pmap, 32-bit kernel virtual address
;				r4 : address of guest pmap, 32-bit kernel virtual address
;				r5 : guest virtual address, high-order 32 bits
;				r6 : guest virtual address,  low-order 32 bits (with mpHWFlags)
;				r7 : new mapping's flags
;				r8 : physical address, 32-bit page number
;
;			Non-volatile register usage:
;				r22 : hash group's physical address
;				r23 : VMM extension block's physical address
;				r24 : mapping's flags
;				r25 : caller's msr image from mapSetUp
;				r26 : physent physical address
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : physical address, 32-bit 4k-page number
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;
			
			.align	5
			.globl	EXT(hw_add_map_gv)
			
			
LEXT(hw_add_map_gv)

#define gadStackSize ((31-22+1)*4)+4

			stwu	r1,-(FM_ALIGN(gadStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(gadStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25
			stw		r24,FM_ARG0+0x1C(r1)		; Save non-volatile r24
			stw		r23,FM_ARG0+0x20(r1)		; Save non-volatile r23
			stw		r22,FM_ARG0+0x24(r1)		; Save non-volatile r22

			rlwinm	r30,r5,0,1,0				; Get high-order 32 bits of guest vaddr
			rlwimi	r30,r6,0,0,31				; Get  low-order 32 bits of guest vaddr
			mr		r24,r7						; Copy guest mapping's flags
			mr		r29,r8						; Copy target frame's physical address

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r4)			; r9 <- guest space ID number
			bt++	pf64Bitb,gad64Salt			; Test for 64-bit machine
			lwz		r23,pmapVmmExtPhys+4(r3)	; r23 <- VMM pmap extension block paddr
			lwz		r27,pmapvr+4(r3)			; Get 32-bit virt<->real host pmap conversion salt
			lwz		r28,pmapvr+4(r4)			; Get 32-bit virt<->real guest pmap conversion salt
			la		r22,VMX_HPIDX_OFFSET(r11)	; r22 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r22,r22,r10					; r22 <- hash page index entry
			lwz		r22,4(r22)					; r22 <- hash page paddr
			rlwimi	r22,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r22 <- hash group paddr
			b		gadStart					; Get to it			

gad64Salt:	ld		r23,pmapVmmExtPhys(r3)		; r23 <- VMM pmap extension block paddr
			ld		r27,pmapvr(r3)				; Get 64-bit virt<->real host pmap conversion salt
			ld		r28,pmapvr(r4)				; Get 64-bit virt<->real guest pmap conversion salt
			la		r22,VMX_HPIDX_OFFSET(r11)	; r22 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r22,r22,r10					; r22 <- hash page index entry
			ld		r22,0(r22)					; r22 <- hash page paddr
			insrdi	r22,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r22 <- hash group paddr

gadStart:	xor		r27,r3,r27					; Convert host pmap_t virt->real
			xor		r28,r4,r28					; Convert guest pmap_t virt->real
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r25,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exlusive

			mr		r31,r22						; Prepare to search this group
			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,gad64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			clrrwi	r12,r30,12					; r12 <- virtual address we're searching for
			b		gad32SrchLp					; Let the search begin!
			
			.align	5
gad32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && space match)
			xor		r8,r8,r12					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && space match && virtual addr match
			beq		gadRelPmap					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gad32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && && space match)
			xor		r5,r5,r12					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- free && space match && virtual addr match
			beq		gadRelPmap					; Join common path on hit (r31 points to guest mapping)
			b		gadScan						; No joy in our hash group
			
gad64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			clrrdi	r12,r30,12					; r12 <- virtual address we're searching for
			b		gad64SrchLp					; Let the search begin!
			
			.align	5
gad64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && space match)
			xor		r8,r8,r12					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && space match && virtual addr match
			beq		gadRelPmap					; Hit, let upper-level redrive sort it out
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gad64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			rlwinm	r11,r6,0,mpgFree			; Isolate guest free flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && && space match)
			xor		r5,r5,r12					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && space match && virtual addr match
			bne		gadScan						; No joy in our hash group
			b		gadRelPmap					; Hit, let upper-level redrive sort it out
			
gadScan:	lbz		r12,mpgCursor(r22)			; Get group's cursor
			rlwinm	r12,r12,GV_SLOT_SZ_LG2,(GV_SLOT_MASK << GV_SLOT_SZ_LG2)
												; Prepare to address slot at cursor
			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			or		r2,r22,r12					; r2 <- 1st mapping to search
			lwz		r3,mpFlags(r2)				; r3 <- 1st mapping slot's flags
			li		r11,0						; No dormant entries found yet
			b		gadScanLoop					; Let the search begin!
			
			.align	5
gadScanLoop:
			addi	r12,r12,GV_SLOT_SZ			; Calculate next slot number to search
			rlwinm	r12,r12,0,(GV_SLOT_MASK << GV_SLOT_SZ_LG2)
												; Trim off any carry, wrapping into slot number range
			mr		r31,r2						; r31 <- current mapping's address
			or		r2,r22,r12					; r2 <- next mapping to search
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags(r2)				; r3 <- next mapping slot's flags
			rlwinm.	r0,r6,0,mpgFree				; Test free flag
			bne		gadFillMap					; Join common path on hit (r31 points to free mapping)
			rlwinm	r0,r6,0,mpgDormant			; Dormant entry?
			xori	r0,r0,mpgDormant			; Invert dormant flag
			or.		r0,r0,r11					; Skip all but the first dormant entry we see
			bne		gadNotDorm					; Not dormant or we've already seen one
			mr		r11,r31						; We'll use this dormant entry if we don't find a free one first
gadNotDorm:	bdnz	gadScanLoop					; Iterate

			mr		r31,r2						; r31 <- final mapping's address
			rlwinm.	r0,r6,0,mpgFree				; Test free flag in final mapping
			bne		gadFillMap					; Join common path on hit (r31 points to dormant mapping)
			rlwinm	r0,r6,0,mpgDormant			; Dormant entry?
			xori	r0,r0,mpgDormant			; Invert dormant flag
			or.		r0,r0,r11					; Skip all but the first dormant entry we see
			bne		gadCkDormant				; Not dormant or we've already seen one
			mr		r11,r31						; We'll use this dormant entry if we don't find a free one first

gadCkDormant:
			mr.		r31,r11						; Get dormant mapping, if any, and test
			bne		gadUpCursor					; Go update the cursor, we'll take the dormant entry
			
gadSteal:
			lbz		r12,mpgCursor(r22)			; Get group's cursor
			rlwinm	r12,r12,GV_SLOT_SZ_LG2,(GV_SLOT_MASK << GV_SLOT_SZ_LG2)
												; Prepare to address slot at cursor
			or		r31,r22,r12					; r31 <- address of mapping to steal

			bt++	pf64Bitb,gadDscon64			; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		gadFreePTE					; Join 64-bit path to release the PTE			
gadDscon64:	bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
gadFreePTE: mr.		r3,r3						; Was there a valid PTE?
			beq-	gadUpCursor					; No valid PTE, we're almost done
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE pointer
			rlwinm	r8,r8,0,~mpHValid			; Make the pointer invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE pointer
			eieio								; Synchronize all previous updates (mapInvPtexx didn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG

gadUpCursor:
			rlwinm	r12,r31,(32-GV_SLOT_SZ_LG2),GV_SLOT_MASK
												; Recover slot number from stolen mapping's address
			addi	r12,r12,1					; Increment slot number
			rlwinm	r12,r12,0,GV_SLOT_MASK		; Clip to slot number range
			stb		r12,mpgCursor(r22)			; Update group's cursor

			lwz		r3,mpPAddr(r31)				; r3 <- physical 4K-page number
			bl		mapFindLockPN				; Find 'n' lock this page's physent
			mr.		r26,r3						; Got lock on our physent?
			beq--	gadBadPLock					; No, time to bail out

			crset	cr1_eq						; cr1_eq <- previous link is the anchor
			bt++	pf64Bitb,gadRemove64		; Use 64-bit version on 64-bit machine
			la		r11,ppLink+4(r26)			; Point to chain anchor
			lwz		r9,ppLink+4(r26)			; Get chain anchor
			rlwinm.	r9,r9,0,~ppFlags			; Remove flags, yielding 32-bit physical chain pointer
gadRemLoop:	beq-	gadPEMissMiss				; End of chain, this is not good
			cmplw	r9,r31						; Is this the mapping to remove?
			lwz		r8,mpAlias+4(r9)			; Get forward chain pointer
			bne		gadRemNext					; No, chain onward
			bt		cr1_eq,gadRemRetry			; Mapping to remove is chained from anchor
			stw		r8,0(r11)					; Unchain gpv->phys mapping
			b		gadDelDone					; Finish deleting mapping
gadRemRetry:
			lwarx	r0,0,r11					; Get previous link
			rlwimi	r0,r8,0,~ppFlags			; Insert new forward pointer whilst preserving flags
			stwcx.	r0,0,r11					; Update previous link
			bne-	gadRemRetry					; Lost reservation, retry
			b		gadDelDone					; Finish deleting mapping
			
gadRemNext:	la		r11,mpAlias+4(r9)			; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		gadRemLoop					; Carry on

gadRemove64:
			li		r7,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r7,r7,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			la		r11,ppLink(r26)				; Point to chain anchor
			ld		r9,ppLink(r26)				; Get chain anchor
			andc.	r9,r9,r7					; Remove flags, yielding 64-bit physical chain pointer
gadRem64Lp:	beq--	gadPEMissMiss				; End of chain, this is not good
			cmpld	r9,r31						; Is this the mapping to remove?
			ld		r8,mpAlias(r9)				; Get forward chain pinter
			bne		gadRem64Nxt					; Not mapping to remove, chain on, dude
			bt		cr1_eq,gadRem64Rt			; Mapping to remove is chained from anchor
			std		r8,0(r11)					; Unchain gpv->phys mapping
			b		gadDelDone					; Finish deleting mapping
gadRem64Rt:	ldarx	r0,0,r11					; Get previous link
			and		r0,r0,r7					; Get flags
			or		r0,r0,r8					; Insert new forward pointer
			stdcx.	r0,0,r11					; Slam it back in
			bne--	gadRem64Rt					; Lost reservation, retry
			b		gadDelDone					; Finish deleting mapping

			.align	5		
gadRem64Nxt:
			la		r11,mpAlias(r9)				; Point to (soon to be) previous link
			crclr	cr1_eq						; ~cr1_eq <- Previous link is not the anchor
			mr.		r9,r8						; Does next entry exist?
			b		gadRem64Lp					; Carry on
			
gadDelDone:
			mr		r3,r26						; Get physent address
			bl		mapPhysUnlock				; Unlock physent chain

gadFillMap:
			lwz		r12,pmapSpace(r28)			; Get guest space id number
			li		r2,0						; Get a zero
			stw		r24,mpFlags(r31)			; Set mapping's flags
			sth		r12,mpSpace(r31)			; Set mapping's space id number
			stw		r2,mpPte(r31)				; Set mapping's pte pointer invalid
			stw		r29,mpPAddr(r31)			; Set mapping's physical address
			bt++	pf64Bitb,gadVA64			; Use 64-bit version on 64-bit machine
			stw		r30,mpVAddr+4(r31)			; Set mapping's virtual address (w/flags)
			b		gadChain					; Continue with chaining mapping to physent
gadVA64:	std		r30,mpVAddr(r31)			; Set mapping's virtual address (w/flags)
			
gadChain:	mr		r3,r29						; r3 <- physical frame address
			bl		mapFindLockPN				; Find 'n' lock this page's physent
			mr.		r26,r3						; Got lock on our physent?
			beq--	gadBadPLock					; No, time to bail out

			bt++	pf64Bitb,gadChain64			; Use 64-bit version on 64-bit machine
			lwz		r12,ppLink+4(r26)			; Get forward chain
			rlwinm	r11,r12,0,~ppFlags			; Get physent's forward pointer sans flags
			rlwimi	r12,r31,0,~ppFlags			; Insert new mapping, preserve physent flags
			stw		r11,mpAlias+4(r31)			; New mapping will head chain
			stw		r12,ppLink+4(r26)			; Point physent to new mapping
			b		gadFinish					; All over now...

gadChain64:	li		r7,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r7,r7,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			ld		r12,ppLink(r26)				; Get forward chain
			andc	r11,r12,r7					; Get physent's forward chain pointer sans flags
			and		r12,r12,r7					; Isolate pointer's flags
			or		r12,r12,r31					; Insert new mapping's address forming pointer
			std		r11,mpAlias(r31)			; New mapping will head chain
			std		r12,ppLink(r26)				; Point physent to new mapping

gadFinish:	eieio								; Ensure new mapping is completely visible
			
gadRelPhy:	mr		r3,r26						; r3 <- physent addr
			bl		mapPhysUnlock				; Unlock physent chain
			
gadRelPmap:	la		r3,pmapSXlk(r27)			; r3 <- host pmap search lock phys addr
			bl		sxlkUnlock					; Release host pmap search lock
			
			bt++	pf64Bitb,gadRtn64			; Handle 64-bit separately
			mtmsr	r25							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		gadPopFrame					; Nothing to do now but pop a frame and return
gadRtn64:	mtmsrd	r25							; Restore 'rupts, translation, 32-bit mode
gadPopFrame:		
			lwz		r0,(FM_ALIGN(gadStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r24,FM_ARG0+0x1C(r1)		; Restore non-volatile r24
			lwz		r23,FM_ARG0+0x20(r1)		; Restore non-volatile r23
			lwz		r22,FM_ARG0+0x24(r1)		; Restore non-volatile r22
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

gadPEMissMiss:
gadBadPLock:
			lis		r0,hi16(Choke)				; Dmitri, you know how we've always talked about the
			ori		r0,r0,lo16(Choke)			;  possibility of something going wrong with the bomb?
			li		r3,failMapping				; The BOMB, Dmitri.
			sc									; The hydrogen bomb.


;
;			Guest shadow assist -- supend a guest mapping
;
;			Suspends a guest mapping.
;
;			Parameters:
;				r3 : address of host pmap, 32-bit kernel virtual address
;				r4 : address of guest pmap, 32-bit kernel virtual address
;				r5 : guest virtual address, high-order 32 bits
;				r6 : guest virtual address,  low-order 32 bits
;
;			Non-volatile register usage:
;				r26 : VMM extension block's physical address
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : caller's msr image from mapSetUp
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;

			.align	5
			.globl	EXT(hw_susp_map_gv)

LEXT(hw_susp_map_gv)

#define gsuStackSize ((31-26+1)*4)+4

			stwu	r1,-(FM_ALIGN(gsuStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(gsuStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26

			rlwinm	r30,r6,0,0xFFFFF000			; Clean up low-order 32 bits of guest vaddr

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r4)			; r9 <- guest space ID number
			bt++	pf64Bitb,gsu64Salt			; Test for 64-bit machine

			lwz		r26,pmapVmmExtPhys+4(r3)	; r26 <- VMM pmap extension block paddr
			lwz		r27,pmapvr+4(r3)			; Get 32-bit virt<->real host pmap conversion salt
			lwz		r28,pmapvr+4(r4)			; Get 32-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
			b		gsuStart					; Get to it			
gsu64Salt:	rldimi	r30,r5,32,0					; Insert high-order 32 bits of 64-bit guest vaddr
			ld		r26,pmapVmmExtPhys(r3)		; r26 <- VMM pmap extension block paddr
			ld		r27,pmapvr(r3)				; Get 64-bit virt<->real host pmap conversion salt
			ld		r28,pmapvr(r4)				; Get 64-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr

gsuStart:	xor		r27,r3,r27					; Convert host pmap_t virt->real
			xor		r28,r4,r28					; Convert guest pmap_t virt->real
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r29,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive

			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,gsu64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		gsu32SrchLp					; Let the search begin!
			
			.align	5
gsu32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gsuSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gsu32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gsuSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		gsuSrchMiss					; No joy in our hash group
			
gsu64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		gsu64SrchLp					; Let the search begin!
			
			.align	5
gsu64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gsuSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gsu64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			bne		gsuSrchMiss					; No joy in our hash group
			
gsuSrchHit:
			bt++	pf64Bitb,gsuDscon64			; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		gsuFreePTE					; Join 64-bit path to release the PTE			
gsuDscon64:	bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
gsuFreePTE: mr.		r3,r3						; Was there a valid PTE?
			beq-	gsuNoPTE					; No valid PTE, we're almost done
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE pointer
			rlwinm	r8,r8,0,~mpHValid			; Make the pointer invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE pointer
			eieio								; Synchronize all previous updates (mapInvPtexx didn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG
			
gsuNoPTE:	lwz		r3,mpFlags(r31)				; Get mapping's flags
			ori		r3,r3,mpgDormant			; Mark entry dormant
			stw		r3,mpFlags(r31)				; Save updated flags
			eieio								; Ensure update is visible when we unlock

gsuSrchMiss:
			la		r3,pmapSXlk(r27)			; r3 <- host pmap search lock phys addr
			bl		sxlkUnlock					; Release host pmap search lock
			
			bt++	pf64Bitb,gsuRtn64			; Handle 64-bit separately
			mtmsr	r29							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		gsuPopFrame					; Nothing to do now but pop a frame and return
gsuRtn64:	mtmsrd	r29							; Restore 'rupts, translation, 32-bit mode
gsuPopFrame:		
			lwz		r0,(FM_ALIGN(gsuStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

;
;			Guest shadow assist -- test guest mapping reference and change bits
;
;			Locates the specified guest mapping, and if it exists gathers its reference
;			and change bit, optionallyÊresetting them.
;
;			Parameters:
;				r3 : address of host pmap, 32-bit kernel virtual address
;				r4 : address of guest pmap, 32-bit kernel virtual address
;				r5 : guest virtual address, high-order 32 bits
;				r6 : guest virtual address,  low-order 32 bits
;				r7 : reset boolean
;
;			Non-volatile register usage:
;				r24 : VMM extension block's physical address
;				r25 : return code (w/reference and change bits)
;				r26 : reset boolean
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : caller's msr image from mapSetUp
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;

			.align	5
			.globl	EXT(hw_test_rc_gv)

LEXT(hw_test_rc_gv)

#define gtdStackSize ((31-24+1)*4)+4

			stwu	r1,-(FM_ALIGN(gtdStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(gtdStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25
			stw		r24,FM_ARG0+0x1C(r1)		; Save non-volatile r24

			rlwinm	r30,r6,0,0xFFFFF000			; Clean up low-order 20 bits of guest vaddr

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r4)			; r9 <- guest space ID number

			bt++	pf64Bitb,gtd64Salt			; Test for 64-bit machine

			lwz		r24,pmapVmmExtPhys+4(r3)	; r24 <- VMM pmap extension block paddr
			lwz		r27,pmapvr+4(r3)			; Get 32-bit virt<->real host pmap conversion salt
			lwz		r28,pmapvr+4(r4)			; Get 32-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
			b		gtdStart					; Get to it			

gtd64Salt:	rldimi	r30,r5,32,0					; Insert high-order 32 bits of 64-bit guest vaddr
			ld		r24,pmapVmmExtPhys(r3)		; r24 <- VMM pmap extension block paddr
			ld		r27,pmapvr(r3)				; Get 64-bit virt<->real host pmap conversion salt
			ld		r28,pmapvr(r4)				; Get 64-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr

gtdStart:	xor		r27,r3,r27					; Convert host pmap_t virt->real
			xor		r28,r4,r28					; Convert guest pmap_t virt->real
			mr		r26,r7						; Save reset boolean
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r29,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive

			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,gtd64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		gtd32SrchLp					; Let the search begin!
			
			.align	5
gtd32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gtdSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gtd32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gtdSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		gtdSrchMiss					; No joy in our hash group
			
gtd64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		gtd64SrchLp					; Let the search begin!
			
			.align	5
gtd64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gtdSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gtd64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			bne		gtdSrchMiss					; No joy in our hash group
			
gtdSrchHit:
			bt++	pf64Bitb,gtdDo64			; Split for 64 bit
			
			bl		mapInvPte32					; Invalidate and lock PTEG, also merge into physent
						
			cmplwi	cr1,r26,0					; Do we want to clear RC?
			lwz		r12,mpVAddr+4(r31)			; Get the bottom of the mapping vaddr field
			mr.		r3,r3						; Was there a previously valid PTE?
			li		r0,lo16(mpR|mpC)			; Get bits to clear

			and		r25,r5,r0					; Copy RC bits into result
			beq++	cr1,gtdNoClr32				; Nope...
			
			andc	r12,r12,r0					; Clear mapping copy of RC
			andc	r5,r5,r0					; Clear PTE copy of RC
			sth		r12,mpVAddr+6(r31)			; Set the new RC in mapping			

gtdNoClr32:	beq--	gtdNoOld32					; No previously valid PTE...
			
			sth		r5,6(r3)					; Store updated RC in PTE
			eieio								; Make sure we do not reorder
			stw		r4,0(r3)					; Revalidate the PTE

			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock PCA

gtdNoOld32:	la		r3,pmapSXlk(r27)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			b		gtdR32						; Join common...

			.align	5			
			
			
gtdDo64:	bl		mapInvPte64					; Invalidate and lock PTEG, also merge into physent
						
			cmplwi	cr1,r26,0					; Do we want to clear RC?
			lwz		r12,mpVAddr+4(r31)			; Get the bottom of the mapping vaddr field
			mr.		r3,r3						; Was there a previously valid PTE?
			li		r0,lo16(mpR|mpC)			; Get bits to clear

			and		r25,r5,r0					; Copy RC bits into result
			beq++	cr1,gtdNoClr64				; Nope...
			
			andc	r12,r12,r0					; Clear mapping copy of RC
			andc	r5,r5,r0					; Clear PTE copy of RC
			sth		r12,mpVAddr+6(r31)			; Set the new RC			

gtdNoClr64:	beq--	gtdNoOld64					; Nope, no pevious pte...
			
			sth		r5,14(r3)					; Store updated RC
			eieio								; Make sure we do not reorder
			std		r4,0(r3)					; Revalidate the PTE

			eieio								; Make sure all updates come first
			stw		r6,0(r7)					; Unlock PCA

gtdNoOld64:	la		r3,pmapSXlk(r27)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			b		gtdR64						; Join common...

gtdSrchMiss:
			la		r3,pmapSXlk(r27)			; Point to the pmap search lock
			bl		sxlkUnlock					; Unlock the search list
			li		r25,mapRtNotFnd				; Get ready to return not found
			bt++	pf64Bitb,gtdR64				; Test for 64-bit machine
			
gtdR32:		mtmsr	r29							; Restore caller's msr image
			isync
			b		gtdEpilog
			
gtdR64:		mtmsrd	r29							; Restore caller's msr image

gtdEpilog:	lwz		r0,(FM_ALIGN(gtdStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			mr		r3,r25						; Get return code
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r24,FM_ARG0+0x1C(r1)		; Restore non-volatile r24
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

;
;			Guest shadow assist -- convert guest to host virtual address
;
;			Locates the specified guest mapping, and if it exists locates the
;			first mapping belonging to its host on the physical chain and returns
;			its virtual address.
;
;			Note that if there are multiple mappings belonging to this host
;			chained to the physent to which the guest mapping is chained, then
;			host virtual aliases exist for this physical address. If host aliases
;			exist, then we select the first on the physent chain, making it 
;			unpredictable which of the two or more possible host virtual addresses
;			will be returned.
;
;			Parameters:
;				r3 : address of guest pmap, 32-bit kernel virtual address
;				r4 : guest virtual address, high-order 32 bits
;				r5 : guest virtual address,  low-order 32 bits
;
;			Non-volatile register usage:
;				r24 : physent physical address
;				r25 : VMM extension block's physical address
;				r26 : host virtual address
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : caller's msr image from mapSetUp
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;

			.align	5
			.globl	EXT(hw_gva_to_hva)

LEXT(hw_gva_to_hva)

#define gthStackSize ((31-24+1)*4)+4

			stwu	r1,-(FM_ALIGN(gtdStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(gtdStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25
			stw		r24,FM_ARG0+0x1C(r1)		; Save non-volatile r24

			rlwinm	r30,r5,0,0xFFFFF000			; Clean up low-order 32 bits of guest vaddr

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r3)			; r9 <- guest space ID number

			bt++	pf64Bitb,gth64Salt			; Test for 64-bit machine

			lwz		r25,pmapVmmExtPhys+4(r3)	; r25 <- VMM pmap extension block paddr
			lwz		r28,pmapvr+4(r3)			; Get 32-bit virt<->real guest pmap conversion salt
			lwz		r27,vmxHostPmapPhys+4(r11)	; Get host pmap physical address
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
			b		gthStart					; Get to it			

gth64Salt:	rldimi	r30,r4,32,0					; Insert high-order 32 bits of 64-bit guest vaddr
			ld		r25,pmapVmmExtPhys(r3)		; r24 <- VMM pmap extension block paddr
			ld		r28,pmapvr(r3)				; Get 64-bit virt<->real guest pmap conversion salt
			ld		r27,vmxHostPmapPhys(r11)	; Get host pmap physical address
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr

gthStart:	xor		r28,r3,r28					; Convert guest pmap_t virt->real
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r29,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive

			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,gth64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		gth32SrchLp					; Let the search begin!
			
			.align	5
gth32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gthSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gth32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gthSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		gthSrchMiss					; No joy in our hash group
			
gth64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		gth64SrchLp					; Let the search begin!
			
			.align	5
gth64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gthSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gth64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			bne		gthSrchMiss					; No joy in our hash group
			
gthSrchHit:	lwz		r3,mpPAddr(r31)				; r3 <- physical 4K-page number
			bl		mapFindLockPN				; Find 'n' lock this page's physent
			mr.		r24,r3						; Got lock on our physent?
			beq--	gthBadPLock					; No, time to bail out
			
			bt++	pf64Bitb,gthPFnd64			; 64-bit version of physent chain search
			
			lwz		r9,ppLink+4(r24)			; Get first mapping on physent
			lwz		r6,pmapSpace(r27)			; Get host pmap's space id number
			rlwinm	r9,r9,0,~ppFlags			; Be-gone, unsightly flags
gthPELoop:	mr.		r12,r9						; Got a mapping to look at?
			beq-	gthPEMiss					; Nope, we've missed hva->phys mapping
			lwz		r7,mpFlags(r12)				; Get mapping's flags
			lhz		r4,mpSpace(r12)				; Get mapping's space id number
			lwz		r26,mpVAddr+4(r12)			; Get mapping's virtual address
			lwz		r9,mpAlias+4(r12)			; Next mapping in physent alias chain
			
			rlwinm	r0,r7,0,mpType				; Isolate mapping's type
			rlwinm	r26,r26,0,~mpHWFlags		; Bye-bye unsightly flags
			xori	r0,r0,mpNormal				; Normal mapping?
			xor		r4,r4,r6					; Compare w/ host space id number
			or.		r0,r0,r4					; cr0_eq <- (normal && space id hit)
			beq		gthPEHit					; Hit
			b		gthPELoop					; Iterate
			
gthPFnd64:	li		r0,ppLFAmask				; Get mask to clean up mapping pointer
			rotrdi	r0,r0,ppLFArrot				; Rotate clean up mask to get 0xF0000000000000000F
			ld		r9,ppLink(r24)				; Get first mapping on physent
			lwz		r6,pmapSpace(r27)			; Get host pmap's space id number
			andc	r9,r9,r0					; Cleanup mapping pointer
gthPELp64:	mr.		r12,r9						; Got a mapping to look at?
			beq--	gthPEMiss					; Nope, we've missed hva->phys mapping
			lwz		r7,mpFlags(r12)				; Get mapping's flags
			lhz		r4,mpSpace(r12)				; Get mapping's space id number
			ld		r26,mpVAddr(r12)			; Get mapping's virtual address
			ld		r9,mpAlias(r12)				; Next mapping physent alias chain
			rlwinm	r0,r7,0,mpType				; Isolate mapping's type
			rldicr	r26,r26,0,mpHWFlagsb-1		; Bye-bye unsightly flags
			xori	r0,r0,mpNormal				; Normal mapping?
			xor		r4,r4,r6					; Compare w/ host space id number
			or.		r0,r0,r4					; cr0_eq <- (normal && space id hit)
			beq		gthPEHit					; Hit
			b		gthPELp64					; Iterate

			.align	5			
gthPEMiss:	mr		r3,r24						; Get physent's address
			bl		mapPhysUnlock				; Unlock physent chain
gthSrchMiss:
			la		r3,pmapSXlk(r27)			; Get host pmap search lock address
			bl		sxlkUnlock					; Release host pmap search lock
			li		r3,-1						; Return 64-bit -1
			li		r4,-1
			bt++	pf64Bitb,gthEpi64			; Take 64-bit exit
			b		gthEpi32					; Take 32-bit exit

			.align	5
gthPEHit:	mr		r3,r24						; Get physent's address
			bl		mapPhysUnlock				; Unlock physent chain
			la		r3,pmapSXlk(r27)			; Get host pmap search lock address
			bl		sxlkUnlock					; Release host pmap search lock

			bt++	pf64Bitb,gthR64				; Test for 64-bit machine
			
gthR32:		li		r3,0						; High-order 32 bits host virtual address
			mr		r4,r26						; Low-order  32 bits host virtual address
gthEpi32:	mtmsr	r29							; Restore caller's msr image
			isync
			b		gthEpilog

			.align	5			
gthR64:		srdi	r3,r26,32					; High-order 32 bits host virtual address
			clrldi	r4,r26,32					; Low-order  32 bits host virtual address
gthEpi64:	mtmsrd	r29							; Restore caller's msr image

gthEpilog:	lwz		r0,(FM_ALIGN(gthStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r24,FM_ARG0+0x1C(r1)		; Restore non-volatile r24
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

gthBadPLock:
			lis		r0,hi16(Choke)				; Dmitri, you know how we've always talked about the
			ori		r0,r0,lo16(Choke)			;  possibility of something going wrong with the bomb?
			li		r3,failMapping				; The BOMB, Dmitri.
			sc									; The hydrogen bomb.


;
;			Guest shadow assist -- find a guest mapping
;
;			Locates the specified guest mapping, and if it exists returns a copy
;			of it.
;
;			Parameters:
;				r3 : address of guest pmap, 32-bit kernel virtual address
;				r4 : guest virtual address, high-order 32 bits
;				r5 : guest virtual address,  low-order 32 bits
;				r6 : 32 byte copy area, 32-bit kernel virtual address
;
;			Non-volatile register usage:
;				r25 : VMM extension block's physical address
;				r26 : copy area virtual address
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : caller's msr image from mapSetUp
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;

			.align	5
			.globl	EXT(hw_find_map_gv)

LEXT(hw_find_map_gv)

#define gfmStackSize ((31-25+1)*4)+4

			stwu	r1,-(FM_ALIGN(gfmStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(gfmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25

			rlwinm	r30,r5,0,0xFFFFF000			; Clean up low-order 32 bits of guest vaddr
			mr		r26,r6						; Copy copy buffer vaddr

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r3)			; r9 <- guest space ID number

			bt++	pf64Bitb,gfm64Salt			; Test for 64-bit machine

			lwz		r25,pmapVmmExtPhys+4(r3)	; r25 <- VMM pmap extension block paddr
			lwz		r28,pmapvr+4(r3)			; Get 32-bit virt<->real guest pmap conversion salt
			lwz		r27,vmxHostPmapPhys+4(r11)	; Get host pmap physical address
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
			b		gfmStart					; Get to it			

gfm64Salt:	rldimi	r30,r4,32,0					; Insert high-order 32 bits of 64-bit guest vaddr
			ld		r25,pmapVmmExtPhys(r3)		; r24 <- VMM pmap extension block paddr
			ld		r28,pmapvr(r3)				; Get 64-bit virt<->real guest pmap conversion salt
			ld		r27,vmxHostPmapPhys(r11)	; Get host pmap physical address
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr

gfmStart:	xor		r28,r3,r28					; Convert guest pmap_t virt->real
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r29,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive

			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,gfm64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		gfm32SrchLp					; Let the search begin!
			
			.align	5
gfm32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gfmSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gfm32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gfmSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		gfmSrchMiss					; No joy in our hash group
			
gfm64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		gfm64SrchLp					; Let the search begin!
			
			.align	5
gfm64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- !(!free && !dormant && space match)
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gfmSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gfm64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free and dormant flags
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- !(!free && !dormant && space match)
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			bne		gfmSrchMiss					; No joy in our hash group
			
gfmSrchHit:	lwz		r5,0(r31)					; Fetch 32 bytes of mapping from physical
			lwz		r6,4(r31)					;  +4
			lwz		r7,8(r31)					;  +8
			lwz		r8,12(r31)					;  +12
			lwz		r9,16(r31)					;  +16
			lwz		r10,20(r31)					;  +20
			lwz		r11,24(r31)					;  +24
			lwz		r12,28(r31)					;  +28
			
			li		r31,mapRtOK					; Return found mapping

			la		r3,pmapSXlk(r27)			; Get host pmap search lock address
			bl		sxlkUnlock					; Release host pmap search lock

			bt++	pf64Bitb,gfmEpi64			; Test for 64-bit machine
			
gfmEpi32:	mtmsr	r29							; Restore caller's msr image
			isync								; A small wrench
			b		gfmEpilog					;  and a larger bubble

			.align	5			
gfmEpi64:	mtmsrd	r29							; Restore caller's msr image

gfmEpilog:	mr.		r3,r31						; Copy/test mapping address
			beq		gfmNotFound					; Skip copy if no mapping found
			
			stw		r5,0(r26)					; Store 32 bytes of mapping into virtual
			stw		r6,4(r26)					;  +4
			stw		r7,8(r26)					;  +8
			stw		r8,12(r26)					;  +12
			stw		r9,16(r26)					;  +16
			stw		r10,20(r26)					;  +20
			stw		r11,24(r26)					;  +24
			stw		r12,28(r26)					;  +28
			
gfmNotFound:
			lwz		r0,(FM_ALIGN(gfmStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

			.align	5			
gfmSrchMiss:
			li		r31,mapRtNotFnd				; Indicate mapping not found
			la		r3,pmapSXlk(r27)			; Get host pmap search lock address
			bl		sxlkUnlock					; Release host pmap search lock
			bt++	pf64Bitb,gfmEpi64			; Take 64-bit exit
			b		gfmEpi32					; Take 32-bit exit


;
;			Guest shadow assist -- change guest page protection
;
;			Locates the specified dormant mapping, and if it is active, changes its
;			protection.
;
;			Parameters:
;				r3 : address of guest pmap, 32-bit kernel virtual address
;				r4 : guest virtual address, high-order 32 bits
;				r5 : guest virtual address,  low-order 32 bits
;				r6 : guest mapping protection code
;
;			Non-volatile register usage:
;				r25 : caller's msr image from mapSetUp
;				r26 : guest mapping protection code
;				r27 : host pmap physical address
;				r28 : guest pmap physical address
;				r29 : VMM extension block's physical address
;				r30 : guest virtual address
;				r31 : gva->phys mapping's physical address
;
			.align	5
			.globl	EXT(hw_protect_gv)
			
LEXT(hw_protect_gv)

#define gcpStackSize ((31-24+1)*4)+4

			stwu	r1,-(FM_ALIGN(gcpStackSize)+FM_SIZE)(r1)
												; Mint a new stack frame
			mflr	r0							; Get caller's return address
			mfsprg	r11,2						; Get feature flags
			mtcrf	0x02,r11					; Insert feature flags into cr6
			stw		r0,(FM_ALIGN(gcpStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Save caller's return address
			stw		r31,FM_ARG0+0x00(r1)		; Save non-volatile r31
			stw		r30,FM_ARG0+0x04(r1)		; Save non-volatile r30
			stw		r29,FM_ARG0+0x08(r1)		; Save non-volatile r29
			stw		r28,FM_ARG0+0x0C(r1)		; Save non-volatile r28
			stw		r27,FM_ARG0+0x10(r1)		; Save non-volatile r27
			stw		r26,FM_ARG0+0x14(r1)		; Save non-volatile r26
			stw		r25,FM_ARG0+0x18(r1)		; Save non-volatile r25

			rlwinm	r30,r5,0,0xFFFFF000			; Clean up low-order 32 bits of guest vaddr
			mr		r26,r6						; Copy guest mapping protection code

			lwz		r11,pmapVmmExt(r3)			; r11 <- VMM pmap extension block vaddr
			lwz		r9,pmapSpace(r3)			; r9 <- guest space ID number
			bt++	pf64Bitb,gcp64Salt			; Handle 64-bit machine separately
			lwz		r29,pmapVmmExtPhys+4(r3)	; r29 <- VMM pmap extension block paddr
			lwz		r27,vmxHostPmapPhys+4(r11)	; r27 <- host pmap paddr
			lwz		r28,pmapvr+4(r3)			; Get 32-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			lwz		r31,4(r31)					; r31 <- hash page paddr
			rlwimi	r31,r11,GV_HGRP_SHIFT,GV_HGRP_MASK
												; r31 <- hash group paddr
			b		gcpStart					; Get to it			

gcp64Salt:	rldimi	r30,r4,32,0					; Insert high-order 32 bits of 64-bit guest vaddr			
			ld		r29,pmapVmmExtPhys(r3)		; r29 <- VMM pmap extension block paddr
			ld		r27,vmxHostPmapPhys(r11)	; r27 <- host pmap paddr
			ld		r28,pmapvr(r3)				; Get 64-bit virt<->real guest pmap conversion salt
			la		r31,VMX_HPIDX_OFFSET(r11)	; r31 <- base of hash page physical index
			srwi	r11,r30,12					; Form shadow hash:
			xor		r11,r11,r9					; 	spaceID ^ (vaddr >> 12) 
			rlwinm	r10,r11,GV_HPAGE_SHIFT,GV_HPAGE_MASK
												; Form index offset from hash page number
			add		r31,r31,r10					; r31 <- hash page index entry
			ld		r31,0(r31)					; r31 <- hash page paddr
			insrdi	r31,r11,GV_GRPS_PPG_LG2,64-(GV_HGRP_SHIFT+GV_GRPS_PPG_LG2)
												; r31 <- hash group paddr

gcpStart:	xor		r28,r4,r28					; Convert guest pmap_t virt->real
			bl		EXT(mapSetUp)				; Disable 'rupts, translation, maybe enter 64-bit mode
			mr		r25,r11						; Save caller's msr image

			la		r3,pmapSXlk(r27)			; r3 <- host pmap's search lock address
			bl		sxlkExclusive				; Get lock exclusive

			li		r0,(GV_SLOTS - 1)			; Prepare to iterate over mapping slots
			mtctr	r0							;  in this group
			bt++	pf64Bitb,gcp64Search		; Test for 64-bit machine

			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			lwz		r5,mpVAddr+4(r31)			; r5 <- 1st mapping slot's virtual address
			b		gcp32SrchLp					; Let the search begin!
			
			.align	5
gcp32SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrwi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			lwz		r5,mpVAddr+4+GV_SLOT_SZ(r31); r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- free || dormant || !space match
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gcpSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gcp32SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrwi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- free || dormant || !space match
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gcpSrchHit					; Join common path on hit (r31 points to guest mapping)
			b		gcpSrchMiss					; No joy in our hash group
			
gcp64Search:			
			lwz		r3,mpFlags(r31)				; r3 <- 1st mapping slot's flags
			lhz		r4,mpSpace(r31)				; r4 <- 1st mapping slot's space ID 
			ld		r5,mpVAddr(r31)				; r5 <- 1st mapping slot's virtual address
			b		gcp64SrchLp					; Let the search begin!
			
			.align	5
gcp64SrchLp:
			mr		r6,r3						; r6 <- current mapping slot's flags
			lwz		r3,mpFlags+GV_SLOT_SZ(r31)	; r3 <- next mapping slot's flags
			mr		r7,r4						; r7 <- current mapping slot's space ID
			lhz		r4,mpSpace+GV_SLOT_SZ(r31)	; r4 <- next mapping slot's space ID
			clrrdi	r8,r5,12					; r8 <- current mapping slot's virtual addr w/o flags
			ld		r5,mpVAddr+GV_SLOT_SZ(r31)	; r5 <- next mapping slot's virtual addr
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free flag
			xor		r7,r7,r9					; Compare space ID
			or		r0,r11,r7					; r0 <- free || dormant || !space match
			xor		r8,r8,r30					; Compare virtual address
			or.		r0,r0,r8					; cr0_eq <- !free && !dormant && space match && virtual addr match
			beq		gcpSrchHit					; Join common path on hit (r31 points to guest mapping)
			
			addi	r31,r31,GV_SLOT_SZ			; r31 <- next mapping slot		
			bdnz	gcp64SrchLp					; Iterate

			mr		r6,r3						; r6 <- current mapping slot's flags
			clrrdi	r5,r5,12					; Remove flags from virtual address			
			andi.	r11,r6,mpgFree+mpgDormant	; Isolate guest free flag
			xor		r4,r4,r9					; Compare space ID
			or		r0,r11,r4					; r0 <- free || dormant || !space match
			xor		r5,r5,r30					; Compare virtual address
			or.		r0,r0,r5					; cr0_eq <- !free && !dormant && space match && virtual addr match
			bne		gcpSrchMiss					; No joy in our hash group
			
gcpSrchHit:
			bt++	pf64Bitb,gcpDscon64			; Handle 64-bit disconnect separately
			bl		mapInvPte32					; Disconnect PTE, invalidate, gather ref and change
												; r31 <- mapping's physical address
												; r3  -> PTE slot physical address
												; r4  -> High-order 32 bits of PTE
												; r5  -> Low-order  32 bits of PTE
												; r6  -> PCA
												; r7  -> PCA physical address
			rlwinm	r2,r3,29,29,31				; Get PTE's slot number in the PTEG (8-byte PTEs)
			b		gcpFreePTE					; Join 64-bit path to release the PTE			
gcpDscon64:	bl		mapInvPte64					; Disconnect PTE, invalidate, gather ref and change
			rlwinm	r2,r3,28,29,31				; Get PTE's slot number in the PTEG (16-byte PTEs)
gcpFreePTE: mr.		r3,r3						; Was there a valid PTE?
			beq-	gcpSetKey					; No valid PTE, we're almost done
			lis		r0,0x8000					; Prepare free bit for this slot
			srw		r0,r0,r2					; Position free bit
			or		r6,r6,r0					; Set it in our PCA image
			lwz		r8,mpPte(r31)				; Get PTE pointer
			rlwinm	r8,r8,0,~mpHValid			; Make the pointer invalid
			stw		r8,mpPte(r31)				; Save invalidated PTE pointer
			eieio								; Synchronize all previous updates (mapInvPtexx didn't)
			stw		r6,0(r7)					; Update PCA and unlock the PTEG
			
gcpSetKey:	lwz		r0,mpVAddr+4(r31)			; Get va word containing protection bits
			rlwimi	r0,r26,0,mpPP				; Insert new protection bits
			stw		r0,mpVAddr+4(r31)			; Write 'em back
			eieio								; Ensure previous mapping updates are visible
			li		r31,mapRtOK					; I'm a success

gcpRelPmap:	la		r3,pmapSXlk(r27)			; r3 <- host pmap search lock phys addr
			bl		sxlkUnlock					; Release host pmap search lock
			
			mr		r3,r31						; r3 <- result code
			bt++	pf64Bitb,gcpRtn64			; Handle 64-bit separately
			mtmsr	r25							; Restore 'rupts, translation
			isync								; Throw a small wrench into the pipeline
			b		gcpPopFrame					; Nothing to do now but pop a frame and return
gcpRtn64:	mtmsrd	r25							; Restore 'rupts, translation, 32-bit mode
gcpPopFrame:		
			lwz		r0,(FM_ALIGN(gcpStackSize)+FM_SIZE+FM_LR_SAVE)(r1)
												; Get caller's return address
			lwz		r31,FM_ARG0+0x00(r1)		; Restore non-volatile r31
			lwz		r30,FM_ARG0+0x04(r1)		; Restore non-volatile r30
			lwz		r29,FM_ARG0+0x08(r1)		; Restore non-volatile r29
			lwz		r28,FM_ARG0+0x0C(r1)		; Restore non-volatile r28
			mtlr	r0							; Prepare return address
			lwz		r27,FM_ARG0+0x10(r1)		; Restore non-volatile r27
			lwz		r26,FM_ARG0+0x14(r1)		; Restore non-volatile r26
			lwz		r25,FM_ARG0+0x18(r1)		; Restore non-volatile r25
			lwz		r1,0(r1)					; Pop stack frame
			blr									; Return to caller

			.align	5
gcpSrchMiss:
			li		r31,mapRtNotFnd				; Could not locate requested mapping
			b		gcpRelPmap					; Exit through host pmap search lock release


;
;			Find the physent based on a physical page and try to lock it (but not too hard) 
;			Note that this table always has an entry that with a 0 table pointer at the end 
;			
;			R3 contains ppnum on entry
;			R3 is 0 if no entry was found
;			R3 is physent if found
;			cr0_eq is true if lock was obtained or there was no entry to lock
;			cr0_eq is false of there was an entry and it was locked
;	

			.align	5
			
mapFindPhyTry:	
			lis		r9,hi16(EXT(pmap_mem_regions))		; Point to the start of the region table
			mr		r2,r3						; Save our target
			ori		r9,r9,lo16(EXT(pmap_mem_regions))	; Point to the start of the region table			

mapFindPhz:	lwz		r3,mrPhysTab(r9)			; Get the actual table address
			lwz		r5,mrStart(r9)				; Get start of table entry
			lwz		r0,mrEnd(r9)				; Get end of table entry
			addi	r9,r9,mrSize				; Point to the next slot
			cmplwi	cr2,r3,0					; Are we at the end of the table?
			cmplw	r2,r5						; See if we are in this table
			cmplw	cr1,r2,r0					; Check end also
			sub		r4,r2,r5					; Calculate index to physical entry
			beq--	cr2,mapFindNo				; Leave if we did not find an entry...
			cror	cr0_lt,cr0_lt,cr1_gt		; Set CR0_LT if it is NOT this entry
			slwi	r4,r4,3						; Get offset to physical entry

			blt--	mapFindPhz					; Did not find it...
			
			add		r3,r3,r4					; Point right to the slot
	
mapFindOv:	lwz		r2,0(r3)					; Get the lock contents right now
			rlwinm.	r0,r2,0,0,0					; Is it locked?
			bnelr--								; Yes it is...
			
			lwarx	r2,0,r3						; Get the lock
			rlwinm.	r0,r2,0,0,0					; Is it locked?
			oris	r0,r2,0x8000				; Set the lock bit
			bne--	mapFindKl					; It is locked, go get rid of reservation and leave...
			stwcx.	r0,0,r3						; Try to stuff it back...
			bne--	mapFindOv					; Collision, try again...
			isync								; Clear any speculations
			blr									; Leave...

mapFindKl:	li		r2,lgKillResv				; Killing field
			stwcx.	r2,0,r2						; Trash reservation...
			crclr	cr0_eq						; Make sure we do not think we got the lock
			blr									; Leave...

mapFindNo:	crset	cr0_eq						; Make sure that we set this
			li		r3,0						; Show that we did not find it
			blr									; Leave...			
;
;			pmapCacheLookup - This function will look up an entry in the pmap segment cache.
;
;			How the pmap cache lookup works:
;
;			We use a combination of three things: a mask of valid entries, a sub-tag, and the
;			ESID (aka the "tag").  The mask indicates which of the cache slots actually contain
;			an entry.  The sub-tag is a 16 entry 4 bit array that contains the low order 4 bits
;			of the ESID, bits 32:36 of the effective for 64-bit and 0:3 for 32-bit.  The cache
;			entry contains the full 36 bit ESID.
;
;			The purpose of the sub-tag is to limit the number of searches necessary when looking
;			for an existing cache entry.  Because there are 16 slots in the cache, we could end up
;			searching all 16 if an match is not found.  
;
;			Essentially, we will search only the slots that have a valid entry and whose sub-tag
;			matches. More than likely, we will eliminate almost all of the searches.
;		
;			Inputs:
;				R3 = pmap
;				R4 = ESID high half
;				R5 = ESID low half
;
;			Outputs:
;				R3 = pmap cache slot if found, 0 if not
;				R10 = pmapCCtl address
;				R11 = pmapCCtl image
;				pmapCCtl locked on exit
;

			.align	5

pmapCacheLookup:		
			la		r10,pmapCCtl(r3)			; Point to the segment cache control

pmapCacheLookuq:		
			lwarx	r11,0,r10					; Get the segment cache control value
			rlwinm.	r0,r11,0,pmapCCtlLckb,pmapCCtlLckb	; Is it already locked?
			ori		r0,r11,lo16(pmapCCtlLck)	; Turn on the lock bit
			bne--	pmapCacheLookur				; Nope...
			stwcx.	r0,0,r10					; Try to take the lock
			bne--	pmapCacheLookuq				; Someone else just stuffed it, try again...

			isync								; Make sure we get reservation first
			lwz		r9,pmapSCSubTag(r3)			; Get the high part of the sub-tag
			rlwimi	r5,r5,28,4,7				; Copy sub-tag just to right of itself (XX------)
			lwz		r10,pmapSCSubTag+4(r3)		; And the bottom half
			rlwimi	r5,r5,24,8,15				; Copy doubled sub-tag to right of itself (XXXX----)
			lis		r8,0x8888					; Get some eights
			rlwimi	r5,r5,16,16,31				; Copy quadrupled sub-tags to the right
			ori		r8,r8,0x8888				; Fill the rest with eights

			eqv		r10,r10,r5					; Get 0xF where we hit in bottom half
			eqv		r9,r9,r5					; Get 0xF where we hit in top half
			
			rlwinm	r2,r10,1,0,30				; Shift over 1
			rlwinm	r0,r9,1,0,30				; Shift over 1
			and		r2,r2,r10					; AND the even/odd pair into the even
			and		r0,r0,r9					; AND the even/odd pair into the even
			rlwinm	r10,r2,2,0,28				; Shift over 2
			rlwinm	r9,r0,2,0,28				; Shift over 2
			and		r10,r2,r10					; AND the even of the ANDed pairs giving the AND of all 4 bits in 0, 4, ...
			and		r9,r0,r9					; AND the even of the ANDed pairs giving the AND of all 4 bits in 0, 4, ...
			
			and		r10,r10,r8					; Clear out extras
			and		r9,r9,r8					; Clear out extras
			
			rlwinm	r0,r10,3,1,28				; Slide adjacent next to each other
			rlwinm	r2,r9,3,1,28				; Slide adjacent next to each other
			or		r10,r0,r10					; Merge them
			or		r9,r2,r9					; Merge them
			rlwinm	r0,r10,6,2,26				; Slide adjacent pairs next to each other
			rlwinm	r2,r9,6,2,26				; Slide adjacent pairs next to each other
			or		r10,r0,r10					; Merge them
			or		r9,r2,r9					; Merge them
			rlwimi	r10,r10,12,4,7				; Stick in the low-order adjacent quad
			rlwimi	r9,r9,12,4,7				; Stick in the low-order adjacent quad
			not		r6,r11						; Turn invalid into valid
			rlwimi	r9,r10,24,8,15				; Merge in the adjacent octs giving a hit mask
			
			la		r10,pmapSegCache(r3)		; Point at the cache slots
			and.	r6,r9,r6					; Get mask of valid and hit
			li		r0,0						; Clear
			li		r3,0						; Assume not found
			oris	r0,r0,0x8000				; Start a mask
			beqlr++								; Leave, should usually be no hits...
			
pclNextEnt:	cntlzw	r5,r6						; Find an in use one
			cmplwi	cr1,r5,pmapSegCacheUse		; Did we find one?
			rlwinm	r7,r5,4,0,27				; Index to the cache entry
			srw		r2,r0,r5					; Get validity mask bit
			add		r7,r7,r10					; Point to the cache slot
			andc	r6,r6,r2					; Clear the validity bit we just tried
			bgelr--	cr1							; Leave if there are no more to check...
			
			lwz		r5,sgcESID(r7)				; Get the top half
			
			cmplw	r5,r4						; Only need to check top because sub-tag is the entire other half
			
			bne++	pclNextEnt					; Nope, try again...

			mr		r3,r7						; Point to the slot
			blr									; Leave....

			.align	5

pmapCacheLookur:
			li		r11,lgKillResv				; The killing spot
			stwcx.	r11,0,r11					; Kill the reservation
			
pmapCacheLookus:		
			lwz		r11,pmapCCtl(r3)			; Get the segment cache control
			rlwinm.	r0,r11,0,pmapCCtlLckb,pmapCCtlLckb	; Is it already locked?
			beq++	pmapCacheLookup				; Nope...
			b		pmapCacheLookus				; Yup, keep waiting...


;
;			mapMergeRC -- Given a physical mapping address in R31, locate its
;           connected PTE (if any) and merge the PTE referenced and changed bits
;			into the mapping and physent.
;

			.align	5
			
mapMergeRC32:
			lwz		r0,mpPte(r31)				; Grab the PTE offset
			mfsdr1	r7							; Get the pointer to the hash table
			lwz		r5,mpVAddr+4(r31)			; Grab the virtual address
			rlwinm	r10,r7,0,0,15				; Clean up the hash table base
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			srwi	r7,r0,4						; Convert to PCA units
			rlwinm	r7,r7,0,0,29				; Clean up PCA offset
			mflr	r2							; Save the return
			subfic	r7,r7,-4					; Convert to -4 based negative index
			add		r7,r10,r7					; Point to the PCA directly
			beqlr--								; There was no PTE to start with...
			
			bl		mapLockPteg					; Lock the PTEG

			lwz		r0,mpPte(r31)				; Grab the PTE offset
			mtlr	r2							; Restore the LR
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			beq-	mMPUnlock					; There is no PTE, someone took it so just unlock and leave...

			rlwinm	r3,r0,0,0,30				; Clear the valid bit
			add		r3,r3,r10					; Point to actual PTE
			lwz		r5,4(r3)					; Get the real part of the PTE
			srwi	r10,r5,12					; Change physical address to a ppnum

mMNmerge:	lbz		r11,mpFlags+1(r31)			; Get the offset to the physical entry table
			lwz		r0,mpVAddr+4(r31)			; Get the flags part of the field
			lis		r8,hi16(EXT(pmap_mem_regions))	; Get the top of the region table
			ori		r8,r8,lo16(EXT(pmap_mem_regions))	; Get the bottom of the region table
			rlwinm	r11,r11,2,24,29				; Mask index bits and convert to byte offset
			add		r11,r11,r8					; Point to the bank table
			lwz		r2,mrPhysTab(r11)			; Get the physical table bank pointer
			lwz		r11,mrStart(r11)			; Get the start of bank
			rlwimi	r0,r5,0,mpRb-32,mpCb-32		; Copy in the RC
			addi	r2,r2,4						; Offset to last half of field
			stw		r0,mpVAddr+4(r31)			; Set the new RC into the field
			sub		r11,r10,r11					; Get the index into the table
			rlwinm	r11,r11,3,0,28				; Get offset to the physent

mMmrgRC:	lwarx	r10,r11,r2					; Get the master RC
			rlwinm	r0,r5,27,ppRb-32,ppCb-32	; Position the new RC
			or		r0,r0,r10					; Merge in the new RC
			stwcx.	r0,r11,r2					; Try to stick it back
			bne--	mMmrgRC						; Try again if we collided...
			eieio								; Commit all updates

mMPUnlock:				
			stw		r6,0(r7)					; Unlock PTEG
			blr									; Return

;
;			64-bit version of mapMergeRC
;
			.align	5

mapMergeRC64:
			lwz		r0,mpPte(r31)				; Grab the PTE offset
			ld		r5,mpVAddr(r31)				; Grab the virtual address
			mfsdr1	r7							; Get the pointer to the hash table
			rldicr	r10,r7,0,45					; Clean up the hash table base
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			srdi	r7,r0,5						; Convert to PCA units
			rldicr	r7,r7,0,61					; Clean up PCA
			subfic	r7,r7,-4					; Convert to -4 based negative index
			mflr	r2							; Save the return
			add		r7,r10,r7					; Point to the PCA directly
			beqlr--								; There was no PTE to start with...
			
			bl		mapLockPteg					; Lock the PTEG
			
			lwz		r0,mpPte(r31)				; Grab the PTE offset again
			mtlr	r2							; Restore the LR
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			beq--	mMPUnlock					; There is no PTE, someone took it so just unlock and leave...

			rlwinm	r3,r0,0,0,30				; Clear the valid bit
			add		r3,r3,r10					; Point to the actual PTE
			ld		r5,8(r3)					; Get the real part
			srdi	r10,r5,12					; Change physical address to a ppnum
			b		mMNmerge					; Join the common 32-64-bit code...


;
;			This routine, given a mapping, will find and lock the PTEG
;			If mpPte does not point to a PTE (checked before and after lock), it will unlock the
;			PTEG and return.  In this case we will have undefined in R4
;			and the low 12 bits of mpVAddr valid in R5.  R3 will contain 0.
;
;			If the mapping is still valid, we will invalidate the PTE and merge
;			the RC bits into the physent and also save them into the mapping.
;
;			We then return with R3 pointing to the PTE slot, R4 is the
;			top of the PTE and R5 is the bottom.  R6 contains the PCA.
;			R7 points to the PCA entry.
;
;			Note that we should NEVER be called on a block or special mapping.
;			We could do many bad things.
;

			.align	5

mapInvPte32:
			lwz		r0,mpPte(r31)				; Grab the PTE offset
			mfsdr1	r7							; Get the pointer to the hash table
			lwz		r5,mpVAddr+4(r31)			; Grab the virtual address
			rlwinm	r10,r7,0,0,15				; Clean up the hash table base
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			srwi	r7,r0,4						; Convert to PCA units
			rlwinm	r7,r7,0,0,29				; Clean up PCA offset
			mflr	r2							; Save the return
			subfic	r7,r7,-4					; Convert to -4 based negative index
			add		r7,r10,r7					; Point to the PCA directly
			beqlr--								; There was no PTE to start with...
			
			bl		mapLockPteg					; Lock the PTEG

			lwz		r0,mpPte(r31)				; Grab the PTE offset
			mtlr	r2							; Restore the LR
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			beq-	mIPUnlock					; There is no PTE, someone took it so just unlock and leave...

			rlwinm	r3,r0,0,0,30				; Clear the valid bit
			add		r3,r3,r10					; Point to actual PTE
			lwz		r4,0(r3)					; Get the top of the PTE
			
			li		r8,tlbieLock				; Get the TLBIE lock
			rlwinm	r0,r4,0,1,31				; Clear the valid bit
			stw		r0,0(r3)					; Invalidate the PTE

			sync								; Make sure everyone sees the invalidate
			
mITLBIE32:	lwarx	r0,0,r8						; Get the TLBIE lock 
			mfsprg	r2,2						; Get feature flags 
			mr.		r0,r0						; Is it locked? 
			li		r0,1						; Get our lock word 
			bne-	mITLBIE32					; It is locked, go wait...
			
			stwcx.	r0,0,r8						; Try to get it
			bne-	mITLBIE32					; We was beat...
			
			rlwinm.	r0,r2,0,pfSMPcapb,pfSMPcapb	; Can this be an MP box?
			li		r0,0						; Lock clear value 

			tlbie	r5							; Invalidate it everywhere 
			
			beq-	mINoTS32					; Can not have MP on this machine...
			
			eieio								; Make sure that the tlbie happens first 
			tlbsync								; Wait for everyone to catch up 
			sync								; Make sure of it all
			
mINoTS32:	stw		r0,tlbieLock(0)				; Clear the tlbie lock
			lwz		r5,4(r3)					; Get the real part
			srwi	r10,r5,12					; Change physical address to a ppnum

mINmerge:	lbz		r11,mpFlags+1(r31)			; Get the offset to the physical entry table
			lwz		r0,mpVAddr+4(r31)			; Get the flags part of the field
			lis		r8,hi16(EXT(pmap_mem_regions))	; Get the top of the region table
			ori		r8,r8,lo16(EXT(pmap_mem_regions))	; Get the bottom of the region table
			rlwinm	r11,r11,2,24,29				; Mask index bits and convert to byte offset
			add		r11,r11,r8					; Point to the bank table
			lwz		r2,mrPhysTab(r11)			; Get the physical table bank pointer
			lwz		r11,mrStart(r11)			; Get the start of bank
			rlwimi	r0,r5,0,mpRb-32,mpCb-32		; Copy in the RC
			addi	r2,r2,4						; Offset to last half of field
			stw		r0,mpVAddr+4(r31)			; Set the new RC into the field
			sub		r11,r10,r11					; Get the index into the table
			rlwinm	r11,r11,3,0,28				; Get offset to the physent


mImrgRC:	lwarx	r10,r11,r2					; Get the master RC
			rlwinm	r0,r5,27,ppRb-32,ppCb-32	; Position the new RC
			or		r0,r0,r10					; Merge in the new RC
			stwcx.	r0,r11,r2					; Try to stick it back
			bne--	mImrgRC						; Try again if we collided...
			
			blr									; Leave with the PCA still locked up...

mIPUnlock:	eieio								; Make sure all updates come first
				
			stw		r6,0(r7)					; Unlock
			blr

;
;			64-bit version
;
			.align	5

mapInvPte64:
			lwz		r0,mpPte(r31)				; Grab the PTE offset
			ld		r5,mpVAddr(r31)				; Grab the virtual address
			mfsdr1	r7							; Get the pointer to the hash table
			rldicr	r10,r7,0,45					; Clean up the hash table base
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			srdi	r7,r0,5						; Convert to PCA units
			rldicr	r7,r7,0,61					; Clean up PCA
			subfic	r7,r7,-4					; Convert to -4 based negative index
			mflr	r2							; Save the return
			add		r7,r10,r7					; Point to the PCA directly
			beqlr--								; There was no PTE to start with...
			
			bl		mapLockPteg					; Lock the PTEG
			
			lwz		r0,mpPte(r31)				; Grab the PTE offset again
			mtlr	r2							; Restore the LR
			andi.	r3,r0,mpHValid				; Is there a possible PTE?
			beq--	mIPUnlock					; There is no PTE, someone took it so just unlock and leave...

			rlwinm	r3,r0,0,0,30				; Clear the valid bit
			add		r3,r3,r10					; Point to the actual PTE
			ld		r4,0(r3)					; Get the top of the PTE

			li		r8,tlbieLock				; Get the TLBIE lock
			rldicr	r0,r4,0,62					; Clear the valid bit
			std		r0,0(r3)					; Invalidate the PTE
			
			rldicr	r2,r4,16,35					; Shift the AVPN over to match VPN
			sync								; Make sure everyone sees the invalidate
			rldimi	r2,r5,0,36					; Cram in the page portion of the EA
			
mITLBIE64:	lwarx	r0,0,r8						; Get the TLBIE lock 
			mr.		r0,r0						; Is it locked? 
			li		r0,1						; Get our lock word 
			bne--	mITLBIE64a					; It is locked, toss reservation and wait...
			
			stwcx.	r0,0,r8						; Try to get it
			bne--	mITLBIE64					; We was beat...

			rldicl	r2,r2,0,16					; Clear bits 0:15 because we are under orders
			
			li		r0,0						; Lock clear value 

			tlbie	r2							; Invalidate it everywhere 

			eieio								; Make sure that the tlbie happens first 
			tlbsync								; Wait for everyone to catch up 
			ptesync								; Wait for quiet again

			stw		r0,tlbieLock(0)				; Clear the tlbie lock

			ld		r5,8(r3)					; Get the real part
			srdi	r10,r5,12					; Change physical address to a ppnum
			b		mINmerge					; Join the common 32-64-bit code...

mITLBIE64a:	li		r5,lgKillResv				; Killing field
			stwcx.	r5,0,r5						; Kill reservation
			
mITLBIE64b:	lwz		r0,0(r8)					; Get the TLBIE lock
			mr.		r0,r0						; Is it locked?
			beq++	mITLBIE64					; Nope, try again...
			b		mITLBIE64b					; Yup, wait for it...

;
;			mapLockPteg - Locks a PTEG
;			R7 points to PCA entry
;			R6 contains PCA on return
;
;

			.align	5
			
mapLockPteg:
			lwarx	r6,0,r7						; Pick up the PCA
			rlwinm.	r0,r6,0,PCAlockb,PCAlockb	; Is the PTEG locked?
			ori		r0,r6,PCAlock				; Set the lock bit
			bne--	mLSkill						; It is locked...
			
			stwcx.	r0,0,r7						; Try to lock the PTEG
			bne--	mapLockPteg					; We collided...
			
			isync								; Nostradamus lied
			blr									; Leave...
				
mLSkill:	li		r6,lgKillResv				; Get killing field
			stwcx.	r6,0,r6						; Kill it

mapLockPteh:
			lwz		r6,0(r7)					; Pick up the PCA
			rlwinm.	r0,r6,0,PCAlockb,PCAlockb	; Is the PTEG locked?
			beq++	mapLockPteg					; Nope, try again...
			b		mapLockPteh					; Yes, wait for it...
			

;
;			The mapSelSlot function selects a PTEG slot to use. As input, it expects R6 
;			to contain the PCA.  When it returns, R3 contains 0 if an unoccupied slot was
;			selected, 1 if it stole a non-block PTE, or 2 if it stole a block mapped PTE.
;			R4 returns the slot index.
;
;			CR7 also indicates that we have a block mapping
;
;			The PTEG allocation controls are a bit map of the state of the PTEG. 
;			PCAfree indicates that the PTE slot is empty. 
;			PCAauto means that it comes from an autogen area.  These
;			guys do not keep track of reference and change and are actually "wired".
;			They are easy to maintain. PCAsteal
;			is a sliding position mask used to "randomize" PTE slot stealing.  All 4 of these
;			fields fit in a single word and are loaded and stored under control of the
;			PTEG control area lock (PCAlock).
;
;			Note that PCAauto does not contribute to the steal calculations at all.  Originally
;			it did, autogens were second in priority.  This can result in a pathalogical
;			case where an instruction can not make forward progress, or one PTE slot
;			thrashes.
;
;			Note that the PCA must be locked when we get here.
;
;			Physically, the fields are arranged:
;				0: PCAfree
;				1: PCAsteal
;				2: PCAauto
;				3: PCAmisc
;				
;
;			At entry, R6 contains new unlocked PCA image (real PCA is locked and untouched)
;
;			At exit:
;
;			R3 = 0 - no steal
;			R3 = 1 - steal regular
;			R3 = 2 - steal autogen
;			R4 contains slot number
;			R6 contains updated PCA image
;

			.align	5
			
mapSelSlot:	lis		r10,0						; Clear autogen mask
			li		r9,0						; Start a mask
			beq		cr7,mSSnotblk				; Skip if this is not a block mapping
			ori		r10,r10,lo16(0xFFFF)		; Make sure we mark a block mapping (autogen)

mSSnotblk:	rlwinm	r11,r6,16,24,31				; Isolate just the steal mask
			oris	r9,r9,0x8000				; Get a mask
			cntlzw	r4,r6						; Find a slot or steal one
			ori		r9,r9,lo16(0x8000)			; Insure that we have 0x80008000
			rlwinm	r4,r4,0,29,31				; Isolate bit position
			rlwimi	r11,r11,8,16,23				; Get set to march a 1 back into top of 8 bit rotate
			srw		r2,r9,r4					; Get mask to isolate selected inuse and autogen flags
			srwi	r11,r11,1					; Slide steal mask right
			and		r8,r6,r2					; Isolate the old in use and autogen bits
			andc	r6,r6,r2					; Allocate the slot and also clear autogen flag
			addi	r0,r8,0x7F00				; Push autogen flag to bit 16
			and		r2,r2,r10					; Keep the autogen part if autogen
			addis	r8,r8,0xFF00				; Push in use to bit 0 and invert
			or		r6,r6,r2					; Add in the new autogen bit 
			rlwinm	r0,r0,17,31,31				; Get a 1 if the old was autogenned (always 0 if not in use)
			rlwinm	r8,r8,1,31,31				; Isolate old in use
			rlwimi	r6,r11,16,8,15				; Stick the new steal slot in

			add		r3,r0,r8					; Get 0 if no steal, 1 if steal normal, 2 if steal autogen			
			blr									; Leave...
			
;
;			Shared/Exclusive locks
;
;			A shared/exclusive lock allows multiple shares of a lock to be taken
;			but only one exclusive.  A shared lock can be "promoted" to exclusive
;			when it is the only share.  If there are multiple sharers, the lock
;			must be "converted".  A promotion drops the share and gains exclusive as
;			an atomic operation.  If anyone else has a share, the operation fails.
;			A conversion first drops the share and then takes an exclusive lock.
;
;			We will want to add a timeout to this eventually.
;
;			R3 is set to 0 for success, non-zero for failure
;

;
;			Convert a share into an exclusive
;

			.align	5
			
sxlkConvert:

			lis		r0,0x8000					; Get the locked lock image
#if 0
			mflr	r0							; (TEST/DEBUG)
			oris	r0,r0,0x8000				; (TEST/DEBUG)
#endif
		
sxlkCTry:	lwarx	r2,0,r3						; Get the lock word
			cmplwi	r2,1						; Does it just have our share?
			subi	r2,r2,1						; Drop our share in case we do not get it
			bne--	sxlkCnotfree				; No, we need to unlock...
			stwcx.	r0,0,r3						; Try to take it exclusively
			bne--	sxlkCTry					; Collision, try again...
			
			isync
			li		r3,0						; Set RC
			blr									; Leave...

sxlkCnotfree:
			stwcx.	r2,0,r3						; Try to drop our share...	
			bne--	sxlkCTry					; Try again if we collided...
			b		sxlkExclusive				; Go take it exclusively...

;
;			Promote shared to exclusive
;

			.align	5
			
sxlkPromote:
			lis		r0,0x8000					; Get the locked lock image
#if 0
			mflr	r0							; (TEST/DEBUG)
			oris	r0,r0,0x8000				; (TEST/DEBUG)
#endif
		
sxlkPTry:	lwarx	r2,0,r3						; Get the lock word
			cmplwi	r2,1						; Does it just have our share?
			bne--	sxlkPkill					; No, just fail (R3 is non-zero)...
			stwcx.	r0,0,r3						; Try to take it exclusively
			bne--	sxlkPTry					; Collision, try again...
			
			isync
			li		r3,0						; Set RC
			blr									; Leave...

sxlkPkill:	li		r2,lgKillResv				; Point to killing field
			stwcx.	r2,0,r2						; Kill reservation
			blr									; Leave



;
;			Take lock exclusivily
;

			.align	5
			
sxlkExclusive:
			lis		r0,0x8000					; Get the locked lock image
#if 0
			mflr	r0							; (TEST/DEBUG)
			oris	r0,r0,0x8000				; (TEST/DEBUG)
#endif
		
sxlkXTry:	lwarx	r2,0,r3						; Get the lock word
			mr.		r2,r2						; Is it locked?
			bne--	sxlkXWait					; Yes...
			stwcx.	r0,0,r3						; Try to take it
			bne--	sxlkXTry					; Collision, try again...
			
			isync								; Toss anything younger than us
			li		r3,0						; Set RC
			blr									; Leave...
			
			.align	5

sxlkXWait:	li		r2,lgKillResv				; Point to killing field
			stwcx.	r2,0,r2						; Kill reservation
			
sxlkXWaiu:	lwz		r2,0(r3)					; Get the lock again
			mr.		r2,r2						; Is it free yet?
			beq++	sxlkXTry					; Yup...
			b		sxlkXWaiu					; Hang around a bit more...

;
;			Take a share of the lock
;

			.align	5
			
sxlkShared:	lwarx	r2,0,r3						; Get the lock word
			rlwinm.	r0,r2,0,0,0					; Is it locked exclusively?
			addi	r2,r2,1						; Up the share count
			bne--	sxlkSWait					; Yes...
			stwcx.	r2,0,r3						; Try to take it
			bne--	sxlkShared					; Collision, try again...
			
			isync								; Toss anything younger than us
			li		r3,0						; Set RC
			blr									; Leave...
			
			.align	5

sxlkSWait:	li		r2,lgKillResv				; Point to killing field
			stwcx.	r2,0,r2						; Kill reservation

sxlkSWaiu:	lwz		r2,0(r3)					; Get the lock again
			rlwinm.	r0,r2,0,0,0					; Is it locked exclusively?
			beq++	sxlkShared					; Nope...
			b		sxlkSWaiu					; Hang around a bit more...

;
;			Unlock either exclusive or shared.
;

			.align	5
			
sxlkUnlock:	eieio								; Make sure we order our stores out
		
sxlkUnTry:	lwarx	r2,0,r3						; Get the lock
			rlwinm.	r0,r2,0,0,0					; Do we hold it exclusively?
			subi	r2,r2,1						; Remove our share if we have one
			li		r0,0						; Clear this
			bne--	sxlkUExclu					; We hold exclusive...
			
			stwcx.	r2,0,r3						; Try to lose our share
			bne--	sxlkUnTry					; Collision...
			blr									; Leave...
			
sxlkUExclu:	stwcx.	r0,0,r3						; Unlock and release reservation
			beqlr++								; Leave if ok...
			b		sxlkUnTry					; Could not store, try over...	
			

			.align	5
			.globl	EXT(fillPage)

LEXT(fillPage)

 			mfsprg	r0,2						; Get feature flags 
			mtcrf	0x02,r0						; move pf64Bit to cr

			rlwinm	r4,r4,0,1,0					; Copy fill to top of 64-bit register
			lis		r2,0x0200					; Get vec
			mr		r6,r4						; Copy
			ori		r2,r2,0x2000				; Get FP
			mr		r7,r4						; Copy
			mfmsr	r5							; Get MSR
			mr		r8,r4						; Copy
			andc	r5,r5,r2					; Clear out permanent turn-offs
			mr		r9,r4						; Copy
			ori		r2,r2,0x8030				; Clear IR, DR and EE
			mr		r10,r4						; Copy
			andc	r0,r5,r2					; Kill them
			mr		r11,r4						; Copy
			mr		r12,r4						; Copy
			bt++	pf64Bitb,fpSF1				; skip if 64-bit (only they take the hint)
			
			slwi	r3,r3,12					; Make into a physical address
			mtmsr	r2							; Interrupts and translation off
			isync
			
			li		r2,4096/32					; Get number of cache lines
			
fp32again:	dcbz	0,r3						; Clear
			addic.	r2,r2,-1					; Count down
			stw		r4,0(r3)					; Fill
			stw		r6,4(r3)					; Fill
			stw		r7,8(r3)					; Fill
			stw		r8,12(r3)					; Fill
			stw		r9,16(r3)					; Fill
			stw		r10,20(r3)					; Fill
			stw		r11,24(r3)					; Fill
			stw		r12,28(r3)					; Fill
			addi	r3,r3,32					; Point next
			bgt+	fp32again					; Keep going

			mtmsr	r5							; Restore all
			isync
			blr									; Return...
			
			.align	5
			
fpSF1:		li		r2,1
			sldi	r2,r2,63					; Get 64-bit bit
			or		r0,r0,r2					; Turn on 64-bit
			sldi	r3,r3,12					; Make into a physical address

			mtmsrd	r0							; Interrupts and translation off
			isync
			
			li		r2,4096/128					; Get number of cache lines
						
fp64again:	dcbz128	0,r3						; Clear
			addic.	r2,r2,-1					; Count down
			std		r4,0(r3)					; Fill
			std		r6,8(r3)					; Fill
			std		r7,16(r3)					; Fill
			std		r8,24(r3)					; Fill
			std		r9,32(r3)					; Fill
			std		r10,40(r3)					; Fill
			std		r11,48(r3)					; Fill
			std		r12,56(r3)					; Fill
			std		r4,64+0(r3)					; Fill
			std		r6,64+8(r3)					; Fill
			std		r7,64+16(r3)				; Fill
			std		r8,64+24(r3)				; Fill
			std		r9,64+32(r3)				; Fill
			std		r10,64+40(r3)				; Fill
			std		r11,64+48(r3)				; Fill
			std		r12,64+56(r3)				; Fill
			addi	r3,r3,128					; Point next
			bgt+	fp64again					; Keep going

			mtmsrd	r5							; Restore all
			isync
			blr									; Return...
			
			.align	5
			.globl	EXT(mapLog)

LEXT(mapLog)

			mfmsr	r12
			lis		r11,hi16(EXT(mapdebug))
			ori		r11,r11,lo16(EXT(mapdebug))
			lwz		r10,0(r11)
			mr.		r10,r10
			bne++	mLxx
			mr		r10,r3
mLxx:		rlwinm	r0,r12,0,MSR_DR_BIT+1,MSR_DR_BIT-1
			mtmsr	r0
			isync
			stw		r4,0(r10)
			stw		r4,4(r10)
			stw		r5,8(r10)
			stw		r6,12(r10)
			mtmsr	r12
			isync
			addi	r10,r10,16
			stw		r10,0(r11)
			blr
			
#if 1
			.align	5
			.globl	EXT(checkBogus)

LEXT(checkBogus)

			BREAKPOINT_TRAP
			blr									; No-op normally
			
#endif						




