/*
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
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

/* skiplists.s
 *
 * These are the subroutines that manage the skip-list data structures used for the
 * resident mappings for each pmap.  We used to use a much simpler hash-based scheme,
 * but it didn't scale well for 64-bit address spaces and multi-GB real memories.
 * Here's a brief tutorial on skip-lists:
 *
 * The basic idea is that each mapping is on one or more singly-linked lists, sorted
 * in increasing order by virtual address.  The number of lists a mapping is on is an
 * invariant property determined when the mapping is created, using an exponentially-
 * distributed random number.  Every mapping is on the first list.  Ideally, each
 * successive list has only 1/F as many nodes on it as the previous, where F is the
 * "fanout."  With a max of n lists, up to F**n nodes can be handled optimally.
 *
 * Searching, adding, and deleting from a skip-list can all be done in O(ln(n)) time.
 * Because the first skip-list is just a sorted list of all mappings, it is also
 * efficient to purge a sparsely populated pmap of all the mappings in a large range,
 * for example when tearing down an address space.  Large-range deletes are the
 * primary advantage of skip-lists over a hash, btw.
 *
 * We currently use a fanout of 4 and a maximum of 12 lists (cf kSkipListFanoutShift
 * and kSkipListMaxLists.)  Thus, we can optimally handle pmaps with as many as 4**12 
 * pages, which is 64GB of resident physical memory per pmap.  Pmaps can be larger than
 * this, albeit with diminishing efficiency.
 *
 * The major problem with skip-lists is that we could waste a lot of space with 12
 * 64-bit link fields in every mapping.  So we currently have two sizes of mappings:
 * 64-byte nodes with 4 list links, and 128-byte nodes with 12.  Only one in every
 * (4**4)==256 mappings requires the larger node, so the average size is 64.25 bytes.
 * In practice, the additional complexity of the variable node size is entirely
 * contained in the allocate and free routines.
 *
 * The other, mostly theoretic problem with skip-lists is that they have worst cases
 * where performance becomes nearly linear.  These worst-cases are quite rare but there
 * is no practical way to prevent them.
 */   
 

; set nonzero to accumulate skip-list stats on a per-map basis:
#define	SKIPLISTSTATS	1

; cr7 bit set when mapSearchFull() finds a match on a high list:
#define	bFullFound	28

#include <assym.s>
#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>


/*
 *  *********************
 * 	* m a p S e a r c h *
 *	*********************
 *
 * Given a pmap and a virtual address (VA), find the mapping for that address.
 * This is the fast call, that does not set up the previous-ptr vector or make
 * consistency checks.  When called:
 *		the pmap is locked (shared or exclusive)
 *		translation is off, interrupts masked
 *		64-bit mode is enabled (if on a 64-bit machine)
 *		cr6 is loaded with the corresponding feature flags (in particular, pf64Bit)
 *		r3 = pmap ptr
 *		r4 = high 32 bits of key to search for (0 if a 32-bit processor)
 *		r5 = low 32 bits of key (low 12 bits may be nonzero garbage)
 *		r7 = mpFlags field if found.  Undefined if not
 *
 * We return the mapping ptr (or 0) in r3, and the next VA (or 0 if no more) in r4 and r5.
 * Except for cr6 (which is global), we trash nonvolatile regs.  Called both on 32- and 64-bit
 * machines, though we quickly branch into parallel code paths.
 */ 
            .text
			.align	5
            .globl	EXT(mapSearch)
LEXT(mapSearch)
            lbz		r7,pmapCurLists(r3)		; get largest #lists any mapping is on
            la		r8,pmapSkipLists+4(r3)	; point to lists in pmap, assuming 32-bit machine
            rlwinm	r5,r5,0,0,19			; zero low 12 bits of key
            mr		r6,r3					; save pmap ptr here so we can accumulate statistics
            li		r9,0					; initialize prev ptr
            addic.	r7,r7,-1				; get base-0 number of last list, and test for 0
            li		r2,0					; initialize count of mappings visited
            slwi	r7,r7,3					; get offset of last list in use
            blt--	mapSrchPmapEmpty		; pmapCurLists==0 (ie, no mappings)
            lwzx	r3,r8,r7				; get 32-bit ptr to 1st mapping in highest list
            bf--	pf64Bitb,mapSrch32c		; skip if 32-bit processor
            subi	r8,r8,4					; we use all 64 bits of ptrs
            rldimi	r5,r4,32,0				; r5 <- 64-bit va
            ldx		r3,r8,r7				; get 64-bit ptr to 1st mapping in highest list
            b		mapSrch64c				; enter 64-bit search loop

            
            ; 64-bit processors.  Check next mapping.
            ;   r2 = count of mappings visited so far
            ;	r3 = current mapping ptr
            ;	r4 = va of current mapping (ie, of r3)
            ;	r5 = va to search for (the "key") (low 12 bits are 0)
            ;	r6 = pmap ptr
            ;	r7 = current skip list number * 8
            ;	r8 = ptr to skip list vector of mapping pointed to by r9 (or pmap, if r9==0)
            ;	r9 = prev ptr, or 0 if none
            
            .align	5
mapSrch64a:									; loop over each mapping
            ld		r4,mpVAddr(r3)			; get va for this mapping (plus flags in low 12 bits)
            addi	r2,r2,1					; count mappings visited
            rldicr	r4,r4,0,51				; zero low 12 bits of mapping va
            cmpld	cr1,r5,r4				; compare the vas
            blt		cr1,mapSrch64d			; key is less, try next list
            la		r8,mpList0(r3)			; point to skip list vector in this mapping
            mr		r9,r3					; remember prev ptr
            beq--	cr1,mapSrch64Found		; this is the correct mapping
            ldx		r3,r7,r8				; get ptr to next mapping in current list
mapSrch64c:
            mr.		r3,r3					; was there another mapping on current list?
            bne++	mapSrch64a				; was another, so loop
mapSrch64d:
            subic.	r7,r7,8					; move on to next list offset
            ldx		r3,r7,r8				; get next mapping on next list (if any)
            bge++	mapSrch64c				; loop to try next list
          
            ; Mapping not found, check to see if prev node was a block mapping or nested pmap.
            ; If not, or if our address is not covered by the block or nested map, return 0.
            ; Note the advantage of keeping the check for block mappings (and nested pmaps)
            ; out of the inner loop; we do the special case work at most once per search, and
            ; never for the most-common case of finding a scalar mapping.  The full searches
            ; must check _in_ the inner loop, to get the prev ptrs right.

			mr.		r9,r9					; was there a prev ptr?
			li		r3,0					; assume we are going to return null
			ld		r4,pmapSkipLists(r6)	; assume prev ptr null... so next is first
			beq--	mapSrch64Exit			; prev ptr was null, search failed
			lwz		r0,mpFlags(r9)			; get flag bits from prev mapping
			lhz		r11,mpBSize(r9)			; get #pages/#segments in block/submap mapping
			
			rlwinm	r0,r0,mpBSub+1,31,31	; 0 if 4K bsu or 1 if 32MB bsu
			ld		r10,mpVAddr(r9)			; re-fetch base address of prev ptr
			ori		r0,r0,0x3216			; OR in 0x00003216 (0x3200 and a base rotate of 22)
			addi	r11,r11,1				; Convert 0-based to 1-based
			rlwnm	r0,r0,r0,27,31			; Rotate to get 12 or 25
			ld		r4,mpList0(r9)			; get 64-bit ptr to next mapping, if any
			sld		r11,r11,r0				; Get the length in bytes
			rldicr	r10,r10,0,51			; zero low 12 bits of mapping va
			subi	r0,r11,4096				; get offset last page in mapping
			add		r10,r10,r0				; r10 <- last page in this mapping
			cmpld	r5,r10					; does this mapping cover our page?
			bgt		mapSrch64Exit			; no, search failed
			mr		r3,r9					; yes, we found it

            ; found the mapping
            ;   r2 = count of nodes visited
            ;	r3 = the mapping
            ;	r6 = pmap ptr
            
mapSrch64Found:								; WARNING: can drop down to here
            ld		r4,mpList0(r3)			; get ptr to next mapping
            lwz		r7,mpFlags(r3)			; Get the flags for our caller
            
            ;   r2 = count of nodes visited
            ;	r3 = return value (ie, found mapping or 0)
            ;   r4 = next mapping (or 0 if none)
            ;	r6 = pmap ptr
            ;	r7 = mpFlags
            
mapSrch64Exit:								; WARNING: can drop down to here
            mr.		r5,r4					; next ptr null?
#if	SKIPLISTSTATS
            lwz		r10,pmapSearchCnt(r6)	; prepare to accumulate statistics
            ld		r8,pmapSearchVisits(r6)
            addi	r10,r10,1				; count searches
            add		r8,r8,r2				; count nodes visited
            stw		r10,pmapSearchCnt(r6)
            std		r8,pmapSearchVisits(r6)
#endif
            beqlr-							; next ptr was null, so return 0 in r4 and r5
            lwz		r5,mpVAddr+4(r4)		; get VA of next node
            lwz		r4,mpVAddr+0(r4)
            blr

            
            ; 32-bit processors.  Check next mapping.
            ;   r2 = count of mappings visited so far
            ;	r3 = current mapping ptr
            ;	r4 = va of current mapping (ie, of r3)
            ;	r5 = va to search for (the "key") (low 12 bits are 0)
            ;	r6 = pmap ptr
            ;	r7 = current skip list number * 8
            ;	r8 = ptr to skip list vector of mapping pointed to by r9 (or pmap, if r9==0)
            ;	r9 = prev ptr, or 0 if none
            
            .align	4
mapSrch32a:									; loop over each mapping
            lwz		r4,mpVAddr+4(r3)		; get va for this mapping (plus flags in low 12 bits)
            addi	r2,r2,1					; count mappings visited
            rlwinm	r4,r4,0,0,19			; zero low 12 bits of mapping va
            cmplw	cr1,r5,r4				; compare the vas
            blt		cr1,mapSrch32d			; key is less, try next list
            la		r8,mpList0+4(r3)		; point to skip list vector in this mapping
            mr		r9,r3					; remember prev ptr
            beq-	cr1,mapSrch32Found		; this is the correct mapping
            lwzx	r3,r7,r8				; get ptr to next mapping in current list
mapSrch32c:
            mr.		r3,r3					; was there another mapping on current list?
            bne+	mapSrch32a				; was another, so loop
mapSrch32d:
            subic.	r7,r7,8					; move on to next list offset
            lwzx	r3,r7,r8				; get next mapping on next list (if any)
            bge+	mapSrch32c				; loop to try next list
          
            ; Mapping not found, check to see if prev node was a block mapping or nested pmap.
            ; If not, or if our address is not covered by the block or nested map, return 0.
            ; Note the advantage of keeping the check for block mappings (and nested pmaps)
            ; out of the inner loop; we do the special case work at most once per search, and
            ; never for the most-common case of finding a scalar mapping.  The full searches
            ; must check _in_ the inner loop, to get the prev ptrs right.

			mr.		r9,r9					; was there a prev ptr?
			li		r3,0					; assume we are going to return null
			lwz		r4,pmapSkipLists+4(r6)	; assume prev ptr null... so next is first
			beq-	mapSrch32Exit			; prev ptr was null, search failed
			lwz		r0,mpFlags(r9)			; get flag bits from prev mapping
			lhz		r11,mpBSize(r9)			; get #pages/#segments in block/submap mapping
			lwz		r10,mpVAddr+4(r9)		; re-fetch base address of prev ptr
			
			rlwinm	r0,r0,mpBSub+1,31,31	; Rotate to get 0 if 4K bsu or 1 if 32MB bsu
			addi	r11,r11,1				; Convert 0-based to 1-based
			ori		r0,r0,0x3216			; OR in 0x00003216 (0x3200 and a base rotate of 22)
			rlwnm	r0,r0,r0,27,31			; Rotate to get 12 or 25
			lwz		r4,mpList0+4(r9)		; get ptr to next mapping, if any
			slw		r11,r11,r0				; Get length in bytes
			rlwinm	r10,r10,0,0,19			; zero low 12 bits of block mapping va
			subi	r0,r11,4096				; get address of last page in submap
			add		r10,r10,r0				; r10 <- last page in this mapping
			cmplw	r5,r10					; does this mapping cover our page?
			bgt		mapSrch32Exit			; no, search failed
			mr		r3,r9					; yes, we found it

            ; found the mapping
            ;   r2 = count of nodes visited
            ;	r3 = the mapping
            ;	r6 = pmap ptr
            
mapSrch32Found:								; WARNING: can drop down to here
            lwz		r4,mpList0+4(r3)		; get ptr to next mapping
            lwz		r7,mpFlags(r3)			; Get mpFlags for our caller
            ;   r2 = count of nodes visited
            ;	r3 = return value (ie, found mapping or 0)
            ;   r4 = next mapping (or 0 if none)
            ;	r6 = pmap ptr
            ;	r7 = mpFlags
            
mapSrch32Exit:
            mr.		r5,r4					; next ptr null?
#if	SKIPLISTSTATS
            lwz		r10,pmapSearchCnt(r6)	; prepare to accumulate statistics
            lwz		r8,pmapSearchVisits(r6)
            lwz		r9,pmapSearchVisits+4(r6)
            addi	r10,r10,1				; count searches
            addc	r9,r9,r2				; count nodes visited
            addze	r8,r8
            stw		r10,pmapSearchCnt(r6)
            stw		r8,pmapSearchVisits(r6)
            stw		r9,pmapSearchVisits+4(r6)
#endif
            beqlr-							; next ptr was null, so return 0 in r4 and r5
            lwz		r5,mpVAddr+4(r4)		; get VA of next node
            lwz		r4,mpVAddr+0(r4)
            blr

            ; Here when the pmap is empty (ie, pmapCurLists==0), both in 32 and 64-bit mode,
            ; and from both mapSearch and mapSearchFull.
            ;	r6 = pmap ptr
            
mapSrchPmapEmpty:
            li		r3,0					; return null
            li		r4,0					; return 0 as virtual address of next node
            li		r5,0
#if	SKIPLISTSTATS
            lwz		r7,pmapSearchCnt(r6)	; prepare to accumulate statistics
            addi	r7,r7,1					; count searches
            stw		r7,pmapSearchCnt(r6)
#endif
            blr
            

/*
 *  *****************************
 * 	* m a p S e a r c h F u l l *
 *	*****************************
 *
 * Given a pmap and a virtual address (VA), find the mapping for that address.
 * This is the "full" call, that sets up a vector of ptrs to the previous node
 * (or to the pmap, if there is no previous node) for each list that the mapping
 * in on.  We also make consistency checks on the skip-lists.  When called:
 *		the pmap is locked (shared or exclusive)
 *		translation is off, interrupts masked
 *		64-bit mode is enabled (if on a 64-bit machine)
 *		cr6 is loaded with the corresponding feature flags (in particular, pf64Bit)
 *		r3 = pmap ptr
 *		r4 = high 32 bits of key to search for (0 if a 32-bit processor)
 *		r5 = low 32 bits of key (low 12 bits may be nonzero garbage)
 *
 * We return the mapping ptr (or 0) in r3, and the next VA (or 0 if no more) in r4 and r5.
 * Except for cr6 (which is global), we trash nonvolatile regs.  Called both on 32- and 64-bit
 * machines, though we quickly branch into parallel code paths.
 */ 
            .text
			.align	5
            .globl	EXT(mapSearchFull)
LEXT(mapSearchFull)
            lbz		r7,pmapCurLists(r3)		; get largest #lists any mapping is on
            la		r8,pmapSkipLists+4(r3)	; point to lists in pmap, assuming 32-bit machine
            rlwinm	r5,r5,0,0,19			; zero low 12 bits of key
            mr		r6,r3					; save pmap ptr here so we can accumulate statistics
            li		r2,0					; initialize count of mappings visited
            mfsprg	r12,0					; get the per-proc data ptr
            crclr	bFullFound				; we have not found the mapping yet
            addic.	r7,r7,-1				; get base-0 number of last list, and test for 0
            subi	r9,r8,mpList0+4			; initialize prev ptr to be a fake mapping
            slwi	r7,r7,3					; get (offset*8) of last list
            la		r12,skipListPrev+4(r12)	; point to vector of prev ptrs, assuming 32-bit machine
            blt--	mapSrchPmapEmpty		; pmapCurLists==0 (ie, no mappings)
            lwzx	r3,r8,r7				; get 32-bit ptr to 1st mapping in highest list
            li		r10,0					; initialize prev ptrs VA to 0 too
            bf--	pf64Bitb,mapSrchFull32c	; skip if 32-bit processor
            subi	r8,r8,4					; we use all 64 bits of ptrs
            subi	r12,r12,4
            rldimi	r5,r4,32,0				; r5 <- 64-bit va
            ldx		r3,r8,r7				; get 64-bit ptr to 1st mapping in highest list
            b		mapSrchFull64c			; enter 64-bit search loop

            
            ; 64-bit processors.  Check next mapping.
            ;   r2 = count of mappings visited so far
            ;	r3 = current mapping ptr
            ;	r4 = va of current mapping (ie, of r3)
            ;	r5 = va to search for (the "key") (low 12 bits are 0)
            ;	r6 = pmap ptr
            ;	r7 = current skip list number * 8
            ;	r8 = ptr to skip list vector of mapping pointed to by r9
            ;	r9 = prev ptr, ie highest mapping that comes before search target (initially the pmap)
            ;  r10 = lowest expected next va, 0 at the beginning of the search 
            ;  r12 = ptr to the skipListPrev vector in the per-proc
            
            .align	5
mapSrchFull64a:								; loop over each mapping
			addi	r2,r2,1					; count mappings visited
			lwz		r0,mpFlags(r3)			; get mapping flag bits
			lhz		r11,mpBSize(r3)			; get #pages/#segments in block/submap mapping
			ld		r4,mpVAddr(r3)			; get va for this mapping (plus flags in low 12 bits)

			rlwinm	r0,r0,mpBSub+1,31,31	; Rotate to get 0 if 4K bsu or 1 if 32MB bsu
			addi	r11,r11,1				; Convert 0-based to 1-based
			ori		r0,r0,0x3216			; OR in 0x00003216 (0x3200 and a base rotate of 22)
			rlwnm	r0,r0,r0,27,31			; Rotate to get 12 or 25
			sld		r11,r11,r0				; Get the length in bytes
            rldicr	r4,r4,0,51				; zero low 12 bits of mapping va
            addic.	r0,r11,-4096			; get offset last page in mapping (set cr0_eq if 1 page)

            cmpld	cr5,r10,r4				; make sure VAs come in strictly ascending order
            cmpld	cr1,r5,r4				; compare the vas
            bgt--	cr5,mapSkipListPanic	; die if keys are out of order

            blt		cr1,mapSrchFull64d		; key is less, try next list
            beq		cr1,mapSrchFull64Found	; this is the correct mapping
            bne--	cr0,mapSrchFull64e		; handle mapping larger than one page
mapSrchFull64b:
            la		r8,mpList0(r3)			; point to skip list vector in this mapping
            mr		r9,r3					; current becomes previous
            ldx		r3,r7,r8				; get ptr to next mapping in current list
            addi	r10,r4,0x1000			; Get the lowest VA we can get next
mapSrchFull64c:
            mr.		r3,r3					; was there another mapping on current list?
            bne++	mapSrchFull64a			; was another, so loop
mapSrchFull64d:
            stdx	r9,r7,r12				; save prev ptr in per-proc vector
            subic.	r7,r7,8					; move on to next list offset
            ldx		r3,r7,r8				; get next mapping on next list (if any)
            bge++	mapSrchFull64c			; loop to try next list
          
            ; Mapping not found, return 0 and next higher key

            li		r3,0					; return null
            bt--	bFullFound,mapSkipListPanic	; panic if it was on earlier list
            ld		r4,mpList0(r9)			; get 64-bit ptr to next mapping, if any
            b		mapSrch64Exit
            
            ; Block mapping or nested pmap, and key > base.  We must compute the va of
            ; the end of the block to see if key fits within it.

mapSrchFull64e:            
            add		r4,r4,r0				; r4 <- last page in this mapping
            cmpld	r5,r4					; does this mapping cover our page?
            bgt		mapSrchFull64b			; no, try next mapping (r4 is advanced to end of range)


            ; found the mapping
            ;   r2 = count of nodes visited
            ;	r3 = the mapping
            ;	r6 = pmap ptr
            ;	r7 = current skip list number * 8
            ;	r8 = ptr to prev mappings (ie, r9) skip-list vector
            ;	r9 = prev ptr, ie highest mapping that comes before search target
            ;  r10 = prev mappings va
            ;  r12 = ptr to the skipListPrev vector in the per-proc
            
mapSrchFull64Found:							; WARNING: can drop down to here
            cmpwi	r7,0					; are we in the last skip-list?
            crset	bFullFound				; remember that we found the mapping
            bne		mapSrchFull64d			; mapSearchFull must search all lists to get prev ptrs
            ld		r4,mpList0(r3)			; get ptr to next mapping
            stdx	r9,r7,r12				; save prev ptr in last list
            lwz		r7,mpFlags(r3)			; Get the flags for our caller
            b		mapSrch64Exit

            
            ; 32-bit processors.  Check next mapping.
            ;   r2 = count of nodes visited
            ;	r3 = ptr to next mapping in current list
            ;	r5 = va to search for (the "key") (low 12 bits are 0)
            ;	r6 = pmap ptr
            ;	r7 = current skip list number * 8
            ;	r8 = ptr to skip list vector of mapping pointed to by r9
            ;	r9 = prev ptr, ie highest mapping that comes before search target (initially the pmap)
            ;  r10 = lowest expected next va, 0 at the beginning of the search 
            ;  r12 = ptr to the skipListPrev vector in the per-proc
            
            .align	4
mapSrchFull32a:								; loop over each mapping
			addi	r2,r2,1					; count mappings visited
			lwz		r0,mpFlags(r3)			; get mapping flag bits
			lhz		r11,mpBSize(r3)			; get #pages/#segments in block/submap mapping
			lwz		r4,mpVAddr+4(r3)		; get va for this mapping (plus flags in low 12 bits)
						
			rlwinm	r0,r0,mpBSub+1,31,31	; Rotate to get 0 if 4K bsu or 1 if 32MB bsu
			addi	r11,r11,1				; Convert 0-based to 1-based
			ori		r0,r0,0x3216			; OR in 0x00003216 (0x3200 and a base rotate of 22)
			rlwnm	r0,r0,r0,27,31			; Rotate to get 12 or 25
			slw		r11,r11,r0				; Get the length in bytes
			rlwinm	r4,r4,0,0,19			; zero low 12 bits of mapping va
            addic.	r0,r11,-4096			; get offset last page in mapping (set cr0_eq if 1 page)

			cmplw	cr0,r10,r4				; make sure VAs come in strictly ascending order
			cmplw	cr1,r5,r4				; compare the vas
			bgt-	cr0,mapSkipListPanic	; die if keys are out of order
			
			blt		cr1,mapSrchFull32d		; key is less than this va, try next list
			beq		cr1,mapSrchFull32Found	; this is the correct mapping
			bne-	cr0,mapSrchFull32e		; handle mapping larger than one page
mapSrchFull32b:
            la		r8,mpList0+4(r3)		; point to skip list vector in this mapping
            mr		r9,r3					; current becomes previous
            lwzx	r3,r7,r8				; get ptr to next mapping in current list
            addi	r10,r4,0x1000			; Get the lowest VA we can get next
mapSrchFull32c:
            mr.		r3,r3					; next becomes current
            bne+	mapSrchFull32a			; was another, so loop
mapSrchFull32d:
            stwx	r9,r7,r12				; save prev ptr in per-proc vector
            subic.	r7,r7,8					; move on to next list offset
            lwzx	r3,r7,r8				; get next mapping on lower list (if any)
            bge+	mapSrchFull32c			; loop to try next list

            ; mapping not found, return 0 and next-key
            
            li		r3,0					; return null
            bt-		bFullFound,mapSkipListPanic	; panic if it was on an earlier list
            lwz		r4,mpList0+4(r9)		; get ptr to next mapping
            b		mapSrch32Exit
            
            ; Block mapping or nested pmap, and key > base.  We must compute the va of
            ; the end of the block to see if our key fits within it.

mapSrchFull32e:            
            add		r4,r4,r0				; r4 <- last page in this mapping
            cmplw	r5,r4					; does this mapping cover our page?
            bgt		mapSrchFull32b			; no, try next mapping
            
            
            ; found the mapping
            ;   r2 = count of nodes visited
            ;	r3 = the mapping
            ;	r6 = pmap ptr
            ;	r7 = current skip list number * 8
            ;	r9 = prev ptr, ie highest mapping that comes before search target, or 0
            ;  r10 = prev mappings va
            ;  r12 = ptr to the skipListPrev vector in the per-proc
            
mapSrchFull32Found:							; WARNING: can drop down to here
            cmpwi	r7,0					; are we in the last skip-list?
            crset	bFullFound				; remember that we found the mapping
            bne		mapSrchFull32d			; mapSearchFull must search all lists to get prev ptrs
            lwz		r4,mpList0+4(r3)		; get ptr to next mapping
            stwx	r9,r7,r12				; save prev ptr in last list
            lwz		r7,mpFlags(r3)			; Get mpFlags for our caller
            b		mapSrch32Exit


/*
 * 	*********************
 * 	* m a p I n s e r t *
 *	*********************
 *
 * Insert a mapping into pmap skip-lists.  The caller has already called mapSearchFull to 
 * determine that this mapping does not overlap other mappings in the pmap.  As a side effect 
 * of calling mapSearchFull, the per-proc skipListPrev array is set up with a vector of the 
 * previous ptrs for each skip list.  When called:
 *		the pmap is locked (exclusive)
 *		translation is off, interrupts masked
 *		64-bit mode is enabled (if on a 64-bit machine)
 *		mapSearchFull has just been called for this mappings key
 *		cr6 is loaded with the corresponding feature flags (in particular, pf64Bit)
 *		r3 = pmap ptr
 *		r4 = mapping ptr
 *
 * There is no return value.  Except for cr6 (which is global), we trash nonvolatile regs.
 */ 

			.align	5
			.globl	EXT(mapInsert)
LEXT(mapInsert)
            lwz		r8,mpFlags(r4)			; get this mappings flags
            lbz		r7,pmapCurLists(r3)		; get current max# lists any mapping is on
            la		r10,pmapSkipLists+4(r3)	; r10 <-- base of pmap list headers, assuming 32-bit machine
            la		r11,mpList0+4(r4)		; r11 <-- base of this mappings list vector
            mfsprg	r12,0					; get ptr to our per-proc
            andi.	r9,r8,mpLists			; get #lists this mapping is on (1<=n<=27)
            la		r12,skipListPrev+4(r12)	; r12 <-- base of prev ptr vector
            sub.	r6,r9,r7				; is this mapping on more lists than any other?
            slwi	r8,r9,3					; get #lists * 8
            subi	r8,r8,8					; get offset to topmost (last) list in use
            bf--	pf64Bitb,mapIns32		; handle 32-bit processor
            subi	r10,r10,4				; we use all 8 bytes of the ptr fields
            subi	r11,r11,4
            subi	r12,r12,4
            ble++	mapIns64a				; not new max #lists
            
            ; 64-bit processor: We must increase pmapCurLists.  Since mapSearchFull() only
            ; sets up the first pmapCurLists prev ptrs, we must initialize the new ones to
            ; point to the pmap.  While we are at it, we verify that the unused list hdrs in
            ; the pmap are 0.
            
            cmpwi	r9,kSkipListMaxLists	; in range?
            stb		r9,pmapCurLists(r3)		; remember new max
            mtctr	r6						; set up count of new lists
            mr		r5,r8					; copy offset to last list
            subi	r0,r10,mpList0			; r0 <-- fake mapping ptr (to pmap) for null prev ptrs
            bgt--	mapSkipListPanic		; choke if this mapping is on too many lists
mapIns64NewList:
            ldx		r6,r5,r10				; get pmap list head
            stdx	r0,r5,r12				; initialize prev ptr
            subi	r5,r5,8					; get next list offset
            cmpdi	r6,0					; was list hdr null?
            bdnzt	cr0_eq,mapIns64NewList	; loop if more lists to initialize and list hdr was 0
            bne--	mapSkipListPanic		; die if pmap list hdr was not null
            b		mapIns64a
            
            ; 64-bit processor: loop over each list this mapping is on
            ;	 r4 = mapping
            ;	 r8 = next list offset
            ;	r10 = ptr to base of pmap list header vector
            ;	r11 = ptr to base of new mappings list vector
            ;	r12 = ptr to base of prev ptr vector in per-proc
            
            .align	5
mapIns64a:
            ldx		r5,r8,r12				; get prev ptr from per-proc vector
            cmpwi	cr1,r8,0				; more to go?
            la		r7,mpList0(r5)			; get base of prev mappings list vector
            ldx		r9,r8,r7				; ***
            stdx	r4,r8,r7				; * insert new mapping in middle of this list
            stdx	r9,r8,r11				; ***
            subi	r8,r8,8					; get next list offset
            bne++	cr1,mapIns64a			; more lists to go
            blr								; done		

            ; Handle 32-bit processor.  First, increase pmapCurLists if necessary; cr0 is bgt
            ; iff the new mapping has more lists.  Since mapSearchFull() only sets up the first
            ; pmapCurLists prev ptrs, we must initialize any new ones to point to the pmap.
            ; While we are at it, we verify that the unused list hdrs in the pmap are 0.
            
mapIns32:
            ble+	mapIns32a				; skip if new mapping does not use extra lists
            cmpwi	r9,kSkipListMaxLists	; in range?
            stb		r9,pmapCurLists(r3)		; remember new max
            mtctr	r6						; set up count of new lists
            mr		r5,r8					; copy offset to last list
            subi	r0,r10,mpList0+4		; r0 <-- fake mapping ptr (to pmap) for null prev ptrs
            bgt-	mapSkipListPanic		; choke if this mapping is on too many lists
mapIns32NewList:
            lwzx	r6,r5,r10				; get pmap list head
            stwx	r0,r5,r12				; initialize prev ptr
            subi	r5,r5,8					; get next list offset
            cmpwi	r6,0					; was list hdr null?
            bdnzt	cr0_eq,mapIns32NewList	; loop if more lists to initialize and list hdr was 0
            bne-	mapSkipListPanic		; die if pmap list hdr was not null
            b		mapIns32a
            
            ; 32-bit processor: loop over each list this mapping is on
            ;	 r4 = mapping
            ;	 r8 = next list offset
            ;	r10 = ptr to base of pmap list header vector
            ;	r11 = ptr to base of new mappings list vector
            ;	r12 = ptr to base of prev ptr vector
            
            .align	4
mapIns32a:
            lwzx	r5,r8,r12				; get prev ptr from per-proc vector
            cmpwi	cr1,r8,0				; more to go?
            la		r7,mpList0+4(r5)		; get base of prev mappings list vector
            lwzx	r9,r8,r7				; ***
            stwx	r4,r8,r7				; * insert new mapping in middle of this list
            stwx	r9,r8,r11				; ***
            subi	r8,r8,8					; get next list offset
            bne+	cr1,mapIns32a			; more lists to go
            blr								; done		


/*
 * 	*********************
 * 	* m a p R e m o v e *
 *	*********************
 *
 * Remove a mapping from pmap skip-lists.  The caller has already called mapSearchFull to 
 * find the mapping, which sets up the skipListPrev array with a vector of the previous
 * ptrs for each skip list.  When called:
 *		the pmap is locked (exclusive)
 *		translation is off, interrupts masked
 *		64-bit mode is enabled (if on a 64-bit machine)
 *		mapSearchFull has just been called for this mappings key
 *		cr6 is loaded with the corresponding feature flags (in particular, pf64Bit)
 *		r3 = pmap ptr
 *		r4 = mapping ptr
 *
 * There is no return value.  Except for cr6 (which is global), we trash nonvolatile regs.
 */ 

			.align	5
			.globl	EXT(mapRemove)
LEXT(mapRemove)
            lwz		r8,mpFlags(r4)			; get this mappings flags
            lbz		r10,pmapCurLists(r3)	; get current #lists in use
            la		r11,mpList0+4(r4)		; r11 <-- base of this mappings list vector
            mfsprg	r12,0					; get ptr to our per-proc
            andi.	r9,r8,mpLists			; get #lists this mapping is on (1<=n<=27)
            slwi	r8,r9,3					; get #lists * 8
            cmpw	cr5,r9,r10				; compare mpLists to pmapCurLists
            la		r12,skipListPrev+4(r12)	; r12 <-- base of prev ptr vector
            bgt--	cr5,mapSkipListPanic	; die if mpLists > pmapCurLists
            subi	r8,r8,8					; get offset to topmast (last) list this mapping is in
            bf--	pf64Bitb,mapRem32a		; skip if 32-bit processor
            subi	r11,r11,4				; we use all 64 bits of list links on 64-bit machines
            subi	r12,r12,4
            b		mapRem64a

            ; 64-bit processor: loop over each list this mapping is on
            ;	 r3 = pmap
            ;	 r4 = mapping
            ;	 r8 = offset to next list
            ;	r10 = pmapCurLists
            ;	r11 = ptr to base of mapping list vector
            ;	r12 = ptr to base of prev ptr vector in per-proc
            ;	cr5 = beq if (mpLists == pmapCurLists)

            .align	5
mapRem64a:
            ldx		r5,r8,r12				; get prev ptr from per-proc vector
            ldx		r9,r8,r11				; get next ptr from mapping
            cmpwi	cr1,r8,0				; more to go?
            la		r7,mpList0(r5)			; get base of prev mappings list vector
            stdx	r9,r8,r7				; point to next from prev
            subi	r8,r8,8					; get next list offset
            bne++	cr1,mapRem64a			; loop if another list to unlink from
            
            ; Did we reduce #lists in use by removing last mapping in last list?
            
            bnelr++	cr5						; if (mpLists!=pmapCurLists) cannot have removed last map
            la		r5,pmapSkipLists(r3)	; point to vector of list hdrs
mapRem64b:
            subic.	r10,r10,1				; get base-0 list#
            slwi	r8,r10,3				; get offset to last list
            ldx		r0,r8,r5				; get last list ptr
            cmpdi	cr1,r0,0				; null?
            bnelr	cr1						; not null, so we are done
            stb		r10,pmapCurLists(r3)	; was null, so decrement pmapCurLists
            bgt		mapRem64b				; loop to see if more than one list was emptied
            blr
            
            
            ; 32-bit processor: loop over each list this mapping is on
            ;	 r3 = pmap
            ;	 r4 = mapping
            ;	 r8 = offset to next list
            ;	r10 = pmapCurLists
            ;	r11 = ptr to base of mapping list vector
            ;	r12 = ptr to base of prev ptr vector in per-proc
            ;	cr5 = beq if (mpLists == pmapCurLists)
            
            .align	4
mapRem32a:
            lwzx	r5,r8,r12				; get prev ptr from per-proc vector
            lwzx	r9,r8,r11				; get next ptr from mapping
            cmpwi	cr1,r8,0				; more to go?
            la		r7,mpList0+4(r5)		; get base of prev mappings list vector
            stwx	r9,r8,r7				; point to next from prev
            subi	r8,r8,8					; get next list offset
            bne+	cr1,mapRem32a			; loop if another list to unlink from
            
            ; Did we reduce #lists in use by removing last mapping in last list?
            
            bnelr+	cr5						; if (mpLists!=pmapCurLists) cannot have removed last map
            la		r5,pmapSkipLists+4(r3)	; point to vector of list hdrs
mapRem32b:
            subic.	r10,r10,1				; get base-0 list#
            slwi	r8,r10,3				; get offset to last list
            lwzx	r0,r8,r5				; get last list ptr
            cmpwi	cr1,r0,0				; null?
            bnelr	cr1						; not null, so we are done
            stb		r10,pmapCurLists(r3)	; was null, so decrement pmapCurLists
            bgt		mapRem32b				; loop to see if more than one list was emptied
            blr
            

/*
 * *************************
 * * m a p S e t L i s t s *
 * *************************
 *
 * Called to decide how many skip-lists the next mapping will be on.  For each pmap,
 * we maintain a psuedo-random sequence based on a linear feedback shift register.  The
 * next number is generated by rotating the old value left by 1 and XORing with a
 * polynomial (actually 4 8-bit polynomials concatanated) and adding 1.
 * The simple (unclamped) number of lists a mapping is on is the number of trailing 0s
 * in the pseudo-random sequence, shifted by the (log2-1) of the fanout F, plus one.  
 * This seems to give us a near perfect distribution, in the sense that about F times more nodes
 * are allocated on n lists, as are on (n+1) lists.
 *
 * At one point we used a simple counter to assign lists.  While this gave perfect
 * distribution, there were certain access pattern that would drive a worst case 
 * distribution (e.g., insert low, then high, then low, etc.).  Unfortunately,
 * these patterns were not too uncommon.  We changed to a less-than-perfect assignment,
 * but one that works consistently across all known access patterns.
 *
 * Also, we modify the "simple" trailing-0-based list count, to account for an important
 * observation: because VM does a lot of removing and restoring of mappings in the process of
 * doing copy-on-write etc, it is common to have the pmap's "random number" (ie, the
 * count of created mappings) be much larger than the number of mappings currently in the
 * pmap.  This means the simple list count will often be larger than justified by the number of 
 * mappings in the pmap.  To avoid this common situation, we clamp the list count to be no more
 * than ceil(logBaseF(pmapResidentCnt)).
 *
 * Finally, we also clamp the list count to kSkipListMaxLists.
 *
 * We are passed the pmap ptr in r3.  Called with translation on, interrupts enabled,
 * and in 32-bit mode.
 */
            .align	5
			.globl	EXT(mapSetLists)
LEXT(mapSetLists)
            lwz		r5,pmapRandNum(r3)		; get the per-pmap counter of mapping creates
            lwz		r4,pmapResidentCnt(r3)	; get number of mappings in this pmap
			lis		r11,hi16(0xA7CBF5B9)	; Get polynomial (I just made this up...)
			li		r0,-1					; get a mask of 1s
			ori		r11,r11,lo16(0xA7CBF5B9)	; Get polynomial (I just made this up...)
			rlwinm	r5,r5,1,0,31			; Rotate
			cntlzw	r7,r4					; get magnitude of pmapResidentCnt
			xor		r5,r5,r11				; Munge with poly
			srw		r7,r0,r7				; r7 <- mask for magnitude of pmapResidentCnt
			addi	r6,r5,1					; increment pmapRandNum non-atomically
            andc	r8,r5,r6				; get a mask for trailing zeroes in pmapRandNum
            stw		r6,pmapRandNum(r3)		; update "random number"
			and		r8,r8,r7				; clamp trailing 0s to magnitude of pmapResidentCnt
            rlwinm	r8,r8,0,32-(kSkipListMaxLists*(kSkipListFanoutShift+1))+1,31 ; clamp to kSkipListMaxLists
            cntlzw	r9,r8					; count leading 0s in the mask
            subfic	r10,r9,32				; r10 <- trailing zero count
            srwi	r11,r10,kSkipListFanoutShift ; shift by 1 if fanout is 4, 2 if 8, etc
            addi	r3,r11,1				; every mapping is on at least one list
            blr
            

/*
 * *************************************
 * * m a p S k i p L i s t V e r i f y *
 * *************************************
 *
 * This does a fairly thorough sweep through a pmaps skip-list data structure, doing
 * consistency checks.  It is typically called (from hw_exceptions.s) from debug or
 * instrumented builds.  It is probably not a good idea to call this in production builds,
 * as it must run with exceptions disabled and can take a long time to verify a big pmap.
 * It runs in O(n*ln(n)).
 *
 * Called on a bl, with the pmap ptr in r20.  We assume the pmap is locked (shared) and
 * that EE and DR are off.  We check all 64 bits of ptrs even on 32-bit machines.
 * We use r20-r31, cr0, cr1, and cr7.  If we return, no inconsistencies were found.
 *
 * You will notice we make little attempt to schedule the code; clarity is deemed more
 * important than speed.
 */
 
 
 /*
  *			mapSkipListVerifyC is a version that is callable from C.
  *			This should be called only from the debugger, IT DOES NOT LOCK THE PMAP!!!!
  */
 
			.globl	EXT(mapSkipListVerifyC)
LEXT(mapSkipListVerifyC)

 			stwu	r1,-(FM_ALIGN((31-13+1)*4)+FM_SIZE)(r1)	; Make some space on the stack
			mflr	r0							; Save the link register
			stmw	r13,FM_ARG0(r1)				; Save all registers
			stw		r0,(FM_ALIGN((31-13+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return
			
			lwz		r15,pmapvr(r3)				; Get the V to R translation
			lwz		r16,pmapvr+4(r3)			; Get the V to R translation
			mr		r19,r4						; Save register dump area
			
			bl		EXT(mapSetUp)				; Get set up
			
			mr		r17,r11
			xor		r20,r3,r16					; Translate 32-bit portion
			bf--	pf64Bitb,mslvc32a			; Skip if 32-bit...
			
			rldimi	r20,r15,32,0				; Shift the fixed upper part of the physical over and cram in top
			
mslvc32a:	lis		r18,hi16(EXT(DebugWork))
			ori		r18,r18,lo16(EXT(DebugWork))
			li		r0,0x4262
			stw		r0,4(r18)					; Make sure the test knows to run
			
			bl		EXT(mapSkipListVerify)		; Run the test

			li		r0,0						
			stw		r0,4(r18)					; Remove explicit call flag

			bt++	pf64Bitb,mslvc64a			; This is 64-bit...

			mtmsr	r17							; Restore enables/translation/etc.
			isync
			
			li		r0,0
			stw		r0,0x000+0(r19)
			stw		r0,0x000+4(r19)
			stw		r0,0x008+0(r19)
			stw		r1,0x008+4(r19)
			stw		r0,0x010+0(r19)
			stw		r2,0x010+4(r19)
			stw		r0,0x018+0(r19)
			stw		r3,0x018+4(r19)
			stw		r0,0x020+0(r19)
			stw		r4,0x020+4(r19)
			stw		r0,0x028+0(r19)
			stw		r5,0x028+4(r19)
			stw		r0,0x030+0(r19)
			stw		r6,0x030+4(r19)
			stw		r0,0x038+0(r19)
			stw		r7,0x038+4(r19)
			stw		r0,0x040+0(r19)
			stw		r8,0x040+4(r19)
			stw		r0,0x048+0(r19)
			stw		r9,0x048+4(r19)
			stw		r0,0x050+0(r19)
			stw		r10,0x050+4(r19)
			stw		r0,0x058+0(r19)
			stw		r11,0x058+4(r19)
			stw		r0,0x060+0(r19)
			stw		r12,0x060+4(r19)
			stw		r0,0x068+0(r19)
			stw		r13,0x068+4(r19)
			stw		r0,0x070+0(r19)
			stw		r14,0x070+4(r19)
			stw		r0,0x078+0(r19)
			stw		r15,0x078+4(r19)
			stw		r0,0x080+0(r19)
			stw		r16,0x080+4(r19)
			stw		r0,0x088+0(r19)
			stw		r17,0x088+4(r19)
			stw		r0,0x090+0(r19)
			stw		r18,0x090+4(r19)
			stw		r0,0x098+0(r19)
			stw		r19,0x098+4(r19)
			stw		r0,0x0A0+0(r19)
			stw		r20,0x0A0+4(r19)
			stw		r0,0x0A8+0(r19)
			stw		r21,0x0A8+4(r19)
			stw		r0,0x0B0+0(r19)
			stw		r22,0x0B0+4(r19)
			stw		r0,0x0B8+0(r19)
			stw		r23,0x0B8+4(r19)
			stw		r0,0x0C0+0(r19)
			stw		r24,0x0C0+4(r19)
			stw		r0,0x0C8+0(r19)
			stw		r25,0x0C8+4(r19)
			stw		r0,0x0D0+0(r19)
			stw		r26,0x0D0+4(r19)
			stw		r0,0x0D8+0(r19)
			stw		r27,0x0D8+4(r19)
			stw		r0,0x0E0+0(r19)
			stw		r28,0x0E0+4(r19)
			stw		r0,0x0E8+0(r19)
			stw		r29,0x0E8+4(r19)
			stw		r0,0x0F0+0(r19)
			stw		r30,0x0F0+4(r19)
			stw		r0,0x0F8+0(r19)
			stw		r31,0x0F8+4(r19)
			
			b		mslvcreturn					; Join common...

mslvc64a:	mtmsrd	r17							; Restore enables/translation/etc.
			isync								
			
			std		r0,0x000(r19)
			std		r1,0x008(r19)
			std		r2,0x010(r19)
			std		r3,0x018(r19)
			std		r4,0x020(r19)
			std		r5,0x028(r19)
			std		r6,0x030(r19)
			std		r7,0x038(r19)
			std		r8,0x040(r19)
			std		r9,0x048(r19)
			std		r10,0x050(r19)
			std		r11,0x058(r19)
			std		r12,0x060(r19)
			std		r13,0x068(r19)
			std		r14,0x070(r19)
			std		r15,0x078(r19)
			std		r16,0x080(r19)
			std		r17,0x088(r19)
			std		r18,0x090(r19)
			std		r19,0x098(r19)
			std		r20,0x0A0(r19)
			std		r21,0x0A8(r19)
			std		r22,0x0B0(r19)
			std		r23,0x0B8(r19)
			std		r24,0x0C0(r19)
			std		r25,0x0C8(r19)
			std		r26,0x0D0(r19)
			std		r27,0x0D8(r19)
			std		r28,0x0E0(r19)
			std		r29,0x0E8(r19)
			std		r30,0x0F0(r19)
			std		r31,0x0F8(r19)
			
			
mslvcreturn:
			lwz		r0,(FM_ALIGN((31-13+1)*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Get the return
			lmw		r13,FM_ARG0(r1)				; Get the registers
			mtlr	r0							; Restore the return
			lwz		r1,0(r1)					; Pop the stack
			blr

 
			.globl	EXT(mapSkipListVerify)
LEXT(mapSkipListVerify)
            mflr	r31						; save LR so we can bl to mapVerifyDie
            
            ; If we have already found an inconsistency and died, don not do so again, to
            ; avoid a loop.
            
			lis		r27,hi16(EXT(DebugWork))
			ori		r27,r27,lo16(EXT(DebugWork))
			lwz		r0,4(r27)				; Get the explicit entry flag
			lwz		r27,0(r27)				; Get lockout
			cmplwi	r0,0x4262				; Should we run anyway?
			beq--	mslvAnyway				; Yes...
            cmpwi	r27,0					; have we already found an error?
            bnelr--							; yes, just return wo checking again

mslvAnyway:           
            ; Not recursive call, so initialize.
            
            mfsprg	r23,2					; get the feature flags
            mtcrf	0x02,r23				; put pf64Bit where we can test it
            lbz		r26,pmapCurLists(r20)	; get #lists that are in use
            lwz		r21,pmapResidentCnt(r20); get #mappings in this pmap
            cmpwi	r26,kSkipListMaxLists	; in range?
            bgtl--	mapVerifyDie			; pmapCurLists is too big
            
            ; To prevent infinite loops, set limit of (pmapCurLists*pmapResidentCnt) iterations.
            ; Since we walk each list this is the max number of mappings we could visit.
            
            li		r23,0					; initialize count
mapVer0:
            subic.	r26,r26,1				; loop pmapCurLists times (but at least once)
            add		r23,r23,r21				; compute (pmapCurLists*pmapResidentCnt) 
            bgt		mapVer0					; this will be a 64-bit qty on 64-bit machines
            
            li		r22,kSkipListMaxLists	; initialize list#
            bf--	pf64Bitb,mapVer32		; go handle a 32-bit processor
            
            ; 64-bit machine.
            ;
            ; Loop over each list, counting mappings in each.  We first check whether or not
            ; the list is empty (ie, if the pmapSlipLists ptr is null.)  All lists above
            ; pmapCurLists should be empty, and no list at or below pmapCurLists should be.
            ;	r20 = pmap ptr
            ;	r21 = decrementing counter of mappings in this pmap
            ;	r22 = next list# (1...kSkipListMaxLists)
            ;	r23 = decrementing counter for infinite loop check
            
mapVer64:
            slwi	r25,r22,3				; get offset to next skiplist
            la		r26,pmapSkipLists(r20)	; get ptr to base of skiplist vector
            subi	r25,r25,8
            ldx		r26,r25,r26				; get 1st mapping on this list, if any
            lbz		r28,pmapCurLists(r20)	; get #lists in use
            cmpdi	cr6,r26,0				; set cr6_eq if this list is null ("null")
            cmpw	cr7,r22,r28				; set cr7_gt if this list is > pmapCurLists ("high")
            crxor	cr0_eq,cr6_eq,cr7_gt	; cr0_eq <-- (null & !high) | (!null & high)
            beql--	mapVerifyDie			; die if this list is null when it should not be, etc
            b		mapVer64g
           
            ; Loop over each node in the list.
            ;	r20 = pmap ptr
            ;	r21 = decrementing counter of mappings in this pmap
            ;	r22 = this list# (1...kSkipListMaxLists)
            ;	r23 = decrementing counter for infinite loop check
            ;	r25 = offset to this skiplist (ie, ((r22<<3)-8))
            ;	r26 = mapping
            
mapVer64a:
            lwz		r29,mpFlags(r26)		; get bits for this mapping
            ld		r28,mpVAddr(r26)		; get key
            subic.	r23,r23,1				; check for loops
            bltl--	mapVerifyDie			; we have visited > (pmapCurLists*pmapResidentCnt) nodes
            andi.	r30,r26,mpBasicSize-1	; test address for alignment
            bnel--	mapVerifyDie			; not aligned
            andi.	r27,r29,mpLists			; get #lists this mapping is supposed to be on
            cmpw	cr1,r27,r22				; is it supposed to be on this list?
            bltl--	cr1,mapVerifyDie		; mappings mpLists is too low
            cmpwi	r27,kSkipListMaxLists	; too big?
            bgtl--	mapVerifyDie			; mappings mpLists > max
            rldicr	r28,r28,0,51			; clear low 12 bits of va
            bne++	cr1,mapVer64f			; jump if this is not highest list for this node
            
            ; This is the "highest" (last) list this mapping is on.
            ; Do some additional checks (so we only do them once per mapping.)
            ; First, if a block mapping or nested pmap, compute block end.
            
			lhz		r27,mpBSize(r26)		; get #pages or #segments
			rlwinm	r29,r29,mpBSub+1,31,31	; Rotate to get 0 if 4K bsu or 1 if 32MB bsu
			addi	r27,r27,1				; units of nested pmap are (#segs-1)
			ori		r29,r29,0x3216			; OR in 0x00003216 (0x3200 and a base rotate of 22)
			rlwnm	r29,r29,r29,27,31		; Rotate to get 12 or 25
			subi	r21,r21,1				; count mappings in this pmap
			sld		r29,r27,r29				; Get the length in bytes
			subi	r29,r29,4096			; get offset to last byte in nested pmap
            
            ; Here with r29 = size of block - 4k, or 0 if mapping is a scalar page.

            add		r24,r28,r29				; r24 <- address of last valid page in this mapping
            la		r28,mpList0(r26)		; get base of this mappings vector            
            lwz		r27,mpFlags(r26)		; Get the number of lists
            andi.	r27,r27,mpLists			; get #lists this mapping is on (1<=n<=27)
            cmplwi	r27,mpBasicLists		; Into bigger mapping?
            li		r27,mpBasicLists*8-8	; Assume normal
            ble+	mapVer64c				; It is...
            li		r27,kSkipListMaxLists*8-8	; initialize list offset for inner loop
            
            ; Inner loop over each list link in this mappingss mpList vector.
            ;	r24 = address of last valid page in this mapping
            ;	r27 = offset for next list in inner loop
            ;	r28 = base of this mappings list links
            
mapVer64c:
            cmpw	cr1,r27,r25				; higher, lower, or same?
            ldx		r29,r27,r28				; get link to next mapping at this level
            mr.		r29,r29					; null?
            beq		mapVer64d				; link null, which is always OK
            bgtl--	cr1,mapVerifyDie		; a mapping has a non-null list higher than its mpLists
            ld		r30,mpVAddr(r29)		; get next mappings va
            rldicr	r30,r30,0,51			; zero low 12 bits
            cmpld	r30,r24					; compare next key with ours
            blel--	mapVerifyDie			; a next node has key <= to ours
mapVer64d:
            subic.	r27,r27,8				; move on to next list
            bne++	mapVer64c				; loop if more to go
            
            ; Next node on current list, or next list if current done, or return if no more lists.
            
mapVer64f:
            la		r28,mpList0(r26)		; get base of this mappings vector
            ldx		r26,r25,r28				; get next mapping on this list
mapVer64g:
            mr.		r26,r26					; is there one?
            bne++	mapVer64a				; yes, handle
            subic.	r22,r22,1				; is there another list?
            bgt++	mapVer64				; loop if so
            
            cmpwi	r21,0					; did we find all the mappings in the pmap?
            bnel--	mapVerifyDie			; no
            mtlr	r31						; restore return address
            li		r3,0
            blr
            
            
            ; Handle 32-bit machine.
            
mapVer32:
            lwz		r24,mpFlags(r20)		; Get number of lists
            la		r30,pmapSkipLists(r20)	; first, check the pmap list hdrs
            andi.	r24,r24,mpLists			; Clean the number of lists
            bl		mapVerUpperWordsAre0	; are the upper words of each list all 0?
            
            ; Loop over each list, counting mappings in each.  We first check whether or not
            ; the list is empty.  All lists above pmapCurLists should be empty, and no list
            ; at or below pmapCurLists should be.
            ;
            ;	r20 = pmap ptr
            ;	r21 = decrementing counter of mappings in this pmap
            ;	r22 = next list# (1...kSkipListMaxLists)
            ;	r23 = decrementing counter for infinite loop check
            
mapVer32NextList:
            lbz		r28,pmapCurLists(r20)	; get #lists in use
            slwi	r25,r22,3				; get offset to next skiplist
            la		r26,pmapSkipLists+4(r20) ; get ptr to base of skiplist vector
            subi	r25,r25,8
            lwzx	r26,r25,r26				; get the 1st mapping on this list, or 0
            cmpw	cr7,r22,r28				; set cr7_gt if this list is > pmapCurLists ("high")
            cmpwi	cr6,r26,0				; set cr6_eq if this list is null ("null")
            crxor	cr0_eq,cr6_eq,cr7_gt	; cr0_eq <-- (null & !high) | (!null & high)
            beql-	mapVerifyDie			; die if this list is null when it should not be, etc
            b		mapVer32g
           
            ; Loop over each node in the list.
            ;	r20 = pmap ptr
            ;	r21 = decrementing counter of mappings in this pmap
            ;	r22 = this list# (1...kSkipListMaxLists)
            ;	r23 = decrementing counter for infinite loop check
            ;	r25 = offset to this skiplist (ie, ((r22<<3)-8))
            ;	r26 = mapping
            
mapVer32a:
            lwz		r29,mpFlags(r26)		; get bits for this mapping
            andi.	r30,r26,mpBasicSize-1	; test address for alignment
            lwz		r24,mpVAddr+0(r26)		; get upper word of key
            bnel-	mapVerifyDie			; mapping address not 64-byte aligned
            lwz		r28,mpVAddr+4(r26)		; get lower word of key
            subic.	r23,r23,1				; check for loops
            bltl-	mapVerifyDie			; we have visited > (pmapCurLists*pmapResidentCnt) nodes
            cmpwi	r24,0					; upper word of key (ie, va) should be 0
            bnel-	mapVerifyDie			; was not
            andi.	r27,r29,mpLists			; get #lists this mapping is supposed to be on
            cmpw	cr1,r27,r22				; is it supposed to be on this list?
            bltl-	cr1,mapVerifyDie		; mappings mpLists is too low
            cmpwi	r27,kSkipListMaxLists	; too big?
            bgtl-	mapVerifyDie			; mappings mpLists > max
            rlwinm	r28,r28,0,0,19			; clear low 12 bits of va
            bne+	cr1,mapVer32f			; jump if this is not highest list for this node
            
            ; This is the "highest" (last) list this mapping is on.
            ; Do some additional checks (so we only do them once per mapping.)
            ; First, make sure upper words of the mpList vector are 0.

			lhz		r27,mpBSize(r26)		; get #blocks
			rlwinm	r29,r29,mpBSub+1,31,31	; Rotate to get 0 if 4K bsu or 1 if 32MB bsu
			addi	r27,r27,1				; units of nested pmap are (#segs-1)
			ori		r29,r29,0x3216			; OR in 0x00003216 (0x3200 and a base rotate of 22)
			rlwnm	r29,r29,r29,27,31		; Rotate to get 12 or 25
			subi	r21,r21,1				; count mappings in this pmap
			slw		r29,r27,r29				; Get the length in bytes
			subi	r29,r29,4096			; get offset to last byte in nested pmap

            lwz		r24,mpFlags(r26)		; Get number of lists
            la		r30,mpList0(r26)		; point to base of skiplist vector
			andi.	r24,r24,mpLists			; Clean the number of lists
			bl		mapVerUpperWordsAre0	; make sure upper words are all 0 (uses r24 and r27)
                        
            ; Here with r29 = size of block - 4k, or 0 if mapping is a scalar page.

            add		r24,r28,r29				; r24 <- address of last valid page in this mapping
            la		r28,mpList0+4(r26)		; get base of this mappings vector            
            lwz		r27,mpFlags(r26)		; Get the number of lists
            andi.	r27,r27,mpLists			; get #lists this mapping is on (1<=n<=27)
            cmplwi	r27,mpBasicLists		; Into bigger mapping?
            li		r27,mpBasicLists*8-8	; Assume normal
            ble+	mapVer32c				; It is...
            li		r27,kSkipListMaxLists*8-8	; initialize list offset for inner loop
            
            ; Inner loop over each list in this mappings mpList vector.
            ;	r24 = address of last valid page in this mapping
            ;	r27 = offset for next list in inner loop
            ;	r28 = base of this mappings list links
            
mapVer32c:
            cmpw	cr1,r27,r25				; higher, lower, or same?
            lwzx	r29,r27,r28				; get link to next mapping at this level
            mr.		r29,r29					; null?
            beq		mapVer32d				; link null, which is always OK
           
           
            bgtl-	cr1,mapVerifyDie		; a mapping has a non-null list higher than its mpLists
            lwz		r30,mpVAddr+4(r29)		; get next mappings va
            rlwinm	r30,r30,0,0,19			; zero low 12 bits
            cmplw	r30,r24					; compare next key with ours
            blel-	mapVerifyDie			; a next node has key <= to ours
mapVer32d:
            subic.	r27,r27,8				; move on to next list
            bne+	mapVer32c				; loop if more to go
            
            ; Next node on current list, or next list if current done, or return if no more lists.
            
mapVer32f:
            la		r28,mpList0+4(r26)		; get base of this mappings vector again
            lwzx	r26,r25,r28				; get next mapping on this list
mapVer32g:
            mr.		r26,r26					; is there one?
            bne+	mapVer32a				; yes, handle
            subic.	r22,r22,1				; is there another list?
            bgt+	mapVer32NextList		; loop if so
            
            cmpwi	r21,0					; did we find all the mappings in the pmap?
            bnel-	mapVerifyDie			; no
            mtlr	r31						; restore return address
            li		r3,0
            blr

            ; Subroutine to verify that the upper words of a vector of kSkipListMaxLists
            ; doublewords are 0.
            ;	r30 = ptr to base of vector
            ; Uses r24 and r27.
            
mapVerUpperWordsAre0:
			cmplwi	r24,mpBasicLists		; Do we have more than basic?
            li		r24,mpBasicLists*8		; Assume basic
            ble++	mapVerUpper1			; We have the basic size
            li		r24,kSkipListMaxLists*8	; Use max size
            
mapVerUpper1:
            subic.	r24,r24,8				; get offset to next doubleword
            lwzx	r27,r24,r30				; get upper word
            cmpwi	cr1,r27,0				; 0 ?
            bne-	cr1,mapVerifyDie		; die if not, passing callers LR
            bgt+	mapVerUpper1			; loop if more to go
            blr
            
            ; bl here if mapSkipListVerify detects an inconsistency.

mapVerifyDie:
			mflr	r3
			mtlr	r31						; Restore return
			lis		r31,hi16(EXT(DebugWork))
			ori		r31,r31,lo16(EXT(DebugWork))
			lwz		r0,4(r31)				; Get the explicit entry flag
			cmplwi	r0,0x4262				; Should we run anyway?
			beqlr--							; Explicit call, return...
			
            li		r0,1
			stw		r0,0(r31)				; Lock out further calls
            BREAKPOINT_TRAP					; hopefully, enter debugger
            b		.-4
            
            
/*
 * Panic (choke, to be exact) because of messed up skip lists.  The LR points back
 * to the original caller of the skip-list function.
 */
 
mapSkipListPanic:							; skip-lists are screwed up
            lis		r0,hi16(Choke)
            ori		r0,r0,lo16(Choke)
            li      r3,failSkipLists		; get choke code
            sc								; choke
            b		.-4
            

