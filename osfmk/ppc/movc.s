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
 * @OSF_COPYRIGHT@
 */
#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>
#include <sys/errno.h>

/*
 * void pmap_zero_page(vm_offset_t pa)
 *
 * zero a page of physical memory.
 */

#if DEBUG
	/* C debug stub in pmap.c calls this */
ENTRY(pmap_zero_page_assembler, TAG_NO_FRAME_USED)
#else
ENTRY(pmap_zero_page, TAG_NO_FRAME_USED)
#endif /* DEBUG */

		mfmsr	r6								/* Get the MSR */
		rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1	/* Turn off DR */
		rlwinm	r7,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Disable interruptions
		li		r4,PPC_PGBYTES-CACHE_LINE_SIZE	/* Point to the end of the page */
		mtmsr	r7								/* Set MSR to DR off */
		isync									/* Ensure data translations are off */


.L_phys_zero_loop:	
		subic.	r5,r4,CACHE_LINE_SIZE			/* Point to the next one */
		dcbz	r4, r3							/* Clear the whole thing to 0s */
		subi	r4,r5,CACHE_LINE_SIZE			/* Point to the next one */
		dcbz	r5, r3							/* Clear the next to zeros */
		bgt+	.L_phys_zero_loop				/* Keep going until we do the page... */

		sync									/* Make sure they're all done */
		li		r4,PPC_PGBYTES-CACHE_LINE_SIZE	/* Point to the end of the page */

.L_inst_inval_loop:	
		subic.	r5,r4,CACHE_LINE_SIZE			/* Point to the next one */
		icbi	r4, r3							/* Clear the whole thing to 0s */
		subi	r4,r5,CACHE_LINE_SIZE			/* Point to the next one */
		icbi	r5, r3							/* Clear the next to zeros */
		bgt+	.L_inst_inval_loop				/* Keep going until we do the page... */

		sync									/* Make sure they're all done */

		mtmsr	r6		/* Restore original translations */
		isync			/* Ensure data translations are on */

		blr

/* void
 * phys_copy(src, dst, bytecount)
 *      vm_offset_t     src;
 *      vm_offset_t     dst;
 *      int             bytecount
 *
 * This routine will copy bytecount bytes from physical address src to physical
 * address dst. 
 */

ENTRY(phys_copy, TAG_NO_FRAME_USED)

	/* Switch off data translations */
	mfmsr	r6
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	rlwinm  r7,     r7,     0,      MSR_EE_BIT+1,   MSR_EE_BIT-1
	mtmsr	r7
	isync			/* Ensure data translations are off */

	subi	r3,	r3,	4
	subi	r4,	r4,	4

	cmpwi	r5,	3
	ble-	.L_phys_copy_bytes
.L_phys_copy_loop:
	lwz	r0,	4(r3)
	addi	r3,	r3,	4
	subi	r5,	r5,	4
	stw	r0,	4(r4)
	addi	r4,	r4,	4
	cmpwi	r5,	3
	bgt+	.L_phys_copy_loop

	/* If no leftover bytes, we're done now */
	cmpwi	r5,	0
	beq+	.L_phys_copy_done
	
.L_phys_copy_bytes:
	addi	r3,	r3,	3
	addi	r4,	r4,	3
.L_phys_copy_byte_loop:	
	lbz	r0,	1(r3)
	addi	r3,	r3,	1
	subi	r5,	r5,	1
	stb	r0,	1(r4)
	addi	r4,	r4,	1
	cmpwi	r5,	0
	bne+	.L_phys_copy_byte_loop

.L_phys_copy_done:
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are off */

	blr

/* void
 * pmap_copy_page(src, dst)
 *      vm_offset_t     src;
 *      vm_offset_t     dst;
 *
 * This routine will copy the physical page src to physical page dst
 * 
 * This routine assumes that the src and dst are page aligned and that the
 * destination is cached.
 *
 * We also must assume that noone will be executing within the destination
 * page.  We also assume that this will be used for paging
 *
 */

#if DEBUG
	/* if debug, we have a little piece of C around this
	 * in pmap.c that gives some trace ability
	 */
ENTRY(pmap_copy_page_assembler, TAG_NO_FRAME_USED)
#else
ENTRY(pmap_copy_page, TAG_NO_FRAME_USED)
#endif /* DEBUG */

#if 0
			mfpvr	r9							; Get the PVR
			rlwinm	r9,r9,16,16,31				; Isolate the PPC processor
			cmplwi	r9,PROCESSOR_VERSION_Max	; Do we have Altivec?
			beq+	wegotaltivec				; Yeah...
#endif
		
			mfmsr	r9							; Get the MSR
			stwu	r1,-(FM_SIZE+32)(r1)		; Make a frame for us
			rlwinm	r7,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Disable interruptions
			ori		r7,r7,lo16(MASK(MSR_FP))	; Turn on the FPU
			mtmsr	r7							; Disable rupts and enable FPU
			isync
		
			stfd	f0,FM_SIZE+0(r1)			; Save an FP register
			rlwinm	r7,r7,0,MSR_DR_BIT+1,MSR_DR_BIT-1	; Clear the DDAT bit
			stfd	f1,FM_SIZE+8(r1)			; Save an FP register
			addi	r6,r3,PPC_PGBYTES			; Point to the start of the next page
			stfd	f2,FM_SIZE+16(r1)			; Save an FP register
			mr		r8,r4						; Save the destination
			stfd	f3,FM_SIZE+24(r1)			; Save an FP register
		
			mtmsr	r7							; Set the new MSR
			isync								; Ensure data translations are off

			dcbt	br0, r3						/* Start in first input line */
			li		r5,	CACHE_LINE_SIZE			/* Get the line size */

.L_pmap_copy_page_loop:
			dcbz	0, r4						/* Allocate a line for the output */
			lfd		f0, 0(r3)					/* Get first 8 */
			lfd		f1, 8(r3)					/* Get second 8 */
			lfd		f2, 16(r3)					/* Get third 8 */
			stfd	f0, 0(r4)					/* Put first 8 */
			dcbt	r5, r3						/* Start next line coming in */
			lfd		f3, 24(r3)					/* Get fourth 8 */
			stfd	f1,	8(r4)					/* Put second 8 */
			addi	r3,r3,CACHE_LINE_SIZE		/* Point to the next line in */
			stfd	f2,	16(r4)					/* Put third 8 */
			cmplw	cr0,r3,r6					/* See if we're finished yet */
			stfd	f3,	24(r4)					/* Put fourth 8 */
			dcbst	br0,r4						/* Force it out */
			addi	r4,r4,CACHE_LINE_SIZE		/* Point to the next line out */
			blt+	.L_pmap_copy_page_loop		/* Copy the whole page */
			
			sync								/* Make sure they're all done */
			li		r4,PPC_PGBYTES-CACHE_LINE_SIZE	/* Point to the end of the page */

invalinst:	
			subic.	r5,r4,CACHE_LINE_SIZE		/* Point to the next one */
			icbi	r4, r8						/* Trash the i-cache */
			subi	r4,r5,CACHE_LINE_SIZE		/* Point to the next one */
			icbi	r5, r8						/* Trash the i-cache */
			bgt+	invalinst					/* Keep going until we do the page... */
	
			rlwimi	r7,r9,0,MSR_DR_BIT,MSR_DR_BIT	; Set DDAT if on
			sync								; Make sure all invalidates done
			
			mtmsr	r7							; Set DDAT correctly
			isync		
			
			lfd		f0,FM_SIZE+0(r1)			; Restore an FP register
			lfd		f1,FM_SIZE+8(r1)			; Restore an FP register
			lfd		f2,FM_SIZE+16(r1)			; Restore an FP register
			lfd		f3,FM_SIZE+24(r1)			; Restore an FP register
			
			lwz		r1,0(r1)					; Pop up the stack
	
			mtmsr	r9							; Turn off FPU now and maybe rupts back on
			isync								
			blr
		
#if 0
;
;			This is not very optimal.  We just do it here for a test of 
;			Altivec in the kernel.
;
wegotaltivec:
			mfmsr	r9							; Get the MSR
			lis		r8,hi16(0xC0000000)			; Make sure we keep the first 2 vector registers
			rlwinm	r7,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Disable interruptions
			lis		r6,lo16(2*256+128)			; Specify 128 blocks of 2 vectors each
			rlwinm	r7,r7,0,MSR_DR_BIT+1,MSR_DR_BIT-1	; Clear the DDAT bit
			ori		r6,r6,32					; Set a 32-byte stride
			mtsprg	256,r8						; Set VRSave
			mtmsr	r7							; Disable rupts and turn xlate off
			isync
	
			addi	r11,r3,4096					; Point to the next page
			li		r10,16						; Get vector size

avmovepg:	lvxl	v0,br0,r3					; Get first half of line
			dcba	br0,r4						; Allocate output
			lvxl	v1,r10,r3					; Get second half of line
			stvxl	v0,br0,r4					; Save first half of line
			addi	r3,r3,32					; Point to the next line
			icbi	br0,r4						; Make the icache go away also
			stvxl	v1,r10,r4					; Save second half of line
			cmplw	r3,r11						; Have we reached the next page?
			dcbst	br0,r4						; Make sure the line is on its way out
			addi	r4,r4,32					; Point to the next line
			blt+	avmovepg					; Move the next line...
			
			li		r8,0						; Clear this
			sync								; Make sure all the memory stuff is done
			mtsprg	256,r8						; Show we are not using VRs any more
			mtmsr	r9							; Translation and interruptions back on
			isync
			blr
#endif
		

	

/*
 * int
 * copyin(src, dst, count)
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	int		count;
 *
 */

ENTRY2(copyin, copyinmsg, TAG_NO_FRAME_USED)

/* Preamble allowing us to call a sub-function */
		mflr	r0
		stw		r0,FM_LR_SAVE(r1)
		stwu	r1,-(FM_SIZE+16)(r1)
		
		mfmsr	r0								/* Get the MSR */
		rlwinm	r6,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear 'rupts */
		mtmsr	r6								/* Disable 'rupts */

		mfsprg	r6,0							/* Get the per_proc */
		lwz		r6,PP_CPU_DATA(r6)
		cmpli	cr0,r5,0
		lwz		r10,CPU_ACTIVE_THREAD(r6)
		mtmsr	r0								/* Set 'rupts back */
		ble-	cr0,.L_copyinout_trivial

/* we know we have a valid copyin to do now */
/* Set up thread_recover in case we hit an illegal address */
		
		lwz		r8,THREAD_TOP_ACT(r10)
		lis		r11,hi16(.L_copyinout_error)
		lwz		r8,ACT_VMMAP(r8)
		ori		r11,r11,lo16(.L_copyinout_error)
		add		r9,r3,r5						/* Get the end of the source */
		lwz		r8,VMMAP_PMAP(r8)				; Get the pmap
		rlwinm	r12,r3,6,26,29					; Get index to the segment slot
		subi	r9,r9,1							/* Make sure we don't go too far */
		add		r8,r8,r12						; Start indexing to the segment value
		stw		r11,THREAD_RECOVER(r10)
		xor		r9,r9,r3						/* Smoosh 'em together */
		lwz		r8,PMAP_SEGS(r8)				; Get the source SR value
		rlwinm.	r9,r9,0,1,3						/* Top nybble equal? */
		mtsr	SR_COPYIN,r8					; Set the SR
		isync
#if 0
		lis		r0,HIGH_ADDR(EXT(dbgRegsCall))	/* (TEST/DEBUG) */	
		ori		r0,r0,LOW_ADDR(EXT(dbgRegsCall))	/* (TEST/DEBUG) */	
		sc										/* (TEST/DEBUG) */
#endif
	
/* For optimization, we check if the copyin lies on a segment
 * boundary. If it doesn't, we can use a simple copy. If it
 * does, we split it into two separate copies in some C code.
 */
	
		bne-	.L_call_copyin_multiple			/* Nope, we went past the segment boundary... */

		rlwinm	r3,r3,0,4,31
		oris	r3,r3,(SR_COPYIN_NUM << (28-16))	/* Set the copyin segment as the source */
	
		bl		EXT(bcopy)
		
/* Now that copyin is done, we don't need a recovery point */
		mfmsr	r7								/* Get the MSR */
		rlwinm	r6,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear 'rupts */
		mtmsr	r6								/* Disable 'rupts */

		mfsprg	r6,0							/* Get the per_proc */
		
		lwz		r6,PP_CPU_DATA(r6)
		addi	r1,r1,FM_SIZE+16
		lwz		r10,CPU_ACTIVE_THREAD(r6)
		mtmsr	r7								; Restore interrupts
		li		r3,0
		lwz		r0,FM_LR_SAVE(r1)
		stw		r3,THREAD_RECOVER(r10)			/* Clear recovery */
		mtlr	r0
		blr
	
/* we get here via the exception handler if an illegal
 * user memory reference was made.
 */
.L_copyinout_error:

/* Now that copyin is done, we don't need a recovery point */
	
		mfmsr	r7								/* Get the MSR */
		rlwinm	r6,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear 'rupts */
		mtmsr	r6								/* Disable 'rupts */

		mfsprg	r6,0							/* Get the per_proc */
		
		lwz		r6,PP_CPU_DATA(r6)
		addi	r1,r1,FM_SIZE+16
		lwz		r10,CPU_ACTIVE_THREAD(r6)
		mtmsr	r7								; Restore interrupts
		li		r4,0
		lwz		r0,FM_LR_SAVE(r1)
		stw		r4,THREAD_RECOVER(r10)			/* Clear recovery */
		mtlr	r0
		li		r3,EFAULT							; Indicate error (EFAULT) 
		blr

.L_copyinout_trivial:
	/* The copyin/out was for either 0 bytes or a negative
	 * number of bytes, return an appropriate value (0 == SUCCESS).
	 * cr0 still contains result of comparison of len with 0.
	 */
	li	r3,	0
	beq+	cr0,	.L_copyinout_negative
	li	r3,	1
.L_copyinout_negative:

	/* unwind the stack */
	addi	r1,	r1,	FM_SIZE+16
	lwz	r0,	FM_LR_SAVE(r1)
	mtlr	r0

	blr

.L_call_copyin_multiple:

	/* unwind the stack */
	addi	r1,	r1,	FM_SIZE+16
	lwz	r0,	FM_LR_SAVE(r1)
	mtlr	r0

	b	EXT(copyin_multiple)				/* not a call - a jump! */

/*
 * int
 * copyout(src, dst, count)
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	int		count;
 *
 */

ENTRY2(copyout, copyoutmsg, TAG_NO_FRAME_USED)

/* Preamble allowing us to call a sub-function */

		mflr	r0
		stw		r0,FM_LR_SAVE(r1)
		stwu	r1,-(FM_SIZE+16)(r1)
		
#if 0
		stw		r3,FM_SIZE+0(r1)				/* (TEST/DEBUG) */
		stw		r4,FM_SIZE+4(r1)				/* (TEST/DEBUG) */
		stw		r5,FM_SIZE+8(r1)				/* (TEST/DEBUG) */
		mr		r6,r0							/* (TEST/DEBUG) */
		
		bl		EXT(tracecopyout)				/* (TEST/DEBUG) */
		
		lwz		r3,FM_SIZE+0(r1)				/* (TEST/DEBUG) */
		lwz		r4,FM_SIZE+4(r1)				/* (TEST/DEBUG) */
		lwz		r5,FM_SIZE+8(r1)				/* (TEST/DEBUG) */
#endif
	
		mfmsr	r7								/* Get the MSR */
		rlwinm	r6,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear 'rupts */
		mtmsr	r6								/* Disable 'rupts */

		mfsprg	r6,0							/* Get the per_proc */
		
		lwz		r6,PP_CPU_DATA(r6)
		cmpli	cr0,r5,0
		lwz		r10,CPU_ACTIVE_THREAD(r6)
		mtmsr	r7								/* Restore 'rupts */
		ble-	cr0,.L_copyinout_trivial
/* we know we have a valid copyout to do now */
/* Set up thread_recover in case we hit an illegal address */
		

		lwz		r8,THREAD_TOP_ACT(r10)
		lis		r11,HIGH_ADDR(.L_copyinout_error)
		lwz		r8,ACT_VMMAP(r8)
		rlwinm	r12,r4,6,26,29					; Get index to the segment slot
		ori		r11,r11,LOW_ADDR(.L_copyinout_error)
		add		r9,r4,r5						/* Get the end of the destination */
		lwz		r8,VMMAP_PMAP(r8)
		subi	r9,r9,1							/* Make sure we don't go too far */
		add		r8,r8,r12						; Start indexing to the segment value
		stw		r11,THREAD_RECOVER(r10)
		xor		r9,r9,r4						/* Smoosh 'em together */
		lwz		r8,PMAP_SEGS(r8)				; Get the source SR value
		rlwinm.	r9,r9,0,1,3						/* Top nybble equal? */
		mtsr	SR_COPYIN,r8
		isync
	
	
/* For optimisation, we check if the copyout lies on a segment
 * boundary. If it doesn't, we can use a simple copy. If it
 * does, we split it into two separate copies in some C code.
 */
	
		bne-	.L_call_copyout_multiple		/* Nope, we went past the segment boundary... */

		rlwinm	r4,r4,0,4,31
		oris	r4,r4,(SR_COPYIN_NUM << (28-16))	/* Set the copyin segment as the source */
	
		bl	EXT(bcopy)
		
/* Now that copyout is done, we don't need a recovery point */
		mfmsr	r7								/* Get the MSR */
		rlwinm	r6,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear 'rupts */
		mtmsr	r6								/* Disable 'rupts */

		mfsprg	r6,0							/* Get the per_proc */
		
		lwz		r6,PP_CPU_DATA(r6)
		addi	r1,r1,FM_SIZE+16
		lwz		r10,CPU_ACTIVE_THREAD(r6)
		mtmsr	r7								; Restore interrupts
		li		r3,0
		lwz		r0,FM_LR_SAVE(r1)
		stw		r3,THREAD_RECOVER(r10)			/* Clear recovery */
		mtlr	r0
		blr

.L_call_copyout_multiple:
	/* unwind the stack */
	addi	r1,	r1,	FM_SIZE+16
	lwz	r0,	FM_LR_SAVE(r1)
	mtlr	r0

	b	EXT(copyout_multiple)					/* not a call - a jump! */

/*
 * boolean_t
 * copyinstr(src, dst, count, maxcount)
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	vm_size_t	maxcount; 
 *	vm_size_t*	count;
 *
 * Set *count to the number of bytes copied
 * 
 * If dst == NULL, don't copy, just count bytes.
 * Only currently called from klcopyinstr. 
 */

ENTRY(copyinstr, TAG_NO_FRAME_USED)

/* Preamble allowing us to call a sub-function */
		mflr	r0
		stw		r0,FM_LR_SAVE(r1)
		stwu	r1,-(FM_SIZE+16)(r1)

#if 0
		stw		r3,FM_SIZE+0(r1)				/* (TEST/DEBUG) */
		stw		r4,FM_SIZE+4(r1)				/* (TEST/DEBUG) */
		stw		r5,FM_SIZE+8(r1)				/* (TEST/DEBUG) */
		stw		r6,FM_SIZE+12(r1)				/* (TEST/DEBUG) */
		mr		r7,r0							/* (TEST/DEBUG) */
		
		bl		EXT(tracecopystr)				/* (TEST/DEBUG) */
		
		lwz		r3,FM_SIZE+0(r1)				/* (TEST/DEBUG) */
		lwz		r4,FM_SIZE+4(r1)				/* (TEST/DEBUG) */
		lwz		r5,FM_SIZE+8(r1)				/* (TEST/DEBUG) */
		stw		r6,FM_SIZE+12(r1)				/* (TEST/DEBUG) */
#endif
				
		mfmsr	r0								/* Get the MSR */
		rlwinm	r7,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear 'rupts */
		mtmsr	r7								/* Disable 'rupts */

		mfsprg	r7,0							/* Get the per_proc */
		lwz		r7,PP_CPU_DATA(r7)
		cmpli	cr0,r5,0
		lwz		r10,CPU_ACTIVE_THREAD(r7)
		mtmsr	r0								/* Restore 'rupts */
		ble-	cr0,.L_copyinout_trivial

/* we know we have a valid copyin to do now */
/* Set up thread_recover in case we hit an illegal address */
		
		li		r0,0							
		lwz		r8,THREAD_TOP_ACT(r10)
		stw		r0,0(r6)						/* Clear result length */
		lis		r11,HIGH_ADDR(.L_copyinout_error)
		lwz		r8,ACT_VMMAP(r8)				; Get the map for this activation
		rlwinm	r12,r3,6,26,29					; Get index to the segment slot
		lwz		r8,VMMAP_PMAP(r8)
		ori		r11,r11,LOW_ADDR(.L_copyinout_error)
		add		r8,r8,r12						; Start indexing to the segment value
		stw		r11,THREAD_RECOVER(r10)
		rlwinm	r3,r3,0,4,31
		lwz		r7,PMAP_SEGS(r8)				; Get the source SR value
		oris	r3,r3,(SR_COPYIN_NUM << (28-16))	/* Set the copyin segment as the source */

/* Copy byte by byte for now - TODO NMGS speed this up with
 * some clever (but fairly standard) logic for word copies.
 * We don't use a copyinstr_multiple since copyinstr is called
 * with INT_MAX in the linux server. Eugh.
 */

		li		r9,0							/* Clear byte counter */

/* If the destination is NULL, don't do writes,
 * just count bytes. We set CR7 outside the loop to save time
 */
		cmpwi	cr7,r4,0						/* Is the destination null? */
		
nxtseg:	mtsr	SR_COPYIN,r7					/* Set the source SR */
		isync

.L_copyinstr_loop:
		lbz		r0,0(r3)						/* Get the source */
		addic.	r5,r5,-1						/* Have we gone far enough? */
		addi	r3,r3,1							/* Bump source pointer */
		
		cmpwi	cr1,r0,0						/* Did we hit a null? */

		beq		cr7,.L_copyinstr_no_store		/* If we are just counting, skip the store... */
	
		stb		r0,0(r4)						/* Move to sink */
		addi	r4,r4,1							/* Advance sink pointer */

.L_copyinstr_no_store:

		addi	r9,r9,1							/* Count the character */
		beq-	cr1,.L_copyinstr_done			/* We're done if we did a null... */
		beq-	cr0,L_copyinstr_toobig			/* Also if we maxed the count... */
	
/* Check to see if the copyin pointer has moved out of the
 * copyin segment, if it has we must remap.
 */

		rlwinm.	r0,r3,0,4,31					/* Did we wrap around to 0? */
		bne+	cr0,.L_copyinstr_loop			/* Nope... */

		lwz		r7,PMAP_SEGS+4(r8)				; Get the next source SR value
		addi	r8,r8,4							; Point to the next segment
		oris	r3,r0,(SR_COPYIN_NUM << (28-16))	/* Reset the segment number */
		b		nxtseg							/* Keep going... */
	
L_copyinstr_toobig:
		li		r3,ENAMETOOLONG
		b		L_copyinstr_return
.L_copyinstr_done:
		li		r3,0							/* Normal return */
L_copyinstr_return:
		li		r4,0							/* to clear thread_recover */
		stw		r9,0(r6)						/* Set how many bytes we did */
		stw		r4,THREAD_RECOVER(r10)			/* Clear recovery exit */

		addi	r1,	r1,	FM_SIZE+16
		lwz		r0,	FM_LR_SAVE(r1)
		mtlr	r0
		blr
