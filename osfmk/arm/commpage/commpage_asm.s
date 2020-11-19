/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <machine/asm.h>

/* This section has all the code necessary for the atomic operations supported by
 * OSAtomicFifoEnqueue, OSAtomicFifoDequeue APIs in libplatform.
 *
 * This code needs to be compiled as 1 section and should not make branches
 * outside of this section. This allows us to copy the entire section to the
 * text comm page once it is created - see osfmk/arm/commpage/commpage.c
 *
 * This section is split into 2 parts - the preemption-free zone (PFZ) routines
 * and the preemptible routines (non-PFZ). The PFZ routines will not be
 * preempted by the scheduler if the pc of the userspace process is in that
 * region while handling asynchronous interrupts (note that traps are still
 * possible in the PFZ). Instead, the scheduler will mark x15 (known through
 * coordination with the functions in the commpage section) to indicate to the
 * userspace code that it needs to take a delayed preemption. The PFZ functions
 * may make callouts to preemptible routines and vice-versa. When a function
 * returns to a preemptible routine after a callout to a function in the PFZ, it
 * needs to check x15 to determine if a delayed preemption needs to be taken. In
 * addition, functions in the PFZ should not have backwards branches.
 *
 * The entry point to execute code in the commpage text section is through the
 * jump table at the very top of the section. The base of the jump table is
 * exposed to userspace via the APPLE array and the offsets from the base of the
 * jump table are listed in the arm/cpu_capabilities.h header. Adding any new
 * functions in the PFZ requires a lockstep change to the cpu_capabilities.h
 * header.
 *
 * Functions in PFZ:
 *		Enqueue function
 *		Dequeue function
 *
 * Functions not in PFZ:
 *		Backoff function as part of spin loop
 *		Preempt function to take delayed preemption as indicated by kernel
 *
 * ----------------------------------------------------------------------
 *
 * The high level goal of the asm code in this section is to enqueue and dequeue
 * from a FIFO linked list.
 *
 * typedef volatile struct {
 *		void *opaque1; <-- ptr to first queue element or null
 *		void *opaque2; <-- ptr to second queue element or null
 *		int opaque3; <-- spinlock
 * } OSFifoQueueHead;
 *
 * This is done through a userspace spin lock stored in the linked list head
 * for synchronization.
 *
 * Here is the pseudocode for the spin lock acquire algorithm which is split
 * between the PFZ and the non-PFZ areas of the commpage text section. The
 * pseudocode here is just for the enqueue operation but it is symmetrical for
 * the dequeue operation.
 *
 * // Not in the PFZ. Entry from jump table.
 * ENQUEUE()
 *		enqueued = TRY_LOCK_AND_ENQUEUE(lock_addr);
 *		// We're running here after running the TRY_LOCK_AND_ENQUEUE code in
 *		// the PFZ so we need to check if we need to take a delayed
 *		// preemption.
 *		if (kernel_wants_to_preempt_us){
 *			// This is done through the pfz_exit() mach trap which is a dummy
 *			// syscall whose sole purpose is to allow the thread to enter the
 *			// kernel so that it can be preempted at AST.
 *			enter_kernel_to_take_delayed_preemption()
 *		}
 *
 *		if (!enqueued) {
 *			ARM_MONITOR;
 *			WFE;
 *			enqueued = TRY_LOCK_AND_ENQUEUE(lock_addr);
 *			if (!enqueued) {
 *				// We failed twice, take a backoff
 *				BACKOFF();
 *				goto ENQUEUE()
 *			} else {
 *				// We got here from PFZ, check for delayed preemption
 *				if (kernel_wants_to_preempt_us){
 *					enter_kernel_to_take_delayed_preemption()
 *				}
 *			}
 *		}
 *
 * // in PFZ
 * TRY_LOCK_AND_ENQUEUE():
 *		is_locked = try_lock(lock_addr);
 *		if (is_locked) {
 *			<do enqueue operation>
 *			return true
 *		} else {
 *			return false
 *		}
 *
 *
 * // Not in the PFZ
 * BACKOFF():
 *		// We're running here after running the TRY_LOCK_AND_ENQUEUE code in
 *		// the PFZ so we need to check if we need to take a delayed
 *		// preemption.
 *		if (kernel_wants_to_preempt_us) {
 *			enter_kernel_to_take_preemption()
 *		} else {
 *			// Note that it is safe to do this loop here since the entire
 *			// BACKOFF function isn't in the PFZ and so can be preempted at any
 *			// time
 *			do {
 *				lock_is_free = peek(lock_addr);
 *				if (lock_is_free) {
 *					return
 *				} else {
 *					pause_with_monitor(lock_addr)
 *				}
 *			} while (1)
 *		}
 */

/* Macros and helpers */

.macro BACKOFF lock_addr
	// Save registers we can't clobber
	stp		x0, x1, [sp, #-16]!
	stp		x2, x9, [sp, #-16]!

	// Pass in lock addr to backoff function
	mov		x0, \lock_addr
	bl		_backoff			// Jump out of the PFZ zone now

	// Restore registers
	ldp		x2, x9, [sp], #16
	ldp		x0, x1, [sp], #16
.endmacro

/* x0 = pointer to queue head
 * x1 = pointer to new elem to enqueue
 * x2 = offset of link field inside element
 * x3 = Address of lock
 *
 * Moves result of the helper function to the register specified
 */
.macro TRYLOCK_ENQUEUE result
	stp		x0, xzr, [sp, #-16]! // Save x0 since it'll be clobbered by return value

	bl	_pfz_trylock_and_enqueue
	mov		\result, x0

	ldp		x0, xzr, [sp], #16 // Restore saved registers
.endmacro

/* x0 = pointer to queue head
 * x1 = offset of link field inside element
 * x2 = Address of lock
 *
 * Moves result of the helper function to the register specified
 */
.macro TRYLOCK_DEQUEUE result
	stp		x0, xzr, [sp, #-16]! // Save x0 since it'll be clobbered by return value

	bl	_pfz_trylock_and_dequeue
	mov		\result, x0

	ldp		x0, xzr, [sp], #16 // Restore saved registers
.endmacro

/*
 * Takes a delayed preemption if needed and then branches to the label
 * specified.
 *
 * Modifies x15
 */
.macro PREEMPT_SELF_THEN branch_to_take_on_success
	cbz		x15,  \branch_to_take_on_success // No delayed preemption to take, just try again

	mov		x15, xzr				// zero out the preemption pending field
	bl _preempt_self
	b \branch_to_take_on_success
.endmacro

	.section __TEXT_EXEC,__commpage_text,regular,pure_instructions

	/* Preemption free functions */
	.align 2
_jump_table:				// 32 entry jump table, only 2 are used
	b	_pfz_enqueue
	b	_pfz_dequeue
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666
	brk #666


/*
 * typedef volatile struct {
 *		void *opaque1; <-- ptr to first queue element or null
 *		void *opaque2; <-- ptr to second queue element or null
 *		int opaque3; <-- spinlock
 * } osfifoqueuehead;
 */

/* Non-preemptible helper routine to FIFO enqueue:
 * int pfz_trylock_and_enqueue(OSFifoQueueHead *__list, void *__new, size_t __offset, uint32_t *lock_addr);
 *
 * x0 = pointer to queue head structure
 * x1 = pointer to new element to enqueue
 * x2 = offset of link field inside element
 * x3 = address of lock
 *
 * Only caller save registers (x9 - x15) are used in this function
 *
 * Returns 0 on success and non-zero value on failure
 */
	.globl _pfz_trylock_and_enqueue
	.align 2
_pfz_trylock_and_enqueue:
	ARM64_STACK_PROLOG
	PUSH_FRAME

	mov		w10, wzr		 // unlock value = w10 = 0
	mov		w11, #1			 // locked value = w11 = 1

	// Try to grab the lock
	casa	w10, w11, [x3]	 // Atomic CAS with acquire barrier
	cbz		w10, Ltrylock_enqueue_success

	mov		x0, #-1			// Failed
	b Ltrylock_enqueue_exit

	/* We got the lock, enqueue the element */

Ltrylock_enqueue_success:
	ldr		x10, [x0, #8]	 // x10 = tail of the queue
	cbnz	x10, Lnon_empty_queue // tail not NULL
	str		x1, [x0]		 // Set head to new element
	b		Lset_new_tail

Lnon_empty_queue:
	str		x1, [x10, x2]	// Set old tail -> offset = new elem

Lset_new_tail:
	str		x1, [x0, #8]		// Set tail = new elem

	// Drop spin lock with release barrier (pairs with acquire in casa)
	stlr	wzr, [x3]

	mov		x0, xzr				// Mark success

Ltrylock_enqueue_exit:
	POP_FRAME
	ARM64_STACK_EPILOG

/* Non-preemptible helper routine to FIFO dequeue:
 * void *pfz_trylock_and_dequeue(OSFifoQueueHead *__list, size_t __offset, uint32_t *lock_addr);
 *
 * x0 = pointer to queue head structure
 * x1 = pointer to new element to enqueue
 * x2 = address of lock
 *
 * Only caller save registers (x9 - x15) are used in this function
 *
 * Returns -1 on failure, and the pointer on success (can be NULL)
 */
	.globl _pfz_trylock_and_dequeue
	.align 2
_pfz_trylock_and_dequeue:
	ARM64_STACK_PROLOG
	PUSH_FRAME

	// Try to grab the lock
	mov		w10, wzr		 // unlock value = w10 = 0
	mov		w11, #1			 // locked value = w11 = 1

	casa	w10, w11, [x2]	 // Atomic CAS with acquire barrier
	cbz		w10, Ltrylock_dequeue_success

	mov		x0, #-1			// Failed
	b Ltrylock_dequeue_exit

	/* We got the lock, dequeue the element */
Ltrylock_dequeue_success:
	ldr		x10, [x0]	 // x10 = head of the queue
	cbz		x10, Lreturn_head // if head is null, return

	ldr		x11, [x10, x1]	// get ptr to new head
	cbnz	x11, Lupdate_new_head // If new head != NULL, then not singleton. Only need to update head

	// Singleton case
	str		xzr, [x0, #8]	// dequeuing from singleton queue, update tail to NULL

Lupdate_new_head:
	str		xzr, [x10, x1]	// zero the link in the old head
	str		x11, [x0]		// Set up a new head

Lreturn_head:
	mov		x0, x10			// Move head to x0
	stlr	wzr, [x2]		// Drop spin lock with release barrier (pairs with acquire in casa)

Ltrylock_dequeue_exit:
	POP_FRAME
	ARM64_STACK_EPILOG


	/* Preemptible functions */
	.private_extern _commpage_text_preemptible_functions
_commpage_text_preemptible_functions:


/*
 * void pfz_enqueue(OSFifoQueueHead *__list, void *__new, size_t __offset);
 * x0 = pointer to queue head
 * x1 = pointer to new elem to enqueue
 * x2 = offset of link field inside element
 */
	.globl _pfz_enqueue

	.align 2
_pfz_enqueue:
	ARM64_STACK_PROLOG
	PUSH_FRAME

	str		xzr, [x1, x2]	// Zero the forward link in the new element
	mov		x15, xzr		// zero out the register used to communicate with kernel

	add		x3, x0, #16		// address of lock = x3 = x0 + 16
Lenqueue_trylock_loop:

	// Attempt #1
	TRYLOCK_ENQUEUE x9
	PREEMPT_SELF_THEN Lenqueue_determine_success

Lenqueue_determine_success:

	cbz		x9, Lenqueue_success // did we succeed? if so, exit

	ldxr	w9, [x3]		// arm the monitor for the lock address
	cbz		w9, Lenqueue_clear_monitor // lock is available, retry.

	wfe						// Wait with monitor armed

	// Attempt #2
	TRYLOCK_ENQUEUE x9
	cbz		x9, Lenqueue_take_delayed_preemption_upon_success  // did we succeed? if so, exit

	// We failed twice - backoff then try again

	BACKOFF x3
	b Lenqueue_trylock_loop

Lenqueue_clear_monitor:
	clrex							// Pairs with the ldxr

	// Take a preemption if needed then branch to enqueue_trylock_loop
	PREEMPT_SELF_THEN Lenqueue_trylock_loop

Lenqueue_take_delayed_preemption_upon_success:
	PREEMPT_SELF_THEN Lenqueue_success

Lenqueue_success:
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * void *pfz_dequeue(OSFifoQueueHead *__list, size_t __offset);
 * x0 = pointer to queue head
 * x1 = offset of link field inside element
 *
 * This function is not in the PFZ but calls out to a helper which is in the PFZ
 * (_pfz_trylock_and_dequeue)
 */
	.globl	_pfz_dequeue
	.align 2
_pfz_dequeue:
	ARM64_STACK_PROLOG
	PUSH_FRAME

	mov		x15, xzr		// zero out the register used to communicate with kernel

	add		x2, x0, #16		// address of lock = x2 = x0 + 16
Ldequeue_trylock_loop:

	// Attempt #1
	TRYLOCK_DEQUEUE x9
	PREEMPT_SELF_THEN Ldequeue_determine_success

Ldequeue_determine_success:
	cmp		x9, #-1			// is result of dequeue == -1?
	b.ne	Ldequeue_success // no, we succeeded

	ldxr	w9, [x2]		// arm the monitor for the lock address
	cbz		w9, Ldequeue_clear_monitor // lock is available, retry.

	wfe						// Wait with monitor armed

	// Attempt #2
	TRYLOCK_DEQUEUE x9
	cmp		x9, #-1		// did we fail?
	b.ne	Ldequeue_take_delayed_preemption_upon_success // no, we succeeded

	// We failed twice - backoff then try again

	BACKOFF x2
	b	Ldequeue_trylock_loop

Ldequeue_take_delayed_preemption_upon_success:
	// We just got here after executing PFZ code, check if we need a preemption
	PREEMPT_SELF_THEN Ldequeue_success

Ldequeue_clear_monitor:
	clrex							// Pairs with the ldxr
	// Take a preemption if needed then branch to dequeue_trylock_loop.
	PREEMPT_SELF_THEN Ldequeue_trylock_loop

Ldequeue_success:
	mov		x0, x9		// Move x9 (where result was stored earlier) to x0
	POP_FRAME
	ARM64_STACK_EPILOG


/* void preempt_self(void)
 *
 * Make a syscall to take a preemption. This function is not in the PFZ.
 */
	.align 2
_preempt_self:
	ARM64_STACK_PROLOG
	PUSH_FRAME

	// Save registers on which will be clobbered by mach trap on stack and keep
	// it 16 byte aligned
	stp		x0, x1, [sp, #-16]!

	// Note: We don't need to caller save registers since svc will trigger an
	// exception and kernel will save and restore register state

	// Make syscall to take delayed preemption
	mov		x16, #-58	// -58 = pfz_exit
	svc		#0x80

	// Restore registers from stack
	ldp		x0, x1, [sp], #16

	POP_FRAME
	ARM64_STACK_EPILOG

/*
 *	void backoff(uint32_t *lock_addr);
 * The function returns when it observes that the lock has become available.
 * This function is not in the PFZ.
 *
 * x0 = lock address
 */
	.align 2
	.globl _backoff
_backoff:
	ARM64_STACK_PROLOG
	PUSH_FRAME

	cbz		x15, Lno_preempt	// Kernel doesn't want to preempt us, jump to loop

	mov		x15, xzr	// zero out the preemption pending field
	bl _preempt_self

Lno_preempt:
	ldxr	w9, [x0]		// Snoop on lock and arm the monitor
	cbz		w9, Lend_backoff // The lock seems to be available, return

	wfe						// pause

	b	Lno_preempt

Lend_backoff:
	clrex

	POP_FRAME
	ARM64_STACK_EPILOG
