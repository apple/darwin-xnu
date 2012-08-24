/*
 * Copyright (c) 2008 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <mach/i386/syscall_sw.h>


/* PREEMPTION FREE ZONE (PFZ)
 *
 * A portion of the commpage is speacial-cased by the kernel to be "preemption free",
 * ie as if we had disabled interrupts in user mode.  This facilitates writing
 * "nearly-lockless" code, for example code that must be serialized by a spinlock but
 * which we do not want to preempt while the spinlock is held.
 *
 * The PFZ is implemented by collecting all the "preemption-free" code into a single
 * contiguous region of the commpage.  Register %ebx is used as a flag register;
 * before entering the PFZ, %ebx is cleared.  If some event occurs that would normally
 * result in a premption while in the PFZ, the kernel sets %ebx nonzero instead of
 * preempting.  Then, when the routine leaves the PFZ we check %ebx and
 * if nonzero execute a special "pfz_exit" syscall to take the delayed preemption.
 *
 * PFZ code must bound the amount of time spent in the PFZ, in order to control
 * latency.  Backward branches are dangerous and must not be used in a way that
 * could inadvertently create a long-running loop.
 *
 * Because they cannot be implemented reasonably without a lock, we put the "atomic"
 * FIFO enqueue and dequeue in the PFZ.  As long as we don't take a page fault trying to
 * access queue elements, these implementations behave nearly-locklessly.
 * But we still must take a spinlock to serialize, and in case of page faults.
 */

/* Work around 10062261 with a dummy non-local symbol */
fifo_queue_dummy_symbol:	

/*
 *	typedef	volatile struct {
 *		void	*opaque1;  <-- ptr to first queue element or null
 *		void	*opaque2;  <-- ptr to last queue element or null
 *		int	 opaque3;  <-- spinlock
 *	} OSFifoQueueHead;
 *
 * void  OSAtomicFifoEnqueue( OSFifoQueueHead *list, void *new, size_t offset);
 */


/* Subroutine to make a preempt syscall.  Called when we notice %ebx is
 * nonzero after returning from a PFZ subroutine.
 * When we enter kernel:
 *	%edx = return address
 *	%ecx = stack ptr
 * Destroys %eax, %ecx, and %edx.
 */
COMMPAGE_FUNCTION_START(preempt, 32, 4)
	popl	%edx		// get return address
	movl	%esp,%ecx	// save stack ptr here
	movl	$(-58),%eax	/* 58 = pfz_exit */
	xorl	%ebx,%ebx	// clear "preemption pending" flag
	sysenter
COMMPAGE_DESCRIPTOR(preempt,_COMM_PAGE_PREEMPT,0,0)


/* Subroutine to back off if we cannot get the spinlock.  Called
 * after a few attempts inline in the PFZ subroutines.  This code is
 * not in the PFZ.
 *	%edi = ptr to queue head structure
 *	%ebx = preemption flag (nonzero if preemption pending)
 * Destroys %eax.
 */
COMMPAGE_FUNCTION_START(backoff, 32, 4)
	testl	%ebx,%ebx	// does kernel want to preempt us?
	jz	1f		// no
	xorl	%ebx,%ebx	// yes, clear flag
	pushl	%edx		// preserve regs used by preempt syscall
	pushl	%ecx
	COMMPAGE_CALL(_COMM_PAGE_PREEMPT,_COMM_PAGE_BACKOFF,backoff)
	popl	%ecx
	popl	%edx
1:
	pause			// SMT-friendly backoff
	cmpl	$0,8(%edi)	// sniff the lockword
	jnz	1b		// loop if still taken
	ret			// lockword is free, so reenter PFZ
COMMPAGE_DESCRIPTOR(backoff,_COMM_PAGE_BACKOFF,0,0)


/* Preemption-free-zone routine to FIFO Enqueue:
 *	%edi = ptr to queue head structure
 *	%esi = ptr to element to enqueue
 *	%edx = offset of link field in elements
 *	%ebx = preemption flag (kernel sets nonzero if we should preempt)
 */
 
COMMPAGE_FUNCTION_START(pfz_enqueue, 32, 4)
	movl	    $0,(%edx,%esi)  // zero forward link in new element
1:
	xorl	    %eax, %eax
	orl	    $-1, %ecx
	lock
	cmpxchgl    %ecx, 8(%edi)   // try to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx, 8(%edi)   // try 2nd time to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx, 8(%edi)   // try 3rd time to take the spinlock
	jz	    2f		    // got it
	
	COMMPAGE_CALL(_COMM_PAGE_BACKOFF,_COMM_PAGE_PFZ_ENQUEUE,pfz_enqueue)
	jmp	    1b		    // loop to try again
2:
	movl	    4(%edi),%ecx    // get ptr to last element in q
	testl	    %ecx,%ecx	    // q null?
	jnz	    3f		    // no
	movl	    %esi,(%edi)	    // q empty so this is first element
	jmp	    4f
3:
	movl	    %esi,(%edx,%ecx) // point to new element from last
4:
	movl	    %esi,4(%edi)    // new element becomes last in q
	movl	    $0,8(%edi)	    // unlock spinlock
	ret
COMMPAGE_DESCRIPTOR(pfz_enqueue,_COMM_PAGE_PFZ_ENQUEUE,0,0)


/* Preemption-free-zone routine to FIFO Dequeue:
 *	%edi = ptr to queue head structure
 *	%edx = offset of link field in elements
 *	%ebx = preemption flag (kernel sets nonzero if we should preempt)
 *
 * Returns with next element (or 0) in %eax.
 */
 
COMMPAGE_FUNCTION_START(pfz_dequeue, 32, 4)
1:
	xorl	    %eax, %eax
	orl	    $-1, %ecx
	lock
	cmpxchgl    %ecx, 8(%edi)   // try to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx, 8(%edi)   // try 2nd time to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx, 8(%edi)   // try 3rd time to take the spinlock
	jz	    2f		    // got it
	
	COMMPAGE_CALL(_COMM_PAGE_BACKOFF,_COMM_PAGE_PFZ_DEQUEUE,pfz_dequeue)
	jmp	    1b		    // loop to try again
2:
	movl	    (%edi),%eax	    // get ptr to first element in q
	testl	    %eax,%eax	    // q null?
	jz	    4f		    // yes
	movl	    (%edx,%eax),%esi// get ptr to 2nd element in q
	testl	    %esi,%esi	    // is there a 2nd element?
	jnz	    3f		    // yes
	movl	    %esi,4(%edi)    // clear "last" field of q head
3:
	movl	    %esi,(%edi)	    // update "first" field of q head
4:
	movl	    $0,8(%edi)	    // unlock spinlock
	ret
COMMPAGE_DESCRIPTOR(pfz_dequeue,_COMM_PAGE_PFZ_DEQUEUE,0,0)




/************************* x86_64 versions follow **************************/


/*
 *	typedef	volatile struct {
 *		void	*opaque1;  <-- ptr to first queue element or null
 *		void	*opaque2;  <-- ptr to last queue element or null
 *		int	 opaque3;  <-- spinlock
 *	} OSFifoQueueHead;
 *
 * void  OSAtomicFifoEnqueue( OSFifoQueueHead *list, void *new, size_t offset);
 */


/* Subroutine to make a preempt syscall.  Called when we notice %ebx is
 * nonzero after returning from a PFZ subroutine.  Not in PFZ.
 *
 * All registers preserved (but does clear the %ebx preemption flag).
 */
COMMPAGE_FUNCTION_START(preempt_64, 64, 4)
	pushq	%rax
	pushq	%rcx
	pushq	%r11
	movl	$(SYSCALL_CONSTRUCT_MACH(58)),%eax	/* 58 = pfz_exit */
	xorl	%ebx,%ebx
	syscall
	popq	%r11
	popq	%rcx
	popq	%rax
	ret
COMMPAGE_DESCRIPTOR(preempt_64,_COMM_PAGE_PREEMPT,0,0)


/* Subroutine to back off if we cannot get the spinlock.  Called
 * after a few attempts inline in the PFZ subroutines.  This code is
 * not in the PFZ.
 *	%rdi = ptr to queue head structure
 *	%ebx = preemption flag (nonzero if preemption pending)
 * Uses: %rax.
 */
COMMPAGE_FUNCTION_START(backoff_64, 64, 4)
	testl	%ebx,%ebx	// does kernel want to preempt us?
	jz	1f		// no
	COMMPAGE_CALL(_COMM_PAGE_PREEMPT,_COMM_PAGE_BACKOFF,backoff_64)
1:
	pause			// SMT-friendly backoff
	cmpl	$0,16(%rdi)	// sniff the lockword
	jnz	1b		// loop if still taken
	ret			// lockword is free, so reenter PFZ
COMMPAGE_DESCRIPTOR(backoff_64,_COMM_PAGE_BACKOFF,0,0)


/* Preemption-free-zone routine to FIFO Enqueue:
 *	%rdi = ptr to queue head structure
 *	%rsi = ptr to new element to enqueue
 *	%rdx = offset of link field in elements
 *	%ebx = preemption flag (kernel sets nonzero if we should preempt)
 */
 
COMMPAGE_FUNCTION_START(pfz_enqueue_64, 64, 4)
	movq	    $0,(%rdx,%rsi)  // zero forward link in new element
1:
	xorl	    %eax, %eax
	orl	    $-1, %ecx
	lock
	cmpxchgl    %ecx,16(%rdi)   // try to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx,16(%rdi)   // try 2nd time to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx,16(%rdi)   // try 3rd time to take the spinlock
	jz	    2f		    // got it
	
	COMMPAGE_CALL(_COMM_PAGE_BACKOFF,_COMM_PAGE_PFZ_ENQUEUE,pfz_enqueue_64)
	jmp	    1b		    // loop to try again
2:
	movq	    8(%rdi),%rcx    // get ptr to last element in q
	testq	    %rcx,%rcx	    // q null?
	jnz	    3f		    // no
	movq	    %rsi,(%rdi)	    // q empty so this is first element
	jmp	    4f
3:
	movq	    %rsi,(%rdx,%rcx) // point to new element from last
4:
	movq	    %rsi,8(%rdi)    // new element becomes last in q
	movl	    $0,16(%rdi)	    // unlock spinlock
	ret
COMMPAGE_DESCRIPTOR(pfz_enqueue_64,_COMM_PAGE_PFZ_ENQUEUE,0,0)



/* Preemption-free-zone routine to FIFO Dequeue:
 *	%rdi = ptr to queue head structure
 *	%rdx = offset of link field in elements
 *	%ebx = preemption flag (kernel sets nonzero if we should preempt)
 *
 * Returns with next element (or 0) in %rax.
 */
 
COMMPAGE_FUNCTION_START(pfz_dequeue_64, 64, 4)
1:
	xorl	    %eax, %eax
	orl	    $-1, %ecx
	lock
	cmpxchgl    %ecx,16(%rdi)   // try to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx,16(%rdi)   // try 2nd time to take the spinlock
	jz	    2f		    // got it
	
	pause
	xorl	    %eax, %eax
	lock
	cmpxchgl    %ecx,16(%rdi)   // try 3rd time to take the spinlock
	jz	    2f		    // got it
	
	COMMPAGE_CALL(_COMM_PAGE_BACKOFF,_COMM_PAGE_PFZ_DEQUEUE,pfz_dequeue_64)
	jmp	    1b		    // loop to try again
2:
	movq	    (%rdi),%rax	    // get ptr to first element in q
	testq	    %rax,%rax	    // q null?
	jz	    4f		    // yes
	movq	    (%rdx,%rax),%rsi// get ptr to 2nd element in q
	testq	    %rsi,%rsi	    // is there a 2nd element?
	jnz	    3f		    // yes
	movq	    %rsi,8(%rdi)    // no - clear "last" field of q head
3:
	movq	    %rsi,(%rdi)	    // update "first" field of q head
4:
	movl	    $0,16(%rdi)	    // unlock spinlock
	ret
COMMPAGE_DESCRIPTOR(pfz_dequeue_64,_COMM_PAGE_PFZ_DEQUEUE,0,0)
