/*
 * Copyright (c) 2003-2009 Apple, Inc. All rights reserved.
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

#define _PTHREAD_TSD_OFFSET32 0x48
#define _PTHREAD_TSD_OFFSET64 0x60


/* These routines do not need to be on the copmmpage on Intel.  They are for now
 * to avoid revlock, but the code should move to Libc, and we should eventually remove
 * these.
 */
COMMPAGE_FUNCTION_START(pthread_getspecific, 32, 4)
	movl	4(%esp), %eax
	movl	%gs:_PTHREAD_TSD_OFFSET32(,%eax,4), %eax
	ret
COMMPAGE_DESCRIPTOR(pthread_getspecific,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,0)

COMMPAGE_FUNCTION_START(pthread_self, 32, 4)
	movl	%gs:_PTHREAD_TSD_OFFSET32, %eax
	ret
COMMPAGE_DESCRIPTOR(pthread_self,_COMM_PAGE_PTHREAD_SELF,0,0)

/* the 64-bit versions: */
COMMPAGE_FUNCTION_START(pthread_getspecific_64, 64, 4)
	movq	%gs:_PTHREAD_TSD_OFFSET64(,%rdi,8), %rax
	ret
COMMPAGE_DESCRIPTOR(pthread_getspecific_64,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,0)

COMMPAGE_FUNCTION_START(pthread_self_64, 64, 4)
	movq	%gs:_PTHREAD_TSD_OFFSET64, %rax
	ret
COMMPAGE_DESCRIPTOR(pthread_self_64,_COMM_PAGE_PTHREAD_SELF,0,0)


/* Temporary definitions.  Replace by #including the correct file when available.  */

#define PTHRW_EBIT      0x01
#define PTHRW_LBIT      0x02
#define PTHRW_YBIT      0x04
#define PTHRW_WBIT      0x08
#define PTHRW_UBIT      0x10
#define PTHRW_RETRYBIT      0x20
#define PTHRW_TRYLKBIT      0x40

#define PTHRW_INC       0x100
#define PTHRW_BIT_MASK  0x000000ff;

#define PTHRW_COUNT_SHIFT       8
#define PTHRW_COUNT_MASK        0xffffff00
#define PTHRW_MAX_READERS       0xffffff00

#define	KSYN_MLWAIT 301	    /* mutex lock wait syscall */

#define	PTHRW_STATUS_ACQUIRED	0
#define	PTHRW_STATUS_SYSCALL	1
#define	PTHRW_STATUS_ERROR	2
 
#define	PTHRW_LVAL    0
#define	PTHRW_UVAL    4



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
 * Because we need to avoid being preempted between changing the mutex stateword
 * and entering the kernel to relinquish, some low-level pthread mutex manipulations
 * are located in the PFZ.
 */


/* int							    // we return 0 on acquire, 1 on syscall
 * pthread_mutex_lock(	uint32_t    *lvalp,		    // ptr to mutex LVAL/UVAL pair
 *			int	    flags,		    // flags to pass kernel if we do syscall
 *			uint64_t    mtid,		    // my Thread ID
 *			uint32_t    mask,		    // bits to test in LVAL (ie, EBIT etc)
 *			uint64_t    *tidp,		    // ptr to TID field of mutex
 *			int	    *syscall_return );	    // if syscall, return value stored here
 */
COMMPAGE_FUNCTION_START(pthread_mutex_lock, 32, 4)
	pushl	%ebp			    // set up frame for backtrace
	movl	%esp,%ebp
	pushl	%esi
	pushl	%edi
	pushl	%ebx
	xorl	%ebx,%ebx		    // clear "preemption pending" flag
	movl	20(%esp),%edi		    // %edi == ptr to LVAL/UVAL structure
	lea	20(%esp),%esi		    // %esi == ptr to argument list
	movl	_COMM_PAGE_SPIN_COUNT, %edx
	movl	16(%esi),%ecx		    // get mask (ie, PTHRW_EBIT etc)
1:
	testl	PTHRW_LVAL(%edi),%ecx	    // is mutex available?
	jz	2f			    // yes, it is available
	pause
	decl	%edx			    // decrement max spin count
	jnz	1b			    // keep spinning
2:
	COMMPAGE_CALL(_COMM_PAGE_PFZ_MUTEX_LOCK,_COMM_PAGE_MUTEX_LOCK,pthread_mutex_lock)
	testl	%ebx,%ebx		    // pending preemption?
	jz	3f
	pushl	%eax			    // save return value across sysenter
	COMMPAGE_CALL(_COMM_PAGE_PREEMPT,_COMM_PAGE_MUTEX_LOCK,pthread_mutex_lock)
	popl	%eax
3:
	popl	%ebx
	popl	%edi
	popl	%esi
	popl	%ebp
	ret
COMMPAGE_DESCRIPTOR(pthread_mutex_lock,_COMM_PAGE_MUTEX_LOCK,0,0)


/* Internal routine to handle pthread mutex lock operation.  This is in the PFZ.
 *	%edi == ptr to LVAL/UVAL pair
 *	%esi == ptr to argument list on stack
 *	%ebx == preempion pending flag (kernel sets nonzero if we should preempt)
 */
COMMPAGE_FUNCTION_START(pfz_mutex_lock, 32, 4)
	pushl	%ebp			    // set up frame for backtrace
	movl	%esp,%ebp
1:	
	movl	16(%esi),%ecx		    // get mask (ie, PTHRW_EBIT etc)
2:
	movl	PTHRW_LVAL(%edi),%eax	    // get mutex LVAL
	testl	%eax,%ecx		    // is mutex available?
	jnz	5f			    // no
	
	/* lock is available (if we act fast) */
	lea	PTHRW_INC(%eax),%edx	    // copy original lval and bump sequence count
	orl	$PTHRW_EBIT, %edx	    // set EBIT
	lock
	cmpxchgl %edx,PTHRW_LVAL(%edi)	    // try to acquire lock for real
	jz	4f			    // got it
3:
	testl	%ebx,%ebx		    // kernel trying to preempt us?
	jz	2b			    // no, so loop and try again
	COMMPAGE_CALL(_COMM_PAGE_PREEMPT,_COMM_PAGE_PFZ_MUTEX_LOCK,pfz_mutex_lock)
	jmp	1b			    // loop to try again
	
	/* we acquired the mutex */
4:
	movl	20(%esi),%eax		    // get ptr to TID field of mutex
	movl	8(%esi),%ecx		    // get 64-bit mtid
	movl	12(%esi),%edx
	movl	%ecx,0(%eax)		    // store my TID in mutex structure
	movl	%edx,4(%eax)
	movl	$PTHRW_STATUS_ACQUIRED,%eax
	popl	%ebp
	ret
	
	/* cannot acquire mutex, so update seq count, set "W", and block in kernel */
	/* this is where we cannot tolerate preemption or being killed */
5:
	lea	PTHRW_INC(%eax),%edx	    // copy original lval and bump sequence count
	orl	$PTHRW_WBIT, %edx	    // set WBIT
	lock
	cmpxchgl %edx,PTHRW_LVAL(%edi)	    // try to update lock status atomically
	jnz	3b			    // failed
	movl	20(%esi),%eax		    // get ptr to TID field of mutex
	pushl	4(%esi)			    // arg 5: flags from arg list
	pushl	4(%eax)			    // arg 4: tid field from mutex
	pushl	0(%eax)
	pushl	PTHRW_UVAL(%edi)	    // arg 3: uval field from mutex
	pushl	%edx			    // arg 2: new value of mutex lval field
	pushl	%edi			    // arg 1: ptr to LVAL/UVAL pair in mutex
	call	6f			    // make ksyn_mlwait call
	jc	6f			    // immediately reissue syscall if error
	movl	24(%esi),%edx		    // get ptr to syscall_return arg
	movl	%eax,(%edx)		    // save syscall return value
	movl	$PTHRW_STATUS_SYSCALL,%eax  // we had to make syscall
	addl	$28,%esp		    // pop off syscall args and return address
	popl	%ebp			    // pop off frame ptr
	ret

	/* subroutine to make a ksyn_mlwait syscall */
6:
	movl	(%esp),%edx		    // get return address but leave on stack
	movl	%esp,%ecx		    // save stack ptr here
	movl	$KSYN_MLWAIT,%eax	    // get syscall code
	orl	$0x00180000,%eax	    // copy 24 bytes of arguments in trampoline
	xorl	%ebx,%ebx		    // clear preemption flag
	sysenter
COMMPAGE_DESCRIPTOR(pfz_mutex_lock,_COMM_PAGE_PFZ_MUTEX_LOCK,0,0)



/************************* x86_64 versions follow **************************/



/* int							    // we return 0 on acquire, 1 on syscall
 * pthread_mutex_lock(	uint32_t    *lvalp,		    // ptr to mutex LVAL/UVAL pair
 *			int	    flags,		    // flags to pass kernel if we do syscall
 *			uint64_t    mtid,		    // my Thread ID
 *			uint32_t    mask,		    // bits to test in LVAL (ie, EBIT etc)
 *			uint64_t    *tidp,		    // ptr to TID field of mutex
 *			int	    *syscall_return );	    // if syscall, return value stored here
 *
 *	%rdi = lvalp
 *	%esi = flags
 *	%rdx = mtid
 *	%ecx = mask
 *	%r8  = tidp
 *	%r9  = &syscall_return
 */
COMMPAGE_FUNCTION_START(pthread_mutex_lock_64, 64, 4)
	pushq	%rbp		    // set up frame for backtrace
	movq	%rsp,%rbp
	pushq	%rbx
	xorl	%ebx,%ebx	    // clear "preemption pending" flag
	movl	_COMM_PAGE_32_TO_64(_COMM_PAGE_SPIN_COUNT), %eax
1:
	testl	PTHRW_LVAL(%rdi),%ecx // is mutex available?
	jz	2f		    // yes, it is available
	pause
	decl	%eax		    // decrement max spin count
	jnz	1b		    // keep spinning
2:
	COMMPAGE_CALL(_COMM_PAGE_PFZ_MUTEX_LOCK,_COMM_PAGE_MUTEX_LOCK,pthread_mutex_lock_64)
	testl	%ebx,%ebx	    // pending preemption?
	jz	1f		    // no
	COMMPAGE_CALL(_COMM_PAGE_PREEMPT,_COMM_PAGE_MUTEX_LOCK,pthread_mutex_lock_64)
1:
	popq	%rbx
	popq	%rbp
	ret
COMMPAGE_DESCRIPTOR(pthread_mutex_lock_64,_COMM_PAGE_MUTEX_LOCK,0,0)


/* Internal routine to handle pthread mutex lock operation.  This is in the PFZ.
 *	%rdi = lvalp
 *	%esi = flags
 *	%rdx = mtid
 *	%ecx = mask
 *	%r8  = tidp
 *	%r9  = &syscall_return
 *	%ebx = preempion pending flag (kernel sets nonzero if we should preempt)
 */
COMMPAGE_FUNCTION_START(pfz_mutex_lock_64, 64, 4)
	pushq	%rbp			    // set up frame for backtrace
	movq	%rsp,%rbp
1:	
	movl	PTHRW_LVAL(%rdi),%eax	    // get old lval from mutex
2:
	testl	%eax,%ecx		    // can we acquire the lock?
	jnz	5f			    // no
	
	/* lock is available (if we act fast) */
	lea	PTHRW_INC(%rax),%r11	    // copy original lval and bump sequence count
	orl	$PTHRW_EBIT, %r11d	    // set EBIT
	lock
	cmpxchgl %r11d,PTHRW_LVAL(%rdi)	    // try to acquire lock
	jz	4f			    // got it
3:
	testl	%ebx,%ebx		    // kernel trying to preempt us?
	jz	2b			    // no, so loop and try again
	COMMPAGE_CALL(_COMM_PAGE_PREEMPT,_COMM_PAGE_PFZ_MUTEX_LOCK,pfz_mutex_lock_64)
	jmp	1b			    // loop to try again
	
	/* we acquired the mutex */
4:
	movq	%rdx,(%r8)		    // store mtid in mutex structure
	movl	$PTHRW_STATUS_ACQUIRED,%eax
	popq	%rbp
	ret
	
	/* cannot acquire mutex, so update seq count and block in kernel */
	/* this is where we cannot tolerate preemption or being killed */
5:
	lea	PTHRW_INC(%rax),%r11	    // copy original lval and bump sequence count
	orl	$PTHRW_WBIT, %r11d	    // set WBIT
	lock
	cmpxchgl %r11d,PTHRW_LVAL(%rdi)	    // try to update lock status atomically
	jnz	3b			    // failed
	movq	(%r8),%r10		    // arg 4: tid field from mutex [NB: passed in R10]
	movl	%esi,%r8d		    // arg 5: flags from arg list
	movl	PTHRW_UVAL(%rdi),%edx	    // arg 3: uval field from mutex
	movl	%r11d,%esi		    // arg 2: new value of mutex lval field
					    // arg 1: LVAL/UVAL ptr already in %rdi
6:
	movl	$(SYSCALL_CONSTRUCT_UNIX(KSYN_MLWAIT)),%eax
	pushq	%rdx			    // some syscalls destroy %rdx so save it
	xorl	%ebx,%ebx		    // clear preemption flag
	syscall
	popq	%rdx			    // restore in case we need to re-execute syscall
	jc	6b			    // immediately re-execute syscall if error
	movl	%eax,(%r9)		    // store kernel return value
	movl	$PTHRW_STATUS_SYSCALL,%eax  // we made syscall
	popq	%rbp
	ret
COMMPAGE_DESCRIPTOR(pfz_mutex_lock_64,_COMM_PAGE_PFZ_MUTEX_LOCK,0,0)

