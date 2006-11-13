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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1989 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <mach_rt.h>
#include <platforms.h>
#include <mach_ldebug.h>
#include <i386/asm.h>

#include "assym.s"

#define	PAUSE		rep; nop

/*
 *	When performance isn't the only concern, it's
 *	nice to build stack frames...
 */
#define	BUILD_STACK_FRAMES   (GPROF || \
				((MACH_LDEBUG || ETAP_LOCK_TRACE) && MACH_KDB))

#if	BUILD_STACK_FRAMES

/* STack-frame-relative: */
#define	L_PC		B_PC
#define	L_ARG0		B_ARG0
#define	L_ARG1		B_ARG1

#define LEAF_ENTRY(name)	\
	Entry(name);		\
	FRAME;			\
	MCOUNT

#define LEAF_ENTRY2(n1,n2)	\
	Entry(n1);		\
	Entry(n2);		\
	FRAME;			\
	MCOUNT

#define LEAF_RET		\
	EMARF;			\
	ret

#else	/* BUILD_STACK_FRAMES */

/* Stack-pointer-relative: */
#define	L_PC		S_PC
#define	L_ARG0		S_ARG0
#define	L_ARG1		S_ARG1

#define LEAF_ENTRY(name)	\
	Entry(name)

#define LEAF_ENTRY2(n1,n2)	\
	Entry(n1);		\
	Entry(n2)

#define LEAF_RET		\
	ret

#endif	/* BUILD_STACK_FRAMES */


/* Non-leaf routines always have a stack frame: */

#define NONLEAF_ENTRY(name)	\
	Entry(name);		\
	FRAME;			\
	MCOUNT

#define NONLEAF_ENTRY2(n1,n2)	\
	Entry(n1);		\
	Entry(n2);		\
	FRAME;			\
	MCOUNT

#define NONLEAF_RET		\
	EMARF;			\
	ret


#define	M_ILK		(%edx)
#define	M_LOCKED	MUTEX_LOCKED(%edx)
#define	M_WAITERS	MUTEX_WAITERS(%edx)
#define	M_PROMOTED_PRI	MUTEX_PROMOTED_PRI(%edx)
#define M_ITAG		MUTEX_ITAG(%edx)
#define M_PTR		MUTEX_PTR(%edx)
#if	MACH_LDEBUG
#define	M_TYPE		MUTEX_TYPE(%edx)
#define	M_PC		MUTEX_PC(%edx)
#define	M_THREAD	MUTEX_THREAD(%edx)
#endif	/* MACH_LDEBUG */

#include <i386/mp.h>
#define	CX(addr,reg)	addr(,reg,4)

#if	MACH_LDEBUG
/*
 *  Routines for general lock debugging.
 */

/* 
 * Checks for expected lock types and calls "panic" on
 * mismatch.  Detects calls to Mutex functions with
 * type simplelock and vice versa.
 */
#define	CHECK_MUTEX_TYPE()					\
	cmpl	$ MUTEX_TAG,M_TYPE			;	\
	je	1f					;	\
	pushl	$2f					;	\
	call	EXT(panic)				;	\
	hlt						;	\
	.data						;	\
2:	String	"not a mutex!"				;	\
	.text						;	\
1:

/*
 * If one or more simplelocks are currently held by a thread,
 * an attempt to acquire a mutex will cause this check to fail
 * (since a mutex lock may context switch, holding a simplelock
 * is not a good thing).
 */
#if	MACH_RT
#define CHECK_PREEMPTION_LEVEL()				\
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL		;	\
	je	1f					;	\
	pushl	$2f					;	\
	call	EXT(panic)				;	\
	hlt						;	\
	.data						;	\
2:	String	"preemption_level != 0!"		;	\
	.text						;	\
1:
#else	/* MACH_RT */
#define	CHECK_PREEMPTION_LEVEL()
#endif	/* MACH_RT */

#define	CHECK_NO_SIMPLELOCKS()					\
	cmpl	$0,%gs:CPU_SIMPLE_LOCK_COUNT		;	\
	je	1f					;	\
	pushl	$2f					;	\
	call	EXT(panic)				;	\
	hlt						;	\
	.data						;	\
2:	String	"simple_locks_held!"			;	\
	.text						;	\
1:

/* 
 * Verifies return to the correct thread in "unlock" situations.
 */
#define	CHECK_THREAD(thd)					\
	movl	%gs:CPU_ACTIVE_THREAD,%ecx		;	\
	testl	%ecx,%ecx				;	\
	je	1f					;	\
	cmpl	%ecx,thd				;	\
	je	1f					;	\
	pushl	$2f					;	\
	call	EXT(panic)				;	\
	hlt						;	\
	.data						;	\
2:	String	"wrong thread!"				;	\
	.text						;	\
1:

#define	CHECK_MYLOCK(thd)					\
	movl	%gs:CPU_ACTIVE_THREAD,%ecx		;	\
	testl	%ecx,%ecx				;	\
	je	1f					;	\
	cmpl	%ecx,thd				;	\
	jne	1f					;	\
	pushl	$2f					;	\
	call	EXT(panic)				;	\
	hlt						;	\
	.data						;	\
2:	String	"mylock attempt!"			;	\
	.text						;	\
1:

#define	METER_SIMPLE_LOCK_LOCK(reg)				\
	pushl	reg					;	\
	call	EXT(meter_simple_lock)			;	\
	popl	reg

#define	METER_SIMPLE_LOCK_UNLOCK(reg)				\
	pushl	reg					;	\
	call	EXT(meter_simple_unlock)		;	\
	popl	reg

#else	/* MACH_LDEBUG */
#define	CHECK_MUTEX_TYPE()
#define	CHECK_SIMPLE_LOCK_TYPE
#define	CHECK_THREAD(thd)
#define CHECK_PREEMPTION_LEVEL()
#define	CHECK_NO_SIMPLELOCKS()
#define	CHECK_MYLOCK(thd)
#define	METER_SIMPLE_LOCK_LOCK(reg)
#define	METER_SIMPLE_LOCK_UNLOCK(reg)
#endif	/* MACH_LDEBUG */


/*
 *	void hw_lock_init(hw_lock_t)
 *
 *	Initialize a hardware lock.
 */
LEAF_ENTRY(hw_lock_init)
	movl	L_ARG0,%edx		/* fetch lock pointer */
	movl	$0,0(%edx)		/* clear the lock */
	LEAF_RET

/*
 *	void hw_lock_lock(hw_lock_t)
 *
 *	Acquire lock, spinning until it becomes available.
 *	MACH_RT:  also return with preemption disabled.
 */
LEAF_ENTRY(hw_lock_lock)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	DISABLE_PREEMPTION
1:
	movl	0(%edx), %eax
	testl	%eax,%eax		/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchgl	%ecx,0(%edx)	/* try to acquire the HW lock */
	jne	3f
	movl	$1,%eax			/* In case this was a timeout call */
	LEAF_RET			/* if yes, then nothing left to do */
3:
	PAUSE				/* pause for hyper-threading */
	jmp	1b			/* try again */

/*
 *	unsigned int hw_lock_to(hw_lock_t, unsigned int)
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	MACH_RT:  also return with preemption disabled.
 */
LEAF_ENTRY(hw_lock_to)
1:
	movl	L_ARG0,%edx		/* fetch lock pointer */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	/*
	 * Attempt to grab the lock immediately
	 * - fastpath without timeout nonsense.
	 */
	DISABLE_PREEMPTION
	movl	0(%edx), %eax
	testl	%eax,%eax		/* lock locked? */
	jne	2f			/* branch if so */
	lock; cmpxchgl	%ecx,0(%edx)	/* try to acquire the HW lock */
	jne	2f			/* branch on failure */
	movl	$1,%eax
	LEAF_RET

2:
#define	INNER_LOOP_COUNT	1000
	/*
	 * Failed to get the lock so set the timeout
	 * and then spin re-checking the lock but pausing
	 * every so many (INNER_LOOP_COUNT) spins to check for timeout.
	 */
	movl	L_ARG1,%ecx		/* fetch timeout */
	push	%edi
	push	%ebx
	mov	%edx,%edi

	rdtsc				/* read cyclecount into %edx:%eax */
	addl	%ecx,%eax		/* fetch and timeout */
	adcl	$0,%edx			/* add carry */
	mov	%edx,%ecx
	mov	%eax,%ebx		/* %ecx:%ebx is the timeout expiry */
4:
	/*
	 * The inner-loop spin to look for the lock being freed.
	 */
	mov	$(INNER_LOOP_COUNT),%edx
5:
	PAUSE				/* pause for hyper-threading */
	movl	0(%edi),%eax		/* spin checking lock value in cache */
	testl	%eax,%eax
	je	6f			/* zero => unlocked, try to grab it */
	decl	%edx			/* decrement inner loop count */
	jnz	5b			/* time to check for timeout? */

	/*
	 * Here after spinning INNER_LOOP_COUNT times, check for timeout
	 */
	rdtsc				/* cyclecount into %edx:%eax */
	cmpl	%ecx,%edx		/* compare high-order 32-bits */
	jb	4b			/* continue spinning if less, or */
	cmpl	%ebx,%eax		/* compare low-order 32-bits */ 
	jb	4b			/* continue if less, else bail */
	xor	%eax,%eax		/* with 0 return value */
	pop	%ebx
	pop	%edi
	LEAF_RET

6:
	/*
	 * Here to try to grab the lock that now appears to be free
	 * after contention.
	 */
	movl	%gs:CPU_ACTIVE_THREAD,%edx
	lock; cmpxchgl	%edx,0(%edi)	/* try to acquire the HW lock */
	jne	4b			/* no - spin again */
	movl	$1,%eax			/* yes */
	pop	%ebx
	pop	%edi
	LEAF_RET

/*
 *	void hw_lock_unlock(hw_lock_t)
 *
 *	Unconditionally release lock.
 *	MACH_RT:  release preemption level.
 */
LEAF_ENTRY(hw_lock_unlock)
	movl	L_ARG0,%edx		/* fetch lock pointer */
	movl	$0,0(%edx)		/* clear the lock */
	ENABLE_PREEMPTION
	LEAF_RET

/*
 *	unsigned int hw_lock_try(hw_lock_t)
 *	MACH_RT:  returns with preemption disabled on success.
 */
LEAF_ENTRY(hw_lock_try)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	DISABLE_PREEMPTION
	movl	0(%edx),%eax
	testl	%eax,%eax
	jne	1f
	lock; cmpxchgl	%ecx,0(%edx)	/* try to acquire the HW lock */
	jne	1f

	movl	$1,%eax			/* success */
	LEAF_RET

1:
	ENABLE_PREEMPTION		/* failure:  release preemption... */
	xorl	%eax,%eax		/* ...and return failure */
	LEAF_RET

/*
 *	unsigned int hw_lock_held(hw_lock_t)
 *	MACH_RT:  doesn't change preemption state.
 *	N.B.  Racy, of course.
 */
LEAF_ENTRY(hw_lock_held)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movl	0(%edx),%eax		/* check lock value */
	testl	%eax,%eax
	movl	$1,%ecx
	cmovne	%ecx,%eax		/* 0 => unlocked, 1 => locked */
	LEAF_RET

LEAF_ENTRY(mutex_init)
	movl	L_ARG0,%edx		/* fetch lock pointer */
	xorl	%eax,%eax
	movl	%eax,M_ILK		/* clear interlock */
	movl	%eax,M_LOCKED		/* clear locked flag */
	movw	%ax,M_WAITERS		/* init waiter count */
	movw	%ax,M_PROMOTED_PRI

#if	MACH_LDEBUG
	movl	$ MUTEX_TAG,M_TYPE	/* set lock type */
	movl	%eax,M_PC		/* init caller pc */
	movl	%eax,M_THREAD		/* and owning thread */
#endif

	LEAF_RET

NONLEAF_ENTRY2(mutex_lock,_mutex_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	pushf				/* save interrupt state */
	cli				/* disable interrupts */
Lml_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Lml_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lml_ilk_fail		/* no - take the slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lml_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Lml_fail		/* yes, we lose */
Lml_acquire:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

#if	MACH_LDEBUG
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lml_waiters		/* yes, more work to do */
Lml_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

Lml_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Lml_return

Lml_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Lml_retry		/* try again */

Lml_fail:
	/*
	 n Check if the owner is on another processor and therefore
	 * we should try to spin before blocking.
	 */
	testl	$(OnProc),ACT_SPF(%ecx)
	jz	Lml_block

	/*
	 * Here if owner is on another processor:
	 *  - release the interlock
	 *  - spin on the holder until release or timeout
	 *  - in either case re-acquire the interlock
	 *  - if released, acquire it
	 *  - otherwise drop thru to block.
	 */
	xorl	%eax,%eax
	movl	%eax,M_ILK		/* zero interlock */
	popf
	pushf				/* restore interrupt state */

	push	%edx			/* lock address */
	call	EXT(lck_mtx_lock_spin)	/* call out to do spinning */
	addl	$4,%esp
	movl	B_ARG0,%edx		/* refetch mutex address */

	/* Re-acquire interlock */
	cli				/* disable interrupts */
Lml_reget_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Lml_reget_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lml_ilk_refail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lml_reget_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex free? */
	je	Lml_acquire		/* yes, acquire */
	
Lml_block:
	CHECK_MYLOCK(M_THREAD)
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	movl	B_ARG0,%edx		/* refetch mutex address */
	cli				/* ensure interrupts disabled */
	jmp	Lml_retry		/* and try again */

Lml_ilk_refail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Lml_reget_retry		/* try again */

NONLEAF_ENTRY2(mutex_try,_mutex_try)	

	movl	B_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()

	pushf				/* save interrupt state */
	cli				/* disable interrupts */
Lmt_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Lmt_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lmt_ilk_fail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lmt_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Lmt_fail		/* yes, we lose */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

#if	MACH_LDEBUG
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif

	cmpl	$0,M_WAITERS		/* are there any waiters? */
	jne	Lmt_waiters		/* yes, more work to do */
Lmt_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK
	popf				/* restore interrupt state */

	movl	$1,%eax

	NONLEAF_RET

Lmt_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Lmt_return

Lmt_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Lmt_retry		/* try again */

Lmt_fail:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	xorl	%eax,%eax

	NONLEAF_RET

NONLEAF_ENTRY(mutex_unlock)
	movl	B_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_THREAD(M_THREAD)

	pushf				/* save interrupt state */
	cli				/* disable interrupts */
Lmu_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Lmu_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lmu_ilk_fail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lmu_get_hw		/* branch on failure to retry */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lmu_wakeup		/* yes, more work to do */

Lmu_doit:

#if	MACH_LDEBUG
	movl	$0,M_THREAD		/* disown thread */
#endif

	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */

	movl	%ecx,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

Lmu_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Lmu_retry		/* try again */

Lmu_wakeup:
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	movl	B_ARG0,%edx		/* restore lock pointer */
	jmp	Lmu_doit

/*
 * lck_mtx_lock()
 * lck_mtx_try_lock()
 * lck_mutex_unlock()
 *
 * These are variants of mutex_lock(), mutex_try() and mutex_unlock() without
 * DEBUG checks (which require fields not present in lck_mtx_t's).
 */
NONLEAF_ENTRY(lck_mtx_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	cmpl	$(MUTEX_IND),M_ITAG	/* is this indirect? */
	cmove	M_PTR,%edx		/* yes - take indirection */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	pushf				/* save interrupt state */
	cli				/* disable interrupts */
Llml_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Llml_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llml_ilk_fail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llml_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llml_fail		/* yes, we lose */
Llml_acquire:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	cmpl	$0,M_WAITERS		/* are there any waiters? */
	jne	Llml_waiters		/* yes, more work to do */
Llml_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

Llml_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llml_return

Llml_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Llml_retry		/* try again */

Llml_fail:
	/*
	 * Check if the owner is on another processor and therefore
	 * we should try to spin before blocking.
	 */
	testl	$(OnProc),ACT_SPF(%ecx)
	jz	Llml_block

	/*
	 * Here if owner is on another processor:
	 *  - release the interlock
	 *  - spin on the holder until release or timeout
	 *  - in either case re-acquire the interlock
	 *  - if released, acquire it
	 *  - otherwise drop thru to block.
	 */
	xorl	%eax,%eax
	movl	%eax,M_ILK		/* zero interlock */
	popf
	pushf				/* restore interrupt state */

	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_spin)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	/* Re-acquire interlock */
	cli				/* disable interrupts */
Llml_reget_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Llml_reget_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llml_ilk_refail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llml_reget_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex free? */
	je	Llml_acquire		/* yes, acquire */
	
Llml_block:
	CHECK_MYLOCK(M_THREAD)
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	popl	%edx			/* restore mutex address */
	cli				/* ensure interrupts disabled */
	jmp	Llml_retry		/* and try again */

Llml_ilk_refail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Llml_reget_retry	/* try again */

NONLEAF_ENTRY(lck_mtx_try_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	cmpl	$(MUTEX_IND),M_ITAG	/* is this indirect? */
	cmove	M_PTR,%edx		/* yes - take indirection */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	pushf				/* save interrupt state */
	cli				/* disable interrupts */
Llmt_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Llmt_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmt_ilk_fail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llmt_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llmt_fail		/* yes, we lose */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	cmpl	$0,M_WAITERS		/* are there any waiters? */
	jne	Llmt_waiters		/* yes, more work to do */
Llmt_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	movl	$1,%eax			/* return success */
	NONLEAF_RET

Llmt_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llmt_return

Llmt_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Llmt_retry		/* try again */

Llmt_fail:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	xorl	%eax,%eax		/* return failure */
	NONLEAF_RET

NONLEAF_ENTRY(lck_mtx_unlock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	cmpl	$(MUTEX_IND),M_ITAG	/* is this indirect? */
	cmove	M_PTR,%edx		/* yes - take indirection */

	pushf				/* save interrupt state */
	cli				/* disable interrupts */
Llmu_retry:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

Llmu_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmu_ilk_fail		/* no - slow path */

	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llmu_get_hw		/* branch on failure to retry */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Llmu_wakeup		/* yes, more work to do */

Llmu_doit:
	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */

	movl	%ecx,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

Llmu_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	pushl	%edx			/* lock address */
	call	EXT(lck_mtx_interlock_spin)
	popl	%edx			/* lock pointer */
	jmp	Llmu_retry		/* try again */

Llmu_wakeup:
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	popl	%edx			/* restore mutex pointer */
	jmp	Llmu_doit

LEAF_ENTRY(lck_mtx_ilk_unlock)
	movl	L_ARG0,%edx		/* no indirection here */

	xorl	%eax,%eax
	movl	%eax,M_ILK

	LEAF_RET
	
LEAF_ENTRY(_disable_preemption)
#if	MACH_RT
	_DISABLE_PREEMPTION
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_enable_preemption)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
	pushl	%gs:CPU_PREEMPTION_LEVEL
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_enable_preemption: preemption_level(%d)  < 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_enable_preemption_no_check)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_enable_preemption_no_check: preemption_level <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION_NO_CHECK
#endif	/* MACH_RT */
	LEAF_RET
	
	
LEAF_ENTRY(_mp_disable_preemption)
#if	MACH_RT
	_DISABLE_PREEMPTION
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_mp_enable_preemption)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
	pushl	%gs:CPU_PREEMPTION_LEVEL
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_mp_enable_preemption: preemption_level (%d) <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_mp_enable_preemption_no_check)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_mp_enable_preemption_no_check: preemption_level <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION_NO_CHECK
#endif	/* MACH_RT */
	LEAF_RET
	
	
LEAF_ENTRY(i_bit_set)
	movl	L_ARG0,%edx
	movl	L_ARG1,%eax
	lock
	bts	%edx,(%eax)
	LEAF_RET

LEAF_ENTRY(i_bit_clear)
	movl	L_ARG0,%edx
	movl	L_ARG1,%eax
	lock
	btr	%edx,(%eax)
	LEAF_RET

LEAF_ENTRY(bit_lock)
	movl	L_ARG0,%ecx
	movl	L_ARG1,%eax
1:
	lock
	bts	%ecx,(%eax)
	jb	1b
	LEAF_RET

LEAF_ENTRY(bit_lock_try)
	movl	L_ARG0,%ecx
	movl	L_ARG1,%eax
	lock
	bts	%ecx,(%eax)
	jb	bit_lock_failed
	LEAF_RET		/* %eax better not be null ! */
bit_lock_failed:
	xorl	%eax,%eax
	LEAF_RET

LEAF_ENTRY(bit_unlock)
	movl	L_ARG0,%ecx
	movl	L_ARG1,%eax
	lock
	btr	%ecx,(%eax)
	LEAF_RET
