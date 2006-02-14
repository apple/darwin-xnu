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
#define	S_TYPE		SLOCK_TYPE(%edx)
#define	S_PC		SLOCK_PC(%edx)
#define	S_THREAD	SLOCK_THREAD(%edx)
#define	S_DURATIONH	SLOCK_DURATIONH(%edx)
#define	S_DURATIONL	SLOCK_DURATIONL(%edx)

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

#define	CHECK_SIMPLE_LOCK_TYPE()				\
	cmpl	$ USLOCK_TAG,S_TYPE 			;	\
	je	1f					;	\
	pushl	$2f					;	\
	call	EXT(panic)				;	\
	hlt						;	\
	.data						;	\
2:	String	"not a simple lock!"			;	\
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

	movl	L_PC,%ecx
1:	DISABLE_PREEMPTION
	movl	0(%edx), %eax
	testl	%eax,%eax		/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchgl	%ecx,0(%edx)	/* try to acquire the HW lock */
	jne	3f
	movl	$1,%eax			/* In case this was a timeout call */
	LEAF_RET			/* if yes, then nothing left to do */

3:	ENABLE_PREEMPTION		/* no reason we can't be preemptable */
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
	movl	L_PC,%ecx
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
3:
	ENABLE_PREEMPTION		/* no reason not to be preempted now */
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
	jb	5b			/* continue if less, else bail */
	xor	%eax,%eax		/* with 0 return value */
	pop	%ebx
	pop	%edi
	LEAF_RET

6:
	/*
	 * Here to try to grab the lock that now appears to be free
	 * after contention.
	 */
	movl	8+L_PC,%edx		/* calling pc (8+ for pushed regs) */
	DISABLE_PREEMPTION
	lock; cmpxchgl	%edx,0(%edi)	/* try to acquire the HW lock */
	jne	3b			/* no - spin again */
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

	movl	L_PC,%ecx
	DISABLE_PREEMPTION
	movl	0(%edx),%eax
	testl	%eax,%eax
	jne	1f
	lock; cmpxchgl	%ecx,0(%edx)	/* try to acquire the HW lock */
	jne	1f

	movl	$1,%eax			/* success */
	LEAF_RET

1:	ENABLE_PREEMPTION		/* failure:  release preemption... */
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

ml_retry:
	movl	B_PC,%ecx

ml_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	1f			/* yes - attempt to lock it */
	PAUSE				/* no  - pause */
	jmp	ml_get_hw		/* try again */
1:
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	ml_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	ml_fail			/* yes, we lose */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

#if	MACH_LDEBUG
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif

	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

ml_fail:
ml_block:
	CHECK_MYLOCK(M_THREAD)
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	movl	B_ARG0,%edx		/* refetch mutex address */
	jmp	ml_retry		/* and try again */

NONLEAF_ENTRY2(mutex_try,_mutex_try)	

	movl	B_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()

	movl	B_PC,%ecx

	pushf				/* save interrupt state */
	cli				/* disable interrupts */

mt_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	1f			/* yes - attempt to lock it */
	PAUSE				/* no  - pause */
	jmp	mt_get_hw		/* try again */
1:
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	mt_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	mt_fail			/* yes, we lose */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

#if	MACH_LDEBUG
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif

	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	movl	$1,%eax

	NONLEAF_RET

mt_fail:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	xorl	%eax,%eax

	NONLEAF_RET

NONLEAF_ENTRY(mutex_unlock)
	movl	B_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_THREAD(M_THREAD)

	movl	B_PC,%ecx

	pushf				/* save interrupt state */
	cli				/* disable interrupts */

mu_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	1f			/* yes - attempt to lock it */
	PAUSE				/* no  - pause */
	jmp	mu_get_hw		/* try again */
1:
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	mu_get_hw		/* branch on failure to retry */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	mu_wakeup		/* yes, more work to do */

mu_doit:

#if	MACH_LDEBUG
	movl	$0,M_THREAD		/* disown thread */
#endif

	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */

	movl	%ecx,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

mu_wakeup:
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	movl	B_ARG0,%edx		/* restore lock pointer */
	jmp	mu_doit

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

lml_retry:
	movl	B_PC,%ecx

lml_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	1f			/* yes - attempt to lock it */
	PAUSE				/* no  - pause */
	jmp	lml_get_hw		/* try again */
1:
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	lml_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	lml_fail		/* yes, we lose */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

lml_fail:
	CHECK_MYLOCK(M_THREAD)
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	popl	%edx			/* restore mutex address */
	jmp	lml_retry		/* and try again */

NONLEAF_ENTRY(lck_mtx_try_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	cmpl	$(MUTEX_IND),M_ITAG	/* is this indirect? */
	cmove	M_PTR,%edx		/* yes - take indirection */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	B_PC,%ecx

	pushf				/* save interrupt state */
	cli				/* disable interrupts */

lmt_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	1f			/* yes - attempt to lock it */
	PAUSE				/* no  - pause */
	jmp	lmt_get_hw		/* try again */
1:
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	lmt_get_hw		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	lmt_fail		/* yes, we lose */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	movl	$1,%eax			/* return success */
	NONLEAF_RET

lmt_fail:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	xorl	%eax,%eax		/* return failure */
	NONLEAF_RET

NONLEAF_ENTRY(lck_mtx_unlock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	cmpl	$(MUTEX_IND),M_ITAG	/* is this indirect? */
	cmove	M_PTR,%edx		/* yes - take indirection */

	movl	B_PC,%ecx

	pushf				/* save interrupt state */
	cli				/* disable interrupts */

lmu_get_hw:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	1f			/* yes - attempt to lock it */
	PAUSE				/* no  - pause */
	jmp	lmu_get_hw		/* try again */
1:
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	lmu_get_hw		/* branch on failure to retry */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	lmu_wakeup		/* yes, more work to do */

lmu_doit:
	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */

	movl	%ecx,M_ILK

	popf				/* restore interrupt state */

	NONLEAF_RET

lmu_wakeup:
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	popl	%edx			/* restore mutex pointer */
	jmp	lmu_doit

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
	bts	%dl,(%eax)
	LEAF_RET

LEAF_ENTRY(i_bit_clear)
	movl	L_ARG0,%edx
	movl	L_ARG1,%eax
	lock
	btr	%dl,(%eax)
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
