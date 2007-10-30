/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <i386/eflags.h>
#include <i386/trap.h>
#include <config_dtrace.h>

#include "assym.s"

#define	PAUSE		rep; nop

/*
 *	When performance isn't the only concern, it's
 *	nice to build stack frames...
 */
#define	BUILD_STACK_FRAMES   (GPROF || \
				((MACH_LDEBUG || ETAP_LOCK_TRACE) && MACH_KDB))

#if	BUILD_STACK_FRAMES

/* Stack-frame-relative: */
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


#define PREEMPTION_DISABLE				\
	incl	%gs:CPU_PREEMPTION_LEVEL
	
	
#define	PREEMPTION_ENABLE				\
	decl	%gs:CPU_PREEMPTION_LEVEL	;	\
	jne	9f				;	\
	pushf					;	\
	testl	$ EFL_IF,(%esp)			;	\
	je	8f				;	\
	cli					;	\
	movl	%gs:CPU_PENDING_AST,%eax	;	\
	testl	$ AST_URGENT,%eax		;	\
	je	8f				;	\
	movl	%gs:CPU_INTERRUPT_LEVEL,%eax	;	\
	testl	%eax,%eax			;	\
	jne	8f				;	\
	popf					;	\
	int	$(T_PREEMPT)			;	\
	jmp	9f				;	\
8:							\
	popf					;	\
9:	

	

#if	CONFIG_DTRACE
#define	LOCKSTAT_LABEL(lab) \
	.data				;\
	.globl	lab			;\
	lab:				;\
	.long 9f			;\
	.text				;\
	9:

	.globl	_lockstat_probe
	.globl	_lockstat_probemap

#define	LOCKSTAT_RECORD(id, lck) \
	push	%ebp					;	\
	mov	%esp,%ebp				;	\
	sub	$0x38,%esp	/* size of dtrace_probe args */ ; \
	movl	_lockstat_probemap + (id * 4),%eax	;	\
	test	%eax,%eax				;	\
	je	9f					;	\
	movl	$0,36(%esp)				;	\
	movl	$0,40(%esp)				;	\
	movl	$0,28(%esp)				;	\
	movl	$0,32(%esp)				;	\
	movl	$0,20(%esp)				;	\
	movl	$0,24(%esp)				;	\
	movl	$0,12(%esp)				;	\
	movl	$0,16(%esp)				;	\
	movl	lck,4(%esp)	/* copy lock pointer to arg 1 */ ; \
	movl	$0,8(%esp)				;	\
	movl	%eax,(%esp) 				; 	\
	call	*_lockstat_probe			;	\
9:	leave
	/* ret - left to subsequent code, e.g. return values */

#define	LOCKSTAT_RECORD2(id, lck, arg) \
	push	%ebp					;	\
	mov	%esp,%ebp				;	\
	sub	$0x38,%esp	/* size of dtrace_probe args */ ; \
	movl	_lockstat_probemap + (id * 4),%eax	;	\
	test	%eax,%eax				;	\
	je	9f					;	\
	movl	$0,36(%esp)				;	\
	movl	$0,40(%esp)				;	\
	movl	$0,28(%esp)				;	\
	movl	$0,32(%esp)				;	\
	movl	$0,20(%esp)				;	\
	movl	$0,24(%esp)				;	\
	movl	$0,12(%esp)				;	\
	movl	$0,16(%esp)				;	\
	movl	lck,4(%esp)	/* copy lock pointer to arg 1 */ ; \
	movl	arg,8(%esp)				;	\
	movl	%eax,(%esp) 				; 	\
	call	*_lockstat_probe			;	\
9:	leave
	/* ret - left to subsequent code, e.g. return values */
#endif


/*
 *	void hw_lock_init(hw_lock_t)
 *
 *	Initialize a hardware lock.
 */
LEAF_ENTRY(hw_lock_init)
	movl	L_ARG0,%edx		/* fetch lock pointer */
	movl	$0,(%edx)		/* clear the lock */
	LEAF_RET


/*
 *	void hw_lock_byte_init(uint8_t *)
 *
 *	Initialize a hardware byte lock.
 */
LEAF_ENTRY(hw_lock_byte_init)
	movl	L_ARG0,%edx		/* fetch lock pointer */
	movb	$0,(%edx)		/* clear the lock */
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
	PREEMPTION_DISABLE
1:
	movl	(%edx), %eax
	testl	%eax,%eax		/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchgl	%ecx,(%edx)	/* try to acquire the HW lock */
	jne	3f
	movl	$1,%eax			/* In case this was a timeout call */
	LEAF_RET			/* if yes, then nothing left to do */
3:
	PAUSE				/* pause for hyper-threading */
	jmp	1b			/* try again */

/*
 *	void	hw_lock_byte_lock(uint8_t *lock_byte)
 *
 *	Acquire byte sized lock operand, spinning until it becomes available.
 *	MACH_RT:  also return with preemption disabled.
 */

LEAF_ENTRY(hw_lock_byte_lock)
	movl	L_ARG0,%edx		/* Load lock pointer */
	PREEMPTION_DISABLE
	movl	$1, %ecx		/* Set lock value */
1:
	movb	(%edx), %al		/* Load byte at address */
	testb	%al,%al			/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchgb	%cl,(%edx)	/* attempt atomic compare exchange */
	jne	3f
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
	PREEMPTION_DISABLE
	movl	(%edx), %eax
	testl	%eax,%eax		/* lock locked? */
	jne	2f			/* branch if so */
	lock; cmpxchgl	%ecx,(%edx)	/* try to acquire the HW lock */
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
	movl	(%edi),%eax		/* spin checking lock value in cache */
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
	lock; cmpxchgl	%edx,(%edi)	/* try to acquire the HW lock */
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
	movl	$0,(%edx)		/* clear the lock */
	PREEMPTION_ENABLE
	LEAF_RET
/*
 *	void hw_lock_byte_unlock(uint8_t *lock_byte)
 *
 *	Unconditionally release byte sized lock operand.
 *	MACH_RT:  release preemption level.
 */

LEAF_ENTRY(hw_lock_byte_unlock)
	movl	L_ARG0,%edx		/* Load lock pointer */
	movb	$0,(%edx)		/* Clear the lock byte */
	PREEMPTION_ENABLE
	LEAF_RET
	
/*
 *	void i386_lock_unlock_with_flush(hw_lock_t)
 *
 *	Unconditionally release lock, followed by a cacheline flush of
 *	the line corresponding to the lock dword. This routine is currently
 *	used with certain locks which are susceptible to lock starvation,
 *	minimizing cache affinity for lock acquisitions. A queued spinlock
 *	or other mechanism that ensures fairness would obviate the need
 *	for this routine, but ideally few or no spinlocks should exhibit
 *	enough contention to require such measures.
 *	MACH_RT:  release preemption level.
 */
LEAF_ENTRY(i386_lock_unlock_with_flush)
	movl	L_ARG0,%edx		/* Fetch lock pointer */
	movl	$0,(%edx)		/* Clear the lock */
	mfence				/* Serialize prior stores */
	clflush	(%edx)			/* Write back and invalidate line */
	PREEMPTION_ENABLE
	LEAF_RET

/*
 *	unsigned int hw_lock_try(hw_lock_t)
 *	MACH_RT:  returns with preemption disabled on success.
 */
LEAF_ENTRY(hw_lock_try)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	PREEMPTION_DISABLE
	movl	(%edx),%eax
	testl	%eax,%eax
	jne	1f
	lock; cmpxchgl	%ecx,(%edx)	/* try to acquire the HW lock */
	jne	1f

	movl	$1,%eax			/* success */
	LEAF_RET

1:
	PREEMPTION_ENABLE		/* failure:  release preemption... */
	xorl	%eax,%eax		/* ...and return failure */
	LEAF_RET

/*
 *	unsigned int hw_lock_held(hw_lock_t)
 *	MACH_RT:  doesn't change preemption state.
 *	N.B.  Racy, of course.
 */
LEAF_ENTRY(hw_lock_held)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movl	(%edx),%eax		/* check lock value */
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

/*
 * Reader-writer lock fastpaths. These currently exist for the
 * shared lock acquire and release paths (where they reduce overhead
 * considerably)--more can be added as necessary (DRK).
 */

/*
 * These should reflect the layout of the bitfield embedded within
 * the lck_rw_t structure (see i386/locks.h).
 */
#define LCK_RW_INTERLOCK 0x1
#define LCK_RW_WANT_UPGRADE 0x2
#define LCK_RW_WANT_WRITE 0x4
#define LCK_R_WAITING 0x8
#define LCK_W_WAITING 0x10

#define	RW_LOCK_SHARED_MASK ((LCK_RW_INTERLOCK<<16) |	\
	((LCK_RW_WANT_UPGRADE|LCK_RW_WANT_WRITE) << 24))
/*
 *		void lck_rw_lock_shared(lck_rw_t*)
 *
 */

Entry(lck_rw_lock_shared)
	movl	S_ARG0, %edx
1:
	movl	(%edx), %eax		/* Load state bitfield and interlock */
	testl	$(RW_LOCK_SHARED_MASK), %eax	/* Eligible for fastpath? */
	jne	3f
	movl	%eax, %ecx
	incl	%ecx				/* Increment reader refcount */
	lock
	cmpxchgl %ecx, (%edx)			/* Attempt atomic exchange */
	jne	2f

#if	CONFIG_DTRACE
	/*
	 * Dtrace lockstat event: LS_LCK_RW_LOCK_SHARED_ACQUIRE
	 * Implemented by swapping between return and no-op instructions.
	 * See bsd/dev/dtrace/lockstat.c.
	 */
	LOCKSTAT_LABEL(_lck_rw_lock_shared_lockstat_patch_point)
	ret
	/* Fall thru when patched, counting on lock pointer in %edx  */
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, %edx)
#endif
	ret

2:
	PAUSE
	jmp	1b
3:
	jmp	EXT(lck_rw_lock_shared_gen)


/*
 *		lck_rw_type_t lck_rw_done(lck_rw_t*)
 *
 */

.data
rwl_release_error_str:
	.asciz	"Releasing non-exclusive RW lock without a reader refcount!"
.text

#define RW_LOCK_RELEASE_MASK ((LCK_RW_INTERLOCK<<16) |	\
	((LCK_RW_WANT_UPGRADE|LCK_RW_WANT_WRITE|LCK_R_WAITING|LCK_W_WAITING) << 24))
Entry(lck_rw_done)
	movl	S_ARG0,	%edx
1:
	movl	(%edx), %eax		/* Load state bitfield and interlock */
	testl	$(RW_LOCK_RELEASE_MASK), %eax	/* Eligible for fastpath? */
	jne	3f
	movl	%eax, %ecx
	/* Assert refcount */
	testl	$(0xFFFF), %ecx
	jne	5f
	movl	$(rwl_release_error_str), S_ARG0
	jmp	EXT(panic)
5:
	decl	%ecx			/* Decrement reader count */
	lock
	cmpxchgl %ecx, (%edx)
	jne	2f
	movl	$(RW_SHARED), %eax	/* Indicate that the lock was shared */
#if	CONFIG_DTRACE
	/* Dtrace lockstat probe: LS_RW_DONE_RELEASE as reader */
	LOCKSTAT_LABEL(_lck_rw_done_lockstat_patch_point)
	ret
	/*
	 * Note: Dtrace's convention is 0 ==> reader, which is
	 * a different absolute value than $(RW_SHARED)
	 * %edx contains the lock address already from the above
	 */
	LOCKSTAT_RECORD2(LS_LCK_RW_DONE_RELEASE, %edx, $0)
	movl	$(RW_SHARED), %eax	/* Indicate that the lock was shared */
#endif
	ret

2:
	PAUSE
	jmp	1b
3:
	jmp	EXT(lck_rw_done_gen)


NONLEAF_ENTRY2(mutex_lock_spin,_mutex_lock_spin)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lmls_ilk_loop		/* no, go spin */
Lmls_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lmls_ilk_fail		/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Lml_fail		/* yes, fall back to a normal mutex lock */
	movl	$(MUTEX_LOCKED_AS_SPIN),M_LOCKED	/* indicate ownership as a spin lock */
	
#if	MACH_LDEBUG
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif
	PREEMPTION_DISABLE
	popf				/* restore interrupt state */
	leave				/* return with the interlock held */
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_lock_spin_lockstat_patch_point)
	ret
	/* %edx contains the lock address from above */
	LOCKSTAT_RECORD(LS_MUTEX_LOCK_SPIN_ACQUIRE, %edx)
#endif
	ret
	
Lmls_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Lmls_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Lmls_retry		/* yes, go for it */
	jmp	Lmls_ilk_loop		/* no, keep spinning */


NONLEAF_ENTRY2(mutex_lock,_mutex_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	M_ILK,%eax		/* is interlock held */
	testl	%eax,%eax
	jne	Lml_ilk_loop		/* yes, go do the spin loop */
Lml_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lml_ilk_fail		/* branch on failure to spin loop */

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
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_lock_lockstat_patch_point)
	ret
	/* %edx still contains the lock pointer */
	LOCKSTAT_RECORD(LS_MUTEX_LOCK_ACQUIRE, %edx)
#endif
	ret

	/*
	 * We got the mutex, but there are waiters.  Update information
	 * on waiters.
	 */
Lml_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Lml_return

Lml_restart:
Lml_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Lml_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Lml_retry		/* yes, go try to grab it */
	jmp	Lml_ilk_loop		/* no - keep spinning */

Lml_fail:
	/*
	 * Check if the owner is on another processor and therefore
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
	call	EXT(lck_mtx_lock_spinwait)	/* call out to do spinning */
	addl	$4,%esp
	movl	B_ARG0,%edx		/* refetch mutex address */

	/* Re-acquire interlock - interrupts currently enabled */
	movl	M_ILK,%eax		/* is interlock held */
	testl	%eax,%eax
	jne	Lml_ilk_reloop		/* yes, go do the spin loop */
Lml_reget_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lml_ilk_refail		/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex free? */
	je	Lml_acquire		/* yes, acquire */
	
Lml_block:
	CHECK_MYLOCK(M_THREAD)
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp			/* returns with interlock dropped */
	movl	B_ARG0,%edx		/* refetch mutex address */
	jmp	Lml_restart		/* and start over */

Lml_ilk_refail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Lml_ilk_reloop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Lml_reget_retry		/* yes, go try to grab it */
	jmp	Lml_ilk_reloop		/* no - keep spinning */

	

NONLEAF_ENTRY2(mutex_try_spin,_mutex_try_spin)	

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()

	movl	M_ILK,%eax
	testl	%eax,%eax		/* is the interlock held? */
	jne	Lmts_ilk_loop		/* yes, go to spin loop */
Lmts_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lmts_ilk_fail		/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Lmt_fail		/* yes, we lose */
Lmts_acquire:
	movl	$(MUTEX_LOCKED_AS_SPIN),M_LOCKED	/* indicate ownership as a spin lock */

#if	MACH_LDEBUG
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif
	PREEMPTION_DISABLE		/* no, return with interlock held */
	popf				/* restore interrupt state */
	movl	$1,%eax
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_try_spin_lockstat_patch_point)
	ret
	/* %edx inherits the lock pointer from above */
	LOCKSTAT_RECORD(LS_MUTEX_TRY_SPIN_ACQUIRE, %edx)
	movl	$1,%eax
#endif
	ret

Lmts_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Lmts_ilk_loop:
	PAUSE
	/*
	 * need to do this check outside of the interlock in
	 * case this lock is held as a simple lock which means
	 * we won't be able to take the interlock
 	 */
	movl	M_LOCKED,%eax
	testl	%eax,%eax		/* is the mutex locked? */
	jne	Lmt_fail_no_ilk		/* yes, go return failure */

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Lmts_retry		/* yes, go try to grab it */
	jmp	Lmts_ilk_loop		/* keep spinning */



NONLEAF_ENTRY2(mutex_try,_mutex_try)	

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lmt_ilk_loop		/* yes, go try to grab it */
Lmt_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lmt_ilk_fail		/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Lmt_fail		/* yes, we lose */
Lmt_acquire:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

#if	MACH_LDEBUG
	movl	%ecx,M_THREAD
	movl	B_PC,%ecx
	movl	%ecx,M_PC
#endif
	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lmt_waiters		/* yes, more work to do */
Lmt_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK
	popf				/* restore interrupt state */

	movl	$1,%eax
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_try_lockstat_patch_point)
	ret
	/* inherit the lock pointer in %edx from above */
	LOCKSTAT_RECORD(LS_MUTEX_TRY_LOCK_ACQUIRE, %edx)
	movl	$1,%eax
#endif
	ret

Lmt_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Lmt_return

Lmt_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Lmt_ilk_loop:
	PAUSE
	/*
	 * need to do this check outside of the interlock in
	 * case this lock is held as a simple lock which means
	 * we won't be able to take the interlock
 	 */
	movl	M_LOCKED,%eax		/* get lock owner */
	testl	%eax,%eax		/* is the mutex locked? */
	jne	Lmt_fail_no_ilk		/* yes, go return failure */

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Lmt_retry		/* yes, go try to grab it */
	jmp	Lmt_ilk_loop		/* no - keep spinning */

Lmt_fail:
	xorl	%eax,%eax
	movl	%eax,M_ILK

Lmt_fail_no_ilk:
	xorl	%eax,%eax
	popf				/* restore interrupt state */
	NONLEAF_RET



LEAF_ENTRY(mutex_convert_spin)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movl	M_LOCKED,%ecx		/* is this the spin variant of the mutex */
	cmpl	$(MUTEX_LOCKED_AS_SPIN),%ecx
	jne	Lmcs_exit		/* already owned as a mutex, just return */

	movl	M_ILK,%ecx		/* convert from spin version to mutex */
	movl	%ecx,M_LOCKED		/* take control of the mutex */
	
	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lmcs_waiters		/* yes, more work to do */

Lmcs_return:
	xorl	%ecx,%ecx
	movl	%ecx,M_ILK		/* clear interlock */
	PREEMPTION_ENABLE
Lmcs_exit:
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_convert_spin_lockstat_patch_point)
	ret
	/* inherit %edx from above */
	LOCKSTAT_RECORD(LS_MUTEX_CONVERT_SPIN_ACQUIRE, %edx)
#endif
	ret


Lmcs_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Lmcs_return

	

NONLEAF_ENTRY(mutex_unlock)
	movl	B_ARG0,%edx		/* fetch lock pointer */

	movl	M_LOCKED,%ecx		/* is this the spin variant of the mutex */
	cmpl	$(MUTEX_LOCKED_AS_SPIN),%ecx
	jne	Lmu_enter		/* no, go treat like a real mutex */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lmus_wakeup		/* yes, more work to do */

Lmus_drop_ilk:	
	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* yes, clear the spin indicator */
	movl	%ecx,M_ILK		/* release the interlock */
	PREEMPTION_ENABLE		/* and re-enable preemption */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx from above */
	LOCKSTAT_RECORD(LS_MUTEX_UNLOCK_RELEASE, %edx)
#endif
	ret

Lmus_wakeup:
	pushl	%edx			/* save mutex address */
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlockspin_wakeup)	/* yes, wake a thread */
	addl	$4,%esp
	popl	%edx			/* restore mutex pointer */
	jmp	Lmus_drop_ilk

Lmu_enter:
	pushf				/* save interrupt state */

	CHECK_MUTEX_TYPE()
	CHECK_THREAD(M_THREAD)

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Lmu_ilk_loop		/* yes, go try to grab it */
Lmu_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Lmu_ilk_fail		/* branch on failure to spin loop */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lmu_wakeup		/* yes, more work to do */

Lmu_doit:
#if	MACH_LDEBUG
	movl	$0,M_THREAD		/* disown thread */
#endif
	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */
	movl	%ecx,M_ILK		/* release the interlock */
	popf				/* restore interrupt state */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_mutex_unlock2_lockstat_patch_point)
	ret
	/* inherit %edx from above */
	LOCKSTAT_RECORD(LS_MUTEX_UNLOCK_RELEASE, %edx)
#endif
	ret

Lmu_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Lmu_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Lmu_retry		/* yes, go try to grab it */
	jmp	Lmu_ilk_loop		/* no - keep spinning */

Lmu_wakeup:
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	movl	B_ARG0,%edx		/* restore lock pointer */
	jmp	Lmu_doit

/*
 *	void lck_mtx_assert(lck_mtx_t* l, unsigned int)
 *	void _mutex_assert(mutex_t, unsigned int)
 *	Takes the address of a lock, and an assertion type as parameters.
 *	The assertion can take one of two forms determine by the type
 *	parameter: either the lock is held by the current thread, and the
 *	type is	LCK_MTX_ASSERT_OWNED, or it isn't and the type is
 *	LCK_MTX_ASSERT_NOT_OWNED. Calls panic on assertion failure.
 *	
 */

Entry(lck_mtx_assert)
Entry(_mutex_assert)
	movl	S_ARG0,%edx			/* Load lock address */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* Load current thread */

	cmpl	$(MUTEX_IND),M_ITAG		/* Is this an indirect mutex? */
	cmove	M_PTR,%edx			/* If so, take indirection */

	movl	M_LOCKED,%eax			/* Load lock word */
	cmpl	$(MUTEX_LOCKED_AS_SPIN),%eax	/* check for spin variant */
	cmove	M_ILK,%eax			/* yes, spin lock owner is in the interlock */

	cmpl	$(MUTEX_ASSERT_OWNED),S_ARG1	/* Determine assert type */
	jne	2f				/* Assert ownership? */
	cmpl	%eax,%ecx			/* Current thread match? */
	jne	3f				/* no, go panic */
1:						/* yes, we own it */
	ret					/* just return */
2:
	cmpl	%eax,%ecx			/* Current thread match? */
	jne	1b				/* No, return */
	movl	%edx,S_ARG1			/* Prep assertion failure */
	movl	$(mutex_assert_owned_str),S_ARG0
	jmp	4f
3:
	movl	%edx,S_ARG1			/* Prep assertion failure */
	movl	$(mutex_assert_not_owned_str),S_ARG0
4:
	jmp	EXT(panic)

.data
mutex_assert_not_owned_str:
	.asciz	"mutex (%p) not owned\n"
mutex_assert_owned_str:
	.asciz	"mutex (%p) owned\n"
.text

/* This preprocessor define controls whether the R-M-W update of the
 * per-group statistics elements are atomic (LOCK-prefixed)
 * Enabled by default.
 */
#define ATOMIC_STAT_UPDATES 1

#if defined(ATOMIC_STAT_UPDATES)
#define LOCK_IF_ATOMIC_STAT_UPDATES lock
#else
#define LOCK_IF_ATOMIC_STAT_UPDATES
#endif /* ATOMIC_STAT_UPDATES */


/*
 * lck_mtx_lock()
 * lck_mtx_try_lock()
 * lck_mutex_unlock()
 * lck_mtx_lock_spin()
 * lck_mtx_convert_spin()
 *
 * These are variants of mutex_lock(), mutex_try(), mutex_unlock()
 * mutex_lock_spin and mutex_convert_spin without
 * DEBUG checks (which require fields not present in lck_mtx_t's).
 */

NONLEAF_ENTRY(lck_mtx_lock_spin)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmls_eval_ilk		/* no, go see if indirect */
Llmls_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llmls_ilk_fail		/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llml_fail		/* yes, fall back to a normal mutex */

Llmls_acquire:	
	movl	$(MUTEX_LOCKED_AS_SPIN),M_LOCKED	/* indicate ownership as a spin lock */
	PREEMPTION_DISABLE
	popf				/* restore interrupt state */
	NONLEAF_RET			/* return with the interlock held */

Llmls_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Llmls_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llmls_retry		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llmls_ilk_loop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llmls_ilk_loop


Llmls_eval_ilk:
	cmpl	$(MUTEX_IND),M_ITAG	/* Is this an indirect mutex? */
	cmove	M_PTR,%edx		/* If so, take indirection */
	jne	Llmls_ilk_loop		/* If not, go to spin loop */

Llmls_lck_ext:
	pushl	%esi			/* Used to hold the lock group ptr */
	pushl	%edi			/* Used for stat update records */
	movl	MUTEX_GRP(%edx),%esi	/* Load lock group */
	xorl	%edi,%edi		/* Clear stat update records */
	/* 64-bit increment of acquire attempt statistic (per-group) */
	LOCK_IF_ATOMIC_STAT_UPDATES
	addl	$1, GRP_MTX_STAT_UTIL(%esi)
	jnc	1f
	incl	GRP_MTX_STAT_UTIL+4(%esi)
1:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmls_ext_ilk_loop	/* no, go to spin loop */
Llmls_ext_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl %ecx,M_ILK	/* atomic compare and exchange */
	jne     Llmls_ext_ilk_fail	/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl   %ecx,%ecx		/* is the mutex locked? */
	jne	Llml_ext_fail		/* yes, we lose */

	popl	%edi
	popl	%esi
	jmp	Llmls_acquire

Llmls_ext_ilk_fail:
	/*
	 * Slow path: call out to do the spinning.
	 */
	movl	8(%esp),%ecx
	pushl	%ecx
	popf				/* restore interrupt state */
	
Llmls_ext_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llmls_ext_retry		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llmls_ext_ilk_loop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llmls_ext_ilk_loop	/* no - keep spinning  */

	

NONLEAF_ENTRY(lck_mtx_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llml_eval_ilk		/* no, go see if indirect */
Llml_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llml_ilk_fail		/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llml_fail		/* yes, we lose */
Llml_acquire:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Lml_waiters		/* yes, more work to do */
Llml_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, %edx)
#endif
	ret

Llml_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llml_return

Llml_restart:
Llml_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Llml_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llml_retry		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llml_ilk_loop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llml_ilk_loop		/* no - keep spinning  */

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
	call	EXT(lck_mtx_lock_spinwait)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	/* Re-acquire interlock */
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llml_ilk_refail		/* no, go to spin loop */
Llml_reget_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llml_ilk_refail		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex free? */
	je	Llml_acquire		/* yes, acquire */
	
Llml_block:
	CHECK_MYLOCK(M_THREAD)
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	/*
	 * N.B.: lck_mtx_lock_wait is called here with interrupts disabled
	 * Consider reworking.
	 */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llml_restart		/* and start over */

Llml_ilk_refail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state on stack */

Llml_ilk_reloop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llml_reget_retry	/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llml_ilk_reloop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llml_ilk_reloop		/* no - keep spinning  */


Llml_eval_ilk:
	cmpl	$(MUTEX_IND),M_ITAG	/* Is this an indirect mutex? */
	cmove	M_PTR,%edx		/* If so, take indirection */
	jne	Llml_ilk_loop		/* If not, go to spin loop */

/*
 * Entry into statistics codepath for lck_mtx_lock:
 * EDX: real lock pointer
 * first dword on stack contains flags
 */

/* Enable this preprocessor define to record the first miss alone
 * By default, we count every miss, hence multiple misses may be
 * recorded for a single lock acquire attempt via lck_mtx_lock
 */
#undef LOG_FIRST_MISS_ALONE	

/*
 * N.B.: On x86, statistics are currently recorded for all indirect mutexes.
 * Also, only the acquire attempt count (GRP_MTX_STAT_UTIL) is maintained
 * as a 64-bit quantity (this matches the existing PowerPC implementation,
 * and the new x86 specific statistics are also maintained as 32-bit
 * quantities).
 */
	
Llml_lck_ext:
	pushl	%esi			/* Used to hold the lock group ptr */
	pushl	%edi			/* Used for stat update records */
	movl	MUTEX_GRP(%edx),%esi	/* Load lock group */
	xorl	%edi,%edi		/* Clear stat update records */
	/* 64-bit increment of acquire attempt statistic (per-group) */
	LOCK_IF_ATOMIC_STAT_UPDATES
	addl	$1, GRP_MTX_STAT_UTIL(%esi)
	jnc	1f
	incl	GRP_MTX_STAT_UTIL+4(%esi)
1:
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llml_ext_ilk_loop	/* no, go to spin loop */
Llml_ext_get_hw:
	cli
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl %ecx,M_ILK	/* atomic compare and exchange */
	jne	Llml_ext_ilk_fail	/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llml_ext_fail		/* yes, we lose */

Llml_ext_acquire:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Llml_ext_waiters	/* yes, more work to do */
Llml_ext_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popl	%edi
	popl	%esi
	popf				/* restore interrupt state */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_ext_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_ACQUIRE, %edx)
#endif
	ret

Llml_ext_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llml_ext_return

Llml_ext_restart:
Llml_ext_ilk_fail:
	movl	8(%esp),%ecx
	pushl	%ecx
	popf				/* restore interrupt state */

Llml_ext_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llml_ext_get_hw		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llml_ext_ilk_loop	/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llml_ext_ilk_loop


Llml_ext_fail:
#ifdef LOG_FIRST_MISS_ALONE
	testl	$1, %edi
	jnz	1f
#endif /* LOG_FIRST_MISS_ALONE */
	/* Record that a lock acquire attempt missed (per-group statistic) */
	LOCK_IF_ATOMIC_STAT_UPDATES
	incl	GRP_MTX_STAT_MISS(%esi)
#ifdef LOG_FIRST_MISS_ALONE
	orl	$1, %edi
#endif /* LOG_FIRST_MISS_ALONE */
1:
	/*
	 * Check if the owner is on another processor and therefore
	 * we should try to spin before blocking.
	 */
	testl	$(OnProc),ACT_SPF(%ecx)
	jnz	2f
	/*
	 * Record the "direct wait" statistic, which indicates if a
	 * miss proceeded to block directly without spinning--occurs
	 * if the owner of the mutex isn't running on another processor
	 * at the time of the check.
	 */
	LOCK_IF_ATOMIC_STAT_UPDATES
	incl	GRP_MTX_STAT_DIRECT_WAIT(%esi)
	jmp	Llml_ext_block
2:
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

	pushl	8(%esp)			/* Make another copy of EFLAGS image */
	popf				/* Restore interrupt state */
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_spinwait)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */

	/* Re-acquire interlock */
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llml_ext_ilk_refail	/* no, go to spin loop */
Llml_ext_reget_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl %ecx,M_ILK	/* atomic compare and exchange */
	jne	Llml_ext_ilk_refail	/* branch on failure to spin loop */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex free? */
	je	Llml_ext_acquire	/* yes, acquire */
	
Llml_ext_block:
	/* If we wanted to count waits just once per lock acquire, we'd
	 * skip over the stat update here
	 */
	LOCK_IF_ATOMIC_STAT_UPDATES
	/* Record that a lock miss proceeded to block */
	incl	GRP_MTX_STAT_WAIT(%esi) 
1:
	CHECK_MYLOCK(M_THREAD)
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	/*
	 * N.B.: lck_mtx_lock_wait is called here with interrupts disabled
	 * Consider reworking.
	 */
	call	EXT(lck_mtx_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llml_ext_restart	/* and start over */

Llml_ext_ilk_refail:
	movl	8(%esp),%ecx
	pushl	%ecx
	popf				/* restore interrupt state */
	
Llml_ext_ilk_reloop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llml_ext_reget_retry	/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llml_ext_ilk_reloop	/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llml_ext_ilk_reloop

	

NONLEAF_ENTRY(lck_mtx_try_lock_spin)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmts_eval_ilk		/* no, go see if indirect */
Llmts_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llmts_ilk_fail		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llmt_fail		/* yes, we lose */

	movl	$(MUTEX_LOCKED_AS_SPIN),M_LOCKED	/* no, indicate ownership as a spin lock */
	PREEMPTION_DISABLE		/* and return with interlock held */

	movl	$1,%eax			/* return success */
	popf				/* restore interrupt state */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_try_lock_spin_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, %edx)
	movl	$1,%eax			/* return success */
#endif
	ret

Llmts_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state */
	
Llmts_ilk_loop:
	PAUSE
	/*
	 * need to do this check outside of the interlock in
	 * case this lock is held as a simple lock which means
	 * we won't be able to take the interlock
 	 */
	movl	M_LOCKED,%eax		/* get lock owner */
	testl	%eax,%eax		/* is the mutex locked? */
	jne	Llmt_fail_no_ilk	/* yes, go return failure */

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llmts_retry		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llmts_ilk_loop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llmts_ilk_loop

Llmts_eval_ilk:
	cmpl	$(MUTEX_IND),M_ITAG	/* Is this an indirect mutex? */
	cmove	M_PTR,%edx		/* If so, take indirection */
	jne	Llmts_ilk_loop		/* If not, go to spin loop */

	/*
	 * bump counter on indirect lock
	 */
	pushl	%esi			/* Used to hold the lock group ptr */
	movl	MUTEX_GRP(%edx),%esi	/* Load lock group */
	/* 64-bit increment of acquire attempt statistic (per-group) */
	LOCK_IF_ATOMIC_STAT_UPDATES
	addl	$1, GRP_MTX_STAT_UTIL(%esi)
	jnc	1f
	incl	GRP_MTX_STAT_UTIL+4(%esi)
1:
	popl	%esi
	jmp	Llmts_ilk_loop


	
NONLEAF_ENTRY(lck_mtx_try_lock)

	movl	B_ARG0,%edx		/* fetch lock pointer */
	pushf				/* save interrupt state */

	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmt_eval_ilk		/* no, go see if indirect */
Llmt_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llmt_ilk_fail		/* branch on failure to retry */

	movl	M_LOCKED,%ecx		/* get lock owner */
	testl	%ecx,%ecx		/* is the mutex locked? */
	jne	Llmt_fail		/* yes, we lose */
Llmt_acquire:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	%ecx,M_LOCKED

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Llmt_waiters		/* yes, more work to do */
Llmt_return:
	xorl	%eax,%eax
	movl	%eax,M_ILK

	popf				/* restore interrupt state */

	movl	$1,%eax			/* return success */
	leave
#if	CONFIG_DTRACE
	/* Dtrace probe: LS_LCK_MTX_TRY_LOCK_ACQUIRE */
	LOCKSTAT_LABEL(_lck_mtx_try_lock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_ACQUIRE, %edx)
	movl	$1,%eax			/* return success */
#endif
	ret

Llmt_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llmt_return

Llmt_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state */
	
Llmt_ilk_loop:
	PAUSE
	/*
	 * need to do this check outside of the interlock in
	 * case this lock is held as a simple lock which means
	 * we won't be able to take the interlock
 	 */
	movl	M_LOCKED,%eax		/* get lock owner */
	testl	%eax,%eax		/* is the mutex locked? */
	jne	Llmt_fail_no_ilk	/* yes, go return failure */

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llmt_retry		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llmt_ilk_loop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llmt_ilk_loop

Llmt_fail:
	xorl	%eax,%eax		/* Zero interlock value */
	movl	%eax,M_ILK

Llmt_fail_no_ilk:
	popf				/* restore interrupt state */

	cmpl	%edx,B_ARG0
	jne	Llmt_fail_indirect

	xorl	%eax,%eax
	/* Note that we don't record a dtrace event for trying and missing */
	NONLEAF_RET

Llmt_fail_indirect:	
	pushl	%esi			/* Used to hold the lock group ptr */
	movl	MUTEX_GRP(%edx),%esi	/* Load lock group */

	/* Record mutex acquire attempt miss statistic */
	LOCK_IF_ATOMIC_STAT_UPDATES
	incl	GRP_MTX_STAT_MISS(%esi)

	popl	%esi
	xorl	%eax,%eax
	NONLEAF_RET

Llmt_eval_ilk:
	cmpl	$(MUTEX_IND),M_ITAG	/* Is this an indirect mutex? */
	cmove	M_PTR,%edx		/* If so, take indirection */
	jne	Llmt_ilk_loop		/* If not, go to spin loop */

	/*
	 * bump counter for indirect lock
  	 */
	pushl	%esi			/* Used to hold the lock group ptr */
	movl	MUTEX_GRP(%edx),%esi	/* Load lock group */

	/* 64-bit increment of acquire attempt statistic (per-group) */
	LOCK_IF_ATOMIC_STAT_UPDATES
	addl	$1, GRP_MTX_STAT_UTIL(%esi)
	jnc	1f
	incl	GRP_MTX_STAT_UTIL+4(%esi)
1:
	pop	%esi
	jmp	Llmt_ilk_loop



LEAF_ENTRY(lck_mtx_convert_spin)
	movl	L_ARG0,%edx		/* fetch lock pointer */

	cmpl	$(MUTEX_IND),M_ITAG	/* Is this an indirect mutex? */
	cmove	M_PTR,%edx		/* If so, take indirection */

	movl	M_LOCKED,%ecx		/* is this the spin variant of the mutex */
	cmpl	$(MUTEX_LOCKED_AS_SPIN),%ecx
	jne	Llmcs_exit		/* already owned as a mutex, just return */

	movl	M_ILK,%ecx		/* convert from spin version to mutex */
	movl	%ecx,M_LOCKED		/* take control of the mutex */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Llmcs_waiters		/* yes, more work to do */

Llmcs_return:
	xorl	%ecx,%ecx
	movl	%ecx,M_ILK		/* clear interlock */
	PREEMPTION_ENABLE
Llmcs_exit:
	LEAF_RET

Llmcs_waiters:
	pushl	%edx			/* save mutex address */
	pushl	%edx
	call	EXT(lck_mtx_lock_acquire)
	addl	$4,%esp
	popl	%edx			/* restore mutex address */
	jmp	Llmcs_return
	
	

NONLEAF_ENTRY(lck_mtx_unlock)

	movl	B_ARG0,%edx		/* fetch lock pointer */

	cmpl	$(MUTEX_IND),M_ITAG	/* Is this an indirect mutex? */
	cmove	M_PTR,%edx		/* If so, take indirection */

	movl	M_LOCKED,%ecx		/* is this the spin variant of the mutex */
	cmpl	$(MUTEX_LOCKED_AS_SPIN),%ecx
	jne	Llmu_enter		/* no, go treat like a real mutex */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Llmus_wakeup		/* yes, more work to do */

Llmu_drop_ilk:
	xorl	%eax,%eax
	movl	%eax,M_LOCKED		/* clear spin indicator */
	movl	%eax,M_ILK		/* release the interlock */

	PREEMPTION_ENABLE		/* and re-enable preemption */
	leave
#if	CONFIG_DTRACE
	/* Dtrace: LS_LCK_MTX_UNLOCK_RELEASE */
	LOCKSTAT_LABEL(_lck_mtx_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, %edx)
#endif
	ret
	
Llmus_wakeup:
	pushl	%edx			/* save mutex address */
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlockspin_wakeup)	/* yes, wake a thread */
	addl	$4,%esp
	popl	%edx			/* restore mutex pointer */
	jmp	Llmu_drop_ilk


Llmu_enter:	
	pushf				/* save interrupt state */

	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	jne	Llmu_ilk_loop		/* no - go to spin loop */
Llmu_retry:
	cli				/* disable interrupts */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	/* eax == 0 at this point */
	lock; cmpxchgl	%ecx,M_ILK	/* atomic compare and exchange */
	jne	Llmu_ilk_fail		/* branch on failure to spin loop */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	Llmu_wakeup		/* yes, more work to do */

Llmu_doit:
	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */
	movl	%ecx,M_ILK		/* clear the interlock */

	popf				/* restore interrupt state */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_unlock2_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, %edx)
#endif
	ret

Llmu_ilk_fail:
	popf				/* restore interrupt state */
	pushf				/* resave interrupt state */
	
Llmu_ilk_loop:
	PAUSE
	movl	M_ILK,%eax		/* read interlock */
	testl	%eax,%eax		/* unlocked? */
	je	Llmu_retry		/* yes - go try to grab it */

	cmpl	$(MUTEX_DESTROYED),%eax	/* check to see if its marked destroyed */
	jne	Llmu_ilk_loop		/* no - keep spinning  */

	pushl	%edx
	call	EXT(lck_mtx_interlock_panic)
	/*
	 * shouldn't return from here, but just in case
	 */
	popl	%edx
	jmp	Llmu_ilk_loop

Llmu_wakeup:
	pushl	%edx			/* save mutex address */
	pushl	M_LOCKED
	pushl	%edx			/* push mutex address */
	call	EXT(lck_mtx_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	popl	%edx			/* restore mutex pointer */
	xorl	%ecx,%ecx
	movl	%ecx,M_LOCKED		/* unlock the mutex */

	movl	%ecx,M_ILK

	popf				/* restore interrupt state */

	leave
#if	CONFIG_DTRACE
	/* Dtrace: LS_LCK_MTX_EXT_UNLOCK_RELEASE */
	LOCKSTAT_LABEL(_lck_mtx_ext_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %edx from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_EXT_UNLOCK_RELEASE, %edx)
#endif
	ret


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

/*
 * Atomic primitives, prototyped in kern/simple_lock.h
 */
LEAF_ENTRY(hw_atomic_add)
	movl	L_ARG0, %ecx		/* Load address of operand */
	movl	L_ARG1, %eax		/* Load addend */
	movl	%eax, %edx
	lock
	xaddl	%eax, (%ecx)		/* Atomic exchange and add */
	addl	%edx, %eax		/* Calculate result */
	LEAF_RET

LEAF_ENTRY(hw_atomic_sub)
	movl	L_ARG0, %ecx		/* Load address of operand */
	movl	L_ARG1, %eax		/* Load subtrahend */
	negl	%eax
	movl	%eax, %edx
	lock
	xaddl	%eax, (%ecx)		/* Atomic exchange and add */
	addl	%edx, %eax		/* Calculate result */
	LEAF_RET

LEAF_ENTRY(hw_atomic_or)
	movl	L_ARG0, %ecx		/* Load address of operand */
	movl	(%ecx), %eax
1:
	movl	L_ARG1, %edx		/* Load mask */
	orl	%eax, %edx
	lock
	cmpxchgl	%edx, (%ecx)	/* Atomic CAS */
	jne	1b
	movl	%edx, %eax		/* Result */
	LEAF_RET
/*
 * A variant of hw_atomic_or which doesn't return a value.
 * The implementation is thus comparatively more efficient.
 */

LEAF_ENTRY(hw_atomic_or_noret)
	movl	L_ARG0, %ecx		/* Load address of operand */
	movl	L_ARG1, %edx		/* Load mask */
	lock
	orl	%edx, (%ecx)		/* Atomic OR */
	LEAF_RET

LEAF_ENTRY(hw_atomic_and)
	movl	L_ARG0, %ecx		/* Load address of operand */
	movl	(%ecx), %eax
1:
	movl	L_ARG1, %edx		/* Load mask */
	andl	%eax, %edx
	lock
	cmpxchgl	%edx, (%ecx)	/* Atomic CAS */
	jne	1b
	movl	%edx, %eax		/* Result */
	LEAF_RET
/*
 * A variant of hw_atomic_and which doesn't return a value.
 * The implementation is thus comparatively more efficient.
 */

LEAF_ENTRY(hw_atomic_and_noret)
	movl	L_ARG0, %ecx		/* Load address of operand */
	movl	L_ARG1, %edx		/* Load mask */
	lock
	andl	%edx, (%ecx)		/* Atomic OR */
	LEAF_RET
