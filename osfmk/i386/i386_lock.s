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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1989 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <cpus.h>
#include <mach_rt.h>
#include <platforms.h>
#include <mach_ldebug.h>
#include <i386/asm.h>
#include <kern/etap_options.h>

#include "assym.s"

/*
 *	When performance isn't the only concern, it's
 *	nice to build stack frames...
 */
#define	BUILD_STACK_FRAMES   ((MACH_LDEBUG || ETAP_LOCK_TRACE) && MACH_KDB)

#if	BUILD_STACK_FRAMES

#define	L_PC		4(%ebp)
#define	L_ARG0		8(%ebp)
#define	L_ARG1		12(%ebp)

#define SWT_HI          -4(%ebp)
#define SWT_LO          -8(%ebp)
#define MISSED          -12(%ebp)

#else   /* BUILD_STACK_FRAMES */

#undef	FRAME
#undef	EMARF
#define	FRAME
#define	EMARF
#define	L_PC		(%esp)
#define	L_ARG0		4(%esp)
#define	L_ARG1		8(%esp)

#endif   /* BUILD_STACK_FRAMES */


#define	M_ILK			(%edx)
#define	M_LOCKED		1(%edx)
#define	M_WAITERS		2(%edx)
#define	M_PROMOTED_PRI	4(%edx)
#if	MACH_LDEBUG
#define	M_TYPE			6(%edx)
#define	M_PC			10(%edx)
#define	M_THREAD		14(%edx)
#endif	/* MACH_LDEBUG */

#include <i386/AT386/mp/mp.h>
#if	(NCPUS > 1)
#define	CX(addr,reg)	addr(,reg,4)
#else
#define	CPU_NUMBER(reg)
#define	CX(addr,reg)	addr
#endif	/* (NCPUS > 1) */

#if	MACH_LDEBUG
/*
 *  Routines for general lock debugging.
 */
#define	S_TYPE		4(%edx)
#define	S_PC		8(%edx)
#define	S_THREAD	12(%edx)
#define	S_DURATIONH	16(%edx)
#define	S_DURATIONL	20(%edx)

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
	cmpl	$ SIMPLE_LOCK_TAG,S_TYPE 		;	\
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
#if	0 /*MACH_RT - 11/12/99 - lion@apple.com disable check for now*/
#define CHECK_PREEMPTION_LEVEL()				\
	movl	$ CPD_PREEMPTION_LEVEL,%eax		;	\
	cmpl	$0,%gs:(%eax)				;	\
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
	movl	$ CPD_SIMPLE_LOCK_COUNT,%eax		;	\
	cmpl	$0,%gs:(%eax)				;	\
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
	movl	$ CPD_ACTIVE_THREAD,%eax			;	\
	movl	%gs:(%eax),%ecx				;	\
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
	movl	$ CPD_ACTIVE_THREAD,%eax			;	\
	movl	%gs:(%eax),%ecx				;	\
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
ENTRY(hw_lock_init)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */
	xorl	%eax,%eax
	movb	%al,0(%edx)		/* clear the lock */
	EMARF
	ret

/*
 *	void hw_lock_lock(hw_lock_t)
 *	unsigned int hw_lock_to(hw_lock_t, unsigned int)
 *
 *	Acquire lock, spinning until it becomes available.
 *	XXX:  For now, we don't actually implement the timeout.
 *	MACH_RT:  also return with preemption disabled.
 */
ENTRY2(hw_lock_lock,hw_lock_to)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

1:	DISABLE_PREEMPTION(%eax)
	movb	$1,%cl
	xchgb	0(%edx),%cl		/* try to acquire the HW lock */
	testb	%cl,%cl			/* success? */
	jne	3f
	movl	$1,%eax			/* In case this was a timeout call */
	EMARF				/* if yes, then nothing left to do */
	ret

3:	ENABLE_PREEMPTION(%eax)		/* no reason we can't be preemptable now */

	movb	$1,%cl
2:	testb	%cl,0(%edx)		/* spin checking lock value in cache */
	jne	2b			/* non-zero means locked, keep spinning */
	jmp	1b			/* zero means unlocked, try to grab it */

/*
 *	void hw_lock_unlock(hw_lock_t)
 *
 *	Unconditionally release lock.
 *	MACH_RT:  release preemption level.
 */
ENTRY(hw_lock_unlock)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */
	xorl	%eax,%eax
	xchgb	0(%edx),%al		/* clear the lock... a mov instruction */
					/* ...might be cheaper and less paranoid */
	ENABLE_PREEMPTION(%eax)
	EMARF
	ret

/*
 *	unsigned int hw_lock_try(hw_lock_t)
 *	MACH_RT:  returns with preemption disabled on success.
 */
ENTRY(hw_lock_try)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

	DISABLE_PREEMPTION(%eax)
	movb	$1,%cl
	xchgb	0(%edx),%cl		/* try to acquire the HW lock */
	testb	%cl,%cl			/* success? */
	jne	1f			/* if yes, let the caller know */

	movl	$1,%eax			/* success */
	EMARF
	ret

1:	ENABLE_PREEMPTION(%eax)		/* failure:  release preemption... */
	xorl	%eax,%eax		/* ...and return failure */
	EMARF
	ret	

/*
 *	unsigned int hw_lock_held(hw_lock_t)
 *	MACH_RT:  doesn't change preemption state.
 *	N.B.  Racy, of course.
 */
ENTRY(hw_lock_held)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

	movb	$1,%cl
	testb	%cl,0(%edx)		/* check lock value */
	jne	1f			/* non-zero means locked */
	xorl	%eax,%eax		/* tell caller:  lock wasn't locked */
	EMARF
	ret	

1:	movl	$1,%eax			/* tell caller:  lock was locked */
	EMARF
	ret
	


#if	0


ENTRY(_usimple_lock_init)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */
	xorl	%eax,%eax
	movb	%al,USL_INTERLOCK(%edx)	/* unlock the HW lock */
	EMARF
	ret

ENTRY(_simple_lock)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

	CHECK_SIMPLE_LOCK_TYPE()

	DISABLE_PREEMPTION(%eax)

sl_get_hw:
	movb	$1,%cl
	xchgb	USL_INTERLOCK(%edx),%cl	/* try to acquire the HW lock */
	testb	%cl,%cl			/* did we succeed? */

#if	MACH_LDEBUG
	je	5f
	CHECK_MYLOCK(S_THREAD)
	jmp	sl_get_hw
5:
#else	/* MACH_LDEBUG */
	jne	sl_get_hw		/* no, try again */
#endif	/* MACH_LDEBUG */

#if	MACH_LDEBUG
	movl	L_PC,%ecx
	movl	%ecx,S_PC
	movl	$ CPD_ACTIVE_THREAD,%eax
	movl	%gs:(%eax),%ecx
	movl	%ecx,S_THREAD
	incl	CX(EXT(simple_lock_count),%eax)
#if 0
	METER_SIMPLE_LOCK_LOCK(%edx)
#endif
#if	NCPUS == 1
	pushf
	pushl	%edx
	cli
	call	EXT(lock_stack_push)
	popl	%edx
	popfl
#endif	/* NCPUS == 1 */
#endif	/* MACH_LDEBUG */

	EMARF
	ret

ENTRY(_simple_lock_try)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

	CHECK_SIMPLE_LOCK_TYPE()

	DISABLE_PREEMPTION(%eax)

	movb	$1,%cl
	xchgb	USL_INTERLOCK(%edx),%cl	/* try to acquire the HW lock */
	testb	%cl,%cl			/* did we succeed? */
	jne	1f			/* no, return failure */

#if	MACH_LDEBUG
	movl	L_PC,%ecx
	movl	%ecx,S_PC
	movl	$ CPD_ACTIVE_THREAD,%eax
	movl	%gs:(%eax),%ecx
	movl	%ecx,S_THREAD
	incl	CX(EXT(simple_lock_count),%eax)
#if 0
	METER_SIMPLE_LOCK_LOCK(%edx)
#endif
#if	NCPUS == 1
	pushf
	pushl	%edx
	cli
	call	EXT(lock_stack_push)
	popl	%edx
	popfl
#endif	/* NCPUS == 1 */
#endif	/* MACH_LDEBUG */

	movl	$1,%eax			/* return success */

	EMARF
	ret

1:
	ENABLE_PREEMPTION(%eax)

	xorl	%eax,%eax		/* and return failure */

	EMARF
	ret

ENTRY(_simple_unlock)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

	CHECK_SIMPLE_LOCK_TYPE()
	CHECK_THREAD(S_THREAD)

#if	MACH_LDEBUG
	xorl	%eax,%eax
	movl	%eax,S_THREAD		/* disown thread */
	MP_DISABLE_PREEMPTION(%eax)
	CPU_NUMBER(%eax)
	decl	CX(EXT(simple_lock_count),%eax)
	MP_ENABLE_PREEMPTION(%eax)
#if 0
	METER_SIMPLE_LOCK_UNLOCK(%edx)
#endif
#if	NCPUS == 1
	pushf
	pushl	%edx
	cli
	call	EXT(lock_stack_pop)
	popl	%edx
	popfl
#endif	/* NCPUS == 1 */
#endif	/* MACH_LDEBUG */

	xorb	%cl,%cl
	xchgb	USL_INTERLOCK(%edx),%cl	/* unlock the HW lock */

	ENABLE_PREEMPTION(%eax)

	EMARF
	ret

#endif	/* 0 */


ENTRY(mutex_init)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */
	xorl	%eax,%eax
	movb	%al,M_ILK		/* clear interlock */
	movb	%al,M_LOCKED		/* clear locked flag */
	movw	%ax,M_WAITERS		/* init waiter count */
	movw	%ax,M_PROMOTED_PRI

#if	MACH_LDEBUG
	movl	$ MUTEX_TAG,M_TYPE	/* set lock type */
	movl	%eax,M_PC		/* init caller pc */
	movl	%eax,M_THREAD		/* and owning thread */
#endif
#if	ETAP_LOCK_TRACE
	movl	L_ARG1,%ecx		/* fetch event type */
	pushl	%ecx			/* push event type */
	pushl	%edx			/* push mutex address */
	call	EXT(etap_mutex_init)	/* init ETAP data */
	addl	$8,%esp
#endif	/* ETAP_LOCK_TRACE */

	EMARF
	ret

ENTRY2(mutex_lock,_mutex_lock)
	FRAME

#if	ETAP_LOCK_TRACE
	subl	$12,%esp		/* make room for locals */
	movl	$0,SWT_HI		/* set wait time to zero (HI) */
	movl	$0,SWT_LO		/* set wait time to zero (LO) */
	movl	$0,MISSED		/* clear local miss marker */
#endif	/* ETAP_LOCK_TRACE */

	movl	L_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()
	CHECK_PREEMPTION_LEVEL()

ml_retry:
	DISABLE_PREEMPTION(%eax)

ml_get_hw:
	movb	$1,%cl
	xchgb	%cl,M_ILK
	testb	%cl,%cl			/* did we succeed? */
	jne	ml_get_hw		/* no, try again */

	movb	$1,%cl
	xchgb	%cl,M_LOCKED		/* try to set locked flag */
	testb	%cl,%cl			/* is the mutex locked? */
	jne	ml_fail			/* yes, we lose */

	pushl	%edx
	call	EXT(mutex_lock_acquire)
	addl	$4,%esp
	movl	L_ARG0,%edx

#if	MACH_LDEBUG
	movl	L_PC,%ecx
	movl	%ecx,M_PC
	movl	$ CPD_ACTIVE_THREAD,%eax
	movl	%gs:(%eax),%ecx
	movl	%ecx,M_THREAD
	testl	%ecx,%ecx
	je	3f
	incl	TH_MUTEX_COUNT(%ecx)
3:
#endif

	xorb	%cl,%cl
	xchgb	%cl,M_ILK

	ENABLE_PREEMPTION(%eax)

#if	ETAP_LOCK_TRACE
	movl	L_PC,%eax		/* fetch pc */
	pushl	SWT_LO			/* push wait time (low) */
	pushl	SWT_HI			/* push wait time (high) */
	pushl	%eax			/* push pc */
	pushl	%edx			/* push mutex address */
	call	EXT(etap_mutex_hold)	/* collect hold timestamp */
	addl	$16+12,%esp		/* clean up stack, adjusting for locals */
#endif	/* ETAP_LOCK_TRACE */

	EMARF
	ret

ml_fail:
#if	ETAP_LOCK_TRACE
	cmp	$0,MISSED		/* did we already take a wait timestamp? */
	jne	ml_block		/* yup. carry-on */
	pushl	%edx			/* push mutex address */
	call	EXT(etap_mutex_miss)	/* get wait timestamp */
	movl	%eax,SWT_HI		/* set wait time (high word) */
	movl	%edx,SWT_LO		/* set wait time (low word) */
	popl	%edx			/* clean up stack */
	movl	$1,MISSED		/* mark wait timestamp as taken */
#endif	/* ETAP_LOCK_TRACE */

ml_block:
	CHECK_MYLOCK(M_THREAD)
	xorl	%eax,%eax
	pushl	%eax			/* no promotion here yet */
	pushl	%edx			/* push mutex address */
	call	EXT(mutex_lock_wait)	/* wait for the lock */
	addl	$8,%esp
	movl	L_ARG0,%edx		/* refetch lock pointer */
	jmp	ml_retry		/* and try again */

ENTRY2(mutex_try,_mutex_try)	
	FRAME

#if	ETAP_LOCK_TRACE
	subl	$8,%esp			/* make room for locals */
	movl	$0,SWT_HI		/* set wait time to zero (HI) */
	movl	$0,SWT_LO		/* set wait time to zero (LO) */
#endif	/* ETAP_LOCK_TRACE */

	movl	L_ARG0,%edx		/* fetch lock pointer */

	CHECK_MUTEX_TYPE()
	CHECK_NO_SIMPLELOCKS()

	DISABLE_PREEMPTION(%eax)

mt_get_hw:
	movb	$1,%cl
	xchgb	%cl,M_ILK
	testb	%cl,%cl
	jne		mt_get_hw

	movb	$1,%cl
	xchgb	%cl,M_LOCKED
	testb	%cl,%cl
	jne		mt_fail

	pushl	%edx
	call	EXT(mutex_lock_acquire)
	addl	$4,%esp
	movl	L_ARG0,%edx

#if	MACH_LDEBUG
	movl	L_PC,%ecx
	movl	%ecx,M_PC
	movl	$ CPD_ACTIVE_THREAD,%ecx
	movl	%gs:(%ecx),%ecx
	movl	%ecx,M_THREAD
	testl	%ecx,%ecx
	je	1f
	incl	TH_MUTEX_COUNT(%ecx)
1:
#endif

	xorb	%cl,%cl
	xchgb	%cl,M_ILK

	ENABLE_PREEMPTION(%eax)

#if	ETAP_LOCK_TRACE
	movl	L_PC,%eax		/* fetch pc */
	pushl	SWT_LO			/* push wait time (low) */
	pushl	SWT_HI			/* push wait time (high) */
	pushl	%eax			/* push pc */
	pushl	%edx			/* push mutex address */
	call	EXT(etap_mutex_hold)	/* get start hold timestamp */
	addl	$16,%esp		/* clean up stack, adjusting for locals */
#endif	/* ETAP_LOCK_TRACE */

	movl	$1,%eax

#if	MACH_LDEBUG || ETAP_LOCK_TRACE
#if	ETAP_LOCK_TRACE
	addl	$8,%esp			/* pop stack claimed on entry */
#endif
#endif

	EMARF
	ret

mt_fail:
#if	MACH_LDEBUG
	movl	L_PC,%ecx
	movl	%ecx,M_PC
	movl	$ CPD_ACTIVE_THREAD,%ecx
	movl	%gs:(%ecx),%ecx
	movl	%ecx,M_THREAD
	testl	%ecx,%ecx
	je	1f
	incl	TH_MUTEX_COUNT(%ecx)
1:
#endif

	xorb	%cl,%cl
	xchgb	%cl,M_ILK

	ENABLE_PREEMPTION(%eax)

#if	ETAP_LOCK_TRACE
	movl	L_PC,%eax		/* fetch pc */
	pushl	SWT_LO			/* push wait time (low) */
	pushl	SWT_HI			/* push wait time (high) */
	pushl	%eax			/* push pc */
	pushl	%edx			/* push mutex address */
	call	EXT(etap_mutex_hold)	/* get start hold timestamp */
	addl	$16,%esp		/* clean up stack, adjusting for locals */
#endif	/* ETAP_LOCK_TRACE */

	xorl	%eax,%eax

#if	MACH_LDEBUG || ETAP_LOCK_TRACE
#if	ETAP_LOCK_TRACE
	addl	$8,%esp			/* pop stack claimed on entry */
#endif
#endif

	EMARF
	ret

ENTRY(mutex_unlock)
	FRAME
	movl	L_ARG0,%edx		/* fetch lock pointer */

#if	ETAP_LOCK_TRACE
	pushl	%edx			/* push mutex address */
	call	EXT(etap_mutex_unlock)	/* collect ETAP data */
	popl	%edx			/* restore mutex address */
#endif	/* ETAP_LOCK_TRACE */

	CHECK_MUTEX_TYPE()
	CHECK_THREAD(M_THREAD)

	DISABLE_PREEMPTION(%eax)

mu_get_hw:
	movb	$1,%cl
	xchgb	%cl,M_ILK
	testb	%cl,%cl			/* did we succeed? */
	jne	mu_get_hw		/* no, try again */

	cmpw	$0,M_WAITERS		/* are there any waiters? */
	jne	mu_wakeup		/* yes, more work to do */

mu_doit:
#if	MACH_LDEBUG
	xorl	%eax,%eax
	movl	%eax,M_THREAD		/* disown thread */
	movl	$ CPD_ACTIVE_THREAD,%eax
	movl	%gs:(%eax),%ecx
	testl	%ecx,%ecx
	je	0f
	decl	TH_MUTEX_COUNT(%ecx)
0:
#endif

	xorb	%cl,%cl
	xchgb	%cl,M_LOCKED		/* unlock the mutex */

	xorb	%cl,%cl
	xchgb	%cl,M_ILK

	ENABLE_PREEMPTION(%eax)

	EMARF
	ret

mu_wakeup:
	xorl	%eax,%eax
	pushl	%eax			/* no promotion here yet */
	pushl	%edx			/* push mutex address */
	call	EXT(mutex_unlock_wakeup)/* yes, wake a thread */
	addl	$8,%esp
	movl	L_ARG0,%edx		/* refetch lock pointer */
	jmp	mu_doit

ENTRY(interlock_unlock)
	FRAME
	movl	L_ARG0,%edx

	xorb	%cl,%cl
	xchgb	%cl,M_ILK

	ENABLE_PREEMPTION(%eax)

	EMARF
	ret

	
ENTRY(_disable_preemption)
#if	MACH_RT
	_DISABLE_PREEMPTION(%eax)
#endif	/* MACH_RT */
	ret

ENTRY(_enable_preemption)
#if	MACH_RT
#if	MACH_ASSERT
	movl	$ CPD_PREEMPTION_LEVEL,%eax
	cmpl	$0,%gs:(%eax)
	jg	1f
	pushl	%gs:(%eax)
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_enable_preemption: preemption_level(%d)  < 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION(%eax)
#endif	/* MACH_RT */
	ret

ENTRY(_enable_preemption_no_check)
#if	MACH_RT
#if	MACH_ASSERT
	movl	$ CPD_PREEMPTION_LEVEL,%eax
	cmpl	$0,%gs:(%eax)
	jg	1f
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_enable_preemption_no_check: preemption_level <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION_NO_CHECK(%eax)
#endif	/* MACH_RT */
	ret
	
	
ENTRY(_mp_disable_preemption)
#if	MACH_RT && NCPUS > 1
	_DISABLE_PREEMPTION(%eax)
#endif	/* MACH_RT && NCPUS > 1*/
	ret

ENTRY(_mp_enable_preemption)
#if	MACH_RT && NCPUS > 1
#if	MACH_ASSERT
	movl	$ CPD_PREEMPTION_LEVEL,%eax
	cmpl	$0,%gs:(%eax)
	jg	1f
	pushl	%gs:(%eax)
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_mp_enable_preemption: preemption_level (%d) <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION(%eax)
#endif	/* MACH_RT && NCPUS > 1 */
	ret

ENTRY(_mp_enable_preemption_no_check)
#if	MACH_RT && NCPUS > 1
#if	MACH_ASSERT
	movl	$ CPD_PREEMPTION_LEVEL,%eax
	cmpl	$0,%gs:(%eax)
	jg	1f
	pushl	$2f
	call	EXT(panic)
	hlt
	.data
2:	String	"_mp_enable_preemption_no_check: preemption_level <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION_NO_CHECK(%eax)
#endif	/* MACH_RT && NCPUS > 1 */
	ret
	
	
ENTRY(i_bit_set)
	movl	S_ARG0,%edx
	movl	S_ARG1,%eax
	lock
	bts	%dl,(%eax)
	ret

ENTRY(i_bit_clear)
	movl	S_ARG0,%edx
	movl	S_ARG1,%eax
	lock
	btr	%dl,(%eax)
	ret

ENTRY(bit_lock)
	movl	S_ARG0,%ecx
	movl	S_ARG1,%eax
1:
	lock
	bts	%ecx,(%eax)
	jb	1b
	ret

ENTRY(bit_lock_try)
	movl	S_ARG0,%ecx
	movl	S_ARG1,%eax
	lock
	bts	%ecx,(%eax)
	jb	bit_lock_failed
	ret			/* %eax better not be null ! */
bit_lock_failed:
	xorl	%eax,%eax
	ret

ENTRY(bit_unlock)
	movl	S_ARG0,%ecx
	movl	S_ARG1,%eax
	lock
	btr	%ecx,(%eax)
	ret
