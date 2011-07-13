/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
#include <i386/mp.h>
	
#include "assym.s"

#define	PAUSE		rep; nop

#include <i386/pal_lock_asm.h>

/*
 *	When performance isn't the only concern, it's
 *	nice to build stack frames...
 */
#define	BUILD_STACK_FRAMES   (GPROF || \
				((MACH_LDEBUG) && MACH_KDB))

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


/* For x86_64, the varargs ABI requires that %al indicate
 * how many SSE register contain arguments. In our case, 0 */
#if __i386__
#define ALIGN_STACK()		subl $8, %esp; andl	$0xFFFFFFF0, %esp ;
#define LOAD_STRING_ARG0(label)	movl $##label, (%esp) ;
#define LOAD_ARG1(x)		mov  x, 4(%esp)	;
#define LOAD_PTR_ARG1(x)	mov  x, 4(%esp)	;
#define CALL_PANIC()		call EXT(panic) ;
#else
#define ALIGN_STACK() 		and  $0xFFFFFFFFFFFFFFF0, %rsp ;
#define LOAD_STRING_ARG0(label)	leaq label(%rip), %rdi ;
#define LOAD_ARG1(x)		mov x, %esi ;
#define LOAD_PTR_ARG1(x)	mov x, %rsi ;
#define CALL_PANIC()		xorb %al,%al ; call EXT(panic) ;
#endif

#define	CHECK_UNLOCK(current, owner)				\
	cmp	current, owner				;	\
	je	1f					;	\
	ALIGN_STACK()					;	\
	LOAD_STRING_ARG0(2f)				;	\
	CALL_PANIC()					;	\
	hlt						;	\
	.data						;	\
2:	String	"Mutex unlock attempted from non-owner thread";	\
	.text						;	\
1:

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
	ALIGN_STACK()					;	\
	LOAD_STRING_ARG0(2f)				;	\
	CALL_PANIC()					;	\
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
	cmpl	$0,%gs:CPU_HIBERNATE			;	\
	jne	1f					;	\
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL		;	\
	je	1f					;	\
	ALIGN_STACK()					;	\
	movl	%gs:CPU_PREEMPTION_LEVEL, %eax		;	\
	LOAD_ARG1(%eax)					;	\
	LOAD_STRING_ARG0(2f)				;	\
	CALL_PANIC()					;	\
	hlt						;	\
	.data						;	\
2:	String	"preemption_level(%d) != 0!"		;	\
	.text						;	\
1:
#else	/* MACH_RT */
#define	CHECK_PREEMPTION_LEVEL()
#endif	/* MACH_RT */

#define	CHECK_MYLOCK(current, owner)				\
	cmp	current, owner				;	\
	jne	1f					;	\
	ALIGN_STACK()					;	\
	LOAD_STRING_ARG0(2f)				;	\
	CALL_PANIC()					;	\
	hlt						;	\
	.data						;	\
2:	String	"Attempt to recursively lock a non-recursive lock";	\
	.text						;	\
1:

#else	/* MACH_LDEBUG */
#define	CHECK_MUTEX_TYPE()
#define CHECK_PREEMPTION_LEVEL()
#define	CHECK_MYLOCK(thd)
#endif	/* MACH_LDEBUG */

#define PREEMPTION_DISABLE				\
	incl	%gs:CPU_PREEMPTION_LEVEL

#if MACH_LDEBUG || 1
#define	PREEMPTION_LEVEL_DEBUG 1	
#endif
#if	PREEMPTION_LEVEL_DEBUG
#define	PREEMPTION_ENABLE				\
	decl	%gs:CPU_PREEMPTION_LEVEL	;	\
	js	17f				;	\
	jnz	19f				;	\
	testl	$AST_URGENT,%gs:CPU_PENDING_AST	;	\
	jz	19f				;	\
	PUSHF					;	\
	testl	$EFL_IF, S_PC			;	\
	jz	18f				;	\
	POPF					;	\
	int	$(T_PREEMPT)			;	\
	jmp	19f				;	\
17:							\
	call	_preemption_underflow_panic	;	\
18:							\
	POPF					;	\
19:
#else
#define	PREEMPTION_ENABLE				\
	decl	%gs:CPU_PREEMPTION_LEVEL	;	\
	jnz	19f				;	\
	testl	$AST_URGENT,%gs:CPU_PENDING_AST	;	\
	jz	19f				;	\
	PUSHF					;	\
	testl	$EFL_IF, S_PC			;	\
	jz	18f				;	\
	POPF					;	\
	int	$(T_PREEMPT)			;	\
	jmp	19f				;	\
18:							\
	POPF					;	\
19:
#endif


#if	CONFIG_DTRACE

       .globl  _lockstat_probe
       .globl  _lockstat_probemap

/*
 * LOCKSTAT_LABEL creates a dtrace symbol which contains
 * a pointer into the lock code function body. At that
 * point is a "ret" instruction that can be patched into
 * a "nop"
 */

#if defined(__i386__)

#define	LOCKSTAT_LABEL(lab) \
	.data				;\
	.globl	lab			;\
	lab:				;\
	.long 9f			;\
	.text				;\
	9:

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

#elif defined(__x86_64__)
#define        LOCKSTAT_LABEL(lab) \
       .data                                       ;\
       .globl  lab                                 ;\
       lab:                                        ;\
       .quad 9f                                    ;\
       .text                                       ;\
       9:

#define LOCKSTAT_RECORD(id, lck) \
       push    %rbp                                ;       \
       mov     %rsp,%rbp                           ;       \
       movl    _lockstat_probemap + (id * 4)(%rip),%eax ;  \
       test    %eax,%eax                           ;       \
       je              9f                          ;       \
       mov             lck, %rsi                   ;       \
       mov             %rax, %rdi                  ;       \
       mov             $0, %rdx                    ;       \
       mov             $0, %rcx                    ;       \
       mov             $0, %r8                     ;       \
       mov             $0, %r9                     ;       \
       call    *_lockstat_probe(%rip)              ;       \
9:	leave
	/* ret - left to subsequent code, e.g. return values */
#else
#error Unsupported architecture
#endif
#endif /* CONFIG_DTRACE */

/*
 * For most routines, the hw_lock_t pointer is loaded into a
 * register initially, and then either a byte or register-sized
 * word is loaded/stored to the pointer
 */
 
#if defined(__i386__)
#define	HW_LOCK_REGISTER	%edx
#define	LOAD_HW_LOCK_REGISTER mov L_ARG0, HW_LOCK_REGISTER
#define	HW_LOCK_THREAD_REGISTER	%ecx
#define	LOAD_HW_LOCK_THREAD_REGISTER mov %gs:CPU_ACTIVE_THREAD, HW_LOCK_THREAD_REGISTER
#define	HW_LOCK_MOV_WORD	movl
#define	HW_LOCK_EXAM_REGISTER	%eax
#elif defined(__x86_64__)
#define	HW_LOCK_REGISTER	%rdi
#define	LOAD_HW_LOCK_REGISTER
#define	HW_LOCK_THREAD_REGISTER	%rcx
#define	LOAD_HW_LOCK_THREAD_REGISTER mov %gs:CPU_ACTIVE_THREAD, HW_LOCK_THREAD_REGISTER
#define	HW_LOCK_MOV_WORD	movq
#define	HW_LOCK_EXAM_REGISTER	%rax
#else
#error Unsupported architecture
#endif

/*
 *	void hw_lock_init(hw_lock_t)
 *
 *	Initialize a hardware lock.
 */
LEAF_ENTRY(hw_lock_init)
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	HW_LOCK_MOV_WORD $0, (HW_LOCK_REGISTER)		/* clear the lock */
	LEAF_RET


/*
 *	void hw_lock_byte_init(uint8_t *)
 *
 *	Initialize a hardware byte lock.
 */
LEAF_ENTRY(hw_lock_byte_init)
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	movb $0, (HW_LOCK_REGISTER)		/* clear the lock */
	LEAF_RET

/*
 *	void hw_lock_lock(hw_lock_t)
 *
 *	Acquire lock, spinning until it becomes available.
 *	MACH_RT:  also return with preemption disabled.
 */
LEAF_ENTRY(hw_lock_lock)
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	LOAD_HW_LOCK_THREAD_REGISTER	/* get thread pointer */
	
	PREEMPTION_DISABLE
1:
	mov	(HW_LOCK_REGISTER), HW_LOCK_EXAM_REGISTER
	test	HW_LOCK_EXAM_REGISTER,HW_LOCK_EXAM_REGISTER		/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchg	HW_LOCK_THREAD_REGISTER,(HW_LOCK_REGISTER)	/* try to acquire the HW lock */
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
	LOAD_HW_LOCK_REGISTER		/* Load lock pointer */
	PREEMPTION_DISABLE
	movl	$1, %ecx		/* Set lock value */
1:
	movb	(HW_LOCK_REGISTER), %al		/* Load byte at address */
	testb	%al,%al			/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchg	%cl,(HW_LOCK_REGISTER)	/* attempt atomic compare exchange */
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
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	LOAD_HW_LOCK_THREAD_REGISTER

	/*
	 * Attempt to grab the lock immediately
	 * - fastpath without timeout nonsense.
	 */
	PREEMPTION_DISABLE

	mov	(HW_LOCK_REGISTER), HW_LOCK_EXAM_REGISTER
	test	HW_LOCK_EXAM_REGISTER,HW_LOCK_EXAM_REGISTER		/* lock locked? */
	jne	2f			/* branch if so */
	lock; cmpxchg	HW_LOCK_THREAD_REGISTER,(HW_LOCK_REGISTER)	/* try to acquire the HW lock */
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
#if __i386__
	movl	L_ARG1,%ecx		/* fetch timeout */
	push	%edi
	push	%ebx
	mov	%edx,%edi

	lfence
	rdtsc				/* read cyclecount into %edx:%eax */
	lfence
	addl	%ecx,%eax		/* fetch and timeout */
	adcl	$0,%edx			/* add carry */
	mov	%edx,%ecx
	mov	%eax,%ebx		/* %ecx:%ebx is the timeout expiry */
	mov	%edi, %edx		/* load lock back into %edx */
#else
	push	%r9
	lfence
	rdtsc				/* read cyclecount into %edx:%eax */
	lfence
	shlq	$32, %rdx
	orq	%rdx, %rax		/* load 64-bit quantity into %rax */
	addq	%rax, %rsi		/* %rsi is the timeout expiry */
#endif
	
4:
	/*
	 * The inner-loop spin to look for the lock being freed.
	 */
#if __i386__
	mov	$(INNER_LOOP_COUNT),%edi
#else
	mov	$(INNER_LOOP_COUNT),%r9
#endif
5:
	PAUSE				/* pause for hyper-threading */
	mov	(HW_LOCK_REGISTER),HW_LOCK_EXAM_REGISTER		/* spin checking lock value in cache */
	test	HW_LOCK_EXAM_REGISTER,HW_LOCK_EXAM_REGISTER
	je	6f			/* zero => unlocked, try to grab it */
#if __i386__
	decl	%edi			/* decrement inner loop count */
#else
	decq	%r9			/* decrement inner loop count */
#endif
	jnz	5b			/* time to check for timeout? */
	
	/*
	 * Here after spinning INNER_LOOP_COUNT times, check for timeout
	 */
#if __i386__
	mov	%edx,%edi		/* Save %edx */
	lfence
	rdtsc				/* cyclecount into %edx:%eax */
	lfence
	xchg	%edx,%edi		/* cyclecount into %edi:%eax */
	cmpl	%ecx,%edi		/* compare high-order 32-bits */
	jb	4b			/* continue spinning if less, or */
	cmpl	%ebx,%eax		/* compare low-order 32-bits */ 
	jb	4b			/* continue if less, else bail */
	xor	%eax,%eax		/* with 0 return value */
	pop	%ebx
	pop	%edi
#else
	lfence
	rdtsc				/* cyclecount into %edx:%eax */
	lfence
	shlq	$32, %rdx
	orq	%rdx, %rax		/* load 64-bit quantity into %rax */
	cmpq	%rsi, %rax		/* compare to timeout */
	jb	4b			/* continue spinning if less, or */
	xor	%rax,%rax		/* with 0 return value */
	pop	%r9
#endif
	LEAF_RET

6:
	/*
	 * Here to try to grab the lock that now appears to be free
	 * after contention.
	 */
	LOAD_HW_LOCK_THREAD_REGISTER
	lock; cmpxchg	HW_LOCK_THREAD_REGISTER,(HW_LOCK_REGISTER)	/* try to acquire the HW lock */
	jne	4b			/* no - spin again */
	movl	$1,%eax			/* yes */
#if __i386__
	pop	%ebx
	pop	%edi
#else
	pop	%r9
#endif
	LEAF_RET

/*
 *	void hw_lock_unlock(hw_lock_t)
 *
 *	Unconditionally release lock.
 *	MACH_RT:  release preemption level.
 */
LEAF_ENTRY(hw_lock_unlock)
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	HW_LOCK_MOV_WORD $0, (HW_LOCK_REGISTER)		/* clear the lock */
	PREEMPTION_ENABLE
	LEAF_RET

/*
 *	void hw_lock_byte_unlock(uint8_t *lock_byte)
 *
 *	Unconditionally release byte sized lock operand.
 *	MACH_RT:  release preemption level.
 */

LEAF_ENTRY(hw_lock_byte_unlock)
	LOAD_HW_LOCK_REGISTER		/* Load lock pointer */
	movb $0, (HW_LOCK_REGISTER)		/* Clear the lock byte */
	PREEMPTION_ENABLE
	LEAF_RET

/*
 *	unsigned int hw_lock_try(hw_lock_t)
 *	MACH_RT:  returns with preemption disabled on success.
 */
LEAF_ENTRY(hw_lock_try)
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	LOAD_HW_LOCK_THREAD_REGISTER
	PREEMPTION_DISABLE

	mov	(HW_LOCK_REGISTER),HW_LOCK_EXAM_REGISTER
	test	HW_LOCK_EXAM_REGISTER,HW_LOCK_EXAM_REGISTER
	jne	1f
	lock; cmpxchg	HW_LOCK_THREAD_REGISTER,(HW_LOCK_REGISTER)	/* try to acquire the HW lock */
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
	LOAD_HW_LOCK_REGISTER		/* fetch lock pointer */
	mov	(HW_LOCK_REGISTER),HW_LOCK_EXAM_REGISTER		/* check lock value */
	test	HW_LOCK_EXAM_REGISTER,HW_LOCK_EXAM_REGISTER
	movl	$1,%ecx
	cmovne	%ecx,%eax		/* 0 => unlocked, 1 => locked */
	LEAF_RET


/*
 * Reader-writer lock fastpaths. These currently exist for the
 * shared lock acquire, the exclusive lock acquire, the shared to
 * exclusive upgrade and the release paths (where they reduce overhead
 * considerably) -- these are by far the most frequently used routines
 *
 * The following should reflect the layout of the bitfield embedded within
 * the lck_rw_t structure (see i386/locks.h).
 */
#define LCK_RW_INTERLOCK	(0x1 << 16)

#define LCK_RW_PRIV_EXCL	(0x1 << 24)
#define LCK_RW_WANT_UPGRADE	(0x2 << 24)
#define LCK_RW_WANT_WRITE	(0x4 << 24)
#define LCK_R_WAITING		(0x8 << 24)
#define LCK_W_WAITING		(0x10 << 24)

#define LCK_RW_SHARED_MASK	(0xffff)

/*
 * For most routines, the lck_rw_t pointer is loaded into a
 * register initially, and the flags bitfield loaded into another
 * register and examined
 */
 
#if defined(__i386__)
#define	LCK_RW_REGISTER	%edx
#define	LOAD_LCK_RW_REGISTER mov S_ARG0, LCK_RW_REGISTER
#define	LCK_RW_FLAGS_REGISTER	%eax
#define	LOAD_LCK_RW_FLAGS_REGISTER mov (LCK_RW_REGISTER), LCK_RW_FLAGS_REGISTER
#elif defined(__x86_64__)
#define	LCK_RW_REGISTER	%rdi
#define	LOAD_LCK_RW_REGISTER
#define	LCK_RW_FLAGS_REGISTER	%eax
#define	LOAD_LCK_RW_FLAGS_REGISTER mov (LCK_RW_REGISTER), LCK_RW_FLAGS_REGISTER
#else
#error Unsupported architecture
#endif
	
#define	RW_LOCK_SHARED_MASK (LCK_RW_INTERLOCK | LCK_RW_WANT_UPGRADE | LCK_RW_WANT_WRITE)
/*
 *	void lck_rw_lock_shared(lck_rw_t *)
 *
 */
Entry(lck_rw_lock_shared)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield and interlock */
	testl	$(RW_LOCK_SHARED_MASK), %eax	/* Eligible for fastpath? */
	jne	3f

	movl	%eax, %ecx			/* original value in %eax for cmpxchgl */
	incl	%ecx				/* Increment reader refcount */
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	2f

#if	CONFIG_DTRACE
	/*
	 * Dtrace lockstat event: LS_LCK_RW_LOCK_SHARED_ACQUIRE
	 * Implemented by swapping between return and no-op instructions.
	 * See bsd/dev/dtrace/lockstat.c.
	 */
	LOCKSTAT_LABEL(_lck_rw_lock_shared_lockstat_patch_point)
	ret
	/*
	Fall thru when patched, counting on lock pointer in LCK_RW_REGISTER
	*/
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, LCK_RW_REGISTER)
#endif
	ret
2:
	PAUSE
	jmp	1b
3:
	jmp	EXT(lck_rw_lock_shared_gen)


	
#define	RW_TRY_LOCK_SHARED_MASK (LCK_RW_WANT_UPGRADE | LCK_RW_WANT_WRITE)
/*
 *	void lck_rw_try_lock_shared(lck_rw_t *)
 *
 */
Entry(lck_rw_try_lock_shared)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield and interlock */
	testl	$(LCK_RW_INTERLOCK), %eax
	jne	2f
	testl	$(RW_TRY_LOCK_SHARED_MASK), %eax
	jne	3f			/* lock is busy */

	movl	%eax, %ecx			/* original value in %eax for cmpxchgl */
	incl	%ecx				/* Increment reader refcount */
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	2f

#if	CONFIG_DTRACE
	movl	$1, %eax
	/*
	 * Dtrace lockstat event: LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE
	 * Implemented by swapping between return and no-op instructions.
	 * See bsd/dev/dtrace/lockstat.c.
	 */
	LOCKSTAT_LABEL(_lck_rw_try_lock_shared_lockstat_patch_point)
	ret
    /* Fall thru when patched, counting on lock pointer in LCK_RW_REGISTER  */
    LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, LCK_RW_REGISTER)
#endif
	movl	$1, %eax			/* return TRUE */
	ret
2:
	PAUSE
	jmp	1b
3:
	xorl	%eax, %eax
	ret

	
#define	RW_LOCK_EXCLUSIVE_HELD	(LCK_RW_WANT_WRITE | LCK_RW_WANT_UPGRADE)
/*
 *	int lck_rw_grab_shared(lck_rw_t *)
 *
 */
Entry(lck_rw_grab_shared)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield and interlock */
	testl	$(LCK_RW_INTERLOCK), %eax
	jne	5f
	testl	$(RW_LOCK_EXCLUSIVE_HELD), %eax	
	jne	3f
2:	
	movl	%eax, %ecx			/* original value in %eax for cmpxchgl */
	incl	%ecx				/* Increment reader refcount */
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	4f

	movl	$1, %eax			/* return success */
	ret
3:
	testl	$(LCK_RW_SHARED_MASK), %eax
	je	4f
	testl	$(LCK_RW_PRIV_EXCL), %eax
	je	2b
4:
	xorl	%eax, %eax			/* return failure */
	ret
5:
	PAUSE
	jmp	1b


	
#define	RW_LOCK_EXCLUSIVE_MASK (LCK_RW_SHARED_MASK | LCK_RW_INTERLOCK | \
	                        LCK_RW_WANT_UPGRADE | LCK_RW_WANT_WRITE)
/*
 *	void lck_rw_lock_exclusive(lck_rw_t*)
 *
 */
Entry(lck_rw_lock_exclusive)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and shared count */
	testl	$(RW_LOCK_EXCLUSIVE_MASK), %eax		/* Eligible for fastpath? */
	jne	3f					/* no, go slow */

	movl	%eax, %ecx				/* original value in %eax for cmpxchgl */
	orl	$(LCK_RW_WANT_WRITE), %ecx
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	2f

#if	CONFIG_DTRACE
	/*
	 * Dtrace lockstat event: LS_LCK_RW_LOCK_EXCL_ACQUIRE
	 * Implemented by swapping between return and no-op instructions.
	 * See bsd/dev/dtrace/lockstat.c.
	 */
	LOCKSTAT_LABEL(_lck_rw_lock_exclusive_lockstat_patch_point)
	ret
    /* Fall thru when patched, counting on lock pointer in LCK_RW_REGISTER  */
    LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, LCK_RW_REGISTER)
#endif
	ret
2:
	PAUSE
	jmp	1b
3:
	jmp	EXT(lck_rw_lock_exclusive_gen)


	
#define	RW_TRY_LOCK_EXCLUSIVE_MASK (LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE | LCK_RW_WANT_WRITE)
/*
 *	void lck_rw_try_lock_exclusive(lck_rw_t *)
 *
 *		Tries to get a write lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */
Entry(lck_rw_try_lock_exclusive)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and shared count */
	testl	$(LCK_RW_INTERLOCK), %eax
	jne	2f
	testl	$(RW_TRY_LOCK_EXCLUSIVE_MASK), %eax
	jne	3f					/* can't get it */

	movl	%eax, %ecx				/* original value in %eax for cmpxchgl */
	orl	$(LCK_RW_WANT_WRITE), %ecx
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	2f

#if	CONFIG_DTRACE
	movl	$1, %eax
	/*
	 * Dtrace lockstat event: LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE
	 * Implemented by swapping between return and no-op instructions.
	 * See bsd/dev/dtrace/lockstat.c.
	 */
	LOCKSTAT_LABEL(_lck_rw_try_lock_exclusive_lockstat_patch_point)
	ret
    /* Fall thru when patched, counting on lock pointer in LCK_RW_REGISTER  */
    LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, LCK_RW_REGISTER)
#endif
	movl	$1, %eax			/* return TRUE */
	ret
2:
	PAUSE
	jmp	1b
3:
	xorl	%eax, %eax			/* return FALSE */
	ret	



/*
 *	void lck_rw_lock_shared_to_exclusive(lck_rw_t*)
 *
 *	fastpath can be taken if
 *	the current rw_shared_count == 1
 *	AND the interlock is clear
 *	AND RW_WANT_UPGRADE is not set
 *
 *	note that RW_WANT_WRITE could be set, but will not
 *	be indicative of an exclusive hold since we have
 * 	a read count on the lock that we have not yet released
 *	we can blow by that state since the lck_rw_lock_exclusive
 * 	function will block until rw_shared_count == 0 and 
 * 	RW_WANT_UPGRADE is clear... it does this check behind
 *	the interlock which we are also checking for
 *
 * 	to make the transition we must be able to atomically
 *	set RW_WANT_UPGRADE and get rid of the read count we hold
 */
Entry(lck_rw_lock_shared_to_exclusive)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and shared count */
	testl	$(LCK_RW_INTERLOCK), %eax
	jne	7f
	testl	$(LCK_RW_WANT_UPGRADE), %eax
	jne	2f

	movl	%eax, %ecx			/* original value in %eax for cmpxchgl */
	orl	$(LCK_RW_WANT_UPGRADE), %ecx	/* ask for WANT_UPGRADE */
	decl	%ecx				/* and shed our read count */
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	7f
						/* we now own the WANT_UPGRADE */
	testl	$(LCK_RW_SHARED_MASK), %ecx	/* check to see if all of the readers are drained */
	jne	8f				/* if not, we need to go wait */

#if	CONFIG_DTRACE
	movl	$1, %eax
	/*
	 * Dtrace lockstat event: LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE
	 * Implemented by swapping between return and no-op instructions.
	 * See bsd/dev/dtrace/lockstat.c.
	 */
	LOCKSTAT_LABEL(_lck_rw_lock_shared_to_exclusive_lockstat_patch_point)
	ret
    /* Fall thru when patched, counting on lock pointer in LCK_RW_REGISTER  */
    LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, LCK_RW_REGISTER)
#endif
	movl	$1, %eax			/* return success */
	ret
	
2:						/* someone else already holds WANT_UPGRADE */
	movl	%eax, %ecx			/* original value in %eax for cmpxchgl */
	decl	%ecx				/* shed our read count */
	testl	$(LCK_RW_SHARED_MASK), %ecx
	jne	3f				/* we were the last reader */
	andl	$(~LCK_W_WAITING), %ecx		/* so clear the wait indicator */
3:	
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	7f

#if __i386__
	pushl	%eax				/* go check to see if we need to */
	push	%edx				/* wakeup anyone */
	call	EXT(lck_rw_lock_shared_to_exclusive_failure)
	addl	$8, %esp
#else
	mov	%eax, %esi			/* put old flags as second arg */
						/* lock is alread in %rdi */
	call	EXT(lck_rw_lock_shared_to_exclusive_failure)
#endif
	ret					/* and pass the failure return along */	
7:
	PAUSE
	jmp	1b
8:
	jmp	EXT(lck_rw_lock_shared_to_exclusive_success)


	
	.cstring
rwl_release_error_str:
	.asciz  "Releasing non-exclusive RW lock without a reader refcount!"
	.text
	
/*
 *	lck_rw_type_t lck_rw_done(lck_rw_t *)
 *
 */
Entry(lck_rw_done)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and reader count */
	testl   $(LCK_RW_INTERLOCK), %eax
	jne     7f				/* wait for interlock to clear */

	movl	%eax, %ecx			/* keep original value in %eax for cmpxchgl */
	testl	$(LCK_RW_SHARED_MASK), %ecx	/* if reader count == 0, must be exclusive lock */
	je	2f
	decl	%ecx				/* Decrement reader count */
	testl	$(LCK_RW_SHARED_MASK), %ecx	/* if reader count has now gone to 0, check for waiters */
	je	4f
	jmp	6f
2:	
	testl	$(LCK_RW_WANT_UPGRADE), %ecx
	je	3f
	andl	$(~LCK_RW_WANT_UPGRADE), %ecx
	jmp	4f
3:	
	testl	$(LCK_RW_WANT_WRITE), %ecx
	je	8f				/* lock is not 'owned', go panic */
	andl	$(~LCK_RW_WANT_WRITE), %ecx
4:	
	/*
	 * test the original values to match what
	 * lck_rw_done_gen is going to do to determine
	 * which wakeups need to happen...
	 *
	 * if !(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting)
	 */
	testl	$(LCK_W_WAITING), %eax
	je	5f
	andl	$(~LCK_W_WAITING), %ecx

	testl	$(LCK_RW_PRIV_EXCL), %eax
	jne	6f
5:	
	andl	$(~LCK_R_WAITING), %ecx
6:	
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	7f

#if __i386__
	pushl	%eax
	push	%edx
	call	EXT(lck_rw_done_gen)
	addl	$8, %esp
#else
	mov	%eax,%esi	/* old flags in %rsi */
				/* lock is in %rdi already */
	call	EXT(lck_rw_done_gen)	
#endif
	ret
7:
	PAUSE
	jmp	1b
8:
	ALIGN_STACK()
	LOAD_STRING_ARG0(rwl_release_error_str)
	CALL_PANIC()
	

	
/*
 *	lck_rw_type_t lck_rw_lock_exclusive_to_shared(lck_rw_t *)
 *
 */
Entry(lck_rw_lock_exclusive_to_shared)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and reader count */
	testl   $(LCK_RW_INTERLOCK), %eax
	jne     6f				/* wait for interlock to clear */

	movl	%eax, %ecx			/* keep original value in %eax for cmpxchgl */
	incl	%ecx				/* Increment reader count */

	testl	$(LCK_RW_WANT_UPGRADE), %ecx
	je	2f
	andl	$(~LCK_RW_WANT_UPGRADE), %ecx
	jmp	3f
2:	
	andl	$(~LCK_RW_WANT_WRITE), %ecx
3:	
	/*
	 * test the original values to match what
	 * lck_rw_lock_exclusive_to_shared_gen is going to do to determine
	 * which wakeups need to happen...
	 *
	 * if !(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting)
	 */
	testl	$(LCK_W_WAITING), %eax
	je	4f
	testl	$(LCK_RW_PRIV_EXCL), %eax
	jne	5f
4:	
	andl	$(~LCK_R_WAITING), %ecx
5:	
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	6f

#if __i386__
	pushl	%eax
	push	%edx
	call	EXT(lck_rw_lock_exclusive_to_shared_gen)
	addl	$8, %esp
#else
	mov	%eax,%esi
	call	EXT(lck_rw_lock_exclusive_to_shared_gen)
#endif
	ret
6:
	PAUSE
	jmp	1b



/*
 *	int lck_rw_grab_want(lck_rw_t *)
 *
 */
Entry(lck_rw_grab_want)
	LOAD_LCK_RW_REGISTER
1:
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and reader count */
	testl   $(LCK_RW_INTERLOCK), %eax
	jne     3f				/* wait for interlock to clear */
	testl	$(LCK_RW_WANT_WRITE), %eax	/* want_write has been grabbed by someone else */
	jne	2f				/* go return failure */
	
	movl	%eax, %ecx			/* original value in %eax for cmpxchgl */
	orl	$(LCK_RW_WANT_WRITE), %ecx
	lock
	cmpxchgl %ecx, (LCK_RW_REGISTER)			/* Attempt atomic exchange */
	jne	2f
						/* we now own want_write */
	movl	$1, %eax			/* return success */
	ret
2:
	xorl	%eax, %eax			/* return failure */
	ret
3:
	PAUSE
	jmp	1b

	
#define	RW_LOCK_SHARED_OR_UPGRADE_MASK (LCK_RW_SHARED_MASK | LCK_RW_INTERLOCK | LCK_RW_WANT_UPGRADE)
/*
 *	int lck_rw_held_read_or_upgrade(lck_rw_t *)
 *
 */
Entry(lck_rw_held_read_or_upgrade)
	LOAD_LCK_RW_REGISTER
	LOAD_LCK_RW_FLAGS_REGISTER		/* Load state bitfield, interlock and reader count */
	andl	$(RW_LOCK_SHARED_OR_UPGRADE_MASK), %eax
	ret


	
/*
 * N.B.: On x86, statistics are currently recorded for all indirect mutexes.
 * Also, only the acquire attempt count (GRP_MTX_STAT_UTIL) is maintained
 * as a 64-bit quantity (this matches the existing PowerPC implementation,
 * and the new x86 specific statistics are also maintained as 32-bit
 * quantities).
 *
 *
 * Enable this preprocessor define to record the first miss alone
 * By default, we count every miss, hence multiple misses may be
 * recorded for a single lock acquire attempt via lck_mtx_lock
 */
#undef LOG_FIRST_MISS_ALONE	

/*
 * This preprocessor define controls whether the R-M-W update of the
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
 * For most routines, the lck_mtx_t pointer is loaded into a
 * register initially, and the owner field checked for indirection.
 * Eventually the lock owner is loaded into a register and examined.
 */

#define M_OWNER		MUTEX_OWNER
#define M_PTR		MUTEX_PTR
#define M_STATE		MUTEX_STATE	
	
#if defined(__i386__)

#define LMTX_ARG0	B_ARG0
#define LMTX_ARG1	B_ARG1
#define	LMTX_REG	%edx
#define LMTX_A_REG	%eax
#define LMTX_A_REG32	%eax
#define LMTX_C_REG	%ecx
#define LMTX_C_REG32	%ecx
#define LMTX_RET_REG	%eax
#define LMTX_RET_REG32	%eax
#define LMTX_LGROUP_REG	%esi
#define LMTX_SSTATE_REG	%edi	
#define	LOAD_LMTX_REG(arg)	mov arg, LMTX_REG
#define LMTX_CHK_EXTENDED	cmp LMTX_REG, LMTX_ARG0
#define LMTX_ASSERT_OWNED	cmpl $(MUTEX_ASSERT_OWNED), LMTX_ARG1

#define LMTX_ENTER_EXTENDED					\
	mov	M_PTR(LMTX_REG), LMTX_REG 		;	\
	push	LMTX_LGROUP_REG	 		 	;	\
	push	LMTX_SSTATE_REG			     	;	\
	xor	LMTX_SSTATE_REG, LMTX_SSTATE_REG	;	\
	mov	MUTEX_GRP(LMTX_REG), LMTX_LGROUP_REG 	;	\
	LOCK_IF_ATOMIC_STAT_UPDATES			;	\
	addl	$1, GRP_MTX_STAT_UTIL(LMTX_LGROUP_REG)	;	\
	jnc	11f			    		;	\
	incl	GRP_MTX_STAT_UTIL+4(LMTX_LGROUP_REG)	;	\
11:

#define LMTX_EXIT_EXTENDED		\
	pop	LMTX_SSTATE_REG	;	\
	pop	LMTX_LGROUP_REG


#define	LMTX_CHK_EXTENDED_EXIT			\
	cmp 	LMTX_REG, LMTX_ARG0	;	\
	je	12f			;	\
	pop	LMTX_SSTATE_REG		;	\
	pop	LMTX_LGROUP_REG		;	\
12:	
	
	
#if	LOG_FIRST_MISS_ALONE
#define LMTX_UPDATE_MISS					\
	test	$1, LMTX_SSTATE_REG 			;	\
	jnz	11f					;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_MISS(LMTX_LGROUP_REG)	;	\
	or	$1, LMTX_SSTATE_REG			;	\
11:
#else
#define LMTX_UPDATE_MISS					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_MISS(LMTX_LGROUP_REG)
#endif

	
#if	LOG_FIRST_MISS_ALONE
#define LMTX_UPDATE_WAIT					\
	test	$2, LMTX_SSTATE_REG 			;	\
	jnz	11f					;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_WAIT(LMTX_LGROUP_REG)	;	\
	or	$2, LMTX_SSTATE_REG			;	\
11:
#else
#define LMTX_UPDATE_WAIT					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_WAIT(LMTX_LGROUP_REG)
#endif

	
/*
 * Record the "direct wait" statistic, which indicates if a
 * miss proceeded to block directly without spinning--occurs
 * if the owner of the mutex isn't running on another processor
 * at the time of the check.
 */
#define LMTX_UPDATE_DIRECT_WAIT					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_DIRECT_WAIT(LMTX_LGROUP_REG)

	
#define LMTX_CALLEXT1(func_name)	\
	push	LMTX_REG	;	\
	push	LMTX_REG	;	\
	call	EXT(func_name)	;	\
	add	$4, %esp	;	\
	pop	LMTX_REG
	
#define LMTX_CALLEXT2(func_name, reg)	\
	push	LMTX_REG	;	\
	push	reg		;	\
	push	LMTX_REG	;	\
	call	EXT(func_name)	;	\
	add	$8, %esp	;	\
	pop	LMTX_REG
	
#elif defined(__x86_64__)

#define LMTX_ARG0	%rdi
#define LMTX_ARG1	%rsi
#define LMTX_REG_ORIG	%rdi
#define	LMTX_REG	%rdx
#define LMTX_A_REG	%rax
#define LMTX_A_REG32	%eax
#define LMTX_C_REG	%rcx
#define LMTX_C_REG32	%ecx
#define LMTX_RET_REG	%rax
#define LMTX_RET_REG32	%eax
#define LMTX_LGROUP_REG	%r10
#define LMTX_SSTATE_REG	%r11	
#define	LOAD_LMTX_REG(arg)	mov %rdi, %rdx
#define LMTX_CHK_EXTENDED	cmp LMTX_REG, LMTX_REG_ORIG
#define LMTX_ASSERT_OWNED	cmp $(MUTEX_ASSERT_OWNED), LMTX_ARG1

#define LMTX_ENTER_EXTENDED					\
	mov	M_PTR(LMTX_REG), LMTX_REG 		;	\
	xor	LMTX_SSTATE_REG, LMTX_SSTATE_REG	;	\
	mov	MUTEX_GRP(LMTX_REG), LMTX_LGROUP_REG 	;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incq	GRP_MTX_STAT_UTIL(LMTX_LGROUP_REG)

#define LMTX_EXIT_EXTENDED

#define	LMTX_CHK_EXTENDED_EXIT


#if	LOG_FIRST_MISS_ALONE
#define LMTX_UPDATE_MISS					\
	test	$1, LMTX_SSTATE_REG 			;	\
	jnz	11f					;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_MISS(LMTX_LGROUP_REG)	;	\
	or	$1, LMTX_SSTATE_REG			;	\
11:
#else
#define LMTX_UPDATE_MISS					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_MISS(LMTX_LGROUP_REG)
#endif
	

#if	LOG_FIRST_MISS_ALONE
#define LMTX_UPDATE_WAIT					\
	test	$2, LMTX_SSTATE_REG 			;	\
	jnz	11f					;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_WAIT(LMTX_LGROUP_REG)	;	\
	or	$2, LMTX_SSTATE_REG			;	\
11:
#else
#define LMTX_UPDATE_WAIT					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_WAIT(LMTX_LGROUP_REG)
#endif


/*
 * Record the "direct wait" statistic, which indicates if a
 * miss proceeded to block directly without spinning--occurs
 * if the owner of the mutex isn't running on another processor
 * at the time of the check.
 */
#define LMTX_UPDATE_DIRECT_WAIT					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_DIRECT_WAIT(LMTX_LGROUP_REG)

	
#define LMTX_CALLEXT1(func_name)		\
	LMTX_CHK_EXTENDED		;	\
	je	12f			;	\
	push	LMTX_LGROUP_REG		;	\
	push	LMTX_SSTATE_REG		;	\
12:	push	LMTX_REG_ORIG		;	\
	push	LMTX_REG		;	\
	mov	LMTX_REG, LMTX_ARG0	;	\
	call	EXT(func_name)		;	\
	pop	LMTX_REG		;	\
	pop	LMTX_REG_ORIG		;	\
	LMTX_CHK_EXTENDED		;	\
	je	12f			;	\
	pop	LMTX_SSTATE_REG		;	\
	pop	LMTX_LGROUP_REG		;	\
12:
	
#define LMTX_CALLEXT2(func_name, reg)		\
	LMTX_CHK_EXTENDED		;	\
	je	12f			;	\
	push	LMTX_LGROUP_REG		;	\
	push	LMTX_SSTATE_REG		;	\
12:	push	LMTX_REG_ORIG		;	\
	push	LMTX_REG		;	\
	mov	reg, LMTX_ARG1		;	\
	mov	LMTX_REG, LMTX_ARG0	;	\
	call	EXT(func_name)		;	\
	pop	LMTX_REG		;	\
	pop	LMTX_REG_ORIG		;	\
	LMTX_CHK_EXTENDED		;	\
	je	12f			;	\
	pop	LMTX_SSTATE_REG		;	\
	pop	LMTX_LGROUP_REG		;	\
12:

#else
#error Unsupported architecture
#endif


#define M_WAITERS_MSK		0x0000ffff
#define M_PRIORITY_MSK		0x00ff0000
#define M_ILOCKED_MSK		0x01000000
#define M_MLOCKED_MSK		0x02000000
#define M_PROMOTED_MSK		0x04000000
#define M_SPIN_MSK		0x08000000

/*
 *	void lck_mtx_assert(lck_mtx_t* l, unsigned int)
 *	Takes the address of a lock, and an assertion type as parameters.
 *	The assertion can take one of two forms determine by the type
 *	parameter: either the lock is held by the current thread, and the
 *	type is	LCK_MTX_ASSERT_OWNED, or it isn't and the type is
 *	LCK_MTX_ASSERT_NOTOWNED. Calls panic on assertion failure.
 *	
 */

NONLEAF_ENTRY(lck_mtx_assert)
        LOAD_LMTX_REG(B_ARG0)	                   	/* Load lock address */
	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG	/* Load current thread */

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	cmp	$(MUTEX_IND), LMTX_C_REG32	/* Is this an indirect mutex? */
	jne	0f
	mov	M_PTR(LMTX_REG), LMTX_REG	/* If so, take indirection */
0:	
	mov	M_OWNER(LMTX_REG), LMTX_C_REG	/* Load owner */
	LMTX_ASSERT_OWNED
	jne	2f				/* Assert ownership? */
	cmp	LMTX_A_REG, LMTX_C_REG		/* Current thread match? */
	jne	3f				/* no, go panic */
	testl	$(M_ILOCKED_MSK | M_MLOCKED_MSK), M_STATE(LMTX_REG)
	je	3f
1:						/* yes, we own it */
	NONLEAF_RET
2:
	cmp	LMTX_A_REG, LMTX_C_REG		/* Current thread match? */
	jne	1b				/* No, return */
	ALIGN_STACK()
	LOAD_PTR_ARG1(LMTX_REG)
	LOAD_STRING_ARG0(mutex_assert_owned_str)
	jmp	4f
3:
	ALIGN_STACK()
	LOAD_PTR_ARG1(LMTX_REG)
	LOAD_STRING_ARG0(mutex_assert_not_owned_str)
4:
	CALL_PANIC()


lck_mtx_destroyed:
	ALIGN_STACK()
	LOAD_PTR_ARG1(LMTX_REG)
	LOAD_STRING_ARG0(mutex_interlock_destroyed_str)
	CALL_PANIC()
	

.data
mutex_assert_not_owned_str:
	.asciz	"mutex (%p) not owned\n"
mutex_assert_owned_str:
	.asciz	"mutex (%p) owned\n"
mutex_interlock_destroyed_str:
	.asciz	"trying to interlock destroyed mutex (%p)"
.text



/*
 * lck_mtx_lock()
 * lck_mtx_try_lock()
 * lck_mtx_unlock()
 * lck_mtx_lock_spin()
 * lck_mtx_lock_spin_always()
 * lck_mtx_convert_spin()
 */
NONLEAF_ENTRY(lck_mtx_lock_spin_always)
	LOAD_LMTX_REG(B_ARG0)		/* fetch lock pointer */
	jmp	Llmls_avoid_check

NONLEAF_ENTRY(lck_mtx_lock_spin)
	LOAD_LMTX_REG(B_ARG0)		/* fetch lock pointer */

	CHECK_PREEMPTION_LEVEL()
Llmls_avoid_check:	
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32	/* is the interlock or mutex held */
	jnz	Llmls_slow
Llmls_try:					/* no - can't be INDIRECT, DESTROYED or locked */
	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_SPIN_MSK), LMTX_C_REG32

	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	Llmls_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)	/* record owner of interlock */
#if	MACH_LDEBUG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	incl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:	
#endif	/* MACH_LDEBUG */

	LMTX_CHK_EXTENDED_EXIT
	/* return with the interlock held and preemption disabled */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_spin_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG above */
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN_ACQUIRE, LMTX_REG)
#endif
	ret

Llmls_slow:	
	test	$M_ILOCKED_MSK, LMTX_C_REG32		/* is the interlock held */
	jz	Llml_contended				/* no, must have been the mutex */

	cmp	$(MUTEX_DESTROYED), LMTX_C_REG32	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), LMTX_C_REG32		/* Is this an indirect mutex */
	jne	Llmls_loop				/* no... must be interlocked */

	LMTX_ENTER_EXTENDED

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_SPIN_MSK), LMTX_C_REG32
	jz	Llmls_loop1

	LMTX_UPDATE_MISS		/* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
Llmls_loop:
	PAUSE
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
Llmls_loop1:
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32
	jz	Llmls_try
	test	$(M_MLOCKED_MSK), LMTX_C_REG32
	jnz	Llml_contended				/* mutex owned by someone else, go contend for it */
	jmp	Llmls_loop

Llmls_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llmls_loop


	
NONLEAF_ENTRY(lck_mtx_lock)
	LOAD_LMTX_REG(B_ARG0)		/* fetch lock pointer */

	CHECK_PREEMPTION_LEVEL()

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32	/* is the interlock or mutex held */
	jnz	Llml_slow
Llml_try:					/* no - can't be INDIRECT, DESTROYED or locked */
	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32

	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	Llml_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	incl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	testl	$(M_WAITERS_MSK), M_STATE(LMTX_REG)
	jz	Llml_finish

	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)

Llml_finish:
	andl	$(~M_ILOCKED_MSK), M_STATE(LMTX_REG)
	PREEMPTION_ENABLE
	
	LMTX_CHK_EXTENDED		/* is this an extended mutex */
	jne	2f

	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG above */
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, LMTX_REG)
#endif
	ret
2:	
	LMTX_EXIT_EXTENDED
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_ext_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG above */
	LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_ACQUIRE, LMTX_REG)
#endif
	ret

	
Llml_slow:
	test	$M_ILOCKED_MSK, LMTX_C_REG32		/* is the interlock held */
	jz	Llml_contended				/* no, must have been the mutex */
	
	cmp	$(MUTEX_DESTROYED), LMTX_C_REG32	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), LMTX_C_REG32		/* Is this an indirect mutex? */
	jne	Llml_loop				/* no... must be interlocked */

	LMTX_ENTER_EXTENDED

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_SPIN_MSK), LMTX_C_REG32
	jz	Llml_loop1

	LMTX_UPDATE_MISS		/* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
Llml_loop:
	PAUSE
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
Llml_loop1:
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32
	jz	Llml_try
	test	$(M_MLOCKED_MSK), LMTX_C_REG32
	jnz	Llml_contended				/* mutex owned by someone else, go contend for it */
	jmp	Llml_loop

Llml_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llml_loop

	
Llml_contended:
	LMTX_CHK_EXTENDED		/* is this an extended mutex */
	je	0f
	LMTX_UPDATE_MISS
0:	
	LMTX_CALLEXT1(lck_mtx_lock_spinwait_x86)

	test	LMTX_RET_REG, LMTX_RET_REG
	jz	Llml_acquired		/* acquired mutex, interlock held and preemption disabled */

	cmp	$1, LMTX_RET_REG	/* check for direct wait status */
	je	2f
	LMTX_CHK_EXTENDED		/* is this an extended mutex */
	je	2f
	LMTX_UPDATE_DIRECT_WAIT
2:	
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_ILOCKED_MSK), LMTX_C_REG32
	jnz	6f

	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK), LMTX_C_REG32	/* try to take the interlock */

	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	5f

	test	$(M_MLOCKED_MSK), LMTX_C_REG32	/* we've got the interlock and */
	jnz	3f
	or	$(M_MLOCKED_MSK), LMTX_C_REG32	/* the mutex is free... grab it directly */
	mov	LMTX_C_REG32, M_STATE(LMTX_REG)
	
 	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	incl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

Llml_acquired:
	testl	$(M_WAITERS_MSK), M_STATE(LMTX_REG)
	jnz	1f
	mov	M_OWNER(LMTX_REG), LMTX_A_REG
	mov	TH_WAS_PROMOTED_ON_WAKEUP(LMTX_A_REG), LMTX_A_REG32
	test	LMTX_A_REG32, LMTX_A_REG32
	jz	Llml_finish
1:	
	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)
	jmp	Llml_finish

3:					/* interlock held, mutex busy */
	LMTX_CHK_EXTENDED		/* is this an extended mutex */
	je	4f
	LMTX_UPDATE_WAIT
4:	
	LMTX_CALLEXT1(lck_mtx_lock_wait_x86)
	jmp	Llml_contended
5:	
	PREEMPTION_ENABLE
6:
	PAUSE
	jmp	2b
	

	
NONLEAF_ENTRY(lck_mtx_try_lock_spin)
	LOAD_LMTX_REG(B_ARG0)			/* fetch lock pointer */

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32	/* is the interlock or mutex held */
	jnz	Llmts_slow
Llmts_try:					/* no - can't be INDIRECT, DESTROYED or locked */
	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_SPIN_MSK), LMTX_C_REG

	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	Llmts_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	incl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	LMTX_CHK_EXTENDED_EXIT
	leave

#if	CONFIG_DTRACE
	mov	$1, LMTX_RET_REG	/* return success */
	LOCKSTAT_LABEL(_lck_mtx_try_lock_spin_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG above */
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, LMTX_REG)
#endif
	mov	$1, LMTX_RET_REG	/* return success */
	ret

Llmts_slow:
	test	$(M_ILOCKED_MSK), LMTX_C_REG32	/* is the interlock held */
	jz	Llmts_fail			/* no, must be held as a mutex */

	cmp	$(MUTEX_DESTROYED), LMTX_C_REG32	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), LMTX_C_REG32	/* Is this an indirect mutex? */
	jne	Llmts_loop1

	LMTX_ENTER_EXTENDED
Llmts_loop:
	PAUSE
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
Llmts_loop1:
	test	$(M_MLOCKED_MSK | M_SPIN_MSK), LMTX_C_REG32
	jnz	Llmts_fail
	test	$(M_ILOCKED_MSK), LMTX_C_REG32
	jz	Llmts_try
	jmp	Llmts_loop
	
Llmts_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llmts_loop


	
NONLEAF_ENTRY(lck_mtx_try_lock)
	LOAD_LMTX_REG(B_ARG0)			/* fetch lock pointer */

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32	/* is the interlock or mutex held */
	jnz	Llmt_slow	
Llmt_try:					/* no - can't be INDIRECT, DESTROYED or locked */
	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32
	
	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	Llmt_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	incl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	LMTX_CHK_EXTENDED_EXIT

	test	$(M_WAITERS_MSK), LMTX_C_REG32
	jz	0f

	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)
0:
	andl	$(~M_ILOCKED_MSK), M_STATE(LMTX_REG)
	PREEMPTION_ENABLE

	leave
#if	CONFIG_DTRACE
	mov	$1, LMTX_RET_REG		/* return success */
	/* Dtrace probe: LS_LCK_MTX_TRY_LOCK_ACQUIRE */
	LOCKSTAT_LABEL(_lck_mtx_try_lock_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_ACQUIRE, LMTX_REG)
#endif	
	mov	$1, LMTX_RET_REG		/* return success */
	ret

Llmt_slow:
	test	$(M_ILOCKED_MSK), LMTX_C_REG32	/* is the interlock held */
	jz	Llmt_fail			/* no, must be held as a mutex */

	cmp	$(MUTEX_DESTROYED), LMTX_C_REG32	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), LMTX_C_REG32	/* Is this an indirect mutex? */
	jne	Llmt_loop

	LMTX_ENTER_EXTENDED
Llmt_loop:
	PAUSE
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
Llmt_loop1:
	test	$(M_MLOCKED_MSK | M_SPIN_MSK), LMTX_C_REG32
	jnz	Llmt_fail
	test	$(M_ILOCKED_MSK), LMTX_C_REG32
	jz	Llmt_try
	jmp	Llmt_loop

Llmt_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llmt_loop


Llmt_fail:
Llmts_fail:
	LMTX_CHK_EXTENDED		/* is this an extended mutex */
	je	0f
	LMTX_UPDATE_MISS
	LMTX_EXIT_EXTENDED
0:
	xor	LMTX_RET_REG, LMTX_RET_REG
	NONLEAF_RET



NONLEAF_ENTRY(lck_mtx_convert_spin)
	LOAD_LMTX_REG(B_ARG0)			/* fetch lock pointer */

	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	cmp	$(MUTEX_IND), LMTX_C_REG32	/* Is this an indirect mutex? */
	jne	0f
	mov	M_PTR(LMTX_REG), LMTX_REG	/* If so, take indirection */
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
0:
	test	$(M_MLOCKED_MSK), LMTX_C_REG32	/* already owned as a mutex, just return */
	jnz	2f
	test	$(M_WAITERS_MSK), LMTX_C_REG32	/* are there any waiters? */
	jz	1f

	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
1:	
	and	$(~(M_ILOCKED_MSK | M_SPIN_MSK)), LMTX_C_REG32	/* convert from spin version to mutex */
	or	$(M_MLOCKED_MSK), LMTX_C_REG32
	mov	LMTX_C_REG32, M_STATE(LMTX_REG)		/* since I own the interlock, I don't need an atomic update */

	PREEMPTION_ENABLE
2:	
	NONLEAF_RET

	

#if	defined(__i386__)
NONLEAF_ENTRY(lck_mtx_unlock)
	LOAD_LMTX_REG(B_ARG0)			/* fetch lock pointer */
	mov	M_OWNER(LMTX_REG), LMTX_A_REG
	test	LMTX_A_REG, LMTX_A_REG
	jnz	Llmu_entry
	leave
	ret
NONLEAF_ENTRY(lck_mtx_unlock_darwin10)
#else
NONLEAF_ENTRY(lck_mtx_unlock)
#endif
	LOAD_LMTX_REG(B_ARG0)			/* fetch lock pointer */
Llmu_entry:
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
Llmu_prim:
	cmp	$(MUTEX_IND), LMTX_C_REG32	/* Is this an indirect mutex? */
	je	Llmu_ext

Llmu_chktype:
	test	$(M_MLOCKED_MSK), LMTX_C_REG32	/* check for full mutex */
	jz	Llmu_unlock
Llmu_mutex:
	test	$(M_ILOCKED_MSK), LMTX_C_REG	/* have to wait for interlock to clear */
	jnz	Llmu_busy

	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	and	$(~M_MLOCKED_MSK), LMTX_C_REG32	/* drop mutex */
	or	$(M_ILOCKED_MSK), LMTX_C_REG32	/* pick up interlock */

	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	Llmu_busy_disabled		/* branch on failure to spin loop */

Llmu_unlock:
	xor	LMTX_A_REG, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)
	mov	LMTX_C_REG, LMTX_A_REG			/* keep original state in %ecx for later evaluation */
	and	$(~(M_ILOCKED_MSK | M_SPIN_MSK | M_PROMOTED_MSK)), LMTX_A_REG

	test	$(M_WAITERS_MSK), LMTX_A_REG32
	jz	2f
	dec	LMTX_A_REG32				/* decrement waiter count */
2:	
	mov	LMTX_A_REG32, M_STATE(LMTX_REG)		/* since I own the interlock, I don't need an atomic update */

#if	MACH_LDEBUG
	/* perform lock statistics after drop to prevent delay */
	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	decl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	test	$(M_PROMOTED_MSK | M_WAITERS_MSK), LMTX_C_REG32
	jz	3f

	LMTX_CALLEXT2(lck_mtx_unlock_wakeup_x86, LMTX_C_REG)
3:	
	PREEMPTION_ENABLE

	LMTX_CHK_EXTENDED
	jne	4f

	leave
#if	CONFIG_DTRACE
	/* Dtrace: LS_LCK_MTX_UNLOCK_RELEASE */
	LOCKSTAT_LABEL(_lck_mtx_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, LMTX_REG)
#endif
	ret
4:	
	leave
#if	CONFIG_DTRACE
	/* Dtrace: LS_LCK_MTX_EXT_UNLOCK_RELEASE */
	LOCKSTAT_LABEL(_lck_mtx_ext_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in LMTX_REG from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_EXT_UNLOCK_RELEASE, LMTX_REG)
#endif
	ret


Llmu_busy_disabled:
	PREEMPTION_ENABLE
Llmu_busy:
	PAUSE
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	jmp	Llmu_mutex

Llmu_ext:
	mov	M_PTR(LMTX_REG), LMTX_REG
	mov	M_OWNER(LMTX_REG), LMTX_A_REG
	mov	%gs:CPU_ACTIVE_THREAD, LMTX_C_REG
	CHECK_UNLOCK(LMTX_C_REG, LMTX_A_REG)
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	jmp 	Llmu_chktype


	
LEAF_ENTRY(lck_mtx_ilk_unlock)
	LOAD_LMTX_REG(L_ARG0)			/* fetch lock pointer - no indirection here */

	andl	$(~M_ILOCKED_MSK), M_STATE(LMTX_REG)

	PREEMPTION_ENABLE			/* need to re-enable preemption */

	LEAF_RET
	

	
LEAF_ENTRY(lck_mtx_lock_grab_mutex)
	LOAD_LMTX_REG(L_ARG0)			/* fetch lock pointer - no indirection here */

	mov	M_STATE(LMTX_REG), LMTX_C_REG32

	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32	/* can't have the mutex yet */
	jnz	3f

	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_MLOCKED_MSK), LMTX_C_REG32

	PREEMPTION_DISABLE
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	2f				/* branch on failure to spin loop */

 	mov	%gs:CPU_ACTIVE_THREAD, LMTX_A_REG
	mov	LMTX_A_REG, M_OWNER(LMTX_REG)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	LMTX_A_REG, LMTX_A_REG
	jz	1f
	incl	TH_MUTEX_COUNT(LMTX_A_REG)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	mov	$1, LMTX_RET_REG		/* return success */
	LEAF_RET
2:						
	PREEMPTION_ENABLE
3:
	xor	LMTX_RET_REG, LMTX_RET_REG	/* return failure */
	LEAF_RET
	


LEAF_ENTRY(lck_mtx_lock_mark_destroyed)
	LOAD_LMTX_REG(L_ARG0)
1:
	mov	M_STATE(LMTX_REG), LMTX_C_REG32
	cmp	$(MUTEX_IND), LMTX_C_REG32	/* Is this an indirect mutex? */
	jne	2f

	movl	$(MUTEX_DESTROYED), M_STATE(LMTX_REG)	/* convert to destroyed state */
	jmp	3f
2:	
	test	$(M_ILOCKED_MSK), LMTX_C_REG	/* have to wait for interlock to clear */
	jnz	5f

	PREEMPTION_DISABLE
	mov	LMTX_C_REG, LMTX_A_REG		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK), LMTX_C_REG32
	lock
	cmpxchg LMTX_C_REG32, M_STATE(LMTX_REG)	/* atomic compare and exchange */
	jne	4f				/* branch on failure to spin loop */
	movl	$(MUTEX_DESTROYED), M_STATE(LMTX_REG)	/* convert to destroyed state */
	PREEMPTION_ENABLE
3:
	LEAF_RET				/* return with M_ILOCKED set */
4:
	PREEMPTION_ENABLE
5:
	PAUSE
	jmp	1b

LEAF_ENTRY(preemption_underflow_panic)
	FRAME
	incl	%gs:CPU_PREEMPTION_LEVEL
	ALIGN_STACK()
	LOAD_STRING_ARG0(16f)
	CALL_PANIC()
	hlt
	.data
16:	String	"Preemption level underflow, possible cause unlocking an unlocked mutex or spinlock"
	.text


LEAF_ENTRY(_disable_preemption)
#if	MACH_RT
	PREEMPTION_DISABLE
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_enable_preemption)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
#if __i386__
	pushl	%gs:CPU_PREEMPTION_LEVEL
#else
	movl	%gs:CPU_PREEMPTION_LEVEL,%esi
#endif
	ALIGN_STACK()
	LOAD_STRING_ARG0(_enable_preemption_less_than_zero)
	CALL_PANIC()
	hlt
	.cstring
_enable_preemption_less_than_zero:
	.asciz	"_enable_preemption: preemption_level(%d)  < 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	PREEMPTION_ENABLE
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_enable_preemption_no_check)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
	ALIGN_STACK()
	LOAD_STRING_ARG0(_enable_preemption_no_check_less_than_zero)
	CALL_PANIC()
	hlt
	.cstring
_enable_preemption_no_check_less_than_zero:
	.asciz	"_enable_preemption_no_check: preemption_level <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION_NO_CHECK
#endif	/* MACH_RT */
	LEAF_RET
	
	
LEAF_ENTRY(_mp_disable_preemption)
#if	MACH_RT
	PREEMPTION_DISABLE
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_mp_enable_preemption)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
#if __i386__
	pushl	%gs:CPU_PREEMPTION_LEVEL
#else
	movl	%gs:CPU_PREEMPTION_LEVEL,%esi
#endif
	ALIGN_PANIC()
	LOAD_STRING_ARG0(_mp_enable_preemption_less_than_zero)
	CALL_PANIC()
	hlt
	.cstring
_mp_enable_preemption_less_than_zero:
	.asciz "_mp_enable_preemption: preemption_level (%d) <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	PREEMPTION_ENABLE
#endif	/* MACH_RT */
	LEAF_RET

LEAF_ENTRY(_mp_enable_preemption_no_check)
#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	jg	1f
	ALIGN_STACK()
	LOAD_STRING_ARG0(_mp_enable_preemption_no_check_less_than_zero)
	CALL_PANIC()
	hlt
	.cstring
_mp_enable_preemption_no_check_less_than_zero:
	.asciz "_mp_enable_preemption_no_check: preemption_level <= 0!"
	.text
1:
#endif	/* MACH_ASSERT */
	_ENABLE_PREEMPTION_NO_CHECK
#endif	/* MACH_RT */
	LEAF_RET
	
#if __i386__
	
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
	andl	%edx, (%ecx)		/* Atomic AND */
	LEAF_RET

#else /* !__i386__ */

LEAF_ENTRY(i_bit_set)
	lock
	bts	%edi,(%rsi)
	LEAF_RET

LEAF_ENTRY(i_bit_clear)
	lock
	btr	%edi,(%rsi)
	LEAF_RET


LEAF_ENTRY(bit_lock)
1:
	lock
	bts	%edi,(%rsi)
	jb	1b
	LEAF_RET


LEAF_ENTRY(bit_lock_try)
	lock
	bts	%edi,(%rsi)
	jb	bit_lock_failed
	movl	$1, %eax
	LEAF_RET
bit_lock_failed:
	xorl	%eax,%eax
	LEAF_RET

LEAF_ENTRY(bit_unlock)
	lock
	btr	%edi,(%rsi)
	LEAF_RET

	
/*
 * Atomic primitives, prototyped in kern/simple_lock.h
 */
LEAF_ENTRY(hw_atomic_add)
	movl	%esi, %eax		/* Load addend */
	lock
	xaddl	%eax, (%rdi)		/* Atomic exchange and add */
	addl	%esi, %eax		/* Calculate result */
	LEAF_RET

LEAF_ENTRY(hw_atomic_sub)
	negl	%esi
	movl	%esi, %eax
	lock
	xaddl	%eax, (%rdi)		/* Atomic exchange and add */
	addl	%esi, %eax		/* Calculate result */
	LEAF_RET

LEAF_ENTRY(hw_atomic_or)
	movl	(%rdi), %eax
1:
	movl	%esi, %edx		/* Load mask */
	orl	%eax, %edx
	lock
	cmpxchgl	%edx, (%rdi)	/* Atomic CAS */
	jne	1b
	movl	%edx, %eax		/* Result */
	LEAF_RET
/*
 * A variant of hw_atomic_or which doesn't return a value.
 * The implementation is thus comparatively more efficient.
 */

LEAF_ENTRY(hw_atomic_or_noret)
	lock
	orl	%esi, (%rdi)		/* Atomic OR */
	LEAF_RET


LEAF_ENTRY(hw_atomic_and)
	movl	(%rdi), %eax
1:
	movl	%esi, %edx		/* Load mask */
	andl	%eax, %edx
	lock
	cmpxchgl	%edx, (%rdi)	/* Atomic CAS */
	jne	1b
	movl	%edx, %eax		/* Result */
	LEAF_RET
/*
 * A variant of hw_atomic_and which doesn't return a value.
 * The implementation is thus comparatively more efficient.
 */

LEAF_ENTRY(hw_atomic_and_noret)
	lock
	andl	%esi, (%rdi)		/* Atomic OR */
	LEAF_RET

#endif /* !__i386 __ */
