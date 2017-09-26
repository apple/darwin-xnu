/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <mach_ldebug.h>
#include <i386/asm.h>
#include <i386/eflags.h>
#include <i386/trap.h>
#include <config_dtrace.h>
#include <i386/mp.h>
	
#include "assym.s"

#define	PAUSE		rep; nop

#include <i386/pal_lock_asm.h>

#define LEAF_ENTRY(name)	\
	Entry(name)

#define LEAF_ENTRY2(n1,n2)	\
	Entry(n1);		\
	Entry(n2)

#define LEAF_RET		\
	ret

/* Non-leaf routines always have a stack frame: */

#define NONLEAF_ENTRY(name)	\
	Entry(name);		\
	FRAME

#define NONLEAF_ENTRY2(n1,n2)	\
	Entry(n1);		\
	Entry(n2);		\
	FRAME

#define NONLEAF_RET		\
	EMARF;			\
	ret


/* For x86_64, the varargs ABI requires that %al indicate
 * how many SSE register contain arguments. In our case, 0 */
#define ALIGN_STACK() 		and  $0xFFFFFFFFFFFFFFF0, %rsp ;
#define LOAD_STRING_ARG0(label)	leaq label(%rip), %rdi ;
#define LOAD_ARG1(x)		mov x, %esi ;
#define LOAD_PTR_ARG1(x)	mov x, %rsi ;
#define CALL_PANIC()		xorb %al,%al ; call EXT(panic) ;

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
#define	CHECK_MYLOCK(thd)
#endif	/* MACH_LDEBUG */

#if DEVELOPMENT || DEBUG
/*
 * If one or more simplelocks are currently held by a thread,
 * an attempt to acquire a mutex will cause this check to fail
 * (since a mutex lock may context switch, holding a simplelock
 * is not a good thing).
 */
#define CHECK_PREEMPTION_LEVEL()				\
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL		;	\
	je	1f					;	\
	cmpl    $0,EXT(LckDisablePreemptCheck)(%rip)	;	\
	jne	1f					;	\
	cmpl	$0,%gs:CPU_HIBERNATE			;	\
	jne	1f					;	\
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
#else /* DEVELOPMENT || DEBUG */
#define CHECK_PREEMPTION_LEVEL()
#endif /* DEVELOPMENT || DEBUG */

#define PREEMPTION_DISABLE				\
	incl	%gs:CPU_PREEMPTION_LEVEL

#define	PREEMPTION_LEVEL_DEBUG 1	
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

#endif /* CONFIG_DTRACE */

/*
 * For most routines, the hw_lock_t pointer is loaded into a
 * register initially, and then either a byte or register-sized
 * word is loaded/stored to the pointer
 */

/*
 *	void hw_lock_byte_init(volatile uint8_t *)
 *
 *	Initialize a hardware byte lock.
 */
LEAF_ENTRY(hw_lock_byte_init)
	movb	$0, (%rdi)		/* clear the lock */
	LEAF_RET

/*
 *	void	hw_lock_byte_lock(uint8_t *lock_byte)
 *
 *	Acquire byte sized lock operand, spinning until it becomes available.
 *	return with preemption disabled.
 */

LEAF_ENTRY(hw_lock_byte_lock)
	PREEMPTION_DISABLE
	movl	$1, %ecx		/* Set lock value */
1:
	movb	(%rdi), %al		/* Load byte at address */
	testb	%al,%al			/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchg %cl,(%rdi)	/* attempt atomic compare exchange */
	jne	3f
	LEAF_RET			/* if yes, then nothing left to do */
3:
	PAUSE				/* pause for hyper-threading */
	jmp	1b			/* try again */

/*
 *	void hw_lock_byte_unlock(uint8_t *lock_byte)
 *
 *	Unconditionally release byte sized lock operand,
 *	release preemption level.
 */

LEAF_ENTRY(hw_lock_byte_unlock)
	movb $0, (%rdi)		/* Clear the lock byte */
	PREEMPTION_ENABLE
	LEAF_RET
	
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
	

#define LMTX_ENTER_EXTENDED					\
	mov	M_PTR(%rdx), %rdx 			;	\
	xor	%r11, %r11				;	\
	mov	MUTEX_GRP(%rdx), %r10		 	;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incq	GRP_MTX_STAT_UTIL(%r10)


#if	LOG_FIRST_MISS_ALONE
#define LMTX_UPDATE_MISS					\
	test	$1, %r11 				;	\
	jnz	11f					;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_MISS(%r10)			;	\
	or	$1, %r11				;	\
11:
#else
#define LMTX_UPDATE_MISS					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_MISS(%r10)
#endif
	

#if	LOG_FIRST_MISS_ALONE
#define LMTX_UPDATE_WAIT					\
	test	$2, %r11 				;	\
	jnz	11f					;	\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_WAIT(%r10)			;	\
	or	$2, %r11				;	\
11:
#else
#define LMTX_UPDATE_WAIT					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_WAIT(%r10)
#endif


/*
 * Record the "direct wait" statistic, which indicates if a
 * miss proceeded to block directly without spinning--occurs
 * if the owner of the mutex isn't running on another processor
 * at the time of the check.
 */
#define LMTX_UPDATE_DIRECT_WAIT					\
	LOCK_IF_ATOMIC_STAT_UPDATES 			;	\
	incl	GRP_MTX_STAT_DIRECT_WAIT(%r10)

	
#define LMTX_CALLEXT1(func_name)		\
	cmp	%rdx, %rdi		;	\
	je	12f			;	\
	push	%r10			;	\
	push	%r11			;	\
12:	push	%rdi			;	\
	push	%rdx			;	\
	mov	%rdx, %rdi		;	\
	call	EXT(func_name)		;	\
	pop	%rdx			;	\
	pop	%rdi			;	\
	cmp	%rdx, %rdi		;	\
	je	12f			;	\
	pop	%r11			;	\
	pop	%r10			;	\
12:
	
#define LMTX_CALLEXT2(func_name, reg)		\
	cmp	%rdx, %rdi		;	\
	je	12f			;	\
	push	%r10			;	\
	push	%r11			;	\
12:	push	%rdi			;	\
	push	%rdx			;	\
	mov	reg, %rsi		;	\
	mov	%rdx, %rdi		;	\
	call	EXT(func_name)		;	\
	pop	%rdx			;	\
	pop	%rdi			;	\
	cmp	%rdx, %rdi		;	\
	je	12f			;	\
	pop	%r11			;	\
	pop	%r10			;	\
12:


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
        mov	%rdi, %rdx                   	/* Load lock address */
	mov	%gs:CPU_ACTIVE_THREAD, %rax	/* Load current thread */

	mov	M_STATE(%rdx), %ecx
	cmp	$(MUTEX_IND), %ecx		/* Is this an indirect mutex? */
	jne	0f
	mov	M_PTR(%rdx), %rdx		/* If so, take indirection */
0:	
	mov	M_OWNER(%rdx), %rcx		/* Load owner */
	cmp	$(MUTEX_ASSERT_OWNED), %rsi
	jne	2f				/* Assert ownership? */
	cmp	%rax, %rcx			/* Current thread match? */
	jne	3f				/* no, go panic */
	testl	$(M_ILOCKED_MSK | M_MLOCKED_MSK), M_STATE(%rdx)
	je	3f
1:						/* yes, we own it */
	NONLEAF_RET
2:
	cmp	%rax, %rcx			/* Current thread match? */
	jne	1b				/* No, return */
	ALIGN_STACK()
	LOAD_PTR_ARG1(%rdx)
	LOAD_STRING_ARG0(mutex_assert_owned_str)
	jmp	4f
3:
	ALIGN_STACK()
	LOAD_PTR_ARG1(%rdx)
	LOAD_STRING_ARG0(mutex_assert_not_owned_str)
4:
	CALL_PANIC()


lck_mtx_destroyed:
	ALIGN_STACK()
	LOAD_PTR_ARG1(%rdx)
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
 * lck_mtx_try_lock_spin()
 * lck_mtx_try_lock_spin_always()
 * lck_mtx_convert_spin()
 */
NONLEAF_ENTRY(lck_mtx_lock_spin_always)
	mov	%rdi, %rdx		/* fetch lock pointer */
	jmp     Llmls_avoid_check
	
NONLEAF_ENTRY(lck_mtx_lock_spin)
	mov	%rdi, %rdx		/* fetch lock pointer */

	CHECK_PREEMPTION_LEVEL()
Llmls_avoid_check:
	mov	M_STATE(%rdx), %ecx
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx	/* is the interlock or mutex held */
	jnz	Llmls_slow
Llmls_try:				/* no - can't be INDIRECT, DESTROYED or locked */
	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_SPIN_MSK), %ecx

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	Llmls_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, %rax
	mov	%rax, M_OWNER(%rdx)	/* record owner of interlock */
#if	MACH_LDEBUG
	test	%rax, %rax
	jz	1f
	incl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:	
#endif	/* MACH_LDEBUG */

	/* return with the interlock held and preemption disabled */
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_spin_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN_ACQUIRE, %rdx)
#endif
	ret

Llmls_slow:	
	test	$M_ILOCKED_MSK, %ecx		/* is the interlock held */
	jz	Llml_contended			/* no, must have been the mutex */

	cmp	$(MUTEX_DESTROYED), %ecx	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), %ecx		/* Is this an indirect mutex */
	jne	Llmls_loop			/* no... must be interlocked */

	LMTX_ENTER_EXTENDED

	mov	M_STATE(%rdx), %ecx
	test	$(M_SPIN_MSK), %ecx
	jz	Llmls_loop1

	LMTX_UPDATE_MISS		/* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
Llmls_loop:
	PAUSE
	mov	M_STATE(%rdx), %ecx
Llmls_loop1:
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx
	jz	Llmls_try
	test	$(M_MLOCKED_MSK), %ecx
	jnz	Llml_contended			/* mutex owned by someone else, go contend for it */
	jmp	Llmls_loop

Llmls_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llmls_loop


	
NONLEAF_ENTRY(lck_mtx_lock)
	mov	%rdi, %rdx		/* fetch lock pointer */

	CHECK_PREEMPTION_LEVEL()

	mov	M_STATE(%rdx), %ecx
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx	/* is the interlock or mutex held */
	jnz	Llml_slow
Llml_try:				/* no - can't be INDIRECT, DESTROYED or locked */
	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	Llml_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, %rax
	mov	%rax, M_OWNER(%rdx)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	%rax, %rax
	jz	1f
	incl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	testl	$(M_WAITERS_MSK), M_STATE(%rdx)
	jz	Llml_finish

	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)

Llml_finish:
	andl	$(~M_ILOCKED_MSK), M_STATE(%rdx)
	PREEMPTION_ENABLE
	
	cmp	%rdx, %rdi		/* is this an extended mutex */
	jne	2f

	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, %rdx)
#endif
	ret
2:	
	leave
#if	CONFIG_DTRACE
	LOCKSTAT_LABEL(_lck_mtx_lock_ext_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_ACQUIRE, %rdx)
#endif
	ret

	
Llml_slow:
	test	$M_ILOCKED_MSK, %ecx		/* is the interlock held */
	jz	Llml_contended			/* no, must have been the mutex */
	
	cmp	$(MUTEX_DESTROYED), %ecx	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), %ecx		/* Is this an indirect mutex? */
	jne	Llml_loop			/* no... must be interlocked */

	LMTX_ENTER_EXTENDED

	mov	M_STATE(%rdx), %ecx
	test	$(M_SPIN_MSK), %ecx
	jz	Llml_loop1

	LMTX_UPDATE_MISS		/* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
Llml_loop:
	PAUSE
	mov	M_STATE(%rdx), %ecx
Llml_loop1:
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx
	jz	Llml_try
	test	$(M_MLOCKED_MSK), %ecx
	jnz	Llml_contended			/* mutex owned by someone else, go contend for it */
	jmp	Llml_loop

Llml_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llml_loop

	
Llml_contended:
	cmp	%rdx, %rdi		/* is this an extended mutex */
	je	0f
	LMTX_UPDATE_MISS
0:	
	LMTX_CALLEXT1(lck_mtx_lock_spinwait_x86)

	test	%rax, %rax
	jz	Llml_acquired		/* acquired mutex, interlock held and preemption disabled */

	cmp	$1, %rax		/* check for direct wait status */
	je	2f
	cmp	%rdx, %rdi		/* is this an extended mutex */
	je	2f
	LMTX_UPDATE_DIRECT_WAIT
2:	
	mov	M_STATE(%rdx), %ecx
	test	$(M_ILOCKED_MSK), %ecx
	jnz	6f

	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK), %ecx	/* try to take the interlock */

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	5f

	test	$(M_MLOCKED_MSK), %ecx	/* we've got the interlock and */
	jnz	3f
	or	$(M_MLOCKED_MSK), %ecx	/* the mutex is free... grab it directly */
	mov	%ecx, M_STATE(%rdx)
	
 	mov	%gs:CPU_ACTIVE_THREAD, %rax
	mov	%rax, M_OWNER(%rdx)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	%rax, %rax
	jz	1f
	incl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

Llml_acquired:
	testl	$(M_WAITERS_MSK), M_STATE(%rdx)
	jnz	1f
	mov	M_OWNER(%rdx), %rax
	mov	TH_WAS_PROMOTED_ON_WAKEUP(%rax), %eax
	test	%eax, %eax
	jz	Llml_finish
1:	
	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)
	jmp	Llml_finish

3:					/* interlock held, mutex busy */
	cmp	%rdx, %rdi		/* is this an extended mutex */
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
	

NONLEAF_ENTRY(lck_mtx_try_lock_spin_always)
	mov	%rdi, %rdx		/* fetch lock pointer */
	jmp     Llmts_avoid_check

NONLEAF_ENTRY(lck_mtx_try_lock_spin)
	mov	%rdi, %rdx		/* fetch lock pointer */

Llmts_avoid_check:
	mov	M_STATE(%rdx), %ecx
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx	/* is the interlock or mutex held */
	jnz	Llmts_slow
Llmts_try:				/* no - can't be INDIRECT, DESTROYED or locked */
	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_SPIN_MSK), %rcx

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	Llmts_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, %rax
	mov	%rax, M_OWNER(%rdx)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	%rax, %rax
	jz	1f
	incl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	leave

#if	CONFIG_DTRACE
	mov	$1, %rax			/* return success */
	LOCKSTAT_LABEL(_lck_mtx_try_lock_spin_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx above */
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, %rdx)
#endif
	mov	$1, %rax			/* return success */
	ret

Llmts_slow:
	test	$(M_ILOCKED_MSK), %ecx	/* is the interlock held */
	jz	Llmts_fail			/* no, must be held as a mutex */

	cmp	$(MUTEX_DESTROYED), %ecx	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), %ecx		/* Is this an indirect mutex? */
	jne	Llmts_loop1

	LMTX_ENTER_EXTENDED
Llmts_loop:
	PAUSE
	mov	M_STATE(%rdx), %ecx
Llmts_loop1:
	test	$(M_MLOCKED_MSK | M_SPIN_MSK), %ecx
	jnz	Llmts_fail
	test	$(M_ILOCKED_MSK), %ecx
	jz	Llmts_try
	jmp	Llmts_loop
	
Llmts_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llmts_loop


	
NONLEAF_ENTRY(lck_mtx_try_lock)
	mov	%rdi, %rdx		/* fetch lock pointer */

	mov	M_STATE(%rdx), %ecx
	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx	/* is the interlock or mutex held */
	jnz	Llmt_slow	
Llmt_try:				/* no - can't be INDIRECT, DESTROYED or locked */
	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx
	
	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	Llmt_busy_disabled

 	mov	%gs:CPU_ACTIVE_THREAD, %rax
	mov	%rax, M_OWNER(%rdx)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	%rax, %rax
	jz	1f
	incl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	test	$(M_WAITERS_MSK), %ecx
	jz	0f

	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)
0:
	andl	$(~M_ILOCKED_MSK), M_STATE(%rdx)
	PREEMPTION_ENABLE

	leave
#if	CONFIG_DTRACE
	mov	$1, %rax			/* return success */
	/* Dtrace probe: LS_LCK_MTX_TRY_LOCK_ACQUIRE */
	LOCKSTAT_LABEL(_lck_mtx_try_lock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_ACQUIRE, %rdx)
#endif	
	mov	$1, %rax			/* return success */
	ret

Llmt_slow:
	test	$(M_ILOCKED_MSK), %ecx	/* is the interlock held */
	jz	Llmt_fail			/* no, must be held as a mutex */

	cmp	$(MUTEX_DESTROYED), %ecx	/* check to see if its marked destroyed */
	je	lck_mtx_destroyed
	cmp	$(MUTEX_IND), %ecx		/* Is this an indirect mutex? */
	jne	Llmt_loop

	LMTX_ENTER_EXTENDED
Llmt_loop:
	PAUSE
	mov	M_STATE(%rdx), %ecx
Llmt_loop1:
	test	$(M_MLOCKED_MSK | M_SPIN_MSK), %ecx
	jnz	Llmt_fail
	test	$(M_ILOCKED_MSK), %ecx
	jz	Llmt_try
	jmp	Llmt_loop

Llmt_busy_disabled:
	PREEMPTION_ENABLE
	jmp	Llmt_loop


Llmt_fail:
Llmts_fail:
	cmp	%rdx, %rdi			/* is this an extended mutex */
	je	0f
	LMTX_UPDATE_MISS
0:
	xor	%rax, %rax
	NONLEAF_RET



NONLEAF_ENTRY(lck_mtx_convert_spin)
	mov	%rdi, %rdx			/* fetch lock pointer */

	mov	M_STATE(%rdx), %ecx
	cmp	$(MUTEX_IND), %ecx		/* Is this an indirect mutex? */
	jne	0f
	mov	M_PTR(%rdx), %rdx		/* If so, take indirection */
	mov	M_STATE(%rdx), %ecx
0:
	test	$(M_MLOCKED_MSK), %ecx		/* already owned as a mutex, just return */
	jnz	2f
	test	$(M_WAITERS_MSK), %ecx		/* are there any waiters? */
	jz	1f

	LMTX_CALLEXT1(lck_mtx_lock_acquire_x86)
	mov	M_STATE(%rdx), %ecx
1:	
	and	$(~(M_ILOCKED_MSK | M_SPIN_MSK)), %ecx	/* convert from spin version to mutex */
	or	$(M_MLOCKED_MSK), %ecx
	mov	%ecx, M_STATE(%rdx)		/* since I own the interlock, I don't need an atomic update */

	PREEMPTION_ENABLE
2:	
	NONLEAF_RET

	

NONLEAF_ENTRY(lck_mtx_unlock)
	mov	%rdi, %rdx		/* fetch lock pointer */
Llmu_entry:
	mov	M_STATE(%rdx), %ecx
Llmu_prim:
	cmp	$(MUTEX_IND), %ecx	/* Is this an indirect mutex? */
	je	Llmu_ext

Llmu_chktype:
	test	$(M_MLOCKED_MSK), %ecx	/* check for full mutex */
	jz	Llmu_unlock
Llmu_mutex:
	test	$(M_ILOCKED_MSK), %rcx	/* have to wait for interlock to clear */
	jnz	Llmu_busy

	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	and	$(~M_MLOCKED_MSK), %ecx	/* drop mutex */
	or	$(M_ILOCKED_MSK), %ecx	/* pick up interlock */

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	Llmu_busy_disabled	/* branch on failure to spin loop */

Llmu_unlock:
	xor	%rax, %rax
	mov	%rax, M_OWNER(%rdx)
	mov	%rcx, %rax		/* keep original state in %ecx for later evaluation */
	and	$(~(M_ILOCKED_MSK | M_SPIN_MSK | M_PROMOTED_MSK)), %rax

	test	$(M_WAITERS_MSK), %eax
	jz	2f
	dec	%eax			/* decrement waiter count */
2:	
	mov	%eax, M_STATE(%rdx)	/* since I own the interlock, I don't need an atomic update */

#if	MACH_LDEBUG
	/* perform lock statistics after drop to prevent delay */
	mov	%gs:CPU_ACTIVE_THREAD, %rax
	test	%rax, %rax
	jz	1f
	decl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	test	$(M_PROMOTED_MSK | M_WAITERS_MSK), %ecx
	jz	3f

	LMTX_CALLEXT2(lck_mtx_unlock_wakeup_x86, %rcx)
3:	
	PREEMPTION_ENABLE

	cmp	%rdx, %rdi
	jne	4f

	leave
#if	CONFIG_DTRACE
	/* Dtrace: LS_LCK_MTX_UNLOCK_RELEASE */
	LOCKSTAT_LABEL(_lck_mtx_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, %rdx)
#endif
	ret
4:	
	leave
#if	CONFIG_DTRACE
	/* Dtrace: LS_LCK_MTX_EXT_UNLOCK_RELEASE */
	LOCKSTAT_LABEL(_lck_mtx_ext_unlock_lockstat_patch_point)
	ret
	/* inherit lock pointer in %rdx from above */
	LOCKSTAT_RECORD(LS_LCK_MTX_EXT_UNLOCK_RELEASE, %rdx)
#endif
	ret


Llmu_busy_disabled:
	PREEMPTION_ENABLE
Llmu_busy:
	PAUSE
	mov	M_STATE(%rdx), %ecx
	jmp	Llmu_mutex

Llmu_ext:
	mov	M_PTR(%rdx), %rdx
	mov	M_OWNER(%rdx), %rax
	mov	%gs:CPU_ACTIVE_THREAD, %rcx
	CHECK_UNLOCK(%rcx, %rax)
	mov	M_STATE(%rdx), %ecx
	jmp 	Llmu_chktype


	
LEAF_ENTRY(lck_mtx_ilk_try_lock)
	mov	%rdi, %rdx		/* fetch lock pointer - no indirection here */

	mov	M_STATE(%rdx), %ecx

	test	$(M_ILOCKED_MSK), %ecx	/* can't have the interlock yet */
	jnz	3f

	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK), %ecx

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	2f			/* return failure after re-enabling preemption */

	mov	$1, %rax		/* return success with preemption disabled */
	LEAF_RET
2:	
	PREEMPTION_ENABLE		/* need to re-enable preemption */
3:	
	xor	%rax, %rax		/* return failure */
	LEAF_RET
	

LEAF_ENTRY(lck_mtx_ilk_unlock)
	mov	%rdi, %rdx		/* fetch lock pointer - no indirection here */

	andl	$(~M_ILOCKED_MSK), M_STATE(%rdx)

	PREEMPTION_ENABLE		/* need to re-enable preemption */

	LEAF_RET

	
LEAF_ENTRY(lck_mtx_lock_grab_mutex)
	mov	%rdi, %rdx		/* fetch lock pointer - no indirection here */

	mov	M_STATE(%rdx), %ecx

	test	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx	/* can't have the mutex yet */
	jnz	3f

	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK | M_MLOCKED_MSK), %ecx

	PREEMPTION_DISABLE
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	2f				/* branch on failure to spin loop */

 	mov	%gs:CPU_ACTIVE_THREAD, %rax
	mov	%rax, M_OWNER(%rdx)	/* record owner of mutex */
#if	MACH_LDEBUG
	test	%rax, %rax
	jz	1f
	incl	TH_MUTEX_COUNT(%rax)	/* lock statistic */
1:
#endif	/* MACH_LDEBUG */

	mov	$1, %rax		/* return success */
	LEAF_RET
2:						
	PREEMPTION_ENABLE
3:
	xor	%rax, %rax	/* return failure */
	LEAF_RET
	


LEAF_ENTRY(lck_mtx_lock_mark_destroyed)
	mov	%rdi, %rdx
1:
	mov	M_STATE(%rdx), %ecx
	cmp	$(MUTEX_IND), %ecx	/* Is this an indirect mutex? */
	jne	2f

	movl	$(MUTEX_DESTROYED), M_STATE(%rdx)	/* convert to destroyed state */
	jmp	3f
2:	
	test	$(M_ILOCKED_MSK), %rcx	/* have to wait for interlock to clear */
	jnz	5f

	PREEMPTION_DISABLE
	mov	%rcx, %rax		/* eax contains snapshot for cmpxchgl */
	or	$(M_ILOCKED_MSK), %ecx
	lock
	cmpxchg %ecx, M_STATE(%rdx)	/* atomic compare and exchange */
	jne	4f			/* branch on failure to spin loop */
	movl	$(MUTEX_DESTROYED), M_STATE(%rdx)	/* convert to destroyed state */
	PREEMPTION_ENABLE
3:
	LEAF_RET			/* return with M_ILOCKED set */
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


