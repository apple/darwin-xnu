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
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach_rt.h>
#include <platforms.h>
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>
#include <stat_time.h>
#include <mach_assert.h>

#include <sys/errno.h>
#include <i386/asm.h>
#include <i386/cpuid.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/trap.h>
#include <assym.s>
#include <mach/exception_types.h>

#define _ARCH_I386_ASM_HELP_H_          /* Prevent inclusion of user header */
#include <mach/i386/syscall_sw.h>

#include <i386/mp.h>

/*
 * PTmap is recursive pagemap at top of virtual address space.
 * Within PTmap, the page directory can be found (third indirection).
*/
	.globl	_PTmap,_PTD,_PTDpde
	.set	_PTmap,(PTDPTDI << PDESHIFT)
	.set	_PTD,_PTmap + (PTDPTDI * NBPG)
	.set	_PTDpde,_PTD + (PTDPTDI * PDESIZE)

/*
 * APTmap, APTD is the alternate recursive pagemap.
 * It's used when modifying another process's page tables.
 */
	.globl	_APTmap,_APTD,_APTDpde
	.set	_APTmap,(APTDPTDI << PDESHIFT)
	.set	_APTD,_APTmap + (APTDPTDI * NBPG)
	.set	_APTDpde,_PTD + (APTDPTDI * PDESIZE)

#if __MACHO__
/* Under Mach-O, etext is a variable which contains
 * the last text address
 */
#define	ETEXT_ADDR	(EXT(etext))
#else
/* Under ELF and other non-Mach-O formats, the address of
 * etext represents the last text address
 */
#define ETEXT_ADDR	$ EXT(etext)
#endif

#define	CX(addr,reg)	addr(,reg,4)

/*
 * The following macros make calls into C code.
 * They dynamically align the stack to 16 bytes.
 * Arguments are moved (not pushed) onto the correctly aligned stack.
 * NOTE: EDI is destroyed in the process, and hence cannot
 * be directly used as a parameter. Users of this macro must
 * independently preserve EDI (a non-volatile) if the routine is
 * intended to be called from C, for instance.
 */

#define CCALL(fn)			\
	movl	%esp, %edi		;\
	andl	$0xFFFFFFF0, %esp	;\
	call	EXT(fn)			;\
	movl	%edi, %esp

#define CCALL1(fn, arg1)		\
	movl	%esp, %edi		;\
	subl	$4, %esp		;\
	andl	$0xFFFFFFF0, %esp	;\
	movl	arg1, 0(%esp)		;\
	call	EXT(fn)			;\
	movl	%edi, %esp

#define CCALL2(fn, arg1, arg2)		\
	movl	%esp, %edi		;\
	subl	$8, %esp		;\
	andl	$0xFFFFFFF0, %esp	;\
	movl	arg2, 4(%esp)		;\
	movl	arg1, 0(%esp)		;\
	call	EXT(fn)			;\
	movl	%edi, %esp

#define CCALL3(fn, arg1, arg2, arg3)	\
	movl	%esp, %edi		;\
	subl	$12, %esp		;\
	andl	$0xFFFFFFF0, %esp	;\
	movl	arg3, 8(%esp)		;\
	movl	arg2, 4(%esp)		;\
	movl	arg1, 0(%esp)		;\
	call	EXT(fn)			;\
	movl	%edi, %esp

	.text
locore_start:

/*
 * Fault recovery.
 */

#ifdef	__MACHO__
#define	RECOVERY_SECTION	.section	__VECTORS, __recover 
#else
#define	RECOVERY_SECTION	.text
#define	RECOVERY_SECTION	.text
#endif

#define	RECOVER_TABLE_START	\
	.align 2		; \
	.globl	EXT(recover_table) ;\
LEXT(recover_table)		;\
	.text

#define	RECOVER(addr)		\
	.align	2;		\
	.long	9f		;\
	.long	addr		;\
	.text			;\
9:

#define	RECOVER_TABLE_END		\
	.align	2			;\
	.globl	EXT(recover_table_end)	;\
LEXT(recover_table_end)			;\
	.text

/*
 * Allocate recovery and table.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_START

/*
 * Timing routines.
 */
Entry(timer_update)
	movl	4(%esp),%ecx
	movl	8(%esp),%eax
	movl	12(%esp),%edx
	movl	%eax,TIMER_HIGHCHK(%ecx)
	movl	%edx,TIMER_LOW(%ecx)
	movl	%eax,TIMER_HIGH(%ecx)
	ret

Entry(timer_grab)
	movl	4(%esp),%ecx
0:	movl	TIMER_HIGH(%ecx),%edx
	movl	TIMER_LOW(%ecx),%eax
	cmpl	TIMER_HIGHCHK(%ecx),%edx
	jne	0b
	ret

#if	STAT_TIME

#define	TIME_TRAP_UENTRY
#define	TIME_TRAP_UEXIT
#define	TIME_INT_ENTRY
#define	TIME_INT_EXIT

#else
/*
 * Nanosecond timing.
 */

/*
 * Nanotime returned in %edx:%eax.
 * Computed from tsc based on the scale factor
 * and an implicit 32 bit shift.
 * This code must match what _rtc_nanotime_read does in
 * i386/machine_routines_asm.s.  Failure to do so can
 * result in "weird" timing results.
 *
 * Uses %eax, %ebx, %ecx, %edx, %esi, %edi.
 */
#define RNT_INFO		_rtc_nanotime_info
#define NANOTIME							\
	lea	RNT_INFO,%edi						; \
0:									; \
	movl	RNT_GENERATION(%edi),%esi	/* being updated? */	; \
	testl	%esi,%esi						; \
	jz	0b				/* wait until done */	; \
	rdtsc								; \
	subl	RNT_TSC_BASE(%edi),%eax					; \
	sbbl	RNT_TSC_BASE+4(%edi),%edx	/* tsc - tsc_base */	; \
	movl	RNT_SCALE(%edi),%ecx		/* * scale factor */	; \
	movl	%edx,%ebx						; \
	mull	%ecx							; \
	movl	%ebx,%eax						; \
	movl	%edx,%ebx						; \
	mull	%ecx							; \
	addl	%ebx,%eax						; \
	adcl	$0,%edx							; \
	addl	RNT_NS_BASE(%edi),%eax		/* + ns_base */		; \
	adcl	RNT_NS_BASE+4(%edi),%edx				; \
	cmpl	RNT_GENERATION(%edi),%esi	/* check for update */	; \
	jne	0b				/* do it all again */


/*
 * Add 64-bit delta in register dreg : areg to timer pointed to by register treg.
 */
#define TIMER_UPDATE(treg,dreg,areg)									  \
	addl	TIMER_LOW(treg),areg		/* add low bits */				; \
	adcl	dreg,TIMER_HIGH(treg)		/* add carry high bits */		; \
	movl	areg,TIMER_LOW(treg)		/* store updated low bit */		; \
	movl	TIMER_HIGH(treg),dreg		/* copy high bits */			; \
	movl    dreg,TIMER_HIGHCHK(treg)	/* to high check */

/*
 * Add time delta to old timer and start new.
 */
#define TIMER_EVENT(old,new)											  \
	NANOTIME							/* edx:eax nanosecs */			; \
	movl	%eax,%esi					/* save timestamp */			; \
	movl	%edx,%edi					/* save timestamp */			; \
	movl	%gs:CPU_PROCESSOR,%ebx		/* get current processor */		; \
	movl 	THREAD_TIMER(%ebx),%ecx		/* get current timer */			; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */		; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */		; \
	TIMER_UPDATE(%ecx,%edx,%eax)		/* update timer */				; \
	addl	$(new##_TIMER-old##_TIMER),%ecx	/* point to new timer */	; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */				; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */				; \
	movl	%ecx,THREAD_TIMER(%ebx)		/* set current timer */			; \
	movl	%esi,%eax					/* restore timestamp */			; \
	movl	%edi,%edx					/* restore timestamp */			; \
	movl	CURRENT_STATE(%ebx),%ecx	/* current state */				; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */		; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */		; \
	TIMER_UPDATE(%ecx,%edx,%eax)		/* update timer */				; \
	addl	$(new##_STATE-old##_STATE),%ecx /* point to new state */	; \
	movl	%ecx,CURRENT_STATE(%ebx)	/* set current state */			; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */				; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */

/*
 * Update time on user trap entry.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 */
#define	TIME_TRAP_UENTRY	TIMER_EVENT(USER,SYSTEM)

/*
 * update time on user trap exit.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 */
#define	TIME_TRAP_UEXIT		TIMER_EVENT(SYSTEM,USER)

/*
 * update time on interrupt entry.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 * Saves processor state info on stack.
 */
#define	TIME_INT_ENTRY													  \
	NANOTIME							/* edx:eax nanosecs */			; \
	movl	%eax,%gs:CPU_INT_EVENT_TIME		/* save in cpu data */		; \
	movl	%edx,%gs:CPU_INT_EVENT_TIME+4	/* save in cpu data */		; \
	movl	%eax,%esi					/* save timestamp */			; \
	movl	%edx,%edi					/* save timestamp */			; \
	movl	%gs:CPU_PROCESSOR,%ebx		/* get current processor */		; \
	movl 	THREAD_TIMER(%ebx),%ecx		/* get current timer */			; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */		; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */		; \
	TIMER_UPDATE(%ecx,%edx,%eax)		/* update timer */				; \
	movl	KERNEL_TIMER(%ebx),%ecx		/* point to kernel timer */		; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */				; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */				; \
	movl	%esi,%eax					/* restore timestamp */			; \
	movl	%edi,%edx					/* restore timestamp */			; \
	movl	CURRENT_STATE(%ebx),%ecx	/* get current state */			; \
	pushl	%ecx						/* save state */				; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */		; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */		; \
	TIMER_UPDATE(%ecx,%edx,%eax)		/* update timer */				; \
	leal	IDLE_STATE(%ebx),%eax		/* get idle state */			; \
	cmpl	%eax,%ecx					/* compare current state */		; \
	je		0f							/* skip if equal */				; \
	leal	SYSTEM_STATE(%ebx),%ecx		/* get system state */			; \
	movl	%ecx,CURRENT_STATE(%ebx)	/* set current state */			; \
0:	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */				; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */

/*
 * update time on interrupt exit.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 * Restores processor state info from stack.
 */
#define	TIME_INT_EXIT													  \
	NANOTIME							/* edx:eax nanosecs */			; \
	movl	%eax,%gs:CPU_INT_EVENT_TIME		/* save in cpu data */		; \
	movl	%edx,%gs:CPU_INT_EVENT_TIME+4	/* save in cpu data */		; \
	movl	%eax,%esi					/* save timestamp */			; \
	movl	%edx,%edi					/* save timestamp */			; \
	movl	%gs:CPU_PROCESSOR,%ebx		/* get current processor */		; \
	movl	KERNEL_TIMER(%ebx),%ecx		/* point to kernel timer */		; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */		; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */		; \
	TIMER_UPDATE(%ecx,%edx,%eax)		/* update timer */				; \
	movl	THREAD_TIMER(%ebx),%ecx		/* interrupted timer */			; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */				; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */				; \
	movl	%esi,%eax					/* restore timestamp */			; \
	movl	%edi,%edx					/* restore timestamp */			; \
	movl	CURRENT_STATE(%ebx),%ecx	/* get current state */			; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */		; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */		; \
	TIMER_UPDATE(%ecx,%edx,%eax)		/* update timer */				; \
	popl	%ecx						/* restore state */				; \
	movl	%ecx,CURRENT_STATE(%ebx)	/* set current state */			; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */				; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */

#endif /* STAT_TIME */

#undef PDEBUG

#ifdef PDEBUG

/*
 * Traditional, not ANSI.
 */
#define CAH(label) \
	.data ;\
	.globl label/**/count ;\
label/**/count: ;\
	.long	0 ;\
	.globl label/**/limit ;\
label/**/limit: ;\
	.long	0 ;\
	.text ;\
	addl	$1,%ss:label/**/count ;\
	cmpl	$0,label/**/limit ;\
	jz	label/**/exit ;\
	pushl	%eax ;\
label/**/loop: ;\
	movl	%ss:label/**/count,%eax ;\
	cmpl	%eax,%ss:label/**/limit ;\
	je	label/**/loop ;\
	popl	%eax ;\
label/**/exit:

#else	/* PDEBUG */

#define CAH(label)

#endif	/* PDEBUG */
	
#if	MACH_KDB
/*
 * Last-ditch debug code to handle faults that might result
 * from entering kernel (from collocated server) on an invalid
 * stack.  On collocated entry, there's no hardware-initiated
 * stack switch, so a valid stack must be in place when an
 * exception occurs, or we may double-fault.
 *
 * In case of a double-fault, our only recourse is to switch
 * hardware "tasks", so that we avoid using the current stack.
 *
 * The idea here is just to get the processor into the debugger,
 * post-haste.  No attempt is made to fix up whatever error got
 * us here, so presumably continuing from the debugger will
 * simply land us here again -- at best.
 */
#if	0
/*
 * Note that the per-fault entry points are not currently
 * functional.  The only way to make them work would be to
 * set up separate TSS's for each fault type, which doesn't
 * currently seem worthwhile.  (The offset part of a task
 * gate is always ignored.)  So all faults that task switch
 * currently resume at db_task_start.
 */
/*
 * Double fault (Murphy's point) - error code (0) on stack
 */
Entry(db_task_dbl_fault)
	popl	%eax
	movl	$(T_DOUBLE_FAULT),%ebx
	jmp	db_task_start
/*
 * Segment not present - error code on stack
 */
Entry(db_task_seg_np)
	popl	%eax
	movl	$(T_SEGMENT_NOT_PRESENT),%ebx
	jmp	db_task_start
/*
 * Stack fault - error code on (current) stack
 */
Entry(db_task_stk_fault)
	popl	%eax
	movl	$(T_STACK_FAULT),%ebx
	jmp	db_task_start
/*
 * General protection fault - error code on stack
 */
Entry(db_task_gen_prot)
	popl	%eax
	movl	$(T_GENERAL_PROTECTION),%ebx
	jmp	db_task_start
#endif	/* 0 */
/*
 * The entry point where execution resumes after last-ditch debugger task
 * switch.
 */
Entry(db_task_start)
	movl	%esp,%edx
	subl	$(ISS32_SIZE),%edx
	movl	%edx,%esp		/* allocate x86_saved_state on stack */
	movl	%eax,R_ERR(%esp)
	movl	%ebx,R_TRAPNO(%esp)
	pushl	%edx
	CPU_NUMBER(%edx)
	movl	CX(EXT(master_dbtss),%edx),%edx
	movl	TSS_LINK(%edx),%eax
	pushl	%eax			/* pass along selector of previous TSS */
	call	EXT(db_tss_to_frame)
	popl	%eax			/* get rid of TSS selector */
	call	EXT(db_trap_from_asm)
	addl	$0x4,%esp
	/*
	 * And now...?
	 */
	iret				/* ha, ha, ha... */
#endif	/* MACH_KDB */

/*
 *	Called as a function, makes the current thread
 *	return from the kernel as if from an exception.
 */

	.globl	EXT(thread_exception_return)
	.globl	EXT(thread_bootstrap_return)
LEXT(thread_exception_return)
LEXT(thread_bootstrap_return)
	cli
	movl	%gs:CPU_KERNEL_STACK,%ecx
	movl	(%ecx),%esp			/* switch back to PCB stack */
	jmp	EXT(return_from_trap)

Entry(call_continuation)
	movl	S_ARG0,%eax			/* get continuation */
	movl	S_ARG1,%edx			/* continuation param */
	movl	S_ARG2,%ecx			/* wait result */
	movl	%gs:CPU_KERNEL_STACK,%esp	/* pop the stack */
	xorl	%ebp,%ebp			/* zero frame pointer */
	subl	$8,%esp				/* align the stack */
	pushl	%ecx
	pushl	%edx
	call	*%eax				/* call continuation */
	addl	$16,%esp
	movl	%gs:CPU_ACTIVE_THREAD,%eax
	pushl	%eax
	call	EXT(thread_terminate)
	
	
	
/*******************************************************************************************************
 *
 * All 64 bit task 'exceptions' enter lo_alltraps:
 *	esp	-> x86_saved_state_t
 * 
 * The rest of the state is set up as:	
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(lo_alltraps)
	movl	R_CS(%esp),%eax		/* assume 32-bit state */
	cmpl	$(SS_64),SS_FLAVOR(%esp)/* 64-bit? */	
	jne	1f
	movl	R64_CS(%esp),%eax	/* 64-bit user mode */
1:
	testb	$3,%al
	jz	trap_from_kernel
						/* user mode trap */
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	ACT_TASK(%ecx),%ebx

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp			/* switch to kernel stack */
	sti

	CCALL1(user_trap, %ebx)		/* call user trap routine */
	cli				/* hold off intrs - critical section */
	popl	%esp			/* switch back to PCB stack */

/*
 * Return from trap or system call, checking for ASTs.
 * On lowbase PCB stack with intrs disabled
 */	
LEXT(return_from_trap)
	movl	%gs:CPU_PENDING_AST,%eax
	testl	%eax,%eax
	je	EXT(return_to_user)	/* branch if no AST */

	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */
	sti				/* interrupts always enabled on return to user mode */

	pushl	%ebx			/* save PCB stack */
	xorl	%ebp,%ebp		/* Clear framepointer */
	CCALL1(i386_astintr, $0)	/* take the AST */
	cli
	popl	%esp			/* switch back to PCB stack (w/exc link) */
	jmp	EXT(return_from_trap)	/* and check again (rare) */

LEXT(return_to_user)
	TIME_TRAP_UEXIT

LEXT(ret_to_user)
	cmpl	$0, %gs:CPU_IS64BIT
	je	EXT(lo_ret_to_user)
	jmp	EXT(lo64_ret_to_user)



/*
 * Trap from kernel mode.  No need to switch stacks.
 * Interrupts must be off here - we will set them to state at time of trap
 * as soon as it's safe for us to do so and not recurse doing preemption
 */
trap_from_kernel:
	movl	%esp, %eax		/* saved state addr */
	pushl	R_EIP(%esp)		/* Simulate a CALL from fault point */
	pushl   %ebp			/* Extend framepointer chain */
	movl	%esp, %ebp
	CCALL1(kernel_trap, %eax)	/* Call kernel trap handler */
	popl	%ebp
	addl	$4, %esp
	cli

	movl	%gs:CPU_PENDING_AST,%eax		/* get pending asts */
	testl	$ AST_URGENT,%eax	/* any urgent preemption? */
	je	ret_to_kernel			/* no, nothing to do */
	cmpl	$ T_PREEMPT,R_TRAPNO(%esp)
	je	ret_to_kernel			  /* T_PREEMPT handled in kernel_trap() */
	testl	$ EFL_IF,R_EFLAGS(%esp)			/* interrupts disabled? */
	je	ret_to_kernel
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL		/* preemption disabled? */
	jne	ret_to_kernel
	movl	%gs:CPU_KERNEL_STACK,%eax
	movl	%esp,%ecx
	xorl	%eax,%ecx
	andl	$(-KERNEL_STACK_SIZE),%ecx
	testl	%ecx,%ecx		/* are we on the kernel stack? */
	jne	ret_to_kernel		/* no, skip it */

	CCALL1(i386_astintr, $1)	/* take the AST */

ret_to_kernel:
	cmpl	$0, %gs:CPU_IS64BIT
	je	EXT(lo_ret_to_kernel)
	jmp	EXT(lo64_ret_to_kernel)



/*******************************************************************************************************
 *
 * All interrupts on all tasks enter here with:
 *	esp->	 -> x86_saved_state_t
 *
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(lo_allintrs)
	/*
	 * test whether already on interrupt stack
	 */
	movl	%gs:CPU_INT_STACK_TOP,%ecx
	cmpl	%esp,%ecx
	jb	1f
	leal	-INTSTACK_SIZE(%ecx),%edx
	cmpl	%esp,%edx
	jb	int_from_intstack
1:	
	xchgl	%ecx,%esp		/* switch to interrupt stack */

	movl	%cr0,%eax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	movl	%eax,%cr0		/* set cr0 */

	subl	$8, %esp		/* for 16-byte stack alignment */
	pushl	%ecx			/* save pointer to old stack */
	movl	%ecx,%gs:CPU_INT_STATE	/* save intr state */
	
	TIME_INT_ENTRY			/* do timing */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	ACT_TASK(%ecx),%ebx

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL

	movl	%gs:CPU_INT_STATE, %eax
	CCALL1(PE_incoming_interrupt, %eax) /* call generic interrupt routine */

	cli				/* just in case we returned with intrs enabled */
	xorl	%eax,%eax
	movl	%eax,%gs:CPU_INT_STATE	/* clear intr state pointer */

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL

	TIME_INT_EXIT			/* do timing */

	movl	%gs:CPU_ACTIVE_THREAD,%eax
	movl	ACT_PCB(%eax),%eax	/* get act`s PCB */
	movl	PCB_FPS(%eax),%eax	/* get pcb's ims.ifps */
	cmpl	$0,%eax			/* Is there a context */
	je	1f			/* Branch if not */
	movl	FP_VALID(%eax),%eax	/* Load fp_valid */
	cmpl	$0,%eax			/* Check if valid */
	jne	1f			/* Branch if valid */
	clts				/* Clear TS */
	jmp	2f
1:
	movl	%cr0,%eax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	movl	%eax,%cr0		/* set cr0 */
2:
	popl	%esp			/* switch back to old stack */

	/* Load interrupted code segment into %eax */
	movl	R_CS(%esp),%eax		/* assume 32-bit state */
	cmpl	$(SS_64),SS_FLAVOR(%esp)/* 64-bit? */	
	jne	3f
	movl	R64_CS(%esp),%eax	/* 64-bit user mode */
3:
	testb	$3,%al			/* user mode, */
	jnz	ast_from_interrupt_user	/* go handle potential ASTs */
	/*
	 * we only want to handle preemption requests if
	 * the interrupt fell in the kernel context
	 * and preemption isn't disabled
	 */
	movl	%gs:CPU_PENDING_AST,%eax	
	testl	$ AST_URGENT,%eax		/* any urgent requests? */
	je	ret_to_kernel			/* no, nothing to do */

	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL	/* preemption disabled? */
	jne	ret_to_kernel			/* yes, skip it */

	movl	%gs:CPU_KERNEL_STACK,%eax
	movl	%esp,%ecx
	xorl	%eax,%ecx
	andl	$(-KERNEL_STACK_SIZE),%ecx
	testl	%ecx,%ecx			/* are we on the kernel stack? */
	jne	ret_to_kernel			/* no, skip it */

	/*
	 * Take an AST from kernel space.  We don't need (and don't want)
	 * to do as much as the case where the interrupt came from user
	 * space.
	 */
	CCALL1(i386_astintr, $1)

	jmp	ret_to_kernel


/*
 * nested int - simple path, can't preempt etc on way out
 */
int_from_intstack:
	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL

	movl	%esp, %edx		/* x86_saved_state */
	CCALL1(PE_incoming_interrupt, %edx)

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL

	jmp	ret_to_kernel

/*
 *	Take an AST from an interrupted user
 */
ast_from_interrupt_user:
	movl	%gs:CPU_PENDING_AST,%eax
	testl	%eax,%eax		/* pending ASTs? */
	je	EXT(ret_to_user)	/* no, nothing to do */

	TIME_TRAP_UENTRY

	jmp	EXT(return_from_trap)	/* return */


/*******************************************************************************************************
 *
 * 32bit Tasks
 * System call entries via INTR_GATE or sysenter:
 *
 *	esp	 -> x86_saved_state32_t
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(lo_sysenter)
	/*
	 * We can be here either for a mach syscall or a unix syscall,
	 * as indicated by the sign of the code:
	 */
	movl	R_EAX(%esp),%eax
	testl	%eax,%eax
	js	EXT(lo_mach_scall)		/* < 0 => mach */
						/* > 0 => unix */
	
Entry(lo_unix_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */
	addl	$1,TASK_SYSCALLS_UNIX(%ebx)	/* increment call count   */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	CCALL1(unix_syscall, %ebx)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo_mach_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */
	addl	$1,TASK_SYSCALLS_MACH(%ebx)	/* increment call count   */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	CCALL1(mach_call_munger, %ebx)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo_mdep_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	CCALL1(machdep_syscall, %ebx)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo_diag_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx	// Get the address of the kernel stack
	xchgl	%ebx,%esp		// Switch to it, saving the previous

	CCALL1(diagCall, %ebx)		// Call diagnostics
	
	cmpl	$0,%eax			// What kind of return is this?
	je	2f
	cli				// Disable interruptions just in case they were enabled
	popl	%esp			// Get back the original stack
	jmp	EXT(return_to_user)	// Normal return, do not check asts...
2:	
	CCALL3(i386_exception, $EXC_SYSCALL, $0x6000, $1)
		// pass what would be the diag syscall
		// error return - cause an exception
	/* no return */
	


/*******************************************************************************************************
 *
 * 64bit Tasks
 * System call entries via syscall only:
 *
 *	esp	 -> x86_saved_state64_t
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(lo_syscall)
	/*
	 * We can be here either for a mach, unix machdep or diag syscall,
	 * as indicated by the syscall class:
	 */
	movl	R64_RAX(%esp), %eax		/* syscall number/class */
	movl	%eax, %ebx
	andl	$(SYSCALL_CLASS_MASK), %ebx	/* syscall class */
	cmpl	$(SYSCALL_CLASS_MACH<<SYSCALL_CLASS_SHIFT), %ebx
	je	EXT(lo64_mach_scall)
	cmpl	$(SYSCALL_CLASS_UNIX<<SYSCALL_CLASS_SHIFT), %ebx
	je	EXT(lo64_unix_scall)
	cmpl	$(SYSCALL_CLASS_MDEP<<SYSCALL_CLASS_SHIFT), %ebx
	je	EXT(lo64_mdep_scall)
	cmpl	$(SYSCALL_CLASS_DIAG<<SYSCALL_CLASS_SHIFT), %ebx
	je	EXT(lo64_diag_scall)

	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	/* Syscall class unknown */
	CCALL3(i386_exception, $(EXC_SYSCALL), %eax, $1)
	/* no return */


Entry(lo64_unix_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */
	addl	$1,TASK_SYSCALLS_UNIX(%ebx)	/* increment call count   */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	CCALL1(unix_syscall64, %ebx)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo64_mach_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */
	addl	$1,TASK_SYSCALLS_MACH(%ebx)	/* increment call count   */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	CCALL1(mach_call_munger64, %ebx)
	/*
	 * always returns through thread_exception_return
	 */



Entry(lo64_mdep_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	sti

	CCALL1(machdep_syscall64, %ebx)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo64_diag_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	ACT_TASK(%ecx),%ebx			/* point to current task  */

	/* Check for active vtimers in the current task */
	cmpl	$0,TASK_VTIMERS(%ebx)
	jz		1f

	/* Set a pending AST */
	orl		$(AST_BSD),%gs:CPU_PENDING_AST

	/* Set a thread AST (atomic) */
	lock
	orl		$(AST_BSD),ACT_AST(%ecx)
	
1:
	movl	%gs:CPU_KERNEL_STACK,%ebx // Get the address of the kernel stack
	xchgl	%ebx,%esp		// Switch to it, saving the previous

	CCALL1(diagCall64, %ebx)	// Call diagnostics
		
	cmpl	$0,%eax			// What kind of return is this?
	je	2f
	cli				// Disable interruptions just in case they were enabled
	popl	%esp			// Get back the original stack
	jmp	EXT(return_to_user)	// Normal return, do not check asts...
2:	
	CCALL3(i386_exception, $EXC_SYSCALL, $0x6000, $1)
		// pass what would be the diag syscall
		// error return - cause an exception
	/* no return */

/**/
/*
 * Utility routines.
 */


/*
 * Copy from user/kernel address space.
 * arg0:	window offset or kernel address
 * arg1:	kernel address
 * arg2:	byte count
 */
Entry(copyinphys_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%ds

Entry(copyinphys_kern)
	movl	$(PHYS_WINDOW_SEL),%ecx	/* physical access through kernel window */
	mov	%cx,%es
	jmp	copyin_common

Entry(copyin_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%ds

Entry(copyin_kern)

copyin_common:
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get source - window offset or kernel address */
	movl	8+S_ARG1,%edi		/* get destination - kernel address */
	movl	8+S_ARG2,%edx		/* get count */

	cld				/* count up */
	movl	%edx,%ecx		/* move by longwords first */
	shrl	$2,%ecx
	RECOVERY_SECTION
	RECOVER(copyin_fail)
	rep
	movsl				/* move longwords */
	movl	%edx,%ecx		/* now move remaining bytes */
	andl	$3,%ecx
	RECOVERY_SECTION
	RECOVER(copyin_fail)
	rep
	movsb
	xorl	%eax,%eax		/* return 0 for success */
copyin_ret:
	mov	%ss,%cx			/* restore kernel data and extended segments */
	mov	%cx,%ds
	mov	%cx,%es

	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copyin_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	jmp	copyin_ret		/* pop frame and return */


	
/*
 * Copy string from user/kern address space.
 * arg0:	window offset or kernel address
 * arg1:	kernel address
 * arg2:	max byte count
 * arg3:	actual byte count (OUT)
 */
Entry(copyinstr_kern)
	mov	%ds,%cx
	jmp	copyinstr_common	

Entry(copyinstr_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */

copyinstr_common:
	mov	%cx,%fs

	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get source - window offset or kernel address */
	movl	8+S_ARG1,%edi		/* get destination - kernel address */
	movl	8+S_ARG2,%edx		/* get count */

	xorl	%eax,%eax		/* set to 0 here so that the high 24 bits */
					/* are 0 for the cmpl against 0 */
2:
	RECOVERY_SECTION
	RECOVER(copystr_fail)		/* copy bytes... */
	movb	%fs:(%esi),%al
	incl	%esi
	testl	%edi,%edi		/* if kernel address is ... */
	jz	3f			/* not NULL */
	movb	%al,(%edi)		/* copy the byte */
	incl	%edi
3:
	testl	%eax,%eax		/* did we just stuff the 0-byte? */
	jz	4f			/* yes, return 0 status already in %eax */
	decl	%edx			/* decrement #bytes left in buffer */
	jnz	2b			/* buffer not full so copy in another byte */
	movl	$(ENAMETOOLONG),%eax	/* buffer full but no 0-byte: ENAMETOOLONG */
4:
	movl	8+S_ARG3,%edi		/* get OUT len ptr */
	cmpl	$0,%edi
	jz	copystr_ret		/* if null, just return */
	subl	8+S_ARG0,%esi
	movl	%esi,(%edi)		/* else set OUT arg to xfer len */
copystr_ret:
	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copystr_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	jmp	copystr_ret		/* pop frame and return */


/*
 * Copy to user/kern address space.
 * arg0:	kernel address
 * arg1:	window offset or kernel address
 * arg2:	byte count
 */
ENTRY(copyoutphys_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%es

ENTRY(copyoutphys_kern)
	movl	$(PHYS_WINDOW_SEL),%ecx	/* physical access through kernel window */
	mov	%cx,%ds
	jmp	copyout_common

ENTRY(copyout_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%es

ENTRY(copyout_kern)

copyout_common:
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get source - kernel address */
	movl	8+S_ARG1,%edi		/* get destination - window offset or kernel address */
	movl	8+S_ARG2,%edx		/* get count */

	cld				/* count up */
	movl	%edx,%ecx		/* move by longwords first */
	shrl	$2,%ecx
	RECOVERY_SECTION
	RECOVER(copyout_fail)
	rep
	movsl
	movl	%edx,%ecx		/* now move remaining bytes */
	andl	$3,%ecx
	RECOVERY_SECTION
	RECOVER(copyout_fail)
	rep
	movsb				/* move */
	xorl	%eax,%eax		/* return 0 for success */
copyout_ret:
	mov	%ss,%cx			/* restore kernel segment */
	mov	%cx,%es
	mov	%cx,%ds

	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copyout_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	jmp	copyout_ret		/* pop frame and return */

/*
 * io register must not be used on slaves (no AT bus)
 */
#define	ILL_ON_SLAVE


#if	MACH_ASSERT

#define ARG0		B_ARG0
#define ARG1		B_ARG1
#define ARG2		B_ARG2
#define PUSH_FRAME	FRAME
#define POP_FRAME	EMARF

#else	/* MACH_ASSERT */

#define ARG0		S_ARG0
#define ARG1		S_ARG1
#define ARG2		S_ARG2
#define PUSH_FRAME	
#define POP_FRAME	

#endif	/* MACH_ASSERT */


#if	MACH_KDB || MACH_ASSERT

/*
 * Following routines are also defined as macros in i386/pio.h
 * Compile then when MACH_KDB is configured so that they
 * can be invoked from the debugger.
 */

/*
 * void outb(unsigned char *io_port,
 *	     unsigned char byte)
 *
 * Output a byte to an IO port.
 */
ENTRY(outb)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	ARG0,%edx		/* IO port address */
	movl	ARG1,%eax		/* data to output */
	outb	%al,%dx			/* send it out */
	POP_FRAME
	ret

/*
 * unsigned char inb(unsigned char *io_port)
 *
 * Input a byte from an IO port.
 */
ENTRY(inb)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	ARG0,%edx		/* IO port address */
	xor	%eax,%eax		/* clear high bits of register */
	inb	%dx,%al			/* get the byte */
	POP_FRAME
	ret

/*
 * void outw(unsigned short *io_port,
 *	     unsigned short word)
 *
 * Output a word to an IO port.
 */
ENTRY(outw)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	ARG0,%edx		/* IO port address */
	movl	ARG1,%eax		/* data to output */
	outw	%ax,%dx			/* send it out */
	POP_FRAME
	ret

/*
 * unsigned short inw(unsigned short *io_port)
 *
 * Input a word from an IO port.
 */
ENTRY(inw)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	ARG0,%edx		/* IO port address */
	xor	%eax,%eax		/* clear high bits of register */
	inw	%dx,%ax			/* get the word */
	POP_FRAME
	ret

/*
 * void outl(unsigned int *io_port,
 *	     unsigned int byte)
 *
 * Output an int to an IO port.
 */
ENTRY(outl)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	ARG0,%edx		/* IO port address*/
	movl	ARG1,%eax		/* data to output */
	outl	%eax,%dx		/* send it out */
	POP_FRAME
	ret

/*
 * unsigned int inl(unsigned int *io_port)
 *
 * Input an int from an IO port.
 */
ENTRY(inl)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	ARG0,%edx		/* IO port address */
	inl	%dx,%eax		/* get the int */
	POP_FRAME
	ret

#endif	/* MACH_KDB  || MACH_ASSERT*/

/*
 * void loutb(unsigned byte *io_port,
 *	      unsigned byte *data,
 *	      unsigned int count)
 *
 * Output an array of bytes to an IO port.
 */
ENTRY(loutb)
ENTRY(outsb)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	%esi,%eax		/* save register */
	movl	ARG0,%edx		/* get io port number */
	movl	ARG1,%esi		/* get data address */
	movl	ARG2,%ecx		/* get count */
	cld				/* count up */
	rep
	outsb				/* output */
	movl	%eax,%esi		/* restore register */
	POP_FRAME
	ret	


/*
 * void loutw(unsigned short *io_port,
 *	      unsigned short *data,
 *	      unsigned int count)
 *
 * Output an array of shorts to an IO port.
 */
ENTRY(loutw)
ENTRY(outsw)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	%esi,%eax		/* save register */
	movl	ARG0,%edx		/* get io port number */
	movl	ARG1,%esi		/* get data address */
	movl	ARG2,%ecx		/* get count */
	cld				/* count up */
	rep
	outsw				/* output */
	movl	%eax,%esi		/* restore register */
	POP_FRAME
	ret

/*
 * void loutw(unsigned short io_port,
 *	      unsigned int *data,
 *	      unsigned int count)
 *
 * Output an array of longs to an IO port.
 */
ENTRY(loutl)
ENTRY(outsl)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	%esi,%eax		/* save register */
	movl	ARG0,%edx		/* get io port number */
	movl	ARG1,%esi		/* get data address */
	movl	ARG2,%ecx		/* get count */
	cld				/* count up */
	rep
	outsl				/* output */
	movl	%eax,%esi		/* restore register */
	POP_FRAME
	ret


/*
 * void linb(unsigned char *io_port,
 *	     unsigned char *data,
 *	     unsigned int count)
 *
 * Input an array of bytes from an IO port.
 */
ENTRY(linb)
ENTRY(insb)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	%edi,%eax		/* save register */
	movl	ARG0,%edx		/* get io port number */
	movl	ARG1,%edi		/* get data address */
	movl	ARG2,%ecx		/* get count */
	cld				/* count up */
	rep
	insb				/* input */
	movl	%eax,%edi		/* restore register */
	POP_FRAME
	ret


/*
 * void linw(unsigned short *io_port,
 *	     unsigned short *data,
 *	     unsigned int count)
 *
 * Input an array of shorts from an IO port.
 */
ENTRY(linw)
ENTRY(insw)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	%edi,%eax		/* save register */
	movl	ARG0,%edx		/* get io port number */
	movl	ARG1,%edi		/* get data address */
	movl	ARG2,%ecx		/* get count */
	cld				/* count up */
	rep
	insw				/* input */
	movl	%eax,%edi		/* restore register */
	POP_FRAME
	ret


/*
 * void linl(unsigned short io_port,
 *	     unsigned int *data,
 *	     unsigned int count)
 *
 * Input an array of longs from an IO port.
 */
ENTRY(linl)
ENTRY(insl)
	PUSH_FRAME
	ILL_ON_SLAVE
	movl	%edi,%eax		/* save register */
	movl	ARG0,%edx		/* get io port number */
	movl	ARG1,%edi		/* get data address */
	movl	ARG2,%ecx		/* get count */
	cld				/* count up */
	rep
	insl				/* input */
	movl	%eax,%edi		/* restore register */
	POP_FRAME
	ret

/*
 * int rdmsr_carefully(uint32_t msr, uint32_t *lo, uint32_t *hi)
 */
ENTRY(rdmsr_carefully)
	movl	S_ARG0, %ecx
	RECOVERY_SECTION
	RECOVER(rdmsr_fail)
	rdmsr
	movl	S_ARG1, %ecx
	movl	%eax, (%ecx)
	movl	S_ARG2, %ecx
	movl	%edx, (%ecx)
	movl	$0, %eax
	ret

rdmsr_fail:
	movl	$1, %eax
	ret

/*
 * Done with recovery table.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_END

	.data
dr_msk:
	.long	~0x000f0003
	.long	~0x00f0000c
	.long	~0x0f000030
	.long	~0xf00000c0
ENTRY(dr_addr)
	.long	0,0,0,0
	.long	0,0,0,0

	.text

#ifndef	SYMMETRY

/*
 * ffs(mask)
 */
ENTRY(ffs)
	bsfl	S_ARG0, %eax
	jz	0f
	incl	%eax
	ret
0:	xorl	%eax, %eax
	ret

/*
 * cpu_shutdown()
 * Force reboot
 */

null_idtr:
	.word	0
	.long	0

Entry(cpu_shutdown)
        lidt    null_idtr       /* disable the interrupt handler */
        xor     %ecx,%ecx       /* generate a divide by zero */
        div     %ecx,%eax       /* reboot now */
        ret                     /* this will "never" be executed */

#endif	/* SYMMETRY */


/*
 * setbit(int bitno, int *s) - set bit in bit string
 */
ENTRY(setbit)
	movl	S_ARG0, %ecx		/* bit number */
	movl	S_ARG1, %eax		/* address */
	btsl	%ecx, (%eax)		/* set bit */
	ret

/*
 * clrbit(int bitno, int *s) - clear bit in bit string
 */
ENTRY(clrbit)
	movl	S_ARG0, %ecx		/* bit number */
	movl	S_ARG1, %eax		/* address */
	btrl	%ecx, (%eax)		/* clear bit */
	ret

/*
 * ffsbit(int *s) - find first set bit in bit string
 */
ENTRY(ffsbit)
	movl	S_ARG0, %ecx		/* address */
	movl	$0, %edx		/* base offset */
0:
	bsfl	(%ecx), %eax		/* check argument bits */
	jnz	1f			/* found bit, return */
	addl	$4, %ecx		/* increment address */
	addl	$32, %edx		/* increment offset */
	jmp	0b			/* try again */
1:
	addl	%edx, %eax		/* return offset */
	ret

/*
 * testbit(int nr, volatile void *array)
 *
 * Test to see if the bit is set within the bit string
 */

ENTRY(testbit)
	movl	S_ARG0,%eax	/* Get the bit to test */
	movl	S_ARG1,%ecx	/* get the array string */
	btl	%eax,(%ecx)
	sbbl	%eax,%eax
	ret

ENTRY(get_pc)
	movl	4(%ebp),%eax
	ret

ENTRY(minsecurity)
	pushl	%ebp
	movl	%esp,%ebp
/*
 * jail: set the EIP to "jail" to block a kernel thread.
 * Useful to debug synchronization problems on MPs.
 */
ENTRY(jail)
	jmp	EXT(jail)

/*
 * unsigned int
 * div_scale(unsigned int dividend,
 *	     unsigned int divisor,
 *	     unsigned int *scale)
 *
 * This function returns (dividend << *scale) //divisor where *scale
 * is the largest possible value before overflow. This is used in
 * computation where precision must be achieved in order to avoid
 * floating point usage.
 *
 * Algorithm:
 *	*scale = 0;
 *	while (((dividend >> *scale) >= divisor))
 *		(*scale)++;
 *	*scale = 32 - *scale;
 *	return ((dividend << *scale) / divisor);  
 */
ENTRY(div_scale)
	PUSH_FRAME
	xorl	%ecx, %ecx		/* *scale = 0 */
	xorl	%eax, %eax
	movl	ARG0, %edx		/* get dividend */
0:
	cmpl	ARG1, %edx 		/* if (divisor > dividend) */
	jle	1f			/* goto 1f */
	addl	$1, %ecx		/* (*scale)++ */
	shrdl	$1, %edx, %eax		/* dividend >> 1 */
	shrl	$1, %edx 		/* dividend >> 1 */
	jmp	0b			/* goto 0b */
1:	
	divl	ARG1			/* (dividend << (32 - *scale)) / divisor */
	movl	ARG2, %edx		/* get scale */
	movl	$32, (%edx)		/* *scale = 32 */
	subl	%ecx, (%edx)		/* *scale -= %ecx */
	POP_FRAME
	ret

/*
 * unsigned int
 * mul_scale(unsigned int multiplicand,
 *	     unsigned int multiplier,
 *	     unsigned int *scale)
 *
 * This function returns ((multiplicand * multiplier) >> *scale) where
 * scale is the largest possible value before overflow. This is used in
 * computation where precision must be achieved in order to avoid
 * floating point usage.
 *
 * Algorithm:
 *	*scale = 0;
 *	while (overflow((multiplicand * multiplier) >> *scale))
 *		(*scale)++;
 *	return ((multiplicand * multiplier) >> *scale);
 */
ENTRY(mul_scale)
	PUSH_FRAME
	xorl	%ecx, %ecx		/* *scale = 0 */
	movl	ARG0, %eax		/* get multiplicand */
	mull	ARG1			/* multiplicand * multiplier */
0:
	cmpl	$0, %edx		/* if (!overflow()) */
	je	1f			/* goto 1 */
	addl	$1, %ecx		/* (*scale)++ */
	shrdl	$1, %edx, %eax		/* (multiplicand * multiplier) >> 1 */
	shrl	$1, %edx		/* (multiplicand * multiplier) >> 1 */
	jmp	0b
1:
	movl	ARG2, %edx		/* get scale */
	movl	%ecx, (%edx)		/* set *scale */
	POP_FRAME
	ret


	
/*
 * Double-fault exception handler task. The last gasp...
 */
Entry(df_task_start)
	CCALL1(panic_double_fault, $(T_DOUBLE_FAULT))
	hlt


/*
 * machine-check handler task. The last gasp...
 */
Entry(mc_task_start)
	CCALL1(panic_machine_check, $(T_MACHINE_CHECK))
	hlt

/*
 * Compatibility mode's last gasp...
 */
Entry(lo_df64)
	movl	%esp, %eax
	CCALL1(panic_double_fault64, %eax)
	hlt

Entry(lo_mc64)
	movl	%esp, %eax
	CCALL1(panic_machine_check64, %eax)
	hlt

