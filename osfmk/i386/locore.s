/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <i386/mp.h>

#define	PREEMPT_DEBUG_LOG 0


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

	.text
locore_start:

/*
 * Fault recovery.
 */

#ifdef	__MACHO__
#define	RECOVERY_SECTION	.section	__VECTORS, __recover 
#define	RETRY_SECTION	.section	__VECTORS, __retries
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
 * Retry table for certain successful faults.
 */
#define	RETRY_TABLE_START	\
	.align	3;		\
	.globl	EXT(retry_table) ;\
LEXT(retry_table)		;\
	.text

#define	RETRY(addr)		\
	.align 3		;\
	.long	9f		;\
	.long	addr		;\
	.text			;\
9:

#define	RETRY_TABLE_END			\
	.align 3;			\
	.globl	EXT(retry_table_end)	;\
LEXT(retry_table_end)			;\
	.text

/*
 * Allocate recovery and retry tables.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_START
	RETRY_SECTION
	RETRY_TABLE_START

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
 * Low 32-bits of nanotime returned in %eax.
 * Computed from tsc using conversion scale/shift from per-cpu data.
 * Uses %ecx and %edx.
 */
#define NANOTIME32							      \
	pushl	%esi				/* save %esi              */ ;\
	movl	%gs:CPU_THIS,%esi		/* per-cpu data ptr       */ ;\
	addl	$(CPU_RTC_NANOTIME),%esi	/* esi -> per-cpu nanotime*/ ;\
	rdtsc					/* edx:eax = tsc          */ ;\
	subl	RTN_TSC(%esi),%eax		/* eax = (tsc - base_tsc) */ ;\
	mull	RTN_SCALE(%esi)			/* eax *= scale           */ ;\
	movl	RTN_SHIFT(%esi),%ecx		/* ecx = shift            */ ;\
	shrdl	%cl,%edx,%eax			/* edx:eax >> shift       */ ;\
	andb	$32,%cl				/* shift == 32?           */ ;\
	cmovnel	%edx,%eax			/* %eax = %edx if so      */ ;\
	addl	RTN_NANOS(%esi),%eax		/* add base ns            */ ;\
	popl	%esi

/*
 * Add 32-bit ns delta in register dreg to timer pointed to by register treg.
 */
#define TIMER_UPDATE(treg,dreg)						      \
	addl	TIMER_LOW(treg),dreg		/* add delta low bits     */ ;\
	adcl	$0,TIMER_HIGHCHK(treg)		/* add carry check bits   */ ;\
	movl	dreg,TIMER_LOW(treg)		/* store updated low bit  */ ;\
	movl	TIMER_HIGHCHK(treg),dreg	/* copy high check bits	  */ ;\
	movl    dreg,TIMER_HIGH(treg)		/*   to high bita         */

/*
 * Add time delta to old timer and start new.
 */
#define TIMER_EVENT(old,new)                                                  \
	pushl	%eax				/* must be invariant	  */ ;\
	cli					/* block interrupts       */ ;\
	NANOTIME32				/* eax low bits nanosecs  */ ;\
	movl	%gs:CPU_PROCESSOR,%ecx		/* get current processor  */ ;\
	movl 	CURRENT_TIMER(%ecx),%ecx	/* get current timer      */ ;\
	movl	%eax,%edx			/* save timestamp in %edx */ ;\
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time   */ ;\
	TIMER_UPDATE(%ecx,%eax)			/* update timer struct    */ ;\
	addl	$(new##_TIMER-old##_TIMER),%ecx	/* point to new timer     */ ;\
	movl	%edx,TIMER_TSTAMP(%ecx)		/* set timestamp          */ ;\
	movl	%gs:CPU_PROCESSOR,%edx		/* get current processor  */ ;\
	movl	%ecx,CURRENT_TIMER(%edx)	/* set current timer      */ ;\
	sti					/* interrupts on          */ ;\
	popl	%eax				/* must be invariant	  */

/*
 * Update time on user trap entry.
 * Uses %ecx,%edx.
 */
#define	TIME_TRAP_UENTRY	TIMER_EVENT(USER,SYSTEM)

/*
 * update time on user trap exit.
 * Uses %ecx,%edx.
 */
#define	TIME_TRAP_UEXIT		TIMER_EVENT(SYSTEM,USER)

/*
 * update time on interrupt entry.
 * Uses %eax,%ecx,%edx.
 */
#define	TIME_INT_ENTRY \
	NANOTIME32				/* eax low bits nanosecs  */ ;\
	movl	%gs:CPU_PROCESSOR,%ecx		/* get current processor  */ ;\
	movl 	CURRENT_TIMER(%ecx),%ecx	/* get current timer      */ ;\
	movl	%eax,%edx			/* save timestamp in %edx */ ;\
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time   */ ;\
	TIMER_UPDATE(%ecx,%eax)			/* update timer struct    */ ;\
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */ ;\
	addl	$(SYSTEM_TIMER),%ecx		/* point to sys timer     */ ;\
	movl	%edx,TIMER_TSTAMP(%ecx)		/* set timestamp          */

/*
 * update time on interrupt exit.
 * Uses %eax, %ecx, %edx.
 */
#define	TIME_INT_EXIT \
	NANOTIME32				/* eax low bits nanosecs  */ ;\
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */ ;\
	addl	$(SYSTEM_TIMER),%ecx		/* point to sys timer 	  */ ;\
	movl	%eax,%edx			/* save timestamp in %edx */ ;\
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time   */ ;\
	TIMER_UPDATE(%ecx,%eax)			/* update timer struct    */ ;\
	movl	%gs:CPU_PROCESSOR,%ecx		/* get current processor  */ ;\
	movl	CURRENT_TIMER(%ecx),%ecx	/* interrupted timer      */ ;\
	movl	%edx,TIMER_TSTAMP(%ecx)		/* set timestamp          */

#endif /* STAT_TIME */

/*
 * Encapsulate the transfer of exception stack frames between a PCB
 * and a thread stack.  Since the whole point of these is to emulate
 * a call or exception that changes privilege level, both macros
 * assume that there is no user esp or ss stored in the source
 * frame (because there was no change of privilege to generate them).
 */

/*
 * Transfer a stack frame from a thread's user stack to its PCB.
 * We assume the thread and stack addresses have been loaded into
 * registers (our arguments).
 *
 * The macro overwrites edi, esi, ecx and whatever registers hold the
 * thread and stack addresses (which can't be one of the above three).
 * The thread address is overwritten with the address of its saved state
 * (where the frame winds up).
 *
 * Must be called on kernel stack.
 */
#define FRAME_STACK_TO_PCB(thread, stkp)				;\
	movl	ACT_PCB(thread),thread	/* get act`s PCB */		;\
	leal	PCB_ISS(thread),%edi	/* point to PCB`s saved state */;\
	movl	%edi,thread		/* save for later */		;\
	movl	stkp,%esi		/* point to start of frame */	;\
	movl	$ R_UESP,%ecx						;\
	sarl	$2,%ecx			/* word count for transfer */	;\
	cld				/* we`re incrementing */	;\
	rep								;\
	movsl				/* transfer the frame */	;\
	addl	$ R_UESP,stkp		/* derive true "user" esp */	;\
	movl	stkp,R_UESP(thread)	/* store in PCB */		;\
	movl	$0,%ecx							;\
	mov	%ss,%cx			/* get current ss */		;\
	movl	%ecx,R_SS(thread)	/* store in PCB */

/*
 * Transfer a stack frame from a thread's PCB to the stack pointed
 * to by the PCB.  We assume the thread address has been loaded into
 * a register (our argument).
 *
 * The macro overwrites edi, esi, ecx and whatever register holds the
 * thread address (which can't be one of the above three).  The
 * thread address is overwritten with the address of its saved state
 * (where the frame winds up).
 *
 * Must be called on kernel stack.
 */
#define FRAME_PCB_TO_STACK(thread)					;\
	movl	ACT_PCB(thread),%esi	/* get act`s PCB */		;\
	leal	PCB_ISS(%esi),%esi	/* point to PCB`s saved state */;\
	movl	R_UESP(%esi),%edi	/* point to end of dest frame */;\
	movl	ACT_MAP(thread),%ecx	/* get act's map */		;\
	movl	MAP_PMAP(%ecx),%ecx	/* get map's pmap */		;\
	cmpl	EXT(kernel_pmap), %ecx	/* If kernel loaded task */	;\
	jz	1f			/* use kernel data segment */	;\
	movl	$ USER_DS,%cx		/* else use user data segment */;\
	mov	%cx,%es							;\
1:									;\
	movl	$ R_UESP,%ecx						;\
	subl	%ecx,%edi		/* derive start of frame */	;\
	movl	%edi,thread		/* save for later */		;\
	sarl	$2,%ecx			/* word count for transfer */	;\
	cld				/* we`re incrementing */	;\
	rep								;\
	movsl				/* transfer the frame */	;\
	mov	%ss,%cx			/* restore kernel segments */	;\
	mov	%cx,%es							

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
	subl	$ISS_SIZE,%edx
	movl	%edx,%esp		/* allocate i386_saved_state on stack */
	movl	%eax,R_ERR(%esp)
	movl	%ebx,R_TRAPNO(%esp)
	pushl	%edx
	CPU_NUMBER(%edx)
	movl	CX(EXT(mp_dbtss),%edx),%edx
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
 * Trap/interrupt entry points.
 *
 * All traps must create the following save area on the PCB "stack":
 *
 *	gs
 *	fs
 *	es
 *	ds
 *	edi
 *	esi
 *	ebp
 *	cr2 if page fault - otherwise unused
 *	ebx
 *	edx
 *	ecx
 *	eax
 *	trap number
 *	error code
 *	eip
 *	cs
 *	eflags
 *	user esp - if from user
 *	user ss  - if from user
 *	es       - if from V86 thread
 *	ds       - if from V86 thread
 *	fs       - if from V86 thread
 *	gs       - if from V86 thread
 *
 */

/*
 * General protection or segment-not-present fault.
 * Check for a GP/NP fault in the kernel_return
 * sequence; if there, report it as a GP/NP fault on the user's instruction.
 *
 * esp->     0:	trap code (NP or GP)
 *	     4:	segment number in error
 *	     8	eip
 *	    12	cs
 *	    16	eflags
 *	    20	old registers (trap is from kernel)
 */
Entry(t_gen_prot)
	pushl	$(T_GENERAL_PROTECTION)	/* indicate fault type */
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(t_segnp)
	pushl	$(T_SEGMENT_NOT_PRESENT)
					/* indicate fault type */

trap_check_kernel_exit:
	testl	$(EFL_VM),16(%esp)	/* is trap from V86 mode? */
	jnz	EXT(alltraps)		/* isn`t kernel trap if so */
	testl	$3,12(%esp)		/* is trap from kernel mode? */
	jne	EXT(alltraps)		/* if so: */
					/* check for the kernel exit sequence */
	cmpl	$ EXT(kret_iret),8(%esp)	/* on IRET? */
	je	fault_iret
	cmpl	$ EXT(kret_popl_ds),8(%esp) /* popping DS? */
	je	fault_popl_ds
	cmpl	$ EXT(kret_popl_es),8(%esp) /* popping ES? */
	je	fault_popl_es
	cmpl	$ EXT(kret_popl_fs),8(%esp) /* popping FS? */
	je	fault_popl_fs
	cmpl	$ EXT(kret_popl_gs),8(%esp) /* popping GS? */
	je	fault_popl_gs
take_fault:				/* if none of the above: */
	jmp	EXT(alltraps)		/* treat as normal trap. */

/*
 * GP/NP fault on IRET: CS or SS is in error.
 * All registers contain the user's values.
 *
 * on SP is
 *  0	trap number
 *  4	errcode
 *  8	eip
 * 12	cs		--> trapno
 * 16	efl		--> errcode
 * 20	user eip
 * 24	user cs
 * 28	user eflags
 * 32	user esp
 * 36	user ss
 */
fault_iret:
	movl	%eax,8(%esp)		/* save eax (we don`t need saved eip) */
	popl	%eax			/* get trap number */
	movl	%eax,12-4(%esp)		/* put in user trap number */
	popl	%eax			/* get error code */
	movl	%eax,16-8(%esp)		/* put in user errcode */
	popl	%eax			/* restore eax */
	CAH(fltir)
	jmp	EXT(alltraps)		/* take fault */

/*
 * Fault restoring a segment register.  The user's registers are still
 * saved on the stack.  The offending segment register has not been
 * popped.
 */
fault_popl_ds:
	popl	%eax			/* get trap number */
	popl	%edx			/* get error code */
	addl	$12,%esp		/* pop stack to user regs */
	jmp	push_es			/* (DS on top of stack) */
fault_popl_es:
	popl	%eax			/* get trap number */
	popl	%edx			/* get error code */
	addl	$12,%esp		/* pop stack to user regs */
	jmp	push_fs			/* (ES on top of stack) */
fault_popl_fs:
	popl	%eax			/* get trap number */
	popl	%edx			/* get error code */
	addl	$12,%esp		/* pop stack to user regs */
	jmp	push_gs			/* (FS on top of stack) */
fault_popl_gs:
	popl	%eax			/* get trap number */
	popl	%edx			/* get error code */
	addl	$12,%esp		/* pop stack to user regs */
	jmp	push_segregs		/* (GS on top of stack) */

push_es:
	pushl	%es			/* restore es, */
push_fs:
	pushl	%fs			/* restore fs, */
push_gs:
	pushl	%gs			/* restore gs. */
push_segregs:
	movl	%eax,R_TRAPNO(%esp)	/* set trap number */
	movl	%edx,R_ERR(%esp)	/* set error code */
	CAH(fltpp)
	jmp	trap_set_segs		/* take trap */

/*
 * Debug trap.  Check for single-stepping across system call into
 * kernel.  If this is the case, taking the debug trap has turned
 * off single-stepping - save the flags register with the trace
 * bit set.
 */
Entry(t_debug)
	testl	$(EFL_VM),8(%esp)	/* is trap from V86 mode? */
	jnz	0f			/* isn`t kernel trap if so */
	testl	$3,4(%esp)		/* is trap from kernel mode? */
	jnz	0f			/* if so: */
	cmpl	$syscall_entry,(%esp)	/* system call entry? */
	jne	1f			/* if so: */
					/* flags are sitting where syscall */
					/* wants them */
	addl	$8,%esp			/* remove eip/cs */
	jmp	syscall_entry_2		/* continue system call entry */

1:	cmpl	$trap_unix_addr,(%esp)
	jne	0f
	addl	$8,%esp
	jmp	trap_unix_2

0:	pushl	$0			/* otherwise: */
	pushl	$(T_DEBUG)		/* handle as normal */
	jmp	EXT(alltraps)		/* debug fault */

/*
 * Page fault traps save cr2.
 */
Entry(t_page_fault)
	pushl	$(T_PAGE_FAULT)		/* mark a page fault trap */
	pusha				/* save the general registers */
	movl	%cr2,%eax		/* get the faulting address */
	movl	%eax,12(%esp)		/* save in esp save slot */
	jmp	trap_push_segs		/* continue fault */

/*
 * All 'exceptions' enter here with:
 *	esp->   trap number
 *		error code
 *		old eip
 *		old cs
 *		old eflags
 *		old esp		if trapped from user
 *		old ss		if trapped from user
 *
 * NB: below use of CPU_NUMBER assumes that macro will use correct
 * segment register for any kernel data accesses.
 */
Entry(alltraps)
	pusha				/* save the general registers */
trap_push_segs:
	pushl	%ds			/* save the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

trap_set_segs:
	movl	%ss,%ax
	movl	%ax,%ds
	movl	%ax,%es			/* switch to kernel data seg */
	cld				/* clear direction flag */
	testl	$(EFL_VM),R_EFLAGS(%esp) /* in V86 mode? */
	jnz	trap_from_user		/* user mode trap if so */
	testb	$3,R_CS(%esp)		/* user mode trap? */
	jnz	trap_from_user
	cmpl	$0,%gs:CPU_ACTIVE_KLOADED
	je	trap_from_kernel	/* if clear, truly in kernel */
#ifdef FIXME
	cmpl	ETEXT_ADDR,R_EIP(%esp)	/* pc within kernel? */
	jb	trap_from_kernel
#endif
trap_from_kloaded:
	/*
	 * We didn't enter here "through" PCB (i.e., using ring 0 stack),
	 * so transfer the stack frame into the PCB explicitly, then
	 * start running on resulting "PCB stack".  We have to set
	 * up a simulated "uesp" manually, since there's none in the
	 * frame.
	 */
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs
	CAH(atstart)
	movl	%gs:CPU_ACTIVE_KLOADED,%ebx
	movl	%gs:CPU_KERNEL_STACK,%eax
	xchgl	%esp,%eax
	FRAME_STACK_TO_PCB(%ebx,%eax)
	CAH(atend)
	jmp	EXT(take_trap)

trap_from_user:
	mov	$ CPU_DATA_GS,%ax
	mov	%ax,%gs

	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */
					/* user regs pointer already set */
LEXT(take_trap)
	pushl	%ebx			/* record register save area */
	pushl	%ebx			/* pass register save area to trap */
	call	EXT(user_trap)		/* call user trap routine */
	movl	4(%esp),%esp		/* switch back to PCB stack */

/*
 * Return from trap or system call, checking for ASTs.
 * On PCB stack.
 */

LEXT(return_from_trap)
	movl	%gs:CPU_PENDING_AST,%edx
	cmpl	$0,%edx
	je	EXT(return_to_user)	/* if we need an AST: */

	movl	%gs:CPU_KERNEL_STACK,%esp
					/* switch to kernel stack */
	pushl	$0			/* push preemption flag */
	call	EXT(i386_astintr)	/* take the AST */
	addl	$4,%esp			/* pop preemption flag */
	popl	%esp			/* switch back to PCB stack (w/exc link) */
	jmp	EXT(return_from_trap)	/* and check again (rare) */
					/* ASTs after this point will */
					/* have to wait */

/*
 * Arrange the checks needed for kernel-loaded (or kernel-loading)
 * threads so that branch is taken in kernel-loaded case.
 */
LEXT(return_to_user)
	TIME_TRAP_UEXIT
	cmpl	$0,%gs:CPU_ACTIVE_KLOADED
	jnz	EXT(return_xfer_stack)
	movl	%gs:CPU_ACTIVE_THREAD, %ebx			/* get active thread */

#if	MACH_RT
#if	MACH_ASSERT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL
	je	EXT(return_from_kernel)
	int	$3
#endif	/* MACH_ASSERT */
#endif	/* MACH_RT */

/*
 * Return from kernel mode to interrupted thread.
 */

LEXT(return_from_kernel)
LEXT(kret_popl_gs)
	popl	%gs			/* restore segment registers */
LEXT(kret_popl_fs)
	popl	%fs
LEXT(kret_popl_es)
	popl	%es
LEXT(kret_popl_ds)
	popl	%ds
	popa				/* restore general registers */
	addl	$8,%esp			/* discard trap number and error code */

LEXT(kret_iret)
	iret				/* return from interrupt */


LEXT(return_xfer_stack)
	/*
	 * If we're on PCB stack in a kernel-loaded task, we have
	 * to transfer saved state back to thread stack and swap
	 * stack pointers here, because the hardware's not going
	 * to do so for us.
	 */
	CAH(rxsstart)
	movl	%gs:CPU_KERNEL_STACK,%esp
	movl	%gs:CPU_ACTIVE_KLOADED,%eax
	FRAME_PCB_TO_STACK(%eax)
	movl	%eax,%esp
	CAH(rxsend)
	jmp	EXT(return_from_kernel)

/*
 * Hate to put this here, but setting up a separate swap_func for
 * kernel-loaded threads no longer works, since thread executes
 * "for a while" (i.e., until it reaches glue code) when first
 * created, even if it's nominally suspended.  Hence we can't
 * transfer the PCB when the thread first resumes, because we
 * haven't initialized it yet.
 */
/*
 * Have to force transfer to new stack "manually".  Use a string
 * move to transfer all of our saved state to the stack pointed
 * to by iss.uesp, then install a pointer to it as our current
 * stack pointer.
 */
LEXT(return_kernel_loading)
	movl	%gs:CPU_KERNEL_STACK,%esp
	movl	%gs:CPU_ACTIVE_THREAD, %ebx			/* get active thread */
	movl	%ebx,%edx			/* save for later */
	FRAME_PCB_TO_STACK(%ebx)
	movl	%ebx,%esp			/* start running on new stack */
	movl	$0,%gs:CPU_ACTIVE_KLOADED       /* set cached indicator */
	jmp	EXT(return_from_kernel)

/*
 * Trap from kernel mode.  No need to switch stacks or load segment registers.
 */
trap_from_kernel:
#if	MACH_KDB || MACH_KGDB
	mov	$ CPU_DATA_GS,%ax
	mov	%ax,%gs
	movl	%esp,%ebx		/* save current stack */

	cmpl	EXT(int_stack_high),%esp /* on an interrupt stack? */
	jb	6f			/* OK if so */

#if     MACH_KGDB 
        cmpl    $0,EXT(kgdb_active)     /* Unexpected trap in kgdb */
        je      0f                      /* no */

        pushl   %esp                    /* Already on kgdb stack */
        cli
        call    EXT(kgdb_trap)
        addl    $4,%esp
        jmp     EXT(return_from_kernel)
0:                                      /* should kgdb handle this exception? */
        cmpl $(T_NO_FPU),R_TRAPNO(%esp) /* FPU disabled? */
        je      2f                      /* yes */
        cmpl $(T_PAGE_FAULT),R_TRAPNO(%esp)	/* page fault? */
        je      2f                      /* yes */
1:
        cli                             /* disable interrupts */
        CPU_NUMBER(%edx)                /* get CPU number */
        movl    CX(EXT(kgdb_stacks),%edx),%ebx
        xchgl   %ebx,%esp               /* switch to kgdb stack */
        pushl   %ebx                    /* pass old sp as an arg */
        call    EXT(kgdb_from_kernel)
        popl    %esp                    /* switch back to kernel stack */
        jmp     EXT(return_from_kernel)
2:
#endif  /* MACH_KGDB */

#if	MACH_KDB
	cmpl	$0,EXT(db_active)       /* could trap be from ddb? */
	je	3f			/* no */
	CPU_NUMBER(%edx)		/* see if this CPU is in ddb */
	cmpl	$0,CX(EXT(kdb_active),%edx)
	je	3f			/* no */
	pushl	%esp
	call	EXT(db_trap_from_asm)
	addl	$0x4,%esp
	jmp	EXT(return_from_kernel)

3:
	/*
	 * Dilemma:  don't want to switch to kernel_stack if trap
	 * "belongs" to ddb; don't want to switch to db_stack if
	 * trap "belongs" to kernel.  So have to duplicate here the
	 * set of trap types that kernel_trap() handles.  Note that
	 * "unexpected" page faults will not be handled by kernel_trap().
	 * In this panic-worthy case, we fall into the debugger with
	 * kernel_stack containing the call chain that led to the
	 * bogus fault.
	 */
	movl	R_TRAPNO(%esp),%edx
	cmpl	$(T_PAGE_FAULT),%edx
	je	4f
	cmpl	$(T_NO_FPU),%edx
	je	4f
	cmpl	$(T_FPU_FAULT),%edx
	je	4f
	cmpl	$(T_FLOATING_POINT_ERROR),%edx
	je	4f
	cmpl	$(T_PREEMPT),%edx
	jne	7f
4:
#endif	/* MACH_KDB */

	cmpl	%gs:CPU_KERNEL_STACK,%esp
					/* if not already on kernel stack, */
	ja	5f			/*   check some more */
	cmpl	%gs:CPU_ACTIVE_STACK,%esp
	ja	6f			/* on kernel stack: no switch */
5:
	movl	%gs:CPU_KERNEL_STACK,%esp
6:
	pushl	%ebx			/* save old stack */
	pushl	%ebx			/* pass as parameter */
	call	EXT(kernel_trap)	/* to kernel trap routine */
	addl	$4,%esp			/* pop parameter */
	testl	%eax,%eax
	jne	8f
	/*
	 * If kernel_trap returns false, trap wasn't handled.
	 */
7:
#if	MACH_KDB
	CPU_NUMBER(%edx)
	movl	CX(EXT(db_stacks),%edx),%esp
	pushl	%ebx			/* pass old stack as parameter */
	call	EXT(db_trap_from_asm)
#endif	/* MACH_KDB */
#if	MACH_KGDB
        cli                             /* disable interrupts */
        CPU_NUMBER(%edx)                /* get CPU number */
        movl    CX(EXT(kgdb_stacks),%edx),%esp
	pushl	%ebx			/* pass old stack as parameter */
	call	EXT(kgdb_from_kernel)
#endif	/* MACH_KGDB */
	addl	$4,%esp			/* pop parameter */
	testl	%eax,%eax
	jne	8f
	/*
	 * Likewise, if kdb_trap/kgdb_from_kernel returns false, trap
	 * wasn't handled.
	 */
	pushl	%ebx			/* pass old stack as parameter */
	call	EXT(panic_trap)
	addl	$4,%esp			/* pop parameter */
8:
	movl	%ebx,%esp		/* get old stack (from callee-saves reg) */
#else	/* MACH_KDB || MACH_KGDB */
	pushl	%esp			/* pass parameter */
	call	EXT(kernel_trap)	/* to kernel trap routine */
	addl	$4,%esp			/* pop parameter */
#endif	/* MACH_KDB || MACH_KGDB */

#if	MACH_RT
	movl	%gs:CPU_PENDING_AST,%eax		/* get pending asts */
	testl	$ AST_URGENT,%eax	/* any urgent preemption? */
	je	EXT(return_from_kernel)	/* no, nothing to do */
	cmpl	$ T_PREEMPT,48(%esp)	/* preempt request? */
	jne	EXT(return_from_kernel)	/* no, nothing to do */
	movl	%gs:CPU_KERNEL_STACK,%eax
	movl	%esp,%ecx
	xorl	%eax,%ecx
	andl	$(-KERNEL_STACK_SIZE),%ecx
	testl	%ecx,%ecx		/* are we on the kernel stack? */
	jne	EXT(return_from_kernel)	/* no, skip it */

#if	PREEMPT_DEBUG_LOG
        pushl   28(%esp)		/* stack pointer */
        pushl   24+4(%esp)		/* frame pointer */
        pushl   56+8(%esp)		/* stack pointer */
        pushl   $0f
        call    EXT(log_thread_action)
        addl    $16, %esp
        .data
0:      String  "trap preempt eip"
        .text
#endif	/* PREEMPT_DEBUG_LOG */

	pushl	$1			/* push preemption flag */
	call	EXT(i386_astintr)	/* take the AST */
	addl	$4,%esp			/* pop preemption flag */
#endif	/* MACH_RT */

	jmp	EXT(return_from_kernel)

/*
 *	Called as a function, makes the current thread
 *	return from the kernel as if from an exception.
 */

	.globl	EXT(thread_exception_return)
	.globl	EXT(thread_bootstrap_return)
LEXT(thread_exception_return)
LEXT(thread_bootstrap_return)
	movl	%esp,%ecx			/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp		/* switch back to PCB stack */
	jmp	EXT(return_from_trap)

Entry(call_continuation)
	movl	S_ARG0,%eax			/* get continuation */
	movl	S_ARG1,%edx			/* continuation param */
	movl	S_ARG2,%ecx			/* wait result */
	movl	%esp,%ebp			/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ebp
	addl	$(-3-IKS_SIZE),%ebp
	movl	%ebp,%esp			/* pop the stack */
	xorl	%ebp,%ebp			/* zero frame pointer */
	pushl	%ecx
	pushl	%edx
	call	*%eax				/* call continuation */
	addl	$8,%esp
	movl	%gs:CPU_ACTIVE_THREAD,%eax
	pushl	%eax
	call	EXT(thread_terminate)

#if 0
#define LOG_INTERRUPT(info,msg)			\
        pushal				;	\
        pushl	msg			;	\
        pushl	info			;	\
        call	EXT(log_thread_action)	;	\
        add	$8,%esp			;	\
        popal
#define CHECK_INTERRUPT_TIME(n)                 \
	pushal				;	\
	pushl	$n			;	\
	call	EXT(check_thread_time)	;	\
	add	$4,%esp			;	\
	popal
#else
#define LOG_INTERRUPT(info,msg)
#define CHECK_INTERRUPT_TIME(n)
#endif
	 
.data
imsg_start:
	String	"interrupt start"
imsg_end:
	String	"interrupt end"

.text
/*
 * All interrupts enter here.
 * old %eax on stack; interrupt number in %eax.
 */
Entry(all_intrs)
	pushl	%ecx			/* save registers */
	pushl	%edx
	cld				/* clear direction flag */

	pushl	%ds			/* save segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs
	mov	%ss,%dx			/* switch to kernel segments */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

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
	movl	%esp,%edx		/* & i386_interrupt_state */
	xchgl	%ecx,%esp		/* switch to interrupt stack */

	pushl	%ecx			/* save pointer to old stack */
	pushl	%edx			/* pass &i386_interrupt_state to pe_incoming_interrupt */
	pushl	%eax			/* push trap number */
	
	TIME_INT_ENTRY			/* do timing */

#if	MACH_RT
	incl	%gs:CPU_PREEMPTION_LEVEL
#endif	/* MACH_RT */
	incl	%gs:CPU_INTERRUPT_LEVEL

	call	EXT(PE_incoming_interrupt)		/* call generic interrupt routine */
	addl	$8,%esp			/* Pop trap number and eip */

	.globl	EXT(return_to_iret)
LEXT(return_to_iret)			/* (label for kdb_kintr and hardclock) */

	decl	%gs:CPU_INTERRUPT_LEVEL

#if	MACH_RT
	decl	%gs:CPU_PREEMPTION_LEVEL
#endif	/* MACH_RT */

	TIME_INT_EXIT			/* do timing */

	popl	%esp			/* switch back to old stack */

	movl	%gs:CPU_PENDING_AST,%eax
	testl	%eax,%eax		/* any pending asts? */
	je	1f			/* no, nothing to do */
	testl	$(EFL_VM),I_EFL(%esp)	/* if in V86 */
	jnz	ast_from_interrupt	/* take it */
	testb	$3,I_CS(%esp)		/* user mode, */
	jnz	ast_from_interrupt	/* take it */
#ifdef FIXME
	cmpl	ETEXT_ADDR,I_EIP(%esp) /* if within kernel-loaded task, */
	jnb	ast_from_interrupt	/* take it */
#endif

#if	MACH_RT
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL		/* preemption masked? */
	jne	1f			/* yes, skip it */
	testl	$ AST_URGENT,%eax	/* any urgent requests? */
	je	1f			/* no, skip it */
	cmpl	$ EXT(locore_end),I_EIP(%esp)	/* are we in locore code? */
	jb	1f			/* yes, skip it */
	movl	%gs:CPU_KERNEL_STACK,%eax
	movl	%esp,%ecx
	xorl	%eax,%ecx
	andl	$(-KERNEL_STACK_SIZE),%ecx
	testl	%ecx,%ecx		/* are we on the kernel stack? */
	jne	1f			/* no, skip it */

/*
 * Take an AST from kernel space.  We don't need (and don't want)
 * to do as much as the case where the interrupt came from user
 * space.
 */
#if	PREEMPT_DEBUG_LOG
	pushl 	$0
	pushl 	$0
	pushl	I_EIP+8(%esp)
	pushl	$0f
	call	EXT(log_thread_action)
	addl	$16, %esp
	.data
0:	String  "intr preempt eip"
	.text
#endif	/* PREEMPT_DEBUG_LOG */

	sti
	pushl	$1			/* push preemption flag */
	call	EXT(i386_astintr)	/* take the AST */
	addl	$4,%esp			/* pop preemption flag */
#endif	/* MACH_RT */

1:
	pop	%gs
	pop	%fs
	pop	%es			/* restore segment regs */
	pop	%ds
	pop	%edx
	pop	%ecx
	pop	%eax
	iret				/* return to caller */

int_from_intstack:
#if	MACH_RT
	incl	%gs:CPU_PREEMPTION_LEVEL
#endif	/* MACH_RT */

	incl	%gs:CPU_INTERRUPT_LEVEL

	movl	%esp, %edx		/* i386_interrupt_state */
	pushl	%edx			/* pass &i386_interrupt_state to PE_incoming_interrupt /*
	
	pushl	%eax			/* Push trap number */

	call	EXT(PE_incoming_interrupt)
	addl	$20,%esp			/* pop i386_interrupt_state, gs,fs,es,ds */

LEXT(return_to_iret_i)			/* ( label for kdb_kintr) */

	addl	$4,%esp			/* pop trap number */

	decl	%gs:CPU_INTERRUPT_LEVEL

#if	MACH_RT
	decl	%gs:CPU_PREEMPTION_LEVEL
#endif	/* MACH_RT */

	pop	%edx			/* must have been on kernel segs */
	pop	%ecx
	pop	%eax			/* no ASTs */
	iret

/*
 *	Take an AST from an interrupt.
 *	On PCB stack.
 * sp->	es	-> edx
 *	ds	-> ecx
 *	edx	-> eax
 *	ecx	-> trapno
 *	eax	-> code
 *	eip
 *	cs
 *	efl
 *	esp
 *	ss
 */
ast_from_interrupt:
	pop	%gs
	pop	%fs
	pop	%es			/* restore all registers ... */
	pop	%ds
	popl	%edx
	popl	%ecx
	popl	%eax
	sti				/* Reenable interrupts */
	pushl	$0			/* zero code */
	pushl	$0			/* zero trap number */
	pusha				/* save general registers */
	push	%ds			/* save segment registers */
	push	%es
	push	%fs
	push	%gs
	mov	%ss,%dx			/* switch to kernel segments */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

	/*
	 * See if we interrupted a kernel-loaded thread executing
	 * in its own task.
	 */
	CPU_NUMBER(%edx)
	testl	$(EFL_VM),R_EFLAGS(%esp) /* in V86 mode? */
	jnz	0f			/* user mode trap if so */
	testb	$3,R_CS(%esp)		
	jnz	0f			/* user mode, back to normal */
#ifdef FIXME
	cmpl	ETEXT_ADDR,R_EIP(%esp)
	jb	0f			/* not kernel-loaded, back to normal */
#endif

	/*
	 * Transfer the current stack frame by hand into the PCB.
	 */
	CAH(afistart)
	movl	%gs:CPU_ACTIVE_KLOADED,%eax
	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp
	FRAME_STACK_TO_PCB(%eax,%ebx)
	CAH(afiend)
	TIME_TRAP_UENTRY
	jmp	3f
0:
	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%eax
					/* switch to kernel stack */
	xchgl	%eax,%esp
3:
	pushl	%eax
	pushl	$0			/* push preemption flag */
	call	EXT(i386_astintr)	/* take the AST */
	addl	$4,%esp			/* pop preemption flag */
	popl	%esp			/* back to PCB stack */
	jmp	EXT(return_from_trap)	/* return */

#if	MACH_KDB || MACH_KGDB 
/*
 * kdb_kintr:	enter kdb from keyboard interrupt.
 * Chase down the stack frames until we find one whose return
 * address is the interrupt handler.   At that point, we have:
 *
 * frame->	saved %ebp
 *		return address in interrupt handler
 *		ivect
 *		saved SPL
 *		return address == return_to_iret_i
 *		saved %edx
 *		saved %ecx
 *		saved %eax
 *		saved %eip
 *		saved %cs
 *		saved %efl
 *
 * OR:
 * frame->	saved %ebp
 *		return address in interrupt handler
 *		ivect
 *		saved SPL
 *		return address == return_to_iret
 *		pointer to save area on old stack
 *	      [ saved %ebx, if accurate timing ]
 *
 * old stack:	saved %es
 *		saved %ds
 *		saved %edx
 *		saved %ecx
 *		saved %eax
 *		saved %eip
 *		saved %cs
 *		saved %efl
 *
 * Call kdb, passing it that register save area.
 */

#if MACH_KGDB
Entry(kgdb_kintr)
#endif /* MACH_KGDB */
#if MACH_KDB
Entry(kdb_kintr)
#endif /* MACH_KDB */
	movl	%ebp,%eax		/* save caller`s frame pointer */
	movl	$ EXT(return_to_iret),%ecx /* interrupt return address 1 */
	movl	$ EXT(return_to_iret_i),%edx /* interrupt return address 2 */

0:	cmpl	16(%eax),%ecx		/* does this frame return to */
					/* interrupt handler (1)? */
	je	1f
	cmpl	$kdb_from_iret,16(%eax)
	je	1f
	cmpl	16(%eax),%edx		/* interrupt handler (2)? */
	je	2f			/* if not: */
	cmpl	$kdb_from_iret_i,16(%eax)
	je	2f
	movl	(%eax),%eax		/* try next frame */
	jmp	0b

1:	movl	$kdb_from_iret,16(%eax)	/* returns to kernel/user stack */
	ret

2:	movl	$kdb_from_iret_i,16(%eax)
					/* returns to interrupt stack */
	ret

/*
 * On return from keyboard interrupt, we will execute
 * kdb_from_iret_i
 *	if returning to an interrupt on the interrupt stack
 * kdb_from_iret
 *	if returning to an interrupt on the user or kernel stack
 */
kdb_from_iret:
					/* save regs in known locations */
	pushl	%ebx			/* caller`s %ebx is in reg */
	pushl	%ebp
	pushl	%esi
	pushl	%edi
	push	%fs
	push	%gs
#if MACH_KGDB
	cli
        pushl   %esp                    /* pass regs */
        call    EXT(kgdb_kentry)        /* to kgdb */
        addl    $4,%esp                 /* pop parameters */
#endif /* MACH_KGDB */
#if MACH_KDB
	pushl	%esp			/* pass regs */
        call    EXT(kdb_kentry)		/* to kdb */
	addl	$4,%esp			/* pop parameters */
#endif /* MACH_KDB */
	pop	%gs			/* restore registers */
	pop	%fs
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	jmp	EXT(return_to_iret)	/* normal interrupt return */

kdb_from_iret_i:			/* on interrupt stack */
	pop	%edx			/* restore saved registers */
	pop	%ecx
	pop	%eax
	pushl	$0			/* zero error code */
	pushl	$0			/* zero trap number */
	pusha				/* save general registers */
	push	%ds			/* save segment registers */
	push	%es
	push	%fs
	push	%gs
#if MACH_KGDB
	cli				/* disable interrupts */
        CPU_NUMBER(%edx)                /* get CPU number */
        movl    CX(EXT(kgdb_stacks),%edx),%ebx
        xchgl   %ebx,%esp               /* switch to kgdb stack */
        pushl   %ebx                    /* pass old sp as an arg */
        call    EXT(kgdb_from_kernel)
        popl    %esp                    /* switch back to interrupt stack */
#endif /* MACH_KGDB */
#if MACH_KDB
        pushl   %esp                    /* pass regs, */
        pushl   $0                      /* code, */
        pushl   $-1                     /* type to kdb */
        call    EXT(kdb_trap)
        addl    $12,%esp
#endif /* MACH_KDB */
	pop	%gs			/* restore segment registers */
	pop	%fs
	pop	%es
	pop	%ds
	popa				/* restore general registers */
	addl	$8,%esp
	iret

#endif	/* MACH_KDB || MACH_KGDB */


/*
 * Mach RPC enters through a call gate, like a system call.
 */

Entry(mach_rpc)
	pushf				/* save flags as soon as possible */
	pushl	%eax			/* save system call number */
	pushl	$0			/* clear trap number slot */

	pusha				/* save the general registers */
	pushl	%ds			/* and the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

	mov	%ss,%dx			/* switch to kernel data segment */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

/*
 * Shuffle eflags,eip,cs into proper places
 */

	movl	R_EIP(%esp),%ebx	/* eflags are in EIP slot */
	movl	R_CS(%esp),%ecx		/* eip is in CS slot */
	movl	R_EFLAGS(%esp),%edx	/* cs is in EFLAGS slot */
	movl	%ecx,R_EIP(%esp)	/* fix eip */
	movl	%edx,R_CS(%esp)		/* fix cs */
	movl	%ebx,R_EFLAGS(%esp)	/* fix eflags */

        TIME_TRAP_UENTRY

        negl    %eax                    /* get system call number */
        shll    $4,%eax                 /* manual indexing */

/*
 * Check here for mach_rpc from kernel-loaded task --
 *  - Note that kernel-loaded task returns via real return.
 * We didn't enter here "through" PCB (i.e., using ring 0 stack),
 * so transfer the stack frame into the PCB explicitly, then
 * start running on resulting "PCB stack".  We have to set
 * up a simulated "uesp" manually, since there's none in the
 * frame.
 */
        cmpl    $0,%gs:CPU_ACTIVE_KLOADED
        jz      2f
        CAH(mrstart)
        movl    %gs:CPU_ACTIVE_KLOADED,%ebx
        movl    %gs:CPU_KERNEL_STACK,%edx
        xchgl   %edx,%esp

        FRAME_STACK_TO_PCB(%ebx,%edx)
        CAH(mrend)

        jmp     3f

2:
	movl	%gs:CPU_KERNEL_STACK,%ebx
					/* get current kernel stack */
	xchgl	%ebx,%esp		/* switch stacks - %ebx points to */
					/* user registers. */

3:

/*
 * Register use on entry:
 *   eax contains syscall number
 *   ebx contains user regs pointer
 */
#undef 	RPC_TRAP_REGISTERS
#ifdef	RPC_TRAP_REGISTERS
	pushl	R_ESI(%ebx)
	pushl	R_EDI(%ebx)
	pushl	R_ECX(%ebx)
	pushl	R_EDX(%ebx)
#else
	movl	EXT(mach_trap_table)(%eax),%ecx
					/* get number of arguments */
	jecxz	2f			/* skip argument copy if none */
	movl	R_UESP(%ebx),%esi	/* get user stack pointer */
	lea	4(%esi,%ecx,4),%esi	/* skip user return address, */
					/* and point past last argument */
	movl	%gs:CPU_ACTIVE_KLOADED,%edx
					/* point to current thread */
	orl	%edx,%edx		/* if ! kernel-loaded, check addr */
	jz	4f			/* else */
	mov	%ds,%dx			/* kernel data segment access */
	jmp	5f
4:
 	cmpl	$(VM_MAX_ADDRESS),%esi	/* in user space? */
 	ja	mach_call_addr		/* address error if not */
	movl	$ USER_DS,%edx		/* user data segment access */
5:
	mov	%dx,%fs
	movl	%esp,%edx		/* save kernel ESP for error recovery */
1:
	subl	$4,%esi
	RECOVERY_SECTION
	RECOVER(mach_call_addr_push)
	pushl	%fs:(%esi)		/* push argument on stack */
	loop	1b			/* loop for all arguments */
#endif

/*
 * Register use on entry:
 *   eax contains syscall number << 4
 * mach_call_munger is declared regparm(1), so the first arg is %eax
 */
2:

	call	EXT(mach_call_munger)
	
	movl	%esp,%ecx		/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp	/* switch back to PCB stack */
	movl	%eax,R_EAX(%esp)	/* save return value */
	jmp	EXT(return_from_trap)	/* return to user */


/*
 * Special system call entry for "int 0x80", which has the "eflags"
 * register saved at the right place already.
 * Fall back to the common syscall path after saving the registers.
 *
 * esp ->	old eip
 *		old cs
 * 		old eflags
 *		old esp		if trapped from user
 * 		old ss		if trapped from user
 *
 * XXX:	for the moment, we don't check for int 0x80 from kernel mode.
 */
Entry(syscall_int80)
	pushl	%eax			/* save system call number */
	pushl	$0			/* clear trap number slot */

	pusha				/* save the general registers */
	pushl	%ds			/* and the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

	mov	%ss,%dx			/* switch to kernel data segment */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

	jmp	syscall_entry_3

/*
 * System call enters through a call gate.  Flags are not saved -
 * we must shuffle stack to look like trap save area.
 *
 * esp->	old eip
 *		old cs
 *		old esp
 *		old ss
 *
 * eax contains system call number.
 *
 * NB: below use of CPU_NUMBER assumes that macro will use correct
 * correct segment register for any kernel data accesses.
 */
Entry(syscall)
syscall_entry:
	pushf				/* save flags as soon as possible */
syscall_entry_2:
	pushl	%eax			/* save system call number */
	pushl	$0			/* clear trap number slot */

	pusha				/* save the general registers */
	pushl	%ds			/* and the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

	mov	%ss,%dx			/* switch to kernel data segment */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

/*
 * Shuffle eflags,eip,cs into proper places
 */

	movl	R_EIP(%esp),%ebx	/* eflags are in EIP slot */
	movl	R_CS(%esp),%ecx		/* eip is in CS slot */
	movl	R_EFLAGS(%esp),%edx	/* cs is in EFLAGS slot */
	movl	%ecx,R_EIP(%esp)	/* fix eip */
	movl	%edx,R_CS(%esp)		/* fix cs */
	movl	%ebx,R_EFLAGS(%esp)	/* fix eflags */

syscall_entry_3:
/*
 * Check here for syscall from kernel-loaded task --
 * We didn't enter here "through" PCB (i.e., using ring 0 stack),
 * so transfer the stack frame into the PCB explicitly, then
 * start running on resulting "PCB stack".  We have to set
 * up a simulated "uesp" manually, since there's none in the
 * frame.
 */
	cmpl	$0,%gs:CPU_ACTIVE_KLOADED
	jz	0f
	CAH(scstart)
	movl	%gs:CPU_ACTIVE_KLOADED,%ebx
	movl	%gs:CPU_KERNEL_STACK,%edx
	xchgl	%edx,%esp
	FRAME_STACK_TO_PCB(%ebx,%edx)
	CAH(scend)
	TIME_TRAP_UENTRY
	jmp	1f

0:
	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%ebx
					/* get current kernel stack */
	xchgl	%ebx,%esp		/* switch stacks - %ebx points to */
					/* user registers. */
					/* user regs pointer already set */

/*
 * Native system call.
 * Register use on entry:
 *   eax contains syscall number
 *   ebx points to user regs
 */
1:
	negl	%eax			/* get system call number */
	jl	mach_call_range		/* out of range if it was positive */

	cmpl	EXT(mach_trap_count),%eax /* check system call table bounds */
	jg	mach_call_range		/* error if out of range */
	shll	$4,%eax			/* manual indexing */

	movl	EXT(mach_trap_table)+4(%eax),%edx
					/* get procedure */
	cmpl	$ EXT(kern_invalid),%edx	/* if not "kern_invalid" */
	jne	do_native_call		/* go on with Mach syscall */
	shrl	$4,%eax			/* restore syscall number */
	jmp	mach_call_range		/* try it as a "server" syscall */

/*
 * Register use on entry:
 *   eax contains syscall number
 *   ebx contains user regs pointer
 */
do_native_call:
	movl	EXT(mach_trap_table)(%eax),%ecx
					/* get number of arguments */
	jecxz	mach_call_call		/* skip argument copy if none */
	movl	R_UESP(%ebx),%esi	/* get user stack pointer */
	lea	4(%esi,%ecx,4),%esi	/* skip user return address, */
					/* and point past last argument */
	movl	%gs:CPU_ACTIVE_KLOADED,%edx
					/* point to current thread */
	orl	%edx,%edx		/* if kernel-loaded, skip addr check */
	jz	0f			/* else */
	mov	%ds,%dx			/* kernel data segment access  */
	jmp	1f
0:
	cmpl	$(VM_MAX_ADDRESS),%esi	/* in user space? */
	ja	mach_call_addr		/* address error if not */
	movl	$ USER_DS,%edx		/* user data segment access */
1:
	mov	%dx,%fs
	movl	%esp,%edx		/* save kernel ESP for error recovery */
2:
	subl	$4,%esi
	RECOVERY_SECTION
	RECOVER(mach_call_addr_push)
	pushl	%fs:(%esi)		/* push argument on stack */
	loop	2b			/* loop for all arguments */

/*
 * Register use on entry:
 *   eax contains syscall number
 *   ebx contains user regs pointer
 */
mach_call_call:

	CAH(call_call)

#if	ETAP_EVENT_MONITOR
	cmpl	$0x200, %eax			/* is this mach_msg? */
	jz	make_syscall			/* if yes, don't record event */

        pushal					/* Otherwise: save registers */
        pushl	%eax				/*   push syscall number on stack*/
        call	EXT(etap_machcall_probe1)	/*   call event begin probe */
        add	$4,%esp				/*   restore stack */
        popal					/*   restore registers */

	call	*EXT(mach_trap_table)+4(%eax)	/* call procedure */
        pushal
        call	EXT(etap_machcall_probe2)	/* call event end probe */
        popal
	jmp	skip_syscall			/* syscall already made */
#endif	/* ETAP_EVENT_MONITOR */

make_syscall:

/*
 * mach_call_munger is declared regparm(1) so the first arg is %eax
 */
	call	EXT(mach_call_munger)

skip_syscall:

	movl	%esp,%ecx		/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp	/* switch back to PCB stack */
	movl	%eax,R_EAX(%esp)	/* save return value */
	jmp	EXT(return_from_trap)	/* return to user */

/*
 * Address out of range.  Change to page fault.
 * %esi holds failing address.
 * Register use on entry:
 *   ebx contains user regs pointer
 */
mach_call_addr_push:
	movl	%edx,%esp		/* clean parameters from stack */
mach_call_addr:
	movl	%esi,R_CR2(%ebx)	/* set fault address */
	movl	$(T_PAGE_FAULT),R_TRAPNO(%ebx)
					/* set page-fault trap */
	movl	$(T_PF_USER),R_ERR(%ebx)
					/* set error code - read user space */
	CAH(call_addr)
	jmp	EXT(take_trap)		/* treat as a trap */

/*
 * System call out of range.  Treat as invalid-instruction trap.
 * (? general protection?)
 * Register use on entry:
 *   eax contains syscall number
 */
mach_call_range:
	push 	%eax
	movl	%esp,%edx
	push	$1			/* code_cnt = 1 */
	push	%edx			/* exception_type_t (see i/f docky) */
	push	$ EXC_SYSCALL
	CAH(call_range)
	call	EXT(exception_triage)
	/* no return */

	.globl	EXT(syscall_failed)
LEXT(syscall_failed)
	movl	%esp,%ecx		/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp	/* switch back to PCB stack */
	movl	%gs:CPU_KERNEL_STACK,%ebx
					/* get current kernel stack */
	xchgl	%ebx,%esp		/* switch stacks - %ebx points to */
					/* user registers. */
					/* user regs pointer already set */

	movl	$(T_INVALID_OPCODE),R_TRAPNO(%ebx)
					/* set invalid-operation trap */
	movl	$0,R_ERR(%ebx)		/* clear error code */
	CAH(failed)
	jmp	EXT(take_trap)		/* treat as a trap */

/**/
/*
 * Utility routines.
 */


/*
 * Copy from user address space.
 * arg0:	user address
 * arg1:	kernel address
 * arg2:	byte count
 */
Entry(copyinmsg)
ENTRY(copyin)
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get user start address */
	movl	8+S_ARG1,%edi		/* get kernel destination address */
	movl	8+S_ARG2,%edx		/* get count */

	lea	0(%esi,%edx),%eax	/* get user end address + 1 */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx			/* get active thread */
	movl	ACT_MAP(%ecx),%ecx		/* get act->map */
	movl	MAP_PMAP(%ecx),%ecx		/* get map->pmap */
	cmpl	EXT(kernel_pmap), %ecx
	jz	1f
	movl	$ USER_DS,%cx		/* user data segment access */
	mov	%cx,%ds
1:
	cmpl	%esi,%eax
	jb	copyin_fail		/* fail if wrap-around */
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
copy_ret:
	mov	%ss,%di			/* restore kernel data segment */
	mov	%di,%ds

	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copyin_fail:
	movl	$ EFAULT,%eax			/* return error for failure */
	jmp	copy_ret		/* pop frame and return */

/*
 * Copy string from user address space.
 * arg0:	user address
 * arg1:	kernel address
 * arg2:	max byte count
 * arg3:	actual byte count (OUT)
 */
Entry(copyinstr)
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get user start address */
	movl	8+S_ARG1,%edi		/* get kernel destination address */
	movl	8+S_ARG2,%edx		/* get count */

	lea	0(%esi,%edx),%eax	/* get user end address + 1 */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx			/* get active thread */
	movl	ACT_MAP(%ecx),%ecx		/* get act->map */
	movl	MAP_PMAP(%ecx),%ecx		/* get map->pmap */
	cmpl	EXT(kernel_pmap), %ecx
	jne	0f
	mov	%ds,%cx			/* kernel data segment access  */
	jmp	1f
0:
	movl	$ USER_DS,%cx		/* user data segment access */
1:
	mov	%cx,%fs
	xorl	%eax,%eax
	cmpl	$0,%edx
	je	4f
2:
	RECOVERY_SECTION
	RECOVER(copystr_fail)		/* copy bytes... */
	movb	%fs:(%esi),%eax
	incl	%esi
	testl	%edi,%edi		/* if kernel address is ... */
	jz	3f			/* not NULL */
	movb	%eax,(%edi)		/* copy the byte */
	incl	%edi
3:
	decl	%edx
	je	5f			/* Zero count.. error out */
	cmpl	$0,%eax
	jne	2b			/* .. a NUL found? */
	jmp	4f			/* return zero (%eax) */
5:
	movl	$ ENAMETOOLONG,%eax	/* String is too long.. */
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
	movl	$ EFAULT,%eax		/* return error for failure */
	jmp	copy_ret		/* pop frame and return */

/*
 * Copy to user address space.
 * arg0:	kernel address
 * arg1:	user address
 * arg2:	byte count
 */
Entry(copyoutmsg)
ENTRY(copyout)
	pushl	%esi
	pushl	%edi			/* save registers */
	pushl	%ebx

	movl	12+S_ARG0,%esi		/* get kernel start address */
	movl	12+S_ARG1,%edi		/* get user start address */
	movl	12+S_ARG2,%edx		/* get count */

	leal	0(%edi,%edx),%eax	/* get user end address + 1 */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx			/* get active thread */
	movl	ACT_MAP(%ecx),%ecx		/* get act->map */
	movl	MAP_PMAP(%ecx),%ecx		/* get map->pmap */
	cmpl	EXT(kernel_pmap), %ecx
	jne	0f
	mov	%ds,%cx			/* else kernel data segment access  */
	jmp	1f
0:
	movl	$ USER_DS,%cx
1:
	mov	%cx,%es

/*
 * Check whether user address space is writable
 * before writing to it - hardware is broken.
 *
 * Skip check if "user" address is really in
 * kernel space (i.e., if it's in a kernel-loaded
 * task).
 *
 * Register usage:
 *	esi/edi	source/dest pointers for rep/mov
 *	ecx	counter for rep/mov
 *	edx	counts down from 3rd arg
 *	eax	count of bytes for each (partial) page copy
 *	ebx	shadows edi, used to adjust edx
 */
	movl	%edi,%ebx		/* copy edi for syncing up */
copyout_retry:
	/* if restarting after a partial copy, put edx back in sync, */
	addl	%ebx,%edx		/* edx -= (edi - ebx); */
	subl	%edi,%edx		/
	movl	%edi,%ebx		/* ebx = edi; */

/*
 * Copy only what fits on the current destination page.
 * Check for write-fault again on the next page.
 */
	leal	NBPG(%edi),%eax		/* point to */
	andl	$(-NBPG),%eax		/* start of next page */
	subl	%edi,%eax		/* get number of bytes to that point */
	cmpl	%edx,%eax		/* bigger than count? */
	jle	1f			/* if so, */
	movl	%edx,%eax		/* use count */
1:
	cld				/* count up */
	movl	%eax,%ecx		/* move by longwords first */
	shrl	$2,%ecx
	RECOVERY_SECTION
	RECOVER(copyout_fail)
	RETRY_SECTION
	RETRY(copyout_retry)
	rep
	movsl
	movl	%eax,%ecx		/* now move remaining bytes */
	andl	$3,%ecx
	RECOVERY_SECTION
	RECOVER(copyout_fail)
	RETRY_SECTION
	RETRY(copyout_retry)
	rep
	movsb				/* move */
	movl	%edi,%ebx		/* copy edi for syncing up */
	subl	%eax,%edx		/* and decrement count */
	jg	copyout_retry		/* restart on next page if not done */
	xorl	%eax,%eax		/* return 0 for success */
copyout_ret:
	mov	%ss,%di			/* restore kernel segment */
	mov	%di,%es

	popl	%ebx
	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copyout_fail:
	movl	$ EFAULT,%eax		/* return error for failure */
	jmp	copyout_ret		/* pop frame and return */

/*
 * FPU routines.
 */

/*
 * Initialize FPU.
 */
ENTRY(_fninit)
	fninit
	ret

/*
 * Read control word
 */
ENTRY(_fstcw)
	pushl	%eax		/* get stack space */
	fstcw	(%esp)
	popl	%eax
	ret

/*
 * Set control word
 */
ENTRY(_fldcw)
	fldcw	4(%esp)
	ret

/*
 * Read status word
 */
ENTRY(_fnstsw)
	xor	%eax,%eax		/* clear high 16 bits of eax */
	fnstsw	%ax			/* read FP status */
	ret

/*
 * Clear FPU exceptions
 */
ENTRY(_fnclex)
	fnclex
	ret

/*
 * Clear task-switched flag.
 */
ENTRY(_clts)
	clts
	ret

/*
 * Save complete FPU state.  Save error for later.
 */
ENTRY(_fpsave)
	movl	4(%esp),%eax		/* get save area pointer */
	fnsave	(%eax)			/* save complete state, including */
					/* errors */
	ret

/*
 * Restore FPU state.
 */
ENTRY(_fprestore)
	movl	4(%esp),%eax		/* get save area pointer */
	frstor	(%eax)			/* restore complete state */
	ret

/*
 * Set cr3
 */
ENTRY(set_cr3)
	CPU_NUMBER(%eax)
	orl	4(%esp), %eax
	/*
	 * Don't set PDBR to a new value (hence invalidating the
	 * "paging cache") if the new value matches the current one.
	 */
	movl	%cr3,%edx		/* get current cr3 value */
	cmpl	%eax,%edx
	je	0f			/* if two are equal, don't set */
	movl	%eax,%cr3		/* load it (and flush cache) */
0:
	ret

/*
 * Read cr3
 */
ENTRY(get_cr3)
	movl	%cr3,%eax
	andl	$(~0x7), %eax		/* remove cpu number */
	ret

/*
 * Flush TLB
 */
ENTRY(flush_tlb)
	movl	%cr3,%eax		/* flush tlb by reloading CR3 */
	movl	%eax,%cr3		/* with itself */
	ret

/*
 * Read cr2
 */
ENTRY(get_cr2)
	movl	%cr2,%eax
	ret

/*
 * Read cr4
 */
ENTRY(get_cr4)
	.byte	0x0f,0x20,0xe0		/* movl	%cr4, %eax */
	ret

/*
 * Write cr4
 */
ENTRY(set_cr4)
	movl	4(%esp), %eax
	.byte	0x0f,0x22,0xe0		/* movl	%eax, %cr4 */
	ret

/*
 * Read ldtr
 */
Entry(get_ldt)
	xorl	%eax,%eax
	sldt	%ax
	ret

/*
 * Set ldtr
 */
Entry(set_ldt)
	lldt	4(%esp)
	ret

/*
 * Read task register.
 */
ENTRY(get_tr)
	xorl	%eax,%eax
	str	%ax
	ret

/*
 * Set task register.  Also clears busy bit of task descriptor.
 */
ENTRY(set_tr)
	movl	S_ARG0,%eax		/* get task segment number */
	subl	$8,%esp			/* push space for SGDT */
	sgdt	2(%esp)			/* store GDT limit and base (linear) */
	movl	4(%esp),%edx		/* address GDT */
	movb	$(K_TSS),5(%edx,%eax)	/* fix access byte in task descriptor */
	ltr	%ax			/* load task register */
	addl	$8,%esp			/* clear stack */
	ret				/* and return */

/*
 * Set task-switched flag.
 */
ENTRY(_setts)
	movl	%cr0,%eax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	movl	%eax,%cr0		/* set cr0 */
	ret

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
 * int inst_fetch(int eip, int cs);
 *
 * Fetch instruction byte.  Return -1 if invalid address.
 */
	.globl	EXT(inst_fetch)
LEXT(inst_fetch)
	movl	S_ARG1, %eax		/* get segment */
	movw	%ax,%fs			/* into FS */
	movl	S_ARG0, %eax		/* get offset */
	RETRY_SECTION
	RETRY(EXT(inst_fetch))		/* re-load FS on retry */
	RECOVERY_SECTION
	RECOVER(EXT(inst_fetch_fault))
	movzbl	%fs:(%eax),%eax		/* load instruction byte */
	ret

LEXT(inst_fetch_fault)
	movl	$-1,%eax		/* return -1 if error */
	ret


#if MACH_KDP
/*
 * kdp_copy_kmem(char *src, char *dst, int count)
 *
 * Similar to copyin except that both addresses are kernel addresses.
 */

ENTRY(kdp_copy_kmem)
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get kernel start address */
	movl	8+S_ARG1,%edi		/* get kernel destination address */

	movl	8+S_ARG2,%edx		/* get count */

	lea	0(%esi,%edx),%eax	/* get kernel end address + 1 */

	cmpl	%esi,%eax
	jb	kdp_vm_read_fail	/* fail if wrap-around */
	cld				/* count up */
	movl	%edx,%ecx		/* move by longwords first */
	shrl	$2,%ecx
	RECOVERY_SECTION
	RECOVER(kdp_vm_read_fail)
	rep
	movsl				/* move longwords */
	movl	%edx,%ecx		/* now move remaining bytes */
	andl	$3,%ecx
	RECOVERY_SECTION
	RECOVER(kdp_vm_read_fail)
	rep
	movsb
kdp_vm_read_done:
	movl	8+S_ARG2,%edx		/* get count */
	subl	%ecx,%edx		/* Return number of bytes transfered */
	movl	%edx,%eax

	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

kdp_vm_read_fail:
	xorl	%eax,%eax	/* didn't copy a thing. */

	popl	%edi
	popl	%esi
	ret
#endif

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
 * Done with recovery and retry tables.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_END
	RETRY_SECTION
	RETRY_TABLE_END



ENTRY(dr6)
	movl	%db6, %eax
	ret

/*	dr<i>(address, type, len, persistence)
 */
ENTRY(dr0)
	movl	S_ARG0, %eax
	movl	%eax,EXT(dr_addr)
	movl	%eax, %db0
	movl	$0, %ecx
	jmp	0f
ENTRY(dr1)
	movl	S_ARG0, %eax
	movl	%eax,EXT(dr_addr)+1*4
	movl	%eax, %db1
	movl	$2, %ecx
	jmp	0f
ENTRY(dr2)
	movl	S_ARG0, %eax
	movl	%eax,EXT(dr_addr)+2*4
	movl	%eax, %db2
	movl	$4, %ecx
	jmp	0f

ENTRY(dr3)
	movl	S_ARG0, %eax
	movl	%eax,EXT(dr_addr)+3*4
	movl	%eax, %db3
	movl	$6, %ecx

0:
	pushl	%ebp
	movl	%esp, %ebp

	movl	%db7, %edx
	movl	%edx,EXT(dr_addr)+4*4
	andl	dr_msk(,%ecx,2),%edx	/* clear out new entry */
	movl	%edx,EXT(dr_addr)+5*4
	movzbl	B_ARG3, %eax
	andb	$3, %al
	shll	%cl, %eax
	orl	%eax, %edx

	movzbl	B_ARG1, %eax
	andb	$3, %al
	addb	$0x10, %ecx
	shll	%cl, %eax
	orl	%eax, %edx

	movzbl	B_ARG2, %eax
	andb	$3, %al
	addb	$0x2, %ecx
	shll	%cl, %eax
	orl	%eax, %edx

	movl	%edx, %db7
	movl	%edx,EXT(dr_addr)+7*4
	movl	%edx, %eax
	leave
	ret

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

ENTRY(get_cr0)
	movl	%cr0, %eax
	ret

ENTRY(set_cr0)
	movl	4(%esp), %eax
	movl	%eax, %cr0
	ret

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

#if	ETAP

ENTRY(etap_get_pc)
	movl	4(%ebp), %eax		/* fetch pc of caller */
	ret

ENTRY(tvals_to_etap)
        movl	S_ARG0, %eax
	movl	$1000000000, %ecx
	mull	%ecx
	addl	S_ARG1, %eax
        adc     $0, %edx
       	ret

/* etap_time_t
 * etap_time_sub(etap_time_t stop, etap_time_t start)
 *	
 *	64bit subtract, returns stop - start
 */		 	
ENTRY(etap_time_sub)
	movl	S_ARG0, %eax		/* stop.low */
	movl	S_ARG1, %edx		/* stop.hi */
	subl	S_ARG2, %eax		/* stop.lo - start.lo */
	sbbl	S_ARG3, %edx		/* stop.hi - start.hi */
	ret
		
#endif	/* ETAP */
	
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

#ifdef	MACH_BSD
/*
 * BSD System call entry point.. 
 */

Entry(trap_unix_syscall)
trap_unix_addr:	
	pushf				/* save flags as soon as possible */
trap_unix_2:	
	pushl	%eax			/* save system call number */
	pushl	$0			/* clear trap number slot */

	pusha				/* save the general registers */
	pushl	%ds			/* and the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

	mov	%ss,%dx			/* switch to kernel data segment */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

/*
 * Shuffle eflags,eip,cs into proper places
 */

	movl	R_EIP(%esp),%ebx	/* eflags are in EIP slot */
	movl	R_CS(%esp),%ecx		/* eip is in CS slot */
	movl	R_EFLAGS(%esp),%edx	/* cs is in EFLAGS slot */
	movl	%ecx,R_EIP(%esp)	/* fix eip */
	movl	%edx,R_CS(%esp)		/* fix cs */
	movl	%ebx,R_EFLAGS(%esp)	/* fix eflags */

        TIME_TRAP_UENTRY

        negl    %eax                    /* get system call number */
        shll    $4,%eax                 /* manual indexing */

	movl	%gs:CPU_KERNEL_STACK,%ebx
					/* get current kernel stack */
	xchgl	%ebx,%esp		/* switch stacks - %ebx points to */
					/* user registers. */

/*
 * Register use on entry:
 *   eax contains syscall number
 *   ebx contains user regs pointer
 */
	CAH(call_call)
	pushl	%ebx			/* Push the regs set onto stack */
	call	EXT(unix_syscall)
	popl	%ebx
	movl	%esp,%ecx		/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp	/* switch back to PCB stack */
	movl	%eax,R_EAX(%esp)	/* save return value */
	jmp	EXT(return_from_trap)	/* return to user */

/*
 * Entry point for machdep system calls..
 */

Entry(trap_machdep_syscall)
	pushf				/* save flags as soon as possible */
	pushl	%eax			/* save system call number */
	pushl	$0			/* clear trap number slot */

	pusha				/* save the general registers */
	pushl	%ds			/* and the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

	mov	%ss,%dx			/* switch to kernel data segment */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

/*
 * Shuffle eflags,eip,cs into proper places
 */

	movl	R_EIP(%esp),%ebx	/* eflags are in EIP slot */
	movl	R_CS(%esp),%ecx		/* eip is in CS slot */
	movl	R_EFLAGS(%esp),%edx	/* cs is in EFLAGS slot */
	movl	%ecx,R_EIP(%esp)	/* fix eip */
	movl	%edx,R_CS(%esp)		/* fix cs */
	movl	%ebx,R_EFLAGS(%esp)	/* fix eflags */

        TIME_TRAP_UENTRY

        negl    %eax                    /* get system call number */
        shll    $4,%eax                 /* manual indexing */

	movl	%gs:CPU_KERNEL_STACK,%ebx
					/* get current kernel stack */
	xchgl	%ebx,%esp		/* switch stacks - %ebx points to */
					/* user registers. */

/*
 * Register use on entry:
 *   eax contains syscall number
 *   ebx contains user regs pointer
 */
	CAH(call_call)
	pushl	%ebx
	call	EXT(machdep_syscall)
	popl	%ebx
	movl	%esp,%ecx		/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp	/* switch back to PCB stack */
	movl	%eax,R_EAX(%esp)	/* save return value */
	jmp	EXT(return_from_trap)	/* return to user */

Entry(trap_mach25_syscall)
	pushf				/* save flags as soon as possible */
	pushl	%eax			/* save system call number */
	pushl	$0			/* clear trap number slot */

	pusha				/* save the general registers */
	pushl	%ds			/* and the segment registers */
	pushl	%es
	pushl	%fs
	pushl	%gs

	mov	%ss,%dx			/* switch to kernel data segment */
	mov	%dx,%ds
	mov	%dx,%es
	mov	$ CPU_DATA_GS,%dx
	mov	%dx,%gs

/*
 * Shuffle eflags,eip,cs into proper places
 */

	movl	R_EIP(%esp),%ebx	/* eflags are in EIP slot */
	movl	R_CS(%esp),%ecx		/* eip is in CS slot */
	movl	R_EFLAGS(%esp),%edx	/* cs is in EFLAGS slot */
	movl	%ecx,R_EIP(%esp)	/* fix eip */
	movl	%edx,R_CS(%esp)		/* fix cs */
	movl	%ebx,R_EFLAGS(%esp)	/* fix eflags */

        TIME_TRAP_UENTRY

        negl    %eax                    /* get system call number */
        shll    $4,%eax                 /* manual indexing */

	movl	%gs:CPU_KERNEL_STACK,%ebx
					/* get current kernel stack */
	xchgl	%ebx,%esp		/* switch stacks - %ebx points to */
					/* user registers. */

/*
 * Register use on entry:
 *   eax contains syscall number
 *   ebx contains user regs pointer
 */
	CAH(call_call)
	pushl	%ebx
	call	EXT(mach25_syscall)
	popl	%ebx
	movl	%esp,%ecx		/* get kernel stack */
	or	$(KERNEL_STACK_SIZE-1),%ecx
	movl	-3-IKS_SIZE(%ecx),%esp	/* switch back to PCB stack */
	movl	%eax,R_EAX(%esp)	/* save return value */
	jmp	EXT(return_from_trap)	/* return to user */

#endif
