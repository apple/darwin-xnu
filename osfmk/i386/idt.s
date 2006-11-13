/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 */
#include <i386/asm.h>
#include <assym.s>
#include <mach_kdb.h>
#include <i386/eflags.h>
#include <i386/trap.h>

#define HI_DATA(lo_addr)	( (EXT(lo_addr) - EXT(hi_remap_data)) + HIGH_IDT_BASE )
#define HI_TEXT(lo_text)	( (EXT(lo_text) - EXT(hi_remap_text)) + HIGH_MEM_BASE )

/*
 * Interrupt descriptor table and code vectors for it.
 */
#define	IDT_BASE_ENTRY(vec,seg,type) \
	.data			;\
	.long	EXT(vec) - EXT(hi_remap_text) + HIGH_MEM_BASE ;\
	.word	seg		;\
	.byte	0		;\
	.byte	type		;\
	.text

#define	IDT_BASE_ENTRY_INT(vec,seg,type) \
	.data			;\
	.long	vec - EXT(hi_remap_text) + HIGH_MEM_BASE ;\
	.word	seg		;\
	.byte	0		;\
	.byte	type		;\
	.text

#define	IDT_BASE_ENTRY_TG(vec,seg,type) \
	.data			;\
	.long	0		;\
	.word	seg		;\
	.byte	0		;\
	.byte	type		;\
	.text

#define	IDT_ENTRY(vec,type)	IDT_BASE_ENTRY(vec,KERNEL_CS,type)
#define	IDT_ENTRY_INT(vec,type)	IDT_BASE_ENTRY_INT(vec,KERNEL_CS,type)

/*
 * No error code.  Clear error code and push trap number.
 */
#define	EXCEPTION(n,name) \
	IDT_ENTRY(name,K_INTR_GATE);\
Entry(name)				;\
	pushl	$0			;\
	pushl	$(n)			;\
	pusha				;\
	movl	$ EXT(lo_alltraps),%ebx	;\
	jmp	enter_lohandler

	
/*
 * Interrupt from user.  Clear error code and push trap number.
 */
#define	EXCEP_USR(n,name) \
	IDT_ENTRY(name,U_INTR_GATE);\
Entry(name)				;\
	pushl	$0			;\
	pushl	$(n)			;\
	pusha				;\
	movl	$ EXT(lo_alltraps),%ebx	;\
	jmp	enter_lohandler
	

/*
 * Special interrupt code.
 */
#define	EXCEP_SPC(n,name)  \
	IDT_ENTRY(name,K_INTR_GATE) 
	
/*
 * Special interrupt code from user.
 */
#define EXCEP_SPC_USR(n,name)  \
	IDT_ENTRY(name,U_INTR_GATE) 


/*
 * Extra-special interrupt code.  Note that no offset may be
 * specified in a task gate descriptor, so name is ignored.
 */
#define	EXCEP_TASK(n,name)  \
	IDT_BASE_ENTRY_TG(0,DEBUG_TSS,K_TASK_GATE)

/* Double-fault fatal handler */
#define DF_FATAL_TASK(n,name)  \
	IDT_BASE_ENTRY_TG(0,DF_TSS,K_TASK_GATE)

/* machine-check handler */
#define MC_FATAL_TASK(n,name)  \
	IDT_BASE_ENTRY_TG(0,MC_TSS,K_TASK_GATE)

/*
 * Error code has been pushed.  Push trap number.
 */
#define	EXCEP_ERR(n,name) \
	IDT_ENTRY(name,K_INTR_GATE);\
Entry(name)				;\
	pushl	$(n)			;\
	pusha				;\
	movl	$ EXT(lo_alltraps),%ebx	;\
	jmp	enter_lohandler

	
/*
 * Interrupt.
 */
#define	INTERRUPT(n) \
	IDT_ENTRY_INT(L_ ## n,K_INTR_GATE)	;\
	.align FALIGN				;\
L_ ## n:					;\
	pushl	$0				;\
	pushl	$(n)				;\
	pusha					;\
	movl	$ EXT(lo_allintrs),%ebx		;\
	jmp	enter_lohandler


	.data
	.align 12
Entry(master_idt)
Entry(hi_remap_data)
	.text
Entry(hi_remap_text)

EXCEPTION(0x00,t_zero_div)
EXCEP_SPC(0x01,hi_debug)
INTERRUPT(0x02)			/* NMI */
EXCEP_USR(0x03,t_int3)
EXCEP_USR(0x04,t_into)
EXCEP_USR(0x05,t_bounds)
EXCEPTION(0x06,t_invop)
EXCEPTION(0x07,t_nofpu)
#if	MACH_KDB
EXCEP_TASK(0x08,db_task_dbl_fault)
#else
DF_FATAL_TASK(0x08,df_task_start)
#endif
EXCEPTION(0x09,a_fpu_over)
EXCEPTION(0x0a,a_inv_tss)
EXCEP_SPC(0x0b,hi_segnp)
#if	MACH_KDB
EXCEP_TASK(0x0c,db_task_stk_fault)
#else
EXCEP_ERR(0x0c,t_stack_fault)
#endif
EXCEP_SPC(0x0d,hi_gen_prot)
EXCEP_SPC(0x0e,hi_page_fault)
EXCEPTION(0x0f,t_trap_0f)
EXCEPTION(0x10,t_fpu_err)
EXCEPTION(0x11,t_trap_11)
MC_FATAL_TASK(0x12,mc_task_start)
EXCEPTION(0x13,t_sse_err)
EXCEPTION(0x14,t_trap_14)
EXCEPTION(0x15,t_trap_15)
EXCEPTION(0x16,t_trap_16)
EXCEPTION(0x17,t_trap_17)
EXCEPTION(0x18,t_trap_18)
EXCEPTION(0x19,t_trap_19)
EXCEPTION(0x1a,t_trap_1a)
EXCEPTION(0x1b,t_trap_1b)
EXCEPTION(0x1c,t_trap_1c)
EXCEPTION(0x1d,t_trap_1d)
EXCEPTION(0x1e,t_trap_1e)
EXCEPTION(0x1f,t_trap_1f)

INTERRUPT(0x20)
INTERRUPT(0x21)
INTERRUPT(0x22)
INTERRUPT(0x23)
INTERRUPT(0x24)
INTERRUPT(0x25)
INTERRUPT(0x26)
INTERRUPT(0x27)
INTERRUPT(0x28)
INTERRUPT(0x29)
INTERRUPT(0x2a)
INTERRUPT(0x2b)
INTERRUPT(0x2c)
INTERRUPT(0x2d)
INTERRUPT(0x2e)
INTERRUPT(0x2f)

INTERRUPT(0x30)
INTERRUPT(0x31)
INTERRUPT(0x32)
INTERRUPT(0x33)
INTERRUPT(0x34)
INTERRUPT(0x35)
INTERRUPT(0x36)
INTERRUPT(0x37)
INTERRUPT(0x38)
INTERRUPT(0x39)
INTERRUPT(0x3a)
INTERRUPT(0x3b)
INTERRUPT(0x3c)
INTERRUPT(0x3d)
INTERRUPT(0x3e)
INTERRUPT(0x3f)

INTERRUPT(0x40)
INTERRUPT(0x41)
INTERRUPT(0x42)
INTERRUPT(0x43)
INTERRUPT(0x44)
INTERRUPT(0x45)
INTERRUPT(0x46)
INTERRUPT(0x47)
INTERRUPT(0x48)
INTERRUPT(0x49)
INTERRUPT(0x4a)
INTERRUPT(0x4b)
INTERRUPT(0x4c)
INTERRUPT(0x4d)
INTERRUPT(0x4e)
INTERRUPT(0x4f)

INTERRUPT(0x50)
INTERRUPT(0x51)
INTERRUPT(0x52)
INTERRUPT(0x53)
INTERRUPT(0x54)
INTERRUPT(0x55)
INTERRUPT(0x56)
INTERRUPT(0x57)
INTERRUPT(0x58)
INTERRUPT(0x59)
INTERRUPT(0x5a)
INTERRUPT(0x5b)
INTERRUPT(0x5c)
INTERRUPT(0x5d)
INTERRUPT(0x5e)
INTERRUPT(0x5f)

INTERRUPT(0x60)
INTERRUPT(0x61)
INTERRUPT(0x62)
INTERRUPT(0x63)
INTERRUPT(0x64)
INTERRUPT(0x65)
INTERRUPT(0x66)
INTERRUPT(0x67)
INTERRUPT(0x68)
INTERRUPT(0x69)
INTERRUPT(0x6a)
INTERRUPT(0x6b)
INTERRUPT(0x6c)
INTERRUPT(0x6d)
INTERRUPT(0x6e)
INTERRUPT(0x6f)

INTERRUPT(0x70)
INTERRUPT(0x71)
INTERRUPT(0x72)
INTERRUPT(0x73)
INTERRUPT(0x74)
INTERRUPT(0x75)
INTERRUPT(0x76)
INTERRUPT(0x77)
INTERRUPT(0x78)
INTERRUPT(0x79)
INTERRUPT(0x7a)
INTERRUPT(0x7b)
INTERRUPT(0x7c)
INTERRUPT(0x7d)
INTERRUPT(0x7e)
INTERRUPT(0x7f)

EXCEP_SPC_USR(0x80,hi_unix_scall)
EXCEP_SPC_USR(0x81,hi_mach_scall)
EXCEP_SPC_USR(0x82,hi_mdep_scall)
EXCEP_SPC_USR(0x83,hi_diag_scall)

INTERRUPT(0x84)
INTERRUPT(0x85)
INTERRUPT(0x86)
INTERRUPT(0x87)
INTERRUPT(0x88)
INTERRUPT(0x89)
INTERRUPT(0x8a)
INTERRUPT(0x8b)
INTERRUPT(0x8c)
INTERRUPT(0x8d)
INTERRUPT(0x8e)
INTERRUPT(0x8f)

INTERRUPT(0x90)
INTERRUPT(0x91)
INTERRUPT(0x92)
INTERRUPT(0x93)
INTERRUPT(0x94)
INTERRUPT(0x95)
INTERRUPT(0x96)
INTERRUPT(0x97)
INTERRUPT(0x98)
INTERRUPT(0x99)
INTERRUPT(0x9a)
INTERRUPT(0x9b)
INTERRUPT(0x9c)
INTERRUPT(0x9d)
INTERRUPT(0x9e)
INTERRUPT(0x9f)

INTERRUPT(0xa0)
INTERRUPT(0xa1)
INTERRUPT(0xa2)
INTERRUPT(0xa3)
INTERRUPT(0xa4)
INTERRUPT(0xa5)
INTERRUPT(0xa6)
INTERRUPT(0xa7)
INTERRUPT(0xa8)
INTERRUPT(0xa9)
INTERRUPT(0xaa)
INTERRUPT(0xab)
INTERRUPT(0xac)
INTERRUPT(0xad)
INTERRUPT(0xae)
INTERRUPT(0xaf)

INTERRUPT(0xb0)
INTERRUPT(0xb1)
INTERRUPT(0xb2)
INTERRUPT(0xb3)
INTERRUPT(0xb4)
INTERRUPT(0xb5)
INTERRUPT(0xb6)
INTERRUPT(0xb7)
INTERRUPT(0xb8)
INTERRUPT(0xb9)
INTERRUPT(0xba)
INTERRUPT(0xbb)
INTERRUPT(0xbc)
INTERRUPT(0xbd)
INTERRUPT(0xbe)
INTERRUPT(0xbf)

INTERRUPT(0xc0)
INTERRUPT(0xc1)
INTERRUPT(0xc2)
INTERRUPT(0xc3)
INTERRUPT(0xc4)
INTERRUPT(0xc5)
INTERRUPT(0xc6)
INTERRUPT(0xc7)
INTERRUPT(0xc8)
INTERRUPT(0xc9)
INTERRUPT(0xca)
INTERRUPT(0xcb)
INTERRUPT(0xcc)
INTERRUPT(0xcd)
INTERRUPT(0xce)
INTERRUPT(0xcf)

INTERRUPT(0xd0)
INTERRUPT(0xd1)
INTERRUPT(0xd2)
INTERRUPT(0xd3)
INTERRUPT(0xd4)
INTERRUPT(0xd5)
INTERRUPT(0xd6)
INTERRUPT(0xd7)
INTERRUPT(0xd8)
INTERRUPT(0xd9)
INTERRUPT(0xda)
INTERRUPT(0xdb)
INTERRUPT(0xdc)
INTERRUPT(0xdd)
INTERRUPT(0xde)
INTERRUPT(0xdf)

INTERRUPT(0xe0)
INTERRUPT(0xe1)
INTERRUPT(0xe2)
INTERRUPT(0xe3)
INTERRUPT(0xe4)
INTERRUPT(0xe5)
INTERRUPT(0xe6)
INTERRUPT(0xe7)
INTERRUPT(0xe8)
INTERRUPT(0xe9)
INTERRUPT(0xea)
INTERRUPT(0xeb)
INTERRUPT(0xec)
INTERRUPT(0xed)
INTERRUPT(0xee)
INTERRUPT(0xef)

INTERRUPT(0xf0)
INTERRUPT(0xf1)
INTERRUPT(0xf2)
INTERRUPT(0xf3)
INTERRUPT(0xf4)
INTERRUPT(0xf5)
INTERRUPT(0xf6)
INTERRUPT(0xf7)
INTERRUPT(0xf8)
INTERRUPT(0xf9)
INTERRUPT(0xfa)
INTERRUPT(0xfb)
INTERRUPT(0xfc)
INTERRUPT(0xfd)
INTERRUPT(0xfe)
EXCEPTION(0xff,t_preempt)


	.data
Entry(lo_kernel_cr3)
	.long 0
	.long 0
	
        .text

	
/*******************************************************************************************************
 *
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
 */

	
Entry(hi_ret_to_user)
	movl	%esp,%ebx
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	subl	ACT_PCB_ISS(%ecx),%ebx
	movl	$(WINDOWS_CLEAN),ACT_COPYIO_STATE(%ecx)

	movl	ACT_PCB_IDS(%ecx),%eax	/* get debug state struct */
	cmpl	$0,%eax			/* is there a debug state */
	je	1f 			/* branch if not */
	movl	DS_DR0(%eax), %ecx	/* Load the 32 bit debug registers */
	movl	%ecx, %db0
	movl	DS_DR1(%eax), %ecx
	movl	%ecx, %db1
	movl	DS_DR2(%eax), %ecx
	movl	%ecx, %db2
	movl	DS_DR3(%eax), %ecx
	movl	%ecx, %db3
	movl	DS_DR7(%eax), %eax
1:
	addl	%gs:CPU_HI_ISS,%ebx	/* rebase PCB save area to high addr */
	movl	%gs:CPU_TASK_CR3,%ecx
	movl	%ecx,%gs:CPU_ACTIVE_CR3
	movl	%ebx,%esp		/* switch to hi based PCB stack */
	movl    %ecx,%cr3               /* switch to user's address space */

	cmpl	$0,%eax			/* is dr7 set to something? */
	je	2f 			/* branch if not */
	movl	%eax,%db7		/* Set dr7 */
2:

Entry(hi_ret_to_kernel)

	popl	%eax			/* ignore flavor of saved state */
EXT(ret_popl_gs):
	popl	%gs			/* restore segment registers */
EXT(ret_popl_fs):
	popl	%fs
EXT(ret_popl_es):
	popl	%es
EXT(ret_popl_ds):	
	popl	%ds

        popa                            /* restore general registers */
        addl    $8,%esp                 /* discard trap number and error code */

        cmpl    $(SYSENTER_CS),4(%esp)  /* test for fast entry/exit */
        je      fast_exit
EXT(ret_iret):
        iret                            /* return from interrupt */
fast_exit:
	popl    %edx                    /* user return eip */
        popl    %ecx                    /* pop and toss cs */
	andl	$(~EFL_IF),(%esp)	/* clear intrs enabled, see sti below */
        popf                            /* flags - carry denotes failure */
        popl    %ecx                    /* user return esp */
	sti				/* interrupts enabled after sysexit */
        sysexit

/*******************************************************************************************************/

		
Entry(hi_unix_scall)
	pushl   %eax                    /* save system call number */
        pushl   $0                      /* clear trap number slot */
        pusha                           /* save the general registers */
	movl	$ EXT(lo_unix_scall),%ebx
	jmp	enter_lohandler

	
Entry(hi_mach_scall)
	pushl   %eax                    /* save system call number */
        pushl   $0                      /* clear trap number slot */
        pusha                           /* save the general registers */
	movl	$ EXT(lo_mach_scall),%ebx
	jmp	enter_lohandler

	
Entry(hi_mdep_scall)
	pushl   %eax                    /* save system call number */
        pushl   $0                      /* clear trap number slot */
        pusha                           /* save the general registers */
	movl	$ EXT(lo_mdep_scall),%ebx
	jmp	enter_lohandler

	
Entry(hi_diag_scall)
	pushl   %eax                    // Save sselector
        pushl   $0                      // Clear trap number slot
        pusha                           // save the general registers
	movl	$EXT(lo_diag_scall),%ebx	// Get the function down low to transfer to
	jmp	enter_lohandler			// Leap to it...

	
/*
 * sysenter entry point
 * Requires user code to set up:
 *	edx: user instruction pointer (return address)
 *	ecx: user stack pointer
 *		on which is pushed stub ret addr and saved ebx
 * Return to user-space is made using sysexit.
 * Note: sysenter/sysexit cannot be used for calls returning a value in edx,
 *       or requiring ecx to be preserved.
 */
Entry(hi_sysenter)
	movl	(%esp), %esp		/* switch from intr stack to pcb */
	/*
	 * Push values on to the PCB stack
	 * to cons up the saved state.
	 */
	pushl	$(USER_DS)		/* ss */
	pushl	%ecx			/* uesp */
	pushf				/* flags */
	/*
	* Clear, among others, the Nested Task (NT) flags bit;
	* This is cleared by INT, but not by sysenter, which only
	* clears RF, VM and IF.
	*/
	pushl	$0
	popfl
	pushl	$(SYSENTER_CS)		/* cs */
hi_sysenter_2:
	pushl	%edx			/* eip */
	pushl	%eax			/* err/eax - syscall code */
	pushl	$0			/* clear trap number slot */
	pusha				/* save the general registers */
	orl	$(EFL_IF),R_EFLAGS-R_EDI(%esp)	/* (edi was last reg pushed) */
	movl	$ EXT(lo_sysenter),%ebx
enter_lohandler:
	pushl   %ds
	pushl   %es
        pushl   %fs
        pushl   %gs
enter_lohandler1:
	pushl	$(SS_32)		/* 32-bit state flavor */
	mov	%ss,%eax
	mov	%eax,%ds
	mov	%eax,%fs
	mov	%eax,%es		/* switch to kernel data seg */
	mov	$(CPU_DATA_GS),%eax
	mov	%eax,%gs
	cld				/* clear direction flag */
	/*
	 * Switch to kernel's address space if necessary
	 */
	movl    HI_DATA(lo_kernel_cr3),%ecx
	movl	%cr3,%eax
	cmpl	%eax,%ecx
	je	1f
	movl	%ecx,%cr3
	movl	%ecx,%gs:CPU_ACTIVE_CR3
1:
	testb	$3,R_CS(%esp)
	jz	2f
	movl	%esp,%edx			/* came from user mode */
	subl	%gs:CPU_HI_ISS,%edx
	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	addl	ACT_PCB_ISS(%ecx),%edx		/* rebase the high stack to a low address */
	movl	%edx,%esp
	cmpl	$0, ACT_PCB_IDS(%ecx)	/* Is there a debug register state? */
	je	2f
	movl	$0, %ecx		/* If so, reset DR7 (the control) */
	movl	%ecx, %dr7
2:
	movl	R_TRAPNO(%esp),%ecx			// Get the interrupt vector
	addl	$1,%gs:hwIntCnt(,%ecx,4)	// Bump the count
	jmp	*%ebx

	
/*
 * Page fault traps save cr2.
 */
Entry(hi_page_fault)
	pushl	$(T_PAGE_FAULT)		/* mark a page fault trap */
	pusha				/* save the general registers */
	movl	%cr2,%eax		/* get the faulting address */
	movl	%eax,R_CR2-R_EDI(%esp)	/* save in esp save slot */

	movl	$ EXT(lo_alltraps),%ebx
	jmp	enter_lohandler



/*
 * Debug trap.  Check for single-stepping across system call into
 * kernel.  If this is the case, taking the debug trap has turned
 * off single-stepping - save the flags register with the trace
 * bit set.
 */
Entry(hi_debug)
	testb	$3,4(%esp)
	jnz	hi_debug_trap
					/* trap came from kernel mode */
	cmpl	$(HI_TEXT(hi_mach_scall)),(%esp)
	jne	6f
	addl	$12,%esp		/* remove eip/cs/eflags from debug_trap */
	jmp	EXT(hi_mach_scall)	/* continue system call entry */
6:
	cmpl	$(HI_TEXT(hi_mdep_scall)),(%esp)
	jne	5f
	addl	$12,%esp		/* remove eip/cs/eflags from debug_trap */
	jmp	EXT(hi_mdep_scall)	/* continue system call entry */
5:
	cmpl	$(HI_TEXT(hi_unix_scall)),(%esp)
	jne	4f
	addl	$12,%esp		/* remove eip/cs/eflags from debug_trap */
	jmp	EXT(hi_unix_scall)	/* continue system call entry */
4:
	cmpl	$(HI_TEXT(hi_sysenter)),(%esp)
	jne	hi_debug_trap
	/*
	 * eip/cs/flags have been pushed on intr stack
	 * We have to switch to pcb stack and copy eflags.
	 * Note: setting the cs selector to SYSENTER_TF_CS
	 * will cause the return to user path to take the iret path so
	 * that eflags (containing the trap bit) is set atomically.
	 * In unix_syscall this is tested so that we'll rewind the pc
	 * to account for with sysenter or int entry.
	 */ 
	addl	$8,%esp			/* remove eip/cs */
	pushl	%ecx			/* save %ecx */
	movl	8(%esp),%ecx		/* top of intr stack -> pcb stack */
	xchgl	%ecx,%esp		/* switch to pcb stack */
	pushl	$(USER_DS)		/* ss */
	pushl	%ss:(%ecx)		/* %ecx into uesp slot */
	pushl	%ss:4(%ecx)		/* eflags */
	movl	%ss:(%ecx),%ecx		/* restore %ecx */
	pushl	$(SYSENTER_TF_CS)	/* cs - not SYSENTER_CS for iret path */
	jmp	hi_sysenter_2		/* continue sysenter entry */
hi_debug_trap:
	pushl	$0
	pushl	$(T_DEBUG)		/* handle as user trap */
	pusha				/* save the general registers */
	movl	$ EXT(lo_alltraps),%ebx
	jmp	enter_lohandler	



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
Entry(hi_gen_prot)
	pushl	$(T_GENERAL_PROTECTION)	/* indicate fault type */
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(hi_segnp)
	pushl	$(T_SEGMENT_NOT_PRESENT)
					/* indicate fault type */
trap_check_kernel_exit:
	testb	$3,12(%esp)
	jnz	hi_take_trap
					/* trap was from kernel mode, so */
					/* check for the kernel exit sequence */
	cmpl	$(HI_TEXT(ret_iret)),8(%esp)	/* on IRET? */
	je	fault_iret
	cmpl	$(HI_TEXT(ret_popl_ds)),8(%esp)	/* popping DS? */
	je	fault_popl_ds
	cmpl	$(HI_TEXT(ret_popl_es)),8(%esp)	/* popping ES? */
	je	fault_popl_es
	cmpl	$(HI_TEXT(ret_popl_fs)),8(%esp)	/* popping FS? */
	je	fault_popl_fs
	cmpl	$(HI_TEXT(ret_popl_gs)),8(%esp)	/* popping GS? */
	je	fault_popl_gs
hi_take_trap:
	pusha				/* save the general registers */
	movl	$ EXT(lo_alltraps),%ebx
	jmp	enter_lohandler

		
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
					/* now treat as fault from user */
	pusha				/* save the general registers */
	movl	$ EXT(lo_alltraps),%ebx
	jmp	enter_lohandler

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
	jmp	push_none		/* (GS on top of stack) */

push_es:
	pushl	%es			/* restore es, */
push_fs:
	pushl	%fs			/* restore fs, */
push_gs:
	pushl	%gs			/* restore gs. */
push_none:
	movl	%eax,R_TRAPNO(%esp)	/* set trap number */
	movl	%edx,R_ERR(%esp)	/* set error code */
					/* now treat as fault from user */
					/* except that segment registers are */
					/* already pushed */
	movl	$ EXT(lo_alltraps),%ebx
	jmp	enter_lohandler1

	
        .text


Entry(lo_ret_to_user)
	jmp *1f
1:	.long HI_TEXT(hi_ret_to_user) 

Entry(lo_ret_to_kernel)
	jmp *1f
1:	.long HI_TEXT(hi_ret_to_kernel)

Entry(hi_remap_etext)
