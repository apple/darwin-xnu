/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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

/*
 *	File:	machine/thread.h
 *
 *	This file contains the structure definitions for the thread
 *	state as applied to I386 processors.
 */

#ifndef	_I386_THREAD_H_
#define _I386_THREAD_H_

#include <mach/boolean.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/fp_reg.h>
#include <mach/thread_status.h>

#include <kern/lock.h>

#include <i386/iopb.h>
#include <i386/seg.h>
#include <i386/tss.h>
#include <i386/eflags.h>

/*
 *	i386_saved_state:
 *
 *	Has been exported to servers.  See: mach/i386/thread_status.h
 *
 *	This structure corresponds to the state of user registers
 *	as saved upon kernel entry.  It lives in the pcb.
 *	It is also pushed onto the stack for exceptions in the kernel.
 *	For performance, it is also used directly in syscall exceptions
 *	if the server has requested i386_THREAD_STATE flavor for the exception
 *	port.
 *
 *	We define the following as an alias for the "esp" field of the
 *	structure, because we actually save cr2 here, not the kernel esp.
 */
#define cr2	esp

/*
 *	Save area for user floating-point state.
 *	Allocated only when necessary.
 */

struct i386_fpsave_state {
	boolean_t		fp_valid;
	struct i386_fp_save	fp_save_state;
	struct i386_fp_regs	fp_regs;
        struct i386_fx_save 	fx_save_state __attribute__ ((aligned (16)));
	int			fp_save_flavor;
};

/*
 *	v86_assist_state:
 *
 *	This structure provides data to simulate 8086 mode
 *	interrupts.  It lives in the pcb.
 */

struct v86_assist_state {
	vm_offset_t		int_table;
	unsigned short		int_count;
	unsigned short		flags;	/* 8086 flag bits */
};
#define	V86_IF_PENDING		0x8000	/* unused bit */

/*
 *	i386_interrupt_state:
 *
 *	This structure describes the set of registers that must
 *	be pushed on the current ring-0 stack by an interrupt before
 *	we can switch to the interrupt stack.
 */

struct i386_interrupt_state {
        int     gs;
        int     fs;
	int	es;
	int	ds;
	int	edx;
	int	ecx;
	int	eax;
	int	eip;
	int	cs;
	int	efl;
};

/*
 *	i386_kernel_state:
 *
 *	This structure corresponds to the state of kernel registers
 *	as saved in a context-switch.  It lives at the base of the stack.
 */

struct i386_kernel_state {
	int			k_ebx;	/* kernel context */
	int			k_esp;
	int			k_ebp;
	int			k_edi;
	int			k_esi;
	int			k_eip;
};

/*
 *	i386_machine_state:
 *
 *	This structure corresponds to special machine state.
 *	It lives in the pcb.  It is not saved by default.
 */

struct i386_machine_state {
	iopb_tss_t		io_tss;
	struct user_ldt	*	ldt;
	struct i386_fpsave_state *ifps;
	struct v86_assist_state	v86s;
};

typedef struct pcb {
	struct i386_interrupt_state iis[2];	/* interrupt and NMI */
	struct i386_saved_state iss;
	struct i386_machine_state ims;
#ifdef	MACH_BSD
	unsigned long	cthread_self;		/* for use of cthread package */
        struct real_descriptor cthread_desc;
	unsigned long  uldt_selector;          /* user ldt selector to set */
	struct real_descriptor uldt_desc;      /* the actual user setable ldt data */
#endif
	decl_simple_lock_data(,lock)
} *pcb_t;

/*
 * Maps state flavor to number of words in the state:
 */
__private_extern__ unsigned int _MachineStateCount[];

#define USER_REGS(ThrAct)	(&(ThrAct)->machine.pcb->iss)

#define act_machine_state_ptr(ThrAct)	(thread_state_t)USER_REGS(ThrAct)


#define	is_user_thread(ThrAct)	\
  	((USER_REGS(ThrAct)->efl & EFL_VM) \
	 || ((USER_REGS(ThrAct)->cs & 0x03) != 0))

#define	user_pc(ThrAct)		(USER_REGS(ThrAct)->eip)
#define	user_sp(ThrAct)		(USER_REGS(ThrAct)->uesp)

struct machine_thread {
	/*
	 * pointer to process control block
	 *	(actual storage may as well be here, too)
	 */
	struct pcb xxx_pcb;
	pcb_t pcb;

};

extern struct i386_saved_state *get_user_regs(thread_t);

extern void *act_thread_csave(void);
extern void act_thread_catt(void *ctx);
extern void act_thread_cfree(void *ctx);

/*
 *	i386_exception_link:
 *
 *	This structure lives at the high end of the kernel stack.
 *	It points to the current thread`s user registers.
 */
struct i386_exception_link {
	struct i386_saved_state *saved_state;
};


/*
 *	On the kernel stack is:
 *	stack:	...
 *		struct i386_exception_link
 *		struct i386_kernel_state
 *	stack+KERNEL_STACK_SIZE
 */

#define STACK_IKS(stack)	\
	((struct i386_kernel_state *)((stack) + KERNEL_STACK_SIZE) - 1)
#define STACK_IEL(stack)	\
	((struct i386_exception_link *)STACK_IKS(stack) - 1)

/*
 * Return address of the function that called current function, given
 *	address of the first parameter of current function.
 */
#define	GET_RETURN_PC(addr)	(*((vm_offset_t *)addr - 1))

/*
 * Defining this indicates that MD code will supply an exception()
 * routine, conformant with kern/exception.c (dependency alert!)
 * but which does wonderfully fast, machine-dependent magic.
 */
#define MACHINE_FAST_EXCEPTION 1

#endif	/* _I386_THREAD_H_ */
