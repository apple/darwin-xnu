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

#include <cpus.h>
#include <mach_rt.h>
#include <mach_debug.h>
#include <mach_ldebug.h>

#include <sys/kdebug.h>

#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/thread_swap.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/spl.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <i386/thread.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/seg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/iopb_entries.h>

vm_offset_t         active_stacks[NCPUS];
vm_offset_t         kernel_stack[NCPUS];
thread_act_t		active_kloaded[NCPUS];

/*
 * Maps state flavor to number of words in the state:
 */
unsigned int state_count[] = {
	/* FLAVOR_LIST */ 0,
	i386_NEW_THREAD_STATE_COUNT,
	i386_FLOAT_STATE_COUNT,
	i386_ISA_PORT_MAP_STATE_COUNT,
	i386_V86_ASSIST_STATE_COUNT,
	i386_REGS_SEGS_STATE_COUNT,
	i386_THREAD_SYSCALL_STATE_COUNT,
	/* THREAD_STATE_NONE */ 0,
	i386_SAVED_STATE_COUNT,
};

/* Forward */

void act_machine_throughcall(thread_act_t thr_act);
extern thread_t		Switch_context(
				thread_t		old,
				void			(*cont)(void),
				thread_t		new);
extern void		Thread_continue(void);
extern void		Load_context(
				thread_t		thread);

/*
 * consider_machine_collect:
 *
 *	Try to collect machine-dependent pages
 */
void
consider_machine_collect()
{
}

void
consider_machine_adjust()
{
}


/*
 *	machine_kernel_stack_init:
 *
 *	Initialize a kernel stack which has already been
 *	attached to its thread_activation.
 */

void
machine_kernel_stack_init(
	thread_t	thread,
	void		(*start_pos)(thread_t))
{
	thread_act_t	thr_act = thread->top_act;
	vm_offset_t	stack;

	assert(thr_act);
	stack = thread->kernel_stack;
	assert(stack);

	/*
	 *	We want to run at start_pos, giving it as an argument
	 *	the return value from Load_context/Switch_context.
	 *	Thread_continue takes care of the mismatch between
	 *	the argument-passing/return-value conventions.
	 *	This function will not return normally,
	 *	so we don`t have to worry about a return address.
	 */
	STACK_IKS(stack)->k_eip = (int) Thread_continue;
	STACK_IKS(stack)->k_ebx = (int) start_pos;
	STACK_IKS(stack)->k_esp = (int) STACK_IEL(stack);

	/*
	 *	Point top of kernel stack to user`s registers.
	 */
	STACK_IEL(stack)->saved_state = &thr_act->mact.pcb->iss;
}


#if	NCPUS > 1
#define	curr_gdt(mycpu)		(mp_gdt[mycpu])
#define	curr_ldt(mycpu)		(mp_ldt[mycpu])
#define	curr_ktss(mycpu)	(mp_ktss[mycpu])
#else
#define	curr_gdt(mycpu)		(gdt)
#define	curr_ldt(mycpu)		(ldt)
#define	curr_ktss(mycpu)	(&ktss)
#endif

#define	gdt_desc_p(mycpu,sel) \
	((struct real_descriptor *)&curr_gdt(mycpu)[sel_idx(sel)])

void
act_machine_switch_pcb( thread_act_t new_act )
{
	pcb_t			pcb = new_act->mact.pcb;
	int			mycpu;
	register iopb_tss_t	tss = pcb->ims.io_tss;
	vm_offset_t		pcb_stack_top;
	register user_ldt_t	ldt = pcb->ims.ldt;

        assert(new_act->thread != NULL);
        assert(new_act->thread->kernel_stack != 0);
        STACK_IEL(new_act->thread->kernel_stack)->saved_state =
                &new_act->mact.pcb->iss;

	/*
	 *	Save a pointer to the top of the "kernel" stack -
	 *	actually the place in the PCB where a trap into
	 *	kernel mode will push the registers.
	 *	The location depends on V8086 mode.  If we are
	 *	not in V8086 mode, then a trap into the kernel
	 *	won`t save the v86 segments, so we leave room.
	 */

	pcb_stack_top = (pcb->iss.efl & EFL_VM)
			? (int) (&pcb->iss + 1)
			: (int) (&pcb->iss.v86_segs);

	mp_disable_preemption();
	mycpu = cpu_number();

	if (tss == 0) {
	    /*
	     *	No per-thread IO permissions.
	     *	Use standard kernel TSS.
	     */
	    if (!(gdt_desc_p(mycpu,KERNEL_TSS)->access & ACC_TSS_BUSY))
		set_tr(KERNEL_TSS);
	    curr_ktss(mycpu)->esp0 = pcb_stack_top;
	}
	else {
	    /*
	     * Set the IO permissions.  Use this thread`s TSS.
	     */
	    *gdt_desc_p(mycpu,USER_TSS)
	    	= *(struct real_descriptor *)tss->iopb_desc;
	    tss->tss.esp0 = pcb_stack_top;
	    set_tr(USER_TSS);
	    gdt_desc_p(mycpu,KERNEL_TSS)->access &= ~ ACC_TSS_BUSY;
	}

	/*
	 * Set the thread`s LDT.
	 */
	if (ldt == 0) {
	    struct real_descriptor *ldtp;
	    /*
	     * Use system LDT.
	     */
	    ldtp = (struct real_descriptor *)curr_ldt(mycpu);
	    ldtp[sel_idx(USER_CTHREAD)] = pcb->cthread_desc;
	    set_ldt(KERNEL_LDT);
	}
	else {
	    /*
	     * Thread has its own LDT.
	     */
	    *gdt_desc_p(mycpu,USER_LDT) = ldt->desc;
	    set_ldt(USER_LDT);
	}

	mp_enable_preemption();
	/*
	 * Load the floating-point context, if necessary.
	 */
	fpu_load_context(pcb);

}

/*
 * Switch to the first thread on a CPU.
 */
void
machine_load_context(
	thread_t		new)
{
	act_machine_switch_pcb(new->top_act);
	Load_context(new);
}

/*
 * Number of times we needed to swap an activation back in before
 * switching to it.
 */
int switch_act_swapins = 0;

/*
 * machine_switch_act
 *
 * Machine-dependent details of activation switching.  Called with
 * RPC locks held and preemption disabled.
 */
void
machine_switch_act( 
	thread_t	thread,
	thread_act_t	old,
	thread_act_t	new)
{
	int		cpu = cpu_number();

	/*
	 *	Switch the vm, ast and pcb context. 
	 *	Save FP registers if in use and set TS (task switch) bit.
	 */
	fpu_save_context(thread);

	active_stacks[cpu] = thread->kernel_stack;
	ast_context(new, cpu);

	PMAP_SWITCH_CONTEXT(old, new, cpu);
	act_machine_switch_pcb(new);
}

/*
 * Switch to a new thread.
 * Save the old thread`s kernel state or continuation,
 * and return it.
 */
thread_t
machine_switch_context(
	thread_t		old,
	void			(*continuation)(void),
	thread_t		new)
{
	register thread_act_t	old_act = old->top_act,
				new_act = new->top_act;

#if MACH_RT
        assert(active_stacks[cpu_number()] == old_act->thread->kernel_stack);
#endif
	check_simple_locks();

	/*
	 *	Save FP registers if in use.
	 */
	fpu_save_context(old);

	/*
	 *	Switch address maps if need be, even if not switching tasks.
	 *	(A server activation may be "borrowing" a client map.)
	 */
    {
	int	mycpu = cpu_number();

	PMAP_SWITCH_CONTEXT(old_act, new_act, mycpu)
    }

	/*
	 *	Load the rest of the user state for the new thread
	 */
	act_machine_switch_pcb(new_act);
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);
	old->continuation = NULL;
	return(Switch_context(old, continuation, new));
}

/*
 * act_machine_sv_free
 * release saveareas associated with an act. if flag is true, release
 * user level savearea(s) too, else don't
 */
void
act_machine_sv_free(thread_act_t act, int flag)
{
}

/*
 *	act_machine_set_state:
 *
 *	Set the status of the specified thread.  Called with "appropriate"
 *	thread-related locks held (see act_lock_thread()), so
 *	thr_act->thread is guaranteed not to change.
 */

kern_return_t
machine_thread_set_state(
	thread_act_t thr_act,
	thread_flavor_t flavor,
	thread_state_t tstate,
	mach_msg_type_number_t count)
{
	int kernel_act = 0;

	switch (flavor) {
	    case THREAD_SYSCALL_STATE:
	    {
		register struct thread_syscall_state *state;
		register struct i386_saved_state *saved_state = USER_REGS(thr_act);

		state = (struct thread_syscall_state *) tstate;
		saved_state->eax = state->eax;
		saved_state->edx = state->edx;
		if (kernel_act)
			saved_state->efl = state->efl;
		else
			saved_state->efl = (state->efl & ~EFL_USER_CLEAR) | EFL_USER_SET;
		saved_state->eip = state->eip;
		saved_state->uesp = state->esp;
		break;
	    }

	    case i386_SAVED_STATE:
	    {
		register struct i386_saved_state	*state;
		register struct i386_saved_state	*saved_state;

		if (count < i386_SAVED_STATE_COUNT) {
		    return(KERN_INVALID_ARGUMENT);
		}

		state = (struct i386_saved_state *) tstate;

		saved_state = USER_REGS(thr_act);

		/*
		 * General registers
		 */
		saved_state->edi = state->edi;
		saved_state->esi = state->esi;
		saved_state->ebp = state->ebp;
		saved_state->uesp = state->uesp;
		saved_state->ebx = state->ebx;
		saved_state->edx = state->edx;
		saved_state->ecx = state->ecx;
		saved_state->eax = state->eax;
		saved_state->eip = state->eip;
		if (kernel_act)
			saved_state->efl = state->efl;
		else
			saved_state->efl = (state->efl & ~EFL_USER_CLEAR)
						| EFL_USER_SET;

		/*
		 * Segment registers.  Set differently in V8086 mode.
		 */
		if (state->efl & EFL_VM) {
		    /*
		     * Set V8086 mode segment registers.
		     */
		    saved_state->cs = state->cs & 0xffff;
		    saved_state->ss = state->ss & 0xffff;
		    saved_state->v86_segs.v86_ds = state->ds & 0xffff;
		    saved_state->v86_segs.v86_es = state->es & 0xffff;
		    saved_state->v86_segs.v86_fs = state->fs & 0xffff;
		    saved_state->v86_segs.v86_gs = state->gs & 0xffff;

		    /*
		     * Zero protected mode segment registers.
		     */
		    saved_state->ds = 0;
		    saved_state->es = 0;
		    saved_state->fs = 0;
		    saved_state->gs = 0;

		    if (thr_act->mact.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on.
			 */
			thr_act->mact.pcb->ims.v86s.flags =
			    state->efl & (EFL_TF | EFL_IF);
		    }
		}
		else if (kernel_act) {
		    /*
		     * 386 mode.  Set segment registers for flat
		     * 32-bit address space.
		     */
		  saved_state->cs = KERNEL_CS;
		  saved_state->ss = KERNEL_DS;
		  saved_state->ds = KERNEL_DS;
		  saved_state->es = KERNEL_DS;
		  saved_state->fs = KERNEL_DS;
		  saved_state->gs = CPU_DATA;
		}
		else {
		    /*
		     * User setting segment registers.
		     * Code and stack selectors have already been
		     * checked.  Others will be reset by 'iret'
		     * if they are not valid.
		     */
		    saved_state->cs = state->cs;
		    saved_state->ss = state->ss;
		    saved_state->ds = state->ds;
		    saved_state->es = state->es;
		    saved_state->fs = state->fs;
		    saved_state->gs = state->gs;
		}
		break;
	    }

	    case i386_NEW_THREAD_STATE:
	    case i386_REGS_SEGS_STATE:
	    {
		register struct i386_new_thread_state	*state;
		register struct i386_saved_state	*saved_state;

		if (count < i386_NEW_THREAD_STATE_COUNT) {
		    return(KERN_INVALID_ARGUMENT);
		}

		if (flavor == i386_REGS_SEGS_STATE) {
		    /*
		     * Code and stack selectors must not be null,
		     * and must have user protection levels.
		     * Only the low 16 bits are valid.
		     */
		    state->cs &= 0xffff;
		    state->ss &= 0xffff;
		    state->ds &= 0xffff;
		    state->es &= 0xffff;
		    state->fs &= 0xffff;
		    state->gs &= 0xffff;

		    if (!kernel_act &&
			(state->cs == 0 || (state->cs & SEL_PL) != SEL_PL_U
		        || state->ss == 0 || (state->ss & SEL_PL) != SEL_PL_U))
			return KERN_INVALID_ARGUMENT;
		}

		state = (struct i386_new_thread_state *) tstate;

		saved_state = USER_REGS(thr_act);

		/*
		 * General registers
		 */
		saved_state->edi = state->edi;
		saved_state->esi = state->esi;
		saved_state->ebp = state->ebp;
		saved_state->uesp = state->uesp;
		saved_state->ebx = state->ebx;
		saved_state->edx = state->edx;
		saved_state->ecx = state->ecx;
		saved_state->eax = state->eax;
		saved_state->eip = state->eip;
		if (kernel_act)
			saved_state->efl = state->efl;
		else
			saved_state->efl = (state->efl & ~EFL_USER_CLEAR)
						| EFL_USER_SET;

		/*
		 * Segment registers.  Set differently in V8086 mode.
		 */
		if (state->efl & EFL_VM) {
		    /*
		     * Set V8086 mode segment registers.
		     */
		    saved_state->cs = state->cs & 0xffff;
		    saved_state->ss = state->ss & 0xffff;
		    saved_state->v86_segs.v86_ds = state->ds & 0xffff;
		    saved_state->v86_segs.v86_es = state->es & 0xffff;
		    saved_state->v86_segs.v86_fs = state->fs & 0xffff;
		    saved_state->v86_segs.v86_gs = state->gs & 0xffff;

		    /*
		     * Zero protected mode segment registers.
		     */
		    saved_state->ds = 0;
		    saved_state->es = 0;
		    saved_state->fs = 0;
		    saved_state->gs = 0;

		    if (thr_act->mact.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on.
			 */
			thr_act->mact.pcb->ims.v86s.flags =
			    state->efl & (EFL_TF | EFL_IF);
		    }
		}
		else if (flavor == i386_NEW_THREAD_STATE && kernel_act) {
		    /*
		     * 386 mode.  Set segment registers for flat
		     * 32-bit address space.
		     */
		  saved_state->cs = KERNEL_CS;
		  saved_state->ss = KERNEL_DS;
		  saved_state->ds = KERNEL_DS;
		  saved_state->es = KERNEL_DS;
		  saved_state->fs = KERNEL_DS;
		  saved_state->gs = CPU_DATA;
		}
		else {
		    /*
		     * User setting segment registers.
		     * Code and stack selectors have already been
		     * checked.  Others will be reset by 'iret'
		     * if they are not valid.
		     */
		    saved_state->cs = state->cs;
		    saved_state->ss = state->ss;
		    saved_state->ds = state->ds;
		    saved_state->es = state->es;
		    saved_state->fs = state->fs;
		    saved_state->gs = state->gs;
		}
		break;
	    }

	    case i386_FLOAT_STATE: {
                struct i386_float_state *state = (struct i386_float_state*)tstate;
		if (count < i386_old_FLOAT_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);
                if (count < i386_FLOAT_STATE_COUNT)
                    return fpu_set_state(thr_act,(struct i386_float_state*)tstate);
                else return fpu_set_fxstate(thr_act,(struct i386_float_state*)tstate);
	    }

	    /*
	     * Temporary - replace by i386_io_map
	     */
	    case i386_ISA_PORT_MAP_STATE: {
		register struct i386_isa_port_map_state *state;
		register iopb_tss_t	tss;

		if (count < i386_ISA_PORT_MAP_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		break;
	    }

	    case i386_V86_ASSIST_STATE:
	    {
		register struct i386_v86_assist_state *state;
		vm_offset_t	int_table;
		int		int_count;

		if (count < i386_V86_ASSIST_STATE_COUNT)
		    return KERN_INVALID_ARGUMENT;

		state = (struct i386_v86_assist_state *) tstate;
		int_table = state->int_table;
		int_count = state->int_count;

		if (int_table >= VM_MAX_ADDRESS ||
		    int_table +
			int_count * sizeof(struct v86_interrupt_table)
			    > VM_MAX_ADDRESS)
		    return KERN_INVALID_ARGUMENT;

		thr_act->mact.pcb->ims.v86s.int_table = int_table;
		thr_act->mact.pcb->ims.v86s.int_count = int_count;

		thr_act->mact.pcb->ims.v86s.flags =
			USER_REGS(thr_act)->efl & (EFL_TF | EFL_IF);
		break;
	    }

	case i386_THREAD_STATE: {
		struct i386_saved_state	*saved_state;
		i386_thread_state_t	*state25;

		saved_state = USER_REGS(thr_act);
		state25 = (i386_thread_state_t *)tstate;

	    	saved_state->eax = state25->eax;
	    	saved_state->ebx = state25->ebx;
	    	saved_state->ecx = state25->ecx;
	    	saved_state->edx = state25->edx;
	    	saved_state->edi = state25->edi;
	    	saved_state->esi = state25->esi;
	    	saved_state->ebp = state25->ebp;
		saved_state->uesp = state25->esp;
		saved_state->efl = (state25->eflags & ~EFL_USER_CLEAR)
						| EFL_USER_SET;
	    	saved_state->eip = state25->eip;
		saved_state->cs = USER_CS;	/* FIXME? */
		saved_state->ss = USER_DS;
		saved_state->ds = USER_DS;
		saved_state->es = USER_DS;
		saved_state->fs = state25->fs;
		saved_state->gs = state25->gs;
	}
		break;

	    default:
		return(KERN_INVALID_ARGUMENT);
	}

	return(KERN_SUCCESS);
}

/*
 *	thread_getstatus:
 *
 *	Get the status of the specified thread.
 */


kern_return_t
machine_thread_get_state(
	thread_act_t thr_act,
	thread_flavor_t flavor,
	thread_state_t tstate,
	mach_msg_type_number_t *count)
{
	switch (flavor)  {

	    case i386_SAVED_STATE:
	    {
		register struct i386_saved_state	*state;
		register struct i386_saved_state	*saved_state;

		if (*count < i386_SAVED_STATE_COUNT)
		    return(KERN_INVALID_ARGUMENT);

		state = (struct i386_saved_state *) tstate;
		saved_state = USER_REGS(thr_act);

		/*
		 * First, copy everything:
		 */
		*state = *saved_state;

		if (saved_state->efl & EFL_VM) {
		    /*
		     * V8086 mode.
		     */
		    state->ds = saved_state->v86_segs.v86_ds & 0xffff;
		    state->es = saved_state->v86_segs.v86_es & 0xffff;
		    state->fs = saved_state->v86_segs.v86_fs & 0xffff;
		    state->gs = saved_state->v86_segs.v86_gs & 0xffff;

		    if (thr_act->mact.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on
			 */
			if ((thr_act->mact.pcb->ims.v86s.flags &
					(EFL_IF|V86_IF_PENDING)) == 0)
			    state->efl &= ~EFL_IF;
		    }
		}
		else {
		    /*
		     * 386 mode.
		     */
		    state->ds = saved_state->ds & 0xffff;
		    state->es = saved_state->es & 0xffff;
		    state->fs = saved_state->fs & 0xffff;
		    state->gs = saved_state->gs & 0xffff;
		}
		*count = i386_SAVED_STATE_COUNT;
		break;
	    }

	    case i386_NEW_THREAD_STATE:
	    case i386_REGS_SEGS_STATE:
	    {
		register struct i386_new_thread_state	*state;
		register struct i386_saved_state	*saved_state;

		if (*count < i386_NEW_THREAD_STATE_COUNT)
		    return(KERN_INVALID_ARGUMENT);

		state = (struct i386_new_thread_state *) tstate;
		saved_state = USER_REGS(thr_act);

		/*
		 * General registers.
		 */
		state->edi = saved_state->edi;
		state->esi = saved_state->esi;
		state->ebp = saved_state->ebp;
		state->ebx = saved_state->ebx;
		state->edx = saved_state->edx;
		state->ecx = saved_state->ecx;
		state->eax = saved_state->eax;
		state->eip = saved_state->eip;
		state->efl = saved_state->efl;
		state->uesp = saved_state->uesp;

		state->cs = saved_state->cs;
		state->ss = saved_state->ss;
		if (saved_state->efl & EFL_VM) {
		    /*
		     * V8086 mode.
		     */
		    state->ds = saved_state->v86_segs.v86_ds & 0xffff;
		    state->es = saved_state->v86_segs.v86_es & 0xffff;
		    state->fs = saved_state->v86_segs.v86_fs & 0xffff;
		    state->gs = saved_state->v86_segs.v86_gs & 0xffff;

		    if (thr_act->mact.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on
			 */
			if ((thr_act->mact.pcb->ims.v86s.flags &
					(EFL_IF|V86_IF_PENDING)) == 0)
			    state->efl &= ~EFL_IF;
		    }
		}
		else {
		    /*
		     * 386 mode.
		     */
		    state->ds = saved_state->ds & 0xffff;
		    state->es = saved_state->es & 0xffff;
		    state->fs = saved_state->fs & 0xffff;
		    state->gs = saved_state->gs & 0xffff;
		}
		*count = i386_NEW_THREAD_STATE_COUNT;
		break;
	    }

	    case THREAD_SYSCALL_STATE:
	    {
		register struct thread_syscall_state *state;
		register struct i386_saved_state *saved_state = USER_REGS(thr_act);

		state = (struct thread_syscall_state *) tstate;
		state->eax = saved_state->eax;
		state->edx = saved_state->edx;
		state->efl = saved_state->efl;
		state->eip = saved_state->eip;
		state->esp = saved_state->uesp;
		*count = i386_THREAD_SYSCALL_STATE_COUNT;
		break;
	    }

	    case THREAD_STATE_FLAVOR_LIST:
		if (*count < 5)
		    return (KERN_INVALID_ARGUMENT);
		tstate[0] = i386_NEW_THREAD_STATE;
		tstate[1] = i386_FLOAT_STATE;
		tstate[2] = i386_ISA_PORT_MAP_STATE;
		tstate[3] = i386_V86_ASSIST_STATE;
		tstate[4] = THREAD_SYSCALL_STATE;
		*count = 5;
		break;

	    case i386_FLOAT_STATE: {
                struct i386_float_state *state = (struct i386_float_state*)tstate;

		if (*count < i386_old_FLOAT_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);
                if (*count< i386_FLOAT_STATE_COUNT) {
                    *count = i386_old_FLOAT_STATE_COUNT;
                    return fpu_get_state(thr_act,(struct i386_float_state *)tstate);
                } else {
                    *count = i386_FLOAT_STATE_COUNT;
                    return fpu_get_fxstate(thr_act,(struct i386_float_state *)tstate);
                }
	    }

	    /*
	     * Temporary - replace by i386_io_map
	     */
	    case i386_ISA_PORT_MAP_STATE: {
		register struct i386_isa_port_map_state *state;
		register iopb_tss_t tss;

		if (*count < i386_ISA_PORT_MAP_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (struct i386_isa_port_map_state *) tstate;
		tss = thr_act->mact.pcb->ims.io_tss;

		if (tss == 0) {
		    int i;

		    /*
		     *	The thread has no ktss, so no IO permissions.
		     */

		    for (i = 0; i < sizeof state->pm; i++)
			state->pm[i] = 0xff;
		} else {
		    /*
		     *	The thread has its own ktss.
		     */

		    bcopy((char *) tss->bitmap,
			  (char *) state->pm,
			  sizeof state->pm);
		}

		*count = i386_ISA_PORT_MAP_STATE_COUNT;
		break;
	    }

	    case i386_V86_ASSIST_STATE:
	    {
		register struct i386_v86_assist_state *state;

		if (*count < i386_V86_ASSIST_STATE_COUNT)
		    return KERN_INVALID_ARGUMENT;

		state = (struct i386_v86_assist_state *) tstate;
		state->int_table = thr_act->mact.pcb->ims.v86s.int_table;
		state->int_count = thr_act->mact.pcb->ims.v86s.int_count;

		*count = i386_V86_ASSIST_STATE_COUNT;
		break;
	    }

	case i386_THREAD_STATE: {
		struct i386_saved_state	*saved_state;
		i386_thread_state_t	*state;

		saved_state = USER_REGS(thr_act);
		state = (i386_thread_state_t *)tstate;

	    	state->eax = saved_state->eax;
	    	state->ebx = saved_state->ebx;
	    	state->ecx = saved_state->ecx;
	    	state->edx = saved_state->edx;
	    	state->edi = saved_state->edi;
	    	state->esi = saved_state->esi;
	    	state->ebp = saved_state->ebp;
		state->esp = saved_state->uesp;
		state->eflags = saved_state->efl;
	    	state->eip = saved_state->eip;
		state->cs = saved_state->cs;
		state->ss = saved_state->ss;
		state->ds = saved_state->ds;
		state->es = saved_state->es;
		state->fs = saved_state->fs;
		state->gs = saved_state->gs;
		break;
	}

	    default:
		return(KERN_INVALID_ARGUMENT);
	}

	return(KERN_SUCCESS);
}

/*
 * Initialize the machine-dependent state for a new thread.
 */
kern_return_t
machine_thread_create(
	thread_t		thread,
	task_t			task)
{
	pcb_t	pcb = &thread->mact.xxx_pcb;

	thread->mact.pcb = pcb;

	simple_lock_init(&pcb->lock, ETAP_MISC_PCB);

	/*
	 *	Guarantee that the bootstrapped thread will be in user
	 *	mode.
	 */
	pcb->iss.cs = USER_CS;
	pcb->iss.ss = USER_DS;
	pcb->iss.ds = USER_DS;
	pcb->iss.es = USER_DS;
	pcb->iss.fs = USER_DS;
	pcb->iss.gs = USER_DS;
	pcb->iss.efl = EFL_USER_SET;
	{
	  extern struct fake_descriptor ldt[];
	  struct real_descriptor *ldtp;
	  ldtp = (struct real_descriptor *)ldt;
	  pcb->cthread_desc = ldtp[sel_idx(USER_DS)];
	}

	/*
	 *      Allocate a kernel stack per shuttle
	 */
	thread->kernel_stack = (int)stack_alloc(thread, thread_continue);
	thread->state &= ~TH_STACK_HANDOFF;
	assert(thread->kernel_stack != 0);

	/*
	 *      Point top of kernel stack to user`s registers.
	 */
	STACK_IEL(thread->kernel_stack)->saved_state = &pcb->iss;

	return(KERN_SUCCESS);
}

/*
 * Machine-dependent cleanup prior to destroying a thread
 */
void
machine_thread_destroy(
	thread_t		thread)
{
	register pcb_t	pcb = thread->mact.pcb;

	assert(pcb);

	if (pcb->ims.io_tss != 0)
		iopb_destroy(pcb->ims.io_tss);
	if (pcb->ims.ifps != 0)
		fp_free(pcb->ims.ifps);
	if (pcb->ims.ldt != 0)
		user_ldt_free(pcb->ims.ldt);
	thread->mact.pcb = (pcb_t)0;
}

/*
 * This is used to set the current thr_act/thread
 * when starting up a new processor
 */
void
machine_thread_set_current( thread_t thread )
{
	register int	my_cpu;

	mp_disable_preemption();
	my_cpu = cpu_number();

        cpu_data[my_cpu].active_thread = thread->top_act;
		active_kloaded[my_cpu] = THR_ACT_NULL;

	mp_enable_preemption();
}

void
machine_thread_terminate_self(void)
{
}

void
act_machine_return(int code)
{
	thread_act_t	thr_act = current_act();

	/*
	 * This code is called with nothing locked.
	 * It also returns with nothing locked, if it returns.
	 *
	 * This routine terminates the current thread activation.
	 * If this is the only activation associated with its
	 * thread shuttle, then the entire thread (shuttle plus
	 * activation) is terminated.
	 */
	assert( code == KERN_TERMINATED );
	assert( thr_act );

	/* This is the only activation attached to the shuttle... */
	/* terminate the entire thread (shuttle plus activation) */

	assert(thr_act->thread->top_act == thr_act);
	thread_terminate_self();

	/*NOTREACHED*/

	panic("act_machine_return: TALKING ZOMBIE! (1)");
}


/*
 * Perform machine-dependent per-thread initializations
 */
void
machine_thread_init(void)
{
	fpu_module_init();
	iopb_init();
}

/*
 * Some routines for debugging activation code
 */
static void	dump_handlers(thread_act_t);
void	dump_regs(thread_act_t);

static void
dump_handlers(thread_act_t thr_act)
{
    ReturnHandler *rhp = thr_act->handlers;
    int	counter = 0;

    printf("\t");
    while (rhp) {
	if (rhp == &thr_act->special_handler){
	    if (rhp->next)
		printf("[NON-Zero next ptr(%x)]", rhp->next);
	    printf("special_handler()->");
	    break;
	}
	printf("hdlr_%d(%x)->",counter,rhp->handler);
	rhp = rhp->next;
	if (++counter > 32) {
		printf("Aborting: HUGE handler chain\n");
		break;
	}
    }
    printf("HLDR_NULL\n");
}

void
dump_regs(thread_act_t thr_act)
{
	if (thr_act->mact.pcb) {
		register struct i386_saved_state *ssp = USER_REGS(thr_act);
		/* Print out user register state */
		printf("\tRegs:\tedi=%x esi=%x ebp=%x ebx=%x edx=%x\n",
		    ssp->edi, ssp->esi, ssp->ebp, ssp->ebx, ssp->edx);
		printf("\t\tecx=%x eax=%x eip=%x efl=%x uesp=%x\n",
		    ssp->ecx, ssp->eax, ssp->eip, ssp->efl, ssp->uesp);
		printf("\t\tcs=%x ss=%x\n", ssp->cs, ssp->ss);
	}
}

int
dump_act(thread_act_t thr_act)
{
	if (!thr_act)
		return(0);

	printf("thr_act(0x%x)(%d): thread=%x(%d) task=%x(%d)\n",
	       thr_act, thr_act->ref_count,
	       thr_act->thread, thr_act->thread ? thr_act->thread->ref_count:0,
	       thr_act->task,   thr_act->task   ? thr_act->task->ref_count : 0);

	printf("\tsusp=%d user_stop=%d active=%x ast=%x\n",
		       thr_act->suspend_count, thr_act->user_stop_count,
		       thr_act->active, thr_act->ast);
	printf("\thi=%x lo=%x\n", thr_act->higher, thr_act->lower);
	printf("\tpcb=%x\n", thr_act->mact.pcb);

	if (thr_act->thread && thr_act->thread->kernel_stack) {
	    vm_offset_t stack = thr_act->thread->kernel_stack;

	    printf("\tk_stk %x  eip %x ebx %x esp %x iss %x\n",
		stack, STACK_IKS(stack)->k_eip, STACK_IKS(stack)->k_ebx,
		STACK_IKS(stack)->k_esp, STACK_IEL(stack)->saved_state);
	}

	dump_handlers(thr_act);
	dump_regs(thr_act);
	return((int)thr_act);
}
unsigned int
get_useraddr()
{
  
        thread_act_t thr_act = current_act();
 
	if (thr_act->mact.pcb) 
         	return(thr_act->mact.pcb->iss.eip);
	else 
		return(0);

}

void
thread_swapin_mach_alloc(thread_t thread)
{

  /* 386 does not have saveareas */

}
/*
 * detach and return a kernel stack from a thread
 */

vm_offset_t
machine_stack_detach(thread_t thread)
{
  vm_offset_t stack;

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_DETACH),
			thread, thread->priority,
			thread->sched_pri, 0,
			0);

  stack = thread->kernel_stack;
  thread->kernel_stack = 0;
  return(stack);
}

/*
 * attach a kernel stack to a thread and initialize it
 */

void
machine_stack_attach(thread_t thread,
	     vm_offset_t stack,
	     void (*start_pos)(thread_t))
{
  struct i386_kernel_state *statep;

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_ATTACH),
			thread, thread->priority,
			thread->sched_pri, continuation, 
			0);

  assert(stack);
  statep = STACK_IKS(stack);
  thread->kernel_stack = stack;

  statep->k_eip = (unsigned long) Thread_continue;
  statep->k_ebx = (unsigned long) start_pos;
  statep->k_esp = (unsigned long) STACK_IEL(stack);

  STACK_IEL(stack)->saved_state = &thread->mact.pcb->iss;

  return;
}

/*
 * move a stack from old to new thread
 */

void
machine_stack_handoff(thread_t old,
	      thread_t new)
{

  vm_offset_t stack;

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF),
			thread, thread->priority,
			thread->sched_pri, continuation, 
			0);

  assert(new->top_act);
  assert(old->top_act);

  stack = machine_stack_detach(old);
  machine_stack_attach(new, stack, 0);

  PMAP_SWITCH_CONTEXT(old->top_act->task, new->top_act->task, cpu_number());

  KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);

  machine_thread_set_current(new);

  active_stacks[cpu_number()] = new->kernel_stack;

  return;
}

struct i386_act_context {
	struct i386_saved_state ss;
	struct i386_float_state fs;
};

void *
act_thread_csave(void)
{
struct i386_act_context *ic;
kern_return_t kret;
int val;

		ic = (struct i386_act_context *)kalloc(sizeof(struct i386_act_context));

		if (ic == (struct i386_act_context *)NULL)
				return((void *)0);

		val = i386_SAVED_STATE_COUNT; 
		kret = machine_thread_get_state(current_act(),
						i386_SAVED_STATE,
						(thread_state_t) &ic->ss,
						&val);
		if (kret != KERN_SUCCESS) {
				kfree((vm_offset_t)ic,sizeof(struct i386_act_context));
				return((void *)0);
		}
		val = i386_FLOAT_STATE_COUNT; 
		kret = machine_thread_get_state(current_act(),
						i386_FLOAT_STATE,
						(thread_state_t) &ic->fs,
						&val);
		if (kret != KERN_SUCCESS) {
				kfree((vm_offset_t)ic,sizeof(struct i386_act_context));
				return((void *)0);
		}
		return(ic);
}
void 
act_thread_catt(void *ctx)
{
struct i386_act_context *ic;
kern_return_t kret;
int val;

		ic = (struct i386_act_context *)ctx;

		if (ic == (struct i386_act_context *)NULL)
				return;

		kret = machine_thread_set_state(current_act(),
						i386_SAVED_STATE,
						(thread_state_t) &ic->ss,
						i386_SAVED_STATE_COUNT);
		if (kret != KERN_SUCCESS) 
				goto out;

		kret = machine_thread_set_state(current_act(),
						i386_FLOAT_STATE,
						(thread_state_t) &ic->fs,
						i386_FLOAT_STATE_COUNT);
		if (kret != KERN_SUCCESS)
				goto out;
out:
	kfree((vm_offset_t)ic,sizeof(struct i386_act_context));		
}

void act_thread_cfree(void *ctx)
{
	kfree((vm_offset_t)ctx,sizeof(struct i386_act_context));		
}

