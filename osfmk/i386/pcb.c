/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach_rt.h>
#include <mach_debug.h>
#include <mach_ldebug.h>

#include <sys/kdebug.h>

#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <i386/cpu_data.h>
#include <i386/cpu_number.h>

#include <kern/counters.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/spl.h>
#include <kern/machine.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <vm/vm_protos.h>

#include <i386/thread.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/seg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/iopb_entries.h>
#include <i386/mp_desc.h>
#include <i386/cpu_data.h>


/*
 * Maps state flavor to number of words in the state:
 */
__private_extern__
unsigned int _MachineStateCount[] = {
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

void		act_machine_throughcall(thread_t thr_act);
user_addr_t	get_useraddr(void);
void		act_machine_return(int);
void		act_machine_sv_free(thread_t, int);

extern thread_t		Switch_context(
				thread_t			old,
				thread_continue_t	cont,
				thread_t			new);
extern void		Thread_continue(void);
extern void		Load_context(
				thread_t			thread);

/*
 * consider_machine_collect:
 *
 *	Try to collect machine-dependent pages
 */
void
consider_machine_collect(void)
{
}

void
consider_machine_adjust(void)
{
}


// DEBUG
int	DEBUG_kldt = 0;
int	DEBUG_uldt = 0;

static void
act_machine_switch_pcb( thread_t new )
{
	pcb_t			pcb = new->machine.pcb;
	int			mycpu;
	register iopb_tss_t	tss = pcb->ims.io_tss;
	vm_offset_t		pcb_stack_top;
	register user_ldt_t	uldt = pcb->ims.ldt;

        assert(new->kernel_stack != 0);
        STACK_IEL(new->kernel_stack)->saved_state =
                &new->machine.pcb->iss;

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
	    if (!(gdt_desc_p(KERNEL_TSS)->access & ACC_TSS_BUSY))
		set_tr(KERNEL_TSS);
	    current_ktss()->esp0 = pcb_stack_top;
	}
	else {
	    /*
	     * Set the IO permissions.  Use this thread`s TSS.
	     */
	    *gdt_desc_p(USER_TSS)
	    	= *(struct real_descriptor *)tss->iopb_desc;
	    tss->tss.esp0 = pcb_stack_top;
	    set_tr(USER_TSS);
	    gdt_desc_p(KERNEL_TSS)->access &= ~ ACC_TSS_BUSY;
	}

	/*
	 * Set the thread`s LDT or LDT entry.
	 */
	if (uldt == 0) {
	    struct real_descriptor *ldtp;
	    /*
	     * Use system LDT.
	     */
            // Set up the tasks specific ldt entries if extant
	    ldtp = (struct real_descriptor *)current_ldt();
	    ldtp[sel_idx(USER_CTHREAD)] = pcb->cthread_desc;
            if (pcb->uldt_selector != 0)
                ldtp[sel_idx(pcb->uldt_selector)] = pcb->uldt_desc;
	    set_ldt(KERNEL_LDT);
	}
	else {
	    /*
	     * Thread has its own LDT. // THIS SHOULD BE REMOVED!!!!
	     */
	    *gdt_desc_p(USER_LDT) = uldt->desc;
	    set_ldt(USER_LDT);
            /*debug*/
	    if ((DEBUG_uldt++ % 0x7fff) == 0)
		printf("KERNEL----> setting user ldt");
	
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
	act_machine_switch_pcb(new);
	Load_context(new);
}

/*
 * Switch to a new thread.
 * Save the old thread`s kernel state or continuation,
 * and return it.
 */
thread_t
machine_switch_context(
	thread_t			old,
	thread_continue_t	continuation,
	thread_t			new)
{
#if MACH_RT
        assert(current_cpu_datap()->cpu_active_stack == old->kernel_stack);
#endif

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

	PMAP_SWITCH_CONTEXT(old, new, mycpu)
    }

	/*
	 *	Load the rest of the user state for the new thread
	 */
	act_machine_switch_pcb(new);
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
act_machine_sv_free(__unused thread_t act, __unused int flag)
{
}


/*
 * This is where registers that are not normally specified by the mach-o
 * file on an execve would be nullified, perhaps to avoid a covert channel.
 */
kern_return_t
machine_thread_state_initialize(
	thread_t thread)
{
#pragma unused (thread)

    return  KERN_SUCCESS;
}
 
 
/*
 *	act_machine_set_state:
 *
 *	Set the status of the specified thread.
 */

kern_return_t
machine_thread_set_state(
	thread_t thr_act,
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

		/* Check segment selectors are safe */
		if (!kernel_act &&
		    !valid_user_segment_selectors(state->cs,
						  state->ss,
						  state->ds,
						  state->es,
						  state->fs,
						  state->gs))
		    return KERN_INVALID_ARGUMENT;
		
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

		    if (thr_act->machine.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on.
			 */
			thr_act->machine.pcb->ims.v86s.flags =
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
		  saved_state->gs = CPU_DATA_GS;
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

		state = (struct i386_new_thread_state *) tstate;

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
			!valid_user_segment_selectors(state->cs,
						      state->ss,
						      state->ds,
						      state->es,
						      state->fs,
						      state->gs))
			return KERN_INVALID_ARGUMENT;
		}

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

		    if (thr_act->machine.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on.
			 */
			thr_act->machine.pcb->ims.v86s.flags =
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
		  saved_state->gs = CPU_DATA_GS;
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

		thr_act->machine.pcb->ims.v86s.int_table = int_table;
		thr_act->machine.pcb->ims.v86s.int_count = int_count;

		thr_act->machine.pcb->ims.v86s.flags =
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
	thread_t thr_act,
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

		    if (thr_act->machine.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on
			 */
			if ((thr_act->machine.pcb->ims.v86s.flags &
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

		    if (thr_act->machine.pcb->ims.v86s.int_table) {
			/*
			 * Hardware assist on
			 */
			if ((thr_act->machine.pcb->ims.v86s.flags &
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
		tss = thr_act->machine.pcb->ims.io_tss;

		if (tss == 0) {
		    unsigned int i;

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
		state->int_table = thr_act->machine.pcb->ims.v86s.int_table;
		state->int_count = thr_act->machine.pcb->ims.v86s.int_count;

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
	__unused task_t		task)
{
	pcb_t	pcb = &thread->machine.xxx_pcb;

	thread->machine.pcb = pcb;

	simple_lock_init(&pcb->lock, 0);

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
	  struct real_descriptor *ldtp;
	  ldtp = (struct real_descriptor *)ldt;
	  pcb->cthread_desc = ldtp[sel_idx(USER_DS)];
          pcb->uldt_desc = ldtp[sel_idx(USER_DS)];
          pcb->uldt_selector = 0;
	}

	/*
	 *      Allocate a kernel stack per thread.
	 */
	stack_alloc(thread);

	return(KERN_SUCCESS);
}

/*
 * Machine-dependent cleanup prior to destroying a thread
 */
void
machine_thread_destroy(
	thread_t		thread)
{
	register pcb_t	pcb = thread->machine.pcb;

	assert(pcb);
        
	if (pcb->ims.io_tss != 0)
		iopb_destroy(pcb->ims.io_tss);
	if (pcb->ims.ifps != 0)
		fpu_free(pcb->ims.ifps);
	if (pcb->ims.ldt != 0)
		user_ldt_free(pcb->ims.ldt);
	thread->machine.pcb = (pcb_t)0;
}

/*
 * This is used to set the current thr_act/thread
 * when starting up a new processor
 */
void
machine_set_current_thread( thread_t thread )
{
	mp_disable_preemption();

        current_cpu_datap()->cpu_active_thread = thread;
	current_cpu_datap()->cpu_active_kloaded = THREAD_NULL;

	mp_enable_preemption();
}

void
machine_thread_terminate_self(void)
{
}

void
act_machine_return(int code)
{
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

	thread_terminate_self();

	/*NOTREACHED*/

	panic("act_machine_return(%d): TALKING ZOMBIE! (1)", code);
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
static void	dump_handlers(thread_t);
void		dump_regs(thread_t);
int		dump_act(thread_t thr_act);

static void
dump_handlers(thread_t thr_act)
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
dump_regs(thread_t thr_act)
{
	if (thr_act->machine.pcb) {
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
dump_act(thread_t thr_act)
{
	if (!thr_act)
		return(0);

	printf("thread(0x%x)(%d): task=%x(%d)\n",
	       thr_act, thr_act->ref_count,
	       thr_act->task,   thr_act->task   ? thr_act->task->ref_count : 0);

	printf("\tsusp=%d user_stop=%d active=%x ast=%x\n",
		       thr_act->suspend_count, thr_act->user_stop_count,
		       thr_act->active, thr_act->ast);
	printf("\tpcb=%x\n", thr_act->machine.pcb);

	if (thr_act->kernel_stack) {
	    vm_offset_t stack = thr_act->kernel_stack;

	    printf("\tk_stk %x  eip %x ebx %x esp %x iss %x\n",
		stack, STACK_IKS(stack)->k_eip, STACK_IKS(stack)->k_ebx,
		STACK_IKS(stack)->k_esp, STACK_IEL(stack)->saved_state);
	}

	dump_handlers(thr_act);
	dump_regs(thr_act);
	return((int)thr_act);
}

user_addr_t
get_useraddr(void)
{
  
        thread_t thr_act = current_thread();
 
	if (thr_act->machine.pcb) 
         	return(thr_act->machine.pcb->iss.eip);
	else 
		return(0);

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
machine_stack_attach(
	thread_t		thread,
	vm_offset_t		stack)
{
  struct i386_kernel_state *statep;

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_ATTACH),
			thread, thread->priority,
			thread->sched_pri, 0, 0);

  assert(stack);
  statep = STACK_IKS(stack);
  thread->kernel_stack = stack;

  statep->k_eip = (unsigned long) Thread_continue;
  statep->k_ebx = (unsigned long) thread_continue;
  statep->k_esp = (unsigned long) STACK_IEL(stack);

  STACK_IEL(stack)->saved_state = &thread->machine.pcb->iss;

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
			thread->sched_pri, 0, 0);

  assert(new);
  assert(old);

  stack = machine_stack_detach(old);
  machine_stack_attach(new, stack);

  PMAP_SWITCH_CONTEXT(old->task, new->task, cpu_number());

  KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);

  machine_set_current_thread(new);

  current_cpu_datap()->cpu_active_stack = new->kernel_stack;

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
		kret = machine_thread_get_state(current_thread(),
						i386_SAVED_STATE,
						(thread_state_t) &ic->ss,
						&val);
		if (kret != KERN_SUCCESS) {
				kfree(ic,sizeof(struct i386_act_context));
				return((void *)0);
		}
		val = i386_FLOAT_STATE_COUNT; 
		kret = machine_thread_get_state(current_thread(),
						i386_FLOAT_STATE,
						(thread_state_t) &ic->fs,
						&val);
		if (kret != KERN_SUCCESS) {
				kfree(ic,sizeof(struct i386_act_context));
				return((void *)0);
		}
		return(ic);
}
void 
act_thread_catt(void *ctx)
{
struct i386_act_context *ic;
kern_return_t kret;

		ic = (struct i386_act_context *)ctx;

		if (ic == (struct i386_act_context *)NULL)
				return;

		kret = machine_thread_set_state(current_thread(),
						i386_SAVED_STATE,
						(thread_state_t) &ic->ss,
						i386_SAVED_STATE_COUNT);
		if (kret != KERN_SUCCESS) 
				goto out;

		kret = machine_thread_set_state(current_thread(),
						i386_FLOAT_STATE,
						(thread_state_t) &ic->fs,
						i386_FLOAT_STATE_COUNT);
		if (kret != KERN_SUCCESS)
				goto out;
out:
	kfree(ic,sizeof(struct i386_act_context));		
}

void act_thread_cfree(void *ctx)
{
	kfree(ctx,sizeof(struct i386_act_context));		
}

