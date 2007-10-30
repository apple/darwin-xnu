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
#include <i386/mp_desc.h>
#include <i386/cpu_data.h>
#include <i386/misc_protos.h>
#include <i386/machine_routines.h>

#include <machine/commpage.h>

/*
 * Maps state flavor to number of words in the state:
 */
unsigned int _MachineStateCount[] = {
	/* FLAVOR_LIST */
        0,
	x86_THREAD_STATE32_COUNT,
	x86_FLOAT_STATE32_COUNT,
	x86_EXCEPTION_STATE32_COUNT,
	x86_THREAD_STATE64_COUNT,
	x86_FLOAT_STATE64_COUNT,
	x86_EXCEPTION_STATE64_COUNT,
	x86_THREAD_STATE_COUNT,
	x86_FLOAT_STATE_COUNT,
	x86_EXCEPTION_STATE_COUNT,
	0,
	x86_SAVED_STATE32_COUNT,
	x86_SAVED_STATE64_COUNT,
	x86_DEBUG_STATE32_COUNT,
	x86_DEBUG_STATE64_COUNT,
	x86_DEBUG_STATE_COUNT
};

zone_t		iss_zone;		/* zone for saved_state area */
zone_t		ids_zone;		/* zone for debug_state area */

/* Forward */

void		act_machine_throughcall(thread_t thr_act);
void		act_machine_return(int);

extern void		Thread_continue(void);
extern void		Load_context(
				thread_t			thread);

static void
get_exception_state32(thread_t thread, x86_exception_state32_t *es);

static void
get_exception_state64(thread_t thread, x86_exception_state64_t *es);

static void
get_thread_state32(thread_t thread, x86_thread_state32_t *ts);

static void
get_thread_state64(thread_t thread, x86_thread_state64_t *ts);

static int
set_thread_state32(thread_t thread, x86_thread_state32_t *ts);

static int
set_thread_state64(thread_t thread, x86_thread_state64_t *ts);

/*
 * Don't let an illegal value for dr7 get set.	Specifically,
 * check for undefined settings.  Setting these bit patterns
 * result in undefined behaviour and can lead to an unexpected
 * TRCTRAP.
 */
static boolean_t
dr7_is_valid(uint32_t *dr7)
{
	int i;
	uint32_t mask1, mask2;

	/*
	 * If the DE bit is set in CR4, R/W0-3 can be pattern
	 * "10B" to indicate i/o reads and write
	 */
	if (!(get_cr4() & CR4_DE))
		for (i = 0, mask1 = 0x3<<16, mask2 = 0x2<<16; i < 4; 
				i++, mask1 <<= 4, mask2 <<= 4)
			if ((*dr7 & mask1) == mask2)
				return (FALSE);

	/*
	 * len0-3 pattern "10B" is ok for len on 64-bit.
	 */
	if (current_cpu_datap()->cpu_is64bit == TRUE)
		for (i = 0, mask1 = 0x3<<18, mask2 = 0x2<<18; i < 4; 
				i++, mask1 <<= 4, mask2 <<= 4)
			if ((*dr7 & mask1) == mask2)
				return (FALSE);

	/*
	 * if we are doing an instruction execution break (indicated
	 * by r/w[x] being "00B"), then the len[x] must also be set
	 * to "00B"
	 */
	for (i = 0; i < 4; i++)
		if (((((*dr7 >> (16 + i*4))) & 0x3) == 0) &&
				((((*dr7 >> (18 + i*4))) & 0x3) != 0))
			return (FALSE);

	/*
	 * Intel docs have these bits fixed.
	 */
	*dr7 |= 0x1 << 10; /* set bit 10 to 1 */
	*dr7 &= ~(0x1 << 11); /* set bit 11 to 0 */
	*dr7 &= ~(0x1 << 12); /* set bit 12 to 0 */
	*dr7 &= ~(0x1 << 14); /* set bit 14 to 0 */
	*dr7 &= ~(0x1 << 15); /* set bit 15 to 0 */

	/*
	 * We don't allow anything to set the global breakpoints.
	 */

	if (*dr7 & 0x2)
		return (FALSE);

	if (*dr7 & (0x2<<2))
		return (FALSE);

	if (*dr7 & (0x2<<4))
		return (FALSE);

	if (*dr7 & (0x2<<6))
		return (FALSE);

	return (TRUE);
}

static inline void
set_live_debug_state32(cpu_data_t *cdp, x86_debug_state32_t *ds)
{
	__asm__ volatile ("movl %0,%%db0" : :"r" (ds->dr0));
	__asm__ volatile ("movl %0,%%db1" : :"r" (ds->dr1));
	__asm__ volatile ("movl %0,%%db2" : :"r" (ds->dr2));
	__asm__ volatile ("movl %0,%%db3" : :"r" (ds->dr3));
	if (cpu_mode_is64bit())
		cdp->cpu_dr7 = ds->dr7;
}

extern void set_64bit_debug_regs(x86_debug_state64_t *ds);

static inline void
set_live_debug_state64(cpu_data_t *cdp, x86_debug_state64_t *ds)
{
	/*
	 * We need to enter 64-bit mode in order to set the full
	 * width of these registers
	 */
	set_64bit_debug_regs(ds);
	cdp->cpu_dr7 = ds->dr7;
}

static kern_return_t
set_debug_state32(thread_t thread, x86_debug_state32_t *ds)
{
	x86_debug_state32_t *ids;
	pcb_t pcb;

	pcb = thread->machine.pcb;
	ids = pcb->ids;

	if (ids == NULL) {
		ids = zalloc(ids_zone);
		bzero(ids, sizeof *ids);

		simple_lock(&pcb->lock);
		/* make sure it wasn't already alloc()'d elsewhere */
		if (pcb->ids == NULL) {
			pcb->ids = ids;
			simple_unlock(&pcb->lock);
		} else {
			simple_unlock(&pcb->lock);
			zfree(ids_zone, ids);
		}
	}

	if (!dr7_is_valid(&ds->dr7))
		goto err;

	/*
	 * Only allow local breakpoints and make sure they are not
	 * in the trampoline code.
	 */

	if (ds->dr7 & 0x1)
		if (ds->dr0 >= (unsigned long)HIGH_MEM_BASE)
			goto err;

	if (ds->dr7 & (0x1<<2))
		if (ds->dr1 >= (unsigned long)HIGH_MEM_BASE)
			goto err;

	if (ds->dr7 & (0x1<<4))
		if (ds->dr2 >= (unsigned long)HIGH_MEM_BASE)
			goto err;

	if (ds->dr7 & (0x1<<6))
		if (ds->dr3 >= (unsigned long)HIGH_MEM_BASE)
			goto err;

	ids->dr0 = ds->dr0;
	ids->dr1 = ds->dr1;
	ids->dr2 = ds->dr2;
	ids->dr3 = ds->dr3;
	ids->dr6 = ds->dr6;
	ids->dr7 = ds->dr7;

	return (KERN_SUCCESS);

err:
	return (KERN_INVALID_ARGUMENT);
}

static kern_return_t
set_debug_state64(thread_t thread, x86_debug_state64_t *ds)
{
	x86_debug_state64_t *ids;
	pcb_t pcb;

	pcb = thread->machine.pcb;
	ids = pcb->ids;

	if (ids == NULL) {
		ids = zalloc(ids_zone);
		bzero(ids, sizeof *ids);

		simple_lock(&pcb->lock);
		/* make sure it wasn't already alloc()'d elsewhere */
		if (pcb->ids == NULL) {
			pcb->ids = ids;
			simple_unlock(&pcb->lock);
		} else {
			simple_unlock(&pcb->lock);
			zfree(ids_zone, ids);
		}
	}

	if (!dr7_is_valid((uint32_t *)&ds->dr7))
		goto err;

	/*
	 * Don't allow the user to set debug addresses above their max
	 * value
	 */
	if (ds->dr7 & 0x1)
		if (ds->dr0 >= VM_MAX_PAGE_ADDRESS)
			goto err;

	if (ds->dr7 & (0x1<<2))
		if (ds->dr1 >= VM_MAX_PAGE_ADDRESS)
			goto err;

	if (ds->dr7 & (0x1<<4))
		if (ds->dr2 >= VM_MAX_PAGE_ADDRESS)
			goto err;

	if (ds->dr7 & (0x1<<6))
		if (ds->dr3 >= VM_MAX_PAGE_ADDRESS)
			goto err;

	ids->dr0 = ds->dr0;
	ids->dr1 = ds->dr1;
	ids->dr2 = ds->dr2;
	ids->dr3 = ds->dr3;
	ids->dr6 = ds->dr6;
	ids->dr7 = ds->dr7;

	return (KERN_SUCCESS);

err:
	return (KERN_INVALID_ARGUMENT);
}

static void
get_debug_state32(thread_t thread, x86_debug_state32_t *ds)
{
	x86_debug_state32_t *saved_state;

	saved_state = thread->machine.pcb->ids;

	if (saved_state) {
		ds->dr0 = saved_state->dr0;
		ds->dr1 = saved_state->dr1;
		ds->dr2 = saved_state->dr2;
		ds->dr3 = saved_state->dr3;
		ds->dr4 = saved_state->dr4;
		ds->dr5 = saved_state->dr5;
		ds->dr6 = saved_state->dr6;
		ds->dr7 = saved_state->dr7;
	} else
		bzero(ds, sizeof *ds);
}

static void
get_debug_state64(thread_t thread, x86_debug_state64_t *ds)
{
	x86_debug_state64_t *saved_state;

	saved_state = (x86_debug_state64_t *)thread->machine.pcb->ids;

	if (saved_state) {
		ds->dr0 = saved_state->dr0;
		ds->dr1 = saved_state->dr1;
		ds->dr2 = saved_state->dr2;
		ds->dr3 = saved_state->dr3;
		ds->dr4 = saved_state->dr4;
		ds->dr5 = saved_state->dr5;
		ds->dr6 = saved_state->dr6;
		ds->dr7 = saved_state->dr7;
	} else
		bzero(ds, sizeof *ds);
}

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
extern void *get_bsduthreadarg(thread_t th);

static void
act_machine_switch_pcb( thread_t new )
{
        pcb_t			pcb = new->machine.pcb;
	struct real_descriptor	*ldtp;
	vm_offset_t		pcb_stack_top;
	vm_offset_t		hi_pcb_stack_top;
        vm_offset_t		hi_iss;
	cpu_data_t              *cdp = current_cpu_datap();

	assert(new->kernel_stack != 0);
	STACK_IEL(new->kernel_stack)->saved_state = pcb->iss;

	if (!cpu_mode_is64bit()) {
		x86_saved_state32_tagged_t	*hi_iss32;
		/*
		 *	Save a pointer to the top of the "kernel" stack -
		 *	actually the place in the PCB where a trap into
		 *	kernel mode will push the registers.
		 */
		hi_iss = (vm_offset_t)((unsigned long)
			pmap_cpu_high_map_vaddr(cpu_number(), HIGH_CPU_ISS0) |
			((unsigned long)pcb->iss & PAGE_MASK));

		cdp->cpu_hi_iss = (void *)hi_iss;

		pmap_high_map(pcb->iss_pte0, HIGH_CPU_ISS0);
		pmap_high_map(pcb->iss_pte1, HIGH_CPU_ISS1);

		hi_iss32 = (x86_saved_state32_tagged_t *) hi_iss;
		assert(hi_iss32->tag == x86_SAVED_STATE32);

		hi_pcb_stack_top = (int) (hi_iss32 + 1);

		/*
		 * For fast syscall, top of interrupt stack points to pcb stack
		 */
		*(vm_offset_t *) current_sstk() = hi_pcb_stack_top;

		current_ktss()->esp0 = hi_pcb_stack_top;

	} else if (is_saved_state64(pcb->iss)) {
		/*
		 * The test above is performed against the thread save state
		 * flavor and not task's 64-bit feature flag because of the
		 * thread/task 64-bit state divergence that can arise in
		 * task_set_64bit() x86: the task state is changed before
		 * the individual thread(s).
		 */
	        x86_saved_state64_tagged_t	*iss64;
		vm_offset_t			isf;

		assert(is_saved_state64(pcb->iss));
						   
		iss64 = (x86_saved_state64_tagged_t *) pcb->iss;
	
		/*
		 * Set pointer to PCB's interrupt stack frame in cpu data.
		 * Used by syscall and double-fault trap handlers.
		 */
		isf = (vm_offset_t) &iss64->state.isf;
		cdp->cpu_uber.cu_isf = UBER64(isf);
		pcb_stack_top = (vm_offset_t) (iss64 + 1);
		/* require 16-byte alignment */
		assert((pcb_stack_top & 0xF) == 0);
		/* Interrupt stack is pcb */
		current_ktss64()->rsp0 = UBER64(pcb_stack_top);

		/*
		 * Top of temporary sysenter stack points to pcb stack.
		 * Although this is not normally used by 64-bit users,
		 * it needs to be set in case a sysenter is attempted.
		 */
		*current_sstk64() = UBER64(pcb_stack_top);

		cdp->cpu_task_map = new->map->pmap->pm_task_map; 

		/*
		 * Enable the 64-bit user code segment, USER64_CS.
		 * Disable the 32-bit user code segment, USER_CS.
		 */
		ldt_desc_p(USER64_CS)->access |= ACC_PL_U;
		ldt_desc_p(USER_CS)->access &= ~ACC_PL_U;

	} else {
		x86_saved_state_compat32_t	*iss32compat;
		vm_offset_t			isf;

		assert(is_saved_state32(pcb->iss));
		iss32compat = (x86_saved_state_compat32_t *) pcb->iss;

		pcb_stack_top = (int) (iss32compat + 1);
		/* require 16-byte alignment */
		assert((pcb_stack_top & 0xF) == 0);

		/*
		 * Set pointer to PCB's interrupt stack frame in cpu data.
		 * Used by debug trap handler.
		 */
		isf = (vm_offset_t) &iss32compat->isf64;
		cdp->cpu_uber.cu_isf = UBER64(isf);

		/* Top of temporary sysenter stack points to pcb stack */
		*current_sstk64() = UBER64(pcb_stack_top);

		/* Interrupt stack is pcb */
		current_ktss64()->rsp0 = UBER64(pcb_stack_top);

		cdp->cpu_task_map = TASK_MAP_32BIT;
		/* Precalculate pointers to syscall argument store, for use
		 * in the trampolines.
		 */
		cdp->cpu_uber_arg_store = UBER64((vm_offset_t)get_bsduthreadarg(new));
		cdp->cpu_uber_arg_store_valid = UBER64((vm_offset_t)&pcb->arg_store_valid);
		pcb->arg_store_valid = 0;

		/*
		 * Disable USER64_CS
		 * Enable USER_CS
		 */
		ldt_desc_p(USER64_CS)->access &= ~ACC_PL_U;
		ldt_desc_p(USER_CS)->access |= ACC_PL_U;
	}

	/*
	 * Set the thread`s cthread (a.k.a pthread)
	 * For 32-bit user this involves setting the USER_CTHREAD
	 * descriptor in the LDT to point to the cthread data.
	 * The involves copying in the pre-initialized descriptor.
	 */ 
	ldtp = (struct real_descriptor *)current_ldt();
	ldtp[sel_idx(USER_CTHREAD)] = pcb->cthread_desc;
	if (pcb->uldt_selector != 0)
		ldtp[sel_idx(pcb->uldt_selector)] = pcb->uldt_desc;
	/*
	 * For 64-bit, we additionally set the 64-bit User GS base
	 * address. On return to 64-bit user, the GS.Base MSR will be written.
	 */
	cdp->cpu_uber.cu_user_gs_base = pcb->cthread_self;

	/*
	 * Set the thread`s LDT or LDT entry.
	 */
	if (new->task == TASK_NULL || new->task->i386_ldt == 0) {
		/*
		 * Use system LDT.
		 */
	       	ml_cpu_set_ldt(KERNEL_LDT);
	} else {
		/*
		 * Task has its own LDT.
		 */
		user_ldt_set(new);
	}

	/*
	 * Bump the scheduler generation count in the commpage.
	 * This can be read by user code to detect its preemption.
	 */
	commpage_sched_gen_inc();
}

/*
 * Switch to the first thread on a CPU.
 */
void
machine_load_context(
	thread_t		new)
{
	new->machine.specFlags |= OnProc;
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

	old->machine.specFlags &= ~OnProc;
	new->machine.specFlags |= OnProc;

	/*
	 *	Switch address maps if need be, even if not switching tasks.
	 *	(A server activation may be "borrowing" a client map.)
	 */
	PMAP_SWITCH_CONTEXT(old, new, cpu_number())

	/*
	 *	Load the rest of the user state for the new thread
	 */
	act_machine_switch_pcb(new);

	return(Switch_context(old, continuation, new));
}

/*
 * act_machine_sv_free
 * release saveareas associated with an act.  if flag is true, release
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
    /*
     * If there's an fpu save area, free it.
     * The initialized state will then be lazily faulted-in, if required.
     * And if we're target, re-arm the no-fpu trap.
     */
        if (thread->machine.pcb->ifps) {
	(void) fpu_set_fxstate(thread, NULL);

    	if (thread == current_thread())
	   clear_fpu();
    }
    return  KERN_SUCCESS;
}

uint32_t
get_eflags_exportmask(void)
{
	return EFL_USER_SET;
}

/*
 * x86_SAVED_STATE32	 - internal save/restore general register state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_SAVED_STATE64	 - internal save/restore general register state on 64 bit processors
 *			   for 64bit tasks only
 * x86_THREAD_STATE32	 - external set/get general register state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_THREAD_STATE64	 - external set/get general register state on 64 bit processors
 *			   for 64bit tasks only
 * x86_SAVED_STATE	 - external set/get general register state on 32/64 bit processors
 *			   for either 32bit or 64bit tasks
 * x86_FLOAT_STATE32	 - internal/external save/restore float and xmm state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_FLOAT_STATE64	 - internal/external save/restore float and xmm state on 64 bit processors
 *			   for 64bit tasks only
 * x86_FLOAT_STATE	 - external save/restore float and xmm state on 32/64 bit processors
 *			   for either 32bit or 64bit tasks
 * x86_EXCEPTION_STATE32 - external get exception state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_EXCEPTION_STATE64 - external get exception state on 64 bit processors
 *			   for 64bit tasks only
 * x86_EXCEPTION_STATE   - external get exception state on 323/64 bit processors
 *			   for either 32bit or 64bit tasks
 */

 
static void
get_exception_state64(thread_t thread, x86_exception_state64_t *es)
{
        x86_saved_state64_t *saved_state;

        saved_state = USER_REGS64(thread);

	es->trapno = saved_state->isf.trapno;
	es->err = saved_state->isf.err;
	es->faultvaddr = saved_state->cr2;
}		

static void
get_exception_state32(thread_t thread, x86_exception_state32_t *es)
{
        x86_saved_state32_t *saved_state;

        saved_state = USER_REGS32(thread);

	es->trapno = saved_state->trapno;
	es->err = saved_state->err;
	es->faultvaddr = saved_state->cr2;
}		


static int
set_thread_state32(thread_t thread, x86_thread_state32_t *ts)
{
        x86_saved_state32_t	*saved_state;

	saved_state = USER_REGS32(thread);

	/*
	 * Scrub segment selector values:
	 */
	if (ts->cs != USER_CS) ts->cs = USER_CS;
	if (ts->ss == 0) ts->ss = USER_DS;
	if (ts->ds == 0) ts->ds = USER_DS;
	if (ts->es == 0) ts->es = USER_DS;

	/* Check segment selectors are safe */
	if (!valid_user_segment_selectors(ts->cs,
					  ts->ss,
					  ts->ds,
					  ts->es,
					  ts->fs,
					  ts->gs))
		return(KERN_INVALID_ARGUMENT);

	saved_state->eax = ts->eax;
	saved_state->ebx = ts->ebx;
	saved_state->ecx = ts->ecx;
	saved_state->edx = ts->edx;
	saved_state->edi = ts->edi;
	saved_state->esi = ts->esi;
	saved_state->ebp = ts->ebp;
	saved_state->uesp = ts->esp;
	saved_state->efl = (ts->eflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
	saved_state->eip = ts->eip;
	saved_state->cs = ts->cs;
	saved_state->ss = ts->ss;
	saved_state->ds = ts->ds;
	saved_state->es = ts->es;
	saved_state->fs = ts->fs;
	saved_state->gs = ts->gs;

	/*
	 * If the trace trap bit is being set,
	 * ensure that the user returns via iret
	 * - which is signaled thusly:
	 */
	if ((saved_state->efl & EFL_TF) && saved_state->cs == SYSENTER_CS)
		saved_state->cs = SYSENTER_TF_CS;

	return(KERN_SUCCESS);
}

static int
set_thread_state64(thread_t thread, x86_thread_state64_t *ts)
{
        x86_saved_state64_t	*saved_state;

	saved_state = USER_REGS64(thread);

	if (!IS_USERADDR64_CANONICAL(ts->rsp) ||
	    !IS_USERADDR64_CANONICAL(ts->rip))
		return(KERN_INVALID_ARGUMENT);

	saved_state->r8 = ts->r8;
	saved_state->r9 = ts->r9;
	saved_state->r10 = ts->r10;
	saved_state->r11 = ts->r11;
	saved_state->r12 = ts->r12;
	saved_state->r13 = ts->r13;
	saved_state->r14 = ts->r14;
	saved_state->r15 = ts->r15;
	saved_state->rax = ts->rax;
	saved_state->rbx = ts->rbx;
	saved_state->rcx = ts->rcx;
	saved_state->rdx = ts->rdx;
	saved_state->rdi = ts->rdi;
	saved_state->rsi = ts->rsi;
	saved_state->rbp = ts->rbp;
	saved_state->isf.rsp = ts->rsp;
	saved_state->isf.rflags = (ts->rflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
	saved_state->isf.rip = ts->rip;
	saved_state->isf.cs = USER64_CS;
	saved_state->fs = ts->fs;
	saved_state->gs = ts->gs;

	return(KERN_SUCCESS);
}



static void
get_thread_state32(thread_t thread, x86_thread_state32_t *ts)
{
        x86_saved_state32_t	*saved_state;

	saved_state = USER_REGS32(thread);

	ts->eax = saved_state->eax;
	ts->ebx = saved_state->ebx;
	ts->ecx = saved_state->ecx;
	ts->edx = saved_state->edx;
	ts->edi = saved_state->edi;
	ts->esi = saved_state->esi;
	ts->ebp = saved_state->ebp;
	ts->esp = saved_state->uesp;
	ts->eflags = saved_state->efl;
	ts->eip = saved_state->eip;
	ts->cs = saved_state->cs;
	ts->ss = saved_state->ss;
	ts->ds = saved_state->ds;
	ts->es = saved_state->es;
	ts->fs = saved_state->fs;
	ts->gs = saved_state->gs;
}


static void
get_thread_state64(thread_t thread, x86_thread_state64_t *ts)
{
        x86_saved_state64_t	*saved_state;

	saved_state = USER_REGS64(thread);

	ts->r8 = saved_state->r8;
	ts->r9 = saved_state->r9;
	ts->r10 = saved_state->r10;
	ts->r11 = saved_state->r11;
	ts->r12 = saved_state->r12;
	ts->r13 = saved_state->r13;
	ts->r14 = saved_state->r14;
	ts->r15 = saved_state->r15;
	ts->rax = saved_state->rax;
	ts->rbx = saved_state->rbx;
	ts->rcx = saved_state->rcx;
	ts->rdx = saved_state->rdx;
	ts->rdi = saved_state->rdi;
	ts->rsi = saved_state->rsi;
	ts->rbp = saved_state->rbp;
	ts->rsp = saved_state->isf.rsp;
	ts->rflags = saved_state->isf.rflags;
	ts->rip = saved_state->isf.rip;
	ts->cs = saved_state->isf.cs;
	ts->fs = saved_state->fs;
	ts->gs = saved_state->gs;
}


void
thread_set_wq_state32(thread_t thread, thread_state_t tstate)
{
        x86_thread_state32_t	*state;
        x86_saved_state32_t	*saved_state;
	thread_t curth = current_thread();

	saved_state = USER_REGS32(thread);
	state = (x86_thread_state32_t *)tstate;
	
	if (curth != thread)
	        thread_lock(thread);

	saved_state->eip = state->eip;
	saved_state->eax = state->eax;
	saved_state->ebx = state->ebx;
	saved_state->ecx = state->ecx;
	saved_state->edx = state->edx;
	saved_state->edi = state->edi;
	saved_state->esi = state->esi;
	saved_state->uesp = state->esp;
	saved_state->efl = EFL_USER_SET;

	saved_state->cs = USER_CS;
	saved_state->ss = USER_DS;
	saved_state->ds = USER_DS;
	saved_state->es = USER_DS;

	if (curth != thread)
	        thread_unlock(thread);
}


void
thread_set_wq_state64(thread_t thread, thread_state_t tstate)
{
        x86_thread_state64_t	*state;
        x86_saved_state64_t	*saved_state;
	thread_t curth = current_thread();

	saved_state = USER_REGS64(thread);
	state = (x86_thread_state64_t *)tstate;
	
	if (curth != thread)
	        thread_lock(thread);

	saved_state->rdi = state->rdi;
	saved_state->rsi = state->rsi;
	saved_state->rdx = state->rdx;
	saved_state->rcx = state->rcx;
	saved_state->r8  = state->r8;
	saved_state->r9  = state->r9;

	saved_state->isf.rip = state->rip;
	saved_state->isf.rsp = state->rsp;
	saved_state->isf.cs = USER64_CS;
	saved_state->isf.rflags = EFL_USER_SET;

	if (curth != thread)
	        thread_unlock(thread);
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
	switch (flavor) {
	case x86_SAVED_STATE32:
	{
		x86_saved_state32_t	*state;
		x86_saved_state32_t	*saved_state;

		if (count < x86_SAVED_STATE32_COUNT)
			return(KERN_INVALID_ARGUMENT);
        
		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		state = (x86_saved_state32_t *) tstate;

		/* Check segment selectors are safe */
		if (!valid_user_segment_selectors(state->cs,
					state->ss,
					state->ds,
					state->es,
					state->fs,
					state->gs))
			return KERN_INVALID_ARGUMENT;

		saved_state = USER_REGS32(thr_act);

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

		saved_state->efl = (state->efl & ~EFL_USER_CLEAR) | EFL_USER_SET;

		/*
		 * If the trace trap bit is being set,
		 * ensure that the user returns via iret
		 * - which is signaled thusly:
		 */
		if ((saved_state->efl & EFL_TF) && state->cs == SYSENTER_CS)
			state->cs = SYSENTER_TF_CS;

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
		break;
	}

	case x86_SAVED_STATE64:
	{
		x86_saved_state64_t	*state;
		x86_saved_state64_t	*saved_state;

		if (count < x86_SAVED_STATE64_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (!thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		state = (x86_saved_state64_t *) tstate;

		/* Verify that the supplied code segment selector is
		 * valid. In 64-bit mode, the FS and GS segment overrides
		 * use the FS.base and GS.base MSRs to calculate
		 * base addresses, and the trampolines don't directly
		 * restore the segment registers--hence they are no
		 * longer relevant for validation.
		 */
		if (!valid_user_code_selector(state->isf.cs))
		        return KERN_INVALID_ARGUMENT;
		
		/* Check pc and stack are canonical addresses */
		if (!IS_USERADDR64_CANONICAL(state->isf.rsp) ||
		    !IS_USERADDR64_CANONICAL(state->isf.rip))
			return KERN_INVALID_ARGUMENT;

		saved_state = USER_REGS64(thr_act);

		/*
		 * General registers
		 */
		saved_state->r8 = state->r8;
		saved_state->r9 = state->r9;
		saved_state->r10 = state->r10;
		saved_state->r11 = state->r11;
		saved_state->r12 = state->r12;
		saved_state->r13 = state->r13;
		saved_state->r14 = state->r14;
		saved_state->r15 = state->r15;
		saved_state->rdi = state->rdi;
		saved_state->rsi = state->rsi;
		saved_state->rbp = state->rbp;
		saved_state->rbx = state->rbx;
		saved_state->rdx = state->rdx;
		saved_state->rcx = state->rcx;
		saved_state->rax = state->rax;
		saved_state->isf.rsp = state->isf.rsp;
		saved_state->isf.rip = state->isf.rip;

		saved_state->isf.rflags = (state->isf.rflags & ~EFL_USER_CLEAR) | EFL_USER_SET;

		/*
		 * User setting segment registers.
		 * Code and stack selectors have already been
		 * checked.  Others will be reset by 'sys'
		 * if they are not valid.
		 */
		saved_state->isf.cs = state->isf.cs;
		saved_state->isf.ss = state->isf.ss;
		saved_state->fs = state->fs;
		saved_state->gs = state->gs;
		break;
	}

	case x86_FLOAT_STATE32:
	{
		if (count != x86_FLOAT_STATE32_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		return fpu_set_fxstate(thr_act, tstate);
	}

	case x86_FLOAT_STATE64:
	{
		if (count != x86_FLOAT_STATE64_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if ( !thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		return fpu_set_fxstate(thr_act, tstate);
	}

	case x86_FLOAT_STATE:
	{   
		x86_float_state_t       *state;

		if (count != x86_FLOAT_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (x86_float_state_t *)tstate;
		if (state->fsh.flavor == x86_FLOAT_STATE64 && state->fsh.count == x86_FLOAT_STATE64_COUNT &&
		    thread_is_64bit(thr_act)) {
			return fpu_set_fxstate(thr_act, (thread_state_t)&state->ufs.fs64);
		}
		if (state->fsh.flavor == x86_FLOAT_STATE32 && state->fsh.count == x86_FLOAT_STATE32_COUNT &&
		    !thread_is_64bit(thr_act)) {
			return fpu_set_fxstate(thr_act, (thread_state_t)&state->ufs.fs32); 
		}
		return(KERN_INVALID_ARGUMENT);
	}

	case x86_THREAD_STATE32: 
	{
		if (count != x86_THREAD_STATE32_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		return set_thread_state32(thr_act, (x86_thread_state32_t *)tstate);
	}

	case x86_THREAD_STATE64: 
	{
		if (count != x86_THREAD_STATE64_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (!thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		return set_thread_state64(thr_act, (x86_thread_state64_t *)tstate);

	}
	case x86_THREAD_STATE:
	{
		x86_thread_state_t      *state;

		if (count != x86_THREAD_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (x86_thread_state_t *)tstate;

		if (state->tsh.flavor == x86_THREAD_STATE64 &&
		    state->tsh.count == x86_THREAD_STATE64_COUNT &&
		    thread_is_64bit(thr_act)) {
			return set_thread_state64(thr_act, &state->uts.ts64);
		} else if (state->tsh.flavor == x86_THREAD_STATE32 &&
			   state->tsh.count == x86_THREAD_STATE32_COUNT &&
			   !thread_is_64bit(thr_act)) {
			return set_thread_state32(thr_act, &state->uts.ts32);
		} else
			return(KERN_INVALID_ARGUMENT);

		break;
	}
	case x86_DEBUG_STATE32:
	{
		x86_debug_state32_t *state;
		kern_return_t ret;

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		state = (x86_debug_state32_t *)tstate;

		ret = set_debug_state32(thr_act, state);

		return ret;
	}
	case x86_DEBUG_STATE64:
	{
		x86_debug_state64_t *state;
		kern_return_t ret;

		if (!thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		state = (x86_debug_state64_t *)tstate;

		ret = set_debug_state64(thr_act, state);

		return ret;
	}
	case x86_DEBUG_STATE:
	{
		x86_debug_state_t *state;
		kern_return_t ret = KERN_INVALID_ARGUMENT;

		if (count != x86_DEBUG_STATE_COUNT)
			return (KERN_INVALID_ARGUMENT);

		state = (x86_debug_state_t *)tstate;
		if (state->dsh.flavor == x86_DEBUG_STATE64 &&
				state->dsh.count == x86_DEBUG_STATE64_COUNT &&
				thread_is_64bit(thr_act)) {
			ret = set_debug_state64(thr_act, &state->uds.ds64);
		}
		else
			if (state->dsh.flavor == x86_DEBUG_STATE32 &&
			    state->dsh.count == x86_DEBUG_STATE32_COUNT &&
			    !thread_is_64bit(thr_act)) {
				ret = set_debug_state32(thr_act, &state->uds.ds32);
		}
		return ret;
	}
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

	    case THREAD_STATE_FLAVOR_LIST:
	    {
		if (*count < 3)
		        return (KERN_INVALID_ARGUMENT);

	        tstate[0] = i386_THREAD_STATE;
		tstate[1] = i386_FLOAT_STATE;
		tstate[2] = i386_EXCEPTION_STATE;

		*count = 3;
		break;
	    }

	    case THREAD_STATE_FLAVOR_LIST_NEW:
	    {
		if (*count < 4)
		        return (KERN_INVALID_ARGUMENT);

	        tstate[0] = x86_THREAD_STATE;
		tstate[1] = x86_FLOAT_STATE;
		tstate[2] = x86_EXCEPTION_STATE;
		tstate[3] = x86_DEBUG_STATE;

		*count = 4;
		break;
	    }

	    case x86_SAVED_STATE32:
	    {
		x86_saved_state32_t	*state;
		x86_saved_state32_t	*saved_state;

		if (*count < x86_SAVED_STATE32_COUNT)
		        return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		state = (x86_saved_state32_t *) tstate;
		saved_state = USER_REGS32(thr_act);

		/*
		 * First, copy everything:
		 */
		*state = *saved_state;
		state->ds = saved_state->ds & 0xffff;
		state->es = saved_state->es & 0xffff;
		state->fs = saved_state->fs & 0xffff;
		state->gs = saved_state->gs & 0xffff;

		*count = x86_SAVED_STATE32_COUNT;
		break;
	    }

	    case x86_SAVED_STATE64:
	    {
		x86_saved_state64_t	*state;
		x86_saved_state64_t	*saved_state;

		if (*count < x86_SAVED_STATE64_COUNT)
		        return(KERN_INVALID_ARGUMENT);

		if (!thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		state = (x86_saved_state64_t *)tstate;
		saved_state = USER_REGS64(thr_act);

		/*
		 * First, copy everything:
		 */
		*state = *saved_state;
		state->fs = saved_state->fs & 0xffff;
		state->gs = saved_state->gs & 0xffff;

		*count = x86_SAVED_STATE64_COUNT;
		break;
	    }

	    case x86_FLOAT_STATE32:
	    {
		if (*count < x86_FLOAT_STATE32_COUNT) 
			return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		*count = x86_FLOAT_STATE32_COUNT;

		return fpu_get_fxstate(thr_act, tstate);
	    }

	    case x86_FLOAT_STATE64:
	    {
		if (*count < x86_FLOAT_STATE64_COUNT) 
			return(KERN_INVALID_ARGUMENT);

		if ( !thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		*count = x86_FLOAT_STATE64_COUNT;

		return fpu_get_fxstate(thr_act, tstate);
	    }

	    case x86_FLOAT_STATE:
	    {
	        x86_float_state_t	*state;
		kern_return_t		kret;

		if (*count < x86_FLOAT_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (x86_float_state_t *)tstate;

		/*
		 * no need to bzero... currently 
		 * x86_FLOAT_STATE64_COUNT == x86_FLOAT_STATE32_COUNT
		 */
		if (thread_is_64bit(thr_act)) {
		        state->fsh.flavor = x86_FLOAT_STATE64;
		        state->fsh.count  = x86_FLOAT_STATE64_COUNT;

			kret = fpu_get_fxstate(thr_act, (thread_state_t)&state->ufs.fs64);
		} else {
		        state->fsh.flavor = x86_FLOAT_STATE32;
			state->fsh.count  = x86_FLOAT_STATE32_COUNT;

			kret = fpu_get_fxstate(thr_act, (thread_state_t)&state->ufs.fs32);
		}
		*count = x86_FLOAT_STATE_COUNT;

		return(kret);
	    }

	    case x86_THREAD_STATE32: 
	    {
		if (*count < x86_THREAD_STATE32_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
		        return(KERN_INVALID_ARGUMENT);

		*count = x86_THREAD_STATE32_COUNT;

		get_thread_state32(thr_act, (x86_thread_state32_t *)tstate);
		break;
	    }

	    case x86_THREAD_STATE64:
	    {
		if (*count < x86_THREAD_STATE64_COUNT)
			return(KERN_INVALID_ARGUMENT);

                if ( !thread_is_64bit(thr_act))
		        return(KERN_INVALID_ARGUMENT);

		*count = x86_THREAD_STATE64_COUNT;

		get_thread_state64(thr_act, (x86_thread_state64_t *)tstate);
		break;
	    }

	    case x86_THREAD_STATE:
	    {
		x86_thread_state_t 	*state;

		if (*count < x86_THREAD_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (x86_thread_state_t *)tstate;

		bzero((char *)state, sizeof(x86_thread_state_t));

		if (thread_is_64bit(thr_act)) {
			state->tsh.flavor = x86_THREAD_STATE64;
			state->tsh.count  = x86_THREAD_STATE64_COUNT;

		        get_thread_state64(thr_act, &state->uts.ts64);
		} else {
			state->tsh.flavor = x86_THREAD_STATE32;
			state->tsh.count  = x86_THREAD_STATE32_COUNT;

		        get_thread_state32(thr_act, &state->uts.ts32);
		}
		*count = x86_THREAD_STATE_COUNT;

		break;
	    }


	    case x86_EXCEPTION_STATE32:
	    {
		if (*count < x86_EXCEPTION_STATE32_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		*count = x86_EXCEPTION_STATE32_COUNT;

		get_exception_state32(thr_act, (x86_exception_state32_t *)tstate);
		break;
	    }

	    case x86_EXCEPTION_STATE64:
	    {
		if (*count < x86_EXCEPTION_STATE64_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if ( !thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		*count = x86_EXCEPTION_STATE64_COUNT;

		get_exception_state64(thr_act, (x86_exception_state64_t *)tstate);
		break;
	    }

	    case x86_EXCEPTION_STATE:
	    {
		x86_exception_state_t 	*state;

		if (*count < x86_EXCEPTION_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (x86_exception_state_t *)tstate;

		bzero((char *)state, sizeof(x86_exception_state_t));

		if (thread_is_64bit(thr_act)) {
			state->esh.flavor = x86_EXCEPTION_STATE64;
			state->esh.count  = x86_EXCEPTION_STATE64_COUNT;

		        get_exception_state64(thr_act, &state->ues.es64);
		} else {
			state->esh.flavor = x86_EXCEPTION_STATE32;
			state->esh.count  = x86_EXCEPTION_STATE32_COUNT;

		        get_exception_state32(thr_act, &state->ues.es32);
		}
		*count = x86_EXCEPTION_STATE_COUNT;

		break;
	}
	case x86_DEBUG_STATE32:
	{
		if (*count < x86_DEBUG_STATE32_COUNT)
			return(KERN_INVALID_ARGUMENT);

		if (thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		get_debug_state32(thr_act, (x86_debug_state32_t *)tstate);

		*count = x86_DEBUG_STATE32_COUNT;

		break;
	}
	case x86_DEBUG_STATE64:
	{
		if (*count < x86_DEBUG_STATE64_COUNT)
			return(KERN_INVALID_ARGUMENT);
		
		if (!thread_is_64bit(thr_act))
			return(KERN_INVALID_ARGUMENT);

		get_debug_state64(thr_act, (x86_debug_state64_t *)tstate);

		*count = x86_DEBUG_STATE64_COUNT;

		break;
	}
	case x86_DEBUG_STATE:
	{
		x86_debug_state_t   *state;

		if (*count < x86_DEBUG_STATE_COUNT)
			return(KERN_INVALID_ARGUMENT);

		state = (x86_debug_state_t *)tstate;

		bzero(state, sizeof *state);

		if (thread_is_64bit(thr_act)) {
			state->dsh.flavor = x86_DEBUG_STATE64;
			state->dsh.count  = x86_DEBUG_STATE64_COUNT;

			get_debug_state64(thr_act, &state->uds.ds64);
		} else {
			state->dsh.flavor = x86_DEBUG_STATE32;
			state->dsh.count  = x86_DEBUG_STATE32_COUNT;

			get_debug_state32(thr_act, &state->uds.ds32);
		}
		*count = x86_DEBUG_STATE_COUNT;
		break;
	}
	default:
		return(KERN_INVALID_ARGUMENT);
	}

	return(KERN_SUCCESS);
}

kern_return_t
machine_thread_get_kern_state(
		thread_t		thread,
		thread_flavor_t		flavor,
		thread_state_t		tstate,
		mach_msg_type_number_t	*count)
{

	/*
	 * This works only for an interrupted kernel thread
	 */
	if (thread != current_thread() || current_cpu_datap()->cpu_int_state == NULL)
		return KERN_FAILURE;

	switch(flavor) {
		case x86_THREAD_STATE32:
		{
			x86_thread_state32_t	*state;
			x86_saved_state32_t	*saved_state;

			if (*count < x86_THREAD_STATE32_COUNT)
				return(KERN_INVALID_ARGUMENT);     

			state = (x86_thread_state32_t *)tstate;

			assert(is_saved_state32(current_cpu_datap()->cpu_int_state));
			saved_state = saved_state32(current_cpu_datap()->cpu_int_state);
			/*
			 * General registers.
			 */
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
			state->ds = saved_state->ds & 0xffff;
			state->es = saved_state->es & 0xffff;
			state->fs = saved_state->fs & 0xffff;
			state->gs = saved_state->gs & 0xffff;

			*count = x86_THREAD_STATE32_COUNT;

			return KERN_SUCCESS;
		}
		break;

		case x86_THREAD_STATE:
		{
			// wrap a 32 bit thread state into a 32/64bit clean thread state
            x86_thread_state_t      *state;
            x86_saved_state32_t     *saved_state;

            if(*count < x86_THREAD_STATE_COUNT)
                return (KERN_INVALID_ARGUMENT);

            state = (x86_thread_state_t *)tstate;
            assert(is_saved_state32(current_cpu_datap()->cpu_int_state));
            saved_state = saved_state32(current_cpu_datap()->cpu_int_state);

            state->tsh.flavor = x86_THREAD_STATE32;
            state->tsh.count = x86_THREAD_STATE32_COUNT;

            /* 
             * General registers.
             */

            state->uts.ts32.eax = saved_state->eax;
            state->uts.ts32.ebx = saved_state->ebx;
            state->uts.ts32.ecx = saved_state->ecx;
            state->uts.ts32.edx = saved_state->edx;
            state->uts.ts32.edi = saved_state->edi;
            state->uts.ts32.esi = saved_state->esi;
            state->uts.ts32.ebp = saved_state->ebp;
            state->uts.ts32.esp = saved_state->uesp;
            state->uts.ts32.eflags = saved_state->efl;
            state->uts.ts32.eip = saved_state->eip;
            state->uts.ts32.cs = saved_state->cs;
            state->uts.ts32.ss = saved_state->ss;
            state->uts.ts32.ds = saved_state->ds & 0xffff;
            state->uts.ts32.es = saved_state->es & 0xffff;
            state->uts.ts32.fs = saved_state->fs & 0xffff;
            state->uts.ts32.gs = saved_state->gs & 0xffff;

            *count = x86_THREAD_STATE_COUNT;
            return KERN_SUCCESS;
		}
		break;
	}
	return KERN_FAILURE;
}


/*
 * Initialize the machine-dependent state for a new thread.
 */
kern_return_t
machine_thread_create(
	thread_t		thread,
	task_t			task)
{
	pcb_t			pcb = &thread->machine.xxx_pcb;
	struct real_descriptor	*ldtp;
	pmap_paddr_t		paddr;
	x86_saved_state_t	*iss;

	inval_copy_windows(thread);

	thread->machine.physwindow_pte = 0;
	thread->machine.physwindow_busy = 0;

	/*
	 * Allocate pcb only if required.
	 */
	if (pcb->sf == NULL) {
		pcb->sf = zalloc(iss_zone);
		if (pcb->sf == NULL)
			panic("iss_zone");
	}

        if (task_has_64BitAddr(task)) {
		x86_sframe64_t		*sf64;

		sf64 = (x86_sframe64_t *) pcb->sf;

		bzero((char *)sf64, sizeof(x86_sframe64_t));

		iss = (x86_saved_state_t *) &sf64->ssf;
		iss->flavor = x86_SAVED_STATE64;
		/*
		 *      Guarantee that the bootstrapped thread will be in user
		 *      mode.
		 */
		iss->ss_64.isf.rflags = EFL_USER_SET;
		iss->ss_64.isf.cs = USER64_CS;
		iss->ss_64.isf.ss = USER_DS;
		iss->ss_64.fs = USER_DS;
		iss->ss_64.gs = USER_DS;
	} else {
		if (cpu_mode_is64bit()) {
			x86_sframe_compat32_t      *sfc32;

			sfc32 = (x86_sframe_compat32_t *)pcb->sf;

			bzero((char *)sfc32, sizeof(x86_sframe_compat32_t));

			iss = (x86_saved_state_t *) &sfc32->ssf.iss32;
			iss->flavor = x86_SAVED_STATE32;
#if DEBUG
			{
				x86_saved_state_compat32_t *xssc;

				xssc  = (x86_saved_state_compat32_t *) iss;
				xssc->pad_for_16byte_alignment[0] = 0x64326432;
				xssc->pad_for_16byte_alignment[1] = 0x64326432;
			}
#endif
		} else {
			x86_sframe32_t  *sf32;

			sf32 = (x86_sframe32_t *) pcb->sf;

			bzero((char *)sf32, sizeof(x86_sframe32_t));

			iss = (x86_saved_state_t *) &sf32->ssf;
			iss->flavor = x86_SAVED_STATE32;
		}
		/*
		 *      Guarantee that the bootstrapped thread will be in user
		 *      mode.
		 */
		iss->ss_32.cs = USER_CS;
		iss->ss_32.ss = USER_DS;
		iss->ss_32.ds = USER_DS;
		iss->ss_32.es = USER_DS;
		iss->ss_32.fs = USER_DS;
		iss->ss_32.gs = USER_DS;
		iss->ss_32.efl = EFL_USER_SET;

	}
	pcb->iss = iss;

	thread->machine.pcb = pcb;
	simple_lock_init(&pcb->lock, 0);

	ldtp = (struct real_descriptor *)pmap_index_to_virt(HIGH_FIXED_LDT_BEGIN);
	pcb->cthread_desc = ldtp[sel_idx(USER_DS)];
	pcb->uldt_desc = ldtp[sel_idx(USER_DS)];
	pcb->uldt_selector = 0;

	pcb->iss_pte0 = (uint64_t)pte_kernel_rw(kvtophys((vm_offset_t)pcb->iss));
	pcb->arg_store_valid = 0;

	if (0 == (paddr = pa_to_pte(kvtophys((vm_offset_t)(pcb->iss) + PAGE_SIZE))))
	        pcb->iss_pte1 = INTEL_PTE_INVALID;
	else
	        pcb->iss_pte1 = (uint64_t)pte_kernel_rw(paddr);

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
        
	if (pcb->ifps != 0)
		fpu_free(pcb->ifps);
	if (pcb->sf != 0) {
		zfree(iss_zone, pcb->sf);
		pcb->sf = 0;
	}
	if (pcb->ids) {
		zfree(ids_zone, pcb->ids);
		pcb->ids = NULL;
	}
	thread->machine.pcb = (pcb_t)0;

}

void
machine_thread_switch_addrmode(thread_t thread)
{
	/*
	 * We don't want to be preempted until we're done
	 * - particularly if we're switching the current thread
	 */
	disable_preemption();

	/*
	 * Reset the state saveareas.
	 */
	machine_thread_create(thread, thread->task);

	/* If we're switching ourselves, reset the pcb addresses etc. */
	if (thread == current_thread())
		act_machine_switch_pcb(thread);

	enable_preemption();
}



/*
 * This is used to set the current thr_act/thread
 * when starting up a new processor
 */
void
machine_set_current_thread( thread_t thread )
{
	current_cpu_datap()->cpu_active_thread = thread;
}

/*
 * This is called when a task is termianted.
 */
void
machine_thread_terminate_self(void)
{
	task_t self_task = current_task();
	if (self_task) {
	    user_ldt_t user_ldt = self_task->i386_ldt;
	    if (user_ldt != 0) {
		self_task->i386_ldt = 0;
		user_ldt_free(user_ldt);
	    }
	}
}

void
act_machine_return(
#if CONFIG_NO_PANIC_STRINGS
		__unused int code
#else
		int code
#endif
		)
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
	if (cpu_mode_is64bit()) {
		assert(sizeof(x86_sframe_compat32_t) % 16 == 0);
		iss_zone = zinit(sizeof(x86_sframe64_t),
				THREAD_MAX * sizeof(x86_sframe64_t),
				THREAD_CHUNK * sizeof(x86_sframe64_t),
				"x86_64 saved state");

	        ids_zone = zinit(sizeof(x86_debug_state64_t),
				 THREAD_MAX * sizeof(x86_debug_state64_t),
				 THREAD_CHUNK * sizeof(x86_debug_state64_t),
				 "x86_64 debug state");

	} else {
		iss_zone = zinit(sizeof(x86_sframe32_t),
				THREAD_MAX * sizeof(x86_sframe32_t),
				THREAD_CHUNK * sizeof(x86_sframe32_t),
				"x86 saved state");
	        ids_zone = zinit(sizeof(x86_debug_state32_t),
				THREAD_MAX * (sizeof(x86_debug_state32_t)),
				THREAD_CHUNK * (sizeof(x86_debug_state32_t)),
				"x86 debug state");
	}
	fpu_module_init();
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
				printf("[NON-Zero next ptr(%p)]", rhp->next);
			printf("special_handler()->");
			break;
		}
		printf("hdlr_%d(%p)->", counter, rhp->handler);
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
	if (thr_act->machine.pcb == NULL)
		return;

	if (thread_is_64bit(thr_act)) {
		x86_saved_state64_t	*ssp;

		ssp = USER_REGS64(thr_act);

		panic("dump_regs: 64bit tasks not yet supported");

	} else {
		x86_saved_state32_t	*ssp;

		ssp = USER_REGS32(thr_act);

		/*
		 * Print out user register state
		 */
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

	printf("thread(%p)(%d): task=%p(%d)\n",
			thr_act, thr_act->ref_count,
			thr_act->task,
			thr_act->task   ? thr_act->task->ref_count : 0);

	printf("\tsusp=%d user_stop=%d active=%x ast=%x\n",
			thr_act->suspend_count, thr_act->user_stop_count,
			thr_act->active, thr_act->ast);
	printf("\tpcb=%p\n", thr_act->machine.pcb);

	if (thr_act->kernel_stack) {
		vm_offset_t stack = thr_act->kernel_stack;

		printf("\tk_stk %x  eip %x ebx %x esp %x iss %p\n",
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
 
	if (thr_act->machine.pcb == NULL) 
		return(0);

        if (thread_is_64bit(thr_act)) {
	        x86_saved_state64_t	*iss64;
		
		iss64 = USER_REGS64(thr_act);

         	return(iss64->isf.rip);
	} else {
	        x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(thr_act);

         	return(iss32->eip);
	}
}

/*
 * detach and return a kernel stack from a thread
 */

vm_offset_t
machine_stack_detach(thread_t thread)
{
	vm_offset_t     stack;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_DETACH),
		     thread, thread->priority,
		     thread->sched_pri, 0,
		     0);

	stack = thread->kernel_stack;
	thread->kernel_stack = 0;

	return (stack);
}

/*
 * attach a kernel stack to a thread and initialize it
 */

void
machine_stack_attach(
	thread_t		thread,
	vm_offset_t		stack)
{
	struct x86_kernel_state32 *statep;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_ATTACH),
		     thread, thread->priority,
		     thread->sched_pri, 0, 0);

	assert(stack);
	thread->kernel_stack = stack;

	statep = STACK_IKS(stack);
	statep->k_eip = (unsigned long) Thread_continue;
	statep->k_ebx = (unsigned long) thread_continue;
	statep->k_esp = (unsigned long) STACK_IEL(stack);

	return;
}

/*
 * move a stack from old to new thread
 */

void
machine_stack_handoff(thread_t old,
	      thread_t new)
{
	vm_offset_t     stack;

	assert(new);
	assert(old);

	stack = old->kernel_stack;
	if (stack == old->reserved_stack) {
		assert(new->reserved_stack);
		old->reserved_stack = new->reserved_stack;
		new->reserved_stack = stack;
	}
	old->kernel_stack = 0;
	/*
	 * A full call to machine_stack_attach() is unnecessry
	 * because old stack is already initialized.
	 */
	new->kernel_stack = stack;

	fpu_save_context(old);

	old->machine.specFlags &= ~OnProc;
	new->machine.specFlags |= OnProc;

	PMAP_SWITCH_CONTEXT(old, new, cpu_number());
	act_machine_switch_pcb(new);

	machine_set_current_thread(new);

	return;
}




struct x86_act_context32 {
	x86_saved_state32_t ss;
	x86_float_state32_t fs;
	x86_debug_state32_t ds;
};

struct x86_act_context64 {
	x86_saved_state64_t ss;
	x86_float_state64_t fs;
	x86_debug_state64_t ds;
};



void *
act_thread_csave(void)
{
	kern_return_t kret;
	mach_msg_type_number_t val;
	thread_t thr_act = current_thread();

	if (thread_is_64bit(thr_act)) {
		struct x86_act_context64 *ic64;

		ic64 = (struct x86_act_context64 *)kalloc(sizeof(struct x86_act_context64));

		if (ic64 == (struct x86_act_context64 *)NULL)
			return((void *)0);

		val = x86_SAVED_STATE64_COUNT; 
		kret = machine_thread_get_state(thr_act, x86_SAVED_STATE64,
				(thread_state_t) &ic64->ss, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic64, sizeof(struct x86_act_context64));
			return((void *)0);
		}
		val = x86_FLOAT_STATE64_COUNT; 
		kret = machine_thread_get_state(thr_act, x86_FLOAT_STATE64,
				(thread_state_t) &ic64->fs, &val);

		if (kret != KERN_SUCCESS) {
			kfree(ic64, sizeof(struct x86_act_context64));
			return((void *)0);
		}

		val = x86_DEBUG_STATE64_COUNT;
		kret = machine_thread_get_state(thr_act,
						x86_DEBUG_STATE64,
						(thread_state_t)&ic64->ds,
						&val);
		if (kret != KERN_SUCCESS) {
		        kfree(ic64, sizeof(struct x86_act_context64));
			return((void *)0);
		}
		return(ic64);

	} else {
		struct x86_act_context32 *ic32;

		ic32 = (struct x86_act_context32 *)kalloc(sizeof(struct x86_act_context32));

		if (ic32 == (struct x86_act_context32 *)NULL)
			return((void *)0);

		val = x86_SAVED_STATE32_COUNT; 
		kret = machine_thread_get_state(thr_act, x86_SAVED_STATE32,
				(thread_state_t) &ic32->ss, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic32, sizeof(struct x86_act_context32));
			return((void *)0);
		}
		val = x86_FLOAT_STATE32_COUNT; 
		kret = machine_thread_get_state(thr_act, x86_FLOAT_STATE32,
				(thread_state_t) &ic32->fs, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic32, sizeof(struct x86_act_context32));
			return((void *)0);
		}

		val = x86_DEBUG_STATE32_COUNT;
		kret = machine_thread_get_state(thr_act,
						x86_DEBUG_STATE32,
						(thread_state_t)&ic32->ds,
						&val);
		if (kret != KERN_SUCCESS) {
		        kfree(ic32, sizeof(struct x86_act_context32));
			return((void *)0);
		}
		return(ic32);
	}
}


void 
act_thread_catt(void *ctx)
{
        thread_t thr_act = current_thread();
	kern_return_t kret;

	if (ctx == (void *)NULL)
				return;

        if (thread_is_64bit(thr_act)) {
	        struct x86_act_context64 *ic64;

	        ic64 = (struct x86_act_context64 *)ctx;

		kret = machine_thread_set_state(thr_act, x86_SAVED_STATE64,
						(thread_state_t) &ic64->ss, x86_SAVED_STATE64_COUNT);
		if (kret == KERN_SUCCESS) {
			        machine_thread_set_state(thr_act, x86_FLOAT_STATE64,
							 (thread_state_t) &ic64->fs, x86_FLOAT_STATE64_COUNT);
		}
		kfree(ic64, sizeof(struct x86_act_context64));
	} else {
	        struct x86_act_context32 *ic32;

	        ic32 = (struct x86_act_context32 *)ctx;

		kret = machine_thread_set_state(thr_act, x86_SAVED_STATE32,
						(thread_state_t) &ic32->ss, x86_SAVED_STATE32_COUNT);
		if (kret == KERN_SUCCESS) {
		        kret = machine_thread_set_state(thr_act, x86_FLOAT_STATE32,
						 (thread_state_t) &ic32->fs, x86_FLOAT_STATE32_COUNT);
			if (kret == KERN_SUCCESS && thr_act->machine.pcb->ids)
				machine_thread_set_state(thr_act,
							 x86_DEBUG_STATE32,
							 (thread_state_t)&ic32->ds,
							 x86_DEBUG_STATE32_COUNT);
		}
		kfree(ic32, sizeof(struct x86_act_context32));
	}
}


void act_thread_cfree(__unused void *ctx)
{
	/* XXX - Unused */
}
void x86_toggle_sysenter_arg_store(thread_t thread, boolean_t valid);
void x86_toggle_sysenter_arg_store(thread_t thread, boolean_t valid) {
	thread->machine.pcb->arg_store_valid = valid;
}

boolean_t x86_sysenter_arg_store_isvalid(thread_t thread);

boolean_t x86_sysenter_arg_store_isvalid(thread_t thread) {
	return (thread->machine.pcb->arg_store_valid);
}
