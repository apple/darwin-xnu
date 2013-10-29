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

#include <i386/commpage/commpage.h>
#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/seg.h>
#include <i386/machine_routines.h>

#define ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(_type_)	\
extern char assert_is_16byte_multiple_sizeof_ ## _type_	\
		[(sizeof(_type_) % 16) == 0 ? 1 : -1]

/* Compile-time checks for vital save area sizing: */
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_64_intr_stack_frame_t);
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_saved_state_t);

#define DIRECTION_FLAG_DEBUG (DEBUG | DEVELOPMENT)

extern zone_t		iss_zone;		/* zone for saved_state area */
extern zone_t		ids_zone;		/* zone for debug_state area */

extern void *get_bsduthreadarg(thread_t);
void
act_machine_switch_pcb(__unused thread_t old, thread_t new)
{
        pcb_t			pcb = THREAD_TO_PCB(new);
	cpu_data_t      	*cdp = current_cpu_datap();
	struct real_descriptor	*ldtp;
	mach_vm_offset_t	pcb_stack_top;

	assert(new->kernel_stack != 0);
	assert(ml_get_interrupts_enabled() == FALSE);
#ifdef	DIRECTION_FLAG_DEBUG
	if (x86_get_flags() & EFL_DF) {
		panic("Direction flag detected: 0x%lx", x86_get_flags());
	}
#endif

	/*
	 * Clear segment state
	 * unconditionally for DS/ES/FS but more carefully for GS whose
	 * cached state we track.
	 */
	set_ds(NULL_SEG);
	set_es(NULL_SEG);
	set_fs(NULL_SEG);
	if (get_gs() != NULL_SEG) {
		swapgs();		/* switch to user's GS context */
		set_gs(NULL_SEG);
		swapgs();		/* and back to kernel */

		/* record the active machine state lost */
		cdp->cpu_uber.cu_user_gs_base = 0;
	} 

	vm_offset_t			isf;

	/*
	 * Set pointer to PCB's interrupt stack frame in cpu data.
	 * Used by syscall and double-fault trap handlers.
	 */
	isf = (vm_offset_t) &pcb->iss->ss_64.isf;
	cdp->cpu_uber.cu_isf = isf;
	pcb_stack_top = (vm_offset_t) (pcb->iss + 1);
	/* require 16-byte alignment */
	assert((pcb_stack_top & 0xF) == 0);

	/* Interrupt stack is pcb */
	current_ktss64()->rsp0 = pcb_stack_top;

	/*
	 * Top of temporary sysenter stack points to pcb stack.
	 * Although this is not normally used by 64-bit users,
	 * it needs to be set in case a sysenter is attempted.
	 */
	*current_sstk64() = pcb_stack_top;

	if (is_saved_state64(pcb->iss)) {

		cdp->cpu_task_map = new->map->pmap->pm_task_map; 

		/*
		 * Enable the 64-bit user code segment, USER64_CS.
		 * Disable the 32-bit user code segment, USER_CS.
		 */
		ldt_desc_p(USER64_CS)->access |= ACC_PL_U;
		ldt_desc_p(USER_CS)->access &= ~ACC_PL_U;

		/*
		 * Switch user's GS base if necessary
		 * by setting the Kernel's GS base MSR
		 * - this will become the user's on the swapgs when
		 * returning to user-space.  Avoid this for
		 * kernel threads (no user TLS support required)
		 * and verify the memory shadow of the segment base
		 * in the event it was altered in user space.
		 */
		if ((pcb->cthread_self != 0) || (new->task != kernel_task)) {
			if ((cdp->cpu_uber.cu_user_gs_base != pcb->cthread_self) || (pcb->cthread_self != rdmsr64(MSR_IA32_KERNEL_GS_BASE))) {
				cdp->cpu_uber.cu_user_gs_base = pcb->cthread_self;
				wrmsr64(MSR_IA32_KERNEL_GS_BASE, pcb->cthread_self);
			}
		}

	} else {

		cdp->cpu_task_map = TASK_MAP_32BIT;

		/*
		 * Disable USER64_CS
		 * Enable USER_CS
		 */
		ldt_desc_p(USER64_CS)->access &= ~ACC_PL_U;
		ldt_desc_p(USER_CS)->access |= ACC_PL_U;

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
	}

	/*
	 * Bump the scheduler generation count in the commpage.
	 * This can be read by user code to detect its preemption.
	 */
	commpage_sched_gen_inc();
}

kern_return_t
thread_set_wq_state32(thread_t thread, thread_state_t tstate)
{
        x86_thread_state32_t	*state;
        x86_saved_state32_t	*saved_state;
	thread_t curth = current_thread();
	spl_t			s=0;

	pal_register_cache_state(thread, DIRTY);

	saved_state = USER_REGS32(thread);

	state = (x86_thread_state32_t *)tstate;
	
	if (curth != thread) {
		s = splsched();
	        thread_lock(thread);
	}

	saved_state->ebp = 0;
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

	if (curth != thread) {
	        thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}


kern_return_t
thread_set_wq_state64(thread_t thread, thread_state_t tstate)
{
        x86_thread_state64_t	*state;
        x86_saved_state64_t	*saved_state;
	thread_t curth = current_thread();
	spl_t			s=0;

	saved_state = USER_REGS64(thread);
	state = (x86_thread_state64_t *)tstate;
	
	/* Disallow setting non-canonical PC or stack */
	if (!IS_USERADDR64_CANONICAL(state->rsp) ||
	    !IS_USERADDR64_CANONICAL(state->rip)) {
		return KERN_FAILURE;
	}

	pal_register_cache_state(thread, DIRTY);

	if (curth != thread) {
		s = splsched();
	        thread_lock(thread);
	}

	saved_state->rbp = 0;
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

	if (curth != thread) {
	        thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}

/*
 * Initialize the machine-dependent state for a new thread.
 */
kern_return_t
machine_thread_create(
	thread_t		thread,
	task_t			task)
{
        pcb_t			pcb = THREAD_TO_PCB(thread);

#if NCOPY_WINDOWS > 0
	inval_copy_windows(thread);

	thread->machine.physwindow_pte = 0;
	thread->machine.physwindow_busy = 0;
#endif

	/*
	 * Allocate save frame only if required.
	 */
	if (pcb->iss == NULL) {
		assert((get_preemption_level() == 0));
		pcb->iss = (x86_saved_state_t *) zalloc(iss_zone);
		if (pcb->iss == NULL)
			panic("iss_zone");
	}

	/*
	 * Assure that the synthesized 32-bit state including
	 * the 64-bit interrupt state can be acommodated in the 
	 * 64-bit state we allocate for both 32-bit and 64-bit threads.
	 */
	assert(sizeof(pcb->iss->ss_32) + sizeof(pcb->iss->ss_64.isf) <=
	       sizeof(pcb->iss->ss_64));

	bzero((char *)pcb->iss, sizeof(x86_saved_state_t));

        if (task_has_64BitAddr(task)) {
		pcb->iss->flavor = x86_SAVED_STATE64;

		pcb->iss->ss_64.isf.cs = USER64_CS;
		pcb->iss->ss_64.isf.ss = USER_DS;
		pcb->iss->ss_64.fs = USER_DS;
		pcb->iss->ss_64.gs = USER_DS;
		pcb->iss->ss_64.isf.rflags = EFL_USER_SET;
	} else {
		pcb->iss->flavor = x86_SAVED_STATE32;

		pcb->iss->ss_32.cs = USER_CS;
		pcb->iss->ss_32.ss = USER_DS;
		pcb->iss->ss_32.ds = USER_DS;
		pcb->iss->ss_32.es = USER_DS;
		pcb->iss->ss_32.fs = USER_DS;
		pcb->iss->ss_32.gs = USER_DS;
		pcb->iss->ss_32.efl = EFL_USER_SET;
	}

	simple_lock_init(&pcb->lock, 0);

	pcb->cthread_self = 0;
	pcb->uldt_selector = 0;

	/* Ensure that the "cthread" descriptor describes a valid
	 * segment.
	 */
	if ((pcb->cthread_desc.access & ACC_P) == 0) {
		struct real_descriptor  *ldtp;
		ldtp = (struct real_descriptor *)current_ldt();
		pcb->cthread_desc = ldtp[sel_idx(USER_DS)];
	}

	return(KERN_SUCCESS);
}

/*
 * Machine-dependent cleanup prior to destroying a thread
 */
void
machine_thread_destroy(
	thread_t		thread)
{
	register pcb_t	pcb = THREAD_TO_PCB(thread);

	if (pcb->ifps != 0)
		fpu_free(pcb->ifps);
	if (pcb->iss != 0) {
		zfree(iss_zone, pcb->iss);
		pcb->iss = 0;
	}
	if (pcb->ids) {
		zfree(ids_zone, pcb->ids);
		pcb->ids = NULL;
	}
}
