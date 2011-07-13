/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
#if defined(__i386__)
#include <i386/fpu.h>
#endif
#include <i386/seg.h>
#include <i386/machine_routines.h>

#define ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(_type_)	\
extern char assert_is_16byte_multiple_sizeof_ ## _type_	\
		[(sizeof(_type_) % 16) == 0 ? 1 : -1]

/* Compile-time checks for vital save area sizing: */
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_64_intr_stack_frame_t);
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_sframe64_t);
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_saved_state_compat32_t);
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

#if defined(__x86_64__)
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

	if (is_saved_state64(pcb->iss)) {
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
		cdp->cpu_uber.cu_isf = isf;
		pcb_stack_top = (vm_offset_t) (iss64 + 1);
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
		x86_saved_state_compat32_t	*iss32compat;
		vm_offset_t			isf;

		assert(is_saved_state32(pcb->iss));
		iss32compat = (x86_saved_state_compat32_t *) pcb->iss;

		pcb_stack_top = (uintptr_t) (iss32compat + 1);
		/* require 16-byte alignment */
		assert((pcb_stack_top & 0xF) == 0);

		/*
		 * Set pointer to PCB's interrupt stack frame in cpu data.
		 * Used by debug trap handler.
		 */
		isf = (vm_offset_t) &iss32compat->isf64;
		cdp->cpu_uber.cu_isf = isf;

		/* Top of temporary sysenter stack points to pcb stack */
		*current_sstk64() = pcb_stack_top;

		/* Interrupt stack is pcb */
		current_ktss64()->rsp0 = pcb_stack_top;

		cdp->cpu_task_map = TASK_MAP_32BIT;
		/* Precalculate pointers to syscall argument store, for use
		 * in the trampolines.
		 */
		cdp->cpu_uber_arg_store = (vm_offset_t)get_bsduthreadarg(new);
		cdp->cpu_uber_arg_store_valid = (vm_offset_t)&pcb->arg_store_valid;
		pcb->arg_store_valid = 0;

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

#else /* !__x86_64__ */

	vm_offset_t		hi_pcb_stack_top;
	vm_offset_t		hi_iss;

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
#endif

	/*
	 * Bump the scheduler generation count in the commpage.
	 * This can be read by user code to detect its preemption.
	 */
	commpage_sched_gen_inc();
}
void
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
}


void
thread_set_wq_state64(thread_t thread, thread_state_t tstate)
{
        x86_thread_state64_t	*state;
        x86_saved_state64_t	*saved_state;
	thread_t curth = current_thread();
	spl_t			s=0;

	pal_register_cache_state(thread, DIRTY);

	saved_state = USER_REGS64(thread);
	state = (x86_thread_state64_t *)tstate;
	
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
	x86_saved_state_t	*iss;

#if NCOPY_WINDOWS > 0
	inval_copy_windows(thread);

	thread->machine.physwindow_pte = 0;
	thread->machine.physwindow_busy = 0;
#endif

	/*
	 * Allocate save frame only if required.
	 */
	if (pcb->sf == NULL) {
		assert((get_preemption_level() == 0));
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
#if defined(__i386__)
#if DEBUG
			{
				sfc32->pad_for_16byte_alignment[0] = 0x64326432;
				sfc32->pad_for_16byte_alignment[1] = 0x64326432;
			}
#endif /* DEBUG */
		} else {
			x86_sframe32_t		*sf32;
			struct real_descriptor	*ldtp;
			pmap_paddr_t		paddr;

			sf32 = (x86_sframe32_t *) pcb->sf;

			bzero((char *)sf32, sizeof(x86_sframe32_t));

			iss = (x86_saved_state_t *) &sf32->ssf;
			iss->flavor = x86_SAVED_STATE32;

			pcb->iss_pte0 = pte_kernel_rw(kvtophys((vm_offset_t)iss));
			if (0 == (paddr = pa_to_pte(kvtophys((vm_offset_t)iss + PAGE_SIZE))))
			        pcb->iss_pte1 = INTEL_PTE_INVALID;
			else
	      			pcb->iss_pte1 = pte_kernel_rw(paddr);

			ldtp = (struct real_descriptor *)
				    pmap_index_to_virt(HIGH_FIXED_LDT_BEGIN);
			pcb->cthread_desc = ldtp[sel_idx(USER_DS)];
			pcb->uldt_desc = ldtp[sel_idx(USER_DS)];
#endif /* __i386__ */
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

	simple_lock_init(&pcb->lock, 0);

	pcb->arg_store_valid = 0;
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
	if (pcb->sf != 0) {
		zfree(iss_zone, pcb->sf);
		pcb->sf = 0;
	}
	if (pcb->ids) {
		zfree(ids_zone, pcb->ids);
		pcb->ids = NULL;
	}
}
