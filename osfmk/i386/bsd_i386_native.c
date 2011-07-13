/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
#include <mach_rt.h>
#include <mach_debug.h>
#include <mach_ldebug.h>

#include <mach/kern_return.h>
#include <mach/mach_traps.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/cpu_data.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/spl.h>
#include <kern/syscall_sw.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <i386/cpu_number.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/machdep_call.h>
#include <i386/vmparam.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/trap.h>
#include <i386/seg.h>
#include <mach/i386/syscall_sw.h>
#include <sys/syscall.h>
#include <sys/kdebug.h>
#include <sys/errno.h>
#include <../bsd/sys/sysent.h>


/*
 * Duplicate parent state in child
 * for U**X fork.
 */
kern_return_t
machine_thread_dup(
    thread_t		parent,
    thread_t		child
)
{
	
	pcb_t		parent_pcb = THREAD_TO_PCB(parent);
	pcb_t		child_pcb = THREAD_TO_PCB(child);

	/*
	 * Copy over the x86_saved_state registers
	 */
	if (cpu_mode_is64bit()) {
		if (thread_is_64bit(parent))
			bcopy(USER_REGS64(parent), USER_REGS64(child), sizeof(x86_saved_state64_t));
		else
			bcopy(USER_REGS32(parent), USER_REGS32(child), sizeof(x86_saved_state_compat32_t));
	} else
		bcopy(USER_REGS32(parent), USER_REGS32(child), sizeof(x86_saved_state32_t));

	/*
	 * Check to see if parent is using floating point
	 * and if so, copy the registers to the child
	 */
	fpu_dup_fxstate(parent, child);

#ifdef	MACH_BSD
	/*
	 * Copy the parent's cthread id and USER_CTHREAD descriptor, if 32-bit.
	 */
	child_pcb->cthread_self = parent_pcb->cthread_self;
	if (!thread_is_64bit(parent))
		child_pcb->cthread_desc = parent_pcb->cthread_desc;

	/*
	 * FIXME - should a user specified LDT, TSS and V86 info
	 * be duplicated as well?? - probably not.
	 */
	// duplicate any use LDT entry that was set I think this is appropriate.
        if (parent_pcb->uldt_selector!= 0) {
	        child_pcb->uldt_selector = parent_pcb->uldt_selector;
		child_pcb->uldt_desc = parent_pcb->uldt_desc;
	}
#endif

	return (KERN_SUCCESS);
}

void thread_set_parent(thread_t parent, int pid);

void
thread_set_parent(thread_t parent, int pid)
{
	pal_register_cache_state(parent, DIRTY);

	if (thread_is_64bit(parent)) {
		x86_saved_state64_t	*iss64;

		iss64 = USER_REGS64(parent);

		iss64->rax = pid;
		iss64->rdx = 0;
		iss64->isf.rflags &= ~EFL_CF;
	} else {
		x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(parent);

		iss32->eax = pid;
		iss32->edx = 0;
		iss32->efl &= ~EFL_CF;
	}
}

/*
 * thread_fast_set_cthread_self: Sets the machine kernel thread ID of the
 * current thread to the given thread ID; fast version for 32-bit processes
 *
 * Parameters:    self                    Thread ID to set
 *                
 * Returns:        0                      Success
 *                !0                      Not success
 */
kern_return_t
thread_fast_set_cthread_self(uint32_t self)
{
	thread_t thread = current_thread();
	pcb_t pcb = THREAD_TO_PCB(thread);
	struct real_descriptor desc = {
		.limit_low = 1,
		.limit_high = 0,
		.base_low = self & 0xffff,
		.base_med = (self >> 16) & 0xff,
		.base_high = (self >> 24) & 0xff,
		.access = ACC_P|ACC_PL_U|ACC_DATA_W,
		.granularity = SZ_32|SZ_G,
	};

	current_thread()->machine.cthread_self = (uint64_t) self;	/* preserve old func too */

	/* assign descriptor */
	mp_disable_preemption();
	pcb->cthread_desc = desc;
	*ldt_desc_p(USER_CTHREAD) = desc;
	saved_state32(pcb->iss)->gs = USER_CTHREAD;
	mp_enable_preemption();

	return (USER_CTHREAD);
}

/*
 * thread_fast_set_cthread_self64: Sets the machine kernel thread ID of the
 * current thread to the given thread ID; fast version for 64-bit processes 
 *
 * Parameters:    self                    Thread ID
 *                
 * Returns:        0                      Success
 *                !0                      Not success
 */
kern_return_t
thread_fast_set_cthread_self64(uint64_t self)
{
	pcb_t pcb = THREAD_TO_PCB(current_thread());
	cpu_data_t              *cdp;

	/* check for canonical address, set 0 otherwise  */
	if (!IS_USERADDR64_CANONICAL(self))
		self = 0ULL;

	pcb->cthread_self = self;
	mp_disable_preemption();
	cdp = current_cpu_datap();
#if defined(__x86_64__)
	if ((cdp->cpu_uber.cu_user_gs_base != pcb->cthread_self) ||
	    (pcb->cthread_self != rdmsr64(MSR_IA32_KERNEL_GS_BASE)))
		wrmsr64(MSR_IA32_KERNEL_GS_BASE, self);
#endif
	cdp->cpu_uber.cu_user_gs_base = self;
	mp_enable_preemption();
	return (USER_CTHREAD); /* N.B.: not a kern_return_t! */
}

/*
 * thread_set_user_ldt routine is the interface for the user level
 * settable ldt entry feature.  allowing a user to create arbitrary
 * ldt entries seems to be too large of a security hole, so instead
 * this mechanism is in place to allow user level processes to have
 * an ldt entry that can be used in conjunction with the FS register.
 *
 * Swapping occurs inside the pcb.c file along with initialization
 * when a thread is created. The basic functioning theory is that the
 * pcb->uldt_selector variable will contain either 0 meaning the
 * process has not set up any entry, or the selector to be used in
 * the FS register. pcb->uldt_desc contains the actual descriptor the
 * user has set up stored in machine usable ldt format.
 *
 * Currently one entry is shared by all threads (USER_SETTABLE), but
 * this could be changed in the future by changing how this routine
 * allocates the selector. There seems to be no real reason at this
 * time to have this added feature, but in the future it might be
 * needed.
 *
 * address is the linear address of the start of the data area size
 * is the size in bytes of the area flags should always be set to 0
 * for now. in the future it could be used to set R/W permisions or
 * other functions. Currently the segment is created as a data segment
 * up to 1 megabyte in size with full read/write permisions only.
 *
 * this call returns the segment selector or -1 if any error occurs
 */
kern_return_t
thread_set_user_ldt(uint32_t address, uint32_t size, uint32_t flags)
{
	pcb_t pcb;
	struct fake_descriptor temp;

	if (flags != 0)
		return -1;		// flags not supported
	if (size > 0xFFFFF)
		return -1;		// size too big, 1 meg is the limit

	mp_disable_preemption();

	// create a "fake" descriptor so we can use fix_desc()
	// to build a real one...
	//   32 bit default operation size
	//   standard read/write perms for a data segment
	pcb = THREAD_TO_PCB(current_thread());
	temp.offset = address;
	temp.lim_or_seg = size;
	temp.size_or_wdct = SZ_32;
	temp.access = ACC_P|ACC_PL_U|ACC_DATA_W;

	// turn this into a real descriptor
	fix_desc(&temp,1);

	// set up our data in the pcb
	pcb->uldt_desc = *(struct real_descriptor*)&temp;
	pcb->uldt_selector = USER_SETTABLE;		// set the selector value

	// now set it up in the current table...
	*ldt_desc_p(USER_SETTABLE) = *(struct real_descriptor*)&temp;

	mp_enable_preemption();

	return USER_SETTABLE;
}
