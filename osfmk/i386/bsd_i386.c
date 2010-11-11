/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#ifdef	MACH_BSD
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

#ifdef MACH_BSD
extern void	mach_kauth_cred_uthread_update(void);
#endif

kern_return_t
thread_userstack(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    mach_vm_offset_t *,
	int *
);

kern_return_t
thread_entrypoint(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    mach_vm_offset_t *
); 

void * find_user_regs(thread_t);

unsigned int get_msr_exportmask(void);

unsigned int get_msr_nbits(void);

unsigned int get_msr_rbits(void);

extern void throttle_lowpri_io(boolean_t);


/*
 * thread_userstack:
 *
 * Return the user stack pointer from the machine
 * dependent thread state info.
 */
kern_return_t
thread_userstack(
    __unused thread_t   thread,
    int                 flavor,
    thread_state_t      tstate,
    __unused unsigned int        count,
    user_addr_t    *user_stack,
	int					*customstack
)
{
	if (customstack)
		*customstack = 0;

	switch (flavor) {
	case x86_THREAD_STATE32:
		{
			x86_thread_state32_t *state25;

			state25 = (x86_thread_state32_t *) tstate;

			if (state25->esp)
				*user_stack = state25->esp;
			else 
				*user_stack = VM_USRSTACK32;
			if (customstack && state25->esp)
				*customstack = 1;
			else
				*customstack = 0;
			break;
		}

	case x86_THREAD_STATE64:
		{
			x86_thread_state64_t *state25;

			state25 = (x86_thread_state64_t *) tstate;

			if (state25->rsp)
				*user_stack = state25->rsp;
			else 
				*user_stack = VM_USRSTACK64;
			if (customstack && state25->rsp)
				*customstack = 1;
			else
				*customstack = 0;
			break;
		}

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	return (KERN_SUCCESS);
}


kern_return_t
thread_entrypoint(
    __unused thread_t   thread,
    int                 flavor,
    thread_state_t      tstate,
    __unused unsigned int        count,
    mach_vm_offset_t    *entry_point
)
{ 
	/*
	 * Set a default.
	 */
	if (*entry_point == 0)
		*entry_point = VM_MIN_ADDRESS;

	switch (flavor) {
	case x86_THREAD_STATE32:
		{
			x86_thread_state32_t *state25;

			state25 = (i386_thread_state_t *) tstate;
			*entry_point = state25->eip ? state25->eip: VM_MIN_ADDRESS;
			break;
		}

	case x86_THREAD_STATE64:
		{
			x86_thread_state64_t *state25;

			state25 = (x86_thread_state64_t *) tstate;
			*entry_point = state25->rip ? state25->rip: VM_MIN_ADDRESS64;
			break;
		}
	}
	return (KERN_SUCCESS);
}

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
	
	pcb_t		parent_pcb;
	pcb_t		child_pcb;

	if ((child_pcb = child->machine.pcb) == NULL ||
	    (parent_pcb = parent->machine.pcb) == NULL)
		return (KERN_FAILURE);
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

/* 
 * FIXME - thread_set_child
 */

void thread_set_child(thread_t child, int pid);
void
thread_set_child(thread_t child, int pid)
{

	if (thread_is_64bit(child)) {
		x86_saved_state64_t	*iss64;

		iss64 = USER_REGS64(child);

		iss64->rax = pid;
		iss64->rdx = 1;
		iss64->isf.rflags &= ~EFL_CF;
	} else {
		x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(child);

		iss32->eax = pid;
		iss32->edx = 1;
		iss32->efl &= ~EFL_CF;
	}
}


void thread_set_parent(thread_t parent, int pid);

void
thread_set_parent(thread_t parent, int pid)
{

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
 * System Call handling code
 */

extern long fuword(vm_offset_t);



void
machdep_syscall(x86_saved_state_t *state)
{
	int			args[machdep_call_count];
	int			trapno;
	int			nargs;
	machdep_call_t		*entry;
	x86_saved_state32_t	*regs;

	assert(is_saved_state32(state));
	regs = saved_state32(state);
    
	trapno = regs->eax;
#if DEBUG_TRACE
	kprintf("machdep_syscall(0x%08x) code=%d\n", regs, trapno);
#endif

	DEBUG_KPRINT_SYSCALL_MDEP(
		"machdep_syscall: trapno=%d\n", trapno);

	if (trapno < 0 || trapno >= machdep_call_count) {
		regs->eax = (unsigned int)kern_invalid(NULL);

		thread_exception_return();
		/* NOTREACHED */
	}
	entry = &machdep_call_table[trapno];
	nargs = entry->nargs;

	if (nargs != 0) {
		if (copyin((user_addr_t) regs->uesp + sizeof (int),
				(char *) args, (nargs * sizeof (int)))) {
			regs->eax = KERN_INVALID_ADDRESS;

			thread_exception_return();
			/* NOTREACHED */
		}
	}
	switch (nargs) {
	case 0:
		regs->eax = (*entry->routine.args_0)();
		break;
	case 1:
		regs->eax = (*entry->routine.args_1)(args[0]);
		break;
	case 2:
		regs->eax = (*entry->routine.args_2)(args[0],args[1]);
		break;
	case 3:
		if (!entry->bsd_style)
			regs->eax = (*entry->routine.args_3)(args[0],args[1],args[2]);
		else {
			int	error;
			uint32_t	rval;

			error = (*entry->routine.args_bsd_3)(&rval, args[0], args[1], args[2]);
			if (error) {
				regs->eax = error;
				regs->efl |= EFL_CF;	/* carry bit */
			} else {
				regs->eax = rval;
				regs->efl &= ~EFL_CF;
			}
		}
		break;
	case 4:
		regs->eax = (*entry->routine.args_4)(args[0], args[1], args[2], args[3]);
		break;

	default:
		panic("machdep_syscall: too many args");
	}
	if (current_thread()->funnel_lock)
		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

	DEBUG_KPRINT_SYSCALL_MDEP("machdep_syscall: retval=%u\n", regs->eax);

	throttle_lowpri_io(TRUE);

	thread_exception_return();
	/* NOTREACHED */
}


void
machdep_syscall64(x86_saved_state_t *state)
{
	int			trapno;
	machdep_call_t		*entry;
	x86_saved_state64_t	*regs;

	assert(is_saved_state64(state));
	regs = saved_state64(state);
    
	trapno = (int)(regs->rax & SYSCALL_NUMBER_MASK);

	DEBUG_KPRINT_SYSCALL_MDEP(
		"machdep_syscall64: trapno=%d\n", trapno);

	if (trapno < 0 || trapno >= machdep_call_count) {
		regs->rax = (unsigned int)kern_invalid(NULL);

		thread_exception_return();
		/* NOTREACHED */
	}
	entry = &machdep_call_table64[trapno];

	switch (entry->nargs) {
	case 0:
		regs->rax = (*entry->routine.args_0)();
		break;
	case 1:
		regs->rax = (*entry->routine.args64_1)(regs->rdi);
		break;
	default:
		panic("machdep_syscall64: too many args");
	}
	if (current_thread()->funnel_lock)
		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

	DEBUG_KPRINT_SYSCALL_MDEP("machdep_syscall: retval=%llu\n", regs->rax);

	throttle_lowpri_io(TRUE);

	thread_exception_return();
	/* NOTREACHED */
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
	pcb_t pcb = thread->machine.pcb;
	struct real_descriptor desc = {
		.limit_low = 1,
		.limit_high = 0,
		.base_low = self & 0xffff,
		.base_med = (self >> 16) & 0xff,
		.base_high = (self >> 24) & 0xff,
		.access = ACC_P|ACC_PL_U|ACC_DATA_W,
		.granularity = SZ_32|SZ_G,
	};

	current_thread()->machine.pcb->cthread_self = (uint64_t) self;	/* preserve old func too */

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
	pcb_t pcb = current_thread()->machine.pcb;
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
	return (USER_CTHREAD);
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
	int mycpu;

	if (flags != 0)
		return -1;		// flags not supported
	if (size > 0xFFFFF)
		return -1;		// size too big, 1 meg is the limit

	mp_disable_preemption();
	mycpu = cpu_number();

	// create a "fake" descriptor so we can use fix_desc()
	// to build a real one...
	//   32 bit default operation size
	//   standard read/write perms for a data segment
	pcb = (pcb_t)current_thread()->machine.pcb;
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

#endif	/* MACH_BSD */


typedef kern_return_t (*mach_call_t)(void *);

struct mach_call_args {
	syscall_arg_t arg1;
	syscall_arg_t arg2;
	syscall_arg_t arg3;
	syscall_arg_t arg4;
	syscall_arg_t arg5;
	syscall_arg_t arg6;
	syscall_arg_t arg7;
	syscall_arg_t arg8;
	syscall_arg_t arg9;
};

static kern_return_t
mach_call_arg_munger32(uint32_t sp, int nargs, int call_number, struct mach_call_args *args);


static kern_return_t
mach_call_arg_munger32(uint32_t sp, int nargs, int call_number, struct mach_call_args *args)
{
	unsigned int args32[9];

	if (copyin((user_addr_t)(sp + sizeof(int)), (char *)args32, nargs * sizeof (int)))
		return KERN_INVALID_ARGUMENT;

	switch (nargs) {
	case 9: args->arg9 = args32[8];
	case 8: args->arg8 = args32[7];
	case 7: args->arg7 = args32[6];
	case 6: args->arg6 = args32[5];
	case 5: args->arg5 = args32[4];
	case 4: args->arg4 = args32[3];
	case 3: args->arg3 = args32[2];
	case 2: args->arg2 = args32[1];
	case 1: args->arg1 = args32[0];
	}
	if (call_number == 90) {
		/* munge_l for mach_wait_until_trap() */
		args->arg1 = (((uint64_t)(args32[0])) | ((((uint64_t)(args32[1]))<<32)));
	}
	if (call_number == 93) {
		/* munge_wl for mk_timer_arm_trap() */
		args->arg2 = (((uint64_t)(args32[1])) | ((((uint64_t)(args32[2]))<<32)));
	}

	return KERN_SUCCESS;
}


__private_extern__ void mach_call_munger(x86_saved_state_t *state);

extern const char *mach_syscall_name_table[];

void
mach_call_munger(x86_saved_state_t *state)
{
	int argc;
	int call_number;
	mach_call_t mach_call;
	kern_return_t retval;
	struct mach_call_args args = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	x86_saved_state32_t	*regs;

	assert(is_saved_state32(state));
	regs = saved_state32(state);

	call_number = -(regs->eax);

	DEBUG_KPRINT_SYSCALL_MACH(
		"mach_call_munger: code=%d(%s)\n",
		call_number, mach_syscall_name_table[call_number]);
#if DEBUG_TRACE
	kprintf("mach_call_munger(0x%08x) code=%d\n", regs, call_number);
#endif

	if (call_number < 0 || call_number >= mach_trap_count) {
		i386_exception(EXC_SYSCALL, call_number, 1);
		/* NOTREACHED */
	}
	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;

	if (mach_call == (mach_call_t)kern_invalid) {
		DEBUG_KPRINT_SYSCALL_MACH(
			"mach_call_munger: kern_invalid 0x%x\n", regs->eax);
		i386_exception(EXC_SYSCALL, call_number, 1);
		/* NOTREACHED */
	}

	argc = mach_trap_table[call_number].mach_trap_arg_count;
	if (argc) {
		retval = mach_call_arg_munger32(regs->uesp, argc, call_number, &args);
		if (retval != KERN_SUCCESS) {
			regs->eax = retval;

			DEBUG_KPRINT_SYSCALL_MACH(
				"mach_call_munger: retval=0x%x\n", retval);

			thread_exception_return();
			/* NOTREACHED */
		}
	}

#ifdef MACH_BSD
	mach_kauth_cred_uthread_update();
#endif
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
			args.arg1, args.arg2, args.arg3, args.arg4, 0);

	retval = mach_call(&args);

	DEBUG_KPRINT_SYSCALL_MACH("mach_call_munger: retval=0x%x\n", retval);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,(call_number)) | DBG_FUNC_END,
			retval, 0, 0, 0, 0);
	regs->eax = retval;

	throttle_lowpri_io(TRUE);

	thread_exception_return();
	/* NOTREACHED */
}


__private_extern__ void mach_call_munger64(x86_saved_state_t *regs);

void
mach_call_munger64(x86_saved_state_t *state)
{
	int call_number;
	int argc;
	mach_call_t mach_call;
	x86_saved_state64_t	*regs;

	assert(is_saved_state64(state));
	regs = saved_state64(state);

	call_number = (int)(regs->rax & SYSCALL_NUMBER_MASK);

	DEBUG_KPRINT_SYSCALL_MACH(
		"mach_call_munger64: code=%d(%s)\n",
		call_number, mach_syscall_name_table[call_number]);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,
					   (call_number)) | DBG_FUNC_START,
			      regs->rdi, regs->rsi,
			      regs->rdx, regs->r10, 0);
	
	if (call_number < 0 || call_number >= mach_trap_count) {
	        i386_exception(EXC_SYSCALL, regs->rax, 1);
		/* NOTREACHED */
	}
	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;

	if (mach_call == (mach_call_t)kern_invalid) {
	        i386_exception(EXC_SYSCALL, regs->rax, 1);
		/* NOTREACHED */
	}
	argc = mach_trap_table[call_number].mach_trap_arg_count;

	if (argc > 6) {
	        int copyin_count;

		copyin_count = (argc - 6) * (int)sizeof(uint64_t);

	        if (copyin((user_addr_t)(regs->isf.rsp + sizeof(user_addr_t)), (char *)&regs->v_arg6, copyin_count)) {
		        regs->rax = KERN_INVALID_ARGUMENT;
			
			thread_exception_return();
			/* NOTREACHED */
		}
	}

#ifdef MACH_BSD
	mach_kauth_cred_uthread_update();
#endif

	regs->rax = (uint64_t)mach_call((void *)(&regs->rdi));
	
	DEBUG_KPRINT_SYSCALL_MACH( "mach_call_munger64: retval=0x%llx\n", regs->rax);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,
					   (call_number)) | DBG_FUNC_END,
			      regs->rax, 0, 0, 0, 0);

	throttle_lowpri_io(TRUE);

	thread_exception_return();
	/* NOTREACHED */
}


/*
 * thread_setuserstack:
 *
 * Sets the user stack pointer into the machine
 * dependent thread state info.
 */
void
thread_setuserstack(
	thread_t	thread,
	mach_vm_address_t	user_stack)
{
	if (thread_is_64bit(thread)) {
		x86_saved_state64_t	*iss64;

		iss64 = USER_REGS64(thread);

		iss64->isf.rsp = (uint64_t)user_stack;
	} else {
		x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(thread);

		iss32->uesp = CAST_DOWN_EXPLICIT(unsigned int, user_stack);
	}
}

/*
 * thread_adjuserstack:
 *
 * Returns the adjusted user stack pointer from the machine
 * dependent thread state info.  Used for small (<2G) deltas.
 */
uint64_t
thread_adjuserstack(
	thread_t	thread,
	int		adjust)
{
	if (thread_is_64bit(thread)) {
		x86_saved_state64_t	*iss64;

		iss64 = USER_REGS64(thread);

		iss64->isf.rsp += adjust;

		return iss64->isf.rsp;
	} else {
		x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(thread);

		iss32->uesp += adjust;

		return CAST_USER_ADDR_T(iss32->uesp);
	}
}

/*
 * thread_setentrypoint:
 *
 * Sets the user PC into the machine
 * dependent thread state info.
 */
void
thread_setentrypoint(thread_t thread, mach_vm_address_t entry)
{
	if (thread_is_64bit(thread)) {
		x86_saved_state64_t	*iss64;

		iss64 = USER_REGS64(thread);

		iss64->isf.rip = (uint64_t)entry;
	} else {
		x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(thread);

		iss32->eip = CAST_DOWN_EXPLICIT(unsigned int, entry);
	}
}


kern_return_t
thread_setsinglestep(thread_t thread, int on)
{
	if (thread_is_64bit(thread)) {
		x86_saved_state64_t	*iss64;

		iss64 = USER_REGS64(thread);

		if (on)
			iss64->isf.rflags |= EFL_TF;
		else
			iss64->isf.rflags &= ~EFL_TF;
	} else {
		x86_saved_state32_t	*iss32;

		iss32 = USER_REGS32(thread);

		if (on) {
			iss32->efl |= EFL_TF;
			/* Ensure IRET */
			if (iss32->cs == SYSENTER_CS)
				iss32->cs = SYSENTER_TF_CS;
		}
		else
			iss32->efl &= ~EFL_TF;
	}
	
	return (KERN_SUCCESS);
}



/* XXX this should be a struct savearea so that CHUD will work better on x86 */
void *
find_user_regs(thread_t thread)
{
	return USER_STATE(thread);
}

void *
get_user_regs(thread_t th)
{
	if (th->machine.pcb)
		return(USER_STATE(th));
	else {
		printf("[get_user_regs: thread does not have pcb]");
		return NULL;
	}
}

#if CONFIG_DTRACE
/*
 * DTrace would like to have a peek at the kernel interrupt state, if available.
 * Based on osfmk/chud/i386/chud_thread_i386.c:chudxnu_thread_get_state(), which see.
 */
x86_saved_state_t *find_kern_regs(thread_t);

x86_saved_state_t *
find_kern_regs(thread_t thread)
{
	if (thread == current_thread() && 
		NULL != current_cpu_datap()->cpu_int_state &&
		!(USER_STATE(thread) == current_cpu_datap()->cpu_int_state &&
		  current_cpu_datap()->cpu_interrupt_level == 1)) {

		return current_cpu_datap()->cpu_int_state;
	} else {
		return NULL;
	}
}

vm_offset_t dtrace_get_cpu_int_stack_top(void);

vm_offset_t
dtrace_get_cpu_int_stack_top(void)
{
	return current_cpu_datap()->cpu_int_stack_top;
}
#endif
