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
#include <kern/spl.h>
#include <kern/syscall_sw.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/thread.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/seg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/iopb_entries.h>
#include <i386/machdep_call.h>
#include <i386/misc_protos.h>
#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/mp_desc.h>
#include <i386/vmparam.h>
#include <i386/trap.h>
#include <mach/i386/syscall_sw.h>
#include <sys/syscall.h>
#include <sys/kdebug.h>
#include <sys/ktrace.h>
#include <sys/errno.h>
#include <../bsd/sys/sysent.h>

extern struct proc *current_proc(void);
extern struct proc * kernproc;

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

kern_return_t
thread_compose_cthread_desc(unsigned int addr, pcb_t pcb);

void IOSleep(int);

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
		 int		*customstack
		 )
{
        if (customstack)
	        *customstack = 0;

        switch (flavor) {
	    case OLD_i386_THREAD_STATE:
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

	    default :
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
	    case OLD_i386_THREAD_STATE:
	    case x86_THREAD_STATE32:
	    {
	        x86_thread_state32_t *state25;

		state25 = (x86_thread_state32_t *) tstate;
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
	 * Copy over the i386_saved_state registers
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

extern struct proc * i386_current_proc(void);

extern long fuword(vm_offset_t);


/* following implemented in bsd/dev/i386/unix_signal.c */
int __pthread_cset(struct sysent *);

void __pthread_creset(struct sysent *);


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
		regs->eax = (*entry->routine.args_2)(args[0], args[1]);
		break;
	    case 3:
	        if (!entry->bsd_style)
		        regs->eax = (*entry->routine.args_3)(args[0], args[1], args[2]);
		else {
		        int	error;
			int	rval;

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
    
	trapno = regs->rax & SYSCALL_NUMBER_MASK;

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

	thread_exception_return();
	/* NOTREACHED */
}


kern_return_t
thread_compose_cthread_desc(unsigned int addr, pcb_t pcb)
{
  struct real_descriptor desc;

  mp_disable_preemption();

  desc.limit_low = 1;
  desc.limit_high = 0;
  desc.base_low = addr & 0xffff;
  desc.base_med = (addr >> 16) & 0xff;
  desc.base_high = (addr >> 24) & 0xff;
  desc.access = ACC_P|ACC_PL_U|ACC_DATA_W;
  desc.granularity = SZ_32|SZ_G;
  pcb->cthread_desc = desc;
  *ldt_desc_p(USER_CTHREAD) = desc;

  mp_enable_preemption();

  return(KERN_SUCCESS);
}

kern_return_t
thread_set_cthread_self(uint32_t self)
{
   current_thread()->machine.pcb->cthread_self = (uint64_t) self;
   
   return (KERN_SUCCESS);
}

kern_return_t
thread_get_cthread_self(void)
{
    return ((kern_return_t)current_thread()->machine.pcb->cthread_self);
}

kern_return_t
thread_fast_set_cthread_self(uint32_t self)
{
	pcb_t			pcb;
	x86_saved_state32_t	*iss;

	pcb = (pcb_t)current_thread()->machine.pcb;
	thread_compose_cthread_desc(self, pcb);
	pcb->cthread_self = (uint64_t) self; /* preserve old func too */
	iss = saved_state32(pcb->iss);
	iss->gs = USER_CTHREAD;

	return (USER_CTHREAD);
}

kern_return_t
thread_fast_set_cthread_self64(uint64_t self)
{
	pcb_t			pcb;
	x86_saved_state64_t	*iss;

	pcb = current_thread()->machine.pcb;

	/* check for canonical address, set 0 otherwise  */
	if (!IS_USERADDR64_CANONICAL(self))
		self = 0ULL;
	pcb->cthread_self = self;
	current_cpu_datap()->cpu_uber.cu_user_gs_base = self;

	/* XXX for 64-in-32 */
	iss = saved_state64(pcb->iss);
	iss->gs = USER_CTHREAD;
	thread_compose_cthread_desc((uint32_t) self, pcb);

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


__private_extern__ void
mach_call_munger(x86_saved_state_t *state);


__private_extern__
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
#if DEBUG_TRACE
	kprintf("mach_call_munger(0x%08x) code=%d\n", regs, call_number);
#endif

	if (call_number < 0 || call_number >= mach_trap_count) {
	        i386_exception(EXC_SYSCALL, call_number, 1);
		/* NOTREACHED */
	}
	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;
	
	if (mach_call == (mach_call_t)kern_invalid) {
	        i386_exception(EXC_SYSCALL, call_number, 1);
		/* NOTREACHED */
	}
	argc = mach_trap_table[call_number].mach_trap_arg_count;

	if (argc) {
	        retval = mach_call_arg_munger32(regs->uesp, argc, call_number, &args);
		
		if (retval != KERN_SUCCESS) {
		        regs->eax = retval;
	
			thread_exception_return();
			/* NOTREACHED */
		}
	}
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
			      (int) args.arg1, (int) args.arg2, (int) args.arg3, (int) args.arg4, 0);
	
	retval = mach_call(&args);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,(call_number)) | DBG_FUNC_END,
			      retval, 0, 0, 0, 0);
	regs->eax = retval;
	
	thread_exception_return();
	/* NOTREACHED */
}



__private_extern__ void
mach_call_munger64(x86_saved_state_t *state);


__private_extern__
void
mach_call_munger64(x86_saved_state_t *state)
{
	int call_number;
	int argc;
	mach_call_t mach_call;
	x86_saved_state64_t	*regs;

	assert(is_saved_state64(state));
	regs = saved_state64(state);

	call_number = regs->rax & SYSCALL_NUMBER_MASK;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
			      (int) regs->rdi, (int) regs->rsi, (int) regs->rdx, (int) regs->r10, 0);
	
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

		copyin_count = (argc - 6) * sizeof(uint64_t);

	        if (copyin((user_addr_t)(regs->isf.rsp + sizeof(user_addr_t)), (char *)&regs->v_arg6, copyin_count)) {
		        regs->rax = KERN_INVALID_ARGUMENT;
			
			thread_exception_return();
			/* NOTREACHED */
		}
	}
	regs->rax = (uint64_t)mach_call((void *)(&regs->rdi));
	
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,(call_number)) | DBG_FUNC_END,
			      (int)regs->rax, 0, 0, 0, 0);

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

		iss32->uesp = CAST_DOWN(unsigned int, user_stack);
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

		iss32->eip = CAST_DOWN(unsigned int, entry);
	}
}


void
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

		if (on)
		        iss32->efl |= EFL_TF;
		else
		        iss32->efl &= ~EFL_TF;
	}
}



/* XXX this should be a struct savearea so that CHUD will work better on x86 */
void *
find_user_regs(
	thread_t        thread)
{
	return USER_STATE(thread);
}

