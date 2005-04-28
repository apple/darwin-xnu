/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/syscall.h>
#include <sys/kdebug.h>
#include <sys/ktrace.h>
#include <../bsd/sys/sysent.h>

extern struct proc *current_proc(void);

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
    unsigned int        count,
    user_addr_t    *user_stack,
	int					*customstack
)
{
        struct i386_saved_state *state;
	i386_thread_state_t *state25;
	vm_offset_t	uesp;

        if (customstack)
			*customstack = 0;

        switch (flavor) {
	case i386_THREAD_STATE:	/* FIXME */
                state25 = (i386_thread_state_t *) tstate;
		if (state25->esp)
			*user_stack = state25->esp;
		else 
			*user_stack = USRSTACK;
		if (customstack && state25->esp)
			*customstack = 1;
		else
			*customstack = 0;
		break;

        case i386_NEW_THREAD_STATE:
                if (count < i386_NEW_THREAD_STATE_COUNT)
                        return (KERN_INVALID_ARGUMENT);
		else {
                	state = (struct i386_saved_state *) tstate;
			uesp = state->uesp;
    		}

                /* If a valid user stack is specified, use it. */
		if (uesp)
			*user_stack = uesp;
		else 
			*user_stack = USRSTACK;
		if (customstack && uesp)
			*customstack = 1;
		else
			*customstack = 0;
                break;
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
    unsigned int        count,
    mach_vm_offset_t    *entry_point
)
{ 
    struct i386_saved_state	*state;
    i386_thread_state_t *state25;

    /*
     * Set a default.
     */
    if (*entry_point == 0)
	*entry_point = VM_MIN_ADDRESS;
		
    switch (flavor) {
    case i386_THREAD_STATE:
	state25 = (i386_thread_state_t *) tstate;
	*entry_point = state25->eip ? state25->eip: VM_MIN_ADDRESS;
	break;

    case i386_NEW_THREAD_STATE:
	if (count < i386_THREAD_STATE_COUNT)
	    return (KERN_INVALID_ARGUMENT);
	else {
		state = (struct i386_saved_state *) tstate;

		/*
	 	* If a valid entry point is specified, use it.
	 	*/
		*entry_point = state->eip ? state->eip: VM_MIN_ADDRESS;
	}
	break;
    }

    return (KERN_SUCCESS);
}   

struct i386_saved_state *
get_user_regs(thread_t th)
{
	if (th->machine.pcb)
		return(USER_REGS(th));
	else {
		printf("[get_user_regs: thread does not have pcb]");
		return NULL;
	}
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
	struct i386_float_state		floatregs;

#ifdef	XXX
	/* Save the FPU state */
	if ((pcb_t)(per_proc_info[cpu_number()].fpu_pcb) == parent->machine.pcb) {
		fp_state_save(parent);
	}
#endif

	if (child->machine.pcb == NULL || parent->machine.pcb == NULL)
		return (KERN_FAILURE);

	/* Copy over the i386_saved_state registers */
	child->machine.pcb->iss = parent->machine.pcb->iss;

	/* Check to see if parent is using floating point
	 * and if so, copy the registers to the child
	 * FIXME - make sure this works.
	 */

	if (parent->machine.pcb->ims.ifps)  {
		if (fpu_get_state(parent, &floatregs) == KERN_SUCCESS)
			fpu_set_state(child, &floatregs);
	}
	
	/* FIXME - should a user specified LDT, TSS and V86 info
	 * be duplicated as well?? - probably not.
	 */
        // duplicate any use LDT entry that was set I think this is appropriate.
#ifdef	MACH_BSD
        if (parent->machine.pcb->uldt_selector!= 0) {
            child->machine.pcb->uldt_selector = parent->machine.pcb->uldt_selector;
            child->machine.pcb->uldt_desc = parent->machine.pcb->uldt_desc;
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
	child->machine.pcb->iss.eax = pid;
	child->machine.pcb->iss.edx = 1;
	child->machine.pcb->iss.efl &= ~EFL_CF;
}
void thread_set_parent(thread_t parent, int pid);
void
thread_set_parent(thread_t parent, int pid)
{
	parent->machine.pcb->iss.eax = pid;
	parent->machine.pcb->iss.edx = 0;
	parent->machine.pcb->iss.efl &= ~EFL_CF;
}



/*
 * System Call handling code
 */

#define	ERESTART	-1		/* restart syscall */
#define	EJUSTRETURN	-2		/* don't modify regs, just return */


#define NO_FUNNEL 0
#define KERNEL_FUNNEL 1

extern funnel_t * kernel_flock;

extern int set_bsduthreadargs (thread_t, struct i386_saved_state *, void *);
extern void * get_bsduthreadarg(thread_t);
extern int * get_bsduthreadrval(thread_t th);
extern int * get_bsduthreadlowpridelay(thread_t th);

extern long fuword(vm_offset_t);

extern void unix_syscall(struct i386_saved_state *);
extern void unix_syscall_return(int);

/* following implemented in bsd/dev/i386/unix_signal.c */
int __pthread_cset(struct sysent *);

void __pthread_creset(struct sysent *);


void
unix_syscall_return(int error)
{
    thread_t		thread;
	volatile int *rval;
	struct i386_saved_state *regs;
	struct proc *p;
	unsigned short code;
	vm_offset_t params;
	struct sysent *callp;
	volatile int *lowpri_delay;

    thread = current_thread();
    rval = get_bsduthreadrval(thread);
    lowpri_delay = get_bsduthreadlowpridelay(thread);
	p = current_proc();

	regs = USER_REGS(thread);

	/* reconstruct code for tracing before blasting eax */
	code = regs->eax;
	params = (vm_offset_t) ((caddr_t)regs->uesp + sizeof (int));
	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];
	if (callp == sysent) {
	  code = fuword(params);
	}

	if (error == ERESTART) {
		regs->eip -= 7;
	}
	else if (error != EJUSTRETURN) {
		if (error) {
		    regs->eax = error;
		    regs->efl |= EFL_CF;	/* carry bit */
		} else { /* (not error) */
		    regs->eax = rval[0];
		    regs->edx = rval[1];
		    regs->efl &= ~EFL_CF;
		} 
	}

	ktrsysret(p, code, error, rval[0], (callp->sy_funnel & FUNNEL_MASK));

	__pthread_creset(callp);

	if ((callp->sy_funnel & FUNNEL_MASK) != NO_FUNNEL)
    		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

	if (*lowpri_delay) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this system call
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		IOSleep(*lowpri_delay);
	        *lowpri_delay = 0;
	}
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
		error, rval[0], rval[1], 0, 0);

    thread_exception_return();
    /* NOTREACHED */
}


void
unix_syscall(struct i386_saved_state *regs)
{
    thread_t		thread;
    void	*vt; 
    unsigned short	code;
    struct sysent		*callp;
	int	nargs;
	int	error;
	int *rval;
	int funnel_type;
    vm_offset_t		params;
	struct proc *p;
	volatile int *lowpri_delay;

    thread = current_thread();
    p = current_proc();
    rval = get_bsduthreadrval(thread);
    lowpri_delay = get_bsduthreadlowpridelay(thread);

    thread->task->syscalls_unix++;		/* MP-safety ignored */

    //printf("[scall : eax %x]",  regs->eax);
    code = regs->eax;
    params = (vm_offset_t) ((caddr_t)regs->uesp + sizeof (int));
    callp = (code >= nsysent) ? &sysent[63] : &sysent[code];
    if (callp == sysent) {
	code = fuword(params);
	params += sizeof (int);
	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];
    }
    
    vt = get_bsduthreadarg(thread);

    if ((nargs = (callp->sy_narg * sizeof (int))) &&
	    (error = copyin((user_addr_t) params, (char *) vt, nargs)) != 0) {
	regs->eax = error;
	regs->efl |= EFL_CF;
	thread_exception_return();
	/* NOTREACHED */
    }
    
    rval[0] = 0;
    rval[1] = regs->edx;

	if ((error = __pthread_cset(callp))) {
		/* cancelled system call; let it returned with EINTR for handling */
		regs->eax = error;
		regs->efl |= EFL_CF;
		thread_exception_return();
		/* NOTREACHED */
	}

	funnel_type = (callp->sy_funnel & FUNNEL_MASK);
	if(funnel_type == KERNEL_FUNNEL)
		(void) thread_funnel_set(kernel_flock, TRUE);
	
    (void) set_bsduthreadargs(thread, regs, NULL);

    if (callp->sy_narg > 8)
	panic("unix_syscall max arg count exceeded (%d)", callp->sy_narg);

	ktrsyscall(p, code, callp->sy_narg, vt, funnel_type);

	{ 
	  int *ip = (int *)vt;
	  KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
	      *ip, *(ip+1), *(ip+2), *(ip+3), 0);
	}

    error = (*(callp->sy_call))((void *) p, (void *) vt, &rval[0]);
	
#if 0
	/* May be needed with vfork changes */
	regs = USER_REGS(thread);
#endif
	if (error == ERESTART) {
		regs->eip -= 7;
	}
	else if (error != EJUSTRETURN) {
		if (error) {
		    regs->eax = error;
		    regs->efl |= EFL_CF;	/* carry bit */
		} else { /* (not error) */
		    regs->eax = rval[0];
		    regs->edx = rval[1];
		    regs->efl &= ~EFL_CF;
		} 
	}

	ktrsysret(p, code, error, rval[0], funnel_type);

        __pthread_creset(callp);

	if(funnel_type != NO_FUNNEL)
    		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

	if (*lowpri_delay) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this system call
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		IOSleep(*lowpri_delay);
	        *lowpri_delay = 0;
	}
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
		error, rval[0], rval[1], 0, 0);

    thread_exception_return();
    /* NOTREACHED */
}


void
machdep_syscall( struct i386_saved_state *regs)
{
    int				trapno, nargs;
    machdep_call_t		*entry;
    
    trapno = regs->eax;
    if (trapno < 0 || trapno >= machdep_call_count) {
	regs->eax = (unsigned int)kern_invalid(NULL);

	thread_exception_return();
	/* NOTREACHED */
    }
    
    entry = &machdep_call_table[trapno];
    nargs = entry->nargs;

    if (nargs > 0) {
	int			args[nargs];

	if (copyin((user_addr_t) regs->uesp + sizeof (int),
		    (char *) args,
		    nargs * sizeof (int))) {

	    regs->eax = KERN_INVALID_ADDRESS;

	    thread_exception_return();
	    /* NOTREACHED */
	}

	switch (nargs) {
	    case 1:
		regs->eax = (*entry->routine.args_1)(args[0]);
		break;
	    case 2:
		regs->eax = (*entry->routine.args_2)(args[0],args[1]);
		break;
	    case 3:
		regs->eax = (*entry->routine.args_3)(args[0],args[1],args[2]);
		break;
	    case 4:
		regs->eax = (*entry->routine.args_4)(args[0],args[1],args[2],args[3]);
		break;
	    default:
		panic("machdep_syscall(): too many args");
	}
    }
    else
	regs->eax = (*entry->routine.args_0)();

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
   current_thread()->machine.pcb->cthread_self = self;
   
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
  pcb_t pcb;
  pcb = (pcb_t)current_thread()->machine.pcb;
  thread_compose_cthread_desc(self, pcb);
  pcb->cthread_self = self; /* preserve old func too */
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
void
mach25_syscall(struct i386_saved_state *regs)
{
	printf("*** Atttempt to execute a Mach 2.5 system call at EIP=%x EAX=%x(%d)\n",
			regs->eip, regs->eax, -regs->eax);
	panic("FIXME!");
}
#endif	/* MACH_BSD */


/* This routine is called from assembly before each and every mach trap.
 */

extern unsigned int mach_call_start(unsigned int, unsigned int *);

__private_extern__
unsigned int
mach_call_start(unsigned int call_number, unsigned int *args)
{
	int i, argc;
	unsigned int kdarg[3];

	current_thread()->task->syscalls_mach++;	/* MP-safety ignored */

/* Always prepare to trace mach system calls */

	kdarg[0]=0;
	kdarg[1]=0;
	kdarg[2]=0;

	argc = mach_trap_table[call_number>>4].mach_trap_arg_count;
	
	if (argc > 3)
		argc = 3;
	
	for (i=0; i < argc; i++)
	  kdarg[i] = (int)*(args + i);
	
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number>>4)) | DBG_FUNC_START,
			      kdarg[0], kdarg[1], kdarg[2], 0, 0);

	return call_number; /* pass this back thru */
}

/* This routine is called from assembly after each mach system call
 */

extern unsigned int mach_call_end(unsigned int, unsigned int);

__private_extern__
unsigned int
mach_call_end(unsigned int call_number, unsigned int retval)
{
  KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,(call_number>>4)) | DBG_FUNC_END,
		retval, 0, 0, 0, 0);
	return retval;  /* pass this back thru */
}

typedef kern_return_t (*mach_call_t)(void *);

extern __attribute__((regparm(1))) kern_return_t
mach_call_munger(unsigned int call_number, 
	unsigned int arg1,
	unsigned int arg2,
	unsigned int arg3,
	unsigned int arg4,
	unsigned int arg5,
	unsigned int arg6,
	unsigned int arg7,
	unsigned int arg8,
	unsigned int arg9
);

struct mach_call_args {
	unsigned int arg1;
	unsigned int arg2;
	unsigned int arg3;
	unsigned int arg4;
	unsigned int arg5;
	unsigned int arg6;
	unsigned int arg7;
	unsigned int arg8;
	unsigned int arg9;
};
__private_extern__
__attribute__((regparm(1))) kern_return_t
mach_call_munger(unsigned int call_number, 
	unsigned int arg1,
	unsigned int arg2,
	unsigned int arg3,
	unsigned int arg4,
	unsigned int arg5,
	unsigned int arg6,
	unsigned int arg7,
	unsigned int arg8,
	unsigned int arg9
)
{
	int argc;
	mach_call_t mach_call;
	kern_return_t retval;
	struct mach_call_args args = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
 
	current_thread()->task->syscalls_mach++;	/* MP-safety ignored */
	call_number >>= 4;
	
	argc = mach_trap_table[call_number].mach_trap_arg_count;
	switch (argc) {
		case 9: args.arg9 = arg9;
		case 8: args.arg8 = arg8;
		case 7: args.arg7 = arg7;
		case 6: args.arg6 = arg6;
		case 5: args.arg5 = arg5;
		case 4: args.arg4 = arg4;
		case 3: args.arg3 = arg3;
		case 2: args.arg2 = arg2;
		case 1: args.arg1 = arg1;
	}
	
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
			      args.arg1, args.arg2, args.arg3, 0, 0);
	
	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;
	retval = mach_call(&args);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_SC,(call_number)) | DBG_FUNC_END,
		retval, 0, 0, 0, 0);

	return retval;
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
	struct i386_saved_state *ss = get_user_regs(thread);

	ss->uesp = CAST_DOWN(unsigned int,user_stack);
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
	struct i386_saved_state *ss = get_user_regs(thread);

	ss->uesp += adjust;
	return CAST_USER_ADDR_T(ss->uesp);
}

/*
 * thread_setentrypoint:
 *
 * Sets the user PC into the machine
 * dependent thread state info.
 */
void
thread_setentrypoint(
	thread_t	thread,
	mach_vm_address_t	entry)
{
	struct i386_saved_state *ss = get_user_regs(thread);

 	ss->eip = CAST_DOWN(unsigned int,entry);
}    

