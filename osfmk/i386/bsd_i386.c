/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
#ifdef	MACH_BSD
#include <cpus.h>
#include <mach_rt.h>
#include <mach_debug.h>
#include <mach_ldebug.h>

#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/cpu_data.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
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
#include <i386/machdep_call.h>

#include <sys/syscall.h>
#include <sys/ktrace.h>
struct proc;

kern_return_t
thread_userstack(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    vm_offset_t *,
	int *
);

kern_return_t
thread_entrypoint(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    vm_offset_t *
); 

struct i386_saved_state *
get_user_regs(
        thread_act_t);

void
act_thread_dup(
    thread_act_t,
    thread_act_t
);

unsigned int get_msr_exportmask(void);

unsigned int get_msr_nbits(void);

unsigned int get_msr_rbits(void);

/*
 * thread_userstack:
 *
 * Return the user stack pointer from the machine
 * dependent thread state info.
 */
kern_return_t
thread_userstack(
    thread_t            thread,
    int                 flavor,
    thread_state_t      tstate,
    unsigned int        count,
    vm_offset_t         *user_stack,
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
    thread_t            thread,
    int                 flavor,
    thread_state_t      tstate,
    unsigned int        count,
    vm_offset_t         *entry_point
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
get_user_regs(thread_act_t th)
{
	if (th->mact.pcb)
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
void
act_thread_dup(
    thread_act_t		parent,
    thread_act_t		child
)
{
	struct i386_saved_state	*parent_state, *child_state;
	struct i386_machine_state	*ims;
	struct i386_float_state		floatregs;

#ifdef	XXX
	/* Save the FPU state */
	if ((pcb_t)(per_proc_info[cpu_number()].fpu_pcb) == parent->mact.pcb) {
		fp_state_save(parent);
	}
#endif

	if (child->mact.pcb == NULL 
	|| parent->mact.pcb == NULL)  {
		panic("[thread_dup, child (%x) or parent (%x) is NULL!]",
			child->mact.pcb, parent->mact.pcb);
		return;
	}

	/* Copy over the i386_saved_state registers */
	child->mact.pcb->iss = parent->mact.pcb->iss;

	/* Check to see if parent is using floating point
	 * and if so, copy the registers to the child
	 * FIXME - make sure this works.
	 */

	if (parent->mact.pcb->ims.ifps)  {
		if (fpu_get_state(parent, &floatregs) == KERN_SUCCESS)
			fpu_set_state(child, &floatregs);
	}
	
	/* FIXME - should a user specified LDT, TSS and V86 info
	 * be duplicated as well?? - probably not.
	 */
}

/* 
 * FIXME - thread_set_child
 */

void thread_set_child(thread_act_t child, int pid);
void
thread_set_child(thread_act_t child, int pid)
{
	child->mact.pcb->iss.eax = pid;
	child->mact.pcb->iss.edx = 1;
	child->mact.pcb->iss.efl &= ~EFL_CF;
}
void thread_set_parent(thread_act_t parent, int pid);
void
thread_set_parent(thread_act_t parent, int pid)
{
	parent->mact.pcb->iss.eax = pid;
	parent->mact.pcb->iss.edx = 0;
	parent->mact.pcb->iss.efl &= ~EFL_CF;
}



/*
 * Move pages from one kernel virtual address to another.
 * Both addresses are assumed to reside in the Sysmap,
 * and size must be a multiple of the page size.
 */
void
pagemove(
	register caddr_t from,
	register caddr_t to,
	int size)
{
	pmap_movepage((unsigned long)from, (unsigned long)to, (vm_size_t)size);
}

/*
 * System Call handling code
 */

#define	ERESTART	-1		/* restart syscall */
#define	EJUSTRETURN	-2		/* don't modify regs, just return */

struct sysent {		/* system call table */
	unsigned short		sy_narg;		/* number of args */
	char			sy_parallel;	/* can execute in parallel */
        char			sy_funnel;	/* funnel type */
	unsigned long		(*sy_call)(void *, void *, int *);	/* implementing function */
};

#define NO_FUNNEL 0
#define KERNEL_FUNNEL 1
#define NETWORK_FUNNEL 2

extern funnel_t * kernel_flock;
extern funnel_t * network_flock;

extern struct sysent sysent[];

int set_bsduthreadargs (thread_act_t, struct i386_saved_state *, void *);

void * get_bsduthreadarg(thread_act_t);

void unix_syscall(struct i386_saved_state *);

void
unix_syscall_return(int error)
{
    thread_act_t		thread;
	volatile int *rval;
	struct i386_saved_state *regs;
	struct proc *p;
	struct proc *current_proc();
	unsigned short code;
	vm_offset_t params;
	struct sysent *callp;
	extern int nsysent;

    thread = current_act();
    rval = (int *)get_bsduthreadrval(thread);
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

	ktrsysret(p, code, error, rval[0], callp->sy_funnel);

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
		error, rval[0], rval[1], 0, 0);

	if (callp->sy_funnel != NO_FUNNEL) {
    		assert(thread_funnel_get() == THR_FUNNEL_NULL);
    		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);
	}

    thread_exception_return();
    /* NOTREACHED */
}


void
unix_syscall(struct i386_saved_state *regs)
{
    thread_act_t		thread;
    void	*vt; 
    unsigned short	code;
    struct sysent		*callp;
	int	nargs, error;
	volatile int *rval;
	int funnel_type;
    vm_offset_t		params;
    extern int nsysent;
	struct proc *p;
	struct proc *current_proc();

    thread = current_act();
    p = current_proc();
    rval = (int *)get_bsduthreadrval(thread);

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
	    (error = copyin((char *) params, (char *)vt , nargs)) != 0) {
	regs->eax = error;
	regs->efl |= EFL_CF;
	thread_exception_return();
	/* NOTREACHED */
    }
    
    rval[0] = 0;
    rval[1] = regs->edx;

	funnel_type = callp->sy_funnel;
	if(funnel_type == KERNEL_FUNNEL)
		(void) thread_funnel_set(kernel_flock, TRUE);
	else if (funnel_type == NETWORK_FUNNEL)
		(void) thread_funnel_set(network_flock, TRUE);
	
   set_bsduthreadargs(thread, regs, NULL);

    if (callp->sy_narg > 8)
	panic("unix_syscall max arg count exceeded (%d)", callp->sy_narg);

	ktrsyscall(p, code, callp->sy_narg, vt, funnel_type);

	{ 
	  int *ip = (int *)vt;
	  KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
	      *ip, *(ip+1), *(ip+2), *(ip+3), 0);
	}

    error = (*(callp->sy_call))(p, (void *) vt, rval);
	
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

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
		error, rval[0], rval[1], 0, 0);

	if(funnel_type != NO_FUNNEL)
    		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

    thread_exception_return();
    /* NOTREACHED */
}


void
machdep_syscall( struct i386_saved_state *regs)
{
    int				trapno, nargs;
    machdep_call_t		*entry;
    thread_t			thread;
	struct proc *p;
	struct proc *current_proc();
    
    trapno = regs->eax;
    if (trapno < 0 || trapno >= machdep_call_count) {
	regs->eax = (unsigned int)kern_invalid();

	thread_exception_return();
	/* NOTREACHED */
    }
    
    entry = &machdep_call_table[trapno];
    nargs = entry->nargs;

    if (nargs > 0) {
	int			args[nargs];

	if (copyin((char *) regs->uesp + sizeof (int),
		    (char *) args,
		    nargs * sizeof (int))) {

	    regs->eax = KERN_INVALID_ADDRESS;

	    thread_exception_return();
	    /* NOTREACHED */
	}

	asm volatile("
	    1:
	    mov (%2),%%eax;
	    pushl %%eax;
	    sub $4,%2;
	    dec %1;
	    jne 1b;
	    mov %3,%%eax;
	    call *%%eax;
	    mov %%eax,%0"
	    
	    : "=r" (regs->eax)
	    : "r" (nargs),
		"r" (&args[nargs - 1]),
		"g" (entry->routine)
	    : "ax", "cx", "dx", "sp");
    }
    else
	regs->eax = (unsigned int)(*entry->routine)();

	if (current_thread()->funnel_lock)
    		(void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

    thread_exception_return();
    /* NOTREACHED */
}


kern_return_t
thread_set_cthread_self(int self)
{
   current_act()->mact.pcb->cthread_self = (unsigned int)self;
   
   return (KERN_SUCCESS);
}

kern_return_t
thread_get_cthread_self(void)
{
    return ((kern_return_t)current_act()->mact.pcb->cthread_self);
}

void
mach25_syscall(struct i386_saved_state *regs)
{
	printf("*** Atttempt to execute a Mach 2.5 system call at EIP=%x EAX=%x(%d)\n",
			regs->eip, regs->eax, -regs->eax);
	panic("FIXME!");
}

#endif	/* MACH_BSD */

#undef current_thread
thread_t
current_thread(void)
{
  return(current_thread_fast());
}
