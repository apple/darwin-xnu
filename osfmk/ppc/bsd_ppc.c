/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/exception_types.h>
#include <mach/error.h>
#include <kern/counters.h>
#include <kern/syscall_sw.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <ppc/thread.h>
#include <kern/thread_act.h>
#include <ppc/thread_act.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/trap.h>
#include <ppc/exception.h>
#include <kern/assert.h>

#include <sys/kdebug.h>

#define	ERESTART	-1		/* restart syscall */
#define	EJUSTRETURN	-2		/* don't modify regs, just return */

struct unix_syscallargs {
	int flavor;
	int r3;
	int arg1, arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9;
};
struct sysent {		/* system call table */
	unsigned short		sy_narg;		/* number of args */
	char			sy_parallel;	/* can execute in parallel */
        char			sy_funnel;	/* funnel type */
	unsigned long		(*sy_call)(void *, void *, int *);	/* implementing function */
};

#define KERNEL_FUNNEL 1
#define NETWORK_FUNNEL 2

extern funnel_t * kernel_flock;
extern funnel_t * network_flock;

extern struct sysent sysent[];

void  *get_bsdtask_info(
	task_t);

int set_bsduthreadargs (
	thread_act_t, struct pcb *, 
	struct unix_syscallargs  *);

void * get_bsduthreadarg(
	thread_act_t);

void
unix_syscall(
	struct pcb * pcb,
    int, int, int, int, int, int, int );

/*
 * Function:	unix_syscall
 *
 * Inputs:	pcb	- pointer to Process Control Block
 *		arg1	- arguments to mach system calls
 *		arg2
 *		arg3
 *		arg4
 *		arg5
 *		arg6
 *		arg7
 *
 * Outputs:	none
 */
void
unix_syscall(
    struct pcb * pcb,
    int arg1,
    int arg2,
    int arg3,
    int arg4,
    int arg5,
    int arg6,
    int arg7 
    )
{
    struct ppc_saved_state	*regs;
    thread_act_t		thread;
    struct sysent		*callp;
    int				nargs, error;
    unsigned short		code;
    void *  p, *vt;
    int * vtint;
	int *rval;
        int funnel_type;

	struct unix_syscallargs sarg;
	extern int nsysent;


    regs = &pcb->ss;
    code = regs->r0;

    thread = current_act();
	p = current_proc();
	rval = (int *)get_bsduthreadrval(thread);

    /*
    ** Get index into sysent table
    */   

    
	/*
	** Set up call pointer
	*/
	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

	sarg. flavor = (callp == sysent)? 1: 0;
	if (sarg.flavor) {
        	code = regs->r3;
        	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

	}
	else 
		sarg. r3 = regs->r3;

	if (code != 180) {
	        if (sarg.flavor)
		        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
					      arg1, arg2, arg3, arg4, 0);
		else
		        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
					      sarg.r3, arg1, arg2, arg3, 0);
	}
	sarg. arg1 = arg1;
	sarg. arg2 = arg2;
	sarg. arg3 = arg3;
	sarg. arg4 = arg4;
	sarg. arg5 = arg5;
	sarg. arg6 = arg6;
	sarg. arg7 = arg7;

        if(callp->sy_funnel == NETWORK_FUNNEL) {
            (void) thread_funnel_set(network_flock, TRUE);
	   }
        else {
            (void) thread_funnel_set(kernel_flock, TRUE);
	   }

	set_bsduthreadargs(thread,pcb,&sarg);


	if (callp->sy_narg > 8)
	panic("unix_syscall: max arg count exceeded");

	rval[0] = 0;

	/* r4 is volatile, if we set it to regs->r4 here the child
	 * will have parents r4 after execve */
	rval[1] = 0;

	error = 0; /* Start with a good value */

	/*
	** the PPC runtime calls cerror after every unix system call, so
	** assume no error and adjust the "pc" to skip this call.
	** It will be set back to the cerror call if an error is detected.
	*/
	regs->srr0 += 4;
	vt = get_bsduthreadarg(thread);
	counter_always(c_syscalls_unix++);
	current_task()->syscalls_unix++;
	error = (*(callp->sy_call))(p, (void *)vt, rval);

	regs = find_user_regs(thread);
	if (regs == (struct ppc_saved_state  *)0)
		panic("No user savearea while returning from system call");

    if (error == ERESTART) {
	regs->srr0 -= 8;
    }
    else if (error != EJUSTRETURN) {
	if (error)
	{
	    regs->r3 = error;
	    /* set the "pc" to execute cerror routine */
	    regs->srr0 -= 4;
	} else { /* (not error) */
	    regs->r3 = rval[0];
	    regs->r4 = rval[1];
	} 
    }
    /* else  (error == EJUSTRETURN) { nothing } */

    (void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

    if (code != 180) {
        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
		       error, rval[0], rval[1], 0, 0);
    }

    thread_exception_return();
    /* NOTREACHED */
}

unix_syscall_return(error)
{
    struct ppc_saved_state	*regs;
    thread_act_t		thread;
    struct sysent		*callp;
    int				nargs;
    unsigned short		code;
	int *rval;
   void *  p, *vt;
    int * vtint;
	struct pcb *pcb;

	struct unix_syscallargs sarg;
	extern int nsysent;

    thread = current_act();
	p = current_proc();
	rval = (int *)get_bsduthreadrval(thread);
	pcb = thread->mact.pcb;
    regs = &pcb->ss;

    if (thread_funnel_get() == THR_FUNNEL_NULL)
        panic("Unix syscall return without funnel held");

    /*
    ** Get index into sysent table
    */   
    code = regs->r0;

    if (error == ERESTART) {
	regs->srr0 -= 8;
    }
    else if (error != EJUSTRETURN) {
	if (error)
	{
	    regs->r3 = error;
	    /* set the "pc" to execute cerror routine */
	    regs->srr0 -= 4;
	} else { /* (not error) */
	    regs->r3 = rval[0];
	    regs->r4 = rval[1];
	} 
    }
    /* else  (error == EJUSTRETURN) { nothing } */

    (void) thread_funnel_set(current_thread()->funnel_lock, FALSE);

    if (code != 180) {
	  KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
		       error, rval[0], rval[1], 0, 0);
    }

    thread_exception_return();
    /* NOTREACHED */
}

