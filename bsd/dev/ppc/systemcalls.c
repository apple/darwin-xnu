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
/*
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 * PowerPC Family:	System Call handlers.
 *
 * HISTORY
 * 27-July-97  A. Ramesh  
 *	Adopted for Common Core.
 */
 
#include <mach/mach_types.h>
#include <mach/error.h>

#include <kern/syscall_sw.h>
#include <kern/kdp.h>

#include <machdep/ppc/frame.h>
#include <machdep/ppc/thread.h>
#include <machdep/ppc/asm.h>
#include <machdep/ppc/proc_reg.h>
#include <machdep/ppc/trap.h>
#include <machdep/ppc/exception.h>


#define	ERESTART	-1		/* restart syscall */
#define	EJUSTRETURN	-2		/* don't modify regs, just return */


struct unix_syscallargs {
	int flavor;
	int r3;
	int arg1, arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9;
};
extern struct sysent {		/* system call table */
	int16_t		sy_narg;	/* number of args */
	int16_t		sy_parallel;/* can execute in parallel */
	int32_t		(*sy_call)();	/* implementing function */
} sysent[];

/*
** Function:	unix_syscall
**
** Inputs:	pcb	- pointer to Process Control Block
**		arg1	- arguments to mach system calls
**		arg2
**		arg3
**		arg4
**		arg5
**		arg6
**		arg7
**
** Outputs:	none
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
    thread_t			thread;
    struct proc			*p;
   struct sysent		*callp;
    int				nargs, error;
    unsigned short		code;
    int				rval[2];
	struct unix_syscallargs sarg;

    if (!USERMODE(pcb->ss.srr1))
	panic("unix_syscall");

    regs = &pcb->ss;
    thread = current_thread();


    /*
    ** Get index into sysent table
    */   
    code = regs->r0;

    
	/*
	** Set up call pointer
	*/
	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

	sarg. flavor = (callp == sysent): 1: 0;
	sarg. r3 = regs->r3;
	sarg. arg1 = arg1;
	sarg. arg2 = arg2;
	sarg. arg3 = arg3;
	sarg. arg4 = arg4;
	sarg. arg5 = arg5;
	sarg. arg6 = arg6;
	sarg. arg7 = arg7;

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
	p = ((struct proc *)get_bsdtask_info(current_task()));
	error = (*(callp->sy_call))(p, (caddr_t)vt, rval);

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

    thread_exception_return();
    /* NOTREACHED */
	
}

