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
/*
 */

#include <string.h>

#include <mach/boolean.h>
#include <vm/vm_map.h>
#include <kern/thread.h>
#include <kern/task.h>

#include <machine/asm.h>
#include <machine/db_machdep.h>
#include <machine/setjmp.h>
#include <mach/machine.h>
#include <mach/kmod.h>

#include <i386/mp.h>
#include <i386/pio.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/machine_routines.h>

#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_output.h>

extern jmp_buf_t *db_recover;
struct x86_kernel_state ddb_null_kregs;
extern kmod_info_t *kmod;


/*
 * Stack trace.
 */

#define	INKERNELSTACK(va, th) 1

#define DB_NUMARGS_MAX  5

struct i386_frame {
	struct i386_frame	*f_frame;
	int			f_retaddr;
	int			f_arg0;
};

#define	TRAP		1
#define	INTERRUPT	2
#define SYSCALL		3

db_addr_t	db_user_trap_symbol_value = 0;
db_addr_t	db_kernel_trap_symbol_value = 0;
db_addr_t	db_interrupt_symbol_value = 0;
db_addr_t	db_return_to_iret_symbol_value = 0;
db_addr_t	db_syscall_symbol_value = 0;
boolean_t	db_trace_symbols_found = FALSE;

struct i386_kregs {
	char	*name;
	unsigned int offset;
} i386_kregs[] = {
	{ "ebx", (unsigned int)(&((struct x86_kernel_state *)0)->k_ebx) },
	{ "esp", (unsigned int)(&((struct x86_kernel_state *)0)->k_esp) },
	{ "ebp", (unsigned int)(&((struct x86_kernel_state *)0)->k_ebp) },
	{ "edi", (unsigned int)(&((struct x86_kernel_state *)0)->k_edi) },
	{ "esi", (unsigned int)(&((struct x86_kernel_state *)0)->k_esi) },
	{ "eip", (unsigned int)(&((struct x86_kernel_state *)0)->k_eip) },
	{ 0 }
};

/* Forward */

extern unsigned int *	db_lookup_i386_kreg(
			char			*name,
			int			*kregp);
extern int	db_i386_reg_value(
			struct db_variable	* vp,
			db_expr_t		* val,
			int			flag,
			db_var_aux_param_t	ap);
extern void	db_find_trace_symbols(void);
extern int	db_numargs(
			struct i386_frame	*fp,
			task_t			task);
extern void	db_nextframe(
			struct i386_frame	**lfp,
			struct i386_frame	**fp,
			db_addr_t		*ip,
			int			frame_type,
			thread_t		thr_act);
extern int	_setjmp(
			jmp_buf_t		* jb);

/*
 * Machine register set.
 */
struct db_variable db_regs[] = {
	{ "cs",	(unsigned int *)&ddb_regs.cs,  db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "ds",	(unsigned int *)&ddb_regs.ds,  db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "es",	(unsigned int *)&ddb_regs.es,  db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "fs",	(unsigned int *)&ddb_regs.fs,  db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "gs",	(unsigned int *)&ddb_regs.gs,  db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "ss",	(unsigned int *)&ddb_regs.ss,  db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "eax",(unsigned int *)&ddb_regs.eax, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "ecx",(unsigned int *)&ddb_regs.ecx, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "edx",(unsigned int *)&ddb_regs.edx, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "ebx",(unsigned int *)&ddb_regs.ebx, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "esp",(unsigned int *)&ddb_regs.uesp,db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "ebp",(unsigned int *)&ddb_regs.ebp, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "esi",(unsigned int *)&ddb_regs.esi, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "edi",(unsigned int *)&ddb_regs.edi, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "eip",(unsigned int *)&ddb_regs.eip, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 },
	{ "efl",(unsigned int *)&ddb_regs.efl, db_i386_reg_value, 0, 0, 0, 0, TRUE, 0, 0, (int *)0, 0 }
};
struct db_variable *db_eregs = db_regs + sizeof(db_regs)/sizeof(db_regs[0]);

unsigned int *
db_lookup_i386_kreg(
	char	*name,
	int	*kregp)
{
	register struct i386_kregs *kp;

	for (kp = i386_kregs; kp->name; kp++) {
	    if (strcmp(name, kp->name) == 0)
		return((unsigned int *)((int)kregp + kp->offset));
	}
	return(0);
}
	
int
db_i386_reg_value(
	struct	db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap)
{
	extern char		etext;
	unsigned int		*dp = 0;
	db_expr_t		null_reg = 0;
	register thread_t	thr_act = ap->thr_act;

	if (db_option(ap->modif, 'u')) {
	    if (thr_act == THREAD_NULL) {
		if ((thr_act = current_thread()) == THREAD_NULL)
		    db_error("no user registers\n");
	    }
	    if (thr_act == current_thread()) {
		if (IS_USER_TRAP(&ddb_regs, &etext))
		    dp = vp->valuep;
	    }
	} else {
	    if (thr_act == THREAD_NULL || thr_act == current_thread()) {
		dp = vp->valuep;
	    } else {
	      if (thr_act &&
	      (thr_act->continuation != THREAD_CONTINUE_NULL) &&
	      thr_act->kernel_stack) {
		int cpu;

		for (cpu = 0; cpu < real_ncpus; cpu++) {
		    if (cpu_datap(cpu)->cpu_running == TRUE &&
			cpu_datap(cpu)->cpu_active_thread == thr_act && cpu_datap(cpu)->cpu_kdb_saved_state) {
			dp = (unsigned int *) (((unsigned int)cpu_datap(cpu)->cpu_kdb_saved_state) +
				      (((unsigned int) vp->valuep) -
				       (unsigned int) &ddb_regs));
			break;
		    }
		}
		if (dp == 0 && thr_act)
		    dp = db_lookup_i386_kreg(vp->name,
			 (unsigned int *)(STACK_IKS(thr_act->kernel_stack)));
		if (dp == 0)
		    dp = &null_reg;
	      } else if (thr_act &&
	      (thr_act->continuation != THREAD_CONTINUE_NULL)) {
 		/* only EIP is valid  */
 		if (vp->valuep == (unsigned int *) &ddb_regs.eip) {
 		    dp = (unsigned int *)(&thr_act->continuation);
 		} else {
		    dp = &null_reg;
		}
	      }
	    }
	}
	if (dp == 0) {
	    int cpu;

	    if (!db_option(ap->modif, 'u')) {
		for (cpu = 0; cpu < real_ncpus; cpu++) {
		    if (cpu_datap(cpu)->cpu_running == TRUE &&
		    	cpu_datap(cpu)->cpu_active_thread == thr_act && cpu_datap(cpu)->cpu_kdb_saved_state) {
		    	    dp = (unsigned int *) (((unsigned int)cpu_datap(cpu)->cpu_kdb_saved_state) +
					  (((unsigned int) vp->valuep) -
					   (unsigned int) &ddb_regs));
			    break;
		    }
		}
	    }
	    if (dp == 0) {
		if (!thr_act)
		    db_error("no pcb\n");
		dp = (unsigned int *)((unsigned int)(thr_act->machine.iss) + 
			     ((unsigned int)vp->valuep - (unsigned int)&ddb_regs));
	    }
	}
	if (flag == DB_VAR_SET)
	    *dp = *valuep;
	else
	    *valuep = *dp;
	return(0);
}

void
db_find_trace_symbols(void)
{
	db_expr_t	value;
	boolean_t	found_some;

	found_some = FALSE;
	if (db_value_of_name(CC_SYM_PREFIX "user_trap", &value)) {
	    db_user_trap_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (db_value_of_name(CC_SYM_PREFIX "kernel_trap", &value)) {
	    db_kernel_trap_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (db_value_of_name(CC_SYM_PREFIX "interrupt", &value)) {
	    db_interrupt_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (db_value_of_name(CC_SYM_PREFIX "return_to_iret", &value)) {
	    db_return_to_iret_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (db_value_of_name(CC_SYM_PREFIX "syscall", &value)) {
	    db_syscall_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (found_some) 
	    db_trace_symbols_found = TRUE;
}

/*
 * Figure out how many arguments were passed into the frame at "fp".
 */
int db_numargs_default = 5;

int
db_numargs(
	struct i386_frame	*fp,
	task_t			task)
{
	int	*argp;
	int	inst;
	int	args;
	extern char	etext;

	argp = (int *)db_get_task_value((int)&fp->f_retaddr, 4, FALSE, task);
	if (argp < (int *)VM_MIN_KERNEL_ADDRESS || (char *)argp > &etext)
	    args = db_numargs_default;
	else if (!DB_CHECK_ACCESS((int)argp, 4, task))
	    args = db_numargs_default;
	else {
	    inst = db_get_task_value((int)argp, 4, FALSE, task);
	    if ((inst & 0xff) == 0x59)	/* popl %ecx */
		args = 1;
	    else if ((inst & 0xffff) == 0xc483)	/* addl %n, %esp */
		args = ((inst >> 16) & 0xff) / 4;
	    else
		args = db_numargs_default;
	}
	return (args);
}

struct interrupt_frame {
	struct i386_frame *if_frame;	/* point to next frame */
	int		  if_retaddr;	/* return address to _interrupt */
	int		  if_unit;	/* unit number */
	int		  if_spl;	/* saved spl */
	int		  if_iretaddr;	/* _return_to_{iret,iret_i} */
	int		  if_edx;	/* old sp(iret) or saved edx(iret_i) */
	int		  if_ecx;	/* saved ecx(iret_i) */
	int		  if_eax;	/* saved eax(iret_i) */
	int		  if_eip;	/* saved eip(iret_i) */
	int		  if_cs;	/* saved cs(iret_i) */
	int		  if_efl;	/* saved efl(iret_i) */
};

extern const char *trap_type[];
extern int	TRAP_TYPES;

/* 
 * Figure out the next frame up in the call stack.  
 * For trap(), we print the address of the faulting instruction and 
 *   proceed with the calling frame.  We return the ip that faulted.
 *   If the trap was caused by jumping through a bogus pointer, then
 *   the next line in the backtrace will list some random function as 
 *   being called.  It should get the argument list correct, though.  
 *   It might be possible to dig out from the next frame up the name
 *   of the function that faulted, but that could get hairy.
 */
void
db_nextframe(
	struct i386_frame	**lfp,		/* in/out */
	struct i386_frame	**fp,		/* in/out */
	db_addr_t		*ip,		/* out */
	int			frame_type,	/* in */
	thread_t		thr_act)	/* in */
{
	x86_saved_state32_t	*iss32;
	struct interrupt_frame *ifp;
	task_t task = (thr_act != THREAD_NULL)? thr_act->task: TASK_NULL;

	switch(frame_type) {
	case TRAP:
		/*
		 * We know that trap() has 1 argument and we know that
		 * it is an (strcut x86_saved_state32_t *).
		 */
		iss32 = (x86_saved_state32_t *)
			db_get_task_value((int)&((*fp)->f_arg0),4,FALSE,task);

		if (iss32->trapno >= 0 && iss32->trapno < TRAP_TYPES) {
			db_printf(">>>>> %s trap at ",
					trap_type[iss32->trapno]);
		} else {
			db_printf(">>>>> trap (number %d) at ",
					iss32->trapno & 0xffff);
		}
		db_task_printsym(iss32->eip, DB_STGY_PROC, task);
		db_printf(" <<<<<\n");
		*fp = (struct i386_frame *)iss32->ebp;
		*ip = (db_addr_t)iss32->eip;
		break;

	case INTERRUPT:
		if (*lfp == 0) {
			db_printf(">>>>> interrupt <<<<<\n");
			goto miss_frame;
		}
		db_printf(">>>>> interrupt at "); 
		ifp = (struct interrupt_frame *)(*lfp);
		*fp = ifp->if_frame;
		if (ifp->if_iretaddr == db_return_to_iret_symbol_value) {
			*ip = ((x86_saved_state32_t *)ifp->if_edx)->eip;
		} else
			*ip = (db_addr_t)ifp->if_eip;
		db_task_printsym(*ip, DB_STGY_PROC, task);
		db_printf(" <<<<<\n");
		break;

	case SYSCALL:
		if (thr_act != THREAD_NULL) {
			iss32 = (x86_saved_state32_t *)thr_act->machine.iss;

			*ip = (db_addr_t)(iss32->eip);
			*fp = (struct i386_frame *)(iss32->ebp);
		}
		break;

	default:	/* falling down for unknown case */
miss_frame:
		*ip = (db_addr_t)
			db_get_task_value((int)&(*fp)->f_retaddr, 4, FALSE, task);
		*lfp = *fp;
		*fp = (struct i386_frame *)
			db_get_task_value((int)&(*fp)->f_frame, 4, FALSE, task);
		break;
	}
}

void
db_stack_trace_cmd(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	struct i386_frame *frame, *lastframe;
        x86_saved_state32_t	*iss32;
	int		*argp;
	db_addr_t	callpc, lastcallpc;
	int		frame_type;
	boolean_t	kernel_only = TRUE;
	boolean_t	trace_thread = FALSE;
	boolean_t	trace_all_threads = FALSE;
	int		thcount = 0;
	char		*filename;
	int		linenum;
	task_t		task;
	thread_t	th, top_act;
	int		user_frame;
	int		frame_count;
	jmp_buf_t	*prev;
	jmp_buf_t	db_jmp_buf;
	queue_entry_t	act_list;

	if (!db_trace_symbols_found)
	    db_find_trace_symbols();

	{
	    register char *cp = modif;
	    register char c;

	    while ((c = *cp++) != 0) {
		if (c == 't')
		    trace_thread = TRUE;
		if (c == 'T') {
		    trace_all_threads = TRUE;
		    trace_thread = TRUE;
		}
		if (c == 'u')
		    kernel_only = FALSE;
	    }
	}

	if (trace_all_threads) {
	    if (!have_addr && !trace_thread) {
		have_addr = TRUE;
		trace_thread = TRUE;
		act_list = &(current_task()->threads);
		addr = (db_expr_t) queue_first(act_list);
	    } else if (trace_thread) {
		if (have_addr) {
		    if (!db_check_act_address_valid((thread_t)addr)) {
			if (db_lookup_task((task_t)addr) == -1)
			    return;
			act_list = &(((task_t)addr)->threads);
			addr = (db_expr_t) queue_first(act_list);
		    } else {
			act_list = &(((thread_t)addr)->task->threads);
			thcount = db_lookup_task_act(((thread_t)addr)->task,
							(thread_t)addr);
		    }
		} else {
		    th = db_default_act;
		    if (th == THREAD_NULL)
			th = current_thread();
		    if (th == THREAD_NULL) {
			db_printf("no active thr_act\n");
			return;
		    }
		    have_addr = TRUE;
		    act_list = &th->task->threads;
		    addr = (db_expr_t) queue_first(act_list);
		}
	    }
	}

	if (count == -1)
	    count = 65535;

next_thread:
	top_act = THREAD_NULL;

	user_frame = 0;
	frame_count = count;

	if (!have_addr && !trace_thread) {
	    frame = (struct i386_frame *)ddb_regs.ebp;
	    callpc = (db_addr_t)ddb_regs.eip;
	    th = current_thread();
	    task = (th != THREAD_NULL)? th->task: TASK_NULL;
	    db_printf("thread 0x%x, current_thread() is 0x%x, ebp is 0x%x, eip is 0x%x\n", th, current_thread(), ddb_regs.ebp, ddb_regs.eip);
	} else if (trace_thread) {
	    if (have_addr) {
		th = (thread_t) addr;
		if (!db_check_act_address_valid(th)) {
			return;
		}
	    } else {
		th = db_default_act;
		if (th == THREAD_NULL)
		   th = current_thread();
		if (th == THREAD_NULL) {
		   db_printf("no active thread\n");
		   return;
		}
	    }
	    if (trace_all_threads)
		db_printf("---------- Thread 0x%x (#%d of %d) ----------\n",
		addr, thcount, th->task->thread_count);

	next_activation:
	    user_frame = 0;
//	    kprintf("th is %x, current_thread() is %x, ddb_regs.ebp is %x ddb_regs.eip is %x\n", th, current_thread(), ddb_regs.ebp, ddb_regs.eip);
	    task = th->task;
	    if (th == current_thread()) {
	        frame = (struct i386_frame *)ddb_regs.ebp;
	        callpc = (db_addr_t)ddb_regs.eip;
	    } else {
		if (!th) {
		    db_printf("thread has no shuttle\n");

		    goto thread_done;
		}
		else if ( (th->continuation != THREAD_CONTINUE_NULL) || 
			  th->kernel_stack == 0) {

		    db_printf("Continuation ");
		    db_task_printsym((db_expr_t)th->continuation,
							DB_STGY_PROC, task);
		    db_printf("\n");

		    iss32 = (x86_saved_state32_t *)th->machine.iss;

			frame = (struct i386_frame *) (iss32->ebp);
			callpc = (db_addr_t) (iss32->eip);

		} else {
		    int cpu;

		    for (cpu = 0; cpu < real_ncpus; cpu++) {
			if (cpu_datap(cpu)->cpu_running == TRUE &&
			    cpu_datap(cpu)->cpu_active_thread == th &&
			    cpu_datap(cpu)->cpu_kdb_saved_state) {
			    break;
			}
		    }
		    if (top_act != THREAD_NULL) {
			    /*
			     * Trying to get the backtrace of an activation
			     * which is not the top_most one in the RPC chain:
			     * use the activation's pcb.
			     */
		            iss32 = (x86_saved_state32_t *)th->machine.iss;

				    frame = (struct i386_frame *) (iss32->ebp);
				    callpc = (db_addr_t) (iss32->eip);
		    } else {
			    if (cpu == real_ncpus) {
			    register struct x86_kernel_state *iks;
			    int r;

			    iks = STACK_IKS(th->kernel_stack);
			    prev = db_recover;
			    if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
				frame = (struct i386_frame *) (iks->k_ebp);
				callpc = (db_addr_t) (iks->k_eip);
			    } else {
				/*
				 * The kernel stack has probably been
				 * paged out (swapped out activation).
				 */
				db_recover = prev;
				if (r == 2)	/* 'q' from db_more() */
				    db_error(0);
				db_printf("<kernel stack (0x%x) error "
					  "(probably swapped out)>\n",
					  iks);
				goto thread_done;
			    }
			    db_recover = prev;
			} else {
			    db_printf(">>>>> active on cpu %d <<<<<\n",
				      cpu);

			    iss32 = (x86_saved_state32_t *)cpu_datap(cpu)->cpu_kdb_saved_state;

				    frame = (struct i386_frame *) (iss32->ebp);
				    callpc = (db_addr_t) (iss32->eip);
			    }
			}
		    }
	        }
	} else {
	    frame = (struct i386_frame *)addr;
	    th = (db_default_act)? db_default_act: current_thread();
	    task = (th != THREAD_NULL)? th->task: TASK_NULL;
	    callpc = (db_addr_t)db_get_task_value((int)&frame->f_retaddr,
						  4, 
						  FALSE, 
						  (user_frame) ? task : 0);
	}

	if (!INKERNELSTACK((unsigned)frame, th)) {
	    db_printf(">>>>> user space <<<<<\n");
	    if (kernel_only)
		goto thread_done;
	    user_frame++;
	}

	lastframe = 0;
	lastcallpc = (db_addr_t) 0;
	while (frame_count-- && frame != 0) {
	    int narg = DB_NUMARGS_MAX;
	    char *	name;
	    db_expr_t	offset;
	    db_addr_t call_func = 0;
	    int r;
	    db_addr_t	off;
	    
	    db_symbol_values(NULL,
			     db_search_task_symbol_and_line(
					callpc,
					DB_STGY_XTRN, 
					&offset,
					&filename,
					&linenum,
					(user_frame) ? task : 0,
					&narg),
			     &name, (db_expr_t *)&call_func);
	    if ( name == NULL) {
		    db_find_task_sym_and_offset(callpc, 
		    &name, &off, (user_frame) ? task : 0);
		    offset = (db_expr_t) off;
		}

	    if (user_frame == 0) {
		if (call_func && call_func == db_user_trap_symbol_value ||
		    call_func == db_kernel_trap_symbol_value) {
		    frame_type = TRAP;
		    narg = 1;
		} else if (call_func &&
		    call_func == db_interrupt_symbol_value) {
		    frame_type = INTERRUPT;
		    goto next_frame;
		} else if (call_func && call_func == db_syscall_symbol_value) {
		    frame_type = SYSCALL;
		    goto next_frame;
		} else {
		    frame_type = 0;
		    prev = db_recover;
		    if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
		    	if (narg < 0)
			    narg = db_numargs(frame,
					      (user_frame) ? task : 0);
			db_recover = prev;
		    } else {
			db_recover = prev;
			goto thread_done;
		    }
		}
	    } else {
	    	frame_type = 0;
		prev = db_recover;
		if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
		    if (narg < 0)
			narg = db_numargs(frame,
					  (user_frame) ? task : 0);
		    db_recover = prev;
		} else {
		    db_recover = prev;
		    goto thread_done;
		}
	    }

	    if (name == 0 || offset > db_maxoff) {
		db_printf("0x%x 0x%x(", frame, callpc);
		offset = 0;
	    } else
	        db_printf("0x%x %s(", frame, name);

	    argp = &frame->f_arg0;
	    while (narg > 0) {
		int value;

		prev = db_recover;
		if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
		    value = db_get_task_value((int)argp,
					      4,
					      FALSE,
					      (user_frame) ? task : 0);
		} else {
		    db_recover = prev;
		    if (r == 2)		/* 'q' from db_more() */
			db_error(0);
		    db_printf("... <stack error>)");
		    if (offset)
			db_printf("+%x", offset);
		    if (filename) {
			db_printf(" [%s", filename);
			if (linenum > 0)
			    db_printf(":%d", linenum);
			db_printf("]");
		    }
		    db_printf("\n");
		    goto thread_done;
		}
		db_recover = prev;
		db_printf("%x", value);
		argp++;
		if (--narg != 0)
		    db_printf(",");
	    }
	    if (narg < 0)
		db_printf("...");
	    db_printf(")");
	    if (offset) {
		db_printf("+%x", offset);
            }
	    if (filename) {
		db_printf(" [%s", filename);
		if (linenum > 0)
		    db_printf(":%d", linenum);
		db_printf("]");
	    }
	    db_printf("\n");

next_frame:
	    lastcallpc = callpc;
	    db_nextframe(&lastframe, &frame, &callpc, frame_type,
			 (user_frame) ? th : THREAD_NULL);

	    if (frame == 0) {
		if (th->task_threads.prev != THREAD_NULL) {
		    if (top_act == THREAD_NULL)
			top_act = th;
		    th = th->task_threads.prev;
		    db_printf(">>>>> next activation 0x%x ($task%d.%d) <<<<<\n",
			      th,
			      db_lookup_task(th->task),
			      db_lookup_task_act(th->task, th));
		    goto next_activation;
		}
		/* end of chain */
		break;
	    }
	    if (!INKERNELSTACK(lastframe, th) ||
		!INKERNELSTACK((unsigned)frame, th))
		user_frame++;
	    if (user_frame == 1) {
		db_printf(">>>>> user space <<<<<\n");
		if (kernel_only)
		    break;
	    }
	    if (frame <= lastframe) {
		if ((INKERNELSTACK(lastframe, th) &&
			!INKERNELSTACK(frame, th)))
		    continue;
		db_printf("Bad frame pointer: 0x%x\n", frame);
		break;
	    }
	}

thread_done:
	if (trace_all_threads) {
	    if (top_act != THREAD_NULL)
		th = top_act;
	    th = (thread_t) queue_next(&th->task_threads);
	    if (! queue_end(act_list, (queue_entry_t) th)) {
		db_printf("\n");
		addr = (db_expr_t) th;
		thcount++;
		goto next_thread;

	    }
	}
}

extern mach_vm_size_t kdp_machine_vm_read(mach_vm_address_t, caddr_t, mach_vm_size_t);
extern boolean_t kdp_trans_off;
/*
 *		Print out 256 bytes of real storage
 *		
 *		dr [entaddr]
 */
void
db_display_real(db_expr_t addr, boolean_t have_addr, db_expr_t count,
		char *modif)
{
	int				i;
	unsigned int xbuf[8];
	unsigned read_result = 0;
/* Print 256 bytes */
	for(i=0; i<8; i++) {

/*
 * Do a physical read using kdp_machine_vm_read(), rather than replicating the same
 * facility
 */
		kdp_trans_off = 1;
		read_result = kdp_machine_vm_read(addr, &xbuf[0], 32);
		kdp_trans_off = 0;

		if (read_result != 32)
			db_printf("Unable to read address\n");
		else
			db_printf("%016llX   %08X %08X %08X %08X  %08X %08X %08X %08X\n", addr,	/* Print a line */
			    xbuf[0], xbuf[1], xbuf[2], xbuf[3], 
			    xbuf[4], xbuf[5], xbuf[6], xbuf[7]);
		addr = addr + 0x00000020;							/* Point to next address */
	}
	db_next = addr;
}

/*
 *	Displays all of the kmods in the system.
 *
 *		dk
 */
void 
db_display_kmod(__unused db_expr_t addr, __unused boolean_t have_addr,
		__unused db_expr_t count, __unused char *modif)
{

	kmod_info_t    *kmd;
	unsigned int    strt, end;

	kmd = kmod;		/* Start at the start */

	db_printf("info      addr      start    - end       name ver\n");

	while (kmd) {		/* Dump 'em all */
		strt = (unsigned int) kmd->address + kmd->hdr_size;
		end = (unsigned int) kmd->address + kmd->size;
		db_printf("%08X  %08X  %08X - %08X: %s, %s\n",
			kmd, kmd->address, strt, end, kmd->name, kmd->version);
		kmd = kmd->next;
	}
}

void
db_display_iokit(__unused db_expr_t addr, __unused boolean_t have_addr,
		__unused db_expr_t count, __unused char *modif)
{
}
