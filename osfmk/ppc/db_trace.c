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
 * @OSF_COPYRIGHT@
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

#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_output.h>

extern jmp_buf_t *db_recover;
extern struct ppc_saved_state *saved_state[];

struct ppc_saved_state ddb_null_kregs;

extern vm_offset_t vm_min_inks_addr;	/* set by db_clone_symtabXXX */

#define DB_NUMARGS_MAX	5


extern  char FixedStackStart[], FixedStackEnd[];
#define	INFIXEDSTACK(va)							\
	((((vm_offset_t)(va)) >= (vm_offset_t)&FixedStackStart) &&	\
	(((vm_offset_t)(va)) < ((vm_offset_t)&FixedStackEnd)))

#if 0

#define	INKERNELSTACK(va, th)					\
	(th == THR_ACT_NULL ||				\
	 (((vm_offset_t)(va)) >= th->thread->kernel_stack &&	\
	  (((vm_offset_t)(va)) < th->thread->kernel_stack +	\
	                         KERNEL_STACK_SIZE)) ||		\
         INFIXEDSTACK(va))
#else
#define INKERNELSTACK(va, th) 1

#endif

#ifdef __MACHO__
struct db_ppc_frame {
	struct db_ppc_frame	*f_frame;
	int			pad1;
	db_addr_t		f_retaddr;
	int			pad3;
	int			pad4;
	int			pad5;
	db_addr_t		f_arg[DB_NUMARGS_MAX];
};
#endif

#define	TRAP		1
#define	INTERRUPT	2
#define SYSCALL		3

db_addr_t	db_user_trap_symbol_value = 0;
db_addr_t	db_kernel_trap_symbol_value = 0;
db_addr_t	db_interrupt_symbol_value = 0;
db_addr_t	db_return_to_iret_symbol_value = 0;
db_addr_t	db_syscall_symbol_value = 0;
boolean_t	db_trace_symbols_found = FALSE;

extern int	db_ppc_reg_value(
			struct db_variable	* vp,
			db_expr_t		* val,
			int			flag,
			db_var_aux_param_t	ap);
extern void	db_find_trace_symbols(void);
extern int	db_numargs(
			struct db_ppc_frame	*fp,
			task_t			task);
extern boolean_t db_find_arg(
			struct db_ppc_frame	*frame,
			db_addr_t		calleepc,
			task_t			task,
			int			narg,
			db_addr_t		*arg);
extern void	db_nextframe(
			struct db_ppc_frame	**lfp,
			struct db_ppc_frame	**fp,
			db_addr_t		*ip,
			int			frame_type,
			thread_act_t		thr_act,
			db_addr_t		linkpc);
extern int	_setjmp(
			jmp_buf_t		* jb);

/*
 * Machine register set.
 */
struct db_variable db_regs[] = {
	/* XXX "pc" is an alias to "srr0"... */
  { "pc",	(int *)&ddb_regs.srr0,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "srr0",	(int *)&ddb_regs.srr0,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "srr1",	(int *)&ddb_regs.srr1,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r0",	(int *)&ddb_regs.r0,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r1",	(int *)&ddb_regs.r1,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r2",	(int *)&ddb_regs.r2,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r3",	(int *)&ddb_regs.r3,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r4",	(int *)&ddb_regs.r4,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r5",	(int *)&ddb_regs.r5,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r6",	(int *)&ddb_regs.r6,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r7",	(int *)&ddb_regs.r7,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r8",	(int *)&ddb_regs.r8,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r9",	(int *)&ddb_regs.r9,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r10",	(int *)&ddb_regs.r10,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r11",	(int *)&ddb_regs.r11,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r12",	(int *)&ddb_regs.r12,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r13",	(int *)&ddb_regs.r13,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r14",	(int *)&ddb_regs.r14,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r15",	(int *)&ddb_regs.r15,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r16",	(int *)&ddb_regs.r16,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r17",	(int *)&ddb_regs.r17,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r18",	(int *)&ddb_regs.r18,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r19",	(int *)&ddb_regs.r19,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r20",	(int *)&ddb_regs.r20,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r21",	(int *)&ddb_regs.r21,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r22",	(int *)&ddb_regs.r22,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r23",	(int *)&ddb_regs.r23,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r24",	(int *)&ddb_regs.r24,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r25",	(int *)&ddb_regs.r25,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r26",	(int *)&ddb_regs.r26,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r27",	(int *)&ddb_regs.r27,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r28",	(int *)&ddb_regs.r28,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r29",	(int *)&ddb_regs.r29,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r30",	(int *)&ddb_regs.r30,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "r31",	(int *)&ddb_regs.r31,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "cr",	(int *)&ddb_regs.cr,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "xer",	(int *)&ddb_regs.xer,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "lr",	(int *)&ddb_regs.lr,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "ctr",	(int *)&ddb_regs.ctr,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "mq",	(int *)&ddb_regs.mq,	db_ppc_reg_value, 0, 0, 0, 0, TRUE },
  { "sr_copyin",(int *)&ddb_regs.sr_copyin,db_ppc_reg_value, 0, 0, 0, 0, TRUE },
};
struct db_variable *db_eregs = db_regs + sizeof(db_regs)/sizeof(db_regs[0]);

int
db_ppc_reg_value(
	struct	db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap)
{
	int			*dp = 0;
	db_expr_t		null_reg = 0;
	register thread_act_t	thr_act = ap->thr_act;
	int			cpu;

	if (db_option(ap->modif, 'u')) {
	    if (thr_act == THR_ACT_NULL) {
		if ((thr_act = current_act()) == THR_ACT_NULL)
		    db_error("no user registers\n");
	    }
	    if (thr_act == current_act()) {
		if (IS_USER_TRAP((&ddb_regs)))
		    dp = vp->valuep;
		else if (INFIXEDSTACK(ddb_regs.r1))
		    db_error("cannot get/set user registers in nested interrupt\n");
	    }
	} else {
	    if (thr_act == THR_ACT_NULL || thr_act == current_act()) {
		dp = vp->valuep;
	    } else {
	      if (thr_act->thread &&
		  !(thr_act->thread->state & TH_STACK_HANDOFF) && 
			thr_act->thread->kernel_stack) {
		int cpu;

		for (cpu = 0; cpu < NCPUS; cpu++) {
		    if (machine_slot[cpu].running == TRUE &&
			cpu_data[cpu].active_thread == thr_act->thread && saved_state[cpu]) {
			dp = (int *) (((int)saved_state[cpu]) +
				      (((int) vp->valuep) -
				       (int) &ddb_regs));
			break;
		    }
		}
#if 0
		if (dp == 0 && thr_act && thr_act->thread)
		    dp = db_lookup_i386_kreg(vp->name,
			 (int *)(STACK_IKS(thr_act->thread->kernel_stack)));
#endif
		if (dp == 0)
		    dp = &null_reg;
	      } else if (thr_act->thread &&
			 (thr_act->thread->state&TH_STACK_HANDOFF)){
		/* only PC is valid */
		if (vp->valuep == (int *) &ddb_regs.srr0) {
		    dp = (int *)(&thr_act->thread->continuation);
		} else {
		    dp = &null_reg;
		}
	      }
	    }
	}
	if (dp == 0) {
	    int cpu;

	    if (!db_option(ap->modif, 'u')) {
		for (cpu = 0; cpu < NCPUS; cpu++) {
		    if (machine_slot[cpu].running == TRUE &&
		    	cpu_data[cpu].active_thread == thr_act->thread && saved_state[cpu]) {
		    	    dp = (int *) (((int)saved_state[cpu]) +
					  (((int) vp->valuep) -
					   (int) &ddb_regs));
			    break;
		    }
		}
	    }
	    if (dp == 0) {
		if (!thr_act || thr_act->mact.pcb == 0)
		    db_error("no pcb\n");
		dp = (int *)((int)(&thr_act->mact.pcb->ss) + 
			     ((int)vp->valuep - (int)&ddb_regs));
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
	if (db_value_of_name(CC_SYM_PREFIX "thandler", &value)) {
	    db_user_trap_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (db_value_of_name(CC_SYM_PREFIX "thandler", &value)) {
	    db_kernel_trap_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (db_value_of_name(CC_SYM_PREFIX "ihandler", &value)) {
	    db_interrupt_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
#if 0
	if (db_value_of_name(CC_SYM_PREFIX "return_to_iret", &value)) {
	    db_return_to_iret_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
#endif
	if (db_value_of_name(CC_SYM_PREFIX "thandler", &value)) {
	    db_syscall_symbol_value = (db_addr_t) value;
	    found_some = TRUE;
	}
	if (found_some) 
	    db_trace_symbols_found = TRUE;
}

int
db_numargs(
	struct db_ppc_frame	*fp,
	task_t			task)
{
	return (DB_NUMARGS_MAX);
}

boolean_t
db_find_arg(
	struct db_ppc_frame 	*fp,
	db_addr_t		calleepc,
	task_t			task,
	int			narg,
	db_addr_t		*arg)
{
	db_addr_t	argp;
	db_addr_t	calleep;
	db_addr_t   	offset;
	int		i;
	int		inst;
	char 		*name;

#if	XXX_BS
	db_find_task_sym_and_offset(calleepc, &name, &offset, task);
	calleep = calleepc-offset;

	for (i = 0; calleep < calleepc; i++, calleep++) {
		if (!DB_CHECK_ACCESS((int) calleep, 4, task)) {
			continue;
		}
		inst = db_get_task_value(calleep, 4, FALSE, task);
		if ((inst & 0xffff0000) == (0x907f0000 + (narg << 21)) ||
		    (inst & 0xffff0000) == (0x90610000 + (narg << 21))) {
			argp = (db_addr_t) &(fp->f_arg[narg]);
			*arg = argp;
			return TRUE;
		}
	}
#endif
	return FALSE;
}

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
	struct db_ppc_frame	**lfp,		/* in/out */
	struct db_ppc_frame	**fp,		/* in/out */
	db_addr_t		*ip,		/* out */
	int			frame_type,	/* in */
	thread_act_t		thr_act,
	db_addr_t		linkpc)		/* in */
{
	extern char *	trap_type[];
	extern int	TRAP_TYPES;

	struct ppc_saved_state *saved_regs;

	task_t task = (thr_act != THR_ACT_NULL)? thr_act->task: TASK_NULL;

	switch(frame_type) {
	case TRAP:
#if 0
	    /*
	     * We know that trap() has 1 argument and we know that
	     * it is an (strcut i386_saved_state *).
	     */
	    saved_regs = (struct i386_saved_state *)
			db_get_task_value((int)&((*fp)->f_arg0),4,FALSE,task);
	    if (saved_regs->trapno >= 0 && saved_regs->trapno < TRAP_TYPES) {
		db_printf(">>>>> %s trap at ",
			trap_type[saved_regs->trapno]);
	    } else {
		db_printf(">>>>> trap (number %d) at ",
			saved_regs->trapno & 0xffff);
	    }
	    db_task_printsym(saved_regs->eip, DB_STGY_PROC, task);
	    db_printf(" <<<<<\n");
	    *fp = (struct i386_frame *)saved_regs->ebp;
	    *ip = (db_addr_t)saved_regs->eip;
#else
	    db_printf(">>>>> trap <<<<<\n");
	    goto miss_frame;
#endif
	    break;
	case INTERRUPT:
	    if (*lfp == 0) {
		db_printf(">>>>> interrupt <<<<<\n");
		goto miss_frame;
	    }
#if 0
	    db_printf(">>>>> interrupt at "); 
	    ifp = (struct interrupt_frame *)(*lfp);
	    *fp = ifp->if_frame;
	    if (ifp->if_iretaddr == db_return_to_iret_symbol_value)
		*ip = ((struct i386_interrupt_state *) ifp->if_edx)->eip;
	    else
		*ip = (db_addr_t) ifp->if_eip;
	    db_task_printsym(*ip, DB_STGY_PROC, task);
	    db_printf(" <<<<<\n");
#else
	    db_printf(">>>>> interrupt <<<<<\n");
	    goto miss_frame;
#endif
	    break;
	case SYSCALL:
	    if (thr_act != THR_ACT_NULL && thr_act->mact.pcb) {
		*ip = (db_addr_t) thr_act->mact.pcb->ss.srr0;
		*fp = (struct db_ppc_frame *) (thr_act->mact.pcb->ss.r1);
		break;
	    }
	    /* falling down for unknown case */
	default:
	miss_frame:
		if ((*fp)->f_frame)
		    *ip = (db_addr_t)
			    db_get_task_value((int)&(*fp)->f_frame->f_retaddr,
					      4, FALSE, task);
		else
			*ip = (db_addr_t) 
                            db_get_task_value((int)&(*fp)->f_retaddr,
                                              4, FALSE, task);

	    *lfp = *fp;
	    *fp = (struct db_ppc_frame *)
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
	struct db_ppc_frame *frame, *lastframe;
	db_addr_t	callpc, linkpc, lastcallpc;
	int		frame_type;
	boolean_t	kernel_only = TRUE;
	boolean_t	trace_thread = FALSE;
	boolean_t	trace_all_threads = FALSE;
	int		thcount = 0;
	char		*filename;
	int		linenum;
	task_t		task;
	thread_act_t	th, top_act;
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
			act_list = &(current_task()->thr_acts);
			addr = (db_expr_t) queue_first(act_list);
	    } 
		else if (trace_thread) {
			if (have_addr) {
				if (!db_check_act_address_valid((thread_act_t)addr)) {
					if (db_lookup_task((task_t)addr) == -1)
						return;
					act_list = &(((task_t)addr)->thr_acts);
					addr = (db_expr_t) queue_first(act_list);
				} 
				else {
					act_list = &(((thread_act_t)addr)->task->thr_acts);
					thcount = db_lookup_task_act(((thread_act_t)addr)->task,
									(thread_act_t)addr);
				}
			} 
			else {
				th = db_default_act;
				if (th == THR_ACT_NULL)
					th = current_act();
				if (th == THR_ACT_NULL) {
					db_printf("no active thr_act\n");
					return;
				}
				have_addr = TRUE;
				act_list = &th->task->thr_acts;
				addr = (db_expr_t) queue_first(act_list);
			}
	    }
	}

	if (count == -1)
	    count = 65535;

next_thread:
	top_act = THR_ACT_NULL;

	user_frame = 0;
	frame_count = count;

	if (!have_addr && !trace_thread) {
	    frame = (struct db_ppc_frame *)(ddb_regs.r1);
	    callpc = (db_addr_t)ddb_regs.srr0;
	    linkpc = (db_addr_t)ddb_regs.lr;
	    th = current_act();
	    task = (th != THR_ACT_NULL)? th->task: TASK_NULL;
	} 
	else if (trace_thread) {
	    if (have_addr) {
			th = (thread_act_t) addr;
			if (!db_check_act_address_valid(th))
		   		return;
	    } 
		else {
			th = db_default_act;
			if (th == THR_ACT_NULL)
			   th = current_act();
			if (th == THR_ACT_NULL) {
			   db_printf("no active thread\n");
			   return;
			}
	    }
	    if (trace_all_threads)
		db_printf("---------- Thread 0x%x (#%d of %d) ----------\n",
			  addr, thcount, th->task->thr_act_count);

next_activation:

	    user_frame = 0;

	    task = th->task;
	    if (th == current_act()) {
	        frame = (struct db_ppc_frame *)(ddb_regs.r1);
	        callpc = (db_addr_t)ddb_regs.srr0;
			linkpc = (db_addr_t)ddb_regs.lr;
	    } 
		else {
			if (th->mact.pcb == 0) {
		    	db_printf("thread has no pcb\n");
				goto thread_done;
			}
			if (!th->thread) {
				register struct ppc_saved_state *pss =
							&th->mact.pcb->ss;
	
				db_printf("thread has no shuttle\n");
	#if 0
				frame = (struct db_ppc_frame *) (pss->r1);
				callpc = (db_addr_t) (pss->srr0);
				linkpc = (db_addr_t) (pss->lr);
	#else
				goto thread_done;
	#endif
			}
			else if ((th->thread->state & TH_STACK_HANDOFF) ||
				  th->thread->kernel_stack == 0) {
				register struct ppc_saved_state *pss =
							&th->mact.pcb->ss;
	
				db_printf("Continuation ");
				db_task_printsym((db_expr_t)th->thread->continuation,
								DB_STGY_PROC, task);
				db_printf("\n");
				frame = (struct db_ppc_frame *) (pss->r1);
				callpc = (db_addr_t) (pss->srr0);
				linkpc = (db_addr_t) (pss->lr);
			} 
			else {
				int cpu;
	
				for (cpu = 0; cpu < NCPUS; cpu++) {
					if (machine_slot[cpu].running == TRUE &&
						cpu_data[cpu].active_thread == th->thread &&
						saved_state[cpu]) {
						break;
					}
				}
				if (top_act != THR_ACT_NULL) {
					/*
					 * Trying to get the backtrace of an activation
					 * which is not the top_most one in the RPC chain:
					 * use the activation's pcb.
					 */
					struct ppc_saved_state *pss;
	
					pss = (struct ppc_saved_state *)th->mact.pcb;
					frame = (struct db_ppc_frame *) (pss->r1);
					callpc = (db_addr_t) (pss->srr0);
					linkpc = (db_addr_t) (pss->lr);
					} else {
						if (cpu == NCPUS) {
							register struct ppc_saved_state *iks;
							int r;
			
							iks = (struct ppc_saved_state *)th->mact.pcb;
							prev = db_recover;
							if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
								frame = (struct db_ppc_frame *) (iks->r1);
								callpc = (db_addr_t) (iks->lr);
								linkpc = 0;
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
								goto next_act;
							}
							db_recover = prev;
						} else {
							db_printf(">>>>> active on cpu %d <<<<<\n",
								  cpu);
							frame = (struct db_ppc_frame *)
							(saved_state[cpu]->r1);
							callpc = (db_addr_t) saved_state[cpu]->srr0;
							linkpc = (db_addr_t) saved_state[cpu]->lr;
						}
					}
				}
	    }
	} else {
	    frame = (struct db_ppc_frame *)addr;
	    th = (db_default_act)? db_default_act: current_act();
	    task = (th != THR_ACT_NULL)? th->task: TASK_NULL;
	    if (frame->f_frame) {
	      callpc = (db_addr_t)db_get_task_value
				((int)&frame->f_frame->f_retaddr,
				4, FALSE, (user_frame) ? task : 0);
	      callpc = callpc-sizeof(callpc);
	    } else
	      callpc =0;
	    linkpc = 0;
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
		int arg;	
		char *	name;
		db_expr_t	offset;
		db_addr_t call_func = 0;
		int r;
		db_addr_t	off;

		db_symbol_values(NULL,
			db_search_task_symbol_and_line(
				callpc, DB_STGY_XTRN, &offset, &filename,
				&linenum, (user_frame) ? task : 0, &narg),
			&name, (db_expr_t *)&call_func);
		if ( name == NULL) {
			db_find_task_sym_and_offset(callpc, 
				&name, &off, (user_frame) ? task : 0);
			offset = (db_expr_t) off;
		}

		if (user_frame == 0) {
			if (call_func &&
				(call_func == db_user_trap_symbol_value ||
				call_func == db_kernel_trap_symbol_value)) {
			frame_type = TRAP;
			narg = 1;
			} else if (call_func &&
				call_func == db_interrupt_symbol_value) {
				frame_type = INTERRUPT;
				goto next_frame;
			} else if (call_func &&
				call_func == db_syscall_symbol_value) {
				frame_type = SYSCALL;
				goto next_frame;
			} else {
				frame_type = 0;
				prev = db_recover;
				if ((r = _setjmp(db_recover = &db_jmp_buf)) 
								== 0) {
			 		if (narg < 0)
						narg = db_numargs(frame,
						    (user_frame) ? task : 0);
					db_recover = prev;
				} else {
					db_recover = prev;
					goto next_act;
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
				goto next_act;
			}
		}

	    if (name == 0 || offset > db_maxoff) {
		db_printf("[%08X]0x%08X(", frame, callpc);
	    } else {
	        db_printf("[%08X]%s", frame, name);
		if (offset)
                        db_printf("+%x", offset);
	        db_printf("(");
	   };

	narg = db_numargs(frame, (user_frame) ? task : 0);

	for (arg =0; arg < narg; arg++) {
		db_addr_t	argp;
		int value;
		boolean_t found;

		prev = db_recover;
		if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
			found = FALSE;
			if (lastframe) 
				found = db_find_arg(frame, lastframe->f_retaddr,
					(user_frame) ? task : 0, arg, &argp);
			if (found)
				value = db_get_task_value(argp, 4, FALSE,
					(user_frame) ? task : 0);
		} else {
			db_recover = prev;
			if (r == 2)	/* 'q' from db_more() */
				db_error(0);
		    	db_printf("... <stack error>)");
			db_printf("\n");
			goto next_act;
		}
		db_recover = prev;
		if (found)
			db_printf("%08X", value);
		else
			db_printf("??");	
		argp = argp + sizeof(argp);
		if (arg < narg-1)
			db_printf(",");
	    }
	    if (arg != narg)
		db_printf("...");
	    db_printf(")");
	    db_printf("\n");

	next_frame:
	    lastcallpc = callpc;
	    prev = db_recover;
	    if ((r = _setjmp(db_recover = &db_jmp_buf)) == 0) {
		    db_nextframe(&lastframe, &frame, &callpc, frame_type,
				 (user_frame) ? th : THR_ACT_NULL, linkpc);
		    callpc = callpc-sizeof(callpc);
		    db_recover = prev;
	    } else {
		    db_recover = prev;
		    frame = 0;
	    }
	    linkpc = 0;

	    if (frame == 0) {
	next_act:
		if (th->lower != THR_ACT_NULL) {
		    if (top_act == THR_ACT_NULL)
			top_act = th;
		    th = th->lower;
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
		if ((INKERNELSTACK(lastframe, th) && !INKERNELSTACK(frame, th))) continue;
		db_printf("Bad frame pointer: 0x%x\n", frame);
		break;
	    }
	}

    thread_done:
	if (trace_all_threads) {
	    if (top_act != THR_ACT_NULL)
		th = top_act;
	    th = (thread_act_t) queue_next(&th->thr_acts);
	    if (! queue_end(act_list, (queue_entry_t) th)) {
		db_printf("\n");
		addr = (db_expr_t) th;
		thcount++;
		goto next_thread;

	    }
	}
}
