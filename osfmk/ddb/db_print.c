/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

/*
 * Miscellaneous printing.
 */
#include <task_swapper.h>

#include <string.h>			/* For strlen() */
#include <mach/port.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/queue.h>
#include <kern/processor.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_pset.h>
#include <vm/vm_print.h>		/* for db_vm() */

#include <machine/db_machdep.h>
#include <machine/thread.h>

#include <ddb/db_lex.h>
#include <ddb/db_variables.h>
#include <ddb/db_sym.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>		/* For db_printf() */
#include <ddb/db_print.h>

#if	TASK_SWAPPER
#include <kern/task_swap.h>
#endif	/* TASK_SWAPPER */

/* Prototypes for functions local to this file.  XXX -- should be static!
 */

char *db_act_stat(
	register thread_act_t	thr_act,
	char	 		*status);

char *db_act_swap_stat(
	register thread_act_t	thr_act,
	char			*status);

void db_print_task(
	task_t	task,
	int	task_id,
	int	flag);

void db_reset_print_entry(
	void);

void db_print_one_entry(
	ipc_entry_t	entry,
	int		index,
	mach_port_name_t	name,
	boolean_t	is_pset,
	ipc_space_t	space);

int db_port_iterate(
	thread_act_t	thr_act,
	boolean_t	is_pset,
	boolean_t	do_output);

ipc_port_t db_lookup_port(
	thread_act_t	thr_act,
	int		id);

static void db_print_port_id(
	int		id,
	ipc_port_t	port,
	unsigned	bits,
	int		n);

void db_print_act(
	thread_act_t 	thr_act,
	int		act_id,
	int	 	flag);

void db_print_space(
	task_t	task,
	int	task_id,
	int	flag);

void db_print_task_vm(
	task_t		task,
	int		task_id,
	boolean_t	title,
	char		*modif);

void db_system_stats(void);


void
db_show_regs(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	register struct db_variable *regp;
	db_expr_t	value;
	db_addr_t	offset;
	char *		name;
	register int	i; 
	struct db_var_aux_param aux_param;
	task_t		task = TASK_NULL;

	aux_param.modif = modif;
	aux_param.thr_act = THR_ACT_NULL;
	if (db_option(modif, 't')) {
	    if (have_addr) {
		if (!db_check_act_address_valid((thread_act_t)addr))
		    return;
		aux_param.thr_act = (thread_act_t)addr;
	    } else
	        aux_param.thr_act = db_default_act;
	    if (aux_param.thr_act != THR_ACT_NULL)
		task = aux_param.thr_act->task;
	}
	for (regp = db_regs; regp < db_eregs; regp++) {
	    if (regp->max_level > 1) {
		db_printf("bad multi-suffixed register %s\n", regp->name);
		continue;
	    }
	    aux_param.level = regp->max_level;
	    for (i = regp->low; i <= regp->high; i++) {
		aux_param.suffix[0] = i;
	        db_read_write_variable(regp, &value, DB_VAR_GET, &aux_param);
		if (regp->max_level > 0)
		    db_printf("%s%d%*s", regp->name, i, 
				12-strlen(regp->name)-((i<10)?1:2), "");
		else
		    db_printf("%-12s", regp->name);
		db_printf("%#*llN", 2+2*sizeof(db_expr_t), value);
		db_find_xtrn_task_sym_and_offset((db_addr_t)value, &name, 
							&offset, task);
		if (name != 0 && offset <= db_maxoff && offset != value) {
		    db_printf("\t%s", name);
		    if (offset != 0)
			db_printf("+%#r", offset);
	    	}
		db_printf("\n");
	    }
	}
}

#define OPTION_LONG		0x001		/* long print option */
#define OPTION_USER		0x002		/* print ps-like stuff */
#define OPTION_INDENT		0x100		/* print with indent */
#define OPTION_THREAD_TITLE	0x200		/* print thread title */
#define OPTION_TASK_TITLE	0x400		/* print thread title */

#ifndef	DB_TASK_NAME
#define DB_TASK_NAME(task)			/* no task name */
#define DB_TASK_NAME_TITLE	""		/* no task name */
#endif	/* DB_TASK_NAME */

#ifndef	db_act_fp_used
#define db_act_fp_used(thr_act)	FALSE
#endif

char *
db_act_stat(
	register thread_act_t	thr_act,
	char	 		*status)
{
	register char *p = status;
	
	if (!thr_act->active) {
		*p++ = 'D',
		*p++ = 'y',
		*p++ = 'i',
		*p++ = 'n',
		*p++ = 'g';
		*p++ = ' ';
	} else if (!thr_act->thread) {
		*p++ = 'E',
		*p++ = 'm',
		*p++ = 'p',
		*p++ = 't',
		*p++ = 'y';
		*p++ = ' ';
	} else {
		thread_t athread = thr_act->thread;

		*p++ = (athread->state & TH_RUN)  ? 'R' : '.';
		*p++ = (athread->state & TH_WAIT) ? 'W' : '.';
		*p++ = (athread->state & TH_SUSP) ? 'S' : '.';
		*p++ = (athread->state & TH_STACK_HANDOFF) ? 'O' : '.';
		*p++ = (athread->state & TH_UNINT) ? 'N' : '.';
		/* show if the FPU has been used */
		*p++ = db_act_fp_used(thr_act) ? 'F' : '.';
	}
	*p++ = 0;
	return(status);
}

char *
db_act_swap_stat(
	register thread_act_t	thr_act,
	char			*status)
{
	register char *p = status;

#if	THREAD_SWAPPER
	switch (thr_act->swap_state & TH_SW_STATE) {
	    case TH_SW_UNSWAPPABLE:
		*p++ = 'U';
		break;
	    case TH_SW_IN:
		*p++ = 'I';
		break;
	    case TH_SW_GOING_OUT:
		*p++ = 'G';
		break;
	    case TH_SW_WANT_IN:
		*p++ = 'W';
		break;
	    case TH_SW_OUT:
		*p++ = 'O';
		break;
	    case TH_SW_COMING_IN:
		*p++ = 'C';
		break;
	    default:
		*p++ = '?';
		break;
	}
	*p++ = (thr_act->swap_state & TH_SW_TASK_SWAPPING) ? 'T' : '.';
#endif	/* THREAD_SWAPPER */
	*p++ = 0;

	return status;
}

char	*policy_list[] = { "TS", "RR", "??", "FF",
			   "??", "??", "??", "BE"};

void
db_print_act(
	thread_act_t 	thr_act,
	int		act_id,
	int		flag)
{
	thread_t athread;
	char status[8];
	char swap_status[3];
	char *indent = "";
	int	 policy;

	if (!thr_act) {
	    db_printf("db_print_act(NULL)!\n");
	    return;
	}

	athread = thr_act->thread;
	if (flag & OPTION_USER) {

	    if (flag & OPTION_LONG) {
		if (flag & OPTION_INDENT)
		    indent = "    ";
		if (flag & OPTION_THREAD_TITLE) {
		    db_printf("%s ID:   ACT     STAT  SW STACK    SHUTTLE", indent);
		    db_printf("  SUS  PRI  WAIT_FUNC\n");
		}
		policy = ((athread && (athread->sched_mode&TH_MODE_TIMESHARE))? 1: 2);
		db_printf("%s%3d%c %0*X %s %s %0*X %0*X %3d %3d/%s ",
		    indent, act_id,
		    (thr_act == current_act())? '#': ':',
		    2*sizeof(vm_offset_t), thr_act,
		    db_act_stat(thr_act, status),
		    db_act_swap_stat(thr_act, swap_status),
		    2*sizeof(vm_offset_t), (athread ?athread->kernel_stack:0),
		    2*sizeof(vm_offset_t), athread,
		    thr_act->suspend_count,
		    (athread ? athread->sched_pri : 999), /* XXX */
		    policy_list[policy-1]);
		if (athread) {
		    /* no longer TH_SWAP, no continuation to print */
		    if (athread->state & TH_WAIT)
			db_task_printsym((db_addr_t)athread->wait_event,
						DB_STGY_ANY, kernel_task);
		}
		db_printf("\n");
	    } else {
		if (act_id % 3 == 0) {
		    if (flag & OPTION_INDENT)
			db_printf("\n    ");
		} else
		    db_printf(" ");
		db_printf("%3d%c(%0*X,%s)", act_id, 
		    (thr_act == current_act())? '#': ':',
		    2*sizeof(vm_offset_t), thr_act,
		    db_act_stat(thr_act, status));
	    }
	} else {
	    if (flag & OPTION_INDENT)
		db_printf("            %3d (%0*X) ", act_id,
			  2*sizeof(vm_offset_t), thr_act);
	    else
		db_printf("(%0*X) ", 2*sizeof(vm_offset_t), thr_act);
	    if (athread) {
		db_printf("%c%c%c%c%c",
			(athread->state & TH_RUN)  ? 'R' : ' ',
			(athread->state & TH_WAIT) ? 'W' : ' ',
			(athread->state & TH_SUSP) ? 'S' : ' ',
			(athread->state & TH_UNINT)? 'N' : ' ',
			db_act_fp_used(thr_act) ? 'F' : ' ');
		/* Obsolete TH_STACK_HANDOFF code, left for now; might enhance
		 * to print out safe_points instead */
		if (athread->state & TH_STACK_HANDOFF) {
		    if (athread->continuation) {
			db_printf("(");
			db_task_printsym((db_addr_t)athread->continuation,
						DB_STGY_ANY, kernel_task);
			db_printf(")");
		    } else {
			db_printf("(handoff)");
		    }
		}
		if (athread->state & TH_WAIT) {
		    db_printf(" ");
		    db_task_printsym((db_addr_t)athread->wait_event,
						DB_STGY_ANY, kernel_task);
		}
	    } else
		db_printf("Empty");
	    db_printf("\n");
	}
}

void
db_print_task(
	task_t	task,
	int	task_id,
	int	flag)
{
	thread_act_t thr_act;
	int act_id;
	char sstate;

	if (flag & OPTION_USER) {
	    if (flag & OPTION_TASK_TITLE) {
		db_printf(" ID: TASK     MAP      THD RES SUS PR SW %s", 
			  DB_TASK_NAME_TITLE);
		if ((flag & OPTION_LONG) == 0)
		    db_printf("  ACTS");
		db_printf("\n");
	    }
#if	TASK_SWAPPER
	    switch ((int) task->swap_state) {
		case TASK_SW_IN:
		    sstate = 'I';
		    break;
		case TASK_SW_OUT:
		    sstate = 'O';
		    break;
		case TASK_SW_GOING_OUT:
		    sstate = 'G';
		    break;
		case TASK_SW_COMING_IN:
		    sstate = 'C';
		    break;
		case TASK_SW_UNSWAPPABLE:
		    sstate = 'U';
		    break;
		default:
		    sstate = '?';
		    break;
	    }
#else	/* TASK_SWAPPER */
	    sstate = 'I';
#endif	/* TASK_SWAPPER */
	    /*** ??? fix me ***/
	    db_printf("%3d: %0*X %0*X %3d %3d %3d %2d %c  ",
			    task_id, 2*sizeof(vm_offset_t), task,
			    2*sizeof(vm_offset_t), task->map,
			    task->thread_count, task->res_thread_count,
			    task->suspend_count,
			    task->priority,
			    sstate);
	    DB_TASK_NAME(task);
	    if (flag & OPTION_LONG) {
		if (flag & OPTION_TASK_TITLE)
		    flag |= OPTION_THREAD_TITLE;
		db_printf("\n");
	    } else if (task->thread_count <= 1)
		flag &= ~OPTION_INDENT;
	    act_id = 0;
	    queue_iterate(&task->threads, thr_act, thread_act_t, task_threads) {
		db_print_act(thr_act, act_id, flag);
		flag &= ~OPTION_THREAD_TITLE;
		act_id++;
	    }
	    if ((flag & OPTION_LONG) == 0)
		db_printf("\n");
	} else {
	    if (flag & OPTION_LONG) {
		if (flag & OPTION_TASK_TITLE) {
		    db_printf("    TASK        ACT\n");
		    if (task->thread_count > 1)
			flag |= OPTION_THREAD_TITLE;
		}
	    }
	    db_printf("%3d (%0*X): ", task_id, 2*sizeof(vm_offset_t), task);
	    if (task->thread_count == 0) {
		db_printf("no threads\n");
	    } else {
		if (task->thread_count > 1) {
		    db_printf("%d threads: \n", task->thread_count);
		    flag |= OPTION_INDENT;
		} else
		    flag &= ~OPTION_INDENT;
		act_id = 0;
		queue_iterate(&task->threads, thr_act,
			      thread_act_t, task_threads) {
		    db_print_act(thr_act, act_id++, flag);
		    flag &= ~OPTION_THREAD_TITLE;
		}
	    }
	}
}

void
db_print_space(
	task_t	task,
	int	task_id,
	int	flag)
{
	ipc_space_t space;
	thread_act_t act = (thread_act_t)queue_first(&task->threads);
	int count;

	count = 0;
	space = task->itk_space;
	if (act)
		count = db_port_iterate(act, FALSE, FALSE);
	db_printf("%3d: %08x %08x %08x %sactive   %d\n",
		  task_id, task, space, task->map,
		  space->is_active? "":"!", count);
}

void
db_print_task_vm(
	task_t		task,
	int		task_id,
	boolean_t	title,
	char		*modif)
{
	vm_map_t	map;
	pmap_t		pmap;
	vm_size_t	size;
	long		resident;
	long		wired;

	if (title) {
		db_printf("id     task      map     pmap  virtual  rss pg rss mem  wir pg wir mem\n");
	}

	map = task->map;
	pmap = vm_map_pmap(map);

	size = db_vm_map_total_size(map);
	resident = pmap->stats.resident_count;
	wired = pmap->stats.wired_count;

	db_printf("%2d %08x %08x %08x %7dK  %6d %6dK  %6d %6dK\n",
		task_id,
		task,
		map,
		pmap,
		size / 1024,
		resident, (resident * PAGE_SIZE) / 1024,
		wired, (wired * PAGE_SIZE) / 1024);
}


void
db_show_one_task_vm(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	thread_act_t	thread;
	task_t		task;
	int		task_id;

	if (have_addr == FALSE) {
		if ((thread = db_default_act) == THR_ACT_NULL) {
			if ((thread = current_act()) == THR_ACT_NULL) {
				db_printf("no thread.\n");
				return;
			}
		}
		task = thread->task;
	} else {
		task = (task_t) addr;
	}

	task_id = db_lookup_task(task);
	if (task_id < 0) {
		db_printf("0x%x is not a task_t\n", addr);
		return;
	}

	db_print_task_vm(task, task_id, TRUE, modif);
}

void
db_show_all_task_vm(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	task_t		task;
	int		task_id;
	boolean_t	title = TRUE;
	processor_set_t	pset = &default_pset;

	task_id = 0;
	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		db_print_task_vm(task, task_id, title, modif);
		title = FALSE;
		task_id++;
	}
}

void
db_show_all_acts(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	task_t task;
	int task_id;
	int flag;
	processor_set_t pset = &default_pset;

	flag = OPTION_TASK_TITLE|OPTION_INDENT;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	task_id = 0;
	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		db_print_task(task, task_id, flag);
		flag &= ~OPTION_TASK_TITLE;
		task_id++;
		if ((flag & (OPTION_LONG|OPTION_INDENT)) == OPTION_INDENT)
		    db_printf("\n");
	}
}

void
db_show_one_space(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	int		flag;
	int		task_id;
	task_t		task;

	flag = OPTION_TASK_TITLE;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	if (!have_addr) {
	    task = db_current_task();
	    if (task == TASK_NULL) {
		db_error("No task\n");
		/*NOTREACHED*/
	    }
	} else
	    task = (task_t) addr;

	if ((task_id = db_lookup_task(task)) < 0) {
	    db_printf("bad task address 0x%x\n", addr);
	    db_error(0);
	    /*NOTREACHED*/
	}

	db_printf(" ID: TASK     SPACE    MAP               COUNT\n");
	db_print_space(task, task_id, flag);
}

void
db_show_all_spaces(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	task_t task;
	int task_id = 0;
	int flag;
	processor_set_t pset = &default_pset;

	flag = OPTION_TASK_TITLE|OPTION_INDENT;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	db_printf(" ID: TASK     SPACE    MAP               COUNT\n");
	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		db_print_space(task, task_id, flag);
		task_id++;
	}
}

db_addr_t
db_task_from_space(
	ipc_space_t	space,
	int		*task_id)
{
	task_t task;
	int tid = 0;
	processor_set_t pset = &default_pset;

	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		if (task->itk_space == space) {
			*task_id = tid;
			return (db_addr_t)task;
		}
		tid++;
	}
	*task_id = 0;
	return (0);
}

void
db_show_one_act(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	int		flag;
	int		act_id;
	thread_act_t		thr_act;

	flag = OPTION_THREAD_TITLE;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	if (!have_addr) {
	    thr_act = current_act();
	    if (thr_act == THR_ACT_NULL) {
		db_error("No thr_act\n");
		/*NOTREACHED*/
	    }
	} else
	    thr_act = (thread_act_t) addr;

	if ((act_id = db_lookup_act(thr_act)) < 0) {
	    db_printf("bad thr_act address %#llX\n", addr);
	    db_error(0);
	    /*NOTREACHED*/
	}

	if (flag & OPTION_USER) {
	    db_printf("TASK%d(%0*X):\n",
		      db_lookup_task(thr_act->task),
		      2*sizeof(vm_offset_t), thr_act->task);
	    db_print_act(thr_act, act_id, flag);
	} else {
	    db_printf("task %d(%0*Xx): thr_act    %d",
		      db_lookup_task(thr_act->task),
		      2*sizeof(vm_offset_t), thr_act->task, act_id);
	    db_print_act(thr_act, act_id, flag);
	}
	if (db_option(modif, 'i') &&  thr_act->thread &&
	    (thr_act->thread->state & TH_WAIT) && 
	    thr_act->thread->kernel_stack == 0) {

	    db_printf("Wait State: option 0x%x\n",
		thr_act->thread->ith_option);
	}
}

void
db_show_one_task(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	int		flag;
	int		task_id;
	task_t		task;

	flag = OPTION_TASK_TITLE|OPTION_INDENT;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	if (!have_addr) {
	    task = db_current_task();
	    if (task == TASK_NULL) {
		db_error("No task\n");
		/*NOTREACHED*/
	    }
	} else
	    task = (task_t) addr;

	if ((task_id = db_lookup_task(task)) < 0) {
	    db_printf("bad task address 0x%llX\n", addr);
	    db_error(0);
	    /*NOTREACHED*/
	}

	db_print_task(task, task_id, flag);
}

void
db_show_shuttle(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	thread_t			shuttle;
	thread_act_t		thr_act;

	if (have_addr)
	    shuttle = (thread_t) addr;
	else {
	    thr_act = current_act();
	    if (thr_act == THR_ACT_NULL) {
		db_error("No thr_act\n");
		/*NOTREACHED*/
	    }
	    shuttle = thr_act->thread;
	    if (shuttle == THREAD_NULL) {
		db_error("No shuttle associated with current thr_act\n");
		/*NOTREACHED*/
	    }
	}
	db_printf("shuttle %x:\n", shuttle);
	if (shuttle->top_act == THR_ACT_NULL)
	    db_printf("  no activations\n");
	else {
	    db_printf("  activations:");
	    for (thr_act = shuttle->top_act; thr_act != THR_ACT_NULL;
		 thr_act = thr_act->lower) {
		if (thr_act != shuttle->top_act)
		    printf(" from");
		printf(" $task%d.%d(%x)", db_lookup_task(thr_act->task),
		       db_lookup_act(thr_act), thr_act);
	    }
	    db_printf("\n");
	}
}

int
db_port_kmsg_count(
	ipc_port_t	port)
{
	return (port->ip_messages.imq_msgcount);
}

static int db_print_ent_cnt = 0;

void db_reset_print_entry(
	void)
{
	db_print_ent_cnt = 0;
}

void
db_print_one_entry(
	ipc_entry_t		entry,
	int			index,
	mach_port_name_t	name,
	boolean_t		is_pset,
	ipc_space_t		space)
{
	ipc_port_t aport = (ipc_port_t)entry->ie_object;
	ipc_entry_bits_t bits;

	bits = entry->ie_bits;
	if (is_pset && !aport->ip_pset_count)
		return;
	if (db_print_ent_cnt && db_print_ent_cnt % 2 == 0)
		db_printf("\n");
	if (!name)
		db_printf("\t%s%d[%x]",
			!is_pset && aport->ip_pset_count ? "pset" : "port",
			index,
			MACH_PORT_MAKE(index, IE_BITS_GEN(bits)));
	else
		db_printf("\t%s[%x]",
			!is_pset && aport->ip_pset_count ? "pset" : "port",
			name);
	if (!is_pset) {
		db_printf("(%s,%x,%d)",
		    (bits & MACH_PORT_TYPE_RECEIVE)? "r":
		    	(bits & MACH_PORT_TYPE_SEND)? "s": "S",
			aport,
		    db_port_kmsg_count(aport));
		db_print_ent_cnt++;
	}
	else {
		db_printf("(%s,%x,set_count=%d,%d)",
			(bits & MACH_PORT_TYPE_RECEIVE)? "r":
				(bits & MACH_PORT_TYPE_SEND)? "s": "S",
			aport,
			aport->ip_pset_count,
			db_port_kmsg_count(aport));
		db_print_ent_cnt++;
	}
}

int
db_port_iterate(
	thread_act_t	thr_act,
	boolean_t	is_pset,
	boolean_t	do_output)
{
	ipc_entry_t entry;
	ipc_tree_entry_t tentry;
	int index;
	int size;
	int count;
	ipc_space_t space;

	count = 0;
	space = thr_act->task->itk_space;
	entry = space->is_table;
	size = space->is_table_size;
	db_reset_print_entry();
	for (index = 0; index < size; ++index, ++entry) {
		if (entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) {
			if (do_output)
				db_print_one_entry(entry,
					index, MACH_PORT_NULL, is_pset, space);
			++count;
		}
	}
	for (tentry = ipc_splay_traverse_start(&space->is_tree);
		tentry != ITE_NULL;
		tentry = ipc_splay_traverse_next(&space->is_tree, FALSE)) {
		entry = &tentry->ite_entry;
		if (entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) {
			if (do_output)
				db_print_one_entry(entry,
					0, tentry->ite_name, is_pset, space);
			++count;
		}
	}
	return (count);
}

ipc_port_t
db_lookup_port(
	thread_act_t	thr_act,
	int		id)
{
	register ipc_space_t space;
	register ipc_entry_t entry;

	if (thr_act == THR_ACT_NULL)
	    return(0);
	space = thr_act->task->itk_space;
	if (id < 0 || id >= space->is_table_size)
	    return(0);
	entry = &space->is_table[id];
	if (entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS)
	    return((ipc_port_t)entry->ie_object);
	return(0);
}

static void
db_print_port_id(
	int		id,
	ipc_port_t	port,
	unsigned	bits,
	int		n)
{
	if (n != 0 && n % 3 == 0)
	    db_printf("\n");
	db_printf("\tport%d(%s,%x)", id,
		(bits & MACH_PORT_TYPE_RECEIVE)? "r":
		(bits & MACH_PORT_TYPE_SEND)? "s": "S", port);
}

void
db_show_port_id(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	thread_act_t thr_act;

	if (!have_addr) {
	    thr_act = current_act();
	    if (thr_act == THR_ACT_NULL) {
		db_error("No thr_act\n");
		/*NOTREACHED*/
	    }
	} else
	    thr_act = (thread_act_t) addr;
	if (db_lookup_act(thr_act) < 0) {
	    db_printf("Bad thr_act address 0x%llX\n", addr);
	    db_error(0);
	    /*NOTREACHED*/
	}
	if (db_port_iterate(thr_act, db_option(modif,'s'), TRUE))
	    db_printf("\n");
}

/*
 *	Useful system state when the world has hung.
 */
void
db_system_stats()
{
	extern void	db_sched(void);

	db_sched();
	iprintf("\n");
	db_vm();
	iprintf("\n");
	iprintf("\n");
	db_printf("current_{thread/task} 0x%x 0x%x\n",
			current_thread(),current_task());
}

void db_show_one_runq(run_queue_t runq);

void
db_show_runq(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	processor_set_t pset = &default_pset;
	processor_t proc;
	run_queue_t runq;
	boolean_t showedany = FALSE;

#if NCPUS > 1	/* This code has not been tested. */
	queue_iterate(&pset->processors, proc, processor_t, processors) {
		runq = &proc->runq;
		if (runq->count > 0) {
		    db_printf("PROCESSOR %x IN SET %x\n", proc, pset);
		    db_show_one_runq(runq);
		    showedany = TRUE;
		}
	}
#endif	/* NCPUS > 1 */
#ifndef NCPUS
#error NCPUS undefined
#endif
	runq = &pset->runq;
	if (runq->count > 0) {
		db_printf("PROCESSOR SET %x\n", pset);
		db_show_one_runq(runq);
		showedany = TRUE;
	}
	if (!showedany)
	    db_printf("No runnable threads\n");
}

void
db_show_one_runq(
	run_queue_t	runq)
{
	int i, task_id, thr_act_id;
	queue_t q;
	thread_act_t thr_act;
	thread_t thread;
	task_t task;

	printf("PRI  TASK.ACTIVATION\n");
	for (i = runq->highq, q = runq->queues + i; i >= 0; i--, q--) {
	    if (!queue_empty(q)) {
		db_printf("%3d:", i);
		queue_iterate(q, thread, thread_t, links) {
		    thr_act = thread->top_act;
		    task = thr_act->task;
		    task_id = db_lookup_task(task);
		    thr_act_id = db_lookup_task_act(task, thr_act);
		    db_printf(" %d.%d", task_id, thr_act_id);
		}
		db_printf("\n");
	    }
	}
}
