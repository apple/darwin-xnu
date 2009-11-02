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

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <machine/db_machdep.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_expr.h>
#include <ddb/db_lex.h>
#include <ddb/db_output.h>		/* For db_printf() */
#include <ddb/db_sym.h>

/*
 * Following constants are used to prevent infinite loop of task
 * or thread search due to the incorrect list.
 */
#define	DB_MAX_TASKID	0x10000		/* max # of tasks */
#define DB_MAX_THREADID	0x10000		/* max # of threads in a task */
#define DB_MAX_PSETS	0x10000		/* max # of processor sets */

task_t		db_default_task;	/* default target task */
thread_t	db_default_act;		/* default target thr_act */



/* Prototypes for functions local to this file.
 */
task_t db_lookup_task_id(register int task_id);

static thread_t db_lookup_act_id(
	task_t	 task,
	register int thread_id);



/*
 * search valid task queue, and return the queue position as the task id
 */
int
db_lookup_task(task_t target_task)
{
	register task_t task;
	register int task_id;
	register processor_set_t pset = &default_pset;
	register int npset = 0;

	task_id = 0;
	if (npset++ >= DB_MAX_PSETS)
		return(-1);
	if (queue_first(&pset->tasks) == 0)
		return(-1);
	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		if (target_task == task)
		    return(task_id);
		if (task_id++ >= DB_MAX_TASKID)
		    return(-1);
	}
	return(-1);
}

/*
 * search thread queue of the task, and return the queue position
 */
int
db_lookup_task_act(
	task_t		task,
	thread_t	target_act)
{
	register thread_t thr_act;
	register int act_id;

	act_id = 0;
	if (queue_first(&task->threads) == 0)
	    return(-1);
	queue_iterate(&task->threads, thr_act, thread_t, task_threads) {
	    if (target_act == thr_act)
		return(act_id);
	    if (act_id++ >= DB_MAX_THREADID)
		return(-1);
	}
	return(-1);
}

/*
 * search thr_act queue of every valid task, and return the queue position
 * as the thread id.
 */
int
db_lookup_act(thread_t target_act)
{
	register int act_id;
	register task_t task;
	register processor_set_t pset = &default_pset;
	register int ntask = 0;
	register int npset = 0;

	if (npset++ >= DB_MAX_PSETS)
		return(-1);
	if (queue_first(&pset->tasks) == 0)
		return(-1);
	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		if (ntask++ > DB_MAX_TASKID)
		    return(-1);
		if (task->thread_count == 0)
		    continue;
		act_id = db_lookup_task_act(task, target_act);
		if (act_id >= 0)
		    return(act_id);
	}
	return(-1);
}

/*
 * check the address is a valid thread address
 */
int force_act_lookup = 0;
boolean_t
db_check_act_address_valid(thread_t thr_act)
{
	if (!force_act_lookup && db_lookup_act(thr_act) < 0) {
	    db_printf("Bad thr_act address 0x%x\n", thr_act);
	    db_flush_lex();
	    return(FALSE);
	} else
	    return(TRUE);
}

/*
 * convert task_id(queue postion) to task address
 */
task_t
db_lookup_task_id(register task_id)
{
	register task_t task;
	register processor_set_t pset = &default_pset;
	register int npset = 0;

	if (task_id > DB_MAX_TASKID)
	    return(TASK_NULL);
	if (npset++ >= DB_MAX_PSETS)
		return(TASK_NULL);
	if (queue_first(&pset->tasks) == 0)
		return(TASK_NULL);
	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		if (task_id-- <= 0)
			return(task);
	}
	return(TASK_NULL);
}

/*
 * convert (task_id, act_id) pair to thr_act address
 */
static thread_t
db_lookup_act_id(
	task_t	 task,
	register int act_id)
{
	register thread_t thr_act;

	
	if (act_id > DB_MAX_THREADID)
	    return(THREAD_NULL);
	if (queue_first(&task->threads) == 0)
	    return(THREAD_NULL);
	queue_iterate(&task->threads, thr_act, thread_t, task_threads) {
	    if (act_id-- <= 0)
		return(thr_act);
	}
	return(THREAD_NULL);
}

/*
 * get next parameter from a command line, and check it as a valid
 * thread address
 */
boolean_t
db_get_next_act(
	thread_t	*actp,
	int		position)
{
	db_expr_t	value;
	thread_t	thr_act;

	*actp = THREAD_NULL;
	if (db_expression(&value)) {
	    thr_act = (thread_t) value;
	    if (!db_check_act_address_valid(thr_act)) {
		db_flush_lex();
		return(FALSE);
	    }
	} else if (position <= 0) {
	    thr_act = db_default_act;
	} else
	    return(FALSE);
	*actp = thr_act;
	return(TRUE);
}

/*
 * check the default thread is still valid
 *	( it is called in entering DDB session )
 */
void
db_init_default_act(void)
{
	if (db_lookup_act(db_default_act) < 0) {
	    db_default_act = THREAD_NULL;
	    db_default_task = TASK_NULL;
	} else
	    db_default_task = db_default_act->task;
}

/*
 * set or get default thread which is used when /t or :t option is specified
 * in the command line
 */
int
db_set_default_act(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap)			/* unused */
{
	thread_t	thr_act;
	int		task_id;
	int		act_id;

	if (flag == DB_VAR_SHOW) {
	    db_printf("%#n", db_default_act);
	    task_id = db_lookup_task(db_default_task);
	    if (task_id != -1) {
		act_id = db_lookup_act(db_default_act);
		if (act_id != -1) {
		    db_printf(" (task%d.%d)", task_id, act_id);
		}
	    }
	    return(0);
	}

	if (flag != DB_VAR_SET) {
	    *valuep = (db_expr_t) db_default_act;
	    return(0);
	}
	thr_act = (thread_t) *valuep;
	if (thr_act != THREAD_NULL && !db_check_act_address_valid(thr_act))
	    db_error(0);
	    /* NOTREACHED */
	db_default_act = thr_act;
	if (thr_act)
		db_default_task = thr_act->task;
	return(0);
}

/*
 * convert $taskXXX[.YYY] type DDB variable to task or thread address
 */
int
db_get_task_act(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap)
{
	task_t	 		task;
	thread_t		thr_act;
	int	 		task_id;

	if (flag == DB_VAR_SHOW) {
	    db_printf("%#n", db_default_task);
	    task_id = db_lookup_task(db_default_task);
	    if (task_id != -1)
		db_printf(" (task%d)", task_id);
	    return(0);
	}

	if (flag != DB_VAR_GET) {
	    db_error("Cannot set to $task variable\n");
	    /* NOTREACHED */
	}
	if ((task = db_lookup_task_id(ap->suffix[0])) == TASK_NULL) {
	    db_printf("no such task($task%d)\n", ap->suffix[0]);
	    db_error(0);
	    /* NOTREACHED */
	}
	if (ap->level <= 1) {
	    *valuep = (db_expr_t) task;
	    return(0);
	}
	if ((thr_act = db_lookup_act_id(task, ap->suffix[1])) == THREAD_NULL){
	    db_printf("no such thr_act($task%d.%d)\n", 
					ap->suffix[0], ap->suffix[1]);
	    db_error(0);
	    /* NOTREACHED */
	}
	*valuep = (db_expr_t) thr_act;
	return(0);
}
