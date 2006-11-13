/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#ifndef _DDB_DB_TASK_THREAD_H_
#define _DDB_DB_TASK_THREAD_H_

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <ddb/db_variables.h>		/* For db_var_aux_param_t */

/*
 * On behalf of kernel-loaded tasks, distinguish between current task
 * (=> symbol table) and current address space (=> where [e.g.]
 * breakpoints are set).  From ddb's perspective, kernel-loaded tasks
 * can retain their own symbol tables, but share the kernel's address
 * space.
 */
#define db_current_task()						\
		((current_thread())? current_thread()->task: TASK_NULL)
#define db_current_space()						\
		((current_thread())?\
			current_thread()->task: TASK_NULL)
#define db_target_space(thr_act, user_space)				\
		((!(user_space) || ((thr_act)))?\
			TASK_NULL:					\
			(thr_act)? 					\
				(thr_act)->task: db_current_space())
#define db_is_current_space(task) 					\
		((task) == TASK_NULL || (task) == db_current_space())

extern task_t		db_default_task;	/* default target task */
extern thread_t	db_default_act;		/* default target thr_act */


/* Prototypes for functions exported by this module.
 */

int db_lookup_act(thread_t target_act);

int db_lookup_task(task_t target_task);

int db_lookup_task_act(
	task_t		task,
	thread_t		target_act);

boolean_t db_check_act_address_valid(thread_t thr_act);

boolean_t db_get_next_act(
	thread_t		*actp,
	int		position);

void db_init_default_act(void);

int db_set_default_act(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap);

int db_get_task_act(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap);

#endif  /* !_DDB_DB_TASK_THREAD_H_ */
