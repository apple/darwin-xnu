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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.9.1  1994/09/23  01:22:09  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:11:13  ezf]
 *
 * Revision 1.1.7.4  1994/03/17  22:35:38  dwm
 * 	The infamous name change:  thread_activation + thread_shuttle = thread.
 * 	[1994/03/17  21:25:53  dwm]
 * 
 * Revision 1.1.7.3  1994/02/03  21:44:27  bolinger
 * 	Change a surviving current_thread() to current_act().
 * 	[1994/02/03  20:48:03  bolinger]
 * 
 * Revision 1.1.7.2  1994/01/12  17:50:56  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	[1994/01/12  17:13:27  dwm]
 * 
 * Revision 1.1.7.1  1994/01/05  19:28:18  bolinger
 * 	Separate notions of "address space" and "task" (i.e., symbol table),
 * 	via new macros db_current_space() and db_is_current_space(); also update
 * 	db_target_space() to treat kernel-loaded tasks correctly.
 * 	[1994/01/04  17:41:47  bolinger]
 * 
 * Revision 1.1.2.4  1993/07/27  18:28:17  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:13:10  elliston]
 * 
 * Revision 1.1.2.3  1993/06/07  22:06:58  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  18:57:35  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:12:46  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:57:32  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:24:23  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.2  91/10/09  16:03:18  af
 * 	 Revision 2.1.3.1  91/10/05  13:08:07  jeffreyh
 * 	 	Created for task/thread handling.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.1.3.1  91/10/05  13:08:07  jeffreyh
 * 	Created for task/thread handling.
 * 	[91/08/29            tak]
 * 
 */
/* CMU_ENDHIST */
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
		((current_act())? current_act()->task: TASK_NULL)
#define db_current_space()						\
		((current_act() && !current_act()->kernel_loaded)?\
			current_act()->task: TASK_NULL)
#define db_target_space(thr_act, user_space)				\
		((!(user_space) || ((thr_act) && (thr_act)->kernel_loaded))?\
			TASK_NULL:					\
			(thr_act)? 					\
				(thr_act)->task: db_current_space())
#define db_is_current_space(task) 					\
		((task) == TASK_NULL || (task) == db_current_space())

extern task_t		db_default_task;	/* default target task */
extern thread_act_t	db_default_act;		/* default target thr_act */


/* Prototypes for functions exported by this module.
 */

int db_lookup_act(thread_act_t target_act);

int db_lookup_task(task_t target_task);

int db_lookup_task_act(
	task_t		task,
	thread_act_t		target_act);

boolean_t db_check_act_address_valid(thread_act_t thr_act);

boolean_t db_get_next_act(
	thread_act_t		*actp,
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
