/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

/*
 * Trap entry point to kernel debugger.
 */
#include <mach/boolean.h>
#include <machine/db_machdep.h>
#include <kern/misc_protos.h>
#include <ddb/db_access.h>
#include <ddb/db_break.h>
#include <ddb/db_command.h>
#include <ddb/db_examine.h>
#include <ddb/db_output.h>             /* For db_printf() */
#include <ddb/db_run.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_trap.h>
#include <machine/setjmp.h>

extern jmp_buf_t *db_recover;

extern int		db_inst_count;
extern int		db_load_count;
extern int		db_store_count;

void
db_task_trap(
	int		type,
	int		code,
	boolean_t	user_space)
{
	jmp_buf_t db_jmpbuf;
	jmp_buf_t *prev;
	boolean_t	bkpt;
	boolean_t	watchpt;
	task_t		task;
	task_t		task_space;

	task = db_current_task();
	task_space = db_target_space(current_thread(), user_space);
	bkpt = IS_BREAKPOINT_TRAP(type, code);
	watchpt = IS_WATCHPOINT_TRAP(type, code);

	/*
	 * Note:  we look up PC values in an address space (task_space),
	 * but print symbols using a (task-specific) symbol table, found
	 * using task.
	 */

	/* Elided since walking the thread/task lists before setting up
	 * safe recovery points is incorrect, and could
	 * potentially cause us to loop and fault indefinitely.
	 */
#if 0	
	db_init_default_act();
#endif       
	db_check_breakpoint_valid();

	if (db_stop_at_pc(&bkpt, task, task_space)) {
	    if (db_inst_count) {
		db_printf("After %d instructions (%d loads, %d stores),\n",
			  db_inst_count, db_load_count, db_store_count);
	    }
	    if (bkpt)
		db_printf("Breakpoint at  ");
	    else if (watchpt)
		db_printf("Watchpoint at  ");
	    else
		db_printf("Stopped at  ");
	    db_dot = PC_REGS(DDB_REGS);

	    prev = db_recover;
	    if (_setjmp(db_recover = &db_jmpbuf) == 0) {
#if defined(__alpha)
		db_print_loc(db_dot, task_space);
		db_printf("\n\t");
		db_print_inst(db_dot, task_space);
#else /* !defined(__alpha) */
#if defined(__ppc__)
		db_print_loc_and_inst(db_dot, task_space);
#else	/* __ppc__ */
		db_print_loc_and_inst(db_dot, task);
#endif	/* __ppc__ */
#endif /* defined(__alpha) */
	    } else
		db_printf("Trouble printing location %#llX.\n", (unsigned long long)db_dot);
	    db_recover = prev;

	    db_command_loop();
	}

	db_restart_at_pc(watchpt, task_space);
}
