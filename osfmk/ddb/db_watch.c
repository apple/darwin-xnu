/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 * 	Author: Richard P. Draves, Carnegie Mellon University
 *	Date:	10/90
 */

#include <mach/boolean.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_types.h>
#include <mach/machine/vm_param.h>
#include <vm/vm_map.h>

#include <machine/db_machdep.h>
#include <ddb/db_lex.h>
#include <ddb/db_watch.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_command.h>
#include <ddb/db_expr.h>
#include <ddb/db_output.h>		/* For db_printf() */
#include <ddb/db_run.h>			/* For db_single_step() */

/*
 * Watchpoints.
 */

boolean_t	db_watchpoints_inserted = TRUE;

#define	NWATCHPOINTS	100
struct db_watchpoint	db_watch_table[NWATCHPOINTS];
db_watchpoint_t		db_next_free_watchpoint = &db_watch_table[0];
db_watchpoint_t		db_free_watchpoints = 0;
db_watchpoint_t		db_watchpoint_list = 0;

extern vm_map_t		kernel_map;



/* Prototypes for functions local to this file.  XXX -- should be static.
 */

db_watchpoint_t db_watchpoint_alloc(void);

void db_watchpoint_free(register db_watchpoint_t watch);

void db_set_watchpoint(
	task_t		task,
	db_addr_t	addr,
	vm_size_t	size);

void db_delete_watchpoint(
	task_t		task,
	db_addr_t	addr);

static int db_get_task(
	char		*modif,
	task_t		*taskp,
	db_addr_t	addr);

void db_list_watchpoints(void);



db_watchpoint_t
db_watchpoint_alloc(void)
{
	register db_watchpoint_t	watch;

	if ((watch = db_free_watchpoints) != 0) {
	    db_free_watchpoints = watch->link;
	    return (watch);
	}
	if (db_next_free_watchpoint == &db_watch_table[NWATCHPOINTS]) {
	    db_printf("All watchpoints used.\n");
	    return (0);
	}
	watch = db_next_free_watchpoint;
	db_next_free_watchpoint++;

	return (watch);
}

void
db_watchpoint_free(register db_watchpoint_t watch)
{
	watch->link = db_free_watchpoints;
	db_free_watchpoints = watch;
}

void
db_set_watchpoint(
	task_t		task,
	db_addr_t	addr,
	vm_size_t	size)
{
	register db_watchpoint_t	watch;

	/*
	 *	Should we do anything fancy with overlapping regions?
	 */

	for (watch = db_watchpoint_list; watch != 0; watch = watch->link) {
	    if (watch->task == task &&
		(watch->loaddr == addr) &&
		(watch->hiaddr == addr+size)) {
		db_printf("Already set.\n");
		return;
	    }
	}

	watch = db_watchpoint_alloc();
	if (watch == 0) {
	    db_printf("Too many watchpoints.\n");
	    return;
	}

	watch->task = task;
	watch->loaddr = addr;
	watch->hiaddr = addr+size;

	watch->link = db_watchpoint_list;
	db_watchpoint_list = watch;

	db_watchpoints_inserted = FALSE;
}

void
db_delete_watchpoint(
	task_t		task,
	db_addr_t	addr)
{
	register db_watchpoint_t	watch;
	register db_watchpoint_t	*prev;

	for (prev = &db_watchpoint_list; (watch = *prev) != 0;
	     prev = &watch->link) {
	    if (watch->task == task &&
		(watch->loaddr <= addr) &&
		(addr < watch->hiaddr)) {
		*prev = watch->link;
		db_watchpoint_free(watch);
		return;
	    }
	}

	db_printf("Not set.\n");
}

void
db_list_watchpoints(void)
{
	register db_watchpoint_t watch;
	int	 task_id;

	if (db_watchpoint_list == 0) {
	    db_printf("No watchpoints set\n");
	    return;
	}

	db_printf("Space      Address  Size\n");
	for (watch = db_watchpoint_list; watch != 0; watch = watch->link)  {
	    if (watch->task == TASK_NULL)
		db_printf("kernel  ");
	    else {
		task_id = db_lookup_task(watch->task);
		if (task_id < 0)
		    db_printf("%*X", 2*sizeof(vm_offset_t), watch->task);
		else
		    db_printf("task%-3d ", task_id);
	    }
	    db_printf("  %*X  %X\n", 2*sizeof(vm_offset_t), watch->loaddr,
		      watch->hiaddr - watch->loaddr);
	}
}

static int
db_get_task(
	char		*modif,
	task_t		*taskp,
	db_addr_t	addr)
{
	task_t		task = TASK_NULL;
	db_expr_t	value;
	boolean_t	user_space;

	user_space = db_option(modif, 'T');
	if (user_space) {
	    if (db_expression(&value)) {
		task = (task_t)(unsigned long)value;
		if (db_lookup_task(task) < 0) {
		    db_printf("bad task address %X\n", task);
		    return(-1);
		}
	    } else {
		task = db_default_task;
		if (task == TASK_NULL) {
		    if ((task = db_current_task()) == TASK_NULL) {
			db_printf("no task\n");
			return(-1);
		    }
		}
	    }
	}
	if (!DB_VALID_ADDRESS(addr, user_space)) {
	    db_printf("Address %#X is not in %s space\n", addr, 
			(user_space)? "user": "kernel");
	    return(-1);
	}
	*taskp = task;
	return(0);
}

/* Delete watchpoint */
void
db_deletewatch_cmd(db_expr_t addr, __unused boolean_t have_addr,
		   __unused db_expr_t count, char *modif)
{
	task_t		task;

	if (db_get_task(modif, &task, addr) < 0)
	    return;
	db_delete_watchpoint(task, addr);
}

/* Set watchpoint */
void
db_watchpoint_cmd(db_expr_t addr, __unused boolean_t have_addr,
		  __unused db_expr_t count, char *modif)
{
	vm_size_t	size;
	db_expr_t	value;
	task_t		task;

	if (db_get_task(modif, &task, addr) < 0)
	    return;
	if (db_expression(&value))
	    size = (vm_size_t) value;
	else
	    size = sizeof(int);
	db_set_watchpoint(task, addr, size);
}

/* list watchpoints */
void
db_listwatch_cmd(__unused db_expr_t addr, __unused boolean_t have_addr,
		 __unused db_expr_t count, __unused char *modif)
{
	db_list_watchpoints();
}

void
db_set_watchpoints(void)
{
	register db_watchpoint_t	watch;
	vm_map_t			map;

	if (!db_watchpoints_inserted) {
	    for (watch = db_watchpoint_list; watch != 0; watch = watch->link) {
		map = (watch->task)? watch->task->map: kernel_map;
		pmap_protect(map->pmap,
			     vm_map_trunc_page(watch->loaddr),
			     vm_map_round_page(watch->hiaddr),
			     VM_PROT_READ);
	    }
	    db_watchpoints_inserted = TRUE;
	}
}

void
db_clear_watchpoints(void)
{
	db_watchpoints_inserted = FALSE;
}

boolean_t
db_find_watchpoint(
	vm_map_t	map,
	db_addr_t	addr,
	db_regs_t	*regs)
{
	register db_watchpoint_t watch;
	db_watchpoint_t found = 0;
	register task_t	task_space;

	task_space = (vm_map_pmap(map) == kernel_pmap)?
		TASK_NULL: db_current_space();
	for (watch = db_watchpoint_list; watch != 0; watch = watch->link) {
	    if (watch->task == task_space) {
		if ((watch->loaddr <= addr) && (addr < watch->hiaddr))
		    return (TRUE);
		else if ((trunc_page(watch->loaddr) <= addr) &&
			 (addr < round_page(watch->hiaddr)))
		    found = watch;
	    }
	}

	/*
	 *	We didn't hit exactly on a watchpoint, but we are
	 *	in a protected region.  We want to single-step
	 *	and then re-protect.
	 */

	if (found) {
	    db_watchpoints_inserted = FALSE;
	    db_single_step(regs, task_space);
	}

	return (FALSE);
}
