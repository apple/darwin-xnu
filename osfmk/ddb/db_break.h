/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:47  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.18.3  1995/01/06  19:10:05  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup, prototypes.
 * 	[1994/10/14  03:39:52  dwm]
 *
 * Revision 1.1.18.2  1994/09/23  01:18:04  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:09:24  ezf]
 * 
 * Revision 1.1.18.1  1994/06/11  21:11:29  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/11  20:03:39  bolinger]
 * 
 * Revision 1.1.16.1  1994/04/11  09:34:32  bernadat
 * 	Moved db_breakpoint struct declaration from db_break.c
 * 	to here.
 * 	[94/03/16            bernadat]
 * 
 * Revision 1.1.12.2  1994/03/17  22:35:24  dwm
 * 	The infamous name change:  thread_activation + thread_shuttle = thread.
 * 	[1994/03/17  21:25:41  dwm]
 * 
 * Revision 1.1.12.1  1994/01/12  17:50:30  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	[1994/01/12  17:13:00  dwm]
 * 
 * Revision 1.1.4.4  1993/07/27  18:26:51  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:10:59  elliston]
 * 
 * Revision 1.1.4.3  1993/06/07  22:06:31  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  18:57:06  jeffc]
 * 
 * Revision 1.1.4.2  1993/06/02  23:10:21  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:55:49  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:24:12  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.6  91/10/09  15:58:03  af
 * 	 Revision 2.5.3.1  91/10/05  13:05:04  jeffreyh
 * 	 	Added db_thread_breakpoint structure, and added task and threads
 * 	 	field to db_breakpoint structure.  Some status flags were also
 * 	 	added to keep track user space break point correctly.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.5.3.1  91/10/05  13:05:04  jeffreyh
 * 	Added db_thread_breakpoint structure, and added task and threads
 * 	field to db_breakpoint structure.  Some status flags were also
 * 	added to keep track user space break point correctly.
 * 	[91/08/29            tak]
 * 
 * Revision 2.5  91/05/14  15:32:35  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/02/05  17:06:06  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:17:10  mrt]
 * 
 * Revision 2.3  90/10/25  14:43:40  rwd
 * 	Added map field to breakpoints.
 * 	[90/10/18            rpd]
 * 
 * Revision 2.2  90/08/27  21:50:00  dbg
 * 	Modularized typedef names.
 * 	[90/08/20            af]
 * 	Add external defintions.
 * 	[90/08/07            dbg]
 * 	Created.
 * 	[90/07/25            dbg]
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
/*
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */
#ifndef	_DDB_DB_BREAK_H_
#define	_DDB_DB_BREAK_H_

#include <machine/db_machdep.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <mach/boolean.h>

/*
 * thread list at the same breakpoint address
 */
struct db_thread_breakpoint {
	vm_offset_t tb_task_thd;		/* target task or thread */
	boolean_t tb_is_task;			/* task qualified */
	short	 tb_number;			/* breakpoint number */
	short	 tb_init_count;			/* skip count(initial value) */
	short	 tb_count;			/* current skip count */
	short	 tb_cond;			/* break condition */
	struct	 db_thread_breakpoint *tb_next;	/* next chain */
};
typedef struct db_thread_breakpoint *db_thread_breakpoint_t;

/*
 * Breakpoint.
 */
struct db_breakpoint {
	task_t	  task;			/* target task */
	db_addr_t address;		/* set here */
	db_thread_breakpoint_t threads; /* thread */
	int	flags;			/* flags: */
#define	BKPT_SINGLE_STEP	0x2	/* to simulate single step */
#define	BKPT_TEMP		0x4	/* temporary */
#define BKPT_USR_GLOBAL		0x8	/* global user space break point */
#define BKPT_SET_IN_MEM		0x10	/* break point is set in memory */
#define BKPT_1ST_SET		0x20	/* 1st time set of user global bkpt */
	vm_size_t	bkpt_inst;	/* saved instruction at bkpt */
	struct db_breakpoint *link;	/* link in in-use or free chain */
};

typedef struct db_breakpoint *db_breakpoint_t;


/*
 * Prototypes for functions exported by this module.
 */

db_thread_breakpoint_t db_find_thread_breakpoint_here(
	task_t		task,
	db_addr_t	addr);

void db_check_breakpoint_valid(void);

void db_set_breakpoint(
	task_t		task,
	db_addr_t	addr,
	int		count,
	thread_t	thr_act,
	boolean_t	task_bpt);

db_breakpoint_t db_find_breakpoint(
	task_t		task,
	db_addr_t	addr);

boolean_t db_find_breakpoint_here(
	task_t		task,
	db_addr_t	addr);

db_thread_breakpoint_t db_find_breakpoint_number(
	int		num,
	db_breakpoint_t *bkptp);

void db_set_breakpoints(void);

void db_clear_breakpoints(void);

db_breakpoint_t db_set_temp_breakpoint(
	task_t		task,
	db_addr_t	addr);

void db_delete_temp_breakpoint(
	task_t		task,
	db_breakpoint_t	bkpt);

void db_delete_cmd(void);

void db_breakpoint_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif);

void db_listbreak_cmd(void);

#endif	/* !_DDB_DB_BREAK_H_ */
