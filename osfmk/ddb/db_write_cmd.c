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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.10.1  1994/09/23  01:23:15  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:11:42  ezf]
 *
 * Revision 1.2.8.3  1994/03/17  22:35:48  dwm
 * 	The infamous name change:  thread_activation + thread_shuttle = thread.
 * 	[1994/03/17  21:26:02  dwm]
 * 
 * Revision 1.2.8.2  1994/01/12  17:51:11  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	[1994/01/12  17:13:42  dwm]
 * 
 * Revision 1.2.8.1  1994/01/05  19:28:25  bolinger
 * 	Target current address space, not current "task", for writes.
 * 	[1994/01/04  17:44:51  bolinger]
 * 
 * Revision 1.2.2.3  1993/07/27  18:28:36  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:13:37  elliston]
 * 
 * Revision 1.2.2.2  1993/06/09  02:21:11  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:58:03  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:03:43  devrcs
 * 	Changes from mk78:
 * 	Removed unused variable 'p' from db_write_cmd().
 * 	[92/05/16            jfriedl]
 * 	Reorganized. w/u now works, instead of just w/tu.
 * 	[92/04/18            danner]
 * 	[93/02/02            bruel]
 * 
 * Revision 1.1  1992/09/30  02:01:35  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.6  91/10/09  16:05:06  af
 * 	 Revision 2.5.3.1  91/10/05  13:09:25  jeffreyh
 * 		Added user space write support including inactive task.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.5.3.1  91/10/05  13:09:25  jeffreyh
 * 	Added user space write support including inactive task.
 * 	[91/08/29            tak]
 * 
 * Revision 2.5  91/05/14  15:38:04  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/02/05  17:07:35  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:20:19  mrt]
 * 
 * Revision 2.3  90/10/25  14:44:26  rwd
 * 	Changed db_write_cmd to print unsigned.
 * 	[90/10/19            rpd]
 * 
 * Revision 2.2  90/08/27  21:53:54  dbg
 * 	Set db_prev and db_next instead of explicitly advancing dot.
 * 	[90/08/22            dbg]
 * 	Reflected changes in db_printsym()'s calling seq.
 * 	[90/08/20            af]
 * 	Warn user if nothing was written.
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
 *	Author: David B. Golub,  Carnegie Mellon University
 *	Date:	7/90
 */

#include <mach/boolean.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <machine/db_machdep.h>

#include <ddb/db_lex.h>
#include <ddb/db_access.h>
#include <ddb/db_command.h>
#include <ddb/db_sym.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_expr.h>
#include <ddb/db_write_cmd.h>
#include <ddb/db_output.h>			/* For db_printf() */

/*
 * Write to file.
 */
void
db_write_cmd(
	db_expr_t	address,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	register db_addr_t	addr;
	register db_expr_t	old_value;
	db_expr_t	new_value;
	register int	size;
	boolean_t	wrote_one = FALSE;
	boolean_t	t_opt, u_opt;
	thread_act_t	thr_act;
	task_t		task;

	addr = (db_addr_t) address;

	size = db_size_option(modif, &u_opt, &t_opt);

	if (t_opt) 
	  {
	    if (!db_get_next_act(&thr_act, 0))
	      return;
	    task = thr_act->task;
	  }
	else
	  task = db_current_space();

	/* if user space is not explicitly specified, 
	   look in the kernel */
	if (!u_opt)
	  task = TASK_NULL;

	if (!DB_VALID_ADDRESS(addr, u_opt)) {
	  db_printf("Bad address 0x%x\n", addr);
	  return;
	}

	while (db_expression(&new_value)) {
	    old_value = db_get_task_value(addr, size, FALSE, task);
	    db_task_printsym(addr, DB_STGY_ANY, task);
	    db_printf("\t\t%#8n\t=\t%#8n\n", old_value, new_value);
	    db_put_task_value(addr, size, new_value, task);
	    addr += size;

	    wrote_one = TRUE;
	}

	if (!wrote_one)
	    db_error("Nothing written.\n");

	db_next = addr;
	db_prev = addr - size;
}
