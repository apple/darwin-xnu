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
 * Revision 1.2  1998/04/29 17:35:25  mburg
 * MK7.3 merger
 *
 * Revision 1.2.85.1  1998/02/03  09:24:09  gdt
 * 	Merge up to MK7.3
 * 	[1998/02/03  09:10:24  gdt]
 *
 * Revision 1.2.81.1  1997/03/27  18:46:38  barbou
 * 	ri-osc CR1565 - clean up db_print_act, removing old !USER code
 * 	which had gotten stale (the option made little sense here anyway).
 * 	Added routine db_show_one_thread() to take either act/shuttle and
 * 	do something sensible. [dwm]  Also rationalize plain, /u and /l
 * 	output for "show act", "show task" and "show all acts".
 * 	[1995/08/28  15:47:00  bolinger]
 * 	[97/02/25            barbou]
 * 
 * Revision 1.2.31.13  1996/01/09  19:16:02  devrcs
 * 	Alpha kdebug Changes:
 * 	  Correct various header spacing to account for 64-bit addresses.
 * 	  Modify db_show_all_*() functions, so the can be called from kdebug.
 * 	  ( There's no way to call with "char *modif", so added NULL check. )
 * 	  Changed db_error() calls to DB_ERROR() macro, so we return on error
 * 	  on Alpha (we gotta return to kdebug).
 * 	Changed declarations of 'register foo' to 'register int foo'.
 * 	[1995/12/01  21:42:20  jfraser]
 * 
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:03:24  jfraser]
 * 
 * Revision 1.2.31.12  1995/10/09  17:03:30  devrcs
 * 	Merge forward.
 * 	[1995/08/24  20:56:42  watkins]
 * 
 * Revision 1.2.59.1  1995/08/04  17:03:17  watkins
 * 	Change to stack per shuttle model.
 * 	[1995/07/19  20:26:13  watkins]
 * 
 * Revision 1.2.31.11  1995/09/18  19:08:49  devrcs
 * 	Merge forward.
 * 	[1995/08/24  20:56:42  watkins]
 * 
 * Revision 1.2.59.1  1995/08/04  17:03:17  watkins
 * 	Change to stack per shuttle model.
 * 	[1995/07/19  20:26:13  watkins]
 * 
 * Revision 1.2.31.10  1995/05/19  15:43:04  bernadat
 * 	Fixed db_print_act for empty activations.
 * 	Let thread swapping be configurable.
 * 	[95/05/19            bernadat]
 * 
 * Revision 1.2.31.9  1995/05/14  18:10:25  dwm
 * 	ri-osc CR1304 - merge (nmk19_latest - nmk19b1) diffs into mainline.
 * 	mk6 CR938 - restore mach_msg hot path
 * 	remove use of now-defunct fields in thread [mmp,dwm]
 * 	[1995/05/14  17:25:05  dwm]
 * 
 * Revision 1.2.31.8  1995/04/07  18:53:00  barbou
 * 	VM Merge - Task Swapper.
 * 	Renamed TH_SWAPPED to TH_STACK_HANDOFF and swap_func to continuation
 * 	to resolve name conflict.
 * 	From kernel/kdb/kdb_mach.c:
 * 	Put in changes for swapping.
 * 	[1991/11/21  20:32:15  mmp]
 * 	[94/07/27            barbou]
 * 	[95/03/08            barbou]
 * 
 * Revision 1.2.31.7  1995/02/28  01:58:38  dwm
 * 	mk6 CR1120 - Merge mk6pro_shared into cnmk_shared
 * 	* Rev1.2.43.1  1995/01/27  22:01:26  bolinger
 * 	* Fix ri-osc CR977:  Make "show space" and "show ipc_port" give
 * 	* accurate count of ports active in IPC space.  Make "show ipc_port"
 * 	* output task-visible port name.
 * 	[1995/02/28  01:12:46  dwm]
 * 
 * Revision 1.2.31.6  1995/02/23  21:43:34  alanl
 * 	Fix db_show_one_task_vm for thread_act_ts.
 * 	[95/01/09            rwd]
 * 
 * 	Merged with DIPC2_SHARED.
 * 	[95/01/04            alanl]
 * 
 * Revision 1.2.31.5  1995/01/10  04:49:52  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	Fix "sh thr/ul"; no cont. to print, fix pri/policy format.
 * 	* Rev 1.2.31.4  1994/10/11  16:35:58  emcmanus
 * 	  Added "show runq" and "show shuttle".
 * 	[1994/12/09  20:36:49  dwm]
 * 
 * 	mk6 CR668 - 1.3b26 merge
 * 	* Revision 1.2.8.6  1994/05/06  18:39:37  tmt
 * 	Merged osc1.3dec/shared with osc1.3b19
 * 	Merge Alpha changes into osc1.312b source code.
 * 	64bit cleanup.
 * 	* End1.3merge
 * 	[1994/11/04  08:49:52  dwm]
 * 
 * Revision 1.2.31.3  1994/09/23  01:20:51  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:10:41  ezf]
 * 
 * Revision 1.2.31.2  1994/06/14  17:21:05  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/14  17:20:35  bolinger]
 * 
 * Revision 1.2.23.4  1994/04/15  18:41:31  paire
 * 	Changed interface of db_task_from_space routine.
 * 	[94/03/31            paire]
 * 
 * Revision 1.2.23.3  1994/03/07  16:37:48  paire
 * 	Merge with Intel R1_1
 * 	Change from NMK14.10 [1993/11/15  16:06:21  rwd]
 * 
 * 	Enhanced pretty print routine and added db_task_from_space.
 * 	Change from NMK14.10 [93/09/24            sjs]
 * 	[94/02/21            paire]
 * 
 * 	Exported ANSI prototype of db_port_kmsg_count routine.
 * 	Added header file include for the declaration of db_norma_ipc routine.
 * 	[94/02/15            paire]
 * 
 * Revision 1.2.23.2  1994/02/11  14:21:58  paire
 * 	Added new vm_print.h header file for db_vm declaration.
 * 	[94/02/09            paire]
 * 
 * Revision 1.2.23.1  1994/02/08  10:58:19  bernadat
 * 	print out msgcount for each port in db_port_iterate
 * 	Change from NORMA_MK14.6(August 93) [1993/07/27  12:35:17  mmp]
 * 
 * 	Removed defintion of db_maxoff (got from <ddb/db_sym.h>).
 * 	[93/08/12            paire]
 * 
 * 	Show ipc_space_remote msg counts only if NORMA_IPC is on
 * 	[93/07/21            bernadat]
 * 
 * 	Add /s option to "show ipc_port" to pick out port sets.
 * 	Change from NORMA_MK14.6 [1993/02/17  16:29:54  dwm]
 * 	[93/07/16            bernadat]
 * 	[94/02/07            bernadat]
 * 
 * Revision 1.2.20.8  1994/06/08  19:11:15  dswartz
 * 	Preemption merge.
 * 	[1994/06/08  19:10:18  dswartz]
 * 
 * Revision 1.2.20.7  1994/04/30  21:28:24  bolinger
 * 	Thread control ops synchronization:  now that TH_SUSP is back,
 * 	enable ddb to show it when printing thread state.
 * 	[1994/04/28  21:55:42  bolinger]
 * 
 * Revision 1.2.20.6  1994/03/17  22:35:31  dwm
 * 	The infamous name change:  thread_activation + thread_shuttle = thread.
 * 	[1994/03/17  21:25:46  dwm]
 * 
 * Revision 1.2.20.5  1994/01/26  15:43:37  bolinger
 * 	Move kernel_stack from thread to activation.
 * 	[1994/01/25  21:53:11  bolinger]
 * 
 * Revision 1.2.20.4  1994/01/12  17:50:44  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	[1994/01/12  17:13:12  dwm]
 * 
 * Revision 1.2.20.3  1993/11/18  18:11:47  dwm
 * 	Coloc: remove continuations entirely; they are incompatible
 * 	with migration, and their volume is obfuscatory.
 * 	[1993/11/18  18:06:27  dwm]
 * 
 * Revision 1.2.20.2  1993/10/12  16:38:50  dwm
 * 	CoLoc: neuter continuations, ifdef USE_CONTINUATIONS.
 * 	[1993/10/12  16:14:46  dwm]
 * 
 * Revision 1.2.8.4  1993/08/11  20:38:06  elliston
 * 	Add ANSI Prototypes.  CR #9523.
 * 	[1993/08/11  03:33:51  elliston]
 * 
 * Revision 1.2.8.3  1993/07/27  18:27:55  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:12:39  elliston]
 * 
 * Revision 1.2.8.2  1993/06/09  02:20:35  gm
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  18:57:22  jeffc]
 * 
 * 	Removed a '#if MACH_FIXPRI' which somehow survived the purge.  CR #9131.
 * 	[1993/05/11  20:56:00  dswartz]
 * 
 * Revision 1.2  1993/04/19  16:02:50  devrcs
 * 	Added printout of thread scheduling policy to long form
 * 	of thread display.
 * 	[93/01/28            jat]
 * 
 * 	Changes from mk78:
 * 	Removed unused variable from db_show_regs().
 * 	[92/05/16            jfriedl]
 * 	Converted some db_printsyms to db_task_printsyms.
 * 	[92/04/10            danner]
 * 	Changed db_print_thread so that both display formats
 * 	show the floating-point-used status of the thread.
 * 	[92/03/16            rpd]
 * 	[93/02/02            bruel]
 * 
 * Revision 1.1  1992/09/30  02:01:18  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.11.3.2  92/04/08  15:43:10  jeffreyh
 * 	Added i option to show thread. This gives wait state information.
 * 	[92/04/08            sjs]
 * 
 * Revision 2.11.3.1  92/03/03  16:13:34  jeffreyh
 * 	Pick up changes from TRUNK
 * 	[92/02/26  11:00:01  jeffreyh]
 * 
 * Revision 2.13  92/02/20  18:34:28  elf
 * 	Fixed typo.
 * 	[92/02/20            elf]
 * 
 * Revision 2.12  92/02/19  15:07:47  elf
 * 	Added db_thread_fp_used, to avoid machine-dependent conditionals.
 * 	[92/02/19            rpd]
 * 
 * 	Added 'F' flag to db_thread_stat showing if the thread has a valid
 * 	FPU context. Tested on i386 and pmax.
 * 	[92/02/17            kivinen]
 * 
 * Revision 2.11  91/11/12  11:50:32  rvb
 * 	Added OPTION_USER ("/u") to db_show_all_threads, db_show_one_thread,
 * 	db_show_one_task.  Without it, we display old-style information.
 * 	[91/10/31            rpd]
 * 
 * Revision 2.10  91/10/09  16:01:48  af
 * 	Supported "show registers" for non current thread.
 * 	Changed display format of thread and task information.
 * 	Changed "show thread" to print current thread information 
 * 	  if no thread is specified.
 * 	Added "show_one_task" for "show task" command.
 * 	Added IPC port print routines for "show ipc_port" command.
 * 	[91/08/29            tak]
 * 
 * Revision 2.9  91/08/03  18:17:19  jsb
 * 	In db_print_thread, if the thread is swapped and there is a
 * 	continuation function, print the function name in parentheses
 * 	instead of '(swapped)'.
 * 	[91/07/04  09:59:27  jsb]
 * 
 * Revision 2.8  91/07/31  17:30:43  dbg
 * 	Revise scheduling state machine.
 * 	[91/07/30  16:43:42  dbg]
 * 
 * Revision 2.7  91/07/09  23:15:57  danner
 * 	Fixed a few printf that should be db_printfs. 
 * 	[91/07/08            danner]
 * 
 * Revision 2.6  91/05/14  15:35:25  mrt
 * 	Correcting copyright
 * 
 * Revision 2.5  91/02/05  17:06:53  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:18:56  mrt]
 * 
 * Revision 2.4  90/10/25  14:43:54  rwd
 * 	Changed db_show_regs to print unsigned.
 * 	[90/10/19            rpd]
 * 	Generalized the watchpoint support.
 * 	[90/10/16            rwd]
 * 
 * Revision 2.3  90/09/09  23:19:52  rpd
 * 	Avoid totally incorrect guesses of symbol names for small values.
 * 	[90/08/30  17:39:08  af]
 * 
 * Revision 2.2  90/08/27  21:51:49  dbg
 * 	Insist that 'show thread' be called with an explicit address.
 * 	[90/08/22            dbg]
 * 
 * 	Fix type for db_maxoff.
 * 	[90/08/20            dbg]
 * 
 * 	Do not dereference the "valuep" field of a variable directly,
 * 	call the new db_read/write_variable functions instead.
 * 	Reflected changes in symbol lookup functions.
 * 	[90/08/20            af]
 * 	Reduce lint.
 * 	[90/08/10  14:33:44  dbg]
 * 
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
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

/*
 * Miscellaneous printing.
 */
#include <dipc.h>
#include <task_swapper.h>

#include <string.h>			/* For strlen() */
#include <mach/port.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/queue.h>
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

#include <kern/sf.h>
#include <kern/sp_mk.h>	/*** ??? fix so this can be removed ***/

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
	boolean_t	is_pset);

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
		db_printf("%#*N", 2+2*sizeof(vm_offset_t), value);
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
		*p++ = (athread->state & TH_SWAPPED_OUT) ? 'O' : '.';
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
		policy = (athread ? athread->policy : 2);
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
			    task->thr_act_count, task->res_act_count,
			    task->suspend_count,
			    ((mk_sp_attributes_t)(task->sp_attributes))->priority,
			    sstate);
	    DB_TASK_NAME(task);
	    if (flag & OPTION_LONG) {
		if (flag & OPTION_TASK_TITLE)
		    flag |= OPTION_THREAD_TITLE;
		db_printf("\n");
	    } else if (task->thr_act_count <= 1)
		flag &= ~OPTION_INDENT;
	    act_id = 0;
	    queue_iterate(&task->thr_acts, thr_act, thread_act_t, thr_acts) {
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
		    if (task->thr_act_count > 1)
			flag |= OPTION_THREAD_TITLE;
		}
	    }
	    db_printf("%3d (%0*X): ", task_id, 2*sizeof(vm_offset_t), task);
	    if (task->thr_act_count == 0) {
		db_printf("no threads\n");
	    } else {
		if (task->thr_act_count > 1) {
		    db_printf("%d threads: \n", task->thr_act_count);
		    flag |= OPTION_INDENT;
		} else
		    flag &= ~OPTION_INDENT;
		act_id = 0;
		queue_iterate(&task->thr_acts, thr_act,
			      thread_act_t, thr_acts) {
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
	thread_act_t act = (thread_act_t)queue_first(&task->thr_acts);
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
	processor_set_t	pset;

	task_id = 0;
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
			db_print_task_vm(task, task_id, title, modif);
			title = FALSE;
			task_id++;
		}
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
	processor_set_t pset;

	flag = OPTION_TASK_TITLE|OPTION_INDENT;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	task_id = 0;
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
	    queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		db_print_task(task, task_id, flag);
		flag &= ~OPTION_TASK_TITLE;
		task_id++;
		if ((flag & (OPTION_LONG|OPTION_INDENT)) == OPTION_INDENT)
		    db_printf("\n");
	    }
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
	processor_set_t pset;

	flag = OPTION_TASK_TITLE|OPTION_INDENT;
	if (db_option(modif, 'u'))
	    flag |= OPTION_USER;
	if (db_option(modif, 'l'))
	    flag |= OPTION_LONG;

	db_printf(" ID: TASK     SPACE    MAP               COUNT\n");
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
	    queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		    db_print_space(task, task_id, flag);
		    task_id++;
	    }
	}
}

db_addr_t
db_task_from_space(
	ipc_space_t	space,
	int		*task_id)
{
	task_t task;
	int tid = 0;
	processor_set_t pset;

	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
	    queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		    if (task->itk_space == space) {
			    *task_id = tid;
			    return (db_addr_t)task;
		    }
		    tid++;
	    }
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
	    db_printf("bad thr_act address %#x\n", addr);
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
	    db_printf("bad task address 0x%x\n", addr);
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
	thread_shuttle_t	shuttle;
	thread_act_t		thr_act;

	if (have_addr)
	    shuttle = (thread_shuttle_t) addr;
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

#define	db_pset_kmsg_count(port) \
	(ipc_list_count((port)->ip_pset->ips_messages.imq_messages.ikmq_base))

int
db_port_kmsg_count(
	ipc_port_t	port)
{
	return (port->ip_pset ? db_pset_kmsg_count(port) : port->ip_msgcount);
}

static int db_print_ent_cnt = 0;

void db_reset_print_entry(
	void)
{
	db_print_ent_cnt = 0;
}

void
db_print_one_entry(
	ipc_entry_t	entry,
	int		index,
	mach_port_t	name,
	boolean_t	is_pset)
{
	ipc_port_t aport = (ipc_port_t)entry->ie_object;
	unsigned bits = entry->ie_bits;

	if (is_pset && !aport->ip_pset)
		return;
	if (db_print_ent_cnt && db_print_ent_cnt % 2 == 0)
		db_printf("\n");
	if (!name)
		db_printf("\t%s%d[%x]",
			!is_pset && aport->ip_pset ? "pset" : "port",
			index,
			MACH_PORT_MAKE(index, IE_BITS_GEN(bits)));
	else
		db_printf("\t%s[%x]",
			!is_pset && aport->ip_pset ? "pset" : "port",
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
		db_printf("(%s,%x,set=%x,%d)",
			(bits & MACH_PORT_TYPE_RECEIVE)? "r":
				(bits & MACH_PORT_TYPE_SEND)? "s": "S",
			aport,
			aport->ip_pset,
			db_pset_kmsg_count(aport));
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
					index, (mach_port_t)0, is_pset);
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
					0, tentry->ite_name, is_pset);
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
	    db_printf("Bad thr_act address 0x%x\n", addr);
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
	extern void	db_device(void);
	extern void	db_sched(void);
#if	DIPC
	extern void	db_dipc_stats(void);
	extern void	db_show_kkt(void);
#endif	/* DIPC */

	db_sched();
	iprintf("\n");
	db_vm();
	iprintf("\n");
	db_device();
#if	DIPC
	iprintf("\n");
	db_dipc_stats();
	iprintf("\n");
	db_show_kkt();
#endif	/* DIPC */
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
	processor_set_t pset;
	processor_t proc;
	run_queue_t runq;
	boolean_t showedany = FALSE;

	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
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
	for (i = runq->low, q = runq->runq + i; i < NRQS; i++, q++) {
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
