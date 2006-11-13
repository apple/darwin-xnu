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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:47  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.18.1  1997/03/27  18:46:29  barbou
 * 	ri-osc CR1558: enable use of breakpoint counts even when no
 * 	condition given.
 * 	[1995/09/20  15:24:24  bolinger]
 * 	[97/02/25            barbou]
 *
 * Revision 1.2.6.2  1996/01/09  19:15:34  devrcs
 * 	Change 'register c' to 'register int c'.
 * 	[1995/12/01  21:42:00  jfraser]
 * 
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:02:54  jfraser]
 * 
 * Revision 1.2.6.1  1994/09/23  01:18:27  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:09:37  ezf]
 * 
 * Revision 1.2.2.4  1993/08/11  20:37:33  elliston
 * 	Add ANSI Prototypes.  CR #9523.
 * 	[1993/08/11  03:32:57  elliston]
 * 
 * Revision 1.2.2.3  1993/07/27  18:26:59  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:11:12  elliston]
 * 
 * Revision 1.2.2.2  1993/06/09  02:19:53  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:56:04  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:01:51  devrcs
 * 	Changes from mk78:
 * 	Changed errant call of db_error in db_cond_cmd() to db_printf/db_error.
 * 	[92/05/20            jfriedl]
 * 	[93/02/02            bruel]
 * 
 * Revision 1.1  1992/09/30  02:00:58  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.2  91/10/09  15:59:09  af
 * 	 Revision 2.1.3.1  91/10/05  13:05:38  jeffreyh
 * 	 	Created to support conditional break point and command execution.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.1.3.1  91/10/05  13:05:38  jeffreyh
 * 	Created to support conditional break point and command execution.
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

#include <machine/db_machdep.h>
#include <machine/setjmp.h>
#include <kern/misc_protos.h>

#include <ddb/db_lex.h>
#include <ddb/db_break.h>
#include <ddb/db_command.h>
#include <ddb/db_cond.h>
#include <ddb/db_expr.h>
#include <ddb/db_output.h>		/* For db_printf() */

#define DB_MAX_COND	10		/* maximum conditions to be set */

int   db_ncond_free = DB_MAX_COND;			/* free condition */
struct db_cond {
	int	c_size;					/* size of cond */
	char	c_cond_cmd[DB_LEX_LINE_SIZE];		/* cond & cmd */
} db_cond[DB_MAX_COND];

void
db_cond_free(db_thread_breakpoint_t bkpt)
{
	if (bkpt->tb_cond > 0) {
	    db_cond[bkpt->tb_cond-1].c_size = 0;
	    db_ncond_free++;
	    bkpt->tb_cond = 0;
	}
}

boolean_t
db_cond_check(db_thread_breakpoint_t bkpt)
{
	register  struct db_cond *cp;
	db_expr_t value;
	int	  t;
	jmp_buf_t db_jmpbuf;
	extern 	  jmp_buf_t *db_recover;

	if (bkpt->tb_cond <= 0) {		/* no condition */
		if (--(bkpt->tb_count) > 0)
			return(FALSE);
		bkpt->tb_count = bkpt->tb_init_count;
	    return(TRUE);
	}
	db_dot = PC_REGS(DDB_REGS);
	db_prev = db_dot;
	db_next = db_dot;
	if (_setjmp(db_recover = &db_jmpbuf)) {
	    /*
	     * in case of error, return true to enter interactive mode
	     */
	    return(TRUE);
	}

	/*
	 * switch input, and evalutate condition
	 */
	cp = &db_cond[bkpt->tb_cond - 1];
	db_switch_input(cp->c_cond_cmd, cp->c_size);
	if (!db_expression(&value)) {
	    db_printf("error: condition evaluation error\n");
	    return(TRUE);
	}
	if (value == 0 || --(bkpt->tb_count) > 0)
	    return(FALSE);

	/*
	 * execute a command list if exist
	 */
	bkpt->tb_count = bkpt->tb_init_count;
	if ((t = db_read_token()) != tEOL) {
	    db_unread_token(t);
	    return(db_exec_cmd_nest(0, 0));
	}
	return(TRUE);
}

void
db_cond_print(db_thread_breakpoint_t bkpt)
{
	register char *p, *ep;
	register struct db_cond *cp;

	if (bkpt->tb_cond <= 0)
	    return;
	cp = &db_cond[bkpt->tb_cond-1];
	p = cp->c_cond_cmd;
	ep = p + cp->c_size;
	while (p < ep) {
	    if (*p == '\n' || *p == 0)
		break;
	    db_putchar(*p++);
	}
}

void
db_cond_cmd(void)
{
	register  int c;
	register  struct db_cond *cp;
	register  char *p;
	db_expr_t value;
	db_thread_breakpoint_t bkpt;

	if (db_read_token() != tHASH || db_read_token() != tNUMBER) {
	    db_printf("#<number> expected instead of \"%s\"\n", db_tok_string);
	    db_error(0);
	    return;
	}
	if ((bkpt = db_find_breakpoint_number(db_tok_number, 0)) == 0) {
	    db_printf("No such break point #%d\n", db_tok_number);
	    db_error(0);
	    return;
	}
	/*
	 * if the break point already has a condition, free it first
	 */
	if (bkpt->tb_cond > 0) {
	    cp = &db_cond[bkpt->tb_cond - 1];
	    db_cond_free(bkpt);
	} else {
	    if (db_ncond_free <= 0) {
		db_error("Too many conditions\n");
		return;
	    }
	    for (cp = db_cond; cp < &db_cond[DB_MAX_COND]; cp++)
		if (cp->c_size == 0)
		    break;
	    if (cp >= &db_cond[DB_MAX_COND])
		panic("bad db_cond_free");
	}
	for (c = db_read_char(); c == ' ' || c == '\t'; c = db_read_char());
	for (p = cp->c_cond_cmd; c >= 0; c = db_read_char())
	    *p++ = c;
	/*
	 * switch to saved data and call db_expression to check the condition.
	 * If no condition is supplied, db_expression will return false.
	 * In this case, clear previous condition of the break point.
         * If condition is supplied, set the condition to the permanent area.
	 * Note: db_expression will not return here, if the condition
	 *       expression is wrong.
	 */
	db_switch_input(cp->c_cond_cmd, p - cp->c_cond_cmd);
	if (!db_expression(&value)) {
	    /* since condition is already freed, do nothing */
	    db_flush_lex();
	    return;
	}
	db_flush_lex();
	db_ncond_free--;
	cp->c_size = p - cp->c_cond_cmd;
	bkpt->tb_cond = (cp - db_cond) + 1;
}
