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
#include <kern/thread.h>
#include <string.h>			/* For strcmp(), strcpy() */

#include <machine/db_machdep.h>
#include <ddb/db_command.h>
#include <ddb/db_expr.h>
#include <ddb/db_lex.h>
#include <ddb/db_macro.h>
#include <ddb/db_output.h>		/* For db_printf() */
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>

/*
 * debugger macro support
 */

#define DB_NUSER_MACRO	10		/* max user macros */

int		db_macro_free = DB_NUSER_MACRO;
struct db_user_macro {
	char	m_name[TOK_STRING_SIZE];
	char	m_lbuf[DB_LEX_LINE_SIZE];
	int	m_size;
} db_user_macro[DB_NUSER_MACRO];

int		db_macro_level = -1;
db_expr_t	db_macro_args[DB_MACRO_LEVEL][DB_MACRO_NARGS];


/* Prototypes for functions local to this file.
 */
static struct db_user_macro *db_lookup_macro(char *name);


static struct db_user_macro *
db_lookup_macro(char *name)
{
	register struct db_user_macro *mp;

	for (mp = db_user_macro; mp < &db_user_macro[DB_NUSER_MACRO]; mp++) {
	    if (mp->m_name[0] == 0)
		continue;
	    if (strcmp(mp->m_name, name) == 0)
		return(mp);
	}
	return(0);
}

void
db_def_macro_cmd(void)
{
	register char *p;
	register int c;
	register struct db_user_macro *mp, *ep;

	if (db_read_token() != tIDENT) {
	    db_printf("Bad macro name \"%s\"\n", db_tok_string);
	    db_error(0);
	    /* NOTREACHED */
	}
	if ((mp = db_lookup_macro(db_tok_string)) == 0) {
	    if (db_macro_free <= 0)
		db_error("Too many macros\n");
		/* NOTREACHED */
	    ep = &db_user_macro[DB_NUSER_MACRO];
	    for (mp = db_user_macro; mp < ep && mp->m_name[0]; mp++);
	    if (mp >= ep)
		db_error("ddb: internal error(macro)\n");
		/* NOTREACHED */
	    db_macro_free--;
	    strcpy(mp->m_name, db_tok_string);
	}
	for (c = db_read_char(); c == ' ' || c == '\t'; c = db_read_char());
	for (p = mp->m_lbuf; c > 0; c = db_read_char())
	    *p++ = c;
	*p = 0;
	mp->m_size = p - mp->m_lbuf;
}

void
db_del_macro_cmd(void)
{
	register struct db_user_macro *mp;

	if (db_read_token() != tIDENT 
	    || (mp = db_lookup_macro(db_tok_string)) == 0) {
	    db_printf("No such macro \"%s\"\n", db_tok_string);
	    db_error(0);
	    /* NOTREACHED */
	}
	mp->m_name[0] = 0;
	db_macro_free++;
}

void
db_show_macro(void)
{
	register struct db_user_macro *mp;
	int  t;
	char *name = 0;

	if ((t = db_read_token()) == tIDENT)
	    name = db_tok_string;
	else
	    db_unread_token(t);
	for (mp = db_user_macro; mp < &db_user_macro[DB_NUSER_MACRO]; mp++) {
	    if (mp->m_name[0] == 0)
		continue;
	    if (name && strcmp(mp->m_name, name))
		continue;
	    db_printf("%s: %s", mp->m_name, mp->m_lbuf);
	}
}

int
db_exec_macro(char *name)
{
	register struct db_user_macro *mp;
	register int n;

	if ((mp = db_lookup_macro(name)) == 0)
	    return(-1);
	if (db_macro_level+1 >= DB_MACRO_LEVEL) {
	    db_macro_level = -1;
	    db_error("Too many macro nest\n");
	    /* NOTREACHED */
	}
	for (n = 0;
	     n < DB_MACRO_NARGS && 
	     db_expression(&db_macro_args[db_macro_level+1][n]);
	     n++);
	while (n < DB_MACRO_NARGS)
	    db_macro_args[db_macro_level+1][n++] = 0;
	db_macro_level++;
	db_exec_cmd_nest(mp->m_lbuf, mp->m_size);
	db_macro_level--;
	return(0);
}

int
db_arg_variable(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap)
{
	db_expr_t value;
	char *name;
	db_addr_t offset;

	if (flag == DB_VAR_SHOW) {
	    value = db_macro_args[ap->hidden_level][ap->suffix[0]-1];
	    db_printf("%#lln", value);
	    db_find_xtrn_task_sym_and_offset(value, &name, &offset, TASK_NULL);
	    if (name != (char *)0 && offset <= db_maxoff && offset != value) {
		db_printf("\t%s", name);
		if (offset != 0)
		    db_printf("+%#r", offset);
	    }
	    return(0);
	}

	if (ap->level != 1 || ap->suffix[0] < 1 ||
	    ap->suffix[0] > DB_MACRO_NARGS) {
	    db_error("Bad $arg variable\n");
	    /* NOTREACHED */
	}
	if (flag == DB_VAR_GET)
	    *valuep = db_macro_args[db_macro_level][ap->suffix[0]-1];
	else
	    db_macro_args[db_macro_level][ap->suffix[0]-1] = *valuep;
	return(0);
}
