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
/*
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

#include <mach/boolean.h>
#include <machine/db_machdep.h>
#include <ddb/db_access.h>
#include <ddb/db_command.h>
#include <ddb/db_expr.h>
#include <ddb/db_lex.h>
#include <ddb/db_output.h>		/* For db_printf() */
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <kern/task.h>



/* Prototypes for functions local to this file.  XXX -- should be static!
 */
boolean_t db_term(db_expr_t *valuep);
boolean_t db_unary(db_expr_t *valuep);
boolean_t db_mult_expr(db_expr_t *valuep);
boolean_t db_add_expr(db_expr_t *valuep);
boolean_t db_shift_expr(db_expr_t *valuep);
boolean_t db_logical_relation_expr(db_expr_t *valuep);
boolean_t db_logical_and_expr(db_expr_t *valuep);
boolean_t db_logical_or_expr(db_expr_t *valuep);


/* try to interpret unknown symbols as hexadecimal constants */
int db_allow_unprefixed_hexa = 1;

boolean_t
db_term(db_expr_t *valuep)
{
	int	t;
	boolean_t valid_symbol = FALSE;
	boolean_t valid_hexa = FALSE;

	switch(t = db_read_token()) {
	case tIDENT:
	    if (db_value_of_name(db_tok_string, valuep)) {
		valid_symbol = TRUE;
	    }
	    if (db_allow_unprefixed_hexa && db_radix == 16 &&
		db_tok_string) {
		char *cp;
		int value;
		    
		value = 0;
		valid_hexa = TRUE;
		for (cp = db_tok_string; *cp; cp++) {
		    if (*cp >= 'a' && *cp <= 'f') {
			value = value * 16 + 10 + (*cp - 'a');
		    } else if (*cp >= 'A' && *cp <= 'F') {
			value = value * 16 + 10 + (*cp - 'A');
		    } else if (*cp >= '0' && *cp <= '9') {
			value = value * 16 + (*cp - '0');
		    } else {
			valid_hexa = FALSE;
			break;
		    }
		}
		if (valid_hexa) {
		    if (valid_symbol) {
			db_printf("Ambiguous constant %x used as a symbol\n",
				  value);
		    } else {
			*valuep = (db_expr_t)value;
		    }	
		}
	    }
	    if (!valid_symbol && !valid_hexa) {
		db_printf("Symbol \"%s\" not found\n", db_tok_string);
		db_error(0);
		/*NOTREACHED*/
	    }
	    return (TRUE);
	case tNUMBER:
	    *valuep = /*(db_expr_t)*/db_tok_number;
	    return (TRUE);
	case tDOT:
	    *valuep = (db_expr_t)db_dot;
	    return (TRUE);
	case tDOTDOT:
	    *valuep = (db_expr_t)db_prev;
	    return (TRUE);
	case tPLUS:
	    *valuep = (db_expr_t) db_next;
	    return (TRUE);
	case tQUOTE:
	    *valuep = (db_expr_t)db_last_addr;
	    return (TRUE);
	case tDOLLAR:
	    if (!db_get_variable(valuep))
		return (FALSE);
	    return (TRUE);
	case tLPAREN:
	    if (!db_expression(valuep)) {
		db_error("Unmached ()s\n");
		/*NOTREACHED*/
	    }
	    t = db_read_token();
	    if (t != tRPAREN) {
		db_printf("')' expected at \"%s...\"\n", db_tok_string);
		db_error(0);
		/*NOTREACHED*/
	    }
	    return (TRUE);
	case tSTRING:
	    {
		    static db_tok_offset = 0;
		    char *sp, *cp;

		    sp = (char *)db_tok_string + db_tok_offset;
		    *valuep = *(int *)sp;
		    for (cp = sp;
			 *cp && cp < sp + sizeof (int);
			 cp++);
		    if (cp == sp + sizeof (int) && *cp) {
			    db_tok_offset += sizeof (int);
			    db_unread_token(t);
		    } else {
			    db_tok_offset = 0;
		    }
		    return (TRUE);
	    }
	default:
	    db_unread_token(t);
	    return (FALSE);
	}
}

int
db_size_option(
	char		*modif,
	boolean_t	*u_option,
	boolean_t	*t_option)
{
	register  char *p;
	int	  size = sizeof(int);

	*u_option = FALSE;
	*t_option = FALSE;
	for (p = modif; *p; p++) {
	    switch(*p) {
	    case 'b':
		size = sizeof(char);
		break;
	    case 'h':
		size = sizeof(short);
		break;
	    case 'l':
		size = sizeof(long);
		break;
	    case 'u':
		*u_option = TRUE;
		break;
	    case 't':
		*t_option = TRUE;
		break;
	    }
	}
	return(size);
}

boolean_t
db_unary(db_expr_t *valuep)
{
	int	  t;
	int	  size;
	boolean_t u_opt, t_opt;
	task_t	  task;
	extern	  task_t db_default_task;

	t = db_read_token();
	if (t == tMINUS) {
	    if (!db_unary(valuep)) {
		db_error("Expression syntax error after '-'\n");
		/*NOTREACHED*/
	    }
	    *valuep = -*valuep;
	    return (TRUE);
	}
	if (t == tSTAR) {
	    /* indirection */
	    if (!db_unary(valuep)) {
		db_error("Expression syntax error after '*'\n");
		/*NOTREACHED*/
	    }
	    task = TASK_NULL;
	    size = sizeof(db_addr_t);
	    u_opt = FALSE;
	    t = db_read_token();
	    if (t == tIDENT && db_tok_string[0] == ':') {
		size = db_size_option(&db_tok_string[1], &u_opt, &t_opt);
		if (t_opt)
		    task = db_default_task;
	    } else
		db_unread_token(t);
	    *valuep = db_get_task_value((db_addr_t)*valuep, size, !u_opt, task);
	    return (TRUE);
	}
	if (t == tEXCL) {
	    if (!db_unary(valuep)) {
		db_error("Expression syntax error after '!'\n");
		/*NOTREACHED*/
	    }
	    *valuep = (!(*valuep));
	    return (TRUE);
	}
	db_unread_token(t);
	return (db_term(valuep));
}

boolean_t
db_mult_expr(db_expr_t *valuep)
{
	db_expr_t	lhs, rhs;
	int		t;
	char		c;

	if (!db_unary(&lhs))
	    return (FALSE);

	t = db_read_token();
	while (t == tSTAR || t == tSLASH || t == tPCT || t == tHASH
		|| t == tBIT_AND) {
	    c = db_tok_string[0];
	    if (!db_term(&rhs)) {
		db_printf("Expression syntax error after '%c'\n", c);
		db_error(0);
		/*NOTREACHED*/
	    }
	    switch(t) {
	    case tSTAR:
		lhs *= rhs;
		break;
	    case tBIT_AND:
		lhs &= rhs;
		break;
	    default:
		if (rhs == 0) {
		    db_error("Divide by 0\n");
		    /*NOTREACHED*/
		}
		if (t == tSLASH)
		    lhs /= rhs;
		else if (t == tPCT)
		    lhs %= rhs;
		else
		    lhs = ((lhs+rhs-1)/rhs)*rhs;
	    }
	    t = db_read_token();
	}
	db_unread_token(t);
	*valuep = lhs;
	return (TRUE);
}

boolean_t
db_add_expr(db_expr_t *valuep)
{
	db_expr_t	lhs, rhs;
	int		t;
	char		c;

	if (!db_mult_expr(&lhs))
	    return (FALSE);

	t = db_read_token();
	while (t == tPLUS || t == tMINUS || t == tBIT_OR) {
	    c = db_tok_string[0];
	    if (!db_mult_expr(&rhs)) {
		db_printf("Expression syntax error after '%c'\n", c);
		db_error(0);
		/*NOTREACHED*/
	    }
	    if (t == tPLUS)
		lhs += rhs;
	    else if (t == tMINUS)
		lhs -= rhs;
	    else
		lhs |= rhs;
	    t = db_read_token();
	}
	db_unread_token(t);
	*valuep = lhs;
	return (TRUE);
}

boolean_t
db_shift_expr(db_expr_t *valuep)
{
	db_expr_t	lhs, rhs;
	int		t;

	if (!db_add_expr(&lhs))
	    return (FALSE);

	t = db_read_token();
	while (t == tSHIFT_L || t == tSHIFT_R) {
	    if (!db_add_expr(&rhs)) {
		db_printf("Expression syntax error after \"%s\"\n",
			(t == tSHIFT_L)? "<<": ">>");
		db_error(0);
		/*NOTREACHED*/
	    }
	    if (rhs < 0) {
		db_error("Negative shift amount\n");
		/*NOTREACHED*/
	    }
	    if (t == tSHIFT_L)
		lhs <<= rhs;
	    else {
		/* Shift right is unsigned */
		lhs = (uint64_t) lhs >> rhs;
	    }
	    t = db_read_token();
	}
	db_unread_token(t);
	*valuep = lhs;
	return (TRUE);
}

boolean_t
db_logical_relation_expr(db_expr_t *valuep)
{
	db_expr_t	lhs, rhs;
	int		t;
	char		op[3];

	if (!db_shift_expr(&lhs))
	    return(FALSE);

	t = db_read_token();
	while (t == tLOG_EQ || t == tLOG_NOT_EQ
		|| t == tGREATER || t == tGREATER_EQ
		|| t == tLESS || t == tLESS_EQ) {
	    op[0] = db_tok_string[0];
	    op[1] = db_tok_string[1];
	    op[2] = 0;
	    if (!db_shift_expr(&rhs)) {
		db_printf("Expression syntax error after \"%s\"\n", op);
		db_error(0);
		/*NOTREACHED*/
	    }
	    switch(t) {
	    case tLOG_EQ:
		lhs = (lhs == rhs);
		break;
	    case tLOG_NOT_EQ:
		lhs = (lhs != rhs);
		break;
	    case tGREATER:
		lhs = (lhs > rhs);
		break;
	    case tGREATER_EQ:
		lhs = (lhs >= rhs);
		break;
	    case tLESS:
		lhs = (lhs < rhs);
		break;
	    case tLESS_EQ:
		lhs = (lhs <= rhs);
		break;
	    }
	    t = db_read_token();
	}
	db_unread_token(t);
	*valuep = lhs;
	return (TRUE);
}

boolean_t
db_logical_and_expr(db_expr_t *valuep)
{
	db_expr_t	lhs, rhs;
	int		t;

	if (!db_logical_relation_expr(&lhs))
	    return(FALSE);

	t = db_read_token();
	while (t == tLOG_AND) {
	    if (!db_logical_relation_expr(&rhs)) {
		db_error("Expression syntax error after \"&&\"\n");
		/*NOTREACHED*/
	    }
	    lhs = (lhs && rhs);
	    t = db_read_token();
	}
	db_unread_token(t);
	*valuep = lhs;
	return (TRUE);
}

boolean_t
db_logical_or_expr(db_expr_t *valuep)
{
	db_expr_t	lhs, rhs;
	int		t;

	if (!db_logical_and_expr(&lhs))
	    return(FALSE);

	t = db_read_token();
	while (t == tLOG_OR) {
	    if (!db_logical_and_expr(&rhs)) {
		db_error("Expression syntax error after \"||\"\n");
		/*NOTREACHED*/
	    }
	    lhs = (lhs || rhs);
	    t = db_read_token();
	}
	db_unread_token(t);
	*valuep = lhs;
	return (TRUE);
}

int
db_expression(db_expr_t *valuep)
{
	return (db_logical_or_expr(valuep));
}
