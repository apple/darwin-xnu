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
#include <string.h>			/* For strcpy() */
#include <mach/boolean.h>
#include <machine/db_machdep.h>

#include <ddb/db_access.h>
#include <ddb/db_lex.h>
#include <ddb/db_output.h>
#include <ddb/db_command.h>
#include <ddb/db_sym.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_command.h>		/* For db_option() */
#include <ddb/db_examine.h>
#include <ddb/db_expr.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <mach/vm_param.h>

#define db_act_to_task(thr_act)	((thr_act)? thr_act->task: TASK_NULL)

char		db_examine_format[TOK_STRING_SIZE] = "x";
int		db_examine_count = 1;
db_addr_t	db_examine_prev_addr = 0;
thread_act_t	db_examine_act = THR_ACT_NULL;

extern int	db_max_width;


/* Prototypes for functions local to this file.  XXX -- should be static!
 */
int db_xcdump(
	db_addr_t	addr,
	int		size,
	int		count,
	task_t		task);

int db_examine_width(
	int size,
	int *items,
	int *remainder);

/*
 * Examine (print) data.
 */
void
db_examine_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	thread_act_t	thr_act;
	extern char	db_last_modifier[];

	if (modif[0] != '\0')
	    strcpy(db_examine_format, modif);

	if (count == -1)
	    count = 1;
	db_examine_count = count;
	if (db_option(modif, 't')) {
	    if (modif == db_last_modifier)
		thr_act = db_examine_act;
	    else if (!db_get_next_act(&thr_act, 0))
		return;
	} else
	  if (db_option(modif,'u'))
	    thr_act = current_act();
	  else
	    thr_act = THR_ACT_NULL;

	db_examine_act = thr_act;
	db_examine((db_addr_t) addr, db_examine_format, count, 
					db_act_to_task(thr_act));
}

void
db_examine_forward(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	db_examine(db_next, db_examine_format, db_examine_count,
				db_act_to_task(db_examine_act));
}

void
db_examine_backward(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	db_examine(db_examine_prev_addr - (db_next - db_examine_prev_addr),
			 db_examine_format, db_examine_count,
				db_act_to_task(db_examine_act));
}

int
db_examine_width(
	int size,
	int *items,
	int *remainder)
{
	int sz;
	int entry;
	int width;

	width = size * 2 + 1;
	sz = (db_max_width - (sizeof (void *) * 2 + 4)) / width;
	for (entry = 1; (entry << 1) < sz; entry <<= 1)
		continue;

	sz = sizeof (void *) * 2 + 4 + entry * width;
	while (sz + entry < db_max_width) {
		width++;
		sz += entry;
	}
	*remainder = (db_max_width - sz + 1) / 2;
	*items = entry;
	return width;
}

void
db_examine(
	db_addr_t	addr,
	char *		fmt,	/* format string */
	int		count,	/* repeat count */
	task_t		task)
{
	int		c;
	db_expr_t	value;
	int		size;
	int		width;
	int		leader;
	int		items;
	int		nitems;
	char *		fp;
	db_addr_t	next_addr;
	int		sz;

	db_examine_prev_addr = addr;
	while (--count >= 0) {
	    fp = fmt;
	    size = sizeof(int);
	    width = db_examine_width(size, &items, &leader);
	    while ((c = *fp++) != 0) {
		switch (c) {
		    case 'b':
			size = sizeof(char);
			width = db_examine_width(size, &items, &leader);
			break;
		    case 'h':
			size = sizeof(short);
			width = db_examine_width(size, &items, &leader);
			break;
		    case 'l':
			size = sizeof(int);
			width = db_examine_width(size, &items, &leader);
			break;
		    case 'q':
			size = sizeof(long);
			width = db_examine_width(size, &items, &leader);
			break;
		    case 'a':	/* address */
		    case 'A':   /* function address */
			/* always forces a new line */
			if (db_print_position() != 0)
			    db_printf("\n");
			db_prev = addr;
			next_addr = addr + 4;
			db_task_printsym(addr, 
					(c == 'a')?DB_STGY_ANY:DB_STGY_PROC,
					task);
			db_printf(":\t");
			break;
		    case 'm':
			db_next = db_xcdump(addr, size, count+1, task);
			return;
		    case 't':
		    case 'u':
			break;
		    default:
		restart:
			/* Reset next_addr in case we are printing in
			   multiple formats.  */
			next_addr = addr;
			if (db_print_position() == 0) {
			    /* If we hit a new symbol, print it */
			    char *	name;
			    db_addr_t	off;

			    db_find_task_sym_and_offset(addr,&name,&off,task);
			    if (off == 0)
				db_printf("\r%s:\n", name);
			    db_printf("%#n: ", addr);
			    for (sz = 0; sz < leader; sz++)
				    db_putchar(' ');
			    db_prev = addr;
			    nitems = items;
			}

			switch (c) {
			    case 'p':	/* Addrs rendered symbolically. */
				if( size == sizeof(void *) )  {
				    char       *symName;
				    db_addr_t	offset;

				    items = 1;
				    value = db_get_task_value( next_addr,
					sizeof(db_expr_t), FALSE, task );
				    db_find_task_sym_and_offset( value,
					&symName, &offset, task);
				    db_printf("\n\t*%8llX(%8llX) = %s",
						next_addr, value, symName );
				    if( offset )  {
					db_printf("+%llX", offset );
				    }
				    next_addr += size;
				}
				break;
			    case 'r':	/* signed, current radix */
				for (sz = size, next_addr = addr;
				     sz >= sizeof (db_expr_t);
				     sz -= sizeof (db_expr_t)) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,
							      sizeof (db_expr_t),
							      TRUE,task);
				    db_printf("%-*llr", width, value);
				    next_addr += sizeof (db_expr_t);
				}
				if (sz > 0) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr, sz,
							      TRUE, task);
				    db_printf("%-*llR", width, value);
				    next_addr += sz;
				}
				break;
			    case 'X':	/* unsigned hex */
			    case 'x':	/* unsigned hex */
				for (sz = size, next_addr = addr;
				     sz >= sizeof (db_expr_t);
				     sz -= sizeof (db_expr_t)) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,
							      sizeof (db_expr_t),
							      FALSE,task);
			            if ( c == 'X')
				      db_printf("%0*llX ", 2*size, value);
				    else
				      db_printf("%-*llx", width, value);
				    next_addr += sizeof (db_expr_t);
			        }
				if (sz > 0) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr, sz,
							      FALSE, task);
			            if ( c == 'X')
				      db_printf("%0*llX ", 2*size, value);
				    else
				      db_printf("%-*llX", width, value);
				    next_addr += sz;
				}
				break;
			    case 'z':	/* signed hex */
				for (sz = size, next_addr = addr;
				     sz >= sizeof (db_expr_t);
				     sz -= sizeof (db_expr_t)) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,
							      sizeof (db_expr_t),
							      TRUE, task);
				    db_printf("%-*llz", width, value);
				    next_addr += sizeof (db_expr_t);
				}
				if (sz > 0) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,sz,
							      TRUE,task);
				    db_printf("%-*llZ", width, value);
				    next_addr += sz;
				}
				break;
			    case 'd':	/* signed decimal */
				for (sz = size, next_addr = addr;
				     sz >= sizeof (db_expr_t);
				     sz -= sizeof (db_expr_t)) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,
							      sizeof (db_expr_t),
							      TRUE,task);
				    db_printf("%-*lld", width, value);
				    next_addr += sizeof (db_expr_t);
				}
				if (sz > 0) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr, sz,
							      TRUE, task);
				    db_printf("%-*llD", width, value);
				    next_addr += sz;
				}
				break;
			    case 'U':	/* unsigned decimal */
			    case 'u':
				for (sz = size, next_addr = addr;
				     sz >= sizeof (db_expr_t);
				     sz -= sizeof (db_expr_t)) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,
							      sizeof (db_expr_t),
							      FALSE,task);
				    db_printf("%-*llu", width, value);
				    next_addr += sizeof (db_expr_t);
				}
				if (sz > 0) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr, sz,
							      FALSE, task);
				    db_printf("%-*llU", width, value);
				    next_addr += sz;
				}
				break;
			    case 'o':	/* unsigned octal */
				for (sz = size, next_addr = addr;
				     sz >= sizeof (db_expr_t);
				     sz -= sizeof (db_expr_t)) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr,
							      sizeof (db_expr_t),
							      FALSE,task);
				    db_printf("%-*llo", width, value);
				    next_addr += sizeof (db_expr_t);
				}
				if (sz > 0) {
				    if (nitems-- == 0) {
					db_putchar('\n');
					goto restart;
				    }
				    value = db_get_task_value(next_addr, sz,
							      FALSE, task);
				    db_printf("%-*llo", width, value);
				    next_addr += sz;
				}
				break;
			    case 'c':	/* character */
				for (sz = 0, next_addr = addr;
				     sz < size;
				     sz++, next_addr++) {
				    value = db_get_task_value(next_addr,1,
							      FALSE,task);
				    if ((value >= ' ' && value <= '~') ||
					value == '\n' ||
					value == '\t')
					    db_printf("%llc", value);
				    else
					    db_printf("\\%03llo", value);
				}
				break;
			    case 's':	/* null-terminated string */
				size = 0;
				for (;;) {
				    value = db_get_task_value(next_addr,1,
							      FALSE,task);
				    next_addr += 1;
				    size++;
				    if (value == 0)
					break;
				    if (value >= ' ' && value <= '~')
					db_printf("%llc", value);
				    else
					db_printf("\\%03llo", value);
				}
				break;
			    case 'i':	/* instruction */
				next_addr = db_disasm(addr, FALSE, task);
				size = next_addr - addr;
				break;
			    case 'I':	/* instruction, alternate form */
				next_addr = db_disasm(addr, TRUE, task);
				size = next_addr - addr;
				break;
			    default:
				break;
			}
			if (db_print_position() != 0)
			    db_end_line();
			break;
		}
	    }
	    addr = next_addr;
	}
	db_next = addr;
}

/*
 * Print value.
 */
char	db_print_format = 'x';

void
db_print_cmd(void)
{
	db_expr_t	value;
	int		t;
	task_t		task = TASK_NULL;

	if ((t = db_read_token()) == tSLASH) {
	    if (db_read_token() != tIDENT) {
		db_printf("Bad modifier \"/%s\"\n", db_tok_string);
		db_error(0);
		/* NOTREACHED */
	    }
	    if (db_tok_string[0])
		db_print_format = db_tok_string[0];
	    if (db_option(db_tok_string, 't')) {
		if (db_default_act)
		    task = db_default_act->task;
		if (db_print_format == 't')
		   db_print_format = db_tok_string[1];
	    }
	} else
	    db_unread_token(t);
	
	for ( ; ; ) {
	    t = db_read_token();
	    if (t == tSTRING) {
		db_printf("%s", db_tok_string);
		continue;
	    }
	    db_unread_token(t);
	    if (!db_expression(&value))
		break;
	    switch (db_print_format) {
	    case 'a':
	    case 'A':
		db_task_printsym((db_addr_t)value,
				 (db_print_format == 'a') ? DB_STGY_ANY:
				 			    DB_STGY_PROC,
				 task);
		break;
	    case 'r':
		db_printf("%11llr", value);
		break;
	    case 'X':
		db_printf("%016llX", value);
		break;
	    case 'x':
		db_printf("%016llx", value);
		break;
	    case 'z':
		db_printf("%16llz", value);
		break;
	    case 'd':
		db_printf("%11lld", value);
		break;
	    case 'u':
		db_printf("%11llu", value);
		break;
	    case 'o':
		db_printf("%16llo", value);
		break;
	    case 'c':
		value = value & 0xFF;
		if (value >= ' ' && value <= '~')
		    db_printf("%llc", value);
		else
		    db_printf("\\%03llo", value);
		break;
	    default:
		db_printf("Unknown format %c\n", db_print_format);
		db_print_format = 'x';
		db_error(0);
	    }
	}
}

void
db_print_loc(
	db_addr_t       loc,
	task_t          task)
{
	db_task_printsym(loc, DB_STGY_PROC, task);
}

void
db_print_inst(
	db_addr_t       loc,
	task_t          task)
{
	(void) db_disasm(loc, TRUE, task);
}

void
db_print_loc_and_inst(
	db_addr_t	loc,
	task_t		task)
{
	db_task_printsym(loc, DB_STGY_PROC, task);
	db_printf(":\t");
	(void) db_disasm(loc, TRUE, task);
}

/*
 * Search for a value in memory.
 * Syntax: search [/bhl] addr value [mask] [,count] [thread]
 */
void
db_search_cmd(void)
{
	int		t;
	db_addr_t	addr;
	int		size = 0;
	db_expr_t	value;
	db_expr_t	mask;
	db_addr_t	count;
	thread_act_t	thr_act;
	boolean_t	thread_flag = FALSE;
	register char	*p;

	t = db_read_token();
	if (t == tSLASH) {
	    t = db_read_token();
	    if (t != tIDENT) {
	      bad_modifier:
		db_printf("Bad modifier \"/%s\"\n", db_tok_string);
		db_flush_lex();
		return;
	    }

	    for (p = db_tok_string; *p; p++) {
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
		case 't':
		    thread_flag = TRUE;
		    break;
		default:
		    goto bad_modifier;
		}
	    }
	} else {
	    db_unread_token(t);
	    size = sizeof(int);
	}

	if (!db_expression((db_expr_t *) &addr)) {
	    db_printf("Address missing\n");
	    db_flush_lex();
	    return;
	}

	if (!db_expression(&value)) {
	    db_printf("Value missing\n");
	    db_flush_lex();
	    return;
	}

	if (!db_expression(&mask))
	    mask = ~0;

	t = db_read_token();
	if (t == tCOMMA) {
	    if (!db_expression((db_expr_t *) &count)) {
		db_printf("Count missing\n");
		db_flush_lex();
		return;
	    }
	} else {
	    db_unread_token(t);
	    count = -1;		/* effectively forever */
	}
	if (thread_flag) {
	    if (!db_get_next_act(&thr_act, 0))
		return;
	} else
	    thr_act = THR_ACT_NULL;

	db_search(addr, size, value, mask, count, db_act_to_task(thr_act));
}

void
db_search(
	db_addr_t	addr,
	int		size,
	db_expr_t	value,
	db_expr_t	mask,
	unsigned int	count,
	task_t		task)
{
	while (count-- != 0) {
		db_prev = addr;
		if ((db_get_task_value(addr,size,FALSE,task) & mask) == value)
			break;
		addr += size;
	}
	db_printf("0x%x: ", addr);
	db_next = addr;
}

#define DB_XCDUMP_NC	16

int
db_xcdump(
	db_addr_t	addr,
	int		size,
	int		count,
	task_t		task)
{
	register int 	i, n;
	db_expr_t	value;
	int		bcount;
	db_addr_t	off;
	char		*name;
	char		data[DB_XCDUMP_NC];

	db_find_task_sym_and_offset(addr, &name, &off, task);
	for (n = count*size; n > 0; n -= bcount) {
	    db_prev = addr;
	    if (off == 0) {
		db_printf("%s:\n", name);
		off = -1;
	    }
	    db_printf("%0*llX:%s", 2*sizeof(db_addr_t), addr,
					(size != 1) ? " " : "" );
	    bcount = ((n > DB_XCDUMP_NC)? DB_XCDUMP_NC: n);
	    if (trunc_page_32(addr) != trunc_page_32(addr+bcount-1)) {
		db_addr_t next_page_addr = trunc_page_32(addr+bcount-1);
		if (!DB_CHECK_ACCESS(next_page_addr, sizeof(int), task))
		    bcount = next_page_addr - addr;
	    }
	    db_read_bytes((vm_offset_t)addr, bcount, data, task);
	    for (i = 0; i < bcount && off != 0; i += size) {
		if (i % 4 == 0)
			db_printf(" ");
		value = db_get_task_value(addr, size, FALSE, task);
		db_printf("%0*llX ", size*2, value);
		addr += size;
		db_find_task_sym_and_offset(addr, &name, &off, task);
	    }
	    db_printf("%*s",
			((DB_XCDUMP_NC-i)/size)*(size*2+1)+(DB_XCDUMP_NC-i)/4,
			 "");
	    bcount = i;
	    db_printf("%s*", (size != 1)? " ": "");
	    for (i = 0; i < bcount; i++) {
		value = data[i];
		db_printf("%llc", (value >= ' ' && value <= '~')? value: '.');
	    }
	    db_printf("*\n");
	}
	return(addr);
}
