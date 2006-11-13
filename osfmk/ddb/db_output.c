/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Printf and character output for debugger.
 */

#include <mach/boolean.h>
#include <kern/misc_protos.h>
#include <stdarg.h>
#include <machine/db_machdep.h>
#include <ddb/db_command.h>
#include <ddb/db_lex.h>
#include <ddb/db_input.h>
#include <ddb/db_output.h>
#include <ddb/db_task_thread.h>

/*
 *	Character output - tracks position in line.
 *	To do this correctly, we should know how wide
 *	the output device is - then we could zero
 *	the line position when the output device wraps
 *	around to the start of the next line.
 *
 *	Instead, we count the number of spaces printed
 *	since the last printing character so that we
 *	don't print trailing spaces.  This avoids most
 *	of the wraparounds.
 */

#ifndef	DB_MAX_LINE
#define	DB_MAX_LINE		43	/* maximum line */
#define DB_MAX_WIDTH		132	/* maximum width */
#endif	/* DB_MAX_LINE */

#define DB_MIN_MAX_WIDTH	20	/* minimum max width */
#define DB_MIN_MAX_LINE		3	/* minimum max line */
#define CTRL(c)			((c) & 0xff)

int	db_output_position = 0;		/* output column */
int	db_output_line = 0;		/* output line number */
int	db_last_non_space = 0;		/* last non-space character */
int	db_last_gen_return = 0;		/* last character generated return */
int	db_auto_wrap = 1;		/* auto wrap at end of line ? */
int	db_tab_stop_width = 8;		/* how wide are tab stops? */
#define	NEXT_TAB(i) \
	((((i) + db_tab_stop_width) / db_tab_stop_width) * db_tab_stop_width)
int	db_max_line = DB_MAX_LINE;	/* output max lines */
int	db_max_width = DB_MAX_WIDTH;	/* output line width */


/* Prototypes for functions local to this file.  XXX -- should be static!
 */
static void db_more(void);
void db_advance_output_position(int new_output_position,
				int blank);


/*
 * Force pending whitespace.
 */
void
db_force_whitespace(void)
{
	register int last_print, next_tab;

	last_print = db_last_non_space;
	while (last_print < db_output_position) {
	    next_tab = NEXT_TAB(last_print);
	    if (next_tab <= db_output_position) {
		cnputc('\t');
		last_print = next_tab;
	    }
	    else {
		cnputc(' ');
		last_print++;
	    }
	}
	db_last_non_space = db_output_position;
}

void
db_reset_more()
{
	db_output_line = 0;
}

static void
db_more(void)
{
	register  char *p;
	boolean_t quit_output = FALSE;

	for (p = "--db_more--"; *p; p++)
	    cnputc(*p);
	switch(cngetc()) {
	case ' ':
	    db_output_line = 0;
	    break;
	case 'q':
	case CTRL('c'):
	    db_output_line = 0;
	    quit_output = TRUE;
	    break;
	default:
	    db_output_line--;
	    break;
	}
	p = "\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b";
	while (*p)
	    cnputc(*p++);
	if (quit_output) {
	    db_error((char *) 0);
	    /* NOTREACHED */
	}
}

void
db_advance_output_position(int new_output_position,
			   int blank)
{
	if (db_max_width >= DB_MIN_MAX_WIDTH 
	    && new_output_position >= db_max_width) {
		/* auto new line */
		if (!db_auto_wrap || blank)
		    cnputc('\n');
		db_output_position = 0;
		db_last_non_space = 0;
		db_last_gen_return = 1;
		db_output_line++;
	} else {
		db_output_position = new_output_position;
	}
}

boolean_t
db_reserve_output_position(int increment)
{
	if (db_max_width >= DB_MIN_MAX_WIDTH
	    && db_output_position + increment >= db_max_width) {
		/* auto new line */
		if (!db_auto_wrap || db_last_non_space != db_output_position)
		    cnputc('\n');
		db_output_position = 0;
		db_last_non_space = 0;
		db_last_gen_return = 1;
		db_output_line++;
		return TRUE;
	}
	return FALSE;
}

/*
 * Output character.  Buffer whitespace.
 */
void
db_putchar(char c)
{
	if (db_max_line >= DB_MIN_MAX_LINE && db_output_line >= db_max_line-1)
	    db_more();
	if (c > ' ' && c <= '~') {
	    /*
	     * Printing character.
	     * If we have spaces to print, print them first.
	     * Use tabs if possible.
	     */
	    db_force_whitespace();
	    cnputc(c);
	    db_last_gen_return = 0;
	    db_advance_output_position(db_output_position+1, 0);
	    db_last_non_space = db_output_position;
	}
	else if (c == '\n') {
	    /* Return */
	    if (db_last_gen_return) {
		db_last_gen_return = 0;
	    } else {
		cnputc(c);
		db_output_position = 0;
		db_last_non_space = 0;
		db_output_line++;
		db_check_interrupt();
	    }
	}
	else if (c == '\t') {
	    /* assume tabs every 8 positions */
	    db_advance_output_position(NEXT_TAB(db_output_position), 1);
	}
	else if (c == ' ') {
	    /* space */
	    db_advance_output_position(db_output_position+1, 1);
	}
	else if (c == '\007') {
	    /* bell */
	    cnputc(c);
	}
	/* other characters are assumed non-printing */
}

/*
 * Return output position
 */
int
db_print_position(void)
{
	return (db_output_position);
}

/*
 * End line if too long.
 */
void
db_end_line(void)
{
	if (db_output_position >= db_max_width-1) {
	    /* auto new line */
	    if (!db_auto_wrap)
		cnputc('\n');
	    db_output_position = 0;
	    db_last_non_space = 0;
	    db_last_gen_return = 1;
	    db_output_line++;
	}
}

/*
 * Printing
 */

void
db_printf(const char *fmt, ...)
{
	va_list	listp;

	va_start(listp, fmt);
	_doprnt(fmt, &listp, db_putchar, db_radix);
	va_end(listp);
}

/* alternate name */

void
kdbprintf(const char *fmt, ...)
{
	va_list	listp;

	va_start(listp, fmt);
	_doprnt(fmt, &listp, db_putchar, db_radix);
	va_end(listp);
}

int	db_indent = 0;

/*
 * Printing (to console) with indentation.
 */
void
iprintf(const char *fmt, ...)
{
	va_list listp;
	register int i;

	for (i = db_indent; i > 0; ){
	    if (i >= 8) {
		kdbprintf("\t");
		i -= 8;
	    }
	    else {
		kdbprintf(" ");
		i--;
	    }
	}

	va_start(listp, fmt);
	_doprnt(fmt, &listp, db_putchar, db_radix);
	va_end(listp);
}

void
db_output_prompt(void)
{
	db_printf("db%s", (db_default_act) ? "t": "");
	db_printf("{%d}", cpu_number());
	db_printf("> ");
}

