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
 * Revision 1.1.11.3  1996/01/09  19:15:49  devrcs
 * 	Change 'register foo' to 'register int foo'.
 * 	[1995/12/01  21:42:12  jfraser]
 *
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:03:11  jfraser]
 *
 * Revision 1.1.11.2  1995/01/06  19:10:21  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	* Revision 1.1.4.6  1994/05/06  18:39:20  tmt
 * 	Merged osc1.3dec/shared with osc1.3b19
 * 	Merge Alpha changes into osc1.312b source code.
 * 	String protos.
 * 	64bit cleanup.
 * 	Cleanup to quiet gcc warnings.
 * 	* End1.3merge
 * 	[1994/11/04  08:49:35  dwm]
 * 
 * Revision 1.1.11.1  1994/09/23  01:19:59  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:10:14  ezf]
 * 
 * Revision 1.1.4.4  1993/08/11  20:37:55  elliston
 * 	Add ANSI Prototypes.  CR #9523.
 * 	[1993/08/11  03:33:26  elliston]
 * 
 * Revision 1.1.4.3  1993/07/27  18:27:38  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:12:13  elliston]
 * 
 * Revision 1.1.4.2  1993/06/02  23:11:27  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:56:32  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:01:10  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/10/09  16:00:20  af
 * 	 Revision 2.4.3.1  91/10/05  13:06:25  jeffreyh
 * 	 	Added relational operator tokens and string constant etc.
 * 	 	Added input switching functions for macro and conditional command.
 * 	 	Moved skip_to_eol() from db_command.c and added db_last_lp to print
 * 	 	  skipped input data as a warning message.
 * 	 	Added last input repetition support to db_read_line.
 * 	 	Changed db_lex() to always set db_tok_string for error message.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.4.3.1  91/10/05  13:06:25  jeffreyh
 * 	Added relational operator tokens and string constant etc.
 * 	Added input switching functions for macro and conditional command.
 * 	Moved skip_to_eol() from db_command.c and added db_last_lp to print
 * 	  skipped input data as a warning message.
 * 	Added last input repetition support to db_read_line.
 * 	Changed db_lex() to always set db_tok_string for error message.
 * 	[91/08/29            tak]
 * 
 * Revision 2.4  91/05/14  15:34:23  mrt
 * 	Correcting copyright
 *
 * Revision 2.3  91/02/05  17:06:36  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:18:20  mrt]
 * 
 * Revision 2.2  90/08/27  21:51:10  dbg
 * 	Add 'dotdot' token.
 * 	[90/08/22            dbg]
 * 
 * 	Allow backslash to quote any character into an identifier.
 * 	Allow colon in identifier for symbol table qualification.
 * 	[90/08/16            dbg]
 * 	Reduce lint.
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
/*
 * Lexical analyzer.
 */
#include <string.h>			/* For strcpy(), strncmp(), strlen() */
#include <ddb/db_lex.h>
#include <ddb/db_command.h>
#include <ddb/db_input.h>
#include <ddb/db_output.h>		/* For db_printf() */

char	db_line[DB_LEX_LINE_SIZE];
char	db_last_line[DB_LEX_LINE_SIZE];
char	*db_lp, *db_endlp;
char	*db_last_lp;
int	db_look_char = 0;
db_expr_t db_look_token = 0;


/* Prototypes for functions local to this file.  XXX -- should be static!
 */
void db_flush_line(void);
void db_unread_char(int c);


int
db_read_line(char *repeat_last)
{
	int	i;

	i = db_readline(db_line, sizeof(db_line));
	if (i == 0)
	    return (0);	/* EOI */
	if (repeat_last) {
	    if (strncmp(db_line, repeat_last, strlen(repeat_last)) == 0) {
		strcpy(db_line, db_last_line);
		db_printf("%s", db_line);
		i = strlen(db_line);
	    } else if (db_line[0] != '\n' && db_line[0] != 0)
		strcpy(db_last_line, db_line);
	}
	db_lp = db_line;
	db_endlp = db_lp + i;
	db_last_lp = db_lp;
	db_look_char = 0;
	db_look_token = 0;
	return (i);
}

void
db_flush_line(void)
{
	db_lp = db_line;
	db_last_lp = db_lp;
	db_endlp = db_line;
}

void
db_switch_input(
	char	*buffer,
	int	size)
{
	db_lp = buffer;
	db_last_lp = db_lp;
	db_endlp = buffer + size;
	db_look_char = 0;
	db_look_token = 0;
}

void
db_save_lex_context(register struct db_lex_context *lp)
{
	lp->l_ptr = db_lp;
	lp->l_eptr = db_endlp;
	lp->l_char = db_look_char;
	lp->l_token = db_look_token;
}

void
db_restore_lex_context(register struct db_lex_context *lp)
{
	db_lp = lp->l_ptr;
	db_last_lp = db_lp;
	db_endlp = lp->l_eptr;
	db_look_char = lp->l_char;
	db_look_token = lp->l_token;
}

int
db_read_char(void)
{
	int	c;

	if (db_look_char != 0) {
	    c = db_look_char;
	    db_look_char = 0;
	}
	else if (db_lp >= db_endlp)
	    c = -1;
	else 
	    c = *db_lp++;
	return (c);
}

void
db_unread_char(int c)
{
	db_look_char = c;
}

void
db_unread_token(int t)
{
	db_look_token = t;
}

int
db_read_token(void)
{
	int	t;

	if (db_look_token) {
	    t = db_look_token;
	    db_look_token = 0;
	}
	else {
	    db_last_lp = db_lp;
	    if (db_look_char)
		db_last_lp--;
	    t = db_lex();
	}
	return (t);
}

db_expr_t db_tok_number;
char	db_tok_string[TOK_STRING_SIZE];

db_expr_t db_radix = 16;

void
db_flush_lex(void)
{
	db_flush_line();
	db_look_char = 0;
	db_look_token = 0;
}

#define	DB_DISP_SKIP	40		/* number of chars to display skip */

void
db_skip_to_eol(void)
{
	register int skip;
	register int t;
	register int n;
	register char *p;

	t = db_read_token();
	p = db_last_lp;
	for (skip = 0; t != tEOL && t != tSEMI_COLON && t != tEOF; skip++)
	    t = db_read_token();
	if (t == tSEMI_COLON)
	    db_unread_token(t);
	if (skip != 0) {
	    while (p < db_last_lp && (*p == ' ' || *p == '\t'))
		p++;
	    db_printf("Warning: Skipped input data \"");
	    for (n = 0; n < DB_DISP_SKIP && p < db_last_lp; n++)
		db_printf("%c", *p++);
	    if (n >= DB_DISP_SKIP)
		db_printf("....");
	    db_printf("\"\n");
	}
}

int
db_lex(void)
{
	register char *cp;
	register int c;

	c = db_read_char();
	while (c <= ' ' || c > '~') {
	    if (c == '\n' || c == -1)
		return (tEOL);
	    c = db_read_char();
	}

	cp = db_tok_string;
	*cp++ = c;

	if (c >= '0' && c <= '9') {
	    /* number */
	    int	r, digit;

	    if (c > '0')
		r = db_radix;
	    else {
		c = db_read_char();
		if (c == 'O' || c == 'o')
		    r = 8;
		else if (c == 'T' || c == 't')
		    r = 10;
		else if (c == 'X' || c == 'x')
		    r = 16;
		else {
		    cp--;
		    r = db_radix;
		    db_unread_char(c);
		}
		c = db_read_char();
		*cp++ = c;
	    }
	    db_tok_number = 0;
	    for (;;) {
		if (c >= '0' && c <= ((r == 8) ? '7' : '9'))
		    digit = c - '0';
		else if (r == 16 && ((c >= 'A' && c <= 'F') ||
				     (c >= 'a' && c <= 'f'))) {
		    if (c >= 'a')
			digit = c - 'a' + 10;
		    else
			digit = c - 'A' + 10;
		}
		else
		    break;
		db_tok_number = db_tok_number * r + digit;
		c = db_read_char();
		if (cp < &db_tok_string[sizeof(db_tok_string)-1])
			*cp++ = c;
	    }
	    cp[-1] = 0;
	    if ((c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c == '_'))
	    {
		db_printf("Bad character '%c' after number %s\n", 
				c, db_tok_string);
		db_error(0);
		db_flush_lex();
		return (tEOF);
	    }
	    db_unread_char(c);
	    return (tNUMBER);
	}
	if ((c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z') ||
	    c == '_' || c == '\\' || c == ':')
	{
	    /* identifier */
	    if (c == '\\') {
		c = db_read_char();
		if (c == '\n' || c == -1)
		    db_error("Bad '\\' at the end of line\n");
	        cp[-1] = c;
	    }
	    while (1) {
		c = db_read_char();
		if ((c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
		    c == '_' || c == '\\' || c == ':' || c == '.')
		{
		    if (c == '\\') {
			c = db_read_char();
			if (c == '\n' || c == -1)
			    db_error("Bad '\\' at the end of line\n");
		    }
		    *cp++ = c;
		    if (cp == db_tok_string+sizeof(db_tok_string)) {
			db_error("String too long\n");
			db_flush_lex();
			return (tEOF);
		    }
		    continue;
		}
		else {
		    *cp = '\0';
		    break;
		}
	    }
	    db_unread_char(c);
	    return (tIDENT);
	}

	*cp = 0;
	switch (c) {
	    case '+':
		return (tPLUS);
	    case '-':
		return (tMINUS);
	    case '.':
		c = db_read_char();
		if (c == '.') {
		    *cp++ = c;
		    *cp = 0;
		    return (tDOTDOT);
		}
		db_unread_char(c);
		return (tDOT);
	    case '*':
		return (tSTAR);
	    case '/':
		return (tSLASH);
	    case '=':
		c = db_read_char();
		if (c == '=') {
		    *cp++ = c;
		    *cp = 0;
		    return(tLOG_EQ);
		}
		db_unread_char(c);
		return (tEQ);
	    case '%':
		return (tPCT);
	    case '#':
		return (tHASH);
	    case '(':
		return (tLPAREN);
	    case ')':
		return (tRPAREN);
	    case ',':
		return (tCOMMA);
	    case '\'':
		return (tQUOTE);
	    case '"':
		/* string */
		cp = db_tok_string;
		c = db_read_char();
		while (c != '"' && c > 0 && c != '\n') {
		    if (cp >= &db_tok_string[sizeof(db_tok_string)-1]) {
			db_error("Too long string\n");
			db_flush_lex();
			return (tEOF);
		    }
		    if (c == '\\') {
			c = db_read_char();
			switch(c) {
			case 'n':
			    c = '\n'; break;
			case 't':
			    c = '\t'; break;
			case '\\':
			case '"':
			    break;
			default:
			    db_printf("Bad escape sequence '\\%c'\n", c);
			    db_error(0);
			    db_flush_lex();
			    return (tEOF);
			}
		    }
		    *cp++ = c;
		    c = db_read_char();
		}
		*cp = 0;
		if (c != '"') {
		    db_error("Non terminated string constant\n");
		    db_flush_lex();
		    return (tEOF);
		}
		return (tSTRING);
	    case '$':
		return (tDOLLAR);
	    case '!':
		c = db_read_char();
		if (c == '=') {
		    *cp++ = c;
		    *cp = 0;
		    return(tLOG_NOT_EQ);
		}
		db_unread_char(c);
		return (tEXCL);
	    case '&':
		c = db_read_char();
		if (c == '&') {
		    *cp++ = c;
		    *cp = 0;
		    return(tLOG_AND);
		}
		db_unread_char(c);
		return(tBIT_AND);
	    case '|':
		c = db_read_char();
		if (c == '|') {
		    *cp++ = c;
		    *cp = 0;
		    return(tLOG_OR);
		}
		db_unread_char(c);
		return(tBIT_OR);
	    case '<':
		c = db_read_char();
		*cp++ = c;
		*cp = 0;
		if (c == '<')
		    return (tSHIFT_L);
		if (c == '=')
		    return (tLESS_EQ);
		cp[-1] = 0;
		db_unread_char(c);
		return(tLESS);
		break;
	    case '>':
		c = db_read_char();
		*cp++ = c;
		*cp = 0;
		if (c == '>')
		    return (tSHIFT_R);
		if (c == '=')
		    return (tGREATER_EQ);
		cp[-1] = 0;
		db_unread_char(c);
		return (tGREATER);
		break;
	    case ';':
		return (tSEMI_COLON);
	    case '?':
		return (tQUESTION);
	    case -1:
		strcpy(db_tok_string, "<EOL>");
		return (tEOF);
	}
	db_printf("Bad character '%c'\n", c);
	db_flush_lex();
	return (tEOF);
}
