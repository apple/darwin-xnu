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
 * Revision 1.1.11.2  1995/01/06  19:10:24  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:39:54  dwm]
 *
 * Revision 1.1.11.1  1994/09/23  01:20:10  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:10:18  ezf]
 * 
 * Revision 1.1.4.3  1993/07/27  18:27:40  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:12:19  elliston]
 * 
 * Revision 1.1.4.2  1993/06/02  23:11:33  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:56:37  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:24:17  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/10/09  16:00:48  af
 * 	 Revision 2.4.3.1  91/10/05  13:06:34  jeffreyh
 * 	 	Added db_lex_context structure and some routine declarations
 * 	 	  for macro and conditinal command.
 * 	 	Added relational operator tokens etc. for condition expression.
 * 	 	Changed TOK_STRING_SIZE from 120 to 64, and defined
 * 	 	  DB_LEX_LINE_SIZE as 256 which was previously embedded
 * 	 	  in db_lex.c as 120.
 * 	 	[91/08/29            tak]
 * 	Revision 2.4.1 91/07/15  09:30:00  tak
 * 		Added db_lex_context for macro support
 * 		Added some lexical constants to support logical expression etc.
 * 		[91/05/15  13:55:00  tak]
 * 
 * Revision 2.4.3.1  91/10/05  13:06:34  jeffreyh
 * 	Added db_lex_context structure and some routine declarations
 * 	  for macro and conditinal command.
 * 	Added relational operator tokens etc. for condition expression.
 * 	Changed TOK_STRING_SIZE from 120 to 64, and defined
 * 	  DB_LEX_LINE_SIZE as 256 which was previously embedded
 * 	  in db_lex.c as 120.
 * 	[91/08/29            tak]
 * 
 * Revision 2.4.1 91/07/15  09:30:00  tak
 *	Added db_lex_context for macro support
 *	Added some lexical constants to support logical expression etc.
 *	[91/05/15  13:55:00  tak]
 *
 * Revision 2.4  91/05/14  15:34:38  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:06:41  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:18:28  mrt]
 * 
 * Revision 2.2  90/08/27  21:51:16  dbg
 * 	Add 'dotdot' token.
 * 	[90/08/22            dbg]
 * 	Export db_flush_lex.
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

#ifndef	_DDB_DB_LEX_H_
#define	_DDB_DB_LEX_H_

#include <machine/db_machdep.h>          /* For db_expr_t */

#define	TOK_STRING_SIZE		64 
#define DB_LEX_LINE_SIZE	256

struct db_lex_context {
	int  l_char;		/* peek char */
	int  l_token;		/* peek token */
	char *l_ptr;		/* line pointer */
	char *l_eptr;		/* line end pointer */
};

extern db_expr_t db_tok_number;
extern char	db_tok_string[TOK_STRING_SIZE];
extern db_expr_t db_radix;

#define	tEOF		(-1)
#define	tEOL		1
#define	tNUMBER		2
#define	tIDENT		3
#define	tPLUS		4
#define	tMINUS		5
#define	tDOT		6
#define	tSTAR		7
#define	tSLASH		8
#define	tEQ		9
#define	tLPAREN		10
#define	tRPAREN		11
#define	tPCT		12
#define	tHASH		13
#define	tCOMMA		14
#define	tQUOTE		15
#define	tDOLLAR		16
#define	tEXCL		17
#define	tSHIFT_L	18
#define	tSHIFT_R	19
#define	tDOTDOT		20
#define tSEMI_COLON	21
#define tLOG_EQ		22
#define tLOG_NOT_EQ	23
#define tLESS		24
#define tLESS_EQ	25
#define tGREATER	26
#define tGREATER_EQ	27
#define tBIT_AND	28
#define tBIT_OR		29
#define tLOG_AND	30
#define tLOG_OR		31
#define tSTRING		32
#define tQUESTION	33

/* Prototypes for functions exported by this module.
 */
int db_read_line(char *repeat_last);

void db_switch_input(
	char	*buffer,
	int	size);

void db_save_lex_context(struct db_lex_context *lp);

void db_restore_lex_context(struct db_lex_context *lp);

int db_read_char(void);

void db_unread_token(int t);

int db_read_token(void);

void db_flush_lex(void);

void db_skip_to_eol(void);

int db_lex(void);

#endif	/* !_DDB_DB_LEX_H_ */
