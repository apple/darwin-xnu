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
 * Revision 1.2.12.2  1994/09/23  01:20:43  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:10:36  ezf]
 *
 * Revision 1.2.12.1  1994/06/11  21:12:00  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/11  20:03:58  bolinger]
 * 
 * Revision 1.2.10.2  1994/03/07  16:37:44  paire
 * 	Added definition of indent.
 * 	[94/02/17            paire]
 * 
 * Revision 1.2.10.1  1994/02/08  10:58:14  bernadat
 * 	Added	db_reserve_output_position
 * 		db_reset_more
 * 	prototypes
 * 	[94/02/07            bernadat]
 * 
 * Revision 1.2.2.4  1993/08/11  22:12:12  elliston
 * 	Add ANSI Prototypes.  CR #9523.
 * 	[1993/08/11  03:33:44  elliston]
 * 
 * Revision 1.2.2.3  1993/07/27  18:27:52  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:12:35  elliston]
 * 
 * Revision 1.2.2.2  1993/06/09  02:20:29  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:56:49  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:02:43  devrcs
 * 	Changes from mk78:
 * 	db_printf is void.
 * 	[92/05/18            jfriedl]
 * 	[93/02/03            bruel]
 * 
 * Revision 1.1  1992/09/30  02:24:18  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  15:35:07  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:06:49  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:18:48  mrt]
 * 
 * Revision 2.2  90/08/27  21:51:32  dbg
 * 	Created.
 * 	[90/08/07            dbg]
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
 *	Date:	8/90
 */

/*
 * Printing routines for kernel debugger.
 */

#ifndef	_DDB_DB_OUTPUT_H_
#define	_DDB_DB_OUTPUT_H_

#include <mach/boolean.h>

extern int db_indent;

/*
 * Prototypes for functions exported by this module.
 */
void db_force_whitespace(void);
void db_putchar(char c);
int db_print_position(void);
void db_end_line(void);
void db_printf(char *fmt, ...);
void kdbprintf(char *fmt, ...);
void iprintf(char *fmt, ...);
boolean_t db_reserve_output_position(int len);
void db_reset_more(void);
void db_output_prompt(void);
#endif	/* !_DDB_DB_OUTPUT_H_ */
