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
 * Revision 1.1.1.1  1998/09/22 21:05:47  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.15.1  1997/03/27  18:46:27  barbou
 * 	Add #include <db_machine_commands.h> so that DB_MACHINE_COMMANDS
 * 	can be defined.
 * 	Move here from db_commands.c the prototype for
 * 	db_machine_commands_install(), referenced by PARAGON/model_dep.c.
 * 	[97/02/25            barbou]
 *
 * Revision 1.1.9.2  1994/09/23  01:18:19  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:09:33  ezf]
 * 
 * Revision 1.1.9.1  1994/06/11  21:11:39  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/11  20:03:50  bolinger]
 * 
 * Revision 1.1.7.1  1994/04/11  09:34:47  bernadat
 * 	Added db_command struct decalration.
 * 	[94/03/17            bernadat]
 * 
 * Revision 1.1.2.3  1993/07/27  18:26:57  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:11:08  elliston]
 * 
 * Revision 1.1.2.2  1993/06/02  23:10:38  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:56:00  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:24:14  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.6  91/10/09  15:58:45  af
 * 	 Revision 2.5.2.1  91/10/05  13:05:30  jeffreyh
 * 	 	Added db_exec_conditional_cmd(), and db_option().
 * 	 	Deleted db_skip_to_eol().
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.5.2.1  91/10/05  13:05:30  jeffreyh
 * 	Added db_exec_conditional_cmd(), and db_option().
 * 	Deleted db_skip_to_eol().
 * 	[91/08/29            tak]
 * 
 * Revision 2.5  91/07/09  23:15:46  danner
 * 	Grabbed up to date copyright.
 * 	[91/07/08            danner]
 * 
 * Revision 2.2  91/04/10  16:02:32  mbj
 * 	Grabbed 3.0 copyright/disclaimer since ddb comes from 3.0.
 * 	[91/04/09            rvb]
 * 
 * Revision 2.3  91/02/05  17:06:15  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:17:28  mrt]
 * 
 * Revision 2.2  90/08/27  21:50:19  dbg
 * 	Replace db_last_address_examined with db_prev, db_next.
 * 	[90/08/22            dbg]
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
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */
/*
 * Command loop declarations.
 */

#ifndef	_DDB_DB_COMMAND_H_
#define	_DDB_DB_COMMAND_H_

#include <machine/db_machdep.h>
#include <db_machine_commands.h>

typedef void	(*db_func)(db_expr_t, int, db_expr_t, char *);

/*
 * Command table
 */
struct db_command {
	char *	name;		/* command name */
	db_func	fcn;		/* function to call */
	int	flag;		/* extra info: */
#define	CS_OWN		0x1	    /* non-standard syntax */
#define	CS_MORE		0x2	    /* standard syntax, but may have other
				       words at end */
#define	CS_SET_DOT	0x100	    /* set dot after command */
	struct db_command *more;   /* another level of command */
};


extern db_addr_t	db_dot;		/* current location */
extern db_addr_t	db_last_addr;	/* last explicit address typed */
extern db_addr_t	db_prev;	/* last address examined
					   or written */
extern db_addr_t	db_next;	/* next address to be examined
					   or written */


/* Prototypes for functions exported by this module.
 */

void db_command_loop(void);

void db_machine_commands_install(struct db_command *ptr);

boolean_t db_exec_cmd_nest(
	char	*cmd,
	int	size);

void db_error(char *s);

boolean_t db_option(
	char	*modif,
	int	option);

#endif	/* !_DDB_DB_COMMAND_H_ */
