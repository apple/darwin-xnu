/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * Revision 1.1.6.1  1994/09/23  01:20:28  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:10:28  ezf]
 *
 * Revision 1.1.2.3  1993/09/17  21:34:39  robert
 * 	change marker to OSF_FREE_COPYRIGHT
 * 	[1993/09/17  21:27:20  robert]
 * 
 * Revision 1.1.2.2  1993/07/27  18:27:48  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:12:28  elliston]
 * 
 * $EndLog$
 */

#ifndef	_DDB_DB_MACRO_H_
#define	_DDB_DB_MACRO_H_

#include <machine/db_machdep.h>
#include <ddb/db_variables.h>

/* Prototypes for functions exported by this module.
 */
void db_def_macro_cmd(void);

void db_del_macro_cmd(void);

void db_show_macro(void);

int db_exec_macro(char *name);

int db_arg_variable(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int			flag,
	db_var_aux_param_t	ap);

#endif	/* !_DDB_DB_MACRO_H_ */
