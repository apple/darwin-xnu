/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
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
 * Revision 1.1.2.1  1995/02/23  16:34:08  alanl
 * 	Initial file creation.
 * 	[95/02/06            sjs]
 *
 * $EndLog$
 */

#ifndef	_DDB_DB_COFF_H_
#define	_DDB_DB_COFF_H_

#define DB_NO_AOUT	1


/*
 * Symbol table routines for COFF format files.
 */

boolean_t coff_db_sym_init(
	char *	symtab,
	char *	esymtab,
	const char *	name,
	char *	task_addr);

db_sym_t coff_db_lookup(
	db_symtab_t	*stab,
	char *		symstr);

int coff_db_lookup_incomplete(
	db_symtab_t	*stab,
	char *		symstr,
	char **		name,
	int		*len,
	int		*toadd);

int coff_db_print_completion(
	db_symtab_t	*stab,
	char *		symstr);

db_sym_t coff_db_search_symbol(
	db_symtab_t	*symtab,
	db_addr_t	off,
	db_strategy_t	strategy,
	db_expr_t	*diffp);		/* in/out */

void coff_db_symbol_values(
	db_sym_t	sym,
	char		**namep,
	db_expr_t	*valuep);

db_sym_t coff_db_search_by_addr(
	db_symtab_t	*stab,
	db_addr_t	addr,
	char		**file,
	char		**func,
	int 	 	*line,
	db_expr_t	*diff,
	int 		*args);

boolean_t coff_db_line_at_pc(
	db_symtab_t	*stab,
	db_sym_t	sym,
	char		**file,
	int		*line,
	db_expr_t	pc);

int coff_db_qualified_print_completion(
	db_symtab_t	*stab,
	char		*sym);

void coff_db_init(void);

#endif	/* !_DDB_DB_COFF_H_ */
