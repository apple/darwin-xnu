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
 * Revision 1.2.20.6  1996/01/09  19:16:22  devrcs
 * 	Add proto for db_task_getlinenum().
 * 	[1995/12/01  21:42:34  jfraser]
 *
 * Revision 1.2.20.5  1995/02/28  01:58:53  dwm
 * 	Merged with changes from 1.2.20.4
 * 	[1995/02/28  01:53:54  dwm]
 * 
 * 	mk6 CR1120 - Merge mk6pro_shared into cnmk_shared
 * 	[1995/02/28  01:12:57  dwm]
 * 
 * Revision 1.2.20.4  1995/02/23  21:43:48  alanl
 * 	Prepend a "db_" to qsort and qsort_limit_search
 * 	(collisions with the real qsort in stdlib.h)
 * 	[95/02/14            travos]
 * 
 * 	Expanded db_sym_switch structure to make ddb object format dependent;
 * 	this allows us to remove all of the aout dependencies.
 * 	[95/01/24            sjs]
 * 
 * Revision 1.2.23.4  1994/12/22  20:36:20  bolinger
 * 	Fix ri-osc CR881:  Fixed glitch in use of symtab cloning hack.
 * 	[1994/12/22  20:35:17  bolinger]
 * 
 * Revision 1.2.23.3  1994/11/02  18:36:07  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup, prototypes
 * 	fix X_db_search_by_addr macro to match prototype
 * 	[1994/11/02  18:16:20  dwm]
 * 
 * Revision 1.2.20.4  1995/02/23  21:43:48  alanl
 * 	Prepend a "db_" to qsort and qsort_limit_search
 * 	(collisions with the real qsort in stdlib.h)
 * 	[95/02/14            travos]
 * 
 * 	Expanded db_sym_switch structure to make ddb object format dependent;
 * 	this allows us to remove all of the aout dependencies.
 * 	[95/01/24            sjs]
 * 
 * Revision 1.2.23.4  1994/12/22  20:36:20  bolinger
 * 	Fix ri-osc CR881:  Fixed glitch in use of symtab cloning hack.
 * 	[1994/12/22  20:35:17  bolinger]
 * 
 * Revision 1.2.23.3  1994/11/02  18:36:07  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup, prototypes
 * 	fix X_db_search_by_addr macro to match prototype
 * 	[1994/11/02  18:16:20  dwm]
 * 
 * Revision 1.2.20.2  1994/09/23  01:21:51  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:11:04  ezf]
 * 
 * Revision 1.2.20.1  1994/06/11  21:12:25  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/11  20:04:14  bolinger]
 * 
 * Revision 1.2.14.1  1994/02/08  10:58:56  bernadat
 * 	Added db_sym_print_completion
 * 	      db_sym_parse_and_lookup_incomplete
 * 	      db_sym_parse_and_print_completion
 * 	      db_print_completion
 * 	      db_lookup_incomplete
 * 	      ddb_init
 * 	prototypes
 * 
 * 	Changed func type to db_sym_parse_and_lookup prototype
 * 
 * 	Added definition of db_maxoff.
 * 	[93/08/12            paire]
 * 	[94/02/07            bernadat]
 * 
 * Revision 1.2.18.1  1994/06/08  19:11:28  dswartz
 * 	Preemption merge.
 * 	[1994/06/08  19:10:27  dswartz]
 * 
 * Revision 1.2.17.2  1994/06/01  21:34:50  klj
 * 	Initial preemption code base merge
 * 
 * Revision 1.2.4.3  1993/07/27  18:28:12  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:13:02  elliston]
 * 
 * Revision 1.2.4.2  1993/06/09  02:20:56  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:57:18  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:03:18  devrcs
 * 	Added 3 new fields in db_symtab_t for sorting.
 * 	[barbou@gr.osf.org]
 * 	[92/12/03            bernadat]
 * 
 * Revision 1.1  1992/09/30  02:24:22  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.6  91/10/09  16:02:45  af
 * 	 Revision 2.5.1.1  91/10/05  13:07:39  jeffreyh
 * 	 	Added macro definitions of db_find_task_sym_and_offset(),
 * 	 	  db_find_xtrn_task_sym_and_offset(), db_search_symbol().
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.5.1.1  91/10/05  13:07:39  jeffreyh
 * 	Added macro definitions of db_find_task_sym_and_offset(),
 * 	  db_find_xtrn_task_sym_and_offset(), db_search_symbol().
 * 	[91/08/29            tak]
 * 
 * Revision 2.5  91/07/31  17:31:49  dbg
 * 	Add map pointer and storage for name to db_symtab_t.
 * 	[91/07/30  16:45:08  dbg]
 * 
 * Revision 2.4  91/05/14  15:36:08  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:07:12  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:19:27  mrt]
 * 
 * Revision 2.2  90/08/27  21:52:39  dbg
 * 	Changed type of db_sym_t to char * - it's a better type for an
 * 	opaque pointer.
 * 	[90/08/22            dbg]
 * 
 * 	Created.
 * 	[90/08/19            af]
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
 * 	Author: Alessandro Forin, Carnegie Mellon University
 *	Date:	8/90
 */

#ifndef	_DDB_DB_SYM_H_
#define	_DDB_DB_SYM_H_

#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <machine/db_machdep.h>
#include <kern/task.h>

/*
 * This module can handle multiple symbol tables,
 * of multiple types, at the same time
 */
#define	SYMTAB_NAME_LEN	32

typedef struct {
	int		type;
#define	SYMTAB_AOUT	0
#define	SYMTAB_COFF	1
#define	SYMTAB_MACHDEP	2
	char		*start;		/* symtab location */
	char		*end;
	char		*private;	/* optional machdep pointer */
	char		*map_pointer;	/* symbols are for this map only,
					   if not null */
	char		name[SYMTAB_NAME_LEN];
					/* symtab name */
	unsigned long	minsym;		/* lowest symbol value */
	unsigned long	maxsym;		/* highest symbol value */
	boolean_t	sorted;		/* is this table sorted ? */
} db_symtab_t;

extern db_symtab_t	*db_last_symtab; /* where last symbol was found */

/*
 * Symbol representation is specific to the symtab style:
 * BSD compilers use dbx' nlist, other compilers might use
 * a different one
 */
typedef	void *		db_sym_t;	/* opaque handle on symbols */
#define	DB_SYM_NULL	((db_sym_t)0)

/*
 * Non-stripped symbol tables will have duplicates, for instance
 * the same string could match a parameter name, a local var, a
 * global var, etc.
 * We are most concern with the following matches.
 */
typedef int		db_strategy_t;	/* search strategy */

#define	DB_STGY_ANY	0			/* anything goes */
#define DB_STGY_XTRN	1			/* only external symbols */
#define DB_STGY_PROC	2			/* only procedures */

extern boolean_t	db_qualify_ambiguous_names;
					/* if TRUE, check across symbol tables
					 * for multiple occurrences of a name.
					 * Might slow down quite a bit */

extern unsigned long	db_maxoff;

/* Prototypes for functions exported by this module.
 */
extern boolean_t db_add_symbol_table(
	int		type,
	char		*start,
	char		*end,
	char		*name,
	char		*ref,
	char		*map_pointer,
	unsigned long	minsym,
	unsigned long	maxsym,
	boolean_t	sorted);

extern void db_install_inks(
	vm_offset_t	base);

extern boolean_t db_value_of_name(
	char		*name,
	db_expr_t	*valuep);

extern db_sym_t db_lookup(char *symstr);

extern char * db_get_sym(
	db_expr_t	* off);

extern db_sym_t db_sym_parse_and_lookup(
	int	(*func)(db_symtab_t *,
			char *,
			char *,
			int,
			db_sym_t*,
			char **,
			int *),
	db_symtab_t	*symtab,
	char		*symstr);

extern int db_sym_parse_and_lookup_incomplete(
	int	(*func)(db_symtab_t *,
			char *,
			char *,
			int,
			db_sym_t*,
			char **,
			int *),
	db_symtab_t	*symtab,
	char		*symstr,
	char		**name,
	int		*len,
	int		*toadd);

extern int db_sym_parse_and_print_completion(
	int	(*func)(db_symtab_t *,
			char *),
	db_symtab_t	*symtab,
	char		*symstr);

extern db_sym_t db_search_task_symbol(
	db_addr_t		val,
	db_strategy_t		strategy,
	db_addr_t		*offp,
	task_t			task);

extern db_sym_t db_search_task_symbol_and_line(
	db_addr_t		val,
	db_strategy_t		strategy,
	db_expr_t		*offp,
	char			**filenamep,
	int			*linenump,
	task_t			task,
	int			*argsp);

extern void db_symbol_values(
	db_symtab_t	*stab,
	db_sym_t	sym,
	char		**namep,
	db_expr_t	*valuep);

extern void db_task_printsym(
	db_expr_t	off,
	db_strategy_t	strategy,
	task_t		task);

extern void db_printsym(
	db_expr_t	off,
	db_strategy_t	strategy);

extern boolean_t db_line_at_pc(
	db_sym_t	sym,
	char		**filename,
	int		*linenum,
	db_expr_t	pc);

extern void db_qsort(
	char	*table,
	int	nbelts,
	int	eltsize,
	int	(*compfun)(char *, char *));

extern void db_qsort_limit_search(
	char	*target,
	char	**start,
	char	**end,
	int	eltsize,
	int	(*compfun)(char *, char *));

extern void db_sym_print_completion(
	db_symtab_t *stab,
	char *name,
	int function,
	char *fname,
	int line);

extern void db_print_completion(
	char *symstr);

extern int db_lookup_incomplete(
	char *symstr,
	int symlen);

extern void ddb_init(void);

extern void db_machdep_init(void);

extern void db_clone_symtabXXX(char *, char *, vm_offset_t);

extern db_symtab_t *db_symtab_cloneeXXX(char *);

extern db_task_getlinenum( db_expr_t, task_t);

/* Some convenience macros.
 */
#define db_find_sym_and_offset(val,namep,offp)	\
	db_symbol_values(0, db_search_symbol(val,DB_STGY_ANY,offp),namep,0)
					/* find name&value given approx val */

#define db_find_xtrn_sym_and_offset(val,namep,offp)	\
	db_symbol_values(0, db_search_symbol(val,DB_STGY_XTRN,offp),namep,0)
					/* ditto, but no locals */

#define db_find_task_sym_and_offset(val,namep,offp,task)	\
	db_symbol_values(0, db_search_task_symbol(val,DB_STGY_ANY,offp,task),  \
			 namep, 0)	/* find name&value given approx val */

#define db_find_xtrn_task_sym_and_offset(val,namep,offp,task)	\
	db_symbol_values(0, db_search_task_symbol(val,DB_STGY_XTRN,offp,task), \
			 namep,0)	/* ditto, but no locals */

#define db_search_symbol(val,strgy,offp)	\
	db_search_task_symbol(val,strgy,offp,0)
					/* find symbol in current task */

/*
 * Symbol table switch, defines the interface
 * to symbol-table specific routines.
 */

extern struct db_sym_switch {

	void		(*init)(void);

	boolean_t	(*sym_init)(
				char *start,
				char *end,
				char *name,
				char *task_addr
				);

	db_sym_t	(*lookup)(
				db_symtab_t *stab,
				char *symstr
				);
	db_sym_t	(*search_symbol)(
				db_symtab_t *stab,
				db_addr_t off,
				db_strategy_t strategy,
				db_expr_t *diffp
				);

	boolean_t	(*line_at_pc)(
				db_symtab_t	*stab,
				db_sym_t	sym,
				char		**file,
				int		*line,
				db_expr_t	pc
				);

	void		(*symbol_values)(
				db_sym_t	sym,
				char		**namep,
				db_expr_t	*valuep
				);
	db_sym_t	(*search_by_addr)(
				db_symtab_t	*stab,
				db_addr_t	off,
				char		**file,
				char		**func,
				int		*line,
				db_expr_t	*diffp,
				int		*args
				);

	int		(*print_completion)(
				db_symtab_t	*stab,
				char		*symstr
				);

	int		(*lookup_incomplete)(
				db_symtab_t	*stab,
				char		*symstr,
				char		**name,
				int		*len,
				int		*toadd
				);
} x_db[];

#ifndef	symtab_type
#define	symtab_type(s)		SYMTAB_AOUT
#endif

#define	X_db_init()			x_db[symtab_type(s)].init()
#define	X_db_sym_init(s,e,n,t)		x_db[symtab_type(s)].sym_init(s,e,n,t)
#define	X_db_lookup(s,n)		x_db[(s)->type].lookup(s,n)
#define	X_db_search_symbol(s,o,t,d)	x_db[(s)->type].search_symbol(s,o,t,d)
#define	X_db_line_at_pc(s,p,f,l,a)	x_db[(s)->type].line_at_pc(s,p,f,l,a)
#define	X_db_symbol_values(s,p,n,v)	x_db[(s)->type].symbol_values(p,n,v)
#define X_db_search_by_addr(s,a,f,c,l,d,r) \
			x_db[(s)->type].search_by_addr(s,a,f,c,l,d,r)
#define	X_db_print_completion(s,p)	x_db[(s)->type].print_completion(s,p)
#define	X_db_lookup_incomplete(s,p,n,l,t)	\
			x_db[(s)->type].lookup_incomplete(s,p,n,l,t)

#endif	/* !_DDB_DB_SYM_H_ */
