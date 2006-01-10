/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

extern int db_task_getlinenum( db_expr_t, task_t);

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
