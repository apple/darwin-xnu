/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <machine/db_machdep.h>
#include <string.h>			/* For strcpy(), strcmp() */
#include <mach/std_types.h>
#include <kern/misc_protos.h>		/* For printf() */
#include <ddb/db_sym.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>		/* For db_printf() */

#include <vm/vm_map.h>	/* vm_map_t */

/*
 * Multiple symbol tables
 *
 * mach, bootstrap, name_server, default_pager, unix, 1 spare
 */
#define	MAXNOSYMTABS	6

db_symtab_t	db_symtabs[MAXNOSYMTABS] = {{0}};
int db_nsymtab = 0;

db_symtab_t	*db_last_symtab;

unsigned long	db_maxoff = 0x4000;
extern		char end;
unsigned long	db_maxval = (unsigned long)&end;
natural_t	db_minval = 0x1000;

/* Prototypes for functions local to this file.  XXX -- should be static!
 */
static char *db_qualify(
	char		*sym,
	register char	*symtabname);

boolean_t db_eqname(
	char		*src,
	char		*dst,
	unsigned	c);

boolean_t db_symbol_is_ambiguous(char *name);

void db_shorten_filename(char **filenamep);

void qsort_swap(
	register int	*a,
	register int	*b,
	register int	size);

void qsort_rotate(
	register int	*a,
	register int	*b,
	register int	*c,
	register int	size);

void qsort_recur(
	char	*left,
	char	*right,
	int	eltsize,
	int	(*compfun)(char *, char *));

void qsort_checker(
	char	*table,
	int	nbelts,
	int	eltsize,
	int	(*compfun)(char *, char *));

void bubble_sort(
	char	*table,
	int	nbelts,
	int	eltsize,
	int	(*compfun)(char *, char *));

int no_print_completion(
	db_symtab_t	*stab,
	char		*symstr	);
int no_lookup_incomplete(
	db_symtab_t	*stab,
	char		*symstr,
	char		**name,
	int		*len,
	int		*toadd);

/*
 * Initialization routine for ddb.
 */
void
ddb_init(void)
{
	X_db_init();
	db_machdep_init();
}

/*
 * Add symbol table, with given name, to list of symbol tables.
 */
boolean_t
db_add_symbol_table(
	int		type,
	char		*start,
	char		*end,
	char		*name,
	char		*ref,
	char		*map_pointer,
	unsigned long	minsym,
	unsigned long	maxsym,
	boolean_t	sorted)
{
	register db_symtab_t *st;
	extern vm_map_t kernel_map;

	if (db_nsymtab >= MAXNOSYMTABS)
	    return (FALSE);

	st = &db_symtabs[db_nsymtab];
	st->type = type;
	st->start = start;
	st->end = end;
	st->private = ref;
	if (map_pointer == (char *)kernel_map || 
	    (VM_MAX_ADDRESS <= VM_MIN_KERNEL_ADDRESS &&
	     VM_MIN_KERNEL_ADDRESS <= minsym))
		st->map_pointer = 0;
	else
		st->map_pointer = map_pointer;
	strcpy(st->name, name);
	st->minsym = minsym;
	st->maxsym = maxsym;
	if (maxsym == 0)
		st->sorted = FALSE;
	else {
		st->sorted = sorted;
		if (db_maxval < maxsym + db_maxoff)
			db_maxval = maxsym + db_maxoff;
	}
	db_nsymtab++;

	return (TRUE);
}

/*
 *  db_qualify("vm_map", "ux") returns "ux::vm_map".
 *
 *  Note: return value points to static data whose content is
 *  overwritten by each call... but in practice this seems okay.
 */
static char *
db_qualify(
	char		*symname,
	register char	*symtabname)
{
	static char     tmp[256];
	register char	*s;

	s = tmp;
	while (*s++ = *symtabname++) {
	}
	s[-1] = ':';
	*s++ = ':';
	while (*s++ = *symname++) {
	}
	return tmp;
}


boolean_t
db_eqname(
	char		*src,
	char		*dst,
	unsigned	c)
{
	if (!strcmp(src, dst))
	    return (TRUE);
	if (src[0] == c)
	    return (!strcmp(src+1,dst));
	return (FALSE);
}

boolean_t
db_value_of_name(
	char		*name,
	db_expr_t	*valuep)
{
	db_sym_t	sym;

	sym = db_lookup(name);
	if (sym == DB_SYM_NULL)
	    return (FALSE);
	db_symbol_values(0, sym, &name, valuep);
	return (TRUE);
}

/*
 * Display list of possible completions for a symbol.
 */
void
db_print_completion(
	char *symstr)
{
	register int i;
	int symtab_start = 0;
	int symtab_end = db_nsymtab;
	register char *cp;
	int nsym = 0;
	char *name = (char *)0;
	int len;
	int toadd;

	/*
	 * Look for, remove, and remember any symbol table specifier.
	 */
	for (cp = symstr; *cp; cp++) {
		if (*cp == ':' && cp[1] == ':') {
			*cp = '\0';
			for (i = 0; i < db_nsymtab; i++) {
				if (! strcmp(symstr, db_symtabs[i].name)) {
					symtab_start = i;
					symtab_end = i + 1;
					break;
				}
			}
			*cp = ':';
			if (i == db_nsymtab)
				return;
			symstr = cp+2;
		}
	}

	/*
	 * Look in the specified set of symbol tables.
	 * Return on first match.
	 */
	for (i = symtab_start; i < symtab_end; i++) {
		if (X_db_print_completion(&db_symtabs[i], symstr))
			break;
	}
}

/*
 * Lookup a (perhaps incomplete) symbol.
 * If the symbol has a qualifier (e.g., ux::vm_map),
 * then only the specified symbol table will be searched;
 * otherwise, all symbol tables will be searched.
 */
int
db_lookup_incomplete(
	char *symstr,
	int symlen)
{
	register int i;
	int symtab_start = 0;
	int symtab_end = db_nsymtab;
	register char *cp;
	int nsym = 0;
	char *name = (char *)0;
	int len;
	int toadd;

	/*
	 * Look for, remove, and remember any symbol table specifier.
	 */
	for (cp = symstr; *cp; cp++) {
		if (*cp == ':' && cp[1] == ':') {
			*cp = '\0';
			for (i = 0; i < db_nsymtab; i++) {
				if (! strcmp(symstr, db_symtabs[i].name)) {
					symtab_start = i;
					symtab_end = i + 1;
					break;
				}
			}
			*cp = ':';
			if (i == db_nsymtab)
				return 0;
			symstr = cp+2;
		}
	}

	/*
	 * Look in the specified set of symbol tables.
	 * Return on first match.
	 */
	for (i = symtab_start; i < symtab_end; i++) {
		nsym = X_db_lookup_incomplete(&db_symtabs[i], symstr,
					      &name, &len, &toadd);
		if (nsym > 0) {
			if (toadd > 0) {
				len = strlen(symstr);
				if (len + toadd >= symlen)
					return 0;
				bcopy(&name[len], &symstr[len], toadd);
				symstr[len + toadd] = '\0';
			}
			break;
		}
	}
	return nsym;
}

/*
 * Lookup a symbol.
 * If the symbol has a qualifier (e.g., ux::vm_map),
 * then only the specified symbol table will be searched;
 * otherwise, all symbol tables will be searched.
 */
db_sym_t
db_lookup(char *symstr)
{
	db_sym_t sp;
	register int i;
	int symtab_start = 0;
	int symtab_end = db_nsymtab;
	register char *cp;

	/*
	 * Look for, remove, and remember any symbol table specifier.
	 */
	for (cp = symstr; *cp; cp++) {
		if (*cp == ':' && cp[1] == ':') {
			*cp = '\0';
			for (i = 0; i < db_nsymtab; i++) {
				if (! strcmp(symstr, db_symtabs[i].name)) {
					symtab_start = i;
					symtab_end = i + 1;
					break;
				}
			}
			*cp = ':';
			if (i == db_nsymtab)
				db_error("Invalid symbol table name\n");
			symstr = cp+2;
		}
	}

	/*
	 * Look in the specified set of symbol tables.
	 * Return on first match.
	 */
	for (i = symtab_start; i < symtab_end; i++) {
		if (sp = X_db_lookup(&db_symtabs[i], symstr)) {
			db_last_symtab = &db_symtabs[i];
			return sp;
		}
	}
	return 0;
}

/*
 * Print a symbol completion
 */
void
db_sym_print_completion(
	db_symtab_t *stab,
	char *name,
	int function,
	char *fname,
	int line)
{
	if (stab != db_symtabs)
		db_printf("%s::", stab->name);
	db_printf(name);
	if (function) {
	    db_putchar('(');
	    db_putchar(')');
	}
	if (fname) {
	    db_printf(" [static from %s", fname);
	    if (line > 0)
		db_printf(":%d", line);
	    db_putchar(']');
	}
	db_putchar('\n');
}

/*
 * Common utility routine to parse a symbol string into a file
 * name, a (possibly incomplete) symbol name without line number.
 * This routine is called from aout_db_print_completion if the object
 * dependent handler supports qualified search with a file name.
 * It parses the symbol string, and call an object dependent routine
 * with parsed file name and symbol name.
 */ 
int
db_sym_parse_and_print_completion(
	int		(*func)(db_symtab_t *,
				 char *),
	db_symtab_t	*symtab,
	char		*symstr)
{
	register 	char *p;
	register int	n;
	char	 	*sym_name;
	char		*component[2];
	int		nsym;

	/*
	 * disassemble the symbol into components: [file_name:]symbol
	 */
	component[0] = symstr;
	component[1] = 0;
	for (p = symstr, n = 1; *p; p++) {
		if (*p == ':') {
			if (n == 2)
				break;
			*p = 0;
			component[n++] = p+1;
		}
	}
	if (*p == 0) {
		if (n == 1) {
			sym_name = component[0];
		} else {
			sym_name = component[1];
		}
		nsym = func(symtab, sym_name);
	} else
		nsym = 0;
	if (n == 2)
		component[1][-1] = ':';
	return nsym;
}

/*
 * Common utility routine to parse a symbol string into a file
 * name, a (possibly incomplete) symbol name without line number.
 * This routine is called from X_db_lookup_incomplete if the object
 * dependent handler supports qualified search with a file name.
 * It parses the symbol string, and call an object dependent routine
 * with parsed file name and symbol name.
 */ 
int
db_sym_parse_and_lookup_incomplete(
	int		(*func)(db_symtab_t *,
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
	int		*toadd)
{
	register 	char *p;
	register int	n;
	char	 	*file_name = 0;
	char	 	*sym_name = 0;
	char		*component[2];
	int		nsym = 0;

	/*
	 * disassemble the symbol into components: [file_name:]symbol
	 */
	component[0] = symstr;
	component[1] = 0;
	for (p = symstr, n = 1; *p; p++) {
		if (*p == ':') {
			if (n == 2)
				break;
			*p = 0;
			component[n++] = p+1;
		}
	}
	if (*p == 0) {
		if (n == 1) {
			file_name = 0;
			sym_name = component[0];
		} else {
			file_name = component[0];
			sym_name = component[1];
		}
		nsym = func(symtab, file_name, sym_name, 0, (db_sym_t *)0,
			    name, len);
		if (nsym > 0)
			*toadd = *len - strlen(sym_name);
	}
	if (n == 2)
		component[1][-1] = ':';
	return(nsym);
}

/*
 * Common utility routine to parse a symbol string into a file
 * name, a symbol name and line number.
 * This routine is called from aout_db_lookup if the object dependent
 * handler supports qualified search with a file name or a line number.
 * It parses the symbol string, and call an object dependent routine
 * with parsed file name, symbol name and line number.
 */ 
db_sym_t
db_sym_parse_and_lookup(
	int		(*func)(db_symtab_t *, char *, char *, int,
				db_sym_t*, char **, int *),
	db_symtab_t	*symtab,
	char		*symstr)
{
	register 	char *p;
	register int	n;
	int	 	n_name;
	int	 	line_number;
	char	 	*file_name = 0;
	char	 	*sym_name = 0;
	char		*component[3];
	db_sym_t 	found = DB_SYM_NULL;

	/*
	 * disassemble the symbol into components:
	 *	[file_name:]symbol[:line_nubmer]
	 */
	component[0] = symstr;
	component[1] = component[2] = 0;
	for (p = symstr, n = 1; *p; p++) {
		if (*p == ':') {
			if (n >= 3)
				break;
			*p = 0;
			component[n++] = p+1;
		}
	}
	if (*p != 0)
		goto out;
	line_number = 0;
	n_name = n;
	p = component[n-1];
	if (*p >= '0' && *p <= '9') {
		if (n == 1)
			goto out;
		for (line_number = 0; *p; p++) {
			if (*p < '0' || *p > '9')
				goto out;
			line_number = line_number*10 + *p - '0';
		}
		n_name--;
	} else if (n >= 3)
		goto out;
	if (n_name == 1) {
		for (p = component[0]; *p && *p != '.'; p++);
		if (*p == '.') {
			file_name = component[0];
			sym_name = 0;
		} else {
			file_name = 0;
			sym_name = component[0];
		}
	} else {
		file_name = component[0];
		sym_name = component[1];
	}
	(void) func(symtab, file_name, sym_name, line_number, &found,
		   (char **)0, (int *)0);
	
out:
	while (--n >= 1)
		component[n][-1] = ':';
	return(found);
}

/*
 * Does this symbol name appear in more than one symbol table?
 * Used by db_symbol_values to decide whether to qualify a symbol.
 */
boolean_t db_qualify_ambiguous_names = TRUE;

boolean_t
db_symbol_is_ambiguous(char *name)
{
	register int	i;
	register
	boolean_t	found_once = FALSE;

	if (!db_qualify_ambiguous_names)
		return FALSE;

	for (i = 0; i < db_nsymtab; i++) {
		if (X_db_lookup(&db_symtabs[i], name)) {
			if (found_once)
				return TRUE;
			found_once = TRUE;
		}
	}
	return FALSE;
}

/*
 * Find the closest symbol to val, and return its name
 * and the difference between val and the symbol found.
 */
unsigned int db_search_maxoff = 0x4000;
db_sym_t
db_search_task_symbol(
	register db_addr_t	val,
	db_strategy_t		strategy,
	db_addr_t		*offp,	/* better be unsigned */
	task_t			task)
{
	db_addr_t diff, newdiff;
	register int	i;
	db_symtab_t	*sp;
	db_sym_t	ret = DB_SYM_NULL, sym;
	vm_map_t	map_for_val;

	if (task == TASK_NULL)
	    task = db_current_task();
	map_for_val = (task == TASK_NULL)? VM_MAP_NULL: task->map;
again:
	newdiff = diff = -1;
	db_last_symtab = 0;
	for (sp = &db_symtabs[0], i = 0;
	     i < db_nsymtab;
	     sp++, i++) {
	    if ((((vm_map_t)sp->map_pointer == VM_MAP_NULL) ||
			((vm_map_t)sp->map_pointer == map_for_val)) &&
			((sp->maxsym == 0) ||
			((val >= (db_addr_t)sp->minsym) &&
			(val <= (db_addr_t)sp->maxsym)))) {
		sym = X_db_search_symbol(sp, val, strategy,
						(db_expr_t *)&newdiff);
		if (newdiff < diff) {
		    db_last_symtab = sp;
		    diff = newdiff;
		    ret = sym;
		    if (diff <= db_search_maxoff)
			break;
		}
	    }
	}
	if (ret == DB_SYM_NULL && map_for_val != VM_MAP_NULL) {
		map_for_val = VM_MAP_NULL;
		goto again;
	}
	*offp = diff;
	return ret;
}

/*
 * Find the closest symbol to val, and return its name
 * and the difference between val and the symbol found.
 * Also return the filename and linenumber if available.
 */
db_sym_t
db_search_task_symbol_and_line(
	register db_addr_t	val,
	db_strategy_t		strategy,
	db_expr_t		*offp,
	char			**filenamep,
	int			*linenump,
	task_t			task,
	int			*argsp)
{
	db_addr_t diff, newdiff;
	register int	i;
	db_symtab_t	*sp;
	db_sym_t	ret = DB_SYM_NULL, sym;
	vm_map_t	map_for_val;
	char 		*func;
	char		*filename;
	int		linenum;
	int		args;

	if (task == TASK_NULL)
	    task = db_current_task();
	map_for_val = (task == TASK_NULL)? VM_MAP_NULL: task->map;
	*filenamep = (char *) 0;
	*linenump = 0;
	*argsp = -1;
    again:
	filename = (char *) 0;
	linenum = 0;
	newdiff = diff = ~0UL;
	db_last_symtab = 0;
	for (sp = &db_symtabs[0], i = 0;
	     i < db_nsymtab;
	     sp++, i++) {
	    if ((((vm_map_t)sp->map_pointer == VM_MAP_NULL) ||
			((vm_map_t)sp->map_pointer == map_for_val)) &&
			((sp->maxsym == 0) ||
			((val >= (db_addr_t)sp->minsym) &&
			(val <= (db_addr_t)sp->maxsym)))) {
		
			sym = X_db_search_by_addr(sp, val, &filename, &func,
						  &linenum, (db_expr_t *)&newdiff,
						  &args);
			if (sym && newdiff < diff) {
				db_last_symtab = sp;
				diff = newdiff;
				ret = sym;
				*filenamep = filename;
				*linenump = linenum;
				*argsp = args;
				if (diff <= db_search_maxoff)
				break;
			}
	    }
	}
	if (ret == DB_SYM_NULL && map_for_val != VM_MAP_NULL) {
		map_for_val = VM_MAP_NULL;
		goto again;
	}
	*offp = diff;
	if (*filenamep)
		db_shorten_filename(filenamep);
	return ret;
}

/*
 * Return name and value of a symbol
 */
void
db_symbol_values(
	db_symtab_t	*stab,
	db_sym_t	sym,
	char		**namep,
	db_expr_t	*valuep)
{
	db_expr_t	value;
	char		*name;

	if (sym == DB_SYM_NULL) {
		*namep = 0;
		return;
	}
	if (stab == 0)
		stab = db_last_symtab;

	X_db_symbol_values(stab, sym, &name, &value);

	if (db_symbol_is_ambiguous(name)) {
		*namep = db_qualify(name, db_last_symtab->name);
	}else {
		*namep = name;
	}
	if (valuep)
		*valuep = value;
}


/*
 * Print a the closest symbol to value
 *
 * After matching the symbol according to the given strategy
 * we print it in the name+offset format, provided the symbol's
 * value is close enough (eg smaller than db_maxoff).
 * We also attempt to print [filename:linenum] when applicable
 * (eg for procedure names).
 *
 * If we could not find a reasonable name+offset representation,
 * then we just print the value in hex.  Small values might get
 * bogus symbol associations, e.g. 3 might get some absolute
 * value like _INCLUDE_VERSION or something, therefore we do
 * not accept symbols whose value is zero (and use plain hex).
 */

void
db_task_printsym(
	db_addr_t	off,
	db_strategy_t	strategy,
	task_t		task)
{
	db_expr_t	d;
	char 		*filename;
	char		*name;
	db_expr_t	value;
	int 		linenum;
	db_sym_t	cursym;

	if (off >= db_maxval || off < db_minval) {
		db_printf("%#lln", (unsigned long long)off);
		return;
	}
	cursym = db_search_task_symbol(off, strategy, &d, task);

	db_symbol_values(0, cursym, &name, &value);
	if (name == 0 || d >= db_maxoff || value == 0) {
		db_printf("%#lln",(unsigned long long) off);
		return;
	}
	db_printf("%s", name);
	if (d)
		db_printf("+%llx", (unsigned long long)d);
	if (strategy == DB_STGY_PROC) {
		if (db_line_at_pc(cursym, &filename, &linenum, off)) {
			db_printf(" [%s", filename);
			if (linenum > 0)
				db_printf(":%d", linenum);
			db_printf("]");
		}
	}
}

/*
 * Return symbol name for a given offset and
 * change the offset to be relative to this symbol.
 * Very usefull for xpr, when you want to log offsets
 * in a user friendly way.
 */

char null_sym[] = "";

char *
db_get_sym(db_expr_t *off)
{
	db_sym_t	cursym;
	db_expr_t	value;
	char		*name;
	db_addr_t	d;

	cursym = db_search_symbol(*off, DB_STGY_ANY, &d);
	db_symbol_values(0, cursym, &name, &value);
	if (name) 
		*off = d;
	else
		name = null_sym;
	return(name);
}

void
db_printsym(
	db_expr_t	off,
	db_strategy_t	strategy)
{
	db_task_printsym(off, strategy, TASK_NULL);
}

int db_short_filename = 1;

void
db_shorten_filename(char **filenamep)
{
	char *cp, *cp_slash;

	if (! *filenamep)
		return;
	for (cp = cp_slash = *filenamep; *cp; cp++) {
		if (*cp == '/')
			cp_slash = cp;
	}
	if (*cp_slash == '/')
		*filenamep = cp_slash+1;
}

int
db_task_getlinenum(
	db_expr_t	off,
	task_t		task)
{
	db_addr_t	d;
	char 		*filename;
	char		*name;
	db_expr_t	value;
	int 		linenum;
	db_sym_t	cursym;
	db_strategy_t	strategy = DB_STGY_PROC;

	if (off >= db_maxval || off < db_minval) {
		db_printf("%#lln", (unsigned long long)off);
		return(-1);
	}
	cursym = db_search_task_symbol(off, strategy, &d, task);

	db_symbol_values(0, cursym, &name, &value);
	if (name == 0 || d >= db_maxoff || value == 0) {
		return(-1);
	}
	if (db_line_at_pc(cursym, &filename, &linenum, off))
		return(linenum);
	else
		return(-1);
}

boolean_t
db_line_at_pc(
	db_sym_t	sym,
	char		**filename,
	int		*linenum,
	db_expr_t	pc)
{
	boolean_t result;

	if (db_last_symtab == 0)
		return FALSE;
	if (X_db_line_at_pc( db_last_symtab, sym, filename, linenum, pc)) {
		if (db_short_filename)
			db_shorten_filename(filename);
		result = TRUE;
	} else 
		result = FALSE;
	return(result);
}

int qsort_check = 0;

void
db_qsort(
	char	*table,
	int	nbelts,
	int	eltsize,
	int	(*compfun)(char *, char *))
{
	if (nbelts <= 0 || eltsize <= 0 || compfun == 0) {
		printf("qsort: invalid parameters\n");
		return;
	}
	qsort_recur(table, table + nbelts * eltsize, eltsize, compfun);

	if (qsort_check)
		qsort_checker(table, nbelts, eltsize, compfun);
}

void
qsort_swap(
	register int	*a,
	register int	*b,
	register int	size)
{
	register int temp;
	char *aa, *bb;
	char ctemp;

	for (; size >= sizeof (int); size -= sizeof (int), a++, b++) {
		temp = *a;
		*a = *b;
		*b = temp;
	}
	aa = (char *)a;
	bb = (char *)b;
	for (; size > 0; size--, aa++, bb++) {
		ctemp = *aa;
		*aa = *bb;
		*bb = ctemp;
	}
}

/* rotate the three elements to the left */
void
qsort_rotate(
	register int	*a,
	register int	*b,
	register int	*c,
	register int	size)
{
	register int temp;
	char *aa, *bb, *cc;
	char ctemp;

	for (; size >= sizeof (int); size -= sizeof (int), a++, b++, c++) {
		temp = *a;
		*a = *c;
		*c = *b;
		*b = temp;
	}
	aa = (char *)a;
	bb = (char *)b;
	cc = (char *)c;
	for (; size > 0; size--, aa++, bb++, cc++) {
		ctemp = *aa;
		*aa = *cc;
		*cc = *bb;
		*bb = ctemp;
	}
}

void
qsort_recur(
	char	*left,
	char	*right,
	int	eltsize,
	int	(*compfun)(char *, char *))
{
	char *i, *j;
	char *sameleft, *sameright;

    top:
	if (left + eltsize - 1 >= right) {
		return;
	}

	/* partition element (reference for "same"ness */
	sameleft = left + (((right - left) / eltsize) / 2) * eltsize;
	sameright = sameleft;

	i = left;
	j = right - eltsize;

    again:
    	while (i < sameleft) {
		int comp;

		comp = (*compfun)(i, sameleft);
		if (comp == 0) {
			/*
			 * Move to the "same" partition.
			 */
			/*
			 * Shift the left part of the "same" partition to
			 * the left, so that "same" elements stay in their
			 * original order.
			 */
			sameleft -= eltsize;
			qsort_swap((int *) i, (int *) sameleft, eltsize);
		} else if (comp < 0) {
			/*
			 * Stay in the "left" partition.
			 */
			i += eltsize;
		} else {
			/*
			 * Should be moved to the "right" partition.
			 * Wait until the next loop finds an appropriate
			 * place to store this element.
			 */
			break;
		}
	}

	while (j > sameright) {
		int comp;

		comp = (*compfun)(sameright, j);
		if (comp == 0) {
			/*
			 * Move to the right of the "same" partition.
			 */
			sameright += eltsize;
			qsort_swap((int *) sameright, (int *) j, eltsize);
		} else if (comp > 0) {
			/*
			 * Move to the "left" partition.
			 */
			if (i == sameleft) {
				/*
				 * Unfortunately, the "left" partition
				 * has already been fully processed, so
				 * we have to shift the "same" partition
				 * to the right to free a "left" element.
				 * This is done by moving the leftest same
				 * to the right of the "same" partition.
				 */
				sameright += eltsize;
				qsort_rotate((int *) sameleft, (int*) sameright,
					     (int *) j, eltsize);
				sameleft += eltsize;
				i = sameleft;
			} else {
				/*
				 * Swap with the "left" partition element
				 * waiting to be moved to the "right"
				 * partition.
				 */
				qsort_swap((int *) i, (int *) j, eltsize);
				j -= eltsize;
				/*
				 * Go back to the 1st loop.
				 */
				i += eltsize;
				goto again;
			}
		} else {
			/*
			 * Stay in the "right" partition.
			 */
			j -= eltsize;
		}
	}
			
	if (i != sameleft) {
		/*
		 * The second loop completed (the"right" partition is ok),
		 * but we have to go back to the first loop, and deal with
		 * the element waiting for a place in the "right" partition.
		 * Let's shift the "same" zone to the left.
		 */
		sameleft -= eltsize;
		qsort_rotate((int *) sameright, (int *) sameleft, (int *) i,
			     eltsize);
		sameright -= eltsize;
		j = sameright;
		/*
		 * Go back to 1st loop.
		 */
		goto again;
	}

	/*
	 * The partitions are correct now. Recur on the smallest side only.
	 */
	if (sameleft - left >= right - (sameright + eltsize)) {
		qsort_recur(sameright + eltsize, right, eltsize, compfun);
		/*
		 * The "right" partition is now completely sorted.
		 * The "same" partition is OK, so...
		 * Ignore them, and start the loops again on the
		 * "left" partition.
		 */
		right = sameleft;
		goto top;
	} else {
		qsort_recur(left, sameleft, eltsize, compfun);
		/*
		 * The "left" partition is now completely sorted.
		 * The "same" partition is OK, so ...
		 * Ignore them, and start the loops again on the
		 * "right" partition.
		 */
		left = sameright + eltsize;
		goto top;
	}
}

void
qsort_checker(
	char	*table,
	int	nbelts,
	int	eltsize,
	int	(*compfun)(char *, char *))
{
	char *curr, *prev, *last;

	prev = table;
	curr = prev + eltsize;
	last = table + (nbelts * eltsize);

	while (prev < last) {
		if ((*compfun)(prev, curr) > 0) {
			printf("**** qsort_checker: error between 0x%x and 0x%x!!!\n", prev, curr);
			break;
		}
		prev = curr;
		curr += eltsize;
	}
	printf("qsort_checker: OK\n");
}

int qsort_search_debug = 0;

void
db_qsort_limit_search(
	char	*target,
	char	**start,
	char	**end,
	int	eltsize,
	int	(*compfun)(char *, char *))
{
	register char *left, *right;
	char *oleft, *oright, *part;
	int nbiter = 0;
	int comp;

	oleft = left = *start;
	oright = right = *end;
	part = (char *) 0;

	while (left < right) {
		nbiter++;
		part = left + (((right - left) / eltsize) / 2) * eltsize;
		comp = (*compfun)(target, part);
		if (comp > 0) {
			oleft = left;
			oright = right;
			left = part;
			if (left == oleft)
				break;
			if (qsort_search_debug > 1)
				printf(" [ Moved left from 0x%x to 0x%x]\n",
				       oleft, left);
		} else if (comp < 0) {
			oright = right;
			oleft = left;
			right = part;
			if (qsort_search_debug > 1)
				printf(" [ Moved right from 0x%x to 0x%x]\n",
				       oright, right);
		} else {
			if (qsort_search_debug > 1)
				printf(" [ FOUND! left=0x%x right=0x%x]\n",
				       left, right);
			for (left = part;
			     left > *start && (*compfun)(left, part) == 0;
			     left -= eltsize);
			for (right = part + eltsize;
			     right < *end && (*compfun)(right, part) == 0;
			     right += eltsize);
			oright = right;
			oleft = left;
			break;
		}
	}
	
	if (qsort_search_debug)
		printf("[ Limited from %x-%x to %x-%x in %d iters ]\n",
			  *start, *end, oleft, oright, nbiter);
	*start = oleft;
	*end = oright;
}

void
bubble_sort(
	char	*table,
	int	nbelts,
	int	eltsize,
	int	(*compfun)(char *, char *))
{
	boolean_t sorted;
	char *end;
	register char *p;

	end = table + ((nbelts-1) * eltsize);
	do {
		sorted = TRUE;
		for (p = table; p < end; p += eltsize) {
			if ((*compfun)(p, p + eltsize) > 0) {
				qsort_swap((int *) p, (int *) (p + eltsize),
					   eltsize);
				sorted = FALSE;
			}
		}
	} while (sorted == FALSE);

	if (qsort_check)
		qsort_checker(table, nbelts, eltsize, compfun);
}

vm_offset_t	vm_min_inks_addr = VM_MAX_KERNEL_ADDRESS;

void
db_install_inks(
      vm_offset_t base)
{
	/* save addr to demarcate kernel/inks boundary (1st time only)  */
	if (vm_min_inks_addr == VM_MAX_KERNEL_ADDRESS) {
		vm_min_inks_addr = base;
		db_qualify_ambiguous_names = TRUE;
	}
}


void
db_clone_symtabXXX(
	char *clonee,			/* which symtab to clone	*/
	char *cloner,			/* in-kernel-server name	*/
	vm_offset_t base)		/* base address of cloner	*/
{
	db_symtab_t	*st, *st_src;
	char *		memp;
	vm_size_t	size;
	long		offset;
	extern void db_clone_offsetXXX(char *, long);

	if (db_nsymtab >= MAXNOSYMTABS) {
	    db_printf("db_clone_symtab: Too Many Symbol Tables\n");
	    return;
	}

	db_install_inks(base);

	st = &db_symtabs[db_nsymtab];	/* destination symtab		*/
	if ((st_src = db_symtab_cloneeXXX(clonee)) == 0) {
	    db_printf("db_clone_symtab: clonee (%s) not found\n", clonee);
	    return;
	}
					/* alloc new symbols		*/
	size = (vm_size_t)(st_src->end - st_src->private);
	memp = (char *)kalloc( round_page(size) );
	if (!memp) {
	    db_printf("db_clone_symtab: no memory for symtab\n");
	    return;
	}

	*st = *st_src;			/* bulk copy src -> dest	*/
	strcpy(st->name, cloner);	/* new name			*/
	st->private = memp;		/* copy symbols			*/
	bcopy((const char *)st_src->private, st->private, size);
	st->start = memp + sizeof(int);	/* fixup pointers to symtab	*/
	st->end   = memp + *(int *)memp;
	st->map_pointer = 0;		/* no map because kernel-loaded */

	/* Offset symbols, leaving strings pointing into st_src		*/
	offset	    = base - st_src->minsym;
	st->minsym  += offset;
	st->maxsym  += offset;
	db_clone_offsetXXX(memp, offset);
	db_nsymtab++;

	db_printf( "[ cloned symbol table for %s: range 0x%x to 0x%x %s]\n",
		  st->name, st->minsym, st->maxsym,
		  st->sorted ? "(sorted) " : "");
	db_maxval = (unsigned int)st->maxsym + db_maxoff;
}

db_symtab_t *
db_symtab_cloneeXXX(
      char *clonee)
{
	db_symtab_t *st, *st_src;

	st = &db_symtabs[db_nsymtab];   /* destination symtab */
	for (st_src = &db_symtabs[0]; st_src < st; ++st_src)
		if (!strcmp(clonee, st_src->name))
			break;
	return ((st_src < st) ? st_src : 0);
}

/*
 * Switch into symbol-table specific routines
 */

#if	!defined(__alpha) && !defined(INTEL860)
#define DB_NO_COFF
#endif

#ifndef	DB_NO_AOUT
#include <ddb/db_aout.h>
#endif

#ifndef	DB_NO_COFF
#include <ddb/db_coff.h>
#endif

static void no_init(void)

{
	db_printf("Non-existent code for ddb init\n");
}

static boolean_t no_sym_init(
	char *start,
	char *end,
	char *name,
	char *task_addr)
{
	db_printf("Non-existent code for init of symtab %s\n", name);
	return FALSE;
}

static db_sym_t no_lookup(
	db_symtab_t *stab,
	char *symstr)
{
	db_printf("Bogus lookup of symbol %s\n", symstr);
	return DB_SYM_NULL;
}

static db_sym_t no_search(
	db_symtab_t *stab,
	db_addr_t off,
	db_strategy_t strategy,
	db_expr_t *diffp)
{
	db_printf("Bogus search for offset %#llXn", (unsigned long long)off);
	return DB_SYM_NULL;
}

static boolean_t no_line_at_pc(
	db_symtab_t *stab,
	db_sym_t sym,
	char **file,
	int *line,
	db_expr_t pc)
{
	db_printf("Bogus search for pc %#llX\n", (unsigned long long)pc);
	return FALSE;
}

static void no_symbol_values(
	db_sym_t sym,
	char **namep,
	db_expr_t *valuep)
{
	db_printf("Bogus symbol value resolution\n");
	if (namep) *namep = NULL;
	if (valuep) *valuep = 0;
}

static db_sym_t no_search_by_addr(
	db_symtab_t *stab,
	db_addr_t off,
	char **file,
	char **func,
	int *line,
	db_expr_t *diffp,
	int *args)
{
	db_printf("Bogus search for address %#llX\n", (unsigned long long)off);
	return DB_SYM_NULL;
}
	
int
no_print_completion(
	db_symtab_t	*stab,
	char		*symstr	)
{
	db_printf("Bogus print completion: not supported\n");
	return 0;
}

int
no_lookup_incomplete(
	db_symtab_t	*stab,
	char		*symstr,
	char		**name,
	int		*len,
	int		*toadd)
{
	db_printf("Bogus lookup incomplete: not supported\n");
	return 0;
}

#define NONE	\
	{ no_init, no_sym_init, no_lookup, no_search, \
	  no_line_at_pc, no_symbol_values, no_search_by_addr, \
		  no_print_completion, no_lookup_incomplete}

struct db_sym_switch x_db[] = {

	/* BSD a.out format (really, sdb/dbx(1) symtabs) */
#ifdef	DB_NO_AOUT
	NONE,
#else	/* DB_NO_AOUT */
	{ aout_db_init, aout_db_sym_init, aout_db_lookup, aout_db_search_symbol,
	  aout_db_line_at_pc, aout_db_symbol_values, aout_db_search_by_addr,
	  aout_db_print_completion, aout_db_lookup_incomplete},
#endif	/* DB_NO_AOUT */

#ifdef	DB_NO_COFF
	NONE,
#else	/* DB_NO_COFF */
	{ coff_db_init, coff_db_sym_init, coff_db_lookup, coff_db_search_symbol,
	  coff_db_line_at_pc, coff_db_symbol_values, coff_db_search_by_addr,
	  coff_db_print_completion, coff_db_lookup_incomplete },
#endif	/* DB_NO_COFF */

	/* Machdep, not inited here */
	NONE
};
