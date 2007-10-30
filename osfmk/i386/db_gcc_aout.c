/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * COPYRIGHT NOTICE
 * 
 * Copyright (c) 1990, 1991, 1992, 1993 Open Software Foundation, Inc. 
 * 
 * Permission is hereby granted to use, copy, modify and freely distribute
 * the software in this file and its documentation for any purpose without
 * fee, provided that the above copyright notice appears in all copies and
 * that both the copyright notice and this permission notice appear in
 * supporting documentation.  Further, provided that the name of Open
 * Software Foundation, Inc. ("OSF") not be used in advertising or
 * publicity pertaining to distribution of the software without prior
 * written permission from OSF.  OSF makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:36  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:37  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.2.3  1994/01/28  17:23:00  chasb
 * 	Expand Copyrights
 * 	[1994/01/27  19:40:16  chasb]
 *
 * Revision 1.2.2.2  1993/06/09  02:27:36  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:04:03  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:13:10  devrcs
 * 	pick up file_io.h from bootstrap directory
 * 	[1993/02/27  15:01:09  david]
 * 
 * 	Added new arguments and a missing one to db_add_symbol_table
 * 	[barbou@gr.osf.org]
 * 	[92/12/03            bernadat]
 * 
 * 	Added gcc symbol table handling based on db_aout.c (Revsion 2.4)
 * 	[91/07/31            tak]
 * 
 * Revision 1.1  1992/09/30  02:02:23  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.1  91/07/31  13:13:51  jeffreyh
 * Created.
 * 
 * 31-Jul-91  Jeffrey Heller (tak) at Open Software Foundation
 *	Added gcc symbol table handling based on db_aout.c (Revsion 2.4)
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
 * Symbol table routines for a.out format files.
 */

#include <mach/boolean.h>
#include <machine/db_machdep.h>		/* data types */
#include <ddb/db_sym.h>

#ifdef	DB_GCC_AOUT

#include <ddb/nlist.h>			/* a.out symbol table */
#include <i386/stab.h>

/*
 * An a.out symbol table as loaded into the kernel debugger:
 *
 * symtab	-> size of symbol entries, in bytes
 * sp		-> first symbol entry
 *		   ...
 * ep		-> last symbol entry + 1
 * strtab	== start of string table
 *		   size of string table in bytes,
 *		   including this word
 *		-> strings
 */

/*
 * Find pointers to the start and end of the symbol entries,
 * given a pointer to the start of the symbol table.
 */
#define	db_get_aout_symtab(symtab, sp, ep) \
	(sp = (struct nlist *)((symtab) + 1), \
	 ep = (struct nlist *)((char *)sp + *(symtab)))

X_db_sym_init(symtab, esymtab, name)
	int *	symtab;		/* pointer to start of symbol table */
	char *	esymtab;	/* pointer to end of string table,
				   for checking - rounded up to integer
				   boundary */
	char *	name;
{
	register struct nlist	*sym_start, *sym_end;
	register struct nlist	*sp;
	register char *	strtab;
	register int	strlen;

	db_get_aout_symtab(symtab, sym_start, sym_end);

	strtab = (char *)sym_end;
	strlen = *(int *)strtab;

	if (strtab + ((strlen + sizeof(int) - 1) & ~(sizeof(int)-1))
	    != esymtab)
	{
	    db_printf("[ %s symbol table not valid ]\n", name);
	    return;
	}

	db_printf("[ preserving %#x bytes of %s symbol table ]\n",
		esymtab - (char *)symtab, name);

	for (sp = sym_start; sp < sym_end; sp++) {
	    register int strx;
	    strx = sp->n_un.n_strx;
	    if (strx != 0) {
		if (strx > strlen) {
		    db_printf("Bad string table index (%#x)\n", strx);
		    sp->n_un.n_name = 0;
		    continue;
		}
		sp->n_un.n_name = strtab + strx;
	    }
	}

	db_add_symbol_table(sym_start, sym_end, name, (char *)symtab,
			    0, 0, 0, FALSE);
}

/*
 * check file name or not (check xxxx.x pattern)
 */
boolean_t
X_db_is_filename(name)
	register char *name;
{
	while (*name) {
	    if (*name == '.') {
		if (name[1])
		    return(TRUE);
	    }
	    name++;
	}
	return(FALSE);
}

/*
 * special name comparison routine with a name in the symbol table entry
 */
boolean_t
X_db_eq_name(sp, name)
	struct nlist *sp;
	char *name;
{
	register char *s1, *s2;

	s1 = sp->n_un.n_name;
	s2 = name;
	if (*s1 == '_' && *s2 && *s2 != '_')
	    s1++;
	while (*s2) {
	    if (*s1++ != *s2++) {
		/*
		 * check .c .o file name comparison case
		 */
		if (*s2 == 0 && sp->n_un.n_name <= s1 - 2 
			&& s1[-2] == '.' && s1[-1] == 'o')
		    return(TRUE);
		return(FALSE);
	    }
	}
	/*
	 * do special check for
	 *     xxx:yyy for N_FUN
	 *     xxx.ttt for N_DATA and N_BSS
	 */
	return(*s1 == 0 || (*s1 == ':' && sp->n_type == N_FUN) || 
		(*s1 == '.' && (sp->n_type == N_DATA || sp->n_type == N_BSS)));
}

/*
 * search a symbol table with name and type
 *	fp(in,out): last found text file name symbol entry
 */
struct nlist *
X_db_search_name(sp, ep, name, type, fp)
	register struct nlist *sp;
	struct nlist	*ep;
	char		*name;
	int 		type;
	struct nlist	**fp;
{
	struct nlist	*file_sp = *fp;
	struct nlist	*found_sp = 0;

	for ( ; sp < ep; sp++) {
	    if (sp->n_type == N_TEXT && X_db_is_filename(sp->n_un.n_name))
		*fp = sp;
	    if (type) {
		if (sp->n_type == type) {
		    if (X_db_eq_name(sp, name))
	    		return(sp);
		}
		if (sp->n_type == N_SO)
		    *fp = sp;
		continue;
	    }
	    if (sp->n_type & N_STAB)
		continue;
	    if (sp->n_un.n_name && X_db_eq_name(sp, name)) {
		/*
		 * In case of qaulified search by a file,
		 * return it immediately with some check.
		 * Otherwise, search external one
		 */
		if (file_sp) {
		    if ((file_sp == *fp) || (sp->n_type & N_EXT))
			return(sp);
		} else if (sp->n_type & N_EXT)
		    return(sp);
		else
		    found_sp = sp;
	    }
	}
	return(found_sp);
}

/*
 * search a symbol with file, func and line qualification
 */
struct nlist *
X_db_qualified_search(stab, file, sym, line)
	db_symtab_t	*stab;
	char		*file;
	char		*sym;
	int 		line;
{
	register struct nlist *sp = (struct nlist *)stab->start;
	struct nlist	*ep = (struct nlist *)stab->end;
	struct nlist	*fp = 0;
	struct nlist	*found_sp;
	unsigned	func_top;
	boolean_t	in_file;

	if (file == 0 && sym == 0)
	    return(0);
	if (file) {
	    if ((sp = X_db_search_name(sp, ep, file, N_TEXT, &fp)) == 0)
		return(0);
	}
	if (sym) {
	    sp = X_db_search_name(sp, ep, sym, (line > 0)? N_FUN: 0, &fp);
	    if (sp == 0)
		return(0);
	}
	if (line > 0) {
	    if (file && !X_db_eq_name(fp, file))
		return(0);
	    found_sp = 0;
	    if (sp->n_type == N_FUN) {
		/*
		 * qualfied by function name
		 *     search backward because line number entries
		 *     for the function are above it in this case.
		 */
		func_top = sp->n_value;
		for (sp--; sp >= (struct nlist *)stab->start; sp--) {
		    if (sp->n_type != N_SLINE)
			continue;
		    if (sp->n_value < func_top)
			break;
		    if (sp->n_desc <= line) {
			if (found_sp == 0 || found_sp->n_desc < sp->n_desc)
			    found_sp = sp;
			if (sp->n_desc == line)
			    break;
		    }
		}
		if (sp->n_type != N_SLINE || sp->n_value < func_top)
		    return(0);
	    } else {
		/*
		 * qualified by only file name
		 *    search forward in this case
		 */
		in_file = TRUE;
		for (sp++; sp < ep; sp++) {
		    if (sp->n_type == N_TEXT 
			&& X_db_is_filename(sp->n_un.n_name))
			break;		/* enter into another file */
		    if (sp->n_type == N_SOL) {
			in_file = X_db_eq_name(sp, file);
			continue;
		    }
		    if (!in_file || sp->n_type != N_SLINE)
			continue;
		    if (sp->n_desc <= line) {
			if (found_sp == 0 || found_sp->n_desc < sp->n_desc)
			    found_sp = sp;
			if (sp->n_desc == line)
			    break;
		    }
		}
	    }
	    sp = found_sp;
	}
	return(sp);
}

/*
 * lookup symbol by name
 */
db_sym_t
X_db_lookup(stab, symstr)
	db_symtab_t	*stab;
	char *		symstr;
{
	register 	char *p;
	register 	n;
	int	 	n_name;
	int	 	line_number;
	char	 	*file_name = 0;
	char	 	*sym_name = 0;
	char		*component[3];
	struct nlist	*found = 0;

	/*
	 * disassemble component:   [file_name:]symbol[:line_nubmer]
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
	    if (X_db_is_filename(component[0])) {
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
	found = X_db_qualified_search(stab, file_name, sym_name, line_number);
	
out:
	while (--n > 1)
	    component[n][-1] = ':';
	return((db_sym_t) found);
}

db_sym_t
X_db_search_symbol(symtab, off, strategy, diffp)
	db_symtab_t *	symtab;
	register
	db_addr_t	off;
	db_strategy_t	strategy;
	db_expr_t	*diffp;		/* in/out */
{
	register unsigned int	diff = *diffp;
	register struct nlist	*symp = 0;
	register struct nlist	*sp, *ep;

	sp = (struct nlist *)symtab->start;
	ep = (struct nlist *)symtab->end;

	for (; sp < ep; sp++) {
	    if (sp->n_un.n_name == 0)
		continue;
	    if ((sp->n_type & N_STAB) != 0)
		continue;
	    if (off >= sp->n_value) {
		if (off - sp->n_value < diff) {
		    diff = off - sp->n_value;
		    symp = sp;
		    if (diff == 0 && (sp->n_type & N_EXT))
			break;
		}
		else if (off - sp->n_value == diff) {
		    if (symp == 0)
			symp = sp;
		    else if ((symp->n_type & N_EXT) == 0 &&
				(sp->n_type & N_EXT) != 0)
			symp = sp;	/* pick the external symbol */
		}
	    }
	}
	if (symp == 0) {
	    *diffp = off;
	}
	else {
	    *diffp = diff;
	}
	return ((db_sym_t)symp);
}

/*
 * Return the name and value for a symbol.
 */
void
X_db_symbol_values(sym, namep, valuep)
	db_sym_t	sym;
	char		**namep;
	db_expr_t	*valuep;
{
	register struct nlist *sp;

	sp = (struct nlist *)sym;
	if (namep)
	    *namep = sp->n_un.n_name;
	if (valuep)
	    *valuep = sp->n_value;
}

#define X_DB_MAX_DIFF	8	/* maximum allowable diff at the end of line */

/*
 * search symbol by value
 */
X_db_search_by_addr(stab, addr, file, func, line, diff)
	db_symtab_t	*stab;
	register	unsigned addr;
	char		**file;
	char		**func;
	int 	 	*line;
	unsigned	*diff;
{
	register	struct nlist *sp;
	register	struct nlist *line_sp, *func_sp, *file_sp, *line_func;
	register	func_diff, line_diff;
	boolean_t	found_line = FALSE;
	struct 	  	nlist *ep = (struct nlist *)stab->end;

	line_sp = func_sp = file_sp = line_func = 0;
	*file = *func = 0;
	*line = 0;
	for (sp = (struct nlist *)stab->start; sp < ep; sp++) {
	    switch(sp->n_type) {
	    case N_SLINE:
		if (sp->n_value <= addr) {
		    if (line_sp == 0 || line_diff >= addr - sp->n_value) {
			if (line_func)
			    line_func = 0;
			line_sp = sp;
			line_diff = addr - sp->n_value;
		    }
		}
		if (sp->n_value >= addr && line_sp)
		    found_line = TRUE;
		continue;
	    case N_FUN:
		if ((found_line || (line_sp && line_diff < X_DB_MAX_DIFF))
		    && line_func == 0)
		    line_func = sp;
		continue;
	    case N_TEXT:
		if (X_db_is_filename(sp->n_un.n_name)) {
		    if (sp->n_value > addr)
			continue;
		    if (file_sp == 0 || file_sp->n_value < sp->n_value)
			file_sp = sp;
		} else if (sp->n_value <= addr &&
			 (func_sp == 0 || func_diff > addr - sp->n_value)) {
		    func_sp = sp;
		    func_diff = addr - sp->n_value;
		}
		continue;
	    case N_TEXT|N_EXT:
		if (sp->n_value <= addr &&
			 (func_sp == 0 || func_diff >= addr - sp->n_value)) {
		    func_sp = sp;
		    func_diff = addr - sp->n_value;
		    if (func_diff == 0 && file_sp && func_sp)
		        break;
		}
	    default:
		continue;
	    }
	    break;
	}
	if (line_sp) {
	    if (line_func == 0 || func_sp == 0
		|| line_func->n_value != func_sp->n_value)
		line_sp = 0;
	}
	if (file_sp) {
	    *diff = addr - file_sp->n_value;
	    *file = file_sp->n_un.n_name;
	}
	if (func_sp) {
	    *diff = addr - func_sp->n_value;
	    *func = (func_sp->n_un.n_name[0] == '_')?
			func_sp->n_un.n_name + 1: func_sp->n_un.n_name;
	}
	if (line_sp) {
	    *diff = addr - line_sp->n_value;
	    *line = line_sp->n_desc;
	}
	return(file_sp || func_sp || line_sp);
}

/* ARGSUSED */
boolean_t
X_db_line_at_pc(stab, sym, file, line, pc)
	db_symtab_t	*stab;
	db_sym_t	sym;
	char		**file;
	int		*line;
	db_expr_t	pc;
{
	char		*func;
	unsigned	diff;
	boolean_t	found;

	found = X_db_search_by_addr(stab,(unsigned)pc,file,&func,line,&diff);
	return(found && func && *file);
}

/*
 * Initialization routine for a.out files.
 */
kdb_init()
{
	extern char	*esym;
	extern int	end;

	if (esym > (char *)&end) {
	    X_db_sym_init((int *)&end, esym, "mach");
	}
}

/*
 * Read symbol table from file.
 * (should be somewhere else)
 */
#include <bootstrap/file_io.h>
#include <vm/vm_kern.h>

read_symtab_from_file(fp, symtab_name)
	struct file	*fp;
	char *		symtab_name;
{
	vm_size_t	resid;
	kern_return_t	result;
	vm_offset_t	symoff;
	vm_size_t	symsize;
	vm_offset_t	stroff;
	vm_size_t	strsize;
	vm_size_t	table_size;
	vm_offset_t	symtab;

	if (!get_symtab(fp, &symoff, &symsize)) {
	    boot_printf("[ error %d reading %s file header ]\n",
			result, symtab_name);
	    return;
	}

	stroff = symoff + symsize;
	result = read_file(fp, (vm_offset_t)stroff,
			(vm_offset_t)&strsize, sizeof(strsize), &resid);
	if (result || resid) {
	    boot_printf("[ no valid symbol table present for %s ]\n",
		symtab_name);
		return;
	}

	table_size = sizeof(int) + symsize + strsize;
	table_size = (table_size + sizeof(int)-1) & ~(sizeof(int)-1);

	result = kmem_alloc_wired(kernel_map, &symtab, table_size);
	if (result) {
	    boot_printf("[ error %d allocating space for %s symbol table ]\n",
			result, symtab_name);
	    return;
	}

	*(int *)symtab = symsize;

	result = read_file(fp, symoff,
			symtab + sizeof(int), symsize, &resid);
	if (result || resid) {
	    boot_printf("[ error %d reading %s symbol table ]\n",
			result, symtab_name);
	    return;
	}

	result = read_file(fp, stroff,
			symtab + sizeof(int) + symsize, strsize, &resid);
	if (result || resid) {
	    boot_printf("[ error %d reading %s string table ]\n",
			result, symtab_name);
	    return;
	}

	X_db_sym_init((int *)symtab,
			(char *)(symtab + table_size),
			symtab_name);
	
}

#endif	/* DB_GCC_AOUT */
