/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
#include <mach_kdb.h>
#include <mach_debug.h>

#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/std_types.h>
#include <mach/mach_types.h>
#include <mach/mach_host_server.h>  /* prototype */

#if MACH_KDB && MACH_DEBUG
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <kern/host.h>
#include <kern/task.h>
#include <ddb/db_sym.h>
#endif

/*
 *	Loads a symbol table for an external file into the kernel debugger.
 *	The symbol table data is an array of characters.  It is assumed that
 *	the caller and the kernel debugger agree on its format.
 */
kern_return_t
host_load_symbol_table(
	host_priv_t	host_priv,
	task_t		task,
	char *		name,
	pointer_t	symtab,
	mach_msg_type_number_t	symtab_count)
{
#if !MACH_DEBUG || !MACH_KDB
        return KERN_FAILURE;
#else
	kern_return_t	result;
	vm_offset_t	symtab_start;
	vm_offset_t	symtab_end;
	vm_map_t	map;
	vm_map_copy_t	symtab_copy_object;

	if (host_priv == HOST_PRIV_NULL)
	    return (KERN_INVALID_ARGUMENT);

	/*
	 * Copy the symbol table array into the kernel.
	 * We make a copy of the copy object, and clear
	 * the old one, so that returning error will not
	 * deallocate the data twice.
	 */
	symtab_copy_object = (vm_map_copy_t) symtab;
	result = vm_map_copyout(
			kernel_map,
			&symtab_start,
			vm_map_copy_copy(symtab_copy_object));
	if (result != KERN_SUCCESS)
	    return (result);

	symtab_end = symtab_start + symtab_count;

	/*
	 * Add the symbol table.
	 * Do not keep a reference for the task map.	XXX
	 */
	if (task == TASK_NULL)
	    map = VM_MAP_NULL;
	else
	    map = task->map;
	if (!X_db_sym_init((char *)symtab_start,
			(char *)symtab_end,
			name,
			(char *)map))
	{
	    /*
	     * Not enough room for symbol table - failure.
	     */
	    (void) vm_deallocate(kernel_map,
			symtab_start,
			symtab_count);
	    return (KERN_FAILURE);
	}

	/*
	 * Wire down the symbol table
	 */
	(void) vm_map_wire(kernel_map,
		symtab_start,
		round_page(symtab_end),
		VM_PROT_READ|VM_PROT_WRITE, FALSE);

	/*
	 * Discard the original copy object
	 */
	vm_map_copy_discard(symtab_copy_object);

	return (KERN_SUCCESS);
#endif /* MACH_DEBUG && MACH_KDB */
}
