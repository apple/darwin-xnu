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
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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

#ifndef	_KERN_SYSCALL_EMULATION_H_
#define	_KERN_SYSCALL_EMULATION_H_

#ifndef	ASSEMBLER
#include <kern/kern_types.h>
#include <mach/machine/vm_types.h>
#include <kern/lock.h>

typedef	vm_offset_t	eml_routine_t;

typedef struct eml_dispatch {
	decl_mutex_data(,lock)		/* lock for reference count */
	int		ref_count;	/* reference count */
	int 		disp_count; 	/* count of entries in vector */
	int		disp_min;	/* index of lowest entry in vector */
	eml_routine_t	disp_vector[1];	/* first entry in array of dispatch */
					/* routines (array has disp_count
					   elements) */
} *eml_dispatch_t;

#define EML_ROUTINE_NULL	(eml_routine_t)0
#define EML_DISPATCH_NULL	(eml_dispatch_t)0

#define	EML_SUCCESS		(0)

#define	EML_MOD			(err_kern|err_sub(2))
#define	EML_BAD_TASK		(EML_MOD|0x0001)
#define	EML_BAD_CNT		(EML_MOD|0x0002)

/* Per-task initialization */
extern void	eml_init(void);

/* Take reference on common task emulation vector */
extern void	eml_task_reference(
			task_t	new_task,
			task_t	parent_task);

/* Deallocate reference on common task emulation vector */
extern void	eml_task_deallocate(
			task_t	task);

#endif	/* ASSEMBLER */

#endif	/* _KERN_SYSCALL_EMULATION_H_ */
