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
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and ditribute this software and its
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

#include <mach/error.h>
#include <mach/vm_param.h>
#include <mach/boolean.h>
#include <kern/misc_protos.h>
#include <kern/syscall_emulation.h>
#include <kern/task.h>
#include <kern/kalloc.h>
#include <vm/vm_kern.h>
#include <machine/thread.h>	/* for syscall_emulation_sync */

/*
 * Exported interface
 */

/*
 * WARNING:
 * This code knows that kalloc() allocates memory most efficiently
 * in sizes that are powers of 2, and asks for those sizes.
 */

/*
 * Go from number of entries to size of struct eml_dispatch and back.
 */
#define	base_size	(sizeof(struct eml_dispatch) - sizeof(eml_routine_t))
#define	count_to_size(count) \
	(base_size + sizeof(vm_offset_t) * (count))

#define	size_to_count(size) \
	( ((size) - base_size) / sizeof(vm_offset_t) )

/* Forwards */
kern_return_t
task_set_emulation_vector_internal(
	task_t 			task,
	int			vector_start,
	emulation_vector_t	emulation_vector,
	mach_msg_type_number_t	emulation_vector_count);

/*
 *  eml_init:	initialize user space emulation code
 */
void
eml_init(void)
{
}

/*
 * eml_task_reference() [Exported]
 *
 *	Bumps the reference count on the common emulation
 *	vector.
 */

void
eml_task_reference(
	task_t	task,
	task_t	parent)
{
	register eml_dispatch_t	eml;

	if (parent == TASK_NULL)
	    eml = EML_DISPATCH_NULL;
	else
	    eml = parent->eml_dispatch;

	if (eml != EML_DISPATCH_NULL) {
	    mutex_lock(&eml->lock);
	    eml->ref_count++;
	    mutex_unlock(&eml->lock);
	}
	task->eml_dispatch = eml;
}


/*
 * eml_task_deallocate() [Exported]
 *
 *	Cleans up after the emulation code when a process exits.
 */
 
void
eml_task_deallocate(
	task_t task)
{
	register eml_dispatch_t	eml;

	eml = task->eml_dispatch;
	if (eml != EML_DISPATCH_NULL) {
	    int count;

	    mutex_lock(&eml->lock);
	    count = --eml->ref_count;
	    mutex_unlock(&eml->lock);

	    if (count == 0)
		kfree((vm_offset_t)eml, count_to_size(eml->disp_count));

	    task->eml_dispatch = EML_DISPATCH_NULL;
	}
}

/*
 *   task_set_emulation_vector:  [Server Entry]
 *   set a list of emulated system calls for this task.
 */
kern_return_t
task_set_emulation_vector_internal(
	task_t 			task,
	int			vector_start,
	emulation_vector_t	emulation_vector,
	mach_msg_type_number_t	emulation_vector_count)
{
	return KERN_NOT_SUPPORTED;
}

/*
 *	task_set_emulation_vector:  [Server Entry]
 *
 *	Set the list of emulated system calls for this task.
 *	The list is out-of-line.
 */
kern_return_t
task_set_emulation_vector(
	task_t 			task,
	int			vector_start,
	emulation_vector_t	emulation_vector,
	mach_msg_type_number_t	emulation_vector_count)
{
	return KERN_NOT_SUPPORTED;
}

/*
 *	task_get_emulation_vector: [Server Entry]
 *
 *	Get the list of emulated system calls for this task.
 *	List is returned out-of-line.
 */
kern_return_t
task_get_emulation_vector(
	task_t			task,
	int			*vector_start,			/* out */
	emulation_vector_t	*emulation_vector,		/* out */
	mach_msg_type_number_t	*emulation_vector_count)	/* out */
{
	return KERN_NOT_SUPPORTED;
}

/*
 *   task_set_emulation:  [Server Entry]
 *   set up for user space emulation of syscalls within this task.
 */
kern_return_t
task_set_emulation(
	task_t		task,
	vm_offset_t 	routine_entry_pt,
	int		routine_number)
{
	return KERN_NOT_SUPPORTED;
}




