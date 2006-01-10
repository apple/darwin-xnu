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
/*
 *	File:	ipc/ipc_space.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for IPC spaces of capabilities.
 */

#ifndef	_IPC_IPC_SPACE_H_
#define _IPC_IPC_SPACE_H_


#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/vm_types.h>

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#ifdef MACH_KERNEL_PRIVATE
#include <mach_kdb.h>
#include <kern/macro_help.h>
#include <kern/kern_types.h>
#include <kern/lock.h>
#include <kern/task.h>
#include <kern/zalloc.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_splay.h>
#include <ipc/ipc_types.h>

/*
 *	Every task has a space of IPC capabilities.
 *	IPC operations like send and receive use this space.
 *	IPC kernel calls manipulate the space of the target task.
 *
 *	Every space has a non-NULL is_table with is_table_size entries.
 *	A space may have a NULL is_tree.  is_tree_small records the
 *	number of entries in the tree that, if the table were to grow
 *	to the next larger size, would move from the tree to the table.
 *
 *	is_growing marks when the table is in the process of growing.
 *	When the table is growing, it can't be freed or grown by another
 *	thread, because of krealloc/kmem_realloc's requirements.
 *
 */

typedef natural_t ipc_space_refs_t;

struct ipc_space {
	decl_mutex_data(,is_ref_lock_data)
	ipc_space_refs_t is_references;

	decl_mutex_data(,is_lock_data)
	boolean_t is_active;		/* is the space alive? */
	boolean_t is_growing;		/* is the space growing? */
	ipc_entry_t is_table;		/* an array of entries */
	ipc_entry_num_t is_table_size;	/* current size of table */
	struct ipc_table_size *is_table_next; /* info for larger table */
	struct ipc_splay_tree is_tree;	/* a splay tree of entries */
	ipc_entry_num_t is_tree_total;	/* number of entries in the tree */
	ipc_entry_num_t is_tree_small;	/* # of small entries in the tree */
	ipc_entry_num_t is_tree_hash;	/* # of hashed entries in the tree */
	boolean_t is_fast;              /* for is_fast_space() */
};

#define	IS_NULL			((ipc_space_t) 0)

extern zone_t ipc_space_zone;

#define is_alloc()		((ipc_space_t) zalloc(ipc_space_zone))
#define	is_free(is)		zfree(ipc_space_zone, (is))

extern ipc_space_t ipc_space_kernel;
extern ipc_space_t ipc_space_reply;
#if	DIPC
extern ipc_space_t ipc_space_remote;
#endif	/* DIPC */
#if	DIPC || MACH_KDB
extern ipc_space_t default_pager_space;
#endif	/* DIPC || MACH_KDB */

#define is_fast_space(is)	((is)->is_fast)

#define	is_ref_lock_init(is)	mutex_init(&(is)->is_ref_lock_data, 0)

#define	ipc_space_reference_macro(is)					\
MACRO_BEGIN								\
	mutex_lock(&(is)->is_ref_lock_data);				\
	assert((is)->is_references > 0);				\
	(is)->is_references++;						\
	mutex_unlock(&(is)->is_ref_lock_data);				\
MACRO_END

#define	ipc_space_release_macro(is)					\
MACRO_BEGIN								\
	ipc_space_refs_t _refs;						\
									\
	mutex_lock(&(is)->is_ref_lock_data);				\
	assert((is)->is_references > 0);				\
	_refs = --(is)->is_references;					\
	mutex_unlock(&(is)->is_ref_lock_data);				\
									\
	if (_refs == 0)							\
		is_free(is);						\
MACRO_END

#define	is_lock_init(is)	mutex_init(&(is)->is_lock_data, 0)

#define	is_read_lock(is)	mutex_lock(&(is)->is_lock_data)
#define is_read_unlock(is)	mutex_unlock(&(is)->is_lock_data)
#define is_read_sleep(is)	thread_sleep_mutex((event_t)(is),	\
						   &(is)->is_lock_data,	\
						   THREAD_UNINT)

#define	is_write_lock(is)	mutex_lock(&(is)->is_lock_data)
#define	is_write_lock_try(is)	mutex_try(&(is)->is_lock_data)
#define is_write_unlock(is)	mutex_unlock(&(is)->is_lock_data)
#define is_write_sleep(is)	thread_sleep_mutex((event_t)(is),	\
						   &(is)->is_lock_data,	\
						   THREAD_UNINT)

#define	is_reference(is)	ipc_space_reference(is)
#define	is_release(is)		ipc_space_release(is)

#define	is_write_to_read_lock(is)

#define	current_space_fast()	(current_task_fast()->itk_space)
#define current_space()		(current_space_fast())

/* Create a special IPC space */
extern kern_return_t ipc_space_create_special(
	ipc_space_t	*spacep);

/* Create  new IPC space */
extern kern_return_t ipc_space_create(
	ipc_table_size_t	initial,
	ipc_space_t		*spacep);

/* Mark a space as dead and cleans up the entries*/
extern void ipc_space_destroy(
	ipc_space_t	space);

/* Clean up the entries - but leave the space alive */
extern void ipc_space_clean(
	ipc_space_t	space);

#endif /* MACH_KERNEL_PRIVATE */
#endif /* __APPLE_API_PRIVATE */

#ifdef  __APPLE_API_UNSTABLE
#ifndef MACH_KERNEL_PRIVATE

extern ipc_space_t		current_space(void);

#endif /* !MACH_KERNEL_PRIVATE */
#endif /* __APPLE_API_UNSTABLE */

/* Take a reference on a space */
extern void ipc_space_reference(
	ipc_space_t	space);

/* Realase a reference on a space */
extern void ipc_space_release(
	ipc_space_t	space);

#endif	/* _IPC_IPC_SPACE_H_ */
