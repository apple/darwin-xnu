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
 * 
 */
/*
 *	File:	kern/sync_sema.h
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed semaphore synchronization service definitions.
 */

#ifndef _KERN_SYNC_SEMA_H_
#define _KERN_SYNC_SEMA_H_

#include <kern/kern_types.h>
#include <mach/sync_policy.h>

#ifdef MACH_KERNEL_PRIVATE

#include <kern/queue.h>
#include <kern/lock.h>
#include <kern/wait_queue.h>

typedef struct semaphore {
	queue_chain_t	  task_link;  /* chain of semaphores owned by a task */
	struct wait_queue wait_queue; /* queue of blocked threads & lock     */
	task_t		  owner;      /* task that owns semaphore            */
	ipc_port_t	  port;	      /* semaphore port	 		     */
	int		  ref_count;  /* reference count		     */
	int		  count;      /* current count value	             */
	boolean_t	  active;     /* active status			     */
} Semaphore;

#define semaphore_lock(semaphore)   wait_queue_lock(&(semaphore)->wait_queue)
#define semaphore_unlock(semaphore) wait_queue_unlock(&(semaphore)->wait_queue)

extern void semaphore_init(void);

extern	void		semaphore_reference	(semaphore_t semaphore);
extern	void		semaphore_dereference	(semaphore_t semaphore);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_SYNC_SEMA_H_ */
