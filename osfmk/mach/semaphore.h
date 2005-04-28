/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _MACH_SEMAPHORE_H_
#define _MACH_SEMAPHORE_H_

#include <mach/port.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/sync_policy.h>

/*
 *	Forward Declarations
 *
 *	The semaphore creation and deallocation routines are
 *	defined with the Mach task APIs in <mach/task.h>.
 *
 *      kern_return_t	semaphore_create(task_t task,
 *                                       semaphore_t *new_semaphore,
 *					 sync_policy_t policy,
 *					 int value);
 *
 *	kern_return_t	semaphore_destroy(task_t task,
 *					  semaphore_t semaphore);
 */

#include <sys/cdefs.h>
__BEGIN_DECLS

extern	kern_return_t	semaphore_signal     	(semaphore_t semaphore);
extern	kern_return_t	semaphore_signal_all 	(semaphore_t semaphore);
extern	kern_return_t	semaphore_signal_thread	(semaphore_t semaphore,
                                                 thread_t thread);

extern	kern_return_t	semaphore_wait       	(semaphore_t semaphore);
extern	kern_return_t	semaphore_timedwait    	(semaphore_t semaphore, 
						 mach_timespec_t wait_time);

extern  kern_return_t   semaphore_wait_signal   (semaphore_t wait_semaphore,
                                                 semaphore_t signal_semaphore);

extern  kern_return_t semaphore_timedwait_signal(semaphore_t wait_semaphore,
                                                 semaphore_t signal_semaphore,
                                                 mach_timespec_t wait_time);
__END_DECLS

#ifdef	PRIVATE

#define SEMAPHORE_OPTION_NONE		0x00000000

#define SEMAPHORE_SIGNAL		0x00000001
#define SEMAPHORE_WAIT			0x00000002
#define SEMAPHORE_WAIT_ON_SIGNAL	0x00000008

#define SEMAPHORE_SIGNAL_TIMEOUT	0x00000010
#define SEMAPHORE_SIGNAL_ALL		0x00000020
#define SEMAPHORE_SIGNAL_INTERRUPT	0x00000040	/* libmach implements */
#define SEMAPHORE_SIGNAL_PREPOST	0x00000080

#define SEMAPHORE_WAIT_TIMEOUT		0x00000100
#define SEMAPHORE_WAIT_INTERRUPT	0x00000400	/* libmach implements */

#define SEMAPHORE_TIMEOUT_NOBLOCK	0x00100000
#define SEMAPHORE_TIMEOUT_RELATIVE	0x00200000

#define SEMAPHORE_USE_SAVED_RESULT	0x01000000	/* internal use only */
#define SEMAPHORE_SIGNAL_RELEASE	0x02000000	/* internal use only */

#endif	/* PRIVATE */

#endif	/* _MACH_SEMAPHORE_H_ */
