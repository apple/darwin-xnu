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
 *	Machine-independent task information structures and definitions.
 *
 *	The definitions in this file are exported to the user.  The kernel
 *	will translate its internal data structures to these structures
 *	as appropriate.
 *
 */

#ifndef	TASK_INFO_H_
#define	TASK_INFO_H_

#include <mach/machine/vm_types.h>
#include <mach/time_value.h>
#include <mach/policy.h>

#include <sys/appleapiopts.h>

/*
 *	Generic information structure to allow for expansion.
 */
typedef	natural_t	task_flavor_t;
typedef	integer_t	*task_info_t;		/* varying array of int */

#define	TASK_INFO_MAX	(1024)		/* maximum array size */
typedef	integer_t	task_info_data_t[TASK_INFO_MAX];

/*
 *	Currently defined information structures.
 */

#define TASK_BASIC_INFO         4       /* basic information */

struct task_basic_info {
        integer_t       suspend_count;  /* suspend count for task */
        vm_size_t       virtual_size;   /* number of virtual pages */
        vm_size_t       resident_size;  /* number of resident pages */
        time_value_t    user_time;      /* total user run time for
                                           terminated threads */
        time_value_t    system_time;    /* total system run time for
                                           terminated threads */
	policy_t	policy;		/* default policy for new threads */
};

typedef struct task_basic_info          task_basic_info_data_t;
typedef struct task_basic_info          *task_basic_info_t;
#define TASK_BASIC_INFO_COUNT   \
                (sizeof(task_basic_info_data_t) / sizeof(natural_t))


#define	TASK_EVENTS_INFO	2	/* various event counts */

struct task_events_info {
	integer_t	faults;		/* number of page faults */
	integer_t 	pageins;	/* number of actual pageins */
	integer_t 	cow_faults;	/* number of copy-on-write faults */
	integer_t 	messages_sent;	/* number of messages sent */
	integer_t 	messages_received; /* number of messages received */
        integer_t 	syscalls_mach;  /* number of mach system calls */
	integer_t 	syscalls_unix;  /* number of unix system calls */
	integer_t 	csw;            /* number of context switches */
};
typedef struct task_events_info		task_events_info_data_t;
typedef struct task_events_info		*task_events_info_t;
#define	TASK_EVENTS_INFO_COUNT	\
		(sizeof(task_events_info_data_t) / sizeof(natural_t))

#define	TASK_THREAD_TIMES_INFO	3	/* total times for live threads -
					   only accurate if suspended */

struct task_thread_times_info {
	time_value_t	user_time;	/* total user run time for
					   live threads */
	time_value_t	system_time;	/* total system run time for
					   live threads */
};

typedef struct task_thread_times_info	task_thread_times_info_data_t;
typedef struct task_thread_times_info	*task_thread_times_info_t;
#define	TASK_THREAD_TIMES_INFO_COUNT	\
		(sizeof(task_thread_times_info_data_t) / sizeof(natural_t))

#ifdef	__APPLE_API_UNSTABLE

#define TASK_SCHED_TIMESHARE_INFO	10
#define TASK_SCHED_RR_INFO		11
#define TASK_SCHED_FIFO_INFO		12

#define TASK_SCHED_INFO			14

#endif	/* __APPLE_API_UNSTABLE */

#define TASK_SECURITY_TOKEN		13
#define TASK_SECURITY_TOKEN_COUNT	\
		(sizeof(security_token_t) / sizeof(natural_t))

#endif	/* TASK_INFO_H_ */
