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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.2  1998/04/29 17:36:54  mburg
 * MK7.3 merger
 *
 * Revision 1.2.31.1  1998/02/03  09:33:56  gdt
 * 	Merge up to MK7.3
 * 	[1998/02/03  09:17:49  gdt]
 *
 * Revision 1.2.29.1  1997/06/17  03:01:26  devrcs
 * 	Added `TASK_SCHED_INFO.'
 * 	[1996/03/18  15:24:59  rkc]
 * 
 * Revision 1.2.21.3  1995/01/06  19:51:51  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup, ledgers, security, flavors.
 * 	[1994/10/14  03:43:10  dwm]
 * 
 * Revision 1.2.21.2  1994/09/23  02:42:46  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:42:56  ezf]
 * 
 * Revision 1.2.21.1  1994/08/07  20:50:07  bolinger
 * 	Merge up to colo_b7.
 * 	[1994/08/01  21:02:06  bolinger]
 * 
 * Revision 1.2.17.4  1994/06/25  03:47:20  dwm
 * 	mk6 CR98 - add flavor interface typedefs (task_flavor_t).
 * 	[1994/06/24  21:54:58  dwm]
 * 
 * Revision 1.2.17.3  1994/05/02  21:36:04  dwm
 * 	Remove nmk15_compat support.
 * 	[1994/05/02  21:09:10  dwm]
 * 
 * Revision 1.2.17.2  1994/01/14  18:42:23  bolinger
 * 	Add TASK_USER_DATA flavor of task_info() (and task_set_info()).
 * 	[1994/01/14  18:20:52  bolinger]
 * 
 * Revision 1.2.17.1  1994/01/12  17:57:26  dwm
 * 	Fix "ifdef" NMK15_COMPAT to "if"
 * 	[1994/01/12  17:31:13  dwm]
 * 
 * Revision 1.2.3.5  1993/08/03  18:29:52  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  18:33:57  gm]
 * 
 * Revision 1.2.3.4  1993/07/08  19:04:52  watkins
 * 	New version of task_basic_info structure; old version
 * 	is now under nmk15_compat.
 * 	[1993/07/07  21:04:11  watkins]
 * 
 * Revision 1.2.3.3  1993/06/29  21:55:50  watkins
 * 	New definitions for scheduling control interfaces.
 * 	[1993/06/29  20:50:59  watkins]
 * 
 * Revision 1.2.3.2  1993/06/09  02:43:32  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:18:18  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:39:27  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:54:59  david]
 * 
 * Revision 1.1  1992/09/30  02:32:09  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:00:41  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:36:25  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:21:17  mrt]
 * 
 * Revision 2.2  90/05/03  15:48:36  dbg
 * 	Added TASK_THREAD_TIMES_INFO flavor.
 * 	[90/04/03            dbg]
 * 
 * Revision 2.1  89/08/03  16:04:49  rwd
 * Created.
 * 
 * Revision 2.3  89/02/25  18:41:06  gm0w
 * 	Changes for cleanup.
 * 
 * 15-Jan-88  David Golub (dbg) at Carnegie-Mellon University
 *	Created, based on old task_statistics.
 *
 */
/* CMU_ENDHIST */
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

#define TASK_SCHED_TIMESHARE_INFO	10
#define TASK_SCHED_RR_INFO		11
#define TASK_SCHED_FIFO_INFO		12

#define TASK_SECURITY_TOKEN		13
#define TASK_SECURITY_TOKEN_COUNT	\
		(sizeof(security_token_t) / sizeof(natural_t))

#define TASK_SCHED_INFO			14

#endif	/* TASK_INFO_H_ */
