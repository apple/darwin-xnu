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
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.17.3  1995/01/06  19:52:05  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup, flavor typedefs
 * 	[1994/10/14  03:43:17  dwm]
 *
 * Revision 1.2.17.2  1994/09/23  02:43:16  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:12  ezf]
 * 
 * Revision 1.2.17.1  1994/08/07  20:50:11  bolinger
 * 	Merge up to colo_b7.
 * 	[1994/08/01  21:02:09  bolinger]
 * 
 * Revision 1.2.13.3  1994/06/25  03:47:23  dwm
 * 	mk6 CR98 - add flavor interface typedefs.
 * 	[1994/06/24  21:55:01  dwm]
 * 
 * Revision 1.2.13.2  1994/05/02  21:36:08  dwm
 * 	Remove nmk15_compat support.
 * 	[1994/05/02  21:09:13  dwm]
 * 
 * Revision 1.2.13.1  1994/01/12  17:57:31  dwm
 * 	Fix "ifdef" NMK15_COMPAT to "if"
 * 	[1994/01/12  17:31:16  dwm]
 * 
 * Revision 1.2.3.5  1993/08/03  18:29:54  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  18:56:17  gm]
 * 
 * Revision 1.2.3.4  1993/07/08  19:04:54  watkins
 * 	New version of thread_basic_info structure; old version
 * 	is now under nmk15_compat.
 * 	[1993/07/07  21:04:15  watkins]
 * 
 * Revision 1.2.3.3  1993/06/29  21:55:52  watkins
 * 	New definitions for scheduling control interfaces.
 * 	[1993/06/29  20:51:04  watkins]
 * 
 * Revision 1.2.3.2  1993/06/09  02:43:43  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:18:25  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:39:43  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:55:07  david]
 * 
 * Revision 1.1  1992/09/30  02:32:13  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:01:06  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:36:34  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:21:39  mrt]
 * 
 * Revision 2.2  90/06/02  15:00:08  rpd
 * 	Updated for new scheduling info.
 * 	[90/03/26  22:40:55  rpd]
 * 
 * Revision 2.1  89/08/03  16:06:07  rwd
 * Created.
 * 
 * Revision 2.4  89/02/25  18:41:18  gm0w
 * 	Changes for cleanup.
 * 
 *  4-Mar-88  David Black (dlb) at Carnegie-Mellon University
 *	Added TH_USAGE_SCALE for cpu_usage field.
 *
 * 15-Jan-88  David Golub (dbg) at Carnegie-Mellon University
 *	Changed to generic interface (variable-length array) to allow
 *	for expansion.  Renamed to thread_info.
 *
 *  1-Jun-87  Avadis Tevanian (avie) at Carnegie-Mellon University
 *	Created.
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
 *	File:	mach/thread_info
 *
 *	Thread information structure and definitions.
 *
 *	The defintions in this file are exported to the user.  The kernel
 *	will translate its internal data structures to these structures
 *	as appropriate.
 *
 */

#ifndef	_MACH_THREAD_INFO_H_
#define _MACH_THREAD_INFO_H_

#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/time_value.h>
#include <mach/machine/vm_types.h>

/*
 *	Generic information structure to allow for expansion.
 */
typedef	natural_t	thread_flavor_t;
typedef	integer_t	*thread_info_t;		/* varying array of int */

#define THREAD_INFO_MAX		(1024)	/* maximum array size */
typedef	integer_t	thread_info_data_t[THREAD_INFO_MAX];

/*
 *	Currently defined information.
 */
#define THREAD_BASIC_INFO         	3     /* basic information */

struct thread_basic_info {
        time_value_t    user_time;      /* user run time */
        time_value_t    system_time;    /* system run time */
        integer_t       cpu_usage;      /* scaled cpu usage percentage */
	policy_t	policy;		/* scheduling policy in effect */
        integer_t       run_state;      /* run state (see below) */
        integer_t       flags;          /* various flags (see below) */
        integer_t       suspend_count;  /* suspend count for thread */
        integer_t       sleep_time;     /* number of seconds that thread
                                           has been sleeping */
};

typedef struct thread_basic_info  thread_basic_info_data_t;
typedef struct thread_basic_info  *thread_basic_info_t;
#define THREAD_BASIC_INFO_COUNT   \
                (sizeof(thread_basic_info_data_t) / sizeof(natural_t))

/*
 *	Scale factor for usage field.
 */

#define TH_USAGE_SCALE	1000

/*
 *	Thread run states (state field).
 */

#define TH_STATE_RUNNING	1	/* thread is running normally */
#define TH_STATE_STOPPED	2	/* thread is stopped */
#define TH_STATE_WAITING	3	/* thread is waiting normally */
#define TH_STATE_UNINTERRUPTIBLE 4	/* thread is in an uninterruptible
					   wait */
#define TH_STATE_HALTED		5	/* thread is halted at a
					   clean point */

/*
 *	Thread flags (flags field).
 */
#define TH_FLAGS_SWAPPED	0x1	/* thread is swapped out */
#define TH_FLAGS_IDLE		0x2	/* thread is an idle thread */

#define THREAD_SCHED_TIMESHARE_INFO	10
#define THREAD_SCHED_RR_INFO		11
#define THREAD_SCHED_FIFO_INFO		12

#endif	/* _MACH_THREAD_INFO_H_ */
