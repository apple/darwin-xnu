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
 * Revision 1.1.1.1  1998/03/07 02:25:45  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.29.1  1997/10/30  15:32:29  barbou
 * 	Added HOST_CPU_LOAD_INFO flavor for host_statistics().
 * 	[1997/10/30  15:22:10  barbou]
 *
 * Revision 1.2.18.6  1996/01/09  19:21:44  devrcs
 * 	Changed members of struct host_priority_info to type integer_t.
 * 	Change HOST_RESOURCE_SIZES_COUNT and HOST_PRIORITY_INFO_COUNT
 * 	to be in integer_t units, not int.  host_info expects the count
 * 	to be the number of integer_t's to copy.
 * 	[1995/12/01  19:49:11  jfraser]
 * 
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:08:49  jfraser]
 * 
 * Revision 1.2.18.5  1995/04/07  19:05:07  barbou
 * 	VM Merge - Task Swapper.
 * 	Add new host_paging_info flavor.
 * 	[91/09/22  13:20:45  jeffc]
 * 	[94/07/28            barbou]
 * 	[95/03/10            barbou]
 * 
 * Revision 1.2.18.4  1995/02/24  14:48:07  alanl
 * 	Merged with DIPC2_SHARED.
 * 	[95/01/03            alanl]
 * 
 * Revision 1.2.22.2  1994/10/14  03:50:38  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:42:37  dwm]
 * 
 * Revision 1.2.18.2  1994/09/23  02:36:22  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:39:41  ezf]
 * 
 * Revision 1.2.18.1  1994/08/07  20:48:45  bolinger
 * 	Merge up to colo_b7.
 * 	[1994/08/01  21:01:21  bolinger]
 * 
 * Revision 1.2.15.2  1994/06/25  03:47:01  dwm
 * 	mk6 CR98 - add flavor interface typedefs (host_flavor_t).
 * 	[1994/06/24  21:54:43  dwm]
 * 
 * Revision 1.2.15.1  1994/02/24  19:05:22  rwd
 * 	Add HOST_PRIORITY_INFO
 * 	[94/02/22            rwd]
 * 
 * Revision 1.2.4.6  1993/10/28  17:17:10  jeffc
 * 	CR10039 -- Add flavor interface typedefs
 * 	[1993/10/28  13:55:48  jeffc]
 * 
 * Revision 1.2.20.1  1994/10/03  18:47:25  sjs
 * 	Intel update: often used KERNEL_BOOTMAGIC_MAX.
 * 	[94/09/22            sjs]
 * 
 * Revision 1.2.4.7  1994/01/28  18:14:07  chasb
 * 	Expand Copyrights
 * 	[1994/01/27  20:04:11  chasb]
 * 
 * Revision 1.2.4.6  1993/10/28  17:17:10  jeffc
 * 	CR10039 -- Add flavor interface typedefs
 * 	[1993/10/28  13:55:48  jeffc]
 * 
 * Revision 1.2.4.5  1993/07/07  15:48:51  brezak
 * 	Add host_info() flavor HOST_RESOURCE_SIZES and attendant struct.
 * 	[1993/07/07  15:47:32  brezak]
 * 
 * Revision 1.2.4.4  1993/06/29  17:54:26  brezak
 * 	Remove HOST_PROCESSOR_SLOTS host_info flavor. Use host_processot_slots().
 * 	[1993/06/28  20:58:50  brezak]
 * 
 * Revision 1.2.4.3  1993/06/15  20:28:11  brezak
 * 	HOST_LOAD_INFO is now returned by host_statistics().
 * 	Add HOST_VM_INFO for host_statistics(). Include <mach/vm_statistics.h>.
 * 	[1993/06/14  14:18:40  brezak]
 * 
 * Revision 1.1.5.2  1993/06/02  23:43:38  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:15:59  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:33:24  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:53:04  david]
 * 
 * Revision 1.1  1992/09/30  02:30:38  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4.2.1  92/01/09  18:44:17  jsb
 * 	From durriya@ri.osf.org: defined kernel_boot_info_t.
 * 	[92/01/08  15:01:53  jsb]
 * 
 * Revision 2.4  91/05/14  16:51:48  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:31:58  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:17:13  mrt]
 * 
 * Revision 2.2  90/06/02  14:57:58  rpd
 * 	Added HOST_LOAD_INFO and related definitions.
 * 	[90/04/27            rpd]
 * 	Created for new host/processor technology.
 * 	[90/03/26  23:50:51  rpd]
 * 
 * 	Cleanup changes.
 * 	[89/08/02            dlb]
 * 	Add sched_info flavor to return minimum times for use by
 * 	external schedulers.
 * 	[89/06/08            dlb]
 * 	Added kernel_version type definitions.
 * 	[88/12/02            dlb]
 * 
 * Revision 2.4  89/10/15  02:05:31  rpd
 * 	Minor cleanups.
 * 
 * Revision 2.3  89/10/11  17:32:15  dlb
 * 	Include mach/machine/vm_types.h instead of mach/vm_param.h
 * 	[89/10/11            dlb]
 * 
 * Revision 2.2  89/10/11  14:36:55  dlb
 * 	Add sched_info flavor to return minimum times for use by
 * 	external schedulers.
 * 	[89/06/08            dlb]
 * 
 * 	Added kernel_version type definitions.
 * 	[88/12/02            dlb]
 * 
 * 30-Nov-88  David Black (dlb) at Carnegie-Mellon University
 *	Created.  2 flavors so far: basic info,  slot numbers.
 *
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	mach/host_info.h
 *
 *	Definitions for host_info call.
 */

#ifndef	_MACH_HOST_INFO_H_
#define	_MACH_HOST_INFO_H_

#include <mach/vm_statistics.h>
#include <mach/machine.h>
#include <mach/machine/vm_types.h>
#include <mach/time_value.h>

/*
 *	Generic information structure to allow for expansion.
 */
typedef integer_t	*host_info_t;		/* varying array of int. */

#define	HOST_INFO_MAX	(1024)		/* max array size */
typedef integer_t	host_info_data_t[HOST_INFO_MAX];

#define KERNEL_VERSION_MAX (512)
typedef char	kernel_version_t[KERNEL_VERSION_MAX];

#define KERNEL_BOOT_INFO_MAX (4096)
typedef char	kernel_boot_info_t[KERNEL_BOOT_INFO_MAX];

#define	KERNEL_BOOTMAGIC_MAX	(8192)

/*
 *	Currently defined information.
 */
/* host_info() */
typedef	integer_t	host_flavor_t;
#define HOST_BASIC_INFO		1	/* basic info */
#define HOST_SCHED_INFO		3	/* scheduling info */
#define HOST_RESOURCE_SIZES	4	/* kernel struct sizes */
#define HOST_PRIORITY_INFO	5	/* priority information */
#define HOST_SEMAPHORE_TRAPS	7	/* Has semaphore traps - temporary */

struct host_basic_info {
	integer_t	max_cpus;	/* max number of cpus possible */
	integer_t	avail_cpus;	/* number of cpus now available */
	vm_size_t	memory_size;	/* size of memory in bytes */
	cpu_type_t	cpu_type;	/* cpu type */
	cpu_subtype_t	cpu_subtype;	/* cpu subtype */
};

typedef	struct host_basic_info	host_basic_info_data_t;
typedef struct host_basic_info	*host_basic_info_t;
#define HOST_BASIC_INFO_COUNT \
		(sizeof(host_basic_info_data_t)/sizeof(integer_t))

struct host_sched_info {
	integer_t	min_timeout;	/* minimum timeout in milliseconds */
	integer_t	min_quantum;	/* minimum quantum in milliseconds */
};

typedef	struct host_sched_info	host_sched_info_data_t;
typedef struct host_sched_info	*host_sched_info_t;
#define HOST_SCHED_INFO_COUNT \
		(sizeof(host_sched_info_data_t)/sizeof(integer_t))

struct kernel_resource_sizes {
	vm_size_t	task;
        vm_size_t	thread;
        vm_size_t	port;
        vm_size_t	memory_region;
        vm_size_t	memory_object;
};

typedef struct kernel_resource_sizes	kernel_resource_sizes_data_t;
typedef struct kernel_resource_sizes	*kernel_resource_sizes_t;
#define HOST_RESOURCE_SIZES_COUNT \
		(sizeof(kernel_resource_sizes_data_t)/sizeof(integer_t))

struct host_priority_info {
    	integer_t	kernel_priority;
    	integer_t	system_priority;
    	integer_t	server_priority;
    	integer_t	user_priority;
    	integer_t	depress_priority;
    	integer_t	idle_priority;
    	integer_t	minimum_priority;
	integer_t	maximum_priority;
};

typedef struct host_priority_info	host_priority_info_data_t;
typedef struct host_priority_info	*host_priority_info_t;
#define HOST_PRIORITY_INFO_COUNT \
		(sizeof(host_priority_info_data_t)/sizeof(integer_t))

/* host_statistics() */
#define	HOST_LOAD_INFO		1	/* System loading stats */
#define HOST_VM_INFO		2	/* Virtual memory stats */
#define HOST_CPU_LOAD_INFO	3	/* CPU load stats */

struct host_load_info {
	integer_t	avenrun[3];	/* scaled by LOAD_SCALE */
	integer_t	mach_factor[3];	/* scaled by LOAD_SCALE */
};

typedef struct host_load_info	host_load_info_data_t;
typedef struct host_load_info	*host_load_info_t;
#define	HOST_LOAD_INFO_COUNT \
		(sizeof(host_load_info_data_t)/sizeof(integer_t))

/* in <mach/vm_statistics.h> */
#define	HOST_VM_INFO_COUNT \
		(sizeof(vm_statistics_data_t)/sizeof(integer_t))

struct host_cpu_load_info {		/* number of ticks while running... */
	unsigned long	cpu_ticks[CPU_STATE_MAX]; /* ... in the given mode */
};
typedef struct host_cpu_load_info	host_cpu_load_info_data_t;
typedef struct host_cpu_load_info	*host_cpu_load_info_t;
#define HOST_CPU_LOAD_INFO_COUNT \
		(sizeof (host_cpu_load_info_data_t) / sizeof (integer_t))

struct host_paging_info {
	time_value_t	sample_time;	/* (TOD) time sample taken */
	time_value_t	reset_time;	/* (TOD) time at last reset */

			/* Information about page queues */
	long	pagesize;		/* page size in bytes */
	long	free_count;		/* # of pages free */
	long	active_count;		/* # of pages active */
	long	inactive_count;		/* # of pages inactive */
	long	wire_count;		/* # of pages wired down */

			/* Information about page faults */
	long	faults;			/* # of faults */
	long	zero_fill_count;	/* # of zero fill pages */
	long	pageins;		/* # of faults resulting in pageins */
	long	pages_pagedin;		/* # of pages paged in */
	long	cow_faults;		/* # of copy-on-write faults */
	long	reactivations;		/* # of pages reactivated */

			/* Information about object cache performance */
	long	lookups;		/* object cache lookups */
	long	hits;			/* object cache hits */

			/* Information about page replacement algorithm */
	long	pageouts;		/* # of pageout operations (clusters) */
	long	pages_pagedout;		/* # of pages paged out */
};

typedef struct host_paging_info	host_paging_info_data_t;
typedef struct host_paging_info	*host_paging_info_t;
#define HOST_PAGING_INFO_COUNT \
		(sizeof(host_paging_info_data_t)/sizeof(int))

#endif	/* _MACH_HOST_INFO_H_ */
