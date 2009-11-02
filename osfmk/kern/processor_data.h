/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 * Machine independent per processor data.
 */

#ifndef _KERN_PROCESSOR_DATA_H_
#define _KERN_PROCESSOR_DATA_H_

/*
 * #include kern/processor.h instead of this file.
 */

#ifdef MACH_KERNEL_PRIVATE

#include <ipc/ipc_kmsg.h>
#include <kern/timer.h>

struct processor_data {
	/* Processor state statistics */
	integer_t				cpu_ticks[CPU_STATE_MAX];

#if !STAT_TIME
	/* Current execution timer */
	timer_t					current_timer;
	timer_data_t			offline_timer;
#endif	/* STAT_TIME */

	/* Kernel stack cache */
	struct stack_cache {
		vm_offset_t				free;
		unsigned int			count;
	}						stack_cache;

	/* Pending timer callouts */
	queue_head_t			timer_call_queue;

	/* VM event counters */
	vm_statistics_data_t	vm_stat;

	/* IPC free message cache */
	struct ikm_cache {
#define IKM_STASH	16
		ipc_kmsg_t				entries[IKM_STASH];
		unsigned int			avail;
	}						ikm_cache;

	int						slot_num;
};

typedef struct processor_data	processor_data_t;

#define PROCESSOR_DATA(processor, member)	\
					(processor)->processor_data.member

extern	void	processor_data_init(
					processor_t		processor);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_PROCESSOR_DATA_H_ */
