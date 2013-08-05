/*
 * Copyright (c) 1993-1995, 1999-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * Declarations for timer interrupt callouts.
 */

#ifndef _KERN_TIMER_CALL_H_
#define _KERN_TIMER_CALL_H_

#include <mach/mach_types.h>

#ifdef MACH_KERNEL_PRIVATE

#include <kern/call_entry.h>

/*
 * NOTE: for now, bsd/dev/dtrace/dtrace_glue.c has its own definition
 * of this data structure, and the two had better match.
 */
typedef struct timer_call {
	struct call_entry 	call_entry;
	decl_simple_lock_data( ,lock);		/* protects call_entry queue */
	uint64_t		soft_deadline;
	uint32_t		flags;
	boolean_t		async_dequeue;	/* this field is protected by
						   call_entry queue's lock */
	uint64_t		ttd; /* Time to deadline at creation */
} *timer_call_t;

typedef void				*timer_call_param_t;
typedef void				(*timer_call_func_t)(
									timer_call_param_t		param0,
									timer_call_param_t		param1);
#define TIMER_CALL_CRITICAL	0x01
#define TIMER_CALL_LOCAL	0x02
extern boolean_t	timer_call_enter(
						timer_call_t	call,
						uint64_t	deadline,
						uint32_t	flags);

extern boolean_t	timer_call_enter1(
						timer_call_t		call,
						timer_call_param_t	param1,
						uint64_t		deadline,
						uint32_t 		flags);

extern boolean_t	timer_call_cancel(
						timer_call_t	call);

typedef struct timer_call 	timer_call_data_t;

extern void		timer_call_initialize(void);

extern void		timer_call_initialize_queue(mpqueue_head_t *);

extern void		timer_call_setup(
					timer_call_t		call,
					timer_call_func_t	func,
					timer_call_param_t	param0);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_TIMER_CALL_H_ */
