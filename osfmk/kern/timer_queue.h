/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
 * Timer queue support routines.
 */

#ifndef _KERN_TIMER_QUEUE_H_
#define _KERN_TIMER_QUEUE_H_

#include <mach/mach_types.h>

#ifdef MACH_KERNEL_PRIVATE

#include <kern/queue.h>

/*
 *	Invoked by kernel, implemented by platform.
 */

/* Request an expiration deadline, returns queue association */
extern mpqueue_head_t *timer_queue_assign(
				uint64_t		deadline);

extern uint64_t		timer_call_slop(
						uint64_t		deadline);

/* Cancel an associated expiration deadline and specify new deadline */
extern void		timer_queue_cancel(
				mpqueue_head_t		*queue,
				uint64_t		deadline,
				uint64_t		new_deadline);

/*
 *	Invoked by platform, implemented by kernel.
 */

/* Process deadline expiration for queue, returns new deadline */
extern uint64_t		timer_queue_expire(
				mpqueue_head_t		*queue,
				uint64_t		deadline);

/* Shutdown a timer queue and reassign existing activities */
extern void		timer_queue_shutdown(
				mpqueue_head_t		*queue);

/* Move timer requests from one queue to another */
extern int		timer_queue_migrate(
				mpqueue_head_t		*from,
				mpqueue_head_t		*to);

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* _KERN_TIMER_QUEUE_H_ */
