/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _I386_CHUD_XNU_PRIVATE_H_
#define _I386_CHUD_XNU_PRIVATE_H_

#include <kern/queue.h>

#pragma mark **** cpu timer ****

/*
 * Cross-cpu signal request entries are queued on the target cpu's
 * chudcpu_data_t struct. This differs from PPC because i386 doesn't
 * support sending arguments with cross-cpu signals. Hence we have
 * to do it ourselves.
 */ 
typedef struct {
	struct queue_entry	req_entry;	/* Must be first */
	uint32_t		req_type;
	uint32_t		req_code;
	volatile uint32_t	req_sync;
} chudcpu_signal_request_t;

typedef struct {
	void					*cpu_chud_fn_tablep;
	timer_call_data_t			cpu_timer_call;
	uint64_t				t_deadline;
	chudxnu_cpu_timer_callback_func_t	cpu_timer_callback_fn;
	mpqueue_head_t				cpu_request_queue;
} chudcpu_data_t;
/* NB: cpu_chud_fn_tablep is expected to be the first member, at offset 0 */

extern void chudxnu_cpu_signal_handler(void);

#endif /* _I386_CHUD_XNU_PRIVATE_H_ */
