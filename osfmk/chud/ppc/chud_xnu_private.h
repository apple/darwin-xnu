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

#ifndef _PPC_CHUD_XNU_PRIVATE_H_
#define _PPC_CHUD_XNU_PRIVATE_H_

#pragma mark **** thread ****
// *****************************************************************************
// thread
// *****************************************************************************
extern kern_return_t chudxnu_copy_savearea_to_threadstate(
			thread_flavor_t flavor, 
			thread_state_t tstate,
			mach_msg_type_number_t *count,
			struct savearea *sv);
							    
extern kern_return_t chudxnu_copy_threadstate_to_savearea(
			struct savearea *sv,
			thread_flavor_t flavor,
			thread_state_t tstate,
			mach_msg_type_number_t *count);

#pragma mark **** cpu timer ****
typedef struct {
	timer_call_data_t			cpu_timer_call;
	uint64_t				t_deadline;
	chudxnu_cpu_timer_callback_func_t	cpu_timer_callback_fn;
} chudcpu_data_t;

#endif /* _PPC_CHUD_XNU_PRIVATE_H_ */
