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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * 29 June 2000 (debo)
 *  Created.
 */

#ifndef	_KERN_MK_TIMER_H_
#define	_KERN_MK_TIMER_H_

#ifdef MACH_KERNEL_PRIVATE
#include <libkern/OSBase.h>

#include <mach/mach_types.h>

#include <kern/call_entry.h>

struct mk_timer {
	decl_simple_lock_data(,lock)
	call_entry_data_t	call_entry;
	AbsoluteTime		time_of_arming;
	boolean_t			is_dead:1,
						is_armed:1;
	int					active;
	ipc_port_t			port;
};

typedef struct mk_timer		*mk_timer_t, mk_timer_data_t;

void		mk_timer_port_destroy(
				ipc_port_t				port);

void		mk_timer_initialize(void);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_MK_TIMER_H_ */
