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

#ifndef _MACH_MACH_SYSCALLS_H_
#define	_MACH_MACH_SYSCALLS_H_

#include <mach/kern_return.h>
#include <mach/std_types.h>
#include <mach/mach_types.h>
#include <mach/clock_types.h>

extern kern_return_t	clock_sleep_trap(
							mach_port_name_t	clock_name,
							sleep_type_t		sleep_type,
							int					sleep_sec,
							int					sleep_nsec,
							mach_timespec_t		*wakeup_time);

extern kern_return_t	thread_switch(
							mach_port_name_t	thread_name,
							int					option,
							mach_msg_timeout_t	option_time);

#endif	/* _MACH_MACH_SYSCALLS_H_ */
