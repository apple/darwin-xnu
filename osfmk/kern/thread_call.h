/*
 * Copyright (c) 1993-1995, 1999-2000 Apple Computer, Inc.
 * All rights reserved.
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
 * Declarations for thread-based callouts.
 *
 * HISTORY
 *
 * 10 July 1999 (debo)
 *  Pulled into Mac OS X (microkernel).
 *
 * 3 July 1993 (debo)
 *	Created.
 */

#ifndef _KERN_THREAD_CALL_H_
#define _KERN_THREAD_CALL_H_

#include <libkern/OSBase.h>

#include <mach/mach_types.h>

typedef struct call_entry	*thread_call_t;
typedef void				*thread_call_param_t;
typedef void				(*thread_call_func_t)(
									thread_call_param_t		param0,
									thread_call_param_t		param1);

boolean_t
thread_call_enter(
	thread_call_t		call
);
boolean_t
thread_call_enter1(
	thread_call_t			call,
	thread_call_param_t		param1
);
boolean_t
thread_call_enter_delayed(
	thread_call_t		call,
	AbsoluteTime		deadline
);
boolean_t
thread_call_enter1_delayed(
	thread_call_t			call,
	thread_call_param_t		param1,
	AbsoluteTime			deadline
);
boolean_t
thread_call_cancel(
	thread_call_t		call
);
boolean_t
thread_call_is_delayed(
	thread_call_t		call,
	AbsoluteTime		*deadline
);

thread_call_t
thread_call_allocate(
	thread_call_func_t		func,
	thread_call_param_t		param0
);
boolean_t
thread_call_free(
	thread_call_t		call
);

/*
 * This portion of the interface
 * is OBSOLETE and DEPRECATED.  It
 * will disappear shortly.
 */
void
thread_call_func(
	thread_call_func_t		func,
	thread_call_param_t		param,
	boolean_t				unique_call
);
void
thread_call_func_delayed(
	thread_call_func_t		func,
	thread_call_param_t		param,
	AbsoluteTime			deadline
);

boolean_t
thread_call_func_cancel(
	thread_call_func_t		func,
	thread_call_param_t		param,
	boolean_t				cancel_all
);
/* End OBSOLETE and DEPRECATED */

#ifdef MACH_KERNEL_PRIVATE
#include <kern/call_entry.h>

typedef struct call_entry	thread_call_data_t;

void
thread_call_initialize(void);

void
thread_call_setup(
	thread_call_t			call,
	thread_call_func_t		func,
	thread_call_param_t		param0
);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_THREAD_CALL_H_ */
