/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
 * devtimer.h 
 * - timer source based on <kern/thread_call.h>
 */


#ifndef _NET_DEVTIMER_H
#define _NET_DEVTIMER_H

#include <sys/types.h>
#include <sys/systm.h>

#define DEVTIMER_USECS_PER_SEC		(1000 * 1000)

enum {
    devtimer_process_func_event_lock,
    devtimer_process_func_event_unlock,
};
typedef int devtimer_process_func_event;

typedef struct devtimer_s * devtimer_ref;
typedef void (*devtimer_process_func)(devtimer_ref timer,
				      devtimer_process_func_event event);
typedef void (*devtimer_timeout_func)(void * arg0, void * arg1, void * arg2);

int
devtimer_valid(devtimer_ref timer);

void
devtimer_retain(devtimer_ref timer);

void *
devtimer_arg0(devtimer_ref timer);

devtimer_ref
devtimer_create(devtimer_process_func process_func, void * arg0);

void
devtimer_invalidate(devtimer_ref timer);

void
devtimer_release(devtimer_ref timer);

void
devtimer_set_absolute(devtimer_ref t,
		      struct timeval abs_time,
		      devtimer_timeout_func func,
		      void * arg1, void * arg2);

void
devtimer_set_relative(devtimer_ref t,
		      struct timeval rel_time,
		      devtimer_timeout_func func,
		      void * arg1, void * arg2);
void
devtimer_cancel(devtimer_ref t);

int
devtimer_enabled(devtimer_ref t);

struct timeval
devtimer_current_time(void);

int32_t
devtimer_current_secs(void);

#endif _NET_DEVTIMER_H
