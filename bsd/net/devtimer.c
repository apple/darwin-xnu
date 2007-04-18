/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
 * devtimer.c 
 * - timer source based on <kern/thread_call.h>
 */

/*
 * Modification History:
 *
 * June 22, 2004	Dieter Siegmund (dieter@apple.com)
 * - created
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <kern/thread_call.h>
#include <net/devtimer.h>
#include <libkern/OSAtomic.h>

#ifdef DEVTIMER_DEBUG
#define _devtimer_printf	printf
#else DEVTIMER_DEBUG
static __inline__ void
_devtimer_printf(__unused const char * fmt, ...)
{
}
#endif DEVTIMER_DEBUG

struct devtimer_s {
    void *			dt_callout;
    devtimer_timeout_func	dt_timeout_func;
    devtimer_process_func	dt_process_func;
    void *			dt_arg0;
    void *			dt_arg1;
    void *			dt_arg2;
    int				dt_generation;
    UInt32			dt_retain_count;
};

#define M_DEVTIMER	M_DEVBUF

static __inline__ void
timeval_add(struct timeval tv1, struct timeval tv2,
	    struct timeval * result)
{
    result->tv_sec = tv1.tv_sec + tv2.tv_sec;
    result->tv_usec = tv1.tv_usec + tv2.tv_usec;
    if (result->tv_usec > DEVTIMER_USECS_PER_SEC) {
	result->tv_usec -= DEVTIMER_USECS_PER_SEC;
	result->tv_sec++;
    }
    return;
}

static __inline__ uint64_t
timeval_to_absolutetime(struct timeval tv)
{
    uint64_t	secs;
    uint64_t	usecs;

    clock_interval_to_absolutetime_interval(tv.tv_sec, NSEC_PER_SEC, 
					    &secs);
    clock_interval_to_absolutetime_interval(tv.tv_usec, NSEC_PER_USEC, 
					    &usecs);
    return (secs + usecs);
}


__private_extern__ int
devtimer_valid(devtimer_ref timer)
{
    return (timer->dt_callout != NULL);
}

__private_extern__ void
devtimer_retain(devtimer_ref timer)
{
    OSIncrementAtomic(&timer->dt_retain_count);
    return;
}

__private_extern__ void
devtimer_invalidate(devtimer_ref timer)
{
    devtimer_cancel(timer);
    timer->dt_arg0 = NULL;
    if (timer->dt_callout != NULL) {
	thread_call_free(timer->dt_callout);
	timer->dt_callout = NULL;
    }
    return;
}

__private_extern__ void
devtimer_release(devtimer_ref timer)
{
    UInt32	old_retain_count;

    old_retain_count = OSDecrementAtomic(&timer->dt_retain_count);
    switch (old_retain_count) {
    case 0:
	panic("devtimer_release: retain count is 0\n");
	break;
    case 1:
	devtimer_invalidate(timer);
	FREE(timer, M_DEVTIMER);
	_devtimer_printf("devtimer: timer released\n");
	break;
    default:
	break;
    }
    return;
}

static void
devtimer_process(void * param0, void * param1)
{
    int				generation = (int)param1;
    devtimer_process_func 	process_func;
    devtimer_timeout_func 	timeout_func;
    devtimer_ref		timer = (devtimer_ref)param0;

    process_func = timer->dt_process_func;
    if (process_func != NULL) {
	(*process_func)(timer, devtimer_process_func_event_lock);
    }
    timeout_func = timer->dt_timeout_func;
    if (timeout_func != NULL) {
	timer->dt_timeout_func = NULL;
	if (timer->dt_generation == generation) {
	    (*timeout_func)(timer->dt_arg0, timer->dt_arg1, timer->dt_arg2);
	}
    }
    devtimer_release(timer);
    if (process_func != NULL) {
	(*process_func)(timer, devtimer_process_func_event_unlock);
    }
    return;
}

__private_extern__ void *
devtimer_arg0(devtimer_ref timer)
{
    return (timer->dt_arg0);
}

__private_extern__ devtimer_ref
devtimer_create(devtimer_process_func process_func, void * arg0)
{
    devtimer_ref	timer;

    timer = _MALLOC(sizeof(*timer), M_DEVTIMER, M_WAITOK);
    if (timer == NULL) {
	return (timer);
    }
    bzero(timer, sizeof(*timer));
    devtimer_retain(timer);
    timer->dt_callout = thread_call_allocate(devtimer_process, timer);
    if (timer->dt_callout == NULL) {
	_devtimer_printf("devtimer: thread_call_allocate failed\n");
	devtimer_release(timer);
	timer = NULL;
    }
    timer->dt_process_func = process_func;
    timer->dt_arg0 = arg0;
    return (timer);
}

__private_extern__ void
devtimer_set_absolute(devtimer_ref timer, 
		      struct timeval abs_time, 
		      devtimer_timeout_func timeout_func, 
		      void * arg1, void * arg2)
{
    if (timer->dt_callout == NULL) {
	printf("devtimer_set_absolute: uninitialized/freed timer\n");
	return;
    }
    devtimer_cancel(timer);
    if (timeout_func == NULL) {
	return;
    }
    timer->dt_timeout_func = timeout_func;
    timer->dt_arg1 = arg1;
    timer->dt_arg2 = arg2;
    _devtimer_printf("devtimer: wakeup time is (%d.%d)\n", 
		     abs_time.tv_sec, abs_time.tv_usec);
    timer->dt_generation++;
    devtimer_retain(timer);
    thread_call_enter1_delayed(timer->dt_callout, 
			       (thread_call_param_t)timer->dt_generation,
			       timeval_to_absolutetime(abs_time));
    return;
}

__private_extern__ void
devtimer_set_relative(devtimer_ref timer, 
		      struct timeval rel_time, 
		      devtimer_timeout_func timeout_func, 
		      void * arg1, void * arg2)
{
    struct timeval		abs_time;
    struct timeval		current_time;

    current_time = devtimer_current_time();
    timeval_add(current_time, rel_time, &abs_time);
    devtimer_set_absolute(timer, abs_time, timeout_func, arg1, arg2);
    return;
}

__private_extern__ void
devtimer_cancel(devtimer_ref timer)
{
    if (timer->dt_timeout_func != NULL) {
	timer->dt_timeout_func = NULL;
	if (timer->dt_callout != NULL) {
	    _devtimer_printf("devtimer: cancelling timer source\n");
	    if (thread_call_cancel(timer->dt_callout)) {
		devtimer_release(timer);
	    }
	    else {
		_devtimer_printf("devtimer: delayed release\n");
	    }
	}
    }
    return;
}

__private_extern__ int
devtimer_enabled(devtimer_ref timer)
{
    return (timer->dt_timeout_func != NULL);
}

__private_extern__ int32_t
devtimer_current_secs(void)
{
    struct timeval	tv;

    tv = devtimer_current_time();
    return (tv.tv_sec);
}

__private_extern__ struct timeval
devtimer_current_time(void)
{
    struct timeval 	tv;
    uint32_t sec;
    uint32_t usec;

    clock_get_system_microtime(&sec, &usec);
    tv.tv_sec = sec;
    tv.tv_usec = usec;
    return (tv);
}
