/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/*  sysctl interface for paramters from user-land */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <libkern/libkern.h>

#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/timetrigger.h>
#include <kperf/pet.h>
#include <kperf/filter.h>
#include <kperf/kperfbsd.h>
#include <kperf/kperf.h>

#define REQ_SAMPLING        (1)
#define REQ_ACTION_COUNT    (2)
#define REQ_ACTION_SAMPLERS (3)
#define REQ_TIMER_COUNT     (4)
#define REQ_TIMER_PERIOD    (5)
#define REQ_TIMER_PET       (6)


static int
sysctl_timer_period( __unused struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint64_t inputs[2], retval;
    unsigned timer, set = 0;
    
    /* get 2x 64-bit words */
    error = SYSCTL_IN( req, inputs, 2*sizeof(inputs[0]) );
    if(error)
    {
	    printf( "error in\n" );
	    return (error);
    }

    /* setup inputs */
    timer = (unsigned) inputs[0];
    if( inputs[1] != ~0ULL )
	    set = 1;

    printf( "%s timer: %u, inp[0] %llu\n", set ? "set" : "get", 
            timer, inputs[0] );

    if( set )
    {
	    printf( "timer set period\n" );
	    error = kperf_timer_set_period( timer, inputs[1] );
	    if( error )
		    return error;
    }

    error = kperf_timer_get_period(timer, &retval);
    if(error)
    {
	    printf( "error get period\n" );
	    return (error);
    }

    inputs[1] = retval;
    
    if( error == 0 )
    {
	    error = SYSCTL_OUT( req, inputs, 2*sizeof(inputs[0]) );
	    if( error )
		    printf( "error out\n" );
    }

    return error;
}

static int
sysctl_action_samplers( __unused struct sysctl_oid *oidp, 
                        struct sysctl_req *req )
{
    int error = 0;
    uint64_t inputs[3];
    uint32_t retval;
    unsigned actionid, set = 0;
    
    /* get 3x 64-bit words */
    error = SYSCTL_IN( req, inputs, 3*sizeof(inputs[0]) );
    if(error)
    {
	    printf( "error in\n" );
	    return (error);
    }

    /* setup inputs */
    set = (unsigned) inputs[0];
    actionid = (unsigned) inputs[1];

    if( set )
    {
	    error = kperf_action_set_samplers( actionid, inputs[2] );
	    if( error )
		    return error;
    }

    printf("set %d actionid %u samplers val %u\n", 
           set, actionid, (unsigned) inputs[2] );

    error = kperf_action_get_samplers(actionid, &retval);
    if(error)
    {
	    printf( "error get samplers\n" );
	    return (error);
    }

    inputs[2] = retval;
    
    if( error == 0 )
    {
	    error = SYSCTL_OUT( req, inputs, 3*sizeof(inputs[0]) );
	    if( error )
		    printf( "error out\n" );
    }

    return error;
}

static int
sysctl_sampling( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint32_t value = 0;
    
    /* get the old value and process it */
    value = kperf_sampling_status();

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    printf( "setting sampling to %d\n", value );

    /* if that worked, and we're writing... */
    if( value )
	    error = kperf_sampling_enable();
    else
	    error = kperf_sampling_disable();

    return error;
}

static int
sysctl_action_count( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint32_t value = 0;
    
    /* get the old value and process it */
    value = kperf_action_get_count();

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    printf( "setting action count to %d\n", value );

    /* if that worked, and we're writing... */
    return kperf_action_set_count(value);
}

static int
sysctl_timer_count( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint32_t value = 0;
    
    /* get the old value and process it */
    value = kperf_timer_get_count();

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    printf( "setting timer count to %d\n", value );

    /* if that worked, and we're writing... */
    return kperf_timer_set_count(value);
}

static int
sysctl_timer_pet( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint32_t value = 0;
    
    /* get the old value and process it */
    value = kperf_timer_get_petid();

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    printf( "setting timer petid to %d\n", value );

    /* if that worked, and we're writing... */
    return kperf_timer_set_petid(value);
}

/*
 * #define SYSCTL_HANDLER_ARGS (struct sysctl_oid *oidp,         \
 *                                void *arg1, int arg2,                 \
 *                              struct sysctl_req *req )
 */
static int
kperf_sysctl SYSCTL_HANDLER_ARGS
{
	// __unused struct sysctl_oid *unused_oidp = oidp;
	(void)arg2;
    
	/* which request */
	switch( (uintptr_t) arg1 )
	{
	case REQ_ACTION_COUNT:
		return sysctl_action_count( oidp, req );
	case REQ_ACTION_SAMPLERS:
		return sysctl_action_samplers( oidp, req );
	case REQ_TIMER_COUNT:
		return sysctl_timer_count( oidp, req );
	case REQ_TIMER_PERIOD:
		return sysctl_timer_period( oidp, req );
	case REQ_TIMER_PET:
		return sysctl_timer_pet( oidp, req );
	case REQ_SAMPLING:
		return sysctl_sampling( oidp, req );

#if 0
	case REQ_TIMER:
		return sysctl_timer_period( req );
	case REQ_PET:
		return sysctl_pet_period( req );
#endif
	default:
		return ENOENT;
	}
}

/* root kperf node */
SYSCTL_NODE(, OID_AUTO, kperf, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
            "kperf");

/* action sub-section */
SYSCTL_NODE(_kperf, OID_AUTO, action, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
            "action");

SYSCTL_PROC(_kperf_action, OID_AUTO, count,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_ACTION_COUNT, 
            sizeof(int), kperf_sysctl, "I", "Number of actions");

SYSCTL_PROC(_kperf_action, OID_AUTO, samplers,
            CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_ACTION_SAMPLERS, 
            3*sizeof(uint64_t), kperf_sysctl, "UQ", 
            "What to sample what a trigger fires an action");

/* timer sub-section */
SYSCTL_NODE(_kperf, OID_AUTO, timer, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
            "timer");

SYSCTL_PROC(_kperf_timer, OID_AUTO, count,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_TIMER_COUNT, 
            sizeof(int), kperf_sysctl, "I", "Number of time triggers");

SYSCTL_PROC(_kperf_timer, OID_AUTO, period,
            CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_TIMER_PERIOD, 
            2*sizeof(uint64_t), kperf_sysctl, "UQ", "Timer number and period");

SYSCTL_PROC(_kperf_timer, OID_AUTO, pet_timer,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_TIMER_PET, 
            sizeof(int), kperf_sysctl, "I", "Which timer ID does PET");

/* misc */
SYSCTL_PROC(_kperf, OID_AUTO, sampling,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_SAMPLING, 
            sizeof(int), kperf_sysctl, "I", "Sampling running");

int legacy_mode = 1;
SYSCTL_INT(_kperf, OID_AUTO, legacy_mode, CTLFLAG_RW, &legacy_mode, 0, "legacy_mode");

#if 0
SYSCTL_PROC(_kperf, OID_AUTO, timer_period, 
            CTLFLAG_RW, (void*)REQ_TIMER, 
            sizeof(uint64_t), kperf_sysctl, "QU", "nanoseconds");

SYSCTL_PROC(_kperf, OID_AUTO, pet_period, 
            CTLFLAG_RW, (void*)REQ_PET, 
            sizeof(uint64_t), kperf_sysctl, "QU", "nanoseconds");

/* FIXME: do real stuff */
SYSCTL_INT(_kperf, OID_AUTO, filter_pid0, 
           CTLFLAG_RW, &pid_list[0], 0, "");
SYSCTL_INT(_kperf, OID_AUTO, filter_pid1, 
           CTLFLAG_RW, &pid_list[1], 0, "");
SYSCTL_INT(_kperf, OID_AUTO, filter_pid2, 
           CTLFLAG_RW, &pid_list[2], 0, "");
SYSCTL_INT(_kperf, OID_AUTO, filter_pid3, 
           CTLFLAG_RW, &pid_list[3], 0, "");

#endif
