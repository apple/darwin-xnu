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
#include <sys/kauth.h>
#include <libkern/libkern.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>

#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/timetrigger.h>
#include <kperf/pet.h>
#include <kperf/kperfbsd.h>
#include <kperf/kperf.h>


/* a pid which is allowed to control kperf without requiring root access */
static pid_t blessed_pid = -1;
static boolean_t blessed_preempt = FALSE;

/* IDs for dispatch from SYSCTL macros */
#define REQ_SAMPLING        (1)
#define REQ_ACTION_COUNT    (2)
#define REQ_ACTION_SAMPLERS (3)
#define REQ_TIMER_COUNT     (4)
#define REQ_TIMER_PERIOD    (5)
#define REQ_TIMER_PET       (6)
#define REQ_TIMER_ACTION    (7)
#define REQ_BLESS           (8)
#define REQ_ACTION_USERDATA (9)
#define REQ_ACTION_FILTER_BY_TASK (10)
#define REQ_ACTION_FILTER_BY_PID  (11)
#define REQ_KDBG_CALLSTACKS (12)
#define REQ_PET_IDLE_RATE   (13)
#define REQ_BLESS_PREEMPT   (14)
#define REQ_KDBG_CSWITCH    (15)
#define REQ_CSWITCH_ACTION  (16)
#define REQ_SIGNPOST_ACTION (17)

/* simple state variables */
int kperf_debug_level = 0;

static lck_grp_attr_t *kperf_cfg_lckgrp_attr = NULL;
static lck_grp_t      *kperf_cfg_lckgrp = NULL;
static lck_mtx_t       kperf_cfg_lock;
static boolean_t       kperf_cfg_initted = FALSE;

void kdbg_swap_global_state_pid(pid_t old_pid, pid_t new_pid); /* bsd/kern/kdebug.c */

/***************************
 *
 * lock init
 *
 ***************************/

void
kperf_bootstrap(void)
{
	kperf_cfg_lckgrp_attr = lck_grp_attr_alloc_init();
	kperf_cfg_lckgrp = lck_grp_alloc_init("kperf cfg", 
                                          kperf_cfg_lckgrp_attr);
	lck_mtx_init(&kperf_cfg_lock, kperf_cfg_lckgrp, LCK_ATTR_NULL);

	kperf_cfg_initted = TRUE;
}

/***************************
 *
 * sysctl handlers
 *
 ***************************/

static int
sysctl_timer_period( __unused struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint64_t inputs[2], retval;
    unsigned timer, set = 0;
    
    /* get 2x 64-bit words */
    error = SYSCTL_IN( req, inputs, 2*sizeof(inputs[0]) );
    if(error)
	    return (error);

    /* setup inputs */
    timer = (unsigned) inputs[0];
    if( inputs[1] != ~0ULL )
	    set = 1;

    if( set )
    {
	    error = kperf_timer_set_period( timer, inputs[1] );
	    if( error )
		    return error;
    }

    error = kperf_timer_get_period(timer, &retval);
    if(error)
	    return (error);

    inputs[1] = retval;
    
    if( error == 0 )
	    error = SYSCTL_OUT( req, inputs, 2*sizeof(inputs[0]) );

    return error;
}

static int
sysctl_timer_action( __unused struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    uint64_t inputs[2];
    uint32_t retval;
    unsigned timer, set = 0;
    
    /* get 2x 64-bit words */
    error = SYSCTL_IN( req, inputs, 2*sizeof(inputs[0]) );
    if(error)
	    return (error);

    /* setup inputs */
    timer = (unsigned) inputs[0];
    if( inputs[1] != ~0ULL )
	    set = 1;

    if( set )
    {
	    error = kperf_timer_set_action( timer, inputs[1] );
	    if( error )
		    return error;
    }

    error = kperf_timer_get_action(timer, &retval);
    if(error)
	    return (error);

    inputs[1] = retval;
    
    if( error == 0 )
	    error = SYSCTL_OUT( req, inputs, 2*sizeof(inputs[0]) );

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
	    return (error);

    /* setup inputs */
    set = (unsigned) inputs[0];
    actionid = (unsigned) inputs[1];

    if( set )
    {
	    error = kperf_action_set_samplers( actionid, inputs[2] );
	    if( error )
		    return error;
    }

    error = kperf_action_get_samplers(actionid, &retval);
    if(error)
	    return (error);

    inputs[2] = retval;
    
    if( error == 0 )
	    error = SYSCTL_OUT( req, inputs, 3*sizeof(inputs[0]) );

    return error;
}

static int
sysctl_action_userdata( __unused struct sysctl_oid *oidp, 
                        struct sysctl_req *req )
{
    int error = 0;
    uint64_t inputs[3];
    uint32_t retval;
    unsigned actionid, set = 0;
    
    /* get 3x 64-bit words */
    error = SYSCTL_IN( req, inputs, 3*sizeof(inputs[0]) );
    if(error)
	    return (error);

    /* setup inputs */
    set = (unsigned) inputs[0];
    actionid = (unsigned) inputs[1];

    if( set )
    {
	    error = kperf_action_set_userdata( actionid, inputs[2] );
	    if( error )
		    return error;
    }

    error = kperf_action_get_userdata(actionid, &retval);
    if(error)
	    return (error);

    inputs[2] = retval;
    
    if( error == 0 )
	    error = SYSCTL_OUT( req, inputs, 3*sizeof(inputs[0]) );

    return error;
}

static int
sysctl_action_filter( __unused struct sysctl_oid *oidp,
		      struct sysctl_req *req, int is_task_t )
{
    int error = 0;
    uint64_t inputs[3];
    int retval;
    unsigned actionid, set = 0;
    mach_port_name_t portname;
    int pid;

    /* get 3x 64-bit words */
    error = SYSCTL_IN( req, inputs, 3*sizeof(inputs[0]) );
    if(error)
	    return (error);

    /* setup inputs */
    set = (unsigned) inputs[0];
    actionid = (unsigned) inputs[1];

    if( set )
    {
	    if( is_task_t )
	    {
		    portname = (mach_port_name_t) inputs[2];
		    pid = kperf_port_to_pid(portname);
	    }
	    else
		    pid = (int) inputs[2];

	    error = kperf_action_set_filter( actionid, pid );
	    if( error )
		    return error;
    }

    error = kperf_action_get_filter(actionid, &retval);
    if(error)
	    return (error);

    inputs[2] = retval;
    
    if( error == 0 )
	    error = SYSCTL_OUT( req, inputs, 3*sizeof(inputs[0]) );

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

    /* if that worked, and we're writing... */
    return kperf_timer_set_petid(value);
}

static int
sysctl_bless( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    int value = 0;

    /* get the old value and process it */
    value = blessed_pid;

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    /* if that worked, and we're writing... */
    error = kperf_bless_pid(value);

    return error;
}

static int
sysctl_bless_preempt( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    int value = 0;

    /* get the old value and process it */
    value = blessed_preempt;

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    /* if that worked, and we're writing... */
    blessed_preempt = value ? TRUE : FALSE;

    return 0;
}


static int
sysctl_kdbg_callstacks( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    int value = 0;
    
    /* get the old value and process it */
    value = kperf_kdbg_get_stacks();

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    /* if that worked, and we're writing... */
    error = kperf_kdbg_set_stacks(value);

    return error;
}

static int
sysctl_pet_idle_rate( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int error = 0;
    int value = 0;
    
    /* get the old value and process it */
    value = kperf_get_pet_idle_rate();

    /* copy out the old value, get the new value */
    error = sysctl_handle_int(oidp, &value, 0, req);
    if (error || !req->newptr)
	    return (error);

    /* if that worked, and we're writing... */
    kperf_set_pet_idle_rate(value);

    return error;
}

static int
sysctl_kdbg_cswitch( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int value = kperf_kdbg_cswitch_get();
    int error = sysctl_handle_int(oidp, &value, 0, req);

    if (error || !req->newptr) {
        return error;
    }

    return kperf_kdbg_cswitch_set(value);
}

static int
sysctl_cswitch_action( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int value = kperf_cswitch_action_get();
    int error = sysctl_handle_int(oidp, &value, 0, req);

    if (error || !req->newptr) {
        return error;
    }

    return kperf_cswitch_action_set(value);
}

static int
sysctl_signpost_action( struct sysctl_oid *oidp, struct sysctl_req *req )
{
    int value = kperf_signpost_action_get();
    int error = sysctl_handle_int(oidp, &value, 0, req);

    if (error || !req->newptr) {
        return error;
    }

    return kperf_signpost_action_set(value);
}

/*
 * #define SYSCTL_HANDLER_ARGS (struct sysctl_oid *oidp,         \
 *                                void *arg1, int arg2,                 \
 *                              struct sysctl_req *req )
 */
static int
kperf_sysctl SYSCTL_HANDLER_ARGS
{
	int ret;

	// __unused struct sysctl_oid *unused_oidp = oidp;
	(void)arg2;

	if ( !kperf_cfg_initted )
		panic("kperf_bootstrap not called");

	ret = kperf_access_check();
	if (ret) {
		return ret;
	}

	lck_mtx_lock(&kperf_cfg_lock);

	/* which request */
	switch( (uintptr_t) arg1 )
	{
	case REQ_ACTION_COUNT:
		ret = sysctl_action_count( oidp, req );
		break;
	case REQ_ACTION_SAMPLERS:
		ret = sysctl_action_samplers( oidp, req );
		break;
	case REQ_ACTION_USERDATA:
		ret = sysctl_action_userdata( oidp, req );
		break;
	case REQ_TIMER_COUNT:
		ret = sysctl_timer_count( oidp, req );
		break;
	case REQ_TIMER_PERIOD:
		ret = sysctl_timer_period( oidp, req );
		break;
	case REQ_TIMER_PET:
		ret = sysctl_timer_pet( oidp, req );
		break;
	case REQ_TIMER_ACTION:
		ret = sysctl_timer_action( oidp, req );
		break;
	case REQ_SAMPLING:
		ret = sysctl_sampling( oidp, req );
		break;
	case REQ_KDBG_CALLSTACKS:
		ret = sysctl_kdbg_callstacks( oidp, req );
		break;
	case REQ_KDBG_CSWITCH:
		ret = sysctl_kdbg_cswitch( oidp, req );
		break;
	case REQ_ACTION_FILTER_BY_TASK:
		ret = sysctl_action_filter( oidp, req, 1 );
		break;
	case REQ_ACTION_FILTER_BY_PID:
		ret = sysctl_action_filter( oidp, req, 0 );
		break;
	case REQ_PET_IDLE_RATE:
		ret = sysctl_pet_idle_rate( oidp, req );
		break;
	case REQ_BLESS_PREEMPT:
		ret = sysctl_bless_preempt( oidp, req );
		break;
	case REQ_CSWITCH_ACTION:
		ret = sysctl_cswitch_action( oidp, req );
		break;
	case REQ_SIGNPOST_ACTION:
		ret = sysctl_signpost_action( oidp, req );
		break;
	default:
		ret = ENOENT;
		break;
	}

	lck_mtx_unlock(&kperf_cfg_lock);

	return ret;
}

static int
kperf_sysctl_bless_handler SYSCTL_HANDLER_ARGS
{
	int ret;
	// __unused struct sysctl_oid *unused_oidp = oidp;
	(void)arg2;
  
	if ( !kperf_cfg_initted )
		panic("kperf_bootstrap not called");

	lck_mtx_lock(&kperf_cfg_lock);

	/* which request */
	if ( (uintptr_t) arg1 == REQ_BLESS )
		ret = sysctl_bless( oidp, req );
	else
		ret = ENOENT;

	lck_mtx_unlock(&kperf_cfg_lock);

	return ret;
}

/***************************
 *
 * Access control
 *
 ***************************/

/* Validate whether the current process has priviledges to access
 * kperf (and by extension, trace). Returns 0 if access is granted.
 */
int
kperf_access_check(void)
{
	proc_t p = current_proc();
	proc_t blessed_p;
	int ret = 0;
	boolean_t pid_gone = FALSE;

	/* check if the pid that held the lock is gone */
	blessed_p = proc_find(blessed_pid);

	if ( blessed_p != NULL )
		proc_rele(blessed_p);
	else
		pid_gone = TRUE;

	if ( blessed_pid == -1 || pid_gone ) {
		/* check for root */
		ret = suser(kauth_cred_get(), &p->p_acflag);
		if( !ret )
			return ret;
	}

	/* check against blessed pid */
	if( p->p_pid != blessed_pid )
		return EACCES;

	/* access granted. */
	return 0;
}

/* specify a pid as being able to access kperf/trace, depiste not
 * being root
 */
int
kperf_bless_pid(pid_t newpid)
{
	proc_t p = NULL;
	pid_t current_pid;

	p = current_proc();
	current_pid = p->p_pid;

	/* are we allowed to preempt? */
	if ( (newpid != -1) && (blessed_pid != -1) &&
	     (blessed_pid != current_pid) && !blessed_preempt ) {
		/* check if the pid that held the lock is gone */
		p = proc_find(blessed_pid);

		if ( p != NULL ) {
			proc_rele(p);
			return EACCES;
		}
	}

	/* validate new pid */
	if ( newpid != -1 ) {
		p = proc_find(newpid);

		if ( p == NULL )
			return EINVAL;

		proc_rele(p);
	}

	/* take trace facility as well */
	kdbg_swap_global_state_pid(blessed_pid, newpid);

	blessed_pid = newpid;
	blessed_preempt = FALSE;

	return 0;
}

/***************************
 *
 * sysctl hooks
 *
 ***************************/

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

SYSCTL_PROC(_kperf_action, OID_AUTO, userdata,
            CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_ACTION_USERDATA, 
            3*sizeof(uint64_t), kperf_sysctl, "UQ", 
            "User data to attribute to action");

SYSCTL_PROC(_kperf_action, OID_AUTO, filter_by_task,
            CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_ACTION_FILTER_BY_TASK, 
            3*sizeof(uint64_t), kperf_sysctl, "UQ", 
            "Apply a task filter to the action");

SYSCTL_PROC(_kperf_action, OID_AUTO, filter_by_pid,
            CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_ACTION_FILTER_BY_PID, 
            3*sizeof(uint64_t), kperf_sysctl, "UQ", 
            "Apply a pid filter to the action");

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

SYSCTL_PROC(_kperf_timer, OID_AUTO, action,
            CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_TIMER_ACTION, 
            2*sizeof(uint64_t), kperf_sysctl, "UQ", "Timer number and actionid");

SYSCTL_PROC(_kperf_timer, OID_AUTO, pet_timer,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_TIMER_PET, 
            sizeof(int), kperf_sysctl, "I", "Which timer ID does PET");

/* misc */
SYSCTL_PROC(_kperf, OID_AUTO, sampling,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_SAMPLING, 
            sizeof(int), kperf_sysctl, "I", "Sampling running");

SYSCTL_PROC(_kperf, OID_AUTO, blessed_pid,
            CTLTYPE_INT|CTLFLAG_RW, /* must be root */
            (void*)REQ_BLESS, 
            sizeof(int), kperf_sysctl_bless_handler, "I", "Blessed pid");

SYSCTL_PROC(_kperf, OID_AUTO, blessed_preempt,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_BLESS_PREEMPT, 
            sizeof(int), kperf_sysctl, "I", "Blessed preemption");

SYSCTL_PROC(_kperf, OID_AUTO, kdbg_callstacks,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_KDBG_CALLSTACKS, 
            sizeof(int), kperf_sysctl, "I", "Generate kdbg callstacks");

SYSCTL_PROC(_kperf, OID_AUTO, kdbg_cswitch,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            (void *)REQ_KDBG_CSWITCH,
            sizeof(int), kperf_sysctl, "I", "Generate context switch info");

SYSCTL_PROC(_kperf, OID_AUTO, pet_idle_rate,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_PET_IDLE_RATE,
            sizeof(int), kperf_sysctl, "I", "Rate at which unscheduled threads are forced to be sampled in PET mode");

SYSCTL_PROC(_kperf, OID_AUTO, cswitch_action,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            (void*)REQ_CSWITCH_ACTION,
            sizeof(int), kperf_sysctl, "I", "ID of action to trigger on context-switch");

SYSCTL_PROC(_kperf, OID_AUTO, signpost_action,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            (void*)REQ_SIGNPOST_ACTION,
            sizeof(int), kperf_sysctl, "I", "ID of action to trigger on signposts");

/* debug */
SYSCTL_INT(_kperf, OID_AUTO, debug_level, CTLFLAG_RW, 
           &kperf_debug_level, 0, "debug level");

