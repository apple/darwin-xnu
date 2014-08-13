/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <kern/debug.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <libkern/libkern.h>
#include <kern/assert.h>

#include <kern/kpc.h>

#include <pexpert/pexpert.h>
#include <kperf/kperf.h>

/* Various sysctl requests */
#define REQ_CLASSES              (1)
#define REQ_COUNTING             (2)
#define REQ_THREAD_COUNTING      (3)
#define REQ_CONFIG_COUNT         (4)
#define REQ_COUNTER_COUNT        (5)
#define REQ_THREAD_COUNTERS      (6)
#define REQ_COUNTERS             (7)
#define REQ_SHADOW_COUNTERS      (8)
#define REQ_CONFIG               (9)
#define REQ_PERIOD              (10)
#define REQ_ACTIONID            (11)
#define REQ_FORCE_ALL_CTRS      (12)
#define REQ_DISABLE_WHITELIST   (13)

/* Type-munging casts */
typedef int (*getint_t)(void);
typedef int (*setint_t)(int);

/* safety */
static int kpc_initted = 0;

/* locking and buffer for large data requests */
static lck_grp_attr_t *sysctl_buffer_lckgrp_attr = NULL;
static lck_grp_t      *sysctl_buffer_lckgrp = NULL;
static lck_mtx_t       sysctl_buffer_lock;
static void           *sysctl_buffer = NULL;

typedef int (*setget_func_t)(int);

/* init our stuff */
extern void kpc_thread_init(void); /* osfmk/kern/kpc_thread.c */
extern void kpc_arch_init(void);

void
kpc_init(void)
{
	sysctl_buffer_lckgrp_attr = lck_grp_attr_alloc_init();
        sysctl_buffer_lckgrp = lck_grp_alloc_init("kpc", 
                                                  sysctl_buffer_lckgrp_attr);
	lck_mtx_init(&sysctl_buffer_lock, sysctl_buffer_lckgrp, LCK_ATTR_NULL);

	kpc_arch_init();
	kpc_thread_init();

	kpc_initted = 1;
}

/* abstract sysctl handlers */
static int
sysctl_get_int( struct sysctl_oid *oidp, struct sysctl_req *req,
                uint32_t value )
{
	int error = 0;
    
	/* copy out the old value */
	error = sysctl_handle_int(oidp, &value, 0, req);
    
	return error;
}

static int
sysctl_getset_int( struct sysctl_oid *oidp, struct sysctl_req *req,
                   int (*get_func)(void), int (*set_func)(int) )
{
	int error = 0;
	uint32_t value = 0;
    
	/* get the old value and process it */
	value = get_func();

	/* copy out the old value, get the new value */
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr)
		return (error);

	/* if that worked, and we're writing... */
	error = set_func( value );

	return error;
}

static int
sysctl_setget_int( struct sysctl_req *req,
                   int (*setget_func)(int) )
{
	int error = 0;
	int value = 0;
    
	error = SYSCTL_IN( req, &value, sizeof(value) );
	if( error )
		return error;
	
	value = setget_func(value);

	error = SYSCTL_OUT( req, &value, sizeof(value) );

	return error;
}

static int
kpc_sysctl_acquire_buffer(void)
{
	if( sysctl_buffer == NULL )
		sysctl_buffer = kpc_counterbuf_alloc();

	if( !sysctl_buffer )
	{
		return ENOMEM;
	}

	return 0;
}

static int 
sysctl_kpc_get_counters(uint32_t counters,
                      uint32_t *size, void *buf)
{
	uint64_t *ctr_buf = (uint64_t*)buf;
	int curcpu;
	uint32_t count;

	count = kpc_get_cpu_counters(counters & KPC_ALL_CPUS,
	                             counters,
	                             &curcpu, &ctr_buf[1]);
	if (!count)
		return EINVAL;

	ctr_buf[0] = curcpu;

	*size = (count+1) * sizeof(uint64_t);

	return 0;
}

static int 
sysctl_kpc_get_shadow_counters(uint32_t counters,
                      uint32_t *size, void *buf)
{
	uint64_t *ctr_buf = (uint64_t*)buf;
	int curcpu;
	uint32_t count;

	count = kpc_get_shadow_counters(counters & KPC_ALL_CPUS,
	                                counters,
	                                &curcpu, &ctr_buf[1]);

	if (!count)
		return EINVAL;

	ctr_buf[0] = curcpu;

	*size = (count+1) * sizeof(uint64_t);

	return 0;
}

static int 
sysctl_kpc_get_thread_counters(uint32_t tid,
                             uint32_t *size, void *buf)
{
	uint32_t count = *size / sizeof(uint64_t);
	int r;

	if( tid != 0 )
		return EINVAL;

	r = kpc_get_curthread_counters(&count, buf);
	if( !r )
		*size = count * sizeof(uint64_t);

	return r;
}   

static int
sysctl_kpc_get_config(uint32_t classes, void* buf)
{
	return kpc_get_config( classes, buf );
}

static int
sysctl_kpc_set_config(uint32_t classes, void* buf)
{
	return kpc_set_config( classes, buf);
}

static int
sysctl_kpc_get_period(uint32_t classes, void* buf)
{
	return kpc_get_period( classes, buf );
}

static int
sysctl_kpc_set_period(uint32_t classes, void* buf)
{
	return kpc_set_period( classes, buf);
}

static int
sysctl_kpc_get_actionid(uint32_t classes, void* buf)
{
	return kpc_get_actionid( classes, buf );
}

static int
sysctl_kpc_set_actionid(uint32_t classes, void* buf)
{
	return kpc_set_actionid( classes, buf);
}


static int
sysctl_get_bigarray( struct sysctl_req *req, 
                     int (*get_fn)(uint32_t, uint32_t*, void*) )
{
	int error = 0;
	uint32_t bufsize = KPC_MAX_COUNTERS * sizeof(uint64_t); /* XXX? */
	uint32_t arg = 0;

	/* get the argument */
	error = SYSCTL_IN( req, &arg, sizeof(arg) );
	if(error)
	{
		printf( "kpc: no arg?\n" );
		return error;
	}

	/* get the wired buffer */
	error = kpc_sysctl_acquire_buffer();
	if (error)
		return error;

	/* atomically get the array into the wired buffer. We have a double
	 * copy, but this is better than page faulting / interrupting during
	 * a copy.
	 */
	error = get_fn( arg, &bufsize, sysctl_buffer );

	/* do the copy out */
	if( !error )
		error = SYSCTL_OUT( req, sysctl_buffer, bufsize );

	return error;
}

/* given a config word, how many bytes does it take? */
static int
sysctl_config_size( uint32_t config )
{
	return kpc_get_config_count(config) * sizeof(kpc_config_t);
}

static int
sysctl_counter_size( uint32_t classes )
{
	return kpc_get_counter_count(classes) * sizeof(uint64_t);
}

static int
sysctl_actionid_size( uint32_t classes )
{
	return kpc_get_counter_count(classes) * sizeof(int32_t);
}

static int
sysctl_getset_bigarray( struct sysctl_req *req, 
                        int (*size_fn)(uint32_t arg),
                        int (*get_fn)(uint32_t, void*),
                        int (*set_fn)(uint32_t, void*) )
{
	int error = 0;
	uint32_t bufsize = KPC_MAX_COUNTERS * sizeof(uint64_t); /* XXX? */
	uint32_t regsize = 0;
	uint64_t arg;

	/* get the config word */
	error = SYSCTL_IN( req, &arg, sizeof(arg) );
	if(error)
	{
		printf( "kpc: no arg?\n" );
		return error;
	}

	/* Work out size of registers */
	regsize = size_fn((uint32_t)arg);

	/* Ignore NULL requests */
	if(regsize == 0)
		return EINVAL;

	/* ensure not too big */
	if( regsize > bufsize )
		return EINVAL;

	/* get the wired buffer */
	error = kpc_sysctl_acquire_buffer();
	if (error)
		return error;

	// if writing...
	if(req->newptr)
	{
		// copy in the rest in -- sysctl remembers we did one already
		error = SYSCTL_IN( req, sysctl_buffer, 
		                   regsize );

		// if SYSCTL_IN fails it means we are only doing a read
		if(!error) {
			// set it
			error = set_fn( (uint32_t)arg, sysctl_buffer );
			if( error )
				goto fail;
		}
	}

	// if reading
	if(req->oldptr)
	{
		// read it
		error = get_fn( (uint32_t)arg, sysctl_buffer );
		if( error )
			goto fail;

		// copy out the full set
		error = SYSCTL_OUT( req, sysctl_buffer, regsize );
	}
   
fail:
	return error;
}



/*
 * #define SYSCTL_HANDLER_ARGS (struct sysctl_oid *oidp,         \
 *                                void *arg1, int arg2,                 \
 *                              struct sysctl_req *req )
 */
static int
kpc_sysctl SYSCTL_HANDLER_ARGS
{
	int ret;

	// __unused struct sysctl_oid *unused_oidp = oidp;
	(void)arg2;
    
	if( !kpc_initted )
		panic("kpc_init not called");

	// Most sysctls require an access check, but a few are public.
	switch( (uintptr_t) arg1 ) {
	case REQ_CLASSES:
	case REQ_CONFIG_COUNT:
	case REQ_COUNTER_COUNT:
		// These read-only sysctls are public.
		break;

	default:
		// Require kperf access to read or write anything else.
		// This is either root or the blessed pid.
		ret = kperf_access_check();
		if (ret) {
			return ret;
		}
		break;
	}

	lck_mtx_lock(&sysctl_buffer_lock);

	/* which request */
	switch( (uintptr_t) arg1 )
	{
	case REQ_CLASSES:
		ret = sysctl_get_int( oidp, req,
		                       kpc_get_classes() );
		break;
	case REQ_COUNTING:
		ret = sysctl_getset_int( oidp, req,
		                          (getint_t)kpc_get_running,
		                          (setint_t)kpc_set_running );
		break;
	case REQ_THREAD_COUNTING:
		ret = sysctl_getset_int( oidp, req,
		                          (getint_t)kpc_get_thread_counting,
		                          (setint_t)kpc_set_thread_counting );
		break;

	case REQ_CONFIG_COUNT:
		ret = sysctl_setget_int( req,
		                          (setget_func_t)kpc_get_config_count );
		break;

	case REQ_COUNTER_COUNT:
		ret = sysctl_setget_int( req,
		                          (setget_func_t)kpc_get_counter_count );
		break;


	case REQ_THREAD_COUNTERS:
		ret = sysctl_get_bigarray( req, sysctl_kpc_get_thread_counters );
		break;

	case REQ_COUNTERS:
		ret = sysctl_get_bigarray( req, sysctl_kpc_get_counters );
		break;

	case REQ_SHADOW_COUNTERS:
		ret = sysctl_get_bigarray( req, sysctl_kpc_get_shadow_counters );
		break;

	case REQ_CONFIG:
		ret = sysctl_getset_bigarray( req,
		                               sysctl_config_size,
		                               sysctl_kpc_get_config,
		                               sysctl_kpc_set_config );
		break;

	case REQ_PERIOD:
		ret = sysctl_getset_bigarray( req,
		                               sysctl_counter_size,
		                               sysctl_kpc_get_period,
		                               sysctl_kpc_set_period );
		break;

	case REQ_ACTIONID:
		ret = sysctl_getset_bigarray( req,
		                               sysctl_actionid_size,
		                               sysctl_kpc_get_actionid,
		                               sysctl_kpc_set_actionid );
		break;

	default:
		ret = ENOENT;
		break;
	}

	lck_mtx_unlock(&sysctl_buffer_lock);
 
	return ret;
}


/***  sysctl definitions  ***/

/* root kperf node */
SYSCTL_NODE(, OID_AUTO, kpc, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
            "kpc");

/* values */
SYSCTL_PROC(_kpc, OID_AUTO, classes,
            CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_ANYBODY,
            (void*)REQ_CLASSES, 
            sizeof(int), kpc_sysctl, "I", "Available classes");

SYSCTL_PROC(_kpc, OID_AUTO, counting,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_COUNTING, 
            sizeof(int), kpc_sysctl, "I", "PMCs counting");

SYSCTL_PROC(_kpc, OID_AUTO, thread_counting,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_THREAD_COUNTING, 
            sizeof(int), kpc_sysctl, "I", "Thread accumulation");

/* faux values */
SYSCTL_PROC(_kpc, OID_AUTO, config_count,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_CONFIG_COUNT, 
            sizeof(int), kpc_sysctl, "S", "Config count");

SYSCTL_PROC(_kpc, OID_AUTO, counter_count,
            CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
            (void*)REQ_COUNTER_COUNT, 
            sizeof(int), kpc_sysctl, "S", "Counter count");

/* arrays */
SYSCTL_PROC(_kpc, OID_AUTO, thread_counters,
            CTLFLAG_RD|CTLFLAG_WR|CTLFLAG_ANYBODY,
            (void*)REQ_THREAD_COUNTERS, 
            sizeof(uint64_t), kpc_sysctl, 
            "QU", "Current thread counters");

SYSCTL_PROC(_kpc, OID_AUTO, counters,
            CTLFLAG_RD|CTLFLAG_WR|CTLFLAG_ANYBODY,
            (void*)REQ_COUNTERS, 
            sizeof(uint64_t), kpc_sysctl, 
            "QU", "Current counters");

SYSCTL_PROC(_kpc, OID_AUTO, shadow_counters,
            CTLFLAG_RD|CTLFLAG_WR|CTLFLAG_ANYBODY,
            (void*)REQ_SHADOW_COUNTERS, 
            sizeof(uint64_t), kpc_sysctl, 
            "QU", "Current shadow counters");

SYSCTL_PROC(_kpc, OID_AUTO, config,
            CTLFLAG_RD|CTLFLAG_WR|CTLFLAG_ANYBODY,
            (void*)REQ_CONFIG, 
            sizeof(uint64_t), kpc_sysctl, 
            "QU", "Set counter configs");

SYSCTL_PROC(_kpc, OID_AUTO, period,
            CTLFLAG_RD|CTLFLAG_WR|CTLFLAG_ANYBODY,
            (void*)REQ_PERIOD, 
            sizeof(uint64_t), kpc_sysctl, 
            "QU", "Set counter periods");

SYSCTL_PROC(_kpc, OID_AUTO, actionid,
            CTLFLAG_RD|CTLFLAG_WR|CTLFLAG_ANYBODY,
            (void*)REQ_ACTIONID, 
            sizeof(uint32_t), kpc_sysctl, 
            "QU", "Set counter actionids");
