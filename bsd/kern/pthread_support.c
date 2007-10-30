/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995-2005 Apple Computer, Inc. All Rights Reserved */
/*
 *	pthread_support.c
 */


#define  _PTHREAD_CONDATTR_T
#define  _PTHREAD_COND_T
#define _PTHREAD_MUTEXATTR_T
#define _PTHREAD_MUTEX_T
#define _PTHREAD_RWLOCKATTR_T
#define _PTHREAD_RWLOCK_T

#undef pthread_mutexattr_t
#undef pthread_mutex_t
#undef pthread_condattr_t
#undef pthread_cond_t
#undef pthread_rwlockattr_t
#undef pthread_rwlock_t

#include <sys/param.h>
#include <sys/resourcevar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/acct.h>
#include <sys/file_internal.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/signalvar.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/lock.h>
#include <sys/kdebug.h>

#include <sys/mount.h>
#include <sys/sysproto.h>

#include <sys/vm.h>
#include <kern/task.h>	
#include <kern/thread.h>

#include <sys/pthread_internal.h>

#define PTHREAD_SYNCH_MAX 256
static pthread_mutex_t * pmutex_trans_array[PTHREAD_SYNCH_MAX];
static pthread_cond_t * pcond_trans_array[PTHREAD_SYNCH_MAX];
//static pthread_rwlock_t * prwlock_trans_array[PTHREAD_SYNCH_MAX];

pthread_mutex_t * 
pthread_id_to_mutex(int mutexid)
{
	pthread_mutex_t * mtx = NULL;


	if (mutexid >= 0 && mutexid < PTHREAD_SYNCH_MAX) {
			pthread_list_lock();
			mtx = pmutex_trans_array[mutexid];
			if (mtx) {
				MTX_LOCK(mtx->lock);
				mtx->refcount++;
				MTX_UNLOCK(mtx->lock);
			} 
			pthread_list_unlock();
	}
	return(mtx);
}


int	
pthread_id_mutex_add(pthread_mutex_t * mutex)
{
	int i;

	pthread_list_lock();
	for(i = 1; i < PTHREAD_SYNCH_MAX; i++) {
		if (pmutex_trans_array[i] == 0) {
			pmutex_trans_array[i]  = mutex;
			break;
		}
	}
	pthread_list_unlock();
	if (i == PTHREAD_SYNCH_MAX)
		return(0);
	return(i);
}


void
pthread_id_mutex_remove(int mutexid)
{
	pthread_list_lock();
	if (pmutex_trans_array[mutexid]) {
		pmutex_trans_array[mutexid] = 0;
	}
	pthread_list_unlock();
}


void 
pthread_mutex_release(pthread_mutex_t * mutex)
{
	MTX_LOCK(mutex->lock);
	mutex->refcount --;
	MTX_UNLOCK(mutex->lock);
}


pthread_cond_t * 
pthread_id_to_cond(int condid)
{
	pthread_cond_t * cond = NULL;


	if (condid >= 0 && condid < PTHREAD_SYNCH_MAX) {
			pthread_list_lock();
			cond = pcond_trans_array[condid];
			if (cond) {
				COND_LOCK(cond->lock);
				cond->refcount++;
				COND_UNLOCK(cond->lock);
			} 
			pthread_list_unlock();
	}
	return(cond);
}


int	
pthread_id_cond_add(pthread_cond_t * cond)
{
	int i;

	pthread_list_lock();
	for(i = 1; i < PTHREAD_SYNCH_MAX; i++) {
		if (pcond_trans_array[i] == 0) {
			pcond_trans_array[i]  = cond;
			break;
		}
	}
	pthread_list_unlock();
	if (i == PTHREAD_SYNCH_MAX)
		return(0);
	return(i);
}


void
pthread_id_cond_remove(int condid)
{
	pthread_list_lock();
	if (pcond_trans_array[condid]) {
		pcond_trans_array[condid] = 0;
	}
	pthread_list_unlock();
}


void 
pthread_cond_release(pthread_cond_t * cond)
{
	COND_LOCK(cond->lock);
	cond->refcount --;
	COND_UNLOCK(cond->lock);
}

