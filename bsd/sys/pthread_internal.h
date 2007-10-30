/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_PTHREAD_INTERNAL_H_
#define _SYS_PTHREAD_INTERNAL_H_

#undef pthread_mutexattr_t;

#include <kern/thread_call.h>

/*
 * Mutex attributes
 */
typedef struct 
{
	long sig;		     /* Unique signature for this structure */
	int prioceiling;
	u_int32_t protocol:2,		/* protocol attribute */
		type:2,			/* mutex type */
		pshared:2,
		rfu:26;
} pthread_mutexattr_t;

#undef pthread_mutex_t
/*
 * Mutex variables
 */
typedef struct _pthread_mutex
{
	long	       sig;	      /* Unique signature for this structure */
	lck_mtx_t *	mutex;		/* the kernel internal mutex */
	lck_mtx_t *	lock;
	thread_t      owner;	      /* Which thread has this mutex locked */
	proc_t      owner_proc;	      /* Which thread has this mutex locked */
	u_int32_t	 protocol:2,		/* protocol */
		type:2,			/* mutex type */
		pshared:2,			/* mutex type */
		refcount:10,
		lock_count:16;
	int16_t       prioceiling;
	int16_t	       priority;      /* Priority to restore when mutex unlocked */
} pthread_mutex_t;

#define MTX_LOCK lck_mtx_lock
#define MTX_UNLOCK lck_mtx_unlock

/*
 * Condition variable attributes
 */
#undef pthread_condattr_t
typedef struct 
{
	long	       sig;	     /* Unique signature for this structure */
	u_int32_t	 pshared:2,		/* pshared */
		unsupported:30;
} pthread_condattr_t;

/*
 * Condition variables
 */
#undef pthread_cond_t
typedef struct _pthread_cond
{
	long	       sig;	     /* Unique signature for this structure */
	lck_mtx_t *	 lock;	     /* Used for internal mutex on structure */
	u_int32_t	waiters:15,	/* Number of threads waiting */
		   sigpending:15,	/* Number of outstanding signals */
			pshared:2;
	int 	refcount;
	pthread_mutex_t * mutex;
	proc_t      owner_proc;	      /* Which thread has this mutex locked */
	semaphore_t	sem;
} pthread_cond_t;
#define COND_LOCK lck_mtx_lock
#define COND_UNLOCK lck_mtx_unlock

#undef pthread_rwlockattr_t
typedef struct {
	long	       sig;	      /* Unique signature for this structure */
	int             pshared;
	int		rfu[2];		/* reserved for future use */
} pthread_rwlockattr_t;

#undef pthread_rwlock_t
typedef struct {
	long 		sig;
	lck_rw_t * rwlock;
	int             pshared;
	thread_t		owner;
	int	rfu[2];
} pthread_rwlock_t;

#define _PTHREAD_NO_SIG			0x00000000
#define _PTHREAD_MUTEX_ATTR_SIG		0x4D545841  /* 'MTXA' */
#define _PTHREAD_MUTEX_SIG		0x4D555458  /* 'MUTX' */
#define _PTHREAD_MUTEX_SIG_init		0x32AAABA7  /* [almost] ~'MUTX' */
#define _PTHREAD_COND_ATTR_SIG		0x434E4441  /* 'CNDA' */
#define _PTHREAD_COND_SIG		0x434F4E44  /* 'COND' */
#define _PTHREAD_COND_SIG_init		0x3CB0B1BB  /* [almost] ~'COND' */
#define _PTHREAD_ATTR_SIG		0x54484441  /* 'THDA' */
#define _PTHREAD_ONCE_SIG		0x4F4E4345  /* 'ONCE' */
#define _PTHREAD_ONCE_SIG_init		0x30B1BCBA  /* [almost] ~'ONCE' */
#define _PTHREAD_SIG			0x54485244  /* 'THRD' */
#define _PTHREAD_RWLOCK_ATTR_SIG	0x52574C41  /* 'RWLA' */
#define _PTHREAD_RWLOCK_SIG		0x52574C4B  /* 'RWLK' */
#define _PTHREAD_RWLOCK_SIG_init	0x2DA8B3B4  /* [almost] ~'RWLK' */

#define _PTHREAD_KERN_COND_SIG		0x12345678  /*  */
#define _PTHREAD_KERN_MUTEX_SIG		0x34567812  /*  */
#define _PTHREAD_KERN_RWLOCK_SIG	0x56781234  /*  */


#define PTHREAD_PROCESS_SHARED 1
#define PTHREAD_PROCESS_PRIVATE 2

#define WORKQUEUE_MAXTHREADS 64
#define WORKITEM_SIZE 64
#define WORKQUEUE_NUMPRIOS 5

struct threadlist {
	TAILQ_ENTRY(threadlist) th_entry;
	thread_t th_thread;
	int	 th_flags;
	uint32_t th_unparked;
	uint32_t th_affinity_tag;
	struct workqueue *th_workq;
	mach_vm_size_t th_stacksize;
	mach_vm_size_t th_allocsize;
	mach_vm_offset_t th_stackaddr;
	mach_port_t th_thport;
};
#define TH_LIST_INITED 		0x01
#define TH_LIST_RUNNING 	0x02
#define TH_LIST_BLOCKED 	0x04
#define TH_LIST_SUSPENDED 	0x08

struct workitem {
	TAILQ_ENTRY(workitem) wi_entry;
	user_addr_t wi_item;
};

struct workitemlist {
	TAILQ_HEAD(, workitem) wl_itemlist;
	TAILQ_HEAD(, workitem) wl_freelist;
};


struct workqueue {
	struct workitem wq_array[WORKITEM_SIZE * WORKQUEUE_NUMPRIOS];
        proc_t		wq_proc;
        vm_map_t	wq_map;
        task_t		wq_task;
        thread_call_t	wq_timer_call;
	int 		wq_flags;
        int		wq_itemcount;
        struct timeval	wq_lastran_ts;
        struct timeval	wq_reduce_ts;
        uint32_t	wq_stalled_count;
        uint32_t	wq_max_threads_scheduled;
        uint32_t	wq_affinity_max;
        uint32_t	wq_threads_scheduled;
	uint32_t	wq_nthreads;
        uint32_t	wq_nextaffinitytag;
	struct workitemlist  wq_list[WORKQUEUE_NUMPRIOS]; /* prio based item list */
	TAILQ_HEAD(, threadlist) wq_thrunlist;
	TAILQ_HEAD(wq_thidlelist, threadlist) * wq_thidlelist;
        uint32_t      *	wq_thactivecount;
        uint32_t      *	wq_thcount;
};
#define WQ_LIST_INITED		0x01
#define WQ_BUSY			0x02
#define WQ_TIMER_RUNNING	0x04
#define WQ_TIMER_WATCH		0x08
#define WQ_ADD_TO_POOL		0x10

#define WQ_STALLED_WINDOW_USECS		20000
#define WQ_REDUCE_POOL_WINDOW_USECS	3000000
#define WQ_MAX_RUN_LATENCY_USECS	500
#define	WQ_TIMER_INTERVAL_MSECS		40

/* workq_ops commands */
#define WQOPS_QUEUE_ADD 1
#define WQOPS_QUEUE_REMOVE 2
#define WQOPS_THREAD_RETURN 4

#define PTH_DEFAULT_STACKSIZE 512*1024
#define PTH_DEFAULT_GUARDSIZE 4*1024
#define MAX_PTHREAD_SIZE 64*1024

void workqueue_exit(struct proc *);

pthread_mutex_t * pthread_id_to_mutex(int mutexid);
int	pthread_id_mutex_add(pthread_mutex_t *);
void	pthread_id_mutex_remove(int);
void pthread_mutex_release(pthread_mutex_t *);
pthread_cond_t * pthread_id_to_cond(int condid);
int	pthread_id_cond_add(pthread_cond_t *);
void	pthread_id_cond_remove(int);
void pthread_cond_release(pthread_cond_t *);

void pthread_list_lock(void);
void pthread_list_unlock(void);

#endif /* _SYS_PTHREAD_INTERNAL_H_ */

