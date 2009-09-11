/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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

#if PSYNCH

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/acct.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/signalvar.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/lock.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/pthread_internal.h>
#include <sys/vm.h>
#include <sys/user.h>

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>
#include <kern/kern_types.h>
#include <kern/task.h>
#include <kern/clock.h>
#include <mach/kern_return.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/thread_call.h>
#include <kern/kalloc.h>
#include <kern/sched_prim.h>
#include <kern/processor.h>
#include <kern/affinity.h>
#include <kern/wait_queue.h>
#include <mach/mach_vm.h>
#include <mach/mach_param.h>
#include <mach/thread_policy.h>
#include <mach/message.h>
#include <mach/port.h>
#include <vm/vm_protos.h>
#include <vm/vm_map.h>
#include <mach/vm_region.h>

#include <libkern/OSAtomic.h>

#define _PSYNCH_TRACE_ 0		/* kdebug trace */
#define __TESTPANICS__ 0		/* panics for error conditions */
#define COND_MTX_WAITQUEUEMOVE 0	/* auto move from cvar wait queue to mutex waitqueue */

#if _PSYNCH_TRACE_
#define _PSYNCH_TRACE_MLWAIT	0x9000000
#define _PSYNCH_TRACE_MLDROP	0x9000004
#define _PSYNCH_TRACE_CVWAIT	0x9000008
#define _PSYNCH_TRACE_CVSIGNAL	0x900000c
#define _PSYNCH_TRACE_CVBROAD	0x9000010
#define _PSYNCH_TRACE_KMDROP	0x9000014
#define _PSYNCH_TRACE_RWRDLOCK	0x9000018
#define _PSYNCH_TRACE_RWLRDLOCK	0x900001c
#define _PSYNCH_TRACE_RWWRLOCK	0x9000020
#define _PSYNCH_TRACE_RWYWRLOCK	0x9000024
#define _PSYNCH_TRACE_RWUPGRADE	0x9000028
#define _PSYNCH_TRACE_RWDOWNGRADE	0x900002c
#define _PSYNCH_TRACE_RWUNLOCK	0x9000030
#define _PSYNCH_TRACE_RWUNLOCK2	0x9000034
#define _PSYNCH_TRACE_RWHANDLEU	0x9000038
#define _PSYNCH_TRACE_FSEQTILL	0x9000040
/* user side */
#define _PSYNCH_TRACE_UM_LOCK	0x9000060
#define _PSYNCH_TRACE_UM_UNLOCK	0x9000064
#define _PSYNCH_TRACE_UM_MHOLD	0x9000068
#define _PSYNCH_TRACE_UM_MDROP	0x900006c
#define _PSYNCH_TRACE_UM_CVWAIT	0x9000070
#define _PSYNCH_TRACE_UM_CVSIG	0x9000074
#define _PSYNCH_TRACE_UM_CVBRD	0x9000078

#endif /* _PSYNCH_TRACE_ */

lck_mtx_t * pthread_list_mlock;

#define PTHHASH(addr)    (&pthashtbl[(addr) & pthhash])
extern LIST_HEAD(pthhashhead, ksyn_wait_queue) *pth_glob_hashtbl;
struct pthhashhead * pth_glob_hashtbl;
u_long pthhash;

LIST_HEAD(, ksyn_wait_queue) pth_free_list;

static int PTH_HASHSIZE = 100;


#define SEQFIT 0
#define FIRSTFIT 1

struct ksyn_queue {
	TAILQ_HEAD(, uthread) ksynq_uthlist;
	uint32_t	ksynq_count;		/* number of entries in queue */
	uint32_t	ksynq_firstnum;		/* lowest seq in queue */
	uint32_t	ksynq_lastnum;		/* highest seq in queue */
};

#define KSYN_QUEUE_READ		0
#define KSYN_QUEUE_LREAD	1
#define KSYN_QUEUE_WRITER	2
#define KSYN_QUEUE_YWRITER	3
#define KSYN_QUEUE_UPGRADE	4
#define KSYN_QUEUE_MAX		5

struct ksyn_wait_queue {
	LIST_ENTRY(ksyn_wait_queue) kw_hash;
	LIST_ENTRY(ksyn_wait_queue) kw_list;
#if USE_WAITQUEUE
	struct wait_queue kw_wq;
#endif /* USE_WAITQUEUE */
	user_addr_t kw_addr;
	uint64_t  kw_owner;
	uint64_t kw_object;		/* object backing in shared mode */
	uint64_t kw_offset;		/* offset inside the object in shared mode */
	int     kw_flags;		/* mutex, cvar options/flags */
	int 	kw_pflags;		/* flags under listlock protection */
	struct timeval kw_ts;		/* timeval need for upkeep before free */
	int	kw_iocount;		/* inuse reference */

	int	kw_type;		/* queue type like mutex, cvar, etc */
	uint32_t kw_inqueue;		/* num of waiters held */
	uint32_t kw_highseq;		/* highest seq in the queue */
	uint32_t kw_lowseq;		/* lowest seq in the queue */
	uint32_t kw_lastunlockseq;	/* the last seq that unlocked */
	uint32_t kw_pre_rwwc;		/* prepost count */
	uint32_t kw_pre_lockseq;	/* prepost target seq */
	uint32_t kw_pre_cvretval;	/* retval for cwait on prepost */
	uint32_t kw_pre_limrd;		/*  prepost read only(rwlock)  */
	uint32_t kw_pre_limrdseq;	/* prepost limit seq for reads(rwlock)  */
	uint32_t kw_pre_limrdbits;	/*  seqbit needed for updates on prepost */
	uint32_t kw_pre_intrcount;	/*  prepost of missed wakeup due to intrs */
	uint32_t kw_pre_intrseq;	/*  prepost of missed wakeup limit seq */
	uint32_t kw_pre_intrretbits;	/*  return bits value for missed wakeup threads */
	uint32_t kw_pre_intrtype;	/*  type of failed wakueps*/

	int 	kw_kflags;
	TAILQ_HEAD(, uthread) kw_uthlist;       /* List of uthreads */
	struct ksyn_queue kw_ksynqueues[KSYN_QUEUE_MAX];	/* queues to hold threads */
	lck_mtx_t kw_lock;		/* mutex lock protecting this structure */
	struct ksyn_wait_queue * kw_attq; /* attached queue (cvar->mutex, need in prepost */ 
};

typedef struct ksyn_queue * ksyn_queue_t;
typedef struct ksyn_wait_queue * ksyn_wait_queue_t;

#define PTHRW_EBIT			0x01
#define PTHRW_LBIT			0x02
#define PTHRW_YBIT			0x04
#define PTHRW_WBIT			0x08
#define PTHRW_UBIT			0x10
#define PTHRW_RETRYBIT      		0x20
/* same as 0x20, shadow W bit for rwlock */
#define PTHRW_SHADOW_W      		0x20        

#define PTHRW_TRYLKBIT      		0x40
#define PTHRW_RW_HUNLOCK      		0x40	/* returning read thread responsible to handle unlock */

#define PTHRW_MTX_NONE			0x80
#define PTHRW_RW_INIT			0x80	/* reset on the lock bits */
/* same as 0x80, spurious rwlock  unlock ret from kernel */
#define PTHRW_RW_SPURIOUS     		0x80      

#define PTHRW_INC			0x100

#define PTHRW_BIT_MASK		0x000000ff;

#define PTHRW_COUNT_SHIFT	8
#define PTHRW_COUNT_MASK	0xffffff00
#define PTHRW_MAX_READERS	0xffffff00

/* first contended seq that kernel sees */
#define KW_MTXFIRST_KSEQ	0x200
#define KW_CVFIRST_KSEQ		1
#define KW_RWFIRST_KSEQ		0x200

#define is_rw_ewubit_set(x) ((x & (PTHRW_EBIT | PTHRW_WBIT | PTHRW_UBIT)) != 0)
#define is_rw_lybit_set(x) ((x & (PTHRW_LBIT | PTHRW_YBIT)) != 0)
#define is_rw_ebit_set(x) ((x & PTHRW_EBIT) != 0)
#define is_rw_uebit_set(x) ((x & (PTHRW_EBIT | PTHRW_UBIT)) != 0)
#define is_rw_ubit_set(x) ((x & PTHRW_UBIT) != 0)
#define is_rw_either_ewyubit_set(x) ((x & (PTHRW_EBIT | PTHRW_WBIT | PTHRW_UBIT | PTHRW_YBIT)) != 0)


/* is x lower than Y */
#define is_seqlower(x, y) ((x  < y) || ((x - y) > (PTHRW_MAX_READERS/2)))
/* is x lower than or eq Y */
#define is_seqlower_eq(x, y) ((x  <= y) || ((x - y) > (PTHRW_MAX_READERS/2)))

/* is x greater than Y */
#define is_seqhigher(x, y) ((x  > y) || ((y - x) > (PTHRW_MAX_READERS/2)))

static inline  int diff_genseq(uint32_t x, uint32_t y) { 
	if (x > y)  {
		return(x-y);
	} else {
		return((PTHRW_MAX_READERS - y) + x + PTHRW_INC);
	}
}

#define TID_ZERO (uint64_t)0

/* bits needed in handling the rwlock unlock */
#define PTH_RW_TYPE_READ	0x01
#define PTH_RW_TYPE_LREAD	0x02
#define PTH_RW_TYPE_WRITE	0x04
#define PTH_RW_TYPE_YWRITE	0x08
#define PTH_RW_TYPE_UPGRADE	0x10
#define PTH_RW_TYPE_MASK	0xff
#define PTH_RW_TYPE_SHIFT  	8

#define PTH_RWSHFT_TYPE_READ	0x0100
#define PTH_RWSHFT_TYPE_LREAD	0x0200
#define PTH_RWSHFT_TYPE_WRITE	0x0400
#define PTH_RWSHFT_TYPE_YWRITE	0x0800
#define PTH_RWSHFT_TYPE_MASK	0xff00

/*
 * Mutex protocol attributes
 */
#define PTHREAD_PRIO_NONE            0
#define PTHREAD_PRIO_INHERIT         1
#define PTHREAD_PRIO_PROTECT         2
#define PTHREAD_PROTOCOL_FLAGS_MASK  0x3

/* 
 * Mutex type attributes
 */
#define PTHREAD_MUTEX_NORMAL            0
#define PTHREAD_MUTEX_ERRORCHECK        4
#define PTHREAD_MUTEX_RECURSIVE         8
#define PTHREAD_MUTEX_DEFAULT           PTHREAD_MUTEX_NORMAL
#define PTHREAD_TYPE_FLAGS_MASK		0xc

/* 
 * Mutex pshared attributes
 */
#define PTHREAD_PROCESS_SHARED         0x10
#define PTHREAD_PROCESS_PRIVATE        0x20
#define PTHREAD_PSHARED_FLAGS_MASK	0x30

/* 
 * Mutex policy attributes
 */
#define _PTHREAD_MUTEX_POLICY_NONE              0
#define _PTHREAD_MUTEX_POLICY_FAIRSHARE         0x040	/* 1 */
#define _PTHREAD_MUTEX_POLICY_FIRSTFIT          0x080	/* 2 */
#define _PTHREAD_MUTEX_POLICY_REALTIME          0x0c0	/* 3 */
#define _PTHREAD_MUTEX_POLICY_ADAPTIVE          0x100	/* 4 */
#define _PTHREAD_MUTEX_POLICY_PRIPROTECT        0x140	/* 5 */
#define _PTHREAD_MUTEX_POLICY_PRIINHERIT        0x180	/* 6 */
#define PTHREAD_POLICY_FLAGS_MASK	0x1c0

#define _PTHREAD_MTX_OPT_HOLDLOCK 	0x200
#define _PTHREAD_MTX_OPT_NOHOLDLOCK 	0x400
#define _PTHREAD_MTX_OPT_LASTDROP (_PTHREAD_MTX_OPT_HOLDLOCK | _PTHREAD_MTX_OPT_NOHOLDLOCK)

#define KSYN_WQ_INLIST	1
#define KSYN_WQ_INHASH	2
#define KSYN_WQ_SHARED	4
#define KSYN_WQ_FLIST 	0X10	/* in free list to be freed after a short delay */

#define KSYN_CLEANUP_DEADLINE 10
int psynch_cleanupset;
thread_call_t psynch_thcall;

#define KSYN_WQTYPE_INWAIT	0x1000
#define KSYN_WQTYPE_MTX		0x1
#define KSYN_WQTYPE_CVAR	0x2
#define KSYN_WQTYPE_RWLOCK	0x4
#define KSYN_WQTYPE_SEMA	0x8
#define KSYN_WQTYPE_BARR	0x10
#define KSYN_WQTYPE_MASK        0xffff

#define KSYN_MTX_MAX 0x0fffffff

#define KW_UNLOCK_PREPOST 		0x01
#define KW_UNLOCK_PREPOST_UPGRADE 	0x02
#define KW_UNLOCK_PREPOST_DOWNGRADE 	0x04
#define KW_UNLOCK_PREPOST_READLOCK 	0x08
#define KW_UNLOCK_PREPOST_LREADLOCK 	0x10
#define KW_UNLOCK_PREPOST_WRLOCK 	0x20
#define KW_UNLOCK_PREPOST_YWRLOCK 	0x40

#define CLEAR_PREPOST_BITS(kwq)  {\
			kwq->kw_pre_lockseq = 0; \
			kwq->kw_pre_rwwc = 0; \
			kwq->kw_pre_cvretval = 0; \
			}

#define CLEAR_READ_PREPOST_BITS(kwq)  {\
			kwq->kw_pre_limrd = 0; \
			kwq->kw_pre_limrdseq = 0; \
			kwq->kw_pre_limrdbits = 0; \
			}

#define CLEAR_INTR_PREPOST_BITS(kwq)  {\
			kwq->kw_pre_intrcount = 0; \
			kwq->kw_pre_intrseq = 0; \
			kwq->kw_pre_intrretbits = 0; \
			kwq->kw_pre_intrtype = 0; \
			}
	
void pthread_list_lock(void);
void pthread_list_unlock(void);
void pthread_list_lock_spin(void);
void pthread_list_lock_convert_spin(void);
void ksyn_wqlock(ksyn_wait_queue_t kwq);
void ksyn_wqunlock(ksyn_wait_queue_t kwq);
ksyn_wait_queue_t ksyn_wq_hash_lookup(user_addr_t mutex, proc_t p, int flags, uint64_t object, uint64_t offset);
int ksyn_wqfind(user_addr_t mutex, uint32_t mgen, uint32_t ugen, uint32_t rw_wc, uint64_t tid, int flags, int wqtype , ksyn_wait_queue_t * wq);
void ksyn_wqrelease(ksyn_wait_queue_t mkwq, ksyn_wait_queue_t ckwq);
int ksyn_block_thread_locked(ksyn_wait_queue_t kwq, uint64_t abstime, uthread_t uth);
kern_return_t ksyn_wakeup_thread(ksyn_wait_queue_t kwq, uthread_t uth);
void ksyn_move_wqthread(ksyn_wait_queue_t ckwq, ksyn_wait_queue_t kwq, uint32_t mgen, uint32_t updateval, int diffgen, int nomutex);
extern thread_t port_name_to_thread(mach_port_name_t port_name);
extern int ksyn_findobj(uint64_t mutex, uint64_t * object, uint64_t * offset);
static void UPDATE_KWQ(ksyn_wait_queue_t kwq, uint32_t mgen, uint32_t ugen, uint32_t rw_wc, uint64_t tid, int wqtype, int retry);
void psynch_mutexdrop_internal(ksyn_wait_queue_t kwq, uint32_t lkseq, uint32_t ugen, int flags);

#if USE_WAITQUEUE
kern_return_t wait_queue_move_all(wait_queue_t from, event64_t eventfrom, wait_queue_t to, event64_t eventto);
kern_return_t wait_queue_move_thread(wait_queue_t from, event64_t eventfrom, thread_t th, wait_queue_t to, event64_t eventto, thread_t * mthp);
#endif /* USE_WAITQUEUE */
int kwq_handle_unlock(ksyn_wait_queue_t, uint32_t mgen, uint32_t * updatep, int flags, int *blockp, uint32_t premgen);
void ksyn_queue_init(ksyn_queue_t kq);
int ksyn_queue_insert(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t mgen, struct uthread * uth, int firstfit);
struct uthread * ksyn_queue_removefirst(ksyn_queue_t kq, ksyn_wait_queue_t kwq);
void ksyn_queue_removeitem(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uthread_t uth);
void update_low_high(ksyn_wait_queue_t kwq, uint32_t lockseq);
uint32_t find_nextlowseq(ksyn_wait_queue_t kwq);
uint32_t find_nexthighseq(ksyn_wait_queue_t kwq);
int find_seq_till(ksyn_wait_queue_t kwq, uint32_t upto, uint32_t  nwaiters, uint32_t *countp);
int find_diff(uint32_t upto, uint32_t lowest);
uint32_t ksyn_queue_count_tolowest(ksyn_queue_t kq, uint32_t upto);
int ksyn_wakeupreaders(ksyn_wait_queue_t kwq, uint32_t limitread, int longreadset, int allreaders, uint32_t updatebits, int * wokenp);
int kwq_find_rw_lowest(ksyn_wait_queue_t kwq, int flags, uint32_t premgen, int * type, uint32_t lowest[]);
uthread_t ksyn_queue_find_seq(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t seq);
int kwq_handle_downgrade(ksyn_wait_queue_t kwq, uint32_t mgen, int flags, uint32_t premgen, int * blockp);


static void
UPDATE_KWQ(__unused ksyn_wait_queue_t kwq, __unused uint32_t mgen, __unused uint32_t ugen, __unused uint32_t rw_wc, __unused uint64_t tid, __unused int wqtype, __unused int retry)  
{
}

/* to protect the hashes, iocounts, freelist */
void
pthread_list_lock(void)
{
	lck_mtx_lock(pthread_list_mlock);
}

void
pthread_list_lock_spin(void)
{
	lck_mtx_lock_spin(pthread_list_mlock);
}

void
pthread_list_lock_convert_spin(void)
{
	lck_mtx_convert_spin(pthread_list_mlock);
}


void
pthread_list_unlock(void)
{
	lck_mtx_unlock(pthread_list_mlock);
}

/* to protect the indiv queue */
void
ksyn_wqlock(ksyn_wait_queue_t kwq)
{

	lck_mtx_lock(&kwq->kw_lock);
}

void
ksyn_wqunlock(ksyn_wait_queue_t kwq)
{
	lck_mtx_unlock(&kwq->kw_lock);
}


/* routine to drop the mutex unlocks , used both for mutexunlock system call and drop during cond wait */
void
psynch_mutexdrop_internal(ksyn_wait_queue_t kwq, uint32_t lkseq, uint32_t ugen, int flags)
{
	uint32_t nextgen, low_writer, updatebits;
	int firstfit = flags & _PTHREAD_MUTEX_POLICY_FIRSTFIT;
	uthread_t uth;
	kern_return_t kret = KERN_SUCCESS;

	
	nextgen = (ugen + PTHRW_INC);

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_START, kwq, lkseq, ugen, flags, 0);
#endif /* _PSYNCH_TRACE_ */

	ksyn_wqlock(kwq);

redrive:

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 1, kwq->kw_inqueue, nextgen, 0);
#endif /* _PSYNCH_TRACE_ */
	if (kwq->kw_inqueue != 0) {
		updatebits = (kwq->kw_highseq & PTHRW_COUNT_MASK) | PTHRW_EBIT;
		kwq->kw_lastunlockseq = ugen;
		if (firstfit != 0) 
		{
#if __TESTPANICS__
		panic("psynch_mutexdrop_internal: first fit mutex arrives, not enabled yet \n");
#endif /* __TESTPANICS__ */
			/* first fit , pick any one */
			uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwq);

			if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0)
				updatebits |= PTHRW_WBIT;
#if _PSYNCH_TRACE_
			KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 2, uth, updatebits, 0);
#endif /* _PSYNCH_TRACE_ */
				
			uth->uu_psynchretval = updatebits;
			uth->uu_kwqqueue = NULL;

			kret = ksyn_wakeup_thread(kwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("psynch_mutexdrop_internal: panic unable to wakeup firstfit mutex thread\n");
			if (kret == KERN_NOT_WAITING)
				goto redrive;
		} else {
			/* handle fairshare */	
			low_writer = kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_firstnum;
			low_writer &= PTHRW_COUNT_MASK;

			if (low_writer == nextgen) {
#if _PSYNCH_TRACE_
				KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 3, low_writer, nextgen, 0);
#endif /* _PSYNCH_TRACE_ */
				/* next seq to be granted found */
				uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwq);
				if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0)
					updatebits |= PTHRW_WBIT;
				
				uth->uu_psynchretval = updatebits;
				uth->uu_kwqqueue = NULL;

				kret = ksyn_wakeup_thread(kwq, uth);
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("psynch_mutexdrop_internal: panic unable to wakeup fairshare mutex thread\n");
				if (kret == KERN_NOT_WAITING)
					goto redrive;

			} else if (is_seqhigher(low_writer, nextgen) != 0) {
#if _PSYNCH_TRACE_
				KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 4, low_writer, nextgen, 0);
#endif /* _PSYNCH_TRACE_ */
				kwq->kw_pre_rwwc++;
				kwq->kw_pre_lockseq = (nextgen & PTHRW_COUNT_MASK); 
			} else {
#if __TESTPANICS__
			panic("psynch_mutexdrop_internal: FS mutex unlock sequence higher than the lowest one is queue\n");
#endif /* __TESTPANICS__ */
#if _PSYNCH_TRACE_
				KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 5, low_writer, nextgen, 0);
#endif /* _PSYNCH_TRACE_ */
				uth = ksyn_queue_find_seq(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], nextgen);
				if (uth != NULL) {
					/* next seq to be granted found */

					if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0)
						updatebits |= PTHRW_WBIT;
				
#if _PSYNCH_TRACE_
					KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 6, updatebits, 0, 0);
#endif /* _PSYNCH_TRACE_ */
					uth->uu_psynchretval = updatebits;
					uth->uu_kwqqueue = NULL;

					kret = ksyn_wakeup_thread(kwq, uth);
					if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
						panic("psynch_mutexdrop_internal: panic unable to wakeup fairshare mutex thread\n");
					if (kret == KERN_NOT_WAITING)
						goto redrive;
				} else {
					/* next seq to be granted not found, prepost */
#if _PSYNCH_TRACE_
					KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 7, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
					kwq->kw_pre_rwwc++;
					kwq->kw_pre_lockseq = (nextgen & PTHRW_COUNT_MASK); 
				}
			}
		} 
	} else {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 8, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		/* if firstfit the last one could be spurious */
		if ((firstfit == 0) || ((lkseq & PTHRW_COUNT_MASK) != nextgen))       {
#if _PSYNCH_TRACE_
			KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, kwq, 9, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			kwq->kw_lastunlockseq = ugen;
			kwq->kw_pre_rwwc++;
			kwq->kw_pre_lockseq = (nextgen & PTHRW_COUNT_MASK); 
		}
	}

	ksyn_wqunlock(kwq);

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_KMDROP | DBG_FUNC_END, kwq, 0, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(kwq, NULL);
	return;
}

/*
 *  psynch_mutexwait: This system call is used for contended psynch mutexes to block.
 */

int
psynch_mutexwait(__unused proc_t p, struct psynch_mutexwait_args * uap, uint32_t * retval)
{
	user_addr_t mutex  = uap->mutex;
	uint32_t mgen = uap->mgen;
	uint32_t ugen = uap->ugen;
	uint64_t tid = uap->tid;
	int flags = uap->flags;
	ksyn_wait_queue_t kwq;
	int error=0;
	int ins_flags;
	uthread_t uth;
	int firstfit = flags & _PTHREAD_MUTEX_POLICY_FIRSTFIT;
	uint32_t lockseq, updatebits;
	

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_START, (uint32_t)mutex, mgen, ugen, flags, 0);
#endif /* _PSYNCH_TRACE_ */

	uth = current_uthread();

	uth->uu_lockseq = uap->mgen;
	lockseq = (uap->mgen & PTHRW_COUNT_MASK);

	if (firstfit  == 0) {
		ins_flags = SEQFIT;
	} else  {
		/* first fit */
		ins_flags = FIRSTFIT;
	}

	error = ksyn_wqfind(mutex, mgen, ugen, 0, tid, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_MTX), &kwq);
	if (error != 0) {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_END, (uint32_t)mutex, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}

	ksyn_wqlock(kwq);

	
	if ((kwq->kw_pre_rwwc != 0) && ((ins_flags == FIRSTFIT) || (lockseq == kwq->kw_pre_lockseq ))) {
		/* got preposted lock */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			CLEAR_PREPOST_BITS(kwq);
			kwq->kw_lastunlockseq = 0;
		} else {
			panic("psynch_mutexwait: more than one prepost %d\n", (kwq->kw_pre_rwwc + 1));
			kwq->kw_pre_lockseq += PTHRW_INC; /* look for next one */
		}
		if (kwq->kw_inqueue == 0) {
			updatebits = lockseq | PTHRW_EBIT;
		} else {
			updatebits = (kwq->kw_highseq & PTHRW_COUNT_MASK) | (PTHRW_EBIT | PTHRW_WBIT);
		}
		
		uth->uu_psynchretval = updatebits;
#if __TESTPANICS__
		if ((updatebits & PTHRW_COUNT_MASK) == 0)
			panic("psynch_mutexwait: (prepost)returning 0 lseq  in mutexwait with EBIT \n");
#endif /* __TESTPANICS__ */
		ksyn_wqunlock(kwq);
		*retval = updatebits;
		goto out;	
	}
	
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], mgen, uth, ins_flags);
	if (error != 0)
		panic("psynch_mutexwait: failed to enqueue\n");
	
	error = ksyn_block_thread_locked(kwq, (uint64_t)0, uth);
		/* drops the wq lock */

	if (error != 0) {
		ksyn_wqlock(kwq);
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_NONE, (uint32_t)mutex, 2, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		if (uth->uu_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], uth);
		ksyn_wqunlock(kwq);
	} else {
		updatebits = uth->uu_psynchretval;
		*retval = updatebits;
#if __TESTPANICS__
		if ((updatebits & PTHRW_COUNT_MASK) == 0)
			panic("psynch_mutexwait: returning 0 lseq  in mutexwait with EBIT \n");
#endif /* __TESTPANICS__ */
	}
out:
	ksyn_wqrelease(kwq, NULL); 
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_END, (uint32_t)mutex, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */

	return(error);
}

/*
 *  psynch_mutexdrop: This system call is used for unlock postings on contended psynch mutexes.
  */
int
psynch_mutexdrop(__unused proc_t p, struct psynch_mutexdrop_args * uap, __unused uint32_t * retval)
{
	user_addr_t mutex  = uap->mutex;
	uint32_t mgen = uap->mgen;
	uint32_t lkseq = mgen &  PTHRW_COUNT_MASK;
	uint32_t ugen = uap->ugen;
	uint64_t tid = uap->tid;
	int flags = uap->flags;
	ksyn_wait_queue_t kwq;
	int error=0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLDROP | DBG_FUNC_START, (uint32_t)mutex, mgen, ugen, flags, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_wqfind(mutex, mgen, ugen, 0, tid, flags, KSYN_WQTYPE_MTX, &kwq);
	if (error != 0) {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLDROP | DBG_FUNC_END, (uint32_t)mutex, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	psynch_mutexdrop_internal(kwq, lkseq, ugen, flags);
	/* drops the kwq reference */
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_MLDROP | DBG_FUNC_END, (uint32_t)mutex, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(0);

}

/*
 *  psynch_cvbroad: This system call is used for broadcast posting on blocked waiters of psynch cvars.
 */
int
psynch_cvbroad(__unused proc_t p, struct psynch_cvbroad_args * uap, int * retval)
{
	user_addr_t cond  = uap->cv;
	uint32_t cgen = uap->cvgen;
	uint32_t diffgen = uap->diffgen;
	uint32_t mgen = uap->mgen;
	int flags = uap->flags;
	ksyn_wait_queue_t kwq, ckwq;
	int error=0;
#if COND_MTX_WAITQUEUEMOVE
	int mutexowned = flags & _PTHREAD_MTX_OPT_HOLDLOCK;
	int nomutex = flags & _PTHREAD_MTX_OPT_NOHOLDLOCK;
	user_addr_t mutex = uap->mutex;
	uint32_t ugen = uap->ugen;
	uint64_t tid = uap->tid;
	uthread_t uth;
	kern_return_t kret = KERN_SUCCESS;
#else /* COND_MTX_WAITQUEUEMOVE */
	int nomutex =  _PTHREAD_MTX_OPT_NOHOLDLOCK;
#endif /* COND_MTX_WAITQUEUEMOVE */
	uint32_t nextgen, ngen;
	int updatebits = 0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_START, (uint32_t)cond, (uint32_t) 0, cgen, mgen, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_wqfind(cond, cgen, cgen, 0, 0, flags, KSYN_WQTYPE_CVAR, &ckwq);
	if (error != 0) {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_END, (uint32_t)cond, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}

#if COND_MTX_WAITQUEUEMOVE
	ngen = mgen + (PTHRW_INC * diffgen);
	if (nomutex ==0) {
		error = ksyn_wqfind(mutex, ngen, ugen, 0, tid, flags, KSYN_WQTYPE_MTX, &kwq);
		if (error != 0)  {
			kwq = NULL;
			goto out;
		}
	}
#else /* COND_MTX_WAITQUEUEMOVE */
	nomutex = _PTHREAD_MTX_OPT_NOHOLDLOCK;
	kwq= NULL;
	ngen = 0;
#endif /* COND_MTX_WAITQUEUEMOVE */


	ksyn_wqlock(ckwq);
#if COND_MTX_WAITQUEUEMOVE
redrive:
#endif /* COND_MTX_WAITQUEUEMOVE */
	if (diffgen > ckwq->kw_inqueue) {
		ckwq->kw_pre_rwwc = diffgen - ckwq->kw_inqueue;
		ckwq->kw_pre_lockseq = cgen & PTHRW_BIT_MASK;
		updatebits = ckwq->kw_pre_rwwc;	/* unused mutex refs */
		nextgen = (mgen + (ckwq->kw_pre_rwwc * PTHRW_INC));
	} else {
		updatebits = 0;
		nextgen = mgen + PTHRW_INC;
	}
	
	if (ckwq->kw_inqueue != 0) {
#if COND_MTX_WAITQUEUEMOVE
		if (mutexowned != 0) {
#if _PSYNCH_TRACE_
			KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_NONE, (uint32_t)cond, 0, 1, ckwq->kw_inqueue, 0);
#endif /* _PSYNCH_TRACE_ */
			uth = ksyn_queue_removefirst(&ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER],ckwq);
			uth->uu_psynchretval = ngen;
			uth->uu_kwqqueue = NULL;

			kret = ksyn_wakeup_thread(ckwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("cvbraoad: failed to remove\n");
			if (kret == KERN_NOT_WAITING) {
				/*
				 * trying to wake one thread to return, so if
				 * failed to wakeup get the next one.. 
				 */
				goto redrive;
			}
			nextgen = nextgen + PTHRW_INC;
			diffgen -= 1;
		}
#else /* COND_MTX_WAITQUEUEMOVE */
		updatebits = 0;
#endif /* COND_MTX_WAITQUEUEMOVE */
		
		/* nomutex case or in mutexowned case after the first one */
		/* move them all to the mutex waitqueue */
		if ((ckwq->kw_inqueue != 0) && (diffgen > 0)) {
			/* atleast one more posting needed and there are waiting threads */
			/* drops the ckwq lock */
#if _PSYNCH_TRACE_
			KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_NONE, (uint32_t)cond, 0, 2, diffgen, 0);
#endif /* _PSYNCH_TRACE_ */
			/* move threads from ckwq to kwq if COND_MTX_WAITQUEUEMOVE, else wakeup */
			ksyn_move_wqthread(ckwq, kwq, nextgen, ngen, diffgen, nomutex);
		} else
			ksyn_wqunlock(ckwq);
	}  else {
		/* no need for prepost as it is covered before */
		ksyn_wqunlock(ckwq);
	}

	if (error == 0) {
		*retval = updatebits;
	}

#if COND_MTX_WAITQUEUEMOVE
out:
#endif /* COND_MTX_WAITQUEUEMOVE */
	ksyn_wqrelease(ckwq, kwq);
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_END, (uint32_t)cond, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	
	return(error);
}

/*
 *  psynch_cvsignal: This system call is used for signalling the  blocked waiters of  psynch cvars.
 */
int
psynch_cvsignal(__unused proc_t p, struct psynch_cvsignal_args * uap, int * retval)
{
	user_addr_t cond  = uap->cv;
	uint32_t cgen = uap->cvgen;
	uint32_t cugen = uap->cvugen;
	uint32_t mgen = uap->mgen;
	int threadport = uap->thread_port;
	int flags = uap->flags;
	ksyn_wait_queue_t kwq, ckwq;
	int error=0, kret;
	uthread_t uth;
#if USE_WAITQUEUE
	thread_t th = THREAD_NULL, mth;
#else /* USE_WAITQUEUE */
	thread_t th = THREAD_NULL;
#endif /* USE_WAITQUEUE */
#if COND_MTX_WAITQUEUEMOVE
	user_addr_t mutex = uap->mutex;
	uint32_t ugen = uap->ugen;
	int mutexowned = flags & _PTHREAD_MTX_OPT_HOLDLOCK;
	int nomutex = flags & _PTHREAD_MTX_OPT_NOHOLDLOCK;
#else /* COND_MTX_WAITQUEUEMOVE */
	int nomutex =  _PTHREAD_MTX_OPT_NOHOLDLOCK;
#endif /* COND_MTX_WAITQUEUEMOVE */
	uint32_t retbits, ngen, lockseq;


	if (nomutex != 0)
		retbits = 0;
	else
		retbits = 1;	
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_START, (uint32_t)cond, (uint32_t) 0, cgen, mgen, 0);
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)cond, (uint32_t)cugen , flags, mgen, 0);
#endif /* _PSYNCH_TRACE_ */

	error = ksyn_wqfind(cond, cgen, cugen, 0, 0, flags, KSYN_WQTYPE_CVAR, &ckwq);
	if (error != 0)  {
		*retval = retbits;	
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_END, (uint32_t)cond, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	
	if ((flags & _PTHREAD_MTX_OPT_LASTDROP) == _PTHREAD_MTX_OPT_LASTDROP) {

		ksyn_wqlock(ckwq);
		lockseq = cgen & PTHRW_COUNT_MASK;
		/* do  we need to check for lockseq as this is from last waiter, may be race ? */
		if ((ckwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, ckwq->kw_pre_lockseq) != 0)) {
			ckwq->kw_pre_rwwc--;
			if (ckwq->kw_pre_rwwc == 0)
				CLEAR_PREPOST_BITS(ckwq);
		}
		ksyn_wqunlock(ckwq);
		/* no mutex or thread is associated with this, just notificaion */
		th = THREAD_NULL;
		error = 0;
		goto out;
	}

	ngen = mgen + PTHRW_INC;

#if COND_MTX_WAITQUEUEMOVE
	if (nomutex == 0) {
		/* mutex was not operated on, ignore it */
		error = ksyn_wqfind(mutex, ngen, ugen, 0, 0, flags, KSYN_WQTYPE_MTX, &kwq); 
		if (error != 0)  {
			*retval = retbits;	
			kwq = NULL;
			goto out;
		}
	} else {
#endif /* COND_MTX_WAITQUEUEMOVE */
		kwq = NULL;
#if COND_MTX_WAITQUEUEMOVE
	}
#endif /* COND_MTX_WAITQUEUEMOVE */

	
	if (threadport != 0) {
		th = (thread_t)port_name_to_thread((mach_port_name_t)threadport);
		if (th == THREAD_NULL) {
			*retval = retbits;	
			error = ESRCH;
			goto out;
		}
	}

	ksyn_wqlock(ckwq);
redrive:
	if (ckwq->kw_inqueue != 0) {
		*retval = 0;	
#if COND_MTX_WAITQUEUEMOVE
		if ((mutexowned != 0) || (nomutex != 0)) {
#if _PSYNCH_TRACE_
			KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)cond, 0, 1, ckwq->kw_inqueue, 0);
#endif /* _PSYNCH_TRACE_ */
			if (th != THREAD_NULL) {
				uth = get_bsdthread_info(th);
				if (nomutex != 0) 
					ngen |= PTHRW_MTX_NONE;
				uth->uu_psynchretval = ngen;
				uth->uu_kwqqueue = NULL;
				ksyn_queue_removeitem(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], uth);
				kret = ksyn_wakeup_thread(ckwq, uth);
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("psynch_cvsignal: panic waking in cvsignal\n");
				if (kret == KERN_NOT_WAITING) {
					if (threadport != 0) {
						error = 0;
					} else
						goto redrive;
				}
			} else {
				uth = ksyn_queue_removefirst(&ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER],ckwq);
				if (nomutex != 0) 
					ngen |= PTHRW_MTX_NONE;
				uth->uu_psynchretval = ngen;
				uth->uu_kwqqueue = NULL;
				kret = ksyn_wakeup_thread(ckwq, uth);
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("psynch_cvsignal: panic waking in cvsignal\n");
				if (kret == KERN_NOT_WAITING) {
					if (threadport != 0) {
						error = 0;
					} else
						goto redrive;
				}
			}
			ksyn_wqunlock(ckwq);
		} else {
#endif /* COND_MTX_WAITQUEUEMOVE */
			/* need to move a thread to another queue */
#if _PSYNCH_TRACE_
			KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)cond, 0, 2, ckwq->kw_inqueue, 0);
#endif /* _PSYNCH_TRACE_ */
			if (th != THREAD_NULL) {
				uth = get_bsdthread_info(th);
				/* if given thread not blocked in cvwait , return error */
				if (uth->uu_kwqqueue != ckwq) {
					error = EINVAL;
					ksyn_wqunlock(ckwq);
					goto out;
				}
				ksyn_queue_removeitem(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], uth);
			} else {
				uth = ksyn_queue_removefirst(&ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER],ckwq);
				if (uth == NULL)
					panic("cvsign: null uthread after rem");
			}
#if COND_MTX_WAITQUEUEMOVE
			ksyn_wqunlock(ckwq);
#else /* COND_MTX_WAITQUEUEMOVE */
			uth->uu_psynchretval = 0;
			uth->uu_kwqqueue = NULL;
			kret = ksyn_wakeup_thread(ckwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("psynch_cvsignal: panic waking in cvsignal\n");
			if (kret == KERN_NOT_WAITING) {
				error = 0;
				if (threadport == 0) 
					goto redrive;
			}
			
			ksyn_wqunlock(ckwq);
			error = 0;
#endif /* COND_MTX_WAITQUEUEMOVE */
			
#if COND_MTX_WAITQUEUEMOVE
			ksyn_wqlock(kwq);
			ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], ngen, uth, SEQFIT);
#if USE_WAITQUEUE
                        kret = wait_queue_move_thread(&ckwq->kw_wq, ckwq->kw_addr, th, &kwq->kw_wq, kwq->kw_addr, &mth);
                        if (kret == KERN_SUCCESS) {
                                if (mth != THREAD_NULL) {
                                        uth = (struct uthread *)get_bsdthread_info(mth);
                                        uth->uu_lockseq = ngen;
                                        TAILQ_INSERT_TAIL(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_uthlist, uth, uu_mtxlist);
                                }
                        }
#else /* USE_WAITQUEUE */
			/* no need to move anything, just update the sequence */
			uth->uu_lockseq = ngen;

#endif /* USE_WAITQUEUE */
			ksyn_wqunlock(kwq);
		}
#endif /* COND_MTX_WAITQUEUEMOVE */
	}   else {
		/* prepost */
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)cond, 0, 3, ckwq->kw_inqueue, 0);
#endif /* _PSYNCH_TRACE_ */
		if (threadport != 0) {
			error = EINVAL;
			ksyn_wqunlock(ckwq);
			goto out;
		}
		
		ckwq->kw_pre_rwwc++;
		ckwq->kw_attq = kwq;
		ckwq->kw_pre_lockseq = cgen & PTHRW_BIT_MASK;
		ckwq->kw_pre_cvretval = ngen;
		*retval = retbits;	
		ksyn_wqunlock(ckwq);
	}
	/* ckwq is unlocked here */
		
out:
	ksyn_wqrelease(ckwq, kwq);
	if (th != THREAD_NULL)
		thread_deallocate(th);
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_END, (uint32_t)cond, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	
	return(error);
}

/*
 *  psynch_cvwait: This system call is used for psynch cvar waiters to block in kernel.
 */
int
psynch_cvwait(__unused proc_t p, struct psynch_cvwait_args * uap, uint32_t * retval)
{
	user_addr_t cond  = uap->cv;
	uint32_t cgen = uap->cvgen;
	uint32_t cugen = uap->cvugen;
	user_addr_t mutex = uap->mutex;
	uint32_t mgen =0, ugen;
	int flags = 0;
	ksyn_wait_queue_t kwq, ckwq;
	int error=0;
	uint64_t abstime = 0;
	uint32_t lockseq, updatebits;
	struct timespec  ts;
	uthread_t uth;

	/* for conformance reasons */
	__pthread_testcancel(0);

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_START, (uint32_t)cond, (uint32_t) mutex, cgen, mgen, 0);
#endif /* _PSYNCH_TRACE_ */
	flags = 0;
	if ((uap->usec & 0xc0000000) != 0) {
		if (uap->usec & 0x40000000)
			flags |= PTHREAD_PROCESS_SHARED;
		if (uap->usec & 0x80000000)
			flags |= _PTHREAD_MUTEX_POLICY_FIRSTFIT;
	}
		
	error = ksyn_wqfind(cond, cgen, cugen, 0, 0, flags, KSYN_WQTYPE_CVAR | KSYN_WQTYPE_INWAIT, &ckwq);
	if (error != 0) {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_END, (uint32_t)cond, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	if (mutex != (user_addr_t)0) {
		mgen = uap->mgen;
		ugen = uap->ugen;

		error = ksyn_wqfind(mutex, mgen, ugen, 0, 0, flags, KSYN_WQTYPE_MTX, &kwq); {
		if (error != 0) 
			goto out;
		}
		
		psynch_mutexdrop_internal(kwq, mgen, ugen, flags);
		/* drops kwq reference */
	}

	uth = current_uthread();
	uth->uu_lockseq = cgen;
	lockseq = (cgen & PTHRW_COUNT_MASK);

	if (uap->sec != 0 || (uap->usec & 0x3fffffff)  != 0) {
		ts.tv_sec = uap->sec;
		ts.tv_nsec = (uap->usec & 0xc0000000);
                nanoseconds_to_absolutetime((uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec,  &abstime );
                clock_absolutetime_interval_to_deadline( abstime, &abstime );
	}
	ksyn_wqlock(ckwq);
	if ((ckwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, ckwq->kw_pre_lockseq) != 0)) {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)cond, 0, 1, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			
#if  COND_MTX_WAITQUEUEMOVE
		updatebits = ckwq->kw_pre_cvretval | PTHRW_MTX_NONE;
#else /* COND_MTX_WAITQUEUEMOVE */
		updatebits = 0;
#endif /* COND_MTX_WAITQUEUEMOVE */
		ckwq->kw_pre_rwwc--;
		if (ckwq->kw_pre_rwwc == 0)
			CLEAR_PREPOST_BITS(ckwq);
		*retval = updatebits;
		error = 0;
		ksyn_wqunlock(ckwq);
		goto out;
		
	} else {
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)cond, 0, 2, cgen, 0);
#endif /* _PSYNCH_TRACE_ */
		error = ksyn_queue_insert(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], cgen, uth, FIRSTFIT);
		if (error != 0)
			panic("psynch_cvwait: failed to enqueue\n");
		error = ksyn_block_thread_locked(ckwq, abstime, uth);
		/* drops the lock */
	}
	
	if (error != 0) {
		ksyn_wqlock(ckwq);
#if _PSYNCH_TRACE_
		KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)cond, 0, 3, error, 0);
#endif /* _PSYNCH_TRACE_ */
		if (uth->uu_kwqqueue != NULL) {
			ksyn_queue_removeitem(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], uth);
		}
		ksyn_wqunlock(ckwq);
	} else  {
		*retval = uth->uu_psynchretval;

	}
out:
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_END, (uint32_t)cond, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(ckwq, NULL);
	return(error);
}

/* ***************** pthread_rwlock ************************ */
/*
 *  psynch_rw_rdlock: This system call is used for psync rwlock readers to block.
 */
int
psynch_rw_rdlock(__unused proc_t p, struct psynch_rw_rdlock_args * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	int error = 0, block;
	uint32_t lockseq = 0, updatebits = 0, preseq = 0;
	ksyn_wait_queue_t kwq;
	uthread_t uth;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	/* preserve the seq number */
	uth->uu_lockseq = lgen;
	lockseq = lgen  & PTHRW_COUNT_MASK;

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		((kwq->kw_pre_intrtype == PTH_RW_TYPE_READ) || (kwq->kw_pre_intrtype == PTH_RW_TYPE_LREAD)) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		uth->uu_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	/* handle unlock2/downgrade first */
	if ((kwq->kw_pre_limrd != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_limrdseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_pre_limrd, kwq->kw_pre_limrdseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_limrd--;
		/* acquired the locks, so return */
		uth->uu_psynchretval = kwq->kw_pre_limrdbits;
		if (kwq->kw_pre_limrd == 0)
			CLEAR_READ_PREPOST_BITS(kwq);
		ksyn_wqunlock(kwq);
		goto out;
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			CLEAR_PREPOST_BITS(kwq);
			error = kwq_handle_unlock(kwq, preseq,  &updatebits, (KW_UNLOCK_PREPOST_READLOCK|KW_UNLOCK_PREPOST), &block, lgen);
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_READ], lgen, uth, SEQFIT);
	if (error != 0)
		panic("psynch_rw_rdlock: failed to enqueue\n");
	error = ksyn_block_thread_locked(kwq, (uint64_t)0, uth);
	/* drops the kwq lock */
	
out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (uth->uu_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_READ], uth);
		ksyn_wqunlock(kwq);
	} else {
		/* update bits */
		*retval = uth->uu_psynchretval;
	}
	ksyn_wqrelease(kwq, NULL); 
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

/*
 *  psynch_rw_longrdlock: This system call is used for psync rwlock long readers to block.
 */
int
psynch_rw_longrdlock(__unused proc_t p, struct psynch_rw_longrdlock_args * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;

	ksyn_wait_queue_t kwq;
	int error=0, block = 0 ;
	uthread_t uth;
	uint32_t lockseq = 0, updatebits = 0, preseq = 0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	uth->uu_lockseq = lgen;
	lockseq = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_LREAD) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		uth->uu_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	/* handle unlock2/downgrade first */
	if ((kwq->kw_pre_limrd != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_limrdseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_pre_limrd, kwq->kw_pre_limrdseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_limrd--;
		if (kwq->kw_pre_limrd == 0)
			CLEAR_READ_PREPOST_BITS(kwq);
		/* not a read proceed */
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			CLEAR_PREPOST_BITS(kwq);
			error = kwq_handle_unlock(kwq, preseq, &updatebits, (KW_UNLOCK_PREPOST_LREADLOCK|KW_UNLOCK_PREPOST), &block, lgen);
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_LREAD], lgen, uth, SEQFIT);
	if (error != 0)
		panic("psynch_rw_longrdlock: failed to enqueue\n");

	error = ksyn_block_thread_locked(kwq, (uint64_t)0, uth);
	/* drops the kwq lock */
out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (uth->uu_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_LREAD], uth);
		ksyn_wqunlock(kwq);
	} else {
		/* update bits */
		*retval = uth->uu_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL); 

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

/*
 *  psynch_rw_wrlock: This system call is used for psync rwlock writers to block.
 */
int
psynch_rw_wrlock(__unused proc_t p, struct psynch_rw_wrlock_args * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	int block;
	ksyn_wait_queue_t kwq;
	int error=0;
	uthread_t uth;
	uint32_t lockseq = 0, updatebits = 0, preseq = 0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	uth->uu_lockseq = lgen;
	lockseq = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_WRITE) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		uth->uu_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	/* handle unlock2/downgrade first */
	if ((kwq->kw_pre_limrd != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_limrdseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_pre_limrd, kwq->kw_pre_limrdseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_limrd--;
		if (kwq->kw_pre_limrd == 0)
			CLEAR_READ_PREPOST_BITS(kwq);
		/* not a read proceed */
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			CLEAR_PREPOST_BITS(kwq);
			error = kwq_handle_unlock(kwq, preseq, &updatebits, (KW_UNLOCK_PREPOST_WRLOCK|KW_UNLOCK_PREPOST), &block, lgen);
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		} 
	}

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], lgen, uth, SEQFIT);
	if (error != 0)
		panic("psynch_rw_wrlock: failed to enqueue\n");

	error = ksyn_block_thread_locked(kwq, (uint64_t)0, uth);
	/* drops the wq lock */

out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (uth->uu_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], uth);
		ksyn_wqunlock(kwq);
	} else  {
		/* update bits */
		*retval = uth->uu_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL); 

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

/*
 *  psynch_rw_yieldwrlock: This system call is used for psync rwlock yielding writers to block.
 */
int
psynch_rw_yieldwrlock(__unused proc_t p, struct  psynch_rw_yieldwrlock_args * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	int block;
	ksyn_wait_queue_t kwq;
	int error=0;
	uthread_t uth;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uint32_t lockseq = 0, updatebits = 0, preseq = 0;

	uth = current_uthread();

	uth->uu_lockseq = lgen;
	lockseq = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_YWRITE) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		uth->uu_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	/* handle unlock2/downgrade first */
	if ((kwq->kw_pre_limrd != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_limrdseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_pre_limrd, kwq->kw_pre_limrdseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_limrd--;
		if (kwq->kw_pre_limrd == 0)
			CLEAR_READ_PREPOST_BITS(kwq);
		/* not a read proceed */
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			CLEAR_PREPOST_BITS(kwq);
			error = kwq_handle_unlock(kwq, preseq,  &updatebits, (KW_UNLOCK_PREPOST_YWRLOCK|KW_UNLOCK_PREPOST), &block, lgen);
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER], lgen, uth, SEQFIT);
	if (error != 0)
		panic("psynch_rw_yieldwrlock: failed to enqueue\n");

	error = ksyn_block_thread_locked(kwq, (uint64_t)0, uth);

out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (uth->uu_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER], uth);
		ksyn_wqunlock(kwq);
	} else  {
		/* update bits */
		*retval = uth->uu_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL); 

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}


/*
 *  psynch_rw_downgrade: This system call is used for wakeup blocked readers who are eligible to run due to downgrade.
 */
int
psynch_rw_downgrade(__unused proc_t p, struct psynch_rw_downgrade_args * uap, __unused int * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	uint32_t count = 0;

	ksyn_wait_queue_t kwq;
	int error=0;
	uthread_t uth;
	uint32_t curgen = 0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	curgen = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);
	
	if (is_seqlower(ugen, kwq->kw_lastunlockseq)!= 0) {
		/* spurious  updatebits?? */
		goto out;
	}
	/* fast path for default case */
	if((rw_wc == kwq->kw_inqueue) && (kwq->kw_highseq == curgen))
		goto dounlock;

	/* have we seen all the waiters? */
	if(rw_wc > kwq->kw_inqueue) {
		goto prepost;
	}
		
	if (is_seqhigher(curgen, kwq->kw_highseq) != 0) {
		goto prepost;
	} else {
		if (find_seq_till(kwq, curgen, rw_wc, &count) == 0) {
			if (count < rw_wc) {
				kwq->kw_pre_limrd = rw_wc - count;
				kwq->kw_pre_limrdseq = lgen;
				kwq->kw_pre_limrdbits = lgen;
				/* found none ? */
				if (count == 0) 
					goto out;
			}
		} 
	}
		
dounlock:		
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = kwq_handle_downgrade(kwq, lgen, 0, 0, NULL);

	if (error != 0)
		panic("psynch_rw_downgrade: failed to wakeup\n");

out:
	ksyn_wqunlock(kwq);
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_END, (uint32_t)rwlock, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(kwq, NULL); 

	return(error);
		
prepost:
	kwq->kw_pre_rwwc = (rw_wc - count);
	kwq->kw_pre_lockseq = lgen;
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
	error = 0;
	goto out;
}


/*
 *  psynch_rw_upgrade: This system call is used by an reader to block waiting for upgrade to be granted.
 */
int
psynch_rw_upgrade(__unused proc_t p, struct psynch_rw_upgrade_args * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	int block;
	ksyn_wait_queue_t kwq;
	int error=0;
	uthread_t uth;
	uint32_t lockseq = 0, updatebits = 0, preseq = 0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	uth->uu_lockseq = lgen;
	lockseq = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);
	
	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_UPGRADE) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		uth->uu_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			CLEAR_PREPOST_BITS(kwq);
			error = kwq_handle_unlock(kwq, preseq, &updatebits, (KW_UNLOCK_PREPOST_UPGRADE|KW_UNLOCK_PREPOST), &block, lgen);
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}
	

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE], lgen, uth, SEQFIT);
	if (error != 0)
		panic("psynch_rw_upgrade: failed to enqueue\n");


	error = ksyn_block_thread_locked(kwq, (uint64_t)0, uth);
	/* drops the lock */
	
out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (uth->uu_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE], uth);
		ksyn_wqunlock(kwq);
	} else {
		/* update bits */
		*retval = uth->uu_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL); 
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

/*
 *  psynch_rw_unlock: This system call is used for unlock state postings. This will grant appropriate
 *			reader/writer variety lock.
 */

int
psynch_rw_unlock(__unused proc_t p, struct psynch_rw_unlock_args  * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	uint32_t curgen;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	uthread_t uth;
	ksyn_wait_queue_t kwq;
	uint32_t updatebits = 0;
	int error=0;
	uint32_t count = 0;
	

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	curgen = lgen & PTHRW_COUNT_MASK;

	ksyn_wqlock(kwq);

	if ((lgen & PTHRW_RW_INIT) != 0) {
		kwq->kw_lastunlockseq = 0;
		lgen &= ~PTHRW_RW_INIT;
	} else if (is_seqlower(ugen, kwq->kw_lastunlockseq) != 0) {
		/* spurious  updatebits  set */
		updatebits = PTHRW_RW_SPURIOUS;
		goto out;
	}


#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_inqueue, curgen, 0);
#endif /* _PSYNCH_TRACE_ */
	if (find_seq_till(kwq, curgen, rw_wc, &count) == 0) {
		if (count < rw_wc)
			goto prepost;
	}


	/* can handle unlock now */
		
	CLEAR_PREPOST_BITS(kwq);
	kwq->kw_lastunlockseq = ugen;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = kwq_handle_unlock(kwq, lgen, &updatebits, 0, NULL, 0);
	if (error != 0)
		panic("psynch_rw_unlock: kwq_handle_unlock failed %d\n",error);
out:
	if (error == 0) {
		/* update bits?? */
		*retval = updatebits;
	}
	ksyn_wqunlock(kwq);

	ksyn_wqrelease(kwq, NULL); 
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_END, (uint32_t)rwlock, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */

	return(error);
		
prepost:
	kwq->kw_pre_rwwc = (rw_wc - count);
	kwq->kw_pre_lockseq = curgen;
	kwq->kw_lastunlockseq = ugen;
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, rw_wc, count, 0);
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
	updatebits = (lgen | PTHRW_RW_SPURIOUS);/* let this not do unlock handling */
	error = 0;
	goto out;
}


/*
 *  psynch_rw_unlock2: This system call is used to wakeup pending readers when  unlock grant frm kernel
 *			  to new reader arrival races
 */
int
psynch_rw_unlock2(__unused proc_t p, struct psynch_rw_unlock2_args  * uap, uint32_t * retval)
{
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	uthread_t uth;
	uint32_t num_lreader, limitread, curgen, updatebits;
	ksyn_wait_queue_t kwq;
	int error=0, longreadset = 0;
	int diff;
	uint32_t count=0;

#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK2 | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK2 | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	curgen = (lgen & PTHRW_COUNT_MASK);	
	diff = find_diff(lgen, ugen);

	limitread = lgen & PTHRW_COUNT_MASK;

	if (find_seq_till(kwq, curgen, diff, &count) == 0) {
		kwq->kw_pre_limrd = diff - count;
		kwq->kw_pre_limrdseq = lgen;
		kwq->kw_pre_limrdbits = lgen;
		/* found none ? */
		if (count == 0) 
			goto out;
	} 

	if (kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_count != 0) {
		num_lreader = kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_firstnum;
		if (is_seqlower_eq(num_lreader, limitread) != 0)
			longreadset = 1;
	}
	
	updatebits = lgen;
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK2 | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	count = ksyn_wakeupreaders(kwq, limitread, longreadset, 0, updatebits, NULL);
	
	if (count != 0) {
		if (kwq->kw_pre_limrd !=  0) {
			kwq->kw_pre_limrd += count;
		} else {
			kwq->kw_pre_limrd = count;
			kwq->kw_pre_limrdseq = lgen;
			kwq->kw_pre_limrdbits = lgen;
		}
	}
	error = 0;

out:
	if (error == 0) {
		/* update bits?? */
		*retval = uth->uu_psynchretval;
	}
	ksyn_wqunlock(kwq);

	ksyn_wqrelease(kwq, NULL); 
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWUNLOCK2 | DBG_FUNC_END, (uint32_t)rwlock, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */

	return(error);
}


/* ************************************************************************** */
void
pth_global_hashinit()
{
	pth_glob_hashtbl = hashinit(PTH_HASHSIZE * 4, M_PROC, &pthhash);
}

void
pth_proc_hashinit(proc_t p)
{
	p->p_pthhash  = hashinit(PTH_HASHSIZE, M_PROC, &pthhash);
	if (p->p_pthhash == NULL)
		panic("pth_proc_hashinit: hash init returned 0\n");
}


ksyn_wait_queue_t 
ksyn_wq_hash_lookup(user_addr_t mutex, proc_t p, int flags, uint64_t object, uint64_t objoffset)
{
	ksyn_wait_queue_t kwq;
	struct pthhashhead * hashptr;

	if ((flags & PTHREAD_PSHARED_FLAGS_MASK) == PTHREAD_PROCESS_SHARED) 
	{
		hashptr = pth_glob_hashtbl;
		kwq = (&hashptr[object & pthhash])->lh_first;
		if (kwq != 0) {
			for (; kwq != NULL; kwq = kwq->kw_hash.le_next) {
				if ((kwq->kw_object == object) &&(kwq->kw_offset == objoffset)) {
					return (kwq);
				}
			}
		}
	} else {
		hashptr = p->p_pthhash;
		kwq = (&hashptr[mutex & pthhash])->lh_first;
		if (kwq != 0)
        		for (; kwq != NULL; kwq = kwq->kw_hash.le_next) {
                		if (kwq->kw_addr == mutex) {
                        		return (kwq);
                		}
			}
        }
	return(NULL);
}

void
pth_proc_hashdelete(proc_t p)
{
	struct pthhashhead * hashptr;
	ksyn_wait_queue_t kwq;
	int hashsize = pthhash + 1;
	int i;

	hashptr = p->p_pthhash;
	if (hashptr == NULL)
		return;

	for(i= 0; i < hashsize; i++) {
		while ((kwq = LIST_FIRST(&hashptr[i])) != NULL) {
			pthread_list_lock();
			if ((kwq->kw_pflags & KSYN_WQ_INHASH) != 0) {
				kwq->kw_pflags &= ~KSYN_WQ_INHASH;
				LIST_REMOVE(kwq, kw_hash);
			}
			if ((kwq->kw_pflags & KSYN_WQ_FLIST) != 0) {
				kwq->kw_pflags &= ~KSYN_WQ_FLIST;
				LIST_REMOVE(kwq, kw_list);
			}
			pthread_list_unlock();
			lck_mtx_destroy(&kwq->kw_lock, pthread_lck_grp);
			kfree(kwq, sizeof(struct ksyn_wait_queue));
		}
	}
	FREE(p->p_pthhash, M_PROC);
	p->p_pthhash = NULL;
}


/* find kernel waitqueue, if not present create one. Grants a reference  */
int
ksyn_wqfind(user_addr_t mutex, uint32_t mgen, uint32_t ugen, uint32_t rw_wc, uint64_t tid, int flags, int wqtype, ksyn_wait_queue_t * kwqp)
{
	ksyn_wait_queue_t kwq;
	ksyn_wait_queue_t nkwq;
	struct pthhashhead * hashptr;
	uint64_t object = 0, offset = 0;
	uint64_t hashhint;
	proc_t p  = current_proc();
	int retry = mgen & PTHRW_RETRYBIT;
	int i;

	if ((flags & PTHREAD_PSHARED_FLAGS_MASK) == PTHREAD_PROCESS_SHARED) 
	{
		(void)ksyn_findobj(mutex, &object, &offset);
		hashhint = object;
		hashptr = pth_glob_hashtbl;
	} else {
		hashptr = p->p_pthhash;
	}

	//pthread_list_lock_spin();
	pthread_list_lock();

	kwq = ksyn_wq_hash_lookup(mutex, p, flags, object, offset);

	if (kwq != NULL) {
		kwq->kw_iocount++;
		if ((kwq->kw_pflags & KSYN_WQ_FLIST) != 0) {
			LIST_REMOVE(kwq, kw_list);
			kwq->kw_pflags &= ~KSYN_WQ_FLIST;
		}
		UPDATE_KWQ(kwq, mgen, ugen, rw_wc, tid, wqtype, retry);
		if (kwqp != NULL)
			*kwqp = kwq;
		pthread_list_unlock();
		return (0);
	}

	pthread_list_unlock();

	nkwq = kalloc(sizeof(struct ksyn_wait_queue));
	bzero(nkwq, sizeof(struct ksyn_wait_queue));
	nkwq->kw_addr = mutex;
	nkwq->kw_flags = flags;
	nkwq->kw_iocount = 1;
	nkwq->kw_object = object;
	nkwq->kw_offset = offset;
	nkwq->kw_type = (wqtype & KSYN_WQTYPE_MASK);
	TAILQ_INIT(&nkwq->kw_uthlist);

	for (i=0; i< KSYN_QUEUE_MAX; i++) 
		ksyn_queue_init(&nkwq->kw_ksynqueues[i]);
		
	UPDATE_KWQ(nkwq, mgen, ugen, rw_wc, tid, wqtype, retry);
#if USE_WAITQUEUE
	wait_queue_init(&nkwq->kw_wq, SYNC_POLICY_FIFO);
#endif /* USE_WAITQUEUE */
	lck_mtx_init(&nkwq->kw_lock, pthread_lck_grp, pthread_lck_attr);

	//pthread_list_lock_spin();
	pthread_list_lock();
	/* see whether it is alread allocated */
	kwq = ksyn_wq_hash_lookup(mutex, p, flags, object, offset);

	if (kwq != NULL) {
		kwq->kw_iocount++;
		if ((kwq->kw_pflags & KSYN_WQ_FLIST) != 0) {
			LIST_REMOVE(kwq, kw_list);
			kwq->kw_pflags &= ~KSYN_WQ_FLIST;
		}
		UPDATE_KWQ(kwq, mgen, ugen, rw_wc, tid, wqtype, retry);
		if (kwqp != NULL)
			*kwqp = kwq;
		pthread_list_unlock();
		lck_mtx_destroy(&nkwq->kw_lock, pthread_lck_grp);
		kfree(nkwq, sizeof(struct ksyn_wait_queue));
		return (0);
	}
	kwq = nkwq;

	if ((flags & PTHREAD_PSHARED_FLAGS_MASK) == PTHREAD_PROCESS_SHARED) 
	{
		kwq->kw_pflags |= KSYN_WQ_SHARED;
		LIST_INSERT_HEAD(&hashptr[kwq->kw_object & pthhash], kwq, kw_hash);
	} else
		LIST_INSERT_HEAD(&hashptr[mutex & pthhash], kwq, kw_hash);

	kwq->kw_pflags |= KSYN_WQ_INHASH;

	pthread_list_unlock();

	if (kwqp != NULL)
		*kwqp = kwq;
        return (0);
}

/* Reference from find is dropped here. Starts the free process if needed  */
void
ksyn_wqrelease(ksyn_wait_queue_t kwq, ksyn_wait_queue_t ckwq)
{
	uint64_t deadline;
	struct timeval t;
	int sched = 0;

	
	//pthread_list_lock_spin();
	pthread_list_lock();
	kwq->kw_iocount--;
	if (kwq->kw_iocount == 0) {
		if ((kwq->kw_pre_rwwc == 0) && (kwq->kw_inqueue == 0)) {
			microuptime(&kwq->kw_ts);
			LIST_INSERT_HEAD(&pth_free_list, kwq, kw_list);
			kwq->kw_pflags |= KSYN_WQ_FLIST;
		}
		sched = 1;
	}
	if (ckwq != NULL){
		ckwq->kw_iocount--;
		if ( ckwq->kw_iocount == 0) {
			if ((ckwq->kw_pre_rwwc == 0) && (ckwq->kw_inqueue == 0)) {
				/* mark for free if we can */
				microuptime(&ckwq->kw_ts);
				LIST_INSERT_HEAD(&pth_free_list, ckwq, kw_list);
				ckwq->kw_pflags |= KSYN_WQ_FLIST;
			}
			sched = 1;
		}
	}

	if (sched == 1 && psynch_cleanupset == 0) {
		psynch_cleanupset = 1;
		microuptime(&t);
		t.tv_sec += KSYN_CLEANUP_DEADLINE;
		
		deadline = tvtoabstime(&t);
		thread_call_enter_delayed(psynch_thcall, deadline);
	}
	pthread_list_unlock();
}

/* responsible to free the waitqueues */
void
psynch_wq_cleanup(__unused void *  param, __unused void * param1)
{
	ksyn_wait_queue_t kwq;
	struct timeval t;
	LIST_HEAD(, ksyn_wait_queue) freelist = {NULL};
	int count = 0, delayed = 0, diff;
	uint64_t deadline = 0;

	//pthread_list_lock_spin();
	pthread_list_lock();

	microuptime(&t);

	LIST_FOREACH(kwq, &pth_free_list, kw_list) {
			
		if (count > 100) {
			delayed = 1;
			break;
		}
		if ((kwq->kw_iocount != 0) && (kwq->kw_inqueue != 0)) {
			/* still in freelist ??? */
			continue;
		}
		diff = t.tv_sec - kwq->kw_ts.tv_sec;
		if (diff < 0) 
			diff *= -1;
		if (diff >= KSYN_CLEANUP_DEADLINE) {
			/* out of hash */
			kwq->kw_pflags &= ~(KSYN_WQ_FLIST | KSYN_WQ_INHASH);
			LIST_REMOVE(kwq, kw_hash);
			LIST_REMOVE(kwq, kw_list);
			LIST_INSERT_HEAD(&freelist, kwq, kw_list);
			count ++;
		} else {
			delayed = 1;
		}

	}
	if (delayed != 0) {
		t.tv_sec += KSYN_CLEANUP_DEADLINE;

		deadline = tvtoabstime(&t);
		thread_call_enter_delayed(psynch_thcall, deadline);
		psynch_cleanupset = 1;
	} else
		psynch_cleanupset = 0;

	pthread_list_unlock();
	
	
	while ((kwq = LIST_FIRST(&freelist)) != NULL) {
		LIST_REMOVE(kwq, kw_list);
		lck_mtx_destroy(&kwq->kw_lock, pthread_lck_grp);
		kfree(kwq, sizeof(struct ksyn_wait_queue));
	}
}


int
ksyn_block_thread_locked(ksyn_wait_queue_t kwq, uint64_t abstime, uthread_t uth)
{
	kern_return_t kret;
	int error = 0;

	uth->uu_kwqqueue = (void *)kwq;
#if USE_WAITQUEUE
	kret  = wait_queue_assert_wait64(&kwq->kw_wq, kwq->kw_addr, THREAD_ABORTSAFE, abstime);
#else /* USE_WAITQUEUE */
	assert_wait_deadline(&uth->uu_psynchretval, THREAD_ABORTSAFE, abstime);
#endif /* USE_WAITQUEUE */
	ksyn_wqunlock(kwq);

	kret = thread_block(NULL);
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
	}
	return(error);
}

kern_return_t
#if USE_WAITQUEUE
ksyn_wakeup_thread(ksyn_wait_queue_t kwq, uthread_t uth)
#else /* USE_WAITQUEUE */
ksyn_wakeup_thread(__unused ksyn_wait_queue_t kwq, uthread_t uth)
#endif /* USE_WAITQUEUE */
{
	thread_t th;
	kern_return_t kret;
	th = uth->uu_context.vc_thread;

#if USE_WAITQUEUE
	kret = wait_queue_wakeup64_thread(&kwq->kw_wq, kwq->kw_addr, th, THREAD_AWAKENED);
#else /* USE_WAITQUEUE */
	kret = thread_wakeup_prim((caddr_t)&uth->uu_psynchretval, TRUE, THREAD_AWAKENED);
#endif /* USE_WAITQUEUE */

	if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
		panic("ksyn_wakeup_thread: panic waking up thread %x\n", kret);
	
	

	return(kret);
}

/* move from one waitqueue to another */
#if COND_MTX_WAITQUEUEMOVE
void 
ksyn_move_wqthread( ksyn_wait_queue_t ckwq, ksyn_wait_queue_t kwq, uint32_t mgen, uint32_t updateval, int diffgen, int nomutex)
#else /* COND_MTX_WAITQUEUEMOVE */
void 
ksyn_move_wqthread( ksyn_wait_queue_t ckwq, __unused ksyn_wait_queue_t kwq, __unused uint32_t mgen, uint32_t updateval, __unused int diffgen, int nomutex)
#endif /* COND_MTX_WAITQUEUEMOVE */
{
	kern_return_t kret;
	uthread_t uth;
#if COND_MTX_WAITQUEUEMOVE
	int count = 0, error, kret;
	uint32_t nextgen = mgen;
#endif /* COND_MTX_WAITQUEUEMOVE */
	struct ksyn_queue  kq;
	uint32_t upgen;
	
	ksyn_queue_init(&kq);
#if USE_WAITQUEUE
	/* TBD wq move */
	kret = wait_queue_move_all(&ckwq->kw_wq, ckwq->kw_addr, &kwq->kw_wq,  kwq->kw_addr);
#else /* USE_WAITQUEUE */
	/* no need to move as the thread is blocked at uthread address */
	kret = KERN_SUCCESS;
#endif /* USE_WAITQUEUE */

	if (nomutex != 0) 
		upgen = updateval | PTHRW_MTX_NONE;
	else
		upgen = updateval;
	
	if (kret== KERN_SUCCESS) {
redrive:
		while ((uth = ksyn_queue_removefirst(&ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], ckwq)) != NULL) {
			if (nomutex != 0) {
#if COND_MTX_WAITQUEUEMOVE
				uth->uu_psynchretval = upgen;
#else /* COND_MTX_WAITQUEUEMOVE */
				uth->uu_psynchretval = 0;
				uth->uu_kwqqueue = NULL;
				kret = ksyn_wakeup_thread(ckwq, uth);
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("ksyn_move_wqthread: panic waking up \n");
				if (kret == KERN_NOT_WAITING)
					goto redrive;
#endif /* COND_MTX_WAITQUEUEMOVE */
			} 
#if COND_MTX_WAITQUEUEMOVE
			  else {
				count++;
				if (count >diffgen)
					panic("movethread inserting more than expected\n");
				TAILQ_INSERT_TAIL(&kq.ksynq_uthlist, uth, uu_mtxlist);
			}
#endif /* COND_MTX_WAITQUEUEMOVE */
			
		}
		ksyn_wqunlock(ckwq);

#if COND_MTX_WAITQUEUEMOVE
		if ( (nomutex == 0) && (count > 0)) {
			ksyn_wqlock(kwq);
			uth = TAILQ_FIRST(&kq.ksynq_uthlist);
			while(uth != NULL) {
				TAILQ_REMOVE(&kq.ksynq_uthlist, uth, uu_mtxlist);
				error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], nextgen,  uth, SEQFIT); 
				if (error != 0) {
					panic("movethread insert failed\n");
				} 
				uth->uu_lockseq = nextgen;
				nextgen += PTHRW_INC;
				uth = TAILQ_FIRST(&kq.ksynq_uthlist);
			}
			ksyn_wqunlock(kwq);
		}
#endif /* COND_MTX_WAITQUEUEMOVE */
	} else
		panic("movethread : wq move all  failed\n");
	return;
}

/* find the true shared obect/offset for shared mutexes */
int 
ksyn_findobj(uint64_t mutex, uint64_t * objectp, uint64_t * offsetp)
{
	vm_page_info_basic_data_t info;
	kern_return_t kret;
	mach_msg_type_number_t count = VM_PAGE_INFO_BASIC_COUNT;

	kret = vm_map_page_info(current_map(), mutex, VM_PAGE_INFO_BASIC, 
			(vm_page_info_t)&info, &count);

	if (kret != KERN_SUCCESS)
		return(EINVAL);

	if (objectp != NULL)
		*objectp = (uint64_t)info.object_id;
	if (offsetp != NULL)
		*offsetp = (uint64_t)info.offset;
	
	return(0);
}


/* lowest of kw_fr, kw_flr, kw_fwr, kw_fywr */
int
kwq_find_rw_lowest(ksyn_wait_queue_t kwq, int flags, uint32_t premgen, int * typep, uint32_t lowest[])
{

	uint32_t kw_fr, kw_flr, kw_fwr, kw_fywr, low;
	int type = 0, lowtype, typenum[4];
	uint32_t numbers[4];
        int count = 0, i;


	if ((kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_READLOCK) != 0)) {
		type |= PTH_RWSHFT_TYPE_READ;
		/* read entries are present */
		if (kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_count != 0) {
			kw_fr = kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_firstnum;
			if (((flags & KW_UNLOCK_PREPOST_READLOCK) != 0) && (is_seqlower(premgen, kw_fr) != 0))
				kw_fr = premgen;
		} else
			kw_fr = premgen;

		lowest[KSYN_QUEUE_READ] = kw_fr;
		numbers[count]= kw_fr;
		typenum[count] = PTH_RW_TYPE_READ;
		count++;
	} else
		lowest[KSYN_QUEUE_READ] = 0;

	if ((kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_LREADLOCK) != 0)) {
		type |= PTH_RWSHFT_TYPE_LREAD;
		/* read entries are present */
		if (kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_count != 0) {
			kw_flr = kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_firstnum;
			if (((flags & KW_UNLOCK_PREPOST_LREADLOCK) != 0) && (is_seqlower(premgen, kw_flr) != 0))
				kw_flr = premgen;
		} else
			kw_flr = premgen;

		lowest[KSYN_QUEUE_LREAD] = kw_flr;
		numbers[count]= kw_flr;
		typenum[count] =  PTH_RW_TYPE_LREAD;
		count++;
	} else
		lowest[KSYN_QUEUE_LREAD] = 0;


	if ((kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_WRLOCK) != 0)) {
		type |= PTH_RWSHFT_TYPE_WRITE;
		/* read entries are present */
		if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0) {
			kw_fwr = kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_firstnum;
			if (((flags & KW_UNLOCK_PREPOST_WRLOCK) != 0) && (is_seqlower(premgen, kw_fwr) != 0))
				kw_fwr = premgen;
		} else
			kw_fwr = premgen;

		lowest[KSYN_QUEUE_WRITER] = kw_fwr;
		numbers[count]= kw_fwr;
		typenum[count] =  PTH_RW_TYPE_WRITE;
		count++;
	} else
		lowest[KSYN_QUEUE_WRITER] = 0;

	if ((kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_YWRLOCK) != 0)) {
		type |= PTH_RWSHFT_TYPE_YWRITE;
		/* read entries are present */
		if (kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0) {
			kw_fywr = kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_firstnum;
			if (((flags & KW_UNLOCK_PREPOST_YWRLOCK) != 0) && (is_seqlower(premgen, kw_fywr) != 0))
				kw_fywr = premgen;
		} else
			kw_fywr = premgen;

		lowest[KSYN_QUEUE_YWRITER] = kw_fywr;
		numbers[count]= kw_fywr;
		typenum[count] =  PTH_RW_TYPE_YWRITE;
		count++;
	} else
		lowest[KSYN_QUEUE_YWRITER] = 0;


	
	if (count == 0)
		panic("nothing in the queue???\n");

        low = numbers[0];
	lowtype = typenum[0];
        if (count > 1) {
                for (i = 1; i< count; i++) {
                        if(is_seqlower(numbers[i] , low) != 0) {
                                low = numbers[i];
				lowtype = typenum[i];
			}
                }
        }
	type |= lowtype;

	if (typep != 0)
		*typep = type;
	return(0);
}

/* wakeup readers and longreaders to upto the  writer limits */
int
ksyn_wakeupreaders(ksyn_wait_queue_t kwq, uint32_t limitread, int longreadset, int allreaders, uint32_t  updatebits, int * wokenp)
{
	uthread_t uth;
	ksyn_queue_t kq;
	int failedwakeup = 0;
	int numwoken = 0;
	kern_return_t kret = KERN_SUCCESS;
	int resetbit = updatebits & PTHRW_RW_HUNLOCK;
	uint32_t lbits = 0;

	lbits = updatebits;
	if (longreadset != 0) {
		/* clear all read and longreads */
		while ((uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_READ], kwq)) != NULL) {
			uth->uu_psynchretval = lbits;
			/* set on one thread */
			if (resetbit != 0) {
				lbits &= ~PTHRW_RW_HUNLOCK;
				resetbit = 0;
			}
			numwoken++;
			uth->uu_kwqqueue = NULL;
			kret = ksyn_wakeup_thread(kwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up readers\n");
			if (kret == KERN_NOT_WAITING) {
				failedwakeup++;
			}
		}
		while ((uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_LREAD], kwq)) != NULL) {
			uth->uu_psynchretval = lbits;
			uth->uu_kwqqueue = NULL;
			if (resetbit != 0) {
				lbits &= ~PTHRW_RW_HUNLOCK;
				resetbit = 0;
			}
			numwoken++;
			kret = ksyn_wakeup_thread(kwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up lreaders\n");
			if (kret == KERN_NOT_WAITING) {
				failedwakeup++;
			}
		}
	} else {
		kq = &kwq->kw_ksynqueues[KSYN_QUEUE_READ];
		while ((kq->ksynq_count != 0) && (allreaders || (is_seqlower(kq->ksynq_firstnum, limitread) != 0))) {
			uth = ksyn_queue_removefirst(kq, kwq);
			uth->uu_psynchretval = lbits;
			if (resetbit != 0) {
				lbits &= ~PTHRW_RW_HUNLOCK;
				resetbit = 0;
			}
			numwoken++;
			uth->uu_kwqqueue = NULL;
			kret = ksyn_wakeup_thread(kwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up readers\n");
			if (kret == KERN_NOT_WAITING) {
				failedwakeup++;
			}
		}
	}
	
	if (wokenp != NULL)
		*wokenp = numwoken;
	return(failedwakeup);
}


/* This handles the unlock grants for next set on rw_unlock() or on arrival of all preposted waiters */
int
kwq_handle_unlock(ksyn_wait_queue_t kwq, uint32_t mgen,  uint32_t * updatep, int flags, int * blockp, uint32_t premgen)
{
	uint32_t low_reader, low_writer, low_ywriter, low_lreader,limitrdnum;
	int rwtype, error=0;
	int longreadset = 0, allreaders, failed;
	uint32_t updatebits;
	int prepost = flags & KW_UNLOCK_PREPOST;
	thread_t preth = THREAD_NULL;
	uthread_t uth;
	thread_t th;
	int woken = 0;
	int block = 1;
        uint32_t lowest[KSYN_QUEUE_MAX]; /* np need for upgrade as it is handled separately */
	kern_return_t kret = KERN_SUCCESS;

#if _PSYNCH_TRACE_
#if defined(__i386__)
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_START, (uint32_t)kwq, mgen, premgen, 0, 0);
#endif
#endif /* _PSYNCH_TRACE_ */
	if (prepost != 0) {
		preth = current_thread();
	}
	
	/* upgrade pending */
	if (is_rw_ubit_set(mgen)) {
		if (prepost != 0)  {
			if((flags & KW_UNLOCK_PREPOST_UPGRADE) != 0) {
				/* upgrade thread calling the prepost */
				/* upgrade granted */
				block = 0;
				goto out;
			}

		}
		if (kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE].ksynq_count > 0) {
			uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE], kwq);
			uth->uu_psynchretval = (mgen  | PTHRW_EBIT) & ~PTHRW_UBIT;
			uth->uu_kwqqueue = NULL;
			kret = ksyn_wakeup_thread(kwq, uth);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("kwq_handle_unlock: panic waking up the upgrade thread \n");
			if (kret == KERN_NOT_WAITING) {
				kwq->kw_pre_intrcount = 1;	/* actually a  count */
				kwq->kw_pre_intrseq = mgen;
				kwq->kw_pre_intrretbits = uth->uu_psynchretval;
				kwq->kw_pre_intrtype = PTH_RW_TYPE_UPGRADE;
			}
			error = 0;
		} else {
			panic("panic unable to find the upgrade thread\n");
		}
		ksyn_wqunlock(kwq);
		goto out;
	}
	
	error = kwq_find_rw_lowest(kwq, flags, premgen, &rwtype, lowest);
	if (error != 0)
		panic("rwunlock: cannot fails to slot next round of threads");

#if _PSYNCH_TRACE_
#if defined(__i386__)
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq, 1, rwtype, lowest, 0);
#endif
#endif /* _PSYNCH_TRACE_ */
	low_reader = lowest[KSYN_QUEUE_READ];
	low_lreader = lowest[KSYN_QUEUE_LREAD];
	low_writer = lowest[KSYN_QUEUE_WRITER];
	low_ywriter = lowest[KSYN_QUEUE_YWRITER];

	
	updatebits = mgen  & ~( PTHRW_EBIT | PTHRW_WBIT |PTHRW_YBIT | PTHRW_UBIT | PTHRW_LBIT);

	longreadset = 0;
	allreaders = 0;
	switch (rwtype & PTH_RW_TYPE_MASK) {
		case PTH_RW_TYPE_LREAD:
			longreadset = 1;
		case PTH_RW_TYPE_READ: {
			limitrdnum = 0;
			if (longreadset == 0) {
				switch (rwtype & (PTH_RWSHFT_TYPE_WRITE | PTH_RWSHFT_TYPE_YWRITE)) {
					case PTH_RWSHFT_TYPE_WRITE: 
						limitrdnum = low_writer;
						if (((rwtype & PTH_RWSHFT_TYPE_LREAD) != 0) && 
							(is_seqlower(low_lreader, low_writer) != 0)) {
							longreadset = 1;
						}
				
						break;
					case PTH_RWSHFT_TYPE_YWRITE: 
						/* all read ? */
						if (((rwtype & PTH_RWSHFT_TYPE_LREAD) != 0) && 
							(is_seqlower(low_lreader, low_ywriter) != 0)) {
							longreadset = 1;
						} else
							allreaders = 1;
						break;
					case (PTH_RWSHFT_TYPE_WRITE | PTH_RWSHFT_TYPE_YWRITE):
						limitrdnum = low_writer; 
						if (((rwtype & PTH_RWSHFT_TYPE_LREAD) != 0) && 
							(is_seqlower(low_lreader, low_ywriter) != 0)) {
							longreadset = 1;
						}
						break;
					default: /* no writers at all */
						if ((rwtype & PTH_RWSHFT_TYPE_LREAD) != 0)
							longreadset = 1;
						else
							allreaders = 1;
				};

			}

			if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
				updatebits |= PTHRW_WBIT;
			else if ((rwtype & PTH_RWSHFT_TYPE_YWRITE) != 0)
				updatebits |= PTHRW_YBIT;

			if (longreadset == 0) {
				if((prepost != 0) && 
						((flags & KW_UNLOCK_PREPOST_READLOCK) != 0) &&
					((allreaders != 0) || (is_seqlower(premgen, limitrdnum) != 0))) {
					block = 0;
					uth = current_uthread();
					uth->uu_psynchretval = updatebits;
				}
			} else {
				updatebits |= PTHRW_LBIT;
				if ((prepost != 0) && 
				   ((flags & (KW_UNLOCK_PREPOST_READLOCK | KW_UNLOCK_PREPOST_LREADLOCK)) != 0)) {
					block = 0;
					uth = current_uthread();
					uth->uu_psynchretval = updatebits;
				}
			}
			
			if (prepost != 0) {
				updatebits |= PTHRW_RW_HUNLOCK;
			}

			failed = ksyn_wakeupreaders(kwq, limitrdnum, longreadset, allreaders, updatebits, &woken);
			if (failed != 0) {
				kwq->kw_pre_intrcount = failed;	/* actually a  count */
				kwq->kw_pre_intrseq = limitrdnum;
				kwq->kw_pre_intrretbits = updatebits;
				if (longreadset)
					kwq->kw_pre_intrtype = PTH_RW_TYPE_LREAD;
				else
					kwq->kw_pre_intrtype = PTH_RW_TYPE_READ;
			} 

			/* if we woken up no one and the current thread is returning, ensure it is doing unlock */
			if ((prepost != 0) && (woken == 0) && (block == 0)&& ((updatebits & PTHRW_RW_HUNLOCK) != 0)) {
				uth = current_uthread();
				uth->uu_psynchretval = updatebits;
	}

			error = 0;

		} 
		break;
			
		case PTH_RW_TYPE_WRITE: {
			updatebits |= PTHRW_EBIT;
			if (((flags & KW_UNLOCK_PREPOST_WRLOCK) != 0) && (low_writer == premgen)) {
				block = 0;
				if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0)
					updatebits |= PTHRW_WBIT;
				else if ((rwtype & PTH_RWSHFT_TYPE_YWRITE) != 0)
					updatebits |= PTHRW_YBIT;
				th = preth;
				uth = get_bsdthread_info(th);
				uth->uu_psynchretval = updatebits;
			}  else {
				/*  we are not granting writelock to the preposting thread */
				uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwq);

				/* if there are writers present or the preposting write thread then W bit is to be set */
				if ((kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_WRLOCK) != 0) )
					updatebits |= PTHRW_WBIT;
				else if ((rwtype & PTH_RWSHFT_TYPE_YWRITE) != 0)
					updatebits |= PTHRW_YBIT;
				uth->uu_psynchretval = updatebits;
				uth->uu_kwqqueue = NULL;
				/* setup next in the queue */
				kret = ksyn_wakeup_thread(kwq, uth);
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("kwq_handle_unlock: panic waking up writer\n");
				if (kret == KERN_NOT_WAITING) {
					kwq->kw_pre_intrcount = 1;	/* actually a  count */
					kwq->kw_pre_intrseq = low_writer;
					kwq->kw_pre_intrretbits = updatebits;
					kwq->kw_pre_intrtype = PTH_RW_TYPE_WRITE;
				}
				error = 0;
			}

		 } 
		break;

		case PTH_RW_TYPE_YWRITE: {
			/* can reader locks be granted ahead of this write? */
			if ((rwtype & PTH_RWSHFT_TYPE_READ) != 0)  {
				if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
					updatebits |= PTHRW_WBIT;
				else if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
					updatebits |= PTHRW_YBIT;
					
				if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0) {
					/* is lowest reader less than the low writer? */
					if (is_seqlower(low_reader,low_writer) == 0)
						goto yielditis;
					if (((flags & KW_UNLOCK_PREPOST_READLOCK) != 0) && (is_seqlower(premgen, low_writer) != 0)) {
						uth = current_uthread();
						uth->uu_psynchretval = updatebits;
						block = 0;
					}
					if (prepost != 0) {
						updatebits |= PTHRW_RW_HUNLOCK;
					}
					
					/* there will be readers to wakeup , no need to check for woken */
					failed = ksyn_wakeupreaders(kwq, low_writer, 0, 0, updatebits, NULL);
					if (failed != 0) {
						kwq->kw_pre_intrcount = failed;	/* actually a  count */
						kwq->kw_pre_intrseq = low_writer;
						kwq->kw_pre_intrretbits = updatebits;
						kwq->kw_pre_intrtype = PTH_RW_TYPE_READ;
					}
					error = 0;
				} else {
					/* wakeup all readers */
					if ((prepost != 0) &&  ((flags & KW_UNLOCK_PREPOST_READLOCK) != 0)) {
						uth = current_uthread();
						uth->uu_psynchretval = updatebits;
						block = 0;
					}
					if (prepost != 0) {
						updatebits |= PTHRW_RW_HUNLOCK;
					}
					failed = ksyn_wakeupreaders(kwq, low_writer, 0, 1, updatebits, &woken);
					if (failed != 0) {
						kwq->kw_pre_intrcount = failed;	/* actually a  count */
						kwq->kw_pre_intrseq = kwq->kw_highseq;
						kwq->kw_pre_intrretbits = updatebits;
						kwq->kw_pre_intrtype = PTH_RW_TYPE_READ;
					}
					/* if we woken up no one and the current thread is returning, ensure it is doing unlock */
					if ((prepost != 0) && (woken ==0) && (block == 0)&& ((updatebits & PTHRW_RW_HUNLOCK) != 0)) {
						uth = current_uthread();
						uth->uu_psynchretval = updatebits;
					}
					error = 0;
				}
			} else {
yielditis:
				/* no reads, so granting yeilding writes */
				updatebits |= PTHRW_EBIT;

				if (((flags & KW_UNLOCK_PREPOST_YWRLOCK) != 0) && (low_writer == premgen)) {
					/* preposting yielding write thread is being granted exclusive lock */

					block = 0;

					if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
						updatebits |= PTHRW_WBIT;
					else if (kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0)
						updatebits |= PTHRW_YBIT;

					th = preth;
					uth = get_bsdthread_info(th);
					uth->uu_psynchretval = updatebits;
				}  else {
					/*  we are granting yield writelock to some other thread */
					uth = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER], kwq);

					if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
						updatebits |= PTHRW_WBIT;
					/* if there are ywriters present or the preposting ywrite thread then W bit is to be set */
					else if ((kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_YWRLOCK) != 0) )
						updatebits |= PTHRW_YBIT;

					uth->uu_psynchretval = updatebits;
					uth->uu_kwqqueue = NULL;

					kret = ksyn_wakeup_thread(kwq, uth);
					if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
						panic("kwq_handle_unlock : panic waking up readers\n");
					if (kret == KERN_NOT_WAITING) {
						kwq->kw_pre_intrcount = 1;	/* actually a  count */
						kwq->kw_pre_intrseq = low_ywriter;
						kwq->kw_pre_intrretbits = updatebits;
						kwq->kw_pre_intrtype = PTH_RW_TYPE_YWRITE;
					}
					error = 0;
				}
			}
		} 
		break;

		default:
			panic("rwunlock: invalid type for lock grants");
			
	};

	if (updatep != NULL)
		*updatep = updatebits;

out:
	if (blockp != NULL)
		*blockp = block;
#if _PSYNCH_TRACE_
#if defined(__i386__)
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_END, (uint32_t)kwq, 0, 0, block, 0);
#endif
#endif /* _PSYNCH_TRACE_ */
	return(error);
}


/* handle downgrade actions */
int
kwq_handle_downgrade(ksyn_wait_queue_t kwq, uint32_t mgen, __unused int flags, __unused uint32_t premgen, __unused int * blockp)
{
	uint32_t updatebits, lowriter = 0;
	int longreadset, allreaders, count;

	/* can handle downgrade now */
	updatebits = mgen;		

	longreadset = 0;
	allreaders = 0;
	if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count > 0) {
		lowriter = kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_firstnum;
		if (kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_count > 0) {
			if (is_seqlower(kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_firstnum, lowriter) != 0)
				longreadset = 1;
		}
	} else {
		allreaders = 1;
		if (kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count > 0) {
			lowriter = kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_firstnum;
			if (kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_count > 0) {
				if (is_seqlower(kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_firstnum, lowriter) != 0)
					longreadset = 1;
			}
		}
	}

	count = ksyn_wakeupreaders(kwq, lowriter, longreadset, allreaders, updatebits, NULL);
	if (count != 0) {
		kwq->kw_pre_limrd = count;
		kwq->kw_pre_limrdseq = lowriter;
		kwq->kw_pre_limrdbits = lowriter;
		/* need to handle prepost */
	}
	return(0);
}
/************* Indiv queue support routines ************************/
void
ksyn_queue_init(ksyn_queue_t kq)
{
	TAILQ_INIT(&kq->ksynq_uthlist);
	kq->ksynq_count = 0;
	kq->ksynq_firstnum = 0;
	kq->ksynq_lastnum = 0;
}


int
ksyn_queue_insert(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t mgen, struct uthread * uth, int fit)
{
	uint32_t lockseq = mgen & PTHRW_COUNT_MASK;
	struct uthread * q_uth, * r_uth;
	
	if (kq->ksynq_count == 0) {
		TAILQ_INSERT_HEAD(&kq->ksynq_uthlist, uth, uu_mtxlist);
		kq->ksynq_firstnum = lockseq;
		kq->ksynq_lastnum = lockseq;
		goto out;
	}

	if (fit == FIRSTFIT) {
		/* firstfit, arriving order */
		TAILQ_INSERT_TAIL(&kq->ksynq_uthlist, uth, uu_mtxlist);
		if (is_seqlower (lockseq, kq->ksynq_firstnum) != 0)
			kq->ksynq_firstnum = lockseq;
		if (is_seqhigher (lockseq, kq->ksynq_lastnum) != 0)
			kq->ksynq_lastnum = lockseq;
		goto out;
	}
		
	if ((lockseq == kq->ksynq_firstnum) || (lockseq == kq->ksynq_lastnum))
		panic("ksyn_queue_insert: two threads with same lockseq ");

	/* check for next seq one */
	if (is_seqlower(kq->ksynq_lastnum, lockseq) != 0) {
		TAILQ_INSERT_TAIL(&kq->ksynq_uthlist, uth, uu_mtxlist);
		kq->ksynq_lastnum = lockseq;
		goto out;
	}

	if (is_seqlower(lockseq, kq->ksynq_firstnum) != 0) {
		TAILQ_INSERT_HEAD(&kq->ksynq_uthlist, uth, uu_mtxlist);
		kq->ksynq_firstnum = lockseq;
		goto out;
	}

	/* goto slow  insert mode */
	TAILQ_FOREACH_SAFE(q_uth, &kq->ksynq_uthlist, uu_mtxlist, r_uth) {
		if (is_seqhigher(q_uth->uu_lockseq, lockseq) != 0) {
			TAILQ_INSERT_BEFORE(q_uth, uth, uu_mtxlist);
			goto out;
		}
	}

	panic("failed to insert \n");
out:
	kq->ksynq_count++;
	kwq->kw_inqueue++;
	update_low_high(kwq, lockseq);
	return(0);
}

struct uthread *
ksyn_queue_removefirst(ksyn_queue_t kq, ksyn_wait_queue_t kwq)
{
	uthread_t uth = NULL;
	uthread_t q_uth;
	uint32_t curseq;

	if (kq->ksynq_count != 0) {
		uth = TAILQ_FIRST(&kq->ksynq_uthlist);
		TAILQ_REMOVE(&kq->ksynq_uthlist, uth, uu_mtxlist);
		curseq = uth->uu_lockseq & PTHRW_COUNT_MASK;
		kq->ksynq_count--;
		kwq->kw_inqueue--;
	
		if(kq->ksynq_count != 0) {
			q_uth = TAILQ_FIRST(&kq->ksynq_uthlist);
			kq->ksynq_firstnum = (q_uth->uu_lockseq & PTHRW_COUNT_MASK);
		} else {
			kq->ksynq_firstnum = 0;
			kq->ksynq_lastnum = 0;
			
		}
		if (kwq->kw_inqueue == 0) {
			kwq->kw_lowseq = 0;
			kwq->kw_highseq = 0;
		} else {
			if (kwq->kw_lowseq == curseq)
				kwq->kw_lowseq = find_nextlowseq(kwq);
			if (kwq->kw_highseq == curseq) 
				kwq->kw_highseq = find_nexthighseq(kwq);
		}
	}
	return(uth);
}

void
ksyn_queue_removeitem(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uthread_t uth)
{
	uthread_t q_uth;
	uint32_t curseq;

	if (kq->ksynq_count > 0) {
		TAILQ_REMOVE(&kq->ksynq_uthlist, uth, uu_mtxlist);
		kq->ksynq_count--;
		if(kq->ksynq_count != 0) {
			q_uth = TAILQ_FIRST(&kq->ksynq_uthlist);
			kq->ksynq_firstnum = (q_uth->uu_lockseq & PTHRW_COUNT_MASK);
		} else {
			kq->ksynq_firstnum = 0;
			kq->ksynq_lastnum = 0;
		
		}
		kwq->kw_inqueue--;
		curseq = uth->uu_lockseq & PTHRW_COUNT_MASK;
		if (kwq->kw_inqueue == 0) {
			kwq->kw_lowseq = 0;
			kwq->kw_highseq = 0;
		} else {
			if (kwq->kw_lowseq == curseq)
				kwq->kw_lowseq = find_nextlowseq(kwq);
			if (kwq->kw_highseq == curseq) 
				kwq->kw_highseq = find_nexthighseq(kwq);
		}
	}
}


void
update_low_high(ksyn_wait_queue_t kwq, uint32_t lockseq)
{
	if (kwq->kw_inqueue == 1) {
		kwq->kw_lowseq = lockseq;
		kwq->kw_highseq = lockseq;
	} else {
		if (is_seqlower(lockseq, kwq->kw_lowseq) != 0)
			kwq->kw_lowseq = lockseq;
		if (is_seqhigher(lockseq, kwq->kw_highseq) != 0)
			kwq->kw_highseq = lockseq;
	}
}

uint32_t 
find_nextlowseq(ksyn_wait_queue_t kwq)
{
	uint32_t numbers[4];
	int count = 0, i;
	uint32_t lowest;

	for(i = 0; i< KSYN_QUEUE_MAX; i++) {
		if (kwq->kw_ksynqueues[i].ksynq_count != 0) {
			numbers[count]= kwq->kw_ksynqueues[i].ksynq_firstnum;
			count++;
		}
	}

	if (count == 0)
		return(0);
	lowest = numbers[0];
	if (count > 1) {
		for (i = 1; i< count; i++) {
			if(is_seqlower(numbers[i] , lowest) != 0) 
				lowest = numbers[count];
	
		}
	}
	return(lowest);
}

uint32_t
find_nexthighseq(ksyn_wait_queue_t kwq)
{
	uint32_t numbers[4];
	int count = 0, i;
	uint32_t highest;

	for(i = 0; i< KSYN_QUEUE_MAX; i++) {
		if (kwq->kw_ksynqueues[i].ksynq_count != 0) {
			numbers[count]= kwq->kw_ksynqueues[i].ksynq_lastnum;
			count++;
		}
	}



	if (count == 0)
		return(0);
	highest = numbers[0];
	if (count > 1) {
		for (i = 1; i< count; i++) {
			if(is_seqhigher(numbers[i], highest) != 0) 
				highest = numbers[i];
	
		}
	}
	return(highest);
}

int
find_diff(uint32_t upto, uint32_t lowest)
{
	uint32_t diff;

	if (upto == lowest)
		return(0);
	diff = diff_genseq(upto, lowest);
	diff = (diff >> PTHRW_COUNT_SHIFT);
	return(diff);
}


int
find_seq_till(ksyn_wait_queue_t kwq, uint32_t upto, uint32_t nwaiters, uint32_t *countp)
{
	int  i;
	uint32_t count = 0;


#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_FSEQTILL | DBG_FUNC_START, 0, 0, upto, nwaiters, 0);
#endif /* _PSYNCH_TRACE_ */

	for (i= 0; i< KSYN_QUEUE_MAX; i++) {
		count += ksyn_queue_count_tolowest(&kwq->kw_ksynqueues[i], upto);
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_FSEQTILL | DBG_FUNC_NONE, 0, 1, i, count, 0);
#endif /* _PSYNCH_TRACE_ */
		if (count >= nwaiters) {
			break;
		}
	}

	if (countp != NULL) {
		*countp = count;
	}
#if _PSYNCH_TRACE_
	KERNEL_DEBUG_CONSTANT(_PSYNCH_TRACE_FSEQTILL | DBG_FUNC_END, 0, 0, count, nwaiters, 0);
#endif /* _PSYNCH_TRACE_ */
	if (count >= nwaiters)
		return(1);
	else
		return(0);
}


uint32_t
ksyn_queue_count_tolowest(ksyn_queue_t kq, uint32_t upto)
{
	uint32_t i = 0;
	uthread_t uth, newuth;
	uint32_t curval;

	/* if nothing or the  first num is greater than upto, return none */
	if ((kq->ksynq_count == 0) || (is_seqhigher(kq->ksynq_firstnum, upto) != 0))
		return(0);
	if (upto == kq->ksynq_firstnum)
		return(1);

	TAILQ_FOREACH_SAFE(uth, &kq->ksynq_uthlist, uu_mtxlist, newuth) {
		curval = (uth->uu_lockseq & PTHRW_COUNT_MASK);
		if (upto == curval) {
			i++;
			break;
		} else if (is_seqhigher(curval, upto) != 0) {
			break;
		}  else {
			/* seq is lower */
			i++;
		}
	}
	return(i);
}

/* find the thread and removes from the queue */
uthread_t
ksyn_queue_find_seq(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t seq)
{
		uthread_t q_uth, r_uth;
		/* case where wrap in the tail of the queue exists */
		TAILQ_FOREACH_SAFE(q_uth, &kq->ksynq_uthlist, uu_mtxlist, r_uth) {
			if (q_uth->uu_lockseq == seq) {
				ksyn_queue_removeitem(kwq, kq, q_uth);
				return(q_uth);
			}
		}
	return(NULL);
}

#endif /* PSYNCH */
