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
#include <kern/zalloc.h>
#include <kern/sched_prim.h>
#include <kern/processor.h>
#include <kern/affinity.h>
#include <kern/wait_queue.h>
#include <kern/mach_param.h>
#include <mach/mach_vm.h>
#include <mach/mach_param.h>
#include <mach/thread_policy.h>
#include <mach/message.h>
#include <mach/port.h>
#include <vm/vm_protos.h>
#include <vm/vm_map.h>
#include <mach/vm_region.h>

#include <libkern/OSAtomic.h>

#include <pexpert/pexpert.h>

#define __PSYNCH_DEBUG__ 0			/* debug panic actions  */
#if (KDEBUG && STANDARD_KDEBUG)
#define _PSYNCH_TRACE_ 1		/* kdebug trace */
#endif

#define __TESTMODE__ 2		/* 0 - return error on user error conditions */
				/* 1 - log error on user error conditions */
				/* 2 - abort caller on user error conditions */
				/* 3 - panic on user error conditions */
static int __test_panics__;
static int __test_aborts__;
static int __test_prints__;

static inline void __FAILEDUSERTEST__(const char *str)
{
	proc_t p;

	if (__test_panics__ != 0)
		panic(str);

	if (__test_aborts__ != 0 || __test_prints__ != 0)
		p = current_proc();

	if (__test_prints__ != 0)
		printf("PSYNCH: pid[%d]: %s\n", p->p_pid, str);

	if (__test_aborts__ != 0)
		psignal(p, SIGABRT);
}

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
#define _PSYNCH_TRACE_CLRPRE	0x9000044
#define _PSYNCH_TRACE_CVHBROAD	0x9000048
#define _PSYNCH_TRACE_CVSEQ	0x900004c
#define _PSYNCH_TRACE_THWAKEUP	0x9000050
/* user side */
#define _PSYNCH_TRACE_UM_LOCK	0x9000060
#define _PSYNCH_TRACE_UM_UNLOCK	0x9000064
#define _PSYNCH_TRACE_UM_MHOLD	0x9000068
#define _PSYNCH_TRACE_UM_MDROP	0x900006c
#define _PSYNCH_TRACE_UM_CVWAIT	0x9000070
#define _PSYNCH_TRACE_UM_CVSIG	0x9000074
#define _PSYNCH_TRACE_UM_CVBRD	0x9000078

proc_t pthread_debug_proc = PROC_NULL;
static inline void __PTHREAD_TRACE_DEBUG(uint32_t debugid, uintptr_t arg1, 
                uintptr_t arg2,
                uintptr_t arg3,
                uintptr_t arg4,
                uintptr_t arg5)
{
	proc_t p = current_proc();

	if ((pthread_debug_proc != NULL) && (p == pthread_debug_proc))
		KERNEL_DEBUG_CONSTANT(debugid, arg1, arg2, arg3, arg4, arg5);
}

#endif /* _PSYNCH_TRACE_ */

#define ECVCERORR       256
#define ECVPERORR       512

lck_mtx_t * pthread_list_mlock;

#define PTHHASH(addr)    (&pthashtbl[(addr) & pthhash])
extern LIST_HEAD(pthhashhead, ksyn_wait_queue) *pth_glob_hashtbl;
struct pthhashhead * pth_glob_hashtbl;
u_long pthhash;

LIST_HEAD(, ksyn_wait_queue) pth_free_list;
int num_total_kwq = 0;  /* number of kwq in use currently */
int num_infreekwq = 0;	/* number of kwq in free list */
int num_freekwq = 0;	/* number of kwq actually  freed from the free the list */
int num_reusekwq = 0;	/* number of kwq pulled back for reuse from free list */
int num_addedfreekwq = 0; /* number of added free kwq from the last instance */
int num_lastfreekwqcount = 0;	/* the free count from the last time */

static int PTH_HASHSIZE = 100;

static zone_t kwq_zone; /* zone for allocation of ksyn_queue */
static zone_t kwe_zone;	/* zone for allocation of ksyn_waitq_element */

#define SEQFIT 0
#define FIRSTFIT 1

struct ksyn_queue {
	TAILQ_HEAD(ksynq_kwelist_head, ksyn_waitq_element) ksynq_kwelist;
	uint32_t	ksynq_count;		/* number of entries in queue */
	uint32_t	ksynq_firstnum;		/* lowest seq in queue */
	uint32_t	ksynq_lastnum;		/* highest seq in queue */
};
typedef struct ksyn_queue * ksyn_queue_t;

#define KSYN_QUEUE_READ		0
#define KSYN_QUEUE_LREAD	1
#define KSYN_QUEUE_WRITER	2
#define KSYN_QUEUE_YWRITER	3
#define KSYN_QUEUE_UPGRADE	4
#define KSYN_QUEUE_MAX		5

struct ksyn_wait_queue {
	LIST_ENTRY(ksyn_wait_queue) kw_hash;
	LIST_ENTRY(ksyn_wait_queue) kw_list;
	user_addr_t kw_addr;
	uint64_t  kw_owner;
	uint64_t kw_object;		/* object backing in shared mode */
	uint64_t kw_offset;		/* offset inside the object in shared mode */
	int     kw_flags;		/* mutex, cvar options/flags */
	int 	kw_pflags;		/* flags under listlock protection */
	struct timeval kw_ts;		/* timeval need for upkeep before free */
	int	kw_iocount;		/* inuse reference */
	int 	kw_dropcount;		/* current users unlocking... */

	int	kw_type;		/* queue type like mutex, cvar, etc */
	uint32_t kw_inqueue;		/* num of waiters held */
	uint32_t kw_fakecount;		/* number of error/prepost fakes */
	uint32_t kw_highseq;		/* highest seq in the queue */
	uint32_t kw_lowseq;		/* lowest seq in the queue */
	uint32_t kw_lword;		/* L value from userland */
	uint32_t kw_uword;		/* U world value from userland */
	uint32_t kw_sword;		/* S word value from userland */
	uint32_t kw_lastunlockseq;	/* the last seq that unlocked */
/* for CV to be used as the seq kernel has seen so far */
#define kw_cvkernelseq kw_lastunlockseq
	uint32_t kw_lastseqword;		/* the last seq that unlocked */
/* for mutex and cvar we need to track I bit values */
	uint32_t kw_nextseqword;	/* the last seq that unlocked; with num of waiters */
#define kw_initrecv kw_nextseqword	/* number of incoming waiters with Ibit seen sofar */
	uint32_t kw_overlapwatch;	/* chance for overlaps  */
#define kw_initcount kw_overlapwatch	/* number of incoming waiters with Ibit expected */
	uint32_t kw_initcountseq;	/* highest seq with Ibit on for mutex and cvar*/
	uint32_t kw_pre_rwwc;		/* prepost count */
	uint32_t kw_pre_lockseq;	/* prepost target seq */
	uint32_t kw_pre_sseq;		/* prepost target sword, in cvar used for mutexowned  */
	uint32_t kw_pre_intrcount;	/*  prepost of missed wakeup due to intrs */
	uint32_t kw_pre_intrseq;	/*  prepost of missed wakeup limit seq */
	uint32_t kw_pre_intrretbits;	/*  return bits value for missed wakeup threads */
	uint32_t kw_pre_intrtype;	/*  type of failed wakueps*/

	int 	kw_kflags;
	struct ksyn_queue kw_ksynqueues[KSYN_QUEUE_MAX];	/* queues to hold threads */
	lck_mtx_t kw_lock;		/* mutex lock protecting this structure */
};
typedef struct ksyn_wait_queue * ksyn_wait_queue_t;

#define PTHRW_INC			0x100
#define PTHRW_BIT_MASK		0x000000ff

#define PTHRW_COUNT_SHIFT	8
#define PTHRW_COUNT_MASK	0xffffff00
#define PTHRW_MAX_READERS	0xffffff00

/* New model bits on Lword */
#define PTH_RWL_KBIT	0x01	/* users cannot acquire in user mode */
#define PTH_RWL_EBIT	0x02	/* exclusive lock in progress */
#define PTH_RWL_WBIT	0x04	/* write waiters pending in kernel */
#define PTH_RWL_PBIT    0x04    /* prepost (cv) pending in kernel */
#define PTH_RWL_YBIT	0x08	/* yielding write waiters pending in kernel */
#define PTH_RWL_RETRYBIT 0x08	/* mutex retry wait */
#define PTH_RWL_LBIT	0x10	/* long read in progress */
#define PTH_RWL_MTXNONE 0x10    /* indicates the cvwait does not have mutex held */
#define PTH_RWL_UBIT	0x20	/* upgrade request pending */
#define PTH_RWL_MTX_WAIT 0x20	/* in cvar in mutex wait */
#define PTH_RWL_RBIT	0x40	/* reader pending in kernel(not used) */
#define PTH_RWL_MBIT	0x40	/* overlapping grants from kernel */
#define PTH_RWL_TRYLKBIT 0x40	/* trylock attempt (mutex only) */
#define PTH_RWL_IBIT	0x80	/* lcok reset, held untill first succeesful unlock */


/* UBIT values for mutex, cvar */
#define PTH_RWU_SBIT    0x01
#define PTH_RWU_BBIT    0x02

#define PTHRW_RWL_INIT       PTH_RWL_IBIT    /* reset state on the lock bits (U)*/

/* New model bits on Sword */
#define PTH_RWS_SBIT	0x01	/* kernel transition seq not set yet*/
#define PTH_RWS_IBIT	0x02	/* Sequence is not set on return from kernel */
#define PTH_RWS_CV_CBIT PTH_RWS_SBIT    /* kernel has cleared all info w.r.s.t CV */ 
#define PTH_RWS_CV_PBIT PTH_RWS_IBIT    /* kernel has prepost/fake structs only,no waiters */
#define PTH_RWS_CV_MBIT PTH_RWL_MBIT	/* to indicate prepost return */
#define PTH_RWS_WSVBIT  0x04    /* save W bit */
#define PTH_RWS_USVBIT  0x08    /* save U bit */
#define PTH_RWS_YSVBIT  0x10    /* save Y bit */
#define PTHRW_RWS_INIT       PTH_RWS_SBIT    /* reset on the lock bits (U)*/
#define PTHRW_RWS_SAVEMASK (PTH_RWS_WSVBIT|PTH_RWS_USVBIT|PTH_RWS_YSVBIT)    /*save bits mask*/
#define PTHRW_SW_Reset_BIT_MASK 0x000000fe      /* remove S bit and get rest of the bits */

#define PTHRW_RWS_INIT       PTH_RWS_SBIT    /* reset on the lock bits (U)*/


#define PTHRW_UN_BIT_MASK 0x000000bf	/* remove overlap  bit */


#define PTHREAD_MTX_TID_SWITCHING (uint64_t)-1

/* new L word defns */
#define is_rwl_readinuser(x) ((((x) & (PTH_RWL_UBIT | PTH_RWL_KBIT)) == 0)||(((x) & PTH_RWL_LBIT) != 0))
#define is_rwl_ebit_set(x) (((x) & PTH_RWL_EBIT) != 0)
#define is_rwl_lbit_set(x) (((x) & PTH_RWL_LBIT) != 0)
#define is_rwl_readoverlap(x) (((x) & PTH_RWL_MBIT) != 0)
#define is_rw_ubit_set(x) (((x) & PTH_RWL_UBIT) != 0)

/* S word checks */
#define is_rws_setseq(x) (((x) & PTH_RWS_SBIT))
#define is_rws_setunlockinit(x) (((x) & PTH_RWS_IBIT))

/* first contended seq that kernel sees */
#define KW_MTXFIRST_KSEQ	0x200
#define KW_CVFIRST_KSEQ		1
#define KW_RWFIRST_KSEQ		0x200

int is_seqlower(uint32_t x, uint32_t y);
int is_seqlower_eq(uint32_t x, uint32_t y);
int is_seqhigher(uint32_t x, uint32_t y);
int is_seqhigher_eq(uint32_t x, uint32_t y);
int find_diff(uint32_t upto, uint32_t lowest);


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
#define _PTHREAD_MTX_OPT_NOMTX 		0x400

#define _PTHREAD_MTX_OPT_NOTIFY 	0x1000
#define _PTHREAD_MTX_OPT_MUTEX		0x2000	/* this is a mutex type  */

#define _PTHREAD_RWLOCK_UPGRADE_TRY 0x10000

/* pflags */
#define KSYN_WQ_INLIST	1
#define KSYN_WQ_INHASH	2
#define KSYN_WQ_SHARED	4
#define KSYN_WQ_WAITING 8	/* threads waiting for this wq to be available */
#define KSYN_WQ_FLIST 	0X10	/* in free list to be freed after a short delay */

/* kflags */
#define KSYN_KWF_INITCLEARED	1	/* the init status found and preposts cleared */
#define KSYN_KWF_ZEROEDOUT	2	/* the lword, etc are inited to 0 */

#define KSYN_CLEANUP_DEADLINE 10
int psynch_cleanupset;
thread_call_t psynch_thcall;

#define KSYN_WQTYPE_INWAIT	0x1000
#define KSYN_WQTYPE_INDROP	0x2000
#define KSYN_WQTYPE_MTX		0x1
#define KSYN_WQTYPE_CVAR	0x2
#define KSYN_WQTYPE_RWLOCK	0x4
#define KSYN_WQTYPE_SEMA	0x8
#define KSYN_WQTYPE_BARR	0x10
#define KSYN_WQTYPE_MASK        0x00ff

#define KSYN_MTX_MAX 0x0fffffff
#define KSYN_WQTYPE_MUTEXDROP	(KSYN_WQTYPE_INDROP | KSYN_WQTYPE_MTX)

#define KW_UNLOCK_PREPOST 		0x01
#define KW_UNLOCK_PREPOST_UPGRADE 	0x02
#define KW_UNLOCK_PREPOST_DOWNGRADE 	0x04
#define KW_UNLOCK_PREPOST_READLOCK 	0x08
#define KW_UNLOCK_PREPOST_LREADLOCK 	0x10
#define KW_UNLOCK_PREPOST_WRLOCK 	0x20
#define KW_UNLOCK_PREPOST_YWRLOCK 	0x40

#define CLEAR_PREPOST_BITS(kwq)  {\
			kwq->kw_pre_lockseq = 0; \
			kwq->kw_pre_sseq = PTHRW_RWS_INIT; \
			kwq->kw_pre_rwwc = 0; \
			}

#define CLEAR_INITCOUNT_BITS(kwq)  {\
			kwq->kw_initcount = 0; \
			kwq->kw_initrecv = 0; \
			kwq->kw_initcountseq = 0; \
			}

#define CLEAR_INTR_PREPOST_BITS(kwq)  {\
			kwq->kw_pre_intrcount = 0; \
			kwq->kw_pre_intrseq = 0; \
			kwq->kw_pre_intrretbits = 0; \
			kwq->kw_pre_intrtype = 0; \
			}

#define CLEAR_REINIT_BITS(kwq)  {\
			if ((kwq->kw_type & KSYN_WQTYPE_MASK) == KSYN_WQTYPE_CVAR) { \
				if((kwq->kw_inqueue != 0) && (kwq->kw_inqueue != kwq->kw_fakecount)) \
					panic("CV:entries in queue durinmg reinit %d:%d\n",kwq->kw_inqueue, kwq->kw_fakecount);	\
			};\
			if ((kwq->kw_type & KSYN_WQTYPE_MASK) == KSYN_WQTYPE_RWLOCK) { \
				kwq->kw_nextseqword = PTHRW_RWS_INIT; \
				kwq->kw_overlapwatch = 0; \
			}; \
			kwq->kw_pre_lockseq = 0; \
			kwq->kw_pre_rwwc = 0; \
			kwq->kw_pre_sseq = PTHRW_RWS_INIT; \
			kwq->kw_lastunlockseq = PTHRW_RWL_INIT; \
			kwq->kw_lastseqword = PTHRW_RWS_INIT; \
			kwq->kw_pre_intrcount = 0; \
			kwq->kw_pre_intrseq = 0; \
			kwq->kw_pre_intrretbits = 0; \
			kwq->kw_pre_intrtype = 0; \
			kwq->kw_lword = 0;	\
			kwq->kw_uword = 0;	\
			kwq->kw_sword = PTHRW_RWS_INIT;	\
			}

void pthread_list_lock(void);
void pthread_list_unlock(void);
void pthread_list_lock_spin(void);
void pthread_list_lock_convert_spin(void);
void ksyn_wqlock(ksyn_wait_queue_t kwq);
void ksyn_wqunlock(ksyn_wait_queue_t kwq);
ksyn_wait_queue_t ksyn_wq_hash_lookup(user_addr_t mutex, proc_t p, int flags, uint64_t object, uint64_t offset);
int ksyn_wqfind(user_addr_t mutex, uint32_t mgen, uint32_t ugen, uint32_t rw_wc, uint64_t tid, int flags, int wqtype , ksyn_wait_queue_t * wq);
void ksyn_wqrelease(ksyn_wait_queue_t mkwq, ksyn_wait_queue_t ckwq, int qfreenow, int wqtype);
extern int ksyn_findobj(uint64_t mutex, uint64_t * object, uint64_t * offset);
static void UPDATE_CVKWQ(ksyn_wait_queue_t kwq, uint32_t mgen, uint32_t ugen, uint32_t rw_wc, uint64_t tid, int wqtype);
extern thread_t port_name_to_thread(mach_port_name_t port_name);

kern_return_t ksyn_block_thread_locked(ksyn_wait_queue_t kwq, uint64_t abstime, ksyn_waitq_element_t kwe, int log, thread_continue_t, void * parameter);
kern_return_t ksyn_wakeup_thread(ksyn_wait_queue_t kwq, ksyn_waitq_element_t kwe);
void ksyn_freeallkwe(ksyn_queue_t kq);

uint32_t psynch_mutexdrop_internal(ksyn_wait_queue_t kwq, uint32_t lkseq, uint32_t ugen, int flags);
int kwq_handle_unlock(ksyn_wait_queue_t, uint32_t mgen, uint32_t rw_wc, uint32_t * updatep, int flags, int *blockp, uint32_t premgen);

void ksyn_queue_init(ksyn_queue_t kq);
int ksyn_queue_insert(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t mgen, struct uthread * uth, ksyn_waitq_element_t kwe, int firstfit);
ksyn_waitq_element_t ksyn_queue_removefirst(ksyn_queue_t kq, ksyn_wait_queue_t kwq);
void ksyn_queue_removeitem(ksyn_wait_queue_t kwq, ksyn_queue_t kq, ksyn_waitq_element_t kwe);
int ksyn_queue_move_tofree(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t upto, ksyn_queue_t freeq, int all, int reease);
void update_low_high(ksyn_wait_queue_t kwq, uint32_t lockseq);
uint32_t find_nextlowseq(ksyn_wait_queue_t kwq);
uint32_t find_nexthighseq(ksyn_wait_queue_t kwq);

int find_seq_till(ksyn_wait_queue_t kwq, uint32_t upto, uint32_t  nwaiters, uint32_t *countp);
uint32_t ksyn_queue_count_tolowest(ksyn_queue_t kq, uint32_t upto);

ksyn_waitq_element_t ksyn_queue_find_cvpreposeq(ksyn_queue_t kq, uint32_t cgen);
uint32_t ksyn_queue_cvcount_entries(ksyn_queue_t kq, uint32_t upto, uint32_t from, int * numwaitersp, int * numintrp, int * numprepop);
void ksyn_handle_cvbroad(ksyn_wait_queue_t ckwq, uint32_t upto, uint32_t *updatep);
void ksyn_cvupdate_fixup(ksyn_wait_queue_t ckwq, uint32_t *updatep, ksyn_queue_t kfreeq, int release);
ksyn_waitq_element_t ksyn_queue_find_signalseq(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t toseq, uint32_t lockseq);
ksyn_waitq_element_t ksyn_queue_find_threadseq(ksyn_wait_queue_t ckwq, ksyn_queue_t kq, thread_t th, uint32_t toseq);
void psynch_cvcontinue(void *, wait_result_t);
void psynch_mtxcontinue(void *, wait_result_t);

int ksyn_wakeupreaders(ksyn_wait_queue_t kwq, uint32_t limitread, int longreadset, int allreaders, uint32_t updatebits, int * wokenp);
int kwq_find_rw_lowest(ksyn_wait_queue_t kwq, int flags, uint32_t premgen, int * type, uint32_t lowest[]);
ksyn_waitq_element_t ksyn_queue_find_seq(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t seq, int remove);
int kwq_handle_overlap(ksyn_wait_queue_t kwq, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, uint32_t *updatebitsp, int flags , int * blockp);
int kwq_handle_downgrade(ksyn_wait_queue_t kwq, uint32_t mgen, int flags, uint32_t premgen, int * blockp);

static void
UPDATE_CVKWQ(ksyn_wait_queue_t kwq, uint32_t mgen, uint32_t ugen, uint32_t rw_wc, __unused uint64_t tid, __unused int wqtype)
{
	if ((kwq->kw_type & KSYN_WQTYPE_MASK) == KSYN_WQTYPE_CVAR) {
		if ((kwq->kw_kflags & KSYN_KWF_ZEROEDOUT) != 0) {
			/* the values of L,U and S are cleared out due to L==S in previous transition */
			kwq->kw_lword = mgen;
			kwq->kw_uword = ugen;
			kwq->kw_sword = rw_wc;
			kwq->kw_kflags &=  ~KSYN_KWF_ZEROEDOUT;
		}
		if (is_seqhigher((mgen & PTHRW_COUNT_MASK), (kwq->kw_lword & PTHRW_COUNT_MASK)) != 0)
			kwq->kw_lword = mgen;
		if (is_seqhigher((ugen & PTHRW_COUNT_MASK), (kwq->kw_uword & PTHRW_COUNT_MASK)) != 0)
			kwq->kw_uword = ugen;
		if ((rw_wc & PTH_RWS_CV_CBIT) != 0) {
			if(is_seqlower(kwq->kw_cvkernelseq, (rw_wc & PTHRW_COUNT_MASK)) != 0) {
				kwq->kw_cvkernelseq = (rw_wc & PTHRW_COUNT_MASK);
			}
			if (is_seqhigher((rw_wc & PTHRW_COUNT_MASK), (kwq->kw_sword & PTHRW_COUNT_MASK)) != 0)
				kwq->kw_sword = rw_wc;
		}
	}
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
uint32_t
psynch_mutexdrop_internal(ksyn_wait_queue_t kwq, uint32_t lkseq, uint32_t ugen, int flags)
{
	uint32_t nextgen, low_writer, updatebits, returnbits = 0;
	int firstfit = flags & _PTHREAD_MUTEX_POLICY_FIRSTFIT;
	ksyn_waitq_element_t kwe = NULL;
	kern_return_t kret = KERN_SUCCESS;
	
	nextgen = (ugen + PTHRW_INC);

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_START, (uint32_t)kwq->kw_addr, lkseq, ugen, flags, 0);
#endif /* _PSYNCH_TRACE_ */

	ksyn_wqlock(kwq);

redrive:
	
	if (kwq->kw_inqueue != 0) {
		updatebits = (kwq->kw_highseq & PTHRW_COUNT_MASK) | (PTH_RWL_EBIT | PTH_RWL_KBIT);
		kwq->kw_lastunlockseq = (ugen & PTHRW_COUNT_MASK);
		if (firstfit != 0) 
		{
			/* first fit , pick any one */
			kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwq);
			kwe->kwe_psynchretval = updatebits;
			kwe->kwe_kwqqueue = NULL;

#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xcafecaf1, (uint32_t)(thread_tid((struct thread *)(((struct uthread *)(kwe->kwe_uth))->uu_context.vc_thread))), kwe->kwe_psynchretval, 0);
#endif /* _PSYNCH_TRACE_ */
			
			kret = ksyn_wakeup_thread(kwq, kwe);
#if __TESTPANICS__
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("psynch_mutexdrop_internal: panic unable to wakeup firstfit mutex thread\n");
#endif /* __TESTPANICS__ */
			if (kret == KERN_NOT_WAITING)
				goto redrive;
		} else {
			/* handle fairshare */	
			low_writer = kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_firstnum;
			low_writer &= PTHRW_COUNT_MASK;

			if (low_writer == nextgen) {
				/* next seq to be granted found */
				kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwq);
				
				/* since the grant could be cv, make sure mutex wait is set incase the thread interrupted out */
				kwe->kwe_psynchretval = updatebits | PTH_RWL_MTX_WAIT;
				kwe->kwe_kwqqueue = NULL;

#if _PSYNCH_TRACE_
				__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xcafecaf2, (uint32_t)(thread_tid((struct thread *)(((struct uthread *)(kwe->kwe_uth))->uu_context.vc_thread))), kwe->kwe_psynchretval, 0);
#endif /* _PSYNCH_TRACE_ */
				
				kret = ksyn_wakeup_thread(kwq, kwe);
#if __TESTPANICS__
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("psynch_mutexdrop_internal: panic unable to wakeup fairshare mutex thread\n");
#endif /* __TESTPANICS__ */
				if (kret == KERN_NOT_WAITING) {
					/* interrupt post */
					kwq->kw_pre_intrcount = 1;
					kwq->kw_pre_intrseq = nextgen;
					kwq->kw_pre_intrretbits = updatebits;
					kwq->kw_pre_intrtype = PTH_RW_TYPE_WRITE;
#if _PSYNCH_TRACE_
					__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfafafaf1, nextgen, kwq->kw_pre_intrretbits, 0);
#endif /* _PSYNCH_TRACE_ */					
				}

			} else if (is_seqhigher(low_writer, nextgen) != 0) {
				kwq->kw_pre_rwwc++;

				if (kwq->kw_pre_rwwc > 1) {
					__FAILEDUSERTEST__("psynch_mutexdrop_internal: prepost more than one (1)\n");
					goto out;
				}

				kwq->kw_pre_lockseq = (nextgen & PTHRW_COUNT_MASK); 
#if _PSYNCH_TRACE_
				__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfefefef1, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
			} else {

				//__FAILEDUSERTEST__("psynch_mutexdrop_internal: FS mutex unlock sequence higher than the lowest one is queue\n");

				kwe = ksyn_queue_find_seq(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], (nextgen & PTHRW_COUNT_MASK), 1);
				if (kwe != NULL) {
					/* next seq to be granted found */
					/* since the grant could be cv, make sure mutex wait is set incase the thread interrupted out */
					kwe->kwe_psynchretval = updatebits | PTH_RWL_MTX_WAIT;
					kwe->kwe_kwqqueue = NULL;
#if _PSYNCH_TRACE_
					__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xcafecaf3, (uint32_t)(thread_tid((struct thread *)(((struct uthread *)(kwe->kwe_uth))->uu_context.vc_thread))), kwe->kwe_psynchretval, 0);
#endif /* _PSYNCH_TRACE_ */
					kret = ksyn_wakeup_thread(kwq, kwe);
#if __TESTPANICS__
					if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
						panic("psynch_mutexdrop_internal: panic unable to wakeup fairshare mutex thread\n");
#endif /* __TESTPANICS__ */
					if (kret == KERN_NOT_WAITING)
						goto redrive;
				} else {
					/* next seq to be granted not found, prepost */
					kwq->kw_pre_rwwc++;

					if (kwq->kw_pre_rwwc > 1) {
						__FAILEDUSERTEST__("psynch_mutexdrop_internal: prepost more than one (2)\n");
						goto out;
					}

					kwq->kw_pre_lockseq = (nextgen & PTHRW_COUNT_MASK); 
#if _PSYNCH_TRACE_
					__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfefefef2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
				}
			}
		} 
	} else {

		/* if firstfit the last one could be spurious */
		if (firstfit == 0) {
			kwq->kw_lastunlockseq = (ugen & PTHRW_COUNT_MASK);
			kwq->kw_pre_rwwc++;

			if (kwq->kw_pre_rwwc > 1) {
				__FAILEDUSERTEST__("psynch_mutexdrop_internal: prepost more than one (3)\n");
				goto out;
			}

			kwq->kw_pre_lockseq = (nextgen & PTHRW_COUNT_MASK); 
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfefefef3, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		} else {
			/* first fit case */
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfefefef3, kwq->kw_lastunlockseq, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
			kwq->kw_lastunlockseq = (ugen & PTHRW_COUNT_MASK);
			/* not set or the new lkseq is higher */
			if ((kwq->kw_pre_rwwc == 0) || (is_seqlower(kwq->kw_pre_lockseq, lkseq) == 0))
				kwq->kw_pre_lockseq = (lkseq & PTHRW_COUNT_MASK);
			kwq->kw_pre_rwwc = 1;
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfefefef3, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */

			/* indicate prepost content in kernel */
			returnbits = lkseq | PTH_RWL_PBIT;
		}
	}

out:
	ksyn_wqunlock(kwq);

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_KMDROP | DBG_FUNC_END, (uint32_t)kwq->kw_addr, 0xeeeeeeed, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(kwq, NULL, 1, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_MTX));
	return(returnbits);
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
	int ins_flags, retry;
	uthread_t uth;
	int firstfit = flags & _PTHREAD_MUTEX_POLICY_FIRSTFIT;
	uint32_t lockseq, updatebits=0;
	ksyn_waitq_element_t kwe;
	kern_return_t kret;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_START, (uint32_t)mutex, mgen, ugen, flags, 0);
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_NONE, (uint32_t)mutex, mgen, ugen, (uint32_t)tid, 0);
#endif /* _PSYNCH_TRACE_ */

	uth = current_uthread();

	kwe = &uth->uu_kwe;
	kwe->kwe_lockseq = uap->mgen;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;
	kwe->kwe_kwqqueue = NULL;
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
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_END, (uint32_t)mutex, 1, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}

	ksyn_wqlock(kwq);


	if ((mgen & PTH_RWL_RETRYBIT) != 0) {
		retry = 1;
		mgen &= ~PTH_RWL_RETRYBIT;
	}

        /* handle first the missed wakeups */
        if ((kwq->kw_pre_intrcount != 0) &&
                ((kwq->kw_pre_intrtype == PTH_RW_TYPE_WRITE)) &&
                (is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {
                kwq->kw_pre_intrcount--;
                kwe->kwe_psynchretval = kwq->kw_pre_intrretbits;
                if (kwq->kw_pre_intrcount==0)
                        CLEAR_INTR_PREPOST_BITS(kwq);
                ksyn_wqunlock(kwq);
				*retval = kwe->kwe_psynchretval;
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_NONE, (uint32_t)mutex, 0xfafafaf1, kwe->kwe_psynchretval, kwq->kw_pre_intrcount, 0);
#endif /* _PSYNCH_TRACE_ */
                goto out;
        }

	if ((kwq->kw_pre_rwwc != 0) && ((ins_flags == FIRSTFIT) || ((lockseq & PTHRW_COUNT_MASK) == (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK) ))) {
		/* got preposted lock */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			CLEAR_PREPOST_BITS(kwq);
			kwq->kw_lastunlockseq = PTHRW_RWL_INIT;
			if (kwq->kw_inqueue == 0) {
				updatebits = lockseq | (PTH_RWL_KBIT | PTH_RWL_EBIT);
			} else {
				updatebits = (kwq->kw_highseq & PTHRW_COUNT_MASK) | (PTH_RWL_KBIT | PTH_RWL_EBIT);
			}
			updatebits &= ~PTH_RWL_MTX_WAIT;
			
			kwe->kwe_psynchretval = updatebits;

			if (updatebits == 0) {
				__FAILEDUSERTEST__("psynch_mutexwait(prepost): returning 0 lseq  in mutexwait with no EBIT \n");
			}
			ksyn_wqunlock(kwq);
			*retval = updatebits;
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfefefef1, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
			goto out;	
		} else {
			__FAILEDUSERTEST__("psynch_mutexwait: more than one prepost\n");
			kwq->kw_pre_lockseq += PTHRW_INC; /* look for next one */
			ksyn_wqunlock(kwq);
			error = EINVAL;
			goto out;
		}
	}
	
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 0xfeedfeed, mgen, ins_flags, 0);
#endif /* _PSYNCH_TRACE_ */
	
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], mgen, uth, kwe, ins_flags);
	if (error != 0) {
		ksyn_wqunlock(kwq);
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_END, (uint32_t)mutex, 2, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
		goto out;
	}
	
	kret = ksyn_block_thread_locked(kwq, (uint64_t)0, kwe, 0, psynch_mtxcontinue, (void *)kwq);

	psynch_mtxcontinue((void *)kwq, kret);

	/* not expected to return from unix_syscall_return */
	panic("psynch_mtxcontinue returned from unix_syscall_return");

out:
	ksyn_wqrelease(kwq, NULL, 1, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_MTX)); 
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_END, (uint32_t)mutex, 0xeeeeeeed, updatebits, error, 0);
#endif /* _PSYNCH_TRACE_ */

	return(error);
}

void 
psynch_mtxcontinue(void * parameter, wait_result_t result)
{
	int error = 0;
	uint32_t updatebits = 0;
	uthread_t uth = current_uthread();
	ksyn_wait_queue_t kwq = (ksyn_wait_queue_t)parameter;
	ksyn_waitq_element_t kwe;

	kwe = &uth->uu_kwe;

	switch (result) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}

	if (error != 0) {
		ksyn_wqlock(kwq);
		
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 3, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
		if (kwe->kwe_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwe);
		ksyn_wqunlock(kwq);
	} else {
		updatebits = kwe->kwe_psynchretval;
		updatebits &= ~PTH_RWL_MTX_WAIT;
		uth->uu_rval[0] = updatebits;

		if (updatebits == 0)
			__FAILEDUSERTEST__("psynch_mutexwait: returning 0 lseq  in mutexwait with no EBIT \n");
	}
	ksyn_wqrelease(kwq, NULL, 1, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_MTX)); 
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_MLWAIT | DBG_FUNC_END, (uint32_t)kwq->kw_addr, 0xeeeeeeed, updatebits, error, 0);
#endif /* _PSYNCH_TRACE_ */

	unix_syscall_return(error);
}

/*
 *  psynch_mutexdrop: This system call is used for unlock postings on contended psynch mutexes.
  */
int
psynch_mutexdrop(__unused proc_t p, struct psynch_mutexdrop_args * uap, uint32_t * retval)
{
	user_addr_t mutex  = uap->mutex;
	uint32_t mgen = uap->mgen;
	uint32_t ugen = uap->ugen;
	uint64_t tid = uap->tid;
	int flags = uap->flags;
	ksyn_wait_queue_t kwq;
	uint32_t updateval;	
	int error=0;

	error = ksyn_wqfind(mutex, mgen, ugen, 0, tid, flags, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_MTX), &kwq);
	if (error != 0) {
		return(error);
	}

	updateval = psynch_mutexdrop_internal(kwq, mgen, ugen, flags);
	/* drops the kwq reference */

	*retval = updateval;
	return(0);

}

/*
 *  psynch_cvbroad: This system call is used for broadcast posting on blocked waiters of psynch cvars.
 */
int
psynch_cvbroad(__unused proc_t p, struct psynch_cvbroad_args * uap, uint32_t * retval)
{
	user_addr_t cond  = uap->cv;
	uint64_t cvlsgen = uap->cvlsgen;
	uint64_t cvudgen = uap->cvudgen;
	uint32_t cgen, cugen, csgen, diffgen;
	uint32_t uptoseq, fromseq;
	int flags = uap->flags;
	ksyn_wait_queue_t ckwq;
	int error=0;
	uint32_t updatebits = 0;
	uint32_t count;
	struct ksyn_queue  kfreeq;

	csgen = (uint32_t)((cvlsgen >> 32) & 0xffffffff);
	cgen = ((uint32_t)(cvlsgen & 0xffffffff));
	cugen = (uint32_t)((cvudgen >> 32) & 0xffffffff);
	diffgen = ((uint32_t)(cvudgen & 0xffffffff));
	count = (diffgen >> PTHRW_COUNT_SHIFT);

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_START, (uint32_t)cond, cgen, cugen, csgen, 0);
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_NONE, (uint32_t)cond, 0xcbcbcbc1, diffgen,flags, 0);
#endif /* _PSYNCH_TRACE_ */

	uptoseq = cgen & PTHRW_COUNT_MASK;
	fromseq = (cugen & PTHRW_COUNT_MASK) + PTHRW_INC;

	if (is_seqhigher(fromseq, uptoseq) || is_seqhigher((csgen & PTHRW_COUNT_MASK), uptoseq)) {
		__FAILEDUSERTEST__("cvbroad: invalid L, U and S values\n");
		return EINVAL;
	}
	if (count > (uint32_t)task_threadmax) {
		__FAILEDUSERTEST__("cvbroad: difference greater than maximum possible thread count\n");
		return EBUSY;
	}

	ckwq = NULL;
	
	error = ksyn_wqfind(cond, cgen, cugen, csgen, 0, flags, (KSYN_WQTYPE_CVAR | KSYN_WQTYPE_INDROP), &ckwq);
	if (error != 0) {
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_END, (uint32_t)cond, 0, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}

	*retval = 0;

	ksyn_wqlock(ckwq);

	/* update L, U and S... */
	UPDATE_CVKWQ(ckwq, cgen, cugen, csgen, 0, KSYN_WQTYPE_CVAR);

	/* broadcast wakeups/prepost handling */
	ksyn_handle_cvbroad(ckwq, uptoseq, &updatebits);

	/* set C or P bits and free if needed */
	ckwq->kw_sword += (updatebits & PTHRW_COUNT_MASK);
	ksyn_cvupdate_fixup(ckwq, &updatebits, &kfreeq, 1);
	ksyn_wqunlock(ckwq);

	*retval = updatebits;

	ksyn_wqrelease(ckwq, NULL, 1, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_CVAR));
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVBROAD | DBG_FUNC_END, (uint32_t)cond, 0xeeeeeeed, (uint32_t)*retval, error, 0);
#endif /* _PSYNCH_TRACE_ */
	
	return(error);
}

ksyn_waitq_element_t
ksyn_queue_find_threadseq(ksyn_wait_queue_t ckwq, __unused ksyn_queue_t kq, thread_t th, uint32_t upto)
{
	uthread_t uth = get_bsdthread_info(th);
	ksyn_waitq_element_t kwe = &uth->uu_kwe;
		
	if (kwe->kwe_kwqqueue != ckwq ||
	    is_seqhigher((kwe->kwe_lockseq & PTHRW_COUNT_MASK), upto)) {
		/* the thread is not waiting in the cv (or wasn't when the wakeup happened) */
		return NULL;
	}
	return kwe;
}

/*
 *  psynch_cvsignal: This system call is used for signalling the  blocked waiters of  psynch cvars.
 */
int
psynch_cvsignal(__unused proc_t p, struct psynch_cvsignal_args * uap, uint32_t * retval)
{
	user_addr_t cond  = uap->cv;
	uint64_t cvlsgen = uap->cvlsgen;
	uint32_t cgen, csgen, signalseq, uptoseq;
	uint32_t cugen = uap->cvugen;
	int threadport = uap->thread_port;
	int flags = uap->flags;
	ksyn_wait_queue_t ckwq = NULL;
	ksyn_waitq_element_t kwe, nkwe = NULL;
	ksyn_queue_t kq;
	int error=0;
	thread_t th = THREAD_NULL;
	uint32_t updatebits = 0;
	kern_return_t kret;
	struct ksyn_queue  kfreeq;


	csgen = (uint32_t)((cvlsgen >> 32) & 0xffffffff);
	cgen = ((uint32_t)(cvlsgen & 0xffffffff));

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_START, (uint32_t)cond, cgen, cugen, threadport, 0);
#endif /* _PSYNCH_TRACE_ */

	uptoseq = cgen & PTHRW_COUNT_MASK;
	signalseq = (cugen & PTHRW_COUNT_MASK) + PTHRW_INC;

	/* validate sane L, U, and S values */
	if (((threadport == 0) && (is_seqhigher(signalseq, uptoseq))) || is_seqhigher((csgen & PTHRW_COUNT_MASK), uptoseq)) {
		__FAILEDUSERTEST__("psync_cvsignal; invalid sequence numbers\n");
		error = EINVAL;
		goto out;
	}

	/* If we are looking for a specific thread, grab a reference for it */
	if (threadport != 0) {
		th = (thread_t)port_name_to_thread((mach_port_name_t)threadport);
		if (th == THREAD_NULL) {
			error = ESRCH;
			goto out;
		}
	}

	error = ksyn_wqfind(cond, cgen, cugen, csgen, 0, flags, (KSYN_WQTYPE_CVAR | KSYN_WQTYPE_INDROP), &ckwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_END, (uint32_t)cond, 0, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */		
		goto out;
	}
	
	ksyn_wqlock(ckwq);

	/* update L, U and S... */
	UPDATE_CVKWQ(ckwq, cgen, cugen, csgen, 0, KSYN_WQTYPE_CVAR);

	kq = &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER];

retry:
	/* Only bother if we aren't already balanced */
	if ((ckwq->kw_lword & PTHRW_COUNT_MASK) != (ckwq->kw_sword & PTHRW_COUNT_MASK)) {

		kwe = (th != NULL) ? ksyn_queue_find_threadseq(ckwq, kq, th, uptoseq) :
			ksyn_queue_find_signalseq(ckwq, kq, uptoseq, signalseq);
		if (kwe != NULL) {
			switch (kwe->kwe_flags) {
				
			case KWE_THREAD_BROADCAST:
				/* broadcasts swallow our signal */
				break;

			case KWE_THREAD_PREPOST:
				/* merge in with existing prepost at our same uptoseq */
				kwe->kwe_count += 1;
				break;

			case KWE_THREAD_INWAIT:
				if (is_seqlower((kwe->kwe_lockseq & PTHRW_COUNT_MASK), signalseq)) {
					/*
					 * A valid thread in our range, but lower than our signal.
					 * Matching it may leave our match with nobody to wake it if/when
					 * it arrives (the signal originally meant for this thread might
					 * not successfully wake it).
					 *
					 * Convert to broadcast - may cause some spurious wakeups
					 * (allowed by spec), but avoids starvation (better choice).
					 */
#if _PSYNCH_TRACE_
					__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xc1c1c1c1, uptoseq, 0, 0);
#endif /* _PSYNCH_TRACE_ */
					ksyn_handle_cvbroad(ckwq, uptoseq, &updatebits);
				} else {
					ksyn_queue_removeitem(ckwq, kq, kwe);
					kwe->kwe_psynchretval = PTH_RWL_MTX_WAIT;
					kwe->kwe_kwqqueue = NULL;
#if _PSYNCH_TRACE_
					__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xcafecaf2, (uint32_t)(thread_tid((struct thread *)(((struct uthread *)(kwe->kwe_uth))->uu_context.vc_thread))), kwe->kwe_psynchretval, 0);
#endif /* _PSYNCH_TRACE_ */
					kret = ksyn_wakeup_thread(ckwq, kwe);
#if __TESTPANICS__
					if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
						panic("ksyn_wakeup_thread: panic waking up condition waiter\n");
#endif /* __TESTPANICS__ */
					updatebits += PTHRW_INC;
				}

				ckwq->kw_sword += (updatebits & PTHRW_COUNT_MASK);
				break;
				
			default: 
				panic("unknown kweflags\n");
				break;
			}

		} else if (th != NULL) {
			/* 
			 * Could not find the thread, post a broadcast, 
			 * otherwise the waiter will be stuck. Use to send
			 * ESRCH here, did lead to rare hangs. 
			 */
			ksyn_handle_cvbroad(ckwq, uptoseq, &updatebits);
			ckwq->kw_sword += (updatebits & PTHRW_COUNT_MASK);
		} else if (nkwe == NULL) {
			ksyn_wqunlock(ckwq);
			nkwe = (ksyn_waitq_element_t)zalloc(kwe_zone);
			ksyn_wqlock(ckwq);
			goto retry;

		} else {
			/* no eligible entries - add prepost */
			bzero(nkwe, sizeof(struct ksyn_waitq_element));
			nkwe->kwe_kwqqueue = ckwq;
			nkwe->kwe_flags = KWE_THREAD_PREPOST;
			nkwe->kwe_lockseq = uptoseq;
			nkwe->kwe_count = 1;
			nkwe->kwe_uth = NULL;
			nkwe->kwe_psynchretval = 0;

#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xfeedfefe, uptoseq, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			
			(void)ksyn_queue_insert(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], uptoseq, NULL, nkwe, SEQFIT);
			ckwq->kw_fakecount++;
			nkwe = NULL;
		}

		/* set C or P bits and free if needed */
		ksyn_cvupdate_fixup(ckwq, &updatebits, &kfreeq, 1);
	}

	ksyn_wqunlock(ckwq);
	if (nkwe != NULL)
		zfree(kwe_zone, nkwe);

	ksyn_wqrelease(ckwq, NULL, 1, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_CVAR));

out:
	if (th != NULL)
		thread_deallocate(th);
	if (error == 0)
		*retval = updatebits;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSIGNAL | DBG_FUNC_END, (uint32_t)cond, 0xeeeeeeed, updatebits, error, 0);
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
	uint64_t cvlsgen = uap->cvlsgen;
	uint32_t cgen, csgen;
	uint32_t cugen = uap->cvugen;
	user_addr_t mutex = uap->mutex;
	uint64_t mugen = uap->mugen;
	uint32_t mgen, ugen;
	int flags = uap->flags;
	ksyn_wait_queue_t kwq, ckwq;
	int error=0, local_error = 0;
	uint64_t abstime = 0;
	uint32_t lockseq, updatebits=0;
	struct timespec  ts;
	uthread_t uth;
	ksyn_waitq_element_t kwe, nkwe = NULL;
	struct ksyn_queue  *kq, kfreeq;
	kern_return_t kret;
	
	/* for conformance reasons */
	__pthread_testcancel(0);

	csgen = (uint32_t)((cvlsgen >> 32) & 0xffffffff);
	cgen = ((uint32_t)(cvlsgen & 0xffffffff));
	ugen = (uint32_t)((mugen >> 32) & 0xffffffff);
	mgen = ((uint32_t)(mugen & 0xffffffff));

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_START, (uint32_t)cond, cgen, cugen, csgen, 0);
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)mutex, mgen, ugen, flags, 0);
#endif /* _PSYNCH_TRACE_ */

	lockseq = (cgen & PTHRW_COUNT_MASK);
	/* 
	 * In cvwait U word can be out of range as cond could be used only for 
	 * timeouts. However S word needs to be within bounds and validated at
	 * user level as well.
	 */
	if (is_seqhigher_eq((csgen & PTHRW_COUNT_MASK), lockseq) != 0) {
		__FAILEDUSERTEST__("psync_cvwait; invalid sequence numbers\n");
		return EINVAL;
	}

	ckwq = kwq = NULL;
	error = ksyn_wqfind(cond, cgen, cugen, csgen, 0, flags, KSYN_WQTYPE_CVAR | KSYN_WQTYPE_INWAIT, &ckwq);
	if (error != 0) {
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_END, (uint32_t)cond, 1, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	

	if (mutex != (user_addr_t)0) {
		error = ksyn_wqfind(mutex, mgen, ugen, 0, 0, flags, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_MTX), &kwq);
		if (error != 0)  {
			local_error = error;
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_END, (uint32_t)mutex, 2, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
			goto out;
		}
		
		(void)psynch_mutexdrop_internal(kwq, mgen, ugen, flags);
		/* drops kwq reference */
		kwq = NULL;
	}

	if (uap->sec != 0 || (uap->nsec & 0x3fffffff)  != 0) {
		ts.tv_sec = uap->sec;
		ts.tv_nsec = (uap->nsec & 0x3fffffff);
		nanoseconds_to_absolutetime((uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec,  &abstime );
		clock_absolutetime_interval_to_deadline( abstime, &abstime );
	}

	ksyn_wqlock(ckwq);

	/* update L, U and S... */
	UPDATE_CVKWQ(ckwq, cgen, cugen, csgen, 0, KSYN_WQTYPE_CVAR);

	/* Look for the sequence for prepost (or conflicting thread */
	kq = &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER];
	kwe = ksyn_queue_find_cvpreposeq(kq, lockseq);

	if (kwe != NULL) {
		switch (kwe->kwe_flags) {

		case KWE_THREAD_INWAIT:
			ksyn_wqunlock(ckwq);
			__FAILEDUSERTEST__("cvwait: thread entry with same sequence already present\n");
			local_error = EBUSY;
			goto out;

		case KWE_THREAD_BROADCAST:
			break;

		case KWE_THREAD_PREPOST:
			if ((kwe->kwe_lockseq & PTHRW_COUNT_MASK) == lockseq) {
				/* we can safely consume a reference, so do so */
				if (--kwe->kwe_count == 0) {
					ksyn_queue_removeitem(ckwq, kq, kwe);
					ckwq->kw_fakecount--;
					nkwe = kwe;
				}
			} else {
				/*
				 * consuming a prepost higher than our lock sequence is valid, but
				 * can leave the higher thread without a match. Convert the entry 
				 * to a broadcast to compensate for this.
				 */
#if _PSYNCH_TRACE_
				__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xc2c2c2c2, kwe->kwe_lockseq, 0, 0);
#endif /* _PSYNCH_TRACE_ */
				
				ksyn_handle_cvbroad(ckwq, kwe->kwe_lockseq, &updatebits);
#if __TESTPANICS__
				if (updatebits != 0)
					panic("psync_cvwait: convert pre-post to broadcast: woke up %d threads that shouldn't be there\n",
					      updatebits);
#endif /* __TESTPANICS__ */
			}

			break;
			
		default:
			panic("psync_cvwait: unexpected wait queue element type\n");
		}

#if _PSYNCH_TRACE_
                                __PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xfefefefe, kwe->kwe_lockseq, 0, 0);
#endif /* _PSYNCH_TRACE_ */


		updatebits = PTHRW_INC;
		ckwq->kw_sword += PTHRW_INC;

		/* set C or P bits and free if needed */
		ksyn_cvupdate_fixup(ckwq, &updatebits, &kfreeq, 1);

		error = 0;
		local_error = 0;

		*retval = updatebits;

		ksyn_wqunlock(ckwq);

		if (nkwe != NULL)
			zfree(kwe_zone, nkwe);

		goto out;

	}
		
	uth = current_uthread();
	kwe = &uth->uu_kwe;
	kwe->kwe_kwqqueue = ckwq;
	kwe->kwe_flags = KWE_THREAD_INWAIT;
	kwe->kwe_lockseq = lockseq;
	kwe->kwe_count = 1;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xfeedfeed, cgen, 0, 0);
#endif /* _PSYNCH_TRACE_ */

	error = ksyn_queue_insert(ckwq, kq, cgen, uth, kwe, SEQFIT);
	if (error != 0) {
		ksyn_wqunlock(ckwq);
		local_error = error;
		goto out;
	}

	kret = ksyn_block_thread_locked(ckwq, abstime, kwe, 1, psynch_cvcontinue, (void *)ckwq);
	/* lock dropped */

	psynch_cvcontinue(ckwq, kret);	
	/* not expected to return from unix_syscall_return */
	panic("psynch_cvcontinue returned from unix_syscall_return");

out:
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_END, (uint32_t)cond, 0xeeeeeeed, (uint32_t)*retval, local_error, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(ckwq, NULL, 1, (KSYN_WQTYPE_INWAIT | KSYN_WQTYPE_CVAR));
	return(local_error);
}


void 
psynch_cvcontinue(void * parameter, wait_result_t result)
{
	int error = 0, local_error = 0;
	uthread_t uth = current_uthread();
	ksyn_wait_queue_t ckwq = (ksyn_wait_queue_t)parameter;
	ksyn_waitq_element_t kwe;
	struct ksyn_queue  kfreeq;

	switch (result) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_THWAKEUP | DBG_FUNC_NONE, 0xf4f3f2f1, (uintptr_t)uth, result, 0, 0);
#endif /* _PSYNCH_TRACE_ */

	local_error = error;
	kwe = &uth->uu_kwe;

	if (error != 0) {
		ksyn_wqlock(ckwq);
		/* just in case it got woken up as we were granting */
		uth->uu_rval[0] = kwe->kwe_psynchretval;

#if __TESTPANICS__
		if ((kwe->kwe_kwqqueue != NULL) && (kwe->kwe_kwqqueue != ckwq))
			panic("cvwait waiting on some other kwq\n");

#endif /* __TESTPANICS__ */


		if (kwe->kwe_kwqqueue != NULL) {
			ksyn_queue_removeitem(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwe);
			kwe->kwe_kwqqueue = NULL;
		}
		if ((kwe->kwe_psynchretval & PTH_RWL_MTX_WAIT) != 0) {
			/* the condition var granted.
			 * reset the error so that the thread returns back.
			 */
			local_error = 0;
			/* no need to set any bits just return as cvsig/broad covers this */
			ksyn_wqunlock(ckwq);
			goto out;
		}

		ckwq->kw_sword += PTHRW_INC;
	
		/* set C and P bits, in the local error */
		if ((ckwq->kw_lword & PTHRW_COUNT_MASK) == (ckwq->kw_sword & PTHRW_COUNT_MASK)) {
			local_error |= ECVCERORR;
			if (ckwq->kw_inqueue != 0) {
				(void)ksyn_queue_move_tofree(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], (ckwq->kw_lword & PTHRW_COUNT_MASK), &kfreeq, 1, 1);
			}
			ckwq->kw_lword = ckwq->kw_uword = ckwq->kw_sword = 0;
			ckwq->kw_kflags |= KSYN_KWF_ZEROEDOUT;
		} else {
			/* everythig in the queue is a fake entry ? */
			if ((ckwq->kw_inqueue != 0) && (ckwq->kw_fakecount == ckwq->kw_inqueue)) {
				local_error |= ECVPERORR;
			}
		}
		ksyn_wqunlock(ckwq);
		
	} else  {
		/* PTH_RWL_MTX_WAIT is removed */
		if ((kwe->kwe_psynchretval & PTH_RWS_CV_MBIT)  != 0)
			uth->uu_rval[0] = PTHRW_INC | PTH_RWS_CV_CBIT;
		else
			uth->uu_rval[0] = 0;
		local_error = 0;
	}
out:
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVWAIT | DBG_FUNC_END, (uint32_t)ckwq->kw_addr, 0xeeeeeeed, uth->uu_rval[0], local_error, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(ckwq, NULL, 1, (KSYN_WQTYPE_INWAIT | KSYN_WQTYPE_CVAR));

	unix_syscall_return(local_error);

}

/*
 *  psynch_cvclrprepost: This system call clears pending prepost if present.
 */
int
psynch_cvclrprepost(__unused proc_t p, struct psynch_cvclrprepost_args * uap, __unused int * retval)
{
	user_addr_t cond  = uap->cv;
	uint32_t cgen = uap->cvgen;
	uint32_t cugen = uap->cvugen;
	uint32_t csgen = uap->cvsgen;
	uint32_t pseq = uap->preposeq;
	uint32_t flags = uap->flags;
	int error;
	ksyn_wait_queue_t ckwq = NULL;
	struct ksyn_queue  kfreeq;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CLRPRE | DBG_FUNC_START, (uint32_t)cond, cgen, cugen, csgen, 0);
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CLRPRE | DBG_FUNC_NONE, (uint32_t)cond, 0xcececece, pseq, flags, 0);
#endif /* _PSYNCH_TRACE_ */

	if ((flags & _PTHREAD_MTX_OPT_MUTEX) == 0) {
		error = ksyn_wqfind(cond, cgen, cugen, csgen, 0, flags, (KSYN_WQTYPE_CVAR | KSYN_WQTYPE_INDROP), &ckwq);
		if (error != 0)  {
			*retval = 0;	
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CLRPRE | DBG_FUNC_END, (uint32_t)cond, 0, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
			return(error);
		}

		ksyn_wqlock(ckwq);
		(void)ksyn_queue_move_tofree(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], (pseq & PTHRW_COUNT_MASK), &kfreeq, 0, 1); 
		ksyn_wqunlock(ckwq);
		ksyn_wqrelease(ckwq, NULL, 1, (KSYN_WQTYPE_CVAR | KSYN_WQTYPE_INDROP));
	} else {
		/* mutex type */
		error = ksyn_wqfind(cond, cgen, cugen, 0, 0, flags, (KSYN_WQTYPE_MTX | KSYN_WQTYPE_INDROP), &ckwq);
		if (error != 0)  {
			*retval = 0;	
#if _PSYNCH_TRACE_
			__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CLRPRE | DBG_FUNC_END, (uint32_t)cond, 0, 0xdeadbeef, error, 0);
#endif /* _PSYNCH_TRACE_ */
			return(error);
		}

		ksyn_wqlock(ckwq);
		if (((flags & _PTHREAD_MUTEX_POLICY_FIRSTFIT) != 0) && (ckwq->kw_pre_rwwc != 0)) {
			if (is_seqlower_eq(ckwq->kw_pre_lockseq, cgen) != 0) {
				/* clear prepost */
				ckwq->kw_pre_rwwc = 0;
				ckwq->kw_pre_lockseq = 0;
			}
		}
		ksyn_wqunlock(ckwq);
		ksyn_wqrelease(ckwq, NULL, 1, (KSYN_WQTYPE_MTX | KSYN_WQTYPE_INDROP));
	}

#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CLRPRE | DBG_FUNC_END, (uint32_t)cond, 0xeeeeeeed, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	return(0);
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
	uint32_t lockseq = 0, updatebits = 0, preseq = 0, prerw_wc = 0;
	ksyn_wait_queue_t kwq;
	uthread_t uth;
	int isinit = lgen & PTHRW_RWL_INIT;
	uint32_t returnbits  = 0;
	ksyn_waitq_element_t kwe;
	kern_return_t kret;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	/* preserve the seq number */
	kwe = &uth->uu_kwe;
	kwe->kwe_lockseq = lgen;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;
	kwe->kwe_kwqqueue = NULL;
	
	lockseq = lgen  & PTHRW_COUNT_MASK;


	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	if (isinit != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0) {
			/* first to notice the reset of the lock, clear preposts */
                	CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
	}

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		((kwq->kw_pre_intrtype == PTH_RW_TYPE_READ) || (kwq->kw_pre_intrtype == PTH_RW_TYPE_LREAD)) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		kwe->kwe_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	/* handle overlap first as they are not counted against pre_rwwc */

	/* check for overlap and if no pending W bit (indicates writers) */
	if ((kwq->kw_overlapwatch != 0) && ((rw_wc & PTHRW_RWS_SAVEMASK) == 0) && ((lgen & PTH_RWL_WBIT) == 0)) { 
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 10, kwq->kw_nextseqword, kwq->kw_lastseqword, 0);
#endif /* _PSYNCH_TRACE_ */
		error = kwq_handle_overlap(kwq, lgen, ugen, rw_wc, &updatebits, (KW_UNLOCK_PREPOST_READLOCK|KW_UNLOCK_PREPOST), &block);
#if __TESTPANICS__
		if (error != 0)
			panic("rw_rdlock: kwq_handle_overlap failed %d\n",error);
#endif /* __TESTPANICS__ */
		if (block == 0) {
			error = 0;
			kwe->kwe_psynchretval = updatebits;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 0xff, updatebits, 0xee, 0);
#endif /* _PSYNCH_TRACE_ */
			ksyn_wqunlock(kwq);
			goto out;
		}
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			prerw_wc = kwq->kw_pre_sseq;
			CLEAR_PREPOST_BITS(kwq);
			if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0){
				kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			}
			error = kwq_handle_unlock(kwq, preseq, prerw_wc, &updatebits, (KW_UNLOCK_PREPOST_READLOCK|KW_UNLOCK_PREPOST), &block, lgen);
#if __TESTPANICS__
			if (error != 0)
				panic("rw_rdlock: kwq_handle_unlock failed %d\n",error);
#endif /* __TESTPANICS__ */
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}


#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_READ], lgen, uth, kwe, SEQFIT);
#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_rdlock: failed to enqueue\n");
#endif /* __TESTPANICS__ */
	kret = ksyn_block_thread_locked(kwq, (uint64_t)0, kwe, 0, THREAD_CONTINUE_NULL, NULL);
	/* drops the kwq lock */
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}
	
out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (kwe->kwe_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_READ], kwe);
		ksyn_wqunlock(kwq);
	} else {
		/* update bits */
		*retval = kwe->kwe_psynchretval;
		returnbits = kwe->kwe_psynchretval;
	}
	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK)); 
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, returnbits, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

/*
 *  psynch_rw_longrdlock: This system call is used for psync rwlock long readers to block.
 */
int
#ifdef NOTYET
psynch_rw_longrdlock(__unused proc_t p, struct psynch_rw_longrdlock_args * uap,  __unused uint32_t * retval)
#else /* NOTYET */
psynch_rw_longrdlock(__unused proc_t p, __unused struct psynch_rw_longrdlock_args * uap,  __unused uint32_t * retval)
#endif /* NOTYET */
{
#ifdef NOTYET
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	int isinit = lgen & PTHRW_RWL_INIT;
	uint32_t returnbits=0;
	ksyn_waitq_element_t kwe;
	kern_return_t kret;

	ksyn_wait_queue_t kwq;
	int error=0, block = 0 ;
	uthread_t uth;
	uint32_t lockseq = 0, updatebits = 0, preseq = 0, prerw_wc = 0;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();
	kwe = &uth->uu_kwe;
	kwe->kwe_lockseq = lgen;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;
	kwe->kwe_kwqqueue = NULL;
	lockseq = (lgen & PTHRW_COUNT_MASK);
	
	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	if (isinit != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0) {
			/* first to notice the reset of the lock, clear preposts */
                	CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
	}

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_LREAD) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		kwe->kwe_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}


	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			prerw_wc = kwq->kw_pre_sseq;
			CLEAR_PREPOST_BITS(kwq);
			if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0){
				kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			}
			error = kwq_handle_unlock(kwq, preseq, prerw_wc, &updatebits, (KW_UNLOCK_PREPOST_LREADLOCK|KW_UNLOCK_PREPOST), &block, lgen);
#if __TESTPANICS__
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
#endif /* __TESTPANICS__ */
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_LREAD], lgen, uth, kwe, SEQFIT);
#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_longrdlock: failed to enqueue\n");
#endif /* __TESTPANICS__ */

	kret = ksyn_block_thread_locked(kwq, (uint64_t)0, kwe, 0, THREAD_CONTINUE_NULL, NULL);
	/* drops the kwq lock */
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}
out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (kwe->kwe_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_LREAD], kwe);
		ksyn_wqunlock(kwq);
	} else {
		/* update bits */
		*retval = kwe->kwe_psynchretval;
		returnbits = kwe->kwe_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK)); 

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWLRDLOCK | DBG_FUNC_END, (uint32_t)rwlock, 0, returnbits, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
#else /* NOTYET */
	return(ESRCH);
#endif /* NOTYET */
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
	uint32_t lockseq = 0, updatebits = 0, preseq = 0, prerw_wc = 0;
	int isinit = lgen & PTHRW_RWL_INIT;
	uint32_t returnbits  = 0;
	ksyn_waitq_element_t kwe;
	kern_return_t kret;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();
	kwe = &uth->uu_kwe;
	kwe->kwe_lockseq = lgen;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;
	kwe->kwe_kwqqueue = NULL;
	lockseq = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);


	if (isinit != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0) {
			/* first to notice the reset of the lock, clear preposts */
                	CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
	}


	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_WRITE) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		kwe->kwe_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}


	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			prerw_wc = kwq->kw_pre_sseq;
			CLEAR_PREPOST_BITS(kwq);
			if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0){
				kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			}
			error = kwq_handle_unlock(kwq, preseq, prerw_wc, &updatebits, (KW_UNLOCK_PREPOST_WRLOCK|KW_UNLOCK_PREPOST), &block, lgen);
#if __TESTPANICS__
			if (error != 0)
				panic("rw_wrlock: kwq_handle_unlock failed %d\n",error);
#endif /* __TESTPANICS__ */
			if (block == 0) {
				ksyn_wqunlock(kwq);
				*retval = updatebits;
				goto out1;
			}
			/* insert to q and proceed as ususal */
		} 
	}

	/* No overlap watch needed  go ahead and block */

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], lgen, uth, kwe, SEQFIT);
#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_wrlock: failed to enqueue\n");
#endif /* __TESTPANICS__ */

	kret = ksyn_block_thread_locked(kwq, (uint64_t)0, kwe, 0, THREAD_CONTINUE_NULL, NULL);
	/* drops the wq lock */
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}

out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (kwe->kwe_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwe);
		ksyn_wqunlock(kwq);
	} else  {
		/* update bits */
		*retval = kwe->kwe_psynchretval;
		returnbits = kwe->kwe_psynchretval;
	}
out1:
	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK)); 

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, returnbits, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

/*
 *  psynch_rw_yieldwrlock: This system call is used for psync rwlock yielding writers to block.
 */
int
#ifdef NOTYET
psynch_rw_yieldwrlock(__unused proc_t p, __unused struct  psynch_rw_yieldwrlock_args * uap, __unused uint32_t * retval)
#else /* NOTYET */
psynch_rw_yieldwrlock(__unused proc_t p, __unused struct  __unused psynch_rw_yieldwrlock_args * uap, __unused uint32_t * retval)
#endif /* NOTYET */
{
#ifdef NOTYET
	user_addr_t rwlock  = uap->rwlock;
	uint32_t lgen = uap->lgenval;
	uint32_t ugen = uap->ugenval;
	uint32_t rw_wc = uap->rw_wc;
	//uint64_t tid = uap->tid;
	int flags = uap->flags;
	int block;
	ksyn_wait_queue_t kwq;
	int error=0;
	int isinit = lgen & PTHRW_RWL_INIT;
	uthread_t uth;
	uint32_t returnbits=0;
	ksyn_waitq_element_t kwe;
	kern_return_t kret;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uint32_t lockseq = 0, updatebits = 0, preseq = 0, prerw_wc = 0;

	uth = current_uthread();
	kwe = &uth->uu_kwe;
	kwe->kwe_lockseq = lgen;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;
	kwe->kwe_kwqqueue = NULL;
	lockseq = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT|KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	if (isinit != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0) {
			/* first to notice the reset of the lock, clear preposts */
                	CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
	}

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		(kwq->kw_pre_intrtype == PTH_RW_TYPE_YWRITE) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		kwe->kwe_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			prerw_wc = kwq->kw_pre_sseq;
			CLEAR_PREPOST_BITS(kwq);
			if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0){
				kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			}
			error = kwq_handle_unlock(kwq, preseq,  prerw_wc, &updatebits, (KW_UNLOCK_PREPOST_YWRLOCK|KW_UNLOCK_PREPOST), &block, lgen);
#if __TESTPANICS__
			if (error != 0)
				panic("kwq_handle_unlock failed %d\n",error);
#endif /* __TESTPANICS__ */
			if (block == 0) {
				ksyn_wqunlock(kwq);
				*retval = updatebits;
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER], lgen, uth, kwe, SEQFIT);
#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_yieldwrlock: failed to enqueue\n");
#endif /* __TESTPANICS__ */

	kret = ksyn_block_thread_locked(kwq, (uint64_t)0, kwe, 0, THREAD_CONTINUE_NULL, NULL);
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}

out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (kwe->kwe_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER], kwe);
		ksyn_wqunlock(kwq);
	} else  {
		/* update bits */
		*retval = kwe->kwe_psynchretval;
		returnbits = kwe->kwe_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INWAIT | KSYN_WQTYPE_RWLOCK)); 

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWYWRLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, returnbits, error, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
#else /* NOTYET */
	return(ESRCH);
#endif /* NOTYET */
}

#if NOTYET
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
	int isinit = lgen & PTHRW_RWL_INIT;
	ksyn_wait_queue_t kwq;
	int error=0;
	uthread_t uth;
	uint32_t curgen = 0;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	curgen = (lgen & PTHRW_COUNT_MASK);

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);
	
	if ((lgen & PTHRW_RWL_INIT) != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0){
			CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
		isinit = 1;
	} 

	/* if lastunlock seq is set, ensure the current one is not lower than that, as it would be spurious */
	if ((kwq->kw_lastunlockseq != PTHRW_RWL_INIT) && (is_seqlower(ugen, kwq->kw_lastunlockseq)!= 0)) {
		/* spurious  updatebits?? */
		error = 0;
		goto out;
	}



	/* If L-U != num of waiters, then it needs to be preposted or spr */
	diff = find_diff(lgen, ugen);
	/* take count of  the downgrade thread itself */
	diff--;


#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_inqueue, curgen, 0);
#endif /* _PSYNCH_TRACE_ */
	if (find_seq_till(kwq, curgen, diff, &count) == 0) {
		if (count < (uint32_t)diff)
			goto prepost;
	}

	/* no prepost and all threads are in place, reset the bit */
	if ((isinit != 0) && ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0)){
		kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	}

	/* can handle unlock now */
		
	CLEAR_PREPOST_BITS(kwq);

dounlock:		
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = kwq_handle_downgrade(kwq, lgen, 0, 0, NULL);

#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_downgrade: failed to wakeup\n");
#endif /* __TESTPANICS__ */

out:
	ksyn_wqunlock(kwq);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_END, (uint32_t)rwlock, 0, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_RWLOCK)); 

	return(error);
		
prepost:
	kwq->kw_pre_rwwc = (rw_wc - count);
	kwq->kw_pre_lockseq = lgen;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWDOWNGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
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
	int isinit = lgen & PTHRW_RWL_INIT;
	ksyn_waitq_element_t kwe;
	kern_return_t kret;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();
	kwe = &uth->uu_kwe;
	kwe->kwe_lockseq = lgen;
	kwe->kwe_uth = uth;
	kwe->kwe_psynchretval = 0;
	kwe->kwe_kwqqueue = NULL;
	lockseq = (lgen & PTHRW_COUNT_MASK);
	
	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INWAIT | KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	ksyn_wqlock(kwq);

	if (isinit != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0) {
			/* first to notice the reset of the lock, clear preposts */
                	CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
	}

	/* handle first the missed wakeups */
	if ((kwq->kw_pre_intrcount != 0) && 
		((kwq->kw_pre_intrtype == PTH_RW_TYPE_READ) || (kwq->kw_pre_intrtype == PTH_RW_TYPE_LREAD)) && 
		(is_seqlower_eq(lockseq, (kwq->kw_pre_intrseq & PTHRW_COUNT_MASK)) != 0)) {

		kwq->kw_pre_intrcount--;
		kwe->kwe_psynchretval = kwq->kw_pre_intrretbits;
		if (kwq->kw_pre_intrcount==0) 
			CLEAR_INTR_PREPOST_BITS(kwq);	
		ksyn_wqunlock(kwq);
		goto out;
	}

	if ((kwq->kw_pre_rwwc != 0) && (is_seqlower_eq(lockseq, (kwq->kw_pre_lockseq & PTHRW_COUNT_MASK)) != 0)) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWRDLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		kwq->kw_pre_rwwc--;
		if (kwq->kw_pre_rwwc == 0) {
			preseq = kwq->kw_pre_lockseq;
			prerw_wc = kwq->kw_pre_sseq;
			CLEAR_PREPOST_BITS(kwq);
			if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0){
				kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
			}
			error = kwq_handle_unlock(kwq, preseq, prerw_wc, &updatebits, (KW_UNLOCK_PREPOST_UPGRADE|KW_UNLOCK_PREPOST), &block, lgen);
#if __TESTPANICS__
			if (error != 0)
				panic("rw_rdlock: kwq_handle_unlock failed %d\n",error);
#endif /* __TESTPANICS__ */
			if (block == 0) {
				ksyn_wqunlock(kwq);
				goto out;
			}
			/* insert to q and proceed as ususal */
		}
	}
	

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 3, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = ksyn_queue_insert(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE], lgen, uth, kwe, SEQFIT);
#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_upgrade: failed to enqueue\n");
#endif /* __TESTPANICS__ */


	kret = ksyn_block_thread_locked(kwq, (uint64_t)0, kwe, 0, THREAD_CONTINUE_NULL, NULL);
	/* drops the lock */
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
		default:
			error = 0;
			break;
	}
	
out:
	if (error != 0) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_NONE, (uint32_t)rwlock, 4, error, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		ksyn_wqlock(kwq);
		if (kwe->kwe_kwqqueue != NULL)
			ksyn_queue_removeitem(kwq, &kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE], kwe);
		ksyn_wqunlock(kwq);
	} else {
		/* update bits */
		*retval = kwe->kwe_psynchretval;
	}

	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INWAIT | KSYN_WQTYPE_RWLOCK)); 
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUPGRADE | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */

	return(error);
}

#else /* NOTYET */
int
psynch_rw_upgrade(__unused proc_t p, __unused struct psynch_rw_upgrade_args * uap, __unused uint32_t * retval)
{
	return(0);
}
int
psynch_rw_downgrade(__unused proc_t p, __unused struct psynch_rw_downgrade_args * uap, __unused int * retval)
{
	return(0);
}
#endif /* NOTYET */
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
	int error=0, diff;
	uint32_t count = 0;
	int isinit = 0;
	

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_START, (uint32_t)rwlock, lgen, ugen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	uth = current_uthread();

	error = ksyn_wqfind(rwlock, lgen, ugen, rw_wc, TID_ZERO, flags, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_RWLOCK), &kwq);
	if (error != 0)  {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_END, (uint32_t)rwlock, 1, 0, error, 0);
#endif /* _PSYNCH_TRACE_ */
		return(error);
	}
	
	curgen = lgen & PTHRW_COUNT_MASK;

	ksyn_wqlock(kwq);

	if ((lgen & PTHRW_RWL_INIT) != 0) {
		lgen &= ~PTHRW_RWL_INIT;
		if ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) == 0){
			CLEAR_REINIT_BITS(kwq);
			kwq->kw_kflags |= KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 1, 0);
#endif /* _PSYNCH_TRACE_ */
		}
		isinit = 1;
	} 

	/* if lastunlock seq is set, ensure the current one is not lower than that, as it would be spurious */
	if ((kwq->kw_lastunlockseq != PTHRW_RWL_INIT) && (is_seqlower(ugen, kwq->kw_lastunlockseq)!= 0)) {
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, (uint32_t)0xeeeeeeee, rw_wc, kwq->kw_lastunlockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		error = 0;
		goto out;
	}

	/* If L-U != num of waiters, then it needs to be preposted or spr */
	diff = find_diff(lgen, ugen);

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 1, kwq->kw_inqueue, curgen, 0);
#endif /* _PSYNCH_TRACE_ */
	if (find_seq_till(kwq, curgen, diff, &count) == 0) {
		if ((count == 0) || (count < (uint32_t)diff))
			goto prepost;
	}

	/* no prepost and all threads are in place, reset the bit */
	if ((isinit != 0) && ((kwq->kw_kflags & KSYN_KWF_INITCLEARED) != 0)){
		kwq->kw_kflags &= ~KSYN_KWF_INITCLEARED;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, lgen, ugen, rw_wc, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	}

	/* can handle unlock now */
		
	CLEAR_PREPOST_BITS(kwq);

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 2, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	error = kwq_handle_unlock(kwq, lgen, rw_wc,  &updatebits, 0, NULL, 0);
#if __TESTPANICS__
	if (error != 0)
		panic("psynch_rw_unlock: kwq_handle_unlock failed %d\n",error);
#endif /* __TESTPANICS__ */
out:
	if (error == 0) {
		/* update bits?? */
		*retval = updatebits;
	}


	ksyn_wqunlock(kwq);

	ksyn_wqrelease(kwq, NULL, 0, (KSYN_WQTYPE_INDROP | KSYN_WQTYPE_RWLOCK)); 
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_END, (uint32_t)rwlock, 0, updatebits, error, 0);
#endif /* _PSYNCH_TRACE_ */

	return(error);
		
prepost:
	/* update if the new seq is higher than prev prepost, or first set */
	if ((is_rws_setseq(kwq->kw_pre_sseq) != 0) || 
			(is_seqhigher_eq((rw_wc & PTHRW_COUNT_MASK), (kwq->kw_pre_sseq & PTHRW_COUNT_MASK)) != 0)) {
		kwq->kw_pre_rwwc = (diff - count);
		kwq->kw_pre_lockseq = curgen;
		kwq->kw_pre_sseq = rw_wc;
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 3, rw_wc, count, 0);
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWUNLOCK | DBG_FUNC_NONE, (uint32_t)rwlock, 4, kwq->kw_pre_rwwc, kwq->kw_pre_lockseq, 0);
#endif /* _PSYNCH_TRACE_ */
		updatebits = lgen;	/* let this not do unlock handling */
	}
	error = 0;
	goto out;
}


/*
 *  psynch_rw_unlock2: This system call is used to wakeup pending readers when  unlock grant frm kernel
 *			  to new reader arrival races
 */
int
psynch_rw_unlock2(__unused proc_t p, __unused struct psynch_rw_unlock2_args  * uap, __unused uint32_t * retval)
{
	return(ENOTSUP);
}


/* ************************************************************************** */
void
pth_global_hashinit()
{
	int arg;

	pth_glob_hashtbl = hashinit(PTH_HASHSIZE * 4, M_PROC, &pthhash);

	/*
	 * pthtest={0,1,2,3} (override default aborting behavior on pthread sync failures)
	 * 0 - just return errors
	 * 1 - print and return errors
	 * 2 - abort user, print and return errors
	 * 3 - panic
	 */
	if (!PE_parse_boot_argn("pthtest", &arg, sizeof(arg)))
		arg = __TESTMODE__;

	if (arg == 3) {
		__test_panics__ = 1;
		printf("Pthread support PANICS when sync kernel primitives misused\n");
	} else if (arg == 2) {
		__test_aborts__ = 1;
		__test_prints__ = 1;
		printf("Pthread support ABORTS when sync kernel primitives misused\n");
	} else if (arg == 1) {
		__test_prints__ = 1;
		printf("Pthread support LOGS when sync kernel primitives misused\n");
	}
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

#if _PSYNCH_TRACE_
	if ((pthread_debug_proc != NULL) && (p == pthread_debug_proc))
		pthread_debug_proc = PROC_NULL;
#endif /* _PSYNCH_TRACE_ */
	hashptr = p->p_pthhash;
	p->p_pthhash = NULL;
	if (hashptr == NULL)
		return;

	pthread_list_lock();
	for(i= 0; i < hashsize; i++) {
		while ((kwq = LIST_FIRST(&hashptr[i])) != NULL) {
			if ((kwq->kw_pflags & KSYN_WQ_INHASH) != 0) {
				kwq->kw_pflags &= ~KSYN_WQ_INHASH;
				LIST_REMOVE(kwq, kw_hash);
			}
			if ((kwq->kw_pflags & KSYN_WQ_FLIST) != 0) {
				kwq->kw_pflags &= ~KSYN_WQ_FLIST;
				LIST_REMOVE(kwq, kw_list);
				num_infreekwq--;
			}
			num_freekwq++;
			pthread_list_unlock();
			/* release fake entries if present for cvars */
			if (((kwq->kw_type & KSYN_WQTYPE_MASK) == KSYN_WQTYPE_CVAR) && (kwq->kw_inqueue != 0))
				ksyn_freeallkwe(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER]);
			lck_mtx_destroy(&kwq->kw_lock, pthread_lck_grp);
			zfree(kwq_zone, kwq);
			pthread_list_lock();
		}
	}
	pthread_list_unlock();
	FREE(hashptr, M_PROC);
}

/* no lock held for this as the waitqueue is getting freed */
void
ksyn_freeallkwe(ksyn_queue_t kq)
{
	ksyn_waitq_element_t kwe;

	/* free all the fake entries, dequeue rest */
	kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
	while (kwe != NULL) {
		if (kwe->kwe_flags != KWE_THREAD_INWAIT) {
			TAILQ_REMOVE(&kq->ksynq_kwelist, kwe, kwe_list);
			zfree(kwe_zone, kwe);
		} else {
			TAILQ_REMOVE(&kq->ksynq_kwelist, kwe, kwe_list);
		}
		kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
	}
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
	int retry = mgen & PTH_RWL_RETRYBIT;
	struct ksyn_queue kfreeq;
	int i;

	if ((flags & PTHREAD_PSHARED_FLAGS_MASK) == PTHREAD_PROCESS_SHARED) 
	{
		(void)ksyn_findobj(mutex, &object, &offset);
		hashhint = object;
		hashptr = pth_glob_hashtbl;
	} else {
		hashptr = p->p_pthhash;
	}

	ksyn_queue_init(&kfreeq);

	if (((wqtype & KSYN_WQTYPE_MASK) == KSYN_WQTYPE_MTX) && (retry != 0))
		mgen &= ~PTH_RWL_RETRYBIT;

loop:
	//pthread_list_lock_spin();
	pthread_list_lock();

	kwq = ksyn_wq_hash_lookup(mutex, p, flags, object, offset);

	if (kwq != NULL) {
		if ((kwq->kw_pflags & KSYN_WQ_FLIST) != 0) {
			LIST_REMOVE(kwq, kw_list);
			kwq->kw_pflags &= ~KSYN_WQ_FLIST;
			num_infreekwq--;
			num_reusekwq++;
		}
		if ((kwq->kw_type & KSYN_WQTYPE_MASK) != (wqtype &KSYN_WQTYPE_MASK)) {
			if ((kwq->kw_inqueue == 0) && (kwq->kw_pre_rwwc ==0) && (kwq->kw_pre_intrcount == 0)) {
				if (kwq->kw_iocount == 0) {
					kwq->kw_addr = mutex;
					kwq->kw_flags = flags;
					kwq->kw_object = object;
					kwq->kw_offset = offset;
					kwq->kw_type = (wqtype & KSYN_WQTYPE_MASK);
					CLEAR_REINIT_BITS(kwq);
					CLEAR_INTR_PREPOST_BITS(kwq);
					CLEAR_PREPOST_BITS(kwq);
					kwq->kw_lword = mgen;
					kwq->kw_uword = ugen;
					kwq->kw_sword = rw_wc;
					kwq->kw_owner = tid;
				} else if ((kwq->kw_iocount == 1) && (kwq->kw_dropcount == kwq->kw_iocount)) {
					/* if all users are unlockers then wait for it to finish */
					kwq->kw_pflags |= KSYN_WQ_WAITING;
					/* wait for the wq to be free */
					(void)msleep(&kwq->kw_pflags, pthread_list_mlock, PDROP, "ksyn_wqfind", 0);
					/* does not have list lock */
					goto loop;
				} else {
					__FAILEDUSERTEST__("address already known to kernel for another (busy) synchronizer type\n");
					pthread_list_unlock();
					return EBUSY;
				}
			} else {
				__FAILEDUSERTEST__("address already known to kernel for another (busy) synchronizer type(1)\n");
				pthread_list_unlock();
				return EBUSY;
			}
		}
		kwq->kw_iocount++;
		if (wqtype == KSYN_WQTYPE_MUTEXDROP)
			kwq->kw_dropcount++;
		if (kwqp != NULL)
			*kwqp = kwq;
		pthread_list_unlock();
		return (0);
	}

	pthread_list_unlock();

	nkwq = (ksyn_wait_queue_t)zalloc(kwq_zone);
	bzero(nkwq, sizeof(struct ksyn_wait_queue));
	nkwq->kw_addr = mutex;
	nkwq->kw_flags = flags;
	nkwq->kw_iocount = 1;
	if (wqtype == KSYN_WQTYPE_MUTEXDROP)
			nkwq->kw_dropcount++;
	nkwq->kw_object = object;
	nkwq->kw_offset = offset;
	nkwq->kw_type = (wqtype & KSYN_WQTYPE_MASK);
	nkwq->kw_lastseqword = PTHRW_RWS_INIT;
	if (nkwq->kw_type == KSYN_WQTYPE_RWLOCK)
		nkwq->kw_nextseqword = PTHRW_RWS_INIT;
		
	nkwq->kw_pre_sseq = PTHRW_RWS_INIT;

	CLEAR_PREPOST_BITS(nkwq);
	CLEAR_INTR_PREPOST_BITS(nkwq);
	CLEAR_REINIT_BITS(nkwq);
	nkwq->kw_lword = mgen;
	nkwq->kw_uword = ugen;
	nkwq->kw_sword = rw_wc;
	nkwq->kw_owner = tid;


	for (i=0; i< KSYN_QUEUE_MAX; i++) 
		ksyn_queue_init(&nkwq->kw_ksynqueues[i]);
		
	lck_mtx_init(&nkwq->kw_lock, pthread_lck_grp, pthread_lck_attr);

	//pthread_list_lock_spin();
	pthread_list_lock();
	/* see whether it is alread allocated */
	kwq = ksyn_wq_hash_lookup(mutex, p, flags, object, offset);

	if (kwq != NULL) {
		if ((kwq->kw_pflags & KSYN_WQ_FLIST) != 0) {
			LIST_REMOVE(kwq, kw_list);
			kwq->kw_pflags &= ~KSYN_WQ_FLIST;
			num_infreekwq--;
			num_reusekwq++;
		}
		if ((kwq->kw_type & KSYN_WQTYPE_MASK) != (wqtype &KSYN_WQTYPE_MASK)) {
			if ((kwq->kw_inqueue == 0) && (kwq->kw_pre_rwwc ==0) && (kwq->kw_pre_intrcount == 0)) {
				if (kwq->kw_iocount == 0) {
					kwq->kw_addr = mutex;
					kwq->kw_flags = flags;
					kwq->kw_object = object;
					kwq->kw_offset = offset;
					kwq->kw_type = (wqtype & KSYN_WQTYPE_MASK);
					CLEAR_REINIT_BITS(kwq);
					CLEAR_INTR_PREPOST_BITS(kwq);
					CLEAR_PREPOST_BITS(kwq);
					kwq->kw_lword = mgen;
					kwq->kw_uword = ugen;
					kwq->kw_sword = rw_wc;
					kwq->kw_owner = tid;
				} else if ((kwq->kw_iocount == 1) && (kwq->kw_dropcount == kwq->kw_iocount)) {
					kwq->kw_pflags |= KSYN_WQ_WAITING;
					/* wait for the wq to be free */
					(void)msleep(&kwq->kw_pflags, pthread_list_mlock, PDROP, "ksyn_wqfind", 0);

					lck_mtx_destroy(&nkwq->kw_lock, pthread_lck_grp);
					zfree(kwq_zone, nkwq);
					/* will acquire lock again */

					goto loop;
				} else {
					__FAILEDUSERTEST__("address already known to kernel for another [busy] synchronizer type(2)\n");
					pthread_list_unlock();
					lck_mtx_destroy(&nkwq->kw_lock, pthread_lck_grp);
					zfree(kwq_zone, nkwq);
					return EBUSY;
				}
			} else {
				__FAILEDUSERTEST__("address already known to kernel for another [busy] synchronizer type(3)\n");
				pthread_list_unlock();
				lck_mtx_destroy(&nkwq->kw_lock, pthread_lck_grp);
				zfree(kwq_zone, nkwq);
				return EBUSY;
			}
		}
		kwq->kw_iocount++;
		if (wqtype == KSYN_WQTYPE_MUTEXDROP)
			kwq->kw_dropcount++;
		if (kwqp != NULL)
			*kwqp = kwq;
		pthread_list_unlock();
		lck_mtx_destroy(&nkwq->kw_lock, pthread_lck_grp);
		zfree(kwq_zone, nkwq);
		return (0);
	}
	kwq = nkwq;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVSEQ | DBG_FUNC_NONE, kwq->kw_lword, kwq->kw_uword, kwq->kw_sword, 0xffff, 0);
#endif /* _PSYNCH_TRACE_ */
	if ((flags & PTHREAD_PSHARED_FLAGS_MASK) == PTHREAD_PROCESS_SHARED) 
	{
		kwq->kw_pflags |= KSYN_WQ_SHARED;
		LIST_INSERT_HEAD(&hashptr[kwq->kw_object & pthhash], kwq, kw_hash);
	} else
		LIST_INSERT_HEAD(&hashptr[mutex & pthhash], kwq, kw_hash);

	kwq->kw_pflags |= KSYN_WQ_INHASH;
	num_total_kwq++;

	pthread_list_unlock();

	if (kwqp != NULL)
		*kwqp = kwq;
        return (0);
}

/* Reference from find is dropped here. Starts the free process if needed  */
void
ksyn_wqrelease(ksyn_wait_queue_t kwq, ksyn_wait_queue_t ckwq, int qfreenow, int wqtype)
{
	uint64_t deadline;
	struct timeval t;
	int sched = 0;
	ksyn_wait_queue_t free_elem = NULL;
	ksyn_wait_queue_t free_elem1 = NULL;
	
	//pthread_list_lock_spin();
	pthread_list_lock();
	kwq->kw_iocount--;
	if (wqtype == KSYN_WQTYPE_MUTEXDROP) {
		kwq->kw_dropcount--;
	}
	if (kwq->kw_iocount == 0) {
		if ((kwq->kw_pflags & KSYN_WQ_WAITING) != 0) {
			/* some one is waiting for the waitqueue, wake them up */
			kwq->kw_pflags &=  ~KSYN_WQ_WAITING;
			wakeup(&kwq->kw_pflags);
		}

		if ((kwq->kw_pre_rwwc == 0) && (kwq->kw_inqueue == 0) && (kwq->kw_pre_intrcount == 0)) {
			if (qfreenow == 0) {
				microuptime(&kwq->kw_ts);
				LIST_INSERT_HEAD(&pth_free_list, kwq, kw_list);
				kwq->kw_pflags |= KSYN_WQ_FLIST;
				num_infreekwq++;
				free_elem = NULL;
			} else {
				/* remove from the only list it is in ie hash */
				kwq->kw_pflags &= ~(KSYN_WQ_FLIST | KSYN_WQ_INHASH);
				LIST_REMOVE(kwq, kw_hash);
				lck_mtx_destroy(&kwq->kw_lock, pthread_lck_grp);
				num_total_kwq--;
				num_freekwq++;
				free_elem = kwq;
			}
		} else 
			free_elem = NULL;
		if (qfreenow == 0)
			sched = 1;
	}

	if (ckwq != NULL) {
		ckwq->kw_iocount--;
		if (wqtype == KSYN_WQTYPE_MUTEXDROP) {
			kwq->kw_dropcount--;
		}
		if ( ckwq->kw_iocount == 0) {
			if ((kwq->kw_pflags & KSYN_WQ_WAITING) != 0) {
				/* some one is waiting for the waitqueue, wake them up */
				kwq->kw_pflags &=  ~KSYN_WQ_WAITING;
				wakeup(&kwq->kw_pflags);
			}
			if ((ckwq->kw_pre_rwwc == 0) && (ckwq->kw_inqueue == 0) && (ckwq->kw_pre_intrcount == 0)) {
				if (qfreenow == 0) {
					/* mark for free if we can */
					microuptime(&ckwq->kw_ts);
					LIST_INSERT_HEAD(&pth_free_list, ckwq, kw_list);
					ckwq->kw_pflags |= KSYN_WQ_FLIST;
					num_infreekwq++;
					free_elem1 = NULL;
				} else {
					/* remove from the only list it is in ie hash */
					ckwq->kw_pflags &= ~(KSYN_WQ_FLIST | KSYN_WQ_INHASH);
					LIST_REMOVE(ckwq, kw_hash);
					lck_mtx_destroy(&ckwq->kw_lock, pthread_lck_grp);
					num_total_kwq--;
					num_freekwq++;
					free_elem1 = ckwq;
				}
			} else
				free_elem1 = NULL;
			if (qfreenow == 0)
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
	if (free_elem != NULL)
		zfree(kwq_zone, free_elem);
	if (free_elem1 != NULL)
		zfree(kwq_zone, free_elem1);
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

	num_addedfreekwq = num_infreekwq - num_lastfreekwqcount;
	num_lastfreekwqcount = num_infreekwq;
	microuptime(&t);

	LIST_FOREACH(kwq, &pth_free_list, kw_list) {
		if ((kwq->kw_iocount != 0) || (kwq->kw_pre_rwwc != 0) || (kwq->kw_inqueue != 0) || (kwq->kw_pre_intrcount != 0)) {
			/* still in use */
			continue;
		}
		diff = t.tv_sec - kwq->kw_ts.tv_sec;
		if (diff < 0) 
			diff *= -1;
		if (diff >= KSYN_CLEANUP_DEADLINE) {
			/* out of hash */
			kwq->kw_pflags &= ~(KSYN_WQ_FLIST | KSYN_WQ_INHASH);
			num_infreekwq--;
			num_freekwq++;
			LIST_REMOVE(kwq, kw_hash);
			LIST_REMOVE(kwq, kw_list);
			LIST_INSERT_HEAD(&freelist, kwq, kw_list);
			count ++;
			num_total_kwq--;
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
		zfree(kwq_zone, kwq);
	}
}


kern_return_t
#if _PSYNCH_TRACE_
ksyn_block_thread_locked(ksyn_wait_queue_t kwq, uint64_t abstime, ksyn_waitq_element_t kwe, int mylog, thread_continue_t continuation, void * parameter)
#else
ksyn_block_thread_locked(ksyn_wait_queue_t kwq, uint64_t abstime, ksyn_waitq_element_t kwe, __unused int mylog, thread_continue_t continuation, void * parameter)
#endif
{
	kern_return_t kret;
#if _PSYNCH_TRACE_
	int error = 0;
	uthread_t uth = NULL;
#endif /* _PSYNCH_TRACE_ */

	kwe->kwe_kwqqueue = (void *)kwq;
	assert_wait_deadline(&kwe->kwe_psynchretval, THREAD_ABORTSAFE, abstime);
	ksyn_wqunlock(kwq);

	if (continuation == THREAD_CONTINUE_NULL)
		kret = thread_block(NULL);
	else
		kret = thread_block_parameter(continuation, parameter);
		
#if _PSYNCH_TRACE_
	switch (kret) {
		case THREAD_TIMED_OUT:
			error  = ETIMEDOUT;
			break;
		case THREAD_INTERRUPTED:
			error  = EINTR;
			break;
	}
	uth = current_uthread();
#if defined(__i386__)
	if (mylog != 0)
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_THWAKEUP | DBG_FUNC_NONE, 0xf4f3f2f1, (uint32_t)uth, kret, 0, 0);
#else
	if (mylog != 0)
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_THWAKEUP | DBG_FUNC_NONE, 0xeeeeeeee, kret, error, 0xeeeeeeee, 0);
#endif
#endif /* _PSYNCH_TRACE_ */
		
	return(kret);
}

kern_return_t
ksyn_wakeup_thread(__unused ksyn_wait_queue_t kwq, ksyn_waitq_element_t kwe)
{
	kern_return_t kret;
#if _PSYNCH_TRACE_
	uthread_t uth = NULL;
#endif /* _PSYNCH_TRACE_ */

	kret = thread_wakeup_one((caddr_t)&kwe->kwe_psynchretval);

	if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
		panic("ksyn_wakeup_thread: panic waking up thread %x\n", kret);
#if _PSYNCH_TRACE_
	uth = kwe->kwe_uth;
#if defined(__i386__)
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_THWAKEUP | DBG_FUNC_NONE, 0xf1f2f3f4, (uint32_t)uth, kret, 0, 0);
#endif
#endif /* _PSYNCH_TRACE_ */
	
	return(kret);
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

	
#if __TESTPANICS__
	if (count == 0)
		panic("nothing in the queue???\n");
#endif /* __TESTPANICS__ */

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
	ksyn_waitq_element_t kwe = NULL;
	ksyn_queue_t kq;
	int failedwakeup = 0;
	int numwoken = 0;
	kern_return_t kret = KERN_SUCCESS;
	uint32_t lbits = 0;

	lbits = updatebits;
	if (longreadset != 0) {
		/* clear all read and longreads */
		while ((kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_READ], kwq)) != NULL) {
			kwe->kwe_psynchretval = lbits;
			kwe->kwe_kwqqueue = NULL;

			numwoken++;
			kret = ksyn_wakeup_thread(kwq, kwe);
#if __TESTPANICS__
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up readers\n");
#endif /* __TESTPANICS__ */
			if (kret == KERN_NOT_WAITING) {
				failedwakeup++;
			}
		}
		while ((kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_LREAD], kwq)) != NULL) {
			kwe->kwe_psynchretval = lbits;
			kwe->kwe_kwqqueue = NULL;
			numwoken++;
			kret = ksyn_wakeup_thread(kwq, kwe);
#if __TESTPANICS__
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up lreaders\n");
#endif /* __TESTPANICS__ */
			if (kret == KERN_NOT_WAITING) {
				failedwakeup++;
			}
		}
	} else {
		kq = &kwq->kw_ksynqueues[KSYN_QUEUE_READ];
		while ((kq->ksynq_count != 0) && (allreaders || (is_seqlower(kq->ksynq_firstnum, limitread) != 0))) {
			kwe = ksyn_queue_removefirst(kq, kwq);
			kwe->kwe_psynchretval = lbits;
			kwe->kwe_kwqqueue = NULL;
			numwoken++;
			kret = ksyn_wakeup_thread(kwq, kwe);
#if __TESTPANICS__
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up readers\n");
#endif /* __TESTPANICS__ */
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
kwq_handle_unlock(ksyn_wait_queue_t kwq, uint32_t mgen,  uint32_t rw_wc, uint32_t * updatep, int flags, int * blockp, uint32_t premgen)
{
	uint32_t low_reader, low_writer, low_ywriter, low_lreader,limitrdnum;
	int rwtype, error=0;
	int longreadset = 0, allreaders, failed;
	uint32_t updatebits=0, numneeded = 0;;
	int prepost = flags & KW_UNLOCK_PREPOST;
	thread_t preth = THREAD_NULL;
	ksyn_waitq_element_t kwe;
	uthread_t uth;
	thread_t th;
	int woken = 0;
	int block = 1;
	uint32_t lowest[KSYN_QUEUE_MAX]; /* np need for upgrade as it is handled separately */
	kern_return_t kret = KERN_SUCCESS;
	ksyn_queue_t kq;
	int curthreturns = 0;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_START, (uint32_t)kwq->kw_addr, mgen, premgen, rw_wc, 0);
#endif /* _PSYNCH_TRACE_ */
	if (prepost != 0) {
		preth = current_thread();
	}
	
	kq = &kwq->kw_ksynqueues[KSYN_QUEUE_READ];	
	kwq->kw_lastseqword = rw_wc;
	kwq->kw_lastunlockseq = (rw_wc & PTHRW_COUNT_MASK);
	kwq->kw_overlapwatch = 0;

	/* upgrade pending */
	if (is_rw_ubit_set(mgen)) {
#if __TESTPANICS__
		panic("NO UBIT SHOULD BE SET\n");
		updatebits = PTH_RWL_EBIT | PTH_RWL_KBIT;
		if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0)
			updatebits |= PTH_RWL_WBIT;
		if (kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0)
			updatebits |= PTH_RWL_YBIT;
		if (prepost != 0)  {
			if((flags & KW_UNLOCK_PREPOST_UPGRADE) != 0) {
				/* upgrade thread calling the prepost */
				/* upgrade granted */
				block = 0;
				goto out;
			}

		}
		if (kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE].ksynq_count > 0) {
			kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_UPGRADE], kwq);
			
			kwq->kw_nextseqword = (rw_wc & PTHRW_COUNT_MASK) + updatebits;
			kwe->kwe_psynchretval = updatebits;
			kwe->kwe_kwqqueue = NULL;
			kret = ksyn_wakeup_thread(kwq, kwe);
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("kwq_handle_unlock: panic waking up the upgrade thread \n");
			if (kret == KERN_NOT_WAITING) {
				kwq->kw_pre_intrcount = 1;	/* actually a  count */
				kwq->kw_pre_intrseq = mgen;
				kwq->kw_pre_intrretbits = kwe->kwe_psynchretval;
				kwq->kw_pre_intrtype = PTH_RW_TYPE_UPGRADE;
			}
			error = 0;
		} else {
			panic("panic unable to find the upgrade thread\n");
		}
#endif /* __TESTPANICS__ */
		ksyn_wqunlock(kwq);
		goto out;
	}
	
	error = kwq_find_rw_lowest(kwq, flags, premgen, &rwtype, lowest);
#if __TESTPANICS__
	if (error != 0)
		panic("rwunlock: cannot fails to slot next round of threads");
#endif /* __TESTPANICS__ */

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 1, rwtype, 0, 0);
#endif /* _PSYNCH_TRACE_ */
	low_reader = lowest[KSYN_QUEUE_READ];
	low_lreader = lowest[KSYN_QUEUE_LREAD];
	low_writer = lowest[KSYN_QUEUE_WRITER];
	low_ywriter = lowest[KSYN_QUEUE_YWRITER];

	
	longreadset = 0;
	allreaders = 0;
	updatebits = 0;


	switch (rwtype & PTH_RW_TYPE_MASK) {
		case PTH_RW_TYPE_LREAD:
			longreadset = 1;
			
		case PTH_RW_TYPE_READ: {
			/* what about the preflight which is LREAD or READ ?? */
			if  ((rwtype & PTH_RWSHFT_TYPE_MASK) != 0) {
				if (rwtype & PTH_RWSHFT_TYPE_WRITE)
					updatebits |= (PTH_RWL_WBIT | PTH_RWL_KBIT);
				if (rwtype & PTH_RWSHFT_TYPE_YWRITE)
					updatebits |= PTH_RWL_YBIT;
			}
			limitrdnum = 0;
			if (longreadset == 0) {
				switch (rwtype & (PTH_RWSHFT_TYPE_WRITE | PTH_RWSHFT_TYPE_YWRITE)) {
					case PTH_RWSHFT_TYPE_WRITE: 
						limitrdnum = low_writer;
						if (((rwtype & PTH_RWSHFT_TYPE_LREAD) != 0) && 
							(is_seqlower(low_lreader, limitrdnum) != 0)) {
							longreadset = 1;
						}
						if (((flags &  KW_UNLOCK_PREPOST_LREADLOCK) != 0) && 
							(is_seqlower(premgen, limitrdnum) != 0)) {
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
						if (((flags &  KW_UNLOCK_PREPOST_LREADLOCK) != 0) && 
							(is_seqlower(premgen, low_ywriter) != 0)) {
							longreadset = 1;
							allreaders = 0;
						}
				
						
						break;
					case (PTH_RWSHFT_TYPE_WRITE | PTH_RWSHFT_TYPE_YWRITE):
						if (is_seqlower(low_ywriter, low_writer) != 0) {
							limitrdnum = low_ywriter;
						} else
							limitrdnum = low_writer;
						if (((rwtype & PTH_RWSHFT_TYPE_LREAD) != 0) && 
							(is_seqlower(low_lreader, limitrdnum) != 0)) {
							longreadset = 1;
						}
						if (((flags &  KW_UNLOCK_PREPOST_LREADLOCK) != 0) && 
							(is_seqlower(premgen, limitrdnum) != 0)) {
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
			numneeded = 0;
			if (longreadset !=  0) {
				updatebits |= PTH_RWL_LBIT;
				updatebits &= ~PTH_RWL_KBIT;
				if ((flags &  (KW_UNLOCK_PREPOST_READLOCK | KW_UNLOCK_PREPOST_LREADLOCK)) != 0)
					numneeded += 1;
				numneeded += kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_count;
				numneeded += kwq->kw_ksynqueues[KSYN_QUEUE_LREAD].ksynq_count;
				updatebits += (numneeded << PTHRW_COUNT_SHIFT);
				kwq->kw_overlapwatch = 1;
			} else {
				/* no longread, evaluate number of readers */

				switch (rwtype & (PTH_RWSHFT_TYPE_WRITE | PTH_RWSHFT_TYPE_YWRITE)) {
					case PTH_RWSHFT_TYPE_WRITE: 
						limitrdnum = low_writer;
						numneeded = ksyn_queue_count_tolowest(kq, limitrdnum);
						if (((flags &  KW_UNLOCK_PREPOST_READLOCK) != 0) && (is_seqlower(premgen, limitrdnum) != 0)) {
							curthreturns = 1;
							numneeded += 1;
						}
						break;
					case PTH_RWSHFT_TYPE_YWRITE: 
						/* all read ? */
						numneeded += kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_count;
						if ((flags &  KW_UNLOCK_PREPOST_READLOCK) != 0) {
							curthreturns = 1;
							numneeded += 1;
						}
						break;
					case (PTH_RWSHFT_TYPE_WRITE | PTH_RWSHFT_TYPE_YWRITE):
						limitrdnum = low_writer; 
						numneeded = ksyn_queue_count_tolowest(kq, limitrdnum);
						if (((flags &  KW_UNLOCK_PREPOST_READLOCK) != 0) && (is_seqlower(premgen, limitrdnum) != 0)) {
							curthreturns = 1;
							numneeded += 1;
						}
						break;
					default: /* no writers at all */
						/* no other waiters only readers */
						kwq->kw_overlapwatch = 1;
						numneeded += kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_count;
						if ((flags &  KW_UNLOCK_PREPOST_READLOCK) != 0) {
							curthreturns = 1;
							numneeded += 1;
						}
				};
		
				updatebits += (numneeded << PTHRW_COUNT_SHIFT);
			}
			kwq->kw_nextseqword = (rw_wc & PTHRW_COUNT_MASK) + updatebits;

			if (curthreturns != 0) {
				block = 0;
				uth = current_uthread();
				kwe = &uth->uu_kwe;
				kwe->kwe_psynchretval = updatebits;
			}
			

			failed = ksyn_wakeupreaders(kwq, limitrdnum, longreadset, allreaders, updatebits, &woken);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 2, woken, failed, 0);
#endif /* _PSYNCH_TRACE_ */

			if (failed != 0) {
				kwq->kw_pre_intrcount = failed;	/* actually a  count */
				kwq->kw_pre_intrseq = limitrdnum;
				kwq->kw_pre_intrretbits = updatebits;
				if (longreadset)
					kwq->kw_pre_intrtype = PTH_RW_TYPE_LREAD;
				else
					kwq->kw_pre_intrtype = PTH_RW_TYPE_READ;
			} 

			error = 0;

			if ((kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0) && ((updatebits & PTH_RWL_WBIT) == 0))
				panic("kwq_handle_unlock: writer pending but no writebit set %x\n", updatebits);
		} 
		break;
			
		case PTH_RW_TYPE_WRITE: {
			
			/* only one thread is goin to be granted */
			updatebits |= (PTHRW_INC);
			updatebits |= PTH_RWL_KBIT| PTH_RWL_EBIT;
			
			if (((flags & KW_UNLOCK_PREPOST_WRLOCK) != 0) && (low_writer == premgen)) {
				block = 0;
				if (kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0)
					updatebits |= PTH_RWL_WBIT;
				if ((rwtype & PTH_RWSHFT_TYPE_YWRITE) != 0)
					updatebits |= PTH_RWL_YBIT;
				th = preth;
				uth = get_bsdthread_info(th);
				kwe = &uth->uu_kwe;
				kwe->kwe_psynchretval = updatebits;
			}  else {
				/*  we are not granting writelock to the preposting thread */
				kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_WRITER], kwq);

				/* if there are writers present or the preposting write thread then W bit is to be set */
				if ((kwq->kw_ksynqueues[KSYN_QUEUE_WRITER].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_WRLOCK) != 0) )
					updatebits |= PTH_RWL_WBIT;
				if ((rwtype & PTH_RWSHFT_TYPE_YWRITE) != 0)
					updatebits |= PTH_RWL_YBIT;
				kwe->kwe_psynchretval = updatebits;
				kwe->kwe_kwqqueue = NULL;
				/* setup next in the queue */
				kret = ksyn_wakeup_thread(kwq, kwe);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 3, kret, 0, 0);
#endif /* _PSYNCH_TRACE_ */
#if __TESTPANICS__
				if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
					panic("kwq_handle_unlock: panic waking up writer\n");
#endif /* __TESTPANICS__ */
				if (kret == KERN_NOT_WAITING) {
					kwq->kw_pre_intrcount = 1;	/* actually a  count */
					kwq->kw_pre_intrseq = low_writer;
					kwq->kw_pre_intrretbits = updatebits;
					kwq->kw_pre_intrtype = PTH_RW_TYPE_WRITE;
				}
				error = 0;
			}
			kwq->kw_nextseqword = (rw_wc & PTHRW_COUNT_MASK) + updatebits;
			if ((updatebits & (PTH_RWL_KBIT | PTH_RWL_EBIT)) != (PTH_RWL_KBIT | PTH_RWL_EBIT))
				panic("kwq_handle_unlock: writer lock granted but no ke set %x\n", updatebits);

		 } 
		break;

		case PTH_RW_TYPE_YWRITE: {
			/* can reader locks be granted ahead of this write? */
			if ((rwtype & PTH_RWSHFT_TYPE_READ) != 0)  {
				if  ((rwtype & PTH_RWSHFT_TYPE_MASK) != 0) {
					if (rwtype & PTH_RWSHFT_TYPE_WRITE)
						updatebits |= (PTH_RWL_WBIT | PTH_RWL_KBIT);
					if (rwtype & PTH_RWSHFT_TYPE_YWRITE)
						updatebits |= PTH_RWL_YBIT;
				}
					
				if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0) {
					/* is lowest reader less than the low writer? */
					if (is_seqlower(low_reader,low_writer) == 0)
						goto yielditis;

					numneeded = ksyn_queue_count_tolowest(kq, low_writer);
					updatebits += (numneeded << PTHRW_COUNT_SHIFT);
					if (((flags & KW_UNLOCK_PREPOST_READLOCK) != 0) && (is_seqlower(premgen, low_writer) != 0)) {
						uth = current_uthread();
						kwe = &uth->uu_kwe;
						/* add one more */
						updatebits += PTHRW_INC;
						kwe->kwe_psynchretval = updatebits;
						block = 0;
					}
					
					kwq->kw_nextseqword = (rw_wc & PTHRW_COUNT_MASK) + updatebits;

					/* there will be readers to wakeup , no need to check for woken */
					failed = ksyn_wakeupreaders(kwq, low_writer, 0, 0, updatebits, NULL);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 2, woken, failed, 0);
#endif /* _PSYNCH_TRACE_ */
					if (failed != 0) {
						kwq->kw_pre_intrcount = failed;	/* actually a  count */
						kwq->kw_pre_intrseq = low_writer;
						kwq->kw_pre_intrretbits = updatebits;
						kwq->kw_pre_intrtype = PTH_RW_TYPE_READ;
					}
					error = 0;
				} else {
					/* wakeup all readers */
					numneeded = kwq->kw_ksynqueues[KSYN_QUEUE_READ].ksynq_count;
					updatebits += (numneeded << PTHRW_COUNT_SHIFT);
					if ((prepost != 0) &&  ((flags & KW_UNLOCK_PREPOST_READLOCK) != 0)) {
						uth = current_uthread();
						kwe = &uth->uu_kwe;
						updatebits += PTHRW_INC;
						kwe->kwe_psynchretval = updatebits;
						block = 0;
					}
					kwq->kw_nextseqword = (rw_wc & PTHRW_COUNT_MASK) + updatebits;
					failed = ksyn_wakeupreaders(kwq, low_writer, 0, 1, updatebits, &woken);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 2, woken, failed, 0);
#endif /* _PSYNCH_TRACE_ */
					if (failed != 0) {
						kwq->kw_pre_intrcount = failed;	/* actually a  count */
						kwq->kw_pre_intrseq = kwq->kw_highseq;
						kwq->kw_pre_intrretbits = updatebits;
						kwq->kw_pre_intrtype = PTH_RW_TYPE_READ;
					}
					error = 0;
				}
			} else {
yielditis:
				/* no reads, so granting yeilding writes */
				updatebits |= PTHRW_INC;
				updatebits |= PTH_RWL_KBIT| PTH_RWL_EBIT;

				if (((flags & KW_UNLOCK_PREPOST_YWRLOCK) != 0) && (low_writer == premgen)) {
					/* preposting yielding write thread is being granted exclusive lock */

					block = 0;

					if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
						updatebits |= PTH_RWL_WBIT;
					else if (kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0)
						updatebits |= PTH_RWL_YBIT;

					th = preth;
					uth = get_bsdthread_info(th);
					kwe = &uth->uu_kwe;
					kwe->kwe_psynchretval = updatebits;
				}  else {
					/*  we are granting yield writelock to some other thread */
					kwe = ksyn_queue_removefirst(&kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER], kwq);

					if ((rwtype & PTH_RWSHFT_TYPE_WRITE) != 0)
						updatebits |= PTH_RWL_WBIT;
					/* if there are ywriters present or the preposting ywrite thread then W bit is to be set */
					else if ((kwq->kw_ksynqueues[KSYN_QUEUE_YWRITER].ksynq_count != 0) || ((flags & KW_UNLOCK_PREPOST_YWRLOCK) != 0) )
						updatebits |= PTH_RWL_YBIT;

					kwe->kwe_psynchretval = updatebits;
					kwe->kwe_kwqqueue = NULL;

					kret = ksyn_wakeup_thread(kwq, kwe);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_NONE, (uint32_t)kwq->kw_addr, 3, kret, 0, 0);
#endif /* _PSYNCH_TRACE_ */
#if __TESTPANICS__
					if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
						panic("kwq_handle_unlock : panic waking up readers\n");
#endif /* __TESTPANICS__ */
					if (kret == KERN_NOT_WAITING) {
						kwq->kw_pre_intrcount = 1;	/* actually a  count */
						kwq->kw_pre_intrseq = low_ywriter;
						kwq->kw_pre_intrretbits = updatebits;
						kwq->kw_pre_intrtype = PTH_RW_TYPE_YWRITE;
					}
					error = 0;
				}
				kwq->kw_nextseqword = (rw_wc & PTHRW_COUNT_MASK) + updatebits;
			}
		} 
		break;

		default:
			panic("rwunlock: invalid type for lock grants");
			
	};


out:
	if (updatep != NULL)
		*updatep = updatebits;
	if (blockp != NULL)
		*blockp = block;
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_RWHANDLEU | DBG_FUNC_END, (uint32_t)kwq->kw_addr, 0, updatebits, block, 0);
#endif /* _PSYNCH_TRACE_ */
	return(error);
}

int
kwq_handle_overlap(ksyn_wait_queue_t kwq, uint32_t lgenval, __unused uint32_t ugenval, uint32_t rw_wc, uint32_t *updatebitsp, __unused int flags , int * blockp)
{
	uint32_t highword = kwq->kw_nextseqword & PTHRW_COUNT_MASK;
	uint32_t lowword = kwq->kw_lastseqword & PTHRW_COUNT_MASK;
	uint32_t val=0;
	int withinseq;


	/* overlap is set, so no need to check for valid state for overlap */
	
	withinseq = ((is_seqlower_eq(rw_wc, highword) != 0) || (is_seqhigher_eq(lowword, rw_wc) != 0));

	if (withinseq != 0) {
		if ((kwq->kw_nextseqword & PTH_RWL_LBIT) == 0)  {
			/* if no writers ahead, overlap granted */
			if ((lgenval & PTH_RWL_WBIT) == 0) {
				goto grantoverlap;
			}
		} else  {
			/* Lbit is set, and writers ahead does not count */
			goto grantoverlap;
		}
	}

	*blockp = 1;
	return(0);

grantoverlap:
		/* increase the next expected seq by one */
		kwq->kw_nextseqword += PTHRW_INC;
		/* set count by one &  bits from the nextseq and add M bit */
		val = PTHRW_INC;
		val |= ((kwq->kw_nextseqword & PTHRW_BIT_MASK) | PTH_RWL_MBIT);
		*updatebitsp = val;
		*blockp = 0;
		return(0);
}

#if NOTYET
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

#endif /* NOTYET */

/************* Indiv queue support routines ************************/
void
ksyn_queue_init(ksyn_queue_t kq)
{
	TAILQ_INIT(&kq->ksynq_kwelist);
	kq->ksynq_count = 0;
	kq->ksynq_firstnum = 0;
	kq->ksynq_lastnum = 0;
}

int
ksyn_queue_insert(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t mgen, struct uthread * uth, ksyn_waitq_element_t kwe, int fit)
{
	uint32_t lockseq = mgen & PTHRW_COUNT_MASK;
	ksyn_waitq_element_t q_kwe, r_kwe;
	int res = 0;
	uthread_t nuth = NULL;
	
	if (kq->ksynq_count == 0) {
		TAILQ_INSERT_HEAD(&kq->ksynq_kwelist, kwe, kwe_list);
		kq->ksynq_firstnum = lockseq;
		kq->ksynq_lastnum = lockseq;
		goto out;
	}

	if (fit == FIRSTFIT) {
		/* TBD: if retry bit is set for mutex, add it to the head */
		/* firstfit, arriving order */
		TAILQ_INSERT_TAIL(&kq->ksynq_kwelist, kwe, kwe_list);
		if (is_seqlower (lockseq, kq->ksynq_firstnum) != 0)
			kq->ksynq_firstnum = lockseq;
		if (is_seqhigher (lockseq, kq->ksynq_lastnum) != 0)
			kq->ksynq_lastnum = lockseq;
		goto out;
	}
		
	if ((lockseq == kq->ksynq_firstnum) || (lockseq == kq->ksynq_lastnum)) {
		/* During prepost when a thread is getting cancelled, we could have two with same seq */
		if (kwe->kwe_flags == KWE_THREAD_PREPOST) {
			q_kwe = ksyn_queue_find_seq(kwq, kq, lockseq, 0);
			if ((q_kwe != NULL) && ((nuth = (uthread_t)q_kwe->kwe_uth) != NULL) && 
				((nuth->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL)) {
				TAILQ_INSERT_TAIL(&kq->ksynq_kwelist, kwe, kwe_list);
				goto out;

			} else {
				__FAILEDUSERTEST__("ksyn_queue_insert: two threads with same lockseq ");
				res = EBUSY;
				goto out1;
			}
		 } else {
			__FAILEDUSERTEST__("ksyn_queue_insert: two threads with same lockseq ");
			res = EBUSY;
			goto out1;
		}
	}

	/* check for next seq one */
	if (is_seqlower(kq->ksynq_lastnum, lockseq) != 0) {
		TAILQ_INSERT_TAIL(&kq->ksynq_kwelist, kwe, kwe_list);
		kq->ksynq_lastnum = lockseq;
		goto out;
	}

	if (is_seqlower(lockseq, kq->ksynq_firstnum) != 0) {
		TAILQ_INSERT_HEAD(&kq->ksynq_kwelist, kwe, kwe_list);
		kq->ksynq_firstnum = lockseq;
		goto out;
	}

	/* goto slow  insert mode */
	TAILQ_FOREACH_SAFE(q_kwe, &kq->ksynq_kwelist, kwe_list, r_kwe) {
		if (is_seqhigher(q_kwe->kwe_lockseq, lockseq) != 0) {
			TAILQ_INSERT_BEFORE(q_kwe, kwe, kwe_list);
			goto out;
		}
	}

#if __TESTPANICS__
	panic("failed to insert \n");
#endif /* __TESTPANICS__ */

out:
	if (uth != NULL)
		kwe->kwe_uth = uth;
	kq->ksynq_count++;
	kwq->kw_inqueue++;
	update_low_high(kwq, lockseq);
out1:
	return(res);
}

ksyn_waitq_element_t
ksyn_queue_removefirst(ksyn_queue_t kq, ksyn_wait_queue_t kwq)
{
	ksyn_waitq_element_t kwe = NULL;
	ksyn_waitq_element_t q_kwe;
	uint32_t curseq;

	if (kq->ksynq_count != 0) {
		kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
		TAILQ_REMOVE(&kq->ksynq_kwelist, kwe, kwe_list);
		curseq = kwe->kwe_lockseq & PTHRW_COUNT_MASK;
		kq->ksynq_count--;
		kwq->kw_inqueue--;
	
		if(kq->ksynq_count != 0) {
			q_kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
			kq->ksynq_firstnum = (q_kwe->kwe_lockseq & PTHRW_COUNT_MASK);
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
	return(kwe);
}

void
ksyn_queue_removeitem(ksyn_wait_queue_t kwq, ksyn_queue_t kq, ksyn_waitq_element_t kwe)
{
	ksyn_waitq_element_t q_kwe;
	uint32_t curseq;

	if (kq->ksynq_count > 0) {
		TAILQ_REMOVE(&kq->ksynq_kwelist, kwe, kwe_list);
		kq->ksynq_count--;
		if(kq->ksynq_count != 0) {
			q_kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
			kq->ksynq_firstnum = (q_kwe->kwe_lockseq & PTHRW_COUNT_MASK);
			q_kwe = TAILQ_LAST(&kq->ksynq_kwelist, ksynq_kwelist_head);
			kq->ksynq_lastnum = (q_kwe->kwe_lockseq & PTHRW_COUNT_MASK);
		} else {
			kq->ksynq_firstnum = 0;
			kq->ksynq_lastnum = 0;
		
		}
		kwq->kw_inqueue--;
		curseq = kwe->kwe_lockseq & PTHRW_COUNT_MASK;
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

/* find the thread and removes from the queue */
ksyn_waitq_element_t
ksyn_queue_find_seq(ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t seq, int remove)
{
	ksyn_waitq_element_t q_kwe, r_kwe;

	/* TBD: bail out if higher seq is seen */
	/* case where wrap in the tail of the queue exists */
	TAILQ_FOREACH_SAFE(q_kwe, &kq->ksynq_kwelist, kwe_list, r_kwe) {
		if ((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK) == seq) {
			if (remove != 0)
				ksyn_queue_removeitem(kwq, kq, q_kwe);
			return(q_kwe);
		}
	}
	return(NULL);
}


/* find the thread at the target sequence (or a broadcast/prepost at or above) */
ksyn_waitq_element_t
ksyn_queue_find_cvpreposeq(ksyn_queue_t kq, uint32_t cgen)
{
	ksyn_waitq_element_t q_kwe, r_kwe;
	uint32_t lgen = (cgen & PTHRW_COUNT_MASK);

	/* case where wrap in the tail of the queue exists */
	TAILQ_FOREACH_SAFE(q_kwe, &kq->ksynq_kwelist, kwe_list, r_kwe) {

		/* skip the lower entries */
		if (is_seqlower((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK), cgen) != 0) 
			continue;

		switch (q_kwe->kwe_flags) {

		case KWE_THREAD_INWAIT:
			if ((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK) != lgen)
				break;
			/* fall thru */

		case KWE_THREAD_BROADCAST:
		case KWE_THREAD_PREPOST:
			return (q_kwe);
		}
	}
	return(NULL);
}

/* look for a thread at lockseq, a  */
ksyn_waitq_element_t
ksyn_queue_find_signalseq(__unused ksyn_wait_queue_t kwq, ksyn_queue_t kq, uint32_t uptoseq, uint32_t signalseq)
{
	ksyn_waitq_element_t q_kwe, r_kwe, t_kwe = NULL;

	/* case where wrap in the tail of the queue exists */
	TAILQ_FOREACH_SAFE(q_kwe, &kq->ksynq_kwelist, kwe_list, r_kwe) {

		switch (q_kwe->kwe_flags) {

		case KWE_THREAD_PREPOST:
			if (is_seqhigher((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK), uptoseq))
				return t_kwe;
			/* fall thru */

		case KWE_THREAD_BROADCAST:
			/* match any prepost at our same uptoseq or any broadcast above */
			if (is_seqlower((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK), uptoseq))
				continue;
			return  q_kwe;

		case KWE_THREAD_INWAIT:
			/*
			 * Match any (non-cancelled) thread at or below our upto sequence -
			 * but prefer an exact match to our signal sequence (if present) to
			 * keep exact matches happening.
			 */
			if (is_seqhigher((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK), uptoseq))
				return t_kwe;

			if (q_kwe->kwe_kwqqueue == kwq) {
				uthread_t ut = q_kwe->kwe_uth;
				if ((ut->uu_flag & ( UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) != UT_CANCEL) {
					/* if equal or higher than our signal sequence, return this one */
					if (is_seqhigher_eq((q_kwe->kwe_lockseq & PTHRW_COUNT_MASK), signalseq))
						return q_kwe;
					
					/* otherwise, just remember this eligible thread and move on */
					if (t_kwe == NULL)
						t_kwe = q_kwe;
				}
			}
			break;

		default:
			panic("ksyn_queue_find_signalseq(): unknow wait queue element type (%d)\n", q_kwe->kwe_flags);
			break;
		}
	}
	return t_kwe;
}


int
ksyn_queue_move_tofree(ksyn_wait_queue_t ckwq, ksyn_queue_t kq, uint32_t upto, ksyn_queue_t kfreeq, int all, int release)
{
	ksyn_waitq_element_t kwe;
	int count = 0;
	uint32_t tseq = upto & PTHRW_COUNT_MASK;
#if _PSYNCH_TRACE_
	uthread_t ut;
#endif /* _PSYNCH_TRACE_ */

	ksyn_queue_init(kfreeq);

	/* free all the entries, must be only fakes.. */
	kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
	while (kwe != NULL) {
		if ((all == 0) && (is_seqhigher((kwe->kwe_lockseq & PTHRW_COUNT_MASK), tseq) != 0)) 
			break;
		if (kwe->kwe_flags == KWE_THREAD_INWAIT) {
			/* 
			 * This scenario is typically noticed when the cvar is 
			 * reinited and the new waiters are waiting. We can
			 * return them as spurious wait so the cvar state gets
			 * reset correctly.
			 */
#if _PSYNCH_TRACE_
			ut = (uthread_t)kwe->kwe_uth;
#endif /* _PSYNCH_TRACE_ */

			/* skip canceled ones */
			/* wake the rest */
			ksyn_queue_removeitem(ckwq, kq, kwe);
			/* set M bit to indicate to waking CV to retun Inc val */
			kwe->kwe_psynchretval = PTHRW_INC | (PTH_RWS_CV_MBIT | PTH_RWL_MTX_WAIT);
			kwe->kwe_kwqqueue = NULL;
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVHBROAD | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xcafecaf3, (uint32_t)(thread_tid((struct thread *)(((struct uthread *)(kwe->kwe_uth))->uu_context.vc_thread))), kwe->kwe_psynchretval, 0);
#endif /* _PSYNCH_TRACE_ */
			(void)ksyn_wakeup_thread(ckwq, kwe);
		} else {
			ksyn_queue_removeitem(ckwq, kq, kwe);
			TAILQ_INSERT_TAIL(&kfreeq->ksynq_kwelist, kwe, kwe_list);
			ckwq->kw_fakecount--;
			count++;
		}
		kwe = TAILQ_FIRST(&kq->ksynq_kwelist);
	}

	if ((release != 0) && (count != 0)) {
		kwe = TAILQ_FIRST(&kfreeq->ksynq_kwelist);
		while (kwe != NULL) {
			TAILQ_REMOVE(&kfreeq->ksynq_kwelist, kwe, kwe_list);
			zfree(kwe_zone, kwe);
			kwe = TAILQ_FIRST(&kfreeq->ksynq_kwelist);
		}
	}

	return(count);
}

/*************************************************************************/

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
	uint32_t numbers[KSYN_QUEUE_MAX];
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
	uint32_t numbers[KSYN_QUEUE_MAX];
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
is_seqlower(uint32_t x, uint32_t y)
{
	if (x < y) {
		if ((y-x) < (PTHRW_MAX_READERS/2))
			return(1);
	} else {
		if ((x-y) > (PTHRW_MAX_READERS/2))
			return(1);
	}
	return(0);
}

int
is_seqlower_eq(uint32_t x, uint32_t y)
{
	if (x==y)
		return(1);
	else
		return(is_seqlower(x,y));
}

int
is_seqhigher(uint32_t x, uint32_t y)
{
	if (x > y) {
		if ((x-y) < (PTHRW_MAX_READERS/2))
			return(1);
	} else {
		if ((y-x) > (PTHRW_MAX_READERS/2))
			return(1);
	}
	return(0);
}

int
is_seqhigher_eq(uint32_t x, uint32_t y)
{
	if (x==y)
		return(1);
	else
		return(is_seqhigher(x,y));
}


int
find_diff(uint32_t upto, uint32_t lowest)
{
	uint32_t diff;

	if (upto == lowest)
		return(0);
#if 0
	diff = diff_genseq(upto, lowest);
#else
        if (is_seqlower(upto, lowest) != 0)
                diff = diff_genseq(lowest, upto);
        else
                diff = diff_genseq(upto, lowest);
#endif
	diff = (diff >> PTHRW_COUNT_SHIFT);
	return(diff);
}


int
find_seq_till(ksyn_wait_queue_t kwq, uint32_t upto, uint32_t nwaiters, uint32_t *countp)
{
	int  i;
	uint32_t count = 0;


#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_FSEQTILL | DBG_FUNC_START, 0, 0, upto, nwaiters, 0);
#endif /* _PSYNCH_TRACE_ */

	for (i= 0; i< KSYN_QUEUE_MAX; i++) {
		count += ksyn_queue_count_tolowest(&kwq->kw_ksynqueues[i], upto);
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_FSEQTILL | DBG_FUNC_NONE, 0, 1, i, count, 0);
#endif /* _PSYNCH_TRACE_ */
		if (count >= nwaiters) {
			break;
		}
	}

	if (countp != NULL) {
		*countp = count;
	}
#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_FSEQTILL | DBG_FUNC_END, 0, 0, count, nwaiters, 0);
#endif /* _PSYNCH_TRACE_ */
	if (count == 0)
		return(0);
	else if (count >= nwaiters)
		return(1);
	else
		return(0);
}


uint32_t
ksyn_queue_count_tolowest(ksyn_queue_t kq, uint32_t upto)
{
	uint32_t i = 0;
	ksyn_waitq_element_t kwe, newkwe;
	uint32_t curval;

	/* if nothing or the  first num is greater than upto, return none */
	if ((kq->ksynq_count == 0) || (is_seqhigher(kq->ksynq_firstnum, upto) != 0))
		return(0);
	if (upto == kq->ksynq_firstnum)
		return(1);

	TAILQ_FOREACH_SAFE(kwe, &kq->ksynq_kwelist, kwe_list, newkwe) {
		curval = (kwe->kwe_lockseq & PTHRW_COUNT_MASK);
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


/* handles the cond broadcast of cvar and returns number of woken threads and bits for syscall return */
void
ksyn_handle_cvbroad(ksyn_wait_queue_t ckwq, uint32_t upto, uint32_t * updatep)
{
	kern_return_t kret;
	ksyn_queue_t kq;
	ksyn_waitq_element_t kwe, newkwe;
	uint32_t updatebits = 0;
	struct ksyn_queue  kfreeq;
	uthread_t ut;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVHBROAD | DBG_FUNC_START, 0xcbcbcbc2, upto, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */

	ksyn_queue_init(&kfreeq);
	kq = &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER];

 retry:
	TAILQ_FOREACH_SAFE(kwe, &kq->ksynq_kwelist, kwe_list, newkwe) {

		if (is_seqhigher((kwe->kwe_lockseq & PTHRW_COUNT_MASK), upto))	/* outside our range */
			break;

		/* now handle the one we found (inside the range) */
		switch (kwe->kwe_flags) {

		case KWE_THREAD_INWAIT:
			ut = (uthread_t)kwe->kwe_uth;

			/* skip canceled ones */
			if (kwe->kwe_kwqqueue != ckwq ||
			    (ut->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL)
				break;

			/* wake the rest */
			ksyn_queue_removeitem(ckwq, kq, kwe);
			kwe->kwe_psynchretval = PTH_RWL_MTX_WAIT;
			kwe->kwe_kwqqueue = NULL;
#if _PSYNCH_TRACE_
				__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVHBROAD | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xcafecaf2, (uint32_t)(thread_tid((struct thread *)(((struct uthread *)(kwe->kwe_uth))->uu_context.vc_thread))), kwe->kwe_psynchretval, 0);
#endif /* _PSYNCH_TRACE_ */
				kret = ksyn_wakeup_thread(ckwq, kwe);
#if __TESTPANICS__
			if ((kret != KERN_SUCCESS) && (kret != KERN_NOT_WAITING))
				panic("ksyn_wakeupreaders: panic waking up readers\n");
#endif /* __TESTPANICS__ */
			updatebits += PTHRW_INC;
			break;
			
		case KWE_THREAD_BROADCAST:
		case KWE_THREAD_PREPOST:
			ksyn_queue_removeitem(ckwq, kq, kwe);
			TAILQ_INSERT_TAIL(&kfreeq.ksynq_kwelist, kwe, kwe_list);
			ckwq->kw_fakecount--;
			break;
			
		default: 
			panic("unknown kweflags\n");
			break;
		}
	}

	/* Need to enter a broadcast in the queue (if not already at L == S) */

	if ((ckwq->kw_lword & PTHRW_COUNT_MASK) != (ckwq->kw_sword & PTHRW_COUNT_MASK)) {

		newkwe = TAILQ_FIRST(&kfreeq.ksynq_kwelist);
		if (newkwe == NULL) {
			ksyn_wqunlock(ckwq);
			newkwe = (ksyn_waitq_element_t)zalloc(kwe_zone);
			TAILQ_INSERT_TAIL(&kfreeq.ksynq_kwelist, newkwe, kwe_list);
			ksyn_wqlock(ckwq);
			goto retry;
		}
		
		TAILQ_REMOVE(&kfreeq.ksynq_kwelist, newkwe, kwe_list);
		bzero(newkwe, sizeof(struct ksyn_waitq_element));
		newkwe->kwe_kwqqueue = ckwq;
		newkwe->kwe_flags = KWE_THREAD_BROADCAST;
		newkwe->kwe_lockseq = upto;
		newkwe->kwe_count = 0;
		newkwe->kwe_uth = NULL;
		newkwe->kwe_psynchretval = 0;
		
#if _PSYNCH_TRACE_
		__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVHBROAD | DBG_FUNC_NONE, (uint32_t)ckwq->kw_addr, 0xfeedfeed, upto, 0, 0);
#endif /* _PSYNCH_TRACE_ */
		
		(void)ksyn_queue_insert(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], upto, NULL, newkwe, SEQFIT);
		ckwq->kw_fakecount++;
	}

	/* free up any remaining things stumbled across above */
	kwe = TAILQ_FIRST(&kfreeq.ksynq_kwelist);
	while (kwe != NULL) {
		TAILQ_REMOVE(&kfreeq.ksynq_kwelist, kwe, kwe_list);
		zfree(kwe_zone, kwe);
		kwe = TAILQ_FIRST(&kfreeq.ksynq_kwelist);
	}

	if (updatep != NULL)
		*updatep = updatebits;

#if _PSYNCH_TRACE_
	__PTHREAD_TRACE_DEBUG(_PSYNCH_TRACE_CVHBROAD | DBG_FUNC_END, 0xeeeeeeed, updatebits, 0, 0, 0);
#endif /* _PSYNCH_TRACE_ */
}

void
ksyn_cvupdate_fixup(ksyn_wait_queue_t ckwq, uint32_t *updatep, ksyn_queue_t kfreeq, int release)
{
	uint32_t updatebits = 0;

	if (updatep != NULL)
		updatebits = *updatep;
	if ((ckwq->kw_lword & PTHRW_COUNT_MASK) == (ckwq->kw_sword & PTHRW_COUNT_MASK)) {
		updatebits |= PTH_RWS_CV_CBIT;
		if (ckwq->kw_inqueue != 0) {
			/* FREE THE QUEUE */
			ksyn_queue_move_tofree(ckwq, &ckwq->kw_ksynqueues[KSYN_QUEUE_WRITER], ckwq->kw_lword, kfreeq, 0, release);
#if __TESTPANICS__
			if (ckwq->kw_inqueue != 0)
				panic("ksyn_cvupdate_fixup: L == S, but entries in queue beyond S");
#endif /* __TESTPANICS__ */
		}
		ckwq->kw_lword = ckwq->kw_uword = ckwq->kw_sword = 0;
		ckwq->kw_kflags |= KSYN_KWF_ZEROEDOUT;
	} else if ((ckwq->kw_inqueue != 0) && (ckwq->kw_fakecount == ckwq->kw_inqueue)) {
		/* only fake entries are present in the queue */
		updatebits |= PTH_RWS_CV_PBIT; 
	}
	if (updatep != NULL)
		*updatep = updatebits;
}

void
psynch_zoneinit(void)
{
        kwq_zone = (zone_t)zinit(sizeof(struct ksyn_wait_queue), 8192 * sizeof(struct ksyn_wait_queue), 4096, "ksyn_waitqueue zone");
        kwe_zone = (zone_t)zinit(sizeof(struct ksyn_waitq_element), 8192 * sizeof(struct ksyn_waitq_element), 4096, "ksyn_waitq_element zone");
}
#endif /* PSYNCH */
