/*
 * Copyright (c) 2003-2020 Apple Inc. All rights reserved.
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
 * todo:
 *		1) ramesh is looking into how to replace taking a reference on
 *		        the user's map (vm_map_reference()) since it is believed that
 *			would not hold the process for us.
 *		2) david is looking into a way for us to set the priority of the
 *		        worker threads to match that of the user's thread when the
 *		        async IO was queued.
 */


/*
 * This file contains support for the POSIX 1003.1B AIO/LIO facility.
 */

#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/mount_internal.h>
#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/user.h>

#include <sys/aio_kern.h>
#include <sys/sysproto.h>

#include <machine/limits.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/task.h>
#include <kern/sched_prim.h>

#include <vm/vm_map.h>

#include <os/refcnt.h>

#include <sys/kdebug.h>
#define AIO_work_queued                 1
#define AIO_worker_wake                 2
#define AIO_completion_sig              3
#define AIO_completion_cleanup_wait     4
#define AIO_completion_cleanup_wake     5
#define AIO_completion_suspend_wake     6
#define AIO_fsync_delay                 7
#define AIO_cancel                      10
#define AIO_cancel_async_workq          11
#define AIO_cancel_sync_workq           12
#define AIO_cancel_activeq              13
#define AIO_cancel_doneq                14
#define AIO_fsync                       20
#define AIO_read                        30
#define AIO_write                       40
#define AIO_listio                      50
#define AIO_error                       60
#define AIO_error_val                   61
#define AIO_error_activeq               62
#define AIO_error_workq                 63
#define AIO_return                      70
#define AIO_return_val                  71
#define AIO_return_activeq              72
#define AIO_return_workq                73
#define AIO_exec                        80
#define AIO_exit                        90
#define AIO_exit_sleep                  91
#define AIO_close                       100
#define AIO_close_sleep                 101
#define AIO_suspend                     110
#define AIO_suspend_sleep               111
#define AIO_worker_thread               120

__options_decl(aio_entry_flags_t, uint32_t, {
	AIO_READ        = 0x00000001, /* a read */
	AIO_WRITE       = 0x00000002, /* a write */
	AIO_FSYNC       = 0x00000004, /* aio_fsync with op = O_SYNC */
	AIO_DSYNC       = 0x00000008, /* aio_fsync with op = O_DSYNC (not supported yet) */
	AIO_LIO         = 0x00000010, /* lio_listio generated IO */
	AIO_LIO_WAIT    = 0x00000020, /* lio_listio is waiting on the leader */

	/*
	 * These flags mean that this entry is blocking either:
	 * - close (AIO_CLOSE_WAIT)
	 * - exit or exec (AIO_EXIT_WAIT)
	 *
	 * These flags are mutually exclusive, and the AIO_EXIT_WAIT variant
	 * will also neuter notifications in do_aio_completion_and_unlock().
	 */
	AIO_CLOSE_WAIT  = 0x00004000,
	AIO_EXIT_WAIT   = 0x00008000,
});

/*! @struct aio_workq_entry
 *
 * @discussion
 * This represents a piece of aio/lio work.
 *
 * The ownership rules go as follows:
 *
 * - the "proc" owns one refcount on the entry (from creation), while it is
 *   enqueued on the aio_activeq and then the aio_doneq.
 *
 *   either aio_return() (user read the status) or _aio_exit() (the process
 *   died) will dequeue the entry and consume this ref.
 *
 * - the async workqueue owns one refcount once the work is submitted,
 *   which is consumed in do_aio_completion_and_unlock().
 *
 *   This ref protects the entry for the the end of
 *   do_aio_completion_and_unlock() (when signal delivery happens).
 *
 * - lio_listio() for batches picks one of the entries to be the "leader"
 *   of the batch. Each work item will have a refcount on its leader
 *   so that the accounting of the batch completion can be done on the leader
 *   (to be able to decrement lio_pending).
 *
 *   This ref is consumed in do_aio_completion_and_unlock() as well.
 *
 * - lastly, in lio_listio() when the LIO_WAIT behavior is requested,
 *   an extra ref is taken in this syscall as it needs to keep accessing
 *   the leader "lio_pending" field until it hits 0.
 */
struct aio_workq_entry {
	/* queue lock */
	TAILQ_ENTRY(aio_workq_entry)    aio_workq_link;

	/* Proc lock */
	TAILQ_ENTRY(aio_workq_entry)    aio_proc_link;  /* p_aio_activeq or p_aio_doneq */
	user_ssize_t                    returnval;      /* return value from read / write request */
	errno_t                         errorval;       /* error value from read / write request */
	os_refcnt_t                     aio_refcount;
	aio_entry_flags_t               flags;

	int                             lio_pending;    /* pending I/Os in lio group, only on leader */
	struct aio_workq_entry         *lio_leader;     /* pointer to the lio leader, can be self */

	/* Initialized and never changed, safe to access */
	struct proc                    *procp;          /* user proc that queued this request */
	user_addr_t                     uaiocbp;        /* pointer passed in from user land */
	struct user_aiocb               aiocb;          /* copy of aiocb from user land */
	thread_t                        thread;         /* thread that queued this request */

	/* Initialized, and possibly freed by aio_work_thread() or at free if cancelled */
	vm_map_t                        aio_map;        /* user land map we have a reference to */
};

/*
 * aio requests queue up on the aio_async_workq or lio_sync_workq (for
 * lio_listio LIO_WAIT).  Requests then move to the per process aio_activeq
 * (proc.aio_activeq) when one of our worker threads start the IO.
 * And finally, requests move to the per process aio_doneq (proc.aio_doneq)
 * when the IO request completes.  The request remains on aio_doneq until
 * user process calls aio_return or the process exits, either way that is our
 * trigger to release aio resources.
 */
typedef struct aio_workq   {
	TAILQ_HEAD(, aio_workq_entry)   aioq_entries;
	lck_spin_t                      aioq_lock;
	struct waitq                    aioq_waitq;
} *aio_workq_t;

#define AIO_NUM_WORK_QUEUES 1
struct aio_anchor_cb {
	os_atomic(int)          aio_total_count;        /* total extant entries */

	/* Hash table of queues here */
	int                     aio_num_workqs;
	struct aio_workq        aio_async_workqs[AIO_NUM_WORK_QUEUES];
};
typedef struct aio_anchor_cb aio_anchor_cb;

/*
 * Notes on aio sleep / wake channels.
 * We currently pick a couple fields within the proc structure that will allow
 * us sleep channels that currently do not collide with any other kernel routines.
 * At this time, for binary compatibility reasons, we cannot create new proc fields.
 */
#define AIO_SUSPEND_SLEEP_CHAN  p_aio_activeq
#define AIO_CLEANUP_SLEEP_CHAN  p_aio_total_count

#define ASSERT_AIO_FROM_PROC(aiop, theproc)     \
	if ((aiop)->procp != (theproc)) {       \
	        panic("AIO on a proc list that does not belong to that proc.\n"); \
	}

/*
 *  LOCAL PROTOTYPES
 */
static void             aio_proc_lock(proc_t procp);
static void             aio_proc_lock_spin(proc_t procp);
static void             aio_proc_unlock(proc_t procp);
static lck_mtx_t       *aio_proc_mutex(proc_t procp);
static bool             aio_has_active_requests_for_process(proc_t procp);
static bool             aio_proc_has_active_requests_for_file(proc_t procp, int fd);
static boolean_t        is_already_queued(proc_t procp, user_addr_t aiocbp);

static aio_workq_t      aio_entry_workq(aio_workq_entry *entryp);
static void             aio_workq_remove_entry_locked(aio_workq_t queue, aio_workq_entry *entryp);
static void             aio_workq_add_entry_locked(aio_workq_t queue, aio_workq_entry *entryp);
static void             aio_entry_ref(aio_workq_entry *entryp);
static void             aio_entry_unref(aio_workq_entry *entryp);
static bool             aio_entry_try_workq_remove(aio_workq_entry *entryp);
static boolean_t        aio_delay_fsync_request(aio_workq_entry *entryp);
static void             aio_free_request(aio_workq_entry *entryp);

static void             aio_workq_init(aio_workq_t wq);
static void             aio_workq_lock_spin(aio_workq_t wq);
static void             aio_workq_unlock(aio_workq_t wq);
static lck_spin_t      *aio_workq_lock(aio_workq_t wq);

static void             aio_work_thread(void *arg, wait_result_t wr);
static aio_workq_entry *aio_get_some_work(void);

static int              aio_queue_async_request(proc_t procp, user_addr_t aiocbp, aio_entry_flags_t);
static int              aio_validate(proc_t, aio_workq_entry *entryp);

static int              do_aio_cancel_locked(proc_t p, int fd, user_addr_t aiocbp, aio_entry_flags_t);
static void             do_aio_completion_and_unlock(proc_t p, aio_workq_entry *entryp);
static int              do_aio_fsync(aio_workq_entry *entryp);
static int              do_aio_read(aio_workq_entry *entryp);
static int              do_aio_write(aio_workq_entry *entryp);
static void             do_munge_aiocb_user32_to_user(struct user32_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp);
static void             do_munge_aiocb_user64_to_user(struct user64_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp);
static aio_workq_entry *aio_create_queue_entry(proc_t procp, user_addr_t aiocbp, aio_entry_flags_t);
static int              aio_copy_in_list(proc_t, user_addr_t, user_addr_t *, int);

#define ASSERT_AIO_PROC_LOCK_OWNED(p)   LCK_MTX_ASSERT(aio_proc_mutex(p), LCK_MTX_ASSERT_OWNED)
#define ASSERT_AIO_WORKQ_LOCK_OWNED(q)  LCK_SPIN_ASSERT(aio_workq_lock(q), LCK_ASSERT_OWNED)

/*
 *  EXTERNAL PROTOTYPES
 */

/* in ...bsd/kern/sys_generic.c */
extern int dofileread(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte,
    off_t offset, int flags, user_ssize_t *retval);
extern int dofilewrite(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte, off_t offset,
    int flags, user_ssize_t *retval);

/*
 * aio external global variables.
 */
extern int aio_max_requests;                    /* AIO_MAX - configurable */
extern int aio_max_requests_per_process;        /* AIO_PROCESS_MAX - configurable */
extern int aio_worker_threads;                  /* AIO_THREAD_COUNT - configurable */


/*
 * aio static variables.
 */
static aio_anchor_cb aio_anchor = {
	.aio_num_workqs = AIO_NUM_WORK_QUEUES,
};
os_refgrp_decl(static, aio_refgrp, "aio", NULL);
static LCK_GRP_DECLARE(aio_proc_lock_grp, "aio_proc");
static LCK_GRP_DECLARE(aio_queue_lock_grp, "aio_queue");
static LCK_MTX_DECLARE(aio_proc_mtx, &aio_proc_lock_grp);

static ZONE_DECLARE(aio_workq_zonep, "aiowq", sizeof(aio_workq_entry),
    ZC_ZFREE_CLEARMEM);

/* Hash */
static aio_workq_t
aio_entry_workq(__unused aio_workq_entry *entryp)
{
	return &aio_anchor.aio_async_workqs[0];
}

static void
aio_workq_init(aio_workq_t wq)
{
	TAILQ_INIT(&wq->aioq_entries);
	lck_spin_init(&wq->aioq_lock, &aio_queue_lock_grp, LCK_ATTR_NULL);
	waitq_init(&wq->aioq_waitq, SYNC_POLICY_FIFO);
}


/*
 * Can be passed a queue which is locked spin.
 */
static void
aio_workq_remove_entry_locked(aio_workq_t queue, aio_workq_entry *entryp)
{
	ASSERT_AIO_WORKQ_LOCK_OWNED(queue);

	if (entryp->aio_workq_link.tqe_prev == NULL) {
		panic("Trying to remove an entry from a work queue, but it is not on a queue\n");
	}

	TAILQ_REMOVE(&queue->aioq_entries, entryp, aio_workq_link);
	entryp->aio_workq_link.tqe_prev = NULL; /* Not on a workq */
}

static void
aio_workq_add_entry_locked(aio_workq_t queue, aio_workq_entry *entryp)
{
	ASSERT_AIO_WORKQ_LOCK_OWNED(queue);

	TAILQ_INSERT_TAIL(&queue->aioq_entries, entryp, aio_workq_link);
}

static void
aio_proc_lock(proc_t procp)
{
	lck_mtx_lock(aio_proc_mutex(procp));
}

static void
aio_proc_lock_spin(proc_t procp)
{
	lck_mtx_lock_spin(aio_proc_mutex(procp));
}

static bool
aio_has_any_work(void)
{
	return os_atomic_load(&aio_anchor.aio_total_count, relaxed) != 0;
}

static bool
aio_try_proc_insert_active_locked(proc_t procp, aio_workq_entry *entryp)
{
	int old, new;

	ASSERT_AIO_PROC_LOCK_OWNED(procp);

	if (procp->p_aio_total_count >= aio_max_requests_per_process) {
		return false;
	}

	if (is_already_queued(procp, entryp->uaiocbp)) {
		return false;
	}

	os_atomic_rmw_loop(&aio_anchor.aio_total_count, old, new, relaxed, {
		if (old >= aio_max_requests) {
		        os_atomic_rmw_loop_give_up(return false);
		}
		new = old + 1;
	});

	TAILQ_INSERT_TAIL(&procp->p_aio_activeq, entryp, aio_proc_link);
	procp->p_aio_total_count++;
	return true;
}

static void
aio_proc_move_done_locked(proc_t procp, aio_workq_entry *entryp)
{
	TAILQ_REMOVE(&procp->p_aio_activeq, entryp, aio_proc_link);
	TAILQ_INSERT_TAIL(&procp->p_aio_doneq, entryp, aio_proc_link);
}

static void
aio_proc_remove_done_locked(proc_t procp, aio_workq_entry *entryp)
{
	TAILQ_REMOVE(&procp->p_aio_doneq, entryp, aio_proc_link);
	entryp->aio_proc_link.tqe_prev = NULL;
	if (os_atomic_dec_orig(&aio_anchor.aio_total_count, relaxed) <= 0) {
		panic("Negative total AIO count!\n");
	}
	if (procp->p_aio_total_count-- <= 0) {
		panic("proc %p: p_aio_total_count accounting mismatch", procp);
	}
}

static void
aio_proc_unlock(proc_t procp)
{
	lck_mtx_unlock(aio_proc_mutex(procp));
}

static lck_mtx_t*
aio_proc_mutex(proc_t procp)
{
	return &procp->p_mlock;
}

static void
aio_entry_ref(aio_workq_entry *entryp)
{
	os_ref_retain(&entryp->aio_refcount);
}

static void
aio_entry_unref(aio_workq_entry *entryp)
{
	if (os_ref_release(&entryp->aio_refcount) == 0) {
		aio_free_request(entryp);
	}
}

static bool
aio_entry_try_workq_remove(aio_workq_entry *entryp)
{
	/* Can only be cancelled if it's still on a work queue */
	if (entryp->aio_workq_link.tqe_prev != NULL) {
		aio_workq_t queue;

		/* Will have to check again under the lock */
		queue = aio_entry_workq(entryp);
		aio_workq_lock_spin(queue);
		if (entryp->aio_workq_link.tqe_prev != NULL) {
			aio_workq_remove_entry_locked(queue, entryp);
			aio_workq_unlock(queue);
			return true;
		} else {
			aio_workq_unlock(queue);
		}
	}

	return false;
}

static void
aio_workq_lock_spin(aio_workq_t wq)
{
	lck_spin_lock(aio_workq_lock(wq));
}

static void
aio_workq_unlock(aio_workq_t wq)
{
	lck_spin_unlock(aio_workq_lock(wq));
}

static lck_spin_t*
aio_workq_lock(aio_workq_t wq)
{
	return &wq->aioq_lock;
}

/*
 * aio_cancel - attempt to cancel one or more async IO requests currently
 * outstanding against file descriptor uap->fd.  If uap->aiocbp is not
 * NULL then only one specific IO is cancelled (if possible).  If uap->aiocbp
 * is NULL then all outstanding async IO request for the given file
 * descriptor are cancelled (if possible).
 */
int
aio_cancel(proc_t p, struct aio_cancel_args *uap, int *retval)
{
	struct user_aiocb my_aiocb;
	int               result;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, 0, 0, 0);

	/* quick check to see if there are any async IO requests queued up */
	if (!aio_has_any_work()) {
		result = 0;
		*retval = AIO_ALLDONE;
		goto ExitRoutine;
	}

	*retval = -1;
	if (uap->aiocbp != USER_ADDR_NULL) {
		if (proc_is64bit(p)) {
			struct user64_aiocb aiocb64;

			result = copyin(uap->aiocbp, &aiocb64, sizeof(aiocb64));
			if (result == 0) {
				do_munge_aiocb_user64_to_user(&aiocb64, &my_aiocb);
			}
		} else {
			struct user32_aiocb aiocb32;

			result = copyin(uap->aiocbp, &aiocb32, sizeof(aiocb32));
			if (result == 0) {
				do_munge_aiocb_user32_to_user(&aiocb32, &my_aiocb);
			}
		}

		if (result != 0) {
			result = EAGAIN;
			goto ExitRoutine;
		}

		/* NOTE - POSIX standard says a mismatch between the file */
		/* descriptor passed in and the file descriptor embedded in */
		/* the aiocb causes unspecified results.  We return EBADF in */
		/* that situation.  */
		if (uap->fd != my_aiocb.aio_fildes) {
			result = EBADF;
			goto ExitRoutine;
		}
	}

	aio_proc_lock(p);
	result = do_aio_cancel_locked(p, uap->fd, uap->aiocbp, 0);
	ASSERT_AIO_PROC_LOCK_OWNED(p);
	aio_proc_unlock(p);

	if (result != -1) {
		*retval = result;
		result = 0;
		goto ExitRoutine;
	}

	result = EBADF;

ExitRoutine:
	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, result, 0, 0);

	return result;
}


/*
 * _aio_close - internal function used to clean up async IO requests for
 * a file descriptor that is closing.
 * THIS MAY BLOCK.
 */
__private_extern__ void
_aio_close(proc_t p, int fd)
{
	int error;

	/* quick check to see if there are any async IO requests queued up */
	if (!aio_has_any_work()) {
		return;
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_close) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), fd, 0, 0, 0);

	/* cancel all async IO requests on our todo queues for this file descriptor */
	aio_proc_lock(p);
	error = do_aio_cancel_locked(p, fd, USER_ADDR_NULL, AIO_CLOSE_WAIT);
	ASSERT_AIO_PROC_LOCK_OWNED(p);
	if (error == AIO_NOTCANCELED) {
		/*
		 * AIO_NOTCANCELED is returned when we find an aio request for this process
		 * and file descriptor on the active async IO queue.  Active requests cannot
		 * be cancelled so we must wait for them to complete.  We will get a special
		 * wake up call on our channel used to sleep for ALL active requests to
		 * complete.  This sleep channel (proc.AIO_CLEANUP_SLEEP_CHAN) is only used
		 * when we must wait for all active aio requests.
		 */

		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_close_sleep) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM(p), fd, 0, 0, 0);

		while (aio_proc_has_active_requests_for_file(p, fd)) {
			msleep(&p->AIO_CLEANUP_SLEEP_CHAN, aio_proc_mutex(p), PRIBIO, "aio_close", 0);
		}
	}

	aio_proc_unlock(p);

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_close) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), fd, 0, 0, 0);
}


/*
 * aio_error - return the error status associated with the async IO
 * request referred to by uap->aiocbp.  The error status is the errno
 * value that would be set by the corresponding IO request (read, wrtie,
 * fdatasync, or sync).
 */
int
aio_error(proc_t p, struct aio_error_args *uap, int *retval)
{
	aio_workq_entry *entryp;
	int              error;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_error) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, 0, 0, 0);

	/* see if there are any aios to check */
	if (!aio_has_any_work()) {
		return EINVAL;
	}

	aio_proc_lock(p);

	/* look for a match on our queue of async IO requests that have completed */
	TAILQ_FOREACH(entryp, &p->p_aio_doneq, aio_proc_link) {
		if (entryp->uaiocbp == uap->aiocbp) {
			ASSERT_AIO_FROM_PROC(entryp, p);

			*retval = entryp->errorval;
			error = 0;

			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_error_val) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), uap->aiocbp, *retval, 0, 0);
			goto ExitRoutine;
		}
	}

	/* look for a match on our queue of active async IO requests */
	TAILQ_FOREACH(entryp, &p->p_aio_activeq, aio_proc_link) {
		if (entryp->uaiocbp == uap->aiocbp) {
			ASSERT_AIO_FROM_PROC(entryp, p);
			*retval = EINPROGRESS;
			error = 0;
			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_error_activeq) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), uap->aiocbp, *retval, 0, 0);
			goto ExitRoutine;
		}
	}

	error = EINVAL;

ExitRoutine:
	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_error) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, error, 0, 0);
	aio_proc_unlock(p);

	return error;
}


/*
 * aio_fsync - asynchronously force all IO operations associated
 * with the file indicated by the file descriptor (uap->aiocbp->aio_fildes) and
 * queued at the time of the call to the synchronized completion state.
 * NOTE - we do not support op O_DSYNC at this point since we do not support the
 * fdatasync() call.
 */
int
aio_fsync(proc_t p, struct aio_fsync_args *uap, int *retval)
{
	aio_entry_flags_t fsync_kind;
	int error;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, uap->op, 0, 0);

	*retval = 0;
	/* 0 := O_SYNC for binary backward compatibility with Panther */
	if (uap->op == O_SYNC || uap->op == 0) {
		fsync_kind = AIO_FSYNC;
	} else if (uap->op == O_DSYNC) {
		fsync_kind = AIO_DSYNC;
	} else {
		*retval = -1;
		error = EINVAL;
		goto ExitRoutine;
	}

	error = aio_queue_async_request(p, uap->aiocbp, fsync_kind);
	if (error != 0) {
		*retval = -1;
	}

ExitRoutine:
	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, error, 0, 0);

	return error;
}


/* aio_read - asynchronously read uap->aiocbp->aio_nbytes bytes from the
 * file descriptor (uap->aiocbp->aio_fildes) into the buffer
 * (uap->aiocbp->aio_buf).
 */
int
aio_read(proc_t p, struct aio_read_args *uap, int *retval)
{
	int error;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_read) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, 0, 0, 0);

	*retval = 0;

	error = aio_queue_async_request(p, uap->aiocbp, AIO_READ);
	if (error != 0) {
		*retval = -1;
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_read) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, error, 0, 0);

	return error;
}


/*
 * aio_return - return the return status associated with the async IO
 * request referred to by uap->aiocbp.  The return status is the value
 * that would be returned by corresponding IO request (read, write,
 * fdatasync, or sync).  This is where we release kernel resources
 * held for async IO call associated with the given aiocb pointer.
 */
int
aio_return(proc_t p, struct aio_return_args *uap, user_ssize_t *retval)
{
	aio_workq_entry *entryp;
	int              error = EINVAL;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_return) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, 0, 0, 0);

	/* See if there are any entries to check */
	if (!aio_has_any_work()) {
		goto ExitRoutine;
	}

	aio_proc_lock(p);
	*retval = 0;

	/* look for a match on our queue of async IO requests that have completed */
	TAILQ_FOREACH(entryp, &p->p_aio_doneq, aio_proc_link) {
		ASSERT_AIO_FROM_PROC(entryp, p);
		if (entryp->uaiocbp == uap->aiocbp) {
			/* Done and valid for aio_return(), pull it off the list */
			aio_proc_remove_done_locked(p, entryp);

			*retval = entryp->returnval;
			error = 0;
			aio_proc_unlock(p);

			aio_entry_unref(entryp);

			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_return_val) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), uap->aiocbp, *retval, 0, 0);
			goto ExitRoutine;
		}
	}

	/* look for a match on our queue of active async IO requests */
	TAILQ_FOREACH(entryp, &p->p_aio_activeq, aio_proc_link) {
		ASSERT_AIO_FROM_PROC(entryp, p);
		if (entryp->uaiocbp == uap->aiocbp) {
			error = EINPROGRESS;
			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_return_activeq) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), uap->aiocbp, *retval, 0, 0);
			break;
		}
	}

	aio_proc_unlock(p);

ExitRoutine:
	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_return) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, error, 0, 0);

	return error;
}


/*
 * _aio_exec - internal function used to clean up async IO requests for
 * a process that is going away due to exec().  We cancel any async IOs
 * we can and wait for those already active.  We also disable signaling
 * for cancelled or active aio requests that complete.
 * This routine MAY block!
 */
__private_extern__ void
_aio_exec(proc_t p)
{
	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_exec) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), 0, 0, 0, 0);

	_aio_exit(p);

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_exec) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), 0, 0, 0, 0);
}


/*
 * _aio_exit - internal function used to clean up async IO requests for
 * a process that is terminating (via exit() or exec()).  We cancel any async IOs
 * we can and wait for those already active.  We also disable signaling
 * for cancelled or active aio requests that complete.  This routine MAY block!
 */
__private_extern__ void
_aio_exit(proc_t p)
{
	TAILQ_HEAD(, aio_workq_entry) tofree = TAILQ_HEAD_INITIALIZER(tofree);
	aio_workq_entry *entryp, *tmp;
	int              error;

	/* quick check to see if there are any async IO requests queued up */
	if (!aio_has_any_work()) {
		return;
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_exit) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), 0, 0, 0, 0);

	aio_proc_lock(p);

	/*
	 * cancel async IO requests on the todo work queue and wait for those
	 * already active to complete.
	 */
	error = do_aio_cancel_locked(p, -1, USER_ADDR_NULL, AIO_EXIT_WAIT);
	ASSERT_AIO_PROC_LOCK_OWNED(p);
	if (error == AIO_NOTCANCELED) {
		/*
		 * AIO_NOTCANCELED is returned when we find an aio request for this process
		 * on the active async IO queue.  Active requests cannot be cancelled so we
		 * must wait for them to complete.  We will get a special wake up call on
		 * our channel used to sleep for ALL active requests to complete.  This sleep
		 * channel (proc.AIO_CLEANUP_SLEEP_CHAN) is only used when we must wait for all
		 * active aio requests.
		 */

		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_exit_sleep) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM(p), 0, 0, 0, 0);

		while (aio_has_active_requests_for_process(p)) {
			msleep(&p->AIO_CLEANUP_SLEEP_CHAN, aio_proc_mutex(p), PRIBIO, "aio_exit", 0);
		}
	}

	assert(!aio_has_active_requests_for_process(p));

	/* release all aio resources used by this process */
	TAILQ_FOREACH_SAFE(entryp, &p->p_aio_doneq, aio_proc_link, tmp) {
		ASSERT_AIO_FROM_PROC(entryp, p);

		aio_proc_remove_done_locked(p, entryp);
		TAILQ_INSERT_TAIL(&tofree, entryp, aio_proc_link);
	}

	aio_proc_unlock(p);

	/* free all the entries outside of the aio_proc_lock() */
	TAILQ_FOREACH_SAFE(entryp, &tofree, aio_proc_link, tmp) {
		entryp->aio_proc_link.tqe_prev = NULL;
		aio_entry_unref(entryp);
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_exit) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), 0, 0, 0, 0);
}


static bool
should_cancel(aio_workq_entry *entryp, int fd, user_addr_t aiocbp,
    aio_entry_flags_t reason)
{
	if (reason & AIO_EXIT_WAIT) {
		/* caller is _aio_exit() */
		return true;
	}
	if (fd != entryp->aiocb.aio_fildes) {
		/* not the file we're looking for */
		return false;
	}
	/*
	 * aio_cancel() or _aio_close() cancel
	 * everything for a given fd when aiocbp is NULL
	 */
	return aiocbp == USER_ADDR_NULL || entryp->uaiocbp == aiocbp;
}

/*
 * do_aio_cancel_locked - cancel async IO requests (if possible).  We get called by
 * aio_cancel, close, and at exit.
 * There are three modes of operation: 1) cancel all async IOs for a process -
 * fd is 0 and aiocbp is NULL 2) cancel all async IOs for file descriptor - fd
 * is > 0 and aiocbp is NULL 3) cancel one async IO associated with the given
 * aiocbp.
 * Returns -1 if no matches were found, AIO_CANCELED when we cancelled all
 * target async IO requests, AIO_NOTCANCELED if we could not cancel all
 * target async IO requests, and AIO_ALLDONE if all target async IO requests
 * were already complete.
 * WARNING - do not deference aiocbp in this routine, it may point to user
 * land data that has not been copied in (when called from aio_cancel())
 *
 * Called with proc locked, and returns the same way.
 */
static int
do_aio_cancel_locked(proc_t p, int fd, user_addr_t aiocbp,
    aio_entry_flags_t reason)
{
	bool multiple_matches = (aiocbp == USER_ADDR_NULL);
	aio_workq_entry *entryp, *tmp;
	int result;

	ASSERT_AIO_PROC_LOCK_OWNED(p);

	/* look for a match on our queue of async todo work. */
again:
	result = -1;
	TAILQ_FOREACH_SAFE(entryp, &p->p_aio_activeq, aio_proc_link, tmp) {
		ASSERT_AIO_FROM_PROC(entryp, p);

		if (!should_cancel(entryp, fd, aiocbp, reason)) {
			continue;
		}

		if (reason) {
			/* mark the entry as blocking close or exit/exec */
			entryp->flags |= reason;
			if ((entryp->flags & AIO_EXIT_WAIT) && (entryp->flags & AIO_CLOSE_WAIT)) {
				panic("Close and exit flags set at the same time\n");
			}
		}

		/* Can only be cancelled if it's still on a work queue */
		if (aio_entry_try_workq_remove(entryp)) {
			entryp->errorval = ECANCELED;
			entryp->returnval = -1;

			/* Now it's officially cancelled.  Do the completion */
			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_async_workq) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
			    fd, 0, 0);
			do_aio_completion_and_unlock(p, entryp);

			aio_proc_lock(p);

			if (multiple_matches) {
				/*
				 * Restart from the head of the proc active queue since it
				 * may have been changed while we were away doing completion
				 * processing.
				 *
				 * Note that if we found an uncancellable AIO before, we will
				 * either find it again or discover that it's been completed,
				 * so resetting the result will not cause us to return success
				 * despite outstanding AIOs.
				 */
				goto again;
			}

			return AIO_CANCELED;
		}

		/*
		 * It's been taken off the active queue already, i.e. is in flight.
		 * All we can do is ask for notification.
		 */
		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_activeq) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
		    fd, 0, 0);

		result = AIO_NOTCANCELED;
		if (!multiple_matches) {
			return result;
		}
	}

	/*
	 * if we didn't find any matches on the todo or active queues then look for a
	 * match on our queue of async IO requests that have completed and if found
	 * return AIO_ALLDONE result.
	 *
	 * Proc AIO lock is still held.
	 */
	if (result == -1) {
		TAILQ_FOREACH(entryp, &p->p_aio_doneq, aio_proc_link) {
			ASSERT_AIO_FROM_PROC(entryp, p);
			if (should_cancel(entryp, fd, aiocbp, reason)) {
				KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_doneq) | DBG_FUNC_NONE,
				    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
				    fd, 0, 0);

				result = AIO_ALLDONE;
				if (!multiple_matches) {
					return result;
				}
			}
		}
	}

	return result;
}


/*
 * aio_suspend - suspend the calling thread until at least one of the async
 * IO operations referenced by uap->aiocblist has completed, until a signal
 * interrupts the function, or uap->timeoutp time interval (optional) has
 * passed.
 * Returns 0 if one or more async IOs have completed else -1 and errno is
 * set appropriately - EAGAIN if timeout elapses or EINTR if an interrupt
 * woke us up.
 */
int
aio_suspend(proc_t p, struct aio_suspend_args *uap, int *retval)
{
	__pthread_testcancel(1);
	return aio_suspend_nocancel(p, (struct aio_suspend_nocancel_args *)uap, retval);
}


int
aio_suspend_nocancel(proc_t p, struct aio_suspend_nocancel_args *uap, int *retval)
{
	int                     error;
	int                     i;
	uint64_t                abstime;
	struct user_timespec    ts;
	aio_workq_entry        *entryp;
	user_addr_t            *aiocbpp;
	size_t                  aiocbpp_size;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->nent, 0, 0, 0);

	*retval = -1;
	abstime = 0;
	aiocbpp = NULL;

	if (!aio_has_any_work()) {
		error = EINVAL;
		goto ExitThisRoutine;
	}

	if (uap->nent < 1 || uap->nent > aio_max_requests_per_process ||
	    os_mul_overflow(sizeof(user_addr_t), uap->nent, &aiocbpp_size)) {
		error = EINVAL;
		goto ExitThisRoutine;
	}

	if (uap->timeoutp != USER_ADDR_NULL) {
		if (proc_is64bit(p)) {
			struct user64_timespec temp;
			error = copyin(uap->timeoutp, &temp, sizeof(temp));
			if (error == 0) {
				ts.tv_sec = (user_time_t)temp.tv_sec;
				ts.tv_nsec = (user_long_t)temp.tv_nsec;
			}
		} else {
			struct user32_timespec temp;
			error = copyin(uap->timeoutp, &temp, sizeof(temp));
			if (error == 0) {
				ts.tv_sec = temp.tv_sec;
				ts.tv_nsec = temp.tv_nsec;
			}
		}
		if (error != 0) {
			error = EAGAIN;
			goto ExitThisRoutine;
		}

		if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000) {
			error = EINVAL;
			goto ExitThisRoutine;
		}

		nanoseconds_to_absolutetime((uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec,
		    &abstime);
		clock_absolutetime_interval_to_deadline(abstime, &abstime);
	}

	aiocbpp = kheap_alloc(KHEAP_TEMP, aiocbpp_size, Z_WAITOK);
	if (aiocbpp == NULL || aio_copy_in_list(p, uap->aiocblist, aiocbpp, uap->nent)) {
		error = EAGAIN;
		goto ExitThisRoutine;
	}

	/* check list of aio requests to see if any have completed */
check_for_our_aiocbp:
	aio_proc_lock_spin(p);
	for (i = 0; i < uap->nent; i++) {
		user_addr_t     aiocbp;

		/* NULL elements are legal so check for 'em */
		aiocbp = *(aiocbpp + i);
		if (aiocbp == USER_ADDR_NULL) {
			continue;
		}

		/* return immediately if any aio request in the list is done */
		TAILQ_FOREACH(entryp, &p->p_aio_doneq, aio_proc_link) {
			ASSERT_AIO_FROM_PROC(entryp, p);
			if (entryp->uaiocbp == aiocbp) {
				aio_proc_unlock(p);
				*retval = 0;
				error = 0;
				goto ExitThisRoutine;
			}
		}
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend_sleep) | DBG_FUNC_NONE,
	    VM_KERNEL_ADDRPERM(p), uap->nent, 0, 0, 0);

	/*
	 * wait for an async IO to complete or a signal fires or timeout expires.
	 * we return EAGAIN (35) for timeout expiration and EINTR (4) when a signal
	 * interrupts us.  If an async IO completes before a signal fires or our
	 * timeout expires, we get a wakeup call from aio_work_thread().
	 */

	error = msleep1(&p->AIO_SUSPEND_SLEEP_CHAN, aio_proc_mutex(p),
	    PCATCH | PWAIT | PDROP, "aio_suspend", abstime);
	if (error == 0) {
		/*
		 * got our wakeup call from aio_work_thread().
		 * Since we can get a wakeup on this channel from another thread in the
		 * same process we head back up to make sure this is for the correct aiocbp.
		 * If it is the correct aiocbp we will return from where we do the check
		 * (see entryp->uaiocbp == aiocbp after check_for_our_aiocbp label)
		 * else we will fall out and just sleep again.
		 */
		goto check_for_our_aiocbp;
	} else if (error == EWOULDBLOCK) {
		/* our timeout expired */
		error = EAGAIN;
	} else {
		/* we were interrupted */
		error = EINTR;
	}

ExitThisRoutine:
	if (aiocbpp != NULL) {
		kheap_free(KHEAP_TEMP, aiocbpp, aiocbpp_size);
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->nent, error, 0, 0);

	return error;
}


/* aio_write - asynchronously write uap->aiocbp->aio_nbytes bytes to the
 * file descriptor (uap->aiocbp->aio_fildes) from the buffer
 * (uap->aiocbp->aio_buf).
 */

int
aio_write(proc_t p, struct aio_write_args *uap, int *retval __unused)
{
	int error;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_write) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, 0, 0, 0);

	error = aio_queue_async_request(p, uap->aiocbp, AIO_WRITE);

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_write) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), uap->aiocbp, error, 0, 0);

	return error;
}


static int
aio_copy_in_list(proc_t procp, user_addr_t aiocblist, user_addr_t *aiocbpp,
    int nent)
{
	int result;

	/* copyin our aiocb pointers from list */
	result = copyin(aiocblist, aiocbpp,
	    proc_is64bit(procp) ? (nent * sizeof(user64_addr_t))
	    : (nent * sizeof(user32_addr_t)));
	if (result) {
		return result;
	}

	/*
	 * We depend on a list of user_addr_t's so we need to
	 * munge and expand when these pointers came from a
	 * 32-bit process
	 */
	if (!proc_is64bit(procp)) {
		/* copy from last to first to deal with overlap */
		user32_addr_t *my_ptrp = ((user32_addr_t *)aiocbpp) + (nent - 1);
		user_addr_t *my_addrp = aiocbpp + (nent - 1);

		for (int i = 0; i < nent; i++, my_ptrp--, my_addrp--) {
			*my_addrp = (user_addr_t) (*my_ptrp);
		}
	}

	return 0;
}


static int
aio_copy_in_sigev(proc_t procp, user_addr_t sigp, struct user_sigevent *sigev)
{
	int     result = 0;

	if (sigp == USER_ADDR_NULL) {
		goto out;
	}

	/*
	 * We need to munge aio_sigevent since it contains pointers.
	 * Since we do not know if sigev_value is an int or a ptr we do
	 * NOT cast the ptr to a user_addr_t.   This means if we send
	 * this info back to user space we need to remember sigev_value
	 * was not expanded for the 32-bit case.
	 *
	 * Notes:	 This does NOT affect us since we don't support
	 *		sigev_value yet in the aio context.
	 */
	if (proc_is64bit(procp)) {
#if __LP64__
		struct user64_sigevent sigevent64;

		result = copyin(sigp, &sigevent64, sizeof(sigevent64));
		if (result == 0) {
			sigev->sigev_notify = sigevent64.sigev_notify;
			sigev->sigev_signo = sigevent64.sigev_signo;
			sigev->sigev_value.size_equivalent.sival_int = sigevent64.sigev_value.size_equivalent.sival_int;
			sigev->sigev_notify_function = sigevent64.sigev_notify_function;
			sigev->sigev_notify_attributes = sigevent64.sigev_notify_attributes;
		}
#else
		panic("64bit process on 32bit kernel is not supported");
#endif
	} else {
		struct user32_sigevent sigevent32;

		result = copyin(sigp, &sigevent32, sizeof(sigevent32));
		if (result == 0) {
			sigev->sigev_notify = sigevent32.sigev_notify;
			sigev->sigev_signo = sigevent32.sigev_signo;
			sigev->sigev_value.size_equivalent.sival_int = sigevent32.sigev_value.sival_int;
			sigev->sigev_notify_function = CAST_USER_ADDR_T(sigevent32.sigev_notify_function);
			sigev->sigev_notify_attributes = CAST_USER_ADDR_T(sigevent32.sigev_notify_attributes);
		}
	}

	if (result != 0) {
		result = EAGAIN;
	}

out:
	return result;
}

/*
 * validate user_sigevent.  at this point we only support
 * sigev_notify equal to SIGEV_SIGNAL or SIGEV_NONE.  this means
 * sigev_value, sigev_notify_function, and sigev_notify_attributes
 * are ignored, since SIGEV_THREAD is unsupported.  This is consistent
 * with no [RTS] (RalTime Signal) option group support.
 */
static int
aio_sigev_validate(const struct user_sigevent *sigev)
{
	switch (sigev->sigev_notify) {
	case SIGEV_SIGNAL:
	{
		int signum;

		/* make sure we have a valid signal number */
		signum = sigev->sigev_signo;
		if (signum <= 0 || signum >= NSIG ||
		    signum == SIGKILL || signum == SIGSTOP) {
			return EINVAL;
		}
	}
	break;

	case SIGEV_NONE:
		break;

	case SIGEV_THREAD:
	/* Unsupported [RTS] */

	default:
		return EINVAL;
	}

	return 0;
}


/*
 * aio_try_enqueue_work_locked
 *
 * Queue up the entry on the aio asynchronous work queue in priority order
 * based on the relative priority of the request.  We calculate the relative
 * priority using the nice value of the caller and the value
 *
 * Parameters:	procp			Process queueing the I/O
 *		entryp			The work queue entry being queued
 *		leader			The work leader if any
 *
 * Returns:	Wether the enqueue was successful
 *
 * Notes:	This function is used for both lio_listio and aio
 *
 * XXX:		At some point, we may have to consider thread priority
 *		rather than process priority, but we don't maintain the
 *		adjusted priority for threads the POSIX way.
 *
 * Called with proc locked.
 */
static bool
aio_try_enqueue_work_locked(proc_t procp, aio_workq_entry *entryp,
    aio_workq_entry *leader)
{
	aio_workq_t queue = aio_entry_workq(entryp);

	ASSERT_AIO_PROC_LOCK_OWNED(procp);

	/* Onto proc queue */
	if (!aio_try_proc_insert_active_locked(procp, entryp)) {
		return false;
	}

	if (leader) {
		aio_entry_ref(leader); /* consumed in do_aio_completion_and_unlock */
		leader->lio_pending++;
		entryp->lio_leader = leader;
	}

	/* And work queue */
	aio_entry_ref(entryp); /* consumed in do_aio_completion_and_unlock */
	aio_workq_lock_spin(queue);
	aio_workq_add_entry_locked(queue, entryp);
	waitq_wakeup64_one(&queue->aioq_waitq, CAST_EVENT64_T(queue),
	    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
	aio_workq_unlock(queue);

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(procp), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
	    entryp->flags, entryp->aiocb.aio_fildes, 0);
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued) | DBG_FUNC_END,
	    entryp->aiocb.aio_offset, 0, entryp->aiocb.aio_nbytes, 0, 0);
	return true;
}


/*
 * lio_listio - initiate a list of IO requests.  We process the list of
 * aiocbs either synchronously (mode == LIO_WAIT) or asynchronously
 * (mode == LIO_NOWAIT).
 *
 * The caller gets error and return status for each aiocb in the list
 * via aio_error and aio_return.  We must keep completed requests until
 * released by the aio_return call.
 */
int
lio_listio(proc_t p, struct lio_listio_args *uap, int *retval __unused)
{
	aio_workq_entry         *entries[AIO_LISTIO_MAX] = { };
	user_addr_t              aiocbpp[AIO_LISTIO_MAX];
	struct user_sigevent     aiosigev = { };
	int                      result = 0;
	int                      lio_count = 0;

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_listio) | DBG_FUNC_START,
	    VM_KERNEL_ADDRPERM(p), uap->nent, uap->mode, 0, 0);

	if (!(uap->mode == LIO_NOWAIT || uap->mode == LIO_WAIT)) {
		result = EINVAL;
		goto ExitRoutine;
	}

	if (uap->nent < 1 || uap->nent > AIO_LISTIO_MAX) {
		result = EINVAL;
		goto ExitRoutine;
	}

	/*
	 * Use sigevent passed in to lio_listio for each of our calls, but
	 * only do completion notification after the last request completes.
	 */
	if (uap->sigp != USER_ADDR_NULL) {
		result = aio_copy_in_sigev(p, uap->sigp, &aiosigev);
		if (result) {
			goto ExitRoutine;
		}
		result = aio_sigev_validate(&aiosigev);
		if (result) {
			goto ExitRoutine;
		}
	}

	if (aio_copy_in_list(p, uap->aiocblist, aiocbpp, uap->nent)) {
		result = EAGAIN;
		goto ExitRoutine;
	}

	/*
	 * allocate/parse all entries
	 */
	for (int i = 0; i < uap->nent; i++) {
		aio_workq_entry *entryp;

		/* NULL elements are legal so check for 'em */
		if (aiocbpp[i] == USER_ADDR_NULL) {
			continue;
		}

		entryp = aio_create_queue_entry(p, aiocbpp[i], AIO_LIO);
		if (entryp == NULL) {
			result = EAGAIN;
			goto ExitRoutine;
		}

		/*
		 * This refcount is cleaned up on exit if the entry
		 * isn't submitted
		 */
		entries[lio_count++] = entryp;
		if (uap->mode == LIO_NOWAIT) {
			/* Set signal hander, if any */
			entryp->aiocb.aio_sigevent = aiosigev;
		}
	}

	if (lio_count == 0) {
		/* There's nothing to submit */
		goto ExitRoutine;
	}

	/*
	 * Past this point we're commited and will not bail out
	 *
	 * - keep a reference on the leader for LIO_WAIT
	 * - perform the submissions and optionally wait
	 */

	aio_workq_entry *leader = entries[0];
	if (uap->mode == LIO_WAIT) {
		aio_entry_ref(leader); /* consumed below */
	}

	aio_proc_lock_spin(p);

	for (int i = 0; i < lio_count; i++) {
		if (aio_try_enqueue_work_locked(p, entries[i], leader)) {
			entries[i] = NULL; /* the entry was submitted */
		} else {
			result = EAGAIN;
		}
	}

	if (uap->mode == LIO_WAIT && result == 0) {
		leader->flags |= AIO_LIO_WAIT;

		while (leader->lio_pending) {
			/* If we were interrupted, fail out (even if all finished) */
			if (msleep(leader, aio_proc_mutex(p),
			    PCATCH | PRIBIO | PSPIN, "lio_listio", 0) != 0) {
				result = EINTR;
				break;
			}
		}

		leader->flags &= ~AIO_LIO_WAIT;
	}

	aio_proc_unlock(p);

	if (uap->mode == LIO_WAIT) {
		aio_entry_unref(leader);
	}

ExitRoutine:
	/* Consume unsubmitted entries */
	for (int i = 0; i < lio_count; i++) {
		if (entries[i]) {
			aio_entry_unref(entries[i]);
		}
	}

	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_listio) | DBG_FUNC_END,
	    VM_KERNEL_ADDRPERM(p), result, 0, 0, 0);

	return result;
}


/*
 * aio worker thread.  this is where all the real work gets done.
 * we get a wake up call on sleep channel &aio_anchor.aio_async_workq
 * after new work is queued up.
 */
__attribute__((noreturn))
static void
aio_work_thread(void *arg __unused, wait_result_t wr __unused)
{
	aio_workq_entry *entryp;
	int              error;
	vm_map_t         currentmap;
	vm_map_t         oldmap = VM_MAP_NULL;
	task_t           oldaiotask = TASK_NULL;
	struct uthread  *uthreadp = NULL;
	proc_t           p = NULL;

	for (;;) {
		/*
		 * returns with the entry ref'ed.
		 * sleeps until work is available.
		 */
		entryp = aio_get_some_work();
		p = entryp->procp;

		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread) | DBG_FUNC_START,
		    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
		    entryp->flags, 0, 0);

		/*
		 * Assume the target's address space identity for the duration
		 * of the IO.  Note: don't need to have the entryp locked,
		 * because the proc and map don't change until it's freed.
		 */
		currentmap = get_task_map((current_proc())->task);
		if (currentmap != entryp->aio_map) {
			uthreadp = (struct uthread *) get_bsdthread_info(current_thread());
			oldaiotask = uthreadp->uu_aio_task;
			/*
			 * workq entries at this stage cause _aio_exec() and _aio_exit() to
			 * block until we hit `do_aio_completion_and_unlock()` below,
			 * which means that it is safe to dereference p->task without
			 * holding a lock or taking references.
			 */
			uthreadp->uu_aio_task = p->task;
			oldmap = vm_map_switch(entryp->aio_map);
		}

		if ((entryp->flags & AIO_READ) != 0) {
			error = do_aio_read(entryp);
		} else if ((entryp->flags & AIO_WRITE) != 0) {
			error = do_aio_write(entryp);
		} else if ((entryp->flags & (AIO_FSYNC | AIO_DSYNC)) != 0) {
			error = do_aio_fsync(entryp);
		} else {
			error = EINVAL;
		}

		/* Restore old map */
		if (currentmap != entryp->aio_map) {
			vm_map_switch(oldmap);
			uthreadp->uu_aio_task = oldaiotask;
		}

		/* liberate unused map */
		vm_map_deallocate(entryp->aio_map);
		entryp->aio_map = VM_MAP_NULL;

		KERNEL_DEBUG(SDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread) | DBG_FUNC_END,
		    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
		    entryp->errorval, entryp->returnval, 0);

		/* we're done with the IO request so pop it off the active queue and */
		/* push it on the done queue */
		aio_proc_lock(p);
		entryp->errorval = error;
		do_aio_completion_and_unlock(p, entryp);
	}
}


/*
 * aio_get_some_work - get the next async IO request that is ready to be executed.
 * aio_fsync complicates matters a bit since we cannot do the fsync until all async
 * IO requests at the time the aio_fsync call came in have completed.
 * NOTE - AIO_LOCK must be held by caller
 */
static aio_workq_entry *
aio_get_some_work(void)
{
	aio_workq_entry *entryp = NULL;
	aio_workq_t      queue = NULL;

	/* Just one queue for the moment.  In the future there will be many. */
	queue = &aio_anchor.aio_async_workqs[0];
	aio_workq_lock_spin(queue);

	/*
	 * Hold the queue lock.
	 *
	 * pop some work off the work queue and add to our active queue
	 * Always start with the queue lock held.
	 */
	while ((entryp = TAILQ_FIRST(&queue->aioq_entries))) {
		/*
		 * Pull of of work queue.  Once it's off, it can't be cancelled,
		 * so we can take our ref once we drop the queue lock.
		 */

		aio_workq_remove_entry_locked(queue, entryp);

		aio_workq_unlock(queue);

		/*
		 * Check if it's an fsync that must be delayed.  No need to lock the entry;
		 * that flag would have been set at initialization.
		 */
		if ((entryp->flags & AIO_FSYNC) != 0) {
			/*
			 * Check for unfinished operations on the same file
			 * in this proc's queue.
			 */
			aio_proc_lock_spin(entryp->procp);
			if (aio_delay_fsync_request(entryp)) {
				/* It needs to be delayed.  Put it back on the end of the work queue */
				KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync_delay) | DBG_FUNC_NONE,
				    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
				    0, 0, 0);

				aio_proc_unlock(entryp->procp);

				aio_workq_lock_spin(queue);
				aio_workq_add_entry_locked(queue, entryp);
				continue;
			}
			aio_proc_unlock(entryp->procp);
		}

		return entryp;
	}

	/* We will wake up when someone enqueues something */
	waitq_assert_wait64(&queue->aioq_waitq, CAST_EVENT64_T(queue), THREAD_UNINT, 0);
	aio_workq_unlock(queue);
	thread_block(aio_work_thread);

	__builtin_unreachable();
}

/*
 * aio_delay_fsync_request - look to see if this aio_fsync request should be delayed.
 * A big, simple hammer: only send it off if it's the most recently filed IO which has
 * not been completed.
 */
static boolean_t
aio_delay_fsync_request(aio_workq_entry *entryp)
{
	if (proc_in_teardown(entryp->procp)) {
		/*
		 * we can't delay FSYNCS when in teardown as it will confuse _aio_exit,
		 * if it was dequeued, then we must now commit to it
		 */
		return FALSE;
	}

	if (entryp == TAILQ_FIRST(&entryp->procp->p_aio_activeq)) {
		return FALSE;
	}

	return TRUE;
}

static aio_workq_entry *
aio_create_queue_entry(proc_t procp, user_addr_t aiocbp, aio_entry_flags_t flags)
{
	aio_workq_entry *entryp;

	entryp = zalloc_flags(aio_workq_zonep, Z_WAITOK | Z_ZERO);
	entryp->procp = procp;
	entryp->uaiocbp = aiocbp;
	entryp->flags = flags;
	/* consumed in aio_return or _aio_exit */
	os_ref_init(&entryp->aio_refcount, &aio_refgrp);

	if (proc_is64bit(procp)) {
		struct user64_aiocb aiocb64;

		if (copyin(aiocbp, &aiocb64, sizeof(aiocb64)) != 0) {
			goto error_exit;
		}
		do_munge_aiocb_user64_to_user(&aiocb64, &entryp->aiocb);
	} else {
		struct user32_aiocb aiocb32;

		if (copyin(aiocbp, &aiocb32, sizeof(aiocb32)) != 0) {
			goto error_exit;
		}
		do_munge_aiocb_user32_to_user(&aiocb32, &entryp->aiocb);
	}

	/* do some more validation on the aiocb and embedded file descriptor */
	if (aio_validate(procp, entryp) != 0) {
		goto error_exit;
	}

	/* get a reference to the user land map in order to keep it around */
	entryp->aio_map = get_task_map(procp->task);
	vm_map_reference(entryp->aio_map);

	/* get a reference on the current_thread, which is passed in vfs_context. */
	entryp->thread = current_thread();
	thread_reference(entryp->thread);
	return entryp;

error_exit:
	zfree(aio_workq_zonep, entryp);
	return NULL;
}


/*
 * aio_queue_async_request - queue up an async IO request on our work queue then
 * wake up one of our worker threads to do the actual work.  We get a reference
 * to our caller's user land map in order to keep it around while we are
 * processing the request.
 */
static int
aio_queue_async_request(proc_t procp, user_addr_t aiocbp,
    aio_entry_flags_t flags)
{
	aio_workq_entry *entryp;
	int              result;

	entryp = aio_create_queue_entry(procp, aiocbp, flags);
	if (entryp == NULL) {
		result = EAGAIN;
		goto error_noalloc;
	}

	aio_proc_lock_spin(procp);
	if (!aio_try_enqueue_work_locked(procp, entryp, NULL)) {
		result = EAGAIN;
		goto error_exit;
	}
	aio_proc_unlock(procp);
	return 0;

error_exit:
	/*
	 * This entry has not been queued up so no worries about
	 * unlocked state and aio_map
	 */
	aio_proc_unlock(procp);
	aio_free_request(entryp);
error_noalloc:
	return result;
}


/*
 * aio_free_request - remove our reference on the user land map and
 * free the work queue entry resources.  The entry is off all lists
 * and has zero refcount, so no one can have a pointer to it.
 */
static void
aio_free_request(aio_workq_entry *entryp)
{
	if (entryp->aio_proc_link.tqe_prev || entryp->aio_workq_link.tqe_prev) {
		panic("aio_workq_entry %p being freed while still enqueued", entryp);
	}

	/* remove our reference to the user land map. */
	if (VM_MAP_NULL != entryp->aio_map) {
		vm_map_deallocate(entryp->aio_map);
	}

	/* remove our reference to thread which enqueued the request */
	if (NULL != entryp->thread) {
		thread_deallocate(entryp->thread);
	}

	zfree(aio_workq_zonep, entryp);
}


/*
 * aio_validate
 *
 * validate the aiocb passed in by one of the aio syscalls.
 */
static int
aio_validate(proc_t p, aio_workq_entry *entryp)
{
	struct fileproc *fp;
	int              flag;
	int              result;

	result = 0;

	if ((entryp->flags & AIO_LIO) != 0) {
		if (entryp->aiocb.aio_lio_opcode == LIO_READ) {
			entryp->flags |= AIO_READ;
		} else if (entryp->aiocb.aio_lio_opcode == LIO_WRITE) {
			entryp->flags |= AIO_WRITE;
		} else if (entryp->aiocb.aio_lio_opcode == LIO_NOP) {
			return 0;
		} else {
			return EINVAL;
		}
	}

	flag = FREAD;
	if ((entryp->flags & (AIO_WRITE | AIO_FSYNC | AIO_DSYNC)) != 0) {
		flag = FWRITE;
	}

	if ((entryp->flags & (AIO_READ | AIO_WRITE)) != 0) {
		if (entryp->aiocb.aio_nbytes > INT_MAX ||
		    entryp->aiocb.aio_buf == USER_ADDR_NULL ||
		    entryp->aiocb.aio_offset < 0) {
			return EINVAL;
		}
	}

	result = aio_sigev_validate(&entryp->aiocb.aio_sigevent);
	if (result) {
		return result;
	}

	/* validate the file descriptor and that the file was opened
	 * for the appropriate read / write access.
	 */
	proc_fdlock(p);

	fp = fp_get_noref_locked(p, entryp->aiocb.aio_fildes);
	if (fp == NULL) {
		result = EBADF;
	} else if ((fp->fp_glob->fg_flag & flag) == 0) {
		/* we don't have read or write access */
		result = EBADF;
	} else if (FILEGLOB_DTYPE(fp->fp_glob) != DTYPE_VNODE) {
		/* this is not a file */
		result = ESPIPE;
	} else {
		fp->fp_flags |= FP_AIOISSUED;
	}

	proc_fdunlock(p);

	return result;
}

/*
 * do_aio_completion_and_unlock.  Handle async IO completion.
 */
static void
do_aio_completion_and_unlock(proc_t p, aio_workq_entry *entryp)
{
	aio_workq_entry *leader = entryp->lio_leader;
	int              lio_pending = 0;
	bool             do_signal = false;

	ASSERT_AIO_PROC_LOCK_OWNED(p);

	aio_proc_move_done_locked(p, entryp);

	if (leader) {
		lio_pending = --leader->lio_pending;
		if (lio_pending < 0) {
			panic("lio_pending accounting mistake");
		}
		if (lio_pending == 0 && (leader->flags & AIO_LIO_WAIT)) {
			wakeup(leader);
		}
		entryp->lio_leader = NULL; /* no dangling pointers please */
	}

	/*
	 * need to handle case where a process is trying to exit, exec, or
	 * close and is currently waiting for active aio requests to complete.
	 * If AIO_CLEANUP_WAIT is set then we need to look to see if there are any
	 * other requests in the active queue for this process.  If there are
	 * none then wakeup using the AIO_CLEANUP_SLEEP_CHAN tsleep channel.
	 * If there are some still active then do nothing - we only want to
	 * wakeup when all active aio requests for the process are complete.
	 */
	if (__improbable(entryp->flags & AIO_EXIT_WAIT)) {
		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wait) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
		    0, 0, 0);

		if (!aio_has_active_requests_for_process(p)) {
			/*
			 * no active aio requests for this process, continue exiting.  In this
			 * case, there should be no one else waiting ont he proc in AIO...
			 */
			wakeup_one((caddr_t)&p->AIO_CLEANUP_SLEEP_CHAN);

			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wake) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
			    0, 0, 0);
		}
	} else if (entryp->aiocb.aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
		/*
		 * If this was the last request in the group, or not part of
		 * a group, and that a signal is desired, send one.
		 */
		do_signal = (lio_pending == 0);
	}

	if (__improbable(entryp->flags & AIO_CLOSE_WAIT)) {
		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wait) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
		    0, 0, 0);

		if (!aio_proc_has_active_requests_for_file(p, entryp->aiocb.aio_fildes)) {
			/* Can't wakeup_one(); multiple closes might be in progress. */
			wakeup(&p->AIO_CLEANUP_SLEEP_CHAN);

			KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wake) | DBG_FUNC_NONE,
			    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
			    0, 0, 0);
		}
	}

	aio_proc_unlock(p);

	if (do_signal) {
		KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_sig) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp),
		    entryp->aiocb.aio_sigevent.sigev_signo, 0, 0);

		psignal(p, entryp->aiocb.aio_sigevent.sigev_signo);
	}

	/*
	 * A thread in aio_suspend() wants to known about completed IOs.  If it checked
	 * the done list before we moved our AIO there, then it already asserted its wait,
	 * and we can wake it up without holding the lock.  If it checked the list after
	 * we did our move, then it already has seen the AIO that we moved.  Herego, we
	 * can do our wakeup without holding the lock.
	 */
	wakeup(&p->AIO_SUSPEND_SLEEP_CHAN);
	KERNEL_DEBUG(BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_suspend_wake) | DBG_FUNC_NONE,
	    VM_KERNEL_ADDRPERM(p), VM_KERNEL_ADDRPERM(entryp->uaiocbp), 0, 0, 0);

	aio_entry_unref(entryp); /* see aio_try_enqueue_work_locked */
	if (leader) {
		aio_entry_unref(leader); /* see lio_listio */
	}
}


/*
 * do_aio_read
 */
static int
do_aio_read(aio_workq_entry *entryp)
{
	struct proc     *p = entryp->procp;
	struct fileproc *fp;
	int error;

	if ((error = fp_lookup(p, entryp->aiocb.aio_fildes, &fp, 0))) {
		return error;
	}

	if (fp->fp_glob->fg_flag & FREAD) {
		struct vfs_context context = {
			.vc_thread = entryp->thread,     /* XXX */
			.vc_ucred = fp->fp_glob->fg_cred,
		};

		error = dofileread(&context, fp,
		    entryp->aiocb.aio_buf,
		    entryp->aiocb.aio_nbytes,
		    entryp->aiocb.aio_offset, FOF_OFFSET,
		    &entryp->returnval);
	} else {
		error = EBADF;
	}

	fp_drop(p, entryp->aiocb.aio_fildes, fp, 0);
	return error;
}


/*
 * do_aio_write
 */
static int
do_aio_write(aio_workq_entry *entryp)
{
	struct proc     *p = entryp->procp;
	struct fileproc *fp;
	int error;

	if ((error = fp_lookup(p, entryp->aiocb.aio_fildes, &fp, 0))) {
		return error;
	}

	if (fp->fp_glob->fg_flag & FWRITE) {
		struct vfs_context context = {
			.vc_thread = entryp->thread,     /* XXX */
			.vc_ucred = fp->fp_glob->fg_cred,
		};
		int flags = FOF_PCRED;

		if ((fp->fp_glob->fg_flag & O_APPEND) == 0) {
			flags |= FOF_OFFSET;
		}

		/* NB: tell dofilewrite the offset, and to use the proc cred */
		error = dofilewrite(&context,
		    fp,
		    entryp->aiocb.aio_buf,
		    entryp->aiocb.aio_nbytes,
		    entryp->aiocb.aio_offset,
		    flags,
		    &entryp->returnval);
	} else {
		error = EBADF;
	}

	fp_drop(p, entryp->aiocb.aio_fildes, fp, 0);
	return error;
}


/*
 * aio_has_active_requests_for_process - return whether the process has active
 * requests pending.
 */
static bool
aio_has_active_requests_for_process(proc_t procp)
{
	return !TAILQ_EMPTY(&procp->p_aio_activeq);
}

/*
 * Called with the proc locked.
 */
static bool
aio_proc_has_active_requests_for_file(proc_t procp, int fd)
{
	aio_workq_entry *entryp;

	TAILQ_FOREACH(entryp, &procp->p_aio_activeq, aio_proc_link) {
		if (entryp->aiocb.aio_fildes == fd) {
			return true;
		}
	}

	return false;
}


/*
 * do_aio_fsync
 */
static int
do_aio_fsync(aio_workq_entry *entryp)
{
	struct proc            *p = entryp->procp;
	struct vnode           *vp;
	struct fileproc        *fp;
	int                     sync_flag;
	int                     error;

	/*
	 * We are never called unless either AIO_FSYNC or AIO_DSYNC are set.
	 *
	 * If AIO_DSYNC is set, we can tell the lower layers that it is OK
	 * to mark for update the metadata not strictly necessary for data
	 * retrieval, rather than forcing it to disk.
	 *
	 * If AIO_FSYNC is set, we have to also wait for metadata not really
	 * necessary to data retrival are committed to stable storage (e.g.
	 * atime, mtime, ctime, etc.).
	 *
	 * Metadata necessary for data retrieval ust be committed to stable
	 * storage in either case (file length, etc.).
	 */
	if (entryp->flags & AIO_FSYNC) {
		sync_flag = MNT_WAIT;
	} else {
		sync_flag = MNT_DWAIT;
	}

	error = fp_get_ftype(p, entryp->aiocb.aio_fildes, DTYPE_VNODE, ENOTSUP, &fp);
	if (error != 0) {
		entryp->returnval = -1;
		return error;
	}
	vp = fp->fp_glob->fg_data;

	if ((error = vnode_getwithref(vp)) == 0) {
		struct vfs_context context = {
			.vc_thread = entryp->thread,     /* XXX */
			.vc_ucred = fp->fp_glob->fg_cred,
		};

		error = VNOP_FSYNC(vp, sync_flag, &context);

		(void)vnode_put(vp);
	} else {
		entryp->returnval = -1;
	}

	fp_drop(p, entryp->aiocb.aio_fildes, fp, 0);
	return error;
}


/*
 * is_already_queued - runs through our queues to see if the given
 * aiocbp / process is there.  Returns TRUE if there is a match
 * on any of our aio queues.
 *
 * Called with proc aio lock held (can be held spin)
 */
static boolean_t
is_already_queued(proc_t procp, user_addr_t aiocbp)
{
	aio_workq_entry *entryp;
	boolean_t        result;

	result = FALSE;

	/* look for matches on our queue of async IO requests that have completed */
	TAILQ_FOREACH(entryp, &procp->p_aio_doneq, aio_proc_link) {
		if (aiocbp == entryp->uaiocbp) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}

	/* look for matches on our queue of active async IO requests */
	TAILQ_FOREACH(entryp, &procp->p_aio_activeq, aio_proc_link) {
		if (aiocbp == entryp->uaiocbp) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}

ExitThisRoutine:
	return result;
}


/*
 * aio initialization
 */
__private_extern__ void
aio_init(void)
{
	for (int i = 0; i < AIO_NUM_WORK_QUEUES; i++) {
		aio_workq_init(&aio_anchor.aio_async_workqs[i]);
	}

	_aio_create_worker_threads(aio_worker_threads);
}


/*
 * aio worker threads created here.
 */
__private_extern__ void
_aio_create_worker_threads(int num)
{
	int i;

	/* create some worker threads to handle the async IO requests */
	for (i = 0; i < num; i++) {
		thread_t                myThread;

		if (KERN_SUCCESS != kernel_thread_start(aio_work_thread, NULL, &myThread)) {
			printf("%s - failed to create a work thread \n", __FUNCTION__);
		} else {
			thread_deallocate(myThread);
		}
	}
}

/*
 * Return the current activation utask
 */
task_t
get_aiotask(void)
{
	return ((struct uthread *)get_bsdthread_info(current_thread()))->uu_aio_task;
}


/*
 * In the case of an aiocb from a
 * 32-bit process we need to expand some longs and pointers to the correct
 * sizes in order to let downstream code always work on the same type of
 * aiocb (in our case that is a user_aiocb)
 */
static void
do_munge_aiocb_user32_to_user(struct user32_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp)
{
	the_user_aiocbp->aio_fildes = my_aiocbp->aio_fildes;
	the_user_aiocbp->aio_offset = my_aiocbp->aio_offset;
	the_user_aiocbp->aio_buf = CAST_USER_ADDR_T(my_aiocbp->aio_buf);
	the_user_aiocbp->aio_nbytes = my_aiocbp->aio_nbytes;
	the_user_aiocbp->aio_reqprio = my_aiocbp->aio_reqprio;
	the_user_aiocbp->aio_lio_opcode = my_aiocbp->aio_lio_opcode;

	/* special case here.  since we do not know if sigev_value is an */
	/* int or a ptr we do NOT cast the ptr to a user_addr_t.   This  */
	/* means if we send this info back to user space we need to remember */
	/* sigev_value was not expanded for the 32-bit case.  */
	/* NOTE - this does NOT affect us since we don't support sigev_value */
	/* yet in the aio context.  */
	//LP64
	the_user_aiocbp->aio_sigevent.sigev_notify = my_aiocbp->aio_sigevent.sigev_notify;
	the_user_aiocbp->aio_sigevent.sigev_signo = my_aiocbp->aio_sigevent.sigev_signo;
	the_user_aiocbp->aio_sigevent.sigev_value.size_equivalent.sival_int =
	    my_aiocbp->aio_sigevent.sigev_value.sival_int;
	the_user_aiocbp->aio_sigevent.sigev_notify_function =
	    CAST_USER_ADDR_T(my_aiocbp->aio_sigevent.sigev_notify_function);
	the_user_aiocbp->aio_sigevent.sigev_notify_attributes =
	    CAST_USER_ADDR_T(my_aiocbp->aio_sigevent.sigev_notify_attributes);
}

/* Similar for 64-bit user process, so that we don't need to satisfy
 * the alignment constraints of the original user64_aiocb
 */
#if !__LP64__
__dead2
#endif
static void
do_munge_aiocb_user64_to_user(struct user64_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp)
{
#if __LP64__
	the_user_aiocbp->aio_fildes = my_aiocbp->aio_fildes;
	the_user_aiocbp->aio_offset = my_aiocbp->aio_offset;
	the_user_aiocbp->aio_buf = my_aiocbp->aio_buf;
	the_user_aiocbp->aio_nbytes = my_aiocbp->aio_nbytes;
	the_user_aiocbp->aio_reqprio = my_aiocbp->aio_reqprio;
	the_user_aiocbp->aio_lio_opcode = my_aiocbp->aio_lio_opcode;

	the_user_aiocbp->aio_sigevent.sigev_notify = my_aiocbp->aio_sigevent.sigev_notify;
	the_user_aiocbp->aio_sigevent.sigev_signo = my_aiocbp->aio_sigevent.sigev_signo;
	the_user_aiocbp->aio_sigevent.sigev_value.size_equivalent.sival_int =
	    my_aiocbp->aio_sigevent.sigev_value.size_equivalent.sival_int;
	the_user_aiocbp->aio_sigevent.sigev_notify_function =
	    my_aiocbp->aio_sigevent.sigev_notify_function;
	the_user_aiocbp->aio_sigevent.sigev_notify_attributes =
	    my_aiocbp->aio_sigevent.sigev_notify_attributes;
#else
#pragma unused(my_aiocbp, the_user_aiocbp)
	panic("64bit process on 32bit kernel is not supported");
#endif
}
