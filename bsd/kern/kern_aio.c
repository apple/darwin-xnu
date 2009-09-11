/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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
 *		   	the user's map (vm_map_reference()) since it is believed that 
 *			would not hold the process for us.
 *		2) david is looking into a way for us to set the priority of the
 *		   	worker threads to match that of the user's thread when the 
 *		   	async IO was queued.
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
#include <kern/zalloc.h>
#include <kern/task.h>
#include <kern/sched_prim.h>

#include <vm/vm_map.h>

#include <libkern/OSAtomic.h>

#include <sys/kdebug.h>
#define AIO_work_queued					1
#define AIO_worker_wake				 	2
#define AIO_completion_sig				3
#define AIO_completion_cleanup_wait		4
#define AIO_completion_cleanup_wake		5
#define AIO_completion_suspend_wake 	6
#define AIO_fsync_delay					7
#define AIO_cancel 						10
#define AIO_cancel_async_workq			11
#define AIO_cancel_sync_workq			12
#define AIO_cancel_activeq				13
#define AIO_cancel_doneq				14
#define AIO_fsync						20
#define AIO_read						30
#define AIO_write						40
#define AIO_listio						50
#define AIO_error						60
#define AIO_error_val					61
#define AIO_error_activeq				62
#define AIO_error_workq					63
#define	AIO_return						70
#define	AIO_return_val					71
#define	AIO_return_activeq				72
#define	AIO_return_workq				73
#define AIO_exec						80
#define AIO_exit						90
#define AIO_exit_sleep					91
#define AIO_close						100
#define AIO_close_sleep					101
#define AIO_suspend						110
#define AIO_suspend_sleep				111
#define AIO_worker_thread				120

#if 0
#undef KERNEL_DEBUG
#define KERNEL_DEBUG KERNEL_DEBUG_CONSTANT
#endif

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
	TAILQ_HEAD(, aio_workq_entry) 	aioq_entries;
	int				aioq_count;
	lck_mtx_t			aioq_mtx;
	wait_queue_t			aioq_waitq;
} *aio_workq_t;

#define AIO_NUM_WORK_QUEUES 1
struct aio_anchor_cb
{
	volatile int32_t	aio_inflight_count; 	/* entries that have been taken from a workq */
	volatile int32_t	aio_done_count; 	/* entries on all done queues (proc.aio_doneq) */
	volatile int32_t	aio_total_count;	/* total extant entries */
	
	/* Hash table of queues here */
	int 			aio_num_workqs;
	struct aio_workq 	aio_async_workqs[AIO_NUM_WORK_QUEUES];
};
typedef struct aio_anchor_cb aio_anchor_cb;

struct aio_lio_context
{
	int		io_waiter;
	int		io_issued;
	int		io_completed;
};
typedef struct aio_lio_context aio_lio_context;


/*
 * Notes on aio sleep / wake channels.
 * We currently pick a couple fields within the proc structure that will allow
 * us sleep channels that currently do not collide with any other kernel routines.
 * At this time, for binary compatibility reasons, we cannot create new proc fields.
 */
#define AIO_SUSPEND_SLEEP_CHAN  p_aio_active_count
#define AIO_CLEANUP_SLEEP_CHAN 	p_aio_total_count

#define ASSERT_AIO_FROM_PROC(aiop, theproc) 	\
	if ((aiop)->procp != (theproc)) { 	\
		panic("AIO on a proc list that does not belong to that proc.\n"); \
	}

/*
 *  LOCAL PROTOTYPES
 */
static void		aio_proc_lock(proc_t procp);
static void		aio_proc_lock_spin(proc_t procp);
static void		aio_proc_unlock(proc_t procp);
static lck_mtx_t*	aio_proc_mutex(proc_t procp);
static void		aio_proc_move_done_locked(proc_t procp, aio_workq_entry *entryp);
static void		aio_proc_remove_done_locked(proc_t procp, aio_workq_entry *entryp);
static int		aio_get_process_count(proc_t procp );
static int		aio_active_requests_for_process(proc_t procp );
static int		aio_proc_active_requests_for_file(proc_t procp, int fd);
static boolean_t	is_already_queued(proc_t procp, user_addr_t aiocbp );
static boolean_t	should_cancel(aio_workq_entry *entryp, user_addr_t aiocbp, int fd);

static void		aio_entry_lock(aio_workq_entry *entryp);
static void		aio_entry_lock_spin(aio_workq_entry *entryp);
static aio_workq_t	aio_entry_workq(aio_workq_entry *entryp);
static lck_mtx_t*	aio_entry_mutex(__unused aio_workq_entry *entryp);
static void		aio_workq_remove_entry_locked(aio_workq_t queue, aio_workq_entry *entryp);
static void		aio_workq_add_entry_locked(aio_workq_t queue, aio_workq_entry *entryp);
static void		aio_entry_ref_locked(aio_workq_entry *entryp);
static void		aio_entry_unref_locked(aio_workq_entry *entryp);
static void		aio_entry_ref(aio_workq_entry *entryp);
static void		aio_entry_unref(aio_workq_entry *entryp);
static void		aio_entry_update_for_cancel(aio_workq_entry *entryp, boolean_t cancelled, 
					int wait_for_completion, boolean_t disable_notification);
static int		aio_entry_try_workq_remove(aio_workq_entry *entryp);
static boolean_t	aio_delay_fsync_request( aio_workq_entry *entryp );
static int		aio_free_request(aio_workq_entry *entryp);

static void		aio_workq_init(aio_workq_t wq);
static void		aio_workq_lock_spin(aio_workq_t wq);
static void		aio_workq_unlock(aio_workq_t wq);
static lck_mtx_t*	aio_workq_mutex(aio_workq_t wq);

static void		aio_work_thread( void );
static aio_workq_entry *aio_get_some_work( void );

static int		aio_get_all_queues_count( void );
static int		aio_queue_async_request(proc_t procp, user_addr_t aiocbp, int kindOfIO );
static int		aio_validate( aio_workq_entry *entryp );
static int 		aio_increment_total_count(void);
static int 		aio_decrement_total_count(void);

static int		do_aio_cancel_locked(proc_t p, int fd, user_addr_t aiocbp, int wait_for_completion, boolean_t disable_notification );
static void		do_aio_completion( aio_workq_entry *entryp );
static int		do_aio_fsync( aio_workq_entry *entryp );
static int		do_aio_read( aio_workq_entry *entryp );
static int		do_aio_write( aio_workq_entry *entryp );
static void 		do_munge_aiocb_user32_to_user( struct user32_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp );
static void 		do_munge_aiocb_user64_to_user( struct user64_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp );
static int	lio_create_entry(proc_t procp, 
					 user_addr_t aiocbp, 
					 void *group_tag,
					 aio_workq_entry **entrypp );
static aio_workq_entry *aio_create_queue_entry(proc_t procp,
					user_addr_t aiocbp,
					void *group_tag,
					int kindOfIO);
static user_addr_t *aio_copy_in_list(proc_t procp, user_addr_t aiocblist, int nent);
static void		free_lio_context(aio_lio_context* context);
static void 		aio_enqueue_work( proc_t procp, aio_workq_entry *entryp, int proc_locked);

#define ASSERT_AIO_PROC_LOCK_OWNED(p)	lck_mtx_assert(aio_proc_mutex((p)), LCK_MTX_ASSERT_OWNED)
#define ASSERT_AIO_WORKQ_LOCK_OWNED(q)	lck_mtx_assert(aio_workq_mutex((q)), LCK_MTX_ASSERT_OWNED)
#define ASSERT_AIO_ENTRY_LOCK_OWNED(e)	lck_mtx_assert(aio_entry_mutex((e)), LCK_MTX_ASSERT_OWNED)

/*
 *  EXTERNAL PROTOTYPES
 */

/* in ...bsd/kern/sys_generic.c */
extern int dofileread(vfs_context_t ctx, struct fileproc *fp,
			user_addr_t bufp, user_size_t nbyte, 
			off_t offset, int flags, user_ssize_t *retval );
extern int dofilewrite(vfs_context_t ctx, struct fileproc *fp,
			 user_addr_t bufp, user_size_t nbyte, off_t offset, 
			 int flags, user_ssize_t *retval );
#if DEBUG
static uint32_t                         lio_contexts_alloced = 0; 
#endif  /* DEBUG */

/*
 * aio external global variables.
 */
extern int aio_max_requests;  			/* AIO_MAX - configurable */
extern int aio_max_requests_per_process;	/* AIO_PROCESS_MAX - configurable */
extern int aio_worker_threads;			/* AIO_THREAD_COUNT - configurable */


/*
 * aio static variables.
 */
static aio_anchor_cb	aio_anchor;
static lck_grp_t	*aio_proc_lock_grp;
static lck_grp_t	*aio_entry_lock_grp;
static lck_grp_t	*aio_queue_lock_grp;
static lck_attr_t	*aio_lock_attr;
static lck_grp_attr_t	*aio_lock_grp_attr;
static struct zone  	*aio_workq_zonep;
static lck_mtx_t	aio_entry_mtx;
static lck_mtx_t	aio_proc_mtx;

static void
aio_entry_lock(__unused aio_workq_entry *entryp)
{
	lck_mtx_lock(&aio_entry_mtx);
}

static void		
aio_entry_lock_spin(__unused aio_workq_entry *entryp)
{
	lck_mtx_lock_spin(&aio_entry_mtx);
}

static void	
aio_entry_unlock(__unused aio_workq_entry *entryp)
{
	lck_mtx_unlock(&aio_entry_mtx);
}

/* Hash */
static aio_workq_t
aio_entry_workq(__unused aio_workq_entry *entryp) 
{
	return &aio_anchor.aio_async_workqs[0];
}

static lck_mtx_t*
aio_entry_mutex(__unused aio_workq_entry *entryp) 
{
	return &aio_entry_mtx;
}

static void 
aio_workq_init(aio_workq_t wq)
{
	TAILQ_INIT(&wq->aioq_entries);
	wq->aioq_count = 0;
	lck_mtx_init(&wq->aioq_mtx, aio_queue_lock_grp, aio_lock_attr);
	wq->aioq_waitq = wait_queue_alloc(SYNC_POLICY_FIFO);
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
	queue->aioq_count--;
	entryp->aio_workq_link.tqe_prev = NULL; /* Not on a workq */
	
	if (queue->aioq_count  < 0) {
		panic("Negative count on a queue.\n");
	}
}

static void		
aio_workq_add_entry_locked(aio_workq_t queue, aio_workq_entry *entryp)
{
	ASSERT_AIO_WORKQ_LOCK_OWNED(queue);

	TAILQ_INSERT_TAIL(&queue->aioq_entries, entryp, aio_workq_link);
	if (queue->aioq_count  < 0) {
		panic("Negative count on a queue.\n");
	}
	queue->aioq_count++;
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

static void
aio_proc_move_done_locked(proc_t procp, aio_workq_entry *entryp)
{
	ASSERT_AIO_PROC_LOCK_OWNED(procp);

	TAILQ_REMOVE(&procp->p_aio_activeq, entryp, aio_proc_link );
	TAILQ_INSERT_TAIL( &procp->p_aio_doneq, entryp, aio_proc_link);
	procp->p_aio_active_count--;
	OSIncrementAtomic(&aio_anchor.aio_done_count);
}

static void
aio_proc_remove_done_locked(proc_t procp, aio_workq_entry *entryp)
{
	TAILQ_REMOVE(&procp->p_aio_doneq, entryp, aio_proc_link);
	OSDecrementAtomic(&aio_anchor.aio_done_count);
	aio_decrement_total_count();
	procp->p_aio_total_count--;
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
aio_entry_ref_locked(aio_workq_entry *entryp)
{
	ASSERT_AIO_ENTRY_LOCK_OWNED(entryp);

	if (entryp->aio_refcount < 0) {
		panic("AIO workq entry with a negative refcount.\n");
	}
	entryp->aio_refcount++;
}


/* Return 1 if you've freed it */
static void
aio_entry_unref_locked(aio_workq_entry *entryp)
{
	ASSERT_AIO_ENTRY_LOCK_OWNED(entryp);

	entryp->aio_refcount--;
	if (entryp->aio_refcount < 0) {
		panic("AIO workq entry with a negative refcount.\n");
	}
}

static void	
aio_entry_ref(aio_workq_entry *entryp)
{
	aio_entry_lock_spin(entryp);
	aio_entry_ref_locked(entryp);
	aio_entry_unlock(entryp);
}
static void		
aio_entry_unref(aio_workq_entry *entryp)
{
	aio_entry_lock_spin(entryp);
	aio_entry_unref_locked(entryp);

	if ((entryp->aio_refcount == 0) && ((entryp->flags & AIO_DO_FREE) != 0)) {
		aio_entry_unlock(entryp);
		aio_free_request(entryp);
	} else {
		aio_entry_unlock(entryp);
	}
	
	return;
}

static void		
aio_entry_update_for_cancel(aio_workq_entry *entryp, boolean_t cancelled, int wait_for_completion, boolean_t disable_notification)
{
	aio_entry_lock_spin(entryp);

	if (cancelled) {
		aio_entry_ref_locked(entryp);
		entryp->errorval = ECANCELED;
		entryp->returnval = -1;
	}
	
	if ( wait_for_completion ) {
		entryp->flags |= wait_for_completion; /* flag for special completion processing */
	}
	
	if ( disable_notification ) { 
		entryp->flags |= AIO_DISABLE; /* Don't want a signal */
	}

	aio_entry_unlock(entryp); 
}

static int
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
			return 1;
		}  else {
			aio_workq_unlock(queue);
		}
	}

	return 0;
}

static void		
aio_workq_lock_spin(aio_workq_t wq)
{
	lck_mtx_lock_spin(aio_workq_mutex(wq));
}

static void		
aio_workq_unlock(aio_workq_t wq)
{
	lck_mtx_unlock(aio_workq_mutex(wq));
}

static lck_mtx_t*
aio_workq_mutex(aio_workq_t wq)
{
	return &wq->aioq_mtx;
}

/*
 * aio_cancel - attempt to cancel one or more async IO requests currently
 * outstanding against file descriptor uap->fd.  If uap->aiocbp is not 
 * NULL then only one specific IO is cancelled (if possible).  If uap->aiocbp
 * is NULL then all outstanding async IO request for the given file
 * descriptor are cancelled (if possible).
 */
int
aio_cancel(proc_t p, struct aio_cancel_args *uap, int *retval )
{
	struct user_aiocb		my_aiocb;
	int							result;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	/* quick check to see if there are any async IO requests queued up */
	if (aio_get_all_queues_count() < 1) {
		result = 0;
		*retval = AIO_ALLDONE;
		goto ExitRoutine;
	}
	
	*retval = -1; 
	if ( uap->aiocbp != USER_ADDR_NULL ) {
		if ( proc_is64bit(p) ) {
			struct user64_aiocb aiocb64;
			
			result = copyin( uap->aiocbp, &aiocb64, sizeof(aiocb64) );
			if (result == 0 )
				do_munge_aiocb_user64_to_user(&aiocb64, &my_aiocb);

		} else {
			struct user32_aiocb aiocb32;

			result = copyin( uap->aiocbp, &aiocb32, sizeof(aiocb32) );
			if ( result == 0 )
				do_munge_aiocb_user32_to_user( &aiocb32, &my_aiocb );
		}

		if ( result != 0 ) {
			result = EAGAIN; 
			goto ExitRoutine;
		}

		/* NOTE - POSIX standard says a mismatch between the file */
		/* descriptor passed in and the file descriptor embedded in */
		/* the aiocb causes unspecified results.  We return EBADF in */
		/* that situation.  */
		if ( uap->fd != my_aiocb.aio_fildes ) {
			result = EBADF;
			goto ExitRoutine;
		}
	}

	aio_proc_lock(p);
	result = do_aio_cancel_locked( p, uap->fd, uap->aiocbp, 0, FALSE );
	ASSERT_AIO_PROC_LOCK_OWNED(p);
	aio_proc_unlock(p);

	if ( result != -1 ) {
		*retval = result;
		result = 0;
		goto ExitRoutine;
	}
	
	result = EBADF;
	
ExitRoutine:
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, result, 0, 0 );

	return( result );

} /* aio_cancel */


/*
 * _aio_close - internal function used to clean up async IO requests for 
 * a file descriptor that is closing.  
 * THIS MAY BLOCK.
 */
__private_extern__ void
_aio_close(proc_t p, int fd )
{
	int			error;

	/* quick check to see if there are any async IO requests queued up */
	if (aio_get_all_queues_count() < 1) {
		return;
	}

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_close)) | DBG_FUNC_START,
		     	  (int)p, fd, 0, 0, 0 );
	
	/* cancel all async IO requests on our todo queues for this file descriptor */
	aio_proc_lock(p);
	error = do_aio_cancel_locked( p, fd, 0, AIO_CLOSE_WAIT, FALSE );
	ASSERT_AIO_PROC_LOCK_OWNED(p);
	if ( error == AIO_NOTCANCELED ) {
		/* 
		 * AIO_NOTCANCELED is returned when we find an aio request for this process 
		 * and file descriptor on the active async IO queue.  Active requests cannot 
		 * be cancelled so we must wait for them to complete.  We will get a special 
		 * wake up call on our channel used to sleep for ALL active requests to 
		 * complete.  This sleep channel (proc.AIO_CLEANUP_SLEEP_CHAN) is only used  
		 * when we must wait for all active aio requests.  
		 */

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_close_sleep)) | DBG_FUNC_NONE,
		     	 	  (int)p, fd, 0, 0, 0 );

		while (aio_proc_active_requests_for_file(p, fd) > 0) {
			msleep(&p->AIO_CLEANUP_SLEEP_CHAN, aio_proc_mutex(p), PRIBIO | PDROP, "aio_close", 0 );
		}

	} else {
		aio_proc_unlock(p);
	}


	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_close)) | DBG_FUNC_END,
		     	  (int)p, fd, 0, 0, 0 );

	return;
	
} /* _aio_close */


/*
 * aio_error - return the error status associated with the async IO
 * request referred to by uap->aiocbp.  The error status is the errno
 * value that would be set by the corresponding IO request (read, wrtie,
 * fdatasync, or sync).
 */
int
aio_error(proc_t p, struct aio_error_args *uap, int *retval )
{
	aio_workq_entry		 		*entryp;
	int							error;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	/* see if there are any aios to check */
	if (aio_get_all_queues_count() < 1) {
		return EINVAL;
	}
	
	aio_proc_lock(p);
	
	/* look for a match on our queue of async IO requests that have completed */
	TAILQ_FOREACH( entryp, &p->p_aio_doneq, aio_proc_link) {
		if ( entryp->uaiocbp == uap->aiocbp ) {
			ASSERT_AIO_FROM_PROC(entryp, p);

			aio_entry_lock_spin(entryp);
			*retval = entryp->errorval;
			error = 0;
			aio_entry_unlock(entryp);
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error_val)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	/* look for a match on our queue of active async IO requests */
	TAILQ_FOREACH( entryp, &p->p_aio_activeq, aio_proc_link) {
		if ( entryp->uaiocbp == uap->aiocbp ) {
			ASSERT_AIO_FROM_PROC(entryp, p);
			*retval = EINPROGRESS;
			error = 0;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error_activeq)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}

	error = EINVAL;
	
ExitRoutine:
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, error, 0, 0 );
	aio_proc_unlock(p);

	return( error );

} /* aio_error */


/*
 * aio_fsync - asynchronously force all IO operations associated 
 * with the file indicated by the file descriptor (uap->aiocbp->aio_fildes) and 
 * queued at the time of the call to the synchronized completion state.
 * NOTE - we do not support op O_DSYNC at this point since we do not support the 
 * fdatasync() call.
 */
int
aio_fsync(proc_t p, struct aio_fsync_args *uap, int *retval )
{
	int			error;
	int			fsync_kind;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, uap->op, 0, 0 );

	*retval = 0;
	/* 0 := O_SYNC for binary backward compatibility with Panther */
	if (uap->op == O_SYNC || uap->op == 0)
		fsync_kind = AIO_FSYNC;
	else if ( uap->op == O_DSYNC )
		fsync_kind = AIO_DSYNC;
	else {
		*retval = -1;
		error = EINVAL;
		goto ExitRoutine;
	}
	
	error = aio_queue_async_request( p, uap->aiocbp, fsync_kind );
	if ( error != 0 )
		*retval = -1;

ExitRoutine:		
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, error, 0, 0 );

	return( error );

} /* aio_fsync */


/* aio_read - asynchronously read uap->aiocbp->aio_nbytes bytes from the 
 * file descriptor (uap->aiocbp->aio_fildes) into the buffer 
 * (uap->aiocbp->aio_buf).
 */
int
aio_read(proc_t p, struct aio_read_args *uap, int *retval )
{
	int			error;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_read)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );
	
	*retval = 0;

	error = aio_queue_async_request( p, uap->aiocbp, AIO_READ );
	if ( error != 0 )
		*retval = -1;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_read)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, error, 0, 0 );
		
	return( error );

} /* aio_read */


/*
 * aio_return - return the return status associated with the async IO
 * request referred to by uap->aiocbp.  The return status is the value
 * that would be returned by corresponding IO request (read, write,
 * fdatasync, or sync).  This is where we release kernel resources 
 * held for async IO call associated with the given aiocb pointer.
 */
int
aio_return(proc_t p, struct aio_return_args *uap, user_ssize_t *retval )
{
	aio_workq_entry		 		*entryp;
	int							error;
	boolean_t					proc_lock_held = FALSE;
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	/* See if there are any entries to check */
	if (aio_get_all_queues_count() < 1) {
		error = EINVAL;
		goto ExitRoutine;
	}

	aio_proc_lock(p);
	proc_lock_held = TRUE;
	*retval = 0;

	/* look for a match on our queue of async IO requests that have completed */
	TAILQ_FOREACH( entryp, &p->p_aio_doneq, aio_proc_link) {
		ASSERT_AIO_FROM_PROC(entryp, p);
		if ( entryp->uaiocbp == uap->aiocbp ) {
			/* Done and valid for aio_return(), pull it off the list */
			aio_proc_remove_done_locked(p, entryp);
			
			/* Drop the proc lock, but keep the entry locked */
			aio_entry_lock(entryp);
			aio_proc_unlock(p);
			proc_lock_held = FALSE;

			*retval = entryp->returnval;
			error = 0;

			/* No references and off all lists, safe to free */
			if (entryp->aio_refcount == 0) {
				aio_entry_unlock(entryp);
				aio_free_request(entryp);
			}
			else {
				/* Whoever has the refcount will have to free it */
				entryp->flags |= AIO_DO_FREE;
				aio_entry_unlock(entryp);
			}


			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return_val)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	/* look for a match on our queue of active async IO requests */
	TAILQ_FOREACH( entryp, &p->p_aio_activeq, aio_proc_link) {
		ASSERT_AIO_FROM_PROC(entryp, p);
		if ( entryp->uaiocbp == uap->aiocbp ) {
			error = EINPROGRESS;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return_activeq)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	error = EINVAL;
	
ExitRoutine:
	if (proc_lock_held)
		aio_proc_unlock(p);
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, error, 0, 0 );

	return( error );

} /* aio_return */


/*
 * _aio_exec - internal function used to clean up async IO requests for 
 * a process that is going away due to exec().  We cancel any async IOs   
 * we can and wait for those already active.  We also disable signaling
 * for cancelled or active aio requests that complete. 
 * This routine MAY block!
 */
__private_extern__ void
_aio_exec(proc_t p )
{

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exec)) | DBG_FUNC_START,
		     	  (int)p, 0, 0, 0, 0 );

	_aio_exit( p );

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exec)) | DBG_FUNC_END,
		     	  (int)p, 0, 0, 0, 0 );

	return;
		
} /* _aio_exec */


/*
 * _aio_exit - internal function used to clean up async IO requests for 
 * a process that is terminating (via exit() or exec() ).  We cancel any async IOs   
 * we can and wait for those already active.  We also disable signaling
 * for cancelled or active aio requests that complete.  This routine MAY block!
 */
__private_extern__ void
_aio_exit(proc_t p )
{
	int						error;
	aio_workq_entry 		*entryp;


	/* quick check to see if there are any async IO requests queued up */
	if (aio_get_all_queues_count() < 1) {
		return;
	}

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exit)) | DBG_FUNC_START,
		     	  (int)p, 0, 0, 0, 0 );

	aio_proc_lock(p);

	/* 
	 * cancel async IO requests on the todo work queue and wait for those  
	 * already active to complete. 
	 */
	error = do_aio_cancel_locked( p, 0, 0, AIO_EXIT_WAIT, TRUE );
	ASSERT_AIO_PROC_LOCK_OWNED(p);
	if ( error == AIO_NOTCANCELED ) {
		/* 
		 * AIO_NOTCANCELED is returned when we find an aio request for this process 
		 * on the active async IO queue.  Active requests cannot be cancelled so we 
		 * must wait for them to complete.  We will get a special wake up call on 
		 * our channel used to sleep for ALL active requests to complete.  This sleep 
		 * channel (proc.AIO_CLEANUP_SLEEP_CHAN) is only used when we must wait for all 
		 * active aio requests.  
		 */

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exit_sleep)) | DBG_FUNC_NONE,
		     	 	  (int)p, 0, 0, 0, 0 );

		while (p->p_aio_active_count != 0) {
			msleep(&p->AIO_CLEANUP_SLEEP_CHAN, aio_proc_mutex(p), PRIBIO, "aio_exit", 0 );
		}
	}
		
	if (p->p_aio_active_count != 0) {
		panic("Exiting process has %d active AIOs after cancellation has completed.\n", p->p_aio_active_count);
	}
	
	/* release all aio resources used by this process */
	entryp = TAILQ_FIRST( &p->p_aio_doneq );
	while ( entryp != NULL ) {
		ASSERT_AIO_FROM_PROC(entryp, p);
		aio_workq_entry		 	*next_entryp;
			
		next_entryp = TAILQ_NEXT( entryp, aio_proc_link);
		aio_proc_remove_done_locked(p, entryp);
			
		/* we cannot free requests that are still completing */
		aio_entry_lock_spin(entryp);
		if (entryp->aio_refcount == 0) {
			aio_proc_unlock(p);
			aio_entry_unlock(entryp);
			aio_free_request(entryp);

			/* need to start over since aio_doneq may have been */
			/* changed while we were away.  */
			aio_proc_lock(p);
			entryp = TAILQ_FIRST( &p->p_aio_doneq );
			continue;
		}
		else {
			/* whoever has the reference will have to do the free */
			entryp->flags |= AIO_DO_FREE;
		} 

		aio_entry_unlock(entryp);
		entryp = next_entryp;
	}
	
	aio_proc_unlock(p);
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exit)) | DBG_FUNC_END,
		     	  (int)p, 0, 0, 0, 0 );
	return;
	
} /* _aio_exit */


static boolean_t
should_cancel(aio_workq_entry *entryp, user_addr_t aiocbp, int fd) 
{
	if ( (aiocbp == USER_ADDR_NULL && fd == 0) ||
			(aiocbp != USER_ADDR_NULL && entryp->uaiocbp == aiocbp) ||
			(aiocbp == USER_ADDR_NULL && fd == entryp->aiocb.aio_fildes) ) {
		return TRUE;
	}

	return FALSE;
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
 * land data that has not been copied in (when called from aio_cancel() )
 *
 * Called with proc locked, and returns the same way.
 */
static int
do_aio_cancel_locked(proc_t p, int fd, user_addr_t aiocbp, 
	int wait_for_completion, boolean_t disable_notification )
{
	ASSERT_AIO_PROC_LOCK_OWNED(p);

	aio_workq_entry		 	*entryp;
	int						result;

	result = -1;
		
	/* look for a match on our queue of async todo work. */
	entryp = TAILQ_FIRST(&p->p_aio_activeq);
	while ( entryp != NULL ) {
		ASSERT_AIO_FROM_PROC(entryp, p);
		aio_workq_entry		 	*next_entryp;

		next_entryp = TAILQ_NEXT( entryp, aio_proc_link);
		if (!should_cancel(entryp, aiocbp, fd)) {
			entryp = next_entryp;
			continue;
		}

		/* Can only be cancelled if it's still on a work queue */
		if (aio_entry_try_workq_remove(entryp) != 0) {
			/* Have removed from workq. Update entry state and take a ref */
			aio_entry_update_for_cancel(entryp, TRUE, 0, disable_notification);

			/* Put on the proc done queue and update counts, then unlock the proc */
			aio_proc_move_done_locked(p, entryp);
			aio_proc_unlock(p);

			/* Now it's officially cancelled.  Do the completion */
			result = AIO_CANCELED;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_async_workq)) | DBG_FUNC_NONE,
					(int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );
			do_aio_completion(entryp);

			/* This will free if the aio_return() has already happened ... */
			aio_entry_unref(entryp);
			aio_proc_lock(p);

			if ( aiocbp != USER_ADDR_NULL ) {
				return( result );
			}

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
			entryp = TAILQ_FIRST(&p->p_aio_activeq);
			result = -1; /* As if beginning anew */
		} else {
			/* 
			 * It's been taken off the active queue already, i.e. is in flight.
			 * All we can do is ask for notification.
			 */
			result = AIO_NOTCANCELED;

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_activeq)) | DBG_FUNC_NONE,
					(int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

			/* Mark for waiting and such; will not take a ref if "cancelled" arg is FALSE */
			aio_entry_update_for_cancel(entryp, FALSE, wait_for_completion, disable_notification);

			if ( aiocbp != USER_ADDR_NULL ) {
				return( result );
			}
			entryp = next_entryp;
		}
	} /* while... */
		
	/* 
	 * if we didn't find any matches on the todo or active queues then look for a 
	 * match on our queue of async IO requests that have completed and if found 
	 * return AIO_ALLDONE result.  
	 *
	 * Proc AIO lock is still held.
	 */
	if ( result == -1 ) {
		TAILQ_FOREACH(entryp, &p->p_aio_doneq, aio_proc_link) {
			ASSERT_AIO_FROM_PROC(entryp, p);
			if (should_cancel(entryp, aiocbp, fd)) {
				result = AIO_ALLDONE;
				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_doneq)) | DBG_FUNC_NONE,
						(int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

				if ( aiocbp != USER_ADDR_NULL ) {
					return( result );
				}
			}
		}
	}

	return( result );
	
}
 /* do_aio_cancel_locked */


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
aio_suspend(proc_t p, struct aio_suspend_args *uap, int *retval )
{
	__pthread_testcancel(1);
	return(aio_suspend_nocancel(p, (struct aio_suspend_nocancel_args *)uap, retval));
}


int
aio_suspend_nocancel(proc_t p, struct aio_suspend_nocancel_args *uap, int *retval )
{
	int					error;
	int					i, count;
	uint64_t			abstime;
	struct user_timespec ts;
	aio_workq_entry 	*entryp;
	user_addr_t			*aiocbpp;
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend)) | DBG_FUNC_START,
		     	  (int)p, uap->nent, 0, 0, 0 );

	*retval = -1;
	abstime = 0;
	aiocbpp = NULL;

	count = aio_get_all_queues_count( ); 
	if ( count < 1 ) {
		error = EINVAL;
		goto ExitThisRoutine;
	}

	if ( uap->nent < 1 || uap->nent > aio_max_requests_per_process ) {
		error = EINVAL;
		goto ExitThisRoutine;
	}

	if ( uap->timeoutp != USER_ADDR_NULL ) {
		if ( proc_is64bit(p) ) {
			struct user64_timespec temp;
			error = copyin( uap->timeoutp, &temp, sizeof(temp) );
			if ( error == 0 ) {
				ts.tv_sec = temp.tv_sec;
				ts.tv_nsec = temp.tv_nsec;
			}
		}
		else {
			struct user32_timespec temp;
			error = copyin( uap->timeoutp, &temp, sizeof(temp) );
			if ( error == 0 ) {
				ts.tv_sec = temp.tv_sec;
				ts.tv_nsec = temp.tv_nsec;
			}
		}
		if ( error != 0 ) {
			error = EAGAIN;
			goto ExitThisRoutine;
		}
			
		if ( ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ) {
			error = EINVAL;
			goto ExitThisRoutine;
		}

		nanoseconds_to_absolutetime( (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec, 
									 &abstime );
		clock_absolutetime_interval_to_deadline( abstime, &abstime );
	}

	aiocbpp = aio_copy_in_list(p, uap->aiocblist, uap->nent);
	if ( aiocbpp == NULL ) {
		error = EAGAIN;
		goto ExitThisRoutine;
	}

	/* check list of aio requests to see if any have completed */
check_for_our_aiocbp:
	aio_proc_lock_spin(p);
	for ( i = 0; i < uap->nent; i++ ) {
		user_addr_t	aiocbp;  

		/* NULL elements are legal so check for 'em */
		aiocbp = *(aiocbpp + i);
		if ( aiocbp == USER_ADDR_NULL )
			continue;
	
		/* return immediately if any aio request in the list is done */
		TAILQ_FOREACH( entryp, &p->p_aio_doneq, aio_proc_link) {
			ASSERT_AIO_FROM_PROC(entryp, p);
			if ( entryp->uaiocbp == aiocbp ) {
				aio_proc_unlock(p);
				*retval = 0;
				error = 0;
				goto ExitThisRoutine;
			}
		}
	} /* for ( ; i < uap->nent; ) */

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend_sleep)) | DBG_FUNC_NONE,
		     	  (int)p, uap->nent, 0, 0, 0 );
	
	/* 
	 * wait for an async IO to complete or a signal fires or timeout expires. 
	 * we return EAGAIN (35) for timeout expiration and EINTR (4) when a signal 
	 * interrupts us.  If an async IO completes before a signal fires or our 
	 * timeout expires, we get a wakeup call from aio_work_thread().
	 */

	error = msleep1(&p->AIO_SUSPEND_SLEEP_CHAN, aio_proc_mutex(p), PCATCH | PWAIT | PDROP, "aio_suspend", abstime); /* XXX better priority? */
	if ( error == THREAD_AWAKENED ) {
		/* 
		 * got our wakeup call from aio_work_thread().
		 * Since we can get a wakeup on this channel from another thread in the 
		 * same process we head back up to make sure this is for the correct aiocbp.  
		 * If it is the correct aiocbp we will return from where we do the check 
		 * (see entryp->uaiocbp == aiocbp after check_for_our_aiocbp label)
		 * else we will fall out and just sleep again.  
		 */
		goto check_for_our_aiocbp;
	}
	else if ( error == THREAD_TIMED_OUT ) {
		/* our timeout expired */
		error = EAGAIN;
	}
	else {
		/* we were interrupted */
		error = EINTR;
	}

ExitThisRoutine:
	if ( aiocbpp != NULL )
		FREE( aiocbpp, M_TEMP );

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend)) | DBG_FUNC_END,
		     	  (int)p, uap->nent, error, 0, 0 );
	
	return( error );	

} /* aio_suspend */


/* aio_write - asynchronously write uap->aiocbp->aio_nbytes bytes to the 
 * file descriptor (uap->aiocbp->aio_fildes) from the buffer 
 * (uap->aiocbp->aio_buf).
 */

int
aio_write(proc_t p, struct aio_write_args *uap, int *retval )
{
	int			error;
	
	*retval = 0;
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_write)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	error = aio_queue_async_request( p, uap->aiocbp, AIO_WRITE );
	if ( error != 0 )
		*retval = -1;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_write)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, error, 0, 0 );
		
	return( error );

} /* aio_write */


static user_addr_t *
aio_copy_in_list(proc_t procp, user_addr_t aiocblist, int nent)
{
	user_addr_t	*aiocbpp;
	int		i, result;

	/* we reserve enough space for largest possible pointer size */
	MALLOC( aiocbpp, user_addr_t *, (nent * sizeof(user_addr_t)), M_TEMP, M_WAITOK );
	if ( aiocbpp == NULL )
		goto err;

	/* copyin our aiocb pointers from list */
	result = copyin( aiocblist, aiocbpp, 
			proc_is64bit(procp) ? (nent * sizeof(user64_addr_t))
					    : (nent * sizeof(user32_addr_t)) );
	if ( result) {
		FREE( aiocbpp, M_TEMP );
		aiocbpp = NULL;
		goto err;
	}

	/*
	 * We depend on a list of user_addr_t's so we need to
	 * munge and expand when these pointers came from a
	 * 32-bit process
	 */
	if ( !proc_is64bit(procp) ) {
		/* copy from last to first to deal with overlap */
		user32_addr_t *my_ptrp = ((user32_addr_t *)aiocbpp) + (nent - 1);
		user_addr_t *my_addrp = aiocbpp + (nent - 1);

		for (i = 0; i < nent; i++, my_ptrp--, my_addrp--) {
			*my_addrp = (user_addr_t) (*my_ptrp);
		}
	}

err:
	return (aiocbpp);
}


static int
aio_copy_in_sigev(proc_t procp, user_addr_t sigp, struct user_sigevent *sigev)
{
	int	result = 0;

	if (sigp == USER_ADDR_NULL)
		goto out;

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
	if ( proc_is64bit(procp) ) {
		struct user64_sigevent sigevent64;

		result = copyin( sigp, &sigevent64, sizeof(sigevent64) );
		if ( result == 0 ) {
			sigev->sigev_notify = sigevent64.sigev_notify;
			sigev->sigev_signo = sigevent64.sigev_signo;
			sigev->sigev_value.size_equivalent.sival_int = sigevent64.sigev_value.size_equivalent.sival_int;
			sigev->sigev_notify_function = sigevent64.sigev_notify_function;
			sigev->sigev_notify_attributes = sigevent64.sigev_notify_attributes;
		}
		
	} else {
		struct user32_sigevent sigevent32;

		result = copyin( sigp, &sigevent32, sizeof(sigevent32) );
		if ( result == 0 ) {
			sigev->sigev_notify = sigevent32.sigev_notify;
			sigev->sigev_signo = sigevent32.sigev_signo;
			sigev->sigev_value.size_equivalent.sival_int = sigevent32.sigev_value.sival_int;
			sigev->sigev_notify_function = CAST_USER_ADDR_T(sigevent32.sigev_notify_function);
			sigev->sigev_notify_attributes = CAST_USER_ADDR_T(sigevent32.sigev_notify_attributes);
		}
	}

	if ( result != 0 ) {
		result = EAGAIN;
	}

out:
	return (result);
}

/*
 * aio_enqueue_work
 *
 * Queue up the entry on the aio asynchronous work queue in priority order
 * based on the relative priority of the request.  We calculate the relative
 * priority using the nice value of the caller and the value
 *
 * Parameters:	procp			Process queueing the I/O
 *		entryp			The work queue entry being queued
 *
 * Returns:	(void)			No failure modes
 *
 * Notes:	This function is used for both lio_listio and aio
 *
 * XXX:		At some point, we may have to consider thread priority
 *		rather than process priority, but we don't maintain the
 *		adjusted priority for threads the POSIX way.
 *
 *
 * Called with proc locked.
 */
static void
aio_enqueue_work( proc_t procp, aio_workq_entry *entryp, int proc_locked)
{
#if 0
	aio_workq_entry	*my_entryp;	/* used for insertion sort */
#endif /* 0 */
	aio_workq_t queue = aio_entry_workq(entryp);

	if (proc_locked == 0) {
		aio_proc_lock(procp);
	}

	ASSERT_AIO_PROC_LOCK_OWNED(procp);

	/* Onto proc queue */
	TAILQ_INSERT_TAIL(&procp->p_aio_activeq, entryp,  aio_proc_link);
	procp->p_aio_active_count++;
	procp->p_aio_total_count++;

	/* And work queue */
	aio_workq_lock_spin(queue);
	aio_workq_add_entry_locked(queue, entryp);
	wait_queue_wakeup_one(queue->aioq_waitq, queue, THREAD_AWAKENED);
	aio_workq_unlock(queue);
	
	if (proc_locked == 0) {
		aio_proc_unlock(procp);
	}

#if 0
	/*
	 * Procedure:
	 *
	 * (1)	The nice value is in the range PRIO_MIN..PRIO_MAX [-20..20]
	 * (2)	The normalized nice value is in the range 0..((2 * NZERO) - 1)
	 *	which is [0..39], with 0 not being used.  In nice values, the
	 *	lower the nice value, the higher the priority.
	 * (3)	The normalized scheduling prioritiy is the highest nice value
	 *	minus the current nice value.  In I/O scheduling priority, the
	 *	higher the value the lower the priority, so it is the inverse
	 *	of the nice value (the higher the number, the higher the I/O
	 *	priority).
	 * (4)	From the normalized scheduling priority, we subtract the
	 *	request priority to get the request priority value number;
	 *	this means that requests are only capable of depressing their
	 *	priority relative to other requests,
	 */
	entryp->priority = (((2 * NZERO) - 1) - procp->p_nice);

	/* only premit depressing the priority */
	if (entryp->aiocb.aio_reqprio < 0)
		entryp->aiocb.aio_reqprio = 0;
	if (entryp->aiocb.aio_reqprio > 0) {
		entryp->priority -= entryp->aiocb.aio_reqprio;
		if (entryp->priority < 0)
			entryp->priority = 0;
	}

	/* Insertion sort the entry; lowest ->priority to highest */
	TAILQ_FOREACH(my_entryp, &aio_anchor.aio_async_workq, aio_workq_link) {
		if ( entryp->priority <= my_entryp->priority) {
			TAILQ_INSERT_BEFORE(my_entryp, entryp, aio_workq_link);
			break;
		}
	}
	if (my_entryp == NULL)
		TAILQ_INSERT_TAIL( &aio_anchor.aio_async_workq, entryp, aio_workq_link );
#endif /* 0 */
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
lio_listio(proc_t p, struct lio_listio_args *uap, int *retval )
{
	int				i;
	int				call_result;
	int				result;
	int				old_count;
	aio_workq_entry			**entryp_listp;
	user_addr_t			*aiocbpp;
	struct user_sigevent		aiosigev;
	aio_lio_context		*lio_context;
	boolean_t 			free_context = FALSE;
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_listio)) | DBG_FUNC_START,
		     	  (int)p, uap->nent, uap->mode, 0, 0 );
	
	entryp_listp = NULL;
	lio_context = NULL;
	aiocbpp = NULL;
	call_result = -1;
	*retval = -1;
	if ( !(uap->mode == LIO_NOWAIT || uap->mode == LIO_WAIT) ) {
		call_result = EINVAL;
		goto ExitRoutine;
	}

	if ( uap->nent < 1 || uap->nent > AIO_LISTIO_MAX ) {
		call_result = EINVAL;
		goto ExitRoutine;
	}
		
	/* 
	 * allocate a list of aio_workq_entry pointers that we will use
	 * to queue up all our requests at once while holding our lock.
	 */
	MALLOC( entryp_listp, void *, (uap->nent * sizeof(aio_workq_entry *)), M_TEMP, M_WAITOK );
	if ( entryp_listp == NULL ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}
	
	MALLOC( lio_context, aio_lio_context*, sizeof(aio_lio_context), M_TEMP, M_WAITOK );
	if ( lio_context == NULL ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}

#if DEBUG	
	OSIncrementAtomic(&lio_contexts_alloced);
#endif /* DEBUG */

	bzero(lio_context, sizeof(aio_lio_context));
	
	aiocbpp = aio_copy_in_list(p, uap->aiocblist, uap->nent);
	if ( aiocbpp == NULL ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}

	/*
	 * Use sigevent passed in to lio_listio for each of our calls, but
	 * only do completion notification after the last request completes.
	 */
	bzero(&aiosigev, sizeof(aiosigev));
	/* Only copy in an sigev if the user supplied one */
	if (uap->sigp != USER_ADDR_NULL) {
		call_result = aio_copy_in_sigev(p, uap->sigp, &aiosigev);
		if ( call_result)
			goto ExitRoutine;
	}

	/* process list of aio requests */
	lio_context->io_issued = uap->nent;
	lio_context->io_waiter = uap->mode == LIO_WAIT ? 1 : 0; /* Should it be freed by last AIO */
	for ( i = 0; i < uap->nent; i++ ) {
		user_addr_t my_aiocbp; 
		aio_workq_entry		 		*entryp;
	
		*(entryp_listp + i) = NULL;
		my_aiocbp = *(aiocbpp + i);
		
		/* NULL elements are legal so check for 'em */
		if ( my_aiocbp == USER_ADDR_NULL ) {
			aio_proc_lock_spin(p);
			lio_context->io_issued--;
			aio_proc_unlock(p);
			continue;
		}

		/* 
		 * We use lio_context to mark IO requests for delayed completion
		 * processing which means we wait until all IO requests in the
		 * group have completed before we either return to the caller
		 * when mode is LIO_WAIT or signal user when mode is LIO_NOWAIT.
		 *
		 * We use the address of the lio_context for this, since it is
		 * unique in the address space.
		 */
		result = lio_create_entry( p, my_aiocbp, lio_context, (entryp_listp + i) );
		if ( result != 0 && call_result == -1 )
			call_result = result;
		
		/* NULL elements are legal so check for 'em */
		entryp = *(entryp_listp + i);
		if ( entryp == NULL ) {
			aio_proc_lock_spin(p);
			lio_context->io_issued--;
			aio_proc_unlock(p);
			continue;
		}
	
		if ( uap->mode == LIO_NOWAIT ) {
			/* Set signal hander, if any */
			entryp->aiocb.aio_sigevent = aiosigev;
		} else {
			/* flag that this thread blocks pending completion */
			entryp->flags |= AIO_LIO_NOTIFY;
		}

		/* check our aio limits to throttle bad or rude user land behavior */
		old_count = aio_increment_total_count();

		aio_proc_lock_spin(p);
		if ( old_count >= aio_max_requests ||
			 aio_get_process_count( entryp->procp ) >= aio_max_requests_per_process ||
			 is_already_queued( entryp->procp, entryp->uaiocbp ) == TRUE ) {
			
			lio_context->io_issued--;
			aio_proc_unlock(p);
	
			aio_decrement_total_count();

			if ( call_result == -1 )
				call_result = EAGAIN;
			aio_free_request(entryp);
			entryp_listp[i] = NULL;
			continue;
		}
		
		lck_mtx_convert_spin(aio_proc_mutex(p));
		aio_enqueue_work(p, entryp, 1);
		aio_proc_unlock(p);
		
		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued)) | DBG_FUNC_NONE,
				  (int)p, (int)entryp->uaiocbp, 0, 0, 0 );
	}

	switch(uap->mode) {
	case LIO_WAIT:
		aio_proc_lock_spin(p);
		while (lio_context->io_completed < lio_context->io_issued) {
			result = msleep(lio_context, aio_proc_mutex(p), PCATCH | PRIBIO | PSPIN, "lio_listio", 0);
			
			/* If we were interrupted, fail out (even if all finished) */
			if (result != 0) {
				call_result = EINTR;
				lio_context->io_waiter = 0;
				break;
			} 
		}

		/* If all IOs have finished must free it */
		if (lio_context->io_completed == lio_context->io_issued) {
			free_context = TRUE;
		} 

		aio_proc_unlock(p);
		break;
		
	case LIO_NOWAIT:
		break;
	}
	
	/* call_result == -1 means we had no trouble queueing up requests */
	if ( call_result == -1 ) {
		call_result = 0;
		*retval = 0;
	}

ExitRoutine:		
	if ( entryp_listp != NULL )
		FREE( entryp_listp, M_TEMP );
	if ( aiocbpp != NULL )
		FREE( aiocbpp, M_TEMP );
	if ((lio_context != NULL) && ((lio_context->io_issued == 0) || (free_context == TRUE))) {
		free_lio_context(lio_context);
	}
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_listio)) | DBG_FUNC_END,
		     	  (int)p, call_result, 0, 0, 0 );
	
	return( call_result );
	
} /* lio_listio */


/*
 * aio worker thread.  this is where all the real work gets done.
 * we get a wake up call on sleep channel &aio_anchor.aio_async_workq 
 * after new work is queued up.
 */
static void
aio_work_thread( void )
{
	aio_workq_entry		 	*entryp;
	int 			error;
	vm_map_t 		currentmap;
	vm_map_t 		oldmap = VM_MAP_NULL;
	task_t			oldaiotask = TASK_NULL;
	struct uthread	*uthreadp = NULL;
	
	for( ;; ) {
		/* 
		 * returns with the entry ref'ed.
		 * sleeps until work is available. 
		 */
		entryp = aio_get_some_work();         

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread)) | DBG_FUNC_START,
				(int)entryp->procp, (int)entryp->uaiocbp, entryp->flags, 0, 0 );

		/*
		 * Assume the target's address space identity for the duration
		 * of the IO.  Note: don't need to have the entryp locked,
		 * because the proc and map don't change until it's freed.
		 */
		currentmap = get_task_map( (current_proc())->task );
		if ( currentmap != entryp->aio_map ) {
			uthreadp = (struct uthread *) get_bsdthread_info(current_thread());
			oldaiotask = uthreadp->uu_aio_task;
			uthreadp->uu_aio_task = entryp->procp->task;
			oldmap = vm_map_switch( entryp->aio_map );
		}

		if ( (entryp->flags & AIO_READ) != 0 ) {
			error = do_aio_read( entryp );
		}
		else if ( (entryp->flags & AIO_WRITE) != 0 ) {
			error = do_aio_write( entryp );
		}
		else if ( (entryp->flags & (AIO_FSYNC | AIO_DSYNC)) != 0 ) {
			error = do_aio_fsync( entryp );
		}
		else {
			printf( "%s - unknown aio request - flags 0x%02X \n", 
					__FUNCTION__, entryp->flags );
			error = EINVAL;
		}

		/* Restore old map */
		if ( currentmap != entryp->aio_map ) {
			(void) vm_map_switch( oldmap );
			uthreadp->uu_aio_task = oldaiotask;
		}

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread)) | DBG_FUNC_END,
				(int)entryp->procp, (int)entryp->uaiocbp, entryp->errorval, 
				entryp->returnval, 0 );

		
		/* XXX COUNTS */
		aio_entry_lock_spin(entryp);
		entryp->errorval = error;	
		aio_entry_unlock(entryp);

		/* we're done with the IO request so pop it off the active queue and */
		/* push it on the done queue */
		aio_proc_lock(entryp->procp);
		aio_proc_move_done_locked(entryp->procp, entryp);
		aio_proc_unlock(entryp->procp);

		OSDecrementAtomic(&aio_anchor.aio_inflight_count);

		/* remove our reference to the user land map. */
		if ( VM_MAP_NULL != entryp->aio_map ) {
			vm_map_t 		my_map;

			my_map = entryp->aio_map;
			entryp->aio_map = VM_MAP_NULL;
			vm_map_deallocate( my_map );
		}

		/* Provide notifications */
		do_aio_completion( entryp );

		/* Will free if needed */
		aio_entry_unref(entryp);

	} /* for ( ;; ) */

	/* NOT REACHED */
	
} /* aio_work_thread */


/*
 * aio_get_some_work - get the next async IO request that is ready to be executed.
 * aio_fsync complicates matters a bit since we cannot do the fsync until all async
 * IO requests at the time the aio_fsync call came in have completed.
 * NOTE - AIO_LOCK must be held by caller
 */
static aio_workq_entry *
aio_get_some_work( void )
{
	aio_workq_entry		 		*entryp = NULL;
	aio_workq_t 				queue = NULL;

	/* Just one queue for the moment.  In the future there will be many. */
	queue = &aio_anchor.aio_async_workqs[0];	
	aio_workq_lock_spin(queue);
	if (queue->aioq_count == 0) {
		goto nowork;
	}

	/* 
	 * Hold the queue lock.
	 *
	 * pop some work off the work queue and add to our active queue
	 * Always start with the queue lock held. 
	 */
	for(;;) {
		/* 
		 * Pull of of work queue.  Once it's off, it can't be cancelled,
		 * so we can take our ref once we drop the queue lock.
		 */
		entryp = TAILQ_FIRST(&queue->aioq_entries);

		/* 
		 * If there's no work or only fsyncs that need delay, go to sleep 
		 * and then start anew from aio_work_thread 
		 */
		if (entryp == NULL) {
			goto nowork;
		}

		aio_workq_remove_entry_locked(queue, entryp);
		
		aio_workq_unlock(queue);

		/* 
		 * Check if it's an fsync that must be delayed.  No need to lock the entry;
		 * that flag would have been set at initialization.
		 */
		if ( (entryp->flags & AIO_FSYNC) != 0 ) {
			/* 
			 * Check for unfinished operations on the same file
			 * in this proc's queue.
			 */
			aio_proc_lock_spin(entryp->procp);
			if ( aio_delay_fsync_request( entryp ) ) {
				/* It needs to be delayed.  Put it back on the end of the work queue */
				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync_delay)) | DBG_FUNC_NONE,
							  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );

				aio_proc_unlock(entryp->procp);

				aio_workq_lock_spin(queue);
				aio_workq_add_entry_locked(queue, entryp);
				continue;
			} 
			aio_proc_unlock(entryp->procp);
		}
		
		break;
	}

	aio_entry_ref(entryp);

	OSIncrementAtomic(&aio_anchor.aio_inflight_count);
	return( entryp );

nowork:
	/* We will wake up when someone enqueues something */
	wait_queue_assert_wait(queue->aioq_waitq, queue, THREAD_UNINT, 0);
	aio_workq_unlock(queue);
	thread_block( (thread_continue_t)aio_work_thread );

	// notreached
	return NULL;
}

/*
 * aio_delay_fsync_request - look to see if this aio_fsync request should be delayed.
 * A big, simple hammer: only send it off if it's the most recently filed IO which has
 * not been completed.
 */
static boolean_t
aio_delay_fsync_request( aio_workq_entry *entryp )
{
	if (entryp == TAILQ_FIRST(&entryp->procp->p_aio_activeq)) {
		return FALSE;
	}
		
	return TRUE;
} /* aio_delay_fsync_request */

static aio_workq_entry *
aio_create_queue_entry(proc_t procp, user_addr_t aiocbp, void *group_tag, int kindOfIO)
{
	aio_workq_entry	*entryp;
	int		result = 0;

	entryp = (aio_workq_entry *) zalloc( aio_workq_zonep );
	if ( entryp == NULL ) {
		result = EAGAIN; 
		goto error_exit;
	}

	bzero( entryp, sizeof(*entryp) );

	/* fill in the rest of the aio_workq_entry */
	entryp->procp = procp;
	entryp->uaiocbp = aiocbp;
	entryp->flags |= kindOfIO;
	entryp->group_tag = group_tag;
	entryp->aio_map = VM_MAP_NULL;
	entryp->aio_refcount = 0;

	if ( proc_is64bit(procp) ) {
		struct user64_aiocb aiocb64;
		
		result = copyin( aiocbp, &aiocb64, sizeof(aiocb64) );
		if (result == 0 )
			do_munge_aiocb_user64_to_user(&aiocb64, &entryp->aiocb);
		
	} else {
		struct user32_aiocb aiocb32;
		
		result = copyin( aiocbp, &aiocb32, sizeof(aiocb32) );
		if ( result == 0 )
			do_munge_aiocb_user32_to_user( &aiocb32, &entryp->aiocb );
	}

	if ( result != 0 ) {
		result = EAGAIN;
		goto error_exit;
	}

	/* get a reference to the user land map in order to keep it around */
	entryp->aio_map = get_task_map( procp->task );
	vm_map_reference( entryp->aio_map );

	/* do some more validation on the aiocb and embedded file descriptor */
	result = aio_validate( entryp );

error_exit:
	if ( result && entryp != NULL ) {
		zfree( aio_workq_zonep, entryp );
		entryp = NULL;
	}

	return ( entryp );
}


/*
 * aio_queue_async_request - queue up an async IO request on our work queue then
 * wake up one of our worker threads to do the actual work.  We get a reference
 * to our caller's user land map in order to keep it around while we are
 * processing the request. 
 */
static int
aio_queue_async_request(proc_t procp, user_addr_t aiocbp, int kindOfIO )
{
	aio_workq_entry	*entryp;
	int		result;
	int		old_count;

	old_count = aio_increment_total_count();
	if (old_count >= aio_max_requests) {
		result = EAGAIN;
		goto error_noalloc;
	}

	entryp = aio_create_queue_entry( procp, aiocbp, 0, kindOfIO);
	if ( entryp == NULL ) {
		result = EAGAIN;
		goto error_noalloc;
	}


	aio_proc_lock_spin(procp);

	if ( is_already_queued( entryp->procp, entryp->uaiocbp ) == TRUE ) {
		result = EAGAIN; 
		goto error_exit;
	}

	/* check our aio limits to throttle bad or rude user land behavior */
	if (aio_get_process_count( procp ) >= aio_max_requests_per_process) {
		printf("aio_queue_async_request(): too many in flight for proc: %d.\n", procp->p_aio_total_count);
		result = EAGAIN; 
		goto error_exit;
	}
	
	/* Add the IO to proc and work queues, wake up threads as appropriate */
	lck_mtx_convert_spin(aio_proc_mutex(procp));
	aio_enqueue_work(procp, entryp, 1);
	
	aio_proc_unlock(procp);
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued)) | DBG_FUNC_NONE,
		     	  (int)procp, (int)aiocbp, 0, 0, 0 );

	return( 0 );
	
error_exit:
	/*
	 * This entry has not been queued up so no worries about
	 * unlocked state and aio_map
	 */
	aio_proc_unlock(procp);
	aio_free_request(entryp);

error_noalloc:
	aio_decrement_total_count();

	return( result );
	
} /* aio_queue_async_request */


/*
 * lio_create_entry
 *
 * Allocate an aio_workq_entry and fill it in.  If all goes well return 0
 * and pass the aio_workq_entry pointer back to our caller.
 *
 * Parameters:	procp			The process makign the request
 *		aiocbp			The aio context buffer pointer
 *		group_tag		The group tag used to indicate a
 *					group of operations has completed
 *		entrypp			Pointer to the pointer to receive the
 *					address of the created aio_workq_entry
 *
 * Returns:	0			Successfully created
 *		EAGAIN			Try again (usually resource shortage)
 *
 *
 * Notes:	We get a reference to our caller's user land map in order
 *		to keep it around while we are processing the request.  
 *
 *		lio_listio calls behave differently at completion they do
 *		completion notification when all async IO requests have
 *		completed.  We use group_tag to tag IO requests that behave
 *		in the delay notification manner. 
 *
 *		All synchronous operations are considered to not have a
 *		signal routine associated with them (sigp == USER_ADDR_NULL).
 */
static int
lio_create_entry(proc_t procp, user_addr_t aiocbp, void *group_tag,
		aio_workq_entry **entrypp )
{
	aio_workq_entry	*entryp;
	int		result;

	entryp = aio_create_queue_entry( procp, aiocbp, group_tag, AIO_LIO);
	if ( entryp == NULL ) {
		result = EAGAIN; 
		goto error_exit;
	}

	/*
	 * Look for lio_listio LIO_NOP requests and ignore them; this is
	 * not really an error, but we need to free our aio_workq_entry.
	 */
	if ( entryp->aiocb.aio_lio_opcode == LIO_NOP ) {
		result = 0;
		goto error_exit;
	}

	*entrypp = entryp;
	return( 0 );
	
error_exit:

	if ( entryp != NULL ) {
		/*
		 * This entry has not been queued up so no worries about
		 * unlocked state and aio_map
		 */
		aio_free_request(entryp);
	}
		
	return( result );
	
} /* lio_create_entry */


/*
 * aio_free_request - remove our reference on the user land map and
 * free the work queue entry resources.  The entry is off all lists
 * and has zero refcount, so no one can have a pointer to it.
 */

static int
aio_free_request(aio_workq_entry *entryp)
{
	/* remove our reference to the user land map. */
	if ( VM_MAP_NULL != entryp->aio_map) {
		vm_map_deallocate(entryp->aio_map);
	}

	entryp->aio_refcount = -1; /* A bit of poisoning in case of bad refcounting. */
	
	zfree( aio_workq_zonep, entryp );

	return( 0 );
	
} /* aio_free_request */


/*
 * aio_validate
 *
 * validate the aiocb passed in by one of the aio syscalls.
 */
static int
aio_validate( aio_workq_entry *entryp ) 
{
	struct fileproc 				*fp;
	int							flag;
	int							result;
	
	result = 0;

	if ( (entryp->flags & AIO_LIO) != 0 ) {
		if ( entryp->aiocb.aio_lio_opcode == LIO_READ )
			entryp->flags |= AIO_READ;
		else if ( entryp->aiocb.aio_lio_opcode == LIO_WRITE )
			entryp->flags |= AIO_WRITE;
		else if ( entryp->aiocb.aio_lio_opcode == LIO_NOP )
			return( 0 );
		else
			return( EINVAL );
	}

	flag = FREAD;
	if ( (entryp->flags & (AIO_WRITE | AIO_FSYNC | AIO_DSYNC)) != 0 ) {
		flag = FWRITE;
	}

	if ( (entryp->flags & (AIO_READ | AIO_WRITE)) != 0 ) {
		if ( entryp->aiocb.aio_nbytes > INT_MAX		||
			 entryp->aiocb.aio_buf == USER_ADDR_NULL ||
			 entryp->aiocb.aio_offset < 0 )
			return( EINVAL );
	}

	/*
	 * validate aiocb.aio_sigevent.  at this point we only support
	 * sigev_notify equal to SIGEV_SIGNAL or SIGEV_NONE.  this means
	 * sigev_value, sigev_notify_function, and sigev_notify_attributes
	 * are ignored, since SIGEV_THREAD is unsupported.  This is consistent
	 * with no [RTS] (RalTime Signal) option group support.
	 */
	switch ( entryp->aiocb.aio_sigevent.sigev_notify ) {
	case SIGEV_SIGNAL:
	    {
		int		signum;

		/* make sure we have a valid signal number */
		signum = entryp->aiocb.aio_sigevent.sigev_signo;
		if ( signum <= 0 || signum >= NSIG || 
			 signum == SIGKILL || signum == SIGSTOP )
			return (EINVAL);
	    }
	    break;

	case SIGEV_NONE:
		break;

	case SIGEV_THREAD:
		/* Unsupported [RTS] */

	default:
		return (EINVAL);
	}
	
	/* validate the file descriptor and that the file was opened
	 * for the appropriate read / write access.
	 */
	proc_fdlock(entryp->procp);

	result = fp_lookup( entryp->procp, entryp->aiocb.aio_fildes, &fp , 1);
	if ( result == 0 ) {
		if ( (fp->f_fglob->fg_flag & flag) == 0 ) {
			/* we don't have read or write access */
			result = EBADF;
		}
		else if ( fp->f_fglob->fg_type != DTYPE_VNODE ) {
			/* this is not a file */
			result = ESPIPE;
		} else
		        fp->f_flags |= FP_AIOISSUED;

		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp , 1);
	}
	else {
		result = EBADF;
	}
	
	proc_fdunlock(entryp->procp);

	return( result );

} /* aio_validate */

static int 
aio_increment_total_count()
{
	return OSIncrementAtomic(&aio_anchor.aio_total_count);
}

static int 		
aio_decrement_total_count()
{
	int old = OSDecrementAtomic(&aio_anchor.aio_total_count);
	if (old <= 0) {
		panic("Negative total AIO count!\n");
	}

	return old;
}

static int
aio_get_process_count(proc_t procp ) 
{
	return procp->p_aio_total_count;
	
} /* aio_get_process_count */

static int
aio_get_all_queues_count( void ) 
{
	return aio_anchor.aio_total_count;
	
} /* aio_get_all_queues_count */


/*
 * do_aio_completion.  Handle async IO completion.  
 */
static void
do_aio_completion( aio_workq_entry *entryp ) 
{

	boolean_t		lastLioCompleted = FALSE;
	aio_lio_context	*lio_context = NULL;
	int waiter = 0;
	
	lio_context = (aio_lio_context *)entryp->group_tag;
	
	if (lio_context != NULL) {
		
		aio_proc_lock_spin(entryp->procp);

		/* Account for this I/O completing. */
	 	lio_context->io_completed++;
		
		/* Are we done with this lio context? */
	 	if (lio_context->io_issued == lio_context->io_completed) {
	 		lastLioCompleted = TRUE;
	 	}
		
		waiter = lio_context->io_waiter;
		
		/* explicit wakeup of lio_listio() waiting in LIO_WAIT */
		if ((entryp->flags & AIO_LIO_NOTIFY) && (lastLioCompleted) && (waiter != 0)) {
			/* wake up the waiter */
			wakeup(lio_context);
		}
		
		aio_proc_unlock(entryp->procp);
	}
	
	if ( entryp->aiocb.aio_sigevent.sigev_notify == SIGEV_SIGNAL &&
		 (entryp->flags & AIO_DISABLE) == 0 ) {
		
		boolean_t	performSignal = FALSE;
		 if (lio_context == NULL) {
		 	performSignal = TRUE;
		 }
		 else {
			/* 
			 * If this was the last request in the group and a signal
			 * is desired, send one.
			 */
			performSignal = lastLioCompleted;
		 }
		 
		 if (performSignal) {
		 	
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_sig)) | DBG_FUNC_NONE,
				 (int)entryp->procp, (int)entryp->uaiocbp, 
				 entryp->aiocb.aio_sigevent.sigev_signo, 0, 0 );
			
			psignal( entryp->procp, entryp->aiocb.aio_sigevent.sigev_signo );
		}
	}

	if ((entryp->flags & AIO_EXIT_WAIT) && (entryp->flags & AIO_CLOSE_WAIT)) {
		panic("Close and exit flags set at the same time\n");
	}
	
	/*
	 * need to handle case where a process is trying to exit, exec, or
	 * close and is currently waiting for active aio requests to complete.
	 * If AIO_CLEANUP_WAIT is set then we need to look to see if there are any 
	 * other requests in the active queue for this process.  If there are 
	 * none then wakeup using the AIO_CLEANUP_SLEEP_CHAN tsleep channel.
	 * If there are some still active then do nothing - we only want to
	 * wakeup when all active aio requests for the process are complete. 
	 *
	 * Don't need to lock the entry or proc to check the cleanup flag.  It can only be
	 * set for cancellation, while the entryp is still on a proc list; now it's 
	 * off, so that flag is already set if it's going to be.
	 */
	if ( (entryp->flags & AIO_EXIT_WAIT) != 0 ) {
		int		active_requests;

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wait)) | DBG_FUNC_NONE,
					  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		
		aio_proc_lock_spin(entryp->procp);
		active_requests = aio_active_requests_for_process( entryp->procp );
		if ( active_requests < 1 ) {
			/* 
			 * no active aio requests for this process, continue exiting.  In this
			 * case, there should be no one else waiting ont he proc in AIO...
			 */
			wakeup_one((caddr_t)&entryp->procp->AIO_CLEANUP_SLEEP_CHAN);
			aio_proc_unlock(entryp->procp);

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wake)) | DBG_FUNC_NONE,
					  	  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		} else {
			aio_proc_unlock(entryp->procp);
		}
	}
	
	if ( (entryp->flags & AIO_CLOSE_WAIT) != 0 ) {
		int		active_requests;

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wait)) | DBG_FUNC_NONE,
					  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		
		aio_proc_lock_spin(entryp->procp);
		active_requests = aio_proc_active_requests_for_file( entryp->procp, entryp->aiocb.aio_fildes);
		if ( active_requests < 1 ) {
			/* Can't wakeup_one(); multiple closes might be in progress. */
			wakeup(&entryp->procp->AIO_CLEANUP_SLEEP_CHAN);
			aio_proc_unlock(entryp->procp);

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wake)) | DBG_FUNC_NONE,
					  	  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		} else {
			aio_proc_unlock(entryp->procp);
		}
	}
	/* 
	 * A thread in aio_suspend() wants to known about completed IOs.  If it checked
	 * the done list before we moved our AIO there, then it already asserted its wait,
	 * and we can wake it up without holding the lock.  If it checked the list after
	 * we did our move, then it already has seen the AIO that we moved.  Herego, we
	 * can do our wakeup without holding the lock.
	 */
	wakeup( (caddr_t) &entryp->procp->AIO_SUSPEND_SLEEP_CHAN ); 
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_suspend_wake)) | DBG_FUNC_NONE,
				  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );

	/*   
	 * free the LIO context if the last lio completed and no thread is
	 * waiting
	 */
	if (lastLioCompleted && (waiter == 0)) 
		free_lio_context (lio_context);

	
} /* do_aio_completion */


/*
 * do_aio_read
 */
static int
do_aio_read( aio_workq_entry *entryp )
{
	struct fileproc		*fp;
	int					error;
	struct vfs_context	context;

	if ( (error = fp_lookup(entryp->procp, entryp->aiocb.aio_fildes, &fp , 0)) )
		return(error);
	if ( (fp->f_fglob->fg_flag & FREAD) == 0 ) {
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
		return(EBADF);
	}

	/*
	 * <rdar://4714366>
	 * Needs vfs_context_t from vfs_context_create() in entryp!
	 */
	context.vc_thread = proc_thread(entryp->procp);	/* XXX */
	context.vc_ucred = fp->f_fglob->fg_cred;

	error = dofileread(&context, fp, 
				entryp->aiocb.aio_buf, 
				entryp->aiocb.aio_nbytes,
				entryp->aiocb.aio_offset, FOF_OFFSET, 
				&entryp->returnval);
	fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
			
	return( error );
	
} /* do_aio_read */


/*
 * do_aio_write
 */
static int
do_aio_write( aio_workq_entry *entryp )
{
	struct fileproc 		*fp;
	int				error, flags;
	struct vfs_context		context;

	if ( (error = fp_lookup(entryp->procp, entryp->aiocb.aio_fildes, &fp , 0)) )
		return(error);
	if ( (fp->f_fglob->fg_flag & FWRITE) == 0 ) {
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
		return(EBADF);
	}

	flags = FOF_PCRED;
	if ( (fp->f_fglob->fg_flag & O_APPEND) == 0 ) {
		flags |= FOF_OFFSET;
	}

	/*
	 * <rdar://4714366>
	 * Needs vfs_context_t from vfs_context_create() in entryp!
	 */
	context.vc_thread = proc_thread(entryp->procp);	/* XXX */
	context.vc_ucred = fp->f_fglob->fg_cred;

	/* NB: tell dofilewrite the offset, and to use the proc cred */
	error = dofilewrite(&context,
				fp,
				entryp->aiocb.aio_buf,
				entryp->aiocb.aio_nbytes,
				entryp->aiocb.aio_offset,
				flags,
				&entryp->returnval);
	
	fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);

	return( error );

} /* do_aio_write */


/*
 * aio_active_requests_for_process - return number of active async IO
 * requests for the given process.
 */
static int
aio_active_requests_for_process(proc_t procp )
{
	return( procp->p_aio_active_count );

} /* aio_active_requests_for_process */

/*
 * Called with the proc locked.
 */
static int
aio_proc_active_requests_for_file(proc_t procp, int fd)
{
	int count = 0;
	aio_workq_entry *entryp;
	TAILQ_FOREACH(entryp, &procp->p_aio_activeq, aio_proc_link) {
		if (entryp->aiocb.aio_fildes == fd) {
			count++;
		}
	}

	return count;
} /* aio_active_requests_for_process */



/*
 * do_aio_fsync
 */
static int
do_aio_fsync( aio_workq_entry *entryp )
{
	struct vfs_context 	context;
	struct vnode 		*vp;
	struct fileproc		*fp;
	int			sync_flag;
	int			error;

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
	if (entryp->flags & AIO_FSYNC)
		sync_flag = MNT_WAIT;
	else
		sync_flag = MNT_DWAIT;
	
	error = fp_getfvp( entryp->procp, entryp->aiocb.aio_fildes, &fp, &vp);
	if ( error == 0 ) {
		if ( (error = vnode_getwithref(vp)) ) {
		        fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
			entryp->returnval = -1;
			return(error);
		}
		context.vc_thread = current_thread();
		context.vc_ucred = fp->f_fglob->fg_cred;

		error = VNOP_FSYNC( vp, sync_flag, &context);

		(void)vnode_put(vp);

		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
	}
	if ( error != 0 )
		entryp->returnval = -1;

	return( error );
		
} /* do_aio_fsync */


/*
 * is_already_queued - runs through our queues to see if the given  
 * aiocbp / process is there.  Returns TRUE if there is a match
 * on any of our aio queues.
 *
 * Called with proc aio lock held (can be held spin)
 */
static boolean_t
is_already_queued(proc_t procp, 
					user_addr_t aiocbp ) 
{
	aio_workq_entry		 	*entryp;
	boolean_t				result;
	
	result = FALSE;
		
	/* look for matches on our queue of async IO requests that have completed */
	TAILQ_FOREACH( entryp, &procp->p_aio_doneq, aio_proc_link ) {
		if ( aiocbp == entryp->uaiocbp ) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}
	
	/* look for matches on our queue of active async IO requests */
	TAILQ_FOREACH( entryp, &procp->p_aio_activeq, aio_proc_link ) {
		if ( aiocbp == entryp->uaiocbp ) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}
	
ExitThisRoutine:
	return( result );
	
} /* is_already_queued */


static void
free_lio_context(aio_lio_context* context)
{

#if DEBUG	
	OSDecrementAtomic(&lio_contexts_alloced);
#endif /* DEBUG */

	FREE( context, M_TEMP );

} /* free_lio_context */


/*
 * aio initialization
 */
__private_extern__ void
aio_init( void )
{
	int			i;
	
	aio_lock_grp_attr = lck_grp_attr_alloc_init();
	aio_proc_lock_grp = lck_grp_alloc_init("aio_proc", aio_lock_grp_attr);;
	aio_entry_lock_grp = lck_grp_alloc_init("aio_entry", aio_lock_grp_attr);;
	aio_queue_lock_grp = lck_grp_alloc_init("aio_queue", aio_lock_grp_attr);;
	aio_lock_attr = lck_attr_alloc_init();

	lck_mtx_init(&aio_entry_mtx, aio_entry_lock_grp, aio_lock_attr);
	lck_mtx_init(&aio_proc_mtx, aio_proc_lock_grp, aio_lock_attr);

	aio_anchor.aio_inflight_count = 0;
	aio_anchor.aio_done_count = 0;
	aio_anchor.aio_total_count = 0;
	aio_anchor.aio_num_workqs = AIO_NUM_WORK_QUEUES;

	for (i = 0; i < AIO_NUM_WORK_QUEUES; i++) {
		aio_workq_init(&aio_anchor.aio_async_workqs[i]);
	}


	i = sizeof( aio_workq_entry );
	aio_workq_zonep = zinit( i, i * aio_max_requests, i * aio_max_requests, "aiowq" );
		
	_aio_create_worker_threads( aio_worker_threads );
	
} /* aio_init */


/*
 * aio worker threads created here.
 */
__private_extern__ void
_aio_create_worker_threads( int num )
{
	int			i;
	
	/* create some worker threads to handle the async IO requests */
	for ( i = 0; i < num; i++ ) {
		thread_t		myThread;
		
		if ( KERN_SUCCESS != kernel_thread_start((thread_continue_t)aio_work_thread, NULL, &myThread) ) {
			printf( "%s - failed to create a work thread \n", __FUNCTION__ ); 
		}
		else
			thread_deallocate(myThread);
	}
	
	return;
	
} /* _aio_create_worker_threads */

/*
 * Return the current activation utask
 */
task_t
get_aiotask(void)
{
	return  ((struct uthread *)get_bsdthread_info(current_thread()))->uu_aio_task;  
}


/*
 * In the case of an aiocb from a
 * 32-bit process we need to expand some longs and pointers to the correct
 * sizes in order to let downstream code always work on the same type of
 * aiocb (in our case that is a user_aiocb)
 */
static void 
do_munge_aiocb_user32_to_user( struct user32_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp ) 
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
static void 
do_munge_aiocb_user64_to_user( struct user64_aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp ) 
{
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
}
