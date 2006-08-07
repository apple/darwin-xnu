/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
struct aio_anchor_cb
{
	int									aio_async_workq_count; 	/* entries on aio_async_workq */
	int									lio_sync_workq_count; 	/* entries on lio_sync_workq */
	int									aio_active_count; 	/* entries on all active queues (proc.aio_activeq) */
	int									aio_done_count; 	/* entries on all done queues (proc.aio_doneq) */
	TAILQ_HEAD( , aio_workq_entry ) 	aio_async_workq;
	TAILQ_HEAD( , aio_workq_entry ) 	lio_sync_workq;
};
typedef struct aio_anchor_cb aio_anchor_cb;


/*
 * Notes on aio sleep / wake channels.
 * We currently pick a couple fields within the proc structure that will allow
 * us sleep channels that currently do not collide with any other kernel routines.
 * At this time, for binary compatibility reasons, we cannot create new proc fields.
 */
#define AIO_SUSPEND_SLEEP_CHAN  p_estcpu
#define AIO_CLEANUP_SLEEP_CHAN 	p_pctcpu


/*
 * aysnc IO locking macros used to protect critical sections.
 */
#define AIO_LOCK	lck_mtx_lock(aio_lock)
#define AIO_UNLOCK	lck_mtx_unlock(aio_lock)


/*
 *  LOCAL PROTOTYPES
 */
static int			aio_active_requests_for_process( struct proc *procp );
static boolean_t	aio_delay_fsync_request( aio_workq_entry *entryp );
static int			aio_free_request( aio_workq_entry *entryp, vm_map_t the_map );
static int			aio_get_all_queues_count( void );
static int			aio_get_process_count( struct proc *procp );
static aio_workq_entry *  aio_get_some_work( void );
static boolean_t	aio_last_group_io( aio_workq_entry *entryp );
static void			aio_mark_requests( aio_workq_entry *entryp );
static int			aio_queue_async_request( struct proc *procp, 
									 		 user_addr_t aiocbp,
									   		 int kindOfIO );
static int			aio_validate( aio_workq_entry *entryp );
static void			aio_work_thread( void );
static int			do_aio_cancel(	struct proc *p, 
									int fd, 
									user_addr_t aiocbp, 
									boolean_t wait_for_completion,
									boolean_t disable_notification );
static void			do_aio_completion( aio_workq_entry *entryp );
static int			do_aio_fsync( aio_workq_entry *entryp );
static int			do_aio_read( aio_workq_entry *entryp );
static int			do_aio_write( aio_workq_entry *entryp );
static void 		do_munge_aiocb( struct aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp );
static boolean_t	is_already_queued( 	struct proc *procp, 
										user_addr_t aiocbp );
static int			lio_create_async_entry( struct proc *procp, 
											 user_addr_t aiocbp, 
						 					 user_addr_t sigp, 
						 					 long group_tag,
						 					 aio_workq_entry **entrypp );
static int			lio_create_sync_entry( struct proc *procp, 
											user_addr_t aiocbp, 
											long group_tag,
											aio_workq_entry **entrypp );


/*
 *  EXTERNAL PROTOTYPES
 */

/* in ...bsd/kern/sys_generic.c */
extern int			dofileread( struct proc *p, struct fileproc *fp, int fd, 
								user_addr_t bufp, user_size_t nbyte, 
								off_t offset, int flags, user_ssize_t *retval );
extern int			dofilewrite( struct proc *p, struct fileproc *fp, int fd, 
								 user_addr_t bufp, user_size_t nbyte, off_t offset, 
								 int flags, user_ssize_t *retval );

/*
 * aio external global variables.
 */
extern int aio_max_requests;  				/* AIO_MAX - configurable */
extern int aio_max_requests_per_process;	/* AIO_PROCESS_MAX - configurable */
extern int aio_worker_threads;				/* AIO_THREAD_COUNT - configurable */


/*
 * aio static variables.
 */
static aio_anchor_cb		aio_anchor;
static lck_mtx_t * 		aio_lock;
static lck_grp_t * 		aio_lock_grp;
static lck_attr_t * 		aio_lock_attr;
static lck_grp_attr_t * 	aio_lock_grp_attr;
static struct zone  		*aio_workq_zonep;




/*
 * aio_cancel - attempt to cancel one or more async IO requests currently
 * outstanding against file descriptor uap->fd.  If uap->aiocbp is not 
 * NULL then only one specific IO is cancelled (if possible).  If uap->aiocbp
 * is NULL then all outstanding async IO request for the given file
 * descriptor are cancelled (if possible).
 */

int
aio_cancel( struct proc *p, struct aio_cancel_args *uap, int *retval )
{
	struct user_aiocb		my_aiocb;
	int							result;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	/* quick check to see if there are any async IO requests queued up */
	AIO_LOCK;
	result = aio_get_all_queues_count( );
	AIO_UNLOCK;
	if ( result < 1 ) {
		result = EBADF;
		goto ExitRoutine;
	}
	
	*retval = -1; 
	if ( uap->aiocbp != USER_ADDR_NULL ) {
		if ( !IS_64BIT_PROCESS(p) ) {
			struct aiocb aiocb32;

			result = copyin( uap->aiocbp, &aiocb32, sizeof(aiocb32) );
			if ( result == 0 )
				do_munge_aiocb( &aiocb32, &my_aiocb );
		} else
			result = copyin( uap->aiocbp, &my_aiocb, sizeof(my_aiocb) );

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
	result = do_aio_cancel( p, uap->fd, uap->aiocbp, FALSE, FALSE );

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
_aio_close( struct proc *p, int fd )
{
	int			error, count;

	/* quick check to see if there are any async IO requests queued up */
	AIO_LOCK;
	count = aio_get_all_queues_count( );
	AIO_UNLOCK;
	if ( count < 1 )
		return;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_close)) | DBG_FUNC_START,
		     	  (int)p, fd, 0, 0, 0 );
	
	/* cancel all async IO requests on our todo queues for this file descriptor */
	error = do_aio_cancel( p, fd, 0, TRUE, FALSE );
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

		tsleep( &p->AIO_CLEANUP_SLEEP_CHAN, PRIBIO, "aio_close", 0 );
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
aio_error( struct proc *p, struct aio_error_args *uap, int *retval )
{
	aio_workq_entry		 		*entryp;
	int							error;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	AIO_LOCK;

	/* quick check to see if there are any async IO requests queued up */
	if ( aio_get_all_queues_count( ) < 1 ) {
		error = EINVAL;
		goto ExitRoutine;
	}
	
	/* look for a match on our queue of async IO requests that have completed */
	TAILQ_FOREACH( entryp, &p->aio_doneq, aio_workq_link ) {
		if ( entryp->uaiocbp == uap->aiocbp ) {
			*retval = entryp->errorval;
			error = 0;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error_val)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	/* look for a match on our queue of active async IO requests */
	TAILQ_FOREACH( entryp, &p->aio_activeq, aio_workq_link ) {
		if ( entryp->uaiocbp == uap->aiocbp ) {
			*retval = EINPROGRESS;
			error = 0;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error_activeq)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	/* look for a match on our queue of todo work */
	TAILQ_FOREACH( entryp, &aio_anchor.aio_async_workq, aio_workq_link ) {
		if ( p == entryp->procp && entryp->uaiocbp == uap->aiocbp ) {
			*retval = EINPROGRESS;
			error = 0;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error_workq)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	error = EINVAL;
	
ExitRoutine:
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_error)) | DBG_FUNC_END,
		     	  (int)p, (int)uap->aiocbp, error, 0, 0 );
	AIO_UNLOCK;

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
aio_fsync( struct proc *p, struct aio_fsync_args *uap, int *retval )
{
	int			error;
	int			fsync_kind;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, uap->op, 0, 0 );

	*retval = 0;
	/* 0 := O_SYNC for binary backward compatibility with Panther */
	if (uap->op == O_SYNC || uap->op == 0)
		fsync_kind = AIO_FSYNC;
#if 0 // we don't support fdatasync() call yet
	else if ( uap->op == O_DSYNC )
		fsync_kind = AIO_DSYNC;
#endif
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
aio_read( struct proc *p, struct aio_read_args *uap, int *retval )
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
 * that would be returned by corresponding IO request (read, wrtie,
 * fdatasync, or sync).  This is where we release kernel resources 
 * held for async IO call associated with the given aiocb pointer.
 */

int
aio_return( struct proc *p, struct aio_return_args *uap, user_ssize_t *retval )
{
	aio_workq_entry		 		*entryp;
	int							error;
	boolean_t					lock_held;
	
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return)) | DBG_FUNC_START,
		     	  (int)p, (int)uap->aiocbp, 0, 0, 0 );

	AIO_LOCK;
	lock_held = TRUE;
	*retval = 0;
	
	/* quick check to see if there are any async IO requests queued up */
	if ( aio_get_all_queues_count( ) < 1 ) {
		error = EINVAL;
		goto ExitRoutine;
	}

	/* look for a match on our queue of async IO requests that have completed */
	TAILQ_FOREACH( entryp, &p->aio_doneq, aio_workq_link ) {
		if ( entryp->uaiocbp == uap->aiocbp ) {
			TAILQ_REMOVE( &p->aio_doneq, entryp, aio_workq_link );
			aio_anchor.aio_done_count--;
			p->aio_done_count--;
			
			*retval = entryp->returnval;

			/* we cannot free requests that are still completing */
			if ( (entryp->flags & AIO_COMPLETION) == 0 ) {
				vm_map_t 		my_map;
			
				my_map = entryp->aio_map;
				entryp->aio_map = VM_MAP_NULL;
				AIO_UNLOCK;
				lock_held = FALSE;
				aio_free_request( entryp, my_map );
			}
			else
				/* tell completion code to free this request */
				entryp->flags |= AIO_DO_FREE;
			error = 0;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return_val)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	/* look for a match on our queue of active async IO requests */
	TAILQ_FOREACH( entryp, &p->aio_activeq, aio_workq_link ) {
		if ( entryp->uaiocbp == uap->aiocbp ) {
			error = EINPROGRESS;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return_activeq)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	
	/* look for a match on our queue of todo work */
	TAILQ_FOREACH( entryp, &aio_anchor.aio_async_workq, aio_workq_link ) {
		if ( p == entryp->procp && entryp->uaiocbp == uap->aiocbp ) {
			error = EINPROGRESS;
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_return_workq)) | DBG_FUNC_NONE,
		     	 		   (int)p, (int)uap->aiocbp, *retval, 0, 0 );
			goto ExitRoutine;
		}
	}
	error = EINVAL;
	
ExitRoutine:
	if ( lock_held )
		AIO_UNLOCK;
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
_aio_exec( struct proc *p )
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
_aio_exit( struct proc *p )
{
	int						error, count;
	aio_workq_entry 		*entryp;

	/* quick check to see if there are any async IO requests queued up */
	AIO_LOCK;
	count = aio_get_all_queues_count( );
	AIO_UNLOCK;
	if ( count < 1 ) {
		return;
	}

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exit)) | DBG_FUNC_START,
		     	  (int)p, 0, 0, 0, 0 );

	/* 
	 * cancel async IO requests on the todo work queue and wait for those  
	 * already active to complete. 
	 */
	error = do_aio_cancel( p, 0, 0, TRUE, TRUE );
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

		tsleep( &p->AIO_CLEANUP_SLEEP_CHAN, PRIBIO, "aio_exit", 0 );
	}
	
	/* release all aio resources used by this process */
	AIO_LOCK;
	entryp = TAILQ_FIRST( &p->aio_doneq );
	while ( entryp != NULL ) {
		aio_workq_entry		 	*next_entryp;
			
		next_entryp = TAILQ_NEXT( entryp, aio_workq_link );
		TAILQ_REMOVE( &p->aio_doneq, entryp, aio_workq_link );
		aio_anchor.aio_done_count--;
		p->aio_done_count--;
			
		/* we cannot free requests that are still completing */
		if ( (entryp->flags & AIO_COMPLETION) == 0 ) {
			vm_map_t 		my_map;
			
			my_map = entryp->aio_map;
			entryp->aio_map = VM_MAP_NULL;
			AIO_UNLOCK;
			aio_free_request( entryp, my_map );

			/* need to start over since aio_doneq may have been */
			/* changed while we were away.  */
			AIO_LOCK;
			entryp = TAILQ_FIRST( &p->aio_doneq );
			continue;
		}
		else
			/* tell completion code to free this request */
			entryp->flags |= AIO_DO_FREE;
		entryp = next_entryp;
	}
	AIO_UNLOCK;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_exit)) | DBG_FUNC_END,
		     	  (int)p, 0, 0, 0, 0 );

	return;
	
} /* _aio_exit */


/*
 * do_aio_cancel - cancel async IO requests (if possible).  We get called by
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
 */

static int
do_aio_cancel( 	struct proc *p, int fd, user_addr_t aiocbp, 
				boolean_t wait_for_completion, boolean_t disable_notification )
{
	aio_workq_entry		 	*entryp;
	int						result;

	result = -1;
		
	/* look for a match on our queue of async todo work. */
	AIO_LOCK;
	entryp = TAILQ_FIRST( &aio_anchor.aio_async_workq );
	while ( entryp != NULL ) {
		aio_workq_entry		 	*next_entryp;
		
		next_entryp = TAILQ_NEXT( entryp, aio_workq_link );
		if ( p == entryp->procp ) {
			if ( (aiocbp == USER_ADDR_NULL && fd == 0) ||
				 (aiocbp != USER_ADDR_NULL && entryp->uaiocbp == aiocbp) ||
				 (aiocbp == USER_ADDR_NULL && fd == entryp->aiocb.aio_fildes) ) {
				/* we found a match so we remove the entry from the */
				/* todo work queue and place it on the done queue */
				TAILQ_REMOVE( &aio_anchor.aio_async_workq, entryp, aio_workq_link );
				aio_anchor.aio_async_workq_count--;
				entryp->errorval = ECANCELED;
				entryp->returnval = -1;
				if ( disable_notification )
					entryp->flags |= AIO_DISABLE; /* flag for special completion processing */
				result = AIO_CANCELED;

				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_async_workq)) | DBG_FUNC_NONE,
							  (int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

				TAILQ_INSERT_TAIL( &p->aio_doneq, entryp, aio_workq_link );
				aio_anchor.aio_done_count++;
				p->aio_done_count++;
				entryp->flags |= AIO_COMPLETION;
				AIO_UNLOCK;
				
				/* do completion processing for this request */
				do_aio_completion( entryp );
			
				AIO_LOCK;
				entryp->flags &= ~AIO_COMPLETION;
				if ( (entryp->flags & AIO_DO_FREE) != 0 ) {
					vm_map_t 		my_map;
					
					my_map = entryp->aio_map;
					entryp->aio_map = VM_MAP_NULL;
					AIO_UNLOCK;
					aio_free_request( entryp, my_map );
				}
				else
					AIO_UNLOCK;

				if ( aiocbp != USER_ADDR_NULL ) {
					return( result );
				}
				
				/* need to start over since aio_async_workq may have been */
				/* changed while we were away doing completion processing.  */
				AIO_LOCK;
 				entryp = TAILQ_FIRST( &aio_anchor.aio_async_workq );
 				continue;
			}
		}
		entryp = next_entryp;
	} /* while... */
		
	/* 
	 * look for a match on our queue of synchronous todo work.  This will 
	 * be a rare occurrence but could happen if a process is terminated while 
	 * processing a lio_listio call. 
	 */
	entryp = TAILQ_FIRST( &aio_anchor.lio_sync_workq );
	while ( entryp != NULL ) {
		aio_workq_entry		 	*next_entryp;
		
		next_entryp = TAILQ_NEXT( entryp, aio_workq_link );
		if ( p == entryp->procp ) {
			if ( (aiocbp == USER_ADDR_NULL && fd == 0) ||
				 (aiocbp != USER_ADDR_NULL && entryp->uaiocbp == aiocbp) ||
				 (aiocbp == USER_ADDR_NULL && fd == entryp->aiocb.aio_fildes) ) {
				/* we found a match so we remove the entry from the */
				/* todo work queue and place it on the done queue */
				TAILQ_REMOVE( &aio_anchor.lio_sync_workq, entryp, aio_workq_link );
				aio_anchor.lio_sync_workq_count--;
				entryp->errorval = ECANCELED;
				entryp->returnval = -1;
				if ( disable_notification )
					entryp->flags |= AIO_DISABLE; /* flag for special completion processing */
				result = AIO_CANCELED;

				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_sync_workq)) | DBG_FUNC_NONE,
							  (int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

				TAILQ_INSERT_TAIL( &p->aio_doneq, entryp, aio_workq_link );
				aio_anchor.aio_done_count++;
				p->aio_done_count++;
				if ( aiocbp != USER_ADDR_NULL ) {
					AIO_UNLOCK;
					return( result );
				}
			}
		}
		entryp = next_entryp;
	} /* while... */

	/* 
	 * look for a match on our queue of active async IO requests and 
	 * return AIO_NOTCANCELED result. 
	 */
	TAILQ_FOREACH( entryp, &p->aio_activeq, aio_workq_link ) {
		if ( (aiocbp == USER_ADDR_NULL && fd == 0) ||
			 (aiocbp != USER_ADDR_NULL && entryp->uaiocbp == aiocbp) ||
			 (aiocbp == USER_ADDR_NULL && fd == entryp->aiocb.aio_fildes) ) {
			result = AIO_NOTCANCELED;

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_activeq)) | DBG_FUNC_NONE,
						  (int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

			if ( wait_for_completion )
				entryp->flags |= AIO_WAITING; /* flag for special completion processing */
			if ( disable_notification )
				entryp->flags |= AIO_DISABLE; /* flag for special completion processing */
			if ( aiocbp != USER_ADDR_NULL ) {
				AIO_UNLOCK;
				return( result );
			}
		}
	}
	
	/* 
	 * if we didn't find any matches on the todo or active queues then look for a 
	 * match on our queue of async IO requests that have completed and if found 
	 * return AIO_ALLDONE result.  
	 */
	if ( result == -1 ) {
		TAILQ_FOREACH( entryp, &p->aio_doneq, aio_workq_link ) {
		if ( (aiocbp == USER_ADDR_NULL && fd == 0) ||
			 (aiocbp != USER_ADDR_NULL && entryp->uaiocbp == aiocbp) ||
			 (aiocbp == USER_ADDR_NULL && fd == entryp->aiocb.aio_fildes) ) {
				result = AIO_ALLDONE;

				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_doneq)) | DBG_FUNC_NONE,
							  (int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

				if ( aiocbp != USER_ADDR_NULL ) {
					AIO_UNLOCK;
					return( result );
				}
			}
		}
	}
	AIO_UNLOCK;

	return( result );
	
} /* do_aio_cancel */


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
aio_suspend( struct proc *p, struct aio_suspend_args *uap, int *retval )
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

	/* quick check to see if there are any async IO requests queued up */
	AIO_LOCK;
	count = aio_get_all_queues_count( );
	AIO_UNLOCK;
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
			error = copyin( uap->timeoutp, &ts, sizeof(ts) );
		}
		else {
			struct timespec temp;
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
			
		if ( ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ) {
			error = EINVAL;
			goto ExitThisRoutine;
		}

		nanoseconds_to_absolutetime( (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec, 
									 &abstime );
		clock_absolutetime_interval_to_deadline( abstime, &abstime );
	}

	/* we reserve enough space for largest possible pointer size */
	MALLOC( aiocbpp, user_addr_t *, (uap->nent * sizeof(user_addr_t)), M_TEMP, M_WAITOK );
	if ( aiocbpp == NULL ) {
		error = EAGAIN;
		goto ExitThisRoutine;
	}

	/* copyin our aiocb pointers from list */
	error = copyin( uap->aiocblist, aiocbpp, 
					proc_is64bit(p) ? (uap->nent * sizeof(user_addr_t)) 
									: (uap->nent * sizeof(uintptr_t)) );
	if ( error != 0 ) {
		error = EAGAIN;
		goto ExitThisRoutine;
	}
	
	/* we depend on a list of user_addr_t's so we need to munge and expand */
	/* when these pointers came from a 32-bit process */
	if ( !proc_is64bit(p) && sizeof(uintptr_t) < sizeof(user_addr_t) ) {
		/* position to the last entry and work back from there */
		uintptr_t 	*my_ptrp = ((uintptr_t *)aiocbpp) + (uap->nent - 1);
		user_addr_t *my_addrp = aiocbpp + (uap->nent - 1);
		for (i = 0; i < uap->nent; i++, my_ptrp--, my_addrp--) {
			*my_addrp = (user_addr_t) (*my_ptrp);
		}
	}
	
	/* check list of aio requests to see if any have completed */
	AIO_LOCK;
	for ( i = 0; i < uap->nent; i++ ) {
		user_addr_t	aiocbp;  

		/* NULL elements are legal so check for 'em */
		aiocbp = *(aiocbpp + i);
		if ( aiocbp == USER_ADDR_NULL )
			continue;
	
		/* return immediately if any aio request in the list is done */
		TAILQ_FOREACH( entryp, &p->aio_doneq, aio_workq_link ) {
			if ( entryp->uaiocbp == aiocbp ) {
				*retval = 0;
				error = 0;
				AIO_UNLOCK;
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
	assert_wait_deadline( (event_t) &p->AIO_SUSPEND_SLEEP_CHAN, THREAD_ABORTSAFE, abstime );
	AIO_UNLOCK;

	error = thread_block( THREAD_CONTINUE_NULL );

	if ( error == THREAD_AWAKENED ) {
		/* got our wakeup call from aio_work_thread() */
		*retval = 0;
		error = 0;
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
aio_write( struct proc *p, struct aio_write_args *uap, int *retval )
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


/*
 * lio_listio - initiate a list of IO requests.  We process the list of aiocbs
 * either synchronously (mode == LIO_WAIT) or asynchronously (mode == LIO_NOWAIT).
 * The caller gets error and return status for each aiocb in the list via aio_error 
 * and aio_return.  We must keep completed requests until released by the 
 * aio_return call.
 */

int
lio_listio( struct proc *p, struct lio_listio_args *uap, int *retval )
{
	int							i;
	int							call_result;
	int							result;
	long						group_tag;
	aio_workq_entry	*	 		*entryp_listp;
	user_addr_t					*aiocbpp;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_listio)) | DBG_FUNC_START,
		     	  (int)p, uap->nent, uap->mode, 0, 0 );
	
	entryp_listp = NULL;
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
	 * we use group_tag to mark IO requests for delayed completion processing
	 * which means we wait until all IO requests in the group have completed 
	 * before we either return to the caller when mode is LIO_WAIT or signal
	 * user when mode is LIO_NOWAIT. 
	 */
	group_tag = random();
		
	/* 
	 * allocate a list of aio_workq_entry pointers that we will use to queue
	 * up all our requests at once while holding our lock.
	 */
	MALLOC( entryp_listp, void *, (uap->nent * sizeof(aio_workq_entry *)), M_TEMP, M_WAITOK );
	if ( entryp_listp == NULL ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}

	/* we reserve enough space for largest possible pointer size */
	MALLOC( aiocbpp, user_addr_t *, (uap->nent * sizeof(user_addr_t)), M_TEMP, M_WAITOK );
	if ( aiocbpp == NULL ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}

	/* copyin our aiocb pointers from list */
	result = copyin( uap->aiocblist, aiocbpp, 
					IS_64BIT_PROCESS(p) ? (uap->nent * sizeof(user_addr_t)) 
										: (uap->nent * sizeof(uintptr_t)) );
	if ( result != 0 ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}
	
	/* we depend on a list of user_addr_t's so we need to munge and expand */
	/* when these pointers came from a 32-bit process */
	if ( !IS_64BIT_PROCESS(p) && sizeof(uintptr_t) < sizeof(user_addr_t) ) {
		/* position to the last entry and work back from there */
		uintptr_t 	*my_ptrp = ((uintptr_t *)aiocbpp) + (uap->nent - 1);
		user_addr_t *my_addrp = aiocbpp + (uap->nent - 1);
		for (i = 0; i < uap->nent; i++, my_ptrp--, my_addrp--) {
			*my_addrp = (user_addr_t) (*my_ptrp);
		}
	}

	/* process list of aio requests */
	for ( i = 0; i < uap->nent; i++ ) {
		user_addr_t my_aiocbp; 
	
		*(entryp_listp + i) = NULL;
		my_aiocbp = *(aiocbpp + i);
		
		/* NULL elements are legal so check for 'em */
		if ( my_aiocbp == USER_ADDR_NULL )
			continue;

		if ( uap->mode == LIO_NOWAIT )
			result = lio_create_async_entry( p, my_aiocbp, uap->sigp, 
											 group_tag, (entryp_listp + i) );
		else
			result = lio_create_sync_entry( p, my_aiocbp, group_tag, 
											(entryp_listp + i) );

		if ( result != 0 && call_result == -1 )
			call_result = result;
	}

	/* 
	 * we need to protect this section since we do not want any of these grouped 
	 * IO requests to begin until we have them all on the queue.
	 */
	AIO_LOCK;
	for ( i = 0; i < uap->nent; i++ ) {
		aio_workq_entry		 		*entryp;
		
		/* NULL elements are legal so check for 'em */
		entryp = *(entryp_listp + i);
		if ( entryp == NULL )
			continue;

		/* check our aio limits to throttle bad or rude user land behavior */
		if ( aio_get_all_queues_count( ) >= aio_max_requests || 
			 aio_get_process_count( entryp->procp ) >= aio_max_requests_per_process ||
			 is_already_queued( entryp->procp, entryp->uaiocbp ) == TRUE ) {
			vm_map_t 		my_map;
			
			my_map = entryp->aio_map;
			entryp->aio_map = VM_MAP_NULL;
			if ( call_result == -1 )
				call_result = EAGAIN; 
			AIO_UNLOCK;
			aio_free_request( entryp, my_map );
			AIO_LOCK;
			continue;
		}
		
		/* place the request on the appropriate queue */
		if ( uap->mode == LIO_NOWAIT ) {
			TAILQ_INSERT_TAIL( &aio_anchor.aio_async_workq, entryp, aio_workq_link );
			aio_anchor.aio_async_workq_count++;

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued)) | DBG_FUNC_NONE,
				     	  (int)p, (int)entryp->uaiocbp, 0, 0, 0 );
		}
		else {
			TAILQ_INSERT_TAIL( &aio_anchor.lio_sync_workq, entryp, aio_workq_link );
			aio_anchor.lio_sync_workq_count++;
		}
	}

	if ( uap->mode == LIO_NOWAIT ) { 
		/* caller does not want to wait so we'll fire off a worker thread and return */
		wakeup_one( (caddr_t) &aio_anchor.aio_async_workq );
	}
	else {
		aio_workq_entry		 	*entryp;
		int 					error;

		/* 
		 * mode is LIO_WAIT - handle the IO requests now.
		 */
 		entryp = TAILQ_FIRST( &aio_anchor.lio_sync_workq );
 		while ( entryp != NULL ) {
			if ( p == entryp->procp && group_tag == entryp->group_tag ) {
					
				TAILQ_REMOVE( &aio_anchor.lio_sync_workq, entryp, aio_workq_link );
				aio_anchor.lio_sync_workq_count--;
				AIO_UNLOCK;
				
				if ( (entryp->flags & AIO_READ) != 0 ) {
					error = do_aio_read( entryp );
				}
				else if ( (entryp->flags & AIO_WRITE) != 0 ) {
					error = do_aio_write( entryp );
				}
				else if ( (entryp->flags & AIO_FSYNC) != 0 ) {
					error = do_aio_fsync( entryp );
				}
				else {
					printf( "%s - unknown aio request - flags 0x%02X \n", 
							__FUNCTION__, entryp->flags );
					error = EINVAL;
				}
				entryp->errorval = error;	
				if ( error != 0 && call_result == -1 )
					call_result = EIO;

				AIO_LOCK;
				/* we're done with the IO request so move it on the done queue */
				TAILQ_INSERT_TAIL( &p->aio_doneq, entryp, aio_workq_link );
				aio_anchor.aio_done_count++;
				p->aio_done_count++;

				/* need to start over since lio_sync_workq may have been changed while we */
				/* were away doing the IO.  */
 				entryp = TAILQ_FIRST( &aio_anchor.lio_sync_workq );
 				continue;
			} /* p == entryp->procp */
			
 			entryp = TAILQ_NEXT( entryp, aio_workq_link );
        } /* while ( entryp != NULL ) */
	} /* uap->mode == LIO_WAIT */
	AIO_UNLOCK;

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
	
	for( ;; ) {
		AIO_LOCK;
		entryp = aio_get_some_work();
        if ( entryp == NULL ) {
        	/* 
        	 * aio worker threads wait for some work to get queued up 
        	 * by aio_queue_async_request.  Once some work gets queued 
        	 * it will wake up one of these worker threads just before 
        	 * returning to our caller in user land.
        	 */
			assert_wait( (event_t) &aio_anchor.aio_async_workq, THREAD_UNINT );
			AIO_UNLOCK; 
			
			thread_block( (thread_continue_t)aio_work_thread );
			/* NOT REACHED */
        }
		else {
			int 			error;
			vm_map_t 		currentmap;
			vm_map_t 		oldmap = VM_MAP_NULL;
			task_t			oldaiotask = TASK_NULL;
			struct uthread	*uthreadp = NULL;

			AIO_UNLOCK; 

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread)) | DBG_FUNC_START,
						  (int)entryp->procp, (int)entryp->uaiocbp, entryp->flags, 0, 0 );
			
			/*
			 * Assume the target's address space identity for the duration
			 * of the IO.
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
			else if ( (entryp->flags & AIO_FSYNC) != 0 ) {
				error = do_aio_fsync( entryp );
			}
			else {
				printf( "%s - unknown aio request - flags 0x%02X \n", 
						__FUNCTION__, entryp->flags );
				error = EINVAL;
			}
			entryp->errorval = error;		
			if ( currentmap != entryp->aio_map ) {
				(void) vm_map_switch( oldmap );
				uthreadp->uu_aio_task = oldaiotask;
			}
				
			/* we're done with the IO request so pop it off the active queue and */
			/* push it on the done queue */
			AIO_LOCK;
			TAILQ_REMOVE( &entryp->procp->aio_activeq, entryp, aio_workq_link );
			aio_anchor.aio_active_count--;
			entryp->procp->aio_active_count--;
			TAILQ_INSERT_TAIL( &entryp->procp->aio_doneq, entryp, aio_workq_link );
			aio_anchor.aio_done_count++;
			entryp->procp->aio_done_count++;
			entryp->flags |= AIO_COMPLETION;

			/* remove our reference to the user land map. */
			if ( VM_MAP_NULL != entryp->aio_map ) {
				vm_map_t 		my_map;
				
				my_map = entryp->aio_map;
				entryp->aio_map = VM_MAP_NULL;
				AIO_UNLOCK;  /* must unlock before calling vm_map_deallocate() */
				vm_map_deallocate( my_map );
			}
			else {
				AIO_UNLOCK;
			}
			
			do_aio_completion( entryp );
			
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread)) | DBG_FUNC_END,
						  (int)entryp->procp, (int)entryp->uaiocbp, entryp->errorval, 
						  entryp->returnval, 0 );
			
			AIO_LOCK;
			entryp->flags &= ~AIO_COMPLETION;
			if ( (entryp->flags & AIO_DO_FREE) != 0 ) {
				vm_map_t 		my_map;
			
				my_map = entryp->aio_map;
				entryp->aio_map = VM_MAP_NULL;
				AIO_UNLOCK;
				aio_free_request( entryp, my_map );
			}
			else
				AIO_UNLOCK;
		}
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
	aio_workq_entry		 		*entryp;
	
	/* pop some work off the work queue and add to our active queue */
	for ( entryp = TAILQ_FIRST( &aio_anchor.aio_async_workq );
		  entryp != NULL;
		  entryp = TAILQ_NEXT( entryp, aio_workq_link ) ) {

		if ( (entryp->flags & AIO_FSYNC) != 0 ) {
			/* leave aio_fsync calls on the work queue if there are IO */
			/* requests on the active queue for the same file descriptor. */
			if ( aio_delay_fsync_request( entryp ) ) {

				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_fsync_delay)) | DBG_FUNC_NONE,
							  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
				continue;
			}
		}
		break;
	}
	
	if ( entryp != NULL ) {
		TAILQ_REMOVE( &aio_anchor.aio_async_workq, entryp, aio_workq_link );
		aio_anchor.aio_async_workq_count--;
		TAILQ_INSERT_TAIL( &entryp->procp->aio_activeq, entryp, aio_workq_link );
		aio_anchor.aio_active_count++;
		entryp->procp->aio_active_count++;
	}
		
	return( entryp );
	
} /* aio_get_some_work */


/*
 * aio_delay_fsync_request - look to see if this aio_fsync request should be delayed at
 * this time.  Delay will happen when there are any active IOs for the same file 
 * descriptor that were queued at time the aio_sync call was queued.  
 * NOTE - AIO_LOCK must be held by caller
 */
static boolean_t
aio_delay_fsync_request( aio_workq_entry *entryp )
{
	aio_workq_entry 		*my_entryp;

	TAILQ_FOREACH( my_entryp, &entryp->procp->aio_activeq, aio_workq_link ) {
		if ( my_entryp->fsyncp != USER_ADDR_NULL &&
			 entryp->uaiocbp == my_entryp->fsyncp &&
			 entryp->aiocb.aio_fildes == my_entryp->aiocb.aio_fildes ) {
			return( TRUE );
		}
	}
		
	return( FALSE );
	
} /* aio_delay_fsync_request */


/*
 * aio_queue_async_request - queue up an async IO request on our work queue then
 * wake up one of our worker threads to do the actual work.  We get a reference
 * to our caller's user land map in order to keep it around while we are
 * processing the request. 
 */

static int
aio_queue_async_request( struct proc *procp, user_addr_t aiocbp, int kindOfIO )
{
	aio_workq_entry		 	*entryp;
	int						result;

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
	entryp->aio_map = VM_MAP_NULL;

	if ( !IS_64BIT_PROCESS(procp) ) {
		struct aiocb aiocb32;

		result = copyin( aiocbp, &aiocb32, sizeof(aiocb32) );
		if ( result == 0 )
			do_munge_aiocb( &aiocb32, &entryp->aiocb );
	} else 
		result = copyin( aiocbp, &entryp->aiocb, sizeof(entryp->aiocb) );

	if ( result != 0 ) {
		result = EAGAIN;
		goto error_exit;
	}

	/* do some more validation on the aiocb and embedded file descriptor */
	result = aio_validate( entryp );
	if ( result != 0 ) 
		goto error_exit;

	/* get a reference to the user land map in order to keep it around */
	entryp->aio_map = get_task_map( procp->task );
	vm_map_reference( entryp->aio_map );

	AIO_LOCK;

	if ( is_already_queued( entryp->procp, entryp->uaiocbp ) == TRUE ) {
		AIO_UNLOCK;
		result = EAGAIN; 
		goto error_exit;
	}

	/* check our aio limits to throttle bad or rude user land behavior */
	if ( aio_get_all_queues_count( ) >= aio_max_requests || 
		 aio_get_process_count( procp ) >= aio_max_requests_per_process ) {
		AIO_UNLOCK;
		result = EAGAIN; 
		goto error_exit;
	}
	
	/* 
	 * aio_fsync calls sync up all async IO requests queued at the time 
	 * the aio_fsync call was made.  So we mark each currently queued async 
	 * IO with a matching file descriptor as must complete before we do the 
	 * fsync.  We set the fsyncp field of each matching async IO 
	 * request with the aiocb pointer passed in on the aio_fsync call to 
	 * know which IOs must complete before we process the aio_fsync call. 
	 */
	if ( (kindOfIO & AIO_FSYNC) != 0 )
		aio_mark_requests( entryp );
	
	/* queue up on our aio asynchronous work queue */
	TAILQ_INSERT_TAIL( &aio_anchor.aio_async_workq, entryp, aio_workq_link );
	aio_anchor.aio_async_workq_count++;
	
	wakeup_one( (caddr_t) &aio_anchor.aio_async_workq );
	AIO_UNLOCK; 

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued)) | DBG_FUNC_NONE,
		     	  (int)procp, (int)aiocbp, 0, 0, 0 );
	
	return( 0 );
	
error_exit:
	if ( entryp != NULL ) {
		/* this entry has not been queued up so no worries about unlocked */
		/* state and aio_map */
		aio_free_request( entryp, entryp->aio_map );
	}
		
	return( result );
	
} /* aio_queue_async_request */


/*
 * lio_create_async_entry - allocate an aio_workq_entry and fill it in.
 * If all goes well return 0 and pass the aio_workq_entry pointer back to
 * our caller.  We get a reference to our caller's user land map in order to keep 
 * it around while we are processing the request.  
 * lio_listio calls behave differently at completion they do completion notification 
 * when all async IO requests have completed.  We use group_tag to tag IO requests 
 * that behave in the delay notification manner. 
 */

static int
lio_create_async_entry( struct proc *procp, user_addr_t aiocbp, 
						 user_addr_t sigp, long group_tag,
						 aio_workq_entry **entrypp )
{
	aio_workq_entry		 		*entryp;
	int							result;

	entryp = (aio_workq_entry *) zalloc( aio_workq_zonep );
	if ( entryp == NULL ) {
		result = EAGAIN; 
		goto error_exit;
	}
	bzero( entryp, sizeof(*entryp) );

	/* fill in the rest of the aio_workq_entry */
	entryp->procp = procp;
	entryp->uaiocbp = aiocbp;
	entryp->flags |= AIO_LIO;
	entryp->group_tag = group_tag;
	entryp->aio_map = VM_MAP_NULL;

	if ( !IS_64BIT_PROCESS(procp) ) {
		struct aiocb aiocb32;

		result = copyin( aiocbp, &aiocb32, sizeof(aiocb32) );
		if ( result == 0 )
			do_munge_aiocb( &aiocb32, &entryp->aiocb );
	} else
		result = copyin( aiocbp, &entryp->aiocb, sizeof(entryp->aiocb) );

	if ( result != 0 ) {
		result = EAGAIN;
		goto error_exit;
	}

	/* look for lio_listio LIO_NOP requests and ignore them. */
	/* Not really an error, but we need to free our aio_workq_entry.  */
	if ( entryp->aiocb.aio_lio_opcode == LIO_NOP ) {
		result = 0;
		goto error_exit;
	}

	/* use sigevent passed in to lio_listio for each of our calls, but only */
	/* do completion notification after the last request completes. */
	if ( sigp != USER_ADDR_NULL ) {
		if ( !IS_64BIT_PROCESS(procp) ) {
			struct sigevent sigevent32;

			result = copyin( sigp, &sigevent32, sizeof(sigevent32) );
			if ( result == 0 ) {
				/* also need to munge aio_sigevent since it contains pointers */
				/* special case here.  since we do not know if sigev_value is an */
				/* int or a ptr we do NOT cast the ptr to a user_addr_t.   This  */
				/* means if we send this info back to user space we need to remember */
				/* sigev_value was not expanded for the 32-bit case.  */
				/* NOTE - this does NOT affect us since we don't support sigev_value */
				/* yet in the aio context.  */
				//LP64
				entryp->aiocb.aio_sigevent.sigev_notify = sigevent32.sigev_notify;
				entryp->aiocb.aio_sigevent.sigev_signo = sigevent32.sigev_signo;
				entryp->aiocb.aio_sigevent.sigev_value.size_equivalent.sival_int = 
					sigevent32.sigev_value.sival_int;
				entryp->aiocb.aio_sigevent.sigev_notify_function = 
					CAST_USER_ADDR_T(sigevent32.sigev_notify_function);
				entryp->aiocb.aio_sigevent.sigev_notify_attributes = 
					CAST_USER_ADDR_T(sigevent32.sigev_notify_attributes);
			}
		} else
			result = copyin( sigp, &entryp->aiocb.aio_sigevent, sizeof(entryp->aiocb.aio_sigevent) );

		if ( result != 0 ) {
			result = EAGAIN;
			goto error_exit;
		}
	}

	/* do some more validation on the aiocb and embedded file descriptor */
	result = aio_validate( entryp );
	if ( result != 0 ) 
		goto error_exit;

	/* get a reference to the user land map in order to keep it around */
	entryp->aio_map = get_task_map( procp->task );
	vm_map_reference( entryp->aio_map );
	
	*entrypp = entryp;
	return( 0 );
	
error_exit:
	if ( entryp != NULL )
		zfree( aio_workq_zonep, entryp );
		
	return( result );
	
} /* lio_create_async_entry */


/*
 * aio_mark_requests - aio_fsync calls synchronize file data for all queued async IO
 * requests at the moment the aio_fsync call is queued.  We use aio_workq_entry.fsyncp
 * to mark each async IO that must complete before the fsync is done.  We use the uaiocbp
 * field from the aio_fsync call as the aio_workq_entry.fsyncp in marked requests.
 * NOTE - AIO_LOCK must be held by caller
 */

static void
aio_mark_requests( aio_workq_entry *entryp )
{
	aio_workq_entry 		*my_entryp;

	TAILQ_FOREACH( my_entryp, &entryp->procp->aio_activeq, aio_workq_link ) {
		if ( entryp->aiocb.aio_fildes == my_entryp->aiocb.aio_fildes ) {
			my_entryp->fsyncp = entryp->uaiocbp;
		}
	}
	
	TAILQ_FOREACH( my_entryp, &aio_anchor.aio_async_workq, aio_workq_link ) {
		if ( entryp->procp == my_entryp->procp &&
			 entryp->aiocb.aio_fildes == my_entryp->aiocb.aio_fildes ) {
			my_entryp->fsyncp = entryp->uaiocbp;
		}
	}
				
} /* aio_mark_requests */


/*
 * lio_create_sync_entry - allocate an aio_workq_entry and fill it in.
 * If all goes well return 0 and pass the aio_workq_entry pointer back to
 * our caller.  
 * lio_listio calls behave differently at completion they do completion notification 
 * when all async IO requests have completed.  We use group_tag to tag IO requests 
 * that behave in the delay notification manner. 
 */

static int
lio_create_sync_entry( struct proc *procp, user_addr_t aiocbp, 
						long group_tag, aio_workq_entry **entrypp )
{
	aio_workq_entry		 		*entryp;
	int							result;

	entryp = (aio_workq_entry *) zalloc( aio_workq_zonep );
	if ( entryp == NULL ) {
		result = EAGAIN; 
		goto error_exit;
	}
	bzero( entryp, sizeof(*entryp) );

	/* fill in the rest of the aio_workq_entry */
	entryp->procp = procp;
	entryp->uaiocbp = aiocbp;
	entryp->flags |= AIO_LIO;
	entryp->group_tag = group_tag;
	entryp->aio_map = VM_MAP_NULL;

	if ( !IS_64BIT_PROCESS(procp) ) {
		struct aiocb aiocb32;

		result = copyin( aiocbp, &aiocb32, sizeof(aiocb32) );
		if ( result == 0 )
			do_munge_aiocb( &aiocb32, &entryp->aiocb );
	} else 
		result = copyin( aiocbp, &entryp->aiocb, sizeof(entryp->aiocb) );

	if ( result != 0 ) {
		result = EAGAIN;
		goto error_exit;
	}

	/* look for lio_listio LIO_NOP requests and ignore them. */
	/* Not really an error, but we need to free our aio_workq_entry.  */
	if ( entryp->aiocb.aio_lio_opcode == LIO_NOP ) {
		result = 0;
		goto error_exit;
	}

	result = aio_validate( entryp );
	if ( result != 0 ) {
		goto error_exit;
	}

	*entrypp = entryp;
	return( 0 );
	
error_exit:
	if ( entryp != NULL )
		zfree( aio_workq_zonep, entryp );
		
	return( result );
	
} /* lio_create_sync_entry */


/*
 * aio_free_request - remove our reference on the user land map and
 * free the work queue entry resources.
 * We are not holding the lock here thus aio_map is passed in and
 * zeroed while we did have the lock.
 */

static int
aio_free_request( aio_workq_entry *entryp, vm_map_t the_map )
{
	/* remove our reference to the user land map. */
	if ( VM_MAP_NULL != the_map ) {
		vm_map_deallocate( the_map );
	}
		
	zfree( aio_workq_zonep, entryp );

	return( 0 );
	
} /* aio_free_request */


/* aio_validate - validate the aiocb passed in by one of the aio syscalls.
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
	if ( (entryp->flags & (AIO_WRITE | AIO_FSYNC)) != 0 ) {
		flag = FWRITE;
	}

	if ( (entryp->flags & (AIO_READ | AIO_WRITE)) != 0 ) {
		// LP64todo - does max value for aio_nbytes need to grow? 
		if ( entryp->aiocb.aio_nbytes > INT_MAX		||
			 entryp->aiocb.aio_buf == USER_ADDR_NULL ||
			 entryp->aiocb.aio_offset < 0 )
			return( EINVAL );
	}

	/* validate aiocb.aio_sigevent.  at this point we only support sigev_notify
	 * equal to SIGEV_SIGNAL or SIGEV_NONE.  this means sigev_value, 
	 * sigev_notify_function, and sigev_notify_attributes are ignored.
	 */
	if ( entryp->aiocb.aio_sigevent.sigev_notify == SIGEV_SIGNAL ) {
		int		signum;
		/* make sure we have a valid signal number */
		signum = entryp->aiocb.aio_sigevent.sigev_signo;
		if ( signum <= 0 || signum >= NSIG || 
			 signum == SIGKILL || signum == SIGSTOP )
			return (EINVAL);
	}
	else if ( entryp->aiocb.aio_sigevent.sigev_notify != SIGEV_NONE )
		return (EINVAL);
	
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


/*
 * aio_get_process_count - runs through our queues that hold outstanding 
 * async IO reqests and totals up number of requests for the given
 * process. 
 * NOTE - caller must hold aio lock! 
 */

static int
aio_get_process_count( struct proc *procp ) 
{
	aio_workq_entry		 		*entryp;
	int							count;
	
	/* begin with count of completed async IO requests for this process */
	count = procp->aio_done_count;
	
	/* add in count of active async IO requests for this process */
	count += procp->aio_active_count;
	
	/* look for matches on our queue of asynchronous todo work */
	TAILQ_FOREACH( entryp, &aio_anchor.aio_async_workq, aio_workq_link ) {
		if ( procp == entryp->procp ) {
			count++;
		}
	}
	
	/* look for matches on our queue of synchronous todo work */
	TAILQ_FOREACH( entryp, &aio_anchor.lio_sync_workq, aio_workq_link ) {
		if ( procp == entryp->procp ) {
			count++;
		}
	}
	
	return( count );
	
} /* aio_get_process_count */


/*
 * aio_get_all_queues_count - get total number of entries on all aio work queues.  
 * NOTE - caller must hold aio lock! 
 */

static int
aio_get_all_queues_count( void ) 
{
	int							count;
	
	count = aio_anchor.aio_async_workq_count;
	count += aio_anchor.lio_sync_workq_count;
	count += aio_anchor.aio_active_count;
	count += aio_anchor.aio_done_count;
		
	return( count );
	
} /* aio_get_all_queues_count */


/*
 * do_aio_completion.  Handle async IO completion.  
 */

static void
do_aio_completion( aio_workq_entry *entryp ) 
{
	/* signal user land process if appropriate */
	if ( entryp->aiocb.aio_sigevent.sigev_notify == SIGEV_SIGNAL &&
		 (entryp->flags & AIO_DISABLE) == 0 ) {

		/* 
		 * if group_tag is non zero then make sure this is the last IO request
		 * in the group before we signal.
		 */
		if ( entryp->group_tag == 0 || 
			 (entryp->group_tag != 0 && aio_last_group_io( entryp )) ) {
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_sig)) | DBG_FUNC_NONE,
						  (int)entryp->procp, (int)entryp->uaiocbp, 
						  entryp->aiocb.aio_sigevent.sigev_signo, 0, 0 );
			
			psignal( entryp->procp, entryp->aiocb.aio_sigevent.sigev_signo );
			return;
		}
	}

	/*
	 * need to handle case where a process is trying to exit, exec, or close
	 * and is currently waiting for active aio requests to complete.  If  
	 * AIO_WAITING is set then we need to look to see if there are any 
	 * other requests in the active queue for this process.  If there are 
	 * none then wakeup using the AIO_CLEANUP_SLEEP_CHAN tsleep channel.  If 
	 * there are some still active then do nothing - we only want to wakeup 
	 * when all active aio requests for the process are complete. 
	 */
	if ( (entryp->flags & AIO_WAITING) != 0 ) {
		int		active_requests;

		KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wait)) | DBG_FUNC_NONE,
					  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		
		AIO_LOCK;
		active_requests = aio_active_requests_for_process( entryp->procp );
		//AIO_UNLOCK;
		if ( active_requests < 1 ) {
			/* no active aio requests for this process, continue exiting */
			wakeup_one( (caddr_t) &entryp->procp->AIO_CLEANUP_SLEEP_CHAN );

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wake)) | DBG_FUNC_NONE,
					  	  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		}
		AIO_UNLOCK;
		return;
	}

	/* 
	 * aio_suspend case when a signal was not requested.  In that scenario we  
	 * are sleeping on the AIO_SUSPEND_SLEEP_CHAN channel.   
	 * NOTE - the assumption here is that this wakeup call is inexpensive.
	 * we really only need to do this when an aio_suspend call is pending.
	 * If we find the wakeup call should be avoided we could mark the 
	 * async IO requests given in the list provided by aio_suspend and only
	 * call wakeup for them.  If we do mark them we should unmark them after
	 * the aio_suspend wakes up.
	 */
	AIO_LOCK; 
	wakeup_one( (caddr_t) &entryp->procp->AIO_SUSPEND_SLEEP_CHAN ); 
	AIO_UNLOCK;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_suspend_wake)) | DBG_FUNC_NONE,
				  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
	
	return;
	
} /* do_aio_completion */


/*
 * aio_last_group_io - checks to see if this is the last unfinished IO request
 * for the given group_tag.  Returns TRUE if there are no other active IO 
 * requests for this group or FALSE if the are active IO requests 
 * NOTE - AIO_LOCK must be held by caller
 */

static boolean_t
aio_last_group_io( aio_workq_entry *entryp ) 
{
	aio_workq_entry		 		*my_entryp;
			
	/* look for matches on our queue of active async IO requests */
	TAILQ_FOREACH( my_entryp, &entryp->procp->aio_activeq, aio_workq_link ) {
		if ( my_entryp->group_tag == entryp->group_tag )
			return( FALSE );
	}
	
	/* look for matches on our queue of asynchronous todo work */
	TAILQ_FOREACH( my_entryp, &aio_anchor.aio_async_workq, aio_workq_link ) {
		if ( my_entryp->group_tag == entryp->group_tag )
			return( FALSE );
	}
	
	/* look for matches on our queue of synchronous todo work */
	TAILQ_FOREACH( my_entryp, &aio_anchor.lio_sync_workq, aio_workq_link ) {
		if ( my_entryp->group_tag == entryp->group_tag )
			return( FALSE );
	}

	return( TRUE );
	
} /* aio_last_group_io */


/*
 * do_aio_read
 */
static int
do_aio_read( aio_workq_entry *entryp )
{
	struct fileproc 			*fp;
	int						error;

	if ( (error = fp_lookup(entryp->procp, entryp->aiocb.aio_fildes, &fp , 0)) )
		return(error);
	if ( (fp->f_fglob->fg_flag & FREAD) == 0 ) {
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
		return(EBADF);
	}
	if ( fp != NULL ) {
		error = dofileread( entryp->procp, fp, entryp->aiocb.aio_fildes, 
							entryp->aiocb.aio_buf, 
							entryp->aiocb.aio_nbytes,
							entryp->aiocb.aio_offset, FOF_OFFSET, 
							&entryp->returnval );
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
	}
	else {
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
		error = EBADF;
	}
			
	return( error );
	
} /* do_aio_read */


/*
 * do_aio_write
 */
static int
do_aio_write( aio_workq_entry *entryp )
{
	struct fileproc 		*fp;
	int						error;

	if ( (error = fp_lookup(entryp->procp, entryp->aiocb.aio_fildes, &fp , 0)) )
		return(error);
	if ( (fp->f_fglob->fg_flag & FWRITE) == 0 ) {
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
		return(EBADF);
	}
	if ( fp != NULL ) {
		/* NB: tell dofilewrite the offset, and to use the proc cred */
		error = dofilewrite( entryp->procp,
				     fp,
				     entryp->aiocb.aio_fildes,
				     entryp->aiocb.aio_buf,
				     entryp->aiocb.aio_nbytes,
				     entryp->aiocb.aio_offset,
				     FOF_OFFSET | FOF_PCRED,
				     &entryp->returnval);
		
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
	}
	else {
		fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
		error = EBADF;
	}

	return( error );

} /* do_aio_write */


/*
 * aio_active_requests_for_process - return number of active async IO
 * requests for the given process.
 * NOTE - caller must hold aio lock!
 */

static int
aio_active_requests_for_process( struct proc *procp )
{
				
	return( procp->aio_active_count );

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
	int					error;
	
	/* 
	 * NOTE - we will not support AIO_DSYNC until fdatasync() is supported.  
	 * AIO_DSYNC is caught before we queue up a request and flagged as an error.  
	 * The following was shamelessly extracted from fsync() implementation. 
	 */

	error = fp_getfvp( entryp->procp, entryp->aiocb.aio_fildes, &fp, &vp);
	if ( error == 0 ) {
		if ( (error = vnode_getwithref(vp)) ) {
		        fp_drop(entryp->procp, entryp->aiocb.aio_fildes, fp, 0);
			entryp->returnval = -1;
			return(error);
		}
		context.vc_proc = entryp->procp;
		context.vc_ucred = fp->f_fglob->fg_cred;

		error = VNOP_FSYNC( vp, MNT_WAIT, &context);

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
 * NOTE - callers must hold aio lock!
 */

static boolean_t
is_already_queued( 	struct proc *procp, 
					user_addr_t aiocbp ) 
{
	aio_workq_entry		 	*entryp;
	boolean_t				result;
		
	result = FALSE;
		
	/* look for matches on our queue of async IO requests that have completed */
	TAILQ_FOREACH( entryp, &procp->aio_doneq, aio_workq_link ) {
		if ( aiocbp == entryp->uaiocbp ) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}
	
	/* look for matches on our queue of active async IO requests */
	TAILQ_FOREACH( entryp, &procp->aio_activeq, aio_workq_link ) {
		if ( aiocbp == entryp->uaiocbp ) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}
	
	/* look for matches on our queue of asynchronous todo work */
	TAILQ_FOREACH( entryp, &aio_anchor.aio_async_workq, aio_workq_link ) {
		if ( procp == entryp->procp && aiocbp == entryp->uaiocbp ) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}
	
	/* look for matches on our queue of synchronous todo work */
	TAILQ_FOREACH( entryp, &aio_anchor.lio_sync_workq, aio_workq_link ) {
		if ( procp == entryp->procp && aiocbp == entryp->uaiocbp ) {
			result = TRUE;
			goto ExitThisRoutine;
		}
	}

ExitThisRoutine:
	return( result );
	
} /* is_already_queued */


/*
 * aio initialization
 */
__private_extern__ void
aio_init( void )
{
	int			i;
	
	aio_lock_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(aio_lock_grp_attr);
	aio_lock_grp = lck_grp_alloc_init("aio", aio_lock_grp_attr);
	aio_lock_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(aio_lock_attr);

	aio_lock = lck_mtx_alloc_init(aio_lock_grp, aio_lock_attr);

	AIO_LOCK;
	TAILQ_INIT( &aio_anchor.aio_async_workq );	
	TAILQ_INIT( &aio_anchor.lio_sync_workq );	
	aio_anchor.aio_async_workq_count = 0;
	aio_anchor.lio_sync_workq_count = 0;
	aio_anchor.aio_active_count = 0;
	aio_anchor.aio_done_count = 0;
	AIO_UNLOCK;

	i = sizeof( aio_workq_entry );
	aio_workq_zonep = zinit( i, i * aio_max_requests, i * aio_max_requests, "aiowq" );
		
	_aio_create_worker_threads( aio_worker_threads );

	return;
	
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
		
		myThread = kernel_thread( kernel_task, aio_work_thread );
		if ( THREAD_NULL == myThread ) {
			printf( "%s - failed to create a work thread \n", __FUNCTION__ ); 
		}
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
do_munge_aiocb( struct aiocb *my_aiocbp, struct user_aiocb *the_user_aiocbp ) 
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
