/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/buf.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/user.h>

#include <sys/aio_kern.h>

#include <machine/limits.h>
#include <kern/zalloc.h>
#include <kern/task.h>

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
#define AIO_LOCK	usimple_lock( &aio_lock )
#define AIO_UNLOCK	usimple_unlock( &aio_lock )


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
									 		 struct aiocb *aiocbp,
									   		 int kindOfIO );
static int			aio_validate( aio_workq_entry *entryp );
static void			aio_work_thread( void );
static int			do_aio_cancel(	struct proc *p, 
									int fd, 
									struct aiocb *aiocbp, 
									boolean_t wait_for_completion,
									boolean_t disable_notification );
static void			do_aio_completion( aio_workq_entry *entryp );
static int			do_aio_fsync( aio_workq_entry *entryp );
static int			do_aio_read( aio_workq_entry *entryp );
static int			do_aio_write( aio_workq_entry *entryp );
static boolean_t	is_already_queued( 	struct proc *procp, 
										struct aiocb *aiocbp );
static int			lio_create_async_entry( struct proc *procp, 
											 struct aiocb *aiocbp, 
						 					 struct sigevent *sigp, 
						 					 long group_tag,
						 					 aio_workq_entry **entrypp );
static int			lio_create_sync_entry( struct proc *procp, 
											struct aiocb *aiocbp, 
											long group_tag,
											aio_workq_entry **entrypp );

/*
 *  EXTERNAL PROTOTYPES
 */

/* in ...bsd/kern/sys_generic.c */
extern struct file*	holdfp( struct filedesc* fdp, int fd, int flag );
extern int			dofileread( struct proc *p, struct file *fp, int fd, 
								void *buf, size_t nbyte, off_t offset, 
								int flags, int *retval );
extern int			dofilewrite( struct proc *p, struct file *fp, int fd, 
								 const void *buf, size_t nbyte, off_t offset, 
								 int flags, int *retval );
extern vm_map_t 	vm_map_switch( vm_map_t    map );


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
static simple_lock_data_t 	aio_lock;
static struct zone  		*aio_workq_zonep;


/*
 * syscall input parameters
 */
#ifndef _SYS_SYSPROTO_H_

struct	aio_cancel_args {
	int				fd;	
	struct aiocb 	*aiocbp;	
};

struct	aio_error_args {
	struct aiocb 			*aiocbp;	
};

struct	aio_fsync_args {
	int						op;	
	struct aiocb 			*aiocbp;	
};

struct	aio_read_args {
	struct aiocb 			*aiocbp;	
};

struct	aio_return_args {
	struct aiocb 	*aiocbp;	
};

struct	aio_suspend_args {
	struct aiocb *const 	*aiocblist;	
	int						nent;	
	const struct timespec 	*timeoutp;	
};

struct	aio_write_args {
	struct aiocb 			*aiocbp;	
};

struct	lio_listio_args {
	int						mode;	
	struct aiocb *const 	*aiocblist;	
	int						nent;	
	struct sigevent 		*sigp;	
};

#endif /* _SYS_SYSPROTO_H_ */


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
	struct aiocb				my_aiocb;
	int							result;
	boolean_t					funnel_state;

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
	if ( uap->aiocbp != NULL ) {
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

	/* current BSD code assumes funnel lock is held */
	funnel_state = thread_funnel_set( kernel_flock, TRUE );
	result = do_aio_cancel( p, uap->fd, uap->aiocbp, FALSE, FALSE );
	(void) thread_funnel_set( kernel_flock, funnel_state );

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
 * NOTE - kernel funnel lock is held when we get called. 
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
	error = do_aio_cancel( p, fd, NULL, TRUE, FALSE );
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
	if ( uap->op == O_SYNC )
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
aio_return( struct proc *p, struct aio_return_args *uap, register_t *retval )
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
 * NOTE - kernel funnel lock is held when we get called. 
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
 * NOTE - kernel funnel lock is held when we get called. 
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
	error = do_aio_cancel( p, 0, NULL, TRUE, TRUE );
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

ExitRoutine:
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
 * NOTE - kernel funnel lock is held when we get called. 
 */

static int
do_aio_cancel( 	struct proc *p, int fd, struct aiocb *aiocbp, 
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
			if ( (aiocbp == NULL && fd == 0) ||
				 (aiocbp != NULL && entryp->uaiocbp == aiocbp) ||
				 (aiocbp == NULL && fd == entryp->aiocb.aio_fildes) ) {
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

				if ( aiocbp != NULL ) {
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
			if ( (aiocbp == NULL && fd == 0) ||
				 (aiocbp != NULL && entryp->uaiocbp == aiocbp) ||
				 (aiocbp == NULL && fd == entryp->aiocb.aio_fildes) ) {
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
				if ( aiocbp != NULL ) {
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
		if ( (aiocbp == NULL && fd == 0) ||
			 (aiocbp != NULL && entryp->uaiocbp == aiocbp) ||
			 (aiocbp == NULL && fd == entryp->aiocb.aio_fildes) ) {
			result = AIO_NOTCANCELED;

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_activeq)) | DBG_FUNC_NONE,
						  (int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

			if ( wait_for_completion )
				entryp->flags |= AIO_WAITING; /* flag for special completion processing */
			if ( disable_notification )
				entryp->flags |= AIO_DISABLE; /* flag for special completion processing */
			if ( aiocbp != NULL ) {
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
		if ( (aiocbp == NULL && fd == 0) ||
			 (aiocbp != NULL && entryp->uaiocbp == aiocbp) ||
			 (aiocbp == NULL && fd == entryp->aiocb.aio_fildes) ) {
				result = AIO_ALLDONE;

				KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_cancel_doneq)) | DBG_FUNC_NONE,
							  (int)entryp->procp, (int)entryp->uaiocbp, fd, 0, 0 );

				if ( aiocbp != NULL ) {
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
	struct timespec		ts;
	struct timeval 		tv;
	aio_workq_entry 	*entryp;
	struct aiocb *		*aiocbpp;
	
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

	if ( uap->nent < 1 || uap->nent > AIO_LISTIO_MAX ) {
		error = EINVAL;
		goto ExitThisRoutine;
	}

	if ( uap->timeoutp != NULL ) {
		error = copyin( (void *)uap->timeoutp, &ts, sizeof(ts) );
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

	MALLOC( aiocbpp, void *, (uap->nent * sizeof(struct aiocb *)), M_TEMP, M_WAITOK );
	if ( aiocbpp == NULL ) {
		error = EAGAIN;
		goto ExitThisRoutine;
	}

	/* check list of aio requests to see if any have completed */
	for ( i = 0; i < uap->nent; i++ ) {
		struct aiocb	*aiocbp;
	
		/* copyin in aiocb pointer from list */
		error = copyin( (void *)(uap->aiocblist + i), (aiocbpp + i), sizeof(aiocbp) );
		if ( error != 0 ) {
			error = EAGAIN;
			goto ExitThisRoutine;
		}
	
		/* NULL elements are legal so check for 'em */
		aiocbp = *(aiocbpp + i);
		if ( aiocbp == NULL )
			continue;

		/* return immediately if any aio request in the list is done */
		AIO_LOCK;
		TAILQ_FOREACH( entryp, &p->aio_doneq, aio_workq_link ) {
			if ( entryp->uaiocbp == aiocbp ) {
				*retval = 0;
				error = 0;
				AIO_UNLOCK;
				goto ExitThisRoutine;
			}
		}
		AIO_UNLOCK;
	} /* for ( ; i < uap->nent; ) */

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_suspend_sleep)) | DBG_FUNC_NONE,
		     	  (int)p, uap->nent, 0, 0, 0 );
	
	/* 
	 * wait for an async IO to complete or a signal fires or timeout expires. 
	 * we return EAGAIN (35) for timeout expiration and EINTR (4) when a signal 
	 * interrupts us.  If an async IO completes before a signal fires or our 
	 * timeout expires, we get a wakeup call from aio_work_thread().  We do not
	 * use tsleep() here in order to avoid getting kernel funnel lock.
	 */
	assert_wait( (event_t) &p->AIO_SUSPEND_SLEEP_CHAN, THREAD_ABORTSAFE );
	if ( abstime > 0 ) {
		thread_set_timer_deadline( abstime );
	}
	error = thread_block( THREAD_CONTINUE_NULL );
	if ( error == THREAD_AWAKENED ) {
		/* got our wakeup call from aio_work_thread() */
		if ( abstime > 0 ) {
			thread_cancel_timer();
		}
		*retval = 0;
		error = 0;
	}
	else if ( error == THREAD_TIMED_OUT ) {
		/* our timeout expired */
		error = EAGAIN;
	}
	else {
		/* we were interrupted */
		if ( abstime > 0 ) {
			thread_cancel_timer();
		}
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

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_listio)) | DBG_FUNC_START,
		     	  (int)p, uap->nent, uap->mode, 0, 0 );
	
	entryp_listp = NULL;
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
	MALLOC( entryp_listp, void *, (uap->nent * sizeof(struct aiocb *)), M_TEMP, M_WAITOK );
	if ( entryp_listp == NULL ) {
		call_result = EAGAIN;
		goto ExitRoutine;
	}

	/* process list of aio requests */
	for ( i = 0; i < uap->nent; i++ ) {
		struct aiocb	*my_aiocbp;
	
		*(entryp_listp + i) = NULL;
		
		/* copyin in aiocb pointer from list */
		result = copyin( (void *)(uap->aiocblist + i), &my_aiocbp, sizeof(my_aiocbp) );
		if ( result != 0 ) {
			call_result = EAGAIN;
			continue;
		}
	
		/* NULL elements are legal so check for 'em */
		if ( my_aiocbp == NULL )
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
			result = EAGAIN; 
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
	AIO_UNLOCK;

	if ( uap->mode == LIO_NOWAIT ) 
		/* caller does not want to wait so we'll fire off a worker thread and return */
		wakeup_one( &aio_anchor.aio_async_workq );
	else {
		aio_workq_entry		 	*entryp;
		int 					error;

		/* 
		 * mode is LIO_WAIT - handle the IO requests now.
		 */
		AIO_LOCK;
 		entryp = TAILQ_FIRST( &aio_anchor.lio_sync_workq );
 		while ( entryp != NULL ) {
			if ( p == entryp->procp && group_tag == entryp->group_tag ) {
				boolean_t	funnel_state;
					
				TAILQ_REMOVE( &aio_anchor.lio_sync_workq, entryp, aio_workq_link );
				aio_anchor.lio_sync_workq_count--;
				AIO_UNLOCK;
				
				// file system IO code path requires kernel funnel lock
				funnel_state = thread_funnel_set( kernel_flock, TRUE );
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
				(void) thread_funnel_set( kernel_flock, funnel_state );

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
		AIO_UNLOCK;
	} /* uap->mode == LIO_WAIT */

	/* call_result == -1 means we had no trouble queueing up requests */
	if ( call_result == -1 ) {
		call_result = 0;
		*retval = 0;
	}

ExitRoutine:		
	if ( entryp_listp != NULL )
		FREE( entryp_listp, M_TEMP );

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
	struct uthread			*uthread = (struct uthread *)get_bsdthread_info(current_act());
	
	for( ;; ) {
		entryp = aio_get_some_work();
        if ( entryp == NULL ) {
        	/* 
        	 * aio worker threads wait for some work to get queued up 
        	 * by aio_queue_async_request.  Once some work gets queued 
        	 * it will wake up one of these worker threads just before 
        	 * returning to our caller in user land.   We do not use
			 * tsleep() here in order to avoid getting kernel funnel lock.
        	 */
			assert_wait( (event_t) &aio_anchor.aio_async_workq, THREAD_UNINT );
			thread_block( THREAD_CONTINUE_NULL );
			
			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_wake)) | DBG_FUNC_NONE,
						  0, 0, 0, 0, 0 );
        }
		else {
			int 			error;
			boolean_t 		funnel_state;
			vm_map_t 		currentmap;
			vm_map_t 		oldmap = VM_MAP_NULL;
			task_t			oldaiotask = TASK_NULL;

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_worker_thread)) | DBG_FUNC_START,
						  (int)entryp->procp, (int)entryp->uaiocbp, entryp->flags, 0, 0 );
			
			/*
			 * Assume the target's address space identity for the duration
			 * of the IO.
			 */
			funnel_state = thread_funnel_set( kernel_flock, TRUE );
			
			currentmap = get_task_map( (current_proc())->task );
			if ( currentmap != entryp->aio_map ) {
				oldaiotask = uthread->uu_aio_task;
				uthread->uu_aio_task = entryp->procp->task;
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
				uthread->uu_aio_task = oldaiotask;
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
			(void) thread_funnel_set( kernel_flock, funnel_state );
			
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
 */

static aio_workq_entry *
aio_get_some_work( void )
{
	aio_workq_entry		 		*entryp;
	int							skip_count = 0;
	
	/* pop some work off the work queue and add to our active queue */
	AIO_LOCK;
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
	AIO_UNLOCK;
		
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
		if ( my_entryp->fsyncp != NULL &&
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
aio_queue_async_request( struct proc *procp, struct aiocb *aiocbp, int kindOfIO )
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
	
	AIO_UNLOCK;

	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_work_queued)) | DBG_FUNC_NONE,
		     	  (int)procp, (int)aiocbp, 0, 0, 0 );

	wakeup_one( &aio_anchor.aio_async_workq );

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
lio_create_async_entry( struct proc *procp, struct aiocb *aiocbp, 
						 struct sigevent *sigp, long group_tag,
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
	if ( sigp != NULL ) {
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
		zfree( aio_workq_zonep, (vm_offset_t) entryp );
		
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
lio_create_sync_entry( struct proc *procp, struct aiocb *aiocbp, 
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
		zfree( aio_workq_zonep, (vm_offset_t) entryp );
		
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
		
	zfree( aio_workq_zonep, (vm_offset_t) entryp );

	return( 0 );
	
} /* aio_free_request */


/* aio_validate - validate the aiocb passed in by one of the aio syscalls.
 */

static int
aio_validate( aio_workq_entry *entryp ) 
{
	boolean_t 					funnel_state;
	struct file 				*fp;
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
		if ( entryp->aiocb.aio_offset < 0 			||
			 entryp->aiocb.aio_nbytes < 0 			||
			 entryp->aiocb.aio_nbytes > INT_MAX  	||
			 entryp->aiocb.aio_buf == NULL )
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
	 * for the appropriate read / write access.  This section requires 
	 * kernel funnel lock.
	 */
	funnel_state = thread_funnel_set( kernel_flock, TRUE );

	result = fdgetf( entryp->procp, entryp->aiocb.aio_fildes, &fp );
	if ( result == 0 ) {
		if ( (fp->f_flag & flag) == 0 ) {
			/* we don't have read or write access */
			result = EBADF;
		}
		else if ( fp->f_type != DTYPE_VNODE ) {
			/* this is not a file */
			result = ESPIPE;
		}
	}
	else {
		result = EBADF;
	}
	
	(void) thread_funnel_set( kernel_flock, funnel_state );

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
	int							error;
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
		AIO_UNLOCK;
		if ( active_requests < 1 ) {
			/* no active aio requests for this process, continue exiting */

			KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_cleanup_wake)) | DBG_FUNC_NONE,
					  	  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		
			wakeup_one( &entryp->procp->AIO_CLEANUP_SLEEP_CHAN );
		}
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
	KERNEL_DEBUG( (BSDDBG_CODE(DBG_BSD_AIO, AIO_completion_suspend_wake)) | DBG_FUNC_NONE,
				  (int)entryp->procp, (int)entryp->uaiocbp, 0, 0, 0 );
		
	wakeup_one( &entryp->procp->AIO_SUSPEND_SLEEP_CHAN ); 
	
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
	struct file 			*fp;
	int						error;

	fp = holdfp( entryp->procp->p_fd, entryp->aiocb.aio_fildes, FREAD );
	if ( fp != NULL ) {
		error = dofileread( entryp->procp, fp, entryp->aiocb.aio_fildes, 
							(void *)entryp->aiocb.aio_buf, 
							entryp->aiocb.aio_nbytes,
							entryp->aiocb.aio_offset, FOF_OFFSET, 
							&entryp->returnval );
		frele( fp );
	}
	else
		error = EBADF;
			
	return( error );
	
} /* do_aio_read */


/*
 * do_aio_write
 */
static int
do_aio_write( aio_workq_entry *entryp )
{
	struct file 			*fp;
	int						error;

	fp = holdfp( entryp->procp->p_fd, entryp->aiocb.aio_fildes, FWRITE );
	if ( fp != NULL ) {
		error = dofilewrite( entryp->procp, fp, entryp->aiocb.aio_fildes, 
							 (const void *)entryp->aiocb.aio_buf, 
							 entryp->aiocb.aio_nbytes,
							 entryp->aiocb.aio_offset, FOF_OFFSET, 
							 &entryp->returnval );
		frele( fp );
	}
	else
		error = EBADF;

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
	register struct vnode 	*vp;
	struct file 			*fp;
	int						error;
	
	/* 
	 * NOTE - we will not support AIO_DSYNC until fdatasync() is supported.  
	 * AIO_DSYNC is caught before we queue up a request and flagged as an error.  
	 * The following was shamelessly extracted from fsync() implementation. 
	 */
	error = getvnode( entryp->procp, entryp->aiocb.aio_fildes, &fp );
	if ( error == 0 ) {
		vp = (struct vnode *)fp->f_data;
		vn_lock( vp, LK_EXCLUSIVE | LK_RETRY, entryp->procp );
		error = VOP_FSYNC( vp, fp->f_cred, MNT_WAIT, entryp->procp );
		VOP_UNLOCK( vp, 0, entryp->procp );
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
					struct aiocb *aiocbp ) 
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
	
	simple_lock_init( &aio_lock );

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
	return  ((struct uthread *)get_bsdthread_info(current_act()))->uu_aio_task;  
}
