/*
 * Copyright (c) 2015 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Scooter Morris at Genentech Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ufs_lockf.c	8.3 (Berkeley) 1/6/94
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/vnode_if.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/sdt.h>
#include <kern/policy_internal.h>

#include <sys/file_internal.h>

/*
 * This variable controls the maximum number of processes that will
 * be checked in doing deadlock detection.
 */
static int maxlockdepth = MAXDEPTH;

#if (DEVELOPMENT || DEBUG)
#define LOCKF_DEBUGGING	1
#endif

#ifdef LOCKF_DEBUGGING
#include <sys/sysctl.h>
void lf_print(const char *tag, struct lockf *lock);
void lf_printlist(const char *tag, struct lockf *lock);

#define	LF_DBG_LOCKOP	(1 << 0)	/* setlk, getlk, clearlk */
#define	LF_DBG_LIST	(1 << 1)	/* split, coalesce */
#define	LF_DBG_IMPINH	(1 << 2)	/* importance inheritance */
#define	LF_DBG_TRACE	(1 << 3)	/* errors, exit */

static int	lockf_debug = 0;	/* was 2, could be 3 ;-) */
SYSCTL_INT(_debug, OID_AUTO, lockf_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &lockf_debug, 0, "");

/*
 * If there is no mask bit selector, or there is one, and the selector is
 * set, then output the debugging diagnostic.
 */
#define LOCKF_DEBUG(mask, ...)					\
	do {							\
		if( !(mask) || ((mask) & lockf_debug)) {	\
			printf(__VA_ARGS__);			\
		}						\
	} while(0)
#else	/* !LOCKF_DEBUGGING */
#define LOCKF_DEBUG(mask, ...)		/* mask */
#endif	/* !LOCKF_DEBUGGING */

MALLOC_DEFINE(M_LOCKF, "lockf", "Byte-range locking structures");

#define NOLOCKF (struct lockf *)0
#define SELF	0x1
#define OTHERS	0x2
#define OFF_MAX	0x7fffffffffffffffULL	/* max off_t */

/*
 * Overlapping lock states
 */
typedef enum {
	OVERLAP_NONE = 0,
	OVERLAP_EQUALS_LOCK,
	OVERLAP_CONTAINS_LOCK,
	OVERLAP_CONTAINED_BY_LOCK,
	OVERLAP_STARTS_BEFORE_LOCK,
	OVERLAP_ENDS_AFTER_LOCK
} overlap_t;

static int	 lf_clearlock(struct lockf *);
static overlap_t lf_findoverlap(struct lockf *,
	    struct lockf *, int, struct lockf ***, struct lockf **);
static struct lockf *lf_getblock(struct lockf *, pid_t);
static int	 lf_getlock(struct lockf *, struct flock *, pid_t);
static int	 lf_setlock(struct lockf *, struct timespec *);
static int	 lf_split(struct lockf *, struct lockf *);
static void	 lf_wakelock(struct lockf *, boolean_t);
#if IMPORTANCE_INHERITANCE
static void	 lf_hold_assertion(task_t, struct lockf *);
static void	 lf_jump_to_queue_head(struct lockf *, struct lockf *);
static void	 lf_drop_assertion(struct lockf *);
static void	 lf_boost_blocking_proc(struct lockf *, struct lockf *);
static void	 lf_adjust_assertion(struct lockf *block);
#endif /* IMPORTANCE_INHERITANCE */

/*
 * lf_advlock
 *
 * Description:	Advisory record locking support
 *
 * Parameters:	ap			Argument pointer to a vnop_advlock_args
 *					argument descriptor structure for the
 *					lock operation to be attempted.
 *
 * Returns:	0			Success
 *		EOVERFLOW
 *		EINVAL
 *		ENOLCK			Number of locked regions exceeds limit
 *	lf_setlock:EAGAIN
 *	lf_setlock:EDEADLK
 *	lf_setlock:EINTR
 *	lf_setlock:ENOLCK
 *	lf_setlock:ETIMEDOUT
 *	lf_clearlock:ENOLCK
 *	vnode_size:???
 *
 * Notes:	We return ENOLCK when we run out of memory to support locks; as
 *		such, there is no specific expectation limit other than the
 *		amount of available resources.
 */
int
lf_advlock(struct vnop_advlock_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct flock *fl = ap->a_fl;
	vfs_context_t context = ap->a_context;
	struct lockf *lock;
	off_t start, end, oadd;
	u_quad_t size;
	int error;
	struct lockf **head = &vp->v_lockf;

	/* XXX HFS may need a !vnode_isreg(vp) EISDIR error here */

	/*
	 * Avoid the common case of unlocking when inode has no locks.
	 */
	if (*head == (struct lockf *)0) {
		if (ap->a_op != F_SETLK) {
			fl->l_type = F_UNLCK;
			LOCKF_DEBUG(LF_DBG_TRACE,
			    "lf_advlock: '%s' unlock without lock\n",
			    vfs_context_proc(context)->p_comm);
			return (0);
		}
	}

	/*
	 * Convert the flock structure into a start and end.
	 */
	switch (fl->l_whence) {

	case SEEK_SET:
	case SEEK_CUR:
		/*
		 * Caller is responsible for adding any necessary offset
		 * when SEEK_CUR is used.
		 */
		start = fl->l_start;
		break;

	case SEEK_END:

		/*
		 * It's OK to cast the u_quad_t to and off_t here, since they
		 * are the same storage size, and the value of the returned
		 * contents will never overflow into the sign bit.  We need to
		 * do this because we will use size to force range checks.
		 */
		if ((error = vnode_size(vp, (off_t *)&size, context))) {
			LOCKF_DEBUG(LF_DBG_TRACE,
			    "lf_advlock: vnode_getattr failed: %d\n", error);
			return (error);
		}

		if (size > OFF_MAX ||
		    (fl->l_start > 0 &&
		     size > (u_quad_t)(OFF_MAX - fl->l_start)))
			return (EOVERFLOW);
		start = size + fl->l_start;
		break;

	default:
		LOCKF_DEBUG(LF_DBG_TRACE, "lf_advlock: unknown whence %d\n",
		    fl->l_whence);
		return (EINVAL);
	}
	if (start < 0) {
		LOCKF_DEBUG(LF_DBG_TRACE, "lf_advlock: start < 0 (%qd)\n",
		    start);
		return (EINVAL);
	}
	if (fl->l_len < 0) {
		if (start == 0) {
			LOCKF_DEBUG(LF_DBG_TRACE,
			    "lf_advlock: len < 0 & start == 0\n");
			return (EINVAL);
		}
		end = start - 1;
		start += fl->l_len;
		if (start < 0) {
			LOCKF_DEBUG(LF_DBG_TRACE,
			    "lf_advlock: start < 0 (%qd)\n", start);
			return (EINVAL);
		}
	} else if (fl->l_len == 0)
		end = -1;
	else {
		oadd = fl->l_len - 1;
		if (oadd > (off_t)(OFF_MAX - start)) {
		        LOCKF_DEBUG(LF_DBG_TRACE, "lf_advlock: overflow\n");
			return (EOVERFLOW);
		}
		end = start + oadd;
	}
	/*
	 * Create the lockf structure
	 */
	MALLOC(lock, struct lockf *, sizeof *lock, M_LOCKF, M_WAITOK);
	if (lock == NULL)
		return (ENOLCK);
	lock->lf_start = start;
	lock->lf_end = end;
	lock->lf_id = ap->a_id;
	lock->lf_vnode = vp;
	lock->lf_type = fl->l_type;
	lock->lf_head = head;
	lock->lf_next = (struct lockf *)0;
	TAILQ_INIT(&lock->lf_blkhd);
	lock->lf_flags = ap->a_flags;
#if IMPORTANCE_INHERITANCE
	lock->lf_boosted = LF_NOT_BOOSTED;
#endif
	if (ap->a_flags & F_POSIX)
		lock->lf_owner = (struct proc *)lock->lf_id;
	else
		lock->lf_owner = NULL;

	if (ap->a_flags & F_FLOCK)
	        lock->lf_flags |= F_WAKE1_SAFE;

	lck_mtx_lock(&vp->v_lock);	/* protect the lockf list */
	/*
	 * Do the requested operation.
	 */
	switch(ap->a_op) {
	case F_SETLK:
		/*
		 * For F_OFD_* locks, lf_id is the fileglob.
		 * Record an "lf_owner" iff this is a confined fd
		 * i.e. it cannot escape this process and will be
		 * F_UNLCKed before the owner exits.  (This is
		 * the implicit guarantee needed to ensure lf_owner
		 * remains a valid reference here.)
		 */
		if (ap->a_flags & F_OFD_LOCK) {
			struct fileglob *fg = (void *)lock->lf_id;
			if (fg->fg_lflags & FG_CONFINED)
				lock->lf_owner = current_proc();
		}
		error = lf_setlock(lock, ap->a_timeout);
		break;

	case F_UNLCK:
		error = lf_clearlock(lock);
		FREE(lock, M_LOCKF);
		break;

	case F_GETLK:
		error = lf_getlock(lock, fl, -1);
		FREE(lock, M_LOCKF);
		break;


	default:
		FREE(lock, M_LOCKF);
		error = EINVAL;
		break;
	}
	lck_mtx_unlock(&vp->v_lock);	/* done manipulating the list */

	LOCKF_DEBUG(LF_DBG_TRACE, "lf_advlock: normal exit: %d\n", error);
	return (error);
}

/*
 * Empty the queue of msleeping requests for a lock on the given vnode.
 * Called with the vnode already locked.  Used for forced unmount, where
 * a flock(2) invoker sleeping on a blocked lock holds an iocount reference
 * that prevents the vnode from ever being drained.  Force unmounting wins.
 */
void
lf_abort_advlocks(vnode_t vp)
{
	struct lockf *lock;

	if ((lock = vp->v_lockf) == NULL)
		return;	

	lck_mtx_assert(&vp->v_lock, LCK_MTX_ASSERT_OWNED);

	if (!TAILQ_EMPTY(&lock->lf_blkhd)) {
		struct lockf *tlock;

		TAILQ_FOREACH(tlock, &lock->lf_blkhd, lf_block) {
			/*
			 * Setting this flag should cause all
			 * currently blocked F_SETLK request to
			 * return to userland with an errno.
			 */
			tlock->lf_flags |= F_ABORT;
		}
		lf_wakelock(lock, TRUE);
	}
}

/*
 * Take any lock attempts which are currently blocked by a given lock ("from")
 * and mark them as blocked by a different lock ("to").  Used in the case
 * where a byte range currently occupied by "from" is to be occupied by "to."
 */
static void
lf_move_blocked(struct lockf *to, struct lockf *from)
{
	struct lockf *tlock;

	TAILQ_FOREACH(tlock, &from->lf_blkhd, lf_block) {
		tlock->lf_next = to;
	}

	TAILQ_CONCAT(&to->lf_blkhd, &from->lf_blkhd, lf_block);
}

/*
 * lf_coalesce_adjacent
 *
 * Description:	Helper function: when setting a lock, coalesce adjacent
 *		locks.  Needed because adjacent locks are not overlapping,
 *		but POSIX requires that they be coalesced.
 *
 * Parameters:	lock			The new lock which may be adjacent
 *					to already locked regions, and which
 *					should therefore be coalesced with them
 *
 * Returns:	<void>
 */
static void
lf_coalesce_adjacent(struct lockf *lock)
{
	struct lockf **lf = lock->lf_head;

	while (*lf != NOLOCKF) {
		/* reject locks that obviously could not be coalesced */
		if ((*lf == lock) ||
		    ((*lf)->lf_id != lock->lf_id) ||
		    ((*lf)->lf_type != lock->lf_type)) {
			lf = &(*lf)->lf_next;
			continue;
		}

		/*
		 * NOTE: Assumes that if two locks are adjacent on the number line 
		 * and belong to the same owner, then they are adjacent on the list.
		 */
		if ((*lf)->lf_end != -1 &&
		    ((*lf)->lf_end + 1) == lock->lf_start) {
			struct lockf *adjacent = *lf;

			LOCKF_DEBUG(LF_DBG_LIST, "lf_coalesce_adjacent: coalesce adjacent previous\n");
			lock->lf_start = (*lf)->lf_start;
			*lf = lock;
			lf = &(*lf)->lf_next;

			lf_move_blocked(lock, adjacent);

			FREE(adjacent, M_LOCKF);
			continue;
		}
		/* If the lock starts adjacent to us, we can coalesce it */
		if (lock->lf_end != -1 &&
		    (lock->lf_end + 1) == (*lf)->lf_start) {
			struct lockf *adjacent = *lf;

			LOCKF_DEBUG(LF_DBG_LIST, "lf_coalesce_adjacent: coalesce adjacent following\n");
			lock->lf_end = (*lf)->lf_end;
			lock->lf_next = (*lf)->lf_next;
			lf = &lock->lf_next;

			lf_move_blocked(lock, adjacent);

			FREE(adjacent, M_LOCKF);
			continue;
		}

		/* no matching conditions; go on to next lock */
		lf = &(*lf)->lf_next;
	}
}

/*
 * lf_setlock
 *
 * Description:	Set a byte-range lock.
 *
 * Parameters:	lock			The lock structure describing the lock
 *					to be set; allocated by the caller, it
 *					will be linked into the lock list if
 *					the set is successful, and freed if the
 *					set is unsuccessful.
 *
 *		timeout			Timeout specified in the case of
 * 					SETLKWTIMEOUT.
 *
 * Returns:	0			Success
 *		EAGAIN
 *		EDEADLK
 *	lf_split:ENOLCK
 *	lf_clearlock:ENOLCK
 *	msleep:EINTR
 *	msleep:ETIMEDOUT
 *
 * Notes:	We add the lock to the provisional lock list.  We do not
 *		coalesce at this time; this has implications for other lock
 *		requestors in the blocker search mechanism.
 */
static int
lf_setlock(struct lockf *lock, struct timespec *timeout)
{
	struct lockf *block;
	struct lockf **head = lock->lf_head;
	struct lockf **prev, *overlap, *ltmp;
	static char lockstr[] = "lockf";
	int priority, needtolink, error;
	struct vnode *vp = lock->lf_vnode;
	overlap_t ovcase;

#ifdef LOCKF_DEBUGGING
	if (lockf_debug & LF_DBG_LOCKOP) {
		lf_print("lf_setlock", lock);
		lf_printlist("lf_setlock(in)", lock);
	}
#endif /* LOCKF_DEBUGGING */

	/*
	 * Set the priority
	 */
	priority = PLOCK;
	if (lock->lf_type == F_WRLCK)
		priority += 4;
	priority |= PCATCH;
	/*
	 * Scan lock list for this file looking for locks that would block us.
	 */
	while ((block = lf_getblock(lock, -1))) {
		/*
		 * Free the structure and return if nonblocking.
		 */
		if ((lock->lf_flags & F_WAIT) == 0) {
			DTRACE_FSINFO(advlock__nowait, vnode_t, vp);
			FREE(lock, M_LOCKF);
			return (EAGAIN);
		}

		/*
		 * We are blocked. Since flock style locks cover
		 * the whole file, there is no chance for deadlock.
		 *
		 * OFD byte-range locks currently do NOT support
		 * deadlock detection.
		 *
		 * For POSIX byte-range locks we must check for deadlock.
		 *
		 * Deadlock detection is done by looking through the
		 * wait channels to see if there are any cycles that
		 * involve us. MAXDEPTH is set just to make sure we
		 * do not go off into neverland.
		 */
		if ((lock->lf_flags & F_POSIX) &&
		    (block->lf_flags & F_POSIX)) {
			struct proc *wproc, *bproc;
			struct uthread *ut;
			struct lockf *waitblock;
			int i = 0;

			/* The block is waiting on something */
			wproc = block->lf_owner;
			proc_lock(wproc);
			TAILQ_FOREACH(ut, &wproc->p_uthlist, uu_list) {
				/*
				 * While the thread is asleep (uu_wchan != 0)
				 * in this code (uu_wmesg == lockstr)
				 * and we have not exceeded the maximum cycle
				 * depth (i < maxlockdepth), then check for a
				 * cycle to see if the lock is blocked behind
				 * someone blocked behind us.
				 */
				while (((waitblock = (struct lockf *)ut->uu_wchan) != NULL) &&
				    ut->uu_wmesg == lockstr &&
				    (i++ < maxlockdepth)) {
					waitblock = (struct lockf *)ut->uu_wchan;
					/*
					 * Get the lock blocking the lock
					 * which would block us, and make
					 * certain it hasn't come unblocked
					 * (been granted, e.g. between the time
					 * we called lf_getblock, and the time
					 * we successfully acquired the
					 * proc_lock).
					 */
					waitblock = waitblock->lf_next;
					if (waitblock == NULL)
						break;

					/*
					 * Make sure it's an advisory range
					 * lock and not any other kind of lock;
					 * if we mix lock types, it's our own
					 * fault.
					 */
					if ((waitblock->lf_flags & F_POSIX) == 0)
						break;

					/*
					 * If the owner of the lock that's
					 * blocking a lock that's blocking us
					 * getting the requested lock, then we
					 * would deadlock, so error out.
					 */
					bproc = waitblock->lf_owner;
					if (bproc == lock->lf_owner) {
						proc_unlock(wproc);
						FREE(lock, M_LOCKF);
						return (EDEADLK);
					}
				}
			}
			proc_unlock(wproc);
		}

		/*
		 * For flock type locks, we must first remove
		 * any shared locks that we hold before we sleep
		 * waiting for an exclusive lock.
		 */
		if ((lock->lf_flags & F_FLOCK) &&
		    lock->lf_type == F_WRLCK) {
			lock->lf_type = F_UNLCK;
			if ((error = lf_clearlock(lock)) != 0) {
				FREE(lock, M_LOCKF);
				return (error);
			}
			lock->lf_type = F_WRLCK;
		}
		/*
		 * Add our lock to the blocked list and sleep until we're free.
		 * Remember who blocked us (for deadlock detection).
		 */
		lock->lf_next = block;
		TAILQ_INSERT_TAIL(&block->lf_blkhd, lock, lf_block);

		if ( !(lock->lf_flags & F_FLOCK))
		        block->lf_flags &= ~F_WAKE1_SAFE;

#if IMPORTANCE_INHERITANCE
		/*
		 * Importance donation is done only for cases where the
		 * owning task can be unambiguously determined.
		 *
		 * POSIX type locks are not inherited by child processes;
		 * we maintain a 1:1 mapping between a lock and its owning
		 * process.
		 *
		 * Flock type locks are inherited across fork() and there is
		 * no 1:1 mapping in the general case.  However, the fileglobs
		 * used by OFD locks *may* be confined to the process that
		 * created them, and thus have an "owner", in which case
		 * we also attempt importance donation.
		 */
		if ((lock->lf_flags & block->lf_flags & F_POSIX) != 0)
			lf_boost_blocking_proc(lock, block);
		else if ((lock->lf_flags & block->lf_flags & F_OFD_LOCK) &&
		    lock->lf_owner != block->lf_owner &&
		    NULL != lock->lf_owner && NULL != block->lf_owner)
			lf_boost_blocking_proc(lock, block);
#endif /* IMPORTANCE_INHERITANCE */

#ifdef LOCKF_DEBUGGING
		if (lockf_debug & LF_DBG_LOCKOP) {
			lf_print("lf_setlock: blocking on", block);
			lf_printlist("lf_setlock(block)", block);
		}
#endif /* LOCKF_DEBUGGING */
		DTRACE_FSINFO(advlock__wait, vnode_t, vp);

		error = msleep(lock, &vp->v_lock, priority, lockstr, timeout);

		if (error == 0 && (lock->lf_flags & F_ABORT) != 0)
			error = EBADF;

		if (lock->lf_next) {
			/*
			 * lf_wakelock() always sets wakelock->lf_next to
			 * NULL before a wakeup; so we've been woken early
			 * - perhaps by a debugger, signal or other event.
			 *
			 * Remove 'lock' from the block list (avoids double-add
			 * in the spurious case, which would create a cycle)
			 */
			TAILQ_REMOVE(&lock->lf_next->lf_blkhd, lock, lf_block);
#if IMPORTANCE_INHERITANCE
			/*
			 * Adjust the boost on lf_next.
			 */
			lf_adjust_assertion(lock->lf_next);
#endif /* IMPORTANCE_INHERITANCE */
			lock->lf_next = NULL;

			if (error == 0) {
				/*
				 * If this was a spurious wakeup, retry
				 */
				printf("%s: spurious wakeup, retrying lock\n",
				    __func__);
				continue;
			}
		}

		if (!TAILQ_EMPTY(&lock->lf_blkhd)) {
		        if ((block = lf_getblock(lock, -1)) != NULL)
				lf_move_blocked(block, lock);
		}

		if (error) {
			if (!TAILQ_EMPTY(&lock->lf_blkhd))
			        lf_wakelock(lock, TRUE);
			FREE(lock, M_LOCKF);
			/* Return ETIMEDOUT if timeout occoured. */
			if (error == EWOULDBLOCK) {
				error = ETIMEDOUT;
			}
			return (error);
		}
	}

	/*
	 * No blocks!!  Add the lock.  Note that we will
	 * downgrade or upgrade any overlapping locks this
	 * process already owns.
	 *
	 * Skip over locks owned by other processes.
	 * Handle any locks that overlap and are owned by ourselves.
	 */
	prev = head;
	block = *head;
	needtolink = 1;
	for (;;) {
		ovcase = lf_findoverlap(block, lock, SELF, &prev, &overlap);
		if (ovcase)
			block = overlap->lf_next;
		/*
		 * Six cases:
		 *	0) no overlap
		 *	1) overlap == lock
		 *	2) overlap contains lock
		 *	3) lock contains overlap
		 *	4) overlap starts before lock
		 *	5) overlap ends after lock
		 */
		switch (ovcase) {
		case OVERLAP_NONE:
			if (needtolink) {
				*prev = lock;
				lock->lf_next = overlap;
			}
			break;

		case OVERLAP_EQUALS_LOCK:
			/*
			 * If downgrading lock, others may be
			 * able to acquire it.
			 */
			if (lock->lf_type == F_RDLCK &&
			    overlap->lf_type == F_WRLCK)
			        lf_wakelock(overlap, TRUE);
			overlap->lf_type = lock->lf_type;
			FREE(lock, M_LOCKF);
			lock = overlap; /* for lf_coalesce_adjacent() */
			break;

		case OVERLAP_CONTAINS_LOCK:
			/*
			 * Check for common starting point and different types.
			 */
			if (overlap->lf_type == lock->lf_type) {
				FREE(lock, M_LOCKF);
				lock = overlap; /* for lf_coalesce_adjacent() */
				break;
			}
			if (overlap->lf_start == lock->lf_start) {
				*prev = lock;
				lock->lf_next = overlap;
				overlap->lf_start = lock->lf_end + 1;
			} else {
				/*
				 * If we can't split the lock, we can't
				 * grant it.  Claim a system limit for the
				 * resource shortage.
				 */
				if (lf_split(overlap, lock)) {
					FREE(lock, M_LOCKF);
					return (ENOLCK);
				}
			}
			lf_wakelock(overlap, TRUE);
			break;

		case OVERLAP_CONTAINED_BY_LOCK:
			/*
			 * If downgrading lock, others may be able to
			 * acquire it, otherwise take the list.
			 */
			if (lock->lf_type == F_RDLCK &&
			    overlap->lf_type == F_WRLCK) {
			        lf_wakelock(overlap, TRUE);
			} else {
				while (!TAILQ_EMPTY(&overlap->lf_blkhd)) {
					ltmp = TAILQ_FIRST(&overlap->lf_blkhd);
					TAILQ_REMOVE(&overlap->lf_blkhd, ltmp,
					    lf_block);
					TAILQ_INSERT_TAIL(&lock->lf_blkhd,
					    ltmp, lf_block);
					ltmp->lf_next = lock;
				}
			}
			/*
			 * Add the new lock if necessary and delete the overlap.
			 */
			if (needtolink) {
				*prev = lock;
				lock->lf_next = overlap->lf_next;
				prev = &lock->lf_next;
				needtolink = 0;
			} else
				*prev = overlap->lf_next;
			FREE(overlap, M_LOCKF);
			continue;

		case OVERLAP_STARTS_BEFORE_LOCK:
			/*
			 * Add lock after overlap on the list.
			 */
			lock->lf_next = overlap->lf_next;
			overlap->lf_next = lock;
			overlap->lf_end = lock->lf_start - 1;
			prev = &lock->lf_next;
			lf_wakelock(overlap, TRUE);
			needtolink = 0;
			continue;

		case OVERLAP_ENDS_AFTER_LOCK:
			/*
			 * Add the new lock before overlap.
			 */
			if (needtolink) {
				*prev = lock;
				lock->lf_next = overlap;
			}
			overlap->lf_start = lock->lf_end + 1;
			lf_wakelock(overlap, TRUE);
			break;
		}
		break;
	}
	/* Coalesce adjacent locks with identical attributes */
	lf_coalesce_adjacent(lock);
#ifdef LOCKF_DEBUGGING
	if (lockf_debug & LF_DBG_LOCKOP) {
		lf_print("lf_setlock: got the lock", lock);
		lf_printlist("lf_setlock(out)", lock);
	}
#endif /* LOCKF_DEBUGGING */
	return (0);
}


/*
 * lf_clearlock
 *
 * Description:	Remove a byte-range lock on an vnode.  Generally, find the
 *		lock (or an overlap to that lock) and remove it (or shrink
 *		it), then wakeup anyone we can.
 *
 * Parameters:	unlock			The lock to clear
 *
 * Returns:	0			Success
 *	lf_split:ENOLCK
 *
 * Notes:	A caller may unlock all the locks owned by the caller by
 *		specifying the entire file range; locks owned by other
 *		callers are not effected by this operation.
 */
static int
lf_clearlock(struct lockf *unlock)
{
	struct lockf **head = unlock->lf_head;
	struct lockf *lf = *head;
	struct lockf *overlap, **prev;
	overlap_t ovcase;

	if (lf == NOLOCKF)
		return (0);
#ifdef LOCKF_DEBUGGING
	if (unlock->lf_type != F_UNLCK)
		panic("lf_clearlock: bad type");
	if (lockf_debug & LF_DBG_LOCKOP)
		lf_print("lf_clearlock", unlock);
#endif /* LOCKF_DEBUGGING */
	prev = head;
	while ((ovcase = lf_findoverlap(lf, unlock, SELF, &prev, &overlap)) != OVERLAP_NONE) {
		/*
		 * Wakeup the list of locks to be retried.
		 */
	        lf_wakelock(overlap, FALSE);
#if IMPORTANCE_INHERITANCE
		if (overlap->lf_boosted == LF_BOOSTED) {
			lf_drop_assertion(overlap);
		}
#endif /* IMPORTANCE_INHERITANCE */

		switch (ovcase) {
		case OVERLAP_NONE:	/* satisfy compiler enum/switch */
			break;

		case OVERLAP_EQUALS_LOCK:
			*prev = overlap->lf_next;
			FREE(overlap, M_LOCKF);
			break;

		case OVERLAP_CONTAINS_LOCK: /* split it */
			if (overlap->lf_start == unlock->lf_start) {
				overlap->lf_start = unlock->lf_end + 1;
				break;
			}
			/*
			 * If we can't split the lock, we can't grant it.
			 * Claim a system limit for the resource shortage.
			 */
			if (lf_split(overlap, unlock))
				return (ENOLCK);
			overlap->lf_next = unlock->lf_next;
			break;

		case OVERLAP_CONTAINED_BY_LOCK:
			*prev = overlap->lf_next;
			lf = overlap->lf_next;
			FREE(overlap, M_LOCKF);
			continue;

		case OVERLAP_STARTS_BEFORE_LOCK:
			overlap->lf_end = unlock->lf_start - 1;
			prev = &overlap->lf_next;
			lf = overlap->lf_next;
			continue;

		case OVERLAP_ENDS_AFTER_LOCK:
			overlap->lf_start = unlock->lf_end + 1;
			break;
		}
		break;
	}
#ifdef LOCKF_DEBUGGING
	if (lockf_debug & LF_DBG_LOCKOP)
		lf_printlist("lf_clearlock", unlock);
#endif /* LOCKF_DEBUGGING */
	return (0);
}


/*
 * lf_getlock
 *
 * Description:	Check whether there is a blocking lock, and if so return
 *		its process identifier into the lock being requested.
 *
 * Parameters:	lock			Pointer to lock to test for blocks
 *		fl			Pointer to flock structure to receive
 *					the blocking lock information, if a
 *					blocking lock is found.
 *		matchpid		-1, or pid value to match in lookup.
 *
 * Returns:	0			Success
 *
 * Implicit Returns:
 *		*fl			Contents modified to reflect the
 *					blocking lock, if one is found; not
 *					modified otherwise
 *
 * Notes:	fl->l_pid will be (-1) for file locks and will only be set to
 *		the blocking process ID for advisory record locks.
 */
static int
lf_getlock(struct lockf *lock, struct flock *fl, pid_t matchpid)
{
	struct lockf *block;

#ifdef LOCKF_DEBUGGING
	if (lockf_debug & LF_DBG_LOCKOP)
		lf_print("lf_getlock", lock);
#endif /* LOCKF_DEBUGGING */

	if ((block = lf_getblock(lock, matchpid))) {
		fl->l_type = block->lf_type;
		fl->l_whence = SEEK_SET;
		fl->l_start = block->lf_start;
		if (block->lf_end == -1)
			fl->l_len = 0;
		else
			fl->l_len = block->lf_end - block->lf_start + 1;
		if (NULL != block->lf_owner) {
			/*
			 * lf_owner is only non-NULL when the lock
			 * "owner" can be unambiguously determined
			 */
			fl->l_pid = proc_pid(block->lf_owner);
		} else
			fl->l_pid = -1;
	} else {
		fl->l_type = F_UNLCK;
	}
	return (0);
}

/*
 * lf_getblock
 *
 * Description:	Walk the list of locks for an inode and return the first
 *		blocking lock.  A lock is considered blocking if we are not
 *		the lock owner; otherwise, we are permitted to upgrade or
 *		downgrade it, and it's not considered blocking.
 *
 * Parameters:	lock			The lock for which we are interested
 *					in obtaining the blocking lock, if any
 *		matchpid		-1, or pid value to match in lookup.
 *
 * Returns:	NOLOCKF			No blocking lock exists
 *		!NOLOCKF		The address of the blocking lock's
 *					struct lockf.
 */
static struct lockf *
lf_getblock(struct lockf *lock, pid_t matchpid)
{
	struct lockf **prev, *overlap, *lf = *(lock->lf_head);

	for (prev = lock->lf_head;
	    lf_findoverlap(lf, lock, OTHERS, &prev, &overlap) != OVERLAP_NONE;
	    lf = overlap->lf_next) {
		/*
		 * Found an overlap.
		 *
		 * If we're matching pids, and it's a record lock,
		 * or it's an OFD lock on a process-confined fd,
		 * but the pid doesn't match, then keep on looking ..
		 */
		if (matchpid != -1 &&
		    (overlap->lf_flags & (F_POSIX|F_OFD_LOCK)) != 0 &&
		    proc_pid(overlap->lf_owner) != matchpid)
			continue;

		/*
		 * does it block us?
		 */
		if ((lock->lf_type == F_WRLCK || overlap->lf_type == F_WRLCK))
			return (overlap);
	}
	return (NOLOCKF);
}


/*
 * lf_findoverlap
 *
 * Description:	Walk the list of locks to find an overlapping lock (if any).
 *
 * Parameters:	lf			First lock on lock list
 *		lock			The lock we are checking for an overlap
 *		check			Check type
 *		prev			pointer to pointer pointer to contain
 *					address of pointer to previous lock
 *					pointer to overlapping lock, if overlap
 *		overlap			pointer to pointer to contain address
 *					of overlapping lock
 *
 * Returns:	OVERLAP_NONE
 *		OVERLAP_EQUALS_LOCK
 *		OVERLAP_CONTAINS_LOCK
 *		OVERLAP_CONTAINED_BY_LOCK
 *		OVERLAP_STARTS_BEFORE_LOCK
 *		OVERLAP_ENDS_AFTER_LOCK
 *
 * Implicit Returns:
 *		*prev			The address of the next pointer in the
 *					lock previous to the overlapping lock;
 *					this is generally used to relink the
 *					lock list, avoiding a second iteration.
 *		*overlap		The pointer to the overlapping lock
 *					itself; this is used to return data in
 *					the check == OTHERS case, and for the
 *					caller to modify the overlapping lock,
 *					in the check == SELF case
 *
 * Note:	This returns only the FIRST overlapping lock.  There may be
 *		more than one.  lf_getlock will return the first blocking lock,
 *		while lf_setlock will iterate over all overlapping locks to
 *
 *		The check parameter can be SELF, meaning we are looking for
 *		overlapping locks owned by us, or it can be OTHERS, meaning
 *		we are looking for overlapping locks owned by someone else so
 *		we can report a blocking lock on an F_GETLK request.
 *
 *		The value of *overlap and *prev are modified, even if there is
 *		no overlapping lock found; always check the return code.
 */
static overlap_t
lf_findoverlap(struct lockf *lf, struct lockf *lock, int type,
	       struct lockf ***prev, struct lockf **overlap)
{
	off_t start, end;
	int found_self = 0;

	*overlap = lf;
	if (lf == NOLOCKF)
		return (0);
#ifdef LOCKF_DEBUGGING
	if (lockf_debug & LF_DBG_LIST)
		lf_print("lf_findoverlap: looking for overlap in", lock);
#endif /* LOCKF_DEBUGGING */
	start = lock->lf_start;
	end = lock->lf_end;
	while (lf != NOLOCKF) {
		if (((type & SELF) && lf->lf_id != lock->lf_id) ||
		    ((type & OTHERS) && lf->lf_id == lock->lf_id)) {
			/* 
			 * Locks belonging to one process are adjacent on the
			 * list, so if we've found any locks belonging to us,
			 * and we're now seeing something else, then we've
			 * examined all "self" locks.  Note that bailing out
			 * here is quite important; for coalescing, we assume 
			 * numerically adjacent locks from the same owner to 
			 * be adjacent on the list.
			 */
			if ((type & SELF) && found_self) {
				return OVERLAP_NONE;
			}

			*prev = &lf->lf_next;
			*overlap = lf = lf->lf_next;
			continue;
		}

		if ((type & SELF)) {
			found_self = 1;
		}

#ifdef LOCKF_DEBUGGING
		if (lockf_debug & LF_DBG_LIST)
			lf_print("\tchecking", lf);
#endif /* LOCKF_DEBUGGING */
		/*
		 * OK, check for overlap
		 */
		if ((lf->lf_end != -1 && start > lf->lf_end) ||
		    (end != -1 && lf->lf_start > end)) {
			/* Case 0 */
			LOCKF_DEBUG(LF_DBG_LIST, "no overlap\n");

			/*
			 * NOTE: assumes that locks for the same process are 
			 * nonintersecting and ordered.
			 */
			if ((type & SELF) && end != -1 && lf->lf_start > end)
				return (OVERLAP_NONE);
			*prev = &lf->lf_next;
			*overlap = lf = lf->lf_next;
			continue;
		}
		if ((lf->lf_start == start) && (lf->lf_end == end)) {
			LOCKF_DEBUG(LF_DBG_LIST, "overlap == lock\n");
			return (OVERLAP_EQUALS_LOCK);
		}
		if ((lf->lf_start <= start) &&
		    (end != -1) &&
		    ((lf->lf_end >= end) || (lf->lf_end == -1))) {
			LOCKF_DEBUG(LF_DBG_LIST, "overlap contains lock\n");
			return (OVERLAP_CONTAINS_LOCK);
		}
		if (start <= lf->lf_start &&
		           (end == -1 ||
			   (lf->lf_end != -1 && end >= lf->lf_end))) {
			LOCKF_DEBUG(LF_DBG_LIST, "lock contains overlap\n");
			return (OVERLAP_CONTAINED_BY_LOCK);
		}
		if ((lf->lf_start < start) &&
			((lf->lf_end >= start) || (lf->lf_end == -1))) {
			LOCKF_DEBUG(LF_DBG_LIST, "overlap starts before lock\n");
			return (OVERLAP_STARTS_BEFORE_LOCK);
		}
		if ((lf->lf_start > start) &&
			(end != -1) &&
			((lf->lf_end > end) || (lf->lf_end == -1))) {
			LOCKF_DEBUG(LF_DBG_LIST, "overlap ends after lock\n");
			return (OVERLAP_ENDS_AFTER_LOCK);
		}
		panic("lf_findoverlap: default");
	}
	return (OVERLAP_NONE);
}


/*
 * lf_split
 *
 * Description:	Split a lock and a contained region into two or three locks
 *		as necessary.
 *
 * Parameters:	lock1			Lock to split
 *		lock2			Overlapping lock region requiring the
 *					split (upgrade/downgrade/unlock)
 *
 * Returns:	0			Success
 *		ENOLCK			No memory for new lock
 *
 * Implicit Returns:
 *		*lock1			Modified original lock
 *		*lock2			Overlapping lock (inserted into list)
 *		(new lock)		Potential new lock inserted into list
 *					if split results in 3 locks
 *
 * Notes:	This operation can only fail if the split would result in three
 *		locks, and there is insufficient memory to allocate the third
 *		lock; in that case, neither of the locks will be modified.
 */
static int
lf_split(struct lockf *lock1, struct lockf *lock2)
{
	struct lockf *splitlock;

#ifdef LOCKF_DEBUGGING
	if (lockf_debug & LF_DBG_LIST) {
		lf_print("lf_split", lock1);
		lf_print("splitting from", lock2);
	}
#endif /* LOCKF_DEBUGGING */
	/*
	 * Check to see if splitting into only two pieces.
	 */
	if (lock1->lf_start == lock2->lf_start) {
		lock1->lf_start = lock2->lf_end + 1;
		lock2->lf_next = lock1;
		return (0);
	}
	if (lock1->lf_end == lock2->lf_end) {
		lock1->lf_end = lock2->lf_start - 1;
		lock2->lf_next = lock1->lf_next;
		lock1->lf_next = lock2;
		return (0);
	}
	/*
	 * Make a new lock consisting of the last part of
	 * the encompassing lock
	 */
	MALLOC(splitlock, struct lockf *, sizeof *splitlock, M_LOCKF, M_WAITOK);
	if (splitlock == NULL)
		return (ENOLCK);
	bcopy(lock1, splitlock, sizeof *splitlock);
	splitlock->lf_start = lock2->lf_end + 1;
	TAILQ_INIT(&splitlock->lf_blkhd);
	lock1->lf_end = lock2->lf_start - 1;
	/*
	 * OK, now link it in
	 */
	splitlock->lf_next = lock1->lf_next;
	lock2->lf_next = splitlock;
	lock1->lf_next = lock2;

	return (0);
}


/*
 * lf_wakelock
 *
 * Wakeup a blocklist in the case of a downgrade or unlock, since others
 * waiting on the lock may now be able to acquire it.
 *
 * Parameters:	listhead		Lock list head on which waiters may
 *					have pending locks
 *
 * Returns:	<void>
 *
 * Notes:	This function iterates a list of locks and wakes all waiters,
 *		rather than only waiters for the contended regions.  Because
 *		of this, for heavily contended files, this can result in a
 *		"thundering herd" situation.  Refactoring the code could make
 *		this operation more efficient, if heavy contention ever results
 *		in a real-world performance problem.
 */
static void
lf_wakelock(struct lockf *listhead, boolean_t force_all)
{
	struct lockf *wakelock;
	boolean_t wake_all = TRUE;

	if (force_all == FALSE && (listhead->lf_flags & F_WAKE1_SAFE))
	        wake_all = FALSE;

	while (!TAILQ_EMPTY(&listhead->lf_blkhd)) {
		wakelock = TAILQ_FIRST(&listhead->lf_blkhd);
		TAILQ_REMOVE(&listhead->lf_blkhd, wakelock, lf_block);

		wakelock->lf_next = NOLOCKF;
#ifdef LOCKF_DEBUGGING
		if (lockf_debug & LF_DBG_LOCKOP)
			lf_print("lf_wakelock: awakening", wakelock);
#endif /* LOCKF_DEBUGGING */
		if (wake_all == FALSE) {
			/*
			 * If there are items on the list head block list,
			 * move them to the wakelock list instead, and then
			 * correct their lf_next pointers.
			 */
			if (!TAILQ_EMPTY(&listhead->lf_blkhd)) {
				TAILQ_CONCAT(&wakelock->lf_blkhd, &listhead->lf_blkhd, lf_block);

			        struct lockf *tlock;

			        TAILQ_FOREACH(tlock, &wakelock->lf_blkhd, lf_block) {
					if (TAILQ_NEXT(tlock, lf_block) == tlock) {
						/* See rdar://10887303 */
						panic("cycle in wakelock list");
					}
				        tlock->lf_next = wakelock;
				}
			}
		}
		wakeup(wakelock);

		if (wake_all == FALSE)
		        break;
	}
}


#ifdef LOCKF_DEBUGGING
#define GET_LF_OWNER_PID(lf)	(proc_pid((lf)->lf_owner))

/*
 * lf_print DEBUG
 *
 * Print out a lock; lock information is prefixed by the string in 'tag'
 *
 * Parameters:	tag			A string tag for debugging
 *		lock			The lock whose information should be
 *					displayed
 *
 * Returns:	<void>
 */
void
lf_print(const char *tag, struct lockf *lock)
{
	printf("%s: lock %p for ", tag, (void *)lock);
	if (lock->lf_flags & F_POSIX)
		printf("proc %p (owner %d)",
		    lock->lf_id, GET_LF_OWNER_PID(lock));
	else if (lock->lf_flags & F_OFD_LOCK)
		printf("fg %p (owner %d)",
		    lock->lf_id, GET_LF_OWNER_PID(lock));
	else
		printf("id %p", (void *)lock->lf_id);
	if (lock->lf_vnode != 0)
		printf(" in vno %p, %s, start 0x%016llx, end 0x%016llx",
		    lock->lf_vnode,
		    lock->lf_type == F_RDLCK ? "shared" :
		    lock->lf_type == F_WRLCK ? "exclusive" :
		    lock->lf_type == F_UNLCK ? "unlock" : "unknown",
		    (intmax_t)lock->lf_start, (intmax_t)lock->lf_end);
	else
		printf(" %s, start 0x%016llx, end 0x%016llx",
		    lock->lf_type == F_RDLCK ? "shared" :
		    lock->lf_type == F_WRLCK ? "exclusive" :
		    lock->lf_type == F_UNLCK ? "unlock" : "unknown",
		    (intmax_t)lock->lf_start, (intmax_t)lock->lf_end);
	if (!TAILQ_EMPTY(&lock->lf_blkhd))
		printf(" block %p\n", (void *)TAILQ_FIRST(&lock->lf_blkhd));
	else
		printf("\n");
}


/*
 * lf_printlist DEBUG
 *
 * Print out a lock list for the vnode associated with 'lock'; lock information
 * is prefixed by the string in 'tag'
 *
 * Parameters:	tag			A string tag for debugging
 *		lock			The lock whose vnode's lock list should
 *					be displayed
 *
 * Returns:	<void>
 */
void
lf_printlist(const char *tag, struct lockf *lock)
{
	struct lockf *lf, *blk;

	if (lock->lf_vnode == 0)
		return;

	printf("%s: Lock list for vno %p:\n",
	    tag, lock->lf_vnode);
	for (lf = lock->lf_vnode->v_lockf; lf; lf = lf->lf_next) {
		printf("\tlock %p for ",(void *)lf);
		if (lf->lf_flags & F_POSIX)
			printf("proc %p (owner %d)",
			    lf->lf_id, GET_LF_OWNER_PID(lf));
		else if (lf->lf_flags & F_OFD_LOCK)
			printf("fg %p (owner %d)",
			    lf->lf_id, GET_LF_OWNER_PID(lf));
		else
			printf("id %p", (void *)lf->lf_id);
		printf(", %s, start 0x%016llx, end 0x%016llx",
		    lf->lf_type == F_RDLCK ? "shared" :
		    lf->lf_type == F_WRLCK ? "exclusive" :
		    lf->lf_type == F_UNLCK ? "unlock" :
		    "unknown", (intmax_t)lf->lf_start, (intmax_t)lf->lf_end);
		TAILQ_FOREACH(blk, &lf->lf_blkhd, lf_block) {
			printf("\n\t\tlock request %p for ", (void *)blk);
			if (blk->lf_flags & F_POSIX)
				printf("proc %p (owner %d)",
				    blk->lf_id, GET_LF_OWNER_PID(blk));
			else if (blk->lf_flags & F_OFD_LOCK)
				printf("fg %p (owner %d)",
				    blk->lf_id, GET_LF_OWNER_PID(blk));
			else
				printf("id %p", (void *)blk->lf_id);
			printf(", %s, start 0x%016llx, end 0x%016llx",
			    blk->lf_type == F_RDLCK ? "shared" :
			    blk->lf_type == F_WRLCK ? "exclusive" :
			    blk->lf_type == F_UNLCK ? "unlock" :
			    "unknown", (intmax_t)blk->lf_start,
			    (intmax_t)blk->lf_end);
			if (!TAILQ_EMPTY(&blk->lf_blkhd))
				panic("lf_printlist: bad list");
		}
		printf("\n");
	}
}
#endif /* LOCKF_DEBUGGING */

#if IMPORTANCE_INHERITANCE

/*
 * lf_hold_assertion
 *
 * Call task importance hold assertion on the owner of the lock.
 *
 * Parameters: block_task               Owner of the lock blocking 
 *                                      current thread.
 *
 *             block                    lock on which the current thread 
 *                                      is blocking on.
 *
 * Returns:    <void>
 *
 * Notes: The task reference on block_task is not needed to be hold since 
 *        the current thread has vnode lock and block_task has a file 
 *        lock, thus removing file lock in exit requires block_task to 
 *        grab the vnode lock.
 */
static void 
lf_hold_assertion(task_t block_task, struct lockf *block)
{
	if (task_importance_hold_file_lock_assertion(block_task, 1) == 0) {
		block->lf_boosted = LF_BOOSTED;
		LOCKF_DEBUG(LF_DBG_IMPINH,
		    "lf: importance hold file lock assert on pid %d lock %p\n",
		    proc_pid(block->lf_owner), block);
	}
}


/*
 * lf_jump_to_queue_head
 *
 * Jump the lock from the tail of the block queue to the head of
 * the queue.
 *
 * Parameters: block                    lockf struct containing the 
 *                                      block queue.
 *             lock                     lockf struct to be jumped to the
 *                                      front.
 *
 * Returns:    <void>
 */
static void
lf_jump_to_queue_head(struct lockf *block, struct lockf *lock) 
{
	/* Move the lock to the head of the block queue. */
	TAILQ_REMOVE(&block->lf_blkhd, lock, lf_block);
	TAILQ_INSERT_HEAD(&block->lf_blkhd, lock, lf_block);
}


/*
 * lf_drop_assertion
 *
 * Drops the task hold assertion.
 *
 * Parameters: block                    lockf struct holding the assertion.
 *
 * Returns:    <void>
 */
static void 
lf_drop_assertion(struct lockf *block)
{
	LOCKF_DEBUG(LF_DBG_IMPINH, "lf: %d: dropping assertion for lock %p\n",
	    proc_pid(block->lf_owner), block);

	task_t current_task = proc_task(block->lf_owner);
	task_importance_drop_file_lock_assertion(current_task, 1);
	block->lf_boosted = LF_NOT_BOOSTED;
}

/*
 * lf_adjust_assertion
 *
 * Adjusts importance assertion of file lock. Goes through
 * all the blocking locks and checks if the file lock needs
 * to be boosted anymore.
 *
 * Parameters: block	lockf structure which needs to be adjusted.
 *
 * Returns:	<void>
 */
static void
lf_adjust_assertion(struct lockf *block)
{
	boolean_t drop_boost = TRUE;
	struct lockf *next;

	/* Return if the lock is not boosted */
	if (block->lf_boosted == LF_NOT_BOOSTED) {
		return;
	}

	TAILQ_FOREACH(next, &block->lf_blkhd, lf_block) {
		/* Check if block and next are same type of locks */
		if (((block->lf_flags & next->lf_flags & F_POSIX) != 0) ||
		    ((block->lf_flags & next->lf_flags & F_OFD_LOCK) &&
		     (block->lf_owner != next->lf_owner) &&
		     (NULL != block->lf_owner && NULL != next->lf_owner))) {

			/* Check if next would be boosting block */
			if (task_is_importance_donor(proc_task(next->lf_owner)) &&
			    task_is_importance_receiver_type(proc_task(block->lf_owner))) {
				/* Found a lock boosting block */
				drop_boost = FALSE;
				break;
			}
		}
	}

	if (drop_boost) {
		lf_drop_assertion(block);
	}
}

static void
lf_boost_blocking_proc(struct lockf *lock, struct lockf *block)
{
	task_t ltask = proc_task(lock->lf_owner);
	task_t btask = proc_task(block->lf_owner);

	/*
	 * Check if ltask can donate importance. The
	 * check of imp_donor bit is done without holding
	 * any lock. The value may change after you read it,
	 * but it is ok to boost a task while someone else is
	 * unboosting you.
	 *
	 * TODO: Support live inheritance on file locks.
	 */
	if (task_is_importance_donor(ltask)) {
		LOCKF_DEBUG(LF_DBG_IMPINH,
		    "lf: %d: attempt to boost pid %d that holds lock %p\n",
		    proc_pid(lock->lf_owner), proc_pid(block->lf_owner), block);

		if (block->lf_boosted != LF_BOOSTED &&
		    task_is_importance_receiver_type(btask)) {
			lf_hold_assertion(btask, block);
		}
		lf_jump_to_queue_head(block, lock);
	}
}
#endif /* IMPORTANCE_INHERITANCE */
