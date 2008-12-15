/*
 * Copyright (c) 2002-2007 Apple Inc.  All rights reserved.
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
/*-
 * Copyright (c) 1997 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      from BSDI nfs_lock.c,v 2.4 1998/12/14 23:49:56 jch Exp
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>		/* for hz */
#include <sys/file_internal.h>
#include <sys/malloc.h>
#include <sys/lockf.h>		/* for hz */ /* Must come after sys/malloc.h */
#include <sys/kpi_mbuf.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>	/* for p_start */
#include <sys/kauth.h>
#include <sys/resourcevar.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <sys/vnode_internal.h>

#include <kern/thread.h>
#include <kern/host.h>

#include <machine/limits.h>

#include <net/if.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_lock.h>

#include <mach/host_priv.h>
#include <mach/mig_errors.h>
#include <mach/host_special_ports.h>
#include <lockd/lockd_mach.h>

extern void ipc_port_release_send(ipc_port_t);

#define OFF_MAX QUAD_MAX

/*
 * pending lock request messages are kept in this queue which is
 * kept sorted by transaction ID (xid).
 */
static uint64_t nfs_lockxid = 0;
static LOCKD_MSG_QUEUE nfs_pendlockq;

/*
 * This structure is used to identify processes which have acquired NFS locks.
 * Knowing which processes have ever acquired locks allows us to short-circuit
 * unlock requests for processes that have never had an NFS file lock.  Thus
 * avoiding a costly and unnecessary lockd request.
 */
struct nfs_lock_pid {
	TAILQ_ENTRY(nfs_lock_pid)	lp_lru;		/* LRU list */
	LIST_ENTRY(nfs_lock_pid)	lp_hash;	/* hash chain */
	int				lp_valid;	/* valid entry? */
	int				lp_time;	/* last time seen valid */
	pid_t				lp_pid;		/* The process ID. */
	struct timeval			lp_pid_start;	/* Start time of process id */
};

#define NFS_LOCK_PID_HASH_SIZE		64	// XXX tune me
#define	NFS_LOCK_PID_HASH(pid)	\
	(&nfs_lock_pid_hash_tbl[(pid) & nfs_lock_pid_hash])
static LIST_HEAD(, nfs_lock_pid) *nfs_lock_pid_hash_tbl;
static TAILQ_HEAD(, nfs_lock_pid) nfs_lock_pid_lru;
static u_long nfs_lock_pid_hash, nfs_lock_pid_hash_trusted;

static lck_grp_t *nfs_lock_lck_grp;
static lck_mtx_t *nfs_lock_mutex;


/*
 * initialize global nfs lock state
 */
void
nfs_lockinit(void)
{
	TAILQ_INIT(&nfs_pendlockq);
	nfs_lock_pid_hash_trusted = 1;
	nfs_lock_pid_hash_tbl = hashinit(NFS_LOCK_PID_HASH_SIZE,
					 M_TEMP, &nfs_lock_pid_hash);
	TAILQ_INIT(&nfs_lock_pid_lru);

	nfs_lock_lck_grp = lck_grp_alloc_init("nfs_lock", LCK_GRP_ATTR_NULL);
	nfs_lock_mutex = lck_mtx_alloc_init(nfs_lock_lck_grp, LCK_ATTR_NULL);
}

/*
 * change the count of NFS mounts that may need to make lockd requests
 *
 * If the mount count drops to zero, then send a shutdown request to
 * lockd if we've sent any requests to it.
 */
void
nfs_lockd_mount_change(int i)
{
	mach_port_t lockd_port = IPC_PORT_NULL;
	kern_return_t kr;
	int send_shutdown;

	lck_mtx_lock(nfs_lock_mutex);

	nfs_lockd_mounts += i;

	/* send a shutdown request if there are no more lockd mounts */
	send_shutdown = ((nfs_lockd_mounts == 0) && nfs_lockd_request_sent);
	if (send_shutdown)
		nfs_lockd_request_sent = 0;

	lck_mtx_unlock(nfs_lock_mutex);

	if (!send_shutdown)
		return;

	/*
	 * Let lockd know that it is no longer need for any NFS mounts
	 */
	kr = host_get_lockd_port(host_priv_self(), &lockd_port);
	if ((kr != KERN_SUCCESS) || !IPC_PORT_VALID(lockd_port)) {
		printf("nfs_lockd_mount_change: shutdown couldn't get port, kr %d, port %s\n",
			kr, (lockd_port == IPC_PORT_NULL) ? "NULL" :
			(lockd_port == IPC_PORT_DEAD) ? "DEAD" : "VALID");
		return;
	}

	kr = lockd_shutdown(lockd_port);
	if (kr != KERN_SUCCESS)
		printf("nfs_lockd_mount_change: shutdown %d\n", kr);

	ipc_port_release_send(lockd_port);
}

/*
 * insert a lock request message into the pending queue
 * (nfs_lock_mutex must be held)
 */
static inline void
nfs_lockdmsg_enqueue(LOCKD_MSG_REQUEST *msgreq)
{
	LOCKD_MSG_REQUEST *mr;

	mr = TAILQ_LAST(&nfs_pendlockq, nfs_lock_msg_queue);
	if (!mr || (msgreq->lmr_msg.lm_xid > mr->lmr_msg.lm_xid)) {
		/* fast path: empty queue or new largest xid */
		TAILQ_INSERT_TAIL(&nfs_pendlockq, msgreq, lmr_next);
		return;
	}
	/* slow path: need to walk list to find insertion point */
	while (mr && (msgreq->lmr_msg.lm_xid > mr->lmr_msg.lm_xid)) {
		mr = TAILQ_PREV(mr, nfs_lock_msg_queue, lmr_next);
	}
	if (mr) {
		TAILQ_INSERT_AFTER(&nfs_pendlockq, mr, msgreq, lmr_next);
	} else {
		TAILQ_INSERT_HEAD(&nfs_pendlockq, msgreq, lmr_next);
	}
}

/*
 * remove a lock request message from the pending queue
 * (nfs_lock_mutex must be held)
 */
static inline void
nfs_lockdmsg_dequeue(LOCKD_MSG_REQUEST *msgreq)
{
	TAILQ_REMOVE(&nfs_pendlockq, msgreq, lmr_next);
}

/*
 * find a pending lock request message by xid
 *
 * We search from the head of the list assuming that the message we're
 * looking for is for an older request (because we have an answer to it).
 * This assumes that lock request will be answered primarily in FIFO order.
 * However, this may not be the case if there are blocked requests.  We may
 * want to move blocked requests to a separate queue (but that'll complicate
 * duplicate xid checking).
 *
 * (nfs_lock_mutex must be held)
 */
static inline LOCKD_MSG_REQUEST *
nfs_lockdmsg_find_by_xid(uint64_t lockxid)
{
	LOCKD_MSG_REQUEST *mr;

	TAILQ_FOREACH(mr, &nfs_pendlockq, lmr_next) {
		if (mr->lmr_msg.lm_xid == lockxid)
			return mr;
		if (mr->lmr_msg.lm_xid > lockxid)
			return NULL;
	}
	return mr;
}

/*
 * Because we can't depend on nlm_granted messages containing the same
 * cookie we sent with the original lock request, we need code test if
 * an nlm_granted answer matches the lock request.  We also need code
 * that can find a lockd message based solely on the nlm_granted answer.
 */

/*
 * compare lockd message to answer
 *
 * returns 0 on equality and 1 if different
 */
static inline int
nfs_lockdmsg_compare_to_answer(LOCKD_MSG_REQUEST *msgreq, struct lockd_ans *ansp)
{
	if (!(ansp->la_flags & LOCKD_ANS_LOCK_INFO))
		return 1;
	if (msgreq->lmr_msg.lm_fl.l_pid != ansp->la_pid)
		return 1;
	if (msgreq->lmr_msg.lm_fl.l_start != ansp->la_start)
		return 1;
	if (msgreq->lmr_msg.lm_fl.l_len != ansp->la_len)
		return 1;
	if (msgreq->lmr_msg.lm_fh_len != ansp->la_fh_len)
		return 1;
	if (bcmp(msgreq->lmr_msg.lm_fh, ansp->la_fh, ansp->la_fh_len))
		return 1;
	return 0;
}

/*
 * find a pending lock request message based on the lock info provided
 * in the lockd_ans/nlm_granted data.  We need this because we can't
 * depend on nlm_granted messages containing the same cookie we sent
 * with the original lock request.
 *
 * We search from the head of the list assuming that the message we're
 * looking for is for an older request (because we have an answer to it).
 * This assumes that lock request will be answered primarily in FIFO order.
 * However, this may not be the case if there are blocked requests.  We may
 * want to move blocked requests to a separate queue (but that'll complicate
 * duplicate xid checking).
 *
 * (nfs_lock_mutex must be held)
 */
static inline LOCKD_MSG_REQUEST *
nfs_lockdmsg_find_by_answer(struct lockd_ans *ansp)
{
	LOCKD_MSG_REQUEST *mr;

	if (!(ansp->la_flags & LOCKD_ANS_LOCK_INFO))
		return NULL;
	TAILQ_FOREACH(mr, &nfs_pendlockq, lmr_next) {
		if (!nfs_lockdmsg_compare_to_answer(mr, ansp))
			break;
	}
	return mr;
}

/*
 * return the next unique lock request transaction ID
 * (nfs_lock_mutex must be held)
 */
static inline uint64_t
nfs_lockxid_get(void)
{
	LOCKD_MSG_REQUEST *mr;

	/* derive initial lock xid from system time */
	if (!nfs_lockxid) {
		/*
		 * Note: it's OK if this code inits nfs_lockxid to 0 (for example,
		 * due to a broken clock) because we immediately increment it
		 * and we guarantee to never use xid 0.  So, nfs_lockxid should only
		 * ever be 0 the first time this function is called.
		 */
		struct timeval tv;
		microtime(&tv);
		nfs_lockxid = (uint64_t)tv.tv_sec << 12;
	}

	/* make sure we get a unique xid */
	do {
		/* Skip zero xid if it should ever happen.  */
		if (++nfs_lockxid == 0)
			nfs_lockxid++;
		if (!(mr = TAILQ_LAST(&nfs_pendlockq, nfs_lock_msg_queue)) ||
		     (mr->lmr_msg.lm_xid < nfs_lockxid)) {
			/* fast path: empty queue or new largest xid */
			break;
		}
		/* check if xid is already in use */
	} while (nfs_lockdmsg_find_by_xid(nfs_lockxid));

	return nfs_lockxid;
}


/*
 * Check the nfs_lock_pid hash table for an entry and, if requested,
 * add the entry if it is not found.
 *
 * (Also, if adding, try to clean up some stale entries.)
 * (nfs_lock_mutex must be held)
 */
static int
nfs_lock_pid_check(proc_t p, int addflag)
{
	struct nfs_lock_pid *lp, *lplru, *lplru_next, *mlp;
	TAILQ_HEAD(, nfs_lock_pid) nfs_lock_pid_free;
	proc_t plru = PROC_NULL;
	pid_t pid;
	int error = 0;
	struct timeval now;

	TAILQ_INIT(&nfs_lock_pid_free);
	mlp = NULL;

loop:
	/* Search hash chain */
	pid = proc_pid(p);
	error = ENOENT;
	lp = NFS_LOCK_PID_HASH(pid)->lh_first;
	for (; lp != NULL; lp = lp->lp_hash.le_next)
		if (lp->lp_pid == pid) {
			/* found pid... */
			if (timevalcmp(&lp->lp_pid_start, &p->p_start, ==)) {
				/* ...and it's valid */
				/* move to tail of LRU */
				TAILQ_REMOVE(&nfs_lock_pid_lru, lp, lp_lru);
				microuptime(&now);
				lp->lp_time = now.tv_sec;
				TAILQ_INSERT_TAIL(&nfs_lock_pid_lru, lp, lp_lru);
				error = 0;
				break;
			}
			/* ...but it's no longer valid */
			/* remove from hash, invalidate, and move to lru head */
			LIST_REMOVE(lp, lp_hash);
			lp->lp_valid = 0;
			TAILQ_REMOVE(&nfs_lock_pid_lru, lp, lp_lru);
			TAILQ_INSERT_HEAD(&nfs_lock_pid_lru, lp, lp_lru);
			lp = NULL;
			break;
		}

	/* if we didn't find it (valid), use any newly allocated one */
	if (!lp)
		lp = mlp;

	/* if we don't have an lp and we've been asked to add it */
	if ((error == ENOENT) && addflag && !lp) {
		/* scan lru list for invalid, stale entries to reuse/free */
		int lrucnt = 0;
		microuptime(&now);
		for (lplru = TAILQ_FIRST(&nfs_lock_pid_lru); lplru; lplru = lplru_next) {
			lplru_next = TAILQ_NEXT(lplru, lp_lru);
			if (lplru->lp_valid && (lplru->lp_time >= (now.tv_sec - 2))) {
				/*
				 * If the oldest LRU entry is relatively new, then don't
				 * bother scanning any further.
				 */
				break;
			}
			/* remove entry from LRU, and check if it's still in use */
			TAILQ_REMOVE(&nfs_lock_pid_lru, lplru, lp_lru);
			if (!lplru->lp_valid || !(plru = proc_find(lplru->lp_pid)) ||
			    timevalcmp(&lplru->lp_pid_start, &plru->p_start, !=)) {
				if (plru != PROC_NULL) {
					proc_rele(plru);
					plru = PROC_NULL;
				}
				/* no longer in use */
				LIST_REMOVE(lplru, lp_hash);
				if (!lp) {
					/* we'll reuse this one */
					lp = lplru;
				} else {
					/* queue it up for freeing */
					TAILQ_INSERT_HEAD(&nfs_lock_pid_free, lplru, lp_lru);
				}
			} else {
				/* still in use */
				if (plru != PROC_NULL) {
					proc_rele(plru);
					plru = PROC_NULL;
				}
				lplru->lp_time = now.tv_sec;
				TAILQ_INSERT_TAIL(&nfs_lock_pid_lru, lplru, lp_lru);
			}
			/* don't check too many entries at once */
			if (++lrucnt > 8)
				break;
		}
		if (!lp) {
			/* we need to allocate a new one */
			lck_mtx_unlock(nfs_lock_mutex);
			MALLOC(mlp, struct nfs_lock_pid *, sizeof(struct nfs_lock_pid),
				M_TEMP, M_WAITOK | M_ZERO);
			lck_mtx_lock(nfs_lock_mutex);
			if (mlp) /* make sure somebody hasn't already added this guy */
				goto loop;
			error = ENOMEM;
		}
	}
	if ((error == ENOENT) && addflag && lp) {
		/* (re)initialize nfs_lock_pid info */
		lp->lp_pid = pid;
		lp->lp_pid_start = p->p_start;
		/* insert pid in hash */
		LIST_INSERT_HEAD(NFS_LOCK_PID_HASH(lp->lp_pid), lp, lp_hash);
		lp->lp_valid = 1;
		lp->lp_time = now.tv_sec;
		TAILQ_INSERT_TAIL(&nfs_lock_pid_lru, lp, lp_lru);
		error = 0;
	}

	if ((mlp && (lp != mlp)) || TAILQ_FIRST(&nfs_lock_pid_free)) {
		lck_mtx_unlock(nfs_lock_mutex);
		if (mlp && (lp != mlp)) {
			/* we didn't need this one, so we can free it */
			FREE(mlp, M_TEMP);
		}
		/* free up any stale entries */
		while ((lp = TAILQ_FIRST(&nfs_lock_pid_free))) {
			TAILQ_REMOVE(&nfs_lock_pid_free, lp, lp_lru);
			FREE(lp, M_TEMP);
		}
		lck_mtx_lock(nfs_lock_mutex);
	}

	return (error);
}

#define MACH_MAX_TRIES 3

static int
send_request(LOCKD_MSG *msg, int interruptable)
{
	kern_return_t kr;
	int retries = 0;
	mach_port_t lockd_port = IPC_PORT_NULL;

	kr = host_get_lockd_port(host_priv_self(), &lockd_port);
	if (kr != KERN_SUCCESS || !IPC_PORT_VALID(lockd_port))
		return (ENOTSUP);

	do {
		/* In the kernel all mach messaging is interruptable */
		do {
			kr = lockd_request(
				lockd_port,
				msg->lm_version,
				msg->lm_flags,
				msg->lm_xid,
				msg->lm_fl.l_start,
				msg->lm_fl.l_len,
				msg->lm_fl.l_pid,
				msg->lm_fl.l_type,
				msg->lm_fl.l_whence,
				(uint32_t *)&msg->lm_addr,
				(uint32_t *)&msg->lm_cred,
				msg->lm_fh_len,
				msg->lm_fh);
			if (kr != KERN_SUCCESS)
				printf("lockd_request received %d!\n", kr);
		} while (!interruptable && kr == MACH_SEND_INTERRUPTED);
	} while (kr == MIG_SERVER_DIED && retries++ < MACH_MAX_TRIES);

	ipc_port_release_send(lockd_port);
	switch (kr) {
	case MACH_SEND_INTERRUPTED: 
		return (EINTR);
	default:
		/*
		 * Other MACH or MIG errors we will retry. Eventually
		 * we will call nfs_down and allow the user to disable 
		 * locking.
		 */
		return (EAGAIN);
	}
	return (kr);
}
				

/*
 * NFS advisory byte-level locks (client)
 */
int
nfs3_vnop_advlock(
	struct vnop_advlock_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		caddr_t a_id;
		int a_op;
		struct flock *a_fl;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx;
	proc_t p;
	LOCKD_MSG_REQUEST msgreq;
	LOCKD_MSG *msg;
	vnode_t vp;
	nfsnode_t np;
	int error, error2;
	int interruptable;
	struct flock *fl;
	struct nfsmount *nmp;
	struct nfs_vattr nvattr;
	off_t start, end;
	struct timeval now;
	int timeo, endtime, lastmsg, wentdown = 0;
	int lockpidcheck, nfsvers;
	struct sockaddr *saddr;
	struct timespec ts;

	ctx = ap->a_context;
	p = vfs_context_proc(ctx);
	vp = ap->a_vp;
	fl = ap->a_fl;
	np = VTONFS(vp);

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_flag & NFSMNT_NOLOCKS) {
		lck_mtx_unlock(&nmp->nm_lock);
		return (ENOTSUP);
	}
	nfsvers = nmp->nm_vers;
	lck_mtx_unlock(&nmp->nm_lock);

	/*
	 * The NLM protocol doesn't allow the server to return an error
	 * on ranges, so we do it.  Pre LFS (Large File Summit)
	 * standards required EINVAL for the range errors.  More recent
	 * standards use EOVERFLOW, but their EINVAL wording still
	 * encompasses these errors.
	 * Any code sensitive to this is either:
	 *  1) written pre-LFS and so can handle only EINVAL, or
	 *  2) written post-LFS and thus ought to be tolerant of pre-LFS
	 *     implementations.
	 * Since returning EOVERFLOW certainly breaks 1), we return EINVAL.
	 */
	if (fl->l_whence != SEEK_END) {
		if ((fl->l_whence != SEEK_CUR && fl->l_whence != SEEK_SET) ||
		    fl->l_start < 0 ||
		    (fl->l_len > 0 && fl->l_len - 1 > OFF_MAX - fl->l_start) ||
		    (fl->l_len < 0 && fl->l_start + fl->l_len < 0))
			return (EINVAL);
	}

	lck_mtx_lock(nfs_lock_mutex);

	/*
	 * Need to check if this process has successfully acquired an NFS lock before.
	 * If not, and this is an unlock request we can simply return success here.
	 */
	lockpidcheck = nfs_lock_pid_check(p, 0);
	lck_mtx_unlock(nfs_lock_mutex);
	if (lockpidcheck) {
		if (lockpidcheck != ENOENT)
			return (lockpidcheck);
		if ((ap->a_op == F_UNLCK) && nfs_lock_pid_hash_trusted)
			return (0);
	}

	/*
	 * The NFS Lock Manager protocol doesn't directly handle
	 * negative lengths or SEEK_END, so we need to normalize
	 * things here where we have all the info.
	 * (Note: SEEK_CUR is already adjusted for at this point)
	 */
	/* Convert the flock structure into a start and end. */
	switch (fl->l_whence) {
	case SEEK_SET:
	case SEEK_CUR:
		/*
		 * Caller is responsible for adding any necessary offset
		 * to fl->l_start when SEEK_CUR is used.
		 */
		start = fl->l_start;
		break;
	case SEEK_END:
		/* need to flush, and refetch attributes to make */
		/* sure we have the correct end of file offset   */
		error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
		if (error)
			return (error);
		NATTRINVALIDATE(np);
		if (np->n_flag & NMODIFIED) {
			nfs_unlock(np);
			error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1);
			if (error)
				return (error);
		} else
			nfs_unlock(np);

		error = nfs_getattr(np, &nvattr, ctx, 0);
		nfs_data_lock(np, NFS_NODE_LOCK_SHARED);
		if (!error)
			error = nfs_lock(np, NFS_NODE_LOCK_SHARED);
		if (error) {
			nfs_data_unlock(np);
			return (error);
		}
		start = np->n_size + fl->l_start;
		nfs_unlock(np);
		nfs_data_unlock(np);
		break;
	default:
		return (EINVAL);
	}
	if (fl->l_len == 0)
		end = -1;
	else if (fl->l_len > 0)
		end = start + fl->l_len - 1;
	else { /* l_len is negative */
		end = start - 1;
		start += fl->l_len;
	}
	if (start < 0)
		return (EINVAL);

	if ((nfsvers == NFS_VER2) &&
	    ((start >= 0x80000000) || (end >= 0x80000000)))
		return (EINVAL);

	/*
	 * Fill in the information structure.
	 * We set all values to zero with bzero to clear
	 * out any information in the sockaddr_storage 
	 * and nfs_filehandle contained in msgreq so that
	 * we will not leak extraneous information out of 
	 * the kernel when calling up to lockd via our mig
	 * generated routine.
	 */
	bzero(&msgreq, sizeof(msgreq));
	msg = &msgreq.lmr_msg;
	msg->lm_version = LOCKD_MSG_VERSION;
	msg->lm_flags = 0;

	msg->lm_fl = *fl;
	msg->lm_fl.l_start = start;
	if (end != -1)
		msg->lm_fl.l_len = end - start + 1;
	msg->lm_fl.l_pid = vfs_context_pid(ctx);

	if (ap->a_flags & F_WAIT)
		msg->lm_flags |= LOCKD_MSG_BLOCK;
	if (ap->a_op == F_GETLK)
		msg->lm_flags |= LOCKD_MSG_TEST;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);

	lck_mtx_lock(&nmp->nm_lock);
	saddr = mbuf_data(nmp->nm_nam);
	bcopy(saddr, &msg->lm_addr, min(sizeof msg->lm_addr, saddr->sa_len));
	msg->lm_fh_len = (nfsvers == NFS_VER2) ? NFSX_V2FH : np->n_fhsize;
	bcopy(np->n_fhp, msg->lm_fh, msg->lm_fh_len);
	if (nfsvers == NFS_VER3)
		msg->lm_flags |= LOCKD_MSG_NFSV3;
	cru2x(vfs_context_ucred(ctx), &msg->lm_cred);

	microuptime(&now);
	lastmsg = now.tv_sec - ((nmp->nm_tprintf_delay) - (nmp->nm_tprintf_initial_delay));
	interruptable = nmp->nm_flag & NFSMNT_INT;
	lck_mtx_unlock(&nmp->nm_lock);

	lck_mtx_lock(nfs_lock_mutex);

	/* allocate unique xid */
	msg->lm_xid = nfs_lockxid_get();
	nfs_lockdmsg_enqueue(&msgreq);

	timeo = 2;

	for (;;) {
		nfs_lockd_request_sent = 1;

		/* need to drop nfs_lock_mutex while calling send_request() */
		lck_mtx_unlock(nfs_lock_mutex);
		error = send_request(msg, interruptable);
		lck_mtx_lock(nfs_lock_mutex);
		if (error && error != EAGAIN)
			break;

		/*
		 * Always wait for an answer.  Not waiting for unlocks could
		 * cause a lock to be left if the unlock request gets dropped.
		 */

		/*
		 * Retry if it takes too long to get a response.
		 *
		 * The timeout numbers were picked out of thin air... they start
		 * at 2 and double each timeout with a max of 60 seconds.
		 *
		 * In order to maintain responsiveness, we pass a small timeout
		 * to msleep and calculate the timeouts ourselves.  This allows
		 * us to pick up on mount changes quicker.
		 */
wait_for_granted:
		error = EWOULDBLOCK;
		ts.tv_sec = 2;
		ts.tv_nsec = 0;
		microuptime(&now);
		endtime = now.tv_sec + timeo;
		while (now.tv_sec < endtime) {
			error = error2 = 0;
			if (!msgreq.lmr_answered)
				error = msleep(&msgreq, nfs_lock_mutex, PCATCH | PUSER, "lockd", &ts);
			if (msgreq.lmr_answered) {
				/*
				 * Note: it's possible to have a lock granted at
				 * essentially the same time that we get interrupted.
				 * Since the lock may be granted, we can't return an
				 * error from this request or we might not unlock the
				 * lock that's been granted.
				 */
				nmp = VTONMP(vp);
				if ((msgreq.lmr_errno == ENOTSUP) && nmp &&
				    (nmp->nm_state & NFSSTA_LOCKSWORK)) {
					/*
					 * We have evidence that locks work, yet lockd
					 * returned ENOTSUP.  This is probably because
					 * it was unable to contact the server's lockd
					 * to send it the request.
					 *
					 * Because we know locks work, we'll consider
					 * this failure to be a timeout.
					 */
					error = EWOULDBLOCK;
				} else {
					error = 0;
				}
				break;
			}
			if (error != EWOULDBLOCK)
				break;
			/* check that we still have our mount... */
			/* ...and that we still support locks */
			nmp = VTONMP(vp);
			if ((error2 = nfs_sigintr(nmp, NULL, vfs_context_thread(ctx), 0))) {
				error = error2;
				if (fl->l_type == F_UNLCK)
					printf("nfs_vnop_advlock: aborting unlock request, error %d\n", error);
				break;
			}
			lck_mtx_lock(&nmp->nm_lock);
			if (nmp->nm_flag & NFSMNT_NOLOCKS) {
				lck_mtx_unlock(&nmp->nm_lock);
				break;
			}
			interruptable = nmp->nm_flag & NFSMNT_INT;
			lck_mtx_unlock(&nmp->nm_lock);
			microuptime(&now);
		}
		if (error) {
			/* check that we still have our mount... */
			nmp = VTONMP(vp);
			if ((error2 = nfs_sigintr(nmp, NULL, vfs_context_thread(ctx), 0))) {
				error = error2;
				if (error2 != EINTR) {
					if (fl->l_type == F_UNLCK)
						printf("nfs_vnop_advlock: aborting unlock request, error %d\n", error);
					break;
				}
			}
			/* ...and that we still support locks */
			lck_mtx_lock(&nmp->nm_lock);
			if (nmp->nm_flag & NFSMNT_NOLOCKS) {
				if (error == EWOULDBLOCK)
					error = ENOTSUP;
				lck_mtx_unlock(&nmp->nm_lock);
				break;
			}
			interruptable = nmp->nm_flag & NFSMNT_INT;
			if (error != EWOULDBLOCK) {
				lck_mtx_unlock(&nmp->nm_lock);
				/*
				 * We're going to bail on this request.
				 * If we were a blocked lock request, send a cancel.
				 */
				if ((msgreq.lmr_errno == EINPROGRESS) &&
				    !(msg->lm_flags & LOCKD_MSG_CANCEL)) {
					/* set this request up as a cancel */
					msg->lm_flags |= LOCKD_MSG_CANCEL;
					nfs_lockdmsg_dequeue(&msgreq);
					msg->lm_xid = nfs_lockxid_get();
					nfs_lockdmsg_enqueue(&msgreq);
					msgreq.lmr_saved_errno = error;
					msgreq.lmr_errno = 0;
					msgreq.lmr_answered = 0;
					/* reset timeout */
					timeo = 2;
					/* send cancel request */
					continue;
				}
				break;
			}

			/* warn if we're not getting any response */
			microuptime(&now);
			if ((msgreq.lmr_errno != EINPROGRESS) &&
			    (nmp->nm_tprintf_initial_delay != 0) &&
			    ((lastmsg + nmp->nm_tprintf_delay) < now.tv_sec)) {
				lck_mtx_unlock(&nmp->nm_lock);
				lastmsg = now.tv_sec;
				nfs_down(nmp, vfs_context_thread(ctx), 0, NFSSTA_LOCKTIMEO, "lockd not responding");
				wentdown = 1;
			} else
				lck_mtx_unlock(&nmp->nm_lock);

			if (msgreq.lmr_errno == EINPROGRESS) {
				/*
				 * We've got a blocked lock request that we are
				 * going to retry.  First, we'll want to try to
				 * send a cancel for the previous request.
				 *
				 * Clear errno so if we don't get a response
				 * to the resend we'll call nfs_down().
				 * Also reset timeout because we'll expect a
				 * quick response to the cancel/resend (even if
				 * it is NLM_BLOCKED).
				 */
				msg->lm_flags |= LOCKD_MSG_CANCEL;
				nfs_lockdmsg_dequeue(&msgreq);
				msg->lm_xid = nfs_lockxid_get();
				nfs_lockdmsg_enqueue(&msgreq);
				msgreq.lmr_saved_errno = msgreq.lmr_errno;
				msgreq.lmr_errno = 0;
				msgreq.lmr_answered = 0;
				timeo = 2;
				/* send cancel then resend request */
				continue;
			}
			/*
			 * We timed out, so we will resend the request.
			 */
			timeo *= 2;
			if (timeo > 60)
				timeo = 60;
			/* resend request */
			continue;
		}

		/* we got a reponse, so the server's lockd is OK */
		nfs_up(VTONMP(vp), vfs_context_thread(ctx), NFSSTA_LOCKTIMEO,
			wentdown ? "lockd alive again" : NULL);
		wentdown = 0;

		if (msgreq.lmr_errno == EINPROGRESS) {
			/* got NLM_BLOCKED response */
			/* need to wait for NLM_GRANTED */
			timeo = 60;
			msgreq.lmr_answered = 0;
			goto wait_for_granted;
		}

		if ((msg->lm_flags & LOCKD_MSG_CANCEL) &&
		    (msgreq.lmr_saved_errno == EINPROGRESS)) {
			/*
			 * We just got a successful reply to the
			 * cancel of the previous blocked lock request.
			 * Now, go ahead and resend the request.
			 */
			msg->lm_flags &= ~LOCKD_MSG_CANCEL;
			nfs_lockdmsg_dequeue(&msgreq);
			msg->lm_xid = nfs_lockxid_get();
			nfs_lockdmsg_enqueue(&msgreq);
			msgreq.lmr_saved_errno = 0;
			msgreq.lmr_errno = 0;
			msgreq.lmr_answered = 0;
			timeo = 2;
			/* resend request */
			continue;
		}

		if ((msg->lm_flags & LOCKD_MSG_TEST) && msgreq.lmr_errno == 0) {
			if (msg->lm_fl.l_type != F_UNLCK) {
				fl->l_type = msg->lm_fl.l_type;
				fl->l_pid = msg->lm_fl.l_pid;
				fl->l_start = msg->lm_fl.l_start;
				fl->l_len = msg->lm_fl.l_len;
				fl->l_whence = SEEK_SET;
			} else
				fl->l_type = F_UNLCK;
		}

		/*
		 * If the blocked lock request was cancelled.
		 * Restore the error condition from when we
		 * originally bailed on the request.
		 */
		if (msg->lm_flags & LOCKD_MSG_CANCEL) {
			msg->lm_flags &= ~LOCKD_MSG_CANCEL;
			error = msgreq.lmr_saved_errno;
		} else
			error = msgreq.lmr_errno;

		nmp = VTONMP(vp);
		if ((error == ENOTSUP) && nmp && !(nmp->nm_state & NFSSTA_LOCKSWORK)) {
			/*
			 * We have NO evidence that locks work and lockd
			 * returned ENOTSUP.  Let's take this as a hint
			 * that locks aren't supported and disable them
			 * for this mount.
			 */
			lck_mtx_lock(&nmp->nm_lock);
			nmp->nm_flag |= NFSMNT_NOLOCKS;
			nmp->nm_state &= ~NFSSTA_LOCKTIMEO;
			lck_mtx_unlock(&nmp->nm_lock);
			printf("lockd returned ENOTSUP, disabling locks for nfs server: %s\n",
				vfs_statfs(nmp->nm_mountp)->f_mntfromname);
		}
		if (!error) {
			/* record that NFS file locking has worked on this mount */
			if (nmp) {
				lck_mtx_lock(&nmp->nm_lock);
				if (!(nmp->nm_state & NFSSTA_LOCKSWORK))
					nmp->nm_state |= NFSSTA_LOCKSWORK;
				lck_mtx_unlock(&nmp->nm_lock);
			}
			/*
			 * If we successfully acquired a lock, make sure this pid
			 * is in the nfs_lock_pid hash table so we know we can't
			 * short-circuit unlock requests.
			 */
			if ((lockpidcheck == ENOENT) &&
			    ((ap->a_op == F_SETLK) || (ap->a_op == F_SETLKW))) {
				error = nfs_lock_pid_check(p, 1);
				if (error) {
					/*
					 * We couldn't add the pid to the table,
					 * so we can no longer trust that a pid
					 * not in the table has no locks.
					 */
					nfs_lock_pid_hash_trusted = 0;
					printf("nfs_vnop_advlock: pid add failed - no longer trusted\n");
				}
			}
		}
		break;
	}

	nfs_lockdmsg_dequeue(&msgreq);

	lck_mtx_unlock(nfs_lock_mutex);

	return (error);
}

/*
 * nfslockdans --
 *      NFS advisory byte-level locks answer from the lock daemon.
 */
int
nfslockdans(proc_t p, struct lockd_ans *ansp)
{
	LOCKD_MSG_REQUEST *msgreq;
	int error;

	/* Let root make this call. */
	error = proc_suser(p);
	if (error)
		return (error);

	/* the version should match, or we're out of sync */
	if (ansp->la_version != LOCKD_ANS_VERSION)
		return (EINVAL);

	lck_mtx_lock(nfs_lock_mutex);

	/* try to find the lockd message by transaction id (cookie) */
	msgreq = nfs_lockdmsg_find_by_xid(ansp->la_xid);
	if (ansp->la_flags & LOCKD_ANS_GRANTED) {
		/*
		 * We can't depend on the granted message having our cookie,
		 * so we check the answer against the lockd message found.
		 * If no message was found or it doesn't match the answer,
		 * we look for the lockd message by the answer's lock info.
		 */
		if (!msgreq || nfs_lockdmsg_compare_to_answer(msgreq, ansp))
			msgreq = nfs_lockdmsg_find_by_answer(ansp);
		/*
		 * We need to make sure this request isn't being cancelled
		 * If it is, we don't want to accept the granted message.
		 */
		if (msgreq && (msgreq->lmr_msg.lm_flags & LOCKD_MSG_CANCEL))
			msgreq = NULL;
	}
	if (!msgreq) {
		lck_mtx_unlock(nfs_lock_mutex);
		return (EPIPE);
	}

	msgreq->lmr_errno = ansp->la_errno;
	if ((msgreq->lmr_msg.lm_flags & LOCKD_MSG_TEST) && msgreq->lmr_errno == 0) {
		if (ansp->la_flags & LOCKD_ANS_LOCK_INFO) {
			if (ansp->la_flags & LOCKD_ANS_LOCK_EXCL)
				msgreq->lmr_msg.lm_fl.l_type = F_WRLCK;
			else
				msgreq->lmr_msg.lm_fl.l_type = F_RDLCK;
			msgreq->lmr_msg.lm_fl.l_pid = ansp->la_pid;
			msgreq->lmr_msg.lm_fl.l_start = ansp->la_start;
			msgreq->lmr_msg.lm_fl.l_len = ansp->la_len;
		} else {
			msgreq->lmr_msg.lm_fl.l_type = F_UNLCK;
		}
	}

	msgreq->lmr_answered = 1;
	lck_mtx_unlock(nfs_lock_mutex);
	wakeup(msgreq);

	return (0);
}

