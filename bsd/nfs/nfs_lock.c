/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/lockf.h>		/* for hz */ /* Must come after sys/malloc.h */
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <kern/thread_act.h>

#include <machine/limits.h>

#include <net/if.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_lock.h>
#include <nfs/nlminfo.h>

#define OFF_MAX QUAD_MAX

uint64_t nfsadvlocks = 0;
struct timeval nfsadvlock_longest = {0, 0};
struct timeval nfsadvlocks_time = {0, 0};

pid_t nfslockdpid = 0;
struct file *nfslockdfp = 0;
int nfslockdwaiting = 0;
int nfslockdfifowritten = 0;
int nfslockdfifolock = 0;
#define NFSLOCKDFIFOLOCK_LOCKED	1
#define NFSLOCKDFIFOLOCK_WANT	2

/*
 * XXX
 * We have to let the process know if the call succeeded.  I'm using an extra
 * field in the uu_nlminfo field in the uthread structure, as it is already for
 * lockd stuff.
 */

/*
 * nfs_advlock --
 *      NFS advisory byte-level locks.
 */
int
nfs_dolock(struct vop_advlock_args *ap)
/* struct vop_advlock_args {
        struct vnodeop_desc *a_desc;
        struct vnode *a_vp;
        caddr_t a_id;
        int a_op;
        struct flock *a_fl;
        int a_flags;
}; */
{
	LOCKD_MSG msg;
	struct nameidata nd;
	struct vnode *vp, *wvp;
	struct nfsnode *np;
	int error, error1;
	struct flock *fl;
	int fmode, ioflg;
	struct proc *p;
        struct uthread *ut;
	struct timeval elapsed;
	struct nfsmount *nmp;
	struct vattr vattr;
	off_t start, end;

        ut = get_bsdthread_info(current_act());
	p = current_proc();

	vp = ap->a_vp;
	fl = ap->a_fl;
	np = VTONFS(vp);

	nmp = VFSTONFS(vp->v_mount);
	if (!nmp)
		return (ENXIO);
	if (nmp->nm_flag & NFSMNT_NOLOCKS)
		return (EOPNOTSUPP);

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
	/*
	 * If daemon is running take a ref on its fifo
	 */
	if (!nfslockdfp || !(wvp = (struct vnode *)nfslockdfp->f_data)) {
		if (!nfslockdwaiting)
			return (EOPNOTSUPP);
		/*
		 * Don't wake lock daemon if it hasn't been started yet and
		 * this is an unlock request (since we couldn't possibly
		 * actually have a lock on the file).  This could be an
		 * uninformed unlock request due to closef()'s behavior of doing
		 * unlocks on all files if a process has had a lock on ANY file.
		 */
		if (!nfslockdfp && (fl->l_type == F_UNLCK))
			return (EINVAL);
		/* wake up lock daemon */
		(void)wakeup((void *)&nfslockdwaiting);
		/* wait on nfslockdfp for a while to allow daemon to start */
		tsleep((void *)&nfslockdfp, PCATCH | PUSER, "lockd", 60*hz);
		/* check for nfslockdfp and f_data */
		if (!nfslockdfp || !(wvp = (struct vnode *)nfslockdfp->f_data))
			return (EOPNOTSUPP);
	}
	VREF(wvp);
	/*
	 * if there is no nfsowner table yet, allocate one.
	 */
	if (ut->uu_nlminfo == NULL) {
		if (ap->a_op == F_UNLCK) {
			vrele(wvp);
			return (0);
		}
		MALLOC(ut->uu_nlminfo, struct nlminfo *,
			sizeof(struct nlminfo), M_LOCKF, M_WAITOK | M_ZERO);
		ut->uu_nlminfo->pid_start = p->p_stats->p_start;
	}
	/*
	 * Fill in the information structure.
	 */
	msg.lm_version = LOCKD_MSG_VERSION;
	msg.lm_msg_ident.pid = p->p_pid;
	msg.lm_msg_ident.ut = ut;
	msg.lm_msg_ident.pid_start = ut->uu_nlminfo->pid_start;
	msg.lm_msg_ident.msg_seq = ++(ut->uu_nlminfo->msg_seq);

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
		if (np->n_flag & NMODIFIED) {
			np->n_xid = 0;
			error = nfs_vinvalbuf(vp, V_SAVE, p->p_ucred, p, 1);
			if (error) {
				vrele(wvp);
				return (error);
			}
		}
		np->n_xid = 0;
		error = VOP_GETATTR(vp, &vattr, p->p_ucred, p);
		if (error) {
			vrele(wvp);
			return (error);
		}
		start = np->n_size + fl->l_start;
		break;
	default:
		vrele(wvp);
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
	if (start < 0) {
		vrele(wvp);
		return (EINVAL);
	}

	msg.lm_fl = *fl;
	msg.lm_fl.l_start = start;
	if (end != -1)
		msg.lm_fl.l_len = end - start + 1;

	msg.lm_wait = ap->a_flags & F_WAIT;
	msg.lm_getlk = ap->a_op == F_GETLK;

	nmp = VFSTONFS(vp->v_mount);
	if (!nmp) {
		vrele(wvp);
		return (ENXIO);
	}

	bcopy(mtod(nmp->nm_nam, struct sockaddr *), &msg.lm_addr,
	      min(sizeof msg.lm_addr,
		  mtod(nmp->nm_nam, struct sockaddr *)->sa_len));
	msg.lm_fh_len = NFS_ISV3(vp) ? VTONFS(vp)->n_fhsize : NFSX_V2FH;
	bcopy(VTONFS(vp)->n_fhp, msg.lm_fh, msg.lm_fh_len);
	msg.lm_nfsv3 = NFS_ISV3(vp);
	cru2x(p->p_ucred, &msg.lm_cred);

	microuptime(&ut->uu_nlminfo->nlm_lockstart);

	fmode = FFLAGS(O_WRONLY);
	if ((error = VOP_OPEN(wvp, fmode, kernproc->p_ucred, p))) {
		vrele(wvp);
		return (error);
	}
	++wvp->v_writecount;

#define IO_NOMACCHECK 0;
	ioflg = IO_UNIT | IO_NOMACCHECK;
	for (;;) {
		VOP_LEASE(wvp, p, kernproc->p_ucred, LEASE_WRITE);

		while (nfslockdfifolock & NFSLOCKDFIFOLOCK_LOCKED) {
			nfslockdfifolock |= NFSLOCKDFIFOLOCK_WANT;
			if (tsleep((void *)&nfslockdfifolock, PCATCH | PUSER, "lockdfifo", 20*hz))
				break;
		}
		nfslockdfifolock |= NFSLOCKDFIFOLOCK_LOCKED;

		error = vn_rdwr(UIO_WRITE, wvp, (caddr_t)&msg, sizeof(msg), 0,
		    UIO_SYSSPACE, ioflg, kernproc->p_ucred, NULL, p);

		nfslockdfifowritten = 1;

		nfslockdfifolock &= ~NFSLOCKDFIFOLOCK_LOCKED;
		if (nfslockdfifolock & NFSLOCKDFIFOLOCK_WANT) {
			nfslockdfifolock &= ~NFSLOCKDFIFOLOCK_WANT;
			wakeup((void *)&nfslockdfifolock);
		}
		/* wake up lock daemon */
		if (nfslockdwaiting)
			(void)wakeup((void *)&nfslockdwaiting);

		if (error && (((ioflg & IO_NDELAY) == 0) || error != EAGAIN)) {
			break;
		}
		/*
		 * If we're locking a file, wait for an answer.  Unlocks succeed
		 * immediately.
		 */
		if (fl->l_type == F_UNLCK)
			/*
			 * XXX this isn't exactly correct.  The client side
			 * needs to continue sending it's unlock until
			 * it gets a response back.
			 */
			break;

		/*
		 * retry after 20 seconds if we haven't gotten a response yet.
		 * This number was picked out of thin air... but is longer
		 * then even a reasonably loaded system should take (at least
		 * on a local network).  XXX Probably should use a back-off
		 * scheme.
		 */
		if ((error = tsleep((void *)ut->uu_nlminfo,
				    PCATCH | PUSER, "lockd", 20*hz)) != 0) {
			if (error == EWOULDBLOCK) {
				/*
				 * We timed out, so we rewrite the request
				 * to the fifo, but only if it isn't already
				 * full.
				 */
				ioflg |= IO_NDELAY;
				continue;
			}

			break;
		}

		if (msg.lm_getlk && ut->uu_nlminfo->retcode == 0) {
			if (ut->uu_nlminfo->set_getlk) {
				fl->l_pid = ut->uu_nlminfo->getlk_pid;
				fl->l_start = ut->uu_nlminfo->getlk_start;
				fl->l_len = ut->uu_nlminfo->getlk_len;
				fl->l_whence = SEEK_SET;
			} else {
				fl->l_type = F_UNLCK;
			}
		}
		error = ut->uu_nlminfo->retcode;
		break;
	}

	/* XXX stats */
	nfsadvlocks++;
	microuptime(&elapsed);
	timevalsub(&elapsed, &ut->uu_nlminfo->nlm_lockstart);
	if (timevalcmp(&elapsed, &nfsadvlock_longest, >))
		nfsadvlock_longest = elapsed;
	timevaladd(&nfsadvlocks_time, &elapsed);
	timerclear(&ut->uu_nlminfo->nlm_lockstart);

	error1 = vn_close(wvp, FWRITE, kernproc->p_ucred, p);
	/* prefer any previous 'error' to our vn_close 'error1'. */
	return (error != 0 ? error : error1);
}

/*
 * nfslockdans --
 *      NFS advisory byte-level locks answer from the lock daemon.
 */
int
nfslockdans(struct proc *p, struct lockd_ans *ansp)
{
	struct proc *targetp;
	struct uthread *targetut, *uth;
	int error;

	/*
	 * Let root, or someone who once was root (lockd generally
	 * switches to the daemon uid once it is done setting up) make
	 * this call.
	 *
	 * XXX This authorization check is probably not right.
	 */
	if ((error = suser(p->p_ucred, &p->p_acflag)) != 0 &&
	    p->p_cred->p_svuid != 0)
		return (error);

	/* the version should match, or we're out of sync */
	if (ansp->la_vers != LOCKD_ANS_VERSION)
		return (EINVAL);

	/* Find the process & thread */
	if ((targetp = pfind(ansp->la_msg_ident.pid)) == NULL)
		return (ESRCH);
	targetut = ansp->la_msg_ident.ut;
	TAILQ_FOREACH(uth, &targetp->p_uthlist, uu_list) {
		if (uth == targetut)
			break;
	}
	/*
	 * Verify the pid hasn't been reused (if we can), and it isn't waiting
	 * for an answer from a more recent request.  We return an EPIPE if
	 * the match fails, because we've already used ESRCH above, and this
	 * is sort of like writing on a pipe after the reader has closed it.
	 * If only the seq# is off, don't return an error just return.  It could
	 * just be a response to a retransmitted request.
	 */
	if (uth == NULL || uth != targetut || targetut->uu_nlminfo == NULL)
		return (EPIPE);
	if (ansp->la_msg_ident.msg_seq != -1) {
		if (timevalcmp(&targetut->uu_nlminfo->pid_start,
		               &ansp->la_msg_ident.pid_start, !=))
			return (EPIPE);
		if (targetut->uu_nlminfo->msg_seq != ansp->la_msg_ident.msg_seq)
			return (0);
	}

	/* Found the thread, so set its return errno and wake it up. */

	targetut->uu_nlminfo->retcode = ansp->la_errno;
	targetut->uu_nlminfo->set_getlk = ansp->la_getlk_set;
	targetut->uu_nlminfo->getlk_pid = ansp->la_getlk_pid;
	targetut->uu_nlminfo->getlk_start = ansp->la_getlk_start;
	targetut->uu_nlminfo->getlk_len = ansp->la_getlk_len;

	(void)wakeup((void *)targetut->uu_nlminfo);

	return (0);
}

/*
 * nfslockdfd --
 *      NFS advisory byte-level locks: fifo file# from the lock daemon.
 */
int
nfslockdfd(struct proc *p, int fd)
{
	int error;
	struct file *fp, *ofp;

	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);
	if (fd < 0) {
		fp = 0;
	} else {
		error = getvnode(p, fd, &fp);
		if (error)
			return (error);
		(void)fref(fp);
	}
	ofp = nfslockdfp;
	nfslockdfp = fp;
	if (ofp)
		(void)frele(ofp);
	nfslockdpid = nfslockdfp ? p->p_pid : 0;
	(void)wakeup((void *)&nfslockdfp);
	return (0);
}

/*
 * nfslockdwait --
 *      lock daemon waiting for lock request
 */
int
nfslockdwait(struct proc *p)
{
	int error;
	struct file *fp, *ofp;

	if (p->p_pid != nfslockdpid) {
		error = suser(p->p_ucred, &p->p_acflag);
		if (error)
			return (error);
	}
	if (nfslockdwaiting)
		return (EBUSY);
	if (nfslockdfifowritten) {
		nfslockdfifowritten = 0;
		return (0);
	}

	nfslockdwaiting = 1;
	tsleep((void *)&nfslockdwaiting, PCATCH | PUSER, "lockd", 0);
	nfslockdwaiting = 0;

	return (0);
}
