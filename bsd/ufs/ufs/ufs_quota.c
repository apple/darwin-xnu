/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1990, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Robert Elz at The University of Melbourne.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *	@(#)ufs_quota.c	8.5 (Berkeley) 5/20/95
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/proc.h>	
#include <sys/kauth.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/quota.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

/*
 * Quota name to error message mapping.
 */
static char *quotatypes[] = INITQFNAMES;

/*
 * Set up the quotas for an inode.
 *
 * This routine completely defines the semantics of quotas.
 * If other criterion want to be used to establish quotas, the
 * MAXQUOTAS value in quotas.h should be increased, and the
 * additional dquots set up here.
 */
int
getinoquota(ip)
	register struct inode *ip;
{
	struct ufsmount *ump;
	struct vnode *vp = ITOV(ip);
	int error;

	ump = VFSTOUFS(vp->v_mount);
	/*
	 * Set up the user quota based on file uid.
	 * EINVAL means that quotas are not enabled.
	 */
	if (ip->i_dquot[USRQUOTA] == NODQUOT &&
	    (error =
		dqget(ip->i_uid, &ump->um_qfiles[USRQUOTA], USRQUOTA, &ip->i_dquot[USRQUOTA])) &&
	    error != EINVAL)
		return (error);
	/*
	 * Set up the group quota based on file gid.
	 * EINVAL means that quotas are not enabled.
	 */
	if (ip->i_dquot[GRPQUOTA] == NODQUOT &&
	    (error =
		dqget(ip->i_gid, &ump->um_qfiles[GRPQUOTA], GRPQUOTA, &ip->i_dquot[GRPQUOTA])) &&
	    error != EINVAL)
		return (error);
	return (0);
}

/*
 * Update disk usage, and take corrective action.
 */
int
chkdq(struct inode *ip, int64_t change, kauth_cred_t cred, int flags)
{
	register struct dquot *dq;
	register int i;
	int64_t ncurbytes;
	int error;
	struct proc *p;

#if DIAGNOSTIC
	if ((flags & CHOWN) == 0)
		chkdquot(ip);
#endif
	if (change == 0)
		return (0);
	if (change < 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = ip->i_dquot[i]) == NODQUOT)
				continue;
			dqlock(dq);

			ncurbytes = dq->dq_curbytes + change;
			if (ncurbytes >= 0)
				dq->dq_curbytes = ncurbytes;
			else
				dq->dq_curbytes = 0;
			dq->dq_flags &= ~DQ_BLKS;
			dq->dq_flags |= DQ_MOD;

			dqunlock(dq);
		}
		return (0);
	}
#warning "hack for no cred passed to chkdq()"
	p = current_proc();
	if (cred == NOCRED)
		cred = proc_ucred(kernproc);
	if ((flags & FORCE) == 0 && (suser(cred, NULL) || (proc_forcequota(p)))) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = ip->i_dquot[i]) == NODQUOT)
				continue;
			if ( (error = chkdqchg(ip, change, cred, i)) )
				return (error);
		}
	}
	for (i = 0; i < MAXQUOTAS; i++) {
		if ((dq = ip->i_dquot[i]) == NODQUOT)
			continue;
		dqlock(dq);

		dq->dq_curbytes += change;
		dq->dq_flags |= DQ_MOD;

		dqunlock(dq);
	}
	return (0);
}

/*
 * Check for a valid change to a users allocation.
 * Issue an error message if appropriate.
 */
int
chkdqchg(struct inode *ip, int64_t change, kauth_cred_t cred, int type)
{
	register struct dquot *dq = ip->i_dquot[type];
	u_int64_t ncurbytes;

	dqlock(dq);

	ncurbytes = dq->dq_curbytes + change;
	/*
	 * If user would exceed their hard limit, disallow space allocation.
	 */
	if (ncurbytes >= dq->dq_bhardlimit && dq->dq_bhardlimit) {
		if ((dq->dq_flags & DQ_BLKS) == 0 &&
		    ip->i_uid == kauth_cred_getuid(cred)) {
#if 1
			printf("\n%s: write failed, %s disk limit reached\n",
			    ITOV(ip)->v_mount->mnt_vfsstat.f_mntonname,
			    quotatypes[type]);
#endif
			dq->dq_flags |= DQ_BLKS;
		}
		dqunlock(dq);

		return (EDQUOT);
	}
	/*
	 * If user is over their soft limit for too long, disallow space
	 * allocation. Reset time limit as they cross their soft limit.
	 */
	if (ncurbytes >= dq->dq_bsoftlimit && dq->dq_bsoftlimit) {
		struct timeval tv;

		microtime(&tv);
		if (dq->dq_curbytes < dq->dq_bsoftlimit) {
			dq->dq_btime = tv.tv_sec +
			    VFSTOUFS(ITOV(ip)->v_mount)->um_qfiles[type].qf_btime;
#if 1
			if (ip->i_uid == kauth_cred_getuid(cred))
				printf("\n%s: warning, %s %s\n",
				    ITOV(ip)->v_mount->mnt_vfsstat.f_mntonname,
				    quotatypes[type], "disk quota exceeded");
#endif
			dqunlock(dq);

			return (0);
		}
		if (tv.tv_sec > dq->dq_btime) {
			if ((dq->dq_flags & DQ_BLKS) == 0 &&
			    ip->i_uid == kauth_cred_getuid(cred)) {
#if 1
				printf("\n%s: write failed, %s %s\n",
				    ITOV(ip)->v_mount->mnt_vfsstat.f_mntonname,
				    quotatypes[type],
				    "disk quota exceeded for too long");
#endif
				dq->dq_flags |= DQ_BLKS;
			}
			dqunlock(dq);

			return (EDQUOT);
		}
	}
	dqunlock(dq);

	return (0);
}

/*
 * Check the inode limit, applying corrective action.
 */
int
chkiq(struct inode *ip, long change, kauth_cred_t cred, int flags)
{
	register struct dquot *dq;
	register int i;
	int ncurinodes, error;
	struct proc *p;

#if DIAGNOSTIC
	if ((flags & CHOWN) == 0)
		chkdquot(ip);
#endif
	if (change == 0)
		return (0);
	if (change < 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = ip->i_dquot[i]) == NODQUOT)
				continue;
			dqlock(dq);

			ncurinodes = dq->dq_curinodes + change;
			if (ncurinodes >= 0)
				dq->dq_curinodes = ncurinodes;
			else
				dq->dq_curinodes = 0;
			dq->dq_flags &= ~DQ_INODS;
			dq->dq_flags |= DQ_MOD;

			dqunlock(dq);
		}
		return (0);
	}
#warning "hack for no cred passed to chkiq()"
	p = current_proc();
	if (cred == NOCRED)
		cred = proc_ucred(kernproc);
	if ((flags & FORCE) == 0 && (suser(cred, NULL) || (proc_forcequota(p)))) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = ip->i_dquot[i]) == NODQUOT)
				continue;
			if ( (error = chkiqchg(ip, change, cred, i)) )
				return (error);
		}
	}
	for (i = 0; i < MAXQUOTAS; i++) {
		if ((dq = ip->i_dquot[i]) == NODQUOT)
			continue;
		dqlock(dq);

		dq->dq_curinodes += change;
		dq->dq_flags |= DQ_MOD;

		dqunlock(dq);
	}
	return (0);
}

/*
 * Check for a valid change to a users allocation.
 * Issue an error message if appropriate.
 */
int
chkiqchg(struct inode *ip, long change, kauth_cred_t cred, int type)
{
	register struct dquot *dq = ip->i_dquot[type];
	long ncurinodes;

	dqlock(dq);

	ncurinodes = dq->dq_curinodes + change;
	/*
	 * If user would exceed their hard limit, disallow inode allocation.
	 */
	if (ncurinodes >= dq->dq_ihardlimit && dq->dq_ihardlimit) {
		if ((dq->dq_flags & DQ_INODS) == 0 &&
		    ip->i_uid == kauth_cred_getuid(cred)) {
#if 1
			printf("\n%s: write failed, %s inode limit reached\n",
			    ITOV(ip)->v_mount->mnt_vfsstat.f_mntonname,
			    quotatypes[type]);
#endif
			dq->dq_flags |= DQ_INODS;
		}
		dqunlock(dq);

		return (EDQUOT);
	}
	/*
	 * If user is over their soft limit for too long, disallow inode
	 * allocation. Reset time limit as they cross their soft limit.
	 */
	if (ncurinodes >= dq->dq_isoftlimit && dq->dq_isoftlimit) {
		struct timeval tv;

		microtime(&tv);
		if (dq->dq_curinodes < dq->dq_isoftlimit) {
			dq->dq_itime = tv.tv_sec +
			    VFSTOUFS(ITOV(ip)->v_mount)->um_qfiles[type].qf_itime;
#if 1
			if (ip->i_uid == kauth_cred_getuid(cred))
				printf("\n%s: warning, %s %s\n",
				    ITOV(ip)->v_mount->mnt_vfsstat.f_mntonname,
				    quotatypes[type], "inode quota exceeded");
#endif
			dqunlock(dq);

			return (0);
		}
		if (tv.tv_sec > dq->dq_itime) {
			if ((dq->dq_flags & DQ_INODS) == 0 &&
			    ip->i_uid == kauth_cred_getuid(cred)) {
#if 1
				printf("\n%s: write failed, %s %s\n",
				    ITOV(ip)->v_mount->mnt_vfsstat.f_mntonname,
				    quotatypes[type],
				    "inode quota exceeded for too long");
#endif
				dq->dq_flags |= DQ_INODS;
			}
			dqunlock(dq);

			return (EDQUOT);
		}
	}
	dqunlock(dq);

	return (0);
}

#if DIAGNOSTIC
/*
 * On filesystems with quotas enabled, it is an error for a file to change
 * size and not to have a dquot structure associated with it.
 */
void
chkdquot(ip)
	register struct inode *ip;
{
	struct ufsmount *ump = VFSTOUFS(ITOV(ip)->v_mount);
	register int i;

	for (i = 0; i < MAXQUOTAS; i++) {
	        if (ump->um_qfiles[i].qf_vp == NULLVP)
			continue;
		if (ip->i_dquot[i] == NODQUOT) {
			vprint("chkdquot: missing dquot", ITOV(ip));
			panic("missing dquot");
		}
	}
}
#endif

/*
 * Code to process quotactl commands.
 */


struct ufs_quotaon_cargs {
        int	error;
};


static int
ufs_quotaon_callback(struct vnode *vp, void *cargs)
{
	struct ufs_quotaon_cargs *args;

	args = (struct ufs_quotaon_cargs *)cargs;

	if ( (args->error = getinoquota(VTOI(vp))) )
	        return (VNODE_RETURNED_DONE);

	return (VNODE_RETURNED);
}


/*
 * Q_QUOTAON - set up a quota file for a particular file system.
 */
int
quotaon(context, mp, type, fnamep)
	vfs_context_t context;
	struct mount *mp;
	register int type;
	caddr_t fnamep;
{
	struct ufsmount *ump = VFSTOUFS(mp);
	struct quotafile *qfp;
	struct vnode *vp;
	int error = 0;
	struct ufs_quotaon_cargs args;

	qfp = &ump->um_qfiles[type];

	if ( (qf_get(qfp, QTF_OPENING)) )
	        return (0);
	
	error = vnode_open(fnamep, FREAD|FWRITE, 0, 0, &vp, NULL);
	if (error) {
	        goto out;
	}
	if (!vnode_isreg(vp)) {
		(void) vnode_close(vp, FREAD|FWRITE, NULL);
		error = EACCES;
		goto out;
	}
	vfs_setflags(mp, (uint64_t)((unsigned int)MNT_QUOTA));
	vnode_setnoflush(vp);
	/*
	 * Save the credential of the process that turned on quotas.
	 */
	qfp->qf_vp = vp;
	qfp->qf_cred = vfs_context_ucred(context);
	kauth_cred_ref(qfp->qf_cred);

	/*
	 * Finish initializing the quota file
	 */
	if ( (error = dqfileopen(&ump->um_qfiles[type], type)) ) {
                (void) vnode_close(vp, FREAD|FWRITE, NULL);

		kauth_cred_rele(qfp->qf_cred);
		qfp->qf_cred = NOCRED;
                qfp->qf_vp = NULLVP;
                goto out;
        }
        qf_put(qfp, QTF_OPENING);

	/*
	 * Search vnodes associated with this mount point,
	 * adding references to quota file being opened.
	 * NB: only need to add dquot's for inodes being modified.
	 *
	 * ufs_quota_callback will be called for each vnode open for
	 * 'write' (VNODE_WRITEABLE) hung off of this mount point
	 * the vnode will be in an 'unbusy' state (VNODE_WAIT) and 
	 * properly referenced and unreferenced around the callback
	 */
	args.error = 0;

	vnode_iterate(mp, VNODE_WRITEABLE | VNODE_WAIT, ufs_quotaon_callback, (void *)&args);
	
	error = args.error;

	if (error)
		quotaoff(mp, type);
	return (error);
out:
	qf_put(qfp, QTF_OPENING);
	
	return (error);
}



struct ufs_quotaoff_cargs {
        int	type;
};

static int
ufs_quotaoff_callback(struct vnode *vp, void *cargs)
{
	struct ufs_quotaoff_cargs *args;
	struct inode *ip;
	struct dquot *dq;

	args = (struct ufs_quotaoff_cargs *)cargs;

        ip = VTOI(vp);

	dq = ip->i_dquot[args->type];
	ip->i_dquot[args->type] = NODQUOT;

	dqrele(dq);

	return (VNODE_RETURNED);
}

/*
 * Q_QUOTAOFF - turn off disk quotas for a filesystem.
 */
int
quotaoff(struct mount *mp, register int type)
{
	struct vnode *qvp;
	struct ufsmount *ump = VFSTOUFS(mp);
	struct quotafile *qfp;
	int error = 0;
	kauth_cred_t cred;
	struct ufs_quotaoff_cargs args;
	
	qfp = &ump->um_qfiles[type];

	if ( (qf_get(qfp, QTF_CLOSING)) )
	        return (0);
	qvp = qfp->qf_vp;

        /*
         * Sync out any orpaned dirty dquot entries.
         */
        dqsync_orphans(qfp);
	
	/*
	 * Search vnodes associated with this mount point,
	 * deleting any references to quota file being closed.
         *
	 * ufs_quotaoff_callback will be called for each vnode
	 * hung off of this mount point
	 * the vnode will be in an 'unbusy' state (VNODE_WAIT) and 
	 * properly referenced and unreferenced around the callback
	 */
	args.type = type;

	vnode_iterate(mp, VNODE_WAIT, ufs_quotaoff_callback, (void *)&args);
	
	dqflush(qvp);
	/* Finish tearing down the quota file */
	dqfileclose(qfp, type);

	vnode_clearnoflush(qvp);
	error = vnode_close(qvp, FREAD|FWRITE, NULL);

	qfp->qf_vp = NULLVP;
	cred = qfp->qf_cred;
	if (cred != NOCRED) {
		qfp->qf_cred = NOCRED;
		kauth_cred_rele(cred);
	}
	for (type = 0; type < MAXQUOTAS; type++)
		if (ump->um_qfiles[type].qf_vp != NULLVP)
			break;
	if (type == MAXQUOTAS)
		mp->mnt_flag &= ~MNT_QUOTA;
	
	qf_put(qfp, QTF_CLOSING);

	return (error);
}

/*
 * Q_GETQUOTA - return current values in a dqblk structure.
 */
int
getquota(mp, id, type, datap)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t datap;
{
	struct dquot *dq;
	int error;

	if ( (error = dqget(id, &VFSTOUFS(mp)->um_qfiles[type], type, &dq)) )
		return (error);
	dqlock(dq);

	bcopy(&dq->dq_dqb, datap, sizeof(dq->dq_dqb));

	dqunlock(dq);
	dqrele(dq);

	return (error);
}

/*
 * Q_SETQUOTA - assign an entire dqblk structure.
 */
int
setquota(mp, id, type, datap)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t datap;
{
	struct dquot *dq;
	struct ufsmount *ump = VFSTOUFS(mp);
	struct dqblk * newlimp = (struct dqblk *) datap;
	struct timeval tv;
	int error;

	error = dqget(id, &ump->um_qfiles[type], type, &dq);
	if (error)
		return (error);
	dqlock(dq);

	/*
	 * Copy all but the current values.
	 * Reset time limit if previously had no soft limit or were
	 * under it, but now have a soft limit and are over it.
	 */
	newlimp->dqb_curbytes = dq->dq_curbytes;
	newlimp->dqb_curinodes = dq->dq_curinodes;
	if (dq->dq_id != 0) {
		newlimp->dqb_btime = dq->dq_btime;
		newlimp->dqb_itime = dq->dq_itime;
	}
	if (newlimp->dqb_bsoftlimit &&
	    dq->dq_curbytes >= newlimp->dqb_bsoftlimit &&
	    (dq->dq_bsoftlimit == 0 || dq->dq_curbytes < dq->dq_bsoftlimit)) {
		microtime(&tv);
		newlimp->dqb_btime = tv.tv_sec + ump->um_qfiles[type].qf_btime;
	}
	if (newlimp->dqb_isoftlimit &&
	    dq->dq_curinodes >= newlimp->dqb_isoftlimit &&
	    (dq->dq_isoftlimit == 0 || dq->dq_curinodes < dq->dq_isoftlimit)) {
		microtime(&tv);
		newlimp->dqb_itime = tv.tv_sec + ump->um_qfiles[type].qf_itime;
	}
	bcopy(newlimp, &dq->dq_dqb, sizeof(dq->dq_dqb));
	if (dq->dq_curbytes < dq->dq_bsoftlimit)
		dq->dq_flags &= ~DQ_BLKS;
	if (dq->dq_curinodes < dq->dq_isoftlimit)
		dq->dq_flags &= ~DQ_INODS;
	if (dq->dq_isoftlimit == 0 && dq->dq_bsoftlimit == 0 &&
	    dq->dq_ihardlimit == 0 && dq->dq_bhardlimit == 0)
		dq->dq_flags |= DQ_FAKE;
	else
		dq->dq_flags &= ~DQ_FAKE;
	dq->dq_flags |= DQ_MOD;

	dqunlock(dq);
	dqrele(dq);

	return (0);
}

/*
 * Q_SETUSE - set current inode and byte usage.
 */
int
setuse(mp, id, type, datap)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t datap;
{
	struct dquot *dq;
	struct ufsmount *ump = VFSTOUFS(mp);
	struct timeval tv;
	int error;
	struct dqblk *quotablkp = (struct dqblk *) datap;
	
	error = dqget(id, &ump->um_qfiles[type], type, &dq);
	if (error)
		return (error);
	dqlock(dq);

	/*
	 * Reset time limit if have a soft limit and were
	 * previously under it, but are now over it.
	 */
	if (dq->dq_bsoftlimit && dq->dq_curbytes < dq->dq_bsoftlimit &&
	    quotablkp->dqb_curbytes >= dq->dq_bsoftlimit) {
		microtime(&tv);
		dq->dq_btime = tv.tv_sec + ump->um_qfiles[type].qf_btime;
	}
	if (dq->dq_isoftlimit && dq->dq_curinodes < dq->dq_isoftlimit &&
	    quotablkp->dqb_curinodes >= dq->dq_isoftlimit) {
		microtime(&tv);
		dq->dq_itime = tv.tv_sec + ump->um_qfiles[type].qf_itime;
	}
	dq->dq_curbytes = quotablkp->dqb_curbytes;
	dq->dq_curinodes = quotablkp->dqb_curinodes;
	if (dq->dq_curbytes < dq->dq_bsoftlimit)
		dq->dq_flags &= ~DQ_BLKS;
	if (dq->dq_curinodes < dq->dq_isoftlimit)
		dq->dq_flags &= ~DQ_INODS;
	dq->dq_flags |= DQ_MOD;

	dqunlock(dq);
	dqrele(dq);

	return (0);
}



static int
ufs_qsync_callback(struct vnode *vp, __unused void *cargs)
{
	struct inode *ip;
	struct dquot *dq;
	int 	i;

        ip = VTOI(vp);

	for (i = 0; i < MAXQUOTAS; i++) {
	        dq = ip->i_dquot[i];
		if (dq != NODQUOT && (dq->dq_flags & DQ_MOD))
		        dqsync(dq);
	}
	return (VNODE_RETURNED);
}


/*
 * Q_SYNC - sync quota files to disk.
 */
int
qsync(mp)
	struct mount *mp;
{
	struct ufsmount *ump = VFSTOUFS(mp);
	int i;

	/*
	 * Check if the mount point has any quotas.
	 * If not, simply return.
	 */
	for (i = 0; i < MAXQUOTAS; i++)
		if (ump->um_qfiles[i].qf_vp != NULLVP)
			break;
	if (i == MAXQUOTAS)
		return (0);
	/*
	 * Search vnodes associated with this mount point,
	 * synchronizing any modified dquot structures.
	 *
	 * ufs_qsync_callback will be called for each vnode
	 * hung off of this mount point
	 * the vnode will be
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mp, 0, ufs_qsync_callback, (void *)NULL);
	
	return (0);
}

/*
 * Q_QUOTASTAT - get quota on/off status 
 */
int
quotastat(mp, type, datap)
	struct mount *mp;
	register int type;
	caddr_t datap;
{
	struct ufsmount *ump = VFSTOUFS(mp);
	int error = 0;
	int qstat;

	if ((mp->mnt_flag & MNT_QUOTA) && (ump->um_qfiles[type].qf_vp != NULLVP))
	  qstat = 1;   /* quotas are on for this type */
	else
	  qstat = 0;   /* quotas are off for this type */
	*((int *)datap) = qstat;
	return (error);
}

