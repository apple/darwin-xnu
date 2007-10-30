/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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
 *	@(#)hfs_quota.c
 *	derived from @(#)ufs_quota.c	8.5 (Berkeley) 5/20/95
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/quota.h>
#include <sys/proc_internal.h>
#include <kern/kalloc.h>

#include <hfs/hfs.h>
#include <hfs/hfs_cnode.h>
#include <hfs/hfs_quota.h>
#include <hfs/hfs_mount.h>

/*
 * Quota name to error message mapping.
 */
#if 0
static char *quotatypes[] = INITQFNAMES;
#endif

/*
 * Set up the quotas for a cnode.
 *
 * This routine completely defines the semantics of quotas.
 * If other criterion want to be used to establish quotas, the
 * MAXQUOTAS value in quotas.h should be increased, and the
 * additional dquots set up here.
 */
int
hfs_getinoquota(cp)
	register struct cnode *cp;
{
	struct hfsmount *hfsmp;
	struct vnode *vp;
	int error;

	vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;
	hfsmp = VTOHFS(vp);
	/*
	 * Set up the user quota based on file uid.
	 * EINVAL means that quotas are not enabled.
	 */
	if (cp->c_dquot[USRQUOTA] == NODQUOT &&
	    (error =
		dqget(cp->c_uid, &hfsmp->hfs_qfiles[USRQUOTA], USRQUOTA, &cp->c_dquot[USRQUOTA])) &&
	    error != EINVAL)
		return (error);
	/*
	 * Set up the group quota based on file gid.
	 * EINVAL means that quotas are not enabled.
	 */
	if (cp->c_dquot[GRPQUOTA] == NODQUOT &&
	    (error =
		dqget(cp->c_gid, &hfsmp->hfs_qfiles[GRPQUOTA], GRPQUOTA, &cp->c_dquot[GRPQUOTA])) &&
	    error != EINVAL)
		return (error);
	return (0);
}

/*
 * Update disk usage, and take corrective action.
 */
int
hfs_chkdq(cp, change, cred, flags)
	register struct cnode *cp;
	int64_t change;
	kauth_cred_t cred;
	int flags;
{
	register struct dquot *dq;
	register int i;
	int64_t ncurbytes;
	int error=0;
	struct proc *p;

#if DIAGNOSTIC
	if ((flags & CHOWN) == 0)
		hfs_chkdquot(cp);
#endif
	if (change == 0)
		return (0);
	if (change < 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
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
	p = current_proc();
	if (cred == NOCRED)
		cred = proc_ucred(kernproc);
	if (suser(cred, NULL) || proc_forcequota(p)) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			error = hfs_chkdqchg(cp, change, cred, i);
			if (error) {
				break;
			}
		}
	}
	if ((flags & FORCE) || error == 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			dqlock(dq);

			dq->dq_curbytes += change;
			dq->dq_flags |= DQ_MOD;

			dqunlock(dq);
		}
	}
	return (error);
}

/*
 * Check for a valid change to a users allocation.
 * Issue an error message if appropriate.
 */
int
hfs_chkdqchg(cp, change, cred, type)
	struct cnode *cp;
	int64_t change;
	kauth_cred_t cred;
	int type;
{
	register struct dquot *dq = cp->c_dquot[type];
	u_int64_t ncurbytes;
	struct vnode *vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;
	
	dqlock(dq);
	
	ncurbytes = dq->dq_curbytes + change;
	/*
	 * If user would exceed their hard limit, disallow space allocation.
	 */
	if (ncurbytes >= dq->dq_bhardlimit && dq->dq_bhardlimit) {
		if ((dq->dq_flags & DQ_BLKS) == 0 &&
		    cp->c_uid == kauth_cred_getuid(cred)) {
#if 0	
			printf("\nwrite failed, %s disk limit reached\n",
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

		microuptime(&tv);
		if (dq->dq_curbytes < dq->dq_bsoftlimit) {
			dq->dq_btime = tv.tv_sec +
			    VTOHFS(vp)->hfs_qfiles[type].qf_btime;
#if 0
			if (cp->c_uid == kauth_cred_getuid(cred))
				printf("\nwarning, %s %s\n",
				    quotatypes[type], "disk quota exceeded");
#endif
			dqunlock(dq);

			return (0);
		}
		if (tv.tv_sec > dq->dq_btime) {
			if ((dq->dq_flags & DQ_BLKS) == 0 &&
			    cp->c_uid == kauth_cred_getuid(cred)) {
#if 0
				printf("\nwrite failed, %s %s\n",
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
hfs_chkiq(cp, change, cred, flags)
	register struct cnode *cp;
	long change;
	kauth_cred_t cred;
	int flags;
{
	register struct dquot *dq;
	register int i;
	int ncurinodes, error=0;
	struct proc *p;

#if DIAGNOSTIC
	if ((flags & CHOWN) == 0)
		hfs_chkdquot(cp);
#endif
	if (change == 0)
		return (0);
	if (change < 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
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
	p = current_proc();
	if (cred == NOCRED)
		cred = proc_ucred(kernproc);
	if (suser(cred, NULL) || proc_forcequota(p)) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			error = hfs_chkiqchg(cp, change, cred, i);
			if (error) {
				break;
			}
		}
	}
	if ((flags & FORCE) || error == 0) { 
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			dqlock(dq);

			dq->dq_curinodes += change;
			dq->dq_flags |= DQ_MOD;

			dqunlock(dq);
		}
	}
	return (error);
}

/*
 * Check for a valid change to a users allocation.
 * Issue an error message if appropriate.
 */
int
hfs_chkiqchg(cp, change, cred, type)
	struct cnode *cp;
	long change;
	kauth_cred_t cred;
	int type;
{
	register struct dquot *dq = cp->c_dquot[type];
	long ncurinodes;
	struct vnode *vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;

	dqlock(dq);

	ncurinodes = dq->dq_curinodes + change;
	/*
	 * If user would exceed their hard limit, disallow cnode allocation.
	 */
	if (ncurinodes >= dq->dq_ihardlimit && dq->dq_ihardlimit) {
		if ((dq->dq_flags & DQ_INODS) == 0 &&
		    cp->c_uid == kauth_cred_getuid(cred)) {
#if 0
			printf("\nwrite failed, %s cnode limit reached\n",
			    quotatypes[type]);
#endif
			dq->dq_flags |= DQ_INODS;
		}
		dqunlock(dq);

		return (EDQUOT);
	}
	/*
	 * If user is over their soft limit for too long, disallow cnode
	 * allocation. Reset time limit as they cross their soft limit.
	 */
	if (ncurinodes >= dq->dq_isoftlimit && dq->dq_isoftlimit) {
		struct timeval tv;
		
		microuptime(&tv);
		if (dq->dq_curinodes < dq->dq_isoftlimit) {
			dq->dq_itime = tv.tv_sec +
			    VTOHFS(vp)->hfs_qfiles[type].qf_itime;
#if 0
			if (cp->c_uid == kauth_cred_getuid(cred))
				printf("\nwarning, %s %s\n",
				    quotatypes[type], "cnode quota exceeded");
#endif
			dqunlock(dq);

			return (0);
		}
		if (tv.tv_sec > dq->dq_itime) {
			if ((dq->dq_flags & DQ_INODS) == 0 &&
			    cp->c_uid == kauth_cred_getuid(cred)) {
#if 0
				printf("\nwrite failed, %s %s\n",
				    quotatypes[type],
				    "cnode quota exceeded for too long");
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
hfs_chkdquot(cp)
	register struct cnode *cp;
{
	struct vnode *vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;
	struct hfsmount *hfsmp = VTOHFS(vp);
	register int i;

	for (i = 0; i < MAXQUOTAS; i++) {
		if (hfsmp->hfs_qfiles[i].qf_vp == NULLVP)
			continue;
		if (cp->c_dquot[i] == NODQUOT) {
			vprint("chkdquot: missing dquot", vp);
			panic("missing dquot");
		}
	}
}
#endif

/*
 * Code to process quotactl commands.
 */

/*
 * Q_QUOTAON - set up a quota file for a particular file system.
 */
struct hfs_quotaon_cargs {
        int	error;
};

static int
hfs_quotaon_callback(struct vnode *vp, void *cargs)
{
	struct hfs_quotaon_cargs *args;

	args = (struct hfs_quotaon_cargs *)cargs;

	args->error = hfs_getinoquota(VTOC(vp));
	if (args->error)
	        return (VNODE_RETURNED_DONE);

	return (VNODE_RETURNED);
}

int
hfs_quotaon(p, mp, type, fnamep)
	struct proc *p;
	struct mount *mp;
	register int type;
	caddr_t fnamep;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct quotafile *qfp;
	struct vnode *vp;
	int error = 0;
	struct hfs_quotaon_cargs args;

	qfp = &hfsmp->hfs_qfiles[type];

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
	qfp->qf_cred = kauth_cred_proc_ref(p);
	qfp->qf_vp = vp;
	/*
	 * Finish initializing the quota file
	 */
	error = dqfileopen(qfp, type);
	if (error) {
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
	 * NB: only need to add dquot's for cnodes being modified.
	 *
	 * hfs_quota_callback will be called for each vnode open for
	 * 'write' (VNODE_WRITEABLE) hung off of this mount point
	 * the vnode will be in an 'unbusy' state (VNODE_WAIT) and 
	 * properly referenced and unreferenced around the callback
	 */
	args.error = 0;

	vnode_iterate(mp, VNODE_WRITEABLE | VNODE_WAIT, hfs_quotaon_callback, (void *)&args);
	
	error = args.error;

	if (error) {
		hfs_quotaoff(p, mp, type);
	}
	return (error);

out:
	qf_put(qfp, QTF_OPENING);

	return (error);
}


/*
 * Q_QUOTAOFF - turn off disk quotas for a filesystem.
 */
struct hfs_quotaoff_cargs {
        int	type;
};

static int
hfs_quotaoff_callback(struct vnode *vp, void *cargs)
{
	struct hfs_quotaoff_cargs *args;
	struct cnode *cp;
	struct dquot *dq;

	args = (struct hfs_quotaoff_cargs *)cargs;

	cp = VTOC(vp);

	dq = cp->c_dquot[args->type];
	cp->c_dquot[args->type] = NODQUOT;

	dqrele(dq);

	return (VNODE_RETURNED);
}

int
hfs_quotaoff(__unused struct proc *p, struct mount *mp, register int type)
{
	struct vnode *qvp;
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct quotafile *qfp;
	int error;
	kauth_cred_t cred;
	struct hfs_quotaoff_cargs args;

	qfp = &hfsmp->hfs_qfiles[type];
	
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
	 * hfs_quotaoff_callback will be called for each vnode
	 * hung off of this mount point
	 * the vnode will be in an 'unbusy' state (VNODE_WAIT) and 
	 * properly referenced and unreferenced around the callback
	 */
	args.type = type;

	vnode_iterate(mp, VNODE_WAIT, hfs_quotaoff_callback, (void *)&args);

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
		if (hfsmp->hfs_qfiles[type].qf_vp != NULLVP)
			break;
	if (type == MAXQUOTAS)
		vfs_clearflags(mp, (uint64_t)((unsigned int)MNT_QUOTA));

	qf_put(qfp, QTF_CLOSING);

	return (error);
}

/*
 * Q_GETQUOTA - return current values in a dqblk structure.
 */
int
hfs_getquota(mp, id, type, datap)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t datap;
{
	struct dquot *dq;
	int error;

	error = dqget(id, &VFSTOHFS(mp)->hfs_qfiles[type], type, &dq);
	if (error)
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
hfs_setquota(mp, id, type, datap)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t datap;
{
	struct dquot *dq;
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct dqblk * newlimp = (struct dqblk *) datap;
	struct timeval tv;
	int error;

	error = dqget(id, &hfsmp->hfs_qfiles[type], type, &dq);
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
		microuptime(&tv);
		newlimp->dqb_btime = tv.tv_sec + hfsmp->hfs_qfiles[type].qf_btime;
	}
	if (newlimp->dqb_isoftlimit &&
	    dq->dq_curinodes >= newlimp->dqb_isoftlimit &&
	    (dq->dq_isoftlimit == 0 || dq->dq_curinodes < dq->dq_isoftlimit)) {
		microuptime(&tv);
		newlimp->dqb_itime = tv.tv_sec + hfsmp->hfs_qfiles[type].qf_itime;
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
 * Q_SETUSE - set current cnode and byte usage.
 */
int
hfs_setuse(mp, id, type, datap)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t datap;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct dquot *dq;
	struct timeval tv;
	int error;
	struct dqblk *quotablkp = (struct dqblk *) datap;

	error = dqget(id, &hfsmp->hfs_qfiles[type], type, &dq);
	if (error)
	        return (error);
	dqlock(dq);

	/*
	 * Reset time limit if have a soft limit and were
	 * previously under it, but are now over it.
	 */
	if (dq->dq_bsoftlimit && dq->dq_curbytes < dq->dq_bsoftlimit &&
	    quotablkp->dqb_curbytes >= dq->dq_bsoftlimit) {
		microuptime(&tv);
		dq->dq_btime = tv.tv_sec + hfsmp->hfs_qfiles[type].qf_btime;
	}
	if (dq->dq_isoftlimit && dq->dq_curinodes < dq->dq_isoftlimit &&
	    quotablkp->dqb_curinodes >= dq->dq_isoftlimit) {
		microuptime(&tv);
		dq->dq_itime = tv.tv_sec + hfsmp->hfs_qfiles[type].qf_itime;
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


/*
 * Q_SYNC - sync quota files to disk.
 */
static int
hfs_qsync_callback(struct vnode *vp, __unused void *cargs)
{
	struct cnode *cp;
	struct dquot *dq;
	int 	i;

	cp = VTOC(vp);
		    
	for (i = 0; i < MAXQUOTAS; i++) {
	        dq = cp->c_dquot[i];
		if (dq != NODQUOT && (dq->dq_flags & DQ_MOD))
		        dqsync(dq);
	}
	return (VNODE_RETURNED);
}

int
hfs_qsync(mp)
	struct mount *mp;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	int i;

	/*
	 * Check if the mount point has any quotas.
	 * If not, simply return.
	 */
	for (i = 0; i < MAXQUOTAS; i++)
		if (hfsmp->hfs_qfiles[i].qf_vp != NULLVP)
			break;
	if (i == MAXQUOTAS)
		return (0);

	/*
	 * Sync out any orpaned dirty dquot entries.
	 */
	for (i = 0; i < MAXQUOTAS; i++)
		if (hfsmp->hfs_qfiles[i].qf_vp != NULLVP)
			dqsync_orphans(&hfsmp->hfs_qfiles[i]);

	/*
	 * Search vnodes associated with this mount point,
	 * synchronizing any modified dquot structures.
	 *
	 * hfs_qsync_callback will be called for each vnode
	 * hung off of this mount point
	 * the vnode will be
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mp, 0, hfs_qsync_callback, (void *)NULL);

	return (0);
}

/*
 * Q_QUOTASTAT - get quota on/off status 
 */
int
hfs_quotastat(mp, type, datap)
	struct mount *mp;
	register int type;
	caddr_t datap;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	int error = 0;
	int qstat;

	if ((((unsigned int)vfs_flags(mp)) & MNT_QUOTA) && (hfsmp->hfs_qfiles[type].qf_vp != NULLVP))
	  qstat = 1;   /* quotas are on for this type */
	else
	  qstat = 0;   /* quotas are off for this type */
	
	*((int *)datap) = qstat;
	return (error);
}

